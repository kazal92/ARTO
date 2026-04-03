import os
import json
import asyncio

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse

from agents.analysis import run_analysis_agent
from core.session import find_session_dir, save_tool_result
from core.logging import stream_log, stream_custom
from core.cancellation import mark_active, mark_inactive, is_active

router = APIRouter()


@router.post("/api/session/{session_id}/clear_log")
async def clear_session_log(session_id: str):
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    log_file = os.path.join(session_dir, "scan_log.jsonl")
    if os.path.exists(log_file):
        open(log_file, "w").close()
    return {"status": "ok"}


@router.post("/api/session/{session_id}/auto_target")
async def auto_target(session_id: str):
    """recon_map.json에 자동 필터링 적용 후 ai_input_full_requests.json 저장 및 타겟 URL 목록 반환"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}

    recon_map_path = os.path.join(session_dir, "recon_map.json")
    if not os.path.exists(recon_map_path):
        return {"status": "error", "message": "정찰 데이터가 없습니다."}

    import urllib.parse
    from tools import minimize_request_raw, extract_relevant_snippet
    from config import ENABLE_REQUEST_COMPRESSION

    with open(recon_map_path, "r", encoding="utf-8") as f:
        recon_data = json.load(f)

    all_requests = []
    endpoints = recon_data.get("endpoints", [])
    for ep in endpoints:
        req_raw = ep.get("request_raw")
        res_raw = ep.get("response_raw", "")
        if not req_raw:
            continue
        minimized_req = minimize_request_raw(req_raw) if ENABLE_REQUEST_COMPRESSION else req_raw
        req_parts = req_raw.split("\n\n", 1)
        r_body = req_parts[1] if len(req_parts) > 1 else ""
        context = extract_relevant_snippet(ep["url"], r_body, res_raw)
        all_requests.append({
            "url": ep["url"],
            "method": ep["method"],
            "source": ep.get("source", "recon"),
            "raw_request": minimized_req,
            "response_context": context["response_context"],
        })

    # 구조적 중복 제거 (자동 타겟지정)
    filtered = []
    seen_structs = {}
    for req in all_requests:
        parsed = urllib.parse.urlparse(req["url"])
        path = parsed.path or "/"
        q_keys = ",".join(sorted(urllib.parse.parse_qs(parsed.query).keys()))
        struct_key = f"{req['method']}:{path}:{q_keys or 'no_params'}"
        seen_structs[struct_key] = seen_structs.get(struct_key, 0) + 1
        if seen_structs[struct_key] <= 2:
            filtered.append(req)

    target_keys = [f"{r['method']}:{r['url']}" for r in filtered]

    for r in filtered:
        r.pop("method", None)
        r.pop("source", None)
        r.pop("url", None)

    save_tool_result(session_dir, "ai_input_full_requests", filtered, indent=None)

    return {"status": "ok", "targets": target_keys}


@router.post("/api/session/{session_id}/ai_targets")
async def save_ai_targets(session_id: str, body: dict):
    """수동 체크박스 변경 시 ai_input_full_requests.json 갱신"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}

    recon_map_path = os.path.join(session_dir, "recon_map.json")
    if not os.path.exists(recon_map_path):
        return {"status": "error", "message": "정찰 데이터가 없습니다."}

    import urllib.parse
    from tools import minimize_request_raw, extract_relevant_snippet
    from config import ENABLE_REQUEST_COMPRESSION

    selected_keys = set(body.get("targets", []))  # ["METHOD:URL", ...]

    with open(recon_map_path, "r", encoding="utf-8") as f:
        recon_data = json.load(f)

    result = []
    for ep in recon_data.get("endpoints", []):
        key = f"{ep['method']}:{ep['url']}"
        if key not in selected_keys:
            continue
        req_raw = ep.get("request_raw")
        if not req_raw:
            continue
        res_raw = ep.get("response_raw", "")
        minimized_req = minimize_request_raw(req_raw) if ENABLE_REQUEST_COMPRESSION else req_raw
        req_parts = req_raw.split("\n\n", 1)
        r_body = req_parts[1] if len(req_parts) > 1 else ""
        context = extract_relevant_snippet(ep["url"], r_body, res_raw)
        result.append({
            "raw_request": minimized_req,
            "response_context": context["response_context"],
        })

    save_tool_result(session_dir, "ai_input_full_requests", result, indent=None)
    return {"status": "ok"}


@router.post("/api/session/{session_id}/run_ai")
async def run_ai(session_id: str, request: Request):
    """ai_input_full_requests.json 기반으로 AI 분석 실행 (SSE)"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    recon_map_path = os.path.join(session_dir, "recon_map.json")
    ai_input_path = os.path.join(session_dir, "ai_input_full_requests.json")

    if not os.path.exists(recon_map_path):
        return {"status": "error", "message": "정찰 데이터가 없습니다."}
    if not os.path.exists(ai_input_path):
        return {"status": "error", "message": "AI 분석 대상이 없습니다. 먼저 타겟을 지정하세요."}

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    ai_config = body.get("ai_config", {})

    with open(recon_map_path, "r", encoding="utf-8") as f:
        recon_data = json.load(f)

    log_file = os.path.join(session_dir, "scan_log.jsonl")

    async def event_generator():
        await mark_active(session_dir)

        async def run_task():
            try:
                async for _ in run_analysis_agent(
                    recon_data.get("target", ""),
                    session_dir,
                    recon_data,
                    {},
                    ai_config,
                    user_specified=True
                ):
                    await asyncio.sleep(0)
            except Exception as e:
                stream_log(session_dir, f"AI 분석 오류: {e}", "System")
            finally:
                await mark_inactive(session_dir)

        asyncio.create_task(run_task())

        sent_lines = 0
        timeout_count = 0
        while timeout_count < 7200:
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8") as f:
                    all_lines = f.readlines()
                    if len(all_lines) > sent_lines:
                        for idx in range(sent_lines, len(all_lines)):
                            line = all_lines[idx].strip()
                            if line:
                                yield f"data: {line}\n\n"
                                sent_lines += 1
                                if "scan_complete" in line:
                                    return

            if not is_active(session_dir):
                await asyncio.sleep(2)
                if os.path.exists(log_file):
                    with open(log_file, "r", encoding="utf-8") as f:
                        if len(f.readlines()) <= sent_lines:
                            break

            await asyncio.sleep(0.5)
            timeout_count += 1

    return StreamingResponse(event_generator(), media_type="text/event-stream")
