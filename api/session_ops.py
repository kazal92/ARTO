import os
import json
import asyncio
import urllib.parse

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse, JSONResponse

from agents.analysis import run_analysis_agent
from core.session import find_session_dir, save_tool_result
from core.logging import stream_log, stream_custom
from core.cancellation import mark_active, mark_inactive, is_active
from core.sse import stream_log_file, count_log_lines
from tools import minimize_request_raw, extract_relevant_snippet
from config import ENABLE_REQUEST_COMPRESSION

router = APIRouter()


@router.post("/api/session/{session_id}/clear_log")
async def clear_session_log(session_id: str):
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    log_file = os.path.join(session_dir, "scan_log.jsonl")
    if os.path.exists(log_file):
        with open(log_file, "w"):
            pass
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

    with open(recon_map_path, "r", encoding="utf-8") as f:
        recon_data = json.load(f)

    all_requests = []
    endpoints = recon_data.get("endpoints", [])
    for ep in endpoints:
        req_raw = ep.get("request_raw")
        res_raw = ep.get("response_raw", "")
        if not req_raw:
            continue
        try:
            status_code = int(ep.get("status", 0) or 0)
        except (ValueError, TypeError):
            status_code = 0
        if status_code in (400, 404, 405):
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

    filtered = []
    seen_structs = {}
    for req in all_requests:
        parsed = urllib.parse.urlparse(req["url"])
        path = parsed.path or "/"
        q_keys = ",".join(sorted(urllib.parse.parse_qs(parsed.query).keys()))
        struct_key = f"{req['method']}:{path}:{q_keys or 'no_params'}"
        seen_structs[struct_key] = seen_structs.get(struct_key, 0) + 1
        if seen_structs[struct_key] <= 1:
            filtered.append(req)

    target_keys = [f"{r['method']}:{r['url']}" for r in filtered]

    for r in filtered:
        r.pop("method", None)
        r.pop("source", None)
        r.pop("url", None)

    save_tool_result(session_dir, "ai_input_full_requests", filtered, indent=None)
    save_tool_result(session_dir, "ai_targets", target_keys)

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
    save_tool_result(session_dir, "ai_targets", list(selected_keys))
    return {"status": "ok"}


@router.get("/api/session/{session_id}/ai_targets")
async def get_ai_targets(session_id: str):
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "targets": []}
    path = os.path.join(session_dir, "ai_targets.json")
    if not os.path.exists(path):
        return {"status": "ok", "targets": []}
    with open(path, "r", encoding="utf-8") as f:
        return {"status": "ok", "targets": json.load(f)}


@router.post("/api/session/{session_id}/save_recon_map")
async def save_recon_map(session_id: str, request: Request):
    """ZAP 히스토리 로드 후 endpoints를 recon_map.json에 저장 (기존 데이터와 병합)"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return JSONResponse(status_code=400, content={"status": "error", "message": "유효하지 않은 세션 ID입니다."})

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass

    endpoints = body.get("endpoints", [])
    target = body.get("target", "")

    if not endpoints:
        return JSONResponse(status_code=400, content={"status": "error", "message": "저장할 엔드포인트가 없습니다."})

    recon_map_path = os.path.join(session_dir, "recon_map.json")

    existing_endpoints = []
    existing_target = target
    if os.path.exists(recon_map_path):
        try:
            with open(recon_map_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
                existing_endpoints = existing.get("endpoints", [])
                if not existing_target:
                    existing_target = existing.get("target", "")
        except Exception:
            pass

    existing_keys = {f"{(ep.get('method') or 'GET').upper()}:{ep.get('url', '')}" for ep in existing_endpoints}
    merged = list(existing_endpoints)
    for ep in endpoints:
        key = f"{(ep.get('method') or 'GET').upper()}:{ep.get('url', '')}"
        if key not in existing_keys:
            merged.append(ep)
            existing_keys.add(key)

    save_tool_result(session_dir, "recon_map", {"target": existing_target, "endpoints": merged})
    return {"status": "ok", "saved": len(merged), "added": len(merged) - len(existing_endpoints)}


@router.post("/api/session/{session_id}/run_ai")
async def run_ai(session_id: str, request: Request):
    """엔드포인트 데이터 기반으로 AI 분석 실행 (SSE)"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return JSONResponse(status_code=400, content={"status": "error", "message": "유효하지 않은 세션 ID입니다."})

    body = {}
    try:
        body = await request.json()
    except Exception:
        pass
    ai_config = body.get("ai_config", {})
    provided_endpoints = body.get("endpoints", [])

    recon_map_path = os.path.join(session_dir, "recon_map.json")

    if provided_endpoints:
        recon_data = {"target": "", "endpoints": provided_endpoints}
        if os.path.exists(recon_map_path):
            with open(recon_map_path, "r", encoding="utf-8") as f:
                recon_data["target"] = json.load(f).get("target", "")
    elif os.path.exists(recon_map_path):
        with open(recon_map_path, "r", encoding="utf-8") as f:
            recon_data = json.load(f)
    else:
        return JSONResponse(status_code=400, content={"status": "error", "message": "분석할 데이터가 없습니다. 타겟을 지정하세요."})

    if not recon_data.get("endpoints"):
        return JSONResponse(status_code=400, content={"status": "error", "message": "AI 분석 대상이 없습니다. 먼저 타겟을 지정하세요."})

    log_file = os.path.join(session_dir, "scan_log.jsonl")
    initial_lines = count_log_lines(log_file)

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

        async for event in stream_log_file(session_dir, log_file, start_line=initial_lines):
            yield event

    return StreamingResponse(event_generator(), media_type="text/event-stream")
