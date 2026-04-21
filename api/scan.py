import os
import json
import asyncio
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from agents.recon import run_recon_agent
from core.session import get_session_dir, find_session_dir, save_tool_result
from core.logging import stream_log, stream_custom
from core.cancellation import is_cancelled, mark_cancelled, mark_active, mark_inactive, is_active, clear_cancelled
from core.sse import stream_log_file
from tools import stop_all_processes

router = APIRouter()


class ScanRequest(BaseModel):
    target_url: Optional[str] = None
    headers: dict = {}
    ai_config: dict = {}
    project_name: str = ""
    session_id: str = ""
    project_type: str = "scan"
    ffuf_options: str = "-t 50 -mc 200,204,301,302,307,401,403,500 -ac -ic"
    ffuf_wordlist: str = ""
    enable_zap_spider: bool = True
    enable_ffuf: bool = True
    enable_deep_recon: bool = True
    enable_nuclei: bool = False
    enable_nmap: bool = False

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v):
        if v is not None and v != "" and not v.startswith(("http://", "https://")):
            raise ValueError("target_url은 http:// 또는 https://로 시작해야 합니다.")
        return v

    @field_validator("project_type")
    @classmethod
    def validate_project_type(cls, v):
        if v not in ("scan", "precheck"):
            raise ValueError("project_type은 'scan' 또는 'precheck'이어야 합니다.")
        return v


@router.post("/api/project/create")
async def create_project(req: ScanRequest):
    """신규 프로젝트 생성 (스캔 실행 안 함, 디렉토리만 초기화)"""
    try:
        p_name = req.project_name if req.project_name else "New_Project"
        p_type = req.project_type
        session_dir = get_session_dir(p_name, p_type)

        info_file = os.path.join(session_dir, "project_info.json")
        with open(info_file, "w", encoding="utf-8") as f:
            json.dump({
                "project_name": p_name,
                "target": req.target_url or "",
                "project_type": p_type,
                "headers": req.headers,
                "ai_config": req.ai_config,
                "ffuf_options": req.ffuf_options,
                "ffuf_wordlist": req.ffuf_wordlist,
                "enable_zap_spider": req.enable_zap_spider,
                "enable_ffuf": req.enable_ffuf,
                "enable_deep_recon": req.enable_deep_recon,
                "enable_nuclei": req.enable_nuclei,
                "enable_nmap": req.enable_nmap
            }, f, ensure_ascii=False, indent=2)

        stream_log(session_dir, "프로젝트가 성공적으로 생성되었습니다. (대시보드 진입 대기)", "System", 0)

        return {"status": "success", "session_id": os.path.basename(session_dir)}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request):
    """Start scan event stream or resume existing one"""
    session_id_query = request.query_params.get("session_id")

    if session_id_query:
        session_dir = find_session_dir(session_id_query)
        if not session_dir or not os.path.exists(session_dir):
            return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}
        is_resume = True
    elif req.session_id:
        session_dir = find_session_dir(req.session_id)
        if not session_dir:
            session_dir = get_session_dir(req.project_name if req.project_name else req.target_url)
        is_resume = False
    else:
        session_dir = get_session_dir(req.target_url)
        is_resume = False

    async def event_generator():
        log_file = os.path.join(session_dir, "scan_log.jsonl")
        sent_lines = 0

        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_strip = line.strip()
                    if line_strip:
                        try:
                            yield f"data: {line_strip}\n\n"
                            sent_lines += 1
                            if sent_lines % 50 == 0:
                                await asyncio.sleep(0.01)
                        except (UnicodeDecodeError, OSError):
                            continue

        current_sid = os.path.basename(session_dir)
        yield f"data: {{\"type\": \"scan_start\", \"session_id\": \"{current_sid}\"}}\n\n"

        if is_resume:
            yield f"data: {{\"type\": \"log\", \"agent\": \"System\", \"message\": \"스캔 세션에 재연결되었습니다.\", \"progress\": null}}\n\n"
        else:
            try:
                info_file = os.path.join(session_dir, "project_info.json")
                with open(info_file, "w", encoding="utf-8") as f:
                    json.dump({
                        "project_name": req.project_name if req.project_name else os.path.basename(session_dir),
                        "target": req.target_url,
                        "project_type": req.project_type,
                        "headers": req.headers,
                        "ai_config": req.ai_config,
                        "ffuf_options": req.ffuf_options,
                        "ffuf_wordlist": req.ffuf_wordlist,
                        "enable_zap_spider": req.enable_zap_spider,
                        "enable_ffuf": req.enable_ffuf,
                        "enable_deep_recon": req.enable_deep_recon,
                        "enable_nuclei": req.enable_nuclei,
                        "enable_nmap": req.enable_nmap
                    }, f, ensure_ascii=False, indent=2)
            except Exception:
                pass

            msg_json = stream_log(session_dir, f"스캔 세션 시작: {session_dir}", "System", 0)
            yield f"data: {msg_json}\n\n"
            sent_lines += 1

        if not is_resume and not is_active(session_dir):
            await clear_cancelled(session_dir)
            await mark_active(session_dir)



            async def run_scan_task(ai_config: dict):
                try:
                    async for update in run_recon_agent(
                        req.target_url, session_dir, req.headers,
                        enable_deep_recon=req.enable_deep_recon,
                        enable_zap=req.enable_zap_spider,
                        enable_ffuf=req.enable_ffuf,
                        ffuf_options=req.ffuf_options,
                        ffuf_wordlist=req.ffuf_wordlist
                    ):
                        await asyncio.sleep(0)

                    stream_custom(session_dir, {"type": "scan_complete", "data": []})
                except Exception as e:
                    stream_log(session_dir, f"Background Scan Error: {str(e)}", "System")
                finally:
                    await mark_inactive(session_dir)

            asyncio.create_task(run_scan_task(req.ai_config))

        async for event in stream_log_file(session_dir, log_file, start_line=sent_lines):
            yield event

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/api/scan/stop")
async def stop_scan(req: ScanRequest):
    """실행 중인 취약점 스캔 중지"""
    session_id = req.session_id
    session_dir = find_session_dir(session_id) if session_id else None
    if session_dir:
        await mark_cancelled(session_dir)
        stop_all_processes()
        return {"status": "success", "message": "스캔 중지 명령이 전달되었습니다."}
    return {"status": "error", "message": "취소 요청용 타겟 세션을 지정할 수 없습니다."}
