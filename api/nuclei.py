import os
import json
import asyncio

from fastapi import APIRouter
from pydantic import BaseModel, field_validator

from tools import run_nuclei, stop_all_processes
from core.session import find_session_dir, save_tool_result
from core.logging import stream_log, stream_custom
from core.cancellation import mark_inactive, mark_cancelled, is_cancelled
from api.common import make_tool_stream

router = APIRouter()

_nuclei_running_sessions: set = set()


class NucleiRequest(BaseModel):
    session_id: str
    target_url: str
    headers: dict = {}
    nuclei_options: str = "-severity critical"

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url은 http:// 또는 https://로 시작해야 합니다.")
        return v


class NucleiStopRequest(BaseModel):
    session_id: str


@router.post("/api/nuclei/run")
async def nuclei_run(req: NucleiRequest):
    """Nuclei 스캔 실행 — SSE 스트리밍"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    if session_dir in _nuclei_running_sessions:
        return {"status": "error", "message": "이미 실행 중인 Nuclei 세션입니다."}
    _nuclei_running_sessions.add(session_dir)

    log_file = os.path.join(session_dir, "scan_log.jsonl")

    async def run_task():
        findings = []
        try:
            async for update in run_nuclei(
                req.target_url,
                session_dir,
                headers=req.headers or None,
                nuclei_options=req.nuclei_options,
            ):
                if is_cancelled(session_dir):
                    stream_log(session_dir, "Nuclei 스캔이 사용자에 의해 중단되었습니다.", "Nuclei")
                    break

                utype = update.get("type")
                if utype == "progress":
                    stream_log(session_dir, update["msg"], "Nuclei", update.get("progress"))
                elif utype == "command":
                    stream_log(session_dir, update["cmd"], "Command")
                elif utype == "finding":
                    finding = update["data"]
                    findings.append(finding)
                    stream_custom(session_dir, {"type": "ai_card", "data": finding})

            if findings:
                existing = []
                findings_path = os.path.join(session_dir, "ai_findings.json")
                if os.path.exists(findings_path):
                    try:
                        with open(findings_path, "r", encoding="utf-8") as f:
                            existing = json.load(f)
                    except Exception:
                        existing = []
                save_tool_result(session_dir, "ai_findings", existing + findings)
                save_tool_result(session_dir, "nuclei_findings", findings)
                stream_log(session_dir, f"Nuclei 결과 {len(findings)}건이 저장되었습니다.", "Nuclei", 100)
            else:
                stream_log(session_dir, "Nuclei 스캔 완료: 발견된 취약점 없음", "Nuclei", 100)

        except Exception as e:
            stream_log(session_dir, f"Nuclei 오류: {str(e)}", "Nuclei")
        finally:
            stream_custom(session_dir, {"type": "scan_complete", "data": findings})
            await mark_inactive(session_dir)
            _nuclei_running_sessions.discard(session_dir)

    return make_tool_stream(session_dir, log_file, run_task, "scan_complete")


@router.post("/api/nuclei/stop")
async def nuclei_stop(req: NucleiStopRequest):
    """실행 중인 Nuclei 스캔 중단"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    await mark_cancelled(session_dir)
    _nuclei_running_sessions.discard(session_dir)
    stop_all_processes()
    stream_log(session_dir, "Nuclei 스캔 중단 요청이 전달되었습니다.", "Nuclei")
    return {"status": "success", "message": "Nuclei 스캔 중단 요청이 전달되었습니다."}
