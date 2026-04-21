import os
import asyncio

from fastapi import APIRouter
from pydantic import BaseModel, field_validator

from tools import run_nmap, stop_all_processes
from core.session import find_session_dir, save_tool_result
from core.logging import stream_log, stream_custom
from core.cancellation import mark_inactive, mark_cancelled, is_cancelled
from api.common import make_tool_stream

router = APIRouter()

_nmap_running_sessions: set = set()


class NmapRequest(BaseModel):
    session_id: str
    target_url: str
    nmap_options: str = "-sS -sV"

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v):
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url은 http:// 또는 https://로 시작해야 합니다.")
        return v


class NmapStopRequest(BaseModel):
    session_id: str


@router.post("/api/nmap/run")
async def nmap_run(req: NmapRequest):
    """Nmap 스캔 실행 — SSE 스트리밍"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    if session_dir in _nmap_running_sessions:
        return {"status": "error", "message": "이미 실행 중인 Nmap 세션입니다."}
    _nmap_running_sessions.add(session_dir)

    log_file = os.path.join(session_dir, "scan_log.jsonl")

    async def run_task():
        findings = []
        try:
            async for update in run_nmap(req.target_url, session_dir, nmap_options=req.nmap_options):
                if is_cancelled(session_dir):
                    stream_log(session_dir, "Nmap 스캔이 사용자에 의해 중단되었습니다.", "Nmap")
                    break

                utype = update.get("type")
                if utype == "progress":
                    # 실시간 로그 콘솔에서 Nmap 출력 제거 (사용자 요청)
                    # 대신 진행률 업데이트를 위해 custom stream 사용 (appendLog 호출 방지)
                    stream_custom(session_dir, {"type": "nmap_progress", "progress": update.get("progress")})
                elif utype == "command":
                    stream_log(session_dir, update["cmd"], "Command")
                elif utype == "finding":
                    finding = update["data"]
                    findings.append(finding)
                    stream_custom(session_dir, {"type": "nmap_finding", "data": finding})

            save_tool_result(session_dir, "nmap_findings", findings)

            tool_dir = os.path.join(session_dir, "nmap")
            os.makedirs(tool_dir, exist_ok=True)
            report_path = os.path.join(tool_dir, "report.txt")
            with open(report_path, "w", encoding="utf-8") as rf:
                rf.write(f"Nmap Scan Report — {req.target_url}\n")
                rf.write(f"Options: {req.nmap_options}\n")
                rf.write("=" * 60 + "\n")
                if findings:
                    rf.write(f"{'PORT':<10} {'PROTO':<6} {'SERVICE':<16} {'PRODUCT/VERSION'}\n")
                    rf.write("-" * 60 + "\n")
                    for f in findings:
                        ver = " ".join(filter(None, [f.get("product", ""), f.get("version", ""), f.get("extrainfo", "")]))
                        rf.write(f"{str(f['port']):<10} {f.get('protocol', ''):<6} {f.get('service', ''):<16} {ver}\n")
                else:
                    rf.write("열린 포트 없음\n")

            # 스캔 완료 메시지도 로그 콘솔에는 남기지 않음
            # if findings:
            #     stream_log(session_dir, f"Nmap 결과 {len(findings)}개 포트 저장 완료 → nmap/report.txt", "Nmap", 100)
            # else:
            #     stream_log(session_dir, "Nmap 스캔 완료: 열린 포트 없음", "Nmap", 100)

        except Exception as e:
            stream_log(session_dir, f"Nmap 오류: {str(e)}", "Nmap")
        finally:
            stream_custom(session_dir, {"type": "nmap_complete", "data": findings})
            await mark_inactive(session_dir)
            _nmap_running_sessions.discard(session_dir)

    return make_tool_stream(session_dir, log_file, run_task, "nmap_complete")


@router.post("/api/nmap/stop")
async def nmap_stop(req: NmapStopRequest):
    """실행 중인 Nmap 스캔 중단"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    await mark_cancelled(session_dir)
    _nmap_running_sessions.discard(session_dir)
    stop_all_processes()
    stream_log(session_dir, "Nmap 스캔 중단 요청이 전달되었습니다.", "Nmap")
    return {"status": "success", "message": "Nmap 스캔 중단 요청이 전달되었습니다."}
