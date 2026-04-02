import os

from fastapi import APIRouter

from core.session import find_session_dir, save_tool_result

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


@router.post("/api/session/{session_id}/manual_targets")
async def save_manual_targets(session_id: str, body: dict):
    """수동 AI 타겟 지정 저장"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    save_tool_result(session_dir, "manual_targets", body.get("targets", []))
    return {"status": "ok"}
