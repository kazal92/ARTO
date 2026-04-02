import json
from typing import Optional
from core.session import save_log


def stream_log(session_dir: str, message: str, agent_type: str = "system", progress: Optional[int] = None) -> str:
    log_data = {"type": "log", "agent": agent_type, "message": message}
    if progress is not None:
        log_data["progress"] = progress
    log_json = json.dumps(log_data)
    save_log(session_dir, log_json)
    return log_json


def stream_custom(session_dir: str, data: dict) -> str:
    log_json = json.dumps(data)
    save_log(session_dir, log_json)
    return log_json


def stream_chunk(session_dir: str, content: str, progress: Optional[int] = None) -> str:
    chunk_data = {"type": "chunk", "content": content}
    if progress is not None:
        chunk_data["progress"] = progress
    return stream_custom(session_dir, chunk_data)
