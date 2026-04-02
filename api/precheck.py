import json
import asyncio
import re
from typing import Optional, List

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, field_validator

from alive_checker import stream_alive_check, stream_google_dork
from core.session import find_session_dir, save_tool_result

router = APIRouter()

# 세션 상태 관리
ALIVE_CHECK_SESSION: dict = {"domains": [], "stop_event": None}
SHODAN_CHECK_SESSION: dict = {"domains": [], "stop_event": None}
DORK_CHECK_SESSION: dict = {"domains": [], "api_keys": [], "cx_id": "", "stop_event": None}


class AliveCheckRequest(BaseModel):
    domains: list
    mode: str = "alive"
    session_id: Optional[str] = None

    @field_validator("domains")
    @classmethod
    def domains_not_empty(cls, v):
        if not v:
            raise ValueError("domains 목록은 비어 있을 수 없습니다.")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v):
        if v not in ("alive", "shodan"):
            raise ValueError("mode는 'alive' 또는 'shodan'이어야 합니다.")
        return v


class DorkCheckRequest(BaseModel):
    domains: list
    api_keys: List[str] = []
    cx_id: str = ""
    session_id: Optional[str] = None
    dork_categories: Optional[dict] = None


async def _generic_precheck_stream(session_data: dict, stream_fn, extract_result_fn, result_key: str):
    """Alive / Shodan / Dork SSE 스트림 공통 처리기"""
    stop_event = session_data.get("stop_event")
    session_id = session_data.get("session_id")

    if not stop_event:
        yield "data: " + json.dumps({"status": "error", "message": "No session"}) + "\n\n"
        return

    accumulated = []
    try:
        async for data in stream_fn():
            yield data
            try:
                clean = data.strip()
                if clean.startswith("data:"):
                    content = clean[5:].strip()
                    parsed = json.loads(content)
                    if parsed.get("status") == "progress":
                        items = extract_result_fn(parsed)
                        if items:
                            if isinstance(items, list):
                                accumulated.extend(items)
                            else:
                                accumulated.append(items)
            except (json.JSONDecodeError, KeyError, AttributeError):
                pass
    finally:
        if session_id and accumulated:
            session_dir = find_session_dir(session_id)
            if session_dir:
                save_tool_result(session_dir, result_key, accumulated)


# ─── Alive Check ─────────────────────────────────────────────

@router.post("/api/alive/start")
async def start_alive_check(req: AliveCheckRequest):
    ALIVE_CHECK_SESSION["domains"] = req.domains
    ALIVE_CHECK_SESSION["mode"] = "alive"
    ALIVE_CHECK_SESSION["session_id"] = req.session_id
    ALIVE_CHECK_SESSION["stop_event"] = asyncio.Event()
    return {"status": "success"}


@router.get("/api/alive/stream")
async def alive_check_stream():
    domains = ALIVE_CHECK_SESSION.get("domains", [])
    stop_event = ALIVE_CHECK_SESSION.get("stop_event")
    mode = ALIVE_CHECK_SESSION.get("mode", "alive")

    def stream_fn():
        return stream_alive_check(domains, stop_event, mode)

    return StreamingResponse(
        _generic_precheck_stream(
            ALIVE_CHECK_SESSION,
            stream_fn,
            lambda p: [p["result"]],
            "alive_check_results"
        ),
        media_type="text/event-stream"
    )


@router.post("/api/alive/stop")
async def stop_alive_check():
    if ALIVE_CHECK_SESSION.get("stop_event"):
        ALIVE_CHECK_SESSION["stop_event"].set()
    return {"status": "success"}


# ─── Shodan Check ────────────────────────────────────────────

@router.post("/api/shodan/start")
async def start_shodan_check(req: AliveCheckRequest):
    SHODAN_CHECK_SESSION["domains"] = req.domains
    SHODAN_CHECK_SESSION["mode"] = "shodan"
    SHODAN_CHECK_SESSION["session_id"] = req.session_id
    SHODAN_CHECK_SESSION["stop_event"] = asyncio.Event()
    return {"status": "success"}


@router.get("/api/shodan/stream")
async def shodan_check_stream():
    domains = SHODAN_CHECK_SESSION.get("domains", [])
    stop_event = SHODAN_CHECK_SESSION.get("stop_event")
    mode = SHODAN_CHECK_SESSION.get("mode", "shodan")

    def stream_fn():
        return stream_alive_check(domains, stop_event, mode)

    return StreamingResponse(
        _generic_precheck_stream(
            SHODAN_CHECK_SESSION,
            stream_fn,
            lambda p: [p["result"]],
            "shodan_results"
        ),
        media_type="text/event-stream"
    )


@router.post("/api/shodan/stop")
async def stop_shodan_check():
    if SHODAN_CHECK_SESSION.get("stop_event"):
        SHODAN_CHECK_SESSION["stop_event"].set()
    return {"status": "success"}


# ─── Google Dork ─────────────────────────────────────────────

@router.post("/api/dork/start")
async def start_dork_check(req: DorkCheckRequest):
    DORK_CHECK_SESSION["domains"] = req.domains
    DORK_CHECK_SESSION["api_keys"] = req.api_keys
    DORK_CHECK_SESSION["cx_id"] = req.cx_id
    DORK_CHECK_SESSION["session_id"] = req.session_id
    DORK_CHECK_SESSION["dork_categories"] = req.dork_categories
    DORK_CHECK_SESSION["stop_event"] = asyncio.Event()
    return {"status": "success"}


@router.get("/api/dork/stream")
async def dork_check_stream():
    domains = DORK_CHECK_SESSION.get("domains", [])
    api_keys = DORK_CHECK_SESSION.get("api_keys", [])
    cx_id = DORK_CHECK_SESSION.get("cx_id", "")
    stop_event = DORK_CHECK_SESSION.get("stop_event")
    dork_categories = DORK_CHECK_SESSION.get("dork_categories")

    if not stop_event:
        async def err_gen():
            yield "data: " + json.dumps({"status": "error", "message": "No session"}) + "\n\n"
        return StreamingResponse(err_gen(), media_type="text/event-stream")

    def stream_fn():
        return stream_google_dork(domains, api_keys, cx_id, stop_event, dork_categories)

    return StreamingResponse(
        _generic_precheck_stream(
            DORK_CHECK_SESSION,
            stream_fn,
            lambda p: p.get("results", []),
            "google_dork_results"
        ),
        media_type="text/event-stream"
    )


@router.post("/api/dork/stop")
async def stop_dork_check():
    if DORK_CHECK_SESSION.get("stop_event"):
        DORK_CHECK_SESSION["stop_event"].set()
    return {"status": "success"}
