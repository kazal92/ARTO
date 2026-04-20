import os
import json
import asyncio

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.session import find_session_dir
from core.logging import stream_log, stream_custom
from core.cancellation import is_cancelled, mark_cancelled, mark_active, mark_inactive, is_active
from core.sse import stream_log_file
from agents.pentest_agent import run_pentest_agent, inject_user_message

router = APIRouter()


class AgentRunRequest(BaseModel):
    session_id: str
    target: str
    ai_config: dict = {}
    custom_headers: dict = {}


class AgentStopRequest(BaseModel):
    session_id: str


class AgentMessageRequest(BaseModel):
    session_id: str
    message: str


@router.post("/api/agent/run")
async def agent_run(req: AgentRunRequest):
    """에이전트 점검 시작 — SSE 스트리밍"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    # 이미 실행 중이면 기존 스트림에 재연결
    log_file = os.path.join(session_dir, "scan_log.jsonl")

    async def event_generator():
        sent_lines = 0

        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        yield f"data: {line}\n\n"
                        sent_lines += 1

        yield f'data: {{"type": "agent_start", "session_id": "{req.session_id}"}}\n\n'

        if not is_active(session_dir):
            await mark_active(session_dir)

            async def run_task():
                try:
                    await run_pentest_agent(
                        target=req.target,
                        session_dir=session_dir,
                        ai_config=req.ai_config,
                        custom_headers=req.custom_headers,
                    )
                except Exception as e:
                    stream_log(session_dir, f"에이전트 오류: {str(e)}", "Agent")
                    stream_custom(session_dir, {"type": "scan_complete", "data": []})
                finally:
                    await mark_inactive(session_dir)

            asyncio.create_task(run_task())

        async for event in stream_log_file(session_dir, log_file, start_line=sent_lines):
            yield event

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/api/agent/stop")
async def agent_stop(req: AgentStopRequest):
    """실행 중인 에이전트 중단"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    await mark_cancelled(session_dir)
    stream_log(session_dir, "사용자가 에이전트를 중단했습니다.", "Agent")
    return {"status": "success", "message": "에이전트 중단 요청이 전송되었습니다."}


@router.post("/api/agent/message")
async def agent_message(req: AgentMessageRequest):
    """진행 중인 에이전트에 사용자 메시지 주입"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    if not is_active(session_dir):
        return {"status": "error", "message": "현재 실행 중인 에이전트가 없습니다."}

    inject_user_message(session_dir, req.message)
    return {"status": "success", "message": "메시지가 에이전트에 전달되었습니다."}
