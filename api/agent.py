

import os
import json
import asyncio

from fastapi import APIRouter
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from core.session import find_session_dir
from core.logging import stream_log, stream_custom
from core.cancellation import is_cancelled, mark_cancelled, mark_active, mark_inactive, is_active
from agents.pentest_agent import run_pentest_agent, inject_user_message
from agents.playwright_agent import run_playwright_agent

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

        # 기존 로그 먼저 전송
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        yield f"data: {line}\n\n"
                        sent_lines += 1

        yield f'data: {{"type": "agent_start", "session_id": "{req.session_id}"}}\n\n'

        # 에이전트 백그라운드 실행 (중복 방지)
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

        # 로그 파일 폴링 → SSE 전송
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


# ── Playwright 에이전트 ───────────────────────────────────────────────────────

PW_CANCEL_FLAG = {}  # session_id → True


@router.post("/api/playwright/run")
async def playwright_run(req: AgentRunRequest):
    """Playwright 에이전트 시작 — SSE 스트리밍 (전용 로그 파일 사용)"""
    session_dir = find_session_dir(req.session_id)
    if not session_dir:
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    # 전용 로그 파일 (scan_log.jsonl 과 분리)
    log_file = os.path.join(session_dir, "playwright_log.jsonl")

    # 이전 로그 초기화
    if os.path.exists(log_file):
        os.remove(log_file)

    PW_CANCEL_FLAG[req.session_id] = False

    async def event_generator():
        sent_lines = 0

        yield f'data: {{"type": "agent_start", "session_id": "{req.session_id}"}}\n\n'

        async def run_task():
            try:
                await run_playwright_agent(
                    target=req.target,
                    session_dir=session_dir,
                    ai_config=req.ai_config,
                    custom_headers=req.custom_headers,
                    log_file=log_file,
                    cancel_flag=PW_CANCEL_FLAG,
                    session_id=req.session_id,
                )
            except Exception as e:
                import traceback, json as _j
                err = traceback.format_exc()
                with open(log_file, "a") as f:
                    f.write(_j.dumps({"type": "log", "message": f"오류: {str(e)}\n{err}"}) + "\n")
                    f.write(_j.dumps({"type": "scan_complete", "data": []}) + "\n")

        asyncio.create_task(run_task())

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

            if PW_CANCEL_FLAG.get(req.session_id):
                break

            await asyncio.sleep(0.5)
            timeout_count += 1

    return StreamingResponse(event_generator(), media_type="text/event-stream")


@router.post("/api/playwright/stop")
async def playwright_stop(req: AgentStopRequest):
    """Playwright 에이전트 중단"""
    PW_CANCEL_FLAG[req.session_id] = True
    return {"status": "success"}
