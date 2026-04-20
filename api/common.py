import asyncio
import os

from fastapi.responses import StreamingResponse

from core.cancellation import mark_active
from core.sse import stream_log_file, count_log_lines


def make_tool_stream(
    session_dir: str,
    log_file: str,
    run_task_fn,
    complete_marker: str,
) -> StreamingResponse:
    """도구 실행 + SSE 스트리밍 응답을 생성하는 공통 헬퍼.

    run_task_fn은 인수 없는 async 함수여야 하며,
    finally 블록에서 complete_marker 이벤트를 직접 기록해야 한다.
    """
    initial_lines = count_log_lines(log_file)

    async def event_generator():
        await mark_active(session_dir)
        asyncio.create_task(run_task_fn())
        async for event in stream_log_file(
            session_dir, log_file,
            start_line=initial_lines,
            complete_marker=complete_marker,
        ):
            yield event

    return StreamingResponse(event_generator(), media_type="text/event-stream")
