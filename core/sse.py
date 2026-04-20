import os
import asyncio
from typing import AsyncGenerator

from core.cancellation import is_active


async def stream_log_file(
    session_dir: str,
    log_file: str,
    start_line: int = 0,
    timeout_seconds: int = 3600,
    complete_marker: str = "scan_complete",
) -> AsyncGenerator[str, None]:
    """
    JSONL 로그 파일을 폴링하며 새 줄을 SSE 형식으로 yield한다.
    scan/agent/ai 스트리밍 엔드포인트에서 공통으로 사용한다.
    """
    sent_lines = start_line
    max_ticks = timeout_seconds * 2  # 0.5초 간격

    for _ in range(max_ticks):
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                all_lines = f.readlines()

            new_lines = all_lines[sent_lines:]
            for line in new_lines:
                line = line.strip()
                if line:
                    yield f"data: {line}\n\n"
                    sent_lines += 1
                    if complete_marker in line:
                        return

        if not is_active(session_dir):
            await asyncio.sleep(2)
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8") as f:
                    if len(f.readlines()) <= sent_lines:
                        return

        await asyncio.sleep(0.5)
