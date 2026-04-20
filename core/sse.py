import os
import asyncio
from typing import AsyncGenerator

from core.cancellation import is_active


def count_log_lines(log_file: str) -> int:
    """로그 파일의 현재 줄 수를 반환합니다."""
    if not os.path.exists(log_file):
        return 0
    with open(log_file, "r", encoding="utf-8") as f:
        return sum(1 for _ in f)


async def stream_log_file(
    session_dir: str,
    log_file: str,
    start_line: int = 0,
    timeout_seconds: int = 3600,
    complete_marker: str = "scan_complete",
) -> AsyncGenerator[str, None]:
    """
    JSONL 로그 파일을 폴링하며 새 줄을 SSE 형식으로 yield한다.
    바이트 포지션을 추적하므로 파일 전체를 매번 읽지 않는다.
    """
    # 이미 전송한 라인들의 끝 바이트 위치를 구한다
    file_pos = 0
    if start_line > 0 and os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            for _ in range(start_line):
                if not f.readline():
                    break
            file_pos = f.tell()

    max_ticks = timeout_seconds * 2  # 0.5초 간격

    for _ in range(max_ticks):
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                f.seek(file_pos)
                chunk = f.read()
                new_pos = f.tell()

            if chunk:
                file_pos = new_pos
                for line in chunk.splitlines():
                    line = line.strip()
                    if line:
                        yield f"data: {line}\n\n"
                        if complete_marker in line:
                            return

        if not is_active(session_dir):
            await asyncio.sleep(2)
            # 비활성 상태에서 새 데이터도 없으면 종료
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8") as f:
                    f.seek(file_pos)
                    if not f.read().strip():
                        return
            else:
                return

        await asyncio.sleep(0.5)
