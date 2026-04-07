"""
api/terminal.py - 웹 터미널 WebSocket 엔드포인트
단일 bash 세션 — 여러 WebSocket이 같은 PTY를 공유
"""

import os
import pty
import asyncio
import struct
import fcntl
import termios
from typing import Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()

# ── 싱글톤 PTY 세션 ───────────────────────────────────────────────────────────

_master_fd: int = -1
_proc: asyncio.subprocess.Process = None
_clients: Set[WebSocket] = set()
_broadcast_task: asyncio.Task = None
_lock = asyncio.Lock()


async def _ensure_session():
    """PTY + bash 세션이 없으면 새로 생성"""
    global _master_fd, _proc, _broadcast_task

    if _proc is not None and _proc.returncode is None:
        return  # 이미 살아있음

    master_fd, slave_fd = pty.openpty()

    # PTY 초기 사이즈 설정 (xterm.js가 접속 후 실제 크기로 업데이트함)
    _resize_pty(master_fd, 40, 150)

    shell = os.environ.get("SHELL", "/bin/bash")
    proc = await asyncio.create_subprocess_exec(
        shell,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        start_new_session=True,
        env={**os.environ, "TERM": "xterm-256color"},
    )
    os.close(slave_fd)

    fl = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    _master_fd = master_fd
    _proc = proc

    # PTY 출력을 모든 클라이언트에 브로드캐스트하는 태스크
    if _broadcast_task is None or _broadcast_task.done():
        _broadcast_task = asyncio.create_task(_broadcast_loop())


async def _broadcast_loop():
    """PTY 출력 → 연결된 모든 WebSocket 브로드캐스트"""
    loop = asyncio.get_event_loop()
    while True:
        if _master_fd < 0:
            await asyncio.sleep(0.05)
            continue
        try:
            data = await loop.run_in_executor(None, lambda: _read_fd(_master_fd))
            if data and _clients:
                dead = set()
                for ws in list(_clients):
                    try:
                        await ws.send_bytes(data)
                    except Exception:
                        dead.add(ws)
                _clients.difference_update(dead)
            else:
                await asyncio.sleep(0.01)
        except OSError:
            await asyncio.sleep(0.1)
        except Exception:
            await asyncio.sleep(0.05)


def _read_fd(fd: int) -> bytes:
    try:
        return os.read(fd, 4096)
    except BlockingIOError:
        return b""
    except OSError:
        raise


def _resize_pty(fd: int, rows: int, cols: int):
    try:
        winsize = struct.pack("HHHH", rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except Exception:
        pass


# ── WebSocket 엔드포인트 ──────────────────────────────────────────────────────

@router.post("/api/terminal/kill")
async def terminal_kill():
    """현재 bash 세션 강제 종료 — 다음 접속 시 새 세션 시작"""
    global _master_fd, _proc
    if _proc:
        try:
            _proc.terminate()
        except Exception:
            pass
        _proc = None
    if _master_fd >= 0:
        try:
            os.close(_master_fd)
        except Exception:
            pass
        _master_fd = -1
    # 연결된 클라이언트에 종료 알림
    for ws in list(_clients):
        try:
            await ws.send_bytes("\r\n\x1b[1;33m[session killed - reconnecting...]\x1b[0m\r\n".encode())
        except Exception:
            pass
    return {"status": "ok"}



@router.websocket("/api/terminal")
async def terminal_ws(websocket: WebSocket):
    await websocket.accept()

    async with _lock:
        await _ensure_session()
        _clients.add(websocket)

    try:
        while True:
            msg = await websocket.receive()

            if "bytes" in msg and msg["bytes"]:
                data = msg["bytes"]
                # resize: \x01 + rows(2) + cols(2)
                if data[0:1] == b'\x01' and len(data) == 5:
                    rows, cols = struct.unpack("!HH", data[1:5])  # 빅엔디안
                    _resize_pty(_master_fd, rows, cols)
                else:
                    if _master_fd >= 0:
                        os.write(_master_fd, data)

            elif "text" in msg and msg["text"]:
                if _master_fd >= 0:
                    os.write(_master_fd, msg["text"].encode())

    except (WebSocketDisconnect, Exception):
        pass
    finally:
        _clients.discard(websocket)
