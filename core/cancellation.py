import asyncio
from typing import Optional, Set

_cancelled_sessions: Set[str] = set()
_active_sessions: Set[str] = set()
_lock: Optional[asyncio.Lock] = None


def _get_lock() -> asyncio.Lock:
    global _lock
    if _lock is None:
        _lock = asyncio.Lock()
    return _lock


async def mark_cancelled(session_dir: str) -> None:
    async with _get_lock():
        _cancelled_sessions.add(session_dir)


def is_cancelled(session_dir: str) -> bool:
    return session_dir in _cancelled_sessions


async def mark_active(session_dir: str) -> None:
    async with _get_lock():
        _active_sessions.add(session_dir)


async def mark_inactive(session_dir: str) -> None:
    async with _get_lock():
        _active_sessions.discard(session_dir)


def is_active(session_dir: str) -> bool:
    return session_dir in _active_sessions
