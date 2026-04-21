import json
from typing import Optional, Literal
from core.session import save_log

# ── 로그 포맷 표준 ──
# [HH:MM:SS] [SOURCE] MESSAGE
# SOURCE: system, recon, zap, ffuf, ai, triage, specialist, nuclei, nmap, command, error
# 규칙:
#   - 간결함: 불필요한 세부사항 제거
#   - 구조화: [태그] 형태로 메타 정보 표현
#   - 일관성: 같은 의미는 같은 표현 사용
#   - 전문성: 비공식적 표현, 이모지 금지

def stream_log(
    session_dir: str,
    message: str,
    agent_type: str = "system",
    progress: Optional[int] = None,
    level: Optional[Literal["info", "warn", "error"]] = None
) -> str:
    """
    로그 스트림에 메시지 기록.

    Args:
        session_dir: 세션 디렉토리
        message: 로그 메시지 (간결하고 구조화된 형태)
        agent_type: 소스 (system/recon/ai/triage/specialist/nuclei/nmap/command/error)
        progress: 진행률 (0-100)
        level: 심각도 (info/warn/error) - UI에서 색상 코딩 시 사용
    """
    log_data = {"type": "log", "agent": agent_type, "message": message}
    if progress is not None:
        log_data["progress"] = max(0, min(100, progress))  # 0-100 범위 강제
    if level:
        log_data["level"] = level
    log_json = json.dumps(log_data)
    save_log(session_dir, log_json)
    return log_json


def stream_custom(session_dir: str, data: dict) -> str:
    """커스텀 데이터 스트림."""
    log_json = json.dumps(data)
    save_log(session_dir, log_json)
    return log_json


def stream_chunk(session_dir: str, content: str, progress: Optional[int] = None) -> str:
    """청크 데이터 스트림 (대용량 출력용)."""
    chunk_data = {"type": "chunk", "content": content}
    if progress is not None:
        chunk_data["progress"] = max(0, min(100, progress))
    return stream_custom(session_dir, chunk_data)
