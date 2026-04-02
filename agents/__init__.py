# agents/__init__.py — 하위 호환성 re-export shim
# 기존 `from agents import ...` 코드가 모두 동작합니다.
from agents.recon import run_recon_agent
from agents.analysis import run_analysis_agent, analyze_selected_packets, _init_ai_client
from core.session import (
    ROOT_SCAN_DIR,
    ROOT_PRECHECK_DIR,
    get_session_dir,
    find_session_dir,
    save_tool_result,
    save_log,
)
from core.logging import stream_log, stream_custom, stream_chunk
from core.cancellation import (
    is_cancelled,
    mark_cancelled,
    mark_active,
    mark_inactive,
    is_active,
    _cancelled_sessions as SCAN_SESSIONS_CANCELLED,
)
