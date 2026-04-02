import os
import re
import json
import datetime
from typing import Optional

ROOT_SCAN_DIR = os.path.abspath("results/scan")
ROOT_PRECHECK_DIR = os.path.abspath("results/precheck")
for _d in [ROOT_SCAN_DIR, ROOT_PRECHECK_DIR]:
    if not os.path.exists(_d):
        os.makedirs(_d)


def get_session_dir(project_name: str, p_type: str = "scan") -> str:
    safe_name = re.sub(r'[^a-zA-Z0-9_\-가-힣]', '_', project_name) if project_name else "unnamed"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = ROOT_SCAN_DIR if p_type == "scan" else ROOT_PRECHECK_DIR
    session_dir = os.path.join(base_dir, f"{safe_name}_{timestamp}")
    if not os.path.exists(session_dir):
        os.makedirs(session_dir)
    return session_dir


def find_session_dir(session_id: str) -> Optional[str]:
    p1 = os.path.join(ROOT_SCAN_DIR, session_id)
    if os.path.exists(p1):
        return p1
    p2 = os.path.join(ROOT_PRECHECK_DIR, session_id)
    if os.path.exists(p2):
        return p2
    legacy = os.path.join("results", session_id)
    if os.path.exists(legacy) and os.path.isdir(legacy) and session_id not in ["scan", "precheck"]:
        return legacy
    return None


def save_log(session_dir: str, log_data: str) -> None:
    try:
        log_file = os.path.join(session_dir, "scan_log.jsonl")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_data + "\n")
    except Exception:
        pass


def save_tool_result(session_dir: str, tool_name: str, data, indent: Optional[int] = 2) -> Optional[str]:
    try:
        save_path = os.path.join(session_dir, f"{tool_name}.json")
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return save_path
    except Exception:
        return None
