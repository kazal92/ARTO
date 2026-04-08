import os
import json
import shutil

from fastapi import APIRouter
from pydantic import BaseModel, field_validator

from core.session import ROOT_SCAN_DIR, ROOT_PRECHECK_DIR, find_session_dir, save_tool_result

router = APIRouter()


class RenameRequest(BaseModel):
    project_name: str

    @field_validator("project_name")
    @classmethod
    def not_empty(cls, v):
        if not v.strip():
            raise ValueError("project_name은 비어 있을 수 없습니다.")
        return v.strip()


class UpdateStatusRequest(BaseModel):
    status: str


class SaveProjectInfoRequest(BaseModel):
    project_name: str = ""
    target: str = ""
    headers: dict = {}
    ai_config: dict = {}
    ffuf_options: str = ""
    ffuf_wordlist: str = ""
    enable_zap_spider: bool = True
    enable_ffuf: bool = True
    enable_deep_recon: bool = True


class SaveFindingsRequest(BaseModel):
    session_id: str
    findings: list


@router.post("/api/findings/save")
async def save_findings(req: SaveFindingsRequest):
    """클라이언트에서 수정된 취약점 리스트를 서버 파일에 동기화합니다."""
    session_dir = find_session_dir(req.session_id)
    if not session_dir or not os.path.exists(session_dir):
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}

    file_path = os.path.join(session_dir, "ai_findings.json")
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(req.findings, f, indent=2, ensure_ascii=False)
        return {"status": "success", "message": "취약점 목록이 성공적으로 저장되었습니다."}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/api/wordlists")
async def get_wordlists():
    """wordlist 폴더 내 파일 목록 반환"""
    wordlist_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "wordlist")
    if not os.path.exists(wordlist_dir):
        return {"status": "ok", "files": []}
    files = sorted([f for f in os.listdir(wordlist_dir) if os.path.isfile(os.path.join(wordlist_dir, f))])
    return {"status": "ok", "files": files}


@router.get("/api/history/list")
async def get_history_list():
    """results/scan 및 results/precheck 내 세션 목록 반환"""
    scan_history = []
    precheck_history = []

    if os.path.exists(ROOT_SCAN_DIR):
        scan_history = [e for e in os.listdir(ROOT_SCAN_DIR) if os.path.isdir(os.path.join(ROOT_SCAN_DIR, e))]
    if os.path.exists(ROOT_PRECHECK_DIR):
        precheck_history = [e for e in os.listdir(ROOT_PRECHECK_DIR) if os.path.isdir(os.path.join(ROOT_PRECHECK_DIR, e))]

    scan_history.sort(reverse=True)
    precheck_history.sort(reverse=True)

    return {"status": "success", "sessions": scan_history, "precheck_sessions": precheck_history}


@router.get("/api/history/{session_id}/report")
async def get_history_report(session_id: str):
    """특정 세션의 strategy_report.md 내용을 반환"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    report_path = os.path.join(session_dir, "strategy_report.md")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
            return {"status": "success", "content": f.read()}
    return {"status": "error", "message": "리포트를 찾을 수 없습니다."}


@router.get("/api/history/{session_id}/agent_log")
async def get_history_agent_log(session_id: str):
    """특정 세션의 agent_log.md 내용을 반환"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    report_path = os.path.join(session_dir, "agent_log.md")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
            return {"status": "success", "content": f.read()}
    return {"status": "error", "message": "에이전트 로그를 찾을 수 없습니다."}


@router.get("/api/history/{session_id}/raw/{tool_name}")
async def get_history_raw_logs(session_id: str, tool_name: str):
    """특정 세션 내 개별 툴의 raw_output.txt 내용을 반환"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    # ffuf만 지원 (katana는 제거됨)
    allowed = {"ffuf"}
    if tool_name not in allowed:
        return {"status": "error", "message": f"지원하지 않는 툴: {tool_name}"}
    log_file = os.path.join(session_dir, tool_name, "raw_output.txt")
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            return {"status": "success", "content": f.read()}
    return {"status": "error", "message": "파일을 찾을 수 없습니다."}


@router.get("/api/history/{session_id}/json/{result_name}")
async def get_history_json_logs(session_id: str, result_name: str):
    """특정 세션 내 결과 JSON 데이터 반환"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    log_file = os.path.join(session_dir, f"{result_name}.json")
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                return {"status": "success", "content": json.dumps(data, indent=2, ensure_ascii=False)}
            except (json.JSONDecodeError, UnicodeDecodeError):
                return {"status": "error", "message": "JSON 파싱 에러"}
    return {"status": "error", "message": "데이터를 찾을 수 없습니다."}


@router.put("/api/history/{session_id}/project_info")
async def save_project_info(session_id: str, req: SaveProjectInfoRequest):
    """프로젝트 설정 저장 (project_info.json 전체 업데이트)"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    info_file = os.path.join(session_dir, "project_info.json")
    try:
        existing = {}
        if os.path.exists(info_file):
            with open(info_file, "r", encoding="utf-8") as f:
                existing = json.load(f)

        # 기존 필드 유지하면서 새 값으로 업데이트
        updated = {
            "project_name": req.project_name if req.project_name else existing.get("project_name", ""),
            "target": req.target if req.target else existing.get("target", ""),
            "project_type": existing.get("project_type", "scan"),  # 기존 type 유지
            "headers": req.headers if req.headers else existing.get("headers", {}),
            "ai_config": req.ai_config if req.ai_config else existing.get("ai_config", {}),
            "ffuf_options": req.ffuf_options if req.ffuf_options else existing.get("ffuf_options", ""),
            "ffuf_wordlist": req.ffuf_wordlist if req.ffuf_wordlist else existing.get("ffuf_wordlist", ""),
            "enable_zap_spider": req.enable_zap_spider,
            "enable_ffuf": req.enable_ffuf,
            "enable_deep_recon": req.enable_deep_recon,
        }

        with open(info_file, "w", encoding="utf-8") as f:
            json.dump(updated, f, ensure_ascii=False, indent=2)
        return {"status": "success", "message": "프로젝트 정보가 저장되었습니다."}
    except Exception as e:
        return {"status": "error", "message": f"저장 실패: {e}"}


@router.put("/api/history/{session_id}/rename")
async def rename_session_project(session_id: str, req: RenameRequest):
    """프로젝트 이름 변경 (project_info.json 업데이트)"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    info_file = os.path.join(session_dir, "project_info.json")
    if os.path.exists(info_file):
        try:
            with open(info_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["project_name"] = req.project_name
            with open(info_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return {"status": "success", "message": "프로젝트 이름 변경 완료"}
        except Exception as e:
            return {"status": "error", "message": f"이름 변경 실패: {e}"}
    return {"status": "error", "message": "프로젝트 정보가 존재하지 않습니다."}


@router.put("/api/history/{session_id}/status")
async def update_session_status(session_id: str, req: UpdateStatusRequest):
    """프로젝트 상태 변경 (project_info.json 업데이트)"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    info_file = os.path.join(session_dir, "project_info.json")
    if os.path.exists(info_file):
        try:
            with open(info_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["status"] = req.status
            with open(info_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return {"status": "success", "message": "프로젝트 상태 변경 완료"}
        except Exception as e:
            return {"status": "error", "message": f"상태 변경 실패: {e}"}
    return {"status": "error", "message": "프로젝트 정보가 존재하지 않습니다."}


@router.delete("/api/history/{session_id}")
async def delete_session_project(session_id: str):
    """프로젝트 전체 데이터 삭제"""
    session_path = find_session_dir(session_id)
    if session_path and os.path.exists(session_path):
        try:
            shutil.rmtree(session_path)
            return {"status": "success", "message": "프로젝트 삭제 완료"}
        except Exception as e:
            return {"status": "error", "message": f"삭제 실패: {e}"}
    return {"status": "error", "message": "프로젝트 폴더를 찾을 수 없습니다."}


@router.get("/api/history/{session_id}/files")
async def get_session_files(session_id: str):
    """특정 세션 디렉토리 내의 파일 목록 반환"""
    session_path = find_session_dir(session_id)
    if session_path and os.path.exists(session_path):
        files = os.listdir(session_path)
        return {"status": "success", "files": sorted(files)}
    return {"status": "error", "message": "세션 폴더를 찾을 수 없습니다."}


@router.get("/api/history/{session_id}/logs")
async def get_session_logs(session_id: str):
    """특정 세션의 전체 로그 반환"""
    session_dir = find_session_dir(session_id)
    if not session_dir:
        return {"status": "error", "message": "세션을 찾을 수 없습니다."}
    log_file = os.path.join(session_dir, "scan_log.jsonl")
    if os.path.exists(log_file):
        logs = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    logs.append(json.loads(line))
                except (json.JSONDecodeError, ValueError):
                    continue
        return {"status": "success", "logs": logs}
    return {"status": "error", "message": "로그 파일이 없습니다."}
