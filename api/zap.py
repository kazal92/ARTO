import os
import json
from datetime import datetime

from fastapi import APIRouter, Request
from pydantic import BaseModel, field_validator

from zap_client import ZAPClient
from agents.analysis import analyze_selected_packets
from core.session import get_session_dir, find_session_dir, save_tool_result
from core.logging import stream_log

router = APIRouter()


class ProxyRequest(BaseModel):
    proxy_host: str
    proxy_port: int
    enabled: bool


class PacketAnalysisRequest(BaseModel):
    packets: list
    ai_config: dict = {}
    session_dir: str = ""
    project_name: str = ""

    @field_validator("packets")
    @classmethod
    def packets_not_empty(cls, v):
        if not v:
            raise ValueError("packets 목록은 비어 있을 수 없습니다.")
        return v


@router.post("/api/proxy")
async def set_proxy(req: ProxyRequest):
    """ZAP 상위 프록시 설정 API"""
    zap = ZAPClient()
    try:
        if req.enabled:
            await zap.set_upstream_proxy(req.proxy_host, req.proxy_port)
            return {"status": "success", "message": f"Upstream proxy set to {req.proxy_host}:{req.proxy_port}"}
        else:
            await zap.disable_upstream_proxy()
            return {"status": "success", "message": "Upstream proxy disabled"}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.get("/api/zap/history")
async def get_zap_history():
    """ZAP 전체 히스토리 메시지 목록 반환"""
    zap = ZAPClient()
    try:
        messages = await zap.get_all_messages()
        return {"status": "success", "messages": messages}
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/zap/analyze")
async def analyze_packets(req: PacketAnalysisRequest):
    """선택한 ZAP 히스토리 패킷 AI 심층 분석 요청"""
    try:
        target_ep_url = req.packets[0].get("url", "http://ai_analysis") if req.packets else "http://ai_analysis"
        new_session_dir = get_session_dir(target_ep_url)

        if req.project_name:
            with open(os.path.join(new_session_dir, "project_info.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "project_name": req.project_name,
                    "target": target_ep_url,
                    "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                }, f, ensure_ascii=False, indent=4)

        findings = await analyze_selected_packets(req.packets, req.ai_config, new_session_dir)

        stream_log(new_session_dir, f"AI 분석 결과 도출 완료. 탐지 건수: {len(findings)}", "AI", 100)
        stream_log(new_session_dir, "scan_complete", "System", 100)

        return {
            "status": "success",
            "findings": findings,
            "session_id": os.path.basename(new_session_dir)
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


@router.post("/api/zap/clear")
async def clear_zap(request: Request):
    """ZAP 히스토리 및 사이트 트리 초기화 API"""
    zap = ZAPClient()
    try:
        await zap.clear_zap_history()

        body = {}
        try:
            body = await request.json()
        except Exception:
            pass
        session_id = body.get("session_id") or ""
        if session_id:
            session_dir = find_session_dir(session_id)
            if session_dir:
                recon_map_path = os.path.join(session_dir, "recon_map.json")
                if os.path.exists(recon_map_path):
                    with open(recon_map_path, "w", encoding="utf-8") as f:
                        json.dump({"target": "", "endpoints": []}, f)

        return {"status": "success", "message": "ZAP history / Site tree 초기화 완료."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
