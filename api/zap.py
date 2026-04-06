import os
import json

from fastapi import APIRouter, Request
from pydantic import BaseModel

from zap_client import ZAPClient
from core.session import find_session_dir
from core.logging import stream_log

router = APIRouter()


class ProxyRequest(BaseModel):
    proxy_host: str
    proxy_port: int
    enabled: bool


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

                for filename in ["ai_input_full_requests.json", "scan_log.jsonl"]:
                    path = os.path.join(session_dir, filename)
                    if os.path.exists(path):
                        os.remove(path)

                for fname in os.listdir(session_dir):
                    if fname.startswith("ai_input_batch_") and fname.endswith(".json"):
                        os.remove(os.path.join(session_dir, fname))

        return {"status": "success", "message": "ZAP history / Site tree 초기화 완료."}
    except Exception as e:
        return {"status": "error", "message": str(e)}
