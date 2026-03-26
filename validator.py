import asyncio
import httpx
import re
import time
from typing import Dict, Any, Tuple
import urllib.parse
import uuid

# Global Client Settings
VERIFY_TIMEOUT = 10.0
HTTP_CLIENT_KWARGS = {
    "verify": False,
    "timeout": VERIFY_TIMEOUT,
    "follow_redirects": True
}

async def run_benign_probe(finding: Dict[str, Any]) -> str:
    """
    무해한 카나리아 문자열(Benign Canary String)을 타겟에 주입하여
    서버의 필터링 수준(WAF, HTML Entity Encoding 여부)만 텍스트로 추출합니다.
    절대 실제 공격 페이로드(<script>, SLEEP)를 전송하지 않습니다.
    """
    target_url = finding.get("target", "")
    
    if not target_url or not target_url.startswith("http"):
        return "진단 불가: 올바르지 않은 목표 URL입니다."

    # 무해한 특수문자 조합 카나리아 생성
    probe_id = str(uuid.uuid4())[:6]
    canary = f"arti_probe{probe_id}'\"<>"
    
    t_url = _inject_canary(target_url, canary)

    async with httpx.AsyncClient(**HTTP_CLIENT_KWARGS) as client:
        try:
            res = await client.get(t_url)
            body_text = res.text
            status = res.status_code
            
            # 서버가 카나리아를 어떻게 처리했는지 상태 분석
            context = f"[HTTP Status: {status}]\n"
            
            if canary in body_text:
                context += "-> 카나리아 문자열 반사됨 (HTML 인코딩/필터링 없음). XSS, Injection에 극히 취약할 가능성 높음.\n"
            elif f"arti_probe{probe_id}" in body_text:
                # 특수문자만 날아가거나 인코딩 된 경우
                if "&lt;" in body_text or "&quot;" in body_text or "&#39;" in body_text:
                    context += "-> 텍스트는 반사되었으나, 특수문자('<', '\"', ''')가 HTML Entity로 안전하게 인코딩됨. (XSS 방어력 높음)\n"
                else:
                    context += "-> 특수문자가 서버에서 완전히 삭제(필터링)됨. (Injection 방어력 높음)\n"
            else:
                context += "-> 카나리아 문자열 반사되지 않음. (입력값이 화면에 노출되지 않거나 다른 처리가 됨)\n"
                
            # Content-Type 체크 (JSON/XML 일 경우 XSS 발현 불가)
            ctype = res.headers.get("Content-Type", "").lower()
            context += f"-> Content-Type: {ctype}\n"
            if "application/json" in ctype:
                context += "-> 응답이 JSON임. DOM 기반 처리가 없으면 Reflected XSS로 동작 불가.\n"
                
            return context

        except Exception as e:
            return f"카나리아 탐침 실패 (네트워크/타임아웃 에러): {str(e)}"

def _inject_canary(url: str, canary: str) -> str:
    """쿼리 파라미터나 경로 끝에 카나리아를 안전하게 삽입합니다."""
    parsed = urllib.parse.urlparse(url)
    
    if parsed.query:
        qs = urllib.parse.parse_qsl(parsed.query)
        if qs:
            modified_qs = [(qs[0][0], qs[0][1] + canary)] + qs[1:]
            new_query = urllib.parse.urlencode(modified_qs)
            return parsed._replace(query=new_query).geturl()
            
    new_path = parsed.path.rstrip('/') + "/" + urllib.parse.quote(canary)
    return parsed._replace(path=new_path).geturl()
