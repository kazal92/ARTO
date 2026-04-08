"""
advanced_agent.py - 고도화된 자율 웹 애플리케이션 점검 에이전트
상태 저장, 멀티스텝 공격, 동적 전략 수립
"""

import os
import json
import asyncio
from typing import Optional, Dict, List, Any
from pathlib import Path


# ── 에이전트 상태 관리 ────────────────────────────────────────────────────

class AgentStateManager:
    """에이전트 점검 상태 영속화"""

    def __init__(self, session_dir: str):
        self.session_dir = session_dir
        self.state_file = os.path.join(session_dir, "agent_state.json")
        self.state = self._load_state()

    def _load_state(self) -> Dict[str, Any]:
        """기존 상태 로드"""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "endpoints": {},          # URL → {method, params, auth, ...}
            "credentials": {},        # username → password
            "cookies": {},            # name → value
            "headers": {},            # header → value
            "vulnerabilities": [],    # 발견된 취약점
            "attack_history": [],     # 시도한 공격 기록
            "current_phase": "recon"  # recon → exploit → verify
        }

    def save(self) -> None:
        """상태 저장"""
        with open(self.state_file, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)

    def add_endpoint(self, url: str, method: str = "GET",
                     params: List[str] = None, auth_required: bool = False):
        """발견한 엔드포인트 저장"""
        if url not in self.state["endpoints"]:
            self.state["endpoints"][url] = {
                "method": method,
                "params": params or [],
                "auth_required": auth_required,
                "tested": False,
                "vulnerabilities": []
            }

    def save_cookie(self, name: str, value: str):
        """로그인 성공 시 쿠키 저장"""
        self.state["cookies"][name] = value
        self.save()

    def add_vulnerability(self, vuln: Dict):
        """취약점 기록"""
        self.state["vulnerabilities"].append(vuln)
        self.save()


# ── 고급 도구 세트 ────────────────────────────────────────────────────

ADVANCED_TOOLS = [
    {
        "name": "scan_endpoint",
        "description": (
            "특정 엔드포인트를 심층 스캔합니다. "
            "요청 방식, 파라미터, 응답 분석을 포함합니다."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "스캔할 URL"},
                "method": {
                    "type": "string",
                    "enum": ["GET", "POST", "PUT", "DELETE", "PATCH"],
                    "description": "HTTP 메서드"
                },
                "params": {
                    "type": "string",
                    "description": "테스트할 파라미터 (JSON 형식)"
                },
                "payload_type": {
                    "type": "string",
                    "enum": ["sqli", "xss", "ssti", "lfi", "rce", "xxe"],
                    "description": "공격 유형"
                }
            },
            "required": ["url", "method", "payload_type"]
        }
    },
    {
        "name": "try_authentication",
        "description": (
            "인증 시도: 로그인 폼을 찾아 자동으로 로그인합니다. "
            "성공 시 세션/쿠키를 저장하고 다음 공격에 사용합니다."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "login_url": {"type": "string", "description": "로그인 URL"},
                "username_field": {"type": "string", "description": "사용자명 필드"},
                "password_field": {"type": "string", "description": "비밀번호 필드"},
                "test_credentials": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "테스트할 인증정보 (admin:admin, test:test 등)"
                }
            },
            "required": ["login_url"]
        }
    },
    {
        "name": "analyze_response",
        "description": (
            "HTTP 응답을 분석하여 취약점 신호를 찾습니다. "
            "에러 메시지, 타이밍, 응답 크기 등을 검토합니다."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "response_body": {"type": "string", "description": "HTTP 응답 본문"},
                "status_code": {"type": "integer", "description": "HTTP 상태 코드"},
                "headers": {
                    "type": "string",
                    "description": "HTTP 헤더 (JSON 형식)"
                },
                "analysis_type": {
                    "type": "string",
                    "enum": ["error_based", "time_based", "boolean_based", "union_based"],
                    "description": "분석 유형"
                }
            },
            "required": ["response_body"]
        }
    },
    {
        "name": "chain_attack",
        "description": (
            "다단계 공격을 수행합니다. "
            "예: 인증 우회 → CSRF 토큰 탈취 → 관리자 권한 상승"
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "attack_chain": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "공격 단계 목록"
                },
                "use_saved_state": {
                    "type": "boolean",
                    "description": "이전 공격의 결과(쿠키, 토큰)를 재사용할지"
                }
            },
            "required": ["attack_chain"]
        }
    },
    {
        "name": "extract_parameters",
        "description": (
            "웹페이지에서 모든 입력 파라미터를 추출합니다. "
            "폼 필드, URL 파라미터, JSON 바디를 분석합니다."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "분석할 URL"},
                "use_js": {
                    "type": "boolean",
                    "description": "JavaScript 렌더링 포함 여부"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "verify_vulnerability",
        "description": (
            "발견된 취약점의 진위를 검증합니다. "
            "실제 악용 가능한지 확인하고 심각도를 평가합니다."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vulnerability_type": {
                    "type": "string",
                    "description": "취약점 유형 (SQLi, XSS 등)"
                },
                "target_url": {"type": "string", "description": "대상 URL"},
                "evidence": {
                    "type": "string",
                    "description": "취약점 증거 (응답, 에러 메시지 등)"
                }
            },
            "required": ["vulnerability_type", "target_url", "evidence"]
        }
    }
]


# ── 시스템 프롬프트 (고급) ────────────────────────────────────────────

ADVANCED_SYSTEM_PROMPT = """당신은 자율적인 웹 보안 AI입니다.
다음 능력이 있습니다:

### 🎯 임무
1. 대상 웹애플리케이션의 모든 엔드포인트 매핑
2. 각 엔드포인트의 입력 파라미터 식별
3. 파라미터별 공격 벡터 자동 생성
4. 다단계 공격으로 복잡한 취약점 발굴
5. 논리적 결함 탐지 (비즈니스 로직)

### 📋 작업 흐름
**Phase 1: 정찰 (Reconnaissance)**
- extract_parameters 도구로 모든 입력점 찾기
- 각 엔드포인트 저장 (상태 유지)
- 인증 메커니즘 파악

**Phase 2: 인증 (Authentication)**
- try_authentication 도구로 로그인 시도
- 기본 인증정보 테스트 (admin/admin, test/test)
- 인증 우회 기법 시도
- 성공 시 쿠키/토큰 저장 (상태에 저장)

**Phase 3: 공격 (Exploitation)**
- scan_endpoint 도구로 각 파라미터 공격
- SQLi, XSS, SSTI, LFI, RCE 시도
- analyze_response 도구로 취약점 신호 분석
- 응답 시간, 에러 메시지, 크기 변화 감지

**Phase 4: 체이닝 (Attack Chaining)**
- chain_attack 도구로 다단계 공격
- 예: Authentication Bypass → CSRF → Privilege Escalation
- 저장된 상태(쿠키, 토큰) 재활용

**Phase 5: 검증 (Verification)**
- verify_vulnerability 도구로 실제 악용 가능성 검증
- 심각도 평가 (CVSS)
- 재현 단계 기록

### 🧠 동적 의사결정
- 각 결과에 따라 다음 공격 전략 자동 수정
- 실패 → 다른 payload 시도
- 성공 → 더 깊은 공격으로 확대
- 패턴 인식 → 취약점 예측

### 💾 상태 관리
- 발견한 엔드포인트 저장
- 획득한 쿠키/토큰 재활용
- 공격 기록 유지
- 다음 단계에서 참고

### ⚠️ 주의사항
- Authorized 점검만 수행
- DoS/서비스 중단 금지
- 모든 동작을 로깅
- 윤리적 해킹 준수"""


# ── 예시: 고급 공격 시나리오 ────────────────────────────────────────────

EXAMPLE_ATTACK_SCENARIOS = {
    "sqli_authentication_bypass": {
        "steps": [
            "extract_parameters(url=target, focus_on=['login', 'auth'])",
            "scan_endpoint(url=login_url, method=POST, params='username&password', payload_type='sqli')",
            "analyze_response(response_body=result, analysis_type='error_based')",
            "chain_attack(attack_chain=['bypass_login', 'extract_user_list', 'elevate_privilege'])"
        ]
    },
    "csrf_privilege_escalation": {
        "steps": [
            "try_authentication(login_url=target/login)",
            "extract_parameters(url=admin_panel, use_js=true)",
            "scan_endpoint(url=admin_api, method=POST, payload_type='csrf')",
            "verify_vulnerability(vulnerability_type='CSRF', target_url=admin_api)"
        ]
    },
    "xxe_data_exfiltration": {
        "steps": [
            "extract_parameters(url=target, focus_on=['upload', 'import'])",
            "scan_endpoint(url=upload_endpoint, method=POST, payload_type='xxe')",
            "analyze_response(response_body=result, analysis_type='error_based')",
            "chain_attack(attack_chain=['trigger_xxe', 'read_local_file', 'extract_credentials'])"
        ]
    }
}


# ── 구현 예시 ────────────────────────────────────────────────────────

def create_advanced_agent_request(target: str, session_dir: str) -> Dict:
    """고급 에이전트 요청 생성"""
    state_mgr = AgentStateManager(session_dir)

    return {
        "system_prompt": ADVANCED_SYSTEM_PROMPT,
        "tools": ADVANCED_TOOLS,
        "initial_message": f"""
대상: {target}

다음을 수행하세요:
1. extract_parameters로 모든 입력점 찾기
2. try_authentication으로 기본 인증정보 시도
3. scan_endpoint로 각 파라미터 공격
4. 발견한 것들을 상태에 저장
5. 다단계 공격 시도

상태 파일: {state_mgr.state_file}
""",
        "state": state_mgr.state,
        "max_iterations": 100
    }


if __name__ == "__main__":
    print("고급 자율 웹 애플리케이션 점검 에이전트")
    print("=" * 60)
    print("\n지원 도구:")
    for tool in ADVANCED_TOOLS:
        print(f"  ✓ {tool['name']}: {tool['description'][:50]}...")
    print("\n예시 공격 시나리오:")
    for scenario in EXAMPLE_ATTACK_SCENARIOS.keys():
        print(f"  ✓ {scenario}")
