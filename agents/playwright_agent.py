"""
playwright_agent.py - Playwright 기반 완전 자율 AI 해킹 에이전트
실제 브라우저(Chromium)를 AI가 직접 제어하며 웹 취약점을 탐색

ReAct 방식:
  AI → Thought / Action / Input 텍스트 응답
  코드 → 파싱 → 브라우저 조작 → 결과 (스크린샷 + HTML) → 다시 AI에게
"""

import os
import re
import json
import base64
import asyncio
from pathlib import Path
from typing import Optional

from core.logging import stream_log, stream_custom
from core.cancellation import is_cancelled

# ── 시스템 프롬프트 ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """당신은 실제 브라우저를 제어하는 웹 보안 전문가입니다.
Playwright 브라우저가 연결되어 있으며, 지시한 액션을 브라우저에서 직접 실행합니다.

## 응답 형식 (반드시 준수)
매 응답은 반드시 다음 형식으로 작성하세요:

Thought: (현재 상황 분석 및 다음 행동 계획, 한국어)
Action: (실행할 액션 이름)
Input: (액션에 전달할 값)

## 사용 가능한 Action 목록

### 브라우저 제어
- navigate: 특정 URL로 이동
  Input: https://target.com/path

- click: 요소 클릭
  Input: CSS셀렉터 또는 텍스트 (예: button#submit, "로그인")

- fill: 입력 폼에 값 입력
  Input: {"selector": "#username", "value": "admin' OR '1'='1"}

- submit: 폼 제출 (Enter 입력)
  Input: #login-form

- screenshot: 현재 페이지 스크린샷 (자동으로 AI에게 전달됨)
  Input: (비워두기)

### 정보 수집
- get_html: 현재 페이지 HTML 추출 (입력 폼, 파라미터 분석)
  Input: (비워두기 또는 CSS셀렉터로 특정 요소만)

- get_cookies: 현재 세션 쿠키 목록
  Input: (비워두기)

- get_url: 현재 URL 확인
  Input: (비워두기)

### 공격 도구
- run_command: 쉘 명령어 실행 (curl, wget, python3 사용 가능)
  Input: noglob curl -s "http://target.com/api?id=1'"

- inject_js: 페이지에 JavaScript 직접 실행
  Input: document.cookie

### 결과 보고
- report_finding: 취약점 발견 시 보고 (반드시 증거 확인 후 호출)
  Input: {
    "title": "취약점명 (한국어)",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "target": "취약한 URL 또는 파라미터",
    "description": "기술적 설명 (한국어)",
    "evidence": "실제 응답, 스크린샷 설명, 에러 메시지",
    "steps": "1. ...\n2. ...",
    "recommendation": "대응 방안 (한국어)",
    "cwe": "CWE-번호",
    "owasp": "A00:2021"
  }

- done: 점검 완료
  Input: (완료 이유)

## 점검 방법론

**Phase 1: 정찰**
- navigate로 대상 접속
- screenshot으로 현재 상태 확인
- get_html로 입력 폼, 파라미터 분석

**Phase 2: 인증 테스트**
- 로그인 폼 발견 → fill + click으로 SQLi 인증 우회 시도
- 기본 계정 시도 (admin/admin, test/test)
- 성공 시 get_cookies로 세션 저장

**Phase 3: 취약점 공격**
- 발견한 파라미터에 payload 삽입
- SQLi: ' OR '1'='1, 1' AND SLEEP(3)--
- XSS: <script>alert(1)</script>
- SSTI: {{7*7}}, ${7*7}
- LFI: ../../../../etc/passwd

**Phase 4: 검증 및 보고**
- 취약점 신호 확인:
  - SQL 오류 메시지
  - XSS 팝업 발생
  - SSTI 계산 결과 (49 등)
  - /etc/passwd 내용 노출
- 확인된 것만 report_finding 호출

## 주의사항
- Authorized 모의해킹입니다. 적극적으로 시도하세요.
- 각 Action 후 screenshot으로 결과 확인
- 같은 취약점 중복 보고 금지
- DoS/서비스 중단 금지
- 설명은 한국어, 명령어/페이로드는 원문 유지"""


# ── ReAct 응답 파서 ───────────────────────────────────────────────────────────

def _parse_react_response(text: str) -> tuple[str, str, str]:
    """AI 응답에서 Thought / Action / Input 파싱"""
    thought = ""
    action = ""
    inp = ""

    # Thought 추출
    m = re.search(r"Thought:\s*(.+?)(?=Action:|$)", text, re.DOTALL | re.IGNORECASE)
    if m:
        thought = m.group(1).strip()

    # Action 추출
    m = re.search(r"Action:\s*(\w+)", text, re.IGNORECASE)
    if m:
        action = m.group(1).strip().lower()

    # Input 추출 (JSON 코드블록 포함 처리)
    m = re.search(r"Input:\s*([\s\S]+?)(?=Thought:|Action:|$)", text, re.IGNORECASE)
    if m:
        raw = m.group(1).strip()
        # 마크다운 코드블록 제거
        raw = re.sub(r"```(?:json)?\n?", "", raw).strip().rstrip("`").strip()
        inp = raw

    return thought, action, inp


def _parse_json_input(inp: str) -> Optional[dict]:
    """Input 문자열을 JSON으로 파싱 (실패 시 None)"""
    try:
        return json.loads(inp)
    except Exception:
        # 중괄호 찾아서 파싱 시도
        m = re.search(r"\{[\s\S]+\}", inp)
        if m:
            try:
                return json.loads(m.group(0))
            except Exception:
                pass
    return None


# ── 브라우저 액션 실행기 ──────────────────────────────────────────────────────

class BrowserController:
    def __init__(self, page, session_dir: str):
        self.page = page
        self.session_dir = session_dir

    async def execute(self, action: str, inp: str) -> dict:
        """액션 실행 후 결과 반환"""
        try:
            if action == "navigate":
                return await self._navigate(inp.strip())
            elif action == "click":
                return await self._click(inp.strip())
            elif action == "fill":
                return await self._fill(inp.strip())
            elif action == "submit":
                return await self._submit(inp.strip())
            elif action == "screenshot":
                return await self._screenshot()
            elif action == "get_html":
                return await self._get_html(inp.strip())
            elif action == "get_cookies":
                return await self._get_cookies()
            elif action == "get_url":
                return {"result": self.page.url, "screenshot": None}
            elif action == "run_command":
                return await self._run_command(inp.strip())
            elif action == "inject_js":
                return await self._inject_js(inp.strip())
            elif action == "report_finding":
                return await self._report_finding(inp)
            elif action == "done":
                return {"result": f"점검 완료: {inp}", "done": True, "screenshot": None}
            else:
                return {"result": f"알 수 없는 액션: {action}", "screenshot": None}
        except Exception as e:
            return {"result": f"액션 실행 오류 ({action}): {str(e)}", "screenshot": None}

    async def _navigate(self, url: str) -> dict:
        await self.page.goto(url, wait_until="domcontentloaded", timeout=15000)
        await asyncio.sleep(1)
        ss = await self._screenshot()
        return {"result": f"이동 완료: {self.page.url}", "screenshot": ss["screenshot"]}

    async def _click(self, selector: str) -> dict:
        try:
            await self.page.click(selector, timeout=5000)
        except Exception:
            # 텍스트로 시도
            await self.page.get_by_text(selector).first.click(timeout=5000)
        await asyncio.sleep(0.5)
        ss = await self._screenshot()
        return {"result": f"클릭 완료: {selector}", "screenshot": ss["screenshot"]}

    async def _fill(self, inp: str) -> dict:
        data = _parse_json_input(inp)
        if data:
            selector = data.get("selector", "")
            value = data.get("value", "")
        else:
            # "selector::value" 형식 시도
            parts = inp.split("::", 1)
            selector = parts[0].strip()
            value = parts[1].strip() if len(parts) > 1 else ""

        await self.page.fill(selector, value, timeout=5000)
        return {"result": f"입력 완료: {selector} = {value[:50]}", "screenshot": None}

    async def _submit(self, selector: str) -> dict:
        await self.page.press(selector or "body", "Enter")
        await asyncio.sleep(1)
        ss = await self._screenshot()
        return {"result": f"폼 제출 완료. 현재 URL: {self.page.url}", "screenshot": ss["screenshot"]}

    async def _screenshot(self) -> dict:
        """스크린샷 → base64 인코딩"""
        ss_bytes = await self.page.screenshot(type="jpeg", quality=60)
        b64 = base64.b64encode(ss_bytes).decode("utf-8")
        # 파일로도 저장
        ss_path = os.path.join(self.session_dir, "playwright_latest.jpg")
        with open(ss_path, "wb") as f:
            f.write(ss_bytes)
        return {"result": "스크린샷 캡처 완료", "screenshot": b64}

    async def _get_html(self, selector: str = "") -> dict:
        if selector:
            try:
                el = await self.page.query_selector(selector)
                html = await el.inner_html() if el else await self.page.content()
            except Exception:
                html = await self.page.content()
        else:
            html = await self.page.content()

        # 불필요한 태그 제거해서 토큰 절약
        html = re.sub(r"<script[\s\S]*?</script>", "", html, flags=re.IGNORECASE)
        html = re.sub(r"<style[\s\S]*?</style>", "", html, flags=re.IGNORECASE)
        html = re.sub(r"<!--[\s\S]*?-->", "", html)
        # 5000자 제한
        if len(html) > 5000:
            html = html[:5000] + "\n...(생략)..."

        return {"result": html, "screenshot": None}

    async def _get_cookies(self) -> dict:
        cookies = await self.page.context.cookies()
        cookie_str = "\n".join([f"{c['name']}={c['value']}" for c in cookies])
        return {"result": cookie_str or "쿠키 없음", "screenshot": None}

    async def _run_command(self, command: str) -> dict:
        env = os.environ.copy()
        env["SHELL"] = "/usr/bin/zsh"
        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
                executable="/usr/bin/zsh"
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
            out = (stdout.decode("utf-8", errors="replace") +
                   stderr.decode("utf-8", errors="replace")).strip()
            if len(out) > 3000:
                out = out[:3000] + "\n...(생략)..."
            return {"result": out or "(출력 없음)", "screenshot": None}
        except asyncio.TimeoutError:
            return {"result": "타임아웃 (30초)", "screenshot": None}

    async def _inject_js(self, script: str) -> dict:
        result = await self.page.evaluate(script)
        return {"result": str(result), "screenshot": None}

    async def _report_finding(self, inp: str) -> dict:
        finding = _parse_json_input(inp)
        if not finding:
            finding = {
                "title": "취약점 발견",
                "severity": "MEDIUM",
                "target": self.page.url,
                "description": inp,
                "evidence": inp,
                "steps": "에이전트가 발견",
                "recommendation": "확인 필요"
            }
        finding.setdefault("verified", True)
        finding.setdefault("confidence", 80)
        finding.setdefault("source", "PlaywrightAgent")
        finding.setdefault("cwe", "")
        finding.setdefault("ttp", "")
        finding.setdefault("owasp", "")

        # 중복 체크
        findings_path = os.path.join(self.session_dir, "ai_findings.json")
        existing = []
        if os.path.exists(findings_path):
            try:
                with open(findings_path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except Exception:
                pass

        for ex in existing:
            if (ex.get("title") == finding.get("title") and
                    ex.get("target") == finding.get("target")):
                return {"result": f"⚠️ 중복 취약점: {finding.get('title')}", "screenshot": None}

        existing.append(finding)
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

        stream_custom(self.session_dir, {"type": "ai_card", "data": finding})
        return {
            "result": f"✅ 취약점 보고 완료: {finding.get('title')} [{finding.get('severity')}]",
            "screenshot": None
        }


# ── 메인 에이전트 루프 ────────────────────────────────────────────────────────

async def run_playwright_agent(
    target: str,
    session_dir: str,
    ai_config: dict,
    custom_headers: dict = None,
) -> None:
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        stream_log(session_dir, "❌ Playwright가 설치되지 않았습니다. pip install playwright && playwright install chromium", "Agent")
        stream_custom(session_dir, {"type": "scan_complete", "data": []})
        return

    ai_type = ai_config.get("type", "gemini")
    api_key = ai_config.get("api_key", "")
    base_url = ai_config.get("base_url", "")
    model = ai_config.get("model", "")

    stream_log(session_dir, f"🎭 Playwright 에이전트 시작", "Agent")
    stream_log(session_dir, f"🤖 AI 엔진: {ai_type.upper()} / {model}", "Agent")
    stream_log(session_dir, f"🎯 대상: {target}", "Agent")

    try:
        from openai import AsyncOpenAI

        if ai_type == "claude":
            import anthropic
            llm_client = None
            claude_client = anthropic.AsyncAnthropic(api_key=api_key)
        else:
            claude_client = None
            llm_client = AsyncOpenAI(
                base_url=base_url or "https://generativelanguage.googleapis.com/v1beta/openai/",
                api_key=api_key if api_key else "not-needed"
            )

        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={"width": 1280, "height": 800},
                extra_http_headers=custom_headers or {}
            )
            page = await context.new_page()
            ctrl = BrowserController(page, session_dir)

            conversation = []
            max_iterations = 50
            iteration = 0

            # 초기 스크린샷
            await page.goto(target, wait_until="domcontentloaded", timeout=15000)
            await asyncio.sleep(1)
            ss_result = await ctrl._screenshot()
            initial_html = await ctrl._get_html()

            # 첫 메시지
            user_content = (
                f"대상: {target}\n\n"
                f"## 현재 페이지 HTML (주요 부분)\n{initial_html['result']}\n\n"
                f"위 대상을 점검하세요. 먼저 screenshot으로 현재 상태를 확인하세요."
            )

            while iteration < max_iterations:
                if is_cancelled(session_dir):
                    stream_log(session_dir, "에이전트가 중단되었습니다.", "Agent")
                    break

                iteration += 1

                # AI 호출
                try:
                    if claude_client:
                        conversation_msgs = [{"role": "user", "content": user_content}] if iteration == 1 else conversation
                        response = await claude_client.messages.create(
                            model=model or "claude-sonnet-4-6",
                            system=SYSTEM_PROMPT,
                            messages=conversation_msgs if iteration > 1 else [{"role": "user", "content": user_content}],
                            max_tokens=2048,
                        )
                        ai_text = response.content[0].text
                    else:
                        if iteration == 1:
                            conversation = [
                                {"role": "system", "content": SYSTEM_PROMPT},
                                {"role": "user", "content": user_content}
                            ]
                        response = await llm_client.chat.completions.create(
                            model=model,
                            messages=conversation,
                            temperature=0.3,
                            max_tokens=1024,
                        )
                        ai_text = response.choices[0].message.content or ""
                        conversation.append({"role": "assistant", "content": ai_text})

                except Exception as e:
                    stream_log(session_dir, f"AI 호출 오류: {str(e)}", "Agent")
                    break

                # ReAct 파싱
                thought, action, inp = _parse_react_response(ai_text)

                if thought:
                    stream_custom(session_dir, {"type": "thinking_chunk", "content": thought})
                    stream_custom(session_dir, {"type": "thinking_start"})

                if not action:
                    stream_log(session_dir, f"Action 파싱 실패. 응답: {ai_text[:200]}", "Agent")
                    break

                # 액션 UI 표시
                stream_custom(session_dir, {
                    "type": "tool_call",
                    "tool_name": action,
                    "tool_input": {"input": inp[:200] if inp else ""}
                })

                # 브라우저 액션 실행
                result = await ctrl.execute(action, inp)
                result_text = result.get("result", "")
                screenshot_b64 = result.get("screenshot")

                # 스크린샷이 있으면 UI에 전송
                if screenshot_b64:
                    stream_custom(session_dir, {
                        "type": "playwright_screenshot",
                        "data": screenshot_b64
                    })

                # 결과 UI 표시
                stream_custom(session_dir, {
                    "type": "tool_result",
                    "result": result_text[:500] if len(result_text) > 500 else result_text
                })

                # 완료 처리
                if result.get("done"):
                    break

                # 다음 AI 메시지 구성
                next_content = f"Action 결과: {result_text}"
                if screenshot_b64:
                    next_content += "\n(스크린샷이 업데이트되었습니다. 현재 페이지 상태를 참고하세요.)"

                if claude_client:
                    conversation.append({"role": "assistant", "content": ai_text})
                    conversation.append({"role": "user", "content": next_content})
                    # 컨텍스트 너무 길면 앞부분 잘라냄
                    if len(conversation) > 40:
                        conversation = conversation[:2] + conversation[-38:]
                else:
                    conversation.append({"role": "user", "content": next_content})
                    if len(conversation) > 40:
                        conversation = [conversation[0]] + conversation[-38:]

                user_content = next_content

            await browser.close()
            stream_log(session_dir, f"🎭 Playwright 에이전트 점검 완료 ({iteration}회 반복)", "Agent")

    except Exception as e:
        stream_log(session_dir, f"Playwright 에이전트 오류: {str(e)}", "Agent")

    stream_custom(session_dir, {"type": "scan_complete", "data": []})
