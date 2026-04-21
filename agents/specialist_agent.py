"""
specialist_agent.py — Phase 2 (Deep Spear) 전문가 디스패처

Phase 1 에서 발견된 의심 취약점(candidate finding) 1건을 전담 검증하는 에이전트를 실행합니다.
특징:
  - 단일 타겟/엔드포인트에 범위 고정
  - 취약점 클래스별 전문 시스템 프롬프트 사용 (agents/specialists.py)
  - 개별 시간 예산 강제 (asyncio.wait_for)
  - 클래스별 추가 도구 해제 (sqlmap, dalfox 등)
  - 결과를 ai_findings.json 에 verified=true/false 로 역기록
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from core.logging import stream_log, stream_custom, stream_chunk
from core.cancellation import is_cancelled
from config import MAX_COMMAND_OUTPUT
from agents.pentest_shared import (
    CLAUDE_TOOLS,
    BLOCKED_TOOLS,
    _execute_tool,
    _save_finding,
    _get_existing_findings,
)
from agents.specialists import (
    classify_finding,
    get_specialist,
    build_specialist_system_prompt,
    get_allowed_extra_tools,
    get_time_budget,
)


# ── Finding ID / 조회 ────────────────────────────────────────────────────────

def compute_finding_id(finding: dict) -> str:
    """title + target 해시 기반 안정적 ID. 저장 시 유실되지 않도록 16자 단축."""
    if not isinstance(finding, dict):
        return ""
    key_src = f"{finding.get('title','')}|{finding.get('target','')}"
    return hashlib.sha1(key_src.encode("utf-8", errors="replace")).hexdigest()[:16]


def _ensure_finding_id(finding: dict) -> str:
    """finding 에 id 필드가 없으면 생성해 주입하고 반환."""
    fid = finding.get("id")
    if not fid:
        fid = compute_finding_id(finding)
        finding["id"] = fid
    return fid


def _load_findings(session_dir: str) -> List[dict]:
    path = os.path.join(session_dir, "ai_findings.json")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, list) else []
    except Exception:
        return []


def _save_findings(session_dir: str, findings: List[dict]) -> None:
    path = os.path.join(session_dir, "ai_findings.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)


def find_finding_by_id(session_dir: str, finding_id: str) -> Tuple[int, Optional[dict]]:
    """저장된 findings 에서 id 매칭되는 항목을 (index, finding) 으로 반환."""
    findings = _load_findings(session_dir)
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            continue
        fid = f.get("id") or compute_finding_id(f)
        if fid == finding_id:
            return i, f
    return -1, None


def update_finding(session_dir: str, finding_id: str, patch: dict) -> bool:
    """해당 id 의 finding 에 patch 를 병합 저장."""
    findings = _load_findings(session_dir)
    updated = False
    for f in findings:
        if not isinstance(f, dict):
            continue
        fid = f.get("id") or compute_finding_id(f)
        if fid == finding_id:
            f.update(patch)
            f["id"] = fid
            updated = True
            break
    if updated:
        _save_findings(session_dir, findings)
    return updated


# ── 도구 실행 (전문가 모드: 차단 도구 선택적 해제) ─────────────────────────────

async def _execute_specialist_command(
    tool_input: dict,
    session_dir: str,
    allow_tools: Optional[set] = None,
) -> str:
    """run_command 를 전문가 모드로 실행. allow_tools 에 포함된 도구는 BLOCKED 체크 우회.

    pentest_shared._execute_run_command 와 유사하지만 BLOCKED 우회 기능 제공.
    """
    command = (tool_input.get("command") or "").strip()
    timeout = int(tool_input.get("timeout", 180))
    if not command:
        return "오류: 명령어가 비어 있습니다."

    cmd_lower = command.lower()
    allow_tools = allow_tools or set()

    for tool in BLOCKED_TOOLS:
        if tool in allow_tools:
            continue
        if re.search(rf"\b{re.escape(tool)}\b", cmd_lower):
            stream_log(session_dir, f"전문가 모드 차단: {tool}", "Specialist")
            return (
                f"오류: '{tool}'은 이 전문가 모드에서 허용되지 않습니다. "
                f"허용 도구: {sorted(allow_tools) or '기본 도구만'}."
            )

    if cmd_lower.startswith("curl ") and " -s" not in cmd_lower:
        command = command.replace("curl ", "curl -sS ", 1)

    stream_log(session_dir, f"$ {command}", "Command")

    try:
        env = os.environ.copy()
        env["SHELL"] = "/usr/bin/zsh"
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            executable="/usr/bin/zsh",
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

        output = stdout.decode("utf-8", errors="replace") if stdout else ""
        if stderr:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            if stderr_text:
                output += f"\n[stderr]\n{stderr_text}"

        output = output.strip()
        if len(output) > MAX_COMMAND_OUTPUT:
            half = MAX_COMMAND_OUTPUT // 2
            output = (
                output[:half]
                + f"\n\n... (출력 생략, 총 {len(output)}자) ...\n\n"
                + output[-half // 2 :]
            )
        return output or f"명령어 실행 완료 (출력 없음, 종료 코드: {proc.returncode})"

    except asyncio.TimeoutError:
        return f"오류: 타임아웃 ({timeout}초) 초과 — 명령어: {command}"
    except Exception as e:
        return f"오류: {str(e)}"


async def _execute_specialist_tool(
    tool_name: str,
    tool_input: dict,
    session_dir: str,
    finding_id: str,
    allow_tools: set,
) -> str:
    """전문가 모드 전용 도구 라우터.
    - run_command: 차단 도구 선택적 해제
    - report_finding: finding_id 와 병합하여 검증 완료 처리
    - 기타: pentest_shared._execute_tool 위임
    """
    if tool_name == "run_command":
        return await _execute_specialist_command(tool_input, session_dir, allow_tools)

    if tool_name == "report_finding":
        # 기존 finding 을 덮어쓰기 (신규 생성 아님)
        patch = {
            "verified": True,
            "verified_at": datetime.now().isoformat(),
            "title": tool_input.get("title") or None,
            "severity": tool_input.get("severity") or None,
            "target": tool_input.get("target") or None,
            "description": tool_input.get("description") or None,
            "evidence": tool_input.get("evidence") or None,
            "steps": tool_input.get("steps") or None,
            "recommendation": tool_input.get("recommendation") or None,
            "cwe": tool_input.get("cwe") or None,
            "ttp": tool_input.get("ttp") or None,
            "owasp": tool_input.get("owasp") or None,
            "source": "Specialist",
            "confidence": max(int(tool_input.get("confidence", 90) or 90), 80),
        }
        patch = {k: v for k, v in patch.items() if v is not None}
        if not update_finding(session_dir, finding_id, patch):
            # 대상 finding 이 사라진 경우 새로 저장 (drift 안전장치)
            merged = dict(tool_input)
            merged.setdefault("verified", True)
            merged.setdefault("source", "Specialist")
            merged["id"] = finding_id
            _save_finding(merged, session_dir)

        stream_custom(
            session_dir,
            {
                "type": "triage_finding_verified",
                "finding_id": finding_id,
                "data": tool_input,
            },
        )
        return f"✅ 전문가 검증 완료: {tool_input.get('title', '')} (finding_id={finding_id})"

    # 나머지(save_state/load_state 등) 는 기본 핸들러 위임
    return await _execute_tool(tool_name, tool_input, session_dir)


# ── 전문가 실행 루프 (Claude / OpenAI-호환 공용 구현) ────────────────────────

async def _run_claude_specialist_loop(
    client,
    model: str,
    system_prompt: str,
    seed_user_message: str,
    session_dir: str,
    finding_id: str,
    allow_tools: set,
    max_iterations: int,
) -> Tuple[bool, str, List[dict]]:
    """Anthropic SDK 루프. (verified, last_text, conversation) 반환."""
    conversation = [{"role": "user", "content": seed_user_message}]
    verified = False
    last_text = ""

    for iteration in range(1, max_iterations + 1):
        if is_cancelled(session_dir):
            stream_log(session_dir, "전문가 에이전트가 중단되었습니다.", "Specialist")
            break

        tool_calls = []
        assistant_content = []

        try:
            async with client.messages.stream(
                model=model,
                system=system_prompt,
                messages=conversation,
                tools=CLAUDE_TOOLS,
                max_tokens=4096,
            ) as stream:
                async for event in stream:
                    etype = type(event).__name__
                    if etype == "RawContentBlockDeltaEvent":
                        delta = getattr(event, "delta", None)
                        if delta and getattr(delta, "type", "") == "text_delta":
                            text = getattr(delta, "text", "")
                            if text:
                                stream_chunk(session_dir, text)
                                last_text += text

                final_msg = await stream.get_final_message()
                for block in final_msg.content:
                    assistant_content.append(block)
                    if block.type == "tool_use":
                        tool_input = block.input if isinstance(block.input, dict) else {}
                        tool_calls.append((block.id, block.name, tool_input))
                        stream_custom(
                            session_dir,
                            {
                                "type": "triage_tool_call",
                                "finding_id": finding_id,
                                "tool_name": block.name,
                                "tool_input": tool_input,
                            },
                        )
        except Exception as e:
            stream_log(session_dir, f"전문가 에이전트 오류: {e}", "Specialist")
            break

        conversation.append({"role": "assistant", "content": assistant_content})

        if not tool_calls:
            stream_log(session_dir, "전문가 에이전트 종료 (도구 호출 없음)", "Specialist")
            break

        tool_results = []
        for tool_id, tool_name, tool_input in tool_calls:
            result = await _execute_specialist_tool(
                tool_name, tool_input, session_dir, finding_id, allow_tools
            )
            if tool_name == "report_finding":
                verified = True
            stream_custom(
                session_dir,
                {
                    "type": "triage_tool_result",
                    "finding_id": finding_id,
                    "tool_name": tool_name,
                    "result": result[:600] + "..." if len(result) > 600 else result,
                },
            )
            tool_results.append(
                {"type": "tool_result", "tool_use_id": tool_id, "content": result}
            )

        conversation.append({"role": "user", "content": tool_results})

        if verified:
            break

    return verified, last_text, conversation


async def _run_openai_specialist_loop(
    client,
    model: str,
    system_prompt: str,
    seed_user_message: str,
    session_dir: str,
    finding_id: str,
    allow_tools: set,
    max_iterations: int,
) -> Tuple[bool, str, List[dict]]:
    """OpenAI / Gemini / LMStudio 호환 루프."""
    from agents.pentest_shared import OPENAI_TOOLS

    conversation = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": seed_user_message},
    ]
    verified = False
    last_text = ""

    for iteration in range(1, max_iterations + 1):
        if is_cancelled(session_dir):
            stream_log(session_dir, "전문가 에이전트가 중단되었습니다.", "Specialist")
            break

        try:
            response = await client.chat.completions.create(
                model=model,
                messages=conversation,
                tools=OPENAI_TOOLS,
                tool_choice="auto",
                temperature=0.2,
            )
        except Exception as e:
            stream_log(session_dir, f"전문가 에이전트 오류: {e}", "Specialist")
            break

        msg = response.choices[0].message
        content_text = msg.content or ""
        if content_text:
            stream_chunk(session_dir, content_text)
            last_text += content_text

        tool_calls = msg.tool_calls or []
        assistant_msg: Dict = {"role": "assistant", "content": content_text}
        if tool_calls:
            assistant_msg["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in tool_calls
            ]
        conversation.append(assistant_msg)

        if not tool_calls:
            stream_log(session_dir, "전문가 에이전트 종료 (도구 호출 없음)", "Specialist")
            break

        for tc in tool_calls:
            tool_name = tc.function.name
            try:
                tool_input = json.loads(tc.function.arguments or "{}")
            except json.JSONDecodeError:
                tool_input = {}

            stream_custom(
                session_dir,
                {
                    "type": "triage_tool_call",
                    "finding_id": finding_id,
                    "tool_name": tool_name,
                    "tool_input": tool_input,
                },
            )

            result = await _execute_specialist_tool(
                tool_name, tool_input, session_dir, finding_id, allow_tools
            )
            if tool_name == "report_finding":
                verified = True

            stream_custom(
                session_dir,
                {
                    "type": "triage_tool_result",
                    "finding_id": finding_id,
                    "tool_name": tool_name,
                    "result": result[:600] + "..." if len(result) > 600 else result,
                },
            )

            conversation.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tool_name,
                    "content": result,
                }
            )

        if verified:
            break

    return verified, last_text, conversation


# ── 메인 진입점 ───────────────────────────────────────────────────────────────

async def run_specialist_agent(
    finding: dict,
    session_dir: str,
    ai_config: dict,
    time_budget_seconds: Optional[int] = None,
    max_iterations: int = 20,
) -> dict:
    """하나의 finding 에 대해 전문가 에이전트를 실행합니다.

    Returns: {"finding_id": str, "verified": bool, "vuln_class": str,
              "elapsed_seconds": float, "reason": str}
    """
    finding_id = _ensure_finding_id(finding)
    vuln_class = finding.get("vuln_class") or classify_finding(finding)
    spec = get_specialist(vuln_class)
    budget = int(time_budget_seconds or get_time_budget(vuln_class))
    allow_tools = set(get_allowed_extra_tools(vuln_class))

    # 기존 findings 에 vuln_class / triage_status 업데이트
    update_finding(
        session_dir,
        finding_id,
        {
            "id": finding_id,
            "vuln_class": vuln_class,
            "triage_status": "in_progress",
            "specialist_started_at": datetime.now().isoformat(),
            "time_budget_seconds": budget,
        },
    )

    stream_custom(
        session_dir,
        {
            "type": "triage_start",
            "finding_id": finding_id,
            "vuln_class": vuln_class,
            "title_kr": spec.get("title_kr", "Generic"),
            "time_budget_seconds": budget,
        },
    )
    stream_log(
        session_dir,
        f"[전문가] {spec.get('title_kr')} 시작 → {finding.get('target','')}  예산 {budget}s",
        "Specialist",
    )

    system_prompt = build_specialist_system_prompt(finding, vuln_class)
    seed_user_message = (
        "위 시스템 프롬프트에 명시된 단일 의심 취약점에 대해 집중 검증을 시작하십시오.\n"
        "검증 성공 시 report_finding 을, 실패 시 '검증 불가: <이유>' 만 출력하고 종료하십시오."
    )

    # ── 백엔드 선택 ──
    ai_type = (ai_config or {}).get("type", "gemini")
    started = datetime.now()
    verified = False
    last_text = ""

    try:
        if ai_type == "claude":
            try:
                import anthropic
            except ImportError:
                stream_log(session_dir, "오류: anthropic 미설치", "Specialist")
                raise RuntimeError("anthropic SDK 미설치")

            api_key = ai_config.get("api_key", "")
            if not api_key:
                raise RuntimeError("Claude API 키가 설정되지 않았습니다.")
            model = ai_config.get("model", "claude-sonnet-4-6")
            client = anthropic.AsyncAnthropic(api_key=api_key)

            verified, last_text, _ = await asyncio.wait_for(
                _run_claude_specialist_loop(
                    client, model, system_prompt, seed_user_message,
                    session_dir, finding_id, allow_tools, max_iterations,
                ),
                timeout=budget,
            )
        else:
            # Gemini / LMStudio / OpenAI 호환
            from openai import AsyncOpenAI
            from config import LM_STUDIO_API_URL, LM_STUDIO_MODEL

            base_url = ai_config.get("base_url") or LM_STUDIO_API_URL
            api_key = ai_config.get("api_key") or "lm-studio"
            model = ai_config.get("model") or LM_STUDIO_MODEL
            client = AsyncOpenAI(base_url=base_url, api_key=api_key)

            verified, last_text, _ = await asyncio.wait_for(
                _run_openai_specialist_loop(
                    client, model, system_prompt, seed_user_message,
                    session_dir, finding_id, allow_tools, max_iterations,
                ),
                timeout=budget,
            )
    except asyncio.TimeoutError:
        stream_log(
            session_dir,
            f"[전문가] 시간 예산 초과 ({budget}s) — 검증 중단",
            "Specialist",
        )
        last_text = last_text or f"시간 예산 초과 ({budget}초)"
    except Exception as e:
        stream_log(session_dir, f"[전문가] 실행 오류: {e}", "Specialist")
        last_text = last_text or f"실행 오류: {e}"

    elapsed = (datetime.now() - started).total_seconds()

    # 검증 실패 사유 추출
    fail_reason = ""
    if not verified:
        m = re.search(r"검증\s*불가\s*[:：]\s*(.+)", last_text)
        fail_reason = (m.group(1).strip() if m else last_text.strip())[:500]

    # 상태 업데이트
    patch = {
        "triage_status": "verified" if verified else "failed",
        "specialist_completed_at": datetime.now().isoformat(),
        "specialist_elapsed_seconds": round(elapsed, 1),
        "vuln_class": vuln_class,
    }
    if not verified and fail_reason:
        patch["verification_reason"] = fail_reason
    update_finding(session_dir, finding_id, patch)

    stream_custom(
        session_dir,
        {
            "type": "triage_complete",
            "finding_id": finding_id,
            "verified": verified,
            "vuln_class": vuln_class,
            "elapsed_seconds": round(elapsed, 1),
            "reason": fail_reason if not verified else "",
        },
    )
    stream_log(
        session_dir,
        (
            f"[전문가] {'✅ 검증 성공' if verified else '❌ 검증 실패'}"
            f" — {finding.get('title','')} ({elapsed:.1f}s)"
        ),
        "Specialist",
    )

    return {
        "finding_id": finding_id,
        "verified": verified,
        "vuln_class": vuln_class,
        "elapsed_seconds": round(elapsed, 1),
        "reason": fail_reason,
    }


async def run_specialists_batch(
    finding_ids: List[str],
    session_dir: str,
    ai_config: dict,
    time_budget_per_finding: Optional[int] = None,
    max_parallel: int = 1,
) -> List[dict]:
    """여러 finding_id 를 순차 또는 제한 병렬 실행.

    기본 max_parallel=1 (순차). Rate limit / WAF 방지 목적으로 병렬 제한 권장.
    """
    results: List[dict] = []
    sem = asyncio.Semaphore(max(1, int(max_parallel)))

    async def _one(fid: str):
        async with sem:
            if is_cancelled(session_dir):
                return None
            _idx, finding = find_finding_by_id(session_dir, fid)
            if not finding:
                stream_log(
                    session_dir,
                    f"[전문가] finding_id={fid} 를 찾을 수 없어 건너뜁니다.",
                    "Specialist",
                )
                return None
            return await run_specialist_agent(
                finding, session_dir, ai_config,
                time_budget_seconds=time_budget_per_finding,
            )

    tasks = [_one(fid) for fid in finding_ids]
    for coro in asyncio.as_completed(tasks):
        r = await coro
        if r:
            results.append(r)
    return results
