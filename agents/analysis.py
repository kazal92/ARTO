import os
import json
import asyncio
import urllib.parse
from typing import Dict, List, Optional

from openai import AsyncOpenAI
from config import LM_STUDIO_API_URL, LM_STUDIO_MODEL, ENABLE_REQUEST_COMPRESSION, AI_MAX_BATCH_SIZE
from tools import minimize_request_raw, extract_relevant_snippet
from core.session import save_tool_result
from core.logging import stream_log, stream_custom, stream_chunk
from core.cancellation import is_cancelled

_default_client: Optional[AsyncOpenAI] = None


def _get_default_client() -> AsyncOpenAI:
    global _default_client
    if _default_client is None:
        _default_client = AsyncOpenAI(base_url=LM_STUDIO_API_URL, api_key="lm-studio")
    return _default_client


def _init_ai_client(ai_config: dict):
    """ai_config dict로부터 AsyncOpenAI 클라이언트와 모델명을 초기화합니다."""
    try:
        c_type = ai_config.get('type', 'lmstudio')
        c_url = ai_config.get('base_url', LM_STUDIO_API_URL)
        c_key = ai_config.get('api_key', 'lm-studio')
        c_model = ai_config.get('model', '').strip() or LM_STUDIO_MODEL
        c_client = AsyncOpenAI(
            base_url=c_url,
            api_key=c_key if c_key and c_key.strip() else 'lm-studio',
        )
        return c_client, c_model, f"AI 엔진 활성화: {c_type.upper()} ({c_model})"
    except Exception as e:
        return None, None, f"AI 클라이언트 초기화 실패: {e}"


async def _find_additional_vectors(client, model, scanned_urls: list, findings: list) -> list:
    """1차 분석 결과를 바탕으로 놓쳤을 수 있는 추가 공격 벡터를 탐색합니다.
    원본 요청/응답 데이터를 재전송하지 않고 URL 목록과 기존 결과 요약만 사용합니다."""
    if not scanned_urls:
        return []

    url_list_str = "\n".join(f"- {u}" for u in scanned_urls)
    found_summary = "\n".join(
        f"- [{f.get('severity','?')}] {f.get('title','?')} → {f.get('target','?')}"
        for f in findings if isinstance(f, dict)
    ) or "없음"

    prompt = f"""당신은 전문적인 보안 침투 테스트 전문가입니다.

아래는 자동화 도구가 수집한 엔드포인트 목록과, 1차 AI 분석에서 이미 식별된 취약점 목록입니다.

### 분석 대상 엔드포인트:
{url_list_str}

### 이미 식별된 취약점:
{found_summary}

### 요청:
위 정보를 바탕으로 1차 분석에서 **놓쳤을 가능성이 있는 추가 공격 벡터나 취약점**을 도출하십시오.
- 이미 식별된 항목과 중복되는 내용은 절대 포함하지 마십시오.
- 엔드포인트 간 연계 취약점(예: A에서 토큰 탈취 후 B에서 사용), 비즈니스 로직 취약점, 인증/인가 우회 시나리오 등을 중점적으로 검토하십시오.
- 추가 항목이 없다면 반드시 빈 배열 []만 반환하십시오.
- 모든 텍스트 필드는 한국어로 작성하십시오.

### 필수 JSON 구조:
[
  {{
    "title": "취약점 명칭 (또는 점검 권장 항목)",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "target": "URL 또는 파라미터 명칭",
    "description": "취약점 또는 예상 공격 접점에 대한 기술적 요약 및 가설",
    "evidence": "이 취약점을 의심하게 만든 근거",
    "steps": "1단계: ...\\n2단계: ...",
    "recommendation": "조치 방법 및 추가 진단 권고",
    "cwe": "CWE-ID (예: CWE-79)",
    "confidence": 0-100,
    "verified": false
  }}
]
"""
    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            stream=False,
            temperature=0.3
        )
        raw = response.choices[0].message.content or ""
        additional = extract_vulnerabilities(raw)
        result = []
        for f in additional:
            if isinstance(f, dict):
                f["source"] = "AI_Agent_B"
                f["verified"] = False
                result.append(f)
        return result
    except Exception:
        return []


async def _dedup_findings_with_ai(client, model, findings: list) -> list:
    """AI를 이용해 전체 findings에서 중복/유사 항목을 제거하고 정리된 목록을 반환합니다.
    파싱 실패 시 원본 findings를 그대로 반환합니다."""
    if len(findings) < 2:
        return findings

    findings_str = json.dumps(findings, ensure_ascii=False)
    prompt = f"""당신은 보안 전문가입니다.
아래는 여러 배치 AI 분석에서 수집된 취약점 목록입니다.

다음 기준으로 정리하십시오:
- 동일한 취약점 유형 + 동일 타겟 → 하나로 합치기 (confidence가 가장 높은 항목 유지)
- 표현만 다르고 실질적으로 같은 취약점 → 하나로 합치기
- 명확히 다른 취약점은 그대로 유지

원본 JSON 구조(title, severity, target, scanned_from, description, evidence, steps, recommendation, cwe, confidence, verified, source)를 그대로 유지하여 정리된 배열만 반환하십시오.

### 정리 대상 목록:
{findings_str}
"""
    try:
        response = await client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            stream=False,
            temperature=0.1
        )
        raw = response.choices[0].message.content or ""
        deduped = extract_vulnerabilities(raw)
        if deduped:
            # source 필드 보존
            for f in deduped:
                if isinstance(f, dict) and 'source' not in f:
                    f['source'] = 'AI_Agent_A'
            return deduped
    except Exception:
        pass
    return findings


def extract_vulnerabilities(raw_content):
    content = raw_content.strip()
    if content.startswith("```json"):
        content = content[len("```json"):].strip()
    if content.startswith("```"):
        content = content[len("```"):].strip()
    if content.endswith("```"):
        content = content[:-3].strip()

    found_list = []
    start_idx = content.find('[')
    end_idx = content.rfind(']')

    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        json_str = content[start_idx:end_idx + 1]
        try:
            parsed = json.loads(json_str)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            brace_count = 0
            start_ptr = -1
            for idx, char in enumerate(json_str):
                if char == '{':
                    if brace_count == 0:
                        start_ptr = idx
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_ptr != -1:
                        try:
                            found_list.append(json.loads(json_str[start_ptr:idx + 1]))
                        except json.JSONDecodeError:
                            pass
    else:
        brace_count = 0
        start_ptr = -1
        for idx, char in enumerate(content):
            if char == '{':
                if brace_count == 0:
                    start_ptr = idx
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and start_ptr != -1:
                    try:
                        found_list.append(json.loads(content[start_ptr:idx + 1]))
                    except json.JSONDecodeError:
                        pass
    return found_list


async def run_analysis_agent(
    target_url: str,
    session_dir: str,
    recon_data: Dict,
    headers: Dict = None,
    ai_config: Dict = None,
    user_specified: bool = False
):
    if is_cancelled(session_dir):
        return

    local_client = _get_default_client()
    local_model = LM_STUDIO_MODEL

    if ai_config:
        _c, _m, _msg = _init_ai_client(ai_config)
        if _c:
            local_client, local_model = _c, _m
        yield stream_log(session_dir, _msg, "AI")

    yield stream_log(session_dir, "정찰 데이터 기반 분석 대상 선별 및 전처리 시작", "AI", 80)

    all_requests = []

    endpoints = recon_data.get('endpoints', [])
    for ep in endpoints:
        await asyncio.sleep(0)
        req_raw = ep.get('request_raw')
        res_raw = ep.get('response_raw', "")

        if not req_raw:
            continue

        minimized_req = minimize_request_raw(req_raw) if ENABLE_REQUEST_COMPRESSION else req_raw

        req_parts = req_raw.split('\n\n', 1)
        r_body = req_parts[1] if len(req_parts) > 1 else ""
        context = extract_relevant_snippet(ep['url'], r_body, res_raw)

        all_requests.append({
            "url": ep['url'],
            "method": ep['method'],
            "source": ep.get('source', 'recon'),
            "raw_request": minimized_req,
            "response_context": context['response_context'],
        })

    if not all_requests:
        yield stream_log(session_dir, "분석 가능한 데이터가 없어 분석을 중단합니다.", "AI", 100)
        return

    if not user_specified:
        filtered_requests = []
        seen_structs = {}
        for req in all_requests:
            parsed = urllib.parse.urlparse(req['url'])
            path = parsed.path if parsed.path else "/"
            queries = urllib.parse.parse_qs(parsed.query)
            q_keys = ",".join(sorted(queries.keys()))
            struct_key = f"{req['method']}:{path}:{q_keys if q_keys else 'no_params'}"
            seen_structs[struct_key] = seen_structs.get(struct_key, 0) + 1
            if seen_structs[struct_key] <= 2:
                filtered_requests.append(req)
        all_requests = filtered_requests

    ai_target_list = [f"{req['method']}:{req['url']}" for req in all_requests]

    for req in all_requests:
        req.pop('method', None)
        req.pop('source', None)
        req.pop('url', None)

    scanned_from_map = {
        req['raw_request'].split('\n')[0].strip(): req
        for req in all_requests
        if req.get('raw_request')
    }

    save_tool_result(session_dir, "ai_input_full_requests", all_requests, indent=None)

    batches = []
    current_batch = []
    current_len = 0
    batch_size = 500000 if (ai_config and ai_config.get('type') == 'gemini') else AI_MAX_BATCH_SIZE

    max_per_batch = int((ai_config or {}).get('max_endpoints_per_batch', 0)) or None

    for req in all_requests:
        await asyncio.sleep(0)
        req_str = json.dumps(req, ensure_ascii=False)
        size_over = (current_len + len(req_str) > batch_size) and current_batch
        count_over = max_per_batch is not None and len(current_batch) >= max_per_batch
        if (size_over or count_over) and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_len = 0
        current_batch.append(req)
        current_len += len(req_str)
    if current_batch:
        batches.append(current_batch)

    yield stream_log(session_dir, f"AI 분석 엔진 가동: {len(all_requests)}개의 타겟을 {len(batches)}개의 배치로 그룹화하여 처리를 시작합니다.", "AI", 85)
    for i, b in enumerate(batches):
        yield stream_log(session_dir, f"Batch #{i+1} 가동 준비 완료: {len(b)}개의 요청 포함", "AI")

    all_findings = []
    seen_finding_keys: set = set()
    prev_findings_count = 0
    old_path = os.path.join(session_dir, "ai_findings.json")
    if os.path.exists(old_path):
        try:
            with open(old_path, 'r', encoding='utf-8') as f:
                all_findings = json.load(f)
                prev_findings_count = len(all_findings)
                seen_finding_keys = {
                    (f.get('title', ''), f.get('target', ''))
                    for f in all_findings if isinstance(f, dict)
                }
        except (json.JSONDecodeError, OSError):
            all_findings = []

    try:
        for i, batch in enumerate(batches):
            if is_cancelled(session_dir):
                break
            save_tool_result(session_dir, f"ai_input_batch_{i+1}", batch)
            yield stream_log(session_dir, f"AI 분석 배치 {i+1}/{len(batches)} 처리 중...", "AI", 85 + int((i / len(batches)) * 10))

            batch_str = json.dumps(batch, ensure_ascii=False)
            custom_prompt = (ai_config or {}).get('custom_prompt', '').strip()
            base_instructions = custom_prompt if custom_prompt else \
                """당신은 전문적인 보안 침투 테스트 전문가이자 취약점 분석가입니다.
다음 HTTP 요청/응답 컨텍스트를 분석하여 잠재적인 보안 취약점을 식별하십시오.

### 중요 지침:
- **단순히 확실한 취약점(Info-Leak 등) 뿐만 아니라, 추가 정밀 침투가 필요한 "잠재적 공격 벡터(Attack Vector)"도 포함하여 과감히 도출하십시오.**
- **모든 설명, 제목, 추천 사항 등 모든 텍스트 필드의 내용은 반드시 한국어로 작성하십시오.**"""
            instructions = base_instructions + "\n- 출력은 반드시 유효한 JSON 객체 리스트 형식이어야 합니다."
            prompt = instructions + f"""

### 필수 JSON 구조 (모든 텍스트 값은 한국어):
[
  {{
    "title": "취약점 명칭 (또는 점검 권장 항목)",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "target": "URL 또는 파라미터 명칭",
    "scanned_from": "취약점을 발견한 raw_request의 첫 줄 (예: GET https://example.com/path HTTP/1.1)",
    "description": "취약점 또는 예상 공격 접점에 대한 기술적 요약 및 가설",
    "evidence": "취약점을 의심하게 만든 페이로드 또는 응답의 특정 코드 특징",
    "steps": "1단계: ...\\n2단계: ... (마크다운 형식의 재현 단계)",
    "recommendation": "조치 방법 및 추가 진단 권고 (마크다운 형식)",
    "cwe": "CWE-ID (예: CWE-79)",
    "ttp": "MITRE ATT&CK TTP ID (예: T1190, T1059.001)",
    "owasp": "OWASP TOP10 2025 분류 (예: A01:2025, A03:2025)",
    "confidence": 0-100,
    "verified": false
  }}
]

### 분석할 컨텍스트:
{batch_str}
"""

            try:
                response = await local_client.chat.completions.create(
                    model=local_model,
                    messages=[{"role": "user", "content": prompt}],
                    stream=True,
                    temperature=0.2
                )

                full_content = ""
                async for chunk in response:
                    if is_cancelled(session_dir):
                        break
                    delta = chunk.choices[0].delta
                    if delta.content:
                        full_content = full_content + delta.content
                        yield stream_chunk(session_dir, delta.content)

                findings = await asyncio.to_thread(extract_vulnerabilities, full_content)

                findings_file = os.path.join(session_dir, "ai_findings.json")
                if os.path.exists(findings_file):
                    try:
                        with open(findings_file, "r", encoding="utf-8") as f:
                            all_findings = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        pass

                newly_added = 0
                for f in findings:
                    if not isinstance(f, dict):
                        continue
                    await asyncio.sleep(0)

                    conf = f.get("confidence", 0)
                    if isinstance(conf, str) and conf.isdigit():
                        conf = int(conf)
                    if not isinstance(conf, (int, float)):
                        conf = 0

                    dup_key = (f.get('title', ''), f.get('target', ''))
                    if dup_key in seen_finding_keys:
                        continue
                    seen_finding_keys.add(dup_key)

                    f["source"] = "AI_Agent_A"
                    f["verified"] = False

                    scanned_from_key = (f.get("scanned_from") or "").strip()
                    matched_req = scanned_from_map.get(scanned_from_key)
                    if matched_req:
                        f["_raw_request"] = matched_req.get("raw_request", "")
                        f["_response_context"] = matched_req.get("response_context", "")

                    all_findings.append(f)
                    newly_added += 1

                    yield stream_log(session_dir, f"잠재적 취약점 식별: '{f.get('title')}'", "System")
                    yield stream_custom(session_dir, {"type": "ai_card", "data": f})

                if newly_added > 0:
                    save_tool_result(session_dir, "ai_findings", all_findings)

            except Exception as e:
                yield stream_log(session_dir, f"배치 {i+1} 결과 처리 중 에러: {str(e)}", "AI")
    except Exception as e:
        yield stream_log(session_dir, f"AI 분석 중 치명적 오류: {e}", "AI")
    else:
        if not is_cancelled(session_dir):
            # 추가 공격 벡터 탐색 패스
            yield stream_log(session_dir, "추가 공격 벡터 탐색 중... (1차 결과 기반 보완 분석)", "AI", 95)
            scanned_urls = ai_target_list
            additional = await _find_additional_vectors(local_client, local_model, scanned_urls, all_findings)

            newly_added_extra = 0
            for f in additional:
                if not isinstance(f, dict):
                    continue
                dup_key = (f.get('title', ''), f.get('target', ''))
                if dup_key in seen_finding_keys:
                    continue
                seen_finding_keys.add(dup_key)
                all_findings.append(f)
                newly_added_extra += 1
                yield stream_log(session_dir, f"추가 벡터 식별: '{f.get('title')}'", "System")
                yield stream_custom(session_dir, {"type": "ai_card", "data": f})

            if newly_added_extra > 0:
                yield stream_log(session_dir, f"추가 벡터 탐색 완료: {newly_added_extra}개 항목 추가됨", "AI")
            else:
                yield stream_log(session_dir, "추가 벡터 탐색 완료: 새로운 항목 없음", "AI")

            # 최종 중복 제거 패스 (추가 벡터 탐색 완료 후)
            if len(all_findings) >= 2:
                yield stream_log(session_dir, f"최종 중복 제거 패스 실행 중... ({len(all_findings)}개 항목 정리)", "AI", 97)
                before_count = len(all_findings)
                all_findings = await _dedup_findings_with_ai(local_client, local_model, all_findings)
                removed = before_count - len(all_findings)
                if removed > 0:
                    yield stream_log(session_dir, f"중복 제거 완료: {removed}개 항목 통합됨 ({len(all_findings)}개 남음)", "AI")

    finally:
        save_tool_result(session_dir, "ai_findings", all_findings)
        new_count = len(all_findings) - prev_findings_count
        total_count = len(all_findings)
        if prev_findings_count > 0:
            yield stream_log(session_dir, f"보안 분석 완료: 이번 스캔에서 {new_count}개 신규 식별 (누적 총 {total_count}개).", "AI", 100)
        else:
            yield stream_log(session_dir, f"보안 분석 완료: 총 {total_count}개의 잠재적 취약점이 식별되었습니다.", "AI", 100)
        yield stream_custom(session_dir, {"type": "scan_complete", "data": all_findings})
