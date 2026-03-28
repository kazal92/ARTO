import os
import json
import urllib.parse
import datetime
import asyncio
import re
from typing import Dict, List, Optional
from openai import AsyncOpenAI

# 전역 설정
LM_STUDIO_API_URL = "http://192.168.1.100:1234/v1"
MODEL_NAME = "qwen/qwen3.5-9b"

client = AsyncOpenAI(base_url=LM_STUDIO_API_URL, api_key="not-needed")

ROOT_SCAN_DIR = os.path.abspath("results/scan")
ROOT_PRECHECK_DIR = os.path.abspath("results/precheck")
for d in [ROOT_SCAN_DIR, ROOT_PRECHECK_DIR]:
    if not os.path.exists(d):
        os.makedirs(d)

# AI 분석에서 제외할 정적 파일 확장자
STATIC_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp', '.css',  '.map', '.woff', '.woff2', '.ttf', '.eot',
    '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.flac', '.aac', '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z'
}

def is_static_file(url: str) -> bool:
    """URL의 확장자가 정적 파일인지 확인합니다."""
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS) or path.endswith('.js')
# 세션별 취소 상태 관리
SCAN_SESSIONS_CANCELLED = set()

def is_cancelled(session_dir: str):
    return session_dir in SCAN_SESSIONS_CANCELLED

from tools import run_ffuf, run_zap_spider, minimize_request_raw, get_heuristic_score, extract_relevant_snippet


def _safe_int(val, default):
    """ZAP API 응답의 숫자 필드 파싱 ('6671 Bytes' 같은 문자열 포함 처리)."""
    if not val: return default
    if isinstance(val, int): return val
    try:
        digits = "".join(filter(str.isdigit, str(val)))
        return int(digits) if digits else default
    except:
        return default

def _collect_endpoint(res: dict, seen_keys: set, endpoints: list, source: str, session_dir: str, log_fn=None, extra_fields: dict = None):
    """단일 엔드포인트 dict를 중복 확인 후 endpoints 리스트에 추가합니다.
    로그 문자열을 반환하며, 추가되지 않은 경우 None 반환.
    log_fn: res를 받아 로그 메시지 문자열을 반환하는 콜백 (없으면 기본 형식 사용).
    extra_fields: 추가할 필드 dict (없으면 기본 필드만).
    """
    u = res.get('url')
    if not u:
        return None
    m = res.get('method', 'GET').upper()
    key = f"{m}:{u}"
    if key in seen_keys or is_static_file(u):
        return None
    entry = {
        "url": u,
        "method": m,
        "source": source,
        "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
    }
    if extra_fields:
        entry.update(extra_fields)
    endpoints.append(entry)
    seen_keys.add(key)
    msg = log_fn(res, m, u) if log_fn else f"[{source}] 식별: {m} {u}"
    return stream_log(session_dir, msg, 'Recon')

def _init_ai_client(ai_config: dict):
    """ai_config dict로부터 AsyncOpenAI 클라이언트와 모델명을 초기화합니다.
    반환: (client, model_name, log_message)
    실패 시: (None, None, error_message)
    """
    try:
        c_type = ai_config.get('type', 'lmstudio')
        c_url = ai_config.get('base_url', LM_STUDIO_API_URL)
        c_key = ai_config.get('api_key', 'not-needed')
        c_model = ai_config.get('model', '').strip()
        if not c_model:
            c_model = MODEL_NAME
        c_client = AsyncOpenAI(
            base_url=c_url,
            api_key=c_key if c_key and c_key.strip() else 'not-needed',
        )
        return c_client, c_model, f"AI 엔진 활성화: {c_type.upper()} ({c_model})"
    except Exception as e:
        return None, None, f"AI 클라이언트 초기화 실패: {e}"

# 🔍 AI 분석 전송 시 요청 패킷 압축 여부 (토글 스위치)
ENABLE_REQUEST_COMPRESSION = True

def extract_vulnerabilities(raw_content):
    content = raw_content.strip()
    if content.startswith("```json"):
        content = content[len("```json"):].strip()
    if content.startswith("```"):
        content = content[len("```"):].strip()
    if content.endswith("```"):
        content = content[:-3].strip()
    
    found_list = []
    # 최외곽 [ ] 사이 텍스트만 추출 시도
    start_idx = content.find('[')
    end_idx = content.rfind(']')
    
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        json_str = content[start_idx:end_idx+1]
        try:
            # 한 번에 파싱 시도
            parsed = json.loads(json_str)
            if isinstance(parsed, list): return parsed
            if isinstance(parsed, dict): return [parsed]
        except:
            # 배열 파싱 실패 시, 개별 객체 {} 단위 추출
            brace_count = 0
            start_ptr = -1
            for idx, char in enumerate(json_str):
                if char == '{':
                    if brace_count == 0: start_ptr = idx
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0 and start_ptr != -1:
                        try:
                            found_list.append(json.loads(json_str[start_ptr:idx+1]))
                        except: pass
    else:
        # [ ] 가 없는 경우 {} 매칭 시도
        brace_count = 0
        start_ptr = -1
        for idx, char in enumerate(content):
            if char == '{':
                if brace_count == 0: start_ptr = idx
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0 and start_ptr != -1:
                    try:
                        found_list.append(json.loads(content[start_ptr:idx+1]))
                    except: pass
    return found_list

def get_session_dir(project_name: str, p_type: str = "scan"):
    safe_name = re.sub(r'[^a-zA-Z0-9_\-가-힣]', '_', project_name) if project_name else "unnamed"
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = ROOT_SCAN_DIR if p_type == "scan" else ROOT_PRECHECK_DIR
    session_dir = os.path.join(base_dir, f"{safe_name}_{timestamp}")
    if not os.path.exists(session_dir):
        os.makedirs(session_dir)
    return session_dir

def find_session_dir(session_id: str):
    p1 = os.path.join(ROOT_SCAN_DIR, session_id)
    if os.path.exists(p1): return p1
    p2 = os.path.join(ROOT_PRECHECK_DIR, session_id)
    if os.path.exists(p2): return p2
    legacy = os.path.join("results", session_id)
    if os.path.exists(legacy) and os.path.isdir(legacy) and session_id not in ["scan", "precheck"]:
        return legacy
    return None

def save_log(session_dir: str, log_data: str):
    try:
        log_file = os.path.join(session_dir, "scan_log.jsonl")
        with open(log_file, "a", encoding="utf-8") as f:
            f.write(log_data + "\n")
    except Exception:
        pass

def save_tool_result(session_dir: str, tool_name: str, data: any, indent: Optional[int] = 2):
    try:
        save_path = os.path.join(session_dir, f"{tool_name}.json")
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
        return save_path
    except Exception:
        return None

def stream_log(session_dir: str, message: str, agent_type: str = "system", progress: Optional[int] = None):
    log_data = {"type": "log", "agent": agent_type, "message": message}
    if progress is not None:
        log_data["progress"] = progress
    log_json = json.dumps(log_data)
    save_log(session_dir, log_json)
    return log_json

def stream_custom(session_dir: str, data: dict):
    log_json = json.dumps(data)
    save_log(session_dir, log_json)
    return log_json

def stream_chunk(session_dir: str, content: str, progress: int = None):
    chunk_data = {"type": "chunk", "content": content}
    if progress is not None:
        chunk_data["progress"] = progress
    return stream_custom(session_dir, chunk_data)

async def run_recon_agent(target_url: str, session_dir: str, headers: Dict = None, enable_deep_recon: bool = True, enable_zap: bool = True, enable_ffuf: bool = True, ffuf_options: str = '', ffuf_wordlist: str = ''):
    yield stream_log(session_dir, f'정찰 시작: {target_url}', 'Recon', 5)

    recon_results = {'target': target_url, 'endpoints': []}

    from zap_client import ZAPClient
    zap = ZAPClient()
    seen_keys = set()

    # 1. ZAP Spider
    if not enable_zap:
        yield stream_log(session_dir, '1. ZAP Spider가 비활성화되어 건너뜁니다.', 'Recon', 10)
    else:
        yield stream_log(session_dir, '1. OWASP ZAP Spider 탐색 시작...', 'Recon', 10)
        async for update in run_zap_spider(target_url, session_dir):
            if is_cancelled(session_dir): break
            utype = update.get('type')
            if utype == 'progress':
                yield stream_log(session_dir, update['msg'], 'Recon', update['progress'])
            elif utype == 'command':
                yield stream_log(session_dir, update['cmd'], 'Command')
            elif utype in ('item', 'result'):
                items = [update['data']] if utype == 'item' else update['data']
                for res in items:
                    log = _collect_endpoint(res, seen_keys, recon_results['endpoints'], "zap_spider", session_dir,
                                            log_fn=lambda r, m, u: f"[ZAP] 식별: {m} {u}")
                    if log: yield log

    # 2. FFuF Fuzzing
    if not enable_ffuf:
        yield stream_log(session_dir, '2. ffuf 퍼징이 비활성화되어 건너뜁니다.', 'Recon', 50)
    else:
        yield stream_log(session_dir, '2. FFuF 디렉토리/파일 퍼징 중...', 'Recon', 50)
        async for update in run_ffuf(target_url, session_dir, headers, ffuf_options=ffuf_options, ffuf_wordlist=ffuf_wordlist):
            if is_cancelled(session_dir): break
            utype = update.get('type')
            if utype == 'progress':
                yield stream_log(session_dir, update['msg'], 'Recon', update['progress'])
            elif utype == 'command':
                yield stream_log(session_dir, update['cmd'], 'Command')
            elif utype in ('item', 'result'):
                items = [update['data']] if utype == 'item' else update['data']
                for res in items:
                    log = _collect_endpoint(res, seen_keys, recon_results['endpoints'], "ffuf", session_dir,
                                            log_fn=lambda r, m, u: f'[FFuF] 식별: {m} {u} (상태: {r.get("status")})',
                                            extra_fields={'status': res.get('status')})
                    if log: yield log

    # 3. 추가 정찰: FFuF로 발견된 새로운 경로들에 대해 다시 ZAP Spider 실행 (Recursive Recon)
    if not enable_deep_recon:
        yield stream_log(session_dir, "[Recon] 재귀적 심층 정찰이 비활성화되어 탐색을 종료합니다.", "Recon", 70)
    elif not enable_ffuf:
        yield stream_log(session_dir, "[Recon] ffuf가 비활성화되어 심층 탐색을 건너뜁니다.", "Recon", 70)
    else:
        new_ffuf_endpoints = [ep for ep in recon_results['endpoints'] if ep.get('source') == 'ffuf']
        
        # 💡 와일드카드(False Positive) 폭탄 방지 임계값 적용
        if len(new_ffuf_endpoints) > 20:
            yield stream_log(session_dir, f"[Warning] 발견된 신규 경로가 너무 많습니다 ({len(new_ffuf_endpoints)}개). 와일드카드 응답이 의심되어 재귀적 크롤링을 건너뜁니다.", "Recon", 70)
            new_ffuf_endpoints = [] # 루프 진입 방지
            
        if not new_ffuf_endpoints:
            if not is_cancelled(session_dir):
                yield stream_log(session_dir, "[Recon] 분석 가능한 신규 공격 요인이 식별되지 않아 심층 탐색을 종료합니다.", "Recon", 70)
        else:
            yield stream_log(session_dir, f"[Recon] {len(new_ffuf_endpoints)}개의 신규 경로를 기반으로 재귀적 자산 탐색을 시작합니다.", "Recon", 70)
        
        # 발견된 모든 FFuF 경로를 ZAP Spider의 새로운 시드로 추가 (하나씩 돌리기보다 ZAP 내부적으로 처리하게 유도 가능하지만 여기서는 순차/병렬 제어)
        for ep in new_ffuf_endpoints:
            if is_cancelled(session_dir): break
            u = ep.get('url')
            yield stream_log(session_dir, f'[Deep Recon] 유효 경로 {u}에 대한 구조 분석 및 하위 노드 탐색 중...', 'Recon')
            
            async for update in run_zap_spider(u, session_dir):
                if is_cancelled(session_dir): break
                utype = update.get('type')
                
                if utype == 'progress':
                    yield stream_log(session_dir, update['msg'], 'Recon', update['progress'])
                elif utype == 'command':
                    yield stream_log(session_dir, update['cmd'], 'Command')
                elif utype in ('item', 'result'):
                    items = [update['data']] if utype == 'item' else update['data']
                    for res in items:
                        log = _collect_endpoint(res, seen_keys, recon_results['endpoints'], "zap_spider_deep", session_dir,
                                                log_fn=lambda r, m, u: f'[Discovery] 신규 엔드포인트 자산 식별: {m} {u}')
                        if log: yield log

    # FINAL SYNC: ZAP 히스토리 + FFuF 결과를 전수 조사하여 모든 엔드포인트 동기화 (122개+ 누락 방지)
    try:
        yield stream_log(session_dir, "[Sync] 정찰 데이터 누락 방지를 위한 전수 정합성 검증 및 통합 중...", "Recon")
        # O(1) 업데이트를 위한 인덱스 (key = "METHOD:URL" → ep dict 참조)
        endpoint_index = {f"{ep['method']}:{ep['url']}": ep for ep in recon_results['endpoints']}
        
        # 1. ZAP 히스토리 전수 조사 (최우선순위 & 가장 상세한 로그)
        all_zap_history = await zap.get_all_messages(target_url)
        for msg in all_zap_history:
            req_h = msg.get("requestHeader", "")
            if not req_h: continue
            
            f_line = req_h.split('\n')[0]
            try:
                parts = f_line.split(' ', 2)
                h_m = parts[0].upper()
                h_u = parts[1]
            except:
                h_m = msg.get("requestMethod", "GET").upper()
                h_u = msg.get("url")
            
            if not h_u: continue
            if not h_u.startswith("http"): h_u = target_url.rstrip("/") + h_u

            if is_static_file(h_u): continue

            # HTTP 0 / Connection Failure 필터링
            res_h = msg.get("responseHeader", "")
            if res_h.startswith("HTTP/1.1 0") or res_h.startswith("HTTP/1.0 0") or res_h.startswith("HTTP/1.1 502"): 
                continue

            key = f"{h_m}:{h_u}"
            
            # ZAP에서 요청/응답 전문 추출 및 상태 코드 파싱
            req_raw = (msg.get("requestHeader") or "") + (msg.get("requestBody") or "")
            res_raw = (msg.get("responseHeader") or "") + (msg.get("responseBody") or "")
            
            h_req_size = _safe_int(msg.get("requestSize"), len(req_raw))
            h_res_size = _safe_int(msg.get("responseSize"), len(res_raw))
            
            # 💡 ZAP API에서 statusCode를 별도로 제공하지 않을 경우 헤더에서 파싱 (강화된 파싱)
            h_status = "-"
            if res_raw:
                try:
                    # HTTP/1.1 200 OK 등 첫 줄에서 두 번째 단어(코드) 추출
                    first_line = res_raw.split('\n')[0].strip()
                    if first_line.startswith("HTTP/"):
                        status_candidate = first_line.split(' ')[1]
                        if status_candidate.isdigit():
                            h_status = status_candidate
                except: pass

            if key not in seen_keys:
                ep = {
                    "url": h_u,
                    "method": h_m,
                    "status": h_status,
                    "source": "zap_history",
                    "id": msg.get("id"),
                    "request_raw": req_raw,
                    "response_raw": res_raw,
                    "requestSize": h_req_size,
                    "responseSize": h_res_size,
                    "time": datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
                }
                recon_results['endpoints'].append(ep)
                endpoint_index[key] = ep
                seen_keys.add(key)
            else:
                # 이미 리스트에 있다면 ZAP 로그로 상태/데이터 덮어씌움
                ep = endpoint_index[key]
                ep['request_raw'] = req_raw
                ep['response_raw'] = res_raw
                ep['source'] = "zap_history"
                if h_status != '-':
                    ep['status'] = h_status
                ep['requestSize'] = h_req_size
                ep['responseSize'] = h_res_size

        # 2. FFuF 응답 폴더 전수 조사 (ZAP 히스토리에 없는 것만 보충)
        ffuf_res_dir = os.path.join(session_dir, "ffuf", "responses")
        if os.path.exists(ffuf_res_dir):
            import codecs
            files = await asyncio.to_thread(os.listdir, ffuf_res_dir)
            for fname in sorted(files):
                fpath = os.path.join(ffuf_res_dir, fname)
                if not os.path.isfile(fpath): continue
                try:
                    with codecs.open(fpath, 'r', 'utf-8', 'ignore') as f:
                        full_content = f.read()
                    first_line = full_content[:2048].split('\n')[0]
                    parts = first_line.split()
                    if len(parts) >= 2:
                        m, p = parts[0].upper(), parts[1]
                        if not p.startswith("/"): p = "/" + p
                        u = target_url.rstrip("/") + p

                        if is_static_file(u): continue

                        key = f"{m}:{u}"

                        # 이미 ZAP 로그에서 더 좋은 품질의 데이터를 가져왔다면 스킵
                        if key in seen_keys and endpoint_index.get(key, {}).get('request_raw'):
                            continue

                        req_raw = f"{m} {p} HTTP/1.1\nHost: {urllib.parse.urlparse(target_url).netloc}\n"
                        res_raw = full_content

                        if key not in seen_keys:
                            ep = {
                                "url": u,
                                "method": m,
                                "source": "ffuf_disk",
                                "request_raw": req_raw,
                                "response_raw": res_raw,
                                "requestSize": len(req_raw),
                                "responseSize": len(res_raw),
                                "time": datetime.datetime.now().strftime("%H:%M:%S")
                            }
                            recon_results['endpoints'].append(ep)
                            endpoint_index[key] = ep
                            seen_keys.add(key)
                        else:
                            # 리스트에는 있지만 raw 데이터가 없었던 경우에만 업데이트
                            ep = endpoint_index[key]
                            ep['request_raw'] = req_raw
                            ep['response_raw'] = res_raw
                            ep['requestSize'] = len(req_raw)
                            ep['responseSize'] = len(res_raw)
                except: pass

        yield stream_log(session_dir, f"[Complete] 정찰 데이터 통합 완료. 최종적으로 {len(recon_results['endpoints'])}개의 유효 공격 데이터를 확보했습니다.", "Recon")
    except Exception as e:
        print(f"Final sync error: {e}")

    yield stream_log(session_dir, f'[Recon] 정찰 단계를 성공적으로 완료하였습니다. (총 {len(recon_results["endpoints"])}개의 공격 접점 확보)', 'Recon', 100)
    save_tool_result(session_dir, 'recon_map', recon_results)
    yield stream_custom(session_dir, {'type': 'recon_result', 'data': recon_results})

async def run_analysis_agent(target_url: str, session_dir: str, recon_data: Dict, headers: Dict = None, ai_config: Dict = None):
    if is_cancelled(session_dir): return

    # AI 클라이언트 동적 설정
    local_client = client
    local_model = MODEL_NAME

    if ai_config:
        _c, _m, _msg = _init_ai_client(ai_config)
        if _c:
            local_client, local_model = _c, _m
        yield stream_log(session_dir, _msg, "AI")

    yield stream_log(session_dir, "정찰 데이터 기반 분석 대상 선별 및 전처리 시작", "AI", 80)

    # 수동 AI 타겟 로드 (있으면 해당 항목만 분석)
    manual_targets = None
    manual_targets_path = os.path.join(session_dir, "manual_targets.json")
    if os.path.exists(manual_targets_path):
        try:
            with open(manual_targets_path, "r", encoding="utf-8") as _f:
                manual_targets = set(json.load(_f))
            yield stream_log(session_dir, f"[AI] 수동 지정 타겟 {len(manual_targets)}개 로드 - 해당 항목만 분석합니다.", "AI")
        except Exception:
            manual_targets = None

    all_requests = []

    # 1. 정찰 데이터(recon_map.json)로부터 분석 대상 추출
    endpoints = recon_data.get('endpoints', [])
    for ep in endpoints:
        await asyncio.sleep(0)
        req_raw = ep.get('request_raw')
        res_raw = ep.get('response_raw', "")

        if not req_raw: continue

        # 수동 타겟이 있으면 해당 항목만 통과
        if manual_targets is not None:
            ep_key = f"{ep.get('method', 'GET')}:{ep['url']}"
            if ep_key not in manual_targets:
                continue

        if is_static_file(ep['url']): continue

        # AI용 데이터 전처리 (On-the-fly)
        minimized_req = minimize_request_raw(req_raw) if ENABLE_REQUEST_COMPRESSION else req_raw
        
        # 요청 헤더와 바디 분리 (Snippet 추출용)
        req_parts = req_raw.split('\n\n', 1)
        r_body = req_parts[1] if len(req_parts) > 1 else ""
        context = extract_relevant_snippet(ep['url'], r_body, res_raw)
        
        # 응답 코드 추출 (필터링 및 우선순위 점수용)
        res_status = 200
        if res_raw:
            try:
                # 첫 줄에서 공백 기준 두 번째 항목(상태 코드)을 파싱
                status_line = res_raw.lstrip().split('\n')[0]
                if "HTTP" in status_line and " " in status_line:
                    res_status = int(status_line.split(" ")[1])
            except:
                res_status = 200

        # AI 분석 대상 필터링: 404 Not Found만 분석 대상에서 제외하고, 401/403/500등은 권한 우회 및 인젝션 분석을 위해 통과시킴
        if res_status == 404:
            continue

        all_requests.append({
            "url": ep['url'],
            "method": ep['method'],
            "source": ep.get('source', 'recon'),
            "raw_request": minimized_req,
            "response_context": context['response_context'],
            "score": get_heuristic_score(ep['method'], ep['url'], body=r_body, res_status=res_status)
        })

    if not all_requests:
        yield stream_log(session_dir, "분석 가능한 데이터가 없어 분석을 중단합니다.", "AI", 100)
        return

    # 2. 중복 제거 및 필터링 (동일 구조 경로 최대 1개로 조정)
    unique_requests = []
    seen_exact = set()
    for req in all_requests:
        exact_key = f"{req['method']}:{req['url']}"
        if exact_key not in seen_exact:
            unique_requests.append(req)
            seen_exact.add(exact_key)
    
    unique_requests.sort(key=lambda x: (-x.get('score', 0), x.get('url', '')))

    filtered_requests = []
    seen_structs = {}
    for req in unique_requests:
        parsed = urllib.parse.urlparse(req['url'])
        path = parsed.path if parsed.path else "/"
        # 쿼리 매개변수 키 명칭 추출하여 소팅 조립 (가장 정확한 구조 키)
        queries = urllib.parse.parse_qs(parsed.query)
        q_keys = ",".join(sorted(queries.keys()))
        
        struct_key = f"{req['method']}:{path}:{q_keys if q_keys else 'no_params'}"
        
        seen_structs[struct_key] = seen_structs.get(struct_key, 0) + 1
        # 개선 사양: 인자 조합이 동일할 때만 3개로 엄격 캡핑 (중복 감소 + 표면 누수 방지)
        if seen_structs[struct_key] <= 2:
            filtered_requests.append(req)
            
    all_requests = filtered_requests

    # AI Target 정보 공유 (필드 제거 전 수행)
    ai_target_list = [f"{req['method']}:{req['url']}" for req in all_requests]
    save_tool_result(session_dir, "ai_targets", ai_target_list)
    yield stream_custom(session_dir, {"type": "ai_targets", "data": ai_target_list})

    # 3. 가공된 데이터 기록 (사용자 요청: method, source, url 필드 제외 및 압축 저장)
    for req in all_requests:
        req.pop('method', None)
        req.pop('source', None)
        req.pop('url', None)

    # ai_input_full_requests.json은 용량 최적화를 위해 indent 없이 저장
    save_tool_result(session_dir, "ai_input_full_requests", all_requests, indent=None)

    # 4. 단일/복수 배치 구성
    batches = []
    current_batch = []
    current_len = 0
    MAX_BATCH_SIZE = 8000
    if ai_config and ai_config.get('type') == 'gemini':
        MAX_BATCH_SIZE = 500000

    for req in all_requests:
        await asyncio.sleep(0) # 양보 포인트
        req_str = json.dumps(req, ensure_ascii=False)
        if current_len + len(req_str) > MAX_BATCH_SIZE and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_len = 0
        current_batch.append(req)
        current_len = current_len + len(req_str)
    if current_batch:
        batches.append(current_batch)

    yield stream_log(session_dir, f"AI 분석 엔진 가동: {len(all_requests)}개의 타겟을 {len(batches)}개의 배치로 그룹화하여 처리를 시작합니다.", "AI", 85)
    for i, b in enumerate(batches):
        yield stream_log(session_dir, f"Batch #{i+1} 가동 준비 완료: {len(b)}개의 요청 포함", "AI")

    all_findings = []
    prev_findings_count = 0
    # 💡 누적(Merge) 방식 적용: 기존 ai_findings.json이 존재하면 불러와 초기화합니다.
    old_path = os.path.join(session_dir, "ai_findings.json")
    if os.path.exists(old_path):
        try:
            with open(old_path, 'r', encoding='utf-8') as f:
                all_findings = json.load(f)
                prev_findings_count = len(all_findings)
        except:
            all_findings = []
    try:
        for i, batch in enumerate(batches):
            if is_cancelled(session_dir): break
            save_tool_result(session_dir, f"ai_input_batch_{i+1}", batch)
            yield stream_log(session_dir, f"AI 분석 배치 {i+1}/{len(batches)} 처리 중...", "AI", 85 + int((i/len(batches))*10))
            
            batch_str = json.dumps(batch, ensure_ascii=False)
            # 4. AI 분석용 메시지 구성 (상세 보고 형식 페르소나 강화, 결과는 한국어 요구)
            prompt = f"""당신은 전문적인 보안 침투 테스트 전문가이자 취약점 분석가입니다.
다음 HTTP 요청/응답 컨텍스트를 분석하여 잠재적인 보안 취약점을 식별하십시오.

### 중요 지침:
- **단순히 확실한 취약점(Info-Leak 등) 뿐만 아니라, 추가 정밀 침투가 필요한 "잠재적 공격 벡터(Attack Vector)"도 포함하여 과감히 도출하십시오.**
- **모든 설명, 제목, 추천 사항 등 모든 텍스트 필드의 내용은 반드시 한국어로 작성하십시오.**
- 출력은 반드시 유효한 JSON 객체 리스트 형식이어야 합니다.

### 필수 JSON 구조 (모든 텍스트 값은 한국어):
[
  {{
    "title": "취약점 명칭 (또는 점검 권장 항목)",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "target": "URL 또는 파라미터 명칭",
    "description": "취약점 또는 예상 공격 접점에 대한 기술적 요약 및 가설",
    "evidence": "취약점을 의심하게 만든 페이로드 또는 응답의 특정 코드 특징",
    "steps": "1단계: ...\\n2단계: ... (마크다운 형식의 재현 단계)",
    "recommendation": "조치 방법 및 추가 진단 권고 (마크다운 형식)",
    "cwe": "CWE-ID (예: CWE-79)",
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
                    if is_cancelled(session_dir): break
                    delta = chunk.choices[0].delta
                    if delta.content:
                        full_content = full_content + delta.content
                        yield stream_chunk(session_dir, delta.content)
                
                # 무거운 연산을 스레드로 보냄
                findings = await asyncio.to_thread(extract_vulnerabilities, full_content)
                
                # 💡 레이스 컨디션 방지: 사용자가 웹 UI에서 삭제/수정한 최신의 내역을 파일에서 불러옵니다.
                findings_file = os.path.join(session_dir, "ai_findings.json")
                if os.path.exists(findings_file):
                    try:
                        with open(findings_file, "r", encoding="utf-8") as f:
                            all_findings = json.load(f)
                    except: pass

                newly_added = 0
                for f in findings:
                    if not isinstance(f, dict): continue
                    await asyncio.sleep(0) # 양보 포인트
                    
                    conf = f.get("confidence", 0)
                    if isinstance(conf, str) and conf.isdigit(): conf = int(conf)
                    if not isinstance(conf, (int, float)): conf = 0
                    
                    # 💡 누적 시 중복 체크: 타이틀과 타겟이 같으면 스킵합니다.
                    is_dup = any(old_f.get('title') == f.get('title') and old_f.get('target') == f.get('target') for old_f in all_findings)
                    if is_dup: continue

                    f["source"] = "AI_Agent_A"
                    f["verified"] = False
                    all_findings.append(f)
                    newly_added += 1
                    
                    yield stream_log(session_dir, f"잠재적 취약점 식별: '{f.get('title')}'", "System")
                    yield stream_custom(session_dir, {"type": "ai_card", "data": f})
                
                # 배치 하나 끝날 때마다 중간 저장 (누락 방지)
                if newly_added > 0:
                    save_tool_result(session_dir, "ai_findings", all_findings)
                    
            except Exception as e:
                yield stream_log(session_dir, f"배치 {i+1} 결과 처리 중 에러: {str(e)}", "AI")
    except Exception as e:
        yield stream_log(session_dir, f"AI 분석 중 치명적 오류: {e}", "AI")

    finally:
        save_tool_result(session_dir, "ai_findings", all_findings)
        new_count = len(all_findings) - prev_findings_count
        total_count = len(all_findings)
        if prev_findings_count > 0:
            yield stream_log(session_dir, f"보안 분석 완료: 이번 스캔에서 {new_count}개 신규 식별 (누적 총 {total_count}개).", "AI", 100)
        else:
            yield stream_log(session_dir, f"보안 분석 완료: 총 {total_count}개의 잠재적 취약점이 식별되었습니다.", "AI", 100)
        yield stream_custom(session_dir, {"type": "scan_complete", "data": all_findings})

async def analyze_selected_packets(packets: List[Dict], ai_config: Dict = None, session_dir: str = "") -> List[Dict]:
    """선택된 ZAP 히스토리 패킷들을 AI로 분석합니다."""
    local_client = client
    local_model = MODEL_NAME

    if ai_config:
        _c, _m, _msg = _init_ai_client(ai_config)
        if _c:
            local_client, local_model = _c, _m
        else:
            print(_msg)

    processed_requests = []
    for ep in packets:
        req_h = ep.get('requestHeader', '')
        req_b = ep.get('requestBody', '')
        res_h = ep.get('responseHeader', '')
        res_b = ep.get('responseBody', '')
        
        req_raw = req_h + req_b
        res_raw = res_h + res_b
        url = ep.get('url', '')
        
        method = "GET"
        if req_h:
             first_line = req_h.split('\n')[0]
             try: method = first_line.split(' ')[0].upper()
             except: method = ep.get("requestMethod", "GET").upper()

        if not req_raw: continue

        minimized_req = minimize_request_raw(req_raw) if ENABLE_REQUEST_COMPRESSION else req_raw
        
        req_parts = req_raw.split('\n\n', 1)
        r_body = req_parts[1] if len(req_parts) > 1 else ""
        context = extract_relevant_snippet(url, r_body, res_raw)
        
        processed_requests.append({
            "url": url,
            "method": method,
            "raw_request": minimized_req,
            "response_context": context['response_context']
        })

    if not processed_requests:
        return []

    prompt = f"""당신은 전문적인 보안 침투 테스트 전문가이자 취약점 분석가입니다.
다음 HTTP 요청/응답 컨텍스트를 분석하여 잠재적인 보안 취약점을 식별하십시오.
### 중요 지침:
- **생각 및 추론 과정(Reasoning/Thinking)을 절대 생성하거나 출력하지 마십시오.** 오직 요구된 결과물만 반환하십시오.
- **모든 설명, 제목, 추천 사항 등 모든 텍스트 필드의 내용은 반드시 한국어로 작성하십시오.**
- 출력은 반드시 유효한 JSON 객체 리스트 형식이어야 합니다.

### 필수 JSON 구조 (모든 텍스트 값은 한국어):
[
  {{
    "title": "취약점 명칭",
    "severity": "CRITICAL|HIGH|MEDIUM|LOW",
    "target": "URL 또는 파라미터 명칭",
    "description": "취약점에 대한 기술적 요약",
    "evidence": "취약점을 확인한 페이지 또는 응답의 특정 부분",
    "steps": "1단계: ...\\n2단계: ... (마크다운 형식의 재현 단계)",
    "recommendation": "조치 방법 (마크다운 형식의 보안 권고 사항)",
    "cwe": "CWE-ID (예: CWE-79)",
    "confidence": 0-100,
    "verified": false
  }}
]

### 분석할 컨텍스트:
{json.dumps(processed_requests, ensure_ascii=False)}
"""

    try:
        response = await local_client.chat.completions.create(
            model=local_model,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2
        )
        full_content = response.choices[0].message.content
        findings = await asyncio.to_thread(extract_vulnerabilities, full_content)
        
        for f in findings:
             if isinstance(f, dict):
                 f["source"] = "AI_Custom_Analysis"
                 f["verified"] = False

        if session_dir:
            try:
                # 1. AI Findings 취약점 저장 (비어있어도 빈 리스트로 저장함)
                existing_findings_path = os.path.join(session_dir, "ai_findings.json")
                with open(existing_findings_path, "w", encoding="utf-8") as f:
                    json.dump(findings, f, ensure_ascii=False, indent=2)

                # 2. AI Input Targets 저장 (히스토리에서 로딩 시 Endpoint에 출력되게)
                input_path = os.path.join(session_dir, "ai_input_full_requests.json")
                with open(input_path, "w", encoding="utf-8") as f:
                    json.dump(packets, f, ensure_ascii=False, indent=2)

            except Exception as e:
                print(f"결과 저장 오류: {e}")

        return findings
    except Exception as e:
        print(f"AI 분석 오류: {e}")
        return []
