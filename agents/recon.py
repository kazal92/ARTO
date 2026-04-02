import os
import codecs
import json
import datetime
import urllib.parse
import asyncio
from typing import Dict, Optional

from zap_client import ZAPClient
from tools import run_ffuf, run_zap_spider
from core.session import save_tool_result
from core.logging import stream_log, stream_custom
from core.cancellation import is_cancelled

# AI 분석에서 제외할 정적 파일 확장자
STATIC_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp', '.css', '.map',
    '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.ogg', '.mp3', '.wav',
    '.flac', '.aac', '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z'
}


def is_static_file(url: str) -> bool:
    """URL의 확장자가 정적 파일인지 확인합니다."""
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS) or path.endswith('.js')


def _safe_int(val, default):
    """ZAP API 응답의 숫자 필드 파싱 ('6671 Bytes' 같은 문자열 포함 처리)."""
    if not val:
        return default
    if isinstance(val, int):
        return val
    try:
        digits = "".join(filter(str.isdigit, str(val)))
        return int(digits) if digits else default
    except (TypeError, ValueError):
        return default


def _collect_endpoint(res: dict, seen_keys: set, endpoints: list, source: str, session_dir: str, log_fn=None, extra_fields: dict = None):
    """단일 엔드포인트 dict를 중복 확인 후 endpoints 리스트에 추가합니다."""
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


async def run_recon_agent(
    target_url: str,
    session_dir: str,
    headers: Dict = None,
    enable_deep_recon: bool = True,
    enable_zap: bool = True,
    enable_ffuf: bool = True,
    ffuf_options: str = '',
    ffuf_wordlist: str = ''
):
    yield stream_log(session_dir, f'정찰 시작: {target_url}', 'Recon', 5)

    recon_results = {'target': target_url, 'endpoints': []}

    zap = ZAPClient()
    seen_keys = set()

    # 1. ZAP Spider
    if not enable_zap:
        yield stream_log(session_dir, '1. ZAP Spider가 비활성화되어 건너뜁니다.', 'Recon', 10)
    else:
        yield stream_log(session_dir, '1. OWASP ZAP Spider 탐색 시작...', 'Recon', 10)
        async for update in run_zap_spider(target_url, session_dir):
            if is_cancelled(session_dir):
                break
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
                    if log:
                        yield log

    # 2. FFuF Fuzzing
    if not enable_ffuf:
        yield stream_log(session_dir, '2. ffuf 퍼징이 비활성화되어 건너뜁니다.', 'Recon', 50)
    else:
        yield stream_log(session_dir, '2. FFuF 디렉토리/파일 퍼징 중...', 'Recon', 50)
        async for update in run_ffuf(target_url, session_dir, headers, ffuf_options=ffuf_options, ffuf_wordlist=ffuf_wordlist):
            if is_cancelled(session_dir):
                break
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
                    if log:
                        yield log

    # 3. 추가 정찰: FFuF로 발견된 새로운 경로에 대해 다시 ZAP Spider 실행 (Recursive Recon)
    if not enable_deep_recon:
        yield stream_log(session_dir, "[Recon] 재귀적 심층 정찰이 비활성화되어 탐색을 종료합니다.", "Recon", 70)
    elif not enable_ffuf:
        yield stream_log(session_dir, "[Recon] ffuf가 비활성화되어 심층 탐색을 건너뜁니다.", "Recon", 70)
    else:
        new_ffuf_endpoints = [ep for ep in recon_results['endpoints'] if ep.get('source') == 'ffuf']

        if len(new_ffuf_endpoints) > 20:
            yield stream_log(session_dir, f"[Warning] 발견된 신규 경로가 너무 많습니다 ({len(new_ffuf_endpoints)}개). 와일드카드 응답이 의심되어 재귀적 크롤링을 건너뜁니다.", "Recon", 70)
            new_ffuf_endpoints = []

        if not new_ffuf_endpoints:
            if not is_cancelled(session_dir):
                yield stream_log(session_dir, "[Recon] 분석 가능한 신규 공격 요인이 식별되지 않아 심층 탐색을 종료합니다.", "Recon", 70)
        else:
            yield stream_log(session_dir, f"[Recon] {len(new_ffuf_endpoints)}개의 신규 경로를 기반으로 재귀적 자산 탐색을 시작합니다.", "Recon", 70)

        for ep in new_ffuf_endpoints:
            if is_cancelled(session_dir):
                break
            u = ep.get('url')
            yield stream_log(session_dir, f'[Deep Recon] 유효 경로 {u}에 대한 구조 분석 및 하위 노드 탐색 중...', 'Recon')

            async for update in run_zap_spider(u, session_dir):
                if is_cancelled(session_dir):
                    break
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
                        if log:
                            yield log

    # FINAL SYNC: ZAP 히스토리 + FFuF 결과를 전수 조사하여 모든 엔드포인트 동기화
    try:
        yield stream_log(session_dir, "[Sync] 정찰 데이터 누락 방지를 위한 전수 정합성 검증 및 통합 중...", "Recon")
        endpoint_index = {f"{ep['method']}:{ep['url']}": ep for ep in recon_results['endpoints']}

        # 1. ZAP 히스토리 전수 조사
        all_zap_history = await zap.get_all_messages(target_url)
        for msg in all_zap_history:
            req_h = msg.get("requestHeader", "")
            if not req_h:
                continue

            f_line = req_h.split('\n')[0]
            try:
                parts = f_line.split(' ', 2)
                h_m = parts[0].upper()
                h_u = parts[1]
            except (IndexError, AttributeError):
                h_m = msg.get("requestMethod", "GET").upper()
                h_u = msg.get("url")

            if not h_u:
                continue
            if not h_u.startswith("http"):
                h_u = target_url.rstrip("/") + h_u

            if is_static_file(h_u):
                continue

            res_h = msg.get("responseHeader", "")
            if res_h.startswith("HTTP/1.1 0") or res_h.startswith("HTTP/1.0 0") or res_h.startswith("HTTP/1.1 502"):
                continue

            key = f"{h_m}:{h_u}"

            req_raw = (msg.get("requestHeader") or "") + (msg.get("requestBody") or "")
            res_raw = (msg.get("responseHeader") or "") + (msg.get("responseBody") or "")

            h_req_size = _safe_int(msg.get("requestSize"), len(req_raw))
            h_res_size = _safe_int(msg.get("responseSize"), len(res_raw))

            h_status = "-"
            if res_raw:
                try:
                    first_line = res_raw.split('\n')[0].strip()
                    if first_line.startswith("HTTP/"):
                        status_candidate = first_line.split(' ')[1]
                        if status_candidate.isdigit():
                            h_status = status_candidate
                except (IndexError, ValueError):
                    pass

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
                ep = endpoint_index[key]
                ep['request_raw'] = req_raw
                ep['response_raw'] = res_raw
                ep['source'] = "zap_history"
                if h_status != '-':
                    ep['status'] = h_status
                ep['requestSize'] = h_req_size
                ep['responseSize'] = h_res_size

        # 2. FFuF 응답 폴더 전수 조사
        ffuf_res_dir = os.path.join(session_dir, "ffuf", "responses")
        if os.path.exists(ffuf_res_dir):
            files = await asyncio.to_thread(os.listdir, ffuf_res_dir)
            for fname in sorted(files):
                fpath = os.path.join(ffuf_res_dir, fname)
                if not os.path.isfile(fpath):
                    continue
                try:
                    with codecs.open(fpath, 'r', 'utf-8', 'ignore') as f:
                        full_content = f.read()
                    first_line = full_content[:2048].split('\n')[0]
                    parts = first_line.split()
                    if len(parts) >= 2:
                        m, p = parts[0].upper(), parts[1]
                        if not p.startswith("/"):
                            p = "/" + p
                        u = target_url.rstrip("/") + p

                        if is_static_file(u):
                            continue

                        key = f"{m}:{u}"

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
                            ep = endpoint_index[key]
                            ep['request_raw'] = req_raw
                            ep['response_raw'] = res_raw
                            ep['requestSize'] = len(req_raw)
                            ep['responseSize'] = len(res_raw)
                except (OSError, UnicodeDecodeError, IndexError):
                    pass

        yield stream_log(session_dir, f"[Complete] 정찰 데이터 통합 완료. 최종적으로 {len(recon_results['endpoints'])}개의 유효 공격 데이터를 확보했습니다.", "Recon")
    except Exception as e:
        yield stream_log(session_dir, f"[Sync] 데이터 통합 중 오류: {e}", "Recon")

    yield stream_log(session_dir, f'[Recon] 정찰 단계를 성공적으로 완료하였습니다. (총 {len(recon_results["endpoints"])}개의 공격 접점 확보)', 'Recon', 100)
    save_tool_result(session_dir, 'recon_map', recon_results)
    yield stream_custom(session_dir, {'type': 'recon_result', 'data': recon_results})
