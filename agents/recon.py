import datetime
import urllib.parse
import asyncio
from typing import Dict

from zap_client import ZAPClient
from tools import run_ffuf, run_zap_spider
from core.session import save_tool_result
from core.logging import stream_log, stream_custom
from core.cancellation import is_cancelled

STATIC_EXTENSIONS = {
    '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp', '.css', '.map',
    '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.webm', '.ogg', '.mp3', '.wav',
    '.flac', '.aac', '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z'
}


def is_static_file(url: str) -> bool:
    path = urllib.parse.urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS) or path.endswith('.js')


def _safe_int(val, default):
    if not val:
        return default
    if isinstance(val, int):
        return val
    try:
        digits = "".join(filter(str.isdigit, str(val)))
        return int(digits) if digits else default
    except (TypeError, ValueError):
        return default


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

    zap = ZAPClient()
    ffuf_urls = []
    ffuf_url_set = set()
    ffuf_status_map = {}  # url → status 코드 저장

    # 1. ZAP Spider
    spider_visited_paths = set()
    if not enable_zap:
        yield stream_log(session_dir, 'ZAP Spider가 비활성화되어 건너뜁니다.', 'Recon', 10)
    else:
        yield stream_log(session_dir, 'OWASP ZAP Spider 탐색 시작...', 'Recon', 10)
        async for update in run_zap_spider(target_url, session_dir, headers):
            if is_cancelled(session_dir):
                break
            utype = update.get('type')
            if utype == 'progress':
                yield stream_log(session_dir, update['msg'], 'Recon', update['progress'])
            elif utype == 'command':
                yield stream_log(session_dir, update['cmd'], 'Command')
            elif utype == 'item':
                u = update['data'].get('url', '')
                if u and not is_static_file(u):
                    spider_visited_paths.add(urllib.parse.urlparse(u).path.rstrip('/').lower())
                    yield stream_log(session_dir, f'[ZAP] {u}', 'Recon')

    # 2. FFuF Fuzzing
    if not enable_ffuf:
        yield stream_log(session_dir, 'FFuF 퍼징이 비활성화되어 건너뜁니다.', 'Recon', 50)
    else:
        yield stream_log(session_dir, 'FFuF 디렉토리/파일 퍼징 중...', 'Recon', 50)
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
                    u = res.get('url')
                    if u and not is_static_file(u) and u not in ffuf_url_set:
                        ffuf_url_set.add(u)
                        status = res.get('status', '')
                        method = res.get('method', 'GET').upper()
                        ffuf_status_map[u] = str(status)
                        # Deep Recon 대상: Spider 미방문 + 200대 응답만
                        norm = urllib.parse.urlparse(u).path.rstrip('/').lower()
                        status_code = int(status) if str(status).isdigit() else 0
                        if norm not in spider_visited_paths and 200 <= status_code < 300:
                            ffuf_urls.append(u)
                        yield stream_log(session_dir, f'[FFUF] {method} {u} → {status}', 'Recon')

    # 3. Deep Recon: ffuf 발견 경로에 추가 Spider 실행
    if not enable_deep_recon:
        yield stream_log(session_dir, '[Recon] 재귀적 심층 정찰이 비활성화되어 탐색을 종료합니다.', 'Recon', 70)
    elif not enable_ffuf:
        yield stream_log(session_dir, '[Recon] ffuf가 비활성화되어 심층 탐색을 건너뜁니다.', 'Recon', 70)
    elif len(ffuf_urls) > 20:
        yield stream_log(session_dir, f'[Warning] 발견된 신규 경로가 너무 많습니다 ({len(ffuf_urls)}개). 와일드카드 응답이 의심되어 재귀적 크롤링을 건너뜁니다.', 'Recon', 70)
    elif not ffuf_urls:
        yield stream_log(session_dir, '[Recon] Deep Recon 대상 없음 (Spider 기방문 또는 2xx 아닌 경로만 발견).', 'Recon', 70)
    else:
        for u in ffuf_urls:
            if is_cancelled(session_dir):
                break
            yield stream_log(session_dir, f'[Deep Recon] {u} 하위 노드 탐색 중...', 'Recon')
            async for update in run_zap_spider(u, session_dir, headers):
                if is_cancelled(session_dir):
                    break
                utype = update.get('type')
                if utype == 'progress':
                    yield stream_log(session_dir, update['msg'], 'Recon', update['progress'])
                elif utype == 'command':
                    yield stream_log(session_dir, update['cmd'], 'Command')
                elif utype == 'item':
                    disc_u = update['data'].get('url', '')
                    if disc_u and not is_static_file(disc_u):
                        yield stream_log(session_dir, f'[ZAP] {disc_u}', 'Recon')

    endpoints = []
    seen_keys = set()

    try:
        parsed_origin = urllib.parse.urlparse(target_url)
        base_origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"
        all_zap_history = await zap.get_all_messages(base_origin)

        for msg in all_zap_history:
            await asyncio.sleep(0)

            req_h = msg.get('requestHeader', '')
            if not req_h:
                continue

            # URL, Method 파싱
            try:
                parts = req_h.split('\n')[0].split(' ', 2)
                h_m = parts[0].upper()
                h_u = parts[1]
            except (IndexError, AttributeError):
                h_m = msg.get('requestMethod', 'GET').upper()
                h_u = msg.get('url')

            if not h_u:
                continue
            if not h_u.startswith('http'):
                h_u = target_url.rstrip('/') + h_u

            if is_static_file(h_u):
                continue

            key = f"{h_m}:{h_u}"
            if key in seen_keys:
                continue

            # 응답 헤더 검증
            res_h = msg.get('responseHeader', '')
            if not res_h.strip():
                continue
            if res_h.startswith('HTTP/1.1 0') or res_h.startswith('HTTP/1.0 0') or res_h.startswith('HTTP/1.1 502'):
                continue

            # status 파싱
            h_status = None
            try:
                first_line = res_h.split('\n')[0].strip()
                if first_line.startswith('HTTP/'):
                    candidate = first_line.split(' ')[1]
                    if candidate.isdigit():
                        h_status = candidate
            except (IndexError, ValueError):
                pass

            if not h_status:
                continue

            req_raw = (msg.get('requestHeader') or '') + (msg.get('requestBody') or '')
            res_raw = (msg.get('responseHeader') or '') + (msg.get('responseBody') or '')

            # 커스텀 헤더 삽입
            if headers and req_raw:
                insert_pos = req_raw.find('\n\n')
                insert_pos = insert_pos if insert_pos != -1 else len(req_raw)
                injected = ''.join(f'{k}: {v}\n' for k, v in headers.items() if k.lower() not in req_raw.lower())
                if injected:
                    req_raw = req_raw[:insert_pos] + '\n' + injected.rstrip('\n') + req_raw[insert_pos:]

            ep_sources = ['zap']
            if h_u in ffuf_url_set:
                ep_sources.append('ffuf')

            endpoints.append({
                'url': h_u,
                'method': h_m,
                'status': h_status,
                'source': 'zap_history',
                'sources': ep_sources,
                'id': msg.get('id'),
                'request_raw': req_raw,
                'response_raw': res_raw,
                'requestSize': _safe_int(msg.get('requestSize'), len(req_raw)),
                'responseSize': _safe_int(msg.get('responseSize'), len(res_raw)),
                'time': datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]
            })
            seen_keys.add(key)

        # 404 중복 제거 (대표 1개만 유지)
        kept_404 = False
        final_endpoints = []
        for ep in endpoints:
            if ep['status'] == '404':
                if not kept_404:
                    kept_404 = True
                    final_endpoints.append(ep)
            else:
                final_endpoints.append(ep)

        endpoints = final_endpoints

    except Exception as e:
        yield stream_log(session_dir, f'[Sync] 데이터 수집 중 오류: {e}', 'Recon')

    recon_results = {'target': target_url, 'endpoints': endpoints}

    yield stream_log(session_dir, f'[Recon] 정찰 단계를 성공적으로 완료하였습니다. (총 {len(endpoints)}개의 공격 접점 확보)', 'Recon', 100)
    save_tool_result(session_dir, 'recon_map', recon_results)
    yield stream_custom(session_dir, {'type': 'recon_result', 'data': recon_results})
