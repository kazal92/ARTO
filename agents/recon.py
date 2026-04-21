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
    yield stream_log(session_dir, f'Recon starting: {target_url}', 'recon', 5)

    # 스캔 모듈 활성화 상태 표시
    tools = []
    if enable_zap:
        tools.append('ZAP')
    if enable_ffuf:
        tools.append('FFuF')
    if enable_deep_recon and enable_ffuf:
        tools.append('(recursive)')


    if headers:
        yield stream_log(
            session_dir,
            f'Custom headers: {len(headers)} ({", ".join(headers.keys())})',
            'recon',
            5
        )

    if not enable_zap and not enable_ffuf:
        recon_results = {'target': target_url, 'endpoints': []}
        save_tool_result(session_dir, 'recon_map', recon_results)
        yield stream_custom(session_dir, {'type': 'recon_result', 'data': recon_results})
        return

    zap = ZAPClient()
    ffuf_urls = []
    ffuf_url_set = set()
    ffuf_status_map = {}

    # 1. ZAP Spider
    spider_visited_paths = set()
    if not enable_zap:
        yield stream_log(session_dir, 'ZAP Spider: disabled', 'recon', 15)
    else:
        yield stream_log(session_dir, 'ZAP Spider: crawling...', 'recon', 15)
        async for update in run_zap_spider(target_url, session_dir, headers):
            if is_cancelled(session_dir):
                break
            utype = update.get('type')
            if utype == 'progress':
                yield stream_log(session_dir, update['msg'], 'recon', update['progress'])
            elif utype == 'command':
                yield stream_log(session_dir, update['cmd'], 'command')
            elif utype == 'item':
                u = update['data'].get('url', '')
                if u and not is_static_file(u):
                    spider_visited_paths.add(urllib.parse.urlparse(u).path.rstrip('/').lower())
                    yield stream_log(session_dir, f'[ZAP] {u}', 'recon')

    # 2. FFuF Fuzzing
    if not enable_ffuf:
        yield stream_log(session_dir, 'FFuF: disabled', 'recon', 50)
    else:
        async for update in run_ffuf(target_url, session_dir, headers, ffuf_options=ffuf_options, ffuf_wordlist=ffuf_wordlist):
            if is_cancelled(session_dir):
                break
            utype = update.get('type')
            if utype == 'progress':
                yield stream_log(session_dir, update['msg'], 'recon', update['progress'])
            elif utype == 'command':
                yield stream_log(session_dir, update['cmd'], 'command')
            elif utype in ('item', 'result'):
                items = [update['data']] if utype == 'item' else update['data']
                for res in items:
                    u = res.get('url')
                    if u and not is_static_file(u) and u not in ffuf_url_set:
                        ffuf_url_set.add(u)
                        status = res.get('status', '')
                        method = res.get('method', 'GET').upper()
                        ffuf_status_map[u] = str(status)
                        norm = urllib.parse.urlparse(u).path.rstrip('/').lower()
                        status_code = int(status) if str(status).isdigit() else 0
                        if norm not in spider_visited_paths and 200 <= status_code < 300:
                            ffuf_urls.append(u)
                        yield stream_log(session_dir, f'[FFuF] {method} {u} → {status}', 'recon')

    # 3. Deep Recon
    if not enable_deep_recon:
        yield stream_log(session_dir, 'Recursive recon: disabled', 'recon', 70)
    elif not enable_ffuf:
        yield stream_log(session_dir, 'Recursive recon: skipped (FFuF disabled)', 'recon', 70)
    elif len(ffuf_urls) > 20:
        yield stream_log(
            session_dir,
            f'Recursive recon: skipped ({len(ffuf_urls)} paths — likely wildcard)',
            'recon',
            70,
            'warn'
        )
    elif not ffuf_urls:
        yield stream_log(session_dir, 'Recursive recon: no targets (all crawled or non-2xx)', 'recon', 70)
    else:
        for u in ffuf_urls:
            if is_cancelled(session_dir):
                break
            async for update in run_zap_spider(u, session_dir, headers=None):
                if is_cancelled(session_dir):
                    break
                utype = update.get('type')
                if utype == 'progress':
                    yield stream_log(session_dir, update['msg'], 'recon', update['progress'])
                elif utype == 'command':
                    yield stream_log(session_dir, update['cmd'], 'command')
                elif utype == 'item':
                    disc_u = update['data'].get('url', '')
                    if disc_u and not is_static_file(disc_u):
                        yield stream_log(session_dir, f'[ZAP] {disc_u}', 'recon')

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
        yield stream_log(
            session_dir,
            f'Error collecting ZAP history: {type(e).__name__}: {str(e)[:100]}',
            'recon',
            level='error'
        )

    recon_results = {'target': target_url, 'endpoints': endpoints}

    yield stream_log(
        session_dir,
        f'Recon complete: {len(endpoints)} endpoints',
        'recon',
        100
    )
    save_tool_result(session_dir, 'recon_map', recon_results)
    yield stream_custom(session_dir, {'type': 'recon_result', 'data': recon_results})
