import asyncio
import re
import ssl
import json
import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urljoin
from urllib3.util.ssl_ import create_urllib3_context
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class LegacyTLSAdapter(HTTPAdapter):
    """구형 SSL/TLS 및 취약한 암호화 알고리즘을 지원하기 위한 커스텀 어댑터"""
    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        ctx = create_urllib3_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0x4)
        try:
            ctx.set_ciphers('DEFAULT@SECLEVEL=0')
        except Exception:
            pass
        pool_kwargs['ssl_context'] = ctx
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)

def extract_js_meta_redirect(html_text):
    """HTML에서 Meta Refresh 또는 JS 기반 리다이렉트 URL 추출"""
    content = html_text.lower()
    meta_match = re.search(r'url=(["\']?)([^"\'>\s]+)\1', content)
    if meta_match:
        return meta_match.group(2)
    
    if 'location' in content:
        js_match = re.search(r'(?:window\.|document\.)?location(?:\.href|\.replace|\.assign)?\s*(?:=\s*|\()\s*(["\'])(.*?)\1', content)
        if js_match:
            return js_match.group(2)
    return None

def check_url_sync(session, url):
    """해당 URL의 HTTP 상태 및 리다이렉트 경로를 추적하여 반환"""
    try:
        response = session.get(url, timeout=15, verify=False, allow_redirects=True)
        trace = [res.status_code for res in response.history] + [response.status_code]
        final_url = response.url

        redirect_count = 0
        while response.status_code == 200 and redirect_count < 2:
            jump_path = extract_js_meta_redirect(response.text)
            if not jump_path:
                break
                
            jump_url = urljoin(response.url, jump_path)
            final_url = jump_url
            
            try:
                response = session.get(jump_url, timeout=15, verify=False, allow_redirects=True)
                trace.extend([res.status_code for res in response.history] + [response.status_code])
                final_url = response.url
                redirect_count += 1
            except requests.exceptions.RequestException:
                break

        # 강제 HTTPS 크로스체크 (HTTP로 남아있고 접속 성공한 경우)
        if final_url.startswith('http://') and response.status_code == 200:
            forced_https_url = final_url.replace('http://', 'https://', 1)
            try:
                check_res = session.get(forced_https_url, timeout=10, verify=False, allow_redirects=True)
                if check_res.status_code == 200:
                    final_url = check_res.url
            except requests.exceptions.RequestException:
                pass

        return trace, final_url
    except requests.exceptions.RequestException:
        return ['X'], '-'

async def process_domain(sem, session, domain_raw, idx, mode='alive'):
    async with sem:
        # 빈 줄 또는 무시 열 유지 로직 (엑셀 붙여넣기 시 행 밀림 방지)
        if not domain_raw.strip() or domain_raw.strip() == '-':
            return idx, ["-", "-", "-", "-", "-", "-", "-", "-", "-"]

        domain = re.sub(r'^https?://', '', domain_raw.strip()).split('/')[0]
        
        # 🔍 Shodan InternetDB lookup
        import socket
        ports_str = "-"
        vulns_str = "-"
        ip_addr = "-"
        
        if mode == 'shodan':
            try:
                # 도메인 ➔ IP 해소 (포트 번호 제거)
                host_only = domain.split(':')[0] if ':' in domain and not domain.startswith('[') else (domain[1:domain.find(']')] if domain.startswith('[') else domain)
                ip_addr = await asyncio.to_thread(socket.gethostbyname, host_only)
                
                # API 호출 (requests 동기 호출이므로 to_thread 처리)
                def fetch_shodan(ip):
                    try:
                        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=5)
                        if r.status_code == 200:
                            return r.json()
                    except: pass
                    return None
    
                shodan_data = await asyncio.to_thread(fetch_shodan, ip_addr)
                if shodan_data:
                    ports = shodan_data.get("ports", [])
                    vulns = shodan_data.get("vulns", [])
                    if ports: ports_str = ", ".join(map(str, sorted(ports)))
                    if vulns: vulns_str = ", ".join(vulns)
            except Exception:
                pass

        # Run sync requests in thread executor to avoid blocking the event loop
        if mode == 'alive':
            http_trace, http_redirect_url = await asyncio.to_thread(check_url_sync, session, f'http://{domain}')
            https_trace, https_redirect_url = await asyncio.to_thread(check_url_sync, session, f'https://{domain}')
            
            last_http = str(http_trace[-1])
            last_https = str(https_trace[-1])
            ox = 'X' if last_http == 'X' and last_https == 'X' else 'O'
            
            http_trace_str = ' > '.join(map(str, http_trace))
            https_trace_str = ' > '.join(map(str, https_trace))
        else:
            http_trace, http_redirect_url = ['-'], '-'
            https_trace, https_redirect_url = ['-'], '-'
            ox = '-'
            http_trace_str = '-'
            https_trace_str = '-'

        return idx, [ox, domain, http_redirect_url, https_redirect_url, http_trace_str, https_trace_str, ports_str, vulns_str, ip_addr]

async def stream_alive_check(domains: list, stop_event: asyncio.Event, mode: str = 'alive'):
    session = requests.Session()
    session.mount('https://', LegacyTLSAdapter())
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': 'ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7'
    })

    sem = asyncio.Semaphore(20) # Max 20 concurrent requests
    pending = {}
    next_idx_to_yield = 0
    
    tasks = [asyncio.create_task(process_domain(sem, session, dom, idx, mode)) for idx, dom in enumerate(domains)]
    
    try:
        from asyncio import as_completed
        for task in as_completed(tasks):
            if stop_event.is_set():
                for t in tasks: t.cancel()
                yield "data: " + json.dumps({"status": "error", "message": "Stopped by user"}) + "\n\n"
                return

            idx, result = await task
            pending[idx] = result
            
            # Yield ready items sequentially to guarantee original row order
            while next_idx_to_yield in pending:
                res_data = {
                    "status": "progress",
                    "index": next_idx_to_yield,
                    "result": pending.pop(next_idx_to_yield)
                }
                yield "data: " + json.dumps(res_data) + "\n\n"
                next_idx_to_yield += 1

        yield "data: " + json.dumps({"status": "completed"}) + "\n\n"
    except asyncio.CancelledError:
        for t in tasks: t.cancel()

# --- Google Dork Scanner ---

DORK_CATEGORIES = {
    "Directory Listing": 'site:{domain} intitle:"index of"',
    "Config/Backup Leaks": 'site:{domain} ext:env OR ext:log OR ext:ini OR ext:bkp OR ext:config',
    "Database Leaks": 'site:{domain} ext:sql OR ext:dump OR ext:db OR ext:备份',
    "Admin/Portals": 'site:{domain} inurl:admin OR inurl:login OR inurl:signin OR intitle:admin',
    "Public Disclosure": 'site:{domain} "confidential" OR "internal use only"'
}

current_dork_key_idx = 0

def get_next_google_key(api_keys):
    global current_dork_key_idx
    if not api_keys: return None
    key = api_keys[current_dork_key_idx % len(api_keys)]
    current_dork_key_idx += 1
    return key

async def process_domain_dork(sem, session, domain_raw, idx, api_keys, cx_id, custom_categories=None):
    categories = custom_categories if custom_categories else DORK_CATEGORIES
    async with sem:
        if not domain_raw.strip() or domain_raw.strip() == '-':
            return idx, []

        domain = re.sub(r'^https?://', '', domain_raw.strip()).split('/')[0]
        domain = domain.split(':')[0] if ':' in domain and not domain.startswith('[') else (domain[1:domain.find(']')] if domain.startswith('[') else domain)

        all_findings = []
        
        for cat_name, query_template in categories.items():
            query = query_template.format(domain=domain)
            tries = 0
            max_tries = len(api_keys)
            
            while tries < max_tries:
                key = get_next_google_key(api_keys)
                if not key: break
                
                url = f"https://www.googleapis.com/customsearch/v1?key={key}&cx={cx_id}&q={query}"
                try:
                    def fetch():
                        try:
                            return requests.get(url, timeout=10).json()
                        except: return None
                    
                    data = await asyncio.to_thread(fetch)
                    if data and "items" in data:
                        for item in data["items"]:
                            all_findings.append([
                                'O', # Hit
                                domain,
                                cat_name,
                                item.get("link", "-"),
                                item.get("snippet", "-")
                            ])
                        break # 성공시 루프 탈출
                    elif data and "error" in data:
                        if data["error"].get("code") in [429, 403]: # 한도 초과 또는 차단 시 로테이션
                            tries += 1
                            continue
                    break # 에러나 결과 없음이면 다음 카테고리로
                except Exception:
                    tries += 1
                    continue

        if not all_findings:
            all_findings.append(['X', domain, '결과 없음', '-', '-'])
            
        return idx, all_findings

async def stream_google_dork(domains: list, api_keys: list, cx_id: str, stop_event: asyncio.Event, custom_categories=None):
    session = requests.Session()
    sem = asyncio.Semaphore(10)
    pending = {}
    next_idx_to_yield = 0
    
    tasks = [asyncio.create_task(process_domain_dork(sem, session, dom, idx, api_keys, cx_id, custom_categories)) for idx, dom in enumerate(domains)]
    
    try:
        from asyncio import as_completed
        for task in as_completed(tasks):
            if stop_event.is_set():
                for t in tasks: t.cancel()
                yield "data: " + json.dumps({"status": "error", "message": "Stopped by user"}) + "\n\n"
                return

            idx, result_list = await task
            pending[idx] = result_list
            
            while next_idx_to_yield in pending:
                res_data = {
                    "status": "progress",
                    "index": next_idx_to_yield,
                    "results": pending.pop(next_idx_to_yield)
                }
                yield "data: " + json.dumps(res_data) + "\n\n"
                next_idx_to_yield += 1

        yield "data: " + json.dumps({"status": "completed"}) + "\n\n"
    except asyncio.CancelledError:
        for t in tasks: t.cancel()
