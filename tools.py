import asyncio
import os
import re
import json
import subprocess
import signal
from typing import List, Dict, Optional, Union

PROXY_URL = None
_current_proc: Optional[subprocess.Popen] = None
_async_procs = set()

def stop_all_processes():
    """현재 실행 중인 모든 서브프로세스를 강제 종료합니다."""
    global _current_proc, _async_procs
    if _current_proc and _current_proc.poll() is None:
        try:
            os.killpg(os.getpgid(_current_proc.pid), signal.SIGTERM)
        except Exception as e:
            print(f"프로세스 종료 중 에러: {e}")
            try:
                _current_proc.terminate()
            except:
                pass
    _current_proc = None
    
    for proc in list(_async_procs):
        try:
            if proc.returncode is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except:
                pass
    _async_procs.clear()

def run_command(command: str) -> str:
    """쉘 명령어를 실행하고 결과를 반환합니다."""
    try:
        proc = subprocess.Popen(
            command, 
            shell=True,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=os.setsid
        )
        stdout, stderr = proc.communicate(timeout=1800)
        return stdout
    except Exception as e:
        return f"Error: {str(e)}"

async def run_command_stream(command: str, log_file: Optional[str] = None):
    """쉘 명령어를 실행하고 출력을 파일과 실시간 스트림으로 반환합니다."""
    global _async_procs
    try:
        proc = await asyncio.create_subprocess_shell(
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            start_new_session=True
        )
        _async_procs.add(proc)
        
        if log_file:
            with open(log_file, "w", encoding="utf-8") as f:
                f.write(f"$ {command}\n")
        
        while True:
            line_bytes = await proc.stdout.readline()
            if not line_bytes:
                break
            line_str = line_bytes.decode('utf-8', errors='ignore')
            
            if log_file:
                with open(log_file, "a", encoding="utf-8") as f:
                    f.write(line_str)
                    
            yield line_str
            
        await proc.wait()
        _async_procs.discard(proc)
    except Exception as e:
        yield f"Error: {str(e)}\n"

async def run_zap_spider(target_url: str, session_dir: str):
    """OWASP ZAP Spider를 사용하여 엔드포인트를 실시간으로 수집합니다."""
    from zap_client import ZAPClient
    zap = ZAPClient()
    
    yield {"type": "command", "cmd": f"# OWASP ZAP Spider 가동: {target_url}"}
    yield {"type": "progress", "msg": "[ZAP] API 인터페이스 연결 중...", "progress": 10}
    
    try:
        if not await zap.wait_for_zap(timeout=60):
            yield {"type": "progress", "msg": "[ZAP] API 서버 응답 없음 (연결 실패)", "progress": 10}
            yield {"type": "result", "data": []}
            return

        yield {"type": "progress", "msg": "[ZAP] Spider 프로세스 초기화 중...", "progress": 12}
        scan_id = await zap.start_spider(target_url)
        if not scan_id:
            yield {"type": "progress", "msg": "[ZAP] Spider 시작 세션 생성 실패", "progress": 10}
            yield {"type": "result", "data": []}
            return

        seen_urls = set()
        # 실시간 모니터링 루프 (상태 변화 및 신규 URL 감지)
        while True:
            # 2026-03-11: ZAP API는 상태를 문자열 숫자로 반환하므로 안전하게 변환
            try:
                status_raw = await zap.get_spider_status(scan_id)
                status = int(status_raw)
            except:
                status = 0
                
            current_results = await zap.get_spider_results(scan_id)
            
            for u in current_results:
                if u not in seen_urls:
                    seen_urls.add(u)
                    # 발견 즉시 개별 아이템으로 yield 하여 에이전트 단계에서 로그 출력 유도
                    yield {"type": "item", "data": {"url": u, "method": "GET", "source": "zap_spider"}}
            
            yield {"type": "progress", "msg": f"[ZAP] Spider 탐색 중... ({status}%) [식별: {len(seen_urls)}개]", "progress": 10 + int(status * 0.4)}
            
            if status >= 100: break
            await asyncio.sleep(2)

        detailed_urls = [{"url": u, "method": "GET", "source": "zap_spider"} for u in seen_urls]
        yield {"type": "progress", "msg": f"[ZAP] Spider 완료! (총 {len(detailed_urls)}개의 경로 식별)", "progress": 50}
        yield {"type": "result", "data": detailed_urls}
        
    except Exception as e:
        yield {"type": "progress", "msg": f"[ZAP] 런타임 에러: {str(e)}", "progress": 50}
        yield {"type": "result", "data": []}

async def run_ffuf(target_url: str, session_dir: str, headers: Dict = None):
    """ffuf를 사용하여 숨겨진 디렉토리 및 파일을 스캔합니다."""
    base_url = target_url.rstrip("/")
    target = base_url + "/FUZZ"
    
    wordlist = "/usr/share/wordlists/dirb/common.txt"
    if not os.path.exists(wordlist):
        wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

    tool_dir = os.path.join(session_dir, "ffuf")
    response_dir = os.path.join(tool_dir, "responses")
    import shutil
    if os.path.exists(response_dir):
        shutil.rmtree(response_dir)
    os.makedirs(response_dir, exist_ok=True)
    raw_log_path = os.path.join(tool_dir, "raw_output.txt")

    # -t 50을 추가해 스레드 수 증가
    cmd_base = f"ffuf -w {wordlist} -u {target} -t 50 -mc 200,204,301,302,307,401,403 -s -json -od {response_dir} -ac"
    if headers:
        for k, v in headers.items():
            cmd_base += f' -H "{k}: {v}"'
            
    yield {"type": "command", "cmd": f"$ {cmd_base}"}
    yield {"type": "progress", "msg": f"[FFuF] 디렉토리 탐색 가동 (Wordlist: {os.path.basename(wordlist)})", "progress": 20}
    
    results = []
    found_count = 0
    import re
    
    async for line in run_command_stream(cmd_base, log_file=raw_log_path):
        line = line.strip()
        if not line: continue
        
        # FFuF JSON 출력을 정규식으로 추출 (한 줄에 여러 개가 나오거나 특수문자가 섞인 경우 대비)
        json_candidates = re.findall(r'\{.*?"url":.*?"host":.*?\}', line)
        
        if not json_candidates:
            # 설정 정보나 에러 메시지 등 일반 텍스트 로그 출력 (너무 긴 것은 제외)
            if not line.startswith('[') and len(line) < 200:
                yield {"type": "progress", "msg": f"[FFuF] {line}", "progress": 22}
            continue

        for json_str in json_candidates:
            try:
                res_data = json.loads(json_str)
                u = res_data.get("url")
                if u:
                    found_count += 1
                    item = {
                        "url": u,
                        "method": res_data.get("method", "GET"),
                        "status": res_data.get("status"),
                        "source": "ffuf"
                    }
                    results.append(item)
                    # 중요: 발견 즉시 개별 아이템 전달 (실시간 로그 연동용)
                    yield {"type": "item", "data": item}
                    
                    if found_count % 10 == 0:
                        yield {"type": "progress", "msg": f"[FFuF] 진행 중... {found_count}개의 숨겨진 경로 식별 완료", "progress": 25}
            except:
                continue
    
    if found_count == 0:
        yield {"type": "progress", "msg": "[FFuF] 탐색을 마쳤으나 유효한 엔드포인트를 발견하지 못했습니다. (응답 코드 필터링 확인 필요)", "progress": 50}
    else:
        yield {"type": "progress", "msg": f"[FFuF] 탐색 종료. 총 {found_count}개의 유효 경로를 확보했습니다.", "progress": 50}
        
    yield {"type": "result", "data": results}

def minimize_request_raw(raw: str) -> str:
    """분석에 불필요한 헤더를 제거하여 토큰을 절약합니다."""
    if not raw: return ""
    lines = raw.splitlines()
    if not lines: return ""
    
    minimized = [lines[0].strip()] # Method Path HTTP/1.1
    # 분석에 거의 영향을 주지 않는 일반적인 헤더들 제거
    skip_headers = {
        "user-agent", "accept-encoding", "accept-language", "connection", 
        "upgrade-insecure-requests", "cache-control", "referer", "accept",
        "date", "server", "x-powered-by", "x-content-type-options", "x-frame-options",
        "content-length", "vary", "keep-alive", "pragma", "host",
        "expect", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
        "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "sec-fetch-user"
    }
    
    for line in lines[1:]:
        line = line.strip()
        if not line: continue 
        if ":" in line:
            header_name, header_value = line.split(":", 1)
            header_name = header_name.strip().lower()
            if header_name in skip_headers:
                continue
            # 쿠키 헤더의 경우, 세션 아이디 외의 일반적인 값들은 일부 생략 고려 가능하나
            # 여기서는 공백만이라도 최적화
            line = f"{header_name}: {header_value.strip()}"
        minimized.append(line)
    return "\n".join(minimized)

def get_heuristic_score(method: str, url: str, params: str = "", body: str = "", res_status: int = 200, res_len: int = 0) -> int:
    """
    취약점 분석에 앞서 '처리 우선순위'를 결정하기 위한 간단한 점수를 부여합니다.
    점수가 낮다고 분석을 버리지는 않으며, 배치의 뒷순서로 밀려나게 됩니다.
    """
    score = 0
    
    # 1. 파라미터나 바디가 있으면 우선 분석 (가장 중요)
    if params or body:
        score += 50
    else:
        # GET 방식이면서 파라미터도 없으면 우선순위를 크게 낮춤 (단순 조회일 확률 높음)
        if method == "GET":
            score -= 30
            
    # 2. 데이터를 전송/수정하는 메서드 우대
    if method in ["POST", "PUT", "PATCH", "DELETE"]:
        score += 30
        
    # 3. 흥미로운 응답 코드 우대 (에러 또는 권한 거부 등)
    if res_status in [401, 403, 500]:
        score += 20
        
    return score


def _html_to_markdown(html_content: str) -> str:
    """BeautifulSoup과 markdownify를 이용해 HTML을 순수 텍스트(마크다운)로 압축합니다."""
    try:
        from bs4 import BeautifulSoup
        import markdownify
        
        soup = BeautifulSoup(html_content, 'lxml')
        # 불필요한 태그 완전히 날리기
        for tag in soup(["css", "style", "svg", "nav", "footer", "meta", "link", "noscript", "iframe"]):
            tag.decompose()
            
        # 스크립트 태그 내의 중요한 로직 보존
        for script in soup.find_all("script"):
            if script.string:
                script_content = f"\n```javascript\n{script.string.strip()}\n```\n"
                script.replace_with(soup.new_string(script_content))
            else:
                script.decompose()
        
        md = markdownify.markdownify(str(soup), heading_style="ATX").strip()
        # 중복 개행 제거하여 압축
        md = re.sub(r'\n\s*\n', '\n\n', md)
        return md
    except Exception:
        return html_content[:5000]

def extract_relevant_snippet(url: str, req_body: str, res_body: str, max_len: int = 3000) -> dict:
    """요청과 응답을 구조적으로 분리하고, 특히 스크립트와 폼 데이터를 우선 추출해 보존합니다."""
    if not res_body: 
        return {"request_context": req_body if req_body else "N/A (GET or Empty Body)", "response_context": ""}
    
    # 1. 시맨틱 축소 (HTML -> Markdown)
    reduced_body = _html_to_markdown(res_body)
    
    # 2. 스크립트 블록 및 폼 요소 우선 추출
    import re
    scripts_found = re.findall(r'```javascript.*?```', reduced_body, re.DOTALL)
    forms_found = re.findall(r'\[INPUT.*?\]', reduced_body)
    
    priority_content = "\n".join(scripts_found + forms_found)
    
    if len(reduced_body) <= max_len:
        final_res = priority_content + "\n\n[Body Text]:\n" + reduced_body if priority_content else reduced_body
    else:
        # 중요한 부분(스크립트 등)이 너무 많으면 잘라냄
        if len(priority_content) > max_len // 2:
            priority_content = priority_content[:max_len // 2] + "\n...(Priority Content Truncated)..."
            
        # 나머지 텍스트는 헤드/테일로 채움
        remaining_space = max_len - len(priority_content)
        half = remaining_space // 2
        
        if priority_content:
            final_res = f"[Extracted Scripts/Forms]\n{priority_content}\n\n[Reduced Body Snippet]:\n{reduced_body[:half]}\n...[SNIPPED]...\n{reduced_body[-half:]}"
        else:
            final_res = f"{reduced_body[:half]}\n...[SNIPPED]...\n{reduced_body[-half:]}"
            
    return {
        "request_context": req_body if req_body else "N/A (GET or Empty Body)",
        "response_context": final_res
    }
