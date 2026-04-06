import asyncio
import os
import re
import json
import shutil
import subprocess
import signal
from typing import List, Dict, Optional, Union

from zap_client import ZAPClient

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
            except OSError:
                pass
    _current_proc = None

    for proc in list(_async_procs):
        try:
            if proc.returncode is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            try:
                proc.terminate()
            except OSError:
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


async def run_zap_spider(target_url: str, session_dir: str, headers: Dict = None):
    """OWASP ZAP Spider를 사용하여 엔드포인트를 실시간으로 수집합니다."""
    zap = ZAPClient()

    try:
        if not await zap.wait_for_zap(timeout=60):
            yield {"type": "progress", "msg": "[ZAP] API 서버 응답 없음 (연결 실패)", "progress": 10}
            yield {"type": "result", "data": []}
            return

        if headers:
            await zap.add_replacer_rules(headers)

        scan_id = await zap.start_spider(target_url)
        if not scan_id:
            yield {"type": "progress", "msg": "[ZAP] Spider 시작 세션 생성 실패", "progress": 10}
            yield {"type": "result", "data": []}
            return

        seen_urls = set()
        while True:
            try:
                status_raw = await zap.get_spider_status(scan_id)
                status = int(status_raw)
            except (ValueError, TypeError):
                status = 0

            current_results = await zap.get_spider_results(scan_id)

            for u in current_results:
                if u not in seen_urls:
                    seen_urls.add(u)
                    yield {"type": "item", "data": {"url": u, "method": "GET", "source": "zap_spider"}}

            if status >= 100:
                break
            await asyncio.sleep(2)

        detailed_urls = [{"url": u, "method": "GET", "source": "zap_spider"} for u in seen_urls]
        if headers:
            await zap.remove_replacer_rules(headers)
        yield {"type": "progress", "msg": f"[ZAP] Spider 완료! (총 {len(detailed_urls)}개의 경로 식별)", "progress": 50}
        yield {"type": "result", "data": detailed_urls}

    except Exception as e:
        if headers:
            try:
                await zap.remove_replacer_rules(headers)
            except Exception:
                pass
        yield {"type": "progress", "msg": f"[ZAP] 런타임 에러: {str(e)}", "progress": 50}
        yield {"type": "result", "data": []}


async def run_ffuf(target_url: str, session_dir: str, headers: Dict = None, ffuf_options: str = '', ffuf_wordlist: str = ''):
    """ffuf를 사용하여 숨겨진 디렉토리 및 파일을 스캔합니다."""
    base_url = target_url.rstrip("/")
    target = base_url + "/FUZZ"

    arto_wordlist_dir = os.path.join(os.path.dirname(__file__), "wordlist")
    if ffuf_wordlist:
        wordlist = os.path.join(arto_wordlist_dir, ffuf_wordlist)
        if not os.path.exists(wordlist):
            wordlist = ffuf_wordlist
    else:
        wordlist = os.path.join(arto_wordlist_dir, "wordlist_last.txt")
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"

    tool_dir = os.path.join(session_dir, "ffuf")
    os.makedirs(tool_dir, exist_ok=True)
    raw_log_path = os.path.join(tool_dir, "raw_output.txt")

    extra_opts = ffuf_options.strip() if ffuf_options else "-t 50 -mc 200,204,301,302,307,401,403,500 -ac"

    if '-u ' in extra_opts:
        cmd_base = f"ffuf -w {wordlist} {extra_opts} -x http://localhost:8080 -s -json"
    else:
        cmd_base = f"ffuf -w {wordlist} -u {target} {extra_opts} -x http://localhost:8080 -s -json"
    if headers:
        for k, v in headers.items():
            cmd_base += f' -H "{k}: {v}"'

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as _wf:
            wl_count = sum(1 for ln in _wf if ln.strip())
    except Exception:
        wl_count = 0

    cmd_display = f"$ {cmd_base}" + (f"  [{os.path.basename(wordlist)}: {wl_count:,}줄]" if wl_count else "")
    yield {"type": "command", "cmd": cmd_display}

    results = []
    found_count = 0

    async for line in run_command_stream(cmd_base, log_file=raw_log_path):
        line = line.strip()
        if not line:
            continue

        json_candidates = re.findall(r'\{.*?"url":.*?"host":.*?\}', line)

        if not json_candidates:
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
                    yield {"type": "item", "data": item}
            except json.JSONDecodeError:
                pass

    if found_count == 0:
        yield {"type": "progress", "msg": "[FFuF] 탐색을 마쳤으나 유효한 엔드포인트를 발견하지 못했습니다. (응답 코드 필터링 확인 필요)", "progress": 50}
    else:
        yield {"type": "progress", "msg": f"[FFuF] 탐색 종료. 총 {found_count}개의 유효 경로를 확보했습니다.", "progress": 50}

def minimize_request_raw(raw: str) -> str:
    """분석에 불필요한 헤더를 제거하여 토큰을 절약합니다."""
    if not raw:
        return ""
    lines = raw.splitlines()
    if not lines:
        return ""

    minimized = [lines[0].strip()]
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
        if not line:
            continue
        if ":" in line:
            header_name, header_value = line.split(":", 1)
            header_name = header_name.strip().lower()
            if header_name in skip_headers:
                continue
            line = f"{header_name}: {header_value.strip()}"
        minimized.append(line)
    return "\n".join(minimized)


def get_heuristic_score(method: str, url: str, params: str = "", body: str = "", res_status: int = 200, res_len: int = 0) -> int:
    """취약점 분석 우선순위 점수를 부여합니다."""
    score = 0

    if params or body:
        score += 50
    else:
        if method == "GET":
            score -= 30

    if method in ["POST", "PUT", "PATCH", "DELETE"]:
        score += 30

    if res_status in [401, 403, 500]:
        score += 20

    return score


def _html_to_markdown(html_content: str) -> str:
    """BeautifulSoup과 markdownify를 이용해 HTML을 순수 텍스트(마크다운)로 압축합니다."""
    try:
        from bs4 import BeautifulSoup
        import markdownify

        soup = BeautifulSoup(html_content, 'lxml')
        for tag in soup(["css", "style", "svg", "nav", "footer", "meta", "link", "noscript", "iframe"]):
            tag.decompose()

        for script in soup.find_all("script"):
            if script.string:
                script_content = f"\n```javascript\n{script.string.strip()}\n```\n"
                script.replace_with(soup.new_string(script_content))
            else:
                script.decompose()

        md = markdownify.markdownify(str(soup), heading_style="ATX").strip()
        md = re.sub(r'\n\s*\n', '\n\n', md)
        return md
    except Exception:
        return html_content[:5000]


def extract_relevant_snippet(url: str, req_body: str, res_body: str, max_len: int = 3000) -> dict:
    """요청과 응답을 구조적으로 분리하고 스크립트/폼 데이터를 우선 추출합니다."""
    if not res_body:
        return {"request_context": req_body if req_body else "N/A (GET or Empty Body)", "response_context": ""}

    reduced_body = _html_to_markdown(res_body)

    scripts_found = re.findall(r'```javascript.*?```', reduced_body, re.DOTALL)
    forms_found = re.findall(r'\[INPUT.*?\]', reduced_body)

    priority_content = "\n".join(scripts_found + forms_found)

    if len(reduced_body) <= max_len:
        final_res = priority_content + "\n\n[Body Text]:\n" + reduced_body if priority_content else reduced_body
    else:
        if len(priority_content) > max_len // 2:
            priority_content = priority_content[:max_len // 2] + "\n...(Priority Content Truncated)..."

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
