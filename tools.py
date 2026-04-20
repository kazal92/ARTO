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

        log_fh = open(log_file, "w", encoding="utf-8") if log_file else None
        try:
            if log_fh:
                log_fh.write(f"$ {command}\n")

            # readline()은 asyncio 기본 버퍼(64KB)를 초과하는 줄에서 LimitOverrunError 발생
            # → 64KB 청크 단위로 읽고 수동으로 개행 분리
            buf = b""
            while True:
                chunk = await proc.stdout.read(65536)
                if not chunk:
                    if buf:
                        line_str = buf.decode("utf-8", errors="ignore")
                        if log_fh:
                            log_fh.write(line_str)
                        yield line_str
                    break
                buf += chunk
                while b"\n" in buf:
                    raw_line, buf = buf.split(b"\n", 1)
                    line_str = raw_line.decode("utf-8", errors="ignore") + "\n"
                    if log_fh:
                        log_fh.write(line_str)
                    yield line_str
        finally:
            if log_fh:
                log_fh.close()

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

async def run_nuclei(target_url: str, session_dir: str, headers: Dict = None, nuclei_options: str = ''):
    """Nuclei를 사용하여 취약점을 스캔합니다."""
    tool_dir = os.path.join(session_dir, "nuclei")
    os.makedirs(tool_dir, exist_ok=True)
    raw_log_path = os.path.join(tool_dir, "raw_output.txt")
    jsonl_path = os.path.join(tool_dir, "findings.jsonl")

    extra_opts = nuclei_options.strip() if nuclei_options else "-severity medium,high,critical -rl 100 -c 25"

    # -jsonl은 stdout에 거대한 JSON 줄을 출력해 LimitOverrunError를 유발하므로
    # stdout에는 일반 텍스트(-stats), 결과는 파일(-o)에만 저장
    cmd = f"nuclei -u {target_url} -o {jsonl_path} -jsonl -nc -silent {extra_opts}"
    if headers:
        for k, v in headers.items():
            cmd += f' -H "{k}: {v}"'

    yield {"type": "command", "cmd": cmd}

    # stdout 진행 메시지만 수집 (JSON 줄은 파일에 저장되므로 파싱하지 않음)
    async for line in run_command_stream(cmd, log_file=raw_log_path):
        line = line.strip()
        if not line:
            continue
        # JSON 줄은 건너뜀 (파일에서 나중에 파싱)
        if line.startswith("{") or line.startswith("["):
            continue
        yield {"type": "progress", "msg": f"[Nuclei] {line}", "progress": 30}

    # 스캔 완료 후 결과 파일 파싱
    found_count = 0
    if os.path.exists(jsonl_path):
        with open(jsonl_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                raw_line = raw_line.strip()
                if not raw_line:
                    continue
                try:
                    data = json.loads(raw_line)
                    info = data.get("info", {})
                    classification = info.get("classification") or {}
                    cwe_list = classification.get("cwe-id") or []
                    cwe = cwe_list[0] if cwe_list else ""
                    severity = info.get("severity", "info").upper()
                    finding = {
                        "title": info.get("name", data.get("template-id", "Unknown")),
                        "severity": severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "INFO",
                        "target": data.get("matched-at", target_url),
                        "description": info.get("description", ""),
                        "evidence": (data.get("curl-command") or data.get("request") or "")[:1000],
                        "steps": f"1. 재현 명령어:\n```\n{data.get('curl-command', '')}\n```",
                        "recommendation": "",
                        "cwe": cwe,
                        "ttp": "",
                        "owasp": "",
                        "confidence": 90,
                        "verified": True,
                        "source": "Nuclei",
                        "template_id": data.get("template-id", ""),
                        "tags": info.get("tags", []),
                    }
                    found_count += 1
                    yield {"type": "finding", "data": finding}
                    yield {"type": "progress", "msg": f"[Nuclei] 발견: {finding['title']} [{finding['severity']}] @ {finding['target']}", "progress": 80}
                except json.JSONDecodeError:
                    pass

    msg = f"[Nuclei] 스캔 완료: {found_count}개의 취약점 발견" if found_count else "[Nuclei] 스캔 완료: 발견된 취약점 없음"
    yield {"type": "progress", "msg": msg, "progress": 100}
    yield {"type": "result", "count": found_count}


async def run_nmap(target_url: str, session_dir: str, nmap_options: str = ''):
    """Nmap을 사용하여 포트/서비스를 스캔합니다."""
    import xml.etree.ElementTree as ET
    from urllib.parse import urlparse

    tool_dir = os.path.join(session_dir, "nmap")
    os.makedirs(tool_dir, exist_ok=True)
    raw_log_path = os.path.join(tool_dir, "raw_output.txt")
    xml_path = os.path.join(tool_dir, "results.xml")

    parsed = urlparse(target_url)
    host = parsed.hostname or target_url

    extra_opts = nmap_options.strip() if nmap_options else "-sV -T4 --open -p 1-10000"
    cmd = f"nmap {extra_opts} -oX {xml_path} {host}"

    yield {"type": "command", "cmd": cmd}

    async for line in run_command_stream(cmd, log_file=raw_log_path):
        line = line.strip()
        if line and not line.startswith("Starting") and not line.startswith("Nmap scan"):
            yield {"type": "progress", "msg": f"[Nmap] {line}", "progress": 50}

    found_count = 0
    if os.path.exists(xml_path):
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()
            for host_el in root.findall("host"):
                status_el = host_el.find("status")
                if status_el is None or status_el.get("state") != "up":
                    continue
                addr_el = host_el.find("address")
                addr = addr_el.get("addr", host) if addr_el is not None else host
                ports_el = host_el.find("ports")
                if ports_el is None:
                    continue
                for port_el in ports_el.findall("port"):
                    state_el = port_el.find("state")
                    if state_el is None or state_el.get("state") != "open":
                        continue
                    port_num = port_el.get("portid", "?")
                    protocol = port_el.get("protocol", "tcp")
                    svc = port_el.find("service")
                    service_name = svc.get("name", "") if svc is not None else ""
                    product = svc.get("product", "") if svc is not None else ""
                    version = svc.get("version", "") if svc is not None else ""
                    extrainfo = svc.get("extrainfo", "") if svc is not None else ""
                    finding = {
                        "host": addr,
                        "port": int(port_num) if port_num.isdigit() else port_num,
                        "protocol": protocol,
                        "service": service_name,
                        "product": product,
                        "version": version,
                        "extrainfo": extrainfo,
                        "state": "open",
                        "target": target_url,
                    }
                    found_count += 1
                    yield {"type": "finding", "data": finding}
                    yield {"type": "progress", "msg": f"[Nmap] {addr}:{port_num}/{protocol} {service_name} {product} {version}", "progress": 70}
        except Exception as e:
            yield {"type": "progress", "msg": f"[Nmap] XML 파싱 오류: {str(e)}", "progress": 100}

    msg = f"[Nmap] 스캔 완료: {found_count}개 포트 발견" if found_count else "[Nmap] 스캔 완료: 열린 포트 없음"
    yield {"type": "progress", "msg": msg, "progress": 100}
    yield {"type": "result", "count": found_count}


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


def _extract_security_elements(html_content: str) -> dict:
    """HTML에서 보안 분석에 필요한 요소(script, form, input)만 직접 추출합니다."""
    try:
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(html_content, 'lxml')

        scripts = []
        for script in soup.find_all("script"):
            if script.string and script.string.strip():
                scripts.append(f"```javascript\n{script.string.strip()}\n```")

        forms = []
        for form in soup.find_all("form"):
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            fields = []
            for inp in form.find_all(['input', 'select', 'textarea']):
                name = inp.get('name', '')
                itype = inp.get('type', 'text')
                value = inp.get('value', '')
                if name:
                    fields.append(f"{itype}:{name}={value}")
            field_str = " | ".join(fields) if fields else "(no fields)"
            forms.append(f"[FORM action={action} method={method}] {field_str}")

        return {"scripts": scripts, "forms": forms}
    except Exception:
        return {"scripts": [], "forms": []}


def extract_relevant_snippet(url: str, req_body: str, res_body: str, max_len: int = 3000) -> dict:
    """요청과 응답에서 보안 분석용 요소를 추출합니다."""
    if not res_body:
        return {"request_context": req_body if req_body else "N/A (GET or Empty Body)", "response_context": ""}

    extracted = _extract_security_elements(res_body)
    scripts = extracted["scripts"]
    forms = extracted["forms"]

    parts = []
    if scripts:
        parts.append("[Scripts]\n" + "\n".join(scripts))
    if forms:
        parts.append("[Forms]\n" + "\n".join(forms))

    priority_content = "\n\n".join(parts)

    if len(priority_content) > max_len:
        priority_content = priority_content[:max_len] + "\n...(Truncated)..."

    final_res = priority_content if priority_content else "(no scripts or forms found)"

    return {
        "request_context": req_body if req_body else "N/A (GET or Empty Body)",
        "response_context": final_res
    }
