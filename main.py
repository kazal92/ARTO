from typing import Optional, List
import os
import json
import asyncio
import shutil

# .env 지원용 (Bulletproof)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import agents
from agents import run_recon_agent, run_analysis_agent, get_session_dir, analyze_selected_packets
from zap_client import ZAPClient
import tools
from alive_checker import stream_alive_check, stream_google_dork

# 전역적으로 실행 중인 스캔 세션을 추적
ACTIVE_SCANS = set()

# Alive Check SSE 세션 관리
ALIVE_CHECK_SESSION = {
    "domains": [],
    "stop_event": None
}

# Shodan InternetDB SSE 세션 관리
SHODAN_CHECK_SESSION = {
    "domains": [],
    "stop_event": None
}

# Google Dork Scanner SSE 세션 관리
DORK_CHECK_SESSION = {
    "domains": [],
    "api_keys": [],
    "cx_id": "",
    "stop_event": None
}

app = FastAPI(title="ARTO Web Dashboard")

# 템플릿 디렉토리 설정
templates = Jinja2Templates(directory="templates")
from fastapi.staticfiles import StaticFiles
app.mount("/static", StaticFiles(directory="static"), name="static")

class ScanRequest(BaseModel):
    target_url: Optional[str] = None
    headers: dict = {}
    ai_config: dict = {} 
    project_name: str = "" 
    session_id: str = "" 
    project_type: str = "scan"
    enable_deep_recon: bool = True # 재귀 탐색 제어 플래그

class ProxyRequest(BaseModel):
    proxy_host: str
    proxy_port: int
    enabled: bool

class RenameRequest(BaseModel):
    project_name: str

class UpdateStatusRequest(BaseModel):
    status: str

class PacketAnalysisRequest(BaseModel):
    packets: list
    ai_config: dict = {}
    session_dir: str = ""
    project_name: str = "" # 💡 수동 생성 시 프로젝트 커스텀 명칭 주입 수신용

class SaveFindingsRequest(BaseModel):
    session_id: str
    findings: list

class AliveCheckRequest(BaseModel):
    domains: list
    mode: str = "alive"
    session_id: Optional[str] = None

class DorkCheckRequest(BaseModel):
    domains: list
    api_keys: List[str] = []
    cx_id: str = ""
    session_id: Optional[str] = None
    dork_categories: Optional[dict] = None # 커스텀 도크 쿼리 맵

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    # 이전에 저장된 리포트가 있는지 확인
    report_content = ""
    report_path = "results/strategy_report.md"
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            report_content = f.read()
            
    return templates.TemplateResponse("index.html", {
        "request": request,
        "existing_report": report_content
    })

@app.post("/api/project/create")
async def create_project(req: ScanRequest):
    """신규 프로젝트 생성 (스캔 실행 안 함, 디렉토리만 초기화)"""
    try:
        from agents import get_session_dir
        import agents
        p_name = req.project_name if req.project_name else "New_Project"
        p_type = getattr(req, "project_type", "scan")
        session_dir = agents.get_session_dir(p_name, p_type)
        
        info_file = os.path.join(session_dir, "project_info.json")
        with open(info_file, "w", encoding="utf-8") as f:
            json.dump({
                "project_name": p_name,
                "target": getattr(req, "target_url", ""),
                "project_type": p_type
            }, f, ensure_ascii=False, indent=2)
            
        # 초기 로그 작성 (생성 시점)
        agents.stream_log(session_dir, "프로젝트가 성공적으로 생성되었습니다. (대시보드 진입 대기)", "System", 0)
        
        return {"status": "success", "session_id": os.path.basename(session_dir)}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/scan")
async def start_scan(req: ScanRequest, request: Request):
    """Start scan event stream or resume existing one"""
    
    # 1. 쿼리 파라미터가 오면 단순 SSE 리프레시/재접속(Resume) 모드
    session_id_query = request.query_params.get("session_id")
    
    if session_id_query:
        session_dir = agents.find_session_dir(session_id_query)
        if not os.path.exists(session_dir):
             return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}
        is_resume = True
    elif req.session_id:
        # 2. 워크스페이스 안에서 스캔을 시작할 때: 기존 폴더 재활용 (중복 생성 방지)
        session_dir = agents.find_session_dir(req.session_id)
        if not session_dir:
            session_dir = agents.get_session_dir(req.project_name if req.project_name else req.target_url)
        is_resume = False
    else:
        # 3. 폴더 없이 외곽에서 즉시 시작할 때: 신규 타임스탬프 폴더 생성
        session_dir = agents.get_session_dir(req.target_url)
        is_resume = False

    async def event_generator():
        log_file = os.path.join(session_dir, "scan_log.jsonl")
        sent_lines = 0
        
        # 1. 파일이 이미 존재한다면 기존 로그들을 먼저 쏟아냄
        if os.path.exists(log_file):
            with open(log_file, "r", encoding="utf-8") as f:
                for line in f:
                    line_strip = line.strip()
                    if line_strip:
                        try:
                            # 2026-03-10: 덩어리(chunk) 로그도 실시간으로 쏟아줘야 
                            # 새로고침 시 AI 분석 과정이 자연스럽게 보임
                            yield f"data: {line_strip}\n\n"
                            sent_lines += 1
                            # 너무 빠르게 쏟으면 클라이언트가 버거울 수 있으므로 아주 짧은 지연
                            if sent_lines % 50 == 0:
                                await asyncio.sleep(0.01)
                        except: continue

        # 세션 ID가 결정되면 실시간 바인딩용 이벤트 전달
        current_sid = os.path.basename(session_dir)
        yield f"data: {{\"type\": \"scan_start\", \"session_id\": \"{current_sid}\"}}\n\n"

        if is_resume:
            yield f"data: {{\"type\": \"log\", \"agent\": \"System\", \"message\": \"스캔 세션에 재연결되었습니다.\", \"progress\": null}}\n\n"
        else:
            # 📌 project_info.json 저장 루틴 추가
            try:
                info_file = os.path.join(session_dir, "project_info.json")
                with open(info_file, "w", encoding="utf-8") as f:
                    json.dump({
                        "project_name": req.project_name if req.project_name else os.path.basename(session_dir),
                        "target": req.target_url
                    }, f, ensure_ascii=False, indent=2)
            except Exception as e:
                print(f"Error saving project_info.json: {e}")

            # 초기 세션 시작 로그를 파일에 기록하여 새로고침 시에도 보이게 함
            msg_json = agents.stream_log(session_dir, f"스캔 세션 시작: {session_dir}", "System", 0)
            yield f"data: {msg_json}\n\n"
            sent_lines += 1

        # 2. 백그라운드 스캔 실행 (새로운 스캔인 경우에만)
        if not is_resume and session_dir not in ACTIVE_SCANS:
            async def run_scan_task(ai_config: dict):
                try:
                    # 📌 .env 기반 Gemini API Key 폴백 제거됨

                    ACTIVE_SCANS.add(session_dir)
                    recon_data = None
                    async for update in run_recon_agent(req.target_url, session_dir, req.headers, enable_deep_recon=getattr(req, 'enable_deep_recon', True)):
                        if "recon_result" in update:
                            try:
                                data = json.loads(update)
                                recon_data = data.get("data")
                            except: pass
                        await asyncio.sleep(0)
                    
                    if recon_data and not agents.is_cancelled(session_dir):
                        async for update in run_analysis_agent(req.target_url, session_dir, recon_data, req.headers, ai_config):
                            await asyncio.sleep(0)
                except Exception as e:
                    agents.stream_log(session_dir, f"Background Scan Error: {str(e)}", "System")
                finally:
                    ACTIVE_SCANS.discard(session_dir)

            asyncio.create_task(run_scan_task(req.ai_config))

        # 3. 실시간 로그 테일링
        # 스캔이 활성 상태이거나 파일에 더 읽을 내용이 있으면 계속 루프
        timeout_count = 0
        while timeout_count < 7200: # 약 1시간
            if os.path.exists(log_file):
                with open(log_file, "r", encoding="utf-8") as f:
                    all_lines = f.readlines()
                    if len(all_lines) > sent_lines:
                        for idx in range(sent_lines, len(all_lines)):
                            line = all_lines[idx].strip()
                            if line:
                                yield f"data: {line}\n\n"
                                sent_lines += 1
                                # 스캔 완료 로그 탐지 시 연결 종료
                                if "scan_complete" in line:
                                    return
            
            # 스캔 작업이 완료된 경우 종료 체크
            if session_dir not in ACTIVE_SCANS:
                # 마지막으로 파일에 더 기록된 게 없는지 확인
                await asyncio.sleep(2)
                if os.path.exists(log_file):
                    with open(log_file, "r", encoding="utf-8") as f:
                        if len(f.readlines()) <= sent_lines:
                            break
            
            await asyncio.sleep(0.5)
            timeout_count += 1

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.post("/api/findings/save")
async def save_findings(req: SaveFindingsRequest):
    """클라이언트 상에서 수정 혹은 삭제된 취약점 리스트(ai_findings.json)를 서버 파일에 동기화해 저장합니다."""
    session_dir = agents.find_session_dir(req.session_id)
    if not os.path.exists(session_dir):
        return {"status": "error", "message": "유효하지 않은 세션 ID입니다."}
    
    file_path = os.path.join(session_dir, "ai_findings.json")
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(req.findings, f, indent=2, ensure_ascii=False)
        return {"status": "success", "message": "취약점 목록이 성공적으로 저장되었습니다."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/history/list")
async def get_history_list():
    """results/scan 및 results/precheck 폴더 내 생성된 개별 세션 목록 분리 반환"""
    scan_history = []
    precheck_history = []
    
    if os.path.exists(agents.ROOT_SCAN_DIR):
        scan_history = [e for e in os.listdir(agents.ROOT_SCAN_DIR) if os.path.isdir(os.path.join(agents.ROOT_SCAN_DIR, e))]
    if os.path.exists(agents.ROOT_PRECHECK_DIR):
        precheck_history = [e for e in os.listdir(agents.ROOT_PRECHECK_DIR) if os.path.isdir(os.path.join(agents.ROOT_PRECHECK_DIR, e))]
        
    scan_history.sort(reverse=True)
    precheck_history.sort(reverse=True)
    
    return {"status": "success", "sessions": scan_history, "precheck_sessions": precheck_history}

@app.get("/api/history/{session_id}/report")
async def get_history_report(session_id: str):
    """특정 세션의 strategy_report.md 내용을 반환"""
    report_path = os.path.join(agents.find_session_dir(session_id) or "", "strategy_report.md")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8", errors="ignore") as f:
            return {"status": "success", "content": f.read()}
    return {"status": "error", "message": "리포트를 찾을 수 없습니다."}

@app.get("/api/history/{session_id}/raw/{tool_name}")
async def get_history_raw_logs(session_id: str, tool_name: str):
    """특정 세션 내 개별 툴의 raw_output.txt 내용을 반환"""
    mapping = {"katana": "katana", "ffuf": "ffuf"}
    folder_name = mapping.get(tool_name, tool_name)
    if tool_name == "katana_jsonl":
        log_file = os.path.join(agents.find_session_dir(session_id) or "", "katana_full.jsonl")
    else:
        log_file = os.path.join(agents.find_session_dir(session_id) or "", folder_name, "raw_output.txt")
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            return {"status": "success", "content": f.read()}
    return {"status": "error", "message": "파일을 찾을 수 없습니다."}

@app.get("/api/history/{session_id}/json/{result_name}")
async def get_history_json_logs(session_id: str, result_name: str):
    """특정 세션 내 결과 JSON 데이터 반환"""
    log_file = os.path.join(agents.find_session_dir(session_id) or "", f"{result_name}.json")
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8") as f:
            try:
                data = json.load(f)
                return {"status": "success", "content": json.dumps(data, indent=2, ensure_ascii=False)}
            except:
                return {"status": "error", "message": "JSON 파싱 에러"}
    return {"status": "error", "message": "데이터를 찾을 수 없습니다."}

@app.put("/api/history/{session_id}/rename")
async def rename_session_project(session_id: str, req: RenameRequest):
    """프로젝트 이름을 수정 (project_info.json 업데이트)"""
    info_file = os.path.join(agents.find_session_dir(session_id) or "", "project_info.json")
    if os.path.exists(info_file):
        try:
            with open(info_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["project_name"] = req.project_name
            with open(info_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return {"status": "success", "message": "프로젝트 이름 변경 완료"}
        except Exception as e:
            return {"status": "error", "message": f"이름 변경 실패: {e}"}
    return {"status": "error", "message": "프로젝트 정보가 존재하지 않습니다."}

@app.put("/api/history/{session_id}/status")
async def update_session_status(session_id: str, req: UpdateStatusRequest):
    """프로젝트 상태 관리 (project_info.json 업데이트)"""
    info_file = os.path.join(agents.find_session_dir(session_id) or "", "project_info.json")
    if os.path.exists(info_file):
        try:
            with open(info_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["status"] = req.status
            with open(info_file, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            return {"status": "success", "message": "프로젝트 상태 변경 완료"}
        except Exception as e:
            return {"status": "error", "message": f"상태 변경 실패: {e}"}
    return {"status": "error", "message": "프로젝트 정보가 존재하지 않습니다."}

@app.delete("/api/history/{session_id}")
async def delete_session_project(session_id: str):
    """프로젝트 전체 데이터 삭제"""
    session_path = agents.find_session_dir(session_id)
    if os.path.exists(session_path):
        try:
            shutil.rmtree(session_path)
            return {"status": "success", "message": "프로젝트 삭제 완료"}
        except Exception as e:
            return {"status": "error", "message": f"삭제 실패: {e}"}
    return {"status": "error", "message": "프로젝트 폴더를 찾을 수 없습니다."}

@app.get("/api/history/{session_id}/files")
async def get_session_files(session_id: str):
    """특정 세션 디렉토리 내의 파일 목록 반환"""
    session_path = agents.find_session_dir(session_id)
    if os.path.exists(session_path):
        files = os.listdir(session_path)
        return {"status": "success", "files": sorted(files)}
    return {"status": "error", "message": "세션 폴더를 찾을 수 없습니다."}

@app.get("/api/history/{session_id}/logs")
async def get_session_logs(session_id: str):
    """특정 세션의 전체 로그 반환"""
    log_file = os.path.join(agents.find_session_dir(session_id) or "", "scan_log.jsonl")
    if os.path.exists(log_file):
        logs = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                try: logs.append(json.loads(line))
                except: continue
        return {"status": "success", "logs": logs}
    return {"status": "error", "message": "로그 파일이 없습니다."}

@app.post("/api/proxy")
async def set_proxy(req: ProxyRequest):
    """ZAP 상위 프록시 설정 API"""
    zap = ZAPClient()
    try:
        if req.enabled:
            await zap.set_upstream_proxy(req.proxy_host, req.proxy_port)
            return {"status": "success", "message": f"Upstream proxy set to {req.proxy_host}:{req.proxy_port}"}
        else:
            await zap.disable_upstream_proxy()
            return {"status": "success", "message": "Upstream proxy disabled"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.get("/api/zap/history")
async def get_zap_history():
    """ZAP 전체 히스토리 메시지 목록 반환"""
    zap = ZAPClient()
    try:
        messages = await zap.get_all_messages()
        return {"status": "success", "messages": messages}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/zap/analyze")
async def analyze_packets(req: PacketAnalysisRequest):
    """선택한 ZAP 히스토리 패킷 AI 심층 분석 요청"""
    try:
        from agents import analyze_selected_packets, get_session_dir
        import agents
        
        # 새로운 독립 스캔 세션 폴더 생성 (과거 이력 등록용)
        target_ep_url = req.packets[0].get("url", "http://ai_analysis") if req.packets else "http://ai_analysis"
        new_session_dir = get_session_dir(target_ep_url)
        
        # 💡 개선: 프로젝트 명칭 커스텀 지정 시 메타 파일 생성
        if req.project_name:
             import json
             from datetime import datetime
             with open(os.path.join(new_session_dir, "project_info.json"), "w", encoding="utf-8") as f:
                 json.dump({
                     "project_name": req.project_name, 
                     "target": target_ep_url, 
                     "created_at": datetime.now().strftime("%Y-%m-%d %H:%M")
                 }, f, ensure_ascii=False, indent=4)
        
        # 로그 초기화 (히스토리 표기용 및 목록 노출 유도)
        ai_config = req.ai_config
        # 📌 .env 기반 Gemini API Key 폴백 제거됨

        findings = await analyze_selected_packets(req.packets, ai_config, new_session_dir)
        
        agents.stream_log(new_session_dir, f"AI 분석 결과 도출 완료. 탐지 건수: {len(findings)}", "AI", 100)
        agents.stream_log(new_session_dir, "scan_complete", "System", 100) # 완료 마크 설정
        
        return {
            "status": "success", 
            "findings": findings,
            "session_id": os.path.basename(new_session_dir) # frontend 로드 제어용
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/zap/clear")
async def clear_zap():
    """ZAP 히스토리 및 사이트 트리 초기화 API"""
    zap = ZAPClient()
    try:
        await zap.clear_zap_history()
        return {"status": "success", "message": "ZAP history /  Site tree 초기화 완료."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/alive/start")
async def start_alive_check(req: AliveCheckRequest):
    """사전 점검(Alive Check) 스캔 시작 및 상태 저장"""
    ALIVE_CHECK_SESSION["domains"] = req.domains
    ALIVE_CHECK_SESSION["mode"] = "alive"
    ALIVE_CHECK_SESSION["session_id"] = req.session_id
    ALIVE_CHECK_SESSION["stop_event"] = asyncio.Event()
    return {"status": "success"}

@app.post("/api/shodan/start")
async def start_shodan_check(req: AliveCheckRequest):
    """Shodan InternetDB 스캔 시작 및 상태 저장"""
    SHODAN_CHECK_SESSION["domains"] = req.domains
    SHODAN_CHECK_SESSION["mode"] = "shodan"
    SHODAN_CHECK_SESSION["session_id"] = req.session_id
    SHODAN_CHECK_SESSION["stop_event"] = asyncio.Event()
    return {"status": "success"}

@app.post("/api/dork/start")
async def start_dork_check(req: DorkCheckRequest):
    """Google Dork 스캔 시작 및 상태 저장"""
    api_keys = req.api_keys
    cx_id = req.cx_id

    pass # 📌 .env 기반 API Key / CX ID 폴백 제거됨

    DORK_CHECK_SESSION["domains"] = req.domains
    DORK_CHECK_SESSION["api_keys"] = api_keys
    DORK_CHECK_SESSION["cx_id"] = cx_id
    DORK_CHECK_SESSION["session_id"] = req.session_id
    DORK_CHECK_SESSION["dork_categories"] = req.dork_categories
    DORK_CHECK_SESSION["stop_event"] = asyncio.Event()
    return {"status": "success"}

async def generic_alive_stream_generator(session_data):
    """Alive 및 Shodan SSE 스트림 통합 처리기"""
    domains = session_data.get("domains", [])
    stop_event = session_data.get("stop_event")
    mode = session_data.get("mode", "alive")
    session_id = session_data.get("session_id")
    
    if not stop_event:
        yield "data: " + json.dumps({"status": "error", "message": "No session"}) + "\n\n"
        return
        
    accumulated_results = []
    try:
        async for data in stream_alive_check(domains, stop_event, mode):
            yield data
            try:
                clean = data.strip()
                import re
                for match in re.finditer(r'data:\s*({.*?})(?=\s*data:|\s*$)', clean, re.DOTALL):
                    try:
                        parsed = json.loads(match.group(1).strip())
                        if parsed.get("status") == "progress":
                            accumulated_results.append(parsed["result"])
                    except: pass
            except: pass
    finally:
        if session_id and accumulated_results:
            from agents import find_session_dir, save_tool_result
            session_dir = find_session_dir(session_id)
            if session_dir:
                save_tool_result(session_dir, "alive_check_results" if mode == "alive" else "shodan_results", accumulated_results)

@app.get("/api/alive/stream")
async def alive_check_stream():
    """SSE 스트림으로 Alive Check 결과 즉시 반환"""
    return StreamingResponse(
        generic_alive_stream_generator(ALIVE_CHECK_SESSION),
        media_type="text/event-stream"
    )

@app.get("/api/shodan/stream")
async def shodan_check_stream():
    """SSE 스트림으로 Shodan 결과 즉시 반환"""
    return StreamingResponse(
        generic_alive_stream_generator(SHODAN_CHECK_SESSION),
        media_type="text/event-stream"
    )

@app.get("/api/dork/stream")
async def dork_check_stream():
    """SSE 스트림으로 Google Dork 스캔 결과 리턴"""
    domains = DORK_CHECK_SESSION.get("domains", [])
    api_keys = DORK_CHECK_SESSION.get("api_keys", [])
    cx_id = DORK_CHECK_SESSION.get("cx_id", "")
    stop_event = DORK_CHECK_SESSION.get("stop_event")
    session_id = DORK_CHECK_SESSION.get("session_id")
    dork_categories = DORK_CHECK_SESSION.get("dork_categories")

    if not stop_event:
        async def err_gen(): yield "data: " + json.dumps({"status": "error", "message": "No session"}) + "\n\n"
        return StreamingResponse(err_gen(), media_type="text/event-stream")

    async def dork_stream_generator():
        accumulated_results = []
        try:
            async for data in stream_google_dork(domains, api_keys, cx_id, stop_event, dork_categories):
                yield data
                try:
                    clean = data.strip()
                    if clean.startswith("data:"):
                        content = clean[5:].strip()
                        parsed = json.loads(content)
                        if parsed.get("status") == "progress":
                            # parsed["results"] 는 해당 도메인에서 발견한 리스트
                            accumulated_results.extend(parsed["results"])
                except: pass
        finally:
            if session_id and accumulated_results:
                from agents import find_session_dir, save_tool_result
                session_dir = find_session_dir(session_id)
                if session_dir:
                    save_tool_result(session_dir, "google_dork_results", accumulated_results)

    return StreamingResponse(dork_stream_generator(), media_type="text/event-stream")

@app.post("/api/scan/stop")
async def stop_scan(req: ScanRequest):
    """실행 중인 취약점 스캔 중지"""
    # 📌 요청에서 session_id 획득
    session_id = req.session_id
    from agents import find_session_dir, SCAN_SESSIONS_CANCELLED
    
    session_dir = find_session_dir(session_id) if session_id else None
    if session_dir:
        SCAN_SESSIONS_CANCELLED.add(session_dir)
        
        # 💡 백그라운드 구동 중인 Subprocess 강제 Kill
        from tools import stop_all_processes
        stop_all_processes()
        
        return {"status": "success", "message": "스캔 중지 명령이 전달되었습니다."}
    return {"status": "error", "message": "취소 요청용 타겟 세션을 지정할 수 없습니다."}

@app.post("/api/alive/stop")
async def stop_alive_check():
    """실행 중인 사전 점검 중지"""
    if ALIVE_CHECK_SESSION.get("stop_event"):
        ALIVE_CHECK_SESSION["stop_event"].set()
    return {"status": "success"}

@app.post("/api/shodan/stop")
async def stop_shodan_check():
    """실행 중인 Shodan 중지"""
    if SHODAN_CHECK_SESSION.get("stop_event"):
        SHODAN_CHECK_SESSION["stop_event"].set()
    return {"status": "success"}

@app.post("/api/dork/stop")
async def stop_dork_check():
    """실행 중인 Google Dork 중지"""
    if DORK_CHECK_SESSION.get("stop_event"):
        DORK_CHECK_SESSION["stop_event"].set()
    return {"status": "success"}

# SPA (Single Page Application) Routing Fallback
@app.get("/{full_path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, full_path: str):
    """
    API 경로가 아닌 모든 브라우저 직접 접근에 대해 index.html을 반환하여
    프론트엔드 라우터(History API)가 처리할 수 있도록 지원합니다.
    """
    if full_path.startswith("api/"):
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="API route not found")
    return templates.TemplateResponse("index.html", {"request": request})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
