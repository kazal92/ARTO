# ARTO v2 — AI-powered Recon & Testing & Operation

> **ARTO**는 웹 애플리케이션 보안 취약점 탐지를 위한 AI 기반 자동화 보안 점검 플랫폼입니다.  
> OWASP ZAP · FFuF를 활용한 공격 표면 정찰부터 LLM 기반 취약점 분석, 사전 점검 도구까지 하나의 대시보드에서 관리합니다.

---

## 📋 주요 기능

| 기능 | 설명 |
|------|------|
| 🔍 **자동 정찰 (Recon)** | OWASP ZAP Spider + FFuF 퍼징으로 엔드포인트 자동 수집 |
| 🤖 **AI 취약점 분석** | LM Studio(로컬 LLM) / Google Gemini를 통한 HTTP 트래픽 심층 분석 |
| 📊 **프로젝트 관리** | 다중 스캔 세션 관리, 이름 변경, 상태 추적 (가동중/점검완료/중지) |
| ⚡ **사전 점검 도구** | Alive Check (도메인 생존 여부), Shodan 정보 수집, Google Dork 스캔 |
| 🗂️ **취약점 카드** | AI 분석 결과를 카드 형태로 관리, 수정·삭제·검증 지원 |
| 🔌 **ZAP 히스토리 연동** | 수동 탐색 패킷을 ZAP 히스토리에서 직접 가져와 AI 분석 가능 |
| 📡 **실시간 스트리밍** | SSE(Server-Sent Events) 기반 실시간 스캔 로그 출력 |

---

## 🚀 빠른 시작

### ⚡ 원클릭 설치 (setup.sh)

```bash
# 실행 권한 부여 후 실행
chmod +x setup.sh && sudo ./setup.sh
```

> `setup.sh` 실행 시 **Docker · ZAP 이미지 · FFuF · Python 패키지**를 모두 자동 설정합니다.

---

### 사전 요구사항

- Python 3.10+
- Docker (OWASP ZAP 실행용)
- FFuF (`ffuf` 바이너리가 PATH에 있어야 함)

> 위 요구사항이 설치되지 않았다면 아래 단계적 가이드를 따르세요.

---

### 1️⃣ Docker 설치 (Kali Linux / Debian 계열)

```bash
# 기존 구버전 제거
sudo apt remove docker docker-engine docker.io containerd runc -y

# 의존성 및 GPG 키 설치
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release

# Docker 공식 저장소 추가
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/debian $(lsb_release -cs) stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Docker Engine 설치
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io

# 현재 사용자를 docker 그룹에 추가 (sudo 없이 실행 가능)
sudo usermod -aG docker $USER && newgrp docker

# 설치 확인
docker --version
```

---

### 2️⃣ OWASP ZAP 이미지 다운로드

```bash
# ZAP Stable 이미지 사전 다운로드 (약 1GB)
docker pull ghcr.io/zaproxy/zaproxy:stable
```

---

### 3️⃣ ZAP 수동 실행 (개별 기동 시)

```bash
# ZAP 데몬 모드 실행 (API 키 인증 비활성화)
docker run --net=host --name zap_main -d \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

# 약 15초 대기 후 동작 확인
sleep 15 && curl -s http://127.0.0.1:8080/JSON/core/view/version/

# 컨테이너 중지 및 삭제
docker stop zap_main && docker rm zap_main
```

> ZAP API: **http://127.0.0.1:8080**  
> `api.disablekey=true` 옵션으로 API 키 인증을 비활성화하여 ARTO와 연동합니다.

---

### 4️⃣ ARTO 의존성 설치

```bash
pip install fastapi uvicorn httpx openai python-dotenv
```

---

### 5️⃣ 실행

```bash
# ZAP + 애플리케이션 한 번에 실행 (권장)
./run_app.sh

# 또는 개별 실행
docker run --net=host --name zap_main -d \
  ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
sleep 15
python3 main.py
```

> 기본 접속 주소: **http://localhost:8001**

---

## 📁 프로젝트 구조

```
ARTO_v2/
│
├── main.py                  # FastAPI 애플리케이션 진입점 (API 라우터 전체)
├── agents.py                # 핵심 AI 에이전트 로직 (정찰 · 분석 파이프라인)
├── tools.py                 # 외부 도구 실행 래퍼 (FFuF, ZAP Spider)
├── alive_checker.py         # 사전 점검 도구 (Alive Check, Shodan, Google Dork)
├── zap_client.py            # OWASP ZAP REST API 클라이언트
├── validator.py             # Benign Probe 검증 유틸리티
├── run_app.sh               # ZAP Docker 기동 + 앱 일괄 실행 스크립트
│
├── templates/
│   └── index.html           # 단일 페이지 웹 대시보드 (SPA)
│
├── static/
│   ├── css/
│   │   └── style.css        # 전체 UI 스타일 (다크 글래스모피즘 테마)
│   └── js/
│       ├── app.js           # 진입점 (API_BASE 상수 · 초기화 호출, ~17줄)
│       └── modules/         # 기능별 분리 모듈
│           ├── utils.js     # 공통 유틸리티 (formatTimeWithMs, isStaticFile)
│           ├── ui.js        # UI 제어 (섹션 전환, 드로어, 로그, 테마)
│           ├── settings.js  # 설정 저장/불러오기, 프록시, AI 엔진 설정
│           ├── endpoints.js # 엔드포인트 맵 (렌더링, 정렬, 필터, 페이지네이션)
│           ├── findings.js  # 취약점 카드 (렌더링, 삭제, 저장, 검증 모달)
│           ├── precheck.js  # 사전 점검 (Alive/Shodan/Dork 실행, Handsontable)
│           ├── projects.js  # 프로젝트 관리 (카드 그리드, CRUD, 세션 선택)
│           ├── scan.js      # 스캔 제어 (시작/정지, ZAP 폴링, AI 분석 요청)
│           └── main.js      # 세션 로드, 로그 뷰어, 배치 목록, 라우터
│
└── results/                 # 스캔 결과 저장 디렉토리 (자동 생성)
    ├── scan/                # 취약점 스캔 프로젝트별 폴더
    │   └── {프로젝트명_YYYYMMDD_HHMMSS}/
    │       ├── project_info.json        # 프로젝트 메타 정보
    │       ├── scan_log.jsonl           # 실시간 스캔 로그 (JSONL)
    │       ├── recon_map.json           # 정찰 수집 엔드포인트 전체 목록
    │       ├── ai_targets.json          # AI 분석 선정 타겟 목록
    │       ├── ai_input_full_requests.json  # AI 전송 전처리 요청 데이터
    │       ├── ai_input_batch_{N}.json  # 배치별 분할 입력 데이터
    │       └── ai_findings.json         # AI 분석 결과 (취약점 목록)
    └── precheck/            # 사전 점검 프로젝트별 폴더
        └── {프로젝트명_YYYYMMDD_HHMMSS}/
            ├── alive_check_results.json # Alive Check 결과
            ├── shodan_results.json      # Shodan 조회 결과
            └── google_dork_results.json # Google Dork 스캔 결과
```

---

## 🏗️ 백엔드 파일 설명

### `main.py` — FastAPI API 서버

전체 REST API 엔드포인트를 정의합니다.

| API | 메서드 | 설명 |
|-----|--------|------|
| `/api/project/create` | POST | 신규 프로젝트 생성 (스캔 없이 워크스페이스만 초기화) |
| `/api/scan` | POST | 스캔 시작 · SSE 스트리밍 |
| `/api/scan/stop` | POST | 진행 중인 스캔 강제 중단 |
| `/api/history/list` | GET | 전체 프로젝트 목록 반환 (scan · precheck 분리) |
| `/api/history/{id}/json/{name}` | GET | 세션 내 특정 JSON 파일 조회 |
| `/api/history/{id}/logs` | GET | 세션 전체 로그 조회 |
| `/api/history/{id}` | DELETE | 프로젝트 삭제 |
| `/api/history/{id}/rename` | PUT | 프로젝트 이름 변경 |
| `/api/history/{id}/status` | PUT | 프로젝트 상태 변경 |
| `/api/zap/history` | GET | ZAP 히스토리 전체 조회 |
| `/api/zap/analyze` | POST | 선택 패킷 AI 분석 |
| `/api/zap/clear` | POST | ZAP 히스토리 초기화 |
| `/api/alive/start` · `/stream` · `/stop` | POST / GET | Alive Check 제어 |
| `/api/shodan/start` · `/stream` · `/stop` | POST / GET | Shodan 스캔 제어 |
| `/api/dork/start` · `/stream` · `/stop` | POST / GET | Google Dork 제어 |
| `/api/proxy` | POST | ZAP 상위 프록시 설정 |

---

### `agents.py` — 핵심 AI 에이전트

스캔의 두 단계를 비동기 제너레이터로 구현합니다.

- **`run_recon_agent()`**: ZAP Spider → FFuF 퍼징 → Deep Recon (재귀 크롤링) → 최종 전수 동기화 순서로 엔드포인트를 수집
- **`run_analysis_agent()`**: 수집된 HTTP 요청을 AI에 전송, 배치 처리로 취약점 도출, `ai_findings.json`에 누적 저장
- **`analyze_selected_packets()`**: ZAP 히스토리에서 수동 선택된 패킷 AI 분석 (단회성)
- **`extract_vulnerabilities()`**: AI 응답에서 JSON 구조 파싱 (Markdown 코드 블록 포함 처리)

---

### `tools.py` — 외부 도구 실행

- **`run_ffuf()`**: FFuF 디렉토리 퍼징 실행, 결과를 비동기 스트림으로 반환
- **`run_zap_spider()`**: OWASP ZAP Spider 실행 및 결과 스트리밍
- **`minimize_request_raw()`**: AI 전송 전 요청 패킷 최소화 (토큰 절약)
- **`get_heuristic_score()`**: 엔드포인트 우선순위 점수 계산 (POST > GET, 파라미터 포함 경로 우선)

---

### `alive_checker.py` — 사전 점검 도구

- **`stream_alive_check()`**: 도메인 목록의 HTTP/HTTPS 접근 가능 여부 실시간 체크 (SSE 스트리밍)
- Shodan InternetDB API를 통한 포트 · 취약점 정보 수집
- **`stream_google_dork()`**: Google Custom Search API를 사용한 정보 노출 Dork 스캔

---

### `zap_client.py` — ZAP API 클라이언트

OWASP ZAP REST API(`http://127.0.0.1:8080`) 연동 클래스.

- Spider 실행, 히스토리 조회, 히스토리 초기화
- 상위 프록시 설정/해제

---

### `validator.py` — 검증 유틸리티

- **`run_benign_probe()`**: 무해한 요청을 보내 서버 응답 기준선 확보 (False Positive 방지용)

---

## 🧩 프론트엔드 모듈 설명

```
스크립트 로드 순서:
utils → ui → settings → endpoints → findings → precheck → projects → scan → main → app
```

| 모듈 | 주요 함수 | 설명 |
|------|----------|------|
| `utils.js` | `formatTimeWithMs`, `isStaticFile`, `debounce` | 전역 공통 유틸리티 |
| `ui.js` | `switchSection`, `openDrawer`, `appendLog`, `toggleTheme` | UI 전환 및 컴포넌트 제어 |
| `settings.js` | `saveSettings`, `loadSettings`, `toggleProxy`, `toggleAiSettings` | AI 설정 · 프록시 저장/불러오기 |
| `endpoints.js` | `renderEndpoints`, `applyFilters`, `sortEndpoints`, `changePage` | 엔드포인트 테이블 관리 |
| `findings.js` | `renderCards`, `deleteCard`, `saveFindings`, `openVerifyModal` | 취약점 결과 카드 관리 |
| `precheck.js` | `startAliveCheck`, `startDorkCheck`, `initHandsontable` | 사전 점검 도구 실행 |
| `projects.js` | `renderProjectGrid`, `selectProject`, `loadHistoryList` | 프로젝트 목록 및 CRUD |
| `scan.js` | `startScan`, `stopScan`, `pollZapHistory`, `analyzeSelectedEndpoints` | 스캔 실행 및 ZAP 연동 |
| `main.js` | `loadSession`, `initRouter`, `loadRawJson`, `updateBatchList` | 세션 데이터 로드 및 SPA 라우팅 |
| `app.js` | — | 진입점 (`API_BASE` 상수 + 초기화 호출만 포함) |

---

## 🔧 AI 엔진 설정

대시보드 Settings 탭에서 다음 AI 엔진을 선택할 수 있습니다:

| 엔진 | 설정 항목 | 특징 |
|------|----------|------|
| **LM Studio** (기본) | API URL + 모델명 | 로컬 실행, 인터넷 불필요 |
| **Google Gemini** | API Key + 모델 선택 | 대용량 컨텍스트 (최대 500KB 배치) |
| **Vertex AI** | Bearer Token | Google Cloud 기반 |

---

## 📊 스캔 흐름

```
프로젝트 생성
    ↓
ZAP Spider → 엔드포인트 수집
    ↓
FFuF 퍼징 → 숨겨진 경로 탐색
    ↓
Deep Recon → 신규 경로 재귀 크롤링
    ↓
ZAP 히스토리 전수 동기화
    ↓
AI 분석 (배치 처리) → 취약점 도출
    ↓
ai_findings.json 저장 + 카드 렌더링
```

---

## 📝 라이선스

내부 보안 점검 전용 도구입니다. 허가된 대상에 대해서만 사용하십시오.
