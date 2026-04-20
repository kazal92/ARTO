# ARTO v2.0 - Enterprise Security Scanner

## 프로젝트 개요

**ARTO**는 엔드포인트 매핑, AI 기반 취약점 분석, 그리고 Nuclei 템플릿 기반 자동 스캔을 통합한 **엔터프라이즈급 보안 스캐너**입니다.

- **목적**: 웹 애플리케이션의 보안 취약점을 종합적으로 발견하고 분석
- **타겟 사용자**: 보안 침투 테스트 전문가, 보안 연구원
- **핵심 기능**: 네트워크 정찰 → AI 분석 → Nuclei 템플릿 스캔

---

## 기술 스택

### Backend
- **Framework**: FastAPI (Python 3.x)
- **WebSocket**: 실시간 스트리밍 로그 및 이벤트
- **주요 도구**:
  - ZAP (OWASP ZAP) - 웹 크롤링 및 정찰
  - ffuf - 디렉토리/파일 퍼징
  - Nuclei - 템플릿 기반 취약점 스캔
  - Claude API - AI 기반 취약점 분석

### Frontend
- **Framework**: Vanilla JavaScript (ES6+)
- **UI Library**: Bootstrap 5.3
- **Icon**: FontAwesome 6.4
- **Terminal**: xterm.js (웹 터미널)
- **Spreadsheet**: Handsontable

---

## 폴더 구조

```
arto/
├── api/                          # FastAPI 라우터
│   ├── scan.py                   # 스캔 시작/정지 API
│   ├── history.py                # 프로젝트 설정 저장/로드
│   ├── endpoints.py              # 엔드포인트 관리
│   ├── findings.py               # 취약점 결과 관리
│   ├── nuclei.py                 # Nuclei 스캔 API
│   ├── terminal.py               # 웹 터미널 API
│   └── ...
│
├── agents/                       # AI 에이전트
│   └── pentest_agent.py          # Claude API 기반 분석
│
├── static/
│   ├── js/modules/               # 프론트엔드 모듈
│   │   ├── scan.js               # 스캔 시작/정지 로직
│   │   ├── nuclei.js             # Nuclei 통합
│   │   ├── endpoints.js          # 엔드포인트 테이블 렌더링
│   │   ├── findings.js           # 취약점 카드 렌더링
│   │   ├── projects.js           # 프로젝트 관리
│   │   ├── ui.js                 # 로그, 섹션 전환 등
│   │   └── ...
│   └── css/
│
├── templates/
│   └── index.html                # 단일 SPA 페이지
│
├── results/scan/                 # 스캔 결과 저장소
│   └── {session_id}/
│       ├── project_info.json     # 프로젝트 설정
│       ├── endpoints.json        # 발견된 엔드포인트
│       ├── ai_findings.json      # AI 분석 결과
│       ├── nuclei/
│       │   └── findings.jsonl    # Nuclei 스캔 결과
│       └── ...
│
└── main.py                       # 애플리케이션 진입점

```

---

## 핵심 기능

### 1. 프로젝트 관리
- 타겟 URL 지정
- 커스텀 헤더/쿠키 설정
- ffuf 워드리스트 및 옵션 관리
- 프로젝트별 설정 저장

### 2. 정찰 단계 (Reconnaissance)
- **ZAP Spider**: 웹사이트 크롤링
- **ffuf**: 디렉토리 및 파일 퍼징
- **Deep Recon**: 재귀적 심층 탐색
- → **결과**: 엔드포인트 목록 추출 (endpoints.json)

### 3. AI 분석
- Claude API를 통한 각 엔드포인트 분석
- 가능한 공격 벡터 식별
- 취약점 가능성 평가
- → **결과**: AI 카드 생성 (ai_findings.json)

### 4. Nuclei 스캔
- 템플릿 기반 자동 취약점 스캔
- 중요도별 필터링 (critical, high, medium, low, info)
- 동적 옵션 설정
- → **결과**: Nuclei 발견사항 (nuclei/findings.jsonl)

### 5. 엔드포인트 분석
- 발견된 모든 엔드포인트의 테이블 형식 표시
- AI 분석 대상 선택
- Nuclei 결과 통합 표시
- 자동 타겟지정 기능

---

## 최근 변경사항 (2026-04-18)

### Nuclei 통합 완료
✅ **Nuclei 스캔이 기본 스캔 완료 후 자동 실행**
- 스캔 대상 탭에서 Nuclei 체크박스로 활성화/비활성화
- 실시간 로그: 스캔 대상 탭의 logWindow에 표시
- 결과 표시: 엔드포인트 탭 하단의 "Nuclei 발견사항" 패널
- 설정 저장/로드: enable_nuclei 필드 추가

### 수정된 파일
- `static/js/modules/nuclei.js`: logWindow → appendLog 통합
- `static/js/modules/scan.js`: Nuclei 자동 실행 로직 추가
- `static/js/modules/endpoints.js`: nucleiResults 변수 및 렌더링 함수 추가
- `api/history.py`: enable_nuclei 저장/로드
- `api/scan.py`: enable_nuclei 처리
- `static/js/modules/projects.js`: 프로젝트 로드시 enable_nuclei 복구
- `static/js/modules/settings.js`: enable_nuclei 저장
- `templates/index.html`: Nuclei 탭 제거, 엔드포인트 탭에 패널 추가

---

## 개발 가이드

### 스캔 흐름
```
사용자 설정
    ↓
스캔 시작 (startScan in scan.js)
    ↓
정찰 단계 (Recon: ZAP, ffuf, Deep Recon)
    ├→ logWindow에 실시간 로그
    └→ endpoints.json 생성
    ↓
AI 분석 (Claude API)
    ├→ AI 카드 생성
    └→ ai_findings.json 저장
    ↓
[enableNuclei 체크시] Nuclei 스캔 (startNucleiScan)
    ├→ logWindow에 로그
    ├→ nuclei/findings.jsonl 생성
    └→ nucleiResults에 저장
    ↓
스캔 완료
```

### 로그 시스템
- **`appendLog(msg, source)`**: UI 포맷팅된 로그 출력
  - source: "System", "Recon", "AI", "Nuclei", "Command" 등
  - 자동으로 배지와 색상 적용

### 설정 저장 구조 (project_info.json)
```json
{
  "project_name": "프로젝트명",
  "target": "http://example.com",
  "enable_zap_spider": true,
  "enable_ffuf": true,
  "enable_deep_recon": true,
  "enable_nuclei": true,
  "ffuf_options": "...",
  "ffuf_wordlist": "...",
  "headers": {...},
  "ai_config": {...}
}
```

---

## 주요 모듈 설명

### scan.js
- `startScan()`: 메인 스캔 시작 함수
  - 설정 검증
  - API 호출 (POST /api/scan)
  - SSE 스트림 처리
  - enable_nuclei 체크시 자동 Nuclei 실행

### nuclei.js
- `startNucleiScan()`: Nuclei 스캔 시작
  - 대상 URL, 옵션 설정
  - API 호출 (POST /api/nuclei/run)
  - 실시간 로그 처리
- `_nucleiLog()`: Nuclei 전용 로그 함수
  - `appendLog()` 호출로 통합 로그 포맷 사용
- `_nucleiEvent()`: 스트림 이벤트 처리
  - log, ai_card, scan_complete 타입 처리

### endpoints.js
- `renderEndpoints()`: 엔드포인트 테이블 렌더링
- `addNucleiResult()`: Nuclei 결과 추가
- `renderNucleiResults()`: Nuclei 발견사항 패널 렌더링
- `nucleiResults`: 전역 배열 (Nuclei 결과 저장)

### history.py (Backend)
- `SaveProjectInfoRequest`: 설정 저장 요청 모델
  - enable_nuclei 필드 포함
- `save_project_info()`: 설정 저장 API
  - project_info.json 업데이트

---

## 알려진 문제 및 주의사항

1. **Nuclei 스캔 시간**: 대규모 엔드포인트 목록의 경우 시간이 걸릴 수 있음
2. **메모리**: 많은 엔드포인트 처리시 브라우저 성능 저하 가능
3. **동시 실행**: 여러 프로젝트 동시 스캔 미지원

---

## 다음 개선사항

- [ ] Nuclei 필터링 옵션 UI 추가
- [ ] 스캔 중단 기능
- [ ] 결과 내보내기 (PDF, CSV)
- [ ] 스캔 스케줄링
- [ ] 취약점 우심도 커스터마이징

---

## 문의 및 피드백

새로운 세션에서 코드를 수정할 때 이 문서를 참고하세요!
