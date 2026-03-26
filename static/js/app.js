/**
 * app.js - 애플리케이션 진입점 (경량화)
 * 모든 기능 로직은 static/js/modules/ 폴더의 각 모듈에서 담당합니다.
 *
 * 로드 순서:
 *   utils.js → ui.js → settings.js → endpoints.js → findings.js
 *   → precheck.js → projects.js → scan.js → main.js → app.js
 */

const API_BASE = "";

// 설정 자동 로드
window.onload = loadSettings;

// 프로젝트 목록 초기 로드
loadHistoryList();
