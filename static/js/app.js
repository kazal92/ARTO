/**
 * app.js - 애플리케이션 진입점 (경량화)
 * 모든 기능 로직은 static/js/modules/ 폴더의 각 모듈에서 담당합니다.
 *
 * 로드 순서:
 *   utils.js → ui.js → settings.js → endpoints.js → findings.js
 *   → precheck.js → projects.js → scan.js → main.js → app.js
 */

const API_BASE = "";

window.onload = () => {
    loadSettings();
    initRouter();
    loadHistoryList();
};

function initRouter() {
    const path = window.location.pathname;
    let targetSection = 'section-dashboard';
    
    if (path === '/' || path === '/dashboard' || path === '/index.html') {
        targetSection = 'section-dashboard';
        localStorage.removeItem('currentSessionId');
    } else if (path === '/projects') {
        targetSection = 'section-projects';
        localStorage.removeItem('currentSessionId');
    } else if (path === '/scan/new') {
        targetSection = 'section-newscan';
        localStorage.removeItem('currentSessionId');
    } else if (path === '/settings') {
        targetSection = 'section-settings';
    } else if (path === '/precheck/projects') {
        targetSection = 'section-precheck-projects';
        localStorage.removeItem('currentSessionId');
    } else if (path === '/precheck/new') {
        targetSection = 'section-newprecheck';
        localStorage.removeItem('currentSessionId');
    } else if (path.startsWith('/scan/')) {
        const parts = path.split('/');
        if (parts.length >= 4) {
            localStorage.setItem('currentSessionId', parts[2]);
            const sub = parts[3];
            if(sub === 'endpoints') targetSection = 'section-endpoints';
            else if(sub === 'vulns') targetSection = 'section-vulns';
            else targetSection = 'section-overview';
        } else if (parts.length === 3) {
            localStorage.setItem('currentSessionId', parts[2]);
            targetSection = 'section-overview';
        }
    } else if (path.startsWith('/precheck/')) {
        const parts = path.split('/');
        if (parts.length >= 4) {
            localStorage.setItem('currentSessionId', parts[2]);
            const sub = parts[3];
            if(sub === 'shodan') targetSection = 'section-shodan';
            else targetSection = 'section-alive';
        } else if (parts.length === 3) {
            localStorage.setItem('currentSessionId', parts[2]);
            targetSection = 'section-alive';
        }
    }
    
    window.initialTargetSec = targetSection;
    
    // 세션이 없는 경우 일반 탭으로 즉시 렌더링 (세션이 있으면 loadHistoryList가 selectProject를 거쳐 알아서 전환함)
    if (!localStorage.getItem('currentSessionId')) {
        switchSection(targetSection);
    }
}

// 브라우저 뒤로가기 / 앞으로가기 처리
window.onpopstate = (event) => {
    if (event.state && event.state.sectionId) {
        if (!event.state.sId) {
            localStorage.removeItem('currentSessionId');
        } else {
            localStorage.setItem('currentSessionId', event.state.sId);
        }
        switchSection(event.state.sectionId);
    } else {
        initRouter();
    }
};
