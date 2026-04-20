/**
 * ui.js - ARTO 공통 UI 컨트롤 모듈
 * 섹션 전환, 서랍, 로그 창, 브레드크럼 등
 */

// ── 섹션 전환 ──────────────────────────────────────────

function switchSection(sectionId) {
    document.querySelectorAll('.menu-item').forEach(m => m.classList.remove('active'));
    const activeMenu = document.querySelector(`.menu-item[data-sec="${sectionId}"]`);
    if (activeMenu) activeMenu.classList.add('active');

    document.querySelectorAll('.content-section').forEach(sec => sec.classList.remove('active'));
    const targetSec = document.getElementById(sectionId);
    if (targetSec) targetSec.classList.add('active');

    const breadcrumbText = document.getElementById('breadcrumbText');
    if (breadcrumbText) {
        const labels = {
            'section-dashboard': '<i class="fa-solid fa-house text-primary me-1"></i> ARTO Security Center',
            'section-projects': '<i class="fa-solid fa-folder-tree text-warning me-1"></i> 모든 프로젝트 허브',
            'section-newscan': '<i class="fa-solid fa-square-plus text-success me-1"></i> 신규 프로젝트 생성',
            'section-settings': '<i class="fa-solid fa-gear text-secondary me-1"></i> 환경 설정 (AI / 프록시)',
            'section-precheck': '<i class="fa-solid fa-bolt text-info me-1"></i> 사전 점검 도구 (URL Alive Check)',
            'section-agent': '<i class="fa-solid fa-robot me-1" style="color:#a78bfa;"></i> AI 에이전트 점검',
            'section-terminal': '<i class="fa-solid fa-terminal me-1" style="color:#34d399;"></i> 웹 터미널',
        };
        if (labels[sectionId]) breadcrumbText.innerHTML = labels[sectionId];
    }

    // 엔드포인트 분석 섹션 진입 시 첫 탭(AI 분析)으로 초기화
    if (sectionId === 'section-endpoints') {
        if (typeof switchScanResultTab === 'function') switchScanResultTab('vulns');
    }

    closeDrawer();
    updateBrowserUrlFromSection(sectionId);
}

/**
 * 프로젝트 모드(세션 유지 상태)를 종료하고 일반 섹션으로 이동합니다.
 * @param {string} sectionId - 이동할 섹션 ID (기본값: 'section-projects')
 */
function exitProjectMode(sectionId = 'section-projects') {
    // 1. 현재 세션 정보 삭제
    localStorage.removeItem('currentSessionId');
    if (typeof currentProject !== 'undefined') {
        currentProject = { id: null, name: null };
    }
    
    // 2. 섹션 전환
    switchSection(sectionId);
    
    // 3. UI 초기화
    const subPentestTools = document.getElementById('sub-pentest-tools');
    const subScan = document.getElementById('sub-scan');
    const subPrecheck = document.getElementById('sub-precheck');
    if (subPentestTools) subPentestTools.style.display = 'none';
    if (subScan) subScan.style.display = 'none';
    if (subPrecheck) subPrecheck.style.display = 'none';

    const topbarScanControls = document.getElementById('topbarScanControls');
    if (topbarScanControls) topbarScanControls.style.display = 'none';

    const breadcrumbText = document.getElementById('breadcrumbText');
    if (breadcrumbText) {
        if (sectionId === 'section-dashboard') breadcrumbText.innerHTML = '<i class="fa-solid fa-house text-primary me-1"></i> ARTO Security Center';
        else breadcrumbText.innerText = '모든 프로젝트 허브';
    }

    const scanStatusText = document.getElementById('scanStatusText');
    if (scanStatusText) scanStatusText.innerHTML = '<i class="fa-solid fa-house-chimney text-muted me-2"></i>대기 중';
    
    const progressBar = document.getElementById('progressBar');
    if (progressBar) progressBar.style.width = '0%';
}

function updateBrowserUrlFromSection(sectionId) {
    let newPath = "/";
    const sid = (typeof currentProject !== 'undefined' && currentProject.id)
        || localStorage.getItem('currentSessionId');

    const pathMap = {
        "section-projects": "/projects",
        "section-newscan": "/scan/new",
        "section-settings": "/settings",
        "section-precheck-projects": "/precheck/projects",
        "section-newprecheck": "/precheck/new",
    };

    if (pathMap[sectionId]) {
        newPath = pathMap[sectionId];
    } else if (sectionId === "section-overview" && sid) newPath = `/scan/${sid}/overview`;
    else if (sectionId === "section-endpoints" && sid) newPath = `/scan/${sid}/endpoints`;
    else if (sectionId === "section-vulns" && sid) newPath = `/scan/${sid}/vulns`;
    else if (sectionId === "section-agent" && sid) newPath = `/scan/${sid}/agent`;
    else if (sectionId === "section-terminal" && sid) newPath = `/scan/${sid}/terminal`;
    else if (sectionId === "section-alive" && sid) newPath = `/precheck/${sid}/alive`;
    else if (sectionId === "section-shodan" && sid) newPath = `/precheck/${sid}/shodan`;

    if (window.location.pathname !== newPath) {
        window.history.pushState({ sectionId, sId: sid }, "", newPath);
    }
}

// ── 서브메뉴 토글 ────────────────────────────────────────

function toggleSubMenu(id) {
    const el = document.getElementById(id);
    if (!el) return;
    const isOpen = el.style.display !== 'none';
    el.style.display = isOpen ? 'none' : 'block';
    const chevron = document.getElementById('chevron-' + id.replace('sub-', ''));
    if (chevron) chevron.style.transform = isOpen ? 'rotate(-90deg)' : '';
}

// ── 서랍 (Side Drawer) ──────────────────────────────────

function openDrawer(title, htmlBody) {
    document.getElementById('drawerTitle').innerText = title;
    document.getElementById('drawerBody').innerHTML = htmlBody;
    document.getElementById('sideDrawer').classList.add('open');
    document.getElementById('drawerBackdrop').classList.add('open');

    const drawEditBtn = document.getElementById('btnEditCard');
    if (drawEditBtn) drawEditBtn.style.display = 'none';
}

function closeDrawer() {
    const drawer = document.getElementById('sideDrawer');
    const backdrop = document.getElementById('drawerBackdrop');
    if (drawer) drawer.classList.remove('open');
    if (backdrop) backdrop.classList.remove('open');
}

// ── 로그 창 (appendLog) ─────────────────────────────────

let autoScroll = true;

function appendLog(msg, source = "System") {
    const win = document.getElementById('logWindow');
    if (!win) return;
    const div = document.createElement('div');
    div.className = "log-item";
    div.style.cssText = "display:flex;align-items:center;gap:8px;margin-bottom:3px;";

    let badgeClass = "badge-core";
    let badgeText = source.toUpperCase();
    let msgColor = "var(--text-main)";
    let prefix = "";

    const s = source.toUpperCase();
    if (s === "SYSTEM" || s === "CORE") {
        badgeClass = "badge-core"; badgeText = "시스템"; msgColor = "var(--secondary)";
    } else if (s === "RECON" || s === "NETWORK") {
        badgeClass = "badge-recon"; badgeText = "정찰"; msgColor = "var(--info)";
    } else if (["AI", "AI_ANALYST", "AI_ENGINE"].includes(s)) {
        badgeClass = "badge-ai"; badgeText = "AI 분석"; msgColor = "var(--color-purple)";
    } else if (["COMMAND", "CMD", "SHELL"].includes(s)) {
        badgeClass = "badge-cmd"; badgeText = "쉘";
        msgColor = "var(--high)";
        // 메시지가 이미 $ 로 시작하면 접두사 생략
        const _m = (msg || "").toString().trimStart();
        if (!_m.startsWith('$')) {
            prefix = '<span style="color:var(--high);margin-right:5px;">$</span>';
        }
    }

    const safeMsg = (msg || "").toString();
    const upperMsg = safeMsg.toUpperCase();
    const isBoldMsg = safeMsg.includes('ZAP Spider 탐색 시작') || safeMsg.includes('FFuF 디렉토리/파일 퍼징');
    const isFfufDiscovery = safeMsg.startsWith('[FFUF]');
    const isZapDiscovery = safeMsg.startsWith('[ZAP]') && /^https?:\/\//.test(safeMsg.slice(5).trim());
    const isErrorMsg = (upperMsg.includes("FAIL") || safeMsg.includes("실패") || safeMsg.includes("치명적"))
        || (upperMsg.includes("ERROR") && !upperMsg.includes("HTTP") && !/\/[^\s]*ERROR[^\s]*/i.test(safeMsg));

    const YELLOW = '#facc15';

    let renderedMsg = msg;
    if (isFfufDiscovery) {
        const m = safeMsg.match(/^\[FFUF\]\s+(\w+)\s+(https?:\/\/\S+)\s*→\s*(\S+)$/);
        if (m) {
            renderedMsg = `<span style="color:${YELLOW};font-weight:700;">[FFUF]</span> <span style="color:var(--text-muted);font-size:0.8rem;">${m[1]}</span> <span style="color:${YELLOW};font-family:monospace;">${m[2]}</span> <span style="color:var(--text-muted);">→</span> <span style="color:${YELLOW};font-weight:600;">${m[3]}</span>`;
        } else {
            renderedMsg = `<span style="color:${YELLOW};font-weight:700;">[FFUF]</span> <span style="color:${YELLOW};font-family:monospace;">${safeMsg.slice(6).trim()}</span>`;
        }
    } else if (isZapDiscovery) {
        const url = safeMsg.slice(5).trim();
        renderedMsg = `<span style="color:${YELLOW};font-weight:700;">[ZAP]</span> <span style="color:${YELLOW};font-family:monospace;">${url}</span>`;
    } else if (isErrorMsg) {
        badgeClass = "badge-error"; badgeText = "오류"; msgColor = "var(--critical)";
    } else if (upperMsg.includes("DISCOVERY") || upperMsg.includes("FOUND") || upperMsg.includes("식별")) {
        if (s !== "RECON" && s !== "NETWORK") msgColor = "var(--high)";
    } else if (upperMsg.includes("COMPLETE") || upperMsg.includes("성공") || upperMsg.includes("SUCCESS")) {
        if (s !== "RECON" && s !== "NETWORK") msgColor = "var(--secondary)";
    }

    const timeStr = `<span class="log-time">${new Date().toLocaleTimeString('en-US', { hour12: false })}</span>`;
    const badgeStr = `<span class="log-badge ${badgeClass}">${badgeText}</span>`;
    const msgContent = (isFfufDiscovery || isZapDiscovery)
        ? renderedMsg
        : `${prefix}<span style="color:${msgColor};${isBoldMsg ? 'font-weight:700;' : ''}">${msg}</span>`;
    div.innerHTML = `${timeStr}${badgeStr}<span class="log-msg" style="word-break:break-all;">${msgContent}</span>`;

    win.appendChild(div);
    if (autoScroll) win.scrollTop = win.scrollHeight;

    // 💾 실시간 로그 백업 (다른 섹션 이동했다가 돌아왔을 때 복원용)
    if (typeof logWindowBackup !== 'undefined') {
        logWindowBackup += div.outerHTML;
    }
}

function restoreLogs() {
    const win = document.getElementById('logWindow');
    if (win && typeof logWindowBackup !== 'undefined') win.innerHTML = logWindowBackup;
}

// ── 테마 토글 ────────────────────────────────────────────

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeUI(next);
}

function updateThemeUI(theme) {
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon) icon.className = theme === 'dark' ? 'fa-solid fa-sun' : 'fa-solid fa-moon';
    if (label) label.textContent = theme === 'dark' ? '라이트 모드' : '다크 모드';
}

// ── 옵션 패널 토글 ──────────────────────────────────────

function toggleFfufOptions(show) {
    const panel = document.getElementById('ffufOptionsPanel');
    if (panel) panel.style.display = show ? 'block' : 'none';
}

function toggleNucleiOptions(show) {
    const panel = document.getElementById('nucleiOptionsPanel');
    if (panel) panel.style.display = show ? 'block' : 'none';
}

function toggleNmapOptions(show) {
    const panel = document.getElementById('nmapOptionsPanel');
    if (panel) panel.style.display = show ? 'block' : 'none';
}

// 페이지 로드시 초기 상태 설정
document.addEventListener('DOMContentLoaded', () => {
    const enableFfuf = document.getElementById('enableFfuf');
    const enableNuclei = document.getElementById('enableNuclei');
    const enableNmap = document.getElementById('enableNmap');
    if (enableFfuf) toggleFfufOptions(enableFfuf.checked);
    if (enableNuclei) toggleNucleiOptions(enableNuclei.checked);
    if (enableNmap) toggleNmapOptions(enableNmap.checked);
});
