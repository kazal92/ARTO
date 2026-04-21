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

// ── 로그 창 (appendLog v2) ─────────────────────────────
// 설계:
//   1) 소스(source)는 단일 정규화 맵으로 {뱃지 클래스, 한글 라벨}을 결정한다.
//   2) 레벨(error/warn/ok/cmd/hit)은 메시지 내용과 소스로부터 별도 판정하여
//      좌측 보더와 메시지 톤을 입힌다 — 뱃지와 독립적으로 동작한다.
//   3) URL 디스커버리 라인([RECON]/[ZAP]/[FFUF]/상태코드 포함)은 구조화 렌더.

let autoScroll = true;

const LOG_SOURCE_MAP = (() => {
    const M = {
        SYSTEM: { cls: 'log-src-system', label: 'SYSTEM' },
        CORE: { cls: 'log-src-system', label: 'SYSTEM' },
        RECON: { cls: 'log-src-recon', label: 'RECON' },
        NETWORK: { cls: 'log-src-recon', label: 'RECON' },
        ZAP: { cls: 'log-src-zap', label: 'ZAP' },
        ZAP_SPIDER: { cls: 'log-src-zap', label: 'ZAP' },
        FFUF: { cls: 'log-src-ffuf', label: 'FFUF' },
        AI: { cls: 'log-src-ai', label: 'AI' },
        AI_ANALYST: { cls: 'log-src-ai', label: 'AI' },
        AI_ENGINE: { cls: 'log-src-ai', label: 'AI' },
        TRIAGE: { cls: 'log-src-triage', label: '트리아지' },
        SPECIALIST: { cls: 'log-src-spec', label: '전문가' },
        AGENT: { cls: 'log-src-agent', label: 'AGENT' },
        NUCLEI: { cls: 'log-src-nuclei', label: 'NUCLEI' },
        NMAP: { cls: 'log-src-nmap', label: 'NMAP' },
        COMMAND: { cls: 'log-src-cmd', label: 'SHELL' },
        CMD: { cls: 'log-src-cmd', label: 'SHELL' },
        SHELL: { cls: 'log-src-cmd', label: 'SHELL' },
        ERROR: { cls: 'log-src-error', label: 'ERROR' },
    };
    return M;
})();

function _resolveLogSource(source) {
    const key = (source || 'SYSTEM').toString().toUpperCase().replace(/[^A-Z_]/g, '');
    if (LOG_SOURCE_MAP[key]) return LOG_SOURCE_MAP[key];
    // 미등록 소스는 시스템 뱃지 + 원본 라벨 사용
    return { cls: 'log-src-system', label: (source || 'SYSTEM').toString().toUpperCase().slice(0, 8) };
}

function _detectLogLevel(msg, sourceKey) {
    const s = (msg || '').toString();
    const u = s.toUpperCase();

    if (sourceKey === 'COMMAND' || sourceKey === 'CMD' || sourceKey === 'SHELL') return 'cmd';

    // 오류: 명시적 토큰 우선, 그리고 한글 키워드
    if (/^\s*\[(ERR|ERROR|FAIL|FATAL)\]/i.test(s)) return 'error';
    if (/(치명적|실패했|오류가|에러|예외)/.test(s)) return 'error';
    if (/\b(FAILED|FATAL|CRITICAL|TRACEBACK|EXCEPTION)\b/.test(u)) return 'error';

    // 경고
    if (/^\s*\[(WARN|WARNING)\]/i.test(s)) return 'warn';
    if (/(경고|주의)/.test(s)) return 'warn';

    // 성공/완료
    if (/^\s*\[(OK|DONE|SUCCESS)\]/i.test(s)) return 'ok';
    if (/(완료되었|성공|저장 완료|분석 완료|스캔 완료)/.test(s)) return 'ok';
    if (/\b(SUCCESS|COMPLETED|COMPLETE)\b/.test(u) && !u.includes('HTTP')) return 'ok';

    // 디스커버리 히트
    if (/^\[(FFUF|ZAP|RECON)\]/.test(s)) return 'hit';
    if (/(식별|발견|탐지)/.test(s)) return 'hit';

    return 'info';
}

function _escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, c => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
    })[c]);
}

// 구조화 렌더러들 — 평문을 의미 있는 조각으로 분해한다.
function _renderDiscoveryLine(msg) {
    // 지원 포맷:
    //   [FFUF] <METHOD> <URL> → <STATUS>
    //   [FFUF] <URL>
    //   [ZAP]  <URL>
    //   [RECON] <METHOD> <URL>
    const tagMatch = msg.match(/^\[(FFUF|ZAP|RECON)\]\s*(.*)$/);
    if (!tagMatch) return null;
    const tag = tagMatch[1];
    const rest = tagMatch[2].trim();

    // METHOD URL → STATUS
    let m = rest.match(/^([A-Z]{3,7})\s+(https?:\/\/\S+)\s*(?:→|->)\s*(\S+)$/);
    if (m) {
        return `<span class="log-hit-tag">[${tag}]</span>`
            + `<span class="log-hit-meta">${_escapeHtml(m[1])}</span> `
            + `<span class="log-hit-url">${_escapeHtml(m[2])}</span>`
            + `<span class="log-hit-arrow">→</span>`
            + `<span class="log-hit-status">${_escapeHtml(m[3])}</span>`;
    }
    // METHOD URL
    m = rest.match(/^([A-Z]{3,7})\s+(https?:\/\/\S+)$/);
    if (m) {
        return `<span class="log-hit-tag">[${tag}]</span>`
            + `<span class="log-hit-meta">${_escapeHtml(m[1])}</span> `
            + `<span class="log-hit-url">${_escapeHtml(m[2])}</span>`;
    }
    // URL only
    m = rest.match(/^(https?:\/\/\S+)$/);
    if (m) {
        return `<span class="log-hit-tag">[${tag}]</span>`
            + `<span class="log-hit-url">${_escapeHtml(m[1])}</span>`;
    }
    return null;
}

function _renderCommandLine(msg) {
    const raw = (msg || '').toString();
    const trimmed = raw.trimStart();
    const body = trimmed.startsWith('$') ? trimmed.slice(1).trimStart() : trimmed;
    return `<span class="log-cmd-prompt">$</span>${_escapeHtml(body)}`;
}

function appendLog(msg, source = 'System') {
    const win = document.getElementById('logWindow');
    if (!win) return;

    const rawSource = (source || 'System').toString();
    const sourceKey = rawSource.toUpperCase().replace(/[^A-Z_]/g, '');
    const { cls: badgeClass, label: badgeLabel } = _resolveLogSource(rawSource);
    const level = _detectLogLevel(msg, sourceKey);

    // 메시지 본문 렌더
    const safeMsg = (msg ?? '').toString();
    let msgHtml;
    if (level === 'cmd') {
        msgHtml = _renderCommandLine(safeMsg);
    } else {
        const discovered = _renderDiscoveryLine(safeMsg);
        msgHtml = discovered != null ? discovered : _escapeHtml(safeMsg);
    }

    const now = new Date();
    const hh = String(now.getHours()).padStart(2, '0');
    const mm = String(now.getMinutes()).padStart(2, '0');
    const ss = String(now.getSeconds()).padStart(2, '0');

    const div = document.createElement('div');
    div.className = `log-item log-lv-${level}`;
    div.innerHTML =
        `<span class="log-time">${hh}:${mm}:${ss}</span>`
        + `<span class="log-badge ${badgeClass}">${_escapeHtml(badgeLabel)}</span>`
        + `<span class="log-msg">${msgHtml}</span>`;

    win.appendChild(div);
    if (autoScroll) win.scrollTop = win.scrollHeight;

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
