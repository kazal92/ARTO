/**
 * endpoints.js - 엔드포인트 맵 렌더링/정렬/필터/통계 모듈
 */

let allEndpoints = [];
let aiTargetUrls = new Set();
let endpointSortState = { column: 'ai', direction: 'asc' };
let currentPage = 1;
const pageSize = 100;
let endpointsToRender = [];

// ── 정렬 ────────────────────────────────────────────────

function sortEndpoints(column) {
    if (endpointSortState.column === column) {
        endpointSortState.direction = endpointSortState.direction === 'asc' ? 'desc' : 'asc';
    } else {
        endpointSortState.column = column;
        endpointSortState.direction = 'asc';
    }
    updateSortIcons();
    applyFilters();
}

function updateSortIcons() {
    document.querySelectorAll('th.sortable i').forEach(icon => {
        icon.className = 'fa-solid fa-sort';
        icon.style.opacity = '0.3';
    });
    const activeTh = document.querySelector(`th[onclick="sortEndpoints('${endpointSortState.column}')"] i`);
    if (activeTh) {
        activeTh.className = endpointSortState.direction === 'asc' ? 'fa-solid fa-sort-up' : 'fa-solid fa-sort-down';
        activeTh.style.opacity = '1';
        activeTh.style.color = 'var(--primary)';
    }
}

// ── 필터 ────────────────────────────────────────────────

function applyFilters() {
    const aiVal = document.getElementById('filterAiTarget').value;
    const methodVal = document.getElementById('filter메소드').value.toLowerCase();
    const urlVal = document.getElementById('filterUrl').value.toLowerCase();
    const statusVal = document.getElementById('filterStatus').value.toLowerCase();

    let filtered = allEndpoints.filter(ep => {
        const method = ep.method || 'GET';
        const isTarget = aiTargetUrls.has(method + ":" + ep.url);
        const matchAi = aiVal === "" || (aiVal === "yes" ? isTarget : !isTarget);
        const matchMethod = method.toLowerCase().includes(methodVal);
        const matchUrl = ep.url?.toLowerCase().includes(urlVal);
        const matchStatus = (ep.status || '').toString().toLowerCase().includes(statusVal);
        return matchAi && matchMethod && matchUrl && matchStatus;
    });

    filtered.sort((a, b) => {
        let valA, valB;
        const col = endpointSortState.column;
        if (col === 'ai') {
            valA = aiTargetUrls.has((a.method || 'GET') + ":" + a.url) ? 1 : 0;
            valB = aiTargetUrls.has((b.method || 'GET') + ":" + b.url) ? 1 : 0;
        } else if (col === 'index') {
            valA = a.originalIndex || 0; valB = b.originalIndex || 0;
        } else if (col === 'method') {
            valA = (a.method || '').toLowerCase(); valB = (b.method || '').toLowerCase();
        } else if (col === 'url') {
            valA = (a.url || '').toLowerCase(); valB = (b.url || '').toLowerCase();
        } else if (col === 'status') {
            valA = parseInt(a.status) || 0; valB = parseInt(b.status) || 0;
        } else if (col === 'time') {
            valA = a.time || ''; valB = b.time || '';
        } else if (col === 'size') {
            valA = a.responseSize || 0; valB = b.responseSize || 0;
        } else { valA = 0; valB = 0; }

        if (valA < valB) return endpointSortState.direction === 'asc' ? -1 : 1;
        if (valA > valB) return endpointSortState.direction === 'asc' ? 1 : -1;
        return 0;
    });

    renderEndpoints(filtered, true);
}

// ── 렌더링 ───────────────────────────────────────────────

function renderEndpoints(endpoints, skipClearFilters = false) {
    const el = document.getElementById('endpointsTableBody');
    el.innerHTML = '';
    endpointsToRender = endpoints;

    if (!skipClearFilters) {
        allEndpoints = endpoints;
        currentPage = 1;
    }

    // 통계 계산
    let totalCount = endpointsToRender.length;
    let getCount = 0, postCount = 0, otherCount = 0, aiTargetCount = 0;
    endpointsToRender.forEach(ep => {
        const method = (ep.method || 'GET').toUpperCase();
        if (method === 'GET') getCount++;
        else if (method === 'POST') postCount++;
        else otherCount++;
        if (aiTargetUrls.has(`${ep.method || 'GET'}:${ep.url}`)) aiTargetCount++;
    });

    const updateStat = (id, val) => { const s = document.getElementById(id); if (s) s.textContent = val; };
    updateStat('statEpTotal', totalCount);
    updateStat('statEpGet', getCount);
    updateStat('statEpPost', postCount);
    updateStat('statEpOther', otherCount);
    updateStat('statEpAi', aiTargetCount);
    const statEp = document.getElementById('statEndpoints');
    if (statEp) statEp.textContent = totalCount;

    // 기본 정렬 (AI 타겟 우선, 수동 정렬 시 건너뜀)
    if (!skipClearFilters) {
        endpointsToRender.sort((a, b) => {
            const aT = aiTargetUrls.has((a.method || 'GET') + ":" + a.url);
            const bT = aiTargetUrls.has((b.method || 'GET') + ":" + b.url);
            if (aT && !bT) return -1;
            if (!aT && bT) return 1;
            return 0;
        });
    }

    if (totalCount === 0) {
        el.innerHTML = '<tr><td colspan="9" class="empty-state">발견된 엔드포인트가 없습니다.</td></tr>';
        const pag = document.getElementById('endpointPagination');
        if (pag) pag.innerHTML = '';
        return;
    }

    const totalPages = Math.ceil(totalCount / pageSize);
    if (currentPage > totalPages) currentPage = totalPages;
    if (currentPage < 1) currentPage = 1;

    const startIndex = (currentPage - 1) * pageSize;
    const sliced = endpointsToRender.slice(startIndex, startIndex + pageSize);

    sliced.forEach((ep, sIdx) => {
        const globalIdx = startIndex + sIdx;
        const tr = document.createElement('tr');
        const method = ep.method || 'GET';
        const methodUpper = method.toUpperCase();

        const methodClasses = { GET:'method-get', POST:'method-post', PUT:'method-put', DELETE:'method-delete', PATCH:'method-patch' };
        const methodClass = methodClasses[methodUpper] || 'method-other';

        const aiKey = `${method}:${ep.url}`;
        const isAiTarget = aiTargetUrls.has(aiKey);
        const aiBadge = isAiTarget
            ? '<span class="badge-ai" style="padding:2px 7px;border-radius:4px;font-size:0.68rem;"><i class="fa-solid fa-brain me-1"></i>Yes</span>'
            : '<span class="text-muted" style="font-size:0.75rem;">—</span>';

        const status = (ep.status !== undefined && ep.status !== null) ? String(ep.status) : '-';
        let statusBadge = '';
        if (status === '-') {
            statusBadge = '<span class="status-badge status-unk">—</span>';
        } else {
            const code = parseInt(status);
            let sType = 'status-unk';
            if (code >= 200 && code < 300) sType = 'status-2xx';
            else if (code >= 300 && code < 400) sType = 'status-3xx';
            else if (code >= 400 && code < 500) sType = 'status-4xx';
            else if (code >= 500) sType = 'status-5xx';
            statusBadge = `<span class="status-badge ${sType}">${status}</span>`;
        }

        const resSize = (() => {
            const n = ep.responseSize;
            if (n == null || n === '') return '-';
            const bytes = parseInt(n);
            return isNaN(bytes) ? '-' : bytes;
        })();
        tr.innerHTML = `
            <td class="text-center"><input type="checkbox" class="endpoint-check" data-method="${method}" data-url="${(ep.url || '').replace(/"/g, '&quot;')}" ${isAiTarget ? 'checked' : ''} onchange="handleEndpointCheck(this)"></td>
            <td class="text-center text-muted" style="font-size:0.72rem;">${ep.originalIndex || (globalIdx + 1)}</td>
            <td class="text-center">${aiBadge}</td>
            <td class="text-center"><span class="method-tag ${methodClass}">${methodUpper}</span></td>
            <td class="font-mono" style="word-break:break-all;color:var(--text-main);font-size:0.82rem;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${ep.url}">${ep.url}</td>
            <td class="text-center">${statusBadge}</td>
            <td class="text-center font-mono" style="font-size:0.72rem;color:var(--text-muted);">${ep.time || '-'}</td>
            <td class="text-center font-mono" style="font-size:0.72rem;color:var(--text-muted);">${resSize}</td>
            <td class="text-center">
                <button class="ep-detail-btn" onclick="openEndpointModalByIdx(${globalIdx})" title="상세보기">
                    <i class="fa-solid fa-arrow-up-right-from-square"></i>
                </button>
            </td>
        `;
        el.appendChild(tr);
    });

    renderPaginationControls(totalPages);
}

function renderPaginationControls(totalPages) {
    const container = document.getElementById('endpointPagination');
    if (!container) return;
    container.innerHTML = '';
    if (totalPages <= 1) return;

    const maxVisible = 5;
    let start = Math.max(1, currentPage - 2);
    let end = Math.min(totalPages, start + maxVisible - 1);
    if (end - start < maxVisible - 1) start = Math.max(1, end - maxVisible + 1);

    let html = `<button class="btn btn-sm btn-outline-info ${currentPage === 1 ? 'disabled' : ''}" onclick="changePage(${currentPage - 1})">Prev</button>`;
    for (let i = start; i <= end; i++) {
        html += `<button class="btn btn-sm ${i === currentPage ? 'btn-info text-white' : 'btn-outline-info'}" style="min-width:32px;" onclick="changePage(${i})">${i}</button>`;
    }
    html += `<button class="btn btn-sm btn-outline-info ${currentPage === totalPages ? 'disabled' : ''}" onclick="changePage(${currentPage + 1})">Next</button>`;
    container.innerHTML = html;
}

function changePage(page) {
    currentPage = page;
    renderEndpoints(endpointsToRender, true);
}

// ── 체크박스 = AI 타겟 토글 ───────────────────────────────

function handleEndpointCheck(checkbox) {
    const method = checkbox.getAttribute('data-method') || 'GET';
    const url = checkbox.getAttribute('data-url');
    const key = `${method}:${url}`;
    if (checkbox.checked) aiTargetUrls.add(key);
    else aiTargetUrls.delete(key);
    applyFilters();
    saveAiTargets();
}

function toggleAllEndpoints(masterCheckbox) {
    document.querySelectorAll('.endpoint-check').forEach(c => {
        c.checked = masterCheckbox.checked;
        const key = `${c.getAttribute('data-method') || 'GET'}:${c.getAttribute('data-url')}`;
        if (masterCheckbox.checked) aiTargetUrls.add(key);
        else aiTargetUrls.delete(key);
    });
    applyFilters();
    saveAiTargets();
}

// ── AI 타겟 저장 ─────────────────────────────────────────

function saveAiTargets() {
    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId) return;
    fetch(`${API_BASE}/api/session/${sessionId}/ai_targets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ targets: [...aiTargetUrls] })
    }).catch(() => {});
}

// ── 자동 타겟지정 ────────────────────────────────────────

async function autoTarget() {
    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId) return;
    const btn = document.getElementById('btnAutoTarget');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin me-1"></i>분석 중...'; }

    try {
        const res = await fetch(`${API_BASE}/api/session/${sessionId}/auto_target`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'ok') {
            aiTargetUrls.clear();
            (data.targets || []).forEach(t => aiTargetUrls.add(t));
            applyFilters();
        }
    } catch (e) {
        console.error('auto_target error', e);
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-crosshairs me-1"></i>자동 타겟지정'; }
    }
}

// ── AI 분석 실행 ─────────────────────────────────────────

function runAiAnalysis() {
    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId) return;
    if (aiTargetUrls.size === 0) {
        alert('AI 분석 대상이 없습니다. 먼저 타겟을 지정하세요.');
        return;
    }
    if (typeof startAiScan === 'function') startAiScan(sessionId);
}

// ── 엔드포인트 상세 모달 ───────────────────────────────────

function openEndpointModalByIdx(idx) {
    const ep = endpointsToRender[idx];
    if (!ep) return;

    const methodUpper = (ep.method || 'GET').toUpperCase();
    const methodClasses = { GET:'method-get', POST:'method-post', PUT:'method-put', DELETE:'method-delete', PATCH:'method-patch' };
    const methodClass = methodClasses[methodUpper] || 'method-other';

    const escapeHtml = s => s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const reqRaw = escapeHtml(ep.request_raw || '(No Request Data)');
    const resRaw = escapeHtml(ep.response_raw || '(No Response Data)');
    const reqSize = ep.requestSize ? `${ep.requestSize} bytes` : `${reqRaw.length} bytes`;
    const resSize = ep.responseSize ? `${ep.responseSize} bytes` : `${resRaw.length} bytes`;

    const html = `
        <div class="d-flex align-items-center gap-2 mb-3 flex-wrap">
            <span class="method-tag ${methodClass}">${methodUpper}</span>
            <code class="text-info" style="font-size:0.85rem;word-break:break-all;">${ep.url || '-'}</code>
        </div>
        <div class="d-flex gap-2 mb-3 flex-wrap">
            <span class="badge bg-secondary">📅 ${ep.time || '-'}</span>
            <span class="badge bg-dark border">📤 Request: ${reqSize}</span>
            <span class="badge bg-dark border">📥 Response: ${resSize}</span>
        </div>
        <ul class="nav nav-tabs mb-2" id="epDetailTabs">
            <li class="nav-item">
                <button class="nav-link active" onclick="epDetailTab('req')">Request</button>
            </li>
            <li class="nav-item">
                <button class="nav-link" onclick="epDetailTab('res')">Response</button>
            </li>
        </ul>
        <div id="epReqPane" style="display:block;">
            <pre style="font-size:0.75rem;color:var(--info);white-space:pre-wrap;max-height:350px;overflow:auto;background:rgba(0,0,0,0.2);padding:10px;border-radius:8px;">${reqRaw}</pre>
        </div>
        <div id="epResPane" style="display:none;">
            <pre style="font-size:0.75rem;color:var(--text-main);white-space:pre-wrap;max-height:350px;overflow:auto;background:rgba(0,0,0,0.2);padding:10px;border-radius:8px;">${resRaw}</pre>
        </div>
    `;
    if (typeof openDrawer === 'function') openDrawer(`Endpoint Detail — ${ep.url}`, html);
}

window.epDetailTab = function(tab) {
    document.getElementById('epReqPane').style.display = tab === 'req' ? 'block' : 'none';
    document.getElementById('epResPane').style.display = tab === 'res' ? 'block' : 'none';
    document.querySelectorAll('#epDetailTabs .nav-link').forEach(el => el.classList.remove('active'));
    const activeTab = document.querySelector(`#epDetailTabs .nav-link[onclick="epDetailTab('${tab}')"]`);
    if (activeTab) activeTab.classList.add('active');
};
