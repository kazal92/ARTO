/**
 * endpoints.js - 엔드포인트 맵 렌더링/정렬/필터/통계 모듈
 */

let allEndpoints = [];
let aiTargetUrls = new Set();
let endpointSortState = { column: 'ai', direction: 'asc' };
let currentPage = 1;
const pageSize = 100;
let endpointsToRender = [];
let nucleiResults = [];
let nmapResults = [];

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
    const sourceVal = document.getElementById('filterSource')?.value || '';

    let filtered = allEndpoints.filter(ep => {
        const method = ep.method || 'GET';
        const isTarget = aiTargetUrls.has(method + ":" + ep.url);
        const matchAi = aiVal === "" || (aiVal === "yes" ? isTarget : !isTarget);
        const matchMethod = method.toLowerCase().includes(methodVal);
        const matchUrl = ep.url?.toLowerCase().includes(urlVal);
        const matchStatus = (ep.status || '').toString().toLowerCase().includes(statusVal);
        if (!matchAi || !matchMethod || !matchUrl || !matchStatus) return false;
        if (sourceVal) {
            const srcs = ep.sources || [];
            if (sourceVal === 'zap_only' && !(srcs.includes('zap') && !srcs.includes('ffuf'))) return false;
            if (sourceVal === 'ffuf_only' && !srcs.includes('ffuf')) return false;
            if (sourceVal === 'both' && !(srcs.includes('zap') && srcs.includes('ffuf'))) return false;
        }
        return true;
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
        } else if (col === 'sources') {
            valA = (a.sources || []).join(','); valB = (b.sources || []).join(',');
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
    updateStat('epCount', totalCount);
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
        el.innerHTML = '<tr><td colspan="8" class="empty-state">발견된 엔드포인트가 없습니다.</td></tr>';
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
        if (!ep.url || ep.url === '-') return; // URL이 없으면 렌더링 스킵
        const globalIdx = startIndex + sIdx;
        const tr = document.createElement('tr');
        const method = ep.method || 'GET';
        const methodUpper = method.toUpperCase();

        const methodClasses = { GET:'method-get', POST:'method-post', PUT:'method-put', DELETE:'method-delete', PATCH:'method-patch' };
        const methodClass = methodClasses[methodUpper] || 'method-other';

        const aiKey = `${method}:${ep.url}`;
        const isAiTarget = aiTargetUrls.has(aiKey);
        const aiBadge = `<input type="checkbox" class="endpoint-check" data-method="${method}" data-url="${(ep.url || '').replace(/"/g, '&quot;')}" ${isAiTarget ? 'checked' : ''} onchange="handleEndpointCheck(this)">`;

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
        const srcs = ep.sources || ['zap'];
        const srcBadges = srcs.map(s =>
            `<span class="badge-source badge-source-${s}">${s.toUpperCase()}</span>`
        ).join(' ');
        tr.dataset.epIdx = globalIdx;
        tr.innerHTML = `
            <td class="text-center text-muted" style="font-size:0.72rem;">${ep.originalIndex || (globalIdx + 1)}</td>
            <td class="text-center">${aiBadge}</td>
            <td class="text-center"><span class="method-tag ${methodClass}">${methodUpper}</span></td>
            <td class="font-mono ep-url-cell" onclick="toggleEndpointDetail(${globalIdx})" style="cursor:pointer;word-break:break-all;color:var(--info);font-size:0.82rem;max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${ep.url}">${ep.url}</td>
            <td class="text-center">${statusBadge}</td>
            <td class="text-center">${srcBadges}</td>
            <td class="text-center font-mono" style="font-size:0.72rem;color:var(--text-muted);">${ep.time || '-'}</td>
            <td class="text-center font-mono" style="font-size:0.72rem;color:var(--text-muted);">${resSize}</td>
            <td class="text-center">
                <button class="btn btn-xs btn-outline-info" onclick="deepDiveEndpoint('${method}', '${(ep.url || '').replace(/'/g, "\\'")}', ${globalIdx}); event.stopPropagation();" style="padding:2px 6px;font-size:0.7rem;" title="이 엔드포인트 심층 검증">
                    <i class="fa-solid fa-crosshairs"></i>
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
}

function toggleAllEndpoints(masterCheckbox) {
    document.querySelectorAll('.endpoint-check').forEach(c => {
        c.checked = masterCheckbox.checked;
        const key = `${c.getAttribute('data-method') || 'GET'}:${c.getAttribute('data-url')}`;
        if (masterCheckbox.checked) aiTargetUrls.add(key);
        else aiTargetUrls.delete(key);
    });
    applyFilters();
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
    if (!sessionId) {
        alert('AI 분석을 시작하려면 먼저 프로젝트를 선택해야 합니다.');
        return;
    }
    if (aiTargetUrls.size === 0) {
        alert('AI 분석 대상이 없습니다. 먼저 타겟을 지정하세요.');
        return;
    }
    if (typeof startAiScan === 'function') startAiScan(sessionId);
}

// ── 엔드포인트 인라인 상세 ───────────────────────────────────

function toggleEndpointDetail(idx) {
    const tbody = document.getElementById('endpointsTableBody');
    const parentTr = tbody.querySelector(`tr[data-ep-idx="${idx}"]`);
    if (!parentTr) return;

    const existingDetail = tbody.querySelector(`tr[data-detail-for="${idx}"]`);
    if (existingDetail) {
        existingDetail.remove();
        parentTr.classList.remove('ep-expanded');
        return;
    }

    const ep = endpointsToRender[idx];
    if (!ep) return;

    const escapeHtml = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
    const reqRaw = escapeHtml(ep.request_raw || '(No Request Data)');
    const resRaw = escapeHtml(ep.response_raw || '(No Response Data)');
    const reqSize = ep.requestSize ? `${ep.requestSize} bytes` : '-';
    const resSize = ep.responseSize ? `${ep.responseSize} bytes` : '-';

    const detailTr = document.createElement('tr');
    detailTr.dataset.detailFor = idx;
    detailTr.innerHTML = `
        <td colspan="9" style="padding:0;border-top:none;">
            <div class="ep-detail-panel">
                <div class="d-flex gap-1 mb-2">
                    <button class="ep-tab-btn active" onclick="epInlineTab(${idx},'req',this)">Request</button>
                    <button class="ep-tab-btn" onclick="epInlineTab(${idx},'res',this)">Response</button>
                </div>
                <div id="ep-req-${idx}" style="position:relative;">
                    <button class="ep-copy-btn" onclick="epCopy(this,'ep-copy-req-${idx}')" title="복사">Copy</button>
                    <pre class="ep-detail-pre ep-detail-pre--req" id="ep-copy-req-${idx}">${reqRaw}</pre>
                </div>
                <div id="ep-res-${idx}" style="display:none;position:relative;">
                    <button class="ep-copy-btn" onclick="epCopy(this,'ep-copy-res-${idx}')" title="복사">Copy</button>
                    <pre class="ep-detail-pre" id="ep-copy-res-${idx}">${resRaw}</pre>
                </div>
            </div>
        </td>
    `;

    parentTr.classList.add('ep-expanded');
    parentTr.after(detailTr);
}

window.epCopy = function(btn, preId) {
    const text = document.getElementById(preId)?.innerText || '';
    navigator.clipboard.writeText(text).then(() => {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
    });
};

window.epInlineTab = function(idx, tab, btn) {
    document.getElementById(`ep-req-${idx}`).style.display = tab === 'req' ? 'block' : 'none';
    document.getElementById(`ep-res-${idx}`).style.display = tab === 'res' ? 'block' : 'none';
    btn.closest('.d-flex').querySelectorAll('.ep-tab-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
};

// ── Nuclei 결과 관리 ─────────────────────────────────────────

// ── 스캔 결과 탭 전환 ─────────────────────────────────────

function switchScanResultTab(tab) {
    document.querySelectorAll('.scan-result-tab').forEach(t => t.classList.remove('active'));
    const activeTab = document.querySelector(`.scan-result-tab[data-tab="${tab}"]`);
    if (activeTab) activeTab.classList.add('active');

    const panels = { endpoints: 'endpointsTabPanel', vulns: 'vulnsTabPanel', nuclei: 'nucleiTabPanel', nmap: 'nmapTabPanel' };
    Object.entries(panels).forEach(([key, id]) => {
        const el = document.getElementById(id);
        if (el) el.style.display = key === tab ? '' : 'none';
    });
}

// ── Nuclei 결과 ──────────────────────────────────────────

function addNucleiResult(result) {
    if (!result) return;
    const dup = nucleiResults.some(r => r.title === result.title && r.target === result.target);
    if (!dup) {
        nucleiResults.push(result);
        renderNucleiResults();
    }
}

function renderNucleiResults() {
    const container = document.getElementById('nucleiResultsPanel');
    const countEl = document.getElementById('nucleiCount');
    if (!container) return;

    if (countEl) countEl.textContent = nucleiResults.length;

    if (nucleiResults.length === 0) {
        container.innerHTML = '<div class="scan-result-empty">발견된 Nuclei 결과가 없습니다.</div>';
        return;
    }

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const sorted = [...nucleiResults].sort((a, b) =>
        (severityOrder[(a.severity||'').toLowerCase()] ?? 999) - (severityOrder[(b.severity||'').toLowerCase()] ?? 999)
    );

    const sevColor = { critical: '#ef4444', high: '#f59e0b', medium: '#3b82f6', low: '#10b981', info: '#6366f1' };
    let html = '';
    sorted.forEach(result => {
        const sev = (result.severity || 'info').toLowerCase();
        const color = sevColor[sev] || '#94a3b8';
        html += `
            <div class="scan-result-card" style="border-left:3px solid ${color};">
                <div class="scan-result-card-header">
                    <div>
                        <div class="scan-result-title">${result.title || 'Unknown'}</div>
                        <div class="scan-result-sub">${result.target || ''}</div>
                    </div>
                    <span class="sev-badge" style="background:${color}22;color:${color};">${sev.toUpperCase()}</span>
                </div>
                ${result.description ? `<div class="scan-result-desc">${result.description}</div>` : ''}
                ${result.reference ? `<a href="${result.reference}" target="_blank" class="scan-result-ref">Reference ↗</a>` : ''}
            </div>`;
    });
    container.innerHTML = html;
}

// ── Nmap 결과 ─────────────────────────────────────────────

function addNmapResult(result) {
    if (!result) return;
    const dup = nmapResults.some(r => r.host === result.host && r.port === result.port && r.protocol === result.protocol);
    if (!dup) {
        nmapResults.push(result);
        renderNmapResults();
    }
}

function renderNmapResults() {
    const container = document.getElementById('nmapResultsPanel');
    const countEl = document.getElementById('nmapCount');
    if (!container) return;

    if (countEl) countEl.textContent = nmapResults.length;

    const sid = (typeof currentProject !== 'undefined' && currentProject.id)
        || localStorage.getItem('currentSessionId');

    let tableHtml = '';
    if (nmapResults.length === 0) {
        tableHtml = '<div class="scan-result-empty">발견된 Nmap 결과가 없습니다.</div>';
    } else {
        const sorted = [...nmapResults].sort((a, b) => a.port - b.port);
        const portColor = p => p <= 1024 ? '#f59e0b' : '#10b981';
        tableHtml = '<table class="nmap-table"><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product / Version</th><th>Host</th></tr></thead><tbody>';
        sorted.forEach(r => {
            const color = portColor(r.port);
            const ver = [r.product, r.version, r.extrainfo].filter(Boolean).join(' ');
            tableHtml += `<tr>
                <td><span class="nmap-port" style="color:${color};">${r.port}</span></td>
                <td><span class="nmap-proto">${r.protocol}</span></td>
                <td style="color:#a5f3fc;font-weight:600;">${r.service || '-'}</td>
                <td style="color:#cbd5e1;font-size:0.78rem;">${ver || '-'}</td>
                <td style="color:#94a3b8;font-size:0.75rem;">${r.host}</td>
            </tr>`;
        });
        tableHtml += '</tbody></table>';
    }

    container.innerHTML = tableHtml;

    // Fetch and display nmap/report.txt below the table
    if (sid) {
        const reportBox = document.createElement('div');
        reportBox.id = 'nmapReportBox';
        reportBox.style.cssText = 'margin-top:12px;';
        container.appendChild(reportBox);

        fetch(`${typeof API_BASE !== 'undefined' ? API_BASE : ''}/api/history/${sid}/text/nmap/report.txt`)
            .then(r => r.json())
            .then(data => {
                if (data.status === 'success' && data.content) {
                    reportBox.innerHTML = `<div style="background:var(--bg-card,#1e293b);border:1px solid var(--border,#334155);border-radius:6px;padding:12px 14px;margin-top:4px;">
                        <div style="color:var(--text-muted,#94a3b8);font-size:0.72rem;margin-bottom:6px;font-weight:600;letter-spacing:.05em;">NMAP / REPORT.TXT</div>
                        <pre style="margin:0;color:#e2e8f0;font-family:monospace;font-size:0.78rem;white-space:pre-wrap;word-break:break-all;">${data.content.replace(/</g,'&lt;').replace(/>/g,'&gt;')}</pre>
                    </div>`;
                }
            })
            .catch(() => {});
    }
}

// ── Phase 2: 엔드포인트 심층 검증 ────────────────────────

async function deepDiveEndpoint(method, url, epIdx) {
    const ep = allEndpoints[epIdx];
    if (!ep) return alert("엔드포인트 정보를 찾을 수 없습니다.");

    if (!confirm(`[${method.toUpperCase()}] ${url}\n\n이 엔드포인트에 대해 전문가 심층 검증을 실행할까요?`)) return;

    // findings.js 함수들 호출 확인
    if (typeof aiCardsData === 'undefined' || typeof _toggleTriageRunning === 'undefined') {
        alert("findings.js가 로드되지 않았습니다. 취약점 탭에서 실행해주세요.");
        return;
    }

    if (_triageRunning) {
        alert("이미 전문가 검증이 실행 중입니다.");
        return;
    }

    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId) return alert("세션이 없습니다.");

    // 엔드포인트를 finding으로 변환
    const finding = {
        title: `[${method.toUpperCase()}] ${url}`,
        target: url,
        severity: "MEDIUM",
        confidence: 50,
        description: `Endpoint from reconnaissance: ${method.toUpperCase()} ${url}`,
        evidence: JSON.stringify({ endpoint: url, method, status: ep.status, sources: ep.sources }),
        steps: `curl -X ${method.toUpperCase()} "${url}"`,
        recommendation: "Conduct manual testing with appropriate tools",
        verified: false,
        source: "endpoint_recon",
        ttp: "T1046",
        owasp: "A01:2025",
        cwe: "CWE-200"
    };

    // ID 생성 (SHA1)
    let fid = 'ep_' + Date.now();
    if (typeof CryptoJS !== 'undefined') {
        fid = CryptoJS.SHA1(`${finding.title}|${finding.target}`).toString().substring(0, 16);
    }
    finding.id = fid;

    // aiCardsData에 추가
    aiCardsData.push(finding);

    // ai_findings.json에 저장 (specialist_agent가 찾을 수 있도록)
    if (typeof saveFindings === 'function') {
        await saveFindings();
    }

    const aiCfg = (typeof getAIConfig === 'function') ? getAIConfig() : {};

    _toggleTriageRunning(true);
    _setTriageStatus(`심층 검증 중: [${method.toUpperCase()}] ${url}`, 'running');
    if (typeof appendLog === 'function') appendLog(`엔드포인트 심층 검증 시작: ${method.toUpperCase()} ${url}`, "Triage");

    try {
        const res = await fetch(`${API_BASE}/api/triage/deep-dive`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: sessionId,
                finding_ids: [fid],
                ai_config: aiCfg,
                max_parallel: 1
            })
        });

        if (!res.ok || !res.body) {
            if (typeof appendLog === 'function') appendLog("전문가 검증 API 연결 실패", "Triage");
            _toggleTriageRunning(false);
            _setTriageStatus('연결 실패', 'err');
            return;
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let verified = false;

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const events = buffer.split(/\r?\n\r?\n/);
            buffer = events.pop();

            for (const evt of events) {
                const t = evt.trim();
                if (!t || !t.startsWith('data: ')) continue;
                let data;
                try { data = JSON.parse(t.substring(6)); } catch (e) { continue; }

                if (data.type === 'log' || data.type === 'progress') {
                    if (typeof appendLog === 'function') appendLog(data.message || data.msg || '', data.source || 'Triage');
                }
                else if (data.type === 'triage_start') {
                    if (typeof appendLog === 'function') appendLog(`[${data.vuln_class || 'UNKNOWN'}] 전문가 투입: ${method.toUpperCase()} ${url}`, 'Triage');
                }
                else if (data.type === 'triage_tool_call') {
                    if (typeof appendLog === 'function') appendLog(`  └ ${data.tool}: ...`, 'Triage');
                }
                else if (data.type === 'triage_finding_verified') {
                    verified = true;
                }
                else if (data.type === 'triage_complete') {
                    if (data.finding_id === fid) {
                        verified = data.verified || false;
                    }
                }
                else if (data.type === 'triage_batch_complete' || data.type === 'scan_complete') {
                    break;
                }
            }
        }

        _setTriageStatus(
            verified ? `✅ 검증 성공: [${method.toUpperCase()}] ${url}` : `❌ 검증 실패`,
            verified ? 'ok' : 'err'
        );
        if (typeof appendLog === 'function') {
            appendLog(verified ? `✅ 심층 검증 성공` : `❌ 심층 검증 실패`, "Triage");
        }
        // UI 갱신 (취약점 탭에 추가되지는 않음, 로그만 표시)
    } catch (e) {
        console.error("deep-dive 에러:", e);
        if (typeof appendLog === 'function') appendLog(`전문가 검증 오류: ${e}`, "Triage");
        _setTriageStatus('오류 발생', 'err');
    } finally {
        _toggleTriageRunning(false);
    }
}
