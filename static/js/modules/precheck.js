/**
 * precheck.js - Alive Check, Shodan, Dork 사전 점검 모듈
 */

let aliveHot = null;
let shodanHot = null;
let dorkHot = null;
let aliveCheckEventSource = null;
let aliveCheckData = [];
let dorkCheckEventSource = null;
let dorkCheckData = [];

// ── Handsontable 초기화 (Dork 전용; Alive/Shodan은 카드UI 사용) ──

function initHandsontable(type) {
    let containerId = 'aliveTableGrid';
    if (type === 'shodan') containerId = 'shodanTableGrid';
    if (type === 'dork') containerId = 'dorkTableGrid';

    const container = document.getElementById(containerId);
    if (!container) return null;

    if (type === 'alive' && aliveHot) { aliveHot.destroy(); aliveHot = null; }
    if (type === 'shodan' && shodanHot) { shodanHot.destroy(); shodanHot = null; }
    if (type === 'dork' && dorkHot) { dorkHot.destroy(); dorkHot = null; }

    let columns = [];
    if (type === 'alive') {
        columns = [
            { data: 0, title: 'No.', width: 45, className: "htCenter htMiddle", readOnly: true },
            { data: 1, title: 'O/X', width: 50, className: "htCenter htMiddle", readOnly: true },
            { data: 2, title: 'Target Domain', width: 180, className: "htCenter htMiddle", readOnly: true },
            { data: 3, title: 'HTTP Final URL', width: 200, className: "htCenter htMiddle", readOnly: true },
            { data: 4, title: 'HTTP Traces', width: 150, className: "htCenter htMiddle", readOnly: true },
            { data: 5, title: 'HTTPS Final URL', width: 200, className: "htCenter htMiddle", readOnly: true },
            { data: 6, title: 'HTTPS Traces', className: "htCenter htMiddle", readOnly: true }
        ];
    } else if (type === 'shodan') {
        columns = [
            { data: 0, title: 'No.', width: 45, className: "htCenter htMiddle", readOnly: true },
            { data: 1, title: 'Target', width: 180, className: "htCenter htMiddle", readOnly: true },
            { data: 2, title: 'Shodan IP', width: 140, className: "htCenter htMiddle", readOnly: true },
            { data: 3, title: 'Ports', width: 200, className: "htCenter htMiddle", readOnly: true },
            { data: 4, title: 'Shodan Vulns', className: "htCenter htMiddle", readOnly: true }
        ];
    } else if (type === 'dork') {
        columns = [
            { data: 0, title: 'No.', width: 45, className: "htCenter htMiddle", readOnly: true },
            { data: 1, title: 'Status', width: 50, className: "htCenter htMiddle", readOnly: true },
            { data: 2, title: 'Domain', width: 160, className: "htCenter htMiddle", readOnly: true },
            { data: 3, title: 'Category', width: 140, className: "htCenter htMiddle", readOnly: true },
            { data: 4, title: 'Found URL', width: 280, className: "htCenter htMiddle", readOnly: true, renderer: 'html' },
            { data: 5, title: 'Snippet', className: "htCenter htMiddle", readOnly: true }
        ];
    }

    const hot = new Handsontable(container, {
        data: [], columns, rowHeaders: false, width: '100%', height: '100%',
        stretchH: 'all', selectionMode: 'multiple', outsideClickDeselects: false,
        filters: true, dropdownMenu: true, manualColumnResize: true,
        manualRowResize: true, columnSorting: true, contextMenu: ['copy'],
        licenseKey: 'non-commercial-and-evaluation'
    });

    if (type === 'alive') aliveHot = hot;
    else if (type === 'shodan') shodanHot = hot;
    else dorkHot = hot;

    return hot;
}

// ── Alive / Shodan 스캔 ───────────────────────────────────

function startAliveCheck(mode) {
    const inputId = mode === 'alive' ? 'aliveInput' : 'shodanInput';
    const progressId = mode === 'alive' ? 'aliveProgress' : 'shodanProgress';
    const btnStartId = mode === 'alive' ? 'btnStartAlive' : 'btnStartShodan';
    const btnStopId = mode === 'alive' ? 'btnStopAlive' : 'btnStopShodan';

    const rawText = document.getElementById(inputId).value;
    const lines = rawText.split('\n');
    if (lines.length === 0 || !rawText.trim()) return alert("대상을 입력하세요.");

    document.getElementById(progressId).innerText = `0 / ${lines.length}`;
    aliveCheckData = [];

    const hot = initHandsontable(mode);
    if (hot) {
        const initialData = lines.map((l, i) => mode === 'alive'
            ? [i + 1, '-', l.trim(), '-', '-', '-', '-']
            : [i + 1, l.trim(), '-', '-', '-']);
        hot.loadData(initialData);
    }

    document.getElementById(btnStartId).style.display = 'none';
    document.getElementById(btnStopId).style.display = 'block';

    const sessionId = localStorage.getItem('currentSessionId');
    const urlPrefix = mode === 'shodan' ? 'shodan' : 'alive';

    fetch(`${API_BASE}/api/${urlPrefix}/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: lines, mode, session_id: sessionId })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status !== "success") throw new Error("시작 실패");

            aliveCheckEventSource = new EventSource(`${API_BASE}/api/${urlPrefix}/stream`);
            aliveCheckEventSource.onmessage = (e) => {
                const parsed = JSON.parse(e.data);

                if (parsed.status === "completed" || parsed.status === "error") {
                    stopAliveCheck(mode);
                    if (parsed.status === "completed") alert("사전 검진이 모두 완료되었습니다!");
                    return;
                }

                const idx = parsed.index;
                const result = parsed.result;
                document.getElementById(progressId).innerText = `${idx + 1} / ${lines.length}`;

                const hot = mode === 'alive' ? aliveHot : shodanHot;
                if (hot) {
                    if (mode === 'alive') {
                        hot.setDataAtCell(idx, 1, result[0]);
                        hot.setDataAtCell(idx, 2, result[1]);
                        hot.setDataAtCell(idx, 3, result[2]);
                        hot.setDataAtCell(idx, 4, result[4]);
                        hot.setDataAtCell(idx, 5, result[3]);
                        hot.setDataAtCell(idx, 6, result[5]);
                    } else {
                        hot.setDataAtCell(idx, 2, result[8] || '-');
                        hot.setDataAtCell(idx, 3, result[6] || '-');
                        hot.setDataAtCell(idx, 4, result[7] || '-');
                    }
                }
                const isDataValid = (mode === 'alive' && result[0] !== "-")
                    || (mode === 'shodan' && result[1] !== "-");
                aliveCheckData.push(isDataValid ? result : ["-", "-", "-", "-", "-", "-", "-", "-", "-"]);
            };

            aliveCheckEventSource.onerror = () => stopAliveCheck(mode);
        })
        .catch(err => { alert("연결 중단: " + err); stopAliveCheck(mode); });
}

function stopAliveCheck(mode = 'alive') {
    if (aliveCheckEventSource) { aliveCheckEventSource.close(); aliveCheckEventSource = null; }
    const urlPrefix = mode === 'shodan' ? 'shodan' : 'alive';
    fetch(`${API_BASE}/api/${urlPrefix}/stop`, { method: "POST" }).catch(() => {});

    const btnStartId = mode === 'alive' ? 'btnStartAlive' : 'btnStartShodan';
    const btnStopId = mode === 'alive' ? 'btnStopAlive' : 'btnStopShodan';
    if (document.getElementById(btnStartId)) document.getElementById(btnStartId).style.display = 'block';
    if (document.getElementById(btnStopId)) document.getElementById(btnStopId).style.display = 'none';
}

// ── Dork 스캔 ────────────────────────────────────────────

function startDorkCheck() {
    const rawText = document.getElementById('dorkInput').value;
    const keysText = document.getElementById('dorkKeys').value;
    const cxId = document.getElementById('dorkCx').value.trim();
    const customDorksText = document.getElementById('dorkCustomCategories').value;

    const lines = rawText.split('\n').filter(l => l.trim().length > 0);
    const apiKeys = keysText.split('\n').filter(k => k.trim().length > 0);

    const dorkCategories = {};
    customDorksText.split('\n').forEach(line => {
        if (line.includes('|')) {
            const [cat, ...rest] = line.split('|');
            const query = rest.join('|');
            if (cat.trim() && query.trim()) dorkCategories[cat.trim()] = query.trim();
        }
    });

    if (lines.length === 0) return alert("대상을 입력하세요.");
    if (Object.keys(dorkCategories).length === 0) return alert("Dork 스캔 패턴을 입력하세요.");

    document.getElementById('dorkProgress').innerText = `0 / ${lines.length}`;
    dorkCheckData = [];

    const hot = initHandsontable('dork');
    if (hot) hot.loadData([]);

    if (document.getElementById('btnStartDork')) document.getElementById('btnStartDork').style.display = 'none';
    if (document.getElementById('btnStopDork')) document.getElementById('btnStopDork').style.display = 'block';

    const sessionId = localStorage.getItem('currentSessionId');
    fetch(`${API_BASE}/api/dork/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domains: lines, api_keys: apiKeys, cx_id: cxId, session_id: sessionId, dork_categories: dorkCategories })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status !== "success") throw new Error("시작 실패");

            dorkCheckEventSource = new EventSource(`${API_BASE}/api/dork/stream`);
            dorkCheckEventSource.onmessage = (e) => {
                const parsed = JSON.parse(e.data);
                if (parsed.status === "completed" || parsed.status === "error") {
                    stopDorkCheck();
                    if (parsed.status === "completed") alert("Dork 스캔이 모두 완료되었습니다!");
                    return;
                }

                const idx = parsed.index;
                const result = parsed.result;
                document.getElementById('dorkProgress').innerText = `${idx + 1} / ${lines.length}`;

                const hot = dorkHot;
                if (hot && result) {
                    result.forEach((row, rowIdx) => {
                        const hotRow = (idx * 10) + rowIdx;
                        hot.setDataAtCell(hotRow, 0, hotRow + 1);
                        hot.setDataAtCell(hotRow, 1, row[0] || '-');
                        hot.setDataAtCell(hotRow, 2, row[1] || '-');
                        hot.setDataAtCell(hotRow, 3, row[2] || '-');
                        hot.setDataAtCell(hotRow, 4, row[3] ? `<a href="${row[3]}" target="_blank">${row[3]}</a>` : '-');
                        hot.setDataAtCell(hotRow, 5, row[4] || '-');
                    });
                }
                dorkCheckData.push(...(result || []));
            };

            dorkCheckEventSource.onerror = () => stopDorkCheck();
        })
        .catch(err => { alert("연결 중단: " + err); stopDorkCheck(); });
}

function stopDorkCheck() {
    if (dorkCheckEventSource) { dorkCheckEventSource.close(); dorkCheckEventSource = null; }
    fetch(`${API_BASE}/api/dork/stop`, { method: "POST" }).catch(() => {});
    if (document.getElementById('btnStartDork')) document.getElementById('btnStartDork').style.display = 'block';
    if (document.getElementById('btnStopDork')) document.getElementById('btnStopDork').style.display = 'none';
}

// ── 탭 전환 ──────────────────────────────────────────────

function switchPrecheckTab(mode) {
    ['alive', 'shodan', 'dork'].forEach(m => {
        const s = document.getElementById(`section-${m}`);
        if (s) {
            // 인라인 스타일 대신 클래스 토글 사용 (CSS의 display: none/block 정책 준수)
            if (m === mode) s.classList.add('active');
            else s.classList.remove('active');
            
            // 혹시 남아있을 수 있는 인라인 스타일 제거 (중요!)
            s.style.display = '';
        }
    });
}

// ── CSV 다운로드 ──────────────────────────────────────────

function downloadAliveCheckCSV(mode = 'alive') {
    const hot = mode === 'alive' ? aliveHot : shodanHot;
    if (!hot) return alert("데이터가 없습니다.");

    const data = hot.getData();
    const headers = mode === 'alive'
        ? ['No.', 'O/X', 'Target Domain', 'HTTP Final URL', 'HTTPS Final URL', 'Traces']
        : ['No.', 'Target', 'Shodan IP', 'Ports', 'Shodan Vulns'];

    const csv = [headers.join(',')]
        .concat(data.map(row => row.map(cell => `"${(cell || '').toString().replace(/"/g, '""')}"`).join(',')))
        .join('\n');

    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${mode}_check_results.csv`;
    a.click();
    URL.revokeObjectURL(url);
}

// ── Pre-Check 프로젝트 생성 ───────────────────────────────

function createPrecheckProject() {
    const name = document.getElementById('precheckProjName').value.trim();
    if (!name) return alert("프로젝트 이름을 입력하세요.");

    fetch(`${API_BASE}/api/project/create`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ project_name: name, target_url: "", project_type: 'precheck' })
    })
        .then(res => res.json())
        .then(data => {
            if (data.status === "success") {
                alert("사전점검 프로젝트가 생성되었습니다!");
                if (typeof loadHistoryList === "function") loadHistoryList();
                setTimeout(() => {
                    selectProject(data.session_id);
                    switchSection("section-alive");
                }, 400);
            } else {
                alert("생성 실패: " + (data.message || "알 수 없는 오류"));
            }
        }).catch(err => alert("에러: " + err));
}
