/**
 * nuclei.js - Nuclei 취약점 스캐너 독립 실행 모듈
 */

let _nucleiRunning = false;

function startNucleiScan() {
    const sid = (typeof currentProject !== 'undefined' ? currentProject.id : null)
        || localStorage.getItem('currentSessionId');
    if (!sid) return alert("프로젝트를 먼저 선택해 주세요.");

    const target = (typeof currentProject !== 'undefined' ? currentProject.target : null) || '';
    if (!target || target === 'http://local_workspace') return alert("유효한 타겟 URL이 없습니다. 프로젝트 스캔 대상을 설정하세요.");

    const nucleiOptions = document.getElementById('nucleiOptions')?.value?.trim()
        || '-severity medium,high,critical -rl 100 -c 25';

    const headersRaw = document.getElementById('customHeaders')?.value || '';
    const headers = {};
    if (headersRaw) {
        headersRaw.split('\n').forEach(line => {
            const parts = line.split(':');
            if (parts.length >= 2) {
                headers[parts[0].trim()] = parts.slice(1).join(':').trim();
            }
        });
    }

    const startBtn = document.getElementById('nucleiStartBtn');
    const stopBtn = document.getElementById('nucleiStopBtn');
    if (startBtn) startBtn.style.display = 'none';
    if (stopBtn) stopBtn.style.display = '';

    _nucleiRunning = true;
    fetch(`${API_BASE}/api/nuclei/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid, target_url: target, headers, nuclei_options: nucleiOptions })
    }).then(res => {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        function pump() {
            reader.read().then(({ done, value }) => {
                if (done) { _nucleiDone(); return; }
                buffer += decoder.decode(value, { stream: true });
                const parts = buffer.split('\n\n');
                buffer = parts.pop();
                parts.forEach(chunk => {
                    chunk.split('\n').forEach(line => {
                        if (line.startsWith('data: ')) {
                            try { _nucleiEvent(JSON.parse(line.slice(6))); } catch (_) {}
                        }
                    });
                });
                pump();
            }).catch(() => _nucleiDone());
        }
        pump();
    }).catch(e => {
        _nucleiLog('오류: ' + e.message, 'Error');
        _nucleiDone();
    });
}

function _nucleiEvent(data) {
    const t = data.type;
    if (t === 'log') {
        _nucleiLog(data.message, data.agent || 'Nuclei');
    } else if (t === 'ai_card' && data.data) {
        const f = data.data;
        _nucleiLog(`[발견] ${f.title} [${f.severity}] @ ${f.target}`, 'Nuclei');
        if (Array.isArray(aiCardsData)) {
            const dup = aiCardsData.some(c => c.title === f.title && c.target === f.target);
            if (!dup) {
                aiCardsData.push(f);
                if (typeof renderCards === 'function') renderCards(aiCardsData);
            }
        }
        if (typeof addNucleiResult === 'function') addNucleiResult(f);
    } else if (t === 'scan_complete') {
        _nucleiDone();
    }
}

function _nucleiLog(msg, agent) {
    if (typeof appendLog === 'function') {
        appendLog(msg, agent || 'Nuclei');
    } else {
        const logEl = document.getElementById('logWindow');
        if (!logEl) return;
        const colorMap = { System: '#10b981', Error: '#ef4444', Nuclei: '#f87171', Command: '#60a5fa' };
        const color = colorMap[agent] || '#94a3b8';
        const div = document.createElement('div');
        div.innerHTML = `<span style="color:${color}">[${agent || 'Nuclei'}]</span> `
            + `<span style="color:#e2e8f0">${(msg || '').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</span>`;
        logEl.appendChild(div);
        logEl.scrollTop = logEl.scrollHeight;
    }
}

async function stopNucleiScan() {
    const sid = (typeof currentProject !== 'undefined' ? currentProject.id : null)
        || localStorage.getItem('currentSessionId');
    if (sid) {
        try {
            await fetch(`${API_BASE}/api/nuclei/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sid })
            });
        } catch (_) {}
    }
    _nucleiLog('중단 요청이 전달되었습니다.', 'System');
    _nucleiDone();
}

function _nucleiDone() {
    _nucleiRunning = false;
    const startBtn = document.getElementById('nucleiStartBtn');
    const stopBtn  = document.getElementById('nucleiStopBtn');
    if (startBtn) startBtn.style.display = '';
    if (stopBtn)  stopBtn.style.display  = 'none';
    const statText = document.getElementById('scanStatusText');
    if (statText) statText.innerHTML = `<i class="fa-solid fa-check text-success me-2"></i>모든 스캔 및 분석 작업 완료`;
    if (typeof updateScanConfigButton === 'function') updateScanConfigButton(false);
}
