/**
 * nmap.js - Nmap 포트/서비스 스캐너 모듈
 */

let _nmapRunning = false;

function startNmapScan() {
    const sid = (typeof currentProject !== 'undefined' ? currentProject.id : null)
        || localStorage.getItem('currentSessionId');
    if (!sid) {
        _nmapLog('❌ Nmap 오류: 세션 ID 없음 — 프로젝트를 먼저 선택해주세요.', 'System');
        return;
    }

    const target = (typeof currentProject !== 'undefined' ? currentProject.target : null)
        || document.getElementById('targetUrl')?.value?.trim()
        || '';
    if (!target || target === 'http://local_workspace') {
        _nmapLog('❌ Nmap 오류: 유효한 타겟 URL이 없습니다.', 'System');
        return;
    }

    const nmapOptions = document.getElementById('nmapOptions')?.value?.trim()
        || '-sV -T4 --open -p 1-10000';

    _nmapRunning = true;
    fetch(`${API_BASE}/api/nmap/run`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sid, target_url: target, nmap_options: nmapOptions })
    }).then(res => {
        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        function pump() {
            reader.read().then(({ done, value }) => {
                if (done) { _nmapDone(); return; }
                buffer += decoder.decode(value, { stream: true });
                const parts = buffer.split('\n\n');
                buffer = parts.pop();
                parts.forEach(chunk => {
                    chunk.split('\n').forEach(line => {
                        if (line.startsWith('data: ')) {
                            try { _nmapEvent(JSON.parse(line.slice(6))); } catch (_) { }
                        }
                    });
                });
                pump();
            }).catch(() => _nmapDone());
        }
        pump();
    }).catch(e => {
        _nmapLog('오류: ' + e.message, 'System');
        _nmapDone();
    });
}


async function stopNmapScan() {
    const sid = (typeof currentProject !== 'undefined' ? currentProject.id : null)
        || localStorage.getItem('currentSessionId');
    if (sid) {
        try {
            await fetch(`${API_BASE}/api/nmap/stop`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ session_id: sid })
            });
        } catch (_) { }
    }
    _nmapLog('중단 요청이 전달되었습니다.', 'System');
    _nmapDone();
}

function _nmapDone() {
    _nmapRunning = false;
    const statText = document.getElementById('scanStatusText');
    if (statText) statText.innerHTML = `<i class="fa-solid fa-check text-success me-2"></i>모든 스캔 및 분석 작업 완료`;
    if (typeof updateScanConfigButton === 'function') updateScanConfigButton(false);
    // Nmap 완료 시 엔드포인트 탭 → Nmap 탭으로 자동 전환
    if (typeof switchScanResultTab === 'function') switchScanResultTab('nmap');
    if (typeof switchSection === 'function') switchSection('section-endpoints');
}

function _nmapEvent(data) {
    const t = data.type;
    if (t === 'log') {
        // 일반 로그는 사용자 요청에 의해 콘솔 출력 최소화
        // _nmapLog(data.message, data.agent || 'Nmap');
    } else if (t === 'nmap_finding' && data.data) {
        if (typeof addNmapResult === 'function') addNmapResult(data.data);
    } else if (t === 'nmap_progress' || t === 'progress') {
        if (data.progress !== undefined) {
            const pBar = document.getElementById('progressBar');
            const pText = document.getElementById('progressText');
            if (pBar) pBar.style.width = data.progress + "%";
            if (pText) pText.textContent = Math.floor(data.progress) + "%";
        }
    } else if (t === 'nmap_complete' || t === 'scan_complete') {
        _nmapDone();
    }
}

function _nmapLog(msg, agent) {
    if (typeof appendLog === 'function') {
        appendLog(msg, agent || 'Nmap');
    }
}
