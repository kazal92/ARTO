/**
 * scan.js - 스캔 시작/정지/ZAP 폴링/AI 분석 모듈
 */

let zapHistoryInterval = null;
let zapHistoryData = [];
let _scanLive = false; // true after scan_start received — prevents replayed scan_complete from hiding stopBtn

function syncFfufUrl(url) {
    const opts = document.getElementById('ffufOptions');
    if (!opts) return;
    const defaultOpts = '-t 50 -mc 200,204,301,302,307,401,403,500 -ac -ic';
    let current = opts.value.trim().replace(/-u\s+\S+\s*/g, '').trim() || defaultOpts;
    opts.value = url ? `-u ${url}/FUZZ ${current}` : current;
}

document.addEventListener('DOMContentLoaded', () => {
    const targetInput = document.getElementById('targetUrl');
    if (targetInput) {
        targetInput.addEventListener('input', () => syncFfufUrl(targetInput.value.trim()));
    }
});

function updateScanConfigButton(isRunning) {
    const startBtn = document.getElementById('startBtn');
    const stopBtn = document.getElementById('stopBtn');
    if (startBtn) startBtn.style.display = isRunning ? 'none' : '';
    if (stopBtn) stopBtn.style.display = isRunning ? '' : 'none';
}

async function startScan() {
    let url = document.getElementById('targetUrl') ? document.getElementById('targetUrl').value : '';
    if (url) {
        currentProject.target = url;
    }
    let projectName = currentProject.name || '';

    if (!url && window.currentNewTargetUrl) {
        url = window.currentNewTargetUrl;
        projectName = window.currentNewProjectName || '';
        window.currentNewTargetUrl = null;
        window.currentNewProjectName = null;
    }

    if (!url || url === "http://local_workspace") return alert("유효한 타겟 URL을 입력해 주세요.");

    document.getElementById('logWindow').innerHTML = "";

    // 모듈 설정 요약
    const recon = [];
    const extra = [];
    const zap = document.getElementById('enableZapSpider');
    const ffuf = document.getElementById('enableFfuf');
    const deep = document.getElementById('enableDeepRecon');
    const nuclei = document.getElementById('enableNuclei');
    const nmap = document.getElementById('enableNmap');

    if (zap?.checked || (window._projectSettings?.enable_zap_spider && !zap)) recon.push('ZAP');
    if (ffuf?.checked !== false) recon.push('FFuF');
    if ((deep?.checked !== false) && (ffuf?.checked || !ffuf)) recon.push('(recursive)');
    if (nuclei?.checked || (window._projectSettings?.enable_nuclei && !nuclei)) extra.push('Nuclei');
    if (nmap?.checked || (window._projectSettings?.enable_nmap && !nmap)) extra.push('Nmap');

    document.getElementById('vulnsTableBody').innerHTML = '<tr><td colspan="5" class="empty-state">스캔 프로세스를 시작합니다...</td></tr>';
    document.getElementById('endpointsTableBody').innerHTML = '<tr><td colspan="8" class="empty-state">엔드포인트 자산 수집 중...</td></tr>';
    aiCardsData = [];
    aiTargetUrls.clear();
    renderCards([]);
    renderEndpoints([]);
    document.getElementById('progressBar').style.width = "0%";

    if (projectName) {
        const breadcrumbText = document.getElementById('breadcrumbText');
        if (breadcrumbText) breadcrumbText.innerHTML = `<i class="fa-solid fa-folder-open text-warning me-1"></i> ${projectName} <span class="text-muted small">(${url})</span>`;
        document.querySelectorAll('.project-nav-item').forEach(m => m.style.display = 'flex');
        const topbarScanControls = document.getElementById('topbarScanControls');
        if (topbarScanControls) topbarScanControls.style.display = 'flex';
    }

    _scanLive = false;
    updateScanConfigButton(true);

    const headersRaw = document.getElementById('customHeaders') ? document.getElementById('customHeaders').value : '';
    const headers = {};
    if (headersRaw) {
        headersRaw.split('\n').forEach(line => {
            const parts = line.split(':');
            if (parts.length >= 2) {
                headers[parts[0].trim()] = parts.slice(1).join(':').trim();
            }
        });
    }

    try {
        // ── 도구 활성화 상태 읽기 (체크박스 우선, 없으면 저장된 설정 사용, 둘 다 없으면 기본값) ──
        const getScanOption = (checkboxId, fallbackKey, defaultVal) => {
            const elem = document.getElementById(checkboxId);
            if (elem) return elem.checked;
            // 저장된 프로젝트 설정이 있으면 사용
            const sessionId = currentProject.id || localStorage.getItem('currentSessionId');
            if (window._projectSettings && window._projectSettings[fallbackKey] !== undefined) {
                return window._projectSettings[fallbackKey];
            }
            return defaultVal;
        };

        const res = await fetch(`${API_BASE}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: currentProject.id || localStorage.getItem('currentSessionId') || "",
                target_url: url,
                project_name: projectName,
                headers: headers,
                ffuf_options: document.getElementById('ffufOptions') ? document.getElementById('ffufOptions').value.trim() : '',
                ffuf_wordlist: document.getElementById('ffufWordlist') ? document.getElementById('ffufWordlist').value : '',
                enable_zap_spider: getScanOption('enableZapSpider', 'enable_zap_spider', false),
                enable_ffuf: getScanOption('enableFfuf', 'enable_ffuf', true),
                enable_deep_recon: getScanOption('enableDeepRecon', 'enable_deep_recon', true),
                enable_nuclei: getScanOption('enableNuclei', 'enable_nuclei', false),
                enable_nmap: getScanOption('enableNmap', 'enable_nmap', false),
                ai_config: {
                    type: document.getElementById('aiType').value,
                    api_key: document.getElementById('aiType').value === 'gemini'
                        ? document.getElementById('geminiApiKey').value
                        : (document.getElementById('aiType').value === 'vertex'
                            ? document.getElementById('vertexApiKey').value
                            : document.getElementById('lmstudioApiKey').value),
                    base_url: document.getElementById('aiUrl').value,
                    model: document.getElementById('aiModel').value,
                    max_endpoints_per_batch: parseInt(document.getElementById('maxEndpointsPerBatch')?.value || '0') || 0,
                    custom_prompt: document.getElementById('aiPromptCustom')?.value?.trim() || ''
                }
            })
        });

        if (!res.ok) {
            appendLog("스캔 API 서버 연결에 실패했습니다.", "System");
            document.getElementById('startBtn').disabled = false;
            document.getElementById('stopBtn').disabled = true;
            return;
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const events = buffer.split(/\r?\n\r?\n/);
            buffer = events.pop();

            for (const event of events) {
                const trimmedEvent = event.trim();
                if (!trimmedEvent) continue;

                if (trimmedEvent.startsWith('data: ')) {
                    try {
                        const data = JSON.parse(trimmedEvent.substring(6));

                        if (data.type === "scan_start") {
                            _scanLive = true;
                            localStorage.setItem('currentSessionId', data.session_id);
                            currentProject.id = data.session_id;
                            const select = document.getElementById('historySelect');
                            if (select) select.value = data.session_id;
                            loadHistoryList();
                            allEndpoints = [];
                            startZapPolling();
                        }

                        // 이전 스캔 로그 재전송 구간은 무시 (깜빡임 방지)
                        if (!_scanLive) continue;

                        if (data.type === "log" || data.type === "progress") {
                            appendLog(data.message || data.msg, data.agent || data.source);
                            const match = (data.message || "").match(/AI 분석 배치 (\d+)\/(\d+) 처리 중/);
                            if (match) updateBatchList(parseInt(match[2]));
                        }
                        if (data.progress !== undefined) {
                            const pBar = document.getElementById('progressBar');
                            const pText = document.getElementById('progressText');
                            if (pBar) pBar.style.width = data.progress + "%";
                            if (pText) pText.textContent = Math.floor(data.progress) + "%";

                            if (data.source === "Recon") {
                                const statText = document.getElementById('scanStatusText');
                                if (statText) statText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin text-primary me-2"></i>네트워크 정찰 진행 중...`;
                            } else if (data.source === "AI") {
                                const statText = document.getElementById('scanStatusText');
                                if (statText) statText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin text-info me-2"></i>AI 심층 분석 수행 중...`;
                            }
                        }
                        if (data.type === "recon_result") {
                            stopZapPolling();
                            allEndpoints = data.data.endpoints || [];
                            renderEndpoints(allEndpoints);
                        }
                        if (data.type === "ai_card") {
                            aiCardsData.push(data.data);
                            renderCards(aiCardsData);
                        }
                        if (data.type === "scan_complete" && _scanLive) {
                            _scanLive = false;

                            const pBar = document.getElementById('progressBar');
                            const pText = document.getElementById('progressText');
                            const statText = document.getElementById('scanStatusText');
                            if (pBar) pBar.style.width = "100%";
                            if (pText) pText.textContent = "100%";

                            const nucleiEnabled = document.getElementById('enableNuclei')?.checked;
                            const nmapEnabled = document.getElementById('enableNmap')?.checked;

                            if (nucleiEnabled && typeof startNucleiScan === 'function') {
                                if (statText) statText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin text-danger me-2"></i>Nuclei 취약점 스캔 시작...`;
                                if (typeof _nucleiRunning !== 'undefined') _nucleiRunning = true;
                                setTimeout(() => startNucleiScan(), 1000);
                            }
                            if (nmapEnabled && typeof startNmapScan === 'function') {
                                if (statText) statText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin text-info me-2"></i>Nmap 포트 스캔 시작...`;
                                appendLog('Nmap 스캔을 자동 시작합니다...', 'System');
                                if (typeof _nmapRunning !== 'undefined') _nmapRunning = true;
                                setTimeout(() => startNmapScan(), nucleiEnabled ? 2000 : 1000);
                            }
                            if (!nucleiEnabled && !nmapEnabled) {
                                if (statText) statText.innerHTML = `<i class="fa-solid fa-check text-success me-2"></i>모든 스캔 및 분석 작업 완료`;
                                updateScanConfigButton(false);
                            }

                            loadHistoryList();
                        }
                    } catch (err) {
                        console.error("SSE JSON Parse Error", err);
                    }
                }
            }
        }
    } catch (e) {
        appendLog(`서버와의 연결이 끊어졌습니다: ${e}`, "System");
        updateScanConfigButton(false);
    }
}

async function stopScan() {
    try {
        const sid = currentProject.id || localStorage.getItem('currentSessionId') || "";
        await fetch(`${API_BASE}/api/scan/stop`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sid })
        });
        appendLog("중단 신호가 전송되었습니다. 진행 중인 프로세스를 종료합니다.", "System");

        if (typeof stopNucleiScan === 'function') stopNucleiScan();
        if (typeof stopNmapScan === 'function') stopNmapScan();

        updateScanConfigButton(false);
    } catch (e) { }
}

async function pollZapHistory() {
    try {
        const res = await fetch(`${API_BASE}/api/zap/history`);
        const data = await res.json();
        if (data.status === 'success' && data.messages) {
            const existingKeys = new Set(allEndpoints.map(ep => `${(ep.method || 'GET').toUpperCase()}:${ep.url}`));
            let added = false;

            data.messages.forEach(m => {
                let url = m.uri || m.url || '';

                // [보강] 만약 uri 필드가 없으면 requestHeader에서 추출 시도
                if (!url && m.requestHeader) {
                    const firstLine = m.requestHeader.split('\n')[0].trim();
                    const parts = firstLine.split(' ');
                    if (parts.length >= 2) url = parts[1];
                }

                if (!url || url === '-' || isStaticFile(url)) return;

                let parsedStatus = m.statusCode || '-';
                if (m.responseHeader && (parsedStatus === '-' || parsedStatus === '0')) {
                    const fl = m.responseHeader.split('\n')[0].trim();
                    const parts = fl.split(' ');
                    if (parts.length >= 2 && /^\d+$/.test(parts[1])) parsedStatus = parts[1];
                }

                if (parsedStatus === '0' || parsedStatus === '502') return;

                const key = `${(m.method || 'GET').toUpperCase()}:${url}`;
                if (!existingKeys.has(key)) {
                    allEndpoints.push({
                        url: url,
                        method: m.method || 'GET',
                        status: parsedStatus,
                        source: 'zap_history',
                        sources: ['zap'],
                        request_raw: (m.requestHeader || '') + (m.requestBody || ''),
                        response_raw: (m.responseHeader || '') + (m.responseBody || ''),
                        time: formatTimeWithMs(new Date()),
                        requestSize: (m.requestSize ? String(m.requestSize).replace(/[^\d]/g, '') : '') || ((m.requestHeader || '').length + (m.requestBody || '').length),
                        responseSize: (m.responseSize ? String(m.responseSize).replace(/[^\d]/g, '') : '') || ((m.responseHeader || '').length + (m.responseBody || '').length)
                    });
                    existingKeys.add(key);
                    added = true;
                }
            });

            if (added) {
                if (document.getElementById('section-endpoints').classList.contains('active')) {
                    applyFilters();
                }
            }
        }
    } catch (e) {
        console.warn('ZAP Poll failed:', e);
    }
}

function startZapPolling() {
    if (!zapHistoryInterval) {
        pollZapHistory();
        zapHistoryInterval = setInterval(pollZapHistory, 5000);
    }
}

function stopZapPolling() {
    if (zapHistoryInterval) {
        clearInterval(zapHistoryInterval);
        zapHistoryInterval = null;
    }
}

async function loadZapHistory() {
    // [FIX #4] 세션 없으면 경고 후 중단
    const sessionId = currentProject.id || localStorage.getItem('currentSessionId');
    // 세션이 없어도 목록에 보여주는 것은 허용합니다. (단, 저장은 안됨)

    try {
        appendLog("ZAP 히스토리를 가져오는 중입니다...", "System");
        const res = await fetch(`${API_BASE}/api/zap/history`);
        const data = await res.json();

        if (data.status === 'success' && data.messages) {
            const mapped = data.messages.filter(msg => {
                let url = msg.uri || msg.url || '';
                if (!url && msg.requestHeader) {
                    const firstLine = msg.requestHeader.split('\n')[0].trim();
                    const parts = firstLine.split(' ');
                    if (parts.length >= 2) url = parts[1];
                }
                if (!url || url === '-' || isStaticFile(url)) return false;

                if (!msg.responseHeader) return false;
                const firstLine = msg.responseHeader.split('\n')[0].trim();
                const parts = firstLine.split(' ');
                if (parts.length >= 2 && (parts[1] === '0' || parts[1] === '502')) return false;
                return true;
            }).map(msg => {
                let method = 'GET';
                let url = msg.uri || msg.url || '';

                if (msg.requestHeader) {
                    const firstLine = msg.requestHeader.split('\n')[0].trim();
                    const parts = firstLine.split(' ');
                    if (parts.length >= 1) method = parts[0].toUpperCase();
                    if (!url && parts.length >= 2) url = parts[1];
                }
                if (!url) url = '-';

                let status = msg.statusCode || '-';
                if (msg.responseHeader) {
                    const firstLine = msg.responseHeader.split('\n')[0].trim();
                    const parts = firstLine.split(' ');
                    if (parts.length >= 2) status = parts[1];
                }
                return {
                    url: url,
                    method: method,
                    status: status,
                    source: 'zap_history',
                    sources: ['zap'],  // [FIX #2]
                    request_raw: (msg.requestHeader || "") + (msg.requestBody || ""),
                    response_raw: (msg.responseHeader || "") + (msg.responseBody || ""),
                    time: formatTimeWithMs(new Date()),
                    requestSize: msg.requestSize || ((msg.requestHeader || "").length + (msg.requestBody || "").length),
                    responseSize: msg.responseSize || ((msg.responseHeader || "").length + (msg.responseBody || "").length)
                };
            });

            if (mapped.length === 0) {
                return alert("가져올 수 있는 유효한 ZAP 히스토리가 없습니다.");
            }

            let addedCount = 0;
            mapped.forEach(newItem => {
                const exists = allEndpoints.some(e => e.url === newItem.url && (e.method || 'GET').toUpperCase() === newItem.method);
                if (!exists) {
                    allEndpoints.push(newItem);
                    addedCount++;
                }
            });

            if (addedCount === 0) {
                return alert("새로 가져올 ZAP 히스토리가 없습니다. (이미 존재하는 엔드포인트)");
            }

            renderEndpoints(allEndpoints);
            appendLog(`ZAP 히스토리에서 ${addedCount}개의 신규 엔드포인트를 가져왔습니다.`, "System");

            if (!sessionId) {
                return alert(`ZAP 히스토리에서 ${addedCount}개를 가져왔습니다. (프로젝트 미선택으로 저장은 되지 않았습니다.)`);
            }
            try {
                let zapTarget = '';
                for (const ep of mapped) {
                    if (ep.url && ep.url.startsWith('http')) {
                        try {
                            const parsed = new URL(ep.url);
                            zapTarget = `${parsed.protocol}//${parsed.host}`;
                            break;
                        } catch (e) { }
                    }
                }
                const saveRes = await fetch(`${API_BASE}/api/session/${sessionId}/save_recon_map`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ target: zapTarget, endpoints: mapped })
                });
                const saveData = await saveRes.json();
                if (saveData.status === 'ok') {
                    appendLog(`recon_map.json 저장 완료 (총 ${saveData.saved}개 엔드포인트)`, "System");
                } else {
                    appendLog(`recon_map.json 저장 실패: ${saveData.message}`, "System");
                }
            } catch (saveErr) {
                console.warn('recon_map save failed:', saveErr);
                appendLog('recon_map.json 저장 중 오류 발생', "System");
            }

            alert(`ZAP 히스토리에서 ${addedCount}개의 신규 패킷을 가져와 엔드포인트 목록에 추가했습니다.`);
        } else {
            alert("ZAP 히스토리 로드 실패: " + (data.message || "Unknown Error"));
        }
    } catch (e) {
        alert("ZAP 히스토리 로드 중 에러: " + e.message);
    }
}


async function startAiScan(sessionId) {
    const btn = document.getElementById('btnRunAi');
    if (btn) { btn.disabled = true; btn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin me-1"></i>AI 분석 중...'; }

    const aiConfig = {
        type: document.getElementById('aiType')?.value || '',
        api_key: document.getElementById('aiType')?.value === 'gemini'
            ? document.getElementById('geminiApiKey')?.value
            : (document.getElementById('aiType')?.value === 'vertex'
                ? document.getElementById('vertexApiKey')?.value
                : document.getElementById('lmstudioApiKey')?.value),
        base_url: document.getElementById('aiUrl')?.value || '',
        model: document.getElementById('aiModel')?.value || '',
        max_endpoints_per_batch: parseInt(document.getElementById('maxEndpointsPerBatch')?.value || '0') || 0,
        custom_prompt: document.getElementById('aiPromptCustom')?.value?.trim() || ''
    };

    const selectedEndpoints = (typeof allEndpoints !== 'undefined' ? allEndpoints : [])
        .filter(ep => (typeof aiTargetUrls !== 'undefined') && aiTargetUrls.has(`${ep.method || 'GET'}:${ep.url}`))
        .map(ep => ({
            url: ep.url,
            method: ep.method || 'GET',
            request_raw: ep.request_raw || '',
            response_raw: ep.response_raw || ''
        }));

    try {
        const res = await fetch(`${API_BASE}/api/session/${sessionId}/run_ai`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ai_config: aiConfig, endpoints: selectedEndpoints })
        });

        if (!res.ok) {
            try {
                const err = await res.json();
                appendLog(err.message || 'AI 분석 API 연결에 실패했습니다.', 'System');
            } catch {
                appendLog('AI 분석 API 연결에 실패했습니다.', 'System');
            }
            return;
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            const events = buffer.split(/\r?\n\r?\n/);
            buffer = events.pop();
            for (const event of events) {
                const trimmed = event.trim();
                if (!trimmed.startsWith('data: ')) continue;
                try {
                    const data = JSON.parse(trimmed.substring(6));
                    if (data.type === 'log' || data.type === 'progress') {
                        appendLog(data.message || data.msg, data.agent || data.source);
                    }
                    if (data.progress !== undefined) {
                        const pBar = document.getElementById('progressBar');
                        const pText = document.getElementById('progressText');
                        if (pBar) pBar.style.width = data.progress + '%';
                        if (pText) pText.textContent = Math.floor(data.progress) + '%';
                        const statText = document.getElementById('scanStatusText');
                        if (statText) statText.innerHTML = `<i class="fa-solid fa-circle-notch fa-spin text-info me-2"></i>AI 심층 분석 수행 중...`;
                    }
                    if (data.type === 'ai_card') {
                        aiCardsData.push(data.data);
                        renderCards(aiCardsData);
                    }
                    if (data.type === 'scan_complete') {
                        const statText = document.getElementById('scanStatusText');
                        if (statText) statText.innerHTML = `<i class="fa-solid fa-check-circle text-success me-2"></i>AI 분석 완료`;
                        updateScanConfigButton(false);
                    }
                } catch { }
            }
        }
    } catch (e) {
        console.error('AI scan error', e);
    } finally {
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="fa-solid fa-brain me-1"></i>AI 분석 시작'; }
    }
}
