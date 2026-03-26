/**
 * scan.js - 스캔 시작/정지/ZAP 폴링/AI 분석 모듈
 */

let zapHistoryInterval = null;
let zapHistoryData = [];

function updateScanConfigButton(isRunning) {
    const startBtn = document.getElementById('startBtn');
    if (startBtn) {
        if (isRunning) {
            startBtn.className = "btn btn-sm btn-danger";
            startBtn.onclick = stopScan;
            startBtn.innerHTML = '<i class="fa-solid fa-stop me-1"></i> 스캔 정지';
        } else {
            startBtn.className = "btn btn-sm btn-success";
            startBtn.onclick = startScan;
            startBtn.innerHTML = '<i class="fa-solid fa-play me-1"></i> 스캔 시작';
        }
    }
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
    appendLog(`타겟 프로젝트[${projectName || url}] 스캔을 준비합니다...`, "System");
    document.getElementById('vulnsTableBody').innerHTML = '<tr><td colspan="5" class="empty-state">스캔 프로세스를 시작합니다...</td></tr>';
    document.getElementById('endpointsTableBody').innerHTML = '<tr><td colspan="8" class="empty-state">엔드포인트 자산 수집 중...</td></tr>';
    aiCardsData = [];
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
        const res = await fetch(`${API_BASE}/api/scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: currentProject.id || localStorage.getItem('currentSessionId') || "",
                target_url: url,
                project_name: projectName,
                headers: headers,
                enable_deep_recon: document.getElementById('enableDeepRecon') ? document.getElementById('enableDeepRecon').checked : true,
                ai_config: {
                    type: document.getElementById('aiType').value,
                    api_key: document.getElementById('aiType').value === 'gemini'
                        ? document.getElementById('geminiApiKey').value
                        : (document.getElementById('aiType').value === 'vertex'
                            ? document.getElementById('vertexApiKey').value
                            : document.getElementById('lmstudioApiKey').value),
                    base_url: document.getElementById('aiUrl').value,
                    model: document.getElementById('aiModel').value
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
                            localStorage.setItem('currentSessionId', data.session_id);
                            const select = document.getElementById('historySelect');
                            if (select) select.value = data.session_id;
                            loadHistoryList();
                            allEndpoints = [];
                            startZapPolling();
                        } else if (data.type === "log" || data.type === "progress") {
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
                            appendLog("정찰 단계가 완료되었습니다. AI 분석 엔진을 가동합니다.", "System");
                        }
                        if (data.type === "ai_card") {
                            aiCardsData.push(data.data);
                            renderCards(aiCardsData);
                        }
                        if (data.type === "ai_targets") {
                            aiTargetUrls = new Set(data.data || []);
                            renderEndpoints(allEndpoints, true);
                            appendLog(`AI 엔진이 심층 분석을 위해 ${aiTargetUrls.size}개의 타겟을 선정했습니다.`, "System");
                        }
                        if (data.type === "scan_complete") {
                            const pBar = document.getElementById('progressBar');
                            const pText = document.getElementById('progressText');
                            const statText = document.getElementById('scanStatusText');

                            if (pBar) pBar.style.width = "100%";
                            if (pText) pText.textContent = "100%";
                            if (statText) statText.innerHTML = `<i class="fa-solid fa-check text-success me-2"></i>모든 스캔 및 분석 작업 완료`;

                            updateScanConfigButton(false);
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
        document.getElementById('startBtn').disabled = false;
        document.getElementById('stopBtn').disabled = true;
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
                if (!m.uri || isStaticFile(m.uri)) return;

                let parsedStatus = '-';
                if (m.responseHeader) {
                    const fl = m.responseHeader.split('\n')[0].trim();
                    const parts = fl.split(' ');
                    if (parts.length >= 2 && /^\d+$/.test(parts[1])) parsedStatus = parts[1];
                }

                if (parsedStatus === '0' || parsedStatus === '502') return;

                const key = `${(m.method || 'GET').toUpperCase()}:${m.uri}`;
                if (!existingKeys.has(key)) {
                    allEndpoints.push({
                        url: m.uri,
                        method: m.method || 'GET',
                        status: parsedStatus,
                        source: 'zap_history',
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

            if (added && document.getElementById('section-endpoints').classList.contains('active')) {
                applyFilters();
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
    try {
        appendLog("ZAP 히스토리를 가져오는 중입니다...", "System");
        const res = await fetch(`${API_BASE}/api/zap/history`);
        const data = await res.json();

        if (data.status === 'success' && data.messages) {
            const mapped = data.messages.filter(msg => {
                if (msg.uri && isStaticFile(msg.uri)) return false;
                if (!msg.responseHeader) return false;
                const firstLine = msg.responseHeader.split('\n')[0].trim();
                const parts = firstLine.split(' ');
                if (parts.length >= 2 && (parts[1] === '0' || parts[1] === '502')) return false;
                return true;
            }).map(msg => {
                let method = 'GET';
                let url = '-';
                if (msg.requestHeader) {
                    const firstLine = msg.requestHeader.split('\n')[0].trim();
                    const parts = firstLine.split(' ');
                    if (parts.length >= 1) method = parts[0].toUpperCase();
                    if (parts.length >= 2) url = parts[1];
                }
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
                    source: 'ZAP_History',
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
            alert(`ZAP 히스토리에서 ${addedCount}개의 신규 패킷을 가져와 엔드포인트 목록에 추가했습니다.`);
        } else {
            alert("ZAP 히스토리 로드 실패: " + (data.message || "Unknown Error"));
        }
    } catch (e) {
        alert("ZAP 히스토리 로드 중 에러: " + e.message);
    }
}

async function analyzeSelectedEndpoints() {
    const selectedEndpoints = allEndpoints.filter(ep => selectedEndpointsSet.has(`${ep.method || 'GET'}:${ep.url}`));

    if (selectedEndpoints.length === 0) return alert("분석할 항목을 선택해주세요.");

    const btn = document.getElementById('btnAnalyzeEndpoints');
    const originalText = btn.innerHTML;
    btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin me-1"></i>분석 중...`;
    btn.disabled = true;

    appendLog(`선택한 ${selectedEndpoints.length}개의 항목에 대고 AI 심층 분석을 요청합니다.`, "AI");

    try {
        const sessionId = currentProject.id || localStorage.getItem('currentProject');
        const sessionDir = sessionId ? `${sessionId}` : "";

        const res = await fetch(`${API_BASE}/api/zap/analyze`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                packets: selectedEndpoints.map(ep => ({
                    requestHeader: ep.request_raw || "",
                    requestBody: "",
                    responseHeader: ep.response_raw || "",
                    responseBody: "",
                    url: ep.url,
                    requestMethod: ep.method
                })),
                ai_config: {
                    type: document.getElementById('aiType').value,
                    api_key: document.getElementById('aiType').value === 'gemini'
                        ? document.getElementById('geminiApiKey').value
                        : (document.getElementById('aiType').value === 'vertex'
                            ? document.getElementById('vertexApiKey').value
                            : document.getElementById('lmstudioApiKey').value),
                    base_url: document.getElementById('aiUrl').value,
                    model: document.getElementById('aiModel').value
                },
                session_dir: sessionDir
            })
        });

        const data = await res.json();
        if (data.status === 'success' && data.findings) {
            if (data.session_id) {
                localStorage.setItem('currentSessionId', data.session_id);
            }
            loadHistoryList();
            appendLog(`AI 분석 성공: ${data.findings.length}개의 취약점이 식별되었습니다.`, "AI");

            data.findings.forEach(f => {
                aiCardsData.push(f);
            });
            renderCards(aiCardsData);
            alert(`AI 분석 완료! ${data.findings.length}개의 항목이 탐지되었습니다.`);

            document.querySelectorAll('.endpoint-check').forEach(c => c.checked = false);
            const master = document.getElementById('checkAllEndpoints');
            if (master) master.checked = false;
            toggleMainAnalyzeBtn();
        } else {
            alert("분석 실패: " + (data.message || "Unknown Error"));
        }
    } catch (e) {
        alert("에러 발생: " + e.message);
        appendLog("AI 분석 중 에러 발생", "System");
    } finally {
        btn.innerHTML = originalText;
        btn.disabled = false;
    }
}
