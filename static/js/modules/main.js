/**
 * main.js - 세션 로드, 로그 뷰어, 배치 목록, 라우터 모듈
 */

let logWindowBackup = "";

function renderAliveCheckRow(tbody, result, idx, mode) {
    if (!tbody) return;
    const tr = document.createElement('tr');
    if (mode === 'alive' && result[0] === "-") {
        const colspan = mode === 'alive' ? 6 : 5;
        tr.innerHTML = `<td class="text-center">${idx + 1}</td><td class="text-center">-</td><td class="text-muted" colspan="${colspan - 2}">-</td>`;
    } else {
        const oxColor = result[0] === 'O' ? 'var(--success)' : 'var(--danger)';
        const httpColor = result[4] && result[4].includes('200') ? 'var(--success)' : (result[4] === 'X' ? 'var(--danger)' : 'var(--warning)');
        const httpsColor = result[5] && result[5].includes('200') ? 'var(--success)' : (result[5] === 'X' ? 'var(--danger)' : 'var(--warning)');

        if (mode === 'alive') {
            tr.innerHTML = `
                        <td class="text-center text-muted">${idx + 1}</td>
                        <td class="text-center fw-bold" style="color: ${oxColor}">${result[0]}</td>
                        <td class="font-mono text-light" style="font-size:0.75rem;">${result[1]}</td>
                        <td class="font-mono" style="font-size:0.75rem;"><a href="${result[2]}" target="_blank" style="color:var(--text-main); text-decoration:none;">${result[2]}</a></td>
                        <td class="font-mono" style="font-size:0.75rem;"><a href="${result[3]}" target="_blank" style="color:var(--text-main); text-decoration:none;">${result[3]}</a></td>
                        <td class="font-mono" style="font-size:0.65rem;">
                            <div><span class="badge" style="background:${httpColor}20; color:${httpColor};">HTTP: ${result[4]}</span></div>
                            <div class="mt-1"><span class="badge" style="background:${httpsColor}20; color:${httpsColor};">HTTPS: ${result[5]}</span></div>
                        </td>
                    `;
        } else {
            tr.innerHTML = `
                        <td class="text-center text-muted">${idx + 1}</td>
                        <td class="font-mono text-light" style="font-size:0.75rem;">${result[1]}</td>
                        <td class="font-mono text-light" style="font-size:0.75rem;">${result[8] || '-'}</td>
                        <td class="font-mono" style="font-size:0.75rem;">
                            <div style="max-width:240px; overflow-x:auto; white-space:nowrap;">
                                ${result[6] !== '-' ? result[6].split(', ').map(p => `<span class="badge bg-secondary me-1" style="font-size:0.65rem;">${p}</span>`).join('') : '-'}
                            </div>
                        </td>
                        <td class="font-mono text-danger" style="font-size:0.65rem; max-width:240px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;" title="${result[7]}">
                            ${result[7] !== '-' ? result[7] : '-'}
                        </td>
                    `;
        }
    }
    tbody.appendChild(tr);
}

async function loadSession(sessionId) {
    if (!sessionId) return;
    localStorage.setItem('currentSessionId', sessionId);

    renderEndpoints([]);
    renderCards([]);
    aiCardsData = [];
    aiTargetUrls.clear();
    document.getElementById('batchList').innerHTML = '<li><a class="dropdown-item text-muted">Scanning...</a></li>';
    document.getElementById('logWindow').innerHTML = `<div class="text-muted">Loading session data...</div>`;

    // 0. 프로젝트 기본 정보 로드 (설정값 복원)
    try {
        const resInfo = await fetch(`${API_BASE}/api/history/${sessionId}/json/project_info`);
        const infoJson = await resInfo.json();
        if (infoJson.status === "success") {
            const info = JSON.parse(infoJson.content);
            currentProject.name = info.project_name || "";
            currentProject.target = info.target || "";

            // UI 필드 업데이트
            const targetInput = document.getElementById('targetUrl');
            if (targetInput) targetInput.value = info.target || "";

            if (info.ffuf_options !== undefined) {
                const ffufOpts = document.getElementById('ffufOptions');
                if (ffufOpts) ffufOpts.value = info.ffuf_options;
            }
            if (info.ffuf_wordlist) {
                const ffufWl = document.getElementById('ffufWordlist');
                if (ffufWl) ffufWl.value = info.ffuf_wordlist;
            }
            if (info.enable_zap_spider !== undefined) {
                const zapCheck = document.getElementById('enableZapSpider');
                if (zapCheck) zapCheck.checked = info.enable_zap_spider;
            }
            if (info.enable_ffuf !== undefined) {
                const ffufCheck = document.getElementById('enableFfuf');
                if (ffufCheck) ffufCheck.checked = info.enable_ffuf;
            }
            if (info.enable_deep_recon !== undefined) {
                const deepCheck = document.getElementById('enableDeepRecon');
                if (deepCheck) deepCheck.checked = info.enable_deep_recon;
            }

            // AI 설정 복원
            if (info.ai_config) {
                const ai = info.ai_config;
                const aiType = document.getElementById('aiType');
                if (aiType && ai.type) {
                    aiType.value = ai.type;
                    if (typeof toggleAiSettings === 'function') toggleAiSettings();
                }
                const aiUrl = document.getElementById('aiUrl');
                if (aiUrl && ai.base_url) aiUrl.value = ai.base_url;

                const aiModel = document.getElementById('aiModel');
                if (aiModel && ai.model) aiModel.value = ai.model;

                const aiModelSelect = document.getElementById('aiModelSelect');
                if (aiModelSelect && ai.model) aiModelSelect.value = ai.model;

                const aiPrompt = document.getElementById('aiPromptCustom');
                if (aiPrompt && ai.custom_prompt) aiPrompt.value = ai.custom_prompt;

                const batchSize = document.getElementById('maxEndpointsPerBatch');
                if (batchSize && ai.max_endpoints_per_batch) batchSize.value = ai.max_endpoints_per_batch;

                // API 키 복원 (타입에 따라)
                if (ai.type === 'gemini') document.getElementById('geminiApiKey').value = ai.api_key || "";
                else if (ai.type === 'vertex') document.getElementById('vertexApiKey').value = ai.api_key || "";
                else if (ai.type === 'lmstudio') document.getElementById('lmstudioApiKey').value = ai.api_key || "";
            }

            // 브레드크럼 업데이트
            const breadcrumbText = document.getElementById('breadcrumbText');
            if (breadcrumbText) {
                breadcrumbText.innerHTML = `<i class="fa-solid fa-folder-open text-warning me-1"></i> ${info.project_name} <span class="text-muted small">(${info.target})</span>`;
            }
            // 스캔 버튼 노출
            document.querySelectorAll('.project-nav-item').forEach(m => m.style.display = 'flex');
            const topbarScanControls = document.getElementById('topbarScanControls');
            if (topbarScanControls) topbarScanControls.style.display = 'flex';
        }
    } catch (e) {
        console.warn("Project info load failed", e);
    }

    // 1. AI 분석 대상
    try {
        const resAiInput = await fetch(`${API_BASE}/api/history/${sessionId}/json/ai_input_full_requests`);
        const aiInputJson = await resAiInput.json();
        if (aiInputJson.status === "success") {
            const inputs = JSON.parse(aiInputJson.content);
            allEndpoints = inputs.map((req, idx) => ({
                url: req.url || req.requestHeader?.split(' ')[1] || "http://ai_analysis",
                method: req.method || req.requestMethod || 'GET',
                request_raw: req.raw_request || req.requestHeader || "",
                response_raw: req.response_context || req.responseHeader || "",
                source: "AI_Custom_Analysis",
                originalIndex: idx + 1
            }));

            renderEndpoints(allEndpoints);
        }
    } catch (e) { console.warn("AI input load failed", e); }

    // 2. Endpoints
    try {
        const resMap = await fetch(`${API_BASE}/api/history/${sessionId}/json/recon_map`);
        const mapDataJson = await resMap.json();
        if (mapDataJson.status === "success") {
            allEndpoints = JSON.parse(mapDataJson.content).endpoints || [];

            allEndpoints.forEach((ep, idx) => {
                if (!ep.time) ep.time = '-';
                if (ep.status === undefined || ep.status === null) ep.status = '-';
                ep.originalIndex = idx + 1;
            });

            renderEndpoints(allEndpoints);
        }
    } catch (e) { console.warn("Recon map load failed", e); }

    // 3. AI Targets 복원
    try {
        const resTargets = await fetch(`${API_BASE}/api/session/${sessionId}/ai_targets`);
        const targetsJson = await resTargets.json();
        if (targetsJson.status === 'ok' && targetsJson.targets?.length) {
            aiTargetUrls.clear();
            targetsJson.targets.forEach(t => aiTargetUrls.add(t));
            applyFilters();
        }
    } catch (e) { console.warn("AI targets load failed", e); }

    // 4. AI Findings
    try {
        const resCards = await fetch(`${API_BASE}/api/history/${sessionId}/json/ai_findings`);
        const cardsJson = await resCards.json();
        if (cardsJson.status === "success") {
            aiCardsData = JSON.parse(cardsJson.content);
            renderCards(aiCardsData);
        }
    } catch (e) { console.warn("Findings load failed", e); }

    // 5. Logs & Batches
    try {
        const resFiles = await fetch(`${API_BASE}/api/history/${sessionId}/files`);
        const filesJson = await resFiles.json();
        if (filesJson.status === "success") {
            const batches = filesJson.files.filter(f => f.startsWith('ai_input_batch_') && f.endsWith('.json'));
            updateBatchListFromFiles(batches);
        }

        const resLogs = await fetch(`${API_BASE}/api/history/${sessionId}/logs`);
        const logsJson = await resLogs.json();
        if (logsJson.status === "success" && logsJson.logs) {
            document.getElementById('logWindow').innerHTML = "";
            let lastProgress = 0;
            logsJson.logs.forEach(log => {
                if (log.type === "log" || log.message || log.msg) {
                    appendLog(log.message || log.msg, log.agent || log.source || "System");
                }
                if (log.progress !== undefined) lastProgress = log.progress;
            });
            document.getElementById('progressBar').style.width = lastProgress + "%";
            document.getElementById('progressText').textContent = Math.floor(lastProgress) + "%";
            document.getElementById('scanStatusText').innerHTML = (lastProgress >= 100) ?
                `<i class="fa-solid fa-check text-success me-2"></i>History Complete` :
                `<i class="fa-solid fa-clock-rotate-left text-muted me-2"></i>Loaded History`;
        }
    } catch (e) { console.warn("Logs load failed", e); }
}

function copyToClipboard(btn) {
    const pre = document.getElementById('rawJsonPre');
    if (!pre) return;
    navigator.clipboard.writeText(pre.innerText).then(() => {
        const orig = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check me-1"></i> 완료';
        btn.className = "btn btn-xs btn-success";
        setTimeout(() => {
            btn.innerHTML = orig;
            btn.className = "btn btn-xs btn-outline-warning";
        }, 1500);
    }).catch(e => alert("복사 실패: " + e));
}

async function loadRawJson(jsonName) {
    let sessionId = currentProject.id || localStorage.getItem('currentProject');
    if (!sessionId) return alert("프로젝트를 선택하거나 스캔을 먼저 가동하세요.");

    const viewer = document.getElementById('logWindow');

    if (viewer.querySelector('.log-item') && !logWindowBackup) {
        logWindowBackup = viewer.innerHTML;
    }

    viewer.textContent = "Fetching JSON...";
    try {
        const res = await fetch(`${API_BASE}/api/history/${sessionId}/json/${jsonName}`);
        const data = await res.json();
        if (data.status === "success" || data.logs) {
            let content = data.content;
            if (data.logs) {
                content = JSON.stringify(data.logs, null, 2);
            } else {
                try { content = JSON.stringify(JSON.parse(data.content), null, 2); } catch (e) { }
            }

            const charCount = content ? content.length : 0;
            const approxTokens = Math.ceil(charCount / 4.1);

            viewer.innerHTML = `
                    <div class="text-info mb-2 d-flex justify-content-between align-items-center">
                        <span style="font-size: 0.72rem; opacity: 0.9;">
                           🧾 <b>${jsonName}.json</b> | 🔡 ${charCount.toLocaleString()} 자 | 🔋 약 <b>${approxTokens.toLocaleString()}</b> Tok
                        </span>
                        <div class="d-flex gap-1">
                            <button class="btn btn-xs btn-outline-warning" style="font-size:0.65rem;" onclick="copyToClipboard(this)"><i class="fa-solid fa-copy me-1"></i> 복사</button>
                            <button class="btn btn-xs btn-outline-success" style="font-size:0.65rem;" onclick="restoreLogs()"><i class="fa-solid fa-terminal me-1"></i> 로그 복원</button>
                        </div>
                    </div><pre id="rawJsonPre" style="color: var(--info); white-space: pre-wrap; font-size: 0.8rem; height: calc(100% - 30px); overflow: auto; background: rgba(0,0,0,0.15); padding: 10px; border-radius: 8px;"></pre>`;
            document.getElementById('rawJsonPre').textContent = content;
        } else {
            viewer.textContent = data.message || "No data";
        }
    } catch (e) { viewer.textContent = "Error loading JSON: " + e; }
}

function updateBatchList(count) {
    const batchNames = [];
    for (let i = 1; i <= count; i++) {
        batchNames.push(`ai_input_batch_${i}.json`);
    }
    updateBatchListFromFiles(batchNames);
}

function updateBatchListFromFiles(files) {
    const list = document.getElementById('batchList');
    if (!files || files.length === 0) {
        list.innerHTML = '<li><a class="dropdown-item text-muted">No batches yet</a></li>';
        return;
    }
    list.innerHTML = '';
    files.forEach(file => {
        const batchBase = file.replace('.json', '');
        const batchLabel = batchBase.replace('ai_input_batch_', 'Batch #');
        const li = document.createElement('li');
        li.innerHTML = `<a class="dropdown-item" href="#" onclick="loadRawJson('${batchBase}')">${batchLabel}</a>`;
        list.appendChild(li);
    });
}

// 페이지 최초 로드 시 필요한 로직은 app.js에서 통합 관리합니다.

async function loadWordlists() {
    const select = document.getElementById('ffufWordlist');
    if (!select) return;
    try {
        const res = await fetch(`${API_BASE}/api/wordlists`);
        const data = await res.json();
        if (data.status === 'ok' && data.files.length > 0) {
            select.innerHTML = '';
            data.files.forEach(f => {
                const opt = document.createElement('option');
                opt.value = f;
                opt.textContent = f;
                if (f === 'wordlist_last.txt') opt.selected = true;
                select.appendChild(opt);
            });
        }
    } catch (e) { console.warn('wordlist load failed', e); }
}
