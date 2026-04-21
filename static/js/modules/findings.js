/**
 * findings.js - 취약점(AI 분석 결과) 카드 렌더링 및 관리 모듈
 */

let aiCardsData = [];
let currentEditIndex = -1;
let isEditingCard = false;

// ── 취약점 카드 렌더링 ────────────────────────────────────

function renderCards(cardsArray) {
    const tbody = document.getElementById('vulnsTableBody');
    tbody.innerHTML = '';
    let crit = 0, high = 0, medlow = 0;

    if (!Array.isArray(cardsArray) || cardsArray.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state">현재 시그니처와 일치하는 위협이 탐지되지 않았습니다.</td></tr>';
        ['statCritical', 'statHigh', 'statMedLow'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = 0;
        });
        return;
    }

    cardsArray.forEach((card, index) => {
        const sev = (card.severity || '').toString().toUpperCase();
        let sevClass = "sev-low";
        if (sev.includes("CRITICAL")) { sevClass = "sev-critical"; crit++; }
        else if (sev.includes("HIGH")) { sevClass = "sev-high"; high++; }
        else { sevClass = sev.includes("MEDIUM") ? "sev-medium" : "sev-low"; medlow++; }

        const tr = document.createElement('tr');
        tr.style.cursor = "pointer";
        tr.onclick = () => openVerifyModal(index);

        const safeTitle = (card.title || 'Threat').replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const verifiedBadge = card.verified
            ? ' <span class="badge bg-danger rounded-pill ms-2"><i class="fa-solid fa-fire text-warning me-1"></i>Verified</span>' : '';
        const sourceBadge = card.source === 'Nuclei'
            ? ' <span class="badge ms-1" style="background:#7f1d1d;color:#fca5a5;font-size:0.6rem;vertical-align:middle;"><i class="fa-solid fa-atom me-1"></i>Nuclei</span>' : '';
        const safeTarget = (card.target || '').replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const confScore = card.confidence || 0;
        let confClass = "bg-secondary";
        if (confScore >= 90) confClass = "bg-danger";
        else if (confScore >= 70) confClass = "bg-warning text-dark";

        const safeTtp = (card.ttp || '—').replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const safeOwasp = (card.owasp || '—').replace(/</g, "&lt;").replace(/>/g, "&gt;");

        // ── Triage 상태/분류 배지 ──────────────────────────────
        const tStatus = (card.triage_status || '').toLowerCase();
        let triageBadge = '';
        if (tStatus === 'in_progress') {
            triageBadge = ' <span class="badge bg-info rounded-pill ms-2"><i class="fa-solid fa-circle-notch fa-spin me-1"></i>검증 중</span>';
        } else if (tStatus === 'verified' || card.verified) {
            triageBadge = ' <span class="badge bg-success rounded-pill ms-2"><i class="fa-solid fa-check me-1"></i>검증됨</span>';
        } else if (tStatus === 'failed') {
            triageBadge = ' <span class="badge bg-secondary rounded-pill ms-2"><i class="fa-solid fa-xmark me-1"></i>검증실패</span>';
        } else if (tStatus === 'dismissed') {
            triageBadge = ' <span class="badge bg-dark border rounded-pill ms-2"><i class="fa-solid fa-ban me-1"></i>오탐</span>';
        }
        const vClass = card.vuln_class ? ` <span class="badge ms-1" style="background:rgba(99,102,241,0.15);color:#a5b4fc;font-size:0.6rem;vertical-align:middle;">${card.vuln_class}</span>` : '';
        const fid = card.id || '';

        tr.innerHTML = `
            <td class="text-center" onclick="event.stopPropagation()">
                <input type="checkbox" class="vuln-checkbox" style="cursor:pointer;" value="${index}" data-fid="${fid}">
            </td>
            <td class="text-center text-muted" style="font-size:0.8rem;">${index + 1}</td>
            <td><span class="sev-pill ${sevClass}">${sev}</span></td>
            <td><span class="pill ${confClass}" style="min-width:35px;text-align:center;">${confScore}</span></td>
            <td class="fw-bold" style="color:var(--text-main);" data-fid="${fid}">${safeTitle}${vClass}${triageBadge}${verifiedBadge}${sourceBadge}</td>
            <td class="text-muted font-mono" style="font-size:0.8rem;word-break:break-all;">${safeTarget}</td>
            <td style="font-size:0.8rem;"><span class="badge bg-secondary font-mono" style="padding:4px 8px;white-space:nowrap;display:inline-block;font-size:0.8rem;">${safeTtp}</span></td>
            <td style="font-size:0.8rem;"><span class="badge bg-dark border font-mono" style="padding:4px 8px;white-space:nowrap;display:inline-block;font-size:0.8rem;">${safeOwasp}</span></td>
            <td class="text-center">
                <button class="btn btn-xs btn-outline-danger" style="padding:2px 6px;font-size:0.75rem;" onclick="deleteCard(${index});event.stopPropagation();">
                    <i class="fa-solid fa-trash"></i>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });

    const setVal = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    setVal('statCritical', crit);
    setVal('statHigh', high);
    setVal('statMedLow', medlow);
    setVal('vulnsCount', cardsArray.length);
}

// ── 삭제 ─────────────────────────────────────────────────

function deleteCard(index) {
    if (confirm("이 취약점 항목을 목록에서 삭제하시겠습니까?")) {
        if (aiCardsData[index] !== undefined) {
            aiCardsData.splice(index, 1);
            renderCards(aiCardsData);
            if (typeof appendLog === 'function') appendLog("취약점 항목이 사용자에 의해 수동 삭제되었습니다.", "System");
            if (typeof closeDrawer === 'function') closeDrawer();
            saveFindings();
        }
    }
}

function toggleAllVulns(source) {
    document.querySelectorAll('.vuln-checkbox').forEach(c => c.checked = source.checked);
}

async function deleteSelectedCards() {
    const checkboxes = document.querySelectorAll('.vuln-checkbox:checked');
    if (checkboxes.length === 0) return alert("삭제할 항목을 선택해 주세요.");

    if (confirm(`선택한 ${checkboxes.length}개의 취약점을 목록에서 삭제하시겠습니까?`)) {
        const indices = Array.from(checkboxes).map(c => parseInt(c.value)).sort((a, b) => b - a);
        indices.forEach(idx => aiCardsData.splice(idx, 1));
        renderCards(aiCardsData);
        if (typeof appendLog === 'function') appendLog(`${checkboxes.length}개의 취약점 항목이 선택 삭제되었습니다.`, "System");
        if (typeof closeDrawer === 'function') closeDrawer();
        saveFindings();
        const hc = document.getElementById('checkAllVulns');
        if (hc) hc.checked = false;
    }
}

// ── 저장 ─────────────────────────────────────────────────

async function saveFindings() {
    const sid = (typeof currentProject !== 'undefined' ? currentProject.id : null)
        || localStorage.getItem('currentSessionId');
    if (!sid) return;
    try {
        const res = await fetch(`${API_BASE}/api/findings/save`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sid, findings: aiCardsData || [] })
        });
        const data = await res.json();
        if (data.status !== "success") console.error("취약점 저장 실패:", data.message);
    } catch (e) {
        console.error("취약점 저장 중 에러 발생:", e);
    }
}

// ── 수정 토글 ─────────────────────────────────────────────

async function toggleEditCard() {
    if (currentEditIndex === -1) return;
    isEditingCard = !isEditingCard;
    const drawEditBtn = document.getElementById('btnEditCard');

    if (!isEditingCard) {
        const card = aiCardsData[currentEditIndex];
        ['title', 'severity', 'cwe', 'target', 'description', 'evidence', 'steps', 'recommendation', 'ttp', 'owasp'].forEach(field => {
            const el = document.getElementById(`editCard${field.charAt(0).toUpperCase() + field.slice(1)}`);
            if (el) card[field] = el.value;
        });
        renderCards(aiCardsData);
        if (typeof appendLog === 'function') appendLog("취약점 정보가 수동으로 수정되었습니다.", "System");
        saveFindings();
        if (drawEditBtn) drawEditBtn.innerHTML = '<i class="fa-solid fa-pen-to-square"></i> 수정';
    } else {
        if (drawEditBtn) drawEditBtn.innerHTML = '<i class="fa-solid fa-floppy-disk"></i> 저장';
    }

    openVerifyModal(currentEditIndex, isEditingCard);
}

// ── 상세 모달 ─────────────────────────────────────────────

function openVerifyModal(index, editMode = false) {
    currentEditIndex = index;
    isEditingCard = editMode;
    const card = aiCardsData[index];
    if (!card) return;

    const drawEditBtn = document.getElementById('btnEditCard');
    if (drawEditBtn) {
        drawEditBtn.style.display = 'inline-block';
        drawEditBtn.innerHTML = isEditingCard
            ? '<i class="fa-solid fa-floppy-disk"></i> 저장'
            : '<i class="fa-solid fa-pen-to-square"></i> 수정';
    }

    const sev = (card.severity || 'LOW').toUpperCase();
    const esc = s => (s || '').replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

    let html = "";
    if (isEditingCard) {
        html = `
            <div class="mb-3"><label class="small text-muted mb-1">취약점 명칭</label>
                <input type="text" id="editCardTitle" class="form-control form-control-sm mb-2" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);" value="${esc(card.title)}"></div>
            <div class="mb-3"><label class="small text-muted mb-1">위험도</label>
                <input type="text" id="editCardSeverity" class="form-control form-control-sm mb-2" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);" value="${esc(card.severity)}"></div>
            <div class="mb-3"><label class="small text-muted mb-1">CWE ID</label>
                <input type="text" id="editCardCwe" class="form-control form-control-sm mb-2" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);" value="${esc(card.cwe)}"></div>
            <div class="mb-3"><label class="small text-muted mb-1">TTP (MITRE ATT&CK)</label>
                <input type="text" id="editCardTtp" class="form-control form-control-sm mb-2" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);" placeholder="예: T1190" value="${esc(card.ttp)}"></div>
            <div class="mb-3"><label class="small text-muted mb-1">OWASP TOP10</label>
                <input type="text" id="editCardOwasp" class="form-control form-control-sm mb-2" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);" placeholder="예: A01:2025" value="${esc(card.owasp)}"></div>
            <div class="mb-3"><label class="small text-muted mb-1">Target Location</label>
                <input type="text" id="editCardTarget" class="form-control form-control-sm mb-2" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);" value="${esc(card.target)}"></div>
            <div class="mb-3"><label class="small text-muted mb-1">설명</label>
                <textarea id="editCardDescription" class="form-control font-mono" rows="4" style="font-size:0.85rem;background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);">${esc(card.description)}</textarea></div>
            <div class="mb-3"><label class="small text-muted mb-1">공격 근거</label>
                <textarea id="editCardEvidence" class="form-control font-mono" rows="3" style="font-size:0.75rem;background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);">${esc(card.evidence)}</textarea></div>
            <div class="mb-3"><label class="small text-muted mb-1">재현 단계</label>
                <textarea id="editCardSteps" class="form-control" rows="3" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);">${esc(card.steps)}</textarea></div>
            <div class="mb-0"><label class="small text-muted mb-1">보완 권고</label>
                <textarea id="editCardRecommendation" class="form-control" rows="3" style="background:var(--bg-darker);color:var(--text-main);border-color:var(--border-color);">${esc(card.recommendation)}</textarea></div>
        `;
    } else {
        // 탭 UI
        const detailsTabContent = `
            <div class="mb-3 p-3 rounded" style="background:var(--bg-hover);border:1px solid var(--border-color);">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">위험도 &amp; 신뢰도</div>
                <div class="fw-bold"><span class="sev-pill sev-${sev.toLowerCase()}">${sev}</span>
                    <span class="ms-2" style="color:var(--text-main);">Confidence: ${card.confidence || 0}</span></div>
            </div>
            <div class="mb-3 p-3 rounded" style="background:var(--bg-hover);border:1px solid var(--border-color);">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">식별자</div>
                <div style="font-size:0.85rem;">
                    <div class="mb-2"><span class="text-muted">CWE:</span> <span class="text-warning fw-bold">${card.cwe || '-'}</span></div>
                    <div class="mb-2"><span class="text-muted">TTP:</span> <span class="text-info fw-bold">${card.ttp || '-'}</span></div>
                    <div><span class="text-muted">OWASP:</span> <span class="text-danger fw-bold">${card.owasp || '-'}</span></div>
                </div>
            </div>
            <div class="mb-3">
                <div class="text-muted text-uppercase mb-2" style="font-size:0.7rem;">Target Location</div>
                <div class="text-info font-mono" style="word-break:break-all;background:var(--bg-hover);padding:8px;border-radius:4px;font-size:0.8rem;border:1px solid var(--border-color);">${card.target || '-'}</div>
            </div>
            ${card.scanned_from ? `<div class="mb-3">
                <div class="text-muted text-uppercase mb-2" style="font-size:0.7rem;">Scanned From</div>
                <div class="font-mono" style="word-break:break-all;background:var(--bg-hover);padding:8px;border-radius:4px;font-size:0.78rem;border:1px solid var(--border-color);color:var(--text-muted);">${esc(card.scanned_from)}</div>
            </div>` : ''}
            <hr class="border-secondary opacity-25">
            <div class="mb-3">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Technical Summary</div>
                <div style="font-size:0.9rem;line-height:1.6;">${typeof marked !== 'undefined' ? marked.parse(card.description || 'N/A') : (card.description || 'N/A')}</div>
            </div>
            <div class="mb-3">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Reproduction Evidence</div>
                <pre class="p-2 rounded font-mono" style="font-size:0.75rem;border:1px solid var(--border-color);max-height:200px;overflow:auto;background:var(--bg-hover);color:var(--text-main);">${esc(card.evidence) || 'N/A'}</pre>
            </div>
            <div class="mb-3">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Reproduction Steps</div>
                <div class="p-3 rounded" style="background:var(--bg-hover);border:1px solid var(--border-color);font-size:0.88rem;white-space:pre-line;">${esc(card.steps) || 'N/A'}</div>
            </div>
            <div class="mb-3">
                <button class="btn btn-sm btn-outline-info" onclick="verifyVulnerabilityInTerminal(${index})" style="font-size:0.8rem;">
                    <i class="fa-solid fa-terminal me-1"></i>웹 터미널에서 검증
                </button>
                <button class="btn btn-sm btn-outline-success ms-2" onclick="copyVulnSteps(${index})" style="font-size:0.8rem;">
                    <i class="fa-solid fa-copy me-1"></i>재현 단계 복사
                </button>
            </div>
            <div class="mb-0">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Recommendation / Remediation</div>
                <div class="p-3 rounded border-start border-3 border-success" style="background:rgba(34,197,94,0.05);font-size:0.88rem;">${typeof marked !== 'undefined' ? marked.parse(card.recommendation || 'N/A') : (card.recommendation || 'N/A')}</div>
            </div>
        `;
        
        const jsonTabContent = `
            <div style="margin-bottom:12px;">
                <button class="btn btn-sm btn-outline-secondary" onclick="copyVulnJson(${index})" style="font-size:0.75rem;">
                    <i class="fa-solid fa-copy me-1"></i>복사
                </button>
            </div>
            <pre id="vulnJsonPre_${index}" class="p-3 rounded font-mono" style="font-size:0.75rem;border:1px solid var(--border-color);max-height:500px;overflow:auto;background:var(--bg-hover);color:var(--text-main);white-space:pre-wrap;word-wrap:break-word;">${JSON.stringify(card, null, 2)}</pre>
        `;

        const hasReqRes = card._raw_request || card._response_context;
        const reqresTabContent = hasReqRes ? `
            <div class="mb-3">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Raw Request</div>
                <pre class="p-2 rounded font-mono" style="font-size:0.75rem;border:1px solid var(--border-color);max-height:300px;overflow:auto;background:var(--bg-hover);color:var(--text-main);white-space:pre-wrap;word-wrap:break-word;">${esc(card._raw_request) || 'N/A'}</pre>
            </div>
            <div class="mb-0">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Response Context</div>
                <pre class="p-2 rounded font-mono" style="font-size:0.75rem;border:1px solid var(--border-color);max-height:300px;overflow:auto;background:var(--bg-hover);color:var(--text-main);white-space:pre-wrap;word-wrap:break-word;">${esc(card._response_context) || 'N/A'}</pre>
            </div>
        ` : '<div class="text-muted text-center py-4" style="font-size:0.85rem;">원본 요청/응답 데이터 없음</div>';

        html = `
            <div class="mb-3" style="border-bottom:1px solid var(--border-color);display:flex;gap:12px;">
                <button class="tab-btn active" onclick="switchVulnTab(this, ${index}, 'details')" style="background:none;border:none;color:var(--text-main);padding:12px 16px;cursor:pointer;border-bottom:2px solid var(--primary);font-size:0.9rem;font-weight:600;">
                    <i class="fa-solid fa-list me-2"></i>상세정보
                </button>
                <button class="tab-btn" onclick="switchVulnTab(this, ${index}, 'reqres')" style="background:none;border:none;color:var(--text-muted);padding:12px 16px;cursor:pointer;border-bottom:2px solid transparent;font-size:0.9rem;font-weight:600;">
                    <i class="fa-solid fa-terminal me-2"></i>요청/응답
                </button>
                <button class="tab-btn" onclick="switchVulnTab(this, ${index}, 'json')" style="background:none;border:none;color:var(--text-muted);padding:12px 16px;cursor:pointer;border-bottom:2px solid transparent;font-size:0.9rem;font-weight:600;">
                    <i class="fa-solid fa-code me-2"></i>JSON
                </button>
            </div>

            <div id="vulnTab_details_${index}" class="tab-content" style="display:block;">
                ${detailsTabContent}
            </div>

            <div id="vulnTab_reqres_${index}" class="tab-content" style="display:none;">
                ${reqresTabContent}
            </div>

            <div id="vulnTab_json_${index}" class="tab-content" style="display:none;">
                ${jsonTabContent}
            </div>
        `;
    }


    if (!editMode) {
        if (typeof openDrawer === 'function') openDrawer(card.title || '취약점 상세 정보', html);
    } else {
        document.getElementById('drawerBody').innerHTML = html;
    }
    if (drawEditBtn) drawEditBtn.style.display = 'inline-block';
}

// ── 탭 전환 함수 ─────────────────────────────────────────

function switchVulnTab(tabBtn, cardIndex, tabType) {
    // 모든 탭 버튼 스타일 초기화
    const tabBtns = tabBtn.parentElement.querySelectorAll('.tab-btn');
    tabBtns.forEach(btn => {
        btn.style.borderBottom = '2px solid transparent';
        btn.style.color = 'var(--text-muted)';
    });
    
    // 현재 탭 버튼 스타일 적용
    tabBtn.style.borderBottom = '2px solid var(--primary)';
    tabBtn.style.color = 'var(--text-main)';
    
    // 모든 컨텐츠 숨기기
    const detailsTab = document.getElementById(`vulnTab_details_${cardIndex}`);
    const reqresTab = document.getElementById(`vulnTab_reqres_${cardIndex}`);
    const jsonTab = document.getElementById(`vulnTab_json_${cardIndex}`);

    if (detailsTab) detailsTab.style.display = 'none';
    if (reqresTab) reqresTab.style.display = 'none';
    if (jsonTab) jsonTab.style.display = 'none';

    // 선택된 탭 표시
    if (tabType === 'details' && detailsTab) {
        detailsTab.style.display = 'block';
    } else if (tabType === 'reqres' && reqresTab) {
        reqresTab.style.display = 'block';
    } else if (tabType === 'json' && jsonTab) {
        jsonTab.style.display = 'block';
    }
}

// ── JSON 복사 함수 ─────────────────────────────────────

function copyVulnJson(cardIndex) {
    const card = aiCardsData[cardIndex];
    if (!card) return;

    const jsonStr = JSON.stringify(card, null, 2);
    navigator.clipboard.writeText(jsonStr).then(() => {
        const btn = event.target.closest('button');
        const origText = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check me-1"></i>복사됨';
        btn.disabled = true;
        setTimeout(() => {
            btn.innerHTML = origText;
            btn.disabled = false;
        }, 2000);
    }).catch(err => {
        console.error('JSON 복사 실패:', err);
        alert('클립보드 복사에 실패했습니다.');
    });
}

// ── 웹 터미널에서 취약점 검증 ─────────────────────────────

function verifyVulnerabilityInTerminal(cardIndex) {
    const card = aiCardsData[cardIndex];
    if (!card) return;

    // 재현 단계에서 curl 명령어 추출
    const steps = (card.steps || '').trim();
    const curlMatch = steps.match(/curl\s+[^\n]+/g);

    if (!curlMatch || curlMatch.length === 0) {
        alert('재현 단계에서 curl 명령어를 찾을 수 없습니다.\n\n수동으로 다음을 시도해보세요:\n' + steps);
        return;
    }

    // 웹 터미널 탭으로 전환
    switchSection('section-terminal');

    // 웹 터미널이 준비될 때까지 대기
    setTimeout(() => {
        // 첫 번째 curl 명령어 실행
        const curlCmd = curlMatch[0];
        console.log('[verifyVulnerabilityInTerminal] Executing:', curlCmd);

        // 터미널에 명령어 입력 (터미널 API 사용)
        if (typeof termSend === 'function') {
            termSend(curlCmd + '\n');
            appendLog(`취약점 검증: ${card.title} @ ${card.target}`, 'System');
        } else {
            alert('웹 터미널을 초기화할 수 없습니다.\n\n수동으로 이 명령어를 실행해보세요:\n\n' + curlCmd);
        }
    }, 300);
}

function copyVulnSteps(cardIndex) {
    const card = aiCardsData[cardIndex];
    if (!card) {
        alert('취약점 정보를 찾을 수 없습니다.');
        return;
    }

    const steps = (card.steps || 'N/A').trim();
    navigator.clipboard.writeText(steps).then(() => {
        const btn = event.target.closest('button');
        const origText = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check me-1"></i>복사됨';
        btn.disabled = true;
        setTimeout(() => {
            btn.innerHTML = origText;
            btn.disabled = false;
        }, 2000);
    }).catch(err => {
        console.error('재현 단계 복사 실패:', err);
        alert('클립보드 복사에 실패했습니다.');
    });
}

// ── Phase 2: Triage / Deep Spear ─────────────────────────

let _triageRunning = false;

function _currentSessionId() {
    return (typeof currentProject !== 'undefined' ? currentProject.id : null)
        || localStorage.getItem('currentSessionId') || "";
}

function _setTriageStatus(text, type) {
    const box = document.getElementById('triageStatusInline');
    if (!box) return;
    const color = type === 'running' ? 'var(--info)'
        : type === 'ok' ? 'var(--success, #22c55e)'
        : type === 'err' ? 'var(--danger, #ef4444)'
        : 'var(--text-muted)';
    const icon = type === 'running' ? 'fa-circle-notch fa-spin'
        : type === 'ok' ? 'fa-check'
        : type === 'err' ? 'fa-triangle-exclamation'
        : 'fa-crosshairs';
    box.innerHTML = `<i class="fa-solid ${icon} me-1" style="color:${color}"></i><span>${text}</span>`;
}

function _toggleTriageRunning(running) {
    _triageRunning = running;
    const btnRun = document.getElementById('btnTriageDeepDive');
    const btnStop = document.getElementById('btnTriageStop');
    if (btnRun) btnRun.disabled = running;
    if (btnStop) btnStop.style.display = running ? 'inline-block' : 'none';
}

function _findCardIndexById(fid) {
    if (!fid) return -1;
    return aiCardsData.findIndex(c => c && c.id === fid);
}

function _applyTriagePatch(fid, patch) {
    const idx = _findCardIndexById(fid);
    if (idx < 0) return;
    Object.assign(aiCardsData[idx], patch || {});
    renderCards(aiCardsData);
}

async function _ensureFindingIds() {
    const sid = _currentSessionId();
    if (!sid) return false;
    try {
        const res = await fetch(`${API_BASE}/api/triage/classify`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sid })
        });
        const data = await res.json();
        if (data.status !== 'success') return false;
        // classify 가 id/vuln_class/priority 를 파일에 기록했으므로 reload
        const r2 = await fetch(`${API_BASE}/api/triage/list`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sid })
        });
        const d2 = await r2.json();
        if (d2.status === 'success' && Array.isArray(d2.findings)) {
            aiCardsData = d2.findings;
            renderCards(aiCardsData);
        }
        return true;
    } catch (e) {
        console.error("triage classify 실패:", e);
        return false;
    }
}

function _collectSelectedFindingIds() {
    const boxes = document.querySelectorAll('.vuln-checkbox:checked');
    const fids = [];
    boxes.forEach(b => {
        const fid = b.getAttribute('data-fid');
        if (fid) fids.push(fid);
        else {
            const idx = parseInt(b.value);
            const card = aiCardsData[idx];
            if (card && card.id) fids.push(card.id);
        }
    });
    return Array.from(new Set(fids));
}

async function deepDiveSelected() {
    if (_triageRunning) {
        alert("이미 전문가 검증이 실행 중입니다.");
        return;
    }
    const sid = _currentSessionId();
    if (!sid) {
        alert("세션이 없습니다. 먼저 스캔을 수행하거나 프로젝트를 선택하세요.");
        return;
    }

    await _ensureFindingIds();

    const fids = _collectSelectedFindingIds();
    if (fids.length === 0) {
        alert("심층 검증할 항목을 체크박스로 선택해 주세요.");
        return;
    }

    if (!confirm(`선택된 ${fids.length}건에 전문가 AI 에이전트를 투입합니다. 진행할까요?`)) return;

    // AI 설정 수집
    const aiCfg = (typeof getAIConfig === 'function') ? getAIConfig() : {};

    _toggleTriageRunning(true);
    _setTriageStatus(`Phase 2 실행 중 — 0/${fids.length}`, 'running');
    appendLog(`Phase 2 전문가 검증 시작 — ${fids.length}건`, "Triage");

    // 선택된 카드 in_progress 표시
    fids.forEach(fid => _applyTriagePatch(fid, { triage_status: 'in_progress' }));

    try {
        const res = await fetch(`${API_BASE}/api/triage/deep-dive`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                session_id: sid,
                finding_ids: fids,
                ai_config: aiCfg,
                max_parallel: 1
            })
        });
        if (!res.ok || !res.body) {
            appendLog("전문가 검증 API 연결 실패", "Triage");
            _toggleTriageRunning(false);
            _setTriageStatus('연결 실패', 'err');
            return;
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let done_count = 0;
        let verified_count = 0;

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
                    appendLog(data.message || data.msg || '', data.source || 'Triage');
                }
                else if (data.type === 'triage_start') {
                    _applyTriagePatch(data.finding_id, {
                        triage_status: 'in_progress',
                        vuln_class: data.vuln_class
                    });
                    appendLog(`[${data.vuln_class}] 전문가 투입: ${data.title || data.finding_id}`, 'Triage');
                }
                else if (data.type === 'triage_tool_call') {
                    appendLog(`  └ ${data.tool}: ${JSON.stringify(data.input || {}).slice(0, 180)}`, 'Triage');
                }
                else if (data.type === 'triage_tool_result') {
                    const preview = (data.output || '').split('\n').slice(0, 2).join(' / ').slice(0, 200);
                    if (preview) appendLog(`  └ 결과: ${preview}`, 'Triage');
                }
                else if (data.type === 'triage_finding_verified') {
                    verified_count += 1;
                    _applyTriagePatch(data.finding_id, {
                        triage_status: 'verified',
                        verified: true
                    });
                }
                else if (data.type === 'triage_complete') {
                    done_count += 1;
                    _applyTriagePatch(data.finding_id, {
                        triage_status: data.verified ? 'verified' : 'failed',
                        verified: !!data.verified
                    });
                    _setTriageStatus(
                        `Phase 2 실행 중 — ${done_count}/${fids.length} (검증성공 ${verified_count})`,
                        'running'
                    );
                }
                else if (data.type === 'triage_batch_complete' || data.type === 'scan_complete') {
                    break;
                }
            }
        }

        _setTriageStatus(
            `Phase 2 완료 — 검증성공 ${verified_count} / 전체 ${fids.length}`,
            verified_count > 0 ? 'ok' : 'err'
        );
        appendLog(`Phase 2 완료 — 검증 ${verified_count} / ${fids.length}`, "Triage");
    } catch (e) {
        console.error("deep-dive 에러:", e);
        appendLog(`전문가 검증 오류: ${e}`, "Triage");
        _setTriageStatus('오류 발생', 'err');
    } finally {
        _toggleTriageRunning(false);
        saveFindings();
    }
}

async function stopTriage() {
    const sid = _currentSessionId();
    if (!sid) return;
    try {
        await fetch(`${API_BASE}/api/triage/stop`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sid })
        });
        appendLog("전문가 검증 중단 신호 전송", "Triage");
        _setTriageStatus('중단 요청 전송됨', 'err');
    } catch (e) {
        console.error("triage stop 실패:", e);
    }
}

async function dismissSelected() {
    const sid = _currentSessionId();
    if (!sid) return;
    await _ensureFindingIds();
    const fids = _collectSelectedFindingIds();
    if (fids.length === 0) return alert("오탐 처리할 항목을 선택해 주세요.");

    const reason = prompt(`선택된 ${fids.length}건을 오탐으로 표시합니다. 사유(선택):`, "");
    if (reason === null) return;

    try {
        const res = await fetch(`${API_BASE}/api/triage/dismiss`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ session_id: sid, finding_ids: fids, reason: reason || "" })
        });
        const data = await res.json();
        if (data.status === 'success') {
            fids.forEach(fid => _applyTriagePatch(fid, {
                triage_status: 'dismissed',
                verified: false,
                dismiss_reason: reason || ''
            }));
            appendLog(`오탐 처리 완료: ${data.dismissed}건`, "Triage");
        } else {
            alert("오탐 처리 실패: " + (data.message || ''));
        }
    } catch (e) {
        console.error("dismiss 실패:", e);
        alert("오탐 처리 중 오류가 발생했습니다.");
    }
}
