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

    console.log("renderCards called with:", cardsArray.length, "items");

    if (!Array.isArray(cardsArray) || cardsArray.length === 0) {
        tbody.innerHTML = '<tr><td colspan="9" class="empty-state">현재 시그니처와 일치하는 위협이 탐지되지 않았습니다.</td></tr>';
        ['statCritical', 'statHigh', 'statMedLow'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = 0;
        });
        return;
    }

    cardsArray.forEach((card, index) => {
        if (index === 0) {
            console.log("First card data:", {
                title: card.title,
                ttp: card.ttp,
                owasp: card.owasp,
                severity: card.severity,
                confidence: card.confidence
            });
        }
        
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
        const safeTarget = (card.target || '').replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const confScore = card.confidence || 0;
        let confClass = "bg-secondary";
        if (confScore >= 90) confClass = "bg-danger";
        else if (confScore >= 70) confClass = "bg-warning text-dark";

        const safeTtp = (card.ttp || '—').replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const safeOwasp = (card.owasp || '—').replace(/</g, "&lt;").replace(/>/g, "&gt;");

        tr.innerHTML = `
            <td class="text-center" onclick="event.stopPropagation()">
                <input type="checkbox" class="vuln-checkbox" style="cursor:pointer;" value="${index}">
            </td>
            <td class="text-center text-muted" style="font-size:0.8rem;">${index + 1}</td>
            <td><span class="sev-pill ${sevClass}">${sev}</span></td>
            <td><span class="pill ${confClass}" style="min-width:35px;text-align:center;">${confScore}</span></td>
            <td class="fw-bold" style="color:var(--text-main);">${safeTitle}${verifiedBadge}</td>
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
            <hr class="border-secondary opacity-25">
            <div class="mb-3">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Technical Summary</div>
                <div style="font-size:0.9rem;line-height:1.6;">${typeof marked !== 'undefined' ? marked.parse(card.description || 'N/A') : (card.description || 'N/A')}</div>
            </div>
            <div class="mb-3">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">Reproduction Evidence</div>
                <pre class="p-2 rounded font-mono" style="font-size:0.75rem;border:1px solid var(--border-color);max-height:200px;overflow:auto;background:var(--bg-hover);color:var(--text-main);">${esc(card.evidence) || 'N/A'}</pre>
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
        
        html = `
            <div class="mb-3" style="border-bottom:1px solid var(--border-color);display:flex;gap:12px;">
                <button class="tab-btn active" onclick="switchVulnTab(this, ${index}, 'details')" style="background:none;border:none;color:var(--text-main);padding:12px 16px;cursor:pointer;border-bottom:2px solid var(--primary);font-size:0.9rem;font-weight:600;">
                    <i class="fa-solid fa-list me-2"></i>상세정보
                </button>
                <button class="tab-btn" onclick="switchVulnTab(this, ${index}, 'json')" style="background:none;border:none;color:var(--text-muted);padding:12px 16px;cursor:pointer;border-bottom:2px solid transparent;font-size:0.9rem;font-weight:600;">
                    <i class="fa-solid fa-code me-2"></i>JSON
                </button>
            </div>
            
            <div id="vulnTab_details_${index}" class="tab-content" style="display:block;">
                ${detailsTabContent}
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
    const jsonTab = document.getElementById(`vulnTab_json_${cardIndex}`);
    
    if (detailsTab) detailsTab.style.display = 'none';
    if (jsonTab) jsonTab.style.display = 'none';
    
    // 선택된 탭 표시
    if (tabType === 'details' && detailsTab) {
        detailsTab.style.display = 'block';
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
