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
        tbody.innerHTML = '<tr><td colspan="7" class="empty-state">현재 시그니처와 일치하는 위협이 탐지되지 않았습니다.</td></tr>';
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
        const safeTarget = (card.target || '').replace(/</g, "&lt;").replace(/>/g, "&gt;");
        const confScore = card.confidence || 0;
        let confClass = "bg-secondary";
        if (confScore >= 90) confClass = "bg-danger";
        else if (confScore >= 70) confClass = "bg-warning text-dark";

        tr.innerHTML = `
            <td class="text-center" onclick="event.stopPropagation()">
                <input type="checkbox" class="vuln-checkbox" style="cursor:pointer;" value="${index}">
            </td>
            <td class="text-center text-muted" style="font-size:0.8rem;">${index + 1}</td>
            <td><span class="sev-pill ${sevClass}">${sev}</span></td>
            <td><span class="pill ${confClass}" style="min-width:35px;text-align:center;">${confScore}</span></td>
            <td class="fw-bold" style="color:var(--text-main);">${safeTitle}${verifiedBadge}</td>
            <td class="text-muted font-mono" style="font-size:0.8rem;word-break:break-all;">${safeTarget}</td>
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
        ['title', 'severity', 'cwe', 'target', 'description', 'evidence', 'steps', 'recommendation'].forEach(field => {
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
        html = `
            <div class="mb-3 p-3 rounded" style="background:var(--bg-hover);border:1px solid var(--border-color);">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">위험도 &amp; 신뢰도</div>
                <div class="fw-bold"><span class="sev-pill sev-${sev.toLowerCase()}">${sev}</span>
                    <span class="ms-2" style="color:var(--text-main);">Confidence: ${card.confidence || 0}</span></div>
            </div>
            <div class="mb-3 p-3 rounded" style="background:var(--bg-hover);border:1px solid var(--border-color);">
                <div class="text-muted text-uppercase mb-1" style="font-size:0.7rem;">CWE ID</div>
                <div class="text-warning fw-bold">${card.cwe || 'CWE-Unknown'}</div>
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
    }

    if (!editMode) {
        if (typeof openDrawer === 'function') openDrawer(card.title || '취약점 상세 정보', html);
    } else {
        document.getElementById('drawerBody').innerHTML = html;
    }
    if (drawEditBtn) drawEditBtn.style.display = 'inline-block';
}
