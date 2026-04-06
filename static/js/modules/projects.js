/**
 * projects.js - 프로젝트 목록/카드/CRUD/세션 선택 모듈
 */

let globalStats = { totalProjects: 0, totalVulns: 0, doneProjects: 0 };
let globalSessions = [];
let globalPrecheckSessions = [];
let currentProject = { id: null, name: '프로젝트 미선택', target: '' };

function syncDashboardStats() {
    const el = (id) => document.getElementById(id);
    if (el('dashTotalProjects')) el('dashTotalProjects').innerText = globalStats.totalProjects;
    if (el('dashTotalVulns'))    el('dashTotalVulns').innerText    = globalStats.totalVulns;
    if (el('dashDoneProjects'))  el('dashDoneProjects').innerText  = globalStats.doneProjects;
}

function renderDashRecentProjects(sessions) {
    const container = document.getElementById('dashRecentProjects');
    if (!container) return;
    const recent = sessions.slice(0, 3);
    if (!recent.length) {
        container.innerHTML = '<div class="col-12 text-muted small" style="opacity:0.5;">생성된 프로젝트가 없습니다.</div>';
        return;
    }
    container.innerHTML = recent.map(s => {
        const parts = s.split('_');
        const name = parts[0] || s;
        let dateStr = '';
        if (parts.length >= 3) {
            const d = parts[parts.length - 2];
            const t = parts[parts.length - 1];
            if (d.length === 8 && t.length === 6)
                dateStr = `${d.substring(0,4)}-${d.substring(4,6)}-${d.substring(6,8)} ${t.substring(0,2)}:${t.substring(2,4)}`;
        }
        return `
            <div class="col-md-4">
                <div class="glass-card py-2 px-3" style="cursor:pointer; border-radius:10px; transition:all 0.18s;"
                     onclick="selectProject('${s}')"
                     onmouseover="this.style.borderColor='var(--primary)'; this.style.transform='translateY(-2px)';"
                     onmouseout="this.style.borderColor=''; this.style.transform='';">
                    <div class="d-flex align-items-center gap-2 mb-1">
                        <i class="fa-solid fa-folder-open text-warning" style="font-size:0.9rem;"></i>
                        <span class="fw-bold text-truncate" style="font-size:0.9rem;" id="dash-title-${s}">${name}</span>
                    </div>
                    <div class="small text-muted text-truncate" style="font-size:0.75rem;">
                        <i class="fa-solid fa-clock me-1" style="font-size:0.7rem;"></i>${dateStr || 'N/A'}
                    </div>
                </div>
            </div>`;
    }).join('');

    recent.forEach(s => {
        fetch(`${API_BASE}/api/history/${s}/json/project_info`).then(r => r.json()).then(d => {
            if (d.status === 'success') {
                const info = JSON.parse(d.content);
                const el = document.getElementById(`dash-title-${s}`);
                if (el && info.project_name) el.innerText = info.project_name;
            }
        }).catch(() => {});
    });
}

function renderProjectGrid(sessions, targetGridId = 'projectsGrid', projType = 'scan') {
    const grid = document.getElementById(targetGridId);
    if (!grid) return;
    if (!sessions || sessions.length === 0) {
        grid.innerHTML = '<div class="col-12"><div class="empty-state">생성된 보안 스캔 프로젝트가 없습니다.</div></div>';
        return;
    }
    grid.innerHTML = '';

    const sortSelectId = projType === 'scan' ? 'sortProjects' : 'sortPrecheckProjects';
    const sortVal = document.getElementById(sortSelectId) ? document.getElementById(sortSelectId).value : 'date_desc';

    let sessionObjs = sessions.map(s => {
        const parts = s.split('_');
        const name = parts[0] || s;
        let date = new Date(0);
        if (parts.length >= 3) {
            const d = parts[parts.length - 2];
            const t = parts[parts.length - 1];
            if (d.length === 8 && t.length === 6) {
                const fDate = `${d.substring(0, 4)}-${d.substring(4, 6)}-${d.substring(6, 8)}T${t.substring(0, 2)}:${t.substring(2, 4)}:${t.substring(4, 6)}`;
                date = new Date(fDate);
            }
        }
        return { id: s, name: name.toLowerCase(), date: date };
    });

    if (sortVal === 'name_asc') sessionObjs.sort((a, b) => a.name.localeCompare(b.name));
    else if (sortVal === 'name_desc') sessionObjs.sort((a, b) => b.name.localeCompare(a.name));
    else if (sortVal === 'date_asc') sessionObjs.sort((a, b) => a.date - b.date);
    else sessionObjs.sort((a, b) => b.date - a.date);

    const sortedSessions = sessionObjs.map(o => o.id);

    if (projType === 'scan') {
        globalStats = { totalProjects: sortedSessions.length, totalVulns: 0, doneProjects: 0 };
        document.getElementById('globalTotalProjects').innerText = globalStats.totalProjects;
    }

    let htmlStr = "";
    sortedSessions.forEach(s => {
        const parts = s.split('_');
        const defaultTitle = parts[0] || s;
        let dateStr = "날짜 미상";
        if (parts.length >= 3) {
            const d = parts[parts.length - 2];
            const t = parts[parts.length - 1];
            if (d.length === 8 && t.length === 6) {
                dateStr = `${d.substring(0, 4)}-${d.substring(4, 6)}-${d.substring(6, 8)} ${t.substring(0, 2)}:${t.substring(2, 4)}`;
            }
        }

        htmlStr += `
                    <div class="col-md-4 project-card-item" data-session="${s}" data-title="${defaultTitle.toLowerCase()}">
                        <div class="glass-card h-100 py-2 px-3 shadow-hover" style="cursor: pointer; transition: all 0.2s ease-in-out; border: 1px solid rgba(255,255,255,0.05); border-radius: 12px; position: relative; background: rgba(255,255,255,0.02);" 
                             onclick="selectProject('${s}')"
                             onmouseover="this.style.transform='translateY(-3px)'; this.style.borderColor='var(--primary)';"
                             onmouseout="this.style.transform='translateY(0)'; this.style.borderColor='rgba(255,255,255,0.05)';" id="card-${s}">
                            
                            <div class="d-flex justify-content-between align-items-center mb-1">
                                <div class="d-flex align-items-center gap-2">
                                    <input type="checkbox" class="project-checkbox" style="cursor:pointer;" value="${s}" onclick="event.stopPropagation()">
                                    <div class="badge bg-secondary-subtle text-muted" style="font-size: 0.75rem; letter-spacing: 0.5px; padding: 3px 6px; background: rgba(255,255,255,0.04) !important;">ID: ${s.substring(s.length - 6)}</div>
                                </div>
                                <div class="d-flex align-items-center gap-2" onclick="event.stopPropagation()">
                                    <button class="btn btn-link text-muted p-0" title="이름 변경" onclick="renameProject('${s}')" style="border:none; background:none; opacity: 0.6; font-size: 0.95rem;">
                                        <i class="fa-solid fa-pen-to-square"></i>
                                    </button>
                                    <button class="btn btn-link text-danger p-0" title="프로젝트 삭제" onclick="deleteProject('${s}')" style="border:none; background:none; opacity: 0.8; font-size: 0.95rem;">
                                        <i class="fa-solid fa-trash-can"></i>
                                    </button>
                                </div>
                            </div>

                            <div class="mb-2">
                                <h6 class="m-0 fw-bold text-truncate" style="color: var(--text-main); font-size: 1.15rem;" id="title-${s}">${defaultTitle}</h6>
                                <p class="small text-truncate m-0 mt-0.5" style="font-size: 0.85rem; color: #94a3b8 !important;" id="url-${s}">${defaultTitle}</p>
                            </div>

                            <!-- 📊 위험 지수 프로그레스 -->
                            <div class="mb-2">
                                <div class="d-flex justify-content-between align-items-center mb-0.5" style="font-size: 0.8rem;">
                                     <span class="text-muted">위험 지수</span>
                                     <span id="scoreText-${s}" style="font-weight:600; color: #a1a1aa; font-size: 0.8rem;">측정 중</span>
                                </div>
                                <div style="height: 4px; background: rgba(255,255,255,0.04); border-radius: 2px; overflow: hidden;">
                                     <div id="gaugeBar-${s}" style="width: 5%; height: 100%; border-radius: 2px; background: #64748b; transition: width 0.3s ease;"></div>
                                </div>
                            </div>

                            <!-- 📊 취약점 대형 스코어 그리드 -->
                            <div class="row g-1 mb-1">
                                <div class="col-4">
                                    <div class="text-center py-1" style="background: rgba(239, 68, 68, 0.04); border: 1px solid rgba(239, 68, 68, 0.1); border-radius: 6px;">
                                        <div style="font-size: 0.75rem; color: #ef4444;">치명</div>
                                        <div style="font-size: 1.25rem; font-weight: 800; color: #ef4444;" id="highCount-${s}">0</div>
                                    </div>
                                </div>
                                <div class="col-4">
                                    <div class="text-center py-1" style="background: rgba(234, 179, 8, 0.04); border: 1px solid rgba(234, 179, 8, 0.1); border-radius: 6px;">
                                        <div style="font-size: 0.75rem; color: #eab308;">높음</div>
                                        <div style="font-size: 1.25rem; font-weight: 800; color: #eab308;" id="medCount-${s}">0</div>
                                    </div>
                                </div>
                                <div class="col-4">
                                    <div class="text-center py-1" style="background: rgba(59, 130, 246, 0.04); border: 1px solid rgba(59, 130, 246, 0.1); border-radius: 6px;">
                                        <div style="font-size: 0.75rem; color: #3b82f6;">기타</div>
                                        <div style="font-size: 1.25rem; font-weight: 800; color: #3b82f6;" id="lowCount-${s}">0</div>
                                    </div>
                                </div>
                            </div>

                            <div class="d-flex align-items-center justify-content-between mt-2 pt-1" style="border-top: 1px solid rgba(255,255,255,0.03);">
                                <span class="small text-muted" style="font-size: 0.78rem; color: #94a3b8 !important;"><i class="fa-solid fa-clock me-1" style="font-size: 0.75rem;"></i>${dateStr}</span>
                                <div id="statusBadge-${s}"><span class="badge bg-warning text-dark" style="font-size: 0.75rem; padding: 2px 4px; border-radius: 4px;">가동 중</span></div>
                            </div>
                        </div>
                    </div>
                `;
    });

    grid.innerHTML = htmlStr;

    sessions.forEach(s => {
        (async () => {
            try {
                let high = 0, med = 0, low = 0;
                let savedStatus = null;

                const resI = await fetch(`${API_BASE}/api/history/${s}/json/project_info`);
                const iData = await resI.json();
                if (iData.status === "success" && iData.content) {
                    const info = JSON.parse(iData.content);
                    const pName = info.project_name || s;
                    const pTarget = info.target || '';
                    if (info.status) savedStatus = info.status;
                    const titleEl = document.getElementById(`title-${s}`);
                    const urlEl = document.getElementById(`url-${s}`);
                    if (titleEl) titleEl.innerText = pName;
                    if (urlEl && pTarget) urlEl.innerText = pTarget;
                    const card = document.querySelector(`[data-session="${s}"]`);
                    if (card) card.setAttribute('data-title', pName.toLowerCase() + " " + pTarget.toLowerCase());
                }

                const resF = await fetch(`${API_BASE}/api/history/${s}/json/ai_findings`);
                const fData = await resF.json();
                if (fData.status === "success" && fData.content) {
                    const findings = JSON.parse(fData.content);
                    findings.forEach(v => {
                        const score = v.confidence || 50;
                        if (score >= 80) high++;
                        else if (score >= 40) med++;
                        else low++;
                    });
                    globalStats.totalVulns += (high + med + low);
                    const gVulns = document.getElementById('globalTotalVulns');
                    if (gVulns) gVulns.innerText = globalStats.totalVulns;
                    syncDashboardStats();
                }

                let autoStatus = "running";
                const resL = await fetch(`${API_BASE}/api/history/${s}/logs`);
                const lData = await resL.json();
                if (lData.status === "success" && lData.logs) {
                    const logText = lData.logs.map(l => l.message || '').join("\n");
                    if (logText.includes("태스크 완료") || logText.includes("Scan Complete") || logText.includes("scan_complete") || logText.includes("작업 완료")) {
                        autoStatus = "done";
                        globalStats.doneProjects++;
                        const gDone = document.getElementById('globalDoneProjects');
                        if (gDone) gDone.innerText = globalStats.doneProjects;
                        syncDashboardStats();
                    }
                }

                const currentStatus = savedStatus || autoStatus;

                if (savedStatus === "done" && autoStatus !== "done") {
                    globalStats.doneProjects++;
                    const gDone = document.getElementById('globalDoneProjects');
                    if (gDone) gDone.innerText = globalStats.doneProjects;
                    syncDashboardStats();
                }

                const statusStyles = {
                    "running": { bg: "rgba(234, 179, 8, 0.1)", text: "#eab308", border: "rgba(234, 179, 8, 0.3)", label: "가동 중", icon: "fa-bolt-lightning" },
                    "done": { bg: "rgba(16, 185, 129, 0.1)", text: "#10b981", border: "rgba(16, 185, 129, 0.3)", label: "점검완료", icon: "fa-check" },
                    "stopped": { bg: "rgba(239, 68, 68, 0.1)", text: "#ef4444", border: "rgba(239, 68, 68, 0.3)", label: "중지됨", icon: "fa-stop" }
                };
                const sConf = statusStyles[currentStatus] || statusStyles["running"];

                const selectHtml = `
                            <div class="dropup" onclick="event.stopPropagation()">
                                <button class="btn btn-xs d-flex align-items-center gap-1" type="button" data-bs-toggle="dropdown" aria-expanded="false" style="font-size: 0.72rem; padding: 2px 6px; border-radius: 6px; background: ${sConf.bg} !important; color: ${sConf.text} !important; border: 1px solid ${sConf.border} !important; font-weight: 500;" id="statusBtn-${s}">
                                    <i class="fa-solid ${sConf.icon}" style="font-size: 0.65rem;"></i>
                                    <span>${sConf.label}</span>
                                    <i class="fa-solid fa-angle-down ms-1" style="font-size: 0.6rem; opacity: 0.6;"></i>
                                </button>
                                <ul class="dropdown-menu dropdown-menu-end shadow-sm" style="background: rgba(30,30,40,0.95); backdrop-filter: blur(8px); border: 1px solid rgba(255,255,255,0.05); border-radius: 8px; font-size: 0.75rem; min-width: 100px; padding: 4px;">
                                    <li><a class="dropdown-item d-flex align-items-center gap-2 py-1" style="color: #eab308 !important; border-radius: 4px;" href="#" onclick="updateProjectStatus('${s}', 'running')"><i class="fa-solid fa-bolt-lightning" style="width: 12px;"></i> 가동 중</a></li>
                                    <li><a class="dropdown-item d-flex align-items-center gap-2 py-1" style="color: #10b981 !important; border-radius: 4px;" href="#" onclick="updateProjectStatus('${s}', 'done')"><i class="fa-solid fa-check" style="width: 12px;"></i> 점검완료</a></li>
                                    <li><a class="dropdown-item d-flex align-items-center gap-2 py-1" style="color: #ef4444 !important; border-radius: 4px;" href="#" onclick="updateProjectStatus('${s}', 'stopped')"><i class="fa-solid fa-stop" style="width: 12px;"></i> 중지됨</a></li>
                                </ul>
                            </div>
                        `;

                const badgeEl = document.getElementById(`statusBadge-${s}`);
                if (badgeEl) badgeEl.innerHTML = selectHtml;

                const countH = document.getElementById(`highCount-${s}`);
                const countM = document.getElementById(`medCount-${s}`);
                const countL = document.getElementById(`lowCount-${s}`);
                if (countH) countH.innerText = high;
                if (countM) countM.innerText = med;
                if (countL) countL.innerText = low;

                const totalScore = high * 10 + med * 3 + low;
                const scoreEl = document.getElementById(`scoreText-${s}`);
                if (scoreEl) scoreEl.innerText = totalScore + " pts";

                const gaugeEl = document.getElementById(`gaugeBar-${s}`);
                if (gaugeEl) {
                    const percent = Math.min(Math.max(totalScore, 5), 100);
                    gaugeEl.style.width = percent + "%";
                    if (high > 0) gaugeEl.style.background = "#ef4444";
                    else if (med > 0) gaugeEl.style.background = "#eab308";
                    else gaugeEl.style.background = "#22c55e";
                }

                const sumEl = document.getElementById(`sum-${s}`);
                if (sumEl) {
                    sumEl.innerHTML = `
                                 <span class="badge" style="background: rgba(239, 68, 68, 0.08); color: #ef4444; font-size: 0.58rem; border: 1px solid rgba(239,68,68,0.15); border-radius: 4px; padding: 2px 4px;">C: ${high}</span>
                                 <span class="badge" style="background: rgba(234, 179, 8, 0.08); color: #eab308; font-size: 0.58rem; border: 1px solid rgba(234,179,8,0.15); border-radius: 4px; padding: 2px 4px;">H: ${med}</span>
                                 <span class="badge" style="background: rgba(59, 130, 246, 0.08); color: #3b82f6; font-size: 0.58rem; border: 1px solid rgba(59,130,246,0.15); border-radius: 4px; padding: 2px 4px;">M/L: ${low}</span>
                             `;
                }
            } catch (err) { console.error("Card Async load failed", s, err); }
        })();
    });
}

function filterProjects() {
    const query = document.getElementById('projectSearch').value.toLowerCase();
    document.querySelectorAll('.project-card-item').forEach(card => {
        const title = card.getAttribute('data-title') || '';
        card.style.display = title.includes(query) ? 'block' : 'none';
    });
}

async function deleteProject(sId) {
    if (!confirm(`이 프로젝트를 영구 삭제하시겠습니까?\nID: ${sId}`)) return;
    try {
        const res = await fetch(`${API_BASE}/api/history/${sId}`, { method: 'DELETE' });
        const data = await res.json();
        if (data.status === 'success') {
            alert("삭제 완료되었습니다.");
            loadHistoryList();
        } else {
            alert("삭제 실패: " + data.message);
        }
    } catch (e) { alert("에러 발생: " + e); }
}

async function deleteSelectedProjects(pType = 'scan') {
    const gridId = pType === 'scan' ? 'projectsGrid' : 'precheckProjectsGrid';
    const checkboxes = document.querySelectorAll(`#${gridId} .project-checkbox:checked`);
    if (checkboxes.length === 0) return alert("삭제할 프로젝트를 선택해 주세요.");

    if (confirm(`선택한 ${checkboxes.length}개의 프로젝트를 영구 삭제하시겠습니까?\n모든 데이터가 소멸됩니다.`)) {
        let sCount = 0;
        for (const cb of checkboxes) {
            const sId = cb.value;
            try {
                const res = await fetch(`${API_BASE}/api/history/${sId}`, { method: 'DELETE' });
                const data = await res.json();
                if (data.status === 'success') sCount++;
            } catch (e) { console.error("프로젝트 다중 삭제 오류", sId, e); }
        }
        alert(`${sCount}개의 프로젝트가 일괄 삭제 완료되었습니다.`);
        loadHistoryList();
    }
}

async function renameProject(sId) {
    const titleEl = document.getElementById(`title-${sId}`);
    const currentName = titleEl ? titleEl.innerText : "";
    const newName = prompt("새로운 프로젝트 이름을 입력해 주세요:", currentName);
    if (!newName || newName.trim() === "" || newName === currentName) return;

    try {
        const res = await fetch(`${API_BASE}/api/history/${sId}/rename`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_name: newName })
        });
        const data = await res.json();
        if (data.status === 'success') {
            if (titleEl) titleEl.innerText = newName;
            const card = document.querySelector(`[data-session="${sId}"]`);
            if (card) {
                const targetText = document.getElementById(`target-${sId}`) ? document.getElementById(`target-${sId}`).innerText : '';
                card.setAttribute('data-title', newName.toLowerCase() + " " + targetText.toLowerCase());
            }
        } else {
            alert("이름 변경 실패: " + data.message);
        }
    } catch (e) { alert("에러 발생: " + e); }
}

async function updateProjectStatus(sId, newStatus) {
    try {
        const res = await fetch(`${API_BASE}/api/history/${sId}/status`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ status: newStatus })
        });
        const data = await res.json();
        if (data.status === 'success') {
            const btn = document.getElementById(`statusBtn-${sId}`);
            if (btn) {
                const statusStyles = {
                    "running": { bg: "rgba(234, 179, 8, 0.1)", text: "#eab308", border: "rgba(234, 179, 8, 0.3)", label: "가동 중", icon: "fa-bolt-lightning" },
                    "done": { bg: "rgba(16, 185, 129, 0.1)", text: "#10b981", border: "rgba(16, 185, 129, 0.3)", label: "점검완료", icon: "fa-check" },
                    "stopped": { bg: "rgba(239, 68, 68, 0.1)", text: "#ef4444", border: "rgba(239, 68, 68, 0.3)", label: "중지됨", icon: "fa-stop" }
                };
                const c = statusStyles[newStatus] || statusStyles["running"];
                btn.style.setProperty('background', c.bg, 'important');
                btn.style.setProperty('color', c.text, 'important');
                btn.style.setProperty('border-color', c.border, 'important');
                btn.innerHTML = `<i class="fa-solid ${c.icon}" style="font-size: 0.65rem;"></i><span>${c.label}</span><i class="fa-solid fa-angle-down ms-1" style="font-size: 0.6rem; opacity: 0.6;"></i>`;
            }
        } else {
            alert("상태 변경 실패: " + data.message);
        }
    } catch (e) { alert("상태 변경 에러: " + e); }
}

function exitProjectMode(targetSec = 'section-projects') {
    localStorage.removeItem('currentSessionId');
    currentProject = { id: null, name: '프로젝트 미선택', target: '' };

    const subScan = document.getElementById('sub-scan');
    const subPrecheck = document.getElementById('sub-precheck');
    if (subScan) subScan.style.display = 'none';
    if (subPrecheck) subPrecheck.style.display = 'none';
    const topbarScanControls = document.getElementById('topbarScanControls');
    if (topbarScanControls) topbarScanControls.style.display = 'none';

    const breadcrumbText = document.getElementById('breadcrumbText');
    if (breadcrumbText) {
        breadcrumbText.innerHTML = '<i class="fa-solid fa-folder-tree text-warning me-1"></i> 모든 프로젝트 허브';
    }

    if (typeof loadHistoryList === 'function') loadHistoryList(targetSec !== 'section-projects');
    switchSection(targetSec);
}

function sortAndRenderProjects(type) {
    if (type === 'scan') {
        renderProjectGrid(globalSessions, 'projectsGrid', 'scan');
    } else {
        renderProjectGrid(globalPrecheckSessions, 'precheckProjectsGrid', 'precheck');
    }
}

async function loadHistoryList(skipSwitch = false) {
    try {
        const res = await fetch(`${API_BASE}/api/history/list`);
        const data = await res.json();

        if (data.status === "success") {
            if (data.sessions) {
                globalSessions = data.sessions;
                renderProjectGrid(data.sessions, 'projectsGrid', 'scan');
                renderDashRecentProjects(data.sessions);
            }
            if (data.precheck_sessions) {
                globalPrecheckSessions = data.precheck_sessions;
                renderProjectGrid(data.precheck_sessions, 'precheckProjectsGrid', 'precheck');
            }
            syncDashboardStats();

            const savedSession = localStorage.getItem('currentSessionId');
            const target = window.initialTargetSec || null;
            window.initialTargetSec = null; // 메모리 해제하여 잔존 방지

            if (savedSession && ((data.sessions && data.sessions.includes(savedSession)) || (globalPrecheckSessions.includes(savedSession)))) {
                setTimeout(() => {
                    if (typeof selectProject === 'function') {
                        selectProject(savedSession, target);
                    }
                }, 300);
            }
        }
    } catch (e) { console.error("History Error", e); }
}

async function startNewScanWizard() {
    const name = document.getElementById('newProjectName').value;
    if (!name) return alert("프로젝트 명칭을 입력해 주세요.");
    const target = "http://172.27.50.37:8002";

    try {
        const res = await fetch(`${API_BASE}/api/project/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ project_name: name, target_url: target })
        });
        const data = await res.json();

        if (data.status === 'success' && data.session_id) {
            appendLog(`프로젝트 '${name}'가 생성되었습니다. 대시보드로 진입합니다.`, "System");
            if (typeof loadHistoryList === 'function') await loadHistoryList();
            setTimeout(() => {
                if (typeof selectProject === 'function') selectProject(data.session_id);
            }, 300);
        } else {
            alert("프로젝트 생성 실패: " + (data.message || "알 수 없는 오류"));
        }
    } catch (e) {
        console.error("Create Project Error", e);
        alert("네트워크 오류가 발생했습니다.");
    }
}

async function selectProject(sId, targetSec = null) {
    currentProject.id = sId;
    localStorage.setItem('currentSessionId', sId);

    document.querySelectorAll('.project-nav-item').forEach(m => m.style.display = 'flex');
    const topbarScanControls = document.getElementById('topbarScanControls');
    if (topbarScanControls) topbarScanControls.style.display = 'flex';

    loadSession(sId);

    let pName = sId;
    let pTarget = "";
    try {
        const res = await fetch(`${API_BASE}/api/history/${sId}/json/project_info`);
        const data = await res.json();
        if (data.status === "success") {
            const info = JSON.parse(data.content);
            pName = info.project_name || sId;
            pTarget = info.target || "";
        }
    } catch (e) {
        console.warn("Project Info 조회 실패:", e);
    }

    const subScan = document.getElementById('sub-scan');
    const subPrecheck = document.getElementById('sub-precheck');
    const isPrecheck = typeof globalPrecheckSessions !== 'undefined' && globalPrecheckSessions.includes(sId);

    if (isPrecheck) {
        if (subScan) subScan.style.display = 'none';
        if (subPrecheck) subPrecheck.style.display = 'block';
    } else {
        if (subScan) subScan.style.display = 'block';
        if (subPrecheck) subPrecheck.style.display = 'none';
    }

    currentProject.name = pName;
    currentProject.target = pTarget;

    const targetInput = document.getElementById('targetUrl');
    if (targetInput) {
        targetInput.value = pTarget;
        targetInput.removeAttribute('readonly');
        targetInput.style.background = '';
        if (typeof syncFfufUrl === 'function') syncFfufUrl(pTarget);
    }

    const breadcrumbText = document.getElementById('breadcrumbText');
    if (breadcrumbText) {
        breadcrumbText.innerHTML = `<i class="fa-solid fa-folder-open text-warning me-1"></i> ${pName} <span class="text-muted small">(${pTarget})</span>`;
    }

    if (isPrecheck) {
        switchSection(targetSec || 'section-alive');

        (async () => {
            try {
                const hotA = initHandsontable('alive');
                const hotS = initHandsontable('shodan');

                const resA = await fetch(`${API_BASE}/api/history/${sId}/json/alive_check_results`);
                const aData = await resA.json();
                if (aData.status === "success" && aData.content && hotA) {
                    const saved = JSON.parse(aData.content);
                    hotA.loadData(saved.map((r, i) => [i + 1, r[0], r[1], r[2], r[3], `${r[4] || '-'} | ${r[5] || '-'}`]));
                    aliveCheckData = saved;
                } else if (hotA) {
                    hotA.loadData([]);
                }

                const resS = await fetch(`${API_BASE}/api/history/${sId}/json/shodan_results`);
                const sData = await resS.json();
                if (sData.status === "success" && sData.content && hotS) {
                    const saved = JSON.parse(sData.content);
                    hotS.loadData(saved.map((r, i) => [i + 1, r[1], r[8] || '-', r[6] || '-', r[7] || '-']));
                } else if (hotS) {
                    hotS.loadData([]);
                }
            } catch (e) {
                console.warn("Precheck results load failed", e);
            }
        })();
    } else {
        switchSection(targetSec || 'section-overview');
    }
}
