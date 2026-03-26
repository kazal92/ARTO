/**
 * settings.js - ARTO 설정 관리 모듈
 * AI 설정, 프록시 설정, 테마 관련 로직
 */

// ── AI 설정 토글 ────────────────────────────────────────

function toggleAiSettings() {
    const aiType = document.getElementById('aiType')?.value;
    
    // 1. 모든 컨테이너 숨기기
    const containers = ['aiUrlContainer', 'geminiKeyContainer', 'lmstudioKeyContainer', 'vertexKeyContainer'];
    containers.forEach(id => {
        const el = document.getElementById(id);
        if (el) el.style.display = 'none';
    });

    // 2. 모델 선택 UI 초기화 (input vs select)
    const modelInput = document.getElementById('aiModel');
    const modelSelect = document.getElementById('aiModelSelect');
    const modelLmSelect = document.getElementById('aiModelLmSelect');
    const btnFetch = document.getElementById('btnFetchModels');

    if (modelInput) modelInput.style.display = 'none';
    if (modelSelect) modelSelect.style.display = 'none';
    if (modelLmSelect) modelLmSelect.style.display = 'none';
    if (btnFetch) btnFetch.style.display = 'none';

    // 3. 엔진별 가시성 설정
    if (aiType === 'gemini') {
        const urlCont = document.getElementById('aiUrlContainer');
        const keyCont = document.getElementById('geminiKeyContainer');
        if (urlCont) urlCont.style.display = '';
        if (keyCont) keyCont.style.display = '';
        if (modelSelect) modelSelect.style.display = '';
    } else if (aiType === 'lmstudio') {
        const urlCont = document.getElementById('aiUrlContainer');
        const keyCont = document.getElementById('lmstudioKeyContainer');
        if (urlCont) urlCont.style.display = '';
        if (keyCont) keyCont.style.display = '';
        if (modelInput) modelInput.style.display = '';
        if (btnFetch) btnFetch.style.display = '';
        // LM Studio 모델 목록이 있으면 드롭다운도 표시
        if (modelLmSelect && modelLmSelect.options.length > 0) modelLmSelect.style.display = '';
    } else if (aiType === 'vertex') {
        const urlCont = document.getElementById('aiUrlContainer');
        const keyCont = document.getElementById('vertexKeyContainer');
        if (urlCont) urlCont.style.display = '';
        if (keyCont) keyCont.style.display = '';
        if (modelInput) modelInput.style.display = '';
    }
}

function saveSettings() {
    localStorage.setItem('aiType', document.getElementById('aiType').value);
    localStorage.setItem('geminiApiKey', document.getElementById('geminiApiKey').value);
    localStorage.setItem('lmstudioApiKey', document.getElementById('lmstudioApiKey').value || '');
    localStorage.setItem('vertexApiKey', document.getElementById('vertexApiKey').value || '');
    localStorage.setItem('aiUrl', document.getElementById('aiUrl').value);
    localStorage.setItem('aiModel', document.getElementById('aiModel').value);
    localStorage.setItem('customHeaders', document.getElementById('customHeaders').value);
}

function loadSettings() {
    const savedTheme = localStorage.getItem('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
    if (typeof updateThemeUI === 'function') updateThemeUI(savedTheme);

    const aiType = localStorage.getItem('aiType') || 'lmstudio';
    const aiUrl = localStorage.getItem('aiUrl') || 'http://192.168.1.100:1234/v1';
    const aiModel = localStorage.getItem('aiModel') || 'qwen/qwen3.5-9b';

    const set = (id, val) => { if (document.getElementById(id)) document.getElementById(id).value = val; };
    set('aiType', aiType);
    set('geminiApiKey', localStorage.getItem('geminiApiKey') || '');
    set('lmstudioApiKey', localStorage.getItem('lmstudioApiKey') || '');
    set('vertexApiKey', localStorage.getItem('vertexApiKey') || '');
    set('aiUrl', aiUrl);
    set('aiModel', aiModel);
    set('customHeaders', localStorage.getItem('customHeaders') || '');

    if (document.getElementById('proxyEnabled')) {
        document.getElementById('proxyEnabled').checked = localStorage.getItem('proxyEnabled') === 'true';
        document.getElementById('proxyHost').value = localStorage.getItem('proxyHost') || '192.168.0.15';
        document.getElementById('proxyPort').value = localStorage.getItem('proxyPort') || '8080';
    }

    if (typeof toggleAiSettings === 'function') toggleAiSettings();
}

// ── 프록시 설정 ─────────────────────────────────────────

async function updateProxySettings() {
    const enabled = document.getElementById('proxyEnabled').checked;
    const host = document.getElementById('proxyHost').value;
    const port = parseInt(document.getElementById('proxyPort').value);

    localStorage.setItem('proxyEnabled', enabled);
    localStorage.setItem('proxyHost', host);
    localStorage.setItem('proxyPort', port);

    try {
        const res = await fetch(`${API_BASE}/api/proxy`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ proxy_host: host, proxy_port: port, enabled })
        });
        const data = await res.json();
        if (data.status === 'success') {
            if (typeof appendLog === 'function') appendLog(data.message, "System");
            alert(data.message);
        } else {
            alert("Error: " + data.message);
        }
    } catch (e) {
        console.error(e);
    }
}

async function toggleProxy() {
    localStorage.setItem('proxyEnabled', document.getElementById('proxyEnabled').checked);
}

async function clearZapHistory() {
    if (!confirm("ZAP의 모든 히스토리와 사이트 트리를 초기화하시겠습니까? (복구 불가능)")) return;
    try {
        const res = await fetch(`${API_BASE}/api/zap/clear`, { method: 'POST' });
        const data = await res.json();
        if (data.status === 'success') {
            if (typeof appendLog === 'function') appendLog(data.message, "System");
            alert(data.message);
        } else {
            alert("Error: " + data.message);
        }
    } catch (e) {
        console.error(e);
    }
}

// ── LM Studio 모델 가져오기 ──────────────────────────────

async function fetchLmStudioModels(isAuto = false) {
    const baseUrl = document.getElementById('aiUrl')?.value?.trim();
    if (!baseUrl) { if (!isAuto) alert("AI URL을 입력하세요."); return; }

    try {
        const res = await fetch(`${baseUrl}/models`, { signal: AbortSignal.timeout(3000) });
        const data = await res.json();
        const models = data.data || [];

        const select = document.getElementById('aiModel');
        if (!select) return;

        // 현재 저장된 모델
        const saved = localStorage.getItem('aiModel') || '';
        const currentVal = select.value;

        // 기존 options 초기화 후 새로 추가
        select.innerHTML = '';
        models.forEach(m => {
            const opt = document.createElement('option');
            opt.value = m.id;
            opt.textContent = m.id;
            if (m.id === saved || m.id === currentVal) opt.selected = true;
            select.appendChild(opt);
        });

        if (!isAuto) alert(`${models.length}개의 모델을 가져왔습니다.`);
    } catch (e) {
        if (!isAuto) alert("모델 목록 가져오기 실패: " + e.message);
    }
}
