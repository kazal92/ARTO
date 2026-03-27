/**
 * settings.js - ARTO 설정 관리 모듈
 * AI 설정, 프록시 설정, 테마 관련 로직
 */

// ── AI 설정 토글 ────────────────────────────────────────

function toggleAiSettings(shouldUpdateUrl = false) {
    const aiType = document.getElementById('aiType')?.value;
    const aiUrlInput = document.getElementById('aiUrl');
    const aiModelInput = document.getElementById('aiModel');

    // 엔진 선택 시 URL과 모델 즉시 변경 (사용자 인터랙션 발생 시에만)
    if (shouldUpdateUrl) {
        if (aiType === 'gemini') {
            if (aiUrlInput) aiUrlInput.value = 'https://generativelanguage.googleapis.com/v1beta/openai/';
            if (aiModelInput) aiModelInput.value = 'gemini-2.0-flash';
        } else if (aiType === 'lmstudio') {
            if (aiUrlInput) aiUrlInput.value = 'http://192.168.1.100:1234/v1';
            if (aiModelInput) aiModelInput.value = 'qwen/qwen3.5-9b';
        } else if (aiType === 'vertex') {
            if (aiUrlInput) aiUrlInput.value = 'https://us-central1-aiplatform.googleapis.com/v1';
            if (aiModelInput) aiModelInput.value = 'gemini-2.0-flash';
        }
    }

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
        fetchGeminiModels();
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

    // AI 타입에 따라 기본 모델 결정
    let aiModel = localStorage.getItem('aiModel');
    if (!aiModel) {
        if (aiType === 'gemini') {
            aiModel = 'gemini-2.0-flash';
        } else if (aiType === 'vertex') {
            aiModel = 'gemini-2.0-flash';
        } else {
            aiModel = 'qwen/qwen3.5-9b';
        }
    }

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
        const sessionId = (typeof currentProject !== 'undefined' && currentProject?.id)
            || localStorage.getItem('currentSessionId') || '';
        const res = await fetch(`${API_BASE}/api/zap/clear`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });
        const data = await res.json();
        if (data.status === 'success') {
            if (typeof appendLog === 'function') appendLog(data.message, "System");
            if (typeof allEndpoints !== 'undefined') allEndpoints = [];
            if (typeof renderEndpoints === 'function') renderEndpoints([]);
            alert(data.message);
        } else {
            alert("Error: " + data.message);
        }
    } catch (e) {
        console.error(e);
    }
}

// ── Gemini 모델 목록 가져오기 ────────────────────────────

async function fetchGeminiModels() {
    const apiKey = document.getElementById('geminiApiKey')?.value?.trim();
    const modelSelect = document.getElementById('aiModelSelect');
    if (!modelSelect) return;

    if (!apiKey) {
        modelSelect.innerHTML = '<option value="" disabled selected>올바른 API Key를 입력해주세요</option>';
        const aiModel = document.getElementById('aiModel');
        if (aiModel) aiModel.value = '';
        return;
    }

    modelSelect.innerHTML = '<option value="" disabled selected>모델 목록 로딩 중...</option>';

    try {
        const res = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`,
            { signal: AbortSignal.timeout(5000) }
        );
        const data = await res.json();

        if (data.error || !data.models) {
            modelSelect.innerHTML = '<option value="" disabled selected>올바른 API Key를 입력해주세요</option>';
            return;
        }

        const generateModels = data.models
            .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
            .map(m => m.name.replace('models/', ''));

        if (generateModels.length === 0) {
            modelSelect.innerHTML = '<option value="" disabled selected>사용 가능한 모델이 없습니다</option>';
            return;
        }

        const prev = modelSelect.value;
        modelSelect.innerHTML = generateModels
            .map(m => `<option value="${m}"${m === prev ? ' selected' : ''}>${m}</option>`)
            .join('');

        const aiModel = document.getElementById('aiModel');
        if (aiModel) aiModel.value = modelSelect.value;
    } catch (e) {
        modelSelect.innerHTML = '<option value="" disabled selected>올바른 API Key를 입력해주세요</option>';
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
