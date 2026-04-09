/**
 * playwright_agent.js - Playwright 브라우저 에이전트 UI 모듈
 * 실제 브라우저 스크린샷 + 에이전트 로그를 실시간으로 표시
 */

let pwRunning = false;
let pwFindingCount = 0;
let _pwStreamEl = null;
let _pwThinkingEl = null;

// ── 초기화 ────────────────────────────────────────────────

function initPlaywrightAgent() {
    const target = currentProject?.target || '';
    const el = document.getElementById('pwTargetInput');
    if (el && target) el.value = target;
    _pwUpdateStatus('idle');
}

// ── 에이전트 시작 ─────────────────────────────────────────

async function startPlaywrightAgent() {
    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId) {
        _pwAppend('system', '세션이 선택되지 않았습니다. 프로젝트를 먼저 여세요.');
        return;
    }

    const target = document.getElementById('pwTargetInput')?.value?.trim();
    if (!target) {
        _pwAppend('system', '타겟 URL을 입력하세요.');
        return;
    }

    if (pwRunning) {
        _pwAppend('system', '이미 에이전트가 실행 중입니다.');
        return;
    }

    const aiConfig = _pwCollectAiConfig();
    if (!aiConfig) return;

    pwRunning = true;
    pwFindingCount = 0;
    _pwUpdateStatus('running');
    _pwUpdateBadge(0);
    _pwAppend('system', `🎭 Playwright 브라우저 에이전트 시작`);
    _pwAppend('system', `🤖 AI: ${aiConfig.type.toUpperCase()} / ${aiConfig.model}`);
    _pwAppend('system', `🎯 대상: ${target}`);

    // URL 바 업데이트
    const urlEl = document.getElementById('pwCurrentUrl');
    if (urlEl) urlEl.textContent = target;

    try {
        const response = await fetch(`${API_BASE}/api/playwright/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionId,
                target: target,
                ai_config: aiConfig,
                custom_headers: _pwCollectHeaders()
            })
        });

        if (!response.ok) {
            _pwAppend('system', `서버 오류: ${response.status}`);
            _pwUpdateStatus('idle');
            pwRunning = false;
            return;
        }

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            buffer += decoder.decode(value, { stream: true });
            const events = buffer.split(/\r?\n\r?\n/);
            buffer = events.pop();

            for (const ev of events) {
                if (!ev.startsWith('data: ')) continue;
                const raw = ev.slice(6).trim();
                if (!raw) continue;
                try {
                    const data = JSON.parse(raw);
                    _handlePwEvent(data);
                } catch (e) { }
            }
        }
    } catch (e) {
        if (pwRunning) _pwAppend('system', `연결 오류: ${e.message}`);
    } finally {
        pwRunning = false;
        _pwUpdateStatus('idle');
    }
}

// ── 에이전트 중단 ─────────────────────────────────────────

async function stopPlaywrightAgent() {
    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId || !pwRunning) return;
    try {
        await fetch(`${API_BASE}/api/playwright/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });
        _pwAppend('system', '중단 요청을 보냈습니다...');
    } catch (e) { console.error(e); }
}

// ── SSE 이벤트 처리 ───────────────────────────────────────

function _handlePwEvent(data) {
    switch (data.type) {
        case 'agent_start':
            break;

        case 'thinking_start':
            _pwThinkingEl = _pwAppendStreaming('thinking', '');
            _pwStreamEl = null;
            break;

        case 'thinking_chunk':
            if (_pwThinkingEl) {
                const el = _pwThinkingEl.querySelector('.agent-thinking-text');
                if (el) el.textContent += data.content;
                _pwScrollBottom();
            }
            break;

        case 'chunk':
            if (!_pwStreamEl) {
                _pwThinkingEl = null;
                _pwStreamEl = _pwAppendStreaming('assistant', '');
            }
            const textEl = _pwStreamEl?.querySelector('.agent-text');
            if (textEl) { textEl.textContent += data.content; _pwScrollBottom(); }
            break;

        case 'tool_call':
            _pwStreamEl = null;
            _pwThinkingEl = null;
            const actionLabel = _pwActionLabel(data.tool_name);
            const inputPreview = (data.tool_input?.input || '').trim().substring(0, 150);
            _pwAppend('tool_call', `${actionLabel}\n${inputPreview}`);
            break;

        case 'tool_result':
            _pwAppend('tool_result', data.result || '');
            break;

        case 'playwright_screenshot':
            // 스크린샷 업데이트
            _pwUpdateScreenshot(data.data);
            break;

        case 'log':
            _pwAppend('system', data.message);
            break;

        case 'ai_card':
            pwFindingCount++;
            _pwUpdateBadge(pwFindingCount);
            _pwAppend('finding', `🚨 취약점 발견: ${data.data?.title || '?'} [${data.data?.severity || '?'}]`);
            if (typeof aiCardsData !== 'undefined' && typeof renderCards === 'function') {
                aiCardsData.push(data.data);
                renderCards(aiCardsData);
                if (typeof saveFindings === 'function') saveFindings();
            }
            _pwStreamEl = null;
            break;

        case 'scan_complete':
            _pwStreamEl = null;
            _pwThinkingEl = null;
            _pwAppend('system', `── Playwright 에이전트 점검 완료 (취약점 ${pwFindingCount}건) ──`);
            pwRunning = false;
            _pwUpdateStatus('done');
            break;
    }
}

// ── 스크린샷 업데이트 ─────────────────────────────────────

function _pwUpdateScreenshot(base64Data) {
    const img = document.getElementById('pwScreenshot');
    const placeholder = document.getElementById('pwScreenshotPlaceholder');
    if (!img) return;

    img.src = `data:image/jpeg;base64,${base64Data}`;
    img.style.display = 'block';
    if (placeholder) placeholder.style.display = 'none';

    // URL 바 업데이트는 tool_result에서 처리
}

// ── UI 렌더링 ─────────────────────────────────────────────

function _pwAppend(type, text) {
    const container = document.getElementById('pwOutput');
    if (!container) return null;

    const el = document.createElement('div');
    el.className = `agent-line agent-line-${type}`;

    switch (type) {
        case 'system':
            el.innerHTML = `<span class="agent-system-text">${_pwEsc(text)}</span>`;
            break;
        case 'user':
            el.innerHTML = `<span class="agent-user-label">YOU &gt;</span> <span class="agent-user-text">${_pwEsc(text)}</span>`;
            break;
        case 'assistant':
            el.innerHTML = `<span class="agent-text">${_pwEsc(text)}</span>`;
            break;
        case 'tool_call':
            const lines = text.split('\n');
            el.innerHTML = `<span class="agent-tool-icon">🔧</span> <span class="agent-tool-label">${_pwEsc(lines[0])}</span>${lines[1] ? `<pre class="agent-tool-pre">${_pwEsc(lines[1])}</pre>` : ''}`;
            break;
        case 'tool_result':
            el.innerHTML = `<span class="agent-result-icon">←</span> <pre class="agent-result-pre">${_pwEsc(text)}</pre>`;
            break;
        case 'finding':
            el.innerHTML = `<span class="agent-finding-icon">🚨</span> <span class="agent-finding-text">${_pwEsc(text)}</span>`;
            break;
        default:
            el.textContent = text;
    }

    container.appendChild(el);
    _pwScrollBottom();
    return el;
}

function _pwAppendStreaming(type, initialText) {
    const container = document.getElementById('pwOutput');
    if (!container) return null;

    const el = document.createElement('div');
    if (type === 'thinking') {
        el.className = 'agent-line agent-line-thinking';
        el.innerHTML = `<details open><summary class="agent-thinking-summary"><span class="agent-thinking-icon">💭</span> 생각 중...</summary><div class="agent-thinking-text"></div></details>`;
    } else {
        el.className = 'agent-line agent-line-assistant';
        el.innerHTML = `<span class="agent-text agent-cursor"></span>`;
    }
    container.appendChild(el);
    _pwScrollBottom();
    return el;
}

function _pwScrollBottom() {
    const c = document.getElementById('pwOutput');
    if (c) c.scrollTop = c.scrollHeight;
}

function _pwUpdateStatus(status) {
    const startBtn = document.getElementById('pwStartBtn');
    const stopBtn = document.getElementById('pwStopBtn');
    const dot = document.getElementById('pwStatusDot');
    const text = document.getElementById('pwStatusText');

    if (status === 'running') {
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = false;
        if (dot) dot.className = 'agent-status-dot dot-running';
        if (text) text.textContent = '점검 중...';
    } else if (status === 'done') {
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
        if (dot) dot.className = 'agent-status-dot dot-done';
        if (text) text.textContent = '점검 완료';
    } else {
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
        if (dot) dot.className = 'agent-status-dot dot-idle';
        if (text) text.textContent = '대기 중';
    }
}

function _pwUpdateBadge(count) {
    const badge = document.getElementById('pwFindingBadge');
    if (badge) badge.textContent = `취약점 ${count}건`;
}

function clearPlaywrightOutput() {
    const c = document.getElementById('pwOutput');
    if (c) c.innerHTML = '';
    const img = document.getElementById('pwScreenshot');
    if (img) { img.src = ''; img.style.display = 'none'; }
    const ph = document.getElementById('pwScreenshotPlaceholder');
    if (ph) ph.style.display = '';
    pwFindingCount = 0;
    _pwUpdateBadge(0);
    _pwStreamEl = null;
    _pwThinkingEl = null;
}

// ── 지시 메시지 ───────────────────────────────────────────

async function sendPlaywrightMessage() {
    const sessionId = localStorage.getItem('currentSessionId');
    const input = document.getElementById('pwMsgInput');
    if (!input) return;

    const msg = input.value.trim();
    if (!msg) return;

    _pwAppend('user', msg);
    input.value = '';
    _pwResizeInput(input);

    if (!pwRunning) {
        _pwAppend('system', '에이전트가 실행 중이지 않습니다. 먼저 시작하세요.');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/api/agent/message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, message: msg })
        });
        const data = await res.json();
        if (data.status !== 'success') {
            _pwAppend('system', `메시지 전달 실패: ${data.message}`);
        }
    } catch (e) {
        _pwAppend('system', `오류: ${e.message}`);
    }
}

function pwMsgKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendPlaywrightMessage();
    }
}

// ── 유틸리티 ─────────────────────────────────────────────

function _pwEsc(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function _pwActionLabel(name) {
    const labels = {
        navigate:       '🌐 페이지 이동',
        click:          '🖱️ 클릭',
        fill:           '⌨️ 입력',
        submit:         '📤 폼 제출',
        screenshot:     '📸 스크린샷',
        get_html:       '📄 HTML 분석',
        get_cookies:    '🍪 쿠키 확인',
        get_url:        '🔗 URL 확인',
        run_command:    '💻 명령어 실행',
        inject_js:      '⚡ JS 실행',
        report_finding: '🚨 취약점 보고',
        done:           '✅ 완료',
    };
    return labels[name] || name;
}

function _pwCollectAiConfig() {
    const aiType = localStorage.getItem('aiType') || 'gemini';
    const aiUrl = localStorage.getItem('aiUrl') || '';
    const aiModel = localStorage.getItem('aiModel') || '';

    let apiKey = '';
    if (aiType === 'claude') {
        apiKey = localStorage.getItem('claudeApiKey') || '';
        if (!apiKey) { _pwAppend('system', 'Claude API 키가 없습니다. 설정 탭에서 입력하세요.'); return null; }
    } else if (aiType === 'gemini') {
        apiKey = localStorage.getItem('geminiApiKey') || '';
        if (!apiKey) { _pwAppend('system', 'Gemini API 키가 없습니다. 설정 탭에서 입력하세요.'); return null; }
    } else if (aiType === 'lmstudio') {
        apiKey = 'not-needed';
    }

    return {
        type: aiType,
        api_key: apiKey,
        base_url: aiUrl,
        model: aiModel || (aiType === 'claude' ? 'claude-sonnet-4-6' : 'gemini-2.5-flash')
    };
}

function _pwCollectHeaders() {
    const raw = localStorage.getItem('customHeaders') || '';
    if (!raw.trim()) return {};
    const headers = {};
    raw.split('\n').forEach(line => {
        const idx = line.indexOf(':');
        if (idx > 0) headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
    });
    return headers;
}

function _pwResizeInput(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}
