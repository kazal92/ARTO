/**
 * agent.js - AI 에이전트 점검 탭 모듈
 * Claude / Gemini 에이전트가 직접 모의해킹을 수행하고
 * 발견 즉시 취약점 카드를 생성하는 터미널 인터페이스
 */

let agentEventSource = null;
let agentRunning = false;
let agentFindingCount = 0;
let agentReplaying = true;  // agent_start 이전 = 이전 로그 재전송 구간

// ── 초기화 ────────────────────────────────────────────────────────────────────

function initAgent() {
    const target = currentProject?.target || '';
    const el = document.getElementById('agentTargetInput');
    if (el && target) el.value = target;
    _updateAgentStatus('idle');
}

// ── 에이전트 시작 ─────────────────────────────────────────────────────────────

async function startAgent() {
    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId) {
        _agentAppend('system', '세션이 선택되지 않았습니다. 프로젝트를 먼저 여세요.');
        return;
    }

    const target = document.getElementById('agentTargetInput')?.value?.trim();
    if (!target) {
        _agentAppend('system', '타겟 URL을 입력하세요.');
        return;
    }

    if (agentRunning) {
        _agentAppend('system', '이미 에이전트가 실행 중입니다.');
        return;
    }

    // AI 설정 수집
    const aiConfig = _collectAiConfig();
    if (!aiConfig) return;

    // 커스텀 헤더 수집
    const customHeaders = _collectCustomHeaders();

    agentRunning = true;
    agentReplaying = true;
    agentFindingCount = 0;
    _updateAgentStatus('running');
    _updateFindingBadge(0);
    _agentAppend('system', `에이전트 점검 시작: ${target}`);
    _agentAppend('system', `AI 엔진: ${aiConfig.type.toUpperCase()} / ${aiConfig.model}`);

    try {
        agentEventSource = new EventSource('');  // placeholder, use fetch for POST SSE
        agentEventSource.close();
        agentEventSource = null;

        // fetch 기반 SSE (POST body 필요)
        const response = await fetch(`${API_BASE}/api/agent/run`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                session_id: sessionId,
                target: target,
                ai_config: aiConfig,
                custom_headers: customHeaders
            })
        });

        if (!response.ok) {
            _agentAppend('system', `서버 오류: ${response.status}`);
            _updateAgentStatus('idle');
            agentRunning = false;
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
                    _handleAgentEvent(data);
                } catch (e) {
                    // ignore parse errors
                }
            }
        }
    } catch (e) {
        if (agentRunning) {
            _agentAppend('system', `연결 오류: ${e.message}`);
        }
    } finally {
        agentRunning = false;
        _updateAgentStatus('idle');
    }
}

// ── 에이전트 중단 ─────────────────────────────────────────────────────────────

async function stopAgent() {
    const sessionId = localStorage.getItem('currentSessionId');
    if (!sessionId) return;

    try {
        await fetch(`${API_BASE}/api/agent/stop`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId })
        });
        _agentAppend('system', '에이전트 중단 요청을 보냈습니다...');
    } catch (e) {
        console.error(e);
    }
}

// ── 사용자 메시지 전송 ────────────────────────────────────────────────────────

async function sendAgentMessage() {
    const sessionId = localStorage.getItem('currentSessionId');
    const input = document.getElementById('agentMsgInput');
    if (!input) return;

    const msg = input.value.trim();
    if (!msg) return;

    if (!agentRunning) {
        _agentAppend('system', '🏃 에이전트를 재구동하며 이전 맥락을 로드합니다...');
        input.value = '';
        
        // 1) 강제 시작
        startAgent();
        
        // 2) 서버쪽 백그라운드 루프가 초기화될 시간을 1.5초 정도 기다렸다가 메시지 큐 전송
        setTimeout(async () => {
            _agentAppend('user', msg);
            try {
                await fetch(`${API_BASE}/api/agent/message`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ session_id: sessionId, message: msg })
                });
            } catch (e) { console.error('Resume message failed:', e); }
        }, 1500);
        return;
    }

    input.value = '';
    _agentAppend('user', msg);

    try {
        const res = await fetch(`${API_BASE}/api/agent/message`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ session_id: sessionId, message: msg })
        });
        const data = await res.json();
        if (data.status !== 'success') {
            _agentAppend('system', `⚠️ ${data.message}`);
        }
    } catch (e) {
        _agentAppend('system', `오류: ${e.message}`);
    }
}

function agentMsgKeydown(event) {
    if (event.key === 'Enter' && !event.shiftKey) {
        event.preventDefault();
        sendAgentMessage();
    }
}

// ── SSE 이벤트 처리 ───────────────────────────────────────────────────────────

let _thinkingEl = null;
let _thinkingText = '';
let _streamEl = null;

function _handleAgentEvent(data) {
    switch (data.type) {
        case 'agent_start':
            agentReplaying = false;
            break;

        case 'thinking_start':
            _thinkingText = '';
            _thinkingEl = _agentAppendStreaming('thinking', '');
            _streamEl = null;
            break;

        case 'thinking_chunk':
            if (_thinkingEl) {
                _thinkingText += data.content;
                _thinkingEl.querySelector('.agent-thinking-text').textContent = _thinkingText;
                _scrollAgentBottom();
            }
            break;

        case 'chunk':
            // 텍스트 스트리밍 (에이전트 일반 출력)
            if (!_streamEl) {
                _thinkingEl = null;
                _streamEl = _agentAppendStreaming('assistant', '');
            }
            const textEl = _streamEl.querySelector('.agent-text');
            if (textEl) {
                textEl.textContent += data.content;
                _scrollAgentBottom();
            }
            break;

        case 'tool_call':
            _streamEl = null;
            _thinkingEl = null;
            const toolLabel = _toolLabel(data.tool_name);
            const inputPreview = _formatToolInput(data.tool_name, data.tool_input || {});
            _agentAppend('tool_call', `${toolLabel}\n${inputPreview}`);
            break;

        case 'tool_result':
            const resultText = data.result || '';
            _agentAppend('tool_result', resultText);
            break;

        case 'user_message':
            // 에이전트가 수신한 메시지 확인 (이미 UI에 표시됨)
            break;

        case 'log':
            if (data.agent === 'Agent') {
                _agentAppend('system', data.message);
            }
            break;

        case 'ai_card':
            if (agentReplaying) break;
            agentFindingCount++;
            _updateFindingBadge(agentFindingCount);
            _agentAppend('finding', `취약점 발견: ${data.data?.title || '?'} [${data.data?.severity || '?'}]`);
            // 취약점 탭 카드에도 추가
            if (typeof aiCardsData !== 'undefined' && typeof renderCards === 'function') {
                aiCardsData.push(data.data);
                renderCards(aiCardsData);
                if (typeof saveFindings === 'function') saveFindings();
            }
            _streamEl = null;
            break;

        case 'scan_complete':
            _streamEl = null;
            _thinkingEl = null;
            _agentAppend('system', `── 에이전트 점검 완료 (취약점 ${agentFindingCount}건 발견) ──`);
            agentRunning = false;
            _updateAgentStatus('done');
            break;
    }
}

function replayAgentLogs(logs) {
    if (typeof clearAgentOutput === 'function') clearAgentOutput();
    if (!logs || !logs.length) return;
    
    agentReplaying = true; 
    let hasAgentData = false;
    let isComplete = false;
    
    logs.forEach(log => {
        if (['chunk', 'thinking_start', 'thinking_chunk', 'tool_call', 'tool_result', 'ai_card', 'agent_start', 'scan_complete', 'user_message'].includes(log.type) 
           || (log.type === 'log' && log.agent === 'Agent')) {
            
            // disable sound/UI badge updates during replay using simple hacks or let them be
            _handleAgentEvent(log);
            hasAgentData = true;
            if (log.type === 'scan_complete') isComplete = true;
        }
    });
    
    agentReplaying = false;
    
    if (hasAgentData && !isComplete) {
        // 백엔드에서 아직 실행 중일 수 있음!
        agentRunning = true;
        _updateAgentStatus('running');
    }
}

// ── UI 렌더링 헬퍼 ────────────────────────────────────────────────────────────

function _agentAppend(type, text) {
    const container = document.getElementById('agentOutput');
    if (!container) return null;

    const el = document.createElement('div');
    el.className = `agent-line agent-line-${type}`;

    switch (type) {
        case 'system':
            el.innerHTML = `<span class="agent-system-text">${_escHtml(text)}</span>`;
            break;
        case 'user':
            el.innerHTML = `<span class="agent-user-label">YOU &gt;</span> <span class="agent-user-text">${_escHtml(text)}</span>`;
            break;
        case 'assistant':
            el.innerHTML = `<span class="agent-text">${_escHtml(text)}</span>`;
            break;
        case 'tool_call':
            const lines = text.split('\n');
            el.innerHTML = `<span class="agent-tool-icon">🔧</span> <span class="agent-tool-label">${_escHtml(lines[0])}</span>${lines[1] ? `<pre class="agent-tool-pre">${_escHtml(lines[1])}</pre>` : ''}`;
            break;
        case 'tool_result':
            el.innerHTML = `<span class="agent-result-icon">←</span> <pre class="agent-result-pre">${_escHtml(text)}</pre>`;
            break;
        case 'finding':
            el.innerHTML = `<span class="agent-finding-icon">🚨</span> <span class="agent-finding-text">${_escHtml(text)}</span>`;
            break;
        default:
            el.textContent = text;
    }

    container.appendChild(el);
    _scrollAgentBottom();
    return el;
}

function _agentAppendStreaming(type, initialText) {
    const container = document.getElementById('agentOutput');
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
    _scrollAgentBottom();
    return el;
}

function _scrollAgentBottom() {
    const container = document.getElementById('agentOutput');
    if (container) container.scrollTop = container.scrollHeight;
}

function _updateAgentStatus(status) {
    const startBtn = document.getElementById('agentStartBtn');
    const stopBtn = document.getElementById('agentStopBtn');
    const statusDot = document.getElementById('agentStatusDot');
    const statusText = document.getElementById('agentStatusText');

    if (status === 'running') {
        if (startBtn) startBtn.disabled = true;
        if (stopBtn) stopBtn.disabled = false;
        if (statusDot) statusDot.className = 'agent-status-dot dot-running';
        if (statusText) statusText.textContent = '점검 중...';
    } else if (status === 'done') {
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
        if (statusDot) statusDot.className = 'agent-status-dot dot-done';
        if (statusText) statusText.textContent = '점검 완료';
    } else {
        if (startBtn) startBtn.disabled = false;
        if (stopBtn) stopBtn.disabled = true;
        if (statusDot) statusDot.className = 'agent-status-dot dot-idle';
        if (statusText) statusText.textContent = '대기 중';
    }
}

function _updateFindingBadge(count) {
    const badge = document.getElementById('agentFindingBadge');
    if (badge) badge.textContent = `취약점 ${count}건`;
}

function clearAgentOutput() {
    const container = document.getElementById('agentOutput');
    if (container) container.innerHTML = '';
    agentFindingCount = 0;
    _updateFindingBadge(0);
    _streamEl = null;
    _thinkingEl = null;
}

// ── AI 설정 수집 ──────────────────────────────────────────────────────────────

function _collectAiConfig() {
    const aiType = localStorage.getItem('aiType') || 'gemini';
    const aiUrl = localStorage.getItem('aiUrl') || '';
    const aiModel = localStorage.getItem('aiModel') || '';

    let apiKey = '';
    if (aiType === 'claude') {
        apiKey = localStorage.getItem('claudeApiKey') || '';
        if (!apiKey) {
            _agentAppend('system', 'Claude API 키가 설정되지 않았습니다. 설정 탭에서 입력하세요.');
            return null;
        }
    } else if (aiType === 'gemini') {
        apiKey = localStorage.getItem('geminiApiKey') || '';
        if (!apiKey) {
            _agentAppend('system', 'Gemini API 키가 설정되지 않았습니다. 설정 탭에서 입력하세요.');
            return null;
        }
    } else if (aiType === 'lmstudio') {
        apiKey = localStorage.getItem('lmstudioApiKey') || 'lm-studio';
    }

    return {
        type: aiType,
        api_key: apiKey,
        base_url: aiUrl,
        model: aiModel || (aiType === 'claude' ? 'claude-sonnet-4-6' : 'gemini-2.5-flash')
    };
}

function _collectCustomHeaders() {
    const raw = localStorage.getItem('customHeaders') || '';
    if (!raw.trim()) return {};
    try {
        return JSON.parse(raw);
    } catch (e) {
        // key: value 형식 파싱
        const headers = {};
        raw.split('\n').forEach(line => {
            const idx = line.indexOf(':');
            if (idx > 0) {
                headers[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
            }
        });
        return headers;
    }
}

// ── 유틸리티 ──────────────────────────────────────────────────────────────────

function _escHtml(str) {
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');
}

function _toolLabel(name) {
    const labels = {
        run_command: '명령어 실행',
        report_finding: '취약점 보고',
    };
    return labels[name] || name;
}

function _formatToolInput(toolName, input) {
    if (toolName === 'run_command') {
        return `  $ ${input.command || ''}`;
    }
    if (toolName === 'report_finding') {
        return `  [${input.severity || '?'}] ${input.title || '?'}`;
    }
    return '';
}

function _agentResizeInput(el) {
    el.style.height = 'auto';
    el.style.height = Math.min(el.scrollHeight, 120) + 'px';
}
