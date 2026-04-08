/**
 * terminal.js - 웹 터미널 모듈
 * xterm.js + WebSocket + PTY(bash) 연결
 */

let termInstance = null;
let termWs = null;
let termFitAddon = null;
let termInitialized = false;

function initTerminal() {
    // 탭 전환 시 호출됨 — 이미 초기화됐으면 resize만
    if (termInitialized) {
        _termFit();
        return;
    }
    // section-terminal이 보일 때 초기화
}

function startTerminal() {
    if (termInitialized) return;

    const container = document.getElementById('terminalContainer');
    if (!container) return;

    // xterm.js 인스턴스 생성
    termInstance = new Terminal({
        cursorBlink: true,
        fontSize: 14,
        fontFamily: "'Fira Code', 'Cascadia Code', 'Consolas', monospace",
        theme: {
            background: '#0d0f17',
            foreground: '#e2e8f0',
            cursor: '#a78bfa',
            cursorAccent: '#0d0f17',
            selectionBackground: 'rgba(167,139,250,0.3)',
            black:   '#1e293b', red:     '#f87171',
            green:   '#4ade80', yellow:  '#fbbf24',
            blue:    '#60a5fa', magenta: '#c084fc',
            cyan:    '#22d3ee', white:   '#e2e8f0',
            brightBlack:   '#475569', brightRed:     '#f87171',
            brightGreen:   '#4ade80', brightYellow:  '#fbbf24',
            brightBlue:    '#818cf8', brightMagenta: '#e879f9',
            brightCyan:    '#67e8f9', brightWhite:   '#f8fafc',
        },
        scrollback: 5000,
        allowTransparency: true,
    });

    termFitAddon = new FitAddon.FitAddon();
    termInstance.loadAddon(termFitAddon);
    termInstance.open(container);
    _termFit();

    // WebSocket 연결
    _termConnect();

    // 키 입력 → WS 전송
    termInstance.onData(data => {
        if (termWs && termWs.readyState === WebSocket.OPEN) {
            termWs.send(new TextEncoder().encode(data));
        }
    });

    // 리사이즈 감지
    const ro = new ResizeObserver(() => _termFit());
    ro.observe(container);

    termInitialized = true;
}

// ── 외부 코드에서 터미널에 명령어 전송 ──────────────────

function termSend(command) {
    if (!termInstance || !termWs) {
        console.warn('[termSend] Terminal not initialized');
        return false;
    }

    if (termWs.readyState !== WebSocket.OPEN) {
        console.warn('[termSend] WebSocket not connected');
        return false;
    }

    try {
        // 명령어를 터미널에 표시
        termInstance.write(command);
        // WebSocket으로 전송
        termWs.send(new TextEncoder().encode(command));
        console.log('[termSend] Sent:', command.trim());
        return true;
    } catch (e) {
        console.error('[termSend] Error:', e);
        return false;
    }
}

function _termConnect() {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const wsUrl = `${proto}://${location.host}/api/terminal`;

    termWs = new WebSocket(wsUrl);
    termWs.binaryType = 'arraybuffer';

    termWs.onopen = () => {
        // 접속 즉시 + 50ms 후 한 번 더 resize 전송 (TUI 앱 크기 맞춤)
        _termSendResize();
        setTimeout(_termSendResize, 50);
        setTimeout(_termSendResize, 200);
    };

    termWs.onmessage = (e) => {
        termInstance.write(new Uint8Array(e.data));
    };

    termWs.onclose = () => {
        termInstance.writeln('\r\n\x1b[1;31m[연결 종료] 터미널 재연결 중...\x1b[0m');
        termInitialized = false;
        setTimeout(() => {
            if (document.getElementById('section-terminal')?.classList.contains('active')) {
                termInitialized = false;
                startTerminal();
            }
        }, 2000);
    };

    termWs.onerror = () => {
        termInstance.writeln('\r\n\x1b[1;31m[오류] WebSocket 연결 실패\x1b[0m');
    };
}

function _termFit() {
    if (!termFitAddon || !termInstance) return;
    try {
        termFitAddon.fit();
        _termSendResize();
    } catch (e) {}
}

function _termSendResize() {
    if (!termWs || termWs.readyState !== WebSocket.OPEN || !termInstance) return;
    const rows = termInstance.rows;
    const cols = termInstance.cols;
    // resize 프로토콜: \x01 + rows(uint16) + cols(uint16)
    const buf = new Uint8Array(5);
    buf[0] = 0x01;
    new DataView(buf.buffer).setUint16(1, rows, false);
    new DataView(buf.buffer).setUint16(3, cols, false);
    termWs.send(buf);
}

async function termKillSession() {
    await fetch(`${API_BASE}/api/terminal/kill`, { method: 'POST' });
    termDisconnect();
    setTimeout(() => startTerminal(), 500);
}

function termDisconnect() {
    if (termWs) {
        termWs.close();
        termWs = null;
    }
    termInitialized = false;
}
