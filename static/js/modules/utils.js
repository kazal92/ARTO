/**
 * utils.js - ARTO 공통 유틸리티 함수 모듈
 * 의존성 없는 순수 함수들 모음
 */

/**
 * Date 객체를 HH:MM:SS.mmm 형식으로 포맷
 * @param {Date} date
 * @returns {string}
 */
function formatTimeWithMs(date) {
    const h = String(date.getHours()).padStart(2, '0');
    const m = String(date.getMinutes()).padStart(2, '0');
    const s = String(date.getSeconds()).padStart(2, '0');
    const ms = String(date.getMilliseconds()).padStart(3, '0');
    return `${h}:${m}:${s}.${ms}`;
}

/**
 * URL이 정적 파일(이미지, CSS, JS 등)인지 판별
 * @param {string} url
 * @returns {boolean}
 */
function isStaticFile(url) {
    if (!url) return false;
    const staticExts = [
        '.jpg', '.jpeg', '.png', '.gif', '.ico', '.svg', '.webp',
        '.css', '.map', '.woff', '.woff2', '.ttf', '.eot',
        '.mp4', '.webm', '.ogg', '.mp3', '.wav', '.flac', '.aac',
        '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z', '.js'
    ];
    const path = url.split('?')[0].toLowerCase();
    return staticExts.some(ext => path.endsWith(ext));
}

/**
 * 텍스트를 클립보드에 복사
 * @param {HTMLElement} btn - 복사 트리거 버튼
 */
function copyToClipboard(btn) {
    const targetId = btn.getAttribute('data-target');
    const el = document.getElementById(targetId);
    if (!el) return;
    navigator.clipboard.writeText(el.innerText || el.value).then(() => {
        const original = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check text-success"></i>';
        setTimeout(() => btn.innerHTML = original, 1500);
    });
}

/**
 * 디바운스 유틸리티
 * @param {Function} fn
 * @param {number} delay ms
 * @returns {Function}
 */
function debounce(fn, delay = 300) {
    let timer;
    return (...args) => {
        clearTimeout(timer);
        timer = setTimeout(() => fn(...args), delay);
    };
}
