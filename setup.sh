#!/bin/bash

# ============================================================
#  ARTO v2 — 사전 요구사항 자동 설치 스크립트
#  대상 OS: Kali Linux / Debian 계열
# ============================================================

set -e  # 에러 발생 시 즉시 종료

# ── 색상 정의 ────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ── 로그 함수 ────────────────────────────────────────────────
info()    { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC}   $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERR]${NC}  $1"; exit 1; }
step()    { echo -e "\n${CYAN}══════════════════════════════════════${NC}"; echo -e "${CYAN}  $1${NC}"; echo -e "${CYAN}══════════════════════════════════════${NC}"; }

# ── 루트 권한 확인 ────────────────────────────────────────────
if [ "$EUID" -ne 0 ]; then
    warn "루트 권한이 없습니다. sudo를 사용하여 실행합니다."
    SUDO="sudo"
else
    SUDO=""
fi

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   ARTO v2 — 설치 스크립트 시작           ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
echo ""

# ══════════════════════════════════════════════
# STEP 1: 시스템 패키지 업데이트
# ══════════════════════════════════════════════
step "1/5  시스템 패키지 업데이트"
$SUDO apt-get update -y
$SUDO apt-get install -y \
    ca-certificates curl gnupg lsb-release \
    git wget unzip build-essential
success "시스템 패키지 업데이트 완료"

# ══════════════════════════════════════════════
# STEP 2: Docker 설치
# ══════════════════════════════════════════════
step "2/5  Docker 설치"

if command -v docker &> /dev/null; then
    success "Docker 이미 설치됨: $(docker --version)"
else
    info "기존 Docker 패키지 제거 중..."
    $SUDO apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

    info "Docker 공식 GPG 키 및 저장소 추가 중..."
    $SUDO install -m 0755 -d /etc/apt/keyrings

    curl -fsSL https://download.docker.com/linux/debian/gpg | \
        $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    $SUDO chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian $(lsb_release -cs) stable" | \
        $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null

    $SUDO apt-get update -y
    $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

    # Docker 서비스 시작
    $SUDO systemctl enable docker --now 2>/dev/null || \
        $SUDO service docker start 2>/dev/null || true

    # 현재 유저를 docker 그룹에 추가
    if [ -n "$SUDO_USER" ]; then
        $SUDO usermod -aG docker "$SUDO_USER"
        info "사용자 '$SUDO_USER'를 docker 그룹에 추가했습니다."
        info "그룹 적용을 위해 로그아웃 후 재로그인하거나 'newgrp docker' 실행이 필요합니다."
    fi

    success "Docker 설치 완료: $(docker --version)"
fi

# ══════════════════════════════════════════════
# STEP 3: OWASP ZAP Docker 이미지 다운로드
# ══════════════════════════════════════════════
step "3/5  OWASP ZAP 이미지 다운로드"

if docker image inspect ghcr.io/zaproxy/zaproxy:stable &>/dev/null 2>&1; then
    success "ZAP 이미지 이미 존재함"
else
    info "OWASP ZAP Stable 이미지를 다운로드합니다 (약 1GB, 시간이 걸릴 수 있습니다)..."
    docker pull ghcr.io/zaproxy/zaproxy:stable
    success "ZAP 이미지 다운로드 완료"
fi

# ══════════════════════════════════════════════
# STEP 4: FFuF 설치
# ══════════════════════════════════════════════
step "4/5  FFuF (Fast Web Fuzzer) 설치"

if command -v ffuf &> /dev/null; then
    success "FFuF 이미 설치됨: $(ffuf -V 2>&1 | head -1)"
else
    info "FFuF 최신 릴리즈를 다운로드합니다..."

    FFUF_VERSION=$(curl -s https://api.github.com/repos/ffuf/ffuf/releases/latest \
        | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    ARCH=$(uname -m)
    if [ "$ARCH" = "x86_64" ]; then
        FFUF_ARCH="amd64"
    elif [ "$ARCH" = "aarch64" ]; then
        FFUF_ARCH="arm64"
    else
        FFUF_ARCH="amd64"
    fi

    FFUF_URL="https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz"
    info "다운로드 URL: $FFUF_URL"

    TMP_DIR=$(mktemp -d)
    curl -sL "$FFUF_URL" -o "$TMP_DIR/ffuf.tar.gz"
    tar -xzf "$TMP_DIR/ffuf.tar.gz" -C "$TMP_DIR"
    $SUDO mv "$TMP_DIR/ffuf" /usr/local/bin/ffuf
    $SUDO chmod +x /usr/local/bin/ffuf
    rm -rf "$TMP_DIR"

    success "FFuF 설치 완료: $(ffuf -V 2>&1 | head -1)"
fi

# ══════════════════════════════════════════════
# STEP 5: Python 패키지 설치
# ══════════════════════════════════════════════
step "5/5  Python 의존성 설치"

# Python3 존재 여부 확인
if ! command -v python3 &> /dev/null; then
    info "Python3 설치 중..."
    $SUDO apt-get install -y python3 python3-pip
fi

# pip 업그레이드
python3 -m pip install --upgrade pip --quiet

# ARTO 필수 패키지 설치
info "ARTO 필수 Python 패키지 설치 중..."
python3 -m pip install \
    fastapi \
    "uvicorn[standard]" \
    httpx \
    openai \
    python-dotenv \
    --quiet

success "Python 패키지 설치 완료"

# ══════════════════════════════════════════════
# 설치 완료 요약
# ══════════════════════════════════════════════
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅ 모든 설치가 완료되었습니다!         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}설치된 구성요소:${NC}"
echo -e "  • Docker     : $(docker --version 2>/dev/null || echo '설치됨')"
echo -e "  • ZAP 이미지 : ghcr.io/zaproxy/zaproxy:stable"
echo -e "  • FFuF       : $(ffuf -V 2>&1 | head -1 || echo '설치됨')"
echo -e "  • Python     : $(python3 --version)"
echo ""
echo -e "  ${CYAN}다음 단계:${NC}"
echo -e "  ${GREEN}./run_app.sh${NC}  — ZAP 시작 + ARTO 대시보드 실행"
echo -e "  접속 주소    : http://localhost:8001"
echo ""

# docker 그룹 변경 안내 (재로그인 필요 시)
if id -nG "$USER" 2>/dev/null | grep -qw docker; then
    : # 이미 그룹에 속해 있음
else
    warn "docker 그룹 적용을 위해 아래 명령을 실행하거나 재로그인하세요:"
    echo -e "  ${YELLOW}newgrp docker${NC}"
fi
