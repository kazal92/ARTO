#!/bin/bash

# ============================================================
#  ARTO v2 — 자동 환경 구성 스크립트
#  대상 OS : Kali Linux on WSL2 / Bare-metal Debian 계열
#  사용법  : chmod +x setup.sh && sudo ./setup.sh
# ============================================================

set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# ── 색상 ────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[ OK ]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERR ]${NC} $*"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}── $* ──────────────────────────────────────${NC}"; }

# ── 루트 확인 ───────────────────────────────────────────────
[[ "$EUID" -ne 0 ]] && SUDO="sudo" || SUDO=""

# SUDO_USER: sudo로 실행된 경우 원래 사용자, 아니면 현재 유저
REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# ── WSL 감지 ────────────────────────────────────────────────
IS_WSL=0
if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
    IS_WSL=1
    info "WSL2 환경 감지됨"
fi

# ── 스크립트 위치 = ARTO 루트 ───────────────────────────────
ARTO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
info "ARTO 디렉토리: $ARTO_DIR"

# ══════════════════════════════════════════════════════════
echo ""
echo -e "${CYAN}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   ARTO v2 — 자동 환경 구성 시작              ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ══════════════════════════════════════════════════════════
# STEP 1 : 시스템 패키지
# ══════════════════════════════════════════════════════════
step "1/6  시스템 패키지 업데이트"

$SUDO apt-get update -y -qq
$SUDO apt-get install -y -qq \
    ca-certificates curl gnupg gnupg2 lsb-release \
    git wget unzip build-essential \
    python3 python3-pip python3-venv \
    iptables 2>/dev/null || true

GPG_CMD=$(command -v gpg2 || command -v gpg || echo gpg)

success "시스템 패키지 완료"

# ══════════════════════════════════════════════════════════
# STEP 2 : Docker
# ══════════════════════════════════════════════════════════
step "2/6  Docker 설치"

if command -v docker &>/dev/null; then
    success "Docker 이미 설치됨: $(docker --version)"
else
    info "기존 Docker 패키지 제거..."
    $SUDO apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

    info "Docker 공식 GPG 키 및 저장소 추가..."
    $SUDO install -m 0755 -d /etc/apt/keyrings

    curl -fsSL https://download.docker.com/linux/debian/gpg \
        | $SUDO $GPG_CMD --dearmor -o /etc/apt/keyrings/docker.gpg
    $SUDO chmod a+r /etc/apt/keyrings/docker.gpg

    # Kali는 lsb_release -cs가 "kali-rolling"을 반환하므로 Debian 코드명으로 변환
    DISTRO_CS=$(lsb_release -cs)
    if [[ "$DISTRO_CS" == "kali-rolling" || "$DISTRO_CS" == kali* ]]; then
        DISTRO_CS="bookworm"
    fi

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/debian ${DISTRO_CS} stable" \
        | $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null

    $SUDO apt-get update -y -qq
    $SUDO apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin
    success "Docker 설치 완료: $(docker --version)"
fi

# docker 그룹 추가
if ! id -nG "$REAL_USER" | grep -qw docker; then
    $SUDO usermod -aG docker "$REAL_USER"
    info "사용자 '$REAL_USER'를 docker 그룹에 추가 (재로그인 또는 newgrp docker 필요)"
fi

# ── WSL: iptables legacy 설정 ──────────────────────────────
if [[ "$IS_WSL" -eq 1 ]]; then
    info "WSL: iptables를 legacy 모드로 변경..."
    $SUDO update-alternatives --set iptables  /usr/sbin/iptables-legacy  2>/dev/null || true
    $SUDO update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true
fi

# ── Docker 데몬 시작 ───────────────────────────────────────
_start_docker() {
    # systemd 사용 가능한 경우
    if systemctl is-active --quiet docker 2>/dev/null; then
        return 0
    fi
    if command -v systemctl &>/dev/null && systemctl start docker 2>/dev/null; then
        sleep 2; return 0
    fi
    # service 명령 (WSL 기본)
    if $SUDO service docker start 2>/dev/null; then
        sleep 3; return 0
    fi
    # dockerd 직접 백그라운드 실행
    if ! pgrep -x dockerd &>/dev/null; then
        warn "dockerd를 백그라운드로 직접 실행합니다..."
        $SUDO dockerd --host=unix:///var/run/docker.sock \
                      --host=tcp://127.0.0.1:2375 \
                      --iptables=false \
                      > /tmp/dockerd.log 2>&1 &
        sleep 5
    fi
}

_start_docker

# Docker 소켓 권한
if [[ -S /var/run/docker.sock ]]; then
    $SUDO chmod 666 /var/run/docker.sock
fi

# Docker 동작 확인
if ! docker info &>/dev/null 2>&1; then
    warn "Docker 데몬이 응답하지 않습니다."
    if [[ "$IS_WSL" -eq 1 ]]; then
        warn "WSL에서 Docker를 수동으로 시작하려면:"
        warn "  sudo service docker start"
        warn "또는 Docker Desktop for Windows를 설치하면 자동 연동됩니다."
    fi
else
    success "Docker 데몬 실행 중"
fi

# ══════════════════════════════════════════════════════════
# STEP 3 : OWASP ZAP 이미지
# ══════════════════════════════════════════════════════════
step "3/6  OWASP ZAP Docker 이미지"

if docker image inspect ghcr.io/zaproxy/zaproxy:stable &>/dev/null 2>&1; then
    success "ZAP 이미지 이미 존재함"
else
    info "OWASP ZAP Stable 이미지 다운로드 중 (약 1GB)..."
    docker pull ghcr.io/zaproxy/zaproxy:stable
    success "ZAP 이미지 다운로드 완료"
fi

# ══════════════════════════════════════════════════════════
# STEP 4 : FFuF
# ══════════════════════════════════════════════════════════
step "4/6  FFuF 설치"

if command -v ffuf &>/dev/null; then
    success "FFuF 이미 설치됨: $(ffuf -V 2>&1 | head -1)"
else
    info "FFuF 최신 릴리즈 다운로드..."

    FFUF_VERSION=$(curl -fsSL https://api.github.com/repos/ffuf/ffuf/releases/latest \
        | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')

    [[ -z "$FFUF_VERSION" ]] && error "FFuF 버전 정보를 가져올 수 없습니다. 인터넷 연결을 확인하세요."

    case "$(uname -m)" in
        x86_64)  FFUF_ARCH="amd64" ;;
        aarch64) FFUF_ARCH="arm64" ;;
        *)       FFUF_ARCH="amd64" ;;
    esac

    FFUF_URL="https://github.com/ffuf/ffuf/releases/download/${FFUF_VERSION}/ffuf_${FFUF_VERSION#v}_linux_${FFUF_ARCH}.tar.gz"
    info "URL: $FFUF_URL"

    TMP=$(mktemp -d)
    curl -fsSL "$FFUF_URL" -o "$TMP/ffuf.tar.gz"
    tar -xzf "$TMP/ffuf.tar.gz" -C "$TMP"
    $SUDO mv "$TMP/ffuf" /usr/local/bin/ffuf
    $SUDO chmod +x /usr/local/bin/ffuf
    rm -rf "$TMP"

    success "FFuF 설치 완료: $(ffuf -V 2>&1 | head -1)"
fi

# ══════════════════════════════════════════════════════════
# STEP 5 : Python 가상환경 + 패키지
# ══════════════════════════════════════════════════════════
step "5/6  Python 가상환경 및 패키지 설치"

VENV_DIR="$ARTO_DIR/.venv"

if [[ ! -d "$VENV_DIR" ]]; then
    info "가상환경 생성: $VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

# 가상환경 내 pip 업그레이드 및 패키지 설치
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install \
    fastapi \
    "uvicorn[standard]" \
    httpx \
    openai \
    python-dotenv \
    jinja2 \
    requests \
    -q

# 가상환경 소유권을 실제 사용자에게 부여
$SUDO chown -R "$REAL_USER:$REAL_USER" "$VENV_DIR"

success "Python 패키지 설치 완료 (가상환경: $VENV_DIR)"

# ══════════════════════════════════════════════════════════
# STEP 6 : run_app.sh 패치 — 가상환경 python 사용하도록
# ══════════════════════════════════════════════════════════
step "6/6  실행 스크립트 구성"

# run_app.sh가 .venv python을 사용하도록 업데이트
cat > "$ARTO_DIR/run_app.sh" << 'RUNSCRIPT'
#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
PYTHON="${VENV_PYTHON:-python3}"

# ── Docker 데몬 확인 및 자동 시작 ─────────────────────────
if ! docker info &>/dev/null 2>&1; then
    echo -e "${BLUE}[*] Docker 데몬이 실행 중이 아닙니다. 시작 시도...${NC}"
    if sudo service docker start 2>/dev/null; then
        sleep 3
    else
        echo -e "${RED}[!] Docker를 시작할 수 없습니다.${NC}"
        echo -e "    sudo service docker start  또는  Docker Desktop을 실행하세요."
        exit 1
    fi
fi

# ── ZAP 컨테이너 정리 및 시작 ─────────────────────────────
echo -e "${BLUE}[1/3] 기존 ZAP 컨테이너 정리...${NC}"
docker stop zap_main 2>/dev/null || true
docker rm   zap_main 2>/dev/null || true

echo -e "${BLUE}[2/3] OWASP ZAP 시작 (Docker)...${NC}"
docker run --net=host --name zap_main -d \
    ghcr.io/zaproxy/zaproxy:stable \
    zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

echo -e "${GREEN}[*] ZAP API 준비 대기 (약 15초)...${NC}"
for i in $(seq 15 -1 1); do
    printf "\r    남은 시간: %2ds " "$i"; sleep 1
done
echo ""

if curl -s http://127.0.0.1:8080/JSON/core/view/version/ &>/dev/null; then
    echo -e "${GREEN}[V] ZAP API 연결 성공!${NC}"
else
    echo -e "${BLUE}[!] ZAP 아직 준비 중일 수 있습니다. 계속 진행합니다.${NC}"
fi

# .env 로드
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    echo -e "${GREEN}[*] .env 로드 중...${NC}"
    set -a; source "$SCRIPT_DIR/.env"; set +a
fi

echo -e "${BLUE}[3/3] ARTO 대시보드 시작 (http://localhost:8001)...${NC}"
cd "$SCRIPT_DIR"
exec "$PYTHON" main.py
RUNSCRIPT

chmod +x "$ARTO_DIR/run_app.sh"
$SUDO chown "$REAL_USER:$REAL_USER" "$ARTO_DIR/run_app.sh"
success "run_app.sh 구성 완료"

# ── results 디렉토리 생성 ──────────────────────────────────
mkdir -p "$ARTO_DIR/results/scan" "$ARTO_DIR/results/precheck"
$SUDO chown -R "$REAL_USER:$REAL_USER" "$ARTO_DIR/results"

# ══════════════════════════════════════════════════════════
# 완료 요약
# ══════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}${BOLD}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   모든 설치가 완료되었습니다!                 ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  ${CYAN}설치된 구성요소:${NC}"
echo -e "  • Docker   : $(docker --version 2>/dev/null | cut -d' ' -f3 | tr -d ',')"
echo -e "  • ZAP      : ghcr.io/zaproxy/zaproxy:stable"
echo -e "  • FFuF     : $(ffuf -V 2>&1 | head -1 || echo '설치됨')"
echo -e "  • Python   : $($VENV_DIR/bin/python3 --version)"
echo -e "  • 가상환경 : $VENV_DIR"
echo ""
echo -e "  ${CYAN}다음 단계:${NC}"
echo -e "  ${GREEN}cd $ARTO_DIR && ./run_app.sh${NC}"
echo -e "  접속 주소  : ${GREEN}http://localhost:8001${NC}"
echo ""

if [[ "$IS_WSL" -eq 1 ]]; then
    echo -e "  ${YELLOW}WSL 참고사항:${NC}"
    echo -e "  • Docker가 자동으로 시작되지 않으면:"
    echo -e "    ${YELLOW}sudo service docker start${NC}"
    echo -e "  • docker 그룹 즉시 적용:"
    echo -e "    ${YELLOW}newgrp docker${NC}"
    echo ""
fi

if ! id -nG "$REAL_USER" | grep -qw docker; then
    warn "docker 그룹 적용을 위해 재로그인 또는 아래 명령을 실행하세요:"
    echo -e "  ${YELLOW}newgrp docker${NC}"
fi
