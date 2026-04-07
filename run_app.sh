#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$SCRIPT_DIR/.venv/bin/python3"
if [ -x "$VENV_PYTHON" ]; then
    PYTHON="$VENV_PYTHON"
else
    PYTHON="python3"
fi

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


# .env 로드 (공백/특수문자가 있는 값도 안전하게 처리)
if [[ -f "$SCRIPT_DIR/.env" ]]; then
    echo -e "${GREEN}[*] .env 로드 중...${NC}"
    set -a; source "$SCRIPT_DIR/.env"; set +a
fi

echo -e "${BLUE}[3/3] ARTO 대시보드 시작 (http://localhost:8001)...${NC}"
cd "$SCRIPT_DIR"
exec "$PYTHON" main.py
