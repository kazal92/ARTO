#!/bin/bash

# 색상 정의
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}[1/3] 기존 ZAP 컨테이너 정리 중...${NC}"
docker stop zap_main 2>/dev/null || true
docker rm zap_main 2>/dev/null || true

echo -e "${BLUE}[2/3] OWASP ZAP 시작 중 (Docker)...${NC}"
# --net=host 모드로 실행하여 호스트의 8080 포트를 직접 사용 (안정성 확보)
docker run --net=host --name zap_main -d ghcr.io/zaproxy/zaproxy:stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true

echo -e "${GREEN}[*] ZAP API가 준비될 때까지 잠시 대기합니다 (약 15초)...${NC}"
sleep 15

# ZAP 상태 확인 (옵션)
curl -s http://127.0.0.1:8080/JSON/core/view/version/ > /dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[V] ZAP API 연결 성공!${NC}"
else
    echo -e "${BLUE}[!] ZAP이 아직 준비되지 않았을 수 있습니다. 계속 진행합니다.${NC}"
fi

if [ -f .env ]; then
    echo -e "${GREEN}[*] .env 환경 변수 로드 중...${NC}"
    # 주석 제외하고 로드
    export $(grep -v '^#' .env | xargs)
fi

echo -e "${BLUE}[3/3] 메인 애플리케이션 시작 중 (http://localhost:8001)...${NC}"
python3 main.py
