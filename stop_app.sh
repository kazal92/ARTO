#!/bin/bash

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${BLUE}╔═══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        ARTO 대시보드 중지 스크립트        ║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════╝${NC}"
echo ""

# ── ARTO 프로세스 정지 ────────────────────────────────
echo -e "${BLUE}[1/2] ARTO 프로세스 종료 중...${NC}"

# PID 파일로 프로세스 종료 시도
PID_FILE="$SCRIPT_DIR/.arto.pid"
if [[ -f "$PID_FILE" ]]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        kill "$PID" 2>/dev/null && echo -e "${GREEN}[V] ARTO 프로세스 종료됨 (PID: $PID)${NC}" || echo -e "${YELLOW}[!] ARTO 프로세스 종료 실패${NC}"
    fi
    rm "$PID_FILE" 2>/dev/null
fi

# 포트 기반으로 프로세스 정지 (8001 포트)
PIDS=$(lsof -ti:8001 2>/dev/null || netstat -tln 2>/dev/null | grep 8001 | awk '{print $NF}')
if [[ -n "$PIDS" ]]; then
    for PID in $PIDS; do
        kill "$PID" 2>/dev/null && echo -e "${GREEN}[V] 포트 8001 점유 프로세스 종료됨 (PID: $PID)${NC}"
    done
fi

# uvicorn/gunicorn 프로세스 검색 및 종료
ARTO_PIDS=$(pgrep -f "arto|uvicorn.*8001|gunicorn.*8001" 2>/dev/null | grep -v "$$" | head -5)
if [[ -n "$ARTO_PIDS" ]]; then
    for PID in $ARTO_PIDS; do
        if ps -p "$PID" > /dev/null 2>&1; then
            kill "$PID" 2>/dev/null && echo -e "${GREEN}[V] ARTO 프로세스 종료됨 (PID: $PID)${NC}"
        fi
    done
fi

sleep 1

# ── ZAP 컨테이너 정지 ────────────────────────────────
echo -e "${BLUE}[2/2] ZAP 컨테이너 정지 중...${NC}"

if docker ps -a --format '{{.Names}}' | grep -q '^zap_main$'; then
    if docker stop zap_main 2>/dev/null; then
        echo -e "${GREEN}[V] ZAP 컨테이너 정지됨${NC}"
    else
        echo -e "${YELLOW}[!] ZAP 컨테이너 정지 실패${NC}"
    fi
    
    # 정리 옵션: -r 플래그로 컨테이너도 제거
    if [[ "$1" == "-r" || "$1" == "--remove" ]]; then
        if docker rm zap_main 2>/dev/null; then
            echo -e "${GREEN}[V] ZAP 컨테이너 제거됨${NC}"
        fi
    fi
else
    echo -e "${YELLOW}[*] ZAP 컨테이너가 실행 중이 아님${NC}"
fi

# ── 최종 상태 확인 ────────────────────────────────
echo ""
echo -e "${BLUE}[*] 최종 상태 확인...${NC}"

ARTO_CHECK=$(lsof -ti:8001 2>/dev/null)
ZAP_CHECK=$(docker ps --format '{{.Names}}' 2>/dev/null | grep '^zap_main$')

if [[ -z "$ARTO_CHECK" ]]; then
    echo -e "${GREEN}[V] 포트 8001: 사용 가능${NC}"
else
    echo -e "${RED}[!] 포트 8001: 여전히 점유 중 (강제 종료 필요)${NC}"
fi

if [[ -z "$ZAP_CHECK" ]]; then
    echo -e "${GREEN}[V] ZAP 컨테이너: 정지됨${NC}"
else
    echo -e "${RED}[!] ZAP 컨테이너: 여전히 실행 중${NC}"
fi

echo ""
echo -e "${GREEN}[V] ARTO 중지 작업 완료!${NC}"
echo ""
echo -e "${BLUE}옵션:${NC}"
echo -e "  ${BLUE}./stop_app.sh${NC}           - ARTO 및 ZAP 정지"
echo -e "  ${BLUE}./stop_app.sh -r${NC}        - ZAP 컨테이너까지 제거"
echo -e "  ${BLUE}./stop_app.sh --remove${NC}  - ZAP 컨테이너까지 제거"
echo ""
