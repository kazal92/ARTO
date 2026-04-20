import os

# LM Studio / OpenAI-compatible AI 백엔드
LM_STUDIO_API_URL: str = os.getenv("LM_STUDIO_API_URL", "http://192.168.1.100:1234/v1")
LM_STUDIO_MODEL: str   = os.getenv("LM_STUDIO_MODEL",   "google_gemma-4-26b-a4b-it")

# OWASP ZAP REST API
ZAP_BASE_URL: str = os.getenv("ZAP_BASE_URL", "http://localhost:8080")

# ARTO 서버 바인딩
ARTO_HOST: str = os.getenv("ARTO_HOST", "0.0.0.0")
ARTO_PORT: int = int(os.getenv("ARTO_PORT", "8001"))

# AI 요청 압축 (헤더/바디 최소화)
ENABLE_REQUEST_COMPRESSION: bool = os.getenv("ENABLE_REQUEST_COMPRESSION", "true").lower() == "true"

# AI 분석 배치 크기 (토큰 절약용, Gemini는 별도 처리)
AI_MAX_BATCH_SIZE: int = int(os.getenv("AI_MAX_BATCH_SIZE", "8000"))

# Alive/Shodan/Dork 체크 동시 처리 제한
ALIVE_CHECK_SEMAPHORE: int = int(os.getenv("ALIVE_CHECK_SEMAPHORE", "20"))
DORK_CHECK_SEMAPHORE: int  = int(os.getenv("DORK_CHECK_SEMAPHORE", "10"))

# 펜테스트 에이전트 최대 반복 횟수
MAX_AGENT_ITERATIONS: int = int(os.getenv("MAX_AGENT_ITERATIONS", "50"))

# 명령어 출력 최대 길이 (문자 수)
MAX_COMMAND_OUTPUT: int = int(os.getenv("MAX_COMMAND_OUTPUT", "8000"))
