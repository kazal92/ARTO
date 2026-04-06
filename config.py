import os

# LM Studio / OpenAI-compatible AI 백엔드
LM_STUDIO_API_URL: str = os.getenv("LM_STUDIO_API_URL", "http://192.168.1.100:1234/v1")
LM_STUDIO_MODEL: str   = os.getenv("LM_STUDIO_MODEL",   "qwen/qwen3.5-9b")

# OWASP ZAP REST API
ZAP_BASE_URL: str = os.getenv("ZAP_BASE_URL", "http://localhost:8080")

# ARTO 서버 바인딩
ARTO_HOST: str = os.getenv("ARTO_HOST", "0.0.0.0")
ARTO_PORT: int = int(os.getenv("ARTO_PORT", "8001"))

# AI 요청 압축 (헤더/바디 최소화)
ENABLE_REQUEST_COMPRESSION: bool = os.getenv("ENABLE_REQUEST_COMPRESSION", "true").lower() == "true"
