import time
from fastapi import Request, HTTPException, status

_request_history = {}
LIMIT_COUNT = 1
LIMIT_WINDOW_SEC = 600

def check_openai_rate_limit(request: Request):
    """
    OpenAI API를 실제로 호출하기 직전에만 수동으로 체크하는 함수
    """
    forwarded = request.headers.get("X-Forwarded-For")
    client_ip = forwarded.split(",")[0] if forwarded else (request.client.host if request.client else "127.0.0.1")
    
    now = time.time()
    if client_ip not in _request_history:
        _request_history[client_ip] = []

    # 과거 기록 청소
    _request_history[client_ip] = [
        timestamp for timestamp in _request_history[client_ip]
        if now - timestamp < LIMIT_WINDOW_SEC
    ]

    # 카운트 비교 및 차단
    if len(_request_history[client_ip]) >= LIMIT_COUNT:
        print(f">>> 🚨 [차단] IP {client_ip} OpenAI 실제 호출 한도 초과!", flush=True)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="AI API 호출 한도를 초과했습니다. 1분 후 다시 시도해주세요."
        )

    # 안전하면 현재 시간 기록
    _request_history[client_ip].append(now)