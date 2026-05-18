# 파이썬 3.11 환경
FROM python:3.11-slim

WORKDIR /app

# 시스템 패키지 업데이트 및 빌드 필수 도구 설치 (필요시)
RUN apt-get update && apt-get install -y gcc

# 패키지 설치
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 소스코드 복사
COPY . .

# Uvicorn 서버를 0.0.0.0으로 개방하여 실행
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]