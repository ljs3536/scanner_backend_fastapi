import bcrypt
from datetime import datetime, timedelta
from typing import Optional
from jose import jwt
from core.config import settings
# 보안 설정
SECRET_KEY = settings.secret_key 
ALGORITHM = settings.algorithm
ACCESS_TOKEN_EXPIRE_MINUTES =  60 * 24 

def get_password_hash(password: str) -> str:
    """평문 비밀번호를 bcrypt로 해싱합니다."""
    # bcrypt는 바이트(bytes) 단위를 요구하므로 문자열을 인코딩합니다.
    pwd_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(pwd_bytes, salt)
    # DB에는 문자열(VARCHAR)로 저장해야 하므로 다시 디코딩해서 반환합니다.
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """평문 비밀번호와 DB의 해시 비밀번호를 비교합니다."""
    # 비교할 때도 둘 다 바이트 형태로 맞춰주어야 합니다.
    password_byte_enc = plain_password.encode('utf-8')
    hashed_password_byte_enc = hashed_password.encode('utf-8')
    
    return bcrypt.checkpw(password_byte_enc, hashed_password_byte_enc)

# JWT 토큰 생성 함수 (이전과 동일)
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt