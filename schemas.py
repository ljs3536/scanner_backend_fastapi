from pydantic import BaseModel, EmailStr, Field
from datetime import datetime

# 회원가입 시 프론트엔드에서 받아올 데이터
class UserCreate(BaseModel):
    user_id: str
    email: EmailStr  # 자동으로 이메일 형식(aa@bb.com)인지 검증해 줍니다
    password: str = Field(..., max_length=50)

# 회원가입 성공 시 프론트엔드로 돌려줄 데이터 (비밀번호 제외)
class UserResponse(BaseModel):
    user_seq: int
    user_id: str
    email: str
    role: str
    created_at: datetime

    class Config:
        from_attributes = True  # SQLAlchemy 모델을 Pydantic 모델로 자동 변환