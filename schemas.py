from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
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


class ScanHistoryResponse(BaseModel):
    scan_seq: int
    scan_id: str
    user_seq: int
    target_name: str
    status: str
    duration_ms: int
    issues_count: int
    scan_date: datetime
    
    # 💡 데이터가 없을 수도 있는(None 허용) 필드들은 Optional[str] 처리
    summary: Optional[str] = None
    framework_detected: Optional[str] = None
    analyzers_used: Optional[str] = None
    sbom_id: Optional[str] = None
    sbom_cyclonedx_json: Optional[str] = None
    sbom_summary: Optional[str] = None

    class Config:
        from_attributes = True
    