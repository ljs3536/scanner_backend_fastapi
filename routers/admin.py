import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from database import get_db
from dependencies import get_admin_user
from routers.auth import get_password_hash  # 기존 auth.py에 있는 패스워드 암호화 함수 사용
import models
import schemas

# 💡 라우터 입구에서 get_admin_user 필터를 걸어 권한이 없는 계정은 접근을 원천 차단합니다.
router = APIRouter(
    prefix="/api/admin",
    tags=["Admin-Management"],
    dependencies=[Depends(get_admin_user)]
)

@router.get("/users")
async def list_all_users(db: Session = Depends(get_db)):
    """시스템의 모든 사용자 계정 목록을 조회합니다."""
    users = db.query(models.User).all()
    return [
        {
            "user_seq": u.user_seq,
            "user_id": u.user_id,
            "email": u.email,
            "role": u.role,
            "created_at": u.created_at
        } for u in users
    ]

@router.post("/users")
async def create_new_user_by_admin(payload: schemas.UserCreateByAdmin, db: Session = Depends(get_db)):
    """관리자가 새로운 사용자 계정을 강제로 생성합니다."""
    # 1. 이메일 중복 체크
    existing_user = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="이미 시스템에 등록된 이메일 주소입니다."
        )

    # 2. 계정 생성 (패스워드 암호화 적용)
    hashed_pwd = get_password_hash(payload.password)
    new_user = models.User(
        email=payload.email,
        user_id=payload.user_id,
        password=hashed_pwd,
        role=payload.role.upper()  # USER or ADMIN
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": f"성공적으로 '{new_user.user_id}' 계정이 생성되었습니다.",
        "email": new_user.email,
        "role": new_user.role
    }

@router.get("/dashboard/stats")
async def get_admin_dashboard_stats(db: Session = Depends(get_db)):
    """관리자 메인 대시보드용 전체 시스템 통계 지표를 반환합니다."""
    
    # 1. 시스템 핵심 메트릭 통합 카운트
    total_users = db.query(models.User).count()
    total_scans = db.query(models.ScanHistory).count()
    total_issues = db.query(models.Issue).count()
    
    # 2. 최근 가입한 유저 정보 5건 추출 (name 대신 user_id 반영)
    recent_users = db.query(models.User)\
                     .order_by(models.User.created_at.desc())\
                     .limit(5).all()
                     
    # 3. 최근 발생한 마스터 스캔 이력 5건 추출
    recent_scans = db.query(models.ScanHistory)\
                     .order_by(models.ScanHistory.scan_date.desc())\
                     .limit(5).all()

    return {
        "summary": {
            "total_users": total_users,
            "total_scans": total_scans,
            "total_issues": total_issues
        },
        "recent_users": [
            {
                "user_seq": u.user_seq,
                "user_id": u.user_id, # 💡 name 대신 user_id 반영
                "role": u.role,
                "created_at": u.created_at
            } for u in recent_users
        ],
        "recent_scans": [
            {
                "scan_id": s.scan_id,
                "target_name": s.target_name,
                "issues_count": s.issues_count,
                "scan_date": s.scan_date
            } for s in recent_scans
        ]
    }