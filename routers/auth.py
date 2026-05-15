from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
import models, schemas
from database import get_db
from core.security import get_password_hash, verify_password, create_access_token

router = APIRouter(
    prefix="/api/auth",
    tags=["Auth"]
)

@router.post("/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(user: schemas.UserCreate, db: Session = Depends(get_db)):

    print(user.password)
    # 1. 아이디 중복 체크
    db_user = db.query(models.User).filter(models.User.user_id == user.user_id).first()
    if db_user:
        raise HTTPException(status_code=400, detail="이미 존재하는 아이디입니다.")
        
    # 2. 이메일 중복 체크 (옵션, 필요시 사용)
    db_email = db.query(models.User).filter(models.User.email == user.email).first()
    if db_email:
        raise HTTPException(status_code=400, detail="이미 가입된 이메일입니다.")

    # 3. 비밀번호 암호화
    hashed_password = get_password_hash(user.password)

    # 4. DB에 저장할 모델 생성
    new_user = models.User(
        user_id=user.user_id,
        email=user.email,
        password=hashed_password,
        role="USER" # 데모 테스터는 기본 USER 권한
    )

    # 5. DB 저장 및 커밋
    db.add(new_user)
    db.commit()
    db.refresh(new_user) # DB에서 생성된 user_seq 등을 다시 가져옴

    # 6. 결과 반환 (schemas.UserResponse 형태로 자동 필터링되어 비밀번호는 빠짐)
    return new_user

@router.post("/login")
def login(user_credentials: schemas.UserCreate, db: Session = Depends(get_db)):
    # 1. 유저 존재 확인
    user = db.query(models.User).filter(models.User.user_id == user_credentials.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 잘못되었습니다.")

    # 2. 비밀번호 검증
    if not verify_password(user_credentials.password, user.password):
        raise HTTPException(status_code=401, detail="아이디 또는 비밀번호가 잘못되었습니다.")

    # 3. 토큰 생성 (user_id를 담아서 발급)
    access_token = create_access_token(data={"sub": user.user_id, "role": user.role})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.user_id,
        "role": user.role
    }