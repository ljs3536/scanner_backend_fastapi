import os
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional
from openai import AsyncOpenAI  # 💡 비동기 OpenAI 클라이언트
from dependencies import get_current_user
import models
from core.config import settings

# slowapi 싱글톤 인스턴스 임포트
from core.limiter import check_openai_rate_limit

# DB 세션 관리를 위한 임포트
from sqlalchemy.orm import Session
from database import get_db

router = APIRouter(prefix="/api/ai", tags=["LLM-Advisory"])

# 환경변수에서 제한 값 가져오기
RATE_LIMIT_VALUE = getattr(settings, 'ai_rate_limit', '1/10minute')

# OpenAI 클라이언트 초기화 (환경 변수에서 자동으로 키를 읽어옵니다)
# API 키가 없으면 에러가 날 수 있으니 예외 처리를 해줍니다.
api_key = settings.openai_api_key
if not api_key:
    print("⚠️ 경고: OPENAI_API_KEY가 설정되지 않았습니다. AI 기능이 작동하지 않을 수 있습니다.")
openai_client = AsyncOpenAI(api_key=api_key)

# --- 스키마 정의 (기존과 동일하여 프론트엔드 수정 불필요) ---
class LiveExplainRequest(BaseModel):
    issue_seq: int
    vulnerability_type: str
    cwe_id: Optional[str] = None
    severity: str
    file_path: str
    line_number: int
    code_snippet: Optional[str] = None
    framework: Optional[str] = "Python"
    language: Optional[str] = "python"

class LiveFixRequest(BaseModel):
    issue_seq: int
    vulnerability_type: str
    cwe_id: Optional[str] = "CWE-Unknown"
    code_snippet: Optional[str] = None
    language: Optional[str] = "python"
    preserve_functionality: bool = True

# --- 1. 취약점 설명 (Explain) 라우터 ---
@router.post("/explain")
async def openai_vulnerability_explain(
    request: Request,
    payload: LiveExplainRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """OpenAI를 활용하여 취약점의 원인과 영향을 분석합니다."""

    print(">>> 🟢 [라우터 진입] Explain 로직 실행!")

    # 1️[Cache-Aside] 먼저 DB에 기존 캐시가 있는지 조회
    cached_data = db.query(models.IssueAiResponse).filter(
        models.IssueAiResponse.issue_seq == payload.issue_seq,
        models.IssueAiResponse.provider == "openai",
        models.IssueAiResponse.task_type == "explain"
    ).first()

    # 2[Cache Hit] 이미 조회한 적이 있다면 OpenAI 호출 없이 즉시 반환 (비용 0원!)
    if cached_data:
        print(f">>> 💾 [Cache Hit] Issue {payload.issue_seq}의 설명 데이터가 DB에서 바로 반환됩니다.")
        return {"explanation": cached_data.response_text}

    # 3️[Cache Miss] 캐시가 없다면 기존대로 OpenAI API 호출
    # [Cache Miss] OpenAI를 진짜 호출해야 하므로, 여기서 수동으로 Rate Limit 검사!
    check_openai_rate_limit(request)
    try:
        system_prompt = """당신은 15년 차 시니어 애플리케이션 보안 엔지니어입니다. 
                        주어진 소스코드 취약점을 분석하고, 한국어로 명확하고 전문적인 가이드를 작성해주세요.
                        응답 포맷은 반드시 마크다운을 사용하되, 다음과 같은 구조를 지켜주세요:
                        ### 취약점 개요
                        (설명)
                        ### 발생 원인 및 위험성
                        (설명)
                        """

        user_prompt = f"""
                        - 취약점 유형: {payload.vulnerability_type} ({payload.cwe_id})
                        - 심각도: {payload.severity}
                        - 언어/프레임워크: {payload.language} / {payload.framework}
                        - 파일 경로: {payload.file_path} (Line: {payload.line_number})

                        [취약한 소스 코드]
                        {payload.code_snippet or "코드 조각이 제공되지 않음"}
                        """
        
        response = await openai_client.chat.completions.create(
            model="gpt-4o", # 빠르고 저렴하게 하려면 gpt-4o-mini 추천
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3, # 💡 보안 가이드이므로 환각(Hallucination)을 줄이기 위해 온도를 낮춤
            max_tokens=1000
        )
        ai_content = response.choices[0].message.content

        # [캐시 적재] OpenAI가 정상 응답을 주었으므로, 다음 조회를 위해 DB에 저장
        new_cache = models.IssueAiResponse(
            issue_seq=payload.issue_seq,
            provider="openai",
            task_type="explain",
            response_text=ai_content
        )
        db.add(new_cache)
        db.commit()

        # 프론트엔드가 기대하는 포맷으로 감싸서 리턴
        return {"explanation": ai_content}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI 통신 오류: {str(e)}")

# --- 2. 시큐어 코딩 패치 (Fix) 라우터 ---
@router.post("/fix")
async def openai_vulnerability_fix(
    request: Request,
    payload: LiveFixRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    print(">>> 🟢 [라우터 진입] Fix 로직 실행!")
    """OpenAI를 활용하여 취약점을 수정한 안전한 소스코드를 생성합니다."""
    # 1️[Cache-Aside] DB 캐시 확인
    cached_data = db.query(models.IssueAiResponse).filter(
        models.IssueAiResponse.issue_seq == payload.issue_seq,
        models.IssueAiResponse.provider == "openai",
        models.IssueAiResponse.task_type == "fix"
    ).first()

    # 2️[Cache Hit] 존재하면 즉시 반환
    if cached_data:
        print(f">>> 💾 [Cache Hit] Issue {payload.issue_seq}의 패치 코드가 DB에서 바로 반환됩니다.")
        return {"explanation": cached_data.response_text}

    # 3️[Cache Miss] OpenAI 호출
    # [Cache Miss] OpenAI를 진짜 호출해야 하므로, 여기서 수동으로 Rate Limit 검사!
    check_openai_rate_limit(request)
    try:
        system_prompt = """당신은 시큐어 코딩 전문가입니다.
                        주어진 취약한 코드를 분석하여 보안 결함이 완벽히 해결된 안전한 코드를 작성해주세요.
                        기존의 비즈니스 로직(기능)은 반드시 그대로 유지해야 합니다.
                        응답 포맷:
                        ### 시큐어 코딩 적용 방안
                        (어떻게 고쳤는지 핵심 원리 1~2줄 설명)
                        ### 패치된 소스코드
                        (마크다운 코드 블록으로 작성)
                        """

        user_prompt = f"""
                        - 취약점 유형: {payload.vulnerability_type} ({payload.cwe_id})
                        - 언어: {payload.language}

                        [수정해야 할 취약한 코드]
                        {payload.code_snippet or "수정할 코드가 없습니다."}
                        """

    
        response = await openai_client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.1, # 코드는 창의성보다 정확성이 생명!
            max_tokens=1500
        )
        
        ai_content = response.choices[0].message.content

        # 4️[캐시 적재] DB에 결과 저장
        new_cache = models.IssueAiResponse(
            issue_seq=payload.issue_seq,
            provider="openai",
            task_type="fix",
            response_text=ai_content
        )
        db.add(new_cache)
        db.commit()

        return {"explanation": ai_content}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI 패치 생성 오류: {str(e)}")