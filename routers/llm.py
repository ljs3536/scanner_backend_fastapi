import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from typing import Optional, Dict, Any
from dependencies import get_current_user
import models
from core.config import settings
router = APIRouter(prefix="/api/llm", tags=["LLM-Advisory"])
ANALYZER_BASE_URL = settings.analyzer_base_url

# 분석기 요구 사양 스펙에 맞춘 스키마 정의
class LiveExplainRequest(BaseModel):
    vulnerability_type: str
    cwe_id: Optional[str] = None
    severity: str
    file_path: str
    line_number: int
    code_snippet: Optional[str] = None
    data_flow: Optional[str] = None
    framework: Optional[str] = "Python"
    language: Optional[str] = "python"
    include_remediation: bool = True

class LiveFixRequest(BaseModel):
    vulnerability_type: str
    cwe_id: Optional[str] = "CWE-Unknown"
    code_snippet: Optional[str] = None
    language: Optional[str] = "python"
    preserve_functionality: bool = True

@router.post("/explain")
async def proxy_vulnerability_explain(
    payload: LiveExplainRequest,
    current_user: models.User = Depends(get_current_user)
):
    """실제 분석기 엔진의 LLM Advisory API로 요청을 위임합니다."""
    analyzer_payload = payload.model_dump()

    try:
        async with httpx.AsyncClient(timeout=180.0) as client: # LLM 생성이므로 타임아웃 넉넉히 설정
            response = await client.post(
                f"{ANALYZER_BASE_URL}/api/v1/llm/explain",
                json=analyzer_payload
            )
            response.raise_for_status()
            return response.json() # 분석기가 리턴한 LLMResponse 포맷 그대로 전달
            
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="AI 엔진에서 가이드를 생성하지 못했습니다.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 라우터 외부 통신 장애: {str(e)}")
    
@router.post("/fix")
async def proxy_vulnerability_fix(
    payload: LiveFixRequest,
    current_user: models.User = Depends(get_current_user)
):
    """실제 분석기 엔진의 AI Fix 코딩 생성 API로 요청을 위임합니다."""
    analyzer_payload = payload.model_dump()

    try:
        async with httpx.AsyncClient(timeout=180.0) as client:
            response = await client.post(
                f"{ANALYZER_BASE_URL}/api/v1/llm/fix",
                json=analyzer_payload
            )
            response.raise_for_status()
            return response.json()
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI 패치 엔진 통신 오류: {str(e)}")