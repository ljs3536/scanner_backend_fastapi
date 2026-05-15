import httpx
from fastapi import APIRouter, HTTPException, Query, Response, Depends
from sqlalchemy.orm import Session
from database import get_db
import models
import json
from typing import Dict, Any
from core.config import settings
router = APIRouter(prefix="/api/sbom", tags=["SBOM"])

# 실제 분석기 엔진 주소
ANALYZER_BASE_URL = settings.analyzer_base_url

@router.get("/{sbom_id}")
async def get_sbom_data(
    sbom_id: str, 
    format: str = Query("cyclonedx-json"), 
    download: bool = Query(False) # download 파라미터 추가
):
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            # 1. 분석기 엔진에 download 옵션을 포함해서 요청
            response = await client.get(
                f"{ANALYZER_BASE_URL}/api/v1/sbom/{sbom_id}",
                params={"format": format, "download": str(download).lower()}
            )
            response.raise_for_status()
            
            # 2. 분석기가 보낸 원본 데이터와 헤더를 가져옴
            content = response.content
            content_type = response.headers.get("Content-Type", "application/json")
            content_disposition = response.headers.get("Content-Disposition")

            # 3. FastAPI의 Response 객체를 사용해 헤더를 그대로 프론트엔드에 전달
            headers = {}
            if content_disposition:
                headers["Content-Disposition"] = content_disposition

            return Response(content=content, media_type=content_type, headers=headers)

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SBOM 다운로드 통신 오류: {str(e)}")

import json # 상단에 추가

@router.get("/{sbom_id}/summary")
async def get_sbom_summary_data(sbom_id: str, db: Session = Depends(get_db)):
    """분석기 대신 우리 DB에서 SBOM 요약 정보를 우선 가져옵니다."""
    
    # 1. 우리 DB에서 해당 SBOM_ID를 가진 스캔 기록 조회
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.sbom_id == sbom_id).first()
    
    # 2. DB에 데이터가 있고, sbom_summary가 비어있지 않은 경우
    if scan and scan.sbom_summary:
        # DB에 TEXT(문자열)로 저장된 값을 파이썬 딕셔너리로 변환
        # (만약 모델에서 JSON 타입을 사용 중이라면 자동으로 변환될 수도 있지만, 
        #  TEXT 컬럼이라면 아래처럼 명시적으로 변환하는 것이 안전합니다.)
        print("summary DB 데이터")
        if isinstance(scan.sbom_summary, str):
            return json.loads(scan.sbom_summary)
        return scan.sbom_summary

    # 3. 만약 우리 DB에 없다면? (예외 케이스 대비 - Fallback)
    # 아직 동기화가 안 되었을 수도 있으니 이때만 분석기 엔진을 찌릅니다.
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(f"{ANALYZER_BASE_URL}/api/v1/sbom/{sbom_id}/summary")
            response.raise_for_status()
            summary_data = response.json()
            print("summary API 데이터")
            # 다음 조회를 위해 DB에도 업데이트해두면 좋겠죠?
            if scan:
                scan.sbom_summary = json.dumps(summary_data, ensure_ascii=False)
                db.commit()
                
            return summary_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Summary 데이터 획득 실패: {str(e)}")

@router.get("/{sbom_id}/threats")
async def get_sbom_threats_data(sbom_id: str, db: Session = Depends(get_db)):
    """DB에 저장된 위협 정보를 우선 반환하고, 없으면 분석기에서 가져옵니다."""
    
    # 1. 우리 DB부터 확인 (캐시 히트)
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.sbom_id == sbom_id).first()
    
    if scan and scan.sbom_threats:
        # JSON 문자열로 저장되어 있으므로 다시 딕셔너리로 변환해서 프론트로 전송
        print("DB데이터")
        return json.loads(scan.sbom_threats) if isinstance(scan.sbom_threats, str) else scan.sbom_threats
    # 2. DB에 없다면 (아직 배경 작업이 안 끝났거나 누락된 경우) 실시간 호출 (캐시 미스)
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(f"{ANALYZER_BASE_URL}/api/v1/sbom/{sbom_id}/threats")
            response.raise_for_status()
            threats_data = response.json()
            print("API데이터")
            # 가져온 김에 우리 DB에도 쓱 저장해둡니다.
            if scan:
                scan.sbom_threats = json.dumps(threats_data, ensure_ascii=False)
                db.commit()
                
            return threats_data
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Threats 통신 오류: {str(e)}")