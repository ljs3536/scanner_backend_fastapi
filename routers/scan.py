import uuid
import httpx
from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException
from sqlalchemy.orm import Session
from database import get_db
import models
from dependencies import get_current_user
import random
import json
from core.config import settings
router = APIRouter(
    prefix="/api/scans",
    tags=["Scans"]
)

ANALYZER_BASE_URL = settings.analyzer_base_url

# 그럴싸한 가짜 취약점 데이터 풀(Pool)
MOCK_VULNERABILITIES = [
    {"title": "SQL 인젝션 (SQL Injection)", "severity": "HIGH", "cwe": "CWE-89", "rule": "java.lang.security.audit.SQLInjection", "file": "src/main/java/com/demo/UserController.java", "desc": "사용자 입력값이 쿼리에 직접 결합되어 SQL 인젝션 공격에 취약합니다."},
    {"title": "크로스 사이트 스크립팅 (XSS)", "severity": "HIGH", "cwe": "CWE-79", "rule": "java.lang.security.audit.XSS", "file": "src/main/webapp/views/index.jsp", "desc": "검증되지 않은 사용자 입력이 화면에 출력되어 XSS 공격에 노출될 수 있습니다."},
    {"title": "하드코딩된 비밀번호", "severity": "MEDIUM", "cwe": "CWE-798", "rule": "config.security.HardcodedSecret", "file": "src/main/resources/application.yml", "desc": "소스코드 내에 중요한 인증 정보나 비밀번호가 하드코딩되어 있습니다."},
    {"title": "안전하지 않은 해시 알고리즘", "severity": "LOW", "cwe": "CWE-327", "rule": "java.security.WeakHash", "file": "src/main/java/com/demo/utils/HashUtil.java", "desc": "MD5 또는 SHA-1과 같은 취약한 해시 알고리즘을 사용하고 있습니다."},
    {"title": "디버그 모드 활성화", "severity": "INFO", "cwe": "CWE-489", "rule": "config.debug.Enabled", "file": "src/main/java/com/demo/Application.java", "desc": "상용 환경에서 디버그 모드가 활성화되어 있어 내부 정보가 유출될 수 있습니다."}
]

@router.post("/run")
async def run_mock_scan(target_name: str, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    # 1. 실제 분석하는 것처럼 2~4초 대기 (프론트엔드 로딩 스피너 테스트용)
    await asyncio.sleep(random.uniform(2.0, 4.0))

    # 2. 스캔 이력(scan_histories) 생성
    new_scan = models.ScanHistory(
        scan_id=f"SCAN-{uuid.uuid4().hex[:8].upper()}",
        user_seq=current_user.user_seq,
        target_name=target_name,
        status="COMPLETED",
        duration_ms=random.randint(15000, 120000), # 15초 ~ 2분 소요된 척
        framework_detected="Java/Spring Boot",
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 3. 랜덤하게 3 ~ 10개의 취약점(issues) 생성
    issue_count = random.randint(3, 10)
    for _ in range(issue_count):
        mock_vuln = random.choice(MOCK_VULNERABILITIES)
        new_issue = models.Issue(
            issue_id=f"ISSUE-{uuid.uuid4().hex[:8].upper()}",
            scan_seq=new_scan.scan_seq,
            issue_title=mock_vuln["title"],
            severity=mock_vuln["severity"],
            confidence=round(random.uniform(0.6, 0.99), 2),
            description=mock_vuln["desc"],
            rule_id=mock_vuln["rule"],
            cwe_id=mock_vuln["cwe"],
            file_path=mock_vuln["file"],
            line_number=random.randint(10, 500)
        )
        db.add(new_issue)
    
    # 생성된 취약점 개수 업데이트 및 커밋
    new_scan.issues_count = issue_count
    db.commit()

    return {
        "message": "스캔이 성공적으로 완료되었습니다.",
        "scan_id": new_scan.scan_id,
        "issues_found": issue_count
    }

@router.post("/run-file")
async def run_real_file_scan(
    file: UploadFile = File(...), 
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    # 1. 스캐너 엔진으로 보낼 파일 준비
    files = {'file': (file.filename, await file.read(), file.content_type)}
    params = {"min_severity": "LOW", "min_confidence": 0.5}

    try:
        # 2. 진짜 분석기 API 호출 (스캔이 오래 걸릴 수 있으므로 timeout을 넉넉히 5분으로 설정)
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{ANALYZER_BASE_URL}/api/v1/scan/file", 
                files=files, 
                params=params
            )
            response.raise_for_status() # 400, 500 에러시 예외 발생
            scan_result = response.json() # 분석기가 뱉은 진짜 결과 데이터!

    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"분석기 엔진과 통신할 수 없습니다: {str(e)}")

    # 3. 분석기 결과를 우리 DB(MariaDB) 구조에 맞게 매핑해서 저장
    new_scan = models.ScanHistory(
        scan_id=scan_result["scan_id"],
        user_seq=current_user.user_seq,
        target_name=file.filename,
        status=scan_result["status"].upper(), # 'completed' -> 'COMPLETED'
        duration_ms=scan_result["duration_ms"],
        issues_count=scan_result["issues_count"],
        framework_detected=scan_result.get("framework_detected", "Unknown"),
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 4. 개별 취약점(Issues) 저장
    for issue_data in scan_result.get("issues", []):
        new_issue = models.Issue(
            issue_id=issue_data["id"],
            scan_seq=new_scan.scan_seq,
            issue_title=issue_data["type"],
            severity=issue_data["severity"],
            confidence=issue_data["confidence"],
            description=issue_data["message"],
            rule_id=issue_data["rule_id"],
            cwe_id=issue_data.get("cwe"),   # 분석기에서 넘겨주는 CWE 정보 매핑
            owasp_id=issue_data.get("owasp"),
            file_path=issue_data["file"],
            line_number=issue_data["line"]
        )
        db.add(new_issue)
    
    db.commit()

    # 5. 프론트엔드로 최종 결과 응답
    return {
        "message": "스캔이 성공적으로 완료되었습니다.",
        "scan_id": new_scan.scan_id,
        "issues_found": new_scan.issues_count
    }


@router.post("/run-upload")
async def run_multiple_files_scan(
    # 프론트엔드에서 넘어오는 다중 파일 및 옵션들
    files: List[UploadFile] = File(...),
    llm_advisory: bool = Form(False),
    generate_sbom: bool = Form(False),
    profile: str = Form("security_core"),
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. httpx가 인식할 수 있는 다중 파일 전송 포맷으로 변환
    httpx_files = []
    for file in files:
        content = await file.read()
        # ('필드명', (파일명, 파일내용, MIME타입))
        httpx_files.append(("files", (file.filename, content, file.content_type)))

    # 2. 분석기 엔진으로 보낼 Form 데이터
    form_data = {
        "llm_verify": "false",
        "llm_filter_fp": "false",
        "llm_advisory": str(llm_advisory).lower(), # FastAPI는 'true', 'false' 문자열을 bool로 자동 파싱합니다.
        "generate_sbom": str(generate_sbom).lower(),
        "profile": profile,
        "llm_max_issues": "20"
    }

    try:
        # 3. 진짜 분석기 API 호출
        async with httpx.AsyncClient(timeout=300.0) as client:
            response = await client.post(
                f"{ANALYZER_BASE_URL}/api/v1/scan/upload",
                files=httpx_files,
                data=form_data
            )
            response.raise_for_status()
            scan_result = response.json()
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"분석기 엔진과 통신할 수 없습니다: {str(e)}")

    def safe_json(data):
        """데이터가 dict나 list면 JSON 문자열로 변환하고, 없으면 None 반환"""
        if data is None:
            return None
        # 문자열이 아닌 객체(dict, list)만 변환
        return json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data
    # 4. 파일이 여러 개일 경우를 대비한 target_name 처리
    target_name = files[0].filename if len(files) == 1 else f"{files[0].filename} 외 {len(files)-1}건"

    # DB 저장 (scan_histories)
    new_scan = models.ScanHistory(
        scan_id=scan_result.get("scan_id", f"SCAN-{uuid.uuid4().hex[:8].upper()}"),
        user_seq=current_user.user_seq,
        target_name=target_name,
        status="COMPLETED",
        duration_ms=scan_result.get("duration_ms", 0),
        issues_count=scan_result.get("issues_count", 0),
        framework_detected=scan_result.get("framework_detected", "Unknown"),
        # 분석기 엔진의 새 필드들 매핑
        summary=safe_json(scan_result.get("summary")),
        analyzers_used=safe_json(scan_result.get("analyzers_used")),
        llm_verification=safe_json(scan_result.get("llm_verification")),
        llm_fp_advisory=safe_json(scan_result.get("llm_fp_advisory")),
        
        # SBOM 데이터 (이게 핵심!)
        sbom_id=scan_result.get("sbom_id"),
        sbom_cyclonedx_json=safe_json(scan_result.get("sbom_cyclonedx_json")),
        sbom_summary=safe_json(scan_result.get("sbom_summary")),
        sbom_status=scan_result.get("sbom_status"),
        sbom_error=scan_result.get("sbom_error"),
        
        # 컨텍스트 정보
        source_kind=scan_result.get("source_kind"),
        analysis_scope=scan_result.get("analysis_scope"),
        project_context_applied=scan_result.get("project_context_applied"),
        project_context_reason=scan_result.get("project_context_reason"),
        project_context_root=scan_result.get("project_context_root"),
        profile=scan_result.get("profile")
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 개별 취약점(Issues) 저장 로직은 이전과 동일
    for issue_data in scan_result.get("issues", []):
        new_issue = models.Issue(
            issue_id=issue_data.get("id", f"ISSUE-{uuid.uuid4().hex[:8].upper()}"),
            scan_seq=new_scan.scan_seq,
            issue_title=issue_data.get("type"),
            severity=issue_data.get("severity"),
            confidence=issue_data.get("confidence"),
            description=issue_data.get("message"),
            rule_id=issue_data.get("rule_id"),
            cwe_id=issue_data.get("cwe"),
            owasp_id=issue_data.get("owasp"),
            file_path=issue_data.get("file"),
            line_number=issue_data.get("line")
        )
        db.add(new_issue)
    
    db.commit()

    return {
        "message": "다중 파일 스캔이 완료되었습니다.",
        "scan_id": new_scan.scan_id,
        "issues_found": new_scan.issues_count
    }