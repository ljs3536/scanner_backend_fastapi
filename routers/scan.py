import uuid
import httpx
from typing import List, Optional
from fastapi import APIRouter, Depends, UploadFile, File, Form, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from database import get_db, SessionLocal
import models
from dependencies import get_current_user
import random
import json
from core.config import settings
import schemas
from pydantic import BaseModel

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

@router.get("/history", response_model=List[schemas.ScanHistoryResponse])
def get_scan_history(
    db: Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    # 현재 로그인한 사용자의 스캔 이력을 최신순으로 조회
    scans = db.query(models.ScanHistory)\
              .filter(models.ScanHistory.user_seq == current_user.user_seq)\
              .order_by(models.ScanHistory.scan_date.desc())\
              .all()
    return scans

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

async def sync_sbom_threats(sbom_id: str, scan_seq: int):
    """배경에서 분석기의 SBOM 위협(Threats) 정보를 가져와 DB를 업데이트합니다."""
    # 배경 작업은 별도의 DB 세션을 열고 닫아야 안전합니다.
    db = SessionLocal()
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(f"{ANALYZER_BASE_URL}/api/v1/sbom/{sbom_id}/threats")
            
            if response.status_code == 200:
                threats_data = response.json()
                
                # DB 업데이트
                scan = db.query(models.ScanHistory).filter(models.ScanHistory.scan_seq == scan_seq).first()
                if scan:
                    # 안전하게 JSON 문자열로 변환하여 저장
                    scan.sbom_threats = json.dumps(threats_data, ensure_ascii=False)
                    db.commit()
    except Exception as e:
        print(f"Background Task Error (SBOM Threats Sync): {e}")
    finally:
        db.close()

@router.post("/run-upload")
async def run_multiple_files_scan(
    # 프론트엔드에서 넘어오는 다중 파일 및 옵션들
    background_tasks: BackgroundTasks,
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
            #print(scan_result)
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
        
        # 신규 자산 정보 매핑
        source_ip=scan_result.get("source_ip"),
        source_user_agent=scan_result.get("source_user_agent"),

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
        #print(issue_data)
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
            line_number=issue_data.get("line"),

            column=issue_data.get("column", 1),
            analyzer=issue_data.get("analyzer"),
            code_snippet=issue_data.get("code_snippet"),
            recommendation=issue_data.get("recommendation"),
            language=issue_data.get("language"),
            
            # 한국어 최적화 및 조치 가이드 데이터
            type_ko=issue_data.get("type_ko"),
            severity_ko=issue_data.get("severity_ko"),
            detection_reason_ko=issue_data.get("detection_reason_ko"),
            fix_description_ko=issue_data.get("fix_description_ko"),
            fix_code=issue_data.get("fix_code")
        )
        db.add(new_issue)
    
    db.commit()

    if new_scan.sbom_id:
        background_tasks.add_task(
            sync_sbom_threats, 
            new_scan.sbom_id, 
            new_scan.scan_seq
        )

    return {
        "message": "다중 파일 스캔이 완료되었습니다.",
        "scan_id": new_scan.scan_id,
        "issues_found": new_scan.issues_count
    }

class CodeScanRequest(BaseModel):
    code: str
    filename: str
    profile: Optional[str] = "security_core"


@router.post("/run-code")
async def run_code_snippet_scan(
    payload: CodeScanRequest,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. 코어 분석기 엔진의 코드 스캔 API 스펙에 맞춰 데이터 구성
    analyzer_payload = {
        "code": payload.code,
        "filename": payload.filename,
        "profile": payload.profile
    }

    try:
        # 2. 진짜 분석기 엔진의 /code 엔드포인트 호출
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{ANALYZER_BASE_URL}/api/v1/scan/code",
                json=analyzer_payload
            )
            response.raise_for_status()
            scan_result = response.json() # 분석기가 리턴한 ScanResult 딕셔너리
            
    except httpx.RequestError as e:
        raise HTTPException(status_code=500, detail=f"분석기 엔진과 통신할 수 없습니다: {str(e)}")

    # 💡 안전한 JSON 문자열 변환 헬퍼 (이전 구현 연동)
    def safe_json(data):
        if data is None: return None
        return json.dumps(data, ensure_ascii=False) if not isinstance(data, str) else data

    # 3. 분석기 결과를 우리 MariaDB 스키마(scan_histories)에 매핑하여 저장
    new_scan = models.ScanHistory(
        scan_id=scan_result.get("scan_id"),
        user_seq=current_user.user_seq,
        target_name=scan_result.get("target", payload.filename),
        status=scan_result.get("status", "COMPLETED").upper(),
        duration_ms=int(scan_result.get("duration_ms", 0)),
        issues_count=scan_result.get("issues_count", 0),
        
        # 신규 자산 정보 매핑
        source_ip=scan_result.get("source_ip"),
        source_user_agent=scan_result.get("source_user_agent"),

        # 가공 정보들을 safe_json으로 변환하여 유실 없이 적재
        summary=safe_json(scan_result.get("summary")),
        analyzers_used=safe_json(scan_result.get("analyzers_used")),
        llm_verification=safe_json(scan_result.get("llm_verification")),
        llm_fp_advisory=safe_json(scan_result.get("llm_fp_advisory")),
        
        # 코드 스캔은 오픈소스 종속성 검사(SBOM)가 없으므로 NULL 데이터로 채워짐
        sbom_id=None,
        source_kind=scan_result.get("source_kind", "code_scan"),
        analysis_scope=scan_result.get("analysis_scope", "snippet"),
        project_context_applied=scan_result.get("project_context_applied", False),
        profile=scan_result.get("profile", payload.profile)
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)

    # 4. 발견된 취약점(Issues) 리스트 파싱 및 데이터 적재
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
            file_path=issue_data.get("file", payload.filename),
            line_number=issue_data.get("line", 1),

            column=issue_data.get("column", 1),
            analyzer=issue_data.get("analyzer"),
            code_snippet=issue_data.get("code_snippet"),
            recommendation=issue_data.get("recommendation"),
            language=issue_data.get("language"),
            
            # 한국어 최적화 및 조치 가이드 데이터
            type_ko=issue_data.get("type_ko"),
            severity_ko=issue_data.get("severity_ko"),
            detection_reason_ko=issue_data.get("detection_reason_ko"),
            fix_description_ko=issue_data.get("fix_description_ko"),
            fix_code=issue_data.get("fix_code")
        )
        db.add(new_issue)
    
    db.commit()

    return {
        "message": "코드 조각 스캔이 완료되었습니다.",
        "scan_id": new_scan.scan_id,
        "issues_found": new_scan.issues_count
    }

@router.get("/report/{scan_id}")
async def get_scan_report(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user)
):
    # 1. 스캔 마스터 기록 조회
    scan = db.query(models.ScanHistory).filter(models.ScanHistory.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="해당 스캔 기록을 찾을 수 없습니다.")
    
    # 보안 정책: 본인의 스캔 기록만 볼 수 있도록 검증
    if scan.user_seq != current_user.user_seq:
        raise HTTPException(status_code=403, detail="해당 리포트에 접근할 권한이 없습니다.")

    # 2. 해당 스캔에 매핑된 상세 취약점(Issues) 목록 조회
    issues = db.query(models.Issue).filter(models.Issue.scan_seq == scan.scan_seq).all()

    # 3. 프론트엔드가 차트 및 통계를 바로 그릴 수 있도록 심각도별 카운트 미리 계산 (Aggregating)
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for issue in issues:
        sev = issue.severity.upper() if issue.severity else "INFO"
        if sev in severity_counts:
            severity_counts[sev] += 1

    return {
        "metadata": {
            "scan_id": scan.scan_id,
            "target_name": scan.target_name,
            "status": scan.status,
            "duration_ms": scan.duration_ms,
            "issues_count": scan.issues_count,
            "framework_detected": scan.framework_detected,
            "scan_date": scan.scan_date,
            "profile": scan.profile,
            "source_kind": scan.source_kind,
            "source_ip": scan.source_ip,
            "source_user_agent": scan.source_user_agent
        },
        "severity_totals": severity_counts,
        "issues": [
            {
                "issue_id": issue.issue_id,
                "issue_title": issue.issue_title,
                "severity": issue.severity,
                "confidence": issue.confidence,
                "description": issue.description,
                "rule_id": issue.rule_id,
                "cwe_id": issue.cwe_id,
                "owasp_id": issue.owasp_id,
                "file_path": issue.file_path,
                "line_number": issue.line_number,
                "column": issue.column,
                "analyzer": issue.analyzer,
                "code_snippet": issue.code_snippet,
                "recommendation": issue.recommendation,
                "language": issue.language,
                "type_ko": issue.type_ko,
                "severity_ko": issue.severity_ko,
                "detection_reason_ko": issue.detection_reason_ko,
                "fix_description_ko": issue.fix_description_ko,
                "fix_code": issue.fix_code
            } for issue in issues
        ]
    }