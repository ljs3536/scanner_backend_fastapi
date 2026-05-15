from sqlalchemy import Column, Integer, String, DateTime, Float, Text, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"

    user_seq = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(255), nullable=False)
    password = Column(String(255), nullable=False)
    role = Column(String(20), default="USER")
    created_at = Column(DateTime, default=datetime.utcnow)

    # 릴레이션 (User 1 : N ScanHistory)
    scans = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")

class ScanHistory(Base):
    __tablename__ = "scan_histories"

    scan_seq = Column(Integer, primary_key=True, index=True, autoincrement=True)
    scan_id = Column(String(255), nullable=False, unique=True, index=True)
    user_seq = Column(Integer, ForeignKey("users.user_seq", ondelete="CASCADE"), nullable=False)
    target_name = Column(String(255), nullable=False)
    status = Column(String(20), default="PENDING")
    duration_ms = Column(Integer, default=0)
    issues_count = Column(Integer, default=0)
    summary = Column(Text, nullable=True) # JSON 텍스트 저장용
    framework_detected = Column(String(50), nullable=True)
    scan_date = Column(DateTime, default=datetime.utcnow)

    # 추가된 필드들
    analyzers_used = Column(JSON, nullable=True)
    is_trial = Column(Boolean, default=False)
    llm_verification = Column(JSON, nullable=True)
    llm_fp_advisory = Column(JSON, nullable=True)
    
    # SBOM 관련
    sbom_id = Column(String(255), nullable=True)
    sbom_cyclonedx_json = Column(Text, nullable=True) # 매우 크므로 Text/LongText
    sbom_summary = Column(Text, nullable=True)
    sbom_status = Column(String(50), nullable=True)
    sbom_error = Column(Text, nullable=True)
    
    # 컨텍스트 관련
    source_kind = Column(String(50), nullable=True)
    analysis_scope = Column(String(50), nullable=True)
    project_context_applied = Column(Boolean, default=False)
    project_context_reason = Column(Text, nullable=True)
    project_context_root = Column(Text, nullable=True)
    profile = Column(String(50), nullable=True)

    # 릴레이션
    user = relationship("User", back_populates="scans")
    issues = relationship("Issue", back_populates="scan", cascade="all, delete-orphan")

class Issue(Base):
    __tablename__ = "issues"

    issue_seq = Column(Integer, primary_key=True, index=True, autoincrement=True)
    issue_id = Column(String(255), nullable=False, unique=True, index=True)
    scan_seq = Column(Integer, ForeignKey("scan_histories.scan_seq", ondelete="CASCADE"), nullable=False)
    issue_title = Column(String(255), nullable=False)
    severity = Column(String(20))
    confidence = Column(Float)
    description = Column(Text)
    rule_id = Column(String(50))
    cwe_id = Column(String(20))
    owasp_id = Column(String(50))
    file_path = Column(String(500), nullable=False)
    line_number = Column(Integer)

    # 릴레이션
    scan = relationship("ScanHistory", back_populates="issues")