"""
CRUD Operations for Database Models
"""

from datetime import datetime
from typing import Optional, List, Tuple
from uuid import UUID

from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.models import User, ScanHistory, Finding, APIKey
from database.auth import hash_api_key, generate_api_key


# ============== User CRUD ==============

async def get_users(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 100
) -> List[User]:
    """Get list of users with pagination"""
    result = await db.execute(
        select(User)
        .offset(skip)
        .limit(limit)
        .order_by(User.created_at.desc())
    )
    return result.scalars().all()


async def get_users_count(db: AsyncSession) -> int:
    """Get total user count"""
    result = await db.execute(select(func.count(User.id)))
    return result.scalar_one()


async def update_user(
    db: AsyncSession,
    user: User,
    **kwargs
) -> User:
    """Update user fields"""
    for key, value in kwargs.items():
        if hasattr(user, key) and value is not None:
            setattr(user, key, value)
    user.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user)
    return user


async def update_last_login(db: AsyncSession, user: User) -> User:
    """Update user's last login timestamp"""
    user.last_login = datetime.utcnow()
    await db.commit()
    return user


async def delete_user(db: AsyncSession, user: User) -> bool:
    """Delete a user"""
    await db.delete(user)
    await db.commit()
    return True


# ============== Scan CRUD ==============

async def create_scan(
    db: AsyncSession,
    user_id: UUID,
    scan_id: str,
    target_url: str,
    scan_type: str,
    config: Optional[dict] = None
) -> ScanHistory:
    """Create a new scan record"""
    scan = ScanHistory(
        user_id=user_id,
        scan_id=scan_id,
        target_url=target_url,
        scan_type=scan_type,
        config=config,
        status="queued"
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)
    return scan


async def get_scan_by_id(
    db: AsyncSession,
    scan_id: str,
    user_id: Optional[UUID] = None
) -> Optional[ScanHistory]:
    """Get scan by scan_id, optionally filtered by user"""
    query = select(ScanHistory).where(ScanHistory.scan_id == scan_id)
    if user_id:
        query = query.where(ScanHistory.user_id == user_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_scan_by_uuid(
    db: AsyncSession,
    id: UUID,
    user_id: Optional[UUID] = None
) -> Optional[ScanHistory]:
    """Get scan by UUID"""
    query = select(ScanHistory).where(ScanHistory.id == id)
    if user_id:
        query = query.where(ScanHistory.user_id == user_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()


async def get_user_scans(
    db: AsyncSession,
    user_id: UUID,
    skip: int = 0,
    limit: int = 20,
    status: Optional[str] = None
) -> Tuple[List[ScanHistory], int]:
    """Get paginated scans for a user"""
    query = select(ScanHistory).where(ScanHistory.user_id == user_id)
    
    if status:
        query = query.where(ScanHistory.status == status)
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.execute(count_query)
    total_count = total.scalar_one()
    
    # Get paginated results
    query = query.order_by(desc(ScanHistory.started_at)).offset(skip).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()
    
    return scans, total_count


async def update_scan_status(
    db: AsyncSession,
    scan: ScanHistory,
    status: str,
    progress: Optional[int] = None,
    phase: Optional[str] = None
) -> ScanHistory:
    """Update scan status"""
    scan.status = status
    if progress is not None:
        scan.progress = progress
    if phase is not None:
        scan.phase = phase
    if status in ["completed", "error", "stopped"]:
        scan.completed_at = datetime.utcnow()
    await db.commit()
    await db.refresh(scan)
    return scan


async def update_scan_results(
    db: AsyncSession,
    scan: ScanHistory,
    findings_count: int,
    severity_counts: dict,
    report_paths: dict
) -> ScanHistory:
    """Update scan results after completion"""
    scan.findings_count = findings_count
    scan.critical_count = severity_counts.get("critical", 0)
    scan.high_count = severity_counts.get("high", 0)
    scan.medium_count = severity_counts.get("medium", 0)
    scan.low_count = severity_counts.get("low", 0)
    scan.info_count = severity_counts.get("info", 0)
    
    scan.report_html = report_paths.get("html")
    scan.report_json = report_paths.get("json")
    scan.report_sarif = report_paths.get("sarif")
    
    await db.commit()
    await db.refresh(scan)
    return scan


async def delete_scan(db: AsyncSession, scan: ScanHistory) -> bool:
    """Delete a scan and its findings"""
    await db.delete(scan)
    await db.commit()
    return True


# ============== Finding CRUD ==============

async def create_finding(
    db: AsyncSession,
    scan_id: UUID,
    finding_data: dict
) -> Finding:
    """Create a new finding"""
    finding = Finding(
        scan_id=scan_id,
        **finding_data
    )
    db.add(finding)
    await db.commit()
    await db.refresh(finding)
    return finding


async def create_findings_bulk(
    db: AsyncSession,
    scan_id: UUID,
    findings_data: List[dict]
) -> List[Finding]:
    """Create multiple findings"""
    findings = [
        Finding(scan_id=scan_id, **data)
        for data in findings_data
    ]
    db.add_all(findings)
    await db.commit()
    return findings


async def get_scan_findings(
    db: AsyncSession,
    scan_id: UUID,
    severity: Optional[str] = None,
    category: Optional[str] = None
) -> List[Finding]:
    """Get findings for a scan"""
    query = select(Finding).where(Finding.scan_id == scan_id)
    
    if severity:
        query = query.where(Finding.severity == severity)
    if category:
        query = query.where(Finding.category == category)
    
    query = query.order_by(
        # Order by severity
        func.case(
            (Finding.severity == "critical", 1),
            (Finding.severity == "high", 2),
            (Finding.severity == "medium", 3),
            (Finding.severity == "low", 4),
            else_=5
        )
    )
    
    result = await db.execute(query)
    return result.scalars().all()


async def get_findings_summary(db: AsyncSession, scan_id: UUID) -> dict:
    """Get findings summary by severity"""
    result = await db.execute(
        select(Finding.severity, func.count(Finding.id))
        .where(Finding.scan_id == scan_id)
        .group_by(Finding.severity)
    )
    
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    
    for severity, count in result.all():
        summary[severity] = count
    
    summary["total"] = sum(summary.values())
    return summary


async def mark_finding_false_positive(
    db: AsyncSession,
    finding: Finding,
    is_false_positive: bool = True
) -> Finding:
    """Mark a finding as false positive"""
    finding.is_false_positive = is_false_positive
    await db.commit()
    await db.refresh(finding)
    return finding


# ============== API Key CRUD ==============

async def create_api_key(
    db: AsyncSession,
    user_id: UUID,
    name: str,
    scopes: Optional[dict] = None,
    expires_at: Optional[datetime] = None
) -> Tuple[APIKey, str]:
    """Create a new API key and return (api_key_record, raw_key)"""
    raw_key = generate_api_key()
    
    api_key = APIKey(
        user_id=user_id,
        name=name,
        key_hash=hash_api_key(raw_key),
        scopes=scopes or {},
        expires_at=expires_at
    )
    db.add(api_key)
    await db.commit()
    await db.refresh(api_key)
    
    return api_key, raw_key


async def get_user_api_keys(
    db: AsyncSession,
    user_id: UUID
) -> List[APIKey]:
    """Get all API keys for a user"""
    result = await db.execute(
        select(APIKey)
        .where(APIKey.user_id == user_id)
        .order_by(desc(APIKey.created_at))
    )
    return result.scalars().all()


async def revoke_api_key(
    db: AsyncSession,
    api_key: APIKey
) -> APIKey:
    """Revoke an API key"""
    api_key.is_active = False
    await db.commit()
    await db.refresh(api_key)
    return api_key


async def delete_api_key(
    db: AsyncSession,
    api_key: APIKey
) -> bool:
    """Delete an API key"""
    await db.delete(api_key)
    await db.commit()
    return True
