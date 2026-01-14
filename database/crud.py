"""
CRUD Operations for Database Models
"""

from datetime import datetime
from typing import Optional, List, Tuple
from uuid import UUID

from sqlalchemy import select, func, desc, case
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from database.models import User, ScanHistory, Finding, APIKey, ScanLog
from database.auth import hash_api_key, generate_api_key
from services.scan_state_machine import ScanStateMachine


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
    status: Optional[str] = None,
    scan_type: Optional[str] = None
) -> Tuple[List[ScanHistory], int]:
    """Get paginated scans for a user"""
    query = select(ScanHistory).where(ScanHistory.user_id == user_id)
    
    if status:
        query = query.where(ScanHistory.status == status)
    
    if scan_type:
        query = query.where(ScanHistory.scan_type == scan_type)
    
    # Get total count
    count_query = select(func.count()).select_from(query.subquery())
    total = await db.execute(count_query)
    total_count = total.scalar_one()
    
    # Get paginated results
    query = query.order_by(desc(ScanHistory.started_at)).offset(skip).limit(limit)
    result = await db.execute(query)
    scans = result.scalars().all()
    
    return scans, total_count


async def get_user_scan_count_this_month(
    db: AsyncSession,
    user_id: UUID,
) -> int:
    """Get count of scans started this month for a user"""
    from datetime import date
    
    # Get first day of current month
    today = date.today()
    first_of_month = today.replace(day=1)
    
    query = select(func.count()).select_from(ScanHistory).where(
        ScanHistory.user_id == user_id,
        ScanHistory.started_at >= first_of_month,
    )
    result = await db.execute(query)
    return result.scalar_one() or 0


async def update_scan_status(
    db: AsyncSession,
    scan: ScanHistory,
    status: str,
    progress: Optional[int] = None,
    phase: Optional[str] = None,
    error_message: Optional[str] = None,
    validate_transition: bool = True
) -> ScanHistory:
    """
    Update scan status with optional state machine validation.
    
    Args:
        db: Database session
        scan: ScanHistory object
        status: New status
        progress: Progress percentage (0-100)
        phase: Current phase name
        error_message: Error message if status is 'error'
        validate_transition: If True, validate state transition (default True)
    
    Returns:
        Updated ScanHistory object
    """
    # Validate state transition if requested
    if validate_transition:
        is_valid, msg = ScanStateMachine.validate_transition(
            scan.status, status, scan.scan_id
        )
        if not is_valid:
            # Log warning but allow transition (for backwards compatibility)
            import logging
            logger = logging.getLogger(__name__)
            logger.warning(f"Invalid state transition for scan {scan.scan_id}: {msg}")
    
    # Track last successful phase before error
    if status == "error" and scan.status == "running":
        scan.last_successful_phase = scan.phase
    
    scan.status = status
    if progress is not None:
        scan.progress = progress
    if phase is not None:
        scan.phase = phase
    if error_message is not None:
        scan.error_message = error_message
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
    
    # Use case() expression for severity ordering
    severity_order = case(
        (Finding.severity == "critical", 1),
        (Finding.severity == "high", 2),
        (Finding.severity == "medium", 3),
        (Finding.severity == "low", 4),
        else_=5
    )
    
    query = query.order_by(severity_order)
    
    result = await db.execute(query)
    return result.scalars().all()


async def get_finding_by_id(
    db: AsyncSession,
    finding_id: str,
    user_id: int
) -> Optional[Finding]:
    """Get a single finding by ID, ensuring user owns the parent scan"""
    # Join with ScanHistory to verify ownership
    query = (
        select(Finding)
        .join(ScanHistory, Finding.scan_id == ScanHistory.id)
        .where(
            Finding.id == finding_id,
            ScanHistory.user_id == user_id
        )
    )
    result = await db.execute(query)
    return result.scalar_one_or_none()


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


# ============== Scan Log CRUD ==============

async def add_scan_log(
    db: AsyncSession,
    scan_id: UUID,
    message: str,
    level: str = "info",
    phase: Optional[str] = None
) -> ScanLog:
    """
    Add a log entry to a scan.
    
    Args:
        db: Database session
        scan_id: UUID of the scan (not scan_id string!)
        message: Log message
        level: Log level (info, warning, error, success, phase)
        phase: Current scan phase
    
    Returns:
        Created ScanLog object
    """
    log = ScanLog(
        scan_id=scan_id,
        message=message,
        level=level,
        phase=phase
    )
    db.add(log)
    await db.commit()
    await db.refresh(log)
    return log


async def add_scan_logs_batch(
    db: AsyncSession,
    scan_id: UUID,
    logs: List[dict]
) -> int:
    """
    Add multiple log entries in a batch.
    
    Args:
        db: Database session
        scan_id: UUID of the scan
        logs: List of dicts with keys: message, level (optional), phase (optional)
    
    Returns:
        Number of logs added
    """
    for log_data in logs:
        log = ScanLog(
            scan_id=scan_id,
            message=log_data.get("message", ""),
            level=log_data.get("level", "info"),
            phase=log_data.get("phase")
        )
        db.add(log)
    await db.commit()
    return len(logs)


async def get_scan_logs(
    db: AsyncSession,
    scan_id: UUID,
    limit: int = 100,
    offset: int = 0,
    level: Optional[str] = None
) -> List[ScanLog]:
    """
    Get logs for a scan with optional filtering.
    
    Args:
        db: Database session
        scan_id: UUID of the scan
        limit: Maximum logs to return
        offset: Offset for pagination
        level: Filter by log level
    
    Returns:
        List of ScanLog objects
    """
    query = select(ScanLog).where(ScanLog.scan_id == scan_id)
    
    if level:
        query = query.where(ScanLog.level == level)
    
    query = query.order_by(ScanLog.created_at.desc()).offset(offset).limit(limit)
    
    result = await db.execute(query)
    return result.scalars().all()


async def get_scan_diagnostics(
    db: AsyncSession,
    scan_id: str
) -> dict:
    """
    Get diagnostic information for a failed scan.
    
    Args:
        db: Database session
        scan_id: The short scan_id string
    
    Returns:
        Dict with error details, last phase, recent logs, and suggestions
    """
    # Get scan by scan_id (string)
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.scan_id == scan_id)
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        return {"error": "Scan not found"}
    
    # Get recent logs (last 20)
    logs_result = await db.execute(
        select(ScanLog)
        .where(ScanLog.scan_id == scan.id)
        .order_by(ScanLog.created_at.desc())
        .limit(20)
    )
    logs = logs_result.scalars().all()
    
    # Get error logs specifically
    error_logs_result = await db.execute(
        select(ScanLog)
        .where(ScanLog.scan_id == scan.id, ScanLog.level == "error")
        .order_by(ScanLog.created_at.desc())
        .limit(5)
    )
    error_logs = error_logs_result.scalars().all()
    
    # Build suggestions based on error patterns
    suggestions = []
    error_msg = scan.error_message or ""
    
    if "mitm" in error_msg.lower() or "proxy" in error_msg.lower():
        suggestions.append("MITM proxy failed to start. Try restarting the backend server.")
    if "browser" in error_msg.lower() or "playwright" in error_msg.lower():
        suggestions.append("Browser initialization failed. Ensure Playwright is installed: `playwright install`")
    if "timeout" in error_msg.lower():
        suggestions.append("Request timed out. The target may be slow or blocking requests.")
    if "connection" in error_msg.lower():
        suggestions.append("Connection error. Verify the target URL is accessible.")
    if "dns" in error_msg.lower() or "resolve" in error_msg.lower():
        suggestions.append("DNS resolution failed. Check if the domain exists and is spelled correctly.")
    if "ssl" in error_msg.lower() or "certificate" in error_msg.lower():
        suggestions.append("SSL/TLS error. The target may have an invalid certificate.")
    
    if not suggestions:
        suggestions.append("Check server logs for more details: uvicorn logs in the terminal")
    
    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "target_url": scan.target_url,
        "error_message": scan.error_message,
        "last_successful_phase": scan.last_successful_phase,
        "current_phase": scan.phase,
        "progress": scan.progress,
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
        "recent_logs": [
            {
                "timestamp": log.created_at.isoformat(),
                "level": log.level,
                "message": log.message,
                "phase": log.phase
            }
            for log in reversed(logs)  # Chronological order
        ],
        "error_logs": [
            {
                "timestamp": log.created_at.isoformat(),
                "message": log.message,
                "phase": log.phase
            }
            for log in error_logs
        ],
        "suggestions": suggestions,
        "can_retry": ScanStateMachine.is_retryable(scan.status)
    }


# Module-level namespace for backwards compatibility
# Allows: from database.crud import crud; crud.get_users(db)
class _CrudNamespace:
    """Namespace wrapper for all CRUD functions."""
    get_users = staticmethod(get_users)
    get_users_count = staticmethod(get_users_count)
    update_user = staticmethod(update_user)
    update_last_login = staticmethod(update_last_login)
    delete_user = staticmethod(delete_user)
    create_scan = staticmethod(create_scan)
    get_scan_by_id = staticmethod(get_scan_by_id)
    get_scan_by_uuid = staticmethod(get_scan_by_uuid)
    get_user_scans = staticmethod(get_user_scans)
    update_scan_status = staticmethod(update_scan_status)
    delete_scan = staticmethod(delete_scan)


crud = _CrudNamespace()
