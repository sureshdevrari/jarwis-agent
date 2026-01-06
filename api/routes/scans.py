"""
Security Scan API Routes
Start scans, check status, get results
"""

import uuid as uuid_lib
import logging
import socket
import ipaddress
from datetime import datetime
from typing import Optional
from uuid import UUID
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User, ScanHistory
from database.schemas import (
    ScanCreate, ScanResponse, ScanListResponse, 
    FindingResponse, FindingListResponse, MessageResponse
)
from database.dependencies import get_current_active_user
from database.subscription import (
    enforce_subscription_limit,
    check_subscription_limit,
    SubscriptionAction,
    increment_usage_counter,
    decrement_usage_counter,
    has_feature
)
from database import crud
from database.security import InputValidator, SecurityStore
from core.scope import ScopeManager

logger = logging.getLogger(__name__)

# ========== SSRF PROTECTION ==========
# Private/reserved IP ranges that should not be scanned
BLOCKED_IP_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),        # Private Class A
    ipaddress.ip_network("172.16.0.0/12"),     # Private Class B
    ipaddress.ip_network("192.168.0.0/16"),    # Private Class C
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("0.0.0.0/8"),         # Current network
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("100.64.0.0/10"),     # Shared address space (CGNAT)
    ipaddress.ip_network("198.18.0.0/15"),     # Benchmark testing
]

BLOCKED_HOSTNAMES = [
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    "metadata.google.internal",    # GCP metadata
    "169.254.169.254",             # AWS/Azure metadata
    "metadata.azure.com",          # Azure metadata
]

def is_safe_target(url: str) -> tuple[bool, str]:
    """
    Validate that a URL target is safe to scan (SSRF protection).
    Returns (is_safe, error_message).
    """
    try:
        parsed = urlparse(url)
        
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False, "Invalid URL format"
        
        # Only allow http/https
        if parsed.scheme.lower() not in ["http", "https"]:
            return False, "Only HTTP and HTTPS protocols are allowed"
        
        # Extract hostname (strip port if present)
        hostname = parsed.netloc.split(":")[0].lower()
        
        # Check blocked hostnames
        if hostname in BLOCKED_HOSTNAMES:
            return False, f"Target hostname '{hostname}' is not allowed"
        
        # Check for IP address format
        try:
            ip = ipaddress.ip_address(hostname)
            
            # Check against blocked ranges
            for blocked_range in BLOCKED_IP_RANGES:
                if ip in blocked_range:
                    return False, f"Target IP address is in a blocked range (internal/private network)"
            
            # Block IPv6 loopback
            if ip.is_loopback:
                return False, "Loopback addresses are not allowed"
                
        except ValueError:
            # Not an IP address, it's a hostname - resolve it
            try:
                resolved_ips = socket.gethostbyname_ex(hostname)[2]
                
                for ip_str in resolved_ips:
                    ip = ipaddress.ip_address(ip_str)
                    for blocked_range in BLOCKED_IP_RANGES:
                        if ip in blocked_range:
                            return False, f"Target hostname resolves to internal/private IP address"
                    if ip.is_loopback:
                        return False, "Target hostname resolves to loopback address"
                        
            except socket.gaierror:
                return False, f"Could not resolve hostname '{hostname}'"
        
        return True, ""
        
    except Exception as e:
        logger.warning(f"URL validation error: {e}")
        return False, f"Invalid URL: {str(e)}"
# =====================================

router = APIRouter(prefix="/api/scans", tags=["Security Scans"])

# In-memory store for running scan progress (will be replaced by Redis in production)
scan_progress: dict = {}


@router.post("/", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_data: ScanCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new security scan.
    
    - **target_url**: The URL to scan
    - **scan_type**: Type of scan (web, mobile, cloud)
    - **login_url**: Optional login page URL
    - **username**: Optional username for authenticated scanning
    - **password**: Optional password for authenticated scanning
    - **config**: Optional additional configuration
    """
    # ========== SUBSCRIPTION ENFORCEMENT ==========
    # Check if user can start a new scan based on their subscription
    await enforce_subscription_limit(db, current_user, SubscriptionAction.START_SCAN)
    
    # Check scan type access based on subscription
    if scan_data.scan_type == "mobile":
        await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_MOBILE_PENTEST)
    
    # Check cloud scanning access
    if scan_data.scan_type == "cloud":
        await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_CLOUD_SCAN)
    
    # Check if API testing is requested and allowed
    if scan_data.config and scan_data.config.get("api_testing", False):
        await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_API_TESTING)
    
    # Check credential scanning
    if scan_data.config and scan_data.config.get("credential_scanning", False):
        await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_CREDENTIAL_SCAN)
    # ==============================================
    
    # ========== SSRF PROTECTION ==========
    # Validate target URL is safe to scan (not internal/private)
    is_safe, error_msg = is_safe_target(scan_data.target_url)
    if not is_safe:
        logger.warning(f"SSRF attempt blocked: user={current_user.email}, url={scan_data.target_url}, reason={error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target URL: {error_msg}"
        )
    
    # Also validate login_url if provided
    if scan_data.login_url:
        is_safe_login, login_error = is_safe_target(scan_data.login_url)
        if not is_safe_login:
            logger.warning(f"SSRF attempt in login_url blocked: user={current_user.email}, url={scan_data.login_url}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid login URL: {login_error}"
            )
    # =====================================
    
    # ========== DOMAIN SCOPE VALIDATION ==========
    # Validate and normalize the target domain
    # Each domain/subdomain counts as a separate subscription token
    try:
        scope_manager = ScopeManager(scan_data.target_url)
        target_domain = scope_manager.get_domain_for_subscription()
        
        if not target_domain:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid target URL. Please provide a valid domain."
            )
        
        # Log the normalized domain for subscription tracking
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Scan requested for domain: {target_domain} by user: {current_user.email}")
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target URL: {str(e)}"
        )
    # =============================================
    
    # Validate scan type
    if scan_data.scan_type not in ["web", "mobile", "cloud", "network"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid scan type. Must be: web, mobile, cloud, or network"
        )
    
    # Network scans should use the /api/network/scan endpoint
    if scan_data.scan_type == "network":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use /api/network/scan endpoint for network security scans"
        )
    
    # For now, only web scanning is available in this endpoint
    if scan_data.scan_type in ["mobile", "cloud"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{scan_data.scan_type.title()} scanning coming soon! Only web scanning is available."
        )
    
    # Generate scan ID
    scan_id = str(uuid_lib.uuid4())[:8]
    
    # Extract 2FA configuration if provided
    two_factor_config = None
    if scan_data.two_factor:
        two_factor_config = {
            "enabled": scan_data.two_factor.enabled,
            "type": scan_data.two_factor.type,
            "email": scan_data.two_factor.email,
            "phone": scan_data.two_factor.phone
        }
    
    # Create scan record
    scan = await crud.create_scan(
        db=db,
        user_id=current_user.id,
        scan_id=scan_id,
        target_url=scan_data.target_url,
        scan_type=scan_data.scan_type,
        config={
            "login_url": scan_data.login_url,
            "username": scan_data.username,
            "has_auth": bool(scan_data.username and scan_data.password),
            "two_factor": two_factor_config,
            **(scan_data.config or {})
        }
    )
    
    # Increment usage counter after successful scan creation
    await increment_usage_counter(db, current_user.id, "scans")
    
    # Store password separately for the background task (not in DB)
    scan_progress[scan_id] = {
        "password": scan_data.password,
        "two_factor": two_factor_config,
        "logs": []
    }
    
    # Start scan in background
    background_tasks.add_task(
        run_security_scan,
        scan_id=scan_id,
        target_url=scan_data.target_url,
        login_url=scan_data.login_url,
        username=scan_data.username,
        password=scan_data.password,
        scan_type=scan_data.scan_type,
        user_id=current_user.id,
        two_factor_config=two_factor_config
    )
    
    return ScanResponse(
        id=scan.id,
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        status=scan.status,
        progress=scan.progress,
        phase=scan.phase,
        findings_count=scan.findings_count,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        started_at=scan.started_at,
        completed_at=scan.completed_at
    )


@router.get("/", response_model=ScanListResponse)
async def list_scans(
    page: int = 1,
    per_page: int = 20,
    status_filter: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all scans for the current user.
    
    - **page**: Page number (default 1)
    - **per_page**: Items per page (default 20, max 100)
    - **status_filter**: Filter by status (queued, running, completed, error, stopped)
    """
    per_page = min(per_page, 100)
    skip = (page - 1) * per_page
    
    scans, total = await crud.get_user_scans(
        db=db,
        user_id=current_user.id,
        skip=skip,
        limit=per_page,
        status=status_filter
    )
    
    return ScanListResponse(
        scans=[
            ScanResponse(
                id=s.id,
                scan_id=s.scan_id,
                target_url=s.target_url,
                scan_type=s.scan_type,
                status=s.status,
                progress=s.progress,
                phase=s.phase,
                findings_count=s.findings_count,
                critical_count=s.critical_count,
                high_count=s.high_count,
                medium_count=s.medium_count,
                low_count=s.low_count,
                started_at=s.started_at,
                completed_at=s.completed_at
            )
            for s in scans
        ],
        total=total,
        page=page,
        per_page=per_page
    )


@router.get("/all")
async def list_all_scans_with_stats(
    type: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List all scans for the current user with stats.
    This endpoint is used by the frontend Scan History component.
    
    - **type**: Filter by scan type (web, mobile, cloud)
    - **status**: Filter by status (queued, running, completed, error, stopped)
    - **search**: Search by target URL
    """
    # Get scans from database
    scans, total = await crud.get_user_scans(
        db=db,
        user_id=current_user.id,
        skip=0,
        limit=100,  # Get up to 100 scans
        status=status if status and status != 'all' else None
    )
    
    # Calculate stats
    stats = {'total': 0, 'web': 0, 'mobile': 0, 'cloud': 0, 'running': 0, 'completed': 0, 'error': 0}
    
    result_scans = []
    for s in scans:
        # Update stats
        stats['total'] += 1
        if s.scan_type in stats:
            stats[s.scan_type] = stats.get(s.scan_type, 0) + 1
        if s.status in stats:
            stats[s.status] = stats.get(s.status, 0) + 1
        
        # Apply filters
        if type and type != 'all' and s.scan_type != type:
            continue
        if search and search.lower() not in s.target_url.lower():
            continue
        
        result_scans.append({
            'id': str(s.id),
            'scan_id': s.scan_id,
            'status': s.status,
            'target': s.target_url,
            'target_url': s.target_url,
            'scan_type': s.scan_type,
            'type': s.scan_type,
            'started_at': s.started_at.isoformat() if s.started_at else None,
            'start_time': s.started_at.isoformat() if s.started_at else None,
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'findings_count': s.findings_count,
            'progress': s.progress,
            'phase': s.phase,
            'results': {
                'critical': s.critical_count,
                'high': s.high_count,
                'medium': s.medium_count,
                'low': s.low_count,
            }
        })
    
    return {'scans': result_scans, 'stats': stats}


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific scan.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return ScanResponse(
        id=scan.id,
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        status=scan.status,
        progress=scan.progress,
        phase=scan.phase,
        findings_count=scan.findings_count,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        started_at=scan.started_at,
        completed_at=scan.completed_at
    )


@router.get("/{scan_id}/logs")
async def get_scan_logs(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get real-time logs for a running scan.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    logs = scan_progress.get(scan_id, {}).get("logs", [])
    
    return {
        "scan_id": scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "phase": scan.phase,
        "logs": logs[-100:]  # Last 100 logs
    }


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def get_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    category: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get all findings from a scan.
    
    - **severity**: Filter by severity (critical, high, medium, low, info)
    - **category**: Filter by OWASP category (A01, A02, etc.)
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    findings = await crud.get_scan_findings(db, scan.id, severity, category)
    summary = await crud.get_findings_summary(db, scan.id)
    
    return FindingListResponse(
        findings=[
            FindingResponse(
                id=f.id,
                finding_id=f.finding_id,
                category=f.category,
                severity=f.severity,
                title=f.title,
                description=f.description,
                url=f.url,
                method=f.method,
                parameter=f.parameter,
                evidence=f.evidence,
                poc=f.poc,
                ai_verified=f.ai_verified,
                ai_confidence=f.ai_confidence,
                is_false_positive=f.is_false_positive,
                remediation=f.remediation,
                discovered_at=f.discovered_at
            )
            for f in findings
        ],
        total=summary["total"],
        by_severity=summary
    )


@router.post("/{scan_id}/stop", response_model=MessageResponse)
async def stop_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Stop a running scan.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status not in ["queued", "running"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot stop scan with status: {scan.status}"
        )
    
    await crud.update_scan_status(db, scan, "stopped")
    
    # Signal background task to stop
    if scan_id in scan_progress:
        scan_progress[scan_id]["stop"] = True
    
    return MessageResponse(
        message="Scan stop requested",
        success=True
    )


@router.delete("/{scan_id}", response_model=MessageResponse)
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete a scan and all its findings.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status == "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete a running scan. Stop it first."
        )
    
    await crud.delete_scan(db, scan)
    
    # Clean up progress data
    if scan_id in scan_progress:
        del scan_progress[scan_id]
    
    return MessageResponse(
        message="Scan deleted successfully",
        success=True
    )


async def run_security_scan(
    scan_id: str,
    target_url: str,
    login_url: Optional[str],
    username: Optional[str],
    password: Optional[str],
    scan_type: str,
    user_id: UUID,
    two_factor_config: Optional[dict] = None
):
    """
    Background task to run the actual security scan.
    
    Args:
        scan_id: Unique scan identifier
        target_url: Target website URL
        login_url: Login page URL
        username: Login username
        password: Login password
        scan_type: Type of scan (web, mobile, etc.)
        user_id: User ID who initiated the scan
        two_factor_config: Optional 2FA configuration dict with:
            - enabled: bool
            - type: 'email', 'sms', or 'authenticator'
            - email: email address (for email type)
            - phone: phone number (for sms type)
    """
    from database.connection import AsyncSessionLocal
    
    async with AsyncSessionLocal() as db:
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            return
        
        logs = scan_progress.get(scan_id, {}).get("logs", [])
        
        def log(message: str, level: str = "info"):
            logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "level": level,
                "message": message
            })
        
        try:
            # Update status to running
            await crud.update_scan_status(db, scan, "running", 5, "Initializing")
            log("Starting Jarwis AGI security scan...")
            
            # Log 2FA configuration if enabled
            if two_factor_config and two_factor_config.get('enabled'):
                tfa_type = two_factor_config.get('type', 'unknown')
                log(f"2FA enabled for target website: type={tfa_type}")
            
            # Build runner config
            runner_config = {
                'target': {
                    'url': target_url,
                    'scope': ''
                },
                'auth': {
                    'enabled': bool(username and password),
                    'type': 'form',
                    'login_url': login_url or target_url,
                    'credentials': {
                        'username': username or '',
                        'password': password or ''
                    },
                    'selectors': {
                        'username': '#email, input[name="email"], input[name="username"], input[type="email"]',
                        'password': '#password, input[name="password"], input[type="password"]',
                        'submit': 'button[type="submit"], input[type="submit"], #loginButton'
                    },
                    'two_factor': two_factor_config  # Pass 2FA config to runner
                },
                'browser': {
                    'headless': True,
                    'slow_mo': 100
                },
                'proxy': {'enabled': False},
                'ai': {
                    'provider': 'ollama',
                    'model': 'llama3:latest',
                    'base_url': 'http://localhost:11434'
                },
                'owasp': {
                    'injection': {'enabled': True},
                    'xss': {'enabled': True},
                    'misconfig': {'enabled': True},
                    'sensitive_data': {'enabled': True}
                },
                'report': {
                    'output_dir': 'reports',
                    'formats': ['html', 'json']
                }
            }
            
            # Import and run scanner
            from core.runner import PenTestRunner
            
            # Pass scan_id for 2FA OTP coordination
            runner = PenTestRunner(runner_config, scan_id=scan_id)
            
            # Phases
            phases = [
                ('Anonymous Crawling', 10),
                ('Pre-Login OWASP Scan', 25),
                ('Authentication', 35),
                ('Authenticated Crawling', 45),
                ('Post-Login Scan', 60),
                ('API Testing', 70),
                ('AI-Guided Testing', 80),
                ('AI Verification', 85),
                ('Report Generation', 95)
            ]
            
            await runner.initialize()
            log("Scanner initialized")
            
            for phase_name, progress in phases:
                # Check if stopped
                if scan_progress.get(scan_id, {}).get("stop"):
                    log("Scan stopped by user", "warning")
                    await crud.update_scan_status(db, scan, "stopped")
                    # Refund scan credit for user-stopped scans
                    try:
                        await decrement_usage_counter(db, user_id, "scans")
                        log("Scan credit refunded (user stopped)", "info")
                    except Exception as refund_error:
                        log(f"Failed to refund scan credit: {str(refund_error)}", "warning")
                    return
                
                await crud.update_scan_status(db, scan, "running", progress, phase_name)
                log(f"Phase: {phase_name}")
            
            # Run actual scan
            results = await runner.run()
            
            # Save findings
            if hasattr(runner, 'context') and hasattr(runner.context, 'findings'):
                severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                findings_data = []
                
                for finding in runner.context.findings:
                    severity = getattr(finding, 'severity', 'info').lower()
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    findings_data.append({
                        "finding_id": getattr(finding, 'id', str(uuid_lib.uuid4())[:8]),
                        "category": getattr(finding, 'category', 'Unknown'),
                        "severity": severity,
                        "title": getattr(finding, 'title', 'Finding'),
                        "description": getattr(finding, 'description', ''),
                        "url": getattr(finding, 'url', ''),
                        "method": getattr(finding, 'method', ''),
                        "parameter": getattr(finding, 'parameter', ''),
                        "evidence": getattr(finding, 'evidence', ''),
                        "poc": getattr(finding, 'poc', ''),
                        "remediation": getattr(finding, 'remediation', '')
                    })
                
                # Bulk create findings
                if findings_data:
                    await crud.create_findings_bulk(db, scan.id, findings_data)
                
                # Update scan with results
                await crud.update_scan_results(
                    db, scan,
                    findings_count=len(findings_data),
                    severity_counts=severity_counts,
                    report_paths={}
                )
            
            await crud.update_scan_status(db, scan, "completed", 100, "Completed")
            log("Scan completed successfully!")
            
            await runner.cleanup()
            
        except Exception as e:
            log(f"Scan error: {str(e)}", "error")
            await crud.update_scan_status(db, scan, "error", scan.progress, f"Error: {str(e)}")
            
            # Rollback the scan credit since the scan failed
            try:
                await decrement_usage_counter(db, user_id, "scans")
                log("Scan credit refunded due to failure", "info")
            except Exception as refund_error:
                log(f"Failed to refund scan credit: {str(refund_error)}", "warning")
