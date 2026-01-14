"""
Security Scan API Routes
Start scans, check status, get results
"""

import asyncio
import os
import uuid as uuid_lib
import logging
import socket
import ipaddress
from datetime import datetime
from pathlib import Path
from typing import Optional
from uuid import UUID
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

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
# New centralized subscription manager
from services.subscription_manager import SubscriptionManager
from database import crud
from database.security import InputValidator, SecurityStore
from core.scope import ScopeManager

# Import WebSocket broadcast functions for real-time updates
from api.websocket import (
    broadcast_scan_progress,
    broadcast_scan_status,
    broadcast_scan_log,
    broadcast_scan_complete,
    broadcast_scan_error,
    broadcast_finding
)

# Feature flag for unified orchestrator (enable gradually)
# Options:
#   "false" (default) - Legacy run_security_scan function
#   "true" - Uses core/scan_orchestrator.py (Layer 4 approach)
#   "service" - Uses services/scan_orchestrator_service.py (Layer 3 approach - RECOMMENDED)
USE_UNIFIED_ORCHESTRATOR = os.getenv("USE_UNIFIED_ORCHESTRATOR", "false").lower()

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


# ========== ATTACKS CONFIG BUILDER ==========
def _build_attacks_config(frontend_attacks: Optional[dict] = None, scan_profile: str = 'full') -> dict:
    """
    Build attacks configuration from frontend OWASP selections and scan profile.
    
    Maps frontend OWASP category flags to specific attack types.
    If no frontend config provided, enables attacks based on scan_profile.
    
    Args:
        frontend_attacks: Dict like {"owasp": {"a01_broken_access": True, "a03_injection": True, ...}}
        scan_profile: 'full' | 'quick' | 'api' | 'authenticated' - determines attack depth
    
    Returns:
        Dict mapping attack type to {"enabled": bool}
    """
    # Define attack sets by profile
    # Quick scan: Only critical vulnerability checks
    quick_attacks = {'sqli', 'xss', 'ssrf', 'csrf', 'idor', 'auth_bypass'}
    
    # API scan: Focus on API-specific vulnerabilities
    api_attacks = {'sqli', 'nosqli', 'idor', 'bola', 'bfla', 'auth_bypass', 'jwt', 'ssrf', 'rate_limit'}
    
    # Full/Authenticated scan: All attacks
    all_attacks = {
        'sqli': True, 'xss': True, 'nosqli': True, 'cmdi': True, 'ssti': True,
        'xxe': True, 'ldapi': True, 'xpath': True, 'idor': True, 'bola': True,
        'bfla': True, 'path_traversal': True, 'auth_bypass': True, 'jwt': True,
        'session': True, 'ssrf': True, 'csrf': True, 'host_header': True,
        'cors': True, 'hpp': True, 'crlf': True, 'cache_poison': True,
        'http_smuggling': True, 'open_redirect': True, 'file_upload': True,
        'rate_limit': True
    }
    
    # Apply profile-based filtering if no frontend config
    if not frontend_attacks:
        if scan_profile == 'quick':
            return {k: {'enabled': k in quick_attacks} for k in all_attacks}
        elif scan_profile == 'api':
            return {k: {'enabled': k in api_attacks} for k in all_attacks}
        # full and authenticated use all attacks
        return {k: {'enabled': v} for k, v in all_attacks.items()}
    
    owasp = frontend_attacks.get('owasp', {})
    
    # Map OWASP categories to specific attacks
    # A01: Broken Access Control
    a01_enabled = owasp.get('a01_broken_access', True)
    # A02: Cryptographic Failures
    a02_enabled = owasp.get('a02_crypto', True)
    # A03: Injection
    a03_enabled = owasp.get('a03_injection', True)
    # A04: Insecure Design (logic-based, harder to automate)
    a04_enabled = owasp.get('a04_insecure_design', True)
    # A05: Security Misconfiguration
    a05_enabled = owasp.get('a05_security_misconfig', True)
    # A06: Vulnerable Components (covered by scanning)
    a06_enabled = owasp.get('a06_vulnerable_components', True)
    # A07: Auth Failures (XSS, session)
    a07_enabled = owasp.get('a07_xss', True)
    # A08: Software Integrity
    a08_enabled = owasp.get('a08_integrity', True)
    # A09: Logging Failures
    a09_enabled = owasp.get('a09_logging', True)
    # A10: SSRF
    a10_enabled = owasp.get('a10_ssrf', True)
    
    # Build attack config based on OWASP selections
    attacks = {
        # A01: Broken Access Control
        'idor': a01_enabled,
        'bola': a01_enabled,
        'bfla': a01_enabled,
        'path_traversal': a01_enabled,
        'auth_bypass': a01_enabled,
        
        # A02: Cryptographic Failures (enabled by crypto check)
        'jwt': a02_enabled,
        
        # A03: Injection
        'sqli': a03_enabled,
        'nosqli': a03_enabled,
        'cmdi': a03_enabled,
        'ssti': a03_enabled,
        'xxe': a03_enabled,
        'ldapi': a03_enabled,
        'xpath': a03_enabled,
        'crlf': a03_enabled,
        
        # A05: Security Misconfiguration
        'cors': a05_enabled,
        'host_header': a05_enabled,
        'http_smuggling': a05_enabled,
        'hpp': a05_enabled,
        'cache_poison': a05_enabled,
        'open_redirect': a05_enabled,
        'file_upload': a05_enabled,
        
        # A07: XSS and Session
        'xss': a07_enabled,
        'session': a07_enabled,
        'csrf': a07_enabled,
        
        # A10: SSRF
        'ssrf': a10_enabled,
        
        # Always enabled for rate limit testing
        'rate_limit': True,
    }
    
    return {k: {'enabled': v} for k, v in attacks.items()}
# =============================================


router = APIRouter(prefix="/api/scans", tags=["Security Scans"])

# In-memory store for running scan progress (will be replaced by Redis in production)
scan_progress: dict = {}

# Phase name mapping: backend phase names -> frontend-friendly display names
PHASE_NAME_MAP = {
    "preflight": "Initializing",
    "crawl": "Anonymous Crawling",
    "pre_login_attacks": "Pre-Login OWASP Scan",
    "authentication": "Authentication",
    "post_login_crawl": "Authenticated Crawling",
    "post_login_attacks": "Post-Login Security Scan",
    "api_testing": "API Security Testing",
    "ai_testing": "AI-Guided Testing",
    "reporting": "Report Generation",
    "completed": "Completed",
    # Also handle already-mapped names (pass through)
    "Initializing": "Initializing",
    "Anonymous Crawling": "Anonymous Crawling",
    "Pre-Login OWASP Scan": "Pre-Login OWASP Scan",
    "Authentication": "Authentication",
    "Authenticated Crawling": "Authenticated Crawling",
    "Post-Login Security Scan": "Post-Login Security Scan",
    "API Security Testing": "API Security Testing",
    "AI-Guided Testing": "AI-Guided Testing",
    "Report Generation": "Report Generation",
    "Completed": "Completed",
}

# Stale scan threshold: if no activity for 2 hours, mark as stale
STALE_SCAN_THRESHOLD_SECONDS = 7200


def map_phase_name(backend_phase: str) -> str:
    """Convert backend phase name to frontend-friendly display name."""
    if not backend_phase:
        return "Initializing"
    return PHASE_NAME_MAP.get(backend_phase, backend_phase)


def get_checkpoint_data(scan_id: str) -> dict:
    """
    Load checkpoint data for a scan if available.
    Returns dict with phase, progress, findings_count, is_stale, last_activity.
    """
    try:
        from core.scan_checkpoint import ScanCheckpoint
        checkpoint = ScanCheckpoint(scan_id=scan_id)
        state = checkpoint.load()
        
        if not state:
            return {}
        
        # Calculate progress based on completed phases
        phase_order = ["preflight", "crawl", "pre_login_attacks", "authentication", 
                       "post_login_crawl", "post_login_attacks", "reporting", "completed"]
        current_phase = state.current_phase
        
        # Calculate progress percentage based on phase
        try:
            phase_idx = phase_order.index(current_phase)
            # Each phase is roughly 12.5% (100/8 phases)
            progress = int((phase_idx / len(phase_order)) * 100)
        except ValueError:
            progress = 0
        
        # Get findings count from checkpoint
        findings_count = len(state.findings) if state.findings else 0
        
        # Check if scan is stale (no activity for threshold)
        last_activity = state.updated_at
        is_stale = False
        if last_activity:
            try:
                from datetime import datetime
                last_dt = datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
                now = datetime.utcnow()
                # Make last_dt naive if it has timezone info
                if last_dt.tzinfo:
                    last_dt = last_dt.replace(tzinfo=None)
                elapsed_seconds = (now - last_dt).total_seconds()
                is_stale = elapsed_seconds > STALE_SCAN_THRESHOLD_SECONDS
            except Exception as e:
                logger.warning(f"Error checking stale status: {e}")
        
        return {
            "phase": current_phase,
            "progress": progress,
            "findings_count": findings_count,
            "is_stale": is_stale,
            "last_activity": last_activity,
            "target_url": state.target_url,
        }
    except Exception as e:
        logger.warning(f"Failed to load checkpoint for scan {scan_id}: {e}")
        return {}


def generate_error_id() -> str:
    """Generate a unique error ID for tracking/debugging"""
    import hashlib
    import time
    return f"ERR-{hashlib.sha256(f'{time.time()}'.encode()).hexdigest()[:8].upper()}"


def sanitize_error_for_user(error_msg: str, traceback_str: str = "") -> tuple:
    """
    Convert internal error messages to user-friendly messages.
    This prevents exposing internal implementation details, file paths, or tracebacks.
    
    Returns: (sanitized_message, error_id)
    """
    error_lower = error_msg.lower() if error_msg else ""
    error_id = generate_error_id()
    
    # Log full error with ID for debugging
    if traceback_str:
        logger.error(f"[{error_id}] Full error: {error_msg}\nTraceback:\n{traceback_str}")
    else:
        logger.error(f"[{error_id}] Error: {error_msg}")
    
    # Map common internal errors to user-friendly messages
    if "mitm" in error_lower or "proxy" in error_lower:
        return f"Proxy initialization failed. Please try again or contact support. (Ref: {error_id})", error_id
    if "playwright" in error_lower or "browser" in error_lower:
        return f"Browser automation failed. Please ensure the target is accessible and try again. (Ref: {error_id})", error_id
    if "timeout" in error_lower:
        return f"Request timed out. The target may be slow or unreachable. (Ref: {error_id})", error_id
    if "connection" in error_lower or "connect" in error_lower:
        return f"Connection failed. Please verify the target URL is accessible. (Ref: {error_id})", error_id
    if "dns" in error_lower or "resolve" in error_lower:
        return f"Could not resolve the domain. Please check if the URL is correct. (Ref: {error_id})", error_id
    if "ssl" in error_lower or "certificate" in error_lower:
        return f"SSL/TLS error. The target may have certificate issues. (Ref: {error_id})", error_id
    if "permission" in error_lower or "denied" in error_lower:
        return f"Access denied. Please check your credentials or domain authorization. (Ref: {error_id})", error_id
    if "auth" in error_lower or "login" in error_lower:
        return f"Authentication failed. Please verify your credentials. (Ref: {error_id})", error_id
    if "rate" in error_lower or "limit" in error_lower:
        return f"Rate limited by target. Please try again later. (Ref: {error_id})", error_id
    if "import" in error_lower or "module" in error_lower:
        return f"Scanner initialization failed. Please contact support. (Ref: {error_id})", error_id
    
    # If we can't categorize, return a generic message
    return f"Scan encountered an unexpected error. Please try again or contact support. (Ref: {error_id})", error_id


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
    # ========== DEVELOPER ACCOUNT CHECK (FIRST!) ==========
    # Developer accounts (dev@jarwis.ai) bypass ALL restrictions
    # Only authentication is required - no other policies apply
    from shared.constants import is_developer_account
    is_dev_account = is_developer_account(current_user.email)
    
    if is_dev_account:
        logger.info(f"🔧 DEVELOPER ACCOUNT: {current_user.email} - bypassing ALL restrictions (plan, subscription, SSRF, domain)")
    # =====================================================
    
    # ========== SCAN TYPE RESTRICTIONS BY PLAN ==========
    # Check plan restrictions BEFORE checking scan limits
    # Developer plan bypasses all restrictions (for testing)
    # Developer accounts (dev@jarwis.ai) also bypass everything
    is_dev_plan = current_user.plan == "developer"
    
    # Individual plan can ONLY do web scans (skip for dev accounts)
    if not is_dev_account and not is_dev_plan and current_user.plan == "individual" and scan_data.scan_type != "web":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Individual plan only supports web scanning. Please upgrade to Professional for {scan_data.scan_type} scanning."
        )
    
    # Free plan restrictions (skip for dev accounts)
    if not is_dev_account and not is_dev_plan and current_user.plan == "free" and scan_data.scan_type != "web":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Free plan only supports web scanning. Please upgrade to Professional for {scan_data.scan_type} scanning."
        )
    
    # Check scan type access based on subscription (feature-based checks)
    # Developer accounts skip ALL subscription checks
    if not is_dev_account:
        if scan_data.scan_type == "mobile":
            await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_MOBILE_PENTEST)
        
        # Check network scanning access
        if scan_data.scan_type == "network":
            await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_NETWORK_SCAN)
        
        # Check cloud scanning access
        if scan_data.scan_type == "cloud":
            await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_CLOUD_SCAN)
        
        # Check if API testing is requested and allowed
        if scan_data.scan_type == "api" or (scan_data.config and scan_data.config.get("api_testing", False)):
            await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_API_TESTING)
    
    # Check credential scanning (authenticated scanning)
    if not is_dev_account:
        if scan_data.username or scan_data.password or (scan_data.config and scan_data.config.get("credential_scanning", False)):
            await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_CREDENTIAL_SCAN)
    # ==================================================
    
    # ========== SUBSCRIPTION LIMIT CHECK ==========
    # Check if user can start a new scan based on their scan quota
    # Developer accounts bypass this check
    if not is_dev_account:
        await enforce_subscription_limit(db, current_user, SubscriptionAction.START_SCAN)
    # ==============================================
    
    # ========== SSRF PROTECTION ==========
    # Validate target URL is safe to scan (not internal/private)
    # Developer accounts bypass SSRF protection to test internal services
    if not is_dev_account:
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
    else:
        logger.info(f"🔧 DEVELOPER BYPASS: SSRF protection skipped for {current_user.email}")
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
        logger.info(f"Scan requested for domain: {target_domain} by user: {current_user.email}")
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid target URL: {str(e)}"
        )
    # =============================================
    
    # ========== DOMAIN AUTHORIZATION CHECK ==========
    # Personal email users MUST verify domain ownership for ALL scans
    # Corporate email users can scan their own domain without verification
    # Authorization granted if:
    # 1. User's email domain matches target domain (corporate email only)
    # 2. Domain is explicitly verified via DNS TXT record
    # 3. Developer plan bypasses domain verification (for testing)
    # 4. Developer accounts (dev@jarwis.ai) bypass ALL checks
    
    from shared.constants import is_personal_email
    from urllib.parse import urlparse
    from services.domain_verification_service import DomainVerificationService
    
    target_host = urlparse(scan_data.target_url).netloc.lower()
    # Remove port if present
    if ':' in target_host:
        target_host = target_host.split(':')[0]
    
    user_has_personal_email = is_personal_email(current_user.email)
    has_credentials = bool(
        scan_data.username and scan_data.password
    ) or getattr(scan_data, 'auth_method', 'none') not in ['none', None]
    
    # Developer ACCOUNTS bypass ALL domain verification (dev@jarwis.ai)
    if is_dev_account:
        logger.info(f"🔧 DEVELOPER ACCOUNT BYPASS: {current_user.email} skipping domain verification")
    # Developer plan bypasses ALL domain verification
    elif current_user.plan == "developer":
        logger.info(f"Developer plan bypass: {current_user.email} skipping domain verification")
    # ALL USERS must be authorized to scan any domain
    # Personal email users: MUST verify domain via DNS TXT
    # Corporate email users: Can scan their own domain + verified domains
    else:
        domain_service = DomainVerificationService(db)
        is_authorized, auth_reason = await domain_service.is_authorized_to_scan(
            user_id=current_user.id,
            user_email=current_user.email,
            target_domain=target_host,
            require_verification_for_personal=True  # Personal emails always need verification
        )
        
        if not is_authorized:
            email_domain = current_user.email.split('@')[1] if '@' in current_user.email else None
            
            logger.warning(
                f"Domain authorization DENIED: user={current_user.email}, "
                f"target={target_host}, reason={auth_reason}, personal_email={user_has_personal_email}"
            )
            
            if user_has_personal_email:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "personal_email_requires_verification",
                        "message": "Users with personal email addresses must verify domain ownership before scanning any domain.",
                        "target_domain": target_host,
                        "user_email": current_user.email,
                        "verification_url": f"/api/domains/verify/generate",
                        "help": "Add a DNS TXT record to verify domain ownership. Go to Settings → Verified Domains."
                    }
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "domain_not_authorized",
                        "message": f"You can only scan domains matching your corporate email ({email_domain}) or domains you've verified.",
                        "target_domain": target_host,
                        "user_email_domain": email_domain,
                        "verification_url": f"/api/domains/verify/generate",
                        "help": "Either scan your corporate domain or verify this domain in Settings → Verified Domains."
                    }
                )
        
        logger.info(f"Domain authorization GRANTED: user={current_user.email}, target={target_host}, reason={auth_reason}")
    # ==========================================================
    
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
    
    # Mobile and cloud scans should use their dedicated endpoints
    if scan_data.scan_type == "mobile":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use /api/scan/mobile/start endpoint for mobile app security scans"
        )
    
    if scan_data.scan_type == "cloud":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Use /api/scan/cloud/start endpoint for cloud security scans"
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
    
    # Extract auth method configuration
    auth_method = getattr(scan_data, 'auth_method', None) or 'none'
    auth_config = {
        "auth_method": auth_method,
        "login_url": scan_data.login_url,
        "username": scan_data.username,
        "has_auth": auth_method != 'none',
        "phone_number": getattr(scan_data, 'phone_number', None),
        "session_cookie": getattr(scan_data, 'session_cookie', None),
        "session_token": getattr(scan_data, 'session_token', None),
        "social_providers": getattr(scan_data, 'social_providers', None) or [],
        "two_factor": two_factor_config,
    }
    
    # Create scan record (include scan_name in config)
    scan = await crud.create_scan(
        db=db,
        user_id=current_user.id,
        scan_id=scan_id,
        target_url=scan_data.target_url,
        scan_type=scan_data.scan_type,
        config={
            "scan_name": getattr(scan_data, 'scan_name', None),
            **auth_config,
            **(scan_data.config or {})
        }
    )
    
    # Sync usage counter with actual ScanHistory count
    # This ensures User.scans_this_month stays in sync with the source of truth
    sub_manager = SubscriptionManager(db, current_user)
    await sub_manager.deduct_scan(scan_id)
    
    # Store password separately for the background task (not in DB)
    scan_progress[scan_id] = {
        "password": scan_data.password,
        "auth_method": auth_method,
        "auth_config": auth_config,
        "two_factor": two_factor_config,
        "attacks_config": scan_data.config.get("attacks") if scan_data.config else None,
        "logs": []
    }
    
    # Start scan in background - use orchestrator if enabled
    scan_runner = get_scan_runner_function()
    background_tasks.add_task(
        scan_runner,
        scan_id=scan_id,
        target_url=scan_data.target_url,
        login_url=scan_data.login_url,
        username=scan_data.username,
        password=scan_data.password,
        scan_type=scan_data.scan_type,
        user_id=current_user.id,
        two_factor_config=two_factor_config,
        auth_config=auth_config,  # Pass auth method config
        attacks_config=scan_data.config.get("attacks") if scan_data.config else None  # Pass attacks config
    )
    
    return ScanResponse(
        id=scan.id,
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        scan_name=(scan.config or {}).get('scan_name'),
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
    
    # Helper to check if a scan can be resumed
    def check_can_resume(scan) -> bool:
        if scan.status not in ('error', 'stopped', 'failed'):
            return False
        try:
            from core.scan_checkpoint import ScanCheckpoint
            checkpoint = ScanCheckpoint(scan_id=scan.scan_id)
            return checkpoint.exists() and checkpoint.can_resume()
        except Exception:
            return False
    
    return ScanListResponse(
        scans=[
            ScanResponse(
                id=s.id,
                scan_id=s.scan_id,
                target_url=s.target_url,
                scan_type=s.scan_type,
                scan_name=(s.config or {}).get('scan_name'),
                status=s.status,
                progress=s.progress,
                phase=s.phase,
                findings_count=s.findings_count,
                critical_count=s.critical_count,
                high_count=s.high_count,
                medium_count=s.medium_count,
                low_count=s.low_count,
                started_at=s.started_at,
                completed_at=s.completed_at,
                can_resume=check_can_resume(s)
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
    # Get scans from database (limited to 100 for now)
    scans, total = await crud.get_user_scans(
        db=db,
        user_id=current_user.id,
        skip=0,
        limit=100,
        status=status if status and status != 'all' else None
    )
    
    # Helper to check if a scan can be resumed
    def check_can_resume(scan) -> bool:
        if scan.status not in ('error', 'stopped', 'failed'):
            return False
        try:
            from core.scan_checkpoint import ScanCheckpoint
            checkpoint = ScanCheckpoint(scan_id=scan.scan_id)
            return checkpoint.exists() and checkpoint.can_resume()
        except Exception:
            return False

    # Build filtered list first, then compute stats so cards match the list
    result_scans = []
    for s in scans:
        # Apply filters
        if type and type != 'all' and s.scan_type != type:
            continue
        if search and search.lower() not in (s.target_url or '').lower():
            continue
        
        current_progress = s.progress
        current_phase = s.phase
        current_status = s.status
        findings_count = s.findings_count
        
        # Check in-memory tracker first
        live_state = scan_progress.get(str(s.scan_id)) or scan_progress.get(s.scan_id) or scan_progress.get(s.id)
        if live_state:
            current_progress = live_state.get('progress', current_progress)
            current_phase = live_state.get('phase', current_phase)
        elif s.status == "running":
            # No in-memory state for "running" scan - load checkpoint data
            checkpoint_data = get_checkpoint_data(s.scan_id)
            if checkpoint_data:
                current_progress = checkpoint_data.get("progress", current_progress)
                current_phase = checkpoint_data.get("phase", current_phase)
                checkpoint_findings = checkpoint_data.get("findings_count", 0)
                if checkpoint_findings > findings_count:
                    findings_count = checkpoint_findings
                if checkpoint_data.get("is_stale"):
                    current_status = "stalled"
        
        # Map phase name to frontend-friendly name
        current_phase = map_phase_name(current_phase) if current_phase else "Initializing"
        
        scan_dict = {
            'id': str(s.id),
            'scan_id': s.scan_id,
            'status': current_status,
            'target': s.target_url,
            'target_url': s.target_url,
            'scan_type': s.scan_type,
            'type': s.scan_type,
            'started_at': s.started_at.isoformat() if s.started_at else None,
            'start_time': s.started_at.isoformat() if s.started_at else None,
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'findings_count': findings_count,
            'total_findings': findings_count,
            'progress': current_progress,
            'phase': current_phase,
            'can_resume': check_can_resume(s),
        }

        # Include severity breakdown consistently
        scan_dict['results'] = {
            'critical': s.critical_count,
            'high': s.high_count,
            'medium': s.medium_count,
            'low': s.low_count,
        }

        result_scans.append(scan_dict)
    
    # Compute stats based on the filtered list so the UI cards match the table
    stats = {'total': 0, 'web': 0, 'mobile': 0, 'cloud': 0, 'running': 0, 'completed': 0, 'error': 0, 'stopped': 0, 'queued': 0}
    for item in result_scans:
        stats['total'] += 1
        if item['scan_type'] in stats:
            stats[item['scan_type']] = stats.get(item['scan_type'], 0) + 1
        status_key = item.get('status')
        if status_key in stats:
            stats[status_key] = stats.get(status_key, 0) + 1
    
    return {'scans': result_scans, 'stats': stats, 'total': total}


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get details of a specific scan.
    
    Enhanced to load checkpoint data when in-memory progress is unavailable,
    ensuring accurate status after server restarts.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Use real-time progress from memory if available (for running scans)
    progress_info = scan_progress.get(scan_id, {})
    current_progress = progress_info.get("progress")
    current_phase = progress_info.get("phase")
    current_status = scan.status
    findings_count = scan.findings_count
    
    # If no in-memory progress and scan is supposedly "running", load from checkpoint
    if current_progress is None and scan.status == "running":
        checkpoint_data = get_checkpoint_data(scan_id)
        if checkpoint_data:
            current_progress = checkpoint_data.get("progress", scan.progress)
            current_phase = checkpoint_data.get("phase", scan.phase)
            # Use checkpoint findings if DB has fewer
            checkpoint_findings = checkpoint_data.get("findings_count", 0)
            if checkpoint_findings > findings_count:
                findings_count = checkpoint_findings
            
            # If scan is stale (no activity for 2+ hours), mark as stalled
            if checkpoint_data.get("is_stale"):
                current_status = "stalled"
                logger.warning(f"Scan {scan_id} marked as stalled - no activity since {checkpoint_data.get('last_activity')}")
    
    # Fall back to DB values if still None
    if current_progress is None:
        current_progress = scan.progress or 0
    if current_phase is None:
        current_phase = scan.phase or "Initializing"
    
    # Map backend phase names to frontend-friendly names
    current_phase = map_phase_name(current_phase)
    
    return ScanResponse(
        id=scan.id,
        scan_id=scan.scan_id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        scan_name=(scan.config or {}).get('scan_name'),
        status=current_status,
        progress=current_progress,
        phase=current_phase,
        findings_count=findings_count,
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
    
    Enhanced to load checkpoint data when in-memory progress is unavailable.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Get logs and real-time progress from in-memory dict
    progress_info = scan_progress.get(scan_id, {})
    logs = progress_info.get("logs", [])
    
    # Use real-time progress from memory if available
    current_progress = progress_info.get("progress")
    current_phase = progress_info.get("phase")
    current_status = scan.status
    findings_count = scan.findings_count
    
    # If no in-memory progress and scan is supposedly "running", load from checkpoint
    if current_progress is None and scan.status == "running":
        checkpoint_data = get_checkpoint_data(scan_id)
        if checkpoint_data:
            current_progress = checkpoint_data.get("progress", scan.progress)
            current_phase = checkpoint_data.get("phase", scan.phase)
            checkpoint_findings = checkpoint_data.get("findings_count", 0)
            if checkpoint_findings > findings_count:
                findings_count = checkpoint_findings
            
            # If scan is stale, update status
            if checkpoint_data.get("is_stale"):
                current_status = "stalled"
    
    # Fall back to DB values if still None
    if current_progress is None:
        current_progress = scan.progress or 0
    if current_phase is None:
        current_phase = scan.phase or "Initializing"
    
    # Map backend phase names to frontend-friendly names
    current_phase = map_phase_name(current_phase)
    
    # Check for manual auth waiting states
    waiting_for_manual_auth = scan.status == "waiting_for_manual_auth"
    waiting_for_otp = scan.status == "waiting_for_otp"
    
    return {
        "scan_id": scan_id,
        "status": current_status,
        "progress": current_progress,
        "phase": current_phase,
        "findings_count": findings_count,
        "logs": logs[-100:],  # Last 100 logs
        "waiting_for_manual_auth": waiting_for_manual_auth,
        "waiting_for_otp": waiting_for_otp,
        "error_message": scan.error_message if scan.status == "error" else None,
        "target_url": scan.target_url
    }


@router.get("/{scan_id}/diagnostics")
async def get_scan_diagnostics(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get detailed diagnostics for a failed or errored scan.
    
    Returns error details, logs, last successful phase, and troubleshooting suggestions.
    Useful for debugging why a scan failed.
    """
    # First verify user owns the scan
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Get full diagnostics
    diagnostics = await crud.get_scan_diagnostics(db, scan_id)
    
    # Add in-memory logs if available (more recent than DB)
    progress_info = scan_progress.get(scan_id, {})
    if progress_info.get("logs"):
        diagnostics["in_memory_logs"] = progress_info["logs"][-50:]
    
    return diagnostics


@router.post("/{scan_id}/retry")
async def retry_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retry a failed or stopped scan.
    
    Creates a new scan with the same configuration as the original.
    The original scan remains in the database for audit purposes.
    """
    from services.scan_state_machine import ScanStateMachine
    
    # Get the original scan
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Check if scan can be retried
    if not ScanStateMachine.is_retryable(scan.status):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan with status '{scan.status}' cannot be retried. Only 'error' or 'stopped' scans can be retried."
        )
    
    # ========== DEVELOPER ACCOUNT CHECK ==========
    from shared.constants import is_developer_account
    is_dev_account = is_developer_account(current_user.email)
    # ==============================================
    
    # Check subscription limits (skip for developer accounts)
    if not is_dev_account:
        await enforce_subscription_limit(db, current_user, SubscriptionAction.START_SCAN)
    
    # Create new scan with same config
    new_scan_id = str(uuid_lib.uuid4())[:8]
    
    new_scan = ScanHistory(
        user_id=current_user.id,
        scan_id=new_scan_id,
        target_url=scan.target_url,
        scan_type=scan.scan_type,
        config=scan.config,
        status="queued",
        progress=0,
        phase="Queued (retry)"
    )
    db.add(new_scan)
    await db.commit()
    await db.refresh(new_scan)
    
    # Sync usage counter with actual ScanHistory count
    sub_manager = SubscriptionManager(db, current_user)
    await sub_manager.deduct_scan(new_scan_id)
    
    # Initialize progress tracking
    scan_progress[new_scan_id] = {
        "phase": "Initializing",
        "progress": 0,
        "logs": [],
        "stop": False
    }
    
    # Extract config for background task
    config = scan.config or {}
    auth_config = config.get("auth", {})
    
    # Start new scan in background
    background_tasks.add_task(
        run_security_scan,
        scan_id=new_scan_id,
        target_url=scan.target_url,
        login_url=auth_config.get("login_url"),
        username=auth_config.get("username"),
        password=auth_config.get("password"),
        scan_type=scan.scan_type,
        user_id=current_user.id,
        two_factor_config=auth_config.get("two_factor"),
        auth_config=auth_config,
        attacks_config=config.get("attacks")
    )
    
    return {
        "message": "Scan retry started",
        "original_scan_id": scan_id,
        "new_scan_id": new_scan_id,
        "target_url": scan.target_url
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


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding_by_id(
    finding_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a single finding by its ID.
    
    Returns the full finding details including evidence and remediation.
    """
    finding = await crud.get_finding_by_id(db, finding_id, current_user.id)
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )
    
    return FindingResponse(
        id=finding.id,
        finding_id=finding.finding_id,
        category=finding.category,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        url=finding.url,
        method=finding.method,
        parameter=finding.parameter,
        evidence=finding.evidence,
        poc=finding.poc,
        ai_verified=finding.ai_verified,
        ai_confidence=finding.ai_confidence,
        is_false_positive=finding.is_false_positive,
        remediation=finding.remediation,
        discovered_at=finding.discovered_at
    )


@router.patch("/findings/{finding_id}/false-positive", response_model=MessageResponse)
async def mark_finding_false_positive(
    finding_id: str,
    is_false_positive: bool = True,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Mark a finding as a false positive or revert it.
    
    - **is_false_positive**: True to mark as false positive, False to revert
    """
    finding = await crud.get_finding_by_id(db, finding_id, current_user.id)
    
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found"
        )
    
    finding.is_false_positive = is_false_positive
    await db.commit()
    
    status_text = "marked as false positive" if is_false_positive else "unmarked as false positive"
    return MessageResponse(
        message=f"Finding {status_text} successfully",
        success=True,
        data={"finding_id": finding_id, "is_false_positive": is_false_positive}
    )


@router.post("/{scan_id}/stop", response_model=MessageResponse)
async def stop_scan(
    scan_id: str,
    confirmed: bool = False,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Stop a running scan.
    
    - **confirmed**: Must be True to actually stop the scan. If False, returns confirmation required.
    
    ABUSE PREVENTION:
    - First stop attempt: Requires confirmation, scan credit will be refunded
    - 2nd stop attempt: Warning issued, credit still refunded
    - 3rd+ stop attempts: Considered abuse, NO credit refund (scan counts against limit)
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
    
    # Get current stop attempts (from in-memory tracking or DB)
    current_stop_attempts = scan_progress.get(scan_id, {}).get("stop_attempts", 0)
    
    # If not confirmed, return confirmation required with attempt info
    if not confirmed:
        # Increment stop attempt counter in memory
        if scan_id not in scan_progress:
            scan_progress[scan_id] = {"logs": []}
        scan_progress[scan_id]["stop_attempts"] = current_stop_attempts + 1
        current_stop_attempts += 1
        
        # Build warning message based on attempt count
        if current_stop_attempts >= 3:
            return MessageResponse(
                message="ABUSE DETECTED: Multiple stop attempts detected. If you stop now, your scan credit will NOT be refunded. This scan will count against your monthly limit.",
                success=False,
                data={
                    "requires_confirmation": True,
                    "stop_attempts": current_stop_attempts,
                    "refund_blocked": True,
                    "warning_level": "critical"
                }
            )
        elif current_stop_attempts == 2:
            return MessageResponse(
                message="Warning: This is your second stop attempt. One more attempt will be considered abuse and your scan credit will NOT be refunded.",
                success=False,
                data={
                    "requires_confirmation": True,
                    "stop_attempts": current_stop_attempts,
                    "refund_blocked": False,
                    "warning_level": "warning"
                }
            )
        else:
            return MessageResponse(
                message="Are you sure you want to stop this scan? Stopping will cancel all remaining tests. Your scan credit will be refunded.",
                success=False,
                data={
                    "requires_confirmation": True,
                    "stop_attempts": current_stop_attempts,
                    "refund_blocked": False,
                    "warning_level": "info"
                }
            )
    
    # User confirmed - proceed with stop
    # Check if refund should be blocked (3+ stop attempts = abuse)
    refund_blocked = current_stop_attempts >= 3
    
    # Update scan in database with stop_attempts and refund_blocked flag
    scan.stop_attempts = current_stop_attempts
    scan.refund_blocked = refund_blocked
    await db.commit()
    
    await crud.update_scan_status(db, scan, "stopped")
    
    # Signal background task to stop with refund info
    if scan_id in scan_progress:
        scan_progress[scan_id]["stop"] = True
        scan_progress[scan_id]["refund_blocked"] = refund_blocked
    
    # Force cleanup: close browser and orchestrator
    try:
        # Try to close browser via registry
        from core.browser import BrowserController
        await BrowserController.force_close_by_scan_id(scan_id)
        
        # Try to stop via orchestrator
        from core.scan_orchestrator import ScanOrchestrator
        orchestrator = ScanOrchestrator.get_active_scan(scan_id)
        if orchestrator:
            await orchestrator.stop()
            logger.info(f"Orchestrator stopped for scan {scan_id}")
    except Exception as e:
        logger.warning(f"Error during force cleanup for scan {scan_id}: {e}")
    
    # Broadcast stop status via WebSocket
    try:
        from api.websocket import broadcast_scan_status
        await broadcast_scan_status(scan_id, "stopped", "Scan stopped by user")
    except Exception as e:
        logger.debug(f"WebSocket broadcast failed: {e}")
    
    if refund_blocked:
        return MessageResponse(
            message="Scan stopped. Due to multiple stop attempts, your scan credit was NOT refunded. This scan counts against your monthly limit.",
            success=True,
            data={"refund_blocked": True, "stop_attempts": current_stop_attempts}
        )
    else:
        return MessageResponse(
            message="Scan stopped successfully. Your scan credit has been refunded.",
            success=True,
            data={"refund_blocked": False, "stop_attempts": current_stop_attempts}
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


# ========== RESILIENCE ENDPOINTS ==========

@router.get("/preflight", status_code=status.HTTP_200_OK)
async def run_preflight_check(
    current_user: User = Depends(get_current_active_user)
):
    """
    Run preflight validation before starting a scan.
    
    Returns:
        Validation result with any issues that need to be fixed.
    """
    try:
        from core.preflight_validator import PreflightValidator
        
        validator = PreflightValidator()
        result = await validator.validate_all()
        
        return {
            "passed": result.passed,
            "issues": [
                {
                    "check_name": issue.check_name,
                    "severity": issue.severity,
                    "message": issue.message,
                    "auto_fixable": issue.auto_fixable,
                    "fix_command": issue.fix_command
                }
                for issue in result.issues
            ],
            "checks_run": result.checks_run,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except ImportError:
        # Preflight validator not available
        return {
            "passed": True,
            "issues": [],
            "checks_run": 0,
            "warning": "Preflight validator not available"
        }
    except Exception as e:
        logger.error(f"Preflight check failed: {e}")
        return {
            "passed": False,
            "issues": [{
                "check_name": "preflight",
                "severity": "error",
                "message": f"Preflight check failed: {str(e)}",
                "auto_fixable": False
            }],
            "checks_run": 0
        }


@router.post("/{scan_id}/resume", response_model=MessageResponse)
async def resume_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Resume a failed or stopped scan from its last checkpoint.
    
    Only works for scans that have checkpoint data saved.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if scan.status not in ["failed", "stopped", "error"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot resume scan with status: {scan.status}. Only failed/stopped scans can be resumed."
        )
    
    # Check if checkpoint exists
    try:
        from core.scan_checkpoint import ScanCheckpoint
        
        checkpoint = ScanCheckpoint(scan_id=scan_id)
        state = checkpoint.load()
        
        if not state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No checkpoint found for this scan. Cannot resume."
            )
        
        resume_point = checkpoint.get_resume_point()
        
        if not resume_point or resume_point[0] == "completed":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Scan was already completed. Start a new scan instead."
            )
        
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Scan resume feature not available"
        )
    
    # Get original scan config from progress or DB
    original_config = scan_progress.get(scan_id, {})
    
    # Update status to running
    await crud.update_scan_status(db, scan, "running", 0, f"Resuming from {resume_point[0]}")
    
    # Start resume in background
    background_tasks.add_task(
        run_security_scan,
        scan_id=scan_id,
        target_url=scan.target_url,
        login_url=original_config.get("auth_config", {}).get("login_url"),
        username=original_config.get("auth_config", {}).get("username"),
        password=original_config.get("password"),
        scan_type=scan.scan_type,
        user_id=current_user.id,
        two_factor_config=original_config.get("two_factor"),
        auth_config=original_config.get("auth_config"),
        attacks_config=original_config.get("attacks_config")
    )
    
    return MessageResponse(
        message=f"Scan resuming from phase: {resume_point[0]}",
        success=True,
        data={
            "resume_phase": resume_point[0],
            "checkpoint_data": resume_point[1] if len(resume_point) > 1 else {}
        }
    )


@router.get("/{scan_id}/recovery-status")
async def get_recovery_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get recovery/checkpoint status for a scan.
    
    Returns:
        Checkpoint info, resume capability, and scanner health stats.
    """
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    result = {
        "scan_id": scan_id,
        "status": scan.status,
        "can_resume": False,
        "checkpoint": None,
        "circuit_breakers": {},
        "recovery_attempts": 0
    }
    
    # Check checkpoint
    try:
        from core.scan_checkpoint import ScanCheckpoint
        
        checkpoint = ScanCheckpoint(scan_id=scan_id)
        state = checkpoint.load()
        
        if state:
            result["can_resume"] = checkpoint.can_resume()
            result["checkpoint"] = checkpoint.get_summary()
    except ImportError:
        pass
    
    # Get circuit breaker status
    try:
        from core.unified_executor import UnifiedExecutor
        
        result["circuit_breakers"] = UnifiedExecutor.get_circuit_breaker_status()
        result["problematic_scanners"] = UnifiedExecutor.get_problematic_scanners()
    except ImportError:
        pass
    
    # Get recovery attempts from progress
    if scan_id in scan_progress:
        result["recovery_attempts"] = scan_progress[scan_id].get("recovery_attempts", 0)
    
    return result


@router.get("/scanners/health")
async def get_scanner_health(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get health status of all scanners (circuit breaker states).
    
    Returns:
        Scanner health information including success rates and circuit states.
    """
    try:
        from core.unified_executor import UnifiedExecutor
        
        circuit_status = UnifiedExecutor.get_circuit_breaker_status()
        problematic = UnifiedExecutor.get_problematic_scanners()
        
        return {
            "total_tracked": len(circuit_status),
            "problematic_count": len(problematic),
            "problematic_scanners": problematic,
            "circuit_breakers": circuit_status
        }
    except ImportError:
        return {
            "total_tracked": 0,
            "problematic_count": 0,
            "problematic_scanners": [],
            "circuit_breakers": {},
            "warning": "Unified executor not available"
        }


@router.post("/scanners/{scanner_name}/reset-circuit")
async def reset_scanner_circuit_breaker(
    scanner_name: str,
    current_user: User = Depends(get_current_active_user)
):
    """
    Reset circuit breaker for a specific scanner.
    
    Use this to re-enable a scanner that was disabled due to repeated failures.
    """
    try:
        from core.unified_executor import UnifiedExecutor
        
        UnifiedExecutor.reset_circuit_breaker(scanner_name)
        
        return MessageResponse(
            message=f"Circuit breaker reset for scanner: {scanner_name}",
            success=True
        )
    except ImportError:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="Unified executor not available"
        )

# ==========================================


async def run_security_scan(
    scan_id: str,
    target_url: str,
    login_url: Optional[str],
    username: Optional[str],
    password: Optional[str],
    scan_type: str,
    user_id: UUID,
    two_factor_config: Optional[dict] = None,
    auth_config: Optional[dict] = None,
    attacks_config: Optional[dict] = None
):
    """
    Background task to run the actual security scan using WebScanRunner.
    
    Supports multiple authentication methods:
    - none: No authentication (unauthenticated scan only)
    - username_password: Traditional form-based login
    - social_login: User manually logs in via Google/Facebook/etc
    - phone_otp: Phone number + OTP code
    - manual_session: User provides session cookie/token
    
    Args:
        scan_id: Unique scan identifier
        target_url: Target website URL
        login_url: Login page URL
        username: Login username
        password: Login password
        scan_type: Type of scan (web, mobile, etc.)
        user_id: User ID who initiated the scan
        two_factor_config: Optional 2FA configuration dict
        auth_config: Authentication method configuration dict
        attacks_config: OWASP attack categories configuration from frontend
    """
    from database.connection import AsyncSessionLocal
    from services.manual_auth_service import manual_auth_service
    
    # Default auth config if not provided
    if auth_config is None:
        auth_config = {
            "auth_method": "username_password" if (username and password) else "none",
            "social_providers": [],
        }
    
    auth_method = auth_config.get("auth_method", "none")
    
    async with AsyncSessionLocal() as db:
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            logger.error(f"Scan {scan_id} not found in database")
            return
        
        logs = scan_progress.get(scan_id, {}).get("logs", [])
        
        # Helper to log both in-memory and to database
        async def log_to_db(message: str, level: str = "info", phase: str = None):
            """Persist log to database for audit trail"""
            try:
                async with AsyncSessionLocal() as log_db:
                    log_scan = await crud.get_scan_by_id(log_db, scan_id)
                    if log_scan:
                        await crud.add_scan_log(log_db, log_scan.id, message, level, phase)
            except Exception as e:
                logger.warning(f"Failed to persist log to database: {e}")
        
        def log(message: str, level: str = "info", persist: bool = False):
            """Add log entry (in-memory, optionally persist to DB)"""
            logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "level": level,
                "message": message
            })
            # Important logs should be persisted
            if persist or level in ("error", "warning", "phase"):
                import asyncio
                try:
                    # Create task to persist asynchronously
                    asyncio.create_task(log_to_db(message, level))
                except Exception:
                    pass  # Don't fail if logging fails
        
        try:
            # Update in-memory progress with status for /api/scans/running endpoint
            if scan_id in scan_progress:
                scan_progress[scan_id]["status"] = "running"
                scan_progress[scan_id]["phase"] = "Initializing"
                scan_progress[scan_id]["progress"] = 5
                scan_progress[scan_id]["target_url"] = target_url
                scan_progress[scan_id]["scan_type"] = scan_type
                scan_progress[scan_id]["started_at"] = datetime.utcnow().isoformat()
            
            # Update status to running
            await crud.update_scan_status(db, scan, "running", 5, "Initializing")
            log("Jarwis AGI initializing security assessment...", persist=True)
            
            # Log authentication method
            log(f"Authentication method: {auth_method}")
            
            # Log 2FA configuration if enabled
            if two_factor_config and two_factor_config.get('enabled'):
                tfa_type = two_factor_config.get('type', 'unknown')
                log(f"Two-factor authentication detected for target: type={tfa_type}")
            
            # Determine if auth is enabled based on method
            auth_enabled = auth_method not in ('none', None)
            
            # Get scan profile settings (full/quick/api/authenticated)
            scan_profile = (scan.config or {}).get('scan_profile', 'full')
            
            # Configure crawl settings based on scan profile
            crawl_settings = {
                'full': {'max_pages': 100, 'max_depth': 4},
                'quick': {'max_pages': 25, 'max_depth': 2},
                'api': {'max_pages': 50, 'max_depth': 3},
                'authenticated': {'max_pages': 150, 'max_depth': 5},
            }.get(scan_profile, {'max_pages': 100, 'max_depth': 4})
            
            # Build config for WebScanRunner
            runner_config = {
                'target': {
                    'url': target_url,
                    'scope': (scan.config or {}).get('scope', '')
                },
                'auth': {
                    'enabled': auth_enabled,
                    'method': auth_method,  # NEW: auth method type
                    'login_url': login_url or target_url,
                    'username': username or '',
                    'password': password or '',
                    'phone_number': auth_config.get('phone_number', ''),
                    'session_cookie': auth_config.get('session_cookie', ''),
                    'session_token': auth_config.get('session_token', ''),
                    'social_providers': auth_config.get('social_providers', []),
                    'selectors': (scan.config or {}).get('auth_selectors', {
                        'username': '#email, input[name="email"], input[name="username"], input[type="email"]',
                        'password': '#password, input[name="password"], input[type="password"]',
                        'submit': 'button[type="submit"], input[type="submit"], #loginButton'
                    }),
                    'two_factor': two_factor_config
                },
                'browser': {
                    # Headless mode: True for production (no display), False for local debugging
                    'headless': os.getenv('ENVIRONMENT', 'development') == 'production',
                    'slow_mo': 0 if os.getenv('ENVIRONMENT') == 'production' else 100
                },
                'crawl': crawl_settings,
                'scan_profile': scan_profile,
                'proxy': {
                    'enabled': (scan.config or {}).get('proxy_enabled', True),  # Allow disabling proxy
                    'port': (scan.config or {}).get('proxy_port', None)  # None = auto-allocate via PortManager
                },
                'scan_id': scan_id,  # Pass scan_id for manual auth coordination
                # Use rate_limit from user config, default to 10
                'rate_limit': (scan.config or {}).get('rate_limit', 10),
                # Use timeout from user config, default varies by profile
                'timeout': (scan.config or {}).get('timeout', 30 if scan_profile == 'full' else 15),
                # Pass scan_profile to attacks config for profile-based attack selection
                'attacks': _build_attacks_config(attacks_config, scan_profile),
                'report': {
                    'output_dir': str(Path(__file__).parent.parent.parent / 'data' / 'reports'),
                    'formats': (scan.config or {}).get('report_formats', ['html', 'json', 'pdf'])
                }
            }
            
            # Update progress helper
            def update_progress(phase: str, progress: int, message: str = ""):
                if scan_progress.get(scan_id, {}).get("stop"):
                    raise Exception("Scan stopped by user")
                
                if scan_id in scan_progress:
                    scan_progress[scan_id]["phase"] = phase
                    scan_progress[scan_id]["progress"] = progress
                
                if message:
                    log(f"{phase}: {message}")
                else:
                    log(f"Phase: {phase}")
            
            # Try to use new WebScanRunner, fallback to legacy if not available
            try:
                from core.web_scan_runner import WebScanRunner
                import time
                
                update_progress("Initializing", 5, "Starting advanced security scanner...")
                log("Jarwis is initializing the security assessment engine...")
                
                # Throttle DB updates to prevent SQLite locking
                # Only write to DB every 2 seconds or on important status changes
                _last_db_update = {"time": 0, "progress": 0, "phase": ""}
                _db_update_interval = 2.0  # seconds
                _important_statuses = {'waiting_for_manual_auth', 'waiting_for_otp', 'completed', 'failed'}
                
                async def _update_db_with_retry(scan_id: str, status: str, progress: int, phase: str, max_retries: int = 3):
                    """Update database with retry logic for SQLite locks"""
                    for attempt in range(max_retries):
                        try:
                            async with AsyncSessionLocal() as update_db:
                                update_scan = await crud.get_scan_by_id(update_db, scan_id)
                                if not update_scan:
                                    logger.warning(f"Scan {scan_id} not found in status callback")
                                    return False
                                await crud.update_scan_status(update_db, update_scan, status, progress, phase)
                                return True
                        except Exception as e:
                            if "database is locked" in str(e).lower() and attempt < max_retries - 1:
                                await asyncio.sleep(0.5 * (attempt + 1))  # Exponential backoff
                                continue
                            logger.error(f"DB update failed after {attempt + 1} attempts: {e}")
                            return False
                    return False
                
                # Status callback for WebScanRunner to update scan status
                async def status_callback(status: str, progress: int = None, phase: str = None):
                    """Callback for scanner to update status for all phases (throttled for SQLite)"""
                    try:
                        # Map phase to progress base if not provided
                        phase_progress_base = {
                            'preflight': 5,
                            'crawl': 15,
                            'pre_login_crawl': 15,
                            'Initializing components': 10,
                            'Pre-login crawl': 15,
                            'Crawl complete': 20,
                            'authentication': 30,
                            'Authentication': 30,
                            'Authentication complete': 35,
                            'post_login_crawl': 40,
                            'Post-login crawl': 40,
                            'Post-login crawl complete': 45,
                            'pre_login_attacks': 50,
                            'Running pre-login attacks': 45,
                            'Running security scanners': 55,
                            'Pre-login attacks complete': 65,
                            'post_login_attacks': 75,
                            'Running post-login attacks': 70,
                            'Running authenticated scanners': 80,
                            'Post-login attacks complete': 85,
                            'reporting': 90,
                            'completed': 100
                        }
                        
                        # Determine actual progress
                        actual_phase = phase or status
                        
                        # If phase is pre_login or post_login, it's from UnifiedExecutor
                        # Scale the progress within the appropriate range
                        if phase == 'pre_login':
                            # UnifiedExecutor sends 0-100 for its scanners
                            # Map to 50-65% of overall progress
                            if progress is not None:
                                actual_progress = 50 + int(progress * 0.15)  # 50-65%
                            else:
                                actual_progress = 55
                            actual_phase = 'Running security scanners'
                        elif phase == 'post_login':
                            # Map to 75-85% of overall progress
                            if progress is not None:
                                actual_progress = 75 + int(progress * 0.10)  # 75-85%
                            else:
                                actual_progress = 80
                            actual_phase = 'Running authenticated scanners'
                        else:
                            # Use provided progress or lookup
                            actual_progress = progress if progress is not None else phase_progress_base.get(actual_phase, phase_progress_base.get(phase, 20))
                        
                        # Update in-memory progress for logs endpoint
                        if scan_id in scan_progress:
                            scan_progress[scan_id]["phase"] = actual_phase
                            scan_progress[scan_id]["progress"] = actual_progress
                        
                        # Broadcast WebSocket update for real-time UI
                        try:
                            await broadcast_scan_progress(
                                scan_id=scan_id,
                                progress=actual_progress,
                                phase=actual_phase,
                                message=f"{actual_phase}",
                                findings_count=scan_progress.get(scan_id, {}).get("findings_count", 0),
                                current_task=phase or ""
                            )
                        except Exception as ws_err:
                            logger.debug(f"WebSocket broadcast skipped: {ws_err}")
                        
                        # Throttled database updates to prevent SQLite locking
                        # Important statuses (auth, otp, completed) always update immediately
                        # Regular progress updates only every _db_update_interval seconds
                        current_time = time.time()
                        is_important = status in _important_statuses
                        time_since_update = current_time - _last_db_update["time"]
                        progress_changed_significantly = abs(actual_progress - _last_db_update["progress"]) >= 10
                        phase_changed = actual_phase != _last_db_update["phase"]
                        
                        should_update_db = (
                            is_important or
                            time_since_update >= _db_update_interval or
                            (progress_changed_significantly and time_since_update >= 1.0) or
                            (phase_changed and time_since_update >= 0.5)
                        )
                        
                        if should_update_db:
                            # Special status handling
                            if status == 'waiting_for_manual_auth':
                                await _update_db_with_retry(scan_id, 'waiting_for_manual_auth', actual_progress, 'Waiting for manual login')
                                log(f"Scan paused: Waiting for manual authentication")
                                await broadcast_scan_status(scan_id, 'waiting_for_manual_auth', 'Waiting for manual login')
                            elif status == 'waiting_for_otp':
                                await _update_db_with_retry(scan_id, 'waiting_for_otp', actual_progress, 'Waiting for OTP')
                                log(f"Scan paused: Waiting for OTP input", persist=True)
                                await broadcast_scan_status(scan_id, 'waiting_for_otp', 'Waiting for OTP input')
                            elif status == 'error':
                                # Handle error status (e.g., OTP timeout, max attempts)
                                error_message = phase or 'Scan encountered an error'
                                await _update_db_with_retry(scan_id, 'error', actual_progress, error_message)
                                log(f"Scan error: {error_message}", level="error", persist=True)
                                await broadcast_scan_error(scan_id, error_message, recoverable=False)
                            else:
                                # Update database with current phase and progress
                                await _update_db_with_retry(scan_id, 'running', actual_progress, actual_phase)
                                if phase:
                                    log(phase, level="phase", persist=True)
                            
                            # Update last DB update tracking
                            _last_db_update["time"] = current_time
                            _last_db_update["progress"] = actual_progress
                            _last_db_update["phase"] = actual_phase
                    except Exception as e:
                        # Log error but don't swallow - propagate critical failures
                        error_msg = f"Status callback error: {e}"
                        logger.error(error_msg)
                        log(error_msg, level="error", persist=True)
                        # Don't raise - allow scan to continue
                
                runner = WebScanRunner(runner_config, status_callback=status_callback)
                
                # Run the scan (this handles all 6 steps internally)
                results = await runner.run()
                
                if results.get('status') == 'completed':
                    # Extract findings from results
                    findings_data = []
                    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
                    
                    stats = results.get('stats', {})
                    report = results.get('report', {})
                    
                    pre_login_vulns = results.get('pre_login_vulns', 0)
                    post_login_vulns = results.get('post_login_vulns', 0)
                    
                    pre_login_reqs = stats.get('pre_login', {}).get('total_requests', 0)
                    post_login_reqs = stats.get('post_login', {}).get('total_requests', 0)
                    
                    log(f"Analyzed {pre_login_reqs} requests before authentication")
                    if post_login_reqs > 0:
                        log(f"Analyzed {post_login_reqs} requests after authentication")
                    
                    total_vulns = pre_login_vulns + post_login_vulns
                    if total_vulns > 0:
                        log(f"Found {total_vulns} potential vulnerabilities")
                    
                    # Get severity counts from report
                    if report:
                        severity_counts = report.get('by_severity', severity_counts)
                        
                        # Report is already generated by WebScanRunner
                        report_paths = report.get('report_paths', {})
                    
                    # Update scan with results
                    await crud.update_scan_results(
                        db, scan,
                        findings_count=results.get('total_vulnerabilities', 0),
                        severity_counts=severity_counts,
                        report_paths=report_paths if 'report_paths' in locals() else {}
                    )
                    
                    await crud.update_scan_status(db, scan, "completed", 100, "Completed")
                    log("Scan completed successfully!")
                    
                    # Broadcast completion via WebSocket
                    try:
                        await broadcast_scan_complete(
                            scan_id=scan_id,
                            findings_count=results.get('total_vulnerabilities', 0),
                            duration_seconds=0,  # TODO: Calculate actual duration
                            summary={"severity_counts": severity_counts}
                        )
                    except Exception as ws_err:
                        logger.debug(f"WebSocket completion broadcast skipped: {ws_err}")
                    
                else:
                    raise Exception(results.get('error', 'Unknown error'))
                    
            except ImportError as ie:
                # WebScanRunner not available, fallback to legacy runner
                log("Switching to standard scanner...", "info")
                await _run_legacy_scan(db, scan, scan_id, runner_config, update_progress, log, user_id)
                
            except Exception as e:
                # Check if it's a proxy-related error - switch to standard scanner silently
                if "mitm" in str(e).lower() or "proxy" in str(e).lower():
                    log("Switching to standard scanner...", "info", persist=True)
                    await _run_legacy_scan(db, scan, scan_id, runner_config, update_progress, log, user_id)
                else:
                    raise
                
        except Exception as e:
            import traceback
            error_msg = str(e) or repr(e) or "Unknown error"
            full_traceback = traceback.format_exc()
            
            # Create user-friendly error message with tracking ID
            user_friendly_error, error_id = sanitize_error_for_user(error_msg, full_traceback)
            
            # Log user-friendly message with persistence (shown to user)
            log(f"Scan encountered an issue: {user_friendly_error}", "error", persist=True)
            # Full traceback already logged by sanitize_error_for_user with error_id
            
            # Update status with SANITIZED error message for user display
            # Full traceback is only in server logs, not stored in database
            await crud.update_scan_status(
                db, scan, "error", 
                progress=scan.progress, 
                phase="Error",  # Simple phase, no internal details
                error_message=user_friendly_error  # User-friendly message only
            )
            
            # Broadcast error via WebSocket
            try:
                await broadcast_scan_error(
                    scan_id=scan_id,
                    error=user_friendly_error,
                    recoverable=False
                )
            except Exception as ws_err:
                logger.debug(f"WebSocket error broadcast skipped: {ws_err}")
            
            # Refund the scan credit since the scan failed
            # This syncs the User.scans_this_month counter with actual ScanHistory count
            try:
                from database.models import User
                result = await db.execute(select(User).where(User.id == user_id))
                user = result.scalar_one_or_none()
                if user:
                    sub_manager = SubscriptionManager(db, user)
                    await sub_manager.refund_scan(scan_id, reason="scan_failed")
                    log("Scan credit refunded", "info", persist=True)
            except Exception as refund_error:
                logger.warning(f"Failed to refund scan credit for scan {scan_id}: {str(refund_error)}")


async def _run_legacy_scan(db, scan, scan_id: str, runner_config: dict, update_progress, log, user_id: UUID):
    """
    Fallback legacy scanning using PenTestRunner.
    Used when WebScanRunner or MITM proxy is not available.
    """
    from core.runner import PenTestRunner
    
    log("Jarwis standard scanner activated")
    
    # Convert config to legacy format
    legacy_config = {
        'target': runner_config['target'],
        'auth': {
            'enabled': runner_config['auth']['enabled'],
            'type': 'form',
            'login_url': runner_config['auth']['login_url'],
            'credentials': {
                'username': runner_config['auth']['username'],
                'password': runner_config['auth']['password']
            },
            'selectors': runner_config['auth']['selectors'],
            'two_factor': runner_config['auth'].get('two_factor')
        },
        'browser': runner_config['browser'],
        'proxy': {'enabled': False},
        'ai': {
            'provider': 'gemini',
            'model': 'gemini-2.5-flash'
        },
        'attacks': {
            'rate_limit': runner_config.get('rate_limit', 10),
            'timeout': runner_config.get('timeout', 15)
        },
        'owasp': {
            'injection': {'enabled': True},
            'xss': {'enabled': True},
            'misconfig': {'enabled': True},
            'sensitive_data': {'enabled': True},
            'access_control': {'enabled': True},
            'ssrf': {'enabled': True},
        },
        'report': runner_config['report']
    }
    
    runner = PenTestRunner(legacy_config, scan_id=scan_id)
    
    await runner.initialize()
    log("Legacy scanner initialized")
    
    current_phase = {"name": "Initializing", "progress": 5}
    
    def progress_callback(phase: str, progress: int, message: str = ""):
        nonlocal current_phase
        current_phase["name"] = phase
        current_phase["progress"] = progress
        update_progress(phase, progress, message)
    
    results = await runner.run(progress_callback=progress_callback)
    
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
        
        if findings_data:
            await crud.create_findings_bulk(db, scan.id, findings_data)
        
        await crud.update_scan_results(
            db, scan,
            findings_count=len(findings_data),
            severity_counts=severity_counts,
            report_paths={}
        )
    
    await crud.update_scan_status(db, scan, "completed", 100, "Completed")
    
    # Broadcast completion via WebSocket
    try:
        from api.websocket import broadcast_scan_complete
        await broadcast_scan_complete(
            scan_id=scan_id,
            findings_count=len(findings_data) if 'findings_data' in locals() else 0,
            duration_seconds=0,
            summary={"severity_counts": severity_counts if 'severity_counts' in locals() else {}}
        )
    except Exception as ws_err:
        pass  # Legacy scanner, WebSocket optional
    log("Scan completed successfully!")
    
    await runner.cleanup()


# ==========================================
# UNIFIED ORCHESTRATOR INTEGRATION
# ==========================================

async def run_scan_with_orchestrator(
    scan_id: str,
    target_url: str,
    login_url: Optional[str],
    username: Optional[str],
    password: Optional[str],
    scan_type: str,
    user_id: UUID,
    two_factor_config: Optional[dict] = None,
    auth_config: Optional[dict] = None,
    attacks_config: Optional[dict] = None
):
    """
    Run a security scan using the unified ScanOrchestrator.
    
    This is the new implementation that uses the centralized orchestrator
    for state management, progress tracking, and engine delegation.
    
    Enable by setting environment variable: USE_UNIFIED_ORCHESTRATOR=true
    """
    from database.connection import AsyncSessionLocal
    from core.scan_orchestrator import ScanOrchestrator
    from core.engine_protocol import EngineResult
    from database import crud
    
    logger.info(f"[Orchestrator] Starting scan {scan_id} via unified orchestrator")
    
    async with AsyncSessionLocal() as db:
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            logger.error(f"[Orchestrator] Scan {scan_id} not found in database")
            return
        
        # Default auth config if not provided
        if auth_config is None:
            auth_config = {
                "auth_method": "username_password" if (username and password) else "none",
                "social_providers": [],
            }
        
        # Get scan profile settings
        scan_profile = (scan.config or {}).get('scan_profile', 'full')
        
        # Configure crawl settings based on scan profile
        crawl_settings = {
            'full': {'max_pages': 100, 'max_depth': 4},
            'quick': {'max_pages': 25, 'max_depth': 2},
            'api': {'max_pages': 50, 'max_depth': 3},
            'authenticated': {'max_pages': 150, 'max_depth': 5},
        }.get(scan_profile, {'max_pages': 100, 'max_depth': 4})
        
        # Build config for the engine
        runner_config = {
            'target': {
                'url': target_url,
                'scope': (scan.config or {}).get('scope', '')
            },
            'auth': {
                'enabled': auth_config.get('auth_method') not in ('none', None),
                'method': auth_config.get('auth_method', 'none'),
                'login_url': login_url or target_url,
                'username': username or '',
                'password': password or '',
                'phone_number': auth_config.get('phone_number', ''),
                'session_cookie': auth_config.get('session_cookie', ''),
                'session_token': auth_config.get('session_token', ''),
                'social_providers': auth_config.get('social_providers', []),
                'selectors': (scan.config or {}).get('auth_selectors', {
                    'username': '#email, input[name="email"], input[name="username"], input[type="email"]',
                    'password': '#password, input[name="password"], input[type="password"]',
                    'submit': 'button[type="submit"], input[type="submit"], #loginButton'
                }),
                'two_factor': two_factor_config
            },
            'browser': {
                'headless': os.getenv('ENVIRONMENT', 'development') == 'production',
                'slow_mo': 0 if os.getenv('ENVIRONMENT') == 'production' else 100
            },
            'crawl': crawl_settings,
            'scan_profile': scan_profile,
            'proxy': {
                'enabled': (scan.config or {}).get('proxy_enabled', True),
                'port': (scan.config or {}).get('proxy_port', None)  # None = auto-allocate via PortManager
            },
            'scan_id': scan_id,
            'target_url': target_url,
            'rate_limit': (scan.config or {}).get('rate_limit', 10),
            'timeout': (scan.config or {}).get('timeout', 30 if scan_profile == 'full' else 15),
            'attacks': _build_attacks_config(attacks_config, scan_profile),
            'report': {
                'output_dir': str(Path(__file__).parent.parent.parent / 'data' / 'reports'),
                'formats': (scan.config or {}).get('report_formats', ['html', 'json', 'pdf'])
            }
        }
        
        try:
            # Create orchestrator
            orchestrator = ScanOrchestrator(
                scan_id=scan_id,
                scan_type=scan_type,
                config=runner_config,
                user_id=user_id,
                db=db,
            )
            
            # Run the scan
            result: EngineResult = await orchestrator.run()
            
            # Update database with results
            if result.status == "completed":
                severity_counts = {
                    "critical": result.critical_count,
                    "high": result.high_count,
                    "medium": result.medium_count,
                    "low": result.low_count,
                    "info": result.info_count,
                }
                
                await crud.update_scan_results(
                    db, scan,
                    findings_count=len(result.findings),
                    severity_counts=severity_counts,
                    report_paths=result.report_paths
                )
                
                await crud.update_scan_status(db, scan, "completed", 100, "Completed")
                
                # Broadcast completion
                try:
                    await broadcast_scan_complete(
                        scan_id=scan_id,
                        findings_count=len(result.findings),
                        duration_seconds=int(result.duration_seconds),
                        summary={"severity_counts": severity_counts}
                    )
                except Exception:
                    pass
                
                logger.info(f"[Orchestrator] Scan {scan_id} completed successfully with {len(result.findings)} findings")
            else:
                # Error case
                await crud.update_scan_status(
                    db, scan, "error",
                    progress=scan.progress,
                    phase="Error",
                    error_message=result.error_message
                )
                
                try:
                    await broadcast_scan_error(
                        scan_id=scan_id,
                        error=result.error_message or "Unknown error",
                        recoverable=False
                    )
                except Exception:
                    pass
                
                # Refund scan credit using SubscriptionManager
                try:
                    from database.models import User
                    result_user = await db.execute(select(User).where(User.id == user_id))
                    user = result_user.scalar_one_or_none()
                    if user:
                        sub_manager = SubscriptionManager(db, user)
                        await sub_manager.refund_scan(scan_id, reason="scan_error")
                except Exception as e:
                    logger.warning(f"Failed to refund scan credit: {e}")
                
        except Exception as e:
            import traceback
            logger.exception(f"[Orchestrator] Scan {scan_id} failed: {e}")
            
            user_friendly_error, error_id = sanitize_error_for_user(str(e), traceback.format_exc())
            
            await crud.update_scan_status(
                db, scan, "error",
                progress=scan.progress,
                phase="Error",
                error_message=user_friendly_error
            )
            
            try:
                await broadcast_scan_error(scan_id=scan_id, error=user_friendly_error, recoverable=False)
            except Exception:
                pass
            
            # Refund scan credit using SubscriptionManager
            try:
                from database.models import User
                result_user = await db.execute(select(User).where(User.id == user_id))
                user = result_user.scalar_one_or_none()
                if user:
                    sub_manager = SubscriptionManager(db, user)
                    await sub_manager.refund_scan(scan_id, reason="scan_exception")
            except Exception:
                pass


def get_scan_runner_function():
    """
    Get the appropriate scan runner function based on feature flag.
    
    Feature flag: USE_UNIFIED_ORCHESTRATOR
    - "false" (default): Legacy run_security_scan
    - "true": Uses core/scan_orchestrator.py (Layer 4)
    - "service": Uses services/scan_orchestrator_service.py (Layer 3 - RECOMMENDED)
    
    The "service" option merges orchestration INTO the services layer for cleaner architecture.
    """
    if USE_UNIFIED_ORCHESTRATOR == "service":
        logger.info("Using ScanOrchestratorService (Layer 3) for scans")
        return run_scan_with_service
    elif USE_UNIFIED_ORCHESTRATOR == "true":
        logger.info("Using ScanOrchestrator (Layer 4) for scans")
        return run_scan_with_orchestrator
    else:
        return run_security_scan


async def run_scan_with_service(
    scan_id: str,
    target_url: str,
    login_url: Optional[str],
    username: Optional[str],
    password: Optional[str],
    scan_type: str,
    user_id: UUID,
    two_factor_config: Optional[dict] = None,
    auth_config: Optional[dict] = None,
    attacks_config: Optional[dict] = None
):
    """
    Run a security scan using the ScanOrchestratorService (Layer 3).
    
    This is the RECOMMENDED approach that merges orchestration into the services layer,
    providing a cleaner architecture with fewer hops:
    
    API Route → Service (with orchestration) → Runner
    
    Enable by setting: USE_UNIFIED_ORCHESTRATOR=service
    """
    from services.scan_orchestrator_service import scan_orchestrator_service
    
    logger.info(f"[Service] Starting scan {scan_id} via ScanOrchestratorService")
    
    try:
        result = await scan_orchestrator_service.run_scan(
            scan_id=scan_id,
            target_url=target_url,
            scan_type=scan_type,
            user_id=user_id,
            login_url=login_url,
            username=username,
            password=password,
            two_factor_config=two_factor_config,
            auth_config=auth_config,
            attacks_config=attacks_config,
        )
        
        if result.status == "completed":
            logger.info(f"[Service] Scan {scan_id} completed with {result.findings_count} findings")
        else:
            logger.error(f"[Service] Scan {scan_id} ended with status: {result.status}")
            
    except Exception as e:
        logger.exception(f"[Service] Scan {scan_id} failed: {e}")
