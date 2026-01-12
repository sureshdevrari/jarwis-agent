"""
Jarwis AGI Pen Test - REST API Server (FastAPI)
Provides HTTP API for the React frontend

Security Features:
- Brute force protection on login
- Rate limiting per IP/tier
- Input validation and sanitization
- File upload security
- Security headers middleware
- CORS configuration
"""

import asyncio
import json
import os
import sys
import uuid
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, asdict
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.middleware.base import BaseHTTPMiddleware

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import database and routes
from database.connection import get_db, init_db, close_db
from database.models import User
from database.dependencies import get_current_user, get_current_user_optional, get_current_active_user
from database.security import (
    get_security_headers, get_client_ip, security_store, InputValidator
)
from api.routes import api_router
from shared.ai_config import get_ai_config

logger = logging.getLogger(__name__)

# Store for scan jobs
scan_jobs: Dict[str, dict] = {}
scan_logs: Dict[str, List[dict]] = {}


# Pydantic models for request/response
class ScanRequest(BaseModel):
    target_url: str
    login_url: Optional[str] = ""
    username: Optional[str] = ""
    password: Optional[str] = ""
    scan_type: str  # web, mobile, cloud


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    timestamp: str


@dataclass
class ScanConfig:
    target_url: str
    login_url: str
    username: str
    password: str
    scan_type: str  # web, mobile, cloud
    scan_id: str = ""
    
    def __post_init__(self):
        if not self.scan_id:
            self.scan_id = str(uuid.uuid4())[:8]


# Background task handle for stale scan detector
_stale_detector_task: Optional[asyncio.Task] = None


async def recover_running_scans():
    """
    Recover scan state on startup.
    
    Query database for scans with status="running", load their checkpoints,
    and either mark as "stalled" (if stale) or rebuild scan_progress dict entries.
    """
    from database.connection import get_db
    from database import crud
    from core.scan_checkpoint import ScanCheckpoint
    from api.routes.scans import scan_progress
    from datetime import datetime, timedelta
    
    STALE_THRESHOLD_MINUTES = 60  # 1 hour with no updates = stale
    
    try:
        async for db in get_db():
            # Get all scans marked as "running" in database
            from sqlalchemy import select
            from database.models import ScanHistory
            
            result = await db.execute(
                select(ScanHistory).where(ScanHistory.status == "running")
            )
            running_scans = result.scalars().all()
            
            if not running_scans:
                print("[OK] No orphaned running scans found")
                return
            
            print(f"[INFO] Found {len(running_scans)} scans marked as 'running' in database")
            
            for scan in running_scans:
                scan_id = scan.scan_id
                
                # Check if checkpoint exists and when it was last updated
                try:
                    checkpoint = ScanCheckpoint(scan_id)
                    state = checkpoint.load()
                    
                    if state:
                        # Check if checkpoint is stale
                        last_update = datetime.fromisoformat(state.updated_at)
                        age_minutes = (datetime.utcnow() - last_update).total_seconds() / 60
                        
                        if age_minutes > STALE_THRESHOLD_MINUTES:
                            # Mark as stalled in database
                            await crud.update_scan_status(
                                db, scan, "stalled", 
                                phase=f"Stalled - no updates for {int(age_minutes)} minutes",
                                validate_transition=False
                            )
                            print(f"  [STALLED] Scan {scan_id}: no updates for {int(age_minutes)} min")
                        else:
                            # Rebuild scan_progress entry for active tracking
                            scan_progress[scan_id] = {
                                "phase": state.current_phase,
                                "progress": len(state.phases) * 10,  # Estimate progress
                                "logs": [],
                                "stop": False,
                                "recovered": True,
                            }
                            print(f"  [RECOVERED] Scan {scan_id}: last update {int(age_minutes)} min ago")
                    else:
                        # No checkpoint - mark as stalled
                        await crud.update_scan_status(
                            db, scan, "stalled",
                            phase="Stalled - no checkpoint data",
                            validate_transition=False
                        )
                        print(f"  [STALLED] Scan {scan_id}: no checkpoint found")
                        
                except Exception as e:
                    logger.warning(f"Error processing scan {scan_id}: {e}")
                    # Mark as error if we can't process
                    await crud.update_scan_status(
                        db, scan, "error",
                        error_message=f"Recovery failed: {e}",
                        validate_transition=False
                    )
            
            await db.commit()
            break  # Only need one db session
            
    except Exception as e:
        logger.error(f"Scan recovery failed: {e}")
        print(f"  [WARN] Scan recovery error: {e}")


async def stale_scan_detector():
    """
    Background task that runs every 5 minutes to detect stalled scans.
    
    Checks for scans marked as "running" in DB that have no in-memory tracking
    and haven't been updated recently.
    """
    from database.connection import get_db
    from database import crud
    from api.routes.scans import scan_progress
    from core.scan_orchestrator import ScanOrchestrator
    from datetime import datetime, timedelta
    
    STALE_THRESHOLD_MINUTES = 60  # 1 hour
    CHECK_INTERVAL_SECONDS = 300  # 5 minutes
    
    while True:
        try:
            await asyncio.sleep(CHECK_INTERVAL_SECONDS)
            
            async for db in get_db():
                from sqlalchemy import select
                from database.models import ScanHistory
                
                # Find running scans
                result = await db.execute(
                    select(ScanHistory).where(ScanHistory.status == "running")
                )
                running_scans = result.scalars().all()
                
                stalled_count = 0
                for scan in running_scans:
                    scan_id = scan.scan_id
                    
                    # Skip if actively tracked in memory
                    if scan_id in scan_progress and not scan_progress[scan_id].get("recovered"):
                        continue
                    
                    # Skip if orchestrator is active
                    if ScanOrchestrator.get_active_scan(scan_id):
                        continue
                    
                    # Check how long since started/updated
                    check_time = scan.updated_at or scan.started_at
                    if check_time:
                        age_minutes = (datetime.utcnow() - check_time).total_seconds() / 60
                        
                        if age_minutes > STALE_THRESHOLD_MINUTES:
                            await crud.update_scan_status(
                                db, scan, "stalled",
                                phase=f"Stalled - no updates for {int(age_minutes)} minutes",
                                validate_transition=False
                            )
                            stalled_count += 1
                            logger.info(f"Marked scan {scan_id} as stalled (age: {int(age_minutes)} min)")
                
                if stalled_count > 0:
                    await db.commit()
                    logger.info(f"Stale detector: marked {stalled_count} scans as stalled")
                
                break  # Only need one db session
                
        except asyncio.CancelledError:
            logger.info("Stale scan detector shutting down")
            break
        except Exception as e:
            logger.error(f"Stale detector error: {e}")
            # Continue running despite errors


async def graceful_shutdown():
    """
    Gracefully stop all running scans and cleanup browsers on server shutdown.
    Handles both web scans (BrowserController) and mobile scans (MobileProcessRegistry).
    """
    from core.scan_orchestrator import ScanOrchestrator
    from core.browser import BrowserController
    
    print("  Stopping active scans...")
    
    # =====================================================
    # 1. Stop active web scans
    # =====================================================
    active_scans = ScanOrchestrator.get_all_active()
    
    if active_scans:
        print(f"  Found {len(active_scans)} active web scans to stop")
        
        # Request stop on all scans
        stop_tasks = []
        for scan_id, orchestrator in active_scans.items():
            try:
                stop_tasks.append(orchestrator.stop())
            except Exception as e:
                logger.warning(f"Error requesting stop for scan {scan_id}: {e}")
        
        # Wait up to 10 seconds for graceful stop
        if stop_tasks:
            try:
                await asyncio.wait_for(
                    asyncio.gather(*stop_tasks, return_exceptions=True),
                    timeout=10.0
                )
                print("[OK] Active web scans stopped gracefully")
            except asyncio.TimeoutError:
                print("  [WARN] Timeout waiting for web scans to stop")
    
    # =====================================================
    # 2. Stop active mobile scans
    # =====================================================
    try:
        from core.mobile_process_registry import MobileProcessRegistry
        
        mobile_scan_ids = MobileProcessRegistry.get_active_scans()
        if mobile_scan_ids:
            print(f"  Found {len(mobile_scan_ids)} active mobile scans to stop")
            
            # Cleanup all mobile scans
            cleaned_count = await MobileProcessRegistry.cleanup_all()
            
            if cleaned_count > 0:
                print(f"[OK] Cleaned up {cleaned_count} mobile scans (emulators, Frida, MITM)")
            else:
                print("[OK] No mobile scans needed cleanup")
        else:
            print("[OK] No active mobile scans")
    except ImportError:
        logger.debug("MobileProcessRegistry not available - skipping mobile cleanup")
    except Exception as e:
        logger.warning(f"Mobile scan cleanup error: {e}")
    
    # =====================================================
    # 3. Force cleanup any orphaned web browsers
    # =====================================================
    print("  Cleaning up browsers...")
    try:
        cleanup_result = await BrowserController.cleanup_orphaned_browsers_async(
            max_age_minutes=0,  # Kill all Playwright browsers
            force=True
        )
        if cleanup_result['killed'] > 0:
            print(f"[OK] Killed {cleanup_result['killed']} orphaned browser processes")
        else:
            print("[OK] No orphaned browsers found")
    except Exception as e:
        logger.warning(f"Browser cleanup error: {e}")


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
    global _stale_detector_task
    # Startup
    print("""
    +=============================================================+
    |           Jarwis AGI Pen Test - API SERVER                  |
    +=============================================================+
    |  API running on: http://localhost:8000                      |
    |  Frontend on:    http://localhost:3000                      |
    |  Auth endpoints: /api/auth/*                                |
    |  Admin endpoints: /api/admin/*                              |
    +=============================================================+
    """)
    
    # Initialize database with retry logic
    print("Initializing database connection...")
    try:
        db_success = await init_db(max_retries=3, retry_delay=2.0)
        if db_success:
            print("[OK] Database initialized successfully")
            
            # Warm up the database connection pool with a test query
            from database.connection import test_connection
            connected, error = await test_connection()
            if connected:
                print("[OK] Database connection verified")
                
                # Recover any orphaned running scans from previous session
                print("Recovering scan state...")
                await recover_running_scans()
                
                # Start background stale scan detector
                _stale_detector_task = asyncio.create_task(stale_scan_detector())
                print("[OK] Stale scan detector started")
            else:
                print(f"  Database connection test failed: {error}")
        else:
            from database.connection import get_connection_error
            error_msg = get_connection_error() or "Unknown error"
            print(f"  Database initialization failed: {error_msg}")
            print("    Server will continue but database features may be limited")
            print("    Check your database configuration in .env file")
            
    except Exception as e:
        print(f"  Database initialization error: {e}")
        print("    Server will continue but database features may be limited")
    
    yield
    
    # Shutdown
    print("\nShutting down Jarwis API server...")
    
    # Cancel stale detector
    if _stale_detector_task:
        _stale_detector_task.cancel()
        try:
            await _stale_detector_task
        except asyncio.CancelledError:
            pass
        print("[OK] Stale scan detector stopped")
    
    # Graceful shutdown of active scans and browsers
    await graceful_shutdown()
    
    try:
        await close_db()
        print("[OK] Database connections closed")
    except Exception as e:
        print(f"  Error closing database: {e}")


app = FastAPI(
    title="Jarwis AGI Pen Test API",
    description="AI-powered OWASP Top 10 penetration testing framework",
    version="1.0.0",
    lifespan=lifespan
)


# ============== Security Middleware ==============

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses"""
    
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        
        # Add security headers
        security_headers = get_security_headers()
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware based on IP and user tier"""
    
    # Endpoints exempt from rate limiting
    EXEMPT_PATHS = {
        "/api/health",
        "/api/health/db",
        "/docs",
        "/openapi.json",
        "/redoc",
    }
    
    # Paths with relaxed rate limiting for authenticated users (polling endpoints)
    RELAXED_PATHS = {
        "/api/scans/",  # Scan status polling
        "/logs",        # Log fetching
    }
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Skip rate limiting for exempt paths
        if path in self.EXEMPT_PATHS or path.startswith("/static"):
            return await call_next(request)
        
        client_ip = get_client_ip(request)
        
        # Determine tier from JWT token if available
        tier = "anonymous"
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from database.auth import decode_token
                token = auth_header[7:]  # Remove "Bearer " prefix
                payload = decode_token(token)
                if payload:
                    # Get user's plan from token or default to professional for relaxed limits
                    tier = payload.get("plan", "professional")
                    # Map plan names to rate limit tiers
                    if tier not in ["free", "individual", "professional", "enterprise"]:
                        tier = "professional"  # Default authenticated tier
            except Exception:
                pass  # Keep anonymous tier on any error
        
        # Skip rate limiting entirely for scan-related paths when authenticated
        is_scan_polling = any(pattern in path for pattern in self.RELAXED_PATHS)
        if is_scan_polling and tier != "anonymous":
            return await call_next(request)
        
        # Check rate limit
        is_allowed, current_count, limit = await security_store.check_rate_limit(
            client_ip, tier
        )
        
        if not is_allowed:
            logger.warning(f"Rate limit exceeded for {client_ip}: {current_count}/{limit}")
            return Response(
                content=json.dumps({
                    "detail": "Rate limit exceeded. Please slow down.",
                    "retry_after": 60
                }),
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"}
            )
        
        response = await call_next(request)
        
        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(limit)
        response.headers["X-RateLimit-Remaining"] = str(max(0, limit - current_count))
        response.headers["X-RateLimit-Reset"] = "60"
        
        return response


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF protection using double-submit cookie pattern.
    - Sets a CSRF token cookie on all responses
    - Validates X-CSRF-Token header matches cookie on state-changing requests
    """
    
    CSRF_COOKIE_NAME = "jarwis_csrf_token"
    CSRF_HEADER_NAME = "X-CSRF-Token"
    
    # Methods that require CSRF validation (state-changing)
    PROTECTED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    
    # Paths exempt from CSRF (login, token refresh, webhooks, health checks)
    EXEMPT_PATHS = {
        "/api/auth/login",
        "/api/auth/register",
        "/api/auth/refresh",
        "/api/auth/forgot-password",
        "/api/auth/reset-password",
        "/api/oauth/google/callback",
        "/api/oauth/github/callback",
        "/api/health",
        "/api/webhooks",
    }
    
    def _generate_csrf_token(self) -> str:
        """Generate a cryptographically secure CSRF token"""
        import secrets
        return secrets.token_urlsafe(32)
    
    async def dispatch(self, request: Request, call_next):
        # Get or generate CSRF token
        csrf_cookie = request.cookies.get(self.CSRF_COOKIE_NAME)
        
        # Validate CSRF for protected methods
        if request.method in self.PROTECTED_METHODS:
            path = request.url.path
            
            # Skip validation for exempt paths
            is_exempt = any(path.startswith(exempt) for exempt in self.EXEMPT_PATHS)
            
            if not is_exempt:
                csrf_header = request.headers.get(self.CSRF_HEADER_NAME)
                
                # If no CSRF cookie exists, this is a new session - generate one
                if not csrf_cookie:
                    # For new sessions on protected endpoints, require them to get a token first
                    # This prevents CSRF attacks on first requests
                    pass  # Allow for now, will be set on response
                elif csrf_header != csrf_cookie:
                    # Token mismatch - potential CSRF attack
                    logger.warning(f"CSRF validation failed for {request.method} {path} from {get_client_ip(request)}")
                    return Response(
                        content=json.dumps({
                            "detail": "CSRF validation failed. Please refresh the page and try again.",
                            "error_code": "CSRF_INVALID"
                        }),
                        status_code=403,
                        media_type="application/json"
                    )
        
        response = await call_next(request)
        
        # Set/refresh CSRF cookie on all responses
        new_token = csrf_cookie or self._generate_csrf_token()
        response.set_cookie(
            key=self.CSRF_COOKIE_NAME,
            value=new_token,
            httponly=False,  # Must be readable by JavaScript to send in header
            secure=os.getenv("ENVIRONMENT", "development") == "production",
            samesite="lax",
            max_age=86400,  # 24 hours
            path="/"
        )
        
        return response


# Add security middleware (order matters - first added = last executed)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(CSRFMiddleware)

# Enable CORS with explicit allowed origins
# IMPORTANT: allow_origins=["*"] with allow_credentials=True is INVALID!
# Browsers reject this combination. Must use explicit origins when credentials are enabled.
DEFAULT_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000,http://localhost:8000,http://127.0.0.1:8000"
ALLOWED_ORIGINS = [origin.strip() for origin in os.getenv("CORS_ORIGINS", DEFAULT_ORIGINS).split(",")]

# Log CORS configuration at startup
print(f"[CORS] Allowed origins: {ALLOWED_ORIGINS}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # Must be explicit origins, NOT "*" when credentials=True
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],  # Expose custom headers to frontend
)

# Try to mount static files for React frontend
frontend_build = Path(__file__).parent.parent / 'frontend' / 'build'
if frontend_build.exists():
    app.mount("/static", StaticFiles(directory=str(frontend_build / 'static')), name="static")

# Include API routes (auth, admin, etc.)
app.include_router(api_router)


def check_scan_access(scan_id: str, user: Optional[User] = None) -> dict:
    """Check if user has access to a scan and return the job"""
    if scan_id not in scan_jobs:
        raise HTTPException(status_code=404, detail='Scan not found')
    
    job = scan_jobs[scan_id]
    
    # Check ownership if user is authenticated and scan has a user_id
    if user and job.get('user_id') and job['user_id'] != user.id:
        raise HTTPException(status_code=403, detail='Access denied to this scan')
    
    return job


async def get_scan_report_path(scan_id: str, format: str = 'html', db: AsyncSession = None) -> Optional[Path]:
    """
    Get report path from in-memory cache or database.
    Falls back to database if not in scan_jobs.
    """
    from database import crud
    from uuid import UUID
    
    # First check in-memory scan_jobs
    if scan_id in scan_jobs:
        job = scan_jobs[scan_id]
        report_path = job.get('report_path')
        if report_path:
            path = Path(report_path)
            # For non-html formats, derive from html path
            if format == 'html':
                return path if path.exists() else None
            elif format == 'pdf':
                pdf_path = path.with_suffix('.pdf')
                return pdf_path if pdf_path.exists() else path  # Return html for conversion
            elif format == 'json':
                json_path = path.with_name(path.stem + '.json')
                return json_path if json_path.exists() else None
            elif format == 'sarif':
                sarif_path = path.with_name(path.stem + '.sarif')
                return sarif_path if sarif_path.exists() else None
    
    # Fall back to database lookup
    if db is None:
        # Create a new session for database lookup
        from database.connection import AsyncSessionLocal
        async with AsyncSessionLocal() as db_session:
            return await _get_report_from_db(scan_id, format, db_session)
    else:
        return await _get_report_from_db(scan_id, format, db)


async def _get_report_from_db(scan_id: str, format: str, db: AsyncSession) -> Optional[Path]:
    """Helper to get report path from database"""
    from database import crud
    from uuid import UUID
    
    try:
        scan_uuid = UUID(scan_id)
    except ValueError:
        # Not a valid UUID, try lookup by string scan_id
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            return None
    else:
        scan = await crud.get_scan_by_uuid(db, scan_uuid)
        if not scan:
            return None
    
    # Get the appropriate report path based on format
    report_path = None
    if format == 'html' and scan.report_html:
        report_path = Path(scan.report_html)
    elif format == 'json' and scan.report_json:
        report_path = Path(scan.report_json)
    elif format == 'sarif' and scan.report_sarif:
        report_path = Path(scan.report_sarif)
    elif format == 'pdf':
        # PDF is generated from HTML
        if scan.report_html:
            html_path = Path(scan.report_html)
            pdf_path = html_path.with_suffix('.pdf')
            return pdf_path if pdf_path.exists() else html_path
    
    if report_path and report_path.exists():
        return report_path
    
    return None


@app.get('/', response_class=HTMLResponse)
async def serve():
    """Serve React frontend"""
    index_path = frontend_build / 'index.html'
    if index_path.exists():
        return FileResponse(index_path)
    return HTMLResponse("<h1>Jarwis AGI Pen Test API</h1><p>Frontend not built. Run 'npm run build' in frontend/</p>")


@app.get('/api/health', response_model=HealthResponse)
async def health_check():
    """Health check endpoint"""
    return {
        'status': 'ok',
        'service': 'Jarwis AGI Pen Test API',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    }


@app.get('/api/health/db')
async def database_health_check():
    """Database health check endpoint with connection status"""
    from database.connection import is_db_available, get_connection_error, test_connection
    
    # Get current connection status
    db_available = is_db_available()
    connection_error = get_connection_error()
    
    # Try a live connection test
    connected, live_error = await test_connection()
    
    if connected:
        return {
            'status': 'ok',
            'database': 'connected',
            'message': 'Database connection is healthy',
            'timestamp': datetime.now().isoformat()
        }
    else:
        return {
            'status': 'degraded',
            'database': 'disconnected',
            'error': live_error or connection_error or 'Unknown connection error',
            'message': 'Database connection is not available',
            'timestamp': datetime.now().isoformat()
        }


@app.post('/api/scan/start', response_model=ScanResponse)
async def start_scan(
    data: ScanRequest, 
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),  # SECURITY: Require authentication
    db: AsyncSession = Depends(get_db)
):
    """Start a new security scan
    
    Security Requirements:
    - User MUST be authenticated
    - User MUST be authorized to scan the target domain:
      - Corporate email users can scan their own domain (e.g., user@company.com can scan company.com)
      - Personal email users MUST verify domain ownership via DNS TXT record
      - Developer plan bypasses domain verification (for testing only)
    """
    from urllib.parse import urlparse
    from shared.constants import is_personal_email
    from services.domain_verification_service import DomainVerificationService
    
    # Check scan type
    if data.scan_type not in ['web', 'mobile', 'cloud']:
        raise HTTPException(status_code=400, detail='Invalid scan type')
    
    if data.scan_type in ['mobile', 'cloud']:
        raise HTTPException(
            status_code=400,
            detail=f"{data.scan_type.title()} scanning is coming soon! Only web scanning is available."
        )
    
    # ========== DOMAIN AUTHORIZATION CHECK ==========
    # ALL scans require domain authorization (credential-based or not)
    # Only exceptions: Developer plan (for internal testing)
    
    # Extract target domain from URL
    try:
        parsed_url = urlparse(data.target_url)
        target_host = parsed_url.netloc.lower()
        # Remove port if present
        if ':' in target_host:
            target_host = target_host.split(':')[0]
        
        if not target_host:
            raise HTTPException(
                status_code=400,
                detail="Invalid target URL: could not extract domain"
            )
    except Exception as e:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid target URL: {str(e)}"
        )
    
    # Developer plan bypasses domain verification (for internal testing only)
    if current_user.plan != "developer":
        domain_service = DomainVerificationService(db)
        
        # ALL users must be authorized - personal emails ALWAYS need verification
        # Corporate emails can scan their own domain without verification
        is_authorized, auth_reason = await domain_service.is_authorized_to_scan(
            user_id=current_user.id,
            user_email=current_user.email,
            target_domain=target_host,
            require_verification_for_personal=True  # Personal emails must verify
        )
        
        if not is_authorized:
            user_has_personal_email = is_personal_email(current_user.email)
            email_domain = current_user.email.split('@')[1] if '@' in current_user.email else None
            
            logger.warning(
                f"Domain authorization DENIED: user={current_user.email}, "
                f"target={target_host}, reason={auth_reason}, personal_email={user_has_personal_email}"
            )
            
            if user_has_personal_email:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "domain_verification_required",
                        "message": "Users with personal email addresses must verify domain ownership before scanning any domain.",
                        "target_domain": target_host,
                        "user_email": current_user.email,
                        "action": "Go to Settings → Verified Domains to add and verify this domain via DNS TXT record.",
                        "verification_url": "/settings/domains"
                    }
                )
            else:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "domain_not_authorized",
                        "message": f"You can only scan domains matching your corporate email ({email_domain}) or domains you've verified.",
                        "target_domain": target_host,
                        "user_email_domain": email_domain,
                        "action": "Either scan your corporate domain or verify this domain in Settings → Verified Domains.",
                        "verification_url": "/settings/domains"
                    }
                )
        
        logger.info(f"Domain authorization GRANTED: user={current_user.email}, target={target_host}, reason={auth_reason}")
    else:
        logger.info(f"Developer plan bypass: user={current_user.email} scanning {target_host}")
    # ================================================
    
    # Create scan config
    config = ScanConfig(
        target_url=data.target_url,
        login_url=data.login_url or '',
        username=data.username or '',
        password=data.password or '',
        scan_type=data.scan_type
    )
    
    # Initialize scan job
    scan_jobs[config.scan_id] = {
        'id': config.scan_id,
        'user_id': current_user.id,  # Always associate with authenticated user
        'status': 'queued',
        'progress': 0,
        'phase': 'Initializing',
        'findings': [],
        'logs': [],
        'config': asdict(config),
        'started_at': datetime.now().isoformat(),
        'completed_at': None,
        'report_path': None,
        # Detailed scan data for UI
        'pages_scanned': [],
        'api_endpoints': [],
        'requests': []
    }
    
    # Initialize logs list
    scan_logs[config.scan_id] = []
    
    # Start scan in background
    background_tasks.add_task(run_scan_async, config)
    
    return {
        'scan_id': config.scan_id,
        'status': 'started',
        'message': 'Scan started successfully'
    }


@app.get('/api/scan/{scan_id}/status')
async def get_scan_status(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get status of a scan"""
    job = check_scan_access(scan_id, current_user)
    return {
        'id': job['id'],
        'status': job['status'],
        'progress': job['progress'],
        'phase': job['phase'],
        'findings_count': len(job['findings']),
        'started_at': job['started_at'],
        'completed_at': job['completed_at'],
        # Include target URL for display
        'target_url': job['config'].get('target_url', ''),
        # Detailed data for expandable UI cards
        'pages_scanned': job.get('pages_scanned', []),
        'api_endpoints': job.get('api_endpoints', []),
        'requests': job.get('requests', []),
        'findings': job.get('findings', []),
        'logs': job.get('logs', [])[-50:]  # Last 50 logs
    }


@app.get('/api/scan/{scan_id}/logs')
async def get_scan_logs(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get logs for a scan"""
    job = check_scan_access(scan_id, current_user)
    logs = scan_logs.get(scan_id, [])
    
    # Update job logs
    job['logs'] = logs
    
    return {
        'logs': logs[-100:]  # Last 100 logs
    }


@app.get('/api/scan/{scan_id}/results')
async def get_scan_results(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """Get full results of a scan with DB fallback for historical scans"""
    try:
        return check_scan_access(scan_id, current_user)
    except HTTPException as exc:
        # For completed/historical scans, fall back to persisted results in the database
        if exc.status_code != 404:
            raise
        from database.models import ScanHistory, Finding
        from sqlalchemy import select, or_
        scan_row_result = await db.execute(
            select(ScanHistory).where(
                or_(ScanHistory.scan_id == scan_id, ScanHistory.id == scan_id)
            )
        )
        scan_row = scan_row_result.scalar_one_or_none()
        if not scan_row:
            raise HTTPException(status_code=404, detail='Scan not found')
        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_row.id)
        )
        findings = [f.to_dict() if hasattr(f, 'to_dict') else {
            'id': str(f.id),
            'scan_id': str(f.scan_id),
            'finding_id': f.finding_id,
            'category': f.category,
            'severity': f.severity,
            'title': f.title,
            'description': f.description,
            'url': f.url,
            'method': f.method,
            'parameter': f.parameter,
            'evidence': f.evidence,
            'poc': f.poc,
            'reasoning': f.reasoning,
            'ai_verified': f.ai_verified,
            'is_false_positive': f.is_false_positive,
        } for f in findings_result.scalars().all()]
        return {
            'scan_id': scan_row.scan_id or str(scan_row.id),
            'status': scan_row.status,
            'target': scan_row.target_url,
            'findings': findings,
            'summary': {
                'total': len(findings),
                'critical': len([f for f in findings if f.get('severity') == 'critical']),
                'high': len([f for f in findings if f.get('severity') == 'high']),
                'medium': len([f for f in findings if f.get('severity') == 'medium']),
                'low': len([f for f in findings if f.get('severity') == 'low']),
                'info': len([f for f in findings if f.get('severity') == 'info']),
            }
        }


@app.get('/api/scan/{scan_id}/findings')
async def get_scan_findings(
    scan_id: str, 
    severity: str = None,
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """Get findings/vulnerabilities for a scan, with DB fallback"""
    try:
        job = check_scan_access(scan_id, current_user)
        findings = job.get('findings', [])
        status = job.get('status', 'completed')
    except HTTPException as exc:
        if exc.status_code != 404:
            raise
        from database.models import ScanHistory, Finding
        from sqlalchemy import select, or_
        scan_row_result = await db.execute(
            select(ScanHistory).where(
                or_(ScanHistory.scan_id == scan_id, ScanHistory.id == scan_id)
            )
        )
        scan_row = scan_row_result.scalar_one_or_none()
        if not scan_row:
            raise HTTPException(status_code=404, detail='Scan not found')
        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == scan_row.id)
        )
        findings = [f.to_dict() if hasattr(f, 'to_dict') else {
            'id': str(f.id),
            'scan_id': str(f.scan_id),
            'finding_id': f.finding_id,
            'category': f.category,
            'severity': f.severity,
            'title': f.title,
            'description': f.description,
            'url': f.url,
            'method': f.method,
            'parameter': f.parameter,
            'evidence': f.evidence,
            'poc': f.poc,
            'reasoning': f.reasoning,
            'ai_verified': f.ai_verified,
            'is_false_positive': f.is_false_positive,
        } for f in findings_result.scalars().all()]
        status = scan_row.status
        scan_id = scan_row.scan_id or str(scan_row.id)
    
    # Filter by severity if specified
    if severity and severity != 'all':
        findings = [f for f in findings if f.get('severity', '').lower() == severity.lower()]
    
    # Calculate summary
    summary = {
        'total': len(findings),
        'critical': len([f for f in findings if f.get('severity') == 'critical']),
        'high': len([f for f in findings if f.get('severity') == 'high']),
        'medium': len([f for f in findings if f.get('severity') == 'medium']),
        'low': len([f for f in findings if f.get('severity') == 'low']),
        'info': len([f for f in findings if f.get('severity') == 'info']),
    }
    
    return {
        'scan_id': scan_id,
        'findings': findings,
        'summary': summary,
        'status': status
    }


@app.get('/api/vulnerabilities')
async def get_all_vulnerabilities(
    current_user: Optional[User] = Depends(get_current_user_optional),
    db: AsyncSession = Depends(get_db)
):
    """Get all vulnerabilities across all scans (filtered by user if authenticated)
    
    Reads from database for persistent data, with fallback to in-memory scan_jobs for active scans.
    """
    from database.models import Finding, ScanHistory
    from sqlalchemy import select
    
    all_findings = []
    
    # First, get findings from database (persistent storage)
    if current_user:
        # Get findings for authenticated user's scans
        query = (
            select(Finding, ScanHistory.target_url)
            .join(ScanHistory, Finding.scan_id == ScanHistory.id)
            .where(ScanHistory.user_id == current_user.id)
            .order_by(Finding.severity.desc())
        )
        result = await db.execute(query)
        
        for finding, target_url in result:
            all_findings.append({
                'id': str(finding.id),
                'scan_id': str(finding.scan_id),
                'finding_id': finding.finding_id,
                'category': finding.category,
                'severity': finding.severity,
                'title': finding.title,
                'description': finding.description,
                'url': finding.url,
                'method': finding.method,
                'parameter': finding.parameter,
                'evidence': finding.evidence,
                'poc': finding.poc,
                'reasoning': finding.reasoning,
                'target': target_url,
                'ai_verified': finding.ai_verified,
                'is_false_positive': finding.is_false_positive,
            })
    else:
        # For unauthenticated users, check in-memory scan_jobs only
        for scan_id, job in scan_jobs.items():
            for finding in job.get('findings', []):
                finding_copy = finding.copy()
                finding_copy['scan_id'] = scan_id
                finding_copy['target'] = job['config']['target_url']
                all_findings.append(finding_copy)
    
    # Calculate summary
    summary = {
        'total': len(all_findings),
        'critical': len([f for f in all_findings if f.get('severity') == 'critical']),
        'high': len([f for f in all_findings if f.get('severity') == 'high']),
        'medium': len([f for f in all_findings if f.get('severity') == 'medium']),
        'low': len([f for f in all_findings if f.get('severity') == 'low']),
        'info': len([f for f in all_findings if f.get('severity') == 'info']),
    }
    
    return {
        'vulnerabilities': all_findings,
        'summary': summary
    }


@app.get('/api/reports')
async def list_reports():
    """List all available reports from filesystem and database"""
    from database.connection import AsyncSessionLocal
    from database import crud
    from sqlalchemy import select
    from database.models import ScanHistory
    
    reports = []
    seen_paths = set()  # Track seen report paths to avoid duplicates
    
    # Check report directories (including data/reports where new reports go)
    report_dirs = ['reports', 'report1', 'data/reports']
    for report_dir in report_dirs:
        report_path = Path(report_dir)
        if report_path.exists():
            for report_file in report_path.glob('*.html'):
                path_key = str(report_file.resolve())
                if path_key not in seen_paths:
                    seen_paths.add(path_key)
                    reports.append({
                        'name': report_file.name,
                        'path': f'/api/reports/{report_dir}/{report_file.name}',
                        'dir': report_dir,
                        'modified': report_file.stat().st_mtime,
                        'size': report_file.stat().st_size,
                        'source': 'filesystem'
                    })
    
    # Also check database for completed scans with reports
    try:
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ScanHistory)
                .where(ScanHistory.status == 'completed')
                .where(ScanHistory.report_html.isnot(None))
                .order_by(ScanHistory.ended_at.desc())
                .limit(100)
            )
            scans = result.scalars().all()
            
            for scan in scans:
                if scan.report_html:
                    html_path = Path(scan.report_html)
                    path_key = str(html_path.resolve()) if html_path.exists() else scan.report_html
                    
                    if path_key not in seen_paths:
                        seen_paths.add(path_key)
                        
                        # Extract relative dir for API path
                        if html_path.exists():
                            rel_dir = html_path.parent.name or 'reports'
                            reports.append({
                                'name': html_path.name,
                                'path': f'/api/scan/{scan.id}/report',
                                'scan_id': str(scan.id),
                                'dir': rel_dir,
                                'modified': html_path.stat().st_mtime if html_path.exists() else 0,
                                'size': html_path.stat().st_size if html_path.exists() else 0,
                                'target': scan.target_url,
                                'source': 'database'
                            })
    except Exception as e:
        logger.warning(f"Could not fetch reports from database: {e}")
    
    # Sort by modified time (newest first)
    reports.sort(key=lambda x: x.get('modified', 0), reverse=True)
    
    return {'reports': reports}


@app.get('/api/reports/latest')
async def get_latest_report():
    """Get the most recent report"""
    reports = []
    
    report_dirs = ['reports', 'report1']
    for report_dir in report_dirs:
        report_path = Path(report_dir)
        if report_path.exists():
            for report_file in report_path.glob('*.html'):
                reports.append({
                    'name': report_file.name,
                    'path': f'/api/reports/{report_dir}/{report_file.name}',
                    'dir': report_dir,
                    'modified': report_file.stat().st_mtime,
                    'full_path': str(report_file)
                })
    
    if not reports:
        raise HTTPException(status_code=404, detail='No reports found')
    
    # Get the most recent
    latest = max(reports, key=lambda x: x['modified'])
    return latest


@app.get('/api/reports/{report_dir}/{report_name}')
async def get_report_file(report_dir: str, report_name: str):
    """Serve a specific report file"""
    report_path = Path(report_dir) / report_name
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail='Report not found')
    
    return FileResponse(report_path, media_type='text/html')


@app.get('/api/reports/{report_dir}/{report_name}/pdf')
async def get_report_pdf(report_dir: str, report_name: str):
    """Generate and download PDF version of the report"""
    from core.reporters import ReportGenerator
    
    # Find the HTML report
    html_path = Path(report_dir) / report_name
    if not html_path.exists():
        raise HTTPException(status_code=404, detail='Report not found')
    
    # Generate PDF filename
    pdf_name = report_name.replace('.html', '.pdf')
    pdf_path = Path(report_dir) / pdf_name
    
    # Check if PDF already exists and is newer than HTML
    if pdf_path.exists() and pdf_path.stat().st_mtime >= html_path.stat().st_mtime:
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=pdf_name,
            headers={"Content-Disposition": f"attachment; filename={pdf_name}"}
        )
    
    # Generate PDF using async method
    generator = ReportGenerator(report_dir, ['pdf'])
    success = await generator.generate_pdf_async(html_path, pdf_path)
    
    if success and pdf_path.exists():
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=pdf_name,
            headers={"Content-Disposition": f"attachment; filename={pdf_name}"}
        )
    
    raise HTTPException(
        status_code=500, 
        detail='PDF generation failed. Please ensure weasyprint, pdfkit, or playwright is installed.'
    )


@app.get('/api/scan/{scan_id}/report/pdf')
async def get_scan_report_pdf(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get the PDF report for a scan"""
    from core.reporters import ReportGenerator
    
    # Get HTML path (database-aware lookup)
    html_path = await get_scan_report_path(scan_id, 'html')
    
    if not html_path:
        raise HTTPException(status_code=404, detail='Report not ready yet or scan not found')
    
    if not html_path.exists():
        raise HTTPException(status_code=404, detail='Report file not found')
    
    # Generate PDF path
    pdf_path = html_path.with_suffix('.pdf')
    
    # Check if PDF exists and is current
    if pdf_path.exists() and pdf_path.stat().st_mtime >= html_path.stat().st_mtime:
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=pdf_path.name,
            headers={"Content-Disposition": f"attachment; filename={pdf_path.name}"}
        )
    
    # Generate PDF using async method
    generator = ReportGenerator(str(html_path.parent), ['pdf'])
    success = await generator.generate_pdf_async(html_path, pdf_path)
    
    if success and pdf_path.exists():
        return FileResponse(
            pdf_path,
            media_type='application/pdf',
            filename=pdf_path.name,
            headers={"Content-Disposition": f"attachment; filename={pdf_path.name}"}
        )
    
    raise HTTPException(
        status_code=500,
        detail='PDF generation failed. Please install weasyprint: pip install weasyprint'
    )


@app.get('/api/scan/{scan_id}/report')
async def get_scan_report(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get the HTML report for a scan"""
    # Use database-aware lookup
    report_path = await get_scan_report_path(scan_id, 'html')
    
    if not report_path:
        raise HTTPException(status_code=404, detail='Report not ready yet or scan not found')
    
    if report_path.exists():
        return FileResponse(report_path, media_type='text/html')
    
    raise HTTPException(status_code=404, detail='Report file not found')


@app.get('/api/scan/{scan_id}/report/json')
async def get_scan_report_json(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get the JSON report for a scan"""
    report_path = await get_scan_report_path(scan_id, 'json')
    
    if not report_path:
        raise HTTPException(status_code=404, detail='JSON report not available')
    
    if report_path.exists():
        return FileResponse(report_path, media_type='application/json')
    
    raise HTTPException(status_code=404, detail='Report file not found')


@app.get('/api/scan/{scan_id}/report/sarif')
async def get_scan_report_sarif(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get the SARIF report for a scan (for IDE integration)"""
    report_path = await get_scan_report_path(scan_id, 'sarif')
    
    if not report_path:
        raise HTTPException(status_code=404, detail='SARIF report not available')
    
    if report_path.exists():
        return FileResponse(
            report_path, 
            media_type='application/sarif+json',
            headers={"Content-Disposition": f"attachment; filename={report_path.name}"}
        )
    
    raise HTTPException(status_code=404, detail='Report file not found')


@app.post('/api/scan/{scan_id}/stop')
async def stop_scan(
    scan_id: str,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Stop a running scan"""
    job = check_scan_access(scan_id, current_user)
    job['status'] = 'stopped'
    return {'status': 'stopped'}


@app.get('/api/scans')
async def list_scans(
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """List all scans (filtered by user if authenticated)"""
    scans = []
    for scan_id, job in scan_jobs.items():
        # Filter by user if authenticated
        if current_user and job.get('user_id') and job['user_id'] != current_user.id:
            continue
        
        scans.append({
            'id': job['id'],
            'scan_id': job['id'],
            'status': job['status'],
            'target': job['config']['target_url'],
            'target_url': job['config']['target_url'],
            'scan_type': job['config']['scan_type'],
            'started_at': job['started_at'],
            'completed_at': job.get('completed_at'),
            'findings_count': len(job['findings']),
            'progress': job.get('progress', 0),
            'phase': job.get('phase', '')
        })
    return {'scans': scans}


@app.get('/api/scans/all')
async def list_all_scans(
    type: str = None, 
    status: str = None, 
    search: str = None,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """List all scans with filters for frontend (filtered by user if authenticated)"""
    scans = []
    stats = {'total': 0, 'web': 0, 'mobile': 0, 'cloud': 0, 'running': 0, 'completed': 0, 'error': 0}
    
    for scan_id, job in scan_jobs.items():
        # Filter by user if authenticated
        if current_user and job.get('user_id') and job['user_id'] != current_user.id:
            continue
        
        scan_type = job['config']['scan_type']
        scan_status = job['status']
        target = job['config']['target_url']
        
        # Update stats
        stats['total'] += 1
        stats[scan_type] = stats.get(scan_type, 0) + 1
        if scan_status in stats:
            stats[scan_status] += 1
        
        # Apply filters
        if type and type != 'all' and scan_type != type:
            continue
        if status and status != 'all' and scan_status != status:
            continue
        if search and search.lower() not in target.lower():
            continue
        
        scans.append({
            'id': scan_id,
            'scan_id': scan_id,
            'status': scan_status,
            'target': target,
            'target_url': target,
            'scan_type': scan_type,
            'type': scan_type,
            'started_at': job['started_at'],
            'start_time': job['started_at'],
            'completed_at': job.get('completed_at'),
            'findings_count': len(job['findings']),
            'progress': job.get('progress', 0),
            'phase': job.get('phase', ''),
            'results': {
                'critical': len([f for f in job['findings'] if f.get('severity') == 'critical']),
                'high': len([f for f in job['findings'] if f.get('severity') == 'high']),
                'medium': len([f for f in job['findings'] if f.get('severity') == 'medium']),
                'low': len([f for f in job['findings'] if f.get('severity') == 'low']),
            }
        })
    
    return {'scans': scans, 'stats': stats}


@app.get('/api/scans/running')
async def get_running_scans(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get currently running scans - checks both in-memory and database"""
    running = []
    
    # First check in-memory scan_jobs (legacy)
    for scan_id, job in scan_jobs.items():
        if job['status'] in ['running', 'queued']:
            running.append({
                'id': scan_id,
                'scan_id': scan_id,
                'status': job['status'],
                'target': job['config']['target_url'],
                'scan_type': job['config']['scan_type'],
                'progress': job.get('progress', 0),
                'phase': job.get('phase', ''),
                'started_at': job['started_at']
            })
    
    # Also check in-memory scan_progress from routes/scans.py
    from api.routes.scans import scan_progress
    for scan_id, progress_data in scan_progress.items():
        # Avoid duplicates
        if not any(s['scan_id'] == scan_id for s in running):
            status = progress_data.get('status', 'running')
            if status in ['running', 'queued', 'initializing']:
                running.append({
                    'id': scan_id,
                    'scan_id': scan_id,
                    'status': status,
                    'target': progress_data.get('target_url', 'Unknown'),
                    'scan_type': progress_data.get('scan_type', 'web'),
                    'progress': progress_data.get('progress', 0),
                    'phase': progress_data.get('phase', 'Initializing'),
                    'started_at': progress_data.get('started_at', '')
                })
    
    # Finally check database for user's running scans (most reliable)
    try:
        from sqlalchemy import select
        from database.models import ScanHistory
        
        result = await db.execute(
            select(ScanHistory)
            .where(
                ScanHistory.user_id == current_user.id,
                ScanHistory.status.in_(['running', 'queued', 'initializing'])
            )
            .order_by(ScanHistory.started_at.desc())
            .limit(10)
        )
        db_scans = result.scalars().all()
        
        for scan in db_scans:
            # Avoid duplicates
            if not any(s['scan_id'] == scan.scan_id for s in running):
                running.append({
                    'id': str(scan.id),
                    'scan_id': scan.scan_id,
                    'status': scan.status,
                    'target': scan.target_url,
                    'scan_type': scan.scan_type or 'web',
                    'progress': scan.progress or 0,
                    'phase': scan.phase or 'Initializing',
                    'started_at': scan.started_at.isoformat() if scan.started_at else ''
                })
    except Exception as e:
        logger.warning(f"Failed to fetch running scans from database: {e}")
    
    return {'scans': running}


@app.get('/api/scans/last')
async def get_last_scan():
    """Get the most recent scan"""
    if not scan_jobs:
        raise HTTPException(status_code=404, detail='No scans found')
    
    # Sort by started_at and get the most recent
    sorted_scans = sorted(
        scan_jobs.items(),
        key=lambda x: x[1].get('started_at', ''),
        reverse=True
    )
    
    if sorted_scans:
        scan_id, job = sorted_scans[0]
        return {
            'id': scan_id,
            'scan_id': scan_id,
            'status': job['status'],
            'target': job['config']['target_url'],
            'scan_type': job['config']['scan_type'],
            'progress': job.get('progress', 0),
            'phase': job.get('phase', ''),
            'started_at': job['started_at'],
            'findings_count': len(job['findings'])
        }
    
    raise HTTPException(status_code=404, detail='No scans found')


def _load_ai_key_from_yaml() -> str:
    """Load AI API key from config.yaml as fallback if not in environment"""
    import yaml
    config_path = Path(__file__).parent.parent / 'config' / 'config.yaml'
    local_config_path = Path(__file__).parent.parent / 'config' / 'config.local.yaml'
    
    # Try local config first, then main config
    for path in [local_config_path, config_path]:
        if path.exists():
            try:
                with open(path) as f:
                    cfg = yaml.safe_load(f)
                    key = cfg.get('ai', {}).get('api_key')
                    if key:
                        return key
            except Exception:
                continue
    return ''


async def run_scan_async(config: ScanConfig):
    """Run scan in background"""
    scan_id = config.scan_id
    job = scan_jobs[scan_id]
    logs = scan_logs[scan_id]
    
    def log(message: str, level: str = 'info'):
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'level': level,
            'message': message
        }
        logs.append(log_entry)
        job['logs'] = logs  # Keep job logs in sync
    
    def log_vulnerability_summary(findings):
        """Log vulnerability counts by severity with colored indicators"""
        if not findings:
            return
        critical = len([f for f in findings if (f.severity if hasattr(f, 'severity') else f.get('severity', '')) == 'critical'])
        high = len([f for f in findings if (f.severity if hasattr(f, 'severity') else f.get('severity', '')) == 'high'])
        medium = len([f for f in findings if (f.severity if hasattr(f, 'severity') else f.get('severity', '')) == 'medium'])
        low = len([f for f in findings if (f.severity if hasattr(f, 'severity') else f.get('severity', '')) == 'low'])
        
        if critical > 0:
            log(f'[CRITICAL] {critical} Critical vulnerability found!', 'warning')
        if high > 0:
            log(f'[HIGH] {high} High severity issue(s) detected', 'warning')
        if medium > 0:
            log(f'[MEDIUM] {medium} Medium severity issue(s) detected', 'info')
        if low > 0:
            log(f'[LOW] {low} Low severity issue(s) noted', 'info')
    
    try:
        job['status'] = 'running'
        log('Jarwis AGI initializing security assessment...')
        log('Jarwis is analyzing the target and planning attack vectors...')
        
        # Build config dict for runner
        runner_config = {
            'target': {
                'url': config.target_url,
                'scope': ''
            },
            'auth': {
                'enabled': bool(config.username and config.password),
                'type': 'form',
                'login_url': config.login_url or config.target_url,
                'credentials': {
                    'username': config.username,
                    'password': config.password
                },
                'selectors': {
                    'username': '#email, input[name="email"], input[name="username"], input[type="email"]',
                    'password': '#password, input[name="password"], input[type="password"]',
                    'submit': 'button[type="submit"], input[type="submit"], #loginButton'
                },
                'success_indicator': 'logout, account, dashboard, welcome, profile'
            },
            'browser': {
                'headless': False,  # Show browser so user can see what's happening
                'slow_mo': 100
            },
            'proxy': {
                'enabled': False,
                'mitm': {
                    'enabled': False  # Can be enabled for HTTPS interception
                }
            },
            'ai': {
                'enabled': True,
                # Load AI config - try centralized config first, then YAML fallback
                'provider': get_ai_config().provider or 'gemini',
                'model': get_ai_config().model or 'gemini-2.5-flash',
                'api_key': get_ai_config().api_key or _load_ai_key_from_yaml(),
                'base_url': get_ai_config().base_url,
            },
            'attacks': {
                'enabled': {
                    'injection': True,
                    'xss': True,
                    'misconfig': True,
                    'sensitive_data': True,
                    'upload': True,
                    'api': True
                }
            },
            'owasp': {
                'injection': {'enabled': True},
                'xss': {'enabled': True},
                'misconfig': {'enabled': True},
                'sensitive_data': {'enabled': True}
            },
            'reporting': {
                'output_dir': 'reports',
                'format': ['html', 'json']
            }
        }
        
        # Import runner
        from core.runner import PenTestRunner
        
        # Create runner
        runner = PenTestRunner(runner_config)
        
        # Run the scan
        job['phase'] = 'Initializing'
        job['progress'] = 5
        log('Jarwis is preparing the security assessment plan...')
        
        try:
            await runner.initialize()
            log('Security scanner ready')
            log(f'Target locked: {config.target_url}')
            
            # Check if stopped
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 1: Anonymous Crawling
            job['phase'] = 'Phase 1: Anonymous Crawling'
            job['progress'] = 10
            log('Phase 1: Reconnaissance - Jarwis is mapping the attack surface...')
            try:
                await runner.phase_1_crawl_anonymous()
                endpoint_count = len(runner.context.endpoints) if hasattr(runner, 'context') else 0
                log(f'  Discovered {endpoint_count} endpoints')
                
                # Update detailed data for UI
                if hasattr(runner, 'context'):
                    # Update pages scanned
                    job['pages_scanned'] = [
                        {'url': ep.get('url', ep) if isinstance(ep, dict) else str(ep), 
                         'method': ep.get('method', 'GET') if isinstance(ep, dict) else 'GET'}
                        for ep in runner.context.endpoints[:100]  # Limit to 100
                    ]
                    # Update API endpoints (filter for API-like URLs)
                    job['api_endpoints'] = [
                        {'url': ep.get('url', ep) if isinstance(ep, dict) else str(ep),
                         'method': ep.get('method', 'GET') if isinstance(ep, dict) else 'GET'}
                        for ep in runner.context.endpoints 
                        if '/api/' in str(ep.get('url', ep) if isinstance(ep, dict) else ep).lower()
                        or '/rest/' in str(ep.get('url', ep) if isinstance(ep, dict) else ep).lower()
                        or '/graphql' in str(ep.get('url', ep) if isinstance(ep, dict) else ep).lower()
                    ][:100]
                    # Update requests from crawler
                    if hasattr(runner.context, 'requests'):
                        job['requests'] = [
                            {'url': req.get('url', ''), 'method': req.get('method', 'GET'), 'status': req.get('status', 200)}
                            for req in runner.context.requests[:500]
                        ]
            except Exception as e:
                log(f'  Crawling phase encountered an issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 2: Pre-Login OWASP Scan
            job['phase'] = 'Phase 2: Pre-Login OWASP Scan'
            job['progress'] = 25
            log('Phase 2: Jarwis is testing for OWASP Top 10 vulnerabilities...')
            try:
                await runner.phase_2_prelogin_scan()
                finding_count = len(runner.context.findings) if hasattr(runner, 'context') else 0
                if finding_count > 0:
                    log_vulnerability_summary(runner.context.findings)
                    # Update findings early for UI
                    job['findings'] = [
                        {
                            'id': f.id if hasattr(f, 'id') else f.get('id', ''),
                            'title': f.title if hasattr(f, 'title') else f.get('title', ''),
                            'severity': f.severity if hasattr(f, 'severity') else f.get('severity', 'info'),
                            'category': f.category if hasattr(f, 'category') else f.get('category', ''),
                            'url': f.url if hasattr(f, 'url') else f.get('url', '')
                        }
                        for f in runner.context.findings
                    ]
                else:
                    log('Pre-login security tests completed')
            except Exception as e:
                log(f'  Pre-login scan encountered an issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 3: Authentication
            if runner_config['auth']['enabled']:
                job['phase'] = 'Phase 3: Authentication'
                job['progress'] = 35
                log(' Attempting authentication...')
                try:
                    await runner.phase_3_authenticate()
                    if runner.context.authenticated:
                        log('Successfully logged in - unlocking authenticated testing')
                    else:
                        log('  Authentication not successful', 'warning')
                except Exception as e:
                    log(f'  Authentication failed: {str(e)}', 'warning')
            else:
                job['phase'] = 'Phase 3: Authentication'
                job['progress'] = 35
                log('No credentials provided - testing unauthenticated surfaces only')
            
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 4: Authenticated Crawling
            if runner.context.authenticated:
                job['phase'] = 'Phase 4: Authenticated Crawling'
                job['progress'] = 45
                log('Phase 4: Jarwis is exploring protected areas...')
                try:
                    await runner.phase_4_crawl_authenticated()
                    new_endpoints = len(runner.context.endpoints) if hasattr(runner, 'context') else 0
                    log(f'  Total endpoints after auth crawl: {new_endpoints}')
                    
                    # Update detailed data for UI after authenticated crawl
                    if hasattr(runner, 'context'):
                        job['pages_scanned'] = [
                            {'url': ep.get('url', ep) if isinstance(ep, dict) else str(ep), 
                             'method': ep.get('method', 'GET') if isinstance(ep, dict) else 'GET'}
                            for ep in runner.context.endpoints[:100]
                        ]
                        job['api_endpoints'] = [
                            {'url': ep.get('url', ep) if isinstance(ep, dict) else str(ep),
                             'method': ep.get('method', 'GET') if isinstance(ep, dict) else 'GET'}
                            for ep in runner.context.endpoints 
                            if '/api/' in str(ep.get('url', ep) if isinstance(ep, dict) else ep).lower()
                            or '/rest/' in str(ep.get('url', ep) if isinstance(ep, dict) else ep).lower()
                            or '/graphql' in str(ep.get('url', ep) if isinstance(ep, dict) else ep).lower()
                        ][:100]
                except Exception as e:
                    log(f'  Authenticated crawling issue: {str(e)}', 'warning')
            else:
                job['progress'] = 45
                log('Skipping authenticated crawling (not logged in)')
            
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 5: Post-Login Scan
            job['phase'] = 'Phase 5: Post-Login Security Scan'
            job['progress'] = 60
            log('Phase 5: Jarwis is testing for authorization vulnerabilities...')
            try:
                await runner.phase_5_postlogin_scan()
                finding_count = len(runner.context.findings) if hasattr(runner, 'context') else 0
                log(f'  Total findings: {finding_count}')
                
                # Update findings for UI
                if hasattr(runner, 'context') and runner.context.findings:
                    job['findings'] = [
                        {
                            'id': f.id if hasattr(f, 'id') else f.get('id', ''),
                            'title': f.title if hasattr(f, 'title') else f.get('title', ''),
                            'severity': f.severity if hasattr(f, 'severity') else f.get('severity', 'info'),
                            'category': f.category if hasattr(f, 'category') else f.get('category', ''),
                            'url': f.url if hasattr(f, 'url') else f.get('url', '')
                        }
                        for f in runner.context.findings
                    ]
            except Exception as e:
                log(f'  Post-login scan issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 6: API Testing
            job['phase'] = 'Phase 6: API Security Testing'
            job['progress'] = 70
            log('Phase 6: Jarwis is analyzing API security...')
            try:
                if hasattr(runner, 'phase_6_api_testing'):
                    await runner.phase_6_api_testing()
                log('API security testing completed')
            except Exception as e:
                log(f'  API testing issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 7: AI-Guided Testing
            job['phase'] = 'Phase 7: AI-Guided Testing'
            job['progress'] = 80
            log('Phase 7: Jarwis AGI is thinking... analyzing patterns')
            try:
                if hasattr(runner, 'phase_7_ai_guided_testing'):
                    await runner.phase_7_ai_guided_testing()
                log('AI analysis completed')
            except Exception as e:
                log(f'  AI-guided testing issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log('Scan stopped by user', 'warning')
                return
            
            # Phase 8: Report Generation
            job['phase'] = 'Phase 8: Report Generation'
            job['progress'] = 95
            log(' Generating security report...')
            try:
                if hasattr(runner, 'phase_10_generate_report'):
                    await runner.phase_10_generate_report()
                elif hasattr(runner, 'reporter') and runner.reporter:
                    target_name = config.target_url.replace('https://', '').replace('http://', '').split('/')[0]
                    report_paths = runner.reporter.generate(
                        target_name=target_name,
                        findings=runner.context.findings,
                        scan_config=runner_config,
                        endpoints_count=len(runner.context.endpoints),
                        authenticated=runner.context.authenticated
                    )
                    if report_paths:
                        job['report_path'] = report_paths.get('html', '')
                        log('Security report generated successfully')
            except Exception as e:
                log(f'  Report generation issue: {str(e)}', 'warning')
            
            # Extract findings
            if hasattr(runner, 'context') and hasattr(runner.context, 'findings'):
                for finding in runner.context.findings:
                    job['findings'].append({
                        'id': getattr(finding, 'id', str(uuid.uuid4())[:8]),
                        'category': getattr(finding, 'category', 'Unknown'),
                        'severity': getattr(finding, 'severity', 'info'),
                        'title': getattr(finding, 'title', 'Finding'),
                        'description': getattr(finding, 'description', ''),
                        'url': getattr(finding, 'url', ''),
                        'method': getattr(finding, 'method', ''),
                        'parameter': getattr(finding, 'parameter', ''),
                        'evidence': getattr(finding, 'evidence', ''),
                        'poc': getattr(finding, 'poc', ''),
                        'remediation': getattr(finding, 'remediation', ''),
                        'cwe_id': getattr(finding, 'cwe_id', ''),
                        'status': 'Open'
                    })
            
            # Get report path if not already set
            if not job.get('report_path'):
                report_dir = Path('reports')
                if report_dir.exists():
                    html_reports = list(report_dir.glob('*.html'))
                    if html_reports:
                        job['report_path'] = str(sorted(html_reports, key=lambda x: x.stat().st_mtime)[-1])
            
            # Calculate severity counts
            findings = job['findings']
            critical_count = len([f for f in findings if f.get('severity') == 'critical'])
            high_count = len([f for f in findings if f.get('severity') == 'high'])
            medium_count = len([f for f in findings if f.get('severity') == 'medium'])
            low_count = len([f for f in findings if f.get('severity') == 'low'])
            
            log(f'Scan completed! Jarwis found {len(findings)} security issues', 'success')
            if critical_count > 0:
                log(f'{critical_count} CRITICAL vulnerabilities require immediate attention!', 'warning')
            if high_count > 0:
                log(f'  {high_count} High severity vulnerabilities found!', 'warning')
            
            job['status'] = 'completed'
            job['progress'] = 100
            job['phase'] = 'Completed'
            
        except Exception as e:
            log('Scan encountered an error', 'error')
            job['status'] = 'error'
            job['phase'] = f'Error: {str(e)}'
            import traceback
            # Stack trace logged internally
        
        finally:
            try:
                await runner.cleanup()
            except:
                pass
        
        job['completed_at'] = datetime.now().isoformat()
        
    except Exception as e:
        log('A critical error occurred', 'error')
        job['status'] = 'error'
        job['phase'] = f'Error: {str(e)}'
        job['completed_at'] = datetime.now().isoformat()


if __name__ == '__main__':
    import uvicorn
    port = int(os.environ.get('PORT', 8000))
    uvicorn.run(app, host='0.0.0.0', port=port)
