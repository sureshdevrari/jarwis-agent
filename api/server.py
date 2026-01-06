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
from database.dependencies import get_current_user, get_current_user_optional
from database.security import (
    get_security_headers, get_client_ip, security_store, InputValidator
)
from api.routes import api_router

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


# Lifespan context manager for startup/shutdown
@asynccontextmanager
async def lifespan(app: FastAPI):
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
    try:
        await close_db()
        print("[OK] Database connections closed")
    except Exception as e:
        print(f"  Error closing database: {e}")


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
    
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        
        # Skip rate limiting for exempt paths
        if path in self.EXEMPT_PATHS or path.startswith("/static"):
            return await call_next(request)
        
        client_ip = get_client_ip(request)
        
        # Determine tier (anonymous by default)
        tier = "anonymous"
        
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


# Add security middleware (order matters - first added = last executed)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware)

# Enable CORS with explicit allowed origins for production
# TODO: Configure allowed_origins from environment variable
ALLOWED_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, use: ALLOWED_ORIGINS
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
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
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Start a new security scan"""
    # Check scan type
    if data.scan_type not in ['web', 'mobile', 'cloud']:
        raise HTTPException(status_code=400, detail='Invalid scan type')
    
    if data.scan_type in ['mobile', 'cloud']:
        raise HTTPException(
            status_code=400,
            detail=f"{data.scan_type.title()} scanning is coming soon! Only web scanning is available."
        )
    
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
        'user_id': current_user.id if current_user else None,  # Associate with user
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
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get full results of a scan"""
    return check_scan_access(scan_id, current_user)


@app.get('/api/scan/{scan_id}/findings')
async def get_scan_findings(
    scan_id: str, 
    severity: str = None,
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get findings/vulnerabilities for a scan"""
    job = check_scan_access(scan_id, current_user)
    findings = job.get('findings', [])
    
    # Filter by severity if specified
    if severity and severity != 'all':
        findings = [f for f in findings if f.get('severity', '').lower() == severity.lower()]
    
    # Calculate summary
    summary = {
        'total': len(job.get('findings', [])),
        'critical': len([f for f in job.get('findings', []) if f.get('severity') == 'critical']),
        'high': len([f for f in job.get('findings', []) if f.get('severity') == 'high']),
        'medium': len([f for f in job.get('findings', []) if f.get('severity') == 'medium']),
        'low': len([f for f in job.get('findings', []) if f.get('severity') == 'low']),
        'info': len([f for f in job.get('findings', []) if f.get('severity') == 'info']),
    }
    
    return {
        'scan_id': scan_id,
        'findings': findings,
        'summary': summary,
        'status': job['status']
    }


@app.get('/api/vulnerabilities')
async def get_all_vulnerabilities(
    current_user: Optional[User] = Depends(get_current_user_optional)
):
    """Get all vulnerabilities across all scans (filtered by user if authenticated)"""
    all_findings = []
    
    for scan_id, job in scan_jobs.items():
        # Filter by user if authenticated
        if current_user and job.get('user_id') and job['user_id'] != current_user.id:
            continue  # Skip scans from other users
        # If no user or scan has no user_id, include it (for backward compatibility)
        
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
    """List all available reports"""
    reports = []
    
    # Check report directories
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
                    'size': report_file.stat().st_size
                })
    
    # Sort by modified time (newest first)
    reports.sort(key=lambda x: x['modified'], reverse=True)
    
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
    
    job = check_scan_access(scan_id, current_user)
    
    if not job.get('report_path'):
        raise HTTPException(status_code=404, detail='Report not ready yet')
    
    html_path = Path(job['report_path'])
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
    job = check_scan_access(scan_id, current_user)
    
    if not job.get('report_path'):
        raise HTTPException(status_code=404, detail='Report not ready yet')
    
    report_path = Path(job['report_path'])
    if report_path.exists():
        return FileResponse(report_path)
    
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
async def get_running_scans():
    """Get currently running scans"""
    running = []
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
    
    try:
        job['status'] = 'running'
        log('Starting Jarwis AGI Pen Test scan...')
        
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
                'headless': True,  # Run headless for API
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
                'provider': 'ollama',
                'model': 'llama3:latest',
                'base_url': 'http://localhost:11434'
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
            'report': {
                'output_dir': 'reports',
                'formats': ['html', 'json']
            }
        }
        
        # Import runner
        from core.runner import PenTestRunner
        
        # Create runner
        runner = PenTestRunner(runner_config)
        
        # Run the scan
        job['phase'] = 'Initializing'
        job['progress'] = 5
        log('[START] Initializing Jarwis AGI security scanner...')
        
        try:
            await runner.initialize()
            log('[OK] Scanner components initialized successfully')
            
            # Check if stopped
            if job['status'] == 'stopped':
                log(' Scan stopped by user', 'warning')
                return
            
            # Phase 1: Anonymous Crawling
            job['phase'] = 'Phase 1: Anonymous Crawling'
            job['progress'] = 10
            log(' Starting reconnaissance - discovering endpoints...')
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
                log(' Scan stopped by user', 'warning')
                return
            
            # Phase 2: Pre-Login OWASP Scan
            job['phase'] = 'Phase 2: Pre-Login OWASP Scan'
            job['progress'] = 25
            log('[TEST] Running OWASP security tests on unauthenticated surfaces...')
            try:
                await runner.phase_2_prelogin_scan()
                finding_count = len(runner.context.findings) if hasattr(runner, 'context') else 0
                if finding_count > 0:
                    log(f'[ALERT] Found {finding_count} potential vulnerabilities so far', 'warning')
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
                    log('[OK] Pre-login scan completed')
            except Exception as e:
                log(f'  Pre-login scan encountered an issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log(' Scan stopped by user', 'warning')
                return
            
            # Phase 3: Authentication
            if runner_config['auth']['enabled']:
                job['phase'] = 'Phase 3: Authentication'
                job['progress'] = 35
                log(' Attempting authentication...')
                try:
                    await runner.phase_3_authenticate()
                    if runner.context.authenticated:
                        log('[OK] Successfully authenticated')
                    else:
                        log('  Authentication not successful', 'warning')
                except Exception as e:
                    log(f'  Authentication failed: {str(e)}', 'warning')
            else:
                job['phase'] = 'Phase 3: Authentication'
                job['progress'] = 35
                log('[SKIP] No credentials provided - skipping authentication phase')
            
            if job['status'] == 'stopped':
                log(' Scan stopped by user', 'warning')
                return
            
            # Phase 4: Authenticated Crawling
            if runner.context.authenticated:
                job['phase'] = 'Phase 4: Authenticated Crawling'
                job['progress'] = 45
                log('[CRAWL] Crawling authenticated areas...')
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
                log('[SKIP] Skipping authenticated crawling (not logged in)')
            
            if job['status'] == 'stopped':
                log(' Scan stopped by user', 'warning')
                return
            
            # Phase 5: Post-Login Scan
            job['phase'] = 'Phase 5: Post-Login Security Scan'
            job['progress'] = 60
            log('[TEST] Running post-login security tests (IDOR, CSRF, etc.)...')
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
                log(' Scan stopped by user', 'warning')
                return
            
            # Phase 6: API Testing
            job['phase'] = 'Phase 6: API Security Testing'
            job['progress'] = 70
            log('[API] Testing discovered API endpoints...')
            try:
                if hasattr(runner, 'phase_6_api_testing'):
                    await runner.phase_6_api_testing()
                log('[OK] API testing completed')
            except Exception as e:
                log(f'  API testing issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log(' Scan stopped by user', 'warning')
                return
            
            # Phase 7: AI-Guided Testing
            job['phase'] = 'Phase 7: AI-Guided Testing'
            job['progress'] = 80
            log('[AI] Jarwis AGI analyzing findings and suggesting additional tests...')
            try:
                if hasattr(runner, 'phase_7_ai_guided_testing'):
                    await runner.phase_7_ai_guided_testing()
                log('[OK] AI-guided testing completed')
            except Exception as e:
                log(f'  AI-guided testing issue: {str(e)}', 'warning')
            
            if job['status'] == 'stopped':
                log(' Scan stopped by user', 'warning')
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
                        log(f'[REPORT] Report generated: {job["report_path"]}')
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
            
            log(f'[DONE] Scan completed! Found {len(findings)} vulnerabilities', 'success')
            if critical_count > 0:
                log(f'[CRITICAL] {critical_count} Critical vulnerabilities found!', 'warning')
            if high_count > 0:
                log(f'  {high_count} High severity vulnerabilities found!', 'warning')
            
            job['status'] = 'completed'
            job['progress'] = 100
            job['phase'] = 'Completed'
            
        except Exception as e:
            log(f'[ERROR] Scan error: {str(e)}', 'error')
            job['status'] = 'error'
            job['phase'] = f'Error: {str(e)}'
            import traceback
            log(f'Stack trace: {traceback.format_exc()}', 'error')
        
        finally:
            try:
                await runner.cleanup()
            except:
                pass
        
        job['completed_at'] = datetime.now().isoformat()
        
    except Exception as e:
        log(f'[FATAL] Fatal error: {str(e)}', 'error')
        job['status'] = 'error'
        job['phase'] = f'Error: {str(e)}'
        job['completed_at'] = datetime.now().isoformat()


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000)
