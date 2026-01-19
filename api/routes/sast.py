"""
SAST (Source Code Analysis) API Routes

Endpoints for:
- Starting SAST scans on GitHub/GitLab repositories
- Connecting SCM providers (OAuth flow)
- Listing repositories
- Managing scan status and results

Requires Professional or Enterprise subscription.
"""

import uuid
import logging
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from database.connection import get_db
from database.dependencies import get_current_user
from database.models import User, ScanHistory, SCMConnection
from shared.api_endpoints import APIEndpoints
from shared.constants import is_developer_account
from services.sast_service import SASTService

# Agent requirement enforcement
from core.universal_agent_server import require_agent_connection, get_agent_for_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix=APIEndpoints.SAST_PREFIX, tags=["SAST Scans"])


# ==================== Request/Response Models ====================

class SASTScanRequest(BaseModel):
    """Request to start a SAST scan"""
    repository_url: str = Field(..., description="Repository URL (e.g., https://github.com/owner/repo)")
    branch: str = Field(default="main", description="Branch to scan")
    access_token: Optional[str] = Field(None, description="Personal Access Token (if not using OAuth)")
    
    # Scan options
    languages: Optional[List[str]] = Field(None, description="Languages to analyze (auto-detect if empty)")
    scan_secrets: bool = Field(default=True, description="Scan for hardcoded secrets")
    scan_dependencies: bool = Field(default=True, description="Scan for vulnerable dependencies (SCA)")
    scan_code: bool = Field(default=True, description="Scan for code vulnerabilities")
    exclude_paths: Optional[List[str]] = Field(None, description="Paths to exclude (e.g., test/, vendor/)")
    
    notes: Optional[str] = Field(None, description="Scan notes")


class SASTScanResponse(BaseModel):
    """Response after starting a SAST scan"""
    success: bool
    scan_id: str
    message: str
    status: str = "queued"


class SASTStatusResponse(BaseModel):
    """SAST scan status"""
    scan_id: str
    status: str
    progress: int
    phase: Optional[str]
    findings_count: int
    started_at: datetime
    completed_at: Optional[datetime]
    repository_url: str
    branch: str


class SCMConnectionResponse(BaseModel):
    """SCM connection info"""
    id: str
    provider: str
    username: str
    email: Optional[str]
    connected_at: datetime
    is_active: bool


class RepositoryInfo(BaseModel):
    """Repository info from SCM provider"""
    id: str
    name: str
    full_name: str
    html_url: str
    private: bool
    default_branch: str
    language: Optional[str]
    updated_at: Optional[str]


class ValidateTokenRequest(BaseModel):
    """Request to validate a PAT"""
    provider: str = Field(..., description="github, gitlab, or bitbucket")
    access_token: str = Field(..., description="Personal Access Token")


class ValidateTokenResponse(BaseModel):
    """Token validation result"""
    valid: bool
    username: Optional[str]
    email: Optional[str]
    error: Optional[str]


# ==================== Scan Endpoints ====================

@router.post("/start", response_model=SASTScanResponse)
async def start_sast_scan(
    request: SASTScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Start a SAST scan on a repository.
    
    Scans source code for:
    - Hardcoded secrets (API keys, passwords)
    - Vulnerable dependencies (SCA)
    - Code vulnerabilities (injection, XSS, etc.)
    
    Requires Professional or Enterprise subscription.
    """
    # Check if developer account (bypass certain checks)
    is_dev_account = is_developer_account(current_user.email)
    
    # Check subscription
    if not is_dev_account:
        if not current_user.has_cloud_scanning and current_user.plan not in ['professional', 'enterprise']:
            raise HTTPException(
                status_code=403,
                detail="SAST scanning requires Professional or Enterprise subscription"
            )
    
    # ========== AGENT REQUIREMENT CHECK ==========
    # SAST scans require a connected Jarwis Agent for security
    # Source code is analyzed locally on agent, reducing data exposure
    # Developer accounts bypass this check for testing
    agent_id = None
    if not is_dev_account:
        await require_agent_connection(current_user.id, "sast")
        # Get agent_id for tracking which agent runs this scan
        agent_info = get_agent_for_user(current_user.id, "sast")
        agent_id = agent_info.get("agent_id")
    # =============================================
    
    # Get access token (OAuth connection or provided PAT)
    access_token = request.access_token
    if not access_token:
        # Try to use OAuth connection
        result = await db.execute(
            select(SCMConnection).where(
                SCMConnection.user_id == current_user.id,
                SCMConnection.is_active == True
            )
        )
        connection = result.scalar_one_or_none()
        
        if connection:
            access_token = connection.access_token
        else:
            raise HTTPException(
                status_code=400,
                detail="No access token provided and no SCM connection found. Please connect GitHub/GitLab or provide a Personal Access Token."
            )
    
    # Start scan
    try:
        result = await SASTService.start_scan(
            db=db,
            user=current_user,
            repository_url=request.repository_url,
            branch=request.branch,
            access_token=access_token,
            scan_secrets=request.scan_secrets,
            scan_dependencies=request.scan_dependencies,
            scan_code=request.scan_code,
            languages=request.languages,
            exclude_paths=request.exclude_paths,
            notes=request.notes,
            background_tasks=background_tasks,
            agent_id=agent_id,  # Pass agent_id for distributed execution
        )
        
        return SASTScanResponse(
            success=True,
            scan_id=result['scan_id'],
            message="SAST scan started successfully",
            status="running"
        )
        
    except Exception as e:
        logger.error(f"Failed to start SAST scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[SASTStatusResponse])
async def list_sast_scans(
    limit: int = Query(default=20, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List SAST scans for the current user"""
    result = await db.execute(
        select(ScanHistory).where(
            ScanHistory.user_id == current_user.id,
            ScanHistory.scan_type == "sast"
        ).order_by(ScanHistory.started_at.desc()).limit(limit)
    )
    scans = result.scalars().all()
    
    return [
        SASTStatusResponse(
            scan_id=scan.scan_id,
            status=scan.status,
            progress=scan.progress,
            phase=scan.phase,
            findings_count=scan.findings_count,
            started_at=scan.started_at,
            completed_at=scan.completed_at,
            repository_url=scan.target_url,
            branch=scan.config.get('branch', 'main') if scan.config else 'main'
        )
        for scan in scans
    ]


@router.get("/{scan_id}/status", response_model=SASTStatusResponse)
async def get_sast_status(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get status of a specific SAST scan"""
    result = await db.execute(
        select(ScanHistory).where(
            ScanHistory.scan_id == scan_id,
            ScanHistory.user_id == current_user.id
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return SASTStatusResponse(
        scan_id=scan.scan_id,
        status=scan.status,
        progress=scan.progress,
        phase=scan.phase,
        findings_count=scan.findings_count,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
        repository_url=scan.target_url,
        branch=scan.config.get('branch', 'main') if scan.config else 'main'
    )


@router.get("/{scan_id}/logs")
async def get_sast_logs(
    scan_id: str,
    since: Optional[int] = Query(None, description="Get logs after this index"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get logs for a SAST scan"""
    logs = SASTService.get_scan_logs(scan_id, since)
    return {"logs": logs, "scan_id": scan_id}


@router.post("/{scan_id}/stop")
async def stop_sast_scan(
    scan_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stop a running SAST scan"""
    result = await db.execute(
        select(ScanHistory).where(
            ScanHistory.scan_id == scan_id,
            ScanHistory.user_id == current_user.id
        )
    )
    scan = result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if scan.status not in ['running', 'queued']:
        raise HTTPException(status_code=400, detail="Scan is not running")
    
    SASTService.stop_scan(scan_id)
    
    scan.status = "stopped"
    await db.commit()
    
    return {"success": True, "message": "Scan stopped"}


# ==================== SCM Connection Endpoints ====================

@router.get("/github/connect")
async def connect_github(
    current_user: User = Depends(get_current_user)
):
    """
    Initiate GitHub OAuth flow.
    
    Returns a redirect URL to GitHub for authorization.
    """
    oauth_url = SASTService.get_github_oauth_url(str(current_user.id))
    return {"oauth_url": oauth_url}


@router.get("/github/callback")
async def github_callback(
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Handle GitHub OAuth callback.
    
    Exchanges code for access token and stores connection.
    """
    try:
        result = await SASTService.handle_github_callback(db, code, state)
        
        # Redirect to frontend success page
        return RedirectResponse(
            url=f"/dashboard/settings?tab=integrations&connected=github&status=success"
        )
        
    except Exception as e:
        logger.error(f"GitHub OAuth error: {e}")
        return RedirectResponse(
            url=f"/dashboard/settings?tab=integrations&connected=github&status=error&message={str(e)}"
        )


@router.get("/gitlab/connect")
async def connect_gitlab(
    current_user: User = Depends(get_current_user),
    base_url: Optional[str] = Query(None, description="GitLab base URL for self-hosted")
):
    """Initiate GitLab OAuth flow"""
    oauth_url = SASTService.get_gitlab_oauth_url(str(current_user.id), base_url)
    return {"oauth_url": oauth_url}


@router.get("/gitlab/callback")
async def gitlab_callback(
    code: str,
    state: str,
    db: AsyncSession = Depends(get_db)
):
    """Handle GitLab OAuth callback"""
    try:
        result = await SASTService.handle_gitlab_callback(db, code, state)
        return RedirectResponse(
            url=f"/dashboard/settings?tab=integrations&connected=gitlab&status=success"
        )
    except Exception as e:
        logger.error(f"GitLab OAuth error: {e}")
        return RedirectResponse(
            url=f"/dashboard/settings?tab=integrations&connected=gitlab&status=error&message={str(e)}"
        )


@router.get("/connections", response_model=List[SCMConnectionResponse])
async def list_connections(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List SCM connections for the current user"""
    result = await db.execute(
        select(SCMConnection).where(
            SCMConnection.user_id == current_user.id,
            SCMConnection.is_active == True
        )
    )
    connections = result.scalars().all()
    
    return [
        SCMConnectionResponse(
            id=str(conn.id),
            provider=conn.provider,
            username=conn.provider_username,
            email=conn.provider_email,
            connected_at=conn.created_at,
            is_active=conn.is_active
        )
        for conn in connections
    ]


@router.delete("/connections/{connection_id}")
async def disconnect_scm(
    connection_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Disconnect an SCM provider"""
    result = await db.execute(
        select(SCMConnection).where(
            SCMConnection.id == uuid.UUID(connection_id),
            SCMConnection.user_id == current_user.id
        )
    )
    connection = result.scalar_one_or_none()
    
    if not connection:
        raise HTTPException(status_code=404, detail="Connection not found")
    
    connection.is_active = False
    await db.commit()
    
    return {"success": True, "message": f"{connection.provider} disconnected"}


@router.get("/repositories", response_model=List[RepositoryInfo])
async def list_repositories(
    provider: str = Query("github", description="SCM provider"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List repositories from connected SCM provider"""
    result = await db.execute(
        select(SCMConnection).where(
            SCMConnection.user_id == current_user.id,
            SCMConnection.provider == provider,
            SCMConnection.is_active == True
        )
    )
    connection = result.scalar_one_or_none()
    
    if not connection:
        raise HTTPException(
            status_code=404,
            detail=f"No active {provider} connection found. Please connect first."
        )
    
    repos = await SASTService.list_repositories(connection)
    
    return [
        RepositoryInfo(
            id=str(repo['id']),
            name=repo['name'],
            full_name=repo['full_name'],
            html_url=repo.get('html_url', repo.get('web_url', '')),
            private=repo.get('private', repo.get('visibility', 'public') == 'private'),
            default_branch=repo.get('default_branch', 'main'),
            language=repo.get('language'),
            updated_at=repo.get('updated_at')
        )
        for repo in repos
    ]


@router.post("/validate-token", response_model=ValidateTokenResponse)
async def validate_token(
    request: ValidateTokenRequest,
    current_user: User = Depends(get_current_user)
):
    """Validate a Personal Access Token without saving it"""
    result = await SASTService.validate_token(request.provider, request.access_token)
    
    return ValidateTokenResponse(
        valid=result.get('valid', False),
        username=result.get('username'),
        email=result.get('email'),
        error=result.get('error')
    )
