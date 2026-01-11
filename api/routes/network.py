"""
Jarwis AGI Pen Test - Network Scan API Routes

HTTP endpoint layer only - no business logic.
All business logic delegated to services/network_service.py
All agent management delegated to services/agent_service.py

Routes:
- POST /api/network/scan - Start network scan
- GET /api/network/scan/{scan_id} - Get scan status
- GET /api/network/scan/{scan_id}/findings - Get findings
- DELETE /api/network/scan/{scan_id} - Stop scan
- GET /api/network/scans - List user's scans
- GET /api/network/dashboard/summary - Dashboard stats
- POST /api/network/agents - Register agent
- GET /api/network/agents - List agents
- DELETE /api/network/agents/{agent_id} - Delete agent
"""

import logging
from typing import Optional, List
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_active_user
from services.network_service import (
    NetworkScanService,
    NetworkScanConfig,
)
from services.agent_service import AgentService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/network", tags=["Network Security Scans"])


# ========== REQUEST/RESPONSE MODELS ==========

class NetworkCredentials(BaseModel):
    """Network credentials for authenticated testing"""
    enabled: bool = False
    ssh: Optional[dict] = None
    windows: Optional[dict] = None
    snmp: Optional[dict] = None
    database: Optional[dict] = None


class NetworkScanRequest(BaseModel):
    """Network scan request"""
    targets: str = Field(..., min_length=1, description="Comma-separated IPs/subnets/domains")
    profile: str = Field(default="standard", pattern="^(quick|standard|comprehensive|stealth)$")
    port_range: str = Field(default="common")
    service_detection: bool = True
    vuln_scan_enabled: bool = True
    cve_check: bool = True
    ssl_audit_enabled: bool = True
    safe_checks: bool = True
    use_agent: bool = False
    agent_id: Optional[str] = None
    credentials: Optional[NetworkCredentials] = None
    max_concurrent_hosts: int = Field(default=10, ge=1, le=100)
    timeout_per_host: int = Field(default=300, ge=30, le=3600)
    rate_limit: int = Field(default=100, ge=1, le=1000)


class NetworkScanResponse(BaseModel):
    """Network scan response"""
    scan_id: str
    status: str
    message: str
    targets_count: int
    use_agent: bool


class AgentRegistration(BaseModel):
    """Agent registration request"""
    agent_name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    network_ranges: List[str] = Field(..., description="Private network ranges this agent can scan")


class AgentResponse(BaseModel):
    """Agent registration response"""
    agent_id: str
    agent_key: str
    name: str
    network_ranges: List[str]
    created_at: datetime


# ========== SCAN ENDPOINTS ==========

@router.post("/scan", response_model=NetworkScanResponse, status_code=status.HTTP_201_CREATED)
async def start_network_scan(
    scan_request: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new network security scan.
    
    For private IP ranges, you must use a Jarwis Agent deployed in your network.
    """
    try:
        # Validate targets
        is_valid, error_msg, host_count = NetworkScanService.validate_targets(
            scan_request.targets
        )
        if not is_valid:
            raise HTTPException(status_code=400, detail=error_msg)
        
        # Check for private IPs
        has_private = False
        for target in scan_request.targets.split(','):
            if NetworkScanService.is_private_target(target.strip()):
                has_private = True
                break
        
        if has_private and not scan_request.use_agent:
            raise HTTPException(
                status_code=400,
                detail="Private IP ranges require a Jarwis Agent. "
                       "Deploy an agent in your network and set use_agent=true."
            )
        
        # Validate agent if specified
        if scan_request.use_agent and scan_request.agent_id:
            agent_exists = await AgentService.verify_agent_ownership(
                db, current_user.id, scan_request.agent_id
            )
            if not agent_exists:
                raise HTTPException(status_code=404, detail="Agent not found or access denied")
        
        # Convert request to service config
        config = NetworkScanConfig(
            targets=scan_request.targets,
            profile=scan_request.profile,
            port_range=scan_request.port_range,
            service_detection=scan_request.service_detection,
            vuln_scan_enabled=scan_request.vuln_scan_enabled,
            cve_check=scan_request.cve_check,
            ssl_audit_enabled=scan_request.ssl_audit_enabled,
            safe_checks=scan_request.safe_checks,
            use_agent=scan_request.use_agent,
            agent_id=scan_request.agent_id,
            credentials=scan_request.credentials.model_dump() if scan_request.credentials else None,
            max_concurrent_hosts=scan_request.max_concurrent_hosts,
            timeout_per_host=scan_request.timeout_per_host,
            rate_limit=scan_request.rate_limit,
        )
        
        # Start scan via service
        result = await NetworkScanService.start_scan(db, current_user, config)
        scan_id = result['scan_id']
        
        # Get database URL from settings (not from session)
        from database.config import get_settings
        db_settings = get_settings()
        
        # Start background task
        background_tasks.add_task(
            _run_scan_background,
            scan_id=scan_id,
            config=config,
            user_id=current_user.id,
            db_connection_string=db_settings.DATABASE_URL,
        )
        
        return NetworkScanResponse(
            scan_id=scan_id,
            status=result['status'],
            message=result['message'],
            targets_count=result['targets_count'],
            use_agent=result['use_agent'],
        )
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error starting network scan: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/scan/{scan_id}")
async def get_network_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get status and findings of a network scan"""
    try:
        return await NetworkScanService.get_scan_status(db, current_user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/scan/{scan_id}/findings")
async def get_network_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get paginated findings from a network scan"""
    try:
        return await NetworkScanService.get_findings(
            db, current_user, scan_id, severity, page, per_page
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.delete("/scan/{scan_id}")
async def stop_network_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Stop a running network scan"""
    try:
        return await NetworkScanService.stop_scan(db, current_user, scan_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/scans")
async def list_network_scans(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List all network scans for current user"""
    return await NetworkScanService.list_scans(db, current_user)


@router.get("/dashboard/summary")
async def get_network_dashboard_summary(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get aggregated network security dashboard summary"""
    return await NetworkScanService.get_dashboard_summary(db, current_user)


# ========== AGENT ENDPOINTS ==========

@router.post("/agents", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    agent_data: AgentRegistration,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Register a new Jarwis Agent for private network scanning"""
    try:
        return await AgentService.register_agent(db, current_user, agent_data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/agents")
async def list_agents(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List all agents registered by current user"""
    return await AgentService.list_agents(db, current_user)


@router.delete("/agents/{agent_id}")
async def delete_agent(
    agent_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a registered agent"""
    try:
        return await AgentService.delete_agent(db, current_user, agent_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ========== BACKGROUND SCAN EXECUTION ==========

async def _run_scan_background(
    scan_id: str,
    config: NetworkScanConfig,
    user_id: str,
    db_connection_string: str,
):
    """
    Background task to run network scan.
    Called from start_network_scan endpoint via background_tasks.
    """
    # Import here to avoid circular dependencies
    from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
    from sqlalchemy.orm import sessionmaker
    from core.network_scan_runner import NetworkScanRunner
    
    # Create fresh DB session for background task
    engine = create_async_engine(db_connection_string, echo=False)
    AsyncLocalSession = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    try:
        async with AsyncLocalSession() as db:
            # Create and run scanner
            runner = NetworkScanRunner(config, db)
            await runner.run(scan_id, user_id)
    
    except Exception as e:
        logger.error(f"Background scan task failed for {scan_id}: {e}", exc_info=True)
        # Update scan status to error
        try:
            async with AsyncLocalSession() as db:
                from sqlalchemy import select
                from database.models import ScanHistory
                
                query = select(ScanHistory).where(ScanHistory.id == scan_id)
                result = await db.execute(query)
                scan = result.scalars().first()
                
                if scan:
                    scan.status = 'error'
                    db.add(scan)
                    await db.commit()
        except Exception as update_error:
            logger.error(f"Failed to update scan error status: {update_error}")
    
    finally:
        await engine.dispose()
