"""
Jarwis API - Universal Agent Routes

WebSocket and REST endpoints for Universal Jarwis Agent management.
Handles connections for ALL scan types: Web, Mobile, Network, Cloud, SAST.
"""

import logging
from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, HTTPException, Query
from pydantic import BaseModel

from core.universal_agent_server import universal_agent_manager, AgentState
from api.routes.auth import get_current_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/agent", tags=["Universal Agent"])


# === Models ===

class AgentInfo(BaseModel):
    """Agent information response"""
    agent_id: str
    state: str
    connected_at: str
    last_heartbeat: str
    scan_types: list
    active_scans: list
    agent_name: str
    version: str
    os: str
    hostname: str


class AgentListResponse(BaseModel):
    """Response for listing agents"""
    agents: List[AgentInfo]
    count: int


class AgentStatusResponse(BaseModel):
    """Response for agent status check"""
    has_agent: bool
    agents: List[AgentInfo]
    supported_scan_types: List[str]


class AttackRequest(BaseModel):
    """Request to execute attack via agent"""
    scan_id: str
    scan_type: str
    attack_type: str
    target: dict
    payload: dict
    options: dict = {}
    timeout: int = 300


class AttackResponse(BaseModel):
    """Response from attack execution"""
    attack_id: str
    success: bool
    vulnerable: bool = False
    severity: str = "info"
    evidence: dict = {}
    error: Optional[str] = None
    duration_ms: int = 0


# === WebSocket Endpoint ===

@router.websocket("/ws/{auth_token}")
async def agent_websocket(websocket: WebSocket, auth_token: str):
    """
    WebSocket endpoint for Universal Jarwis Agents.
    
    This is the main connection point for all agent types.
    Agents connect here and maintain persistent connection for:
    - Receiving scan commands for any scan type
    - Executing attack payloads locally
    - Sending results back to server
    """
    # Validate token and get user
    try:
        from services.auth_service import auth_service
        user = await auth_service.get_user_from_token(auth_token)
        if not user:
            await websocket.close(code=4001, reason="Invalid token")
            return
    except Exception as e:
        logger.error(f"Auth error: {e}")
        await websocket.close(code=4001, reason="Authentication failed")
        return
    
    # Handle agent connection
    agent_id = await universal_agent_manager.handle_agent_connection(
        websocket=websocket,
        user_id=user.id,
        auth_token=auth_token
    )
    
    if not agent_id:
        logger.warning(f"Agent connection failed for user {user.id}")
        return
    
    logger.info(f"Agent {agent_id} session ended for user {user.id}")


# === REST Endpoints ===

@router.get("/status", response_model=AgentStatusResponse)
async def get_agent_status(current_user = Depends(get_current_user)):
    """
    Get status of user's connected agents.
    
    Returns:
    - has_agent: Whether user has at least one connected agent
    - agents: List of connected agents with their capabilities
    - supported_scan_types: Combined list of all supported scan types
    """
    agents_data = universal_agent_manager.get_user_agents(current_user.id)
    
    # Collect all supported scan types
    all_scan_types = set()
    for agent in agents_data:
        all_scan_types.update(agent.get("scan_types", []))
    
    return AgentStatusResponse(
        has_agent=len(agents_data) > 0,
        agents=[AgentInfo(**a) for a in agents_data],
        supported_scan_types=sorted(list(all_scan_types))
    )


@router.get("/list", response_model=AgentListResponse)
async def list_agents(current_user = Depends(get_current_user)):
    """List all connected agents for the current user"""
    agents_data = universal_agent_manager.get_user_agents(current_user.id)
    
    return AgentListResponse(
        agents=[AgentInfo(**a) for a in agents_data],
        count=len(agents_data)
    )


@router.get("/check/{scan_type}")
async def check_agent_for_scan_type(
    scan_type: str,
    current_user = Depends(get_current_user)
):
    """
    Check if user has an agent that supports a specific scan type.
    
    Scan types:
    - web: Web application security
    - mobile_static: Mobile static analysis
    - mobile_dynamic: Mobile dynamic analysis
    - network: Network security
    - cloud_aws: AWS cloud security
    - cloud_azure: Azure cloud security
    - cloud_gcp: GCP cloud security
    - cloud_kubernetes: Kubernetes security
    - sast: Static application security testing
    """
    has_capability = universal_agent_manager.has_agent_for_scan_type(
        current_user.id, 
        scan_type
    )
    
    if not has_capability:
        available_agents = universal_agent_manager.get_user_agents(current_user.id)
        available_types = set()
        for agent in available_agents:
            available_types.update(agent.get("scan_types", []))
        
        return {
            "supported": False,
            "scan_type": scan_type,
            "message": f"No connected agent supports {scan_type} scans",
            "available_scan_types": sorted(list(available_types)),
            "suggestion": "Install required tools on your agent machine or connect an agent with the required capabilities"
        }
    
    return {
        "supported": True,
        "scan_type": scan_type,
        "message": f"Agent available for {scan_type} scans"
    }


@router.post("/attack", response_model=AttackResponse)
async def execute_attack(
    request: AttackRequest,
    agent_id: Optional[str] = Query(None, description="Specific agent to use"),
    current_user = Depends(get_current_user)
):
    """
    Execute an attack via connected agent.
    
    This endpoint routes attack requests to an appropriate agent based on:
    1. The specified agent_id (if provided)
    2. An agent that supports the scan_type
    3. Load balancing across available agents
    """
    import uuid
    
    # Determine which agent to use
    if agent_id:
        # Verify agent belongs to user and is connected
        user_agents = universal_agent_manager.get_user_agents(current_user.id)
        if not any(a["agent_id"] == agent_id for a in user_agents):
            raise HTTPException(
                status_code=400,
                detail="Specified agent not found or not connected"
            )
    else:
        # Auto-select agent
        agent_id = universal_agent_manager.get_agent_for_scan(
            current_user.id,
            request.scan_type
        )
        if not agent_id:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "no_agent_available",
                    "message": f"No agent available for {request.scan_type} scans. "
                              "Connect an agent with the required capabilities.",
                    "scan_type": request.scan_type
                }
            )
    
    # Generate attack ID
    attack_id = f"attack-{uuid.uuid4().hex[:12]}"
    
    # Send attack to agent
    result = await universal_agent_manager.send_attack_request(
        agent_id=agent_id,
        scan_id=request.scan_id,
        scan_type=request.scan_type,
        attack_id=attack_id,
        attack_type=request.attack_type,
        target=request.target,
        payload=request.payload,
        options=request.options,
        timeout=request.timeout,
    )
    
    if result.get("error"):
        raise HTTPException(
            status_code=500,
            detail=result
        )
    
    return AttackResponse(
        attack_id=attack_id,
        success=result.get("success", False),
        vulnerable=result.get("vulnerable", False),
        severity=result.get("severity", "info"),
        evidence=result.get("evidence", {}),
        error=result.get("error"),
        duration_ms=result.get("duration_ms", 0),
    )


@router.post("/scan/{scan_id}/start")
async def start_scan_on_agent(
    scan_id: str,
    scan_type: str = Query(..., description="Type of scan: web, mobile, network, cloud, sast"),
    agent_id: Optional[str] = Query(None, description="Specific agent to use"),
    config: dict = {},
    current_user = Depends(get_current_user)
):
    """Start a scan on an agent"""
    # Auto-select agent if not specified
    if not agent_id:
        agent_id = universal_agent_manager.get_agent_for_scan(
            current_user.id,
            scan_type
        )
        if not agent_id:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "no_agent_available",
                    "message": f"No agent available for {scan_type} scans"
                }
            )
    
    success = await universal_agent_manager.start_scan_on_agent(
        agent_id=agent_id,
        scan_id=scan_id,
        scan_type=scan_type,
        config=config
    )
    
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Failed to start scan on agent"
        )
    
    return {
        "status": "started",
        "scan_id": scan_id,
        "agent_id": agent_id
    }


@router.post("/scan/{scan_id}/stop")
async def stop_scan_on_agent(
    scan_id: str,
    agent_id: str = Query(..., description="Agent running the scan"),
    current_user = Depends(get_current_user)
):
    """Stop a scan on an agent"""
    success = await universal_agent_manager.stop_scan_on_agent(
        agent_id=agent_id,
        scan_id=scan_id
    )
    
    if not success:
        raise HTTPException(
            status_code=500,
            detail="Failed to stop scan on agent"
        )
    
    return {
        "status": "stopped",
        "scan_id": scan_id
    }


@router.get("/token")
async def get_agent_connection_token(current_user = Depends(get_current_user)):
    """
    Get a WebSocket connection token for agent setup.
    
    Returns a token that can be used to connect an agent:
    python jarwis_agent.py --server wss://jarwis.io/api/agent/ws/<token>
    """
    from services.auth_service import auth_service
    
    # Generate a token valid for 24 hours
    token = await auth_service.create_agent_token(current_user.id, expires_hours=24)
    
    return {
        "token": token,
        "websocket_url": f"wss://jarwis.io/api/agent/ws/{token}",
        "expires_in": "24 hours",
        "command": f"python jarwis_agent.py --server wss://jarwis.io/api/agent/ws/{token}"
    }


# === Startup/Shutdown ===

async def startup_agent_manager():
    """Start the agent manager on app startup"""
    await universal_agent_manager.start()


async def shutdown_agent_manager():
    """Stop the agent manager on app shutdown"""
    await universal_agent_manager.stop()
