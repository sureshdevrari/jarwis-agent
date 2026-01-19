"""
Jarwis Universal Agent Server
==============================

Server-side handler for Universal Jarwis Agents.
Manages WebSocket connections and routes attack requests to connected agents.

This server is REQUIRED for all scan types:
- Web Application Security
- Mobile Security
- Network Security  
- Cloud Security
- SAST

Architecture:
    ┌─────────────────────────────────────────────────────────────────┐
    │                      JARWIS SERVER                              │
    │  ┌─────────────────────────────────────────────────────────────┐│
    │  │           Universal Agent Manager (this module)              ││
    │  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ ││
    │  │  │ Connection  │  │ Agent       │  │ Attack              │ ││
    │  │  │ Pool        │  │ Registry    │  │ Router              │ ││
    │  │  └─────────────┘  └─────────────┘  └─────────────────────┘ ││
    │  └─────────────────────────────────────────────────────────────┘│
    │                               │                                  │
    │                    WebSocket (wss://)                           │
    │                               │                                  │
    └───────────────────────────────┼──────────────────────────────────┘
                                    │
            ┌───────────────────────┼───────────────────────┐
            │                       │                       │
    ┌───────┴───────┐      ┌───────┴───────┐      ┌───────┴───────┐
    │  Agent 1      │      │  Agent 2      │      │  Agent N      │
    │  (Web+Mobile) │      │  (Network)    │      │  (Cloud+SAST) │
    └───────────────┘      └───────────────┘      └───────────────┘
"""

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class AgentState(str, Enum):
    """Agent connection states"""
    CONNECTING = "connecting"
    REGISTERING = "registering"
    READY = "ready"
    SCANNING = "scanning"
    DISCONNECTED = "disconnected"
    ERROR = "error"


class MessageType(str, Enum):
    """WebSocket message types"""
    # Agent -> Server
    REGISTER = "register"
    CAPABILITIES = "capabilities"
    HEARTBEAT = "heartbeat"
    ATTACK_RESULT = "attack_result"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETE = "scan_complete"
    ERROR = "error"
    LOG = "log"
    
    # Server -> Agent
    ATTACK_REQUEST = "attack_request"
    SCAN_START = "scan_start"
    SCAN_STOP = "scan_stop"
    CONFIG_UPDATE = "config_update"
    PING = "ping"


@dataclass
class ConnectedAgent:
    """Represents a connected agent"""
    agent_id: str
    user_id: int
    websocket: WebSocket
    state: AgentState = AgentState.CONNECTING
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    scan_types: List[str] = field(default_factory=list)
    active_scans: Set[str] = field(default_factory=set)
    agent_name: str = ""
    version: str = ""
    
    # System info from capabilities
    os: str = ""
    hostname: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "state": self.state.value,
            "connected_at": self.connected_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "scan_types": self.scan_types,
            "active_scans": list(self.active_scans),
            "agent_name": self.agent_name,
            "version": self.version,
            "os": self.os,
            "hostname": self.hostname,
        }


@dataclass
class PendingAttack:
    """Tracks a pending attack request"""
    attack_id: str
    scan_id: str
    agent_id: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    timeout: int = 300
    callback: Optional[Callable] = None
    result: Optional[Dict[str, Any]] = None
    completed: bool = False
    error: Optional[str] = None


class UniversalAgentManager:
    """
    Manages all connected Universal Jarwis Agents.
    
    Responsibilities:
    - WebSocket connection handling
    - Agent registration and capability tracking
    - Attack request routing to appropriate agents
    - Load balancing across multiple agents
    - Heartbeat monitoring and cleanup
    """
    
    def __init__(self):
        # Connected agents by agent_id
        self.agents: Dict[str, ConnectedAgent] = {}
        
        # Agents by user_id for user-specific lookups
        self.user_agents: Dict[int, Set[str]] = {}
        
        # Agents by scan type for routing
        self.agents_by_scan_type: Dict[str, Set[str]] = {}
        
        # Pending attack requests
        self.pending_attacks: Dict[str, PendingAttack] = {}
        
        # Locks for thread safety
        self._agents_lock = asyncio.Lock()
        self._attacks_lock = asyncio.Lock()
        
        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._cleanup_task: Optional[asyncio.Task] = None
        
        # Callback for agent disconnection (to update scan status)
        self._on_agent_disconnected: Optional[Callable] = None
    
    async def start(self):
        """Start background tasks"""
        self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        logger.info("Universal Agent Manager started")
    
    async def stop(self):
        """Stop background tasks"""
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        if self._cleanup_task:
            self._cleanup_task.cancel()
        
        # Disconnect all agents
        for agent in list(self.agents.values()):
            await self._disconnect_agent(agent.agent_id, "Server shutdown")
        
        logger.info("Universal Agent Manager stopped")
    
    async def handle_agent_connection(
        self,
        websocket: WebSocket,
        user_id: int,
        auth_token: str
    ) -> Optional[str]:
        """
        Handle a new agent WebSocket connection.
        
        Returns agent_id on success, None on failure.
        """
        await websocket.accept()
        
        # Generate temporary agent ID (will be updated on registration)
        temp_agent_id = f"pending-{uuid.uuid4().hex[:12]}"
        
        agent = ConnectedAgent(
            agent_id=temp_agent_id,
            user_id=user_id,
            websocket=websocket,
            state=AgentState.CONNECTING,
        )
        
        try:
            # Wait for registration message
            try:
                raw_message = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                message = json.loads(raw_message)
            except asyncio.TimeoutError:
                await websocket.close(code=4002, reason="Registration timeout")
                return None
            
            if message.get("type") != MessageType.REGISTER.value:
                await websocket.close(code=4003, reason="Expected registration message")
                return None
            
            # Process registration
            data = message.get("data", {})
            agent.agent_id = data.get("agent_id", temp_agent_id)
            agent.agent_name = data.get("agent_name", "")
            agent.version = data.get("version", "")
            agent.state = AgentState.REGISTERING
            
            # Register agent
            async with self._agents_lock:
                # Remove any existing agent with same ID
                if agent.agent_id in self.agents:
                    old_agent = self.agents[agent.agent_id]
                    await self._disconnect_agent(old_agent.agent_id, "Replaced by new connection")
                
                self.agents[agent.agent_id] = agent
                
                # Track by user
                if user_id not in self.user_agents:
                    self.user_agents[user_id] = set()
                self.user_agents[user_id].add(agent.agent_id)
            
            logger.info(f"Agent registered: {agent.agent_id} (user {user_id})")
            
            # Wait for capabilities message
            try:
                raw_message = await asyncio.wait_for(
                    websocket.receive_text(),
                    timeout=30.0
                )
                message = json.loads(raw_message)
            except asyncio.TimeoutError:
                await websocket.close(code=4004, reason="Capabilities timeout")
                await self._disconnect_agent(agent.agent_id, "Capabilities timeout")
                return None
            
            if message.get("type") == MessageType.CAPABILITIES.value:
                await self._process_capabilities(agent, message.get("data", {}))
            
            agent.state = AgentState.READY
            
            # Send acknowledgment
            await self._send_to_agent(agent.agent_id, {
                "type": "registered",
                "data": {
                    "agent_id": agent.agent_id,
                    "status": "connected",
                    "scan_types": agent.scan_types,
                }
            })
            
            # Main message loop
            await self._agent_message_loop(agent)
            
        except WebSocketDisconnect:
            logger.info(f"Agent disconnected: {agent.agent_id}")
        except Exception as e:
            logger.error(f"Agent connection error: {e}")
        finally:
            await self._disconnect_agent(agent.agent_id, "Connection closed")
        
        return agent.agent_id
    
    async def _process_capabilities(self, agent: ConnectedAgent, capabilities: Dict[str, Any]):
        """Process agent capabilities message"""
        agent.capabilities = capabilities
        agent.scan_types = capabilities.get("scan_types", [])
        
        # Extract system info
        system = capabilities.get("system", {})
        agent.os = system.get("os", "")
        agent.hostname = system.get("hostname", "")
        
        # Track by scan type
        async with self._agents_lock:
            for scan_type in agent.scan_types:
                if scan_type not in self.agents_by_scan_type:
                    self.agents_by_scan_type[scan_type] = set()
                self.agents_by_scan_type[scan_type].add(agent.agent_id)
        
        logger.info(f"Agent {agent.agent_id} capabilities: {agent.scan_types}")
    
    async def _agent_message_loop(self, agent: ConnectedAgent):
        """Main message loop for connected agent"""
        while True:
            try:
                raw_message = await agent.websocket.receive_text()
                message = json.loads(raw_message)
                
                msg_type = message.get("type")
                data = message.get("data", {})
                
                if msg_type == MessageType.HEARTBEAT.value:
                    agent.last_heartbeat = datetime.utcnow()
                    
                elif msg_type == MessageType.ATTACK_RESULT.value:
                    await self._handle_attack_result(agent, data)
                    
                elif msg_type == MessageType.SCAN_PROGRESS.value:
                    await self._handle_scan_progress(agent, data)
                    
                elif msg_type == MessageType.SCAN_COMPLETE.value:
                    await self._handle_scan_complete(agent, data)
                    
                elif msg_type == MessageType.ERROR.value:
                    await self._handle_agent_error(agent, data)
                    
                elif msg_type == MessageType.LOG.value:
                    logger.debug(f"Agent {agent.agent_id} log: {data.get('message', '')}")
                    
            except WebSocketDisconnect:
                break
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from agent {agent.agent_id}")
            except Exception as e:
                logger.error(f"Error in agent message loop: {e}")
    
    async def _disconnect_agent(self, agent_id: str, reason: str = ""):
        """Disconnect and clean up an agent"""
        active_scans = set()
        
        async with self._agents_lock:
            if agent_id not in self.agents:
                return
            
            agent = self.agents.pop(agent_id)
            
            # Save active scans before cleanup for status update
            active_scans = agent.active_scans.copy()
            
            # Remove from user tracking
            if agent.user_id in self.user_agents:
                self.user_agents[agent.user_id].discard(agent_id)
                if not self.user_agents[agent.user_id]:
                    del self.user_agents[agent.user_id]
            
            # Remove from scan type tracking
            for scan_type in agent.scan_types:
                if scan_type in self.agents_by_scan_type:
                    self.agents_by_scan_type[scan_type].discard(agent_id)
        
        # Fail any pending attacks
        async with self._attacks_lock:
            for attack_id, pending in list(self.pending_attacks.items()):
                if pending.agent_id == agent_id and not pending.completed:
                    pending.completed = True
                    pending.error = f"Agent disconnected: {reason}"
        
        # Mark active scans as agent_disconnected
        if active_scans and self._on_agent_disconnected:
            await self._on_agent_disconnected(agent_id, active_scans, reason)
        
        try:
            await agent.websocket.close(reason=reason)
        except:
            pass
        
        logger.info(f"Agent {agent_id} disconnected: {reason}")
    
    async def _send_to_agent(self, agent_id: str, message: Dict[str, Any]) -> bool:
        """Send message to specific agent"""
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        try:
            await agent.websocket.send_json(message)
            return True
        except Exception as e:
            logger.error(f"Failed to send to agent {agent_id}: {e}")
            return False
    
    # ==========================================================================
    # Public API for Scan Routes
    # ==========================================================================
    
    def has_connected_agent(self, user_id: int) -> bool:
        """Check if user has at least one connected agent"""
        return user_id in self.user_agents and len(self.user_agents[user_id]) > 0
    
    def has_agent_for_scan_type(self, user_id: int, scan_type: str) -> bool:
        """Check if user has an agent that supports the given scan type"""
        if user_id not in self.user_agents:
            return False
        
        for agent_id in self.user_agents[user_id]:
            if agent_id in self.agents:
                agent = self.agents[agent_id]
                if scan_type in agent.scan_types:
                    return True
        
        return False
    
    def get_user_agents(self, user_id: int) -> List[Dict[str, Any]]:
        """Get list of user's connected agents"""
        if user_id not in self.user_agents:
            return []
        
        return [
            self.agents[aid].to_dict()
            for aid in self.user_agents[user_id]
            if aid in self.agents
        ]
    
    def get_agent_for_scan(self, user_id: int, scan_type: str) -> Optional[str]:
        """
        Get the best available agent for a scan type.
        Returns agent_id or None.
        """
        if user_id not in self.user_agents:
            return None
        
        candidates = []
        for agent_id in self.user_agents[user_id]:
            if agent_id in self.agents:
                agent = self.agents[agent_id]
                if scan_type in agent.scan_types and agent.state == AgentState.READY:
                    # Prefer agents with fewer active scans
                    candidates.append((len(agent.active_scans), agent_id))
        
        if not candidates:
            return None
        
        # Return agent with fewest active scans
        candidates.sort()
        return candidates[0][1]
    
    async def send_attack_request(
        self,
        agent_id: str,
        scan_id: str,
        scan_type: str,
        attack_id: str,
        attack_type: str,
        target: Dict[str, Any],
        payload: Dict[str, Any],
        options: Dict[str, Any] = None,
        timeout: int = 300,
    ) -> Optional[Dict[str, Any]]:
        """
        Send an attack request to an agent and wait for result.
        
        Returns attack result or None on timeout/error.
        """
        if agent_id not in self.agents:
            return {"error": "Agent not connected"}
        
        agent = self.agents[agent_id]
        
        # Create pending attack
        pending = PendingAttack(
            attack_id=attack_id,
            scan_id=scan_id,
            agent_id=agent_id,
            timeout=timeout,
        )
        
        async with self._attacks_lock:
            self.pending_attacks[attack_id] = pending
        
        # Send attack request
        message = {
            "type": MessageType.ATTACK_REQUEST.value,
            "data": {
                "attack_id": attack_id,
                "scan_id": scan_id,
                "scan_type": scan_type,
                "attack_type": attack_type,
                "target": target,
                "payload": payload,
                "options": options or {},
            }
        }
        
        success = await self._send_to_agent(agent_id, message)
        if not success:
            async with self._attacks_lock:
                del self.pending_attacks[attack_id]
            return {"error": "Failed to send to agent"}
        
        # Wait for result
        try:
            result = await asyncio.wait_for(
                self._wait_for_attack_result(attack_id),
                timeout=timeout
            )
            return result
        except asyncio.TimeoutError:
            async with self._attacks_lock:
                if attack_id in self.pending_attacks:
                    del self.pending_attacks[attack_id]
            return {"error": "Attack timeout", "timeout": True}
    
    async def _wait_for_attack_result(self, attack_id: str) -> Dict[str, Any]:
        """Wait for attack result"""
        while True:
            async with self._attacks_lock:
                if attack_id in self.pending_attacks:
                    pending = self.pending_attacks[attack_id]
                    if pending.completed:
                        result = pending.result or {"error": pending.error}
                        del self.pending_attacks[attack_id]
                        return result
            await asyncio.sleep(0.1)
    
    async def _handle_attack_result(self, agent: ConnectedAgent, data: Dict[str, Any]):
        """Handle attack result from agent"""
        attack_id = data.get("attack_id")
        
        async with self._attacks_lock:
            if attack_id in self.pending_attacks:
                pending = self.pending_attacks[attack_id]
                pending.completed = True
                pending.result = data
        
        logger.debug(f"Attack result received: {attack_id}")
    
    async def start_scan_on_agent(
        self,
        agent_id: str,
        scan_id: str,
        scan_type: str,
        config: Dict[str, Any]
    ) -> bool:
        """Start a scan on an agent"""
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        agent.active_scans.add(scan_id)
        agent.state = AgentState.SCANNING
        
        message = {
            "type": MessageType.SCAN_START.value,
            "data": {
                "scan_id": scan_id,
                "scan_type": scan_type,
                "config": config,
            }
        }
        
        return await self._send_to_agent(agent_id, message)
    
    async def stop_scan_on_agent(self, agent_id: str, scan_id: str) -> bool:
        """Stop a scan on an agent"""
        if agent_id not in self.agents:
            return False
        
        agent = self.agents[agent_id]
        agent.active_scans.discard(scan_id)
        
        if not agent.active_scans:
            agent.state = AgentState.READY
        
        message = {
            "type": MessageType.SCAN_STOP.value,
            "data": {
                "scan_id": scan_id,
            }
        }
        
        return await self._send_to_agent(agent_id, message)
    
    async def _handle_scan_progress(self, agent: ConnectedAgent, data: Dict[str, Any]):
        """Handle scan progress from agent"""
        scan_id = data.get("scan_id")
        progress = data.get("progress", 0)
        message = data.get("message", "")
        
        # Broadcast to connected WebSocket clients
        # This would integrate with your existing progress tracking
        logger.debug(f"Scan {scan_id} progress: {progress}% - {message}")
    
    async def _handle_scan_complete(self, agent: ConnectedAgent, data: Dict[str, Any]):
        """Handle scan completion from agent"""
        scan_id = data.get("scan_id")
        agent.active_scans.discard(scan_id)
        
        if not agent.active_scans:
            agent.state = AgentState.READY
        
        logger.info(f"Scan {scan_id} completed on agent {agent.agent_id}")
    
    async def _handle_agent_error(self, agent: ConnectedAgent, data: Dict[str, Any]):
        """Handle error from agent"""
        error = data.get("error", "Unknown error")
        attack_id = data.get("attack_id")
        scan_id = data.get("scan_id")
        
        logger.error(f"Agent {agent.agent_id} error: {error}")
        
        # Complete any pending attack with error
        if attack_id:
            async with self._attacks_lock:
                if attack_id in self.pending_attacks:
                    pending = self.pending_attacks[attack_id]
                    pending.completed = True
                    pending.error = error
    
    def set_disconnection_callback(self, callback: Callable):
        """
        Set callback to be called when an agent disconnects with active scans.
        
        The callback receives (agent_id, active_scan_ids, reason).
        Use this to update scan statuses to 'agent_disconnected'.
        """
        self._on_agent_disconnected = callback
    
    # ==========================================================================
    # Background Tasks
    # ==========================================================================
    
    async def _heartbeat_loop(self):
        """Send periodic pings to agents"""
        while True:
            try:
                await asyncio.sleep(30)
                
                for agent_id in list(self.agents.keys()):
                    await self._send_to_agent(agent_id, {
                        "type": MessageType.PING.value,
                        "data": {"timestamp": datetime.utcnow().isoformat()}
                    })
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat loop error: {e}")
    
    async def _cleanup_loop(self):
        """Clean up stale connections and expired attacks"""
        while True:
            try:
                await asyncio.sleep(60)
                
                now = datetime.utcnow()
                
                # Check for stale agents (no heartbeat in 2 minutes)
                for agent_id, agent in list(self.agents.items()):
                    if (now - agent.last_heartbeat).total_seconds() > 120:
                        logger.warning(f"Agent {agent_id} heartbeat timeout")
                        await self._disconnect_agent(agent_id, "Heartbeat timeout")
                
                # Clean up old pending attacks
                async with self._attacks_lock:
                    for attack_id, pending in list(self.pending_attacks.items()):
                        age = (now - pending.created_at).total_seconds()
                        if age > pending.timeout * 2:
                            pending.completed = True
                            pending.error = "Attack expired"
                            
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Cleanup loop error: {e}")


# Global manager instance
universal_agent_manager = UniversalAgentManager()


# ==========================================================================
# Dependency for requiring agent connection
# ==========================================================================

class AgentRequired:
    """
    FastAPI dependency that ensures user has a connected agent.
    
    Usage in routes:
        from core.universal_agent_server import AgentRequired
        
        @router.post("/scan")
        async def start_scan(
            current_user: User = Depends(get_current_active_user),
            _agent: None = Depends(AgentRequired(scan_type="web"))
        ):
            # Agent is verified, proceed with scan
            pass
    
    The dependency will:
    1. Check if user has any connected agent
    2. If scan_type specified, verify agent supports that scan type
    3. Raise HTTPException with download link if no agent
    """
    
    def __init__(self, scan_type: str = None, required: bool = True):
        """
        Args:
            scan_type: Optional scan type to verify agent capability
                      Options: web, mobile_static, mobile_dynamic, network,
                              cloud_aws, cloud_azure, cloud_gcp, cloud_kubernetes, sast
            required: If False, agent is optional (returns status instead of raising)
        """
        self.scan_type = scan_type
        self.required = required
    
    async def __call__(self, request: "Request" = None, current_user: "User" = None):
        """
        Callable for FastAPI dependency injection.
        
        Note: current_user must be resolved before this dependency.
        Use in route like: Depends(AgentRequired(scan_type="web"))
        """
        from fastapi import HTTPException, Request
        from database.dependencies import get_current_active_user
        
        # Get user_id from request state (set by auth middleware) or from current_user
        user_id = None
        if current_user:
            user_id = current_user.id
        elif request and hasattr(request.state, 'user'):
            user_id = request.state.user.id
        
        if not user_id:
            # Cannot check agent without user - let auth handle this
            return None
        
        # Check for developer account bypass
        try:
            from shared.constants import is_developer_account
            if hasattr(request, 'state') and hasattr(request.state, 'user'):
                if is_developer_account(request.state.user.email):
                    return {"agent_required": False, "reason": "developer_account"}
        except:
            pass
        
        # Check if user has connected agent
        has_agent = universal_agent_manager.has_connected_agent(user_id)
        
        if not has_agent:
            if self.required:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "agent_required",
                        "message": "A Jarwis Agent must be connected to run security scans. "
                                  "Download and install the agent from your dashboard.",
                        "download_url": "/dashboard/agent",
                        "docs_url": "/docs/agent-setup",
                        "scan_type": self.scan_type
                    }
                )
            return {"agent_connected": False, "scan_type": self.scan_type}
        
        # Check scan type capability if specified
        if self.scan_type:
            has_capability = universal_agent_manager.has_agent_for_scan_type(user_id, self.scan_type)
            
            if not has_capability:
                if self.required:
                    # Get what capabilities the agent DOES have
                    agents = universal_agent_manager.get_user_agents(user_id)
                    available_types = set()
                    for agent in agents:
                        available_types.update(agent.get("scan_types", []))
                    
                    raise HTTPException(
                        status_code=400,
                        detail={
                            "error": "agent_capability_missing",
                            "message": f"Your connected agent does not support '{self.scan_type}' scans. "
                                      "Please ensure the required tools are installed on the agent machine.",
                            "required_scan_type": self.scan_type,
                            "available_scan_types": list(available_types),
                            "setup_url": f"/docs/agent-setup#{self.scan_type}"
                        }
                    )
                return {"agent_connected": True, "has_capability": False, "scan_type": self.scan_type}
        
        return {"agent_connected": True, "has_capability": True, "scan_type": self.scan_type}


async def require_agent_connection(user_id: int, scan_type: str = None):
    """
    Standalone function to check agent connection.
    
    For use in route handlers directly (not as dependency):
        await require_agent_connection(current_user.id, "web")
    
    Raises HTTPException if no agent connected.
    """
    from fastapi import HTTPException
    
    if not universal_agent_manager.has_connected_agent(user_id):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "agent_required",
                "message": "A Jarwis Agent must be connected to run security scans. "
                          "Download and install the agent from your dashboard.",
                "download_url": "/dashboard/agent"
            }
        )
    
    if scan_type and not universal_agent_manager.has_agent_for_scan_type(user_id, scan_type):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "agent_capability_missing",
                "message": f"Your connected agent does not support {scan_type} scans. "
                          "Please ensure the required tools are installed on the agent machine.",
                "scan_type": scan_type
            }
        )


def get_agent_for_user(user_id: int, scan_type: str = None) -> dict:
    """
    Get agent info for a user without raising exceptions.
    
    Returns dict with:
        - has_agent: bool
        - agent_id: str or None
        - scan_types: list of supported scan types
    """
    if not universal_agent_manager.has_connected_agent(user_id):
        return {"has_agent": False, "agent_id": None, "scan_types": []}
    
    agents = universal_agent_manager.get_user_agents(user_id)
    if not agents:
        return {"has_agent": False, "agent_id": None, "scan_types": []}
    
    # Get first agent that supports the scan type, or just the first one
    if scan_type:
        for agent in agents:
            if scan_type in agent.get("scan_types", []):
                return {
                    "has_agent": True,
                    "agent_id": agent["agent_id"],
                    "scan_types": agent.get("scan_types", [])
                }
    
    # Return first available agent
    return {
        "has_agent": True,
        "agent_id": agents[0]["agent_id"],
        "scan_types": agents[0].get("scan_types", [])
    }
