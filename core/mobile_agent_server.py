"""
Jarwis Server - Mobile Agent Session Manager

Server-side component for managing remote mobile agent connections.
Handles agent authentication, session lifecycle, and traffic relay.
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Set, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class AgentState(str, Enum):
    """Agent connection state"""
    CONNECTING = "connecting"
    AUTHENTICATING = "authenticating"
    IDLE = "idle"
    SCANNING = "scanning"
    PAUSED = "paused"
    ERROR = "error"
    DISCONNECTED = "disconnected"


@dataclass
class AgentSession:
    """Represents a connected mobile agent"""
    agent_id: str
    websocket: WebSocket
    user_id: int
    
    # Connection state
    state: AgentState = AgentState.CONNECTING
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_heartbeat: datetime = field(default_factory=datetime.utcnow)
    
    # Agent capabilities
    capabilities: List[str] = field(default_factory=list)
    os: str = ""
    os_version: str = ""
    hostname: str = ""
    agent_version: str = ""
    
    # Current scan
    current_scan_id: Optional[str] = None
    
    # Statistics
    traffic_received: int = 0
    attacks_executed: int = 0
    
    def to_dict(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "user_id": self.user_id,
            "state": self.state.value,
            "connected_at": self.connected_at.isoformat(),
            "last_heartbeat": self.last_heartbeat.isoformat(),
            "capabilities": self.capabilities,
            "os": self.os,
            "hostname": self.hostname,
            "agent_version": self.agent_version,
            "current_scan_id": self.current_scan_id,
            "traffic_received": self.traffic_received,
            "attacks_executed": self.attacks_executed
        }


class MobileAgentManager:
    """
    Manages mobile agent connections on Jarwis server.
    
    Responsibilities:
    - Agent authentication and session management
    - Message routing between server and agents
    - Traffic relay to MobileRequestStore
    - Attack request forwarding to agents
    - Session cleanup and heartbeat monitoring
    """
    
    def __init__(self):
        # agent_id -> AgentSession
        self._sessions: Dict[str, AgentSession] = {}
        
        # user_id -> set of agent_ids
        self._user_agents: Dict[int, Set[str]] = {}
        
        # scan_id -> agent_id (which agent is running which scan)
        self._scan_agents: Dict[str, str] = {}
        
        # Callbacks
        self._on_traffic_received: Optional[Callable] = None
        self._on_agent_connected: Optional[Callable] = None
        self._on_agent_disconnected: Optional[Callable] = None
        
        # Background tasks
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Lock for thread safety
        self._lock = asyncio.Lock()
    
    async def start(self):
        """Start the agent manager"""
        self._running = True
        self._heartbeat_task = asyncio.create_task(self._heartbeat_monitor())
        logger.info("MobileAgentManager started")
    
    async def stop(self):
        """Stop the agent manager"""
        self._running = False
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
        
        # Disconnect all agents
        for session in list(self._sessions.values()):
            await self.disconnect_agent(session.agent_id)
        
        logger.info("MobileAgentManager stopped")
    
    # === Agent Connection ===
    
    async def handle_agent_connection(
        self,
        websocket: WebSocket,
        user_id: int,
        auth_token: str
    ) -> Optional[str]:
        """
        Handle new agent WebSocket connection.
        
        Returns agent_id if successful, None if auth fails.
        """
        await websocket.accept()
        
        try:
            # Wait for auth message
            raw_msg = await asyncio.wait_for(websocket.receive_text(), timeout=10)
            msg = json.loads(raw_msg)
            
            if msg.get("type") != "auth_request":
                await self._send_error(websocket, "Expected auth_request")
                return None
            
            agent_id = msg.get("data", {}).get("agent_id")
            token = msg.get("data", {}).get("token")
            
            # Validate token (should match user's token)
            if token != auth_token:
                await self._send_auth_response(websocket, False, "Invalid token")
                return None
            
            # Create session
            async with self._lock:
                session = AgentSession(
                    agent_id=agent_id,
                    websocket=websocket,
                    user_id=user_id,
                    state=AgentState.IDLE
                )
                
                self._sessions[agent_id] = session
                
                if user_id not in self._user_agents:
                    self._user_agents[user_id] = set()
                self._user_agents[user_id].add(agent_id)
            
            # Send success
            await self._send_auth_response(websocket, True)
            
            logger.info(f"Agent connected: {agent_id} (user: {user_id})")
            
            if self._on_agent_connected:
                await self._on_agent_connected(session)
            
            return agent_id
            
        except asyncio.TimeoutError:
            logger.warning("Agent auth timeout")
            return None
        except Exception as e:
            logger.error(f"Agent connection error: {e}")
            return None
    
    async def disconnect_agent(self, agent_id: str):
        """Disconnect an agent"""
        async with self._lock:
            session = self._sessions.pop(agent_id, None)
            if not session:
                return
            
            # Remove from user mapping
            if session.user_id in self._user_agents:
                self._user_agents[session.user_id].discard(agent_id)
            
            # Remove scan mapping
            if session.current_scan_id:
                self._scan_agents.pop(session.current_scan_id, None)
        
        # Close WebSocket
        try:
            await session.websocket.close()
        except Exception:
            pass
        
        logger.info(f"Agent disconnected: {agent_id}")
        
        if self._on_agent_disconnected:
            await self._on_agent_disconnected(session)
    
    # === Message Handling ===
    
    async def handle_agent_message(self, agent_id: str, raw_message: str):
        """Process message from agent"""
        session = self._sessions.get(agent_id)
        if not session:
            logger.warning(f"Message from unknown agent: {agent_id}")
            return
        
        try:
            msg = json.loads(raw_message)
            msg_type = msg.get("type")
            data = msg.get("data", {})
            scan_id = msg.get("scan_id")
            
            # Update heartbeat
            session.last_heartbeat = datetime.utcnow()
            
            # Route by message type
            if msg_type == "agent_status":
                await self._handle_status(session, data)
            
            elif msg_type == "heartbeat":
                await self._handle_heartbeat(session, data)
            
            elif msg_type == "traffic_captured":
                await self._handle_traffic(session, scan_id, data)
            
            elif msg_type == "traffic_batch":
                await self._handle_traffic_batch(session, scan_id, data)
            
            elif msg_type == "attack_response":
                await self._handle_attack_response(session, scan_id, data)
            
            elif msg_type == "scan_progress":
                await self._handle_scan_progress(session, scan_id, data)
            
            elif msg_type == "scan_complete":
                await self._handle_scan_complete(session, scan_id, data)
            
            elif msg_type == "agent_error":
                await self._handle_agent_error(session, scan_id, data)
            
            elif msg_type == "app_launched":
                logger.info(f"App launched on agent {agent_id}: {data.get('package')}")
            
            else:
                logger.debug(f"Unhandled message type: {msg_type}")
                
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON from agent {agent_id}")
        except Exception as e:
            logger.error(f"Error handling agent message: {e}")
    
    async def _handle_status(self, session: AgentSession, data: dict):
        """Handle agent status update"""
        session.capabilities = data.get("capabilities", [])
        session.os = data.get("os", "")
        session.os_version = data.get("os_version", "")
        session.hostname = data.get("hostname", "")
        session.agent_version = data.get("version", "")
        
        state = data.get("state", "idle")
        session.state = AgentState(state) if state in AgentState.__members__.values() else AgentState.IDLE
        
        logger.debug(f"Agent status updated: {session.agent_id}")
    
    async def _handle_heartbeat(self, session: AgentSession, data: dict):
        """Handle heartbeat"""
        # Send pong if this was a ping
        if data.get("ping"):
            await self._send_to_agent(session.agent_id, {
                "type": "heartbeat",
                "data": {"pong": True}
            })
    
    async def _handle_traffic(self, session: AgentSession, scan_id: str, data: dict):
        """Handle captured traffic from agent"""
        session.traffic_received += 1
        
        if self._on_traffic_received:
            await self._on_traffic_received(scan_id, data)
        
        # Send acknowledgment
        await self._send_to_agent(session.agent_id, {
            "type": "traffic_ack",
            "scan_id": scan_id,
            "data": {"request_id": data.get("request_id")}
        })
    
    async def _handle_traffic_batch(self, session: AgentSession, scan_id: str, data: dict):
        """Handle batch of traffic from agent"""
        traffic_items = data.get("traffic", [])
        session.traffic_received += len(traffic_items)
        
        if self._on_traffic_received:
            for item in traffic_items:
                await self._on_traffic_received(scan_id, item)
        
        # Send batch acknowledgment
        await self._send_to_agent(session.agent_id, {
            "type": "traffic_ack",
            "scan_id": scan_id,
            "data": {"count": len(traffic_items)}
        })
    
    async def _handle_attack_response(self, session: AgentSession, scan_id: str, data: dict):
        """Handle attack response from agent"""
        session.attacks_executed += 1
        
        # Forward to scan's attack handler
        # This will be connected to the scanner that requested the attack
        attack_id = data.get("attack_id")
        
        # Emit event for scanner to pick up
        from api.websocket import manager as ws_manager, WSMessage, MessageType
        
        await ws_manager.send_to_scan(scan_id, WSMessage(
            type=MessageType.SCAN_LOG,
            data={
                "level": "debug",
                "message": f"Attack response received: {attack_id}",
                "attack_data": data
            }
        ))
    
    async def _handle_scan_progress(self, session: AgentSession, scan_id: str, data: dict):
        """Handle scan progress update"""
        from api.websocket import manager as ws_manager, WSMessage, MessageType
        
        await ws_manager.send_to_scan(scan_id, WSMessage(
            type=MessageType.SCAN_PROGRESS,
            data=data
        ))
    
    async def _handle_scan_complete(self, session: AgentSession, scan_id: str, data: dict):
        """Handle scan completion"""
        session.state = AgentState.IDLE
        session.current_scan_id = None
        
        async with self._lock:
            self._scan_agents.pop(scan_id, None)
        
        from api.websocket import manager as ws_manager, WSMessage, MessageType
        
        await ws_manager.send_to_scan(scan_id, WSMessage(
            type=MessageType.SCAN_COMPLETE,
            data=data
        ))
    
    async def _handle_agent_error(self, session: AgentSession, scan_id: str, data: dict):
        """Handle agent error"""
        logger.error(f"Agent error ({session.agent_id}): {data.get('error')}")
        session.state = AgentState.ERROR
        
        if scan_id:
            from api.websocket import manager as ws_manager, WSMessage, MessageType
            
            await ws_manager.send_to_scan(scan_id, WSMessage(
                type=MessageType.SCAN_ERROR,
                data={"error": data.get("error"), "source": "agent"}
            ))
    
    # === Commands to Agent ===
    
    async def start_scan_on_agent(
        self,
        agent_id: str,
        scan_id: str,
        scan_config: dict
    ) -> bool:
        """Start a scan on specified agent"""
        session = self._sessions.get(agent_id)
        if not session:
            logger.error(f"Agent not found: {agent_id}")
            return False
        
        if session.state != AgentState.IDLE:
            logger.error(f"Agent not idle: {session.state}")
            return False
        
        # Update state
        session.state = AgentState.SCANNING
        session.current_scan_id = scan_id
        
        async with self._lock:
            self._scan_agents[scan_id] = agent_id
        
        # Send scan start command
        await self._send_to_agent(agent_id, {
            "type": "scan_start",
            "scan_id": scan_id,
            "data": scan_config
        })
        
        logger.info(f"Scan {scan_id} started on agent {agent_id}")
        return True
    
    async def stop_scan_on_agent(self, scan_id: str) -> bool:
        """Stop a scan running on an agent"""
        agent_id = self._scan_agents.get(scan_id)
        if not agent_id:
            logger.warning(f"No agent found for scan: {scan_id}")
            return False
        
        await self._send_to_agent(agent_id, {
            "type": "scan_stop",
            "scan_id": scan_id,
            "data": {}
        })
        
        return True
    
    async def send_attack_to_agent(
        self,
        scan_id: str,
        attack_request: dict
    ) -> bool:
        """Send attack request to agent running the scan"""
        agent_id = self._scan_agents.get(scan_id)
        if not agent_id:
            logger.warning(f"No agent found for scan: {scan_id}")
            return False
        
        await self._send_to_agent(agent_id, {
            "type": "attack_request",
            "scan_id": scan_id,
            "data": attack_request
        })
        
        return True
    
    async def send_attack_batch_to_agent(
        self,
        scan_id: str,
        attacks: List[dict]
    ) -> bool:
        """Send batch of attack requests to agent"""
        agent_id = self._scan_agents.get(scan_id)
        if not agent_id:
            return False
        
        await self._send_to_agent(agent_id, {
            "type": "attack_batch",
            "scan_id": scan_id,
            "data": {"attacks": attacks}
        })
        
        return True
    
    # === Helper Methods ===
    
    async def _send_to_agent(self, agent_id: str, message: dict):
        """Send message to agent"""
        session = self._sessions.get(agent_id)
        if not session:
            return
        
        try:
            await session.websocket.send_text(json.dumps(message))
        except Exception as e:
            logger.error(f"Failed to send to agent {agent_id}: {e}")
            await self.disconnect_agent(agent_id)
    
    async def _send_auth_response(self, websocket: WebSocket, success: bool, error: str = ""):
        """Send authentication response"""
        await websocket.send_text(json.dumps({
            "type": "auth_response",
            "data": {"success": success, "error": error}
        }))
    
    async def _send_error(self, websocket: WebSocket, error: str):
        """Send error message"""
        await websocket.send_text(json.dumps({
            "type": "agent_error",
            "data": {"error": error}
        }))
    
    async def _heartbeat_monitor(self):
        """Monitor agent heartbeats and disconnect stale connections"""
        while self._running:
            try:
                await asyncio.sleep(30)
                
                now = datetime.utcnow()
                stale_threshold = timedelta(minutes=2)
                
                stale_agents = []
                for agent_id, session in self._sessions.items():
                    if now - session.last_heartbeat > stale_threshold:
                        stale_agents.append(agent_id)
                
                for agent_id in stale_agents:
                    logger.warning(f"Agent heartbeat timeout: {agent_id}")
                    await self.disconnect_agent(agent_id)
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Heartbeat monitor error: {e}")
    
    # === Query Methods ===
    
    def get_agent(self, agent_id: str) -> Optional[AgentSession]:
        """Get agent session by ID"""
        return self._sessions.get(agent_id)
    
    def get_user_agents(self, user_id: int) -> List[AgentSession]:
        """Get all agents for a user"""
        agent_ids = self._user_agents.get(user_id, set())
        return [self._sessions[aid] for aid in agent_ids if aid in self._sessions]
    
    def get_idle_agent(self, user_id: int) -> Optional[AgentSession]:
        """Get an idle agent for user (for starting new scans)"""
        for session in self.get_user_agents(user_id):
            if session.state == AgentState.IDLE:
                return session
        return None
    
    def get_scan_agent(self, scan_id: str) -> Optional[AgentSession]:
        """Get agent running a specific scan"""
        agent_id = self._scan_agents.get(scan_id)
        return self._sessions.get(agent_id) if agent_id else None
    
    def get_stats(self) -> dict:
        """Get manager statistics"""
        return {
            "total_agents": len(self._sessions),
            "active_scans": len(self._scan_agents),
            "agents_by_state": {
                state.value: sum(1 for s in self._sessions.values() if s.state == state)
                for state in AgentState
            }
        }
    
    # === Callbacks ===
    
    def set_traffic_callback(self, callback: Callable):
        """Set callback for traffic received from agents"""
        self._on_traffic_received = callback
    
    def set_connection_callbacks(
        self,
        on_connected: Optional[Callable] = None,
        on_disconnected: Optional[Callable] = None
    ):
        """Set connection lifecycle callbacks"""
        self._on_agent_connected = on_connected
        self._on_agent_disconnected = on_disconnected


# Global instance
mobile_agent_manager = MobileAgentManager()
