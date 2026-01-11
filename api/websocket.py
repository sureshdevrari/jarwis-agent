"""
WebSocket Manager for Real-Time Updates

Provides real-time push updates for:
- Scan progress and status changes
- Live log streaming
- Dashboard statistics updates
- Notifications

Uses the observer pattern to broadcast updates to connected clients.
"""

import asyncio
import json
import logging
from typing import Dict, Set, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class MessageType(str, Enum):
    """WebSocket message types"""
    SCAN_PROGRESS = "scan_progress"
    SCAN_STATUS = "scan_status"
    SCAN_LOG = "scan_log"
    SCAN_COMPLETE = "scan_complete"
    SCAN_ERROR = "scan_error"
    FINDING = "finding"
    DASHBOARD_UPDATE = "dashboard_update"
    NOTIFICATION = "notification"
    PING = "ping"
    PONG = "pong"


@dataclass
class WSMessage:
    """Standard WebSocket message format"""
    type: MessageType
    data: dict
    scan_id: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_json(self) -> str:
        return json.dumps({
            "type": self.type.value if isinstance(self.type, MessageType) else self.type,
            "data": self.data,
            "scan_id": self.scan_id,
            "timestamp": self.timestamp
        })


class ConnectionManager:
    """
    Manages WebSocket connections for real-time updates.
    
    Supports:
    - Per-scan subscriptions (clients watching specific scans)
    - User-level subscriptions (all updates for a user)
    - Broadcast to all connected clients
    """
    
    def __init__(self):
        # scan_id -> set of WebSocket connections
        self.scan_connections: Dict[str, Set[WebSocket]] = {}
        
        # user_id -> set of WebSocket connections (for dashboard updates)
        self.user_connections: Dict[int, Set[WebSocket]] = {}
        
        # All active connections (for broadcasts)
        self.active_connections: Set[WebSocket] = set()
        
        # WebSocket -> metadata (user_id, subscriptions, etc.)
        self.connection_metadata: Dict[WebSocket, dict] = {}
        
        # Lock for thread-safe operations
        self._lock = asyncio.Lock()
    
    async def connect(
        self, 
        websocket: WebSocket, 
        user_id: Optional[int] = None,
        scan_id: Optional[str] = None
    ):
        """Accept a new WebSocket connection"""
        await websocket.accept()
        
        async with self._lock:
            self.active_connections.add(websocket)
            
            # Store connection metadata
            self.connection_metadata[websocket] = {
                "user_id": user_id,
                "scan_ids": set(),
                "connected_at": datetime.utcnow().isoformat()
            }
            
            # Subscribe to user updates if authenticated
            if user_id is not None:
                if user_id not in self.user_connections:
                    self.user_connections[user_id] = set()
                self.user_connections[user_id].add(websocket)
            
            # Subscribe to scan updates if specified
            if scan_id:
                await self._subscribe_to_scan(websocket, scan_id)
        
        logger.info(f"WebSocket connected: user={user_id}, scan={scan_id}, total={len(self.active_connections)}")
    
    async def disconnect(self, websocket: WebSocket):
        """Handle WebSocket disconnection"""
        async with self._lock:
            # Remove from active connections
            self.active_connections.discard(websocket)
            
            # Get metadata and clean up subscriptions
            metadata = self.connection_metadata.pop(websocket, {})
            user_id = metadata.get("user_id")
            scan_ids = metadata.get("scan_ids", set())
            
            # Remove from user connections
            if user_id and user_id in self.user_connections:
                self.user_connections[user_id].discard(websocket)
                if not self.user_connections[user_id]:
                    del self.user_connections[user_id]
            
            # Remove from scan connections
            for scan_id in scan_ids:
                if scan_id in self.scan_connections:
                    self.scan_connections[scan_id].discard(websocket)
                    if not self.scan_connections[scan_id]:
                        del self.scan_connections[scan_id]
        
        logger.info(f"WebSocket disconnected: user={user_id}, remaining={len(self.active_connections)}")
    
    async def subscribe_to_scan(self, websocket: WebSocket, scan_id: str):
        """Subscribe a connection to scan updates"""
        async with self._lock:
            await self._subscribe_to_scan(websocket, scan_id)
    
    async def _subscribe_to_scan(self, websocket: WebSocket, scan_id: str):
        """Internal method to subscribe (must hold lock)"""
        if scan_id not in self.scan_connections:
            self.scan_connections[scan_id] = set()
        self.scan_connections[scan_id].add(websocket)
        
        if websocket in self.connection_metadata:
            self.connection_metadata[websocket]["scan_ids"].add(scan_id)
        
        logger.debug(f"Subscribed to scan {scan_id}, subscribers={len(self.scan_connections[scan_id])}")
    
    async def unsubscribe_from_scan(self, websocket: WebSocket, scan_id: str):
        """Unsubscribe a connection from scan updates"""
        async with self._lock:
            if scan_id in self.scan_connections:
                self.scan_connections[scan_id].discard(websocket)
                if not self.scan_connections[scan_id]:
                    del self.scan_connections[scan_id]
            
            if websocket in self.connection_metadata:
                self.connection_metadata[websocket]["scan_ids"].discard(scan_id)
    
    async def send_to_scan(self, scan_id: str, message: WSMessage):
        """Send a message to all clients subscribed to a scan"""
        message.scan_id = scan_id
        json_message = message.to_json()
        
        connections = self.scan_connections.get(scan_id, set()).copy()
        if not connections:
            return
        
        disconnected = []
        for websocket in connections:
            try:
                await websocket.send_text(json_message)
            except Exception as e:
                logger.warning(f"Failed to send to websocket: {e}")
                disconnected.append(websocket)
        
        # Clean up disconnected
        for ws in disconnected:
            await self.disconnect(ws)
    
    async def send_to_user(self, user_id: int, message: WSMessage):
        """Send a message to all connections for a user"""
        json_message = message.to_json()
        
        connections = self.user_connections.get(user_id, set()).copy()
        if not connections:
            return
        
        disconnected = []
        for websocket in connections:
            try:
                await websocket.send_text(json_message)
            except Exception as e:
                logger.warning(f"Failed to send to user {user_id}: {e}")
                disconnected.append(websocket)
        
        for ws in disconnected:
            await self.disconnect(ws)
    
    async def broadcast(self, message: WSMessage):
        """Broadcast a message to all connected clients"""
        json_message = message.to_json()
        
        connections = self.active_connections.copy()
        disconnected = []
        
        for websocket in connections:
            try:
                await websocket.send_text(json_message)
            except Exception:
                disconnected.append(websocket)
        
        for ws in disconnected:
            await self.disconnect(ws)
    
    async def send_personal(self, websocket: WebSocket, message: WSMessage):
        """Send a message to a specific connection"""
        try:
            await websocket.send_text(message.to_json())
        except Exception as e:
            logger.warning(f"Failed to send personal message: {e}")
            await self.disconnect(websocket)
    
    def get_scan_subscriber_count(self, scan_id: str) -> int:
        """Get number of subscribers for a scan"""
        return len(self.scan_connections.get(scan_id, set()))
    
    def get_stats(self) -> dict:
        """Get connection statistics"""
        return {
            "total_connections": len(self.active_connections),
            "unique_users": len(self.user_connections),
            "active_scan_subscriptions": len(self.scan_connections),
            "scans_with_subscribers": list(self.scan_connections.keys())
        }


# Global connection manager instance
manager = ConnectionManager()


# ============== Helper Functions for Scan Updates ==============

async def broadcast_scan_progress(
    scan_id: str,
    progress: int,
    phase: str,
    message: str = "",
    findings_count: int = 0,
    current_task: str = ""
):
    """Broadcast scan progress update"""
    await manager.send_to_scan(scan_id, WSMessage(
        type=MessageType.SCAN_PROGRESS,
        data={
            "progress": progress,
            "phase": phase,
            "message": message,
            "findings_count": findings_count,
            "current_task": current_task
        }
    ))


async def broadcast_scan_status(scan_id: str, status: str, message: str = ""):
    """Broadcast scan status change"""
    await manager.send_to_scan(scan_id, WSMessage(
        type=MessageType.SCAN_STATUS,
        data={
            "status": status,
            "message": message
        }
    ))


async def broadcast_scan_log(scan_id: str, level: str, message: str, phase: str = ""):
    """Broadcast a log entry for a scan"""
    await manager.send_to_scan(scan_id, WSMessage(
        type=MessageType.SCAN_LOG,
        data={
            "level": level,
            "message": message,
            "phase": phase,
            "timestamp": datetime.utcnow().isoformat()
        }
    ))


async def broadcast_scan_complete(
    scan_id: str,
    findings_count: int,
    duration_seconds: int,
    summary: dict = None
):
    """Broadcast scan completion"""
    await manager.send_to_scan(scan_id, WSMessage(
        type=MessageType.SCAN_COMPLETE,
        data={
            "findings_count": findings_count,
            "duration_seconds": duration_seconds,
            "summary": summary or {}
        }
    ))


async def broadcast_scan_error(scan_id: str, error: str, recoverable: bool = False):
    """Broadcast scan error"""
    await manager.send_to_scan(scan_id, WSMessage(
        type=MessageType.SCAN_ERROR,
        data={
            "error": error,
            "recoverable": recoverable
        }
    ))


async def broadcast_finding(scan_id: str, finding: dict):
    """Broadcast a new finding discovered during scan"""
    await manager.send_to_scan(scan_id, WSMessage(
        type=MessageType.FINDING,
        data=finding
    ))


async def broadcast_dashboard_update(user_id: int, stats: dict):
    """Broadcast dashboard statistics update to a user"""
    await manager.send_to_user(user_id, WSMessage(
        type=MessageType.DASHBOARD_UPDATE,
        data=stats
    ))


async def broadcast_notification(user_id: int, title: str, message: str, level: str = "info"):
    """Send a notification to a user"""
    await manager.send_to_user(user_id, WSMessage(
        type=MessageType.NOTIFICATION,
        data={
            "title": title,
            "message": message,
            "level": level
        }
    ))
