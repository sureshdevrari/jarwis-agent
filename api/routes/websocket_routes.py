"""
WebSocket Routes for Real-Time Updates

Endpoints:
- /ws/scans/{scan_id} - Subscribe to scan updates
- /ws/dashboard - Subscribe to dashboard updates
- /ws/notifications - Subscribe to user notifications
"""

import logging
from typing import Optional

from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from starlette.websockets import WebSocketState

from api.websocket import (
    manager, WSMessage, MessageType,
    broadcast_scan_progress, broadcast_scan_status
)
from database.auth import decode_token

logger = logging.getLogger(__name__)

router = APIRouter(tags=["WebSocket"])


def get_user_from_token(token: Optional[str]) -> Optional[dict]:
    """Validate JWT token and return user info"""
    if not token:
        return None
    try:
        payload = decode_token(token)
        return payload
    except Exception as e:
        logger.warning(f"Invalid WebSocket token: {e}")
        return None


@router.websocket("/ws/scans/{scan_id}")
async def websocket_scan_updates(
    websocket: WebSocket,
    scan_id: str,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for real-time scan updates.
    
    Connect: ws://localhost:8000/ws/scans/{scan_id}?token={jwt_token}
    
    Messages received:
    - scan_progress: { progress, phase, message, findings_count }
    - scan_status: { status, message }
    - scan_log: { level, message, phase, timestamp }
    - scan_complete: { findings_count, duration_seconds, summary }
    - scan_error: { error, recoverable }
    - finding: { severity, title, url, ... }
    
    Messages you can send:
    - { "action": "subscribe", "scan_id": "..." } - Subscribe to another scan
    - { "action": "unsubscribe", "scan_id": "..." } - Unsubscribe from a scan
    - { "action": "ping" } - Keep-alive ping
    """
    # Validate token (optional - allow anonymous for public scans)
    user = get_user_from_token(token)
    user_id = user.get("sub") if user else None
    
    try:
        # Accept connection and subscribe to scan
        await manager.connect(websocket, user_id=user_id, scan_id=scan_id)
        
        # Send initial acknowledgment
        await manager.send_personal(websocket, WSMessage(
            type=MessageType.SCAN_STATUS,
            scan_id=scan_id,
            data={
                "status": "connected",
                "message": f"Subscribed to scan {scan_id} updates",
                "subscribers": manager.get_scan_subscriber_count(scan_id)
            }
        ))
        
        # Listen for messages from client
        while True:
            try:
                data = await websocket.receive_json()
                action = data.get("action")
                
                if action == "ping":
                    await manager.send_personal(websocket, WSMessage(
                        type=MessageType.PONG,
                        data={"message": "pong"}
                    ))
                
                elif action == "subscribe":
                    new_scan_id = data.get("scan_id")
                    if new_scan_id:
                        await manager.subscribe_to_scan(websocket, new_scan_id)
                        await manager.send_personal(websocket, WSMessage(
                            type=MessageType.SCAN_STATUS,
                            scan_id=new_scan_id,
                            data={"status": "subscribed", "message": f"Subscribed to {new_scan_id}"}
                        ))
                
                elif action == "unsubscribe":
                    old_scan_id = data.get("scan_id")
                    if old_scan_id:
                        await manager.unsubscribe_from_scan(websocket, old_scan_id)
                        await manager.send_personal(websocket, WSMessage(
                            type=MessageType.SCAN_STATUS,
                            scan_id=old_scan_id,
                            data={"status": "unsubscribed", "message": f"Unsubscribed from {old_scan_id}"}
                        ))
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.warning(f"WebSocket message error: {e}")
                # Continue listening, don't break on message errors
    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        await manager.disconnect(websocket)


@router.websocket("/ws/dashboard")
async def websocket_dashboard_updates(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    WebSocket endpoint for real-time dashboard updates.
    
    Connect: ws://localhost:8000/ws/dashboard?token={jwt_token}
    
    Requires authentication. Receives:
    - dashboard_update: { stats... }
    - notification: { title, message, level }
    """
    # Require authentication for dashboard
    user = get_user_from_token(token)
    if not user:
        await websocket.close(code=4001, reason="Authentication required")
        return
    
    user_id = user.get("sub")
    
    try:
        await manager.connect(websocket, user_id=user_id)
        
        await manager.send_personal(websocket, WSMessage(
            type=MessageType.DASHBOARD_UPDATE,
            data={"status": "connected", "message": "Dashboard updates active"}
        ))
        
        while True:
            try:
                data = await websocket.receive_json()
                action = data.get("action")
                
                if action == "ping":
                    await manager.send_personal(websocket, WSMessage(
                        type=MessageType.PONG,
                        data={"message": "pong"}
                    ))
                
                elif action == "subscribe_scan":
                    scan_id = data.get("scan_id")
                    if scan_id:
                        await manager.subscribe_to_scan(websocket, scan_id)
                
            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.warning(f"Dashboard WebSocket error: {e}")
    
    except WebSocketDisconnect:
        pass
    finally:
        await manager.disconnect(websocket)


@router.get("/ws/stats")
async def get_websocket_stats():
    """Get WebSocket connection statistics (admin only)"""
    return manager.get_stats()
