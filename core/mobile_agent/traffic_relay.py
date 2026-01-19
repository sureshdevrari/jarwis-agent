"""
Jarwis Mobile Agent - Traffic Relay

Bridges local MITM proxy traffic to Jarwis server via WebSocket.
Captures HTTP traffic from mobile app and relays to server for attack analysis.
"""

import asyncio
import logging
import hashlib
from typing import Dict, List, Optional, Set, TYPE_CHECKING
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .agent_core import MobileAgent
    from .local_mitm import LocalMITMManager

from .agent_protocol import (
    AgentMessageType,
    AgentMessage,
    TrafficData,
)

logger = logging.getLogger(__name__)


@dataclass
class TrafficFilter:
    """Filter configuration for traffic capture"""
    target_hosts: List[str]           # Only capture traffic to these hosts
    exclude_paths: List[str]          # Exclude paths matching these patterns
    exclude_extensions: Set[str]      # Exclude static resources
    min_content_length: int = 0       # Minimum response size to capture
    
    def __init__(
        self,
        target_hosts: Optional[List[str]] = None,
        exclude_paths: Optional[List[str]] = None
    ):
        self.target_hosts = target_hosts or []
        self.exclude_paths = exclude_paths or [
            "/static/", "/assets/", "/images/", 
            "/_next/", "/favicon", "/manifest.json"
        ]
        self.exclude_extensions = {
            ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
            ".css", ".woff", ".woff2", ".ttf", ".eot",
            ".mp3", ".mp4", ".webm", ".ogg"
        }
    
    def should_capture(self, url: str) -> bool:
        """Check if this URL should be captured"""
        parsed = urlparse(url)
        
        # Check host filter
        if self.target_hosts:
            if not any(host in parsed.netloc for host in self.target_hosts):
                return False
        
        # Check path exclusions
        path_lower = parsed.path.lower()
        for exclude in self.exclude_paths:
            if exclude in path_lower:
                return False
        
        # Check extension exclusions
        for ext in self.exclude_extensions:
            if path_lower.endswith(ext):
                return False
        
        return True


class TrafficRelay:
    """
    Captures traffic from local MITM proxy and relays to Jarwis server.
    
    Flow:
    1. MITM proxy captures mobile app HTTPS traffic
    2. TrafficRelay receives flow via callback
    3. Traffic is filtered (target hosts, exclude static)
    4. Filtered traffic is batched and sent to server via WebSocket
    5. Server stores in MobileRequestStore for attack scanning
    """
    
    def __init__(
        self,
        agent: 'MobileAgent',
        mitm_manager: 'LocalMITMManager',
        batch_size: int = 10,
        batch_interval: float = 1.0
    ):
        self.agent = agent
        self.mitm_manager = mitm_manager
        self.batch_size = batch_size
        self.batch_interval = batch_interval
        
        self.filter = TrafficFilter()
        self._running = False
        self._batch_task: Optional[asyncio.Task] = None
        
        # Traffic buffer for batching
        self._traffic_buffer: List[TrafficData] = []
        self._buffer_lock = asyncio.Lock()
        
        # Deduplication
        self._seen_hashes: Set[str] = set()
        self._max_seen_cache = 10000
        
        # Statistics
        self.stats = {
            "total_captured": 0,
            "total_relayed": 0,
            "filtered_out": 0,
            "deduplicated": 0
        }
    
    def set_target_hosts(self, hosts: List[str]):
        """Set target hosts for filtering"""
        self.filter.target_hosts = hosts
        logger.info(f"Traffic filter set to hosts: {hosts}")
    
    async def start(self):
        """Start traffic relay"""
        if self._running:
            return
        
        logger.info("Starting traffic relay...")
        self._running = True
        
        # Register callback with MITM manager
        self.mitm_manager.set_traffic_callback(self._on_traffic_captured)
        
        # Start batch sender
        self._batch_task = asyncio.create_task(self._batch_sender_loop())
        
        logger.info("Traffic relay started")
    
    async def stop(self):
        """Stop traffic relay"""
        if not self._running:
            return
        
        logger.info("Stopping traffic relay...")
        self._running = False
        
        # Cancel batch task
        if self._batch_task:
            self._batch_task.cancel()
            try:
                await self._batch_task
            except asyncio.CancelledError:
                pass
        
        # Flush remaining buffer
        await self._flush_buffer()
        
        # Clear callback
        self.mitm_manager.set_traffic_callback(None)
        
        logger.info(f"Traffic relay stopped. Stats: {self.stats}")
    
    async def _on_traffic_captured(
        self,
        url: str,
        method: str,
        request_headers: Dict[str, str],
        request_body: str,
        response_status: int,
        response_headers: Dict[str, str],
        response_body: str,
        duration_ms: int
    ):
        """Callback when MITM captures traffic"""
        self.stats["total_captured"] += 1
        
        # Apply filter
        if not self.filter.should_capture(url):
            self.stats["filtered_out"] += 1
            return
        
        # Create traffic data
        request_id = self._generate_request_id(url, method, request_body)
        
        # Deduplicate
        if request_id in self._seen_hashes:
            self.stats["deduplicated"] += 1
            return
        
        self._seen_hashes.add(request_id)
        if len(self._seen_hashes) > self._max_seen_cache:
            # Clear oldest half
            self._seen_hashes = set(list(self._seen_hashes)[self._max_seen_cache // 2:])
        
        # Detect auth
        has_auth, auth_type, auth_header = self._detect_auth(request_headers)
        
        traffic = TrafficData(
            request_id=request_id,
            url=url,
            method=method,
            headers=request_headers,
            body=request_body,
            response_status=response_status,
            response_headers=response_headers,
            response_body=response_body[:50000] if response_body else "",  # Truncate large responses
            source="mitm",
            has_auth=has_auth,
            auth_type=auth_type,
            auth_header=auth_header,
            timestamp=datetime.utcnow().isoformat(),
            duration_ms=duration_ms
        )
        
        # Add to buffer
        async with self._buffer_lock:
            self._traffic_buffer.append(traffic)
            
            # Immediate send if buffer full
            if len(self._traffic_buffer) >= self.batch_size:
                await self._flush_buffer()
    
    async def _batch_sender_loop(self):
        """Background task to send buffered traffic"""
        while self._running:
            try:
                await asyncio.sleep(self.batch_interval)
                await self._flush_buffer()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Batch sender error: {e}")
    
    async def _flush_buffer(self):
        """Send buffered traffic to server"""
        async with self._buffer_lock:
            if not self._traffic_buffer:
                return
            
            batch = self._traffic_buffer.copy()
            self._traffic_buffer.clear()
        
        if not batch:
            return
        
        try:
            if len(batch) == 1:
                # Single item - send directly
                await self.agent._send_message(AgentMessage(
                    type=AgentMessageType.TRAFFIC_CAPTURED,
                    scan_id=self.agent.current_scan_id,
                    data=batch[0].to_dict()
                ))
            else:
                # Batch send
                await self.agent._send_message(AgentMessage(
                    type=AgentMessageType.TRAFFIC_BATCH,
                    scan_id=self.agent.current_scan_id,
                    data={
                        "count": len(batch),
                        "traffic": [t.to_dict() for t in batch]
                    }
                ))
            
            self.stats["total_relayed"] += len(batch)
            logger.debug(f"Relayed {len(batch)} traffic items to server")
            
        except Exception as e:
            logger.error(f"Failed to relay traffic: {e}")
            # Re-add to buffer for retry
            async with self._buffer_lock:
                self._traffic_buffer = batch + self._traffic_buffer
    
    def _generate_request_id(self, url: str, method: str, body: str) -> str:
        """Generate unique ID for request (for deduplication)"""
        content = f"{method}:{url}:{body or ''}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _detect_auth(self, headers: Dict[str, str]) -> tuple:
        """Detect authentication in request headers"""
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check Authorization header
        if "authorization" in headers_lower:
            auth_value = headers_lower["authorization"]
            if auth_value.lower().startswith("bearer"):
                return True, "bearer", "Authorization"
            elif auth_value.lower().startswith("basic"):
                return True, "basic", "Authorization"
            else:
                return True, "custom", "Authorization"
        
        # Check common API key headers
        api_key_headers = ["x-api-key", "api-key", "apikey", "x-auth-token", "x-access-token"]
        for header in api_key_headers:
            if header in headers_lower:
                return True, "api_key", header
        
        # Check cookies for session tokens
        if "cookie" in headers_lower:
            cookie = headers_lower["cookie"].lower()
            if any(s in cookie for s in ["session", "token", "auth", "jwt"]):
                return True, "cookie", "Cookie"
        
        return False, "", ""


class FridaTrafficBridge:
    """
    Bridges traffic captured by Frida hooks to the relay.
    
    Frida hooks capture HTTP calls before SSL/TLS encryption,
    providing visibility into pinned certificate traffic.
    """
    
    def __init__(self, relay: TrafficRelay):
        self.relay = relay
        self._frida_session = None
    
    async def on_frida_request(
        self,
        hook_name: str,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str,
        app_package: str
    ):
        """Handle request captured by Frida hook"""
        request_id = self.relay._generate_request_id(url, method, body)
        
        has_auth, auth_type, auth_header = self.relay._detect_auth(headers)
        
        traffic = TrafficData(
            request_id=request_id,
            url=url,
            method=method,
            headers=headers,
            body=body,
            source="frida",
            frida_hook=hook_name,
            app_package=app_package,
            has_auth=has_auth,
            auth_type=auth_type,
            auth_header=auth_header,
            timestamp=datetime.utcnow().isoformat()
        )
        
        # Note: Frida doesn't capture response - will be filled by MITM
        async with self.relay._buffer_lock:
            self.relay._traffic_buffer.append(traffic)
