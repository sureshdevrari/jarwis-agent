"""
Jarwis AGI Pen Test - Proxy-Aware HTTP Client

This is the CORE of the true hacker methodology.
ALL attack requests MUST go through this client which routes them through MITM proxy.

Flow:
1. Scanner reads stored request from RequestStore
2. Scanner modifies headers/body (like Burp Suite Repeater)
3. Scanner calls JarwisHTTPClient.send_attack()
4. Client routes request THROUGH MITM proxy
5. MITM captures attack request and response
6. Response returned to scanner for analysis

This ensures ALL attack traffic is captured and can be replayed/analyzed.

Usage:
    # Port is now auto-allocated per scan via MITMPortManager
    client = JarwisHTTPClient(proxy_host="127.0.0.1", proxy_port=mitm_proxy.port)
    await client.start()
    
    response = await client.send_attack(
        original_request=captured_request,
        modified_headers={"X-Injected": "payload"},
        modified_body="id=1' OR 1=1--"
    )
    
    await client.stop()
"""

import asyncio
import aiohttp
import ssl
import logging
import hashlib
import time
from typing import Dict, List, Optional, Any, Tuple, Callable
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class AttackRequest:
    """Represents a modified attack request to be sent through MITM"""
    id: str
    original_request_id: str  # Links to source CapturedRequest
    scanner_name: str  # Which scanner/tool sent this
    attack_type: str  # sqli, xss, ssrf, etc.
    
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    
    # Payload info for later analysis
    payload: str = ""
    payload_location: str = ""  # header, query, body, path
    parameter_name: str = ""  # Which param was modified
    
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass
class AttackResponse:
    """Response from an attack request"""
    attack_request_id: str
    
    status_code: int
    headers: Dict[str, str]
    body: str = ""
    
    # Timing for detection
    response_time_ms: float = 0
    
    # Analysis helpers
    body_length: int = 0
    content_type: str = ""
    
    # Request details for Burp-style evidence (what was actually sent)
    request_url: str = ""  # The URL with payload injected
    request_body: str = ""  # The body with payload injected
    request_method: str = ""  # HTTP method used
    
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        self.body_length = len(self.body)
        self.content_type = self.headers.get('Content-Type', self.headers.get('content-type', ''))


class JarwisHTTPClient:
    """
    Proxy-aware HTTP client for attack requests.
    
    This client ensures ALL attack traffic goes through the MITM proxy,
    exactly like how Burp Suite's Repeater works.
    
    Features:
    - Routes all requests through MITM proxy
    - Maintains connection pool for performance
    - Handles SSL/TLS certificate verification bypass
    - Provides timing information for time-based attacks
    - Supports authentication token injection
    - Rate limiting to avoid WAF/throttling
    - Retry logic for transient failures
    """
    
    def __init__(
        self,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = None,  # None = get from MITM proxy instance or use 8080
        use_proxy: bool = True,
        timeout: int = 30,
        max_connections: int = 50,
        rate_limit: float = 0,  # Requests per second, 0 = unlimited
        retry_count: int = 2,
        verify_ssl: bool = False
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port or 8080  # Default fallback
        self.use_proxy = use_proxy
        self.proxy_url = f"http://{proxy_host}:{self.proxy_port}" if use_proxy else None
        
        self.timeout = timeout
        self.max_connections = max_connections
        self.rate_limit = rate_limit
        self.retry_count = retry_count
        self.verify_ssl = verify_ssl
        
        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        
        # SSL context (ignore cert errors for testing)
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        
        # Rate limiting
        self._last_request_time: float = 0
        self._request_lock = asyncio.Lock()
        
        # Auth token management
        self._auth_headers: Dict[str, str] = {}
        self._auth_cookies: Dict[str, str] = {}
        self._token_refresh_callback: Optional[Callable] = None
        
        # Statistics
        self.stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'total_response_time_ms': 0,
            'errors': []
        }
        
        # Attack request/response storage for MITM capture verification
        self._attack_requests: Dict[str, AttackRequest] = {}
        self._attack_responses: Dict[str, AttackResponse] = {}
        
        logger.info(f"JarwisHTTPClient initialized - Proxy: {'enabled' if use_proxy else 'disabled'} at {self.proxy_url}")
    
    async def start(self):
        """Initialize the HTTP session and connection pool"""
        if self._session is not None:
            return
        
        self._connector = aiohttp.TCPConnector(
            ssl=self._ssl_context,
            limit=self.max_connections,
            limit_per_host=20,
            enable_cleanup_closed=True
        )
        
        timeout_config = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=10,
            sock_read=self.timeout
        )
        
        self._session = aiohttp.ClientSession(
            connector=self._connector,
            timeout=timeout_config,
            trust_env=True  # Respect proxy environment variables as fallback
        )
        
        logger.info("JarwisHTTPClient session started")
    
    async def stop(self):
        """Close the HTTP session and cleanup"""
        if self._session:
            await self._session.close()
            self._session = None
        if self._connector:
            await self._connector.close()
            self._connector = None
        
        logger.info(f"JarwisHTTPClient stopped. Stats: {self.stats['requests_sent']} sent, {self.stats['requests_failed']} failed")
    
    def set_auth_headers(self, headers: Dict[str, str]):
        """Set authentication headers to include in all requests"""
        self._auth_headers = headers
        logger.debug(f"Auth headers set: {list(headers.keys())}")
    
    def set_auth_cookies(self, cookies: Dict[str, str]):
        """Set authentication cookies to include in all requests"""
        self._auth_cookies = cookies
        logger.debug(f"Auth cookies set: {list(cookies.keys())}")
    
    def set_token_refresh_callback(self, callback: Callable):
        """Set callback to refresh auth token when expired"""
        self._token_refresh_callback = callback
    
    def update_auth_token(self, token_type: str, token_value: str):
        """Update a specific auth token (called after refresh)"""
        if token_type == 'bearer' or token_type == 'jwt':
            self._auth_headers['Authorization'] = f"Bearer {token_value}"
        elif token_type == 'api_key':
            self._auth_headers['X-API-Key'] = token_value
        elif token_type == 'session_cookie':
            self._auth_cookies['session'] = token_value
        
        logger.info(f"Auth token updated: {token_type}")
    
    def _generate_attack_id(self, scanner_name: str, url: str, payload: str) -> str:
        """Generate unique ID for an attack request"""
        content = f"{scanner_name}:{url}:{payload}:{time.time()}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    async def _apply_rate_limit(self):
        """Apply rate limiting between requests"""
        if self.rate_limit <= 0:
            return
        
        async with self._request_lock:
            now = time.time()
            min_interval = 1.0 / self.rate_limit
            elapsed = now - self._last_request_time
            
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            
            self._last_request_time = time.time()
    
    def _merge_headers(
        self,
        original_headers: Dict[str, str],
        modified_headers: Optional[Dict[str, str]] = None,
        include_auth: bool = True
    ) -> Dict[str, str]:
        """Merge headers: original -> auth -> modified (modified wins)"""
        headers = dict(original_headers)
        
        if include_auth:
            headers.update(self._auth_headers)
        
        if modified_headers:
            headers.update(modified_headers)
        
        return headers
    
    async def send_attack(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        scanner_name: str = "unknown",
        attack_type: str = "unknown",
        original_request_id: str = "",
        payload: str = "",
        payload_location: str = "",
        parameter_name: str = "",
        include_auth: bool = True,
        follow_redirects: bool = True
    ) -> Tuple[Optional[AttackResponse], Optional[str]]:
        """
        Send an attack request through MITM proxy.
        
        This is the main method scanners should use. It:
        1. Creates an AttackRequest record
        2. Merges auth headers
        3. Sends through MITM proxy
        4. Records response with timing
        5. Returns AttackResponse for analysis
        
        Args:
            url: Target URL (can be modified from original)
            method: HTTP method
            headers: Request headers (merged with auth)
            body: Request body (for POST/PUT)
            scanner_name: Name of the calling scanner
            attack_type: Type of attack (sqli, xss, etc.)
            original_request_id: ID of source CapturedRequest
            payload: The injected payload
            payload_location: Where payload was injected
            parameter_name: Which parameter was modified
            include_auth: Whether to include auth headers
            follow_redirects: Whether to follow 3xx redirects
            
        Returns:
            Tuple of (AttackResponse, error_message)
            error_message is None on success
        """
        await self._apply_rate_limit()
        
        if not self._session:
            await self.start()
        
        # Ensure headers is a dict
        if headers is None:
            headers = {}
        
        # Merge with auth headers
        final_headers = self._merge_headers({}, headers, include_auth)
        
        # Generate attack ID
        attack_id = self._generate_attack_id(scanner_name, url, payload)
        
        # Record attack request
        attack_request = AttackRequest(
            id=attack_id,
            original_request_id=original_request_id,
            scanner_name=scanner_name,
            attack_type=attack_type,
            url=url,
            method=method.upper(),
            headers=final_headers,
            body=body or "",
            payload=payload,
            payload_location=payload_location,
            parameter_name=parameter_name
        )
        self._attack_requests[attack_id] = attack_request
        
        # Attempt request with retries
        last_error = None
        for attempt in range(self.retry_count + 1):
            try:
                start_time = time.time()
                
                # Build request kwargs
                kwargs = {
                    'method': method.upper(),
                    'url': url,
                    'headers': final_headers,
                    'allow_redirects': follow_redirects,
                    'ssl': self._ssl_context
                }
                
                # Add body for methods that support it
                if body and method.upper() in ['POST', 'PUT', 'PATCH', 'DELETE']:
                    kwargs['data'] = body
                
                # Route through MITM proxy if enabled
                if self.use_proxy and self.proxy_url:
                    kwargs['proxy'] = self.proxy_url
                
                # Add cookies
                if self._auth_cookies and include_auth:
                    kwargs['cookies'] = self._auth_cookies
                
                async with self._session.request(**kwargs) as response:
                    response_time_ms = (time.time() - start_time) * 1000
                    
                    # Read response body
                    try:
                        response_body = await response.text()
                    except:
                        response_body = ""
                    
                    # Create attack response with request details for Burp-style evidence
                    attack_response = AttackResponse(
                        attack_request_id=attack_id,
                        status_code=response.status,
                        headers=dict(response.headers),
                        body=response_body,
                        response_time_ms=response_time_ms,
                        # Include the actual request sent for PoC evidence
                        request_url=url,
                        request_body=body or "",
                        request_method=method.upper()
                    )
                    self._attack_responses[attack_id] = attack_response
                    
                    # Update stats
                    self.stats['requests_sent'] += 1
                    self.stats['total_response_time_ms'] += response_time_ms
                    
                    # Check for auth expiry
                    if response.status in [401, 403] and self._token_refresh_callback:
                        logger.warning(f"Got {response.status} - may need token refresh")
                    
                    logger.debug(
                        f"[{scanner_name}] {method} {url[:60]}... -> {response.status} "
                        f"({response_time_ms:.0f}ms)"
                    )
                    
                    return attack_response, None
            
            except aiohttp.ClientProxyConnectionError as e:
                last_error = f"Proxy connection failed: {e}"
                logger.warning(f"Proxy error (attempt {attempt + 1}): {e}")
                
            except aiohttp.ClientConnectorError as e:
                last_error = f"Connection failed: {e}"
                logger.warning(f"Connection error (attempt {attempt + 1}): {e}")
                
            except aiohttp.ClientTimeout as e:
                last_error = f"Request timeout: {e}"
                logger.warning(f"Timeout (attempt {attempt + 1}): {e}")
                
            except Exception as e:
                last_error = f"Request error: {e}"
                logger.error(f"Unexpected error (attempt {attempt + 1}): {e}")
            
            # Wait before retry
            if attempt < self.retry_count:
                await asyncio.sleep(1 * (attempt + 1))
        
        # All retries failed
        self.stats['requests_failed'] += 1
        self.stats['errors'].append(last_error)
        
        return None, last_error
    
    async def send_modified_request(
        self,
        original_url: str,
        original_method: str,
        original_headers: Dict[str, str],
        original_body: str = "",
        modified_headers: Optional[Dict[str, str]] = None,
        modified_body: Optional[str] = None,
        modified_url: Optional[str] = None,
        scanner_name: str = "unknown",
        attack_type: str = "unknown",
        payload: str = "",
        parameter_name: str = ""
    ) -> Tuple[Optional[AttackResponse], Optional[str]]:
        """
        Send a modified version of an original request.
        
        This is a convenience method that takes an original request
        and applies modifications before sending through MITM.
        
        Args:
            original_*: Original request details from RequestStore
            modified_*: Modifications to apply (None = keep original)
            scanner_name: Calling scanner name
            attack_type: Type of attack
            payload: Injected payload
            parameter_name: Modified parameter
            
        Returns:
            Tuple of (AttackResponse, error_message)
        """
        # Determine final values
        url = modified_url if modified_url is not None else original_url
        method = original_method
        headers = self._merge_headers(original_headers, modified_headers)
        body = modified_body if modified_body is not None else original_body
        
        # Detect payload location
        payload_location = "unknown"
        if modified_url and payload in modified_url:
            payload_location = "url"
        elif modified_body and payload in (modified_body or ""):
            payload_location = "body"
        elif modified_headers:
            for h, v in modified_headers.items():
                if payload in str(v):
                    payload_location = f"header:{h}"
                    break
        
        return await self.send_attack(
            url=url,
            method=method,
            headers=headers,
            body=body,
            scanner_name=scanner_name,
            attack_type=attack_type,
            payload=payload,
            payload_location=payload_location,
            parameter_name=parameter_name
        )
    
    async def send_batch(
        self,
        requests: List[Dict[str, Any]],
        concurrency: int = 10,
        scanner_name: str = "unknown"
    ) -> List[Tuple[Optional[AttackResponse], Optional[str]]]:
        """
        Send multiple attack requests concurrently.
        
        Args:
            requests: List of request dicts with url, method, headers, body, payload, etc.
            concurrency: Max concurrent requests
            scanner_name: Calling scanner name
            
        Returns:
            List of (AttackResponse, error) tuples in same order as input
        """
        semaphore = asyncio.Semaphore(concurrency)
        
        async def send_one(req: Dict[str, Any]) -> Tuple[Optional[AttackResponse], Optional[str]]:
            async with semaphore:
                return await self.send_attack(
                    url=req.get('url', ''),
                    method=req.get('method', 'GET'),
                    headers=req.get('headers'),
                    body=req.get('body'),
                    scanner_name=scanner_name,
                    attack_type=req.get('attack_type', 'batch'),
                    payload=req.get('payload', ''),
                    parameter_name=req.get('parameter_name', '')
                )
        
        tasks = [send_one(r) for r in requests]
        return await asyncio.gather(*tasks)
    
    def get_attack_requests(self) -> Dict[str, AttackRequest]:
        """Get all recorded attack requests"""
        return self._attack_requests
    
    def get_attack_responses(self) -> Dict[str, AttackResponse]:
        """Get all recorded attack responses"""
        return self._attack_responses
    
    def clear_attack_history(self):
        """Clear recorded attack requests/responses"""
        self._attack_requests.clear()
        self._attack_responses.clear()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        stats = dict(self.stats)
        if stats['requests_sent'] > 0:
            stats['avg_response_time_ms'] = stats['total_response_time_ms'] / stats['requests_sent']
        else:
            stats['avg_response_time_ms'] = 0
        return stats


# Singleton instance for shared use
_client_instance: Optional[JarwisHTTPClient] = None


def get_http_client(
    proxy_host: str = "127.0.0.1",
    proxy_port: int = None,  # None = use default from JarwisHTTPClient
    use_proxy: bool = True
) -> JarwisHTTPClient:
    """Get or create the singleton HTTP client instance"""
    global _client_instance
    if _client_instance is None:
        _client_instance = JarwisHTTPClient(
            proxy_host=proxy_host,
            proxy_port=proxy_port,
            use_proxy=use_proxy
        )
    return _client_instance


async def reset_http_client():
    """Reset the singleton HTTP client"""
    global _client_instance
    if _client_instance:
        await _client_instance.stop()
        _client_instance = None
