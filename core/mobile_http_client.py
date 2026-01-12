"""
Jarwis AGI Pen Test - Mobile HTTP Client (MITM-routed)

HTTP client for mobile security scanning that routes all attack traffic
through MITM proxy - exactly like how Burp Suite works for mobile pentesting.

Flow:
1. Frida captures mobile app API call
2. Request stored in MobileRequestStoreDB
3. Scanner reads request, modifies payload
4. MobileHTTPClient.send_attack() routes through MITM
5. MITM captures attack request/response
6. Response returned to scanner for vulnerability analysis

This ensures all mobile attack traffic is captured for PoC documentation.

Usage:
    client = MobileHTTPClient(
        proxy_host="127.0.0.1",
        proxy_port=8082,
        request_store=mobile_request_store
    )
    await client.start()
    
    # Inject auth token from Frida capture
    client.set_auth_from_frida(token_type="bearer", token_value="xxx")
    
    # Send attack
    response = await client.send_attack(
        original_request=captured_request,
        payload="' OR 1=1--",
        payload_location="body",
        parameter_name="username"
    )
    
    await client.stop()
"""

import asyncio
import aiohttp
import ssl
import logging
import hashlib
import time
import json
import re
from typing import Dict, List, Optional, Any, Tuple, Callable, Union
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, quote

from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


@dataclass
class MobileAttackRequest:
    """Attack request for mobile security testing"""
    id: str
    original_request_id: str
    scanner_name: str
    attack_type: str
    
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    
    # Payload tracking
    payload: str = ""
    payload_location: str = ""    # query, body, header, path, cookie
    parameter_name: str = ""
    original_value: str = ""
    
    # Mobile context
    app_package: str = ""
    platform: str = "android"
    
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


@dataclass 
class MobileAttackResponse:
    """Response from mobile attack request"""
    attack_request_id: str
    
    status_code: int
    headers: Dict[str, str]
    body: str = ""
    
    # Timing for blind injection detection
    response_time_ms: float = 0
    
    # Analysis
    body_length: int = 0
    content_type: str = ""
    is_json: bool = False
    is_error: bool = False
    
    timestamp: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        self.body_length = len(self.body)
        ct = self.headers.get('Content-Type', self.headers.get('content-type', ''))
        self.content_type = ct
        self.is_json = 'json' in ct.lower()
    
    def json(self) -> Optional[dict]:
        """Parse body as JSON"""
        if self.is_json and self.body:
            try:
                return json.loads(self.body)
            except:
                return None
        return None


class MobileHTTPClient:
    """
    MITM-routed HTTP client for mobile security testing.
    
    This is the mobile equivalent of JarwisHTTPClient.
    All attack traffic goes through the MITM proxy for capture.
    
    Features:
    - Routes all requests through MITM proxy
    - Integrates with MobileRequestStoreDB for persistence
    - Auto-injects auth tokens from Frida captures
    - Handles mobile-specific headers (User-Agent, device IDs)
    - Rate limiting for API protection
    - Retry logic with exponential backoff
    - Time-based attack support with precise timing
    """
    
    # Common mobile User-Agents
    MOBILE_USER_AGENTS = {
        'android': 'Dalvik/2.1.0 (Linux; U; Android 13; Pixel 6 Build/TP1A.221005.002)',
        'ios': 'Mobile/15E148 (iPhone; iOS 16.0; Scale/3.0)',
        'android_chrome': 'Mozilla/5.0 (Linux; Android 13; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
        'ios_safari': 'Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1'
    }
    
    def __init__(
        self,
        proxy_host: str = "127.0.0.1",
        proxy_port: int = 8082,
        use_proxy: bool = True,
        timeout: int = 30,
        max_connections: int = 30,
        rate_limit: float = 0,       # Requests per second, 0 = unlimited
        retry_count: int = 2,
        verify_ssl: bool = False,
        request_store: Optional[MobileRequestStoreDB] = None,
        platform: str = "android"
    ):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.use_proxy = use_proxy
        self.proxy_url = f"http://{proxy_host}:{proxy_port}" if use_proxy else None
        
        self.timeout = timeout
        self.max_connections = max_connections
        self.rate_limit = rate_limit
        self.retry_count = retry_count
        self.verify_ssl = verify_ssl
        self.request_store = request_store
        self.platform = platform
        
        # Session
        self._session: Optional[aiohttp.ClientSession] = None
        self._connector: Optional[aiohttp.TCPConnector] = None
        
        # SSL context (bypass cert verification for mobile testing)
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        
        # Rate limiting
        self._last_request_time: float = 0
        self._request_lock = asyncio.Lock()
        
        # Auth management (populated from Frida captures)
        self._auth_headers: Dict[str, str] = {}
        self._auth_cookies: Dict[str, str] = {}
        self._bearer_token: str = ""
        self._api_keys: Dict[str, str] = {}  # header_name -> value
        
        # Mobile-specific headers
        self._device_headers: Dict[str, str] = {}
        
        # Stats
        self.stats = {
            'requests_sent': 0,
            'requests_failed': 0,
            'total_response_time_ms': 0,
            'vulnerabilities_found': 0
        }
        
        logger.info(f"MobileHTTPClient initialized - Proxy: {'enabled' if use_proxy else 'disabled'} at {self.proxy_url}")
    
    async def start(self):
        """Initialize HTTP session"""
        if self._session is not None:
            return
        
        self._connector = aiohttp.TCPConnector(
            ssl=self._ssl_context,
            limit=self.max_connections,
            limit_per_host=10,
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
            trust_env=True
        )
        
        logger.info("MobileHTTPClient session started")
    
    async def stop(self):
        """Close HTTP session"""
        if self._session:
            await self._session.close()
            self._session = None
        if self._connector:
            await self._connector.close()
            self._connector = None
        
        logger.info(f"MobileHTTPClient stopped. Stats: {self.stats}")
    
    # ==================== Auth Management ====================
    
    def set_auth_from_frida(
        self,
        token_type: str,
        token_value: str,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer"
    ):
        """
        Set auth token captured from Frida hooks.
        
        Called when Frida intercepts an authenticated request.
        """
        if token_type in ['bearer', 'jwt']:
            self._bearer_token = token_value
            self._auth_headers[header_name] = f"{header_prefix} {token_value}"
        elif token_type == 'api_key':
            self._api_keys[header_name] = token_value
            self._auth_headers[header_name] = token_value
        elif token_type == 'basic':
            self._auth_headers[header_name] = f"Basic {token_value}"
        else:
            # Custom token type
            self._auth_headers[header_name] = token_value
        
        logger.info(f"Auth set from Frida: {token_type} in {header_name}")
    
    def set_auth_cookies(self, cookies: Dict[str, str]):
        """Set auth cookies (session, CSRF, etc.)"""
        self._auth_cookies.update(cookies)
        logger.debug(f"Auth cookies set: {list(cookies.keys())}")
    
    def set_device_headers(self, headers: Dict[str, str]):
        """
        Set device-specific headers for realistic mobile traffic.
        
        Common headers: X-Device-ID, X-App-Version, X-Platform, etc.
        """
        self._device_headers.update(headers)
    
    async def refresh_auth_from_store(self):
        """Refresh auth token from MobileRequestStoreDB"""
        if not self.request_store:
            return
        
        token_data = await self.request_store.get_latest_auth_token('bearer')
        if token_data:
            self.set_auth_from_frida(
                token_type='bearer',
                token_value=token_data['token_value'],
                header_name=token_data['header_name'],
                header_prefix=token_data['header_prefix']
            )
    
    def clear_auth(self):
        """Clear all auth state"""
        self._auth_headers.clear()
        self._auth_cookies.clear()
        self._bearer_token = ""
        self._api_keys.clear()
    
    # ==================== Request Building ====================
    
    def _generate_attack_id(self, scanner_name: str, url: str, payload: str) -> str:
        """Generate unique attack request ID"""
        content = f"{scanner_name}:{url}:{payload}:{time.time()}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _build_headers(
        self,
        original_headers: Dict[str, str],
        modified_headers: Optional[Dict[str, str]] = None,
        include_auth: bool = True,
        include_device: bool = True
    ) -> Dict[str, str]:
        """
        Build final headers for attack request.
        
        Order (later wins): original -> device -> auth -> modified
        """
        headers = dict(original_headers)
        
        # Add mobile User-Agent if not present
        if 'User-Agent' not in headers and 'user-agent' not in headers:
            headers['User-Agent'] = self.MOBILE_USER_AGENTS.get(
                self.platform, self.MOBILE_USER_AGENTS['android']
            )
        
        if include_device:
            headers.update(self._device_headers)
        
        if include_auth:
            headers.update(self._auth_headers)
        
        if modified_headers:
            headers.update(modified_headers)
        
        return headers
    
    def _inject_payload_query(
        self,
        url: str,
        param_name: str,
        payload: str
    ) -> Tuple[str, str]:
        """Inject payload into URL query parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        original_value = params.get(param_name, [''])[0]
        if isinstance(original_value, list):
            original_value = original_value[0] if original_value else ''
        
        params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        
        return new_url, original_value
    
    def _inject_payload_body_json(
        self,
        body: str,
        param_name: str,
        payload: str
    ) -> Tuple[str, str]:
        """Inject payload into JSON body parameter"""
        try:
            data = json.loads(body)
            original_value = str(data.get(param_name, ''))
            
            # Handle nested keys (e.g., "user.name")
            if '.' in param_name:
                keys = param_name.split('.')
                obj = data
                for key in keys[:-1]:
                    obj = obj.get(key, {})
                original_value = str(obj.get(keys[-1], ''))
                obj[keys[-1]] = payload
            else:
                data[param_name] = payload
            
            return json.dumps(data), original_value
        except:
            return body, ""
    
    def _inject_payload_body_form(
        self,
        body: str,
        param_name: str,
        payload: str
    ) -> Tuple[str, str]:
        """Inject payload into form-urlencoded body"""
        params = parse_qs(body, keep_blank_values=True)
        original_value = params.get(param_name, [''])[0]
        if isinstance(original_value, list):
            original_value = original_value[0] if original_value else ''
        
        params[param_name] = [payload]
        return urlencode(params, doseq=True), original_value
    
    async def _apply_rate_limit(self):
        """Apply rate limiting"""
        if self.rate_limit <= 0:
            return
        
        async with self._request_lock:
            now = time.time()
            min_interval = 1.0 / self.rate_limit
            elapsed = now - self._last_request_time
            
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            
            self._last_request_time = time.time()
    
    # ==================== Attack Request Sending ====================
    
    async def send_attack(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        scanner_name: str = "mobile_scanner",
        attack_type: str = "unknown",
        original_request_id: str = "",
        payload: str = "",
        payload_location: str = "",
        parameter_name: str = "",
        include_auth: bool = True,
        follow_redirects: bool = True,
        store_in_db: bool = True
    ) -> Tuple[Optional[MobileAttackResponse], Optional[str]]:
        """
        Send attack request through MITM proxy.
        
        Args:
            url: Target URL
            method: HTTP method
            headers: Request headers
            body: Request body
            scanner_name: Scanner name for tracking
            attack_type: Attack type (sqli, xss, etc.)
            original_request_id: Source request ID
            payload: Injected payload
            payload_location: Where payload was injected
            parameter_name: Target parameter
            include_auth: Include auth headers
            follow_redirects: Follow HTTP redirects
            store_in_db: Store attack in request store
            
        Returns:
            Tuple of (MobileAttackResponse, error_message)
        """
        await self._apply_rate_limit()
        
        if not self._session:
            await self.start()
        
        # Build headers
        final_headers = self._build_headers(
            headers or {},
            include_auth=include_auth
        )
        
        # Generate attack ID
        attack_id = self._generate_attack_id(scanner_name, url, payload)
        
        # Store attack request in DB
        if store_in_db and self.request_store:
            await self.request_store.add_attack_request(
                original_request_id=original_request_id,
                scanner_name=scanner_name,
                attack_type=attack_type,
                url=url,
                method=method,
                headers=final_headers,
                body=body or "",
                payload=payload,
                payload_location=payload_location,
                parameter_name=parameter_name
            )
        
        # Send with retries
        last_error = None
        for attempt in range(self.retry_count + 1):
            try:
                start_time = time.time()
                
                # Build request kwargs
                kwargs: Dict[str, Any] = {
                    'method': method.upper(),
                    'url': url,
                    'headers': final_headers,
                    'allow_redirects': follow_redirects,
                    'ssl': self._ssl_context
                }
                
                # Add proxy
                if self.use_proxy:
                    kwargs['proxy'] = self.proxy_url
                
                # Add body
                if body and method.upper() in ['POST', 'PUT', 'PATCH']:
                    content_type = final_headers.get('Content-Type', 
                                                     final_headers.get('content-type', ''))
                    if 'json' in content_type.lower():
                        kwargs['data'] = body
                    else:
                        kwargs['data'] = body
                
                # Add cookies
                if self._auth_cookies:
                    kwargs['cookies'] = self._auth_cookies
                
                # Send request
                async with self._session.request(**kwargs) as response:
                    response_time_ms = (time.time() - start_time) * 1000
                    
                    # Read response
                    try:
                        response_body = await response.text()
                    except:
                        response_body = ""
                    
                    response_headers = dict(response.headers)
                    
                    # Create response object
                    attack_response = MobileAttackResponse(
                        attack_request_id=attack_id,
                        status_code=response.status,
                        headers=response_headers,
                        body=response_body,
                        response_time_ms=response_time_ms,
                        is_error=response.status >= 400
                    )
                    
                    # Store in DB
                    if store_in_db and self.request_store:
                        await self.request_store.add_attack_response(
                            attack_request_id=attack_id,
                            status_code=response.status,
                            headers=response_headers,
                            body=response_body[:50000],
                            response_time_ms=response_time_ms
                        )
                    
                    # Update stats
                    self.stats['requests_sent'] += 1
                    self.stats['total_response_time_ms'] += response_time_ms
                    
                    return attack_response, None
                    
            except asyncio.TimeoutError:
                last_error = f"Timeout after {self.timeout}s"
                logger.warning(f"Timeout on attempt {attempt + 1}: {url}")
            except aiohttp.ClientProxyConnectionError as e:
                last_error = f"Proxy connection failed: {e}"
                logger.error(f"Proxy error: {e}")
                break  # Don't retry proxy errors
            except aiohttp.ClientError as e:
                last_error = f"HTTP error: {e}"
                logger.warning(f"HTTP error on attempt {attempt + 1}: {e}")
            except Exception as e:
                last_error = f"Unexpected error: {e}"
                logger.error(f"Unexpected error: {e}")
            
            # Exponential backoff
            if attempt < self.retry_count:
                await asyncio.sleep(0.5 * (2 ** attempt))
        
        self.stats['requests_failed'] += 1
        return None, last_error
    
    async def send_attack_from_request(
        self,
        request: StoredMobileRequest,
        payload: str,
        payload_location: str,
        parameter_name: str,
        scanner_name: str = "mobile_scanner",
        attack_type: str = "unknown"
    ) -> Tuple[Optional[MobileAttackResponse], Optional[str]]:
        """
        Send attack by modifying a stored request.
        
        This is the main method for scanners - takes original request,
        injects payload, and sends through MITM.
        
        Args:
            request: Original captured request
            payload: Payload to inject
            payload_location: Where to inject (query, body, header)
            parameter_name: Parameter to modify
            scanner_name: Scanner name
            attack_type: Attack type
            
        Returns:
            Tuple of (MobileAttackResponse, error_message)
        """
        url = request.url
        method = request.method
        headers = dict(request.headers)
        body = request.body
        original_value = ""
        
        # Inject payload based on location
        if payload_location == 'query':
            url, original_value = self._inject_payload_query(url, parameter_name, payload)
        
        elif payload_location == 'body':
            content_type = headers.get('Content-Type', headers.get('content-type', ''))
            if 'json' in content_type.lower():
                body, original_value = self._inject_payload_body_json(body, parameter_name, payload)
            elif 'form' in content_type.lower():
                body, original_value = self._inject_payload_body_form(body, parameter_name, payload)
            else:
                # Try JSON first, then form
                body, original_value = self._inject_payload_body_json(body, parameter_name, payload)
                if not original_value:
                    body, original_value = self._inject_payload_body_form(body, parameter_name, payload)
        
        elif payload_location == 'header':
            original_value = headers.get(parameter_name, '')
            headers[parameter_name] = payload
        
        elif payload_location == 'cookie':
            cookies = request.cookies
            original_value = cookies.get(parameter_name, '')
            cookies[parameter_name] = payload
            # Convert cookies to header
            cookie_str = '; '.join(f"{k}={v}" for k, v in cookies.items())
            headers['Cookie'] = cookie_str
        
        return await self.send_attack(
            url=url,
            method=method,
            headers=headers,
            body=body,
            scanner_name=scanner_name,
            attack_type=attack_type,
            original_request_id=request.id,
            payload=payload,
            payload_location=payload_location,
            parameter_name=parameter_name
        )
    
    async def send_baseline(
        self,
        request: StoredMobileRequest,
        include_auth: bool = True
    ) -> Tuple[Optional[MobileAttackResponse], Optional[str]]:
        """
        Send original request unmodified to get baseline response.
        
        Used for comparison-based detection (response length, content, timing).
        """
        return await self.send_attack(
            url=request.url,
            method=request.method,
            headers=request.headers,
            body=request.body,
            scanner_name="baseline",
            attack_type="baseline",
            original_request_id=request.id,
            include_auth=include_auth,
            store_in_db=False  # Don't store baseline requests
        )
    
    # ==================== Utility Methods ====================
    
    async def health_check(self) -> bool:
        """Check if MITM proxy is reachable"""
        if not self.use_proxy:
            return True
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://{self.proxy_host}:{self.proxy_port}",
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    return True
        except:
            return False
    
    def get_stats(self) -> Dict[str, Any]:
        """Get client statistics"""
        avg_time = 0
        if self.stats['requests_sent'] > 0:
            avg_time = self.stats['total_response_time_ms'] / self.stats['requests_sent']
        
        return {
            **self.stats,
            'avg_response_time_ms': round(avg_time, 2),
            'success_rate': round(
                self.stats['requests_sent'] / 
                max(self.stats['requests_sent'] + self.stats['requests_failed'], 1) * 100, 2
            )
        }
    
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.stop()
