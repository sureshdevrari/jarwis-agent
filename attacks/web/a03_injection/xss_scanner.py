"""
JARWIS AGI PEN TEST - XSS Scanner
Cross-Site Scripting vulnerability detection
Uses OWASP Detection Logic for evidence-based detection
Supports JavaScript rendering for DOM-based XSS detection
"""

import asyncio
import logging
import re
import html
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse
import aiohttp

# Import detection engine
try:
    from core.detection_logic import OWASPDetectionEngine, detection_engine
except ImportError:
    try:
        from ...core.detection_logic import OWASPDetectionEngine, detection_engine
    except ImportError:
        detection_engine = None

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
    poc: str = ""  # Proof of Concept payload
    reasoning: str = ""  # Why this is detected as vulnerability
    request_data: str = ""  # Full request details (Burp-style)
    response_data: str = ""  # Full response details (Burp-style)


class XSSScanner:
    """Scans for Cross-Site Scripting vulnerabilities (A07:2017)
    
    Enhanced with JavaScript rendering support for detecting:
    - Reflected XSS (traditional HTTP-based)
    - DOM XSS (JavaScript-executed, browser-rendered)
    - Stored XSS (requires authenticated context)
    """
    
    # XSS Payloads - reflected detection
    XSS_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "'-alert('XSS')-'",
        '<img src=x onerror=alert("XSS")>',
        '"><img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><svg/onload=alert("XSS")>',
        "javascript:alert('XSS')",
        '<body onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '{{constructor.constructor("alert(1)")()}}',  # Template injection
        '${alert(1)}',  # Template literal
    ]
    
    # DOM-based XSS payloads (for browser execution)
    DOM_XSS_PAYLOADS = [
        '<img src=x onerror=alert("JARWIS_XSS")>',
        '<svg/onload=alert("JARWIS_XSS")>',
        '"><script>alert("JARWIS_XSS")</script>',
        "'-alert('JARWIS_XSS')-'",
    ]
    
    # Unique markers for detection
    XSS_MARKERS = [
        'JARWIS_XSS_TEST_12345',
        '<jarwis>test</jarwis>',
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Will be set by PreLoginAttacks if available
        self.use_js_rendering = config.get('js_rendering', True)  # Enable by default
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers from context for post-login attacks"""
        if hasattr(self.context, 'auth_headers') and self.context.auth_headers:
            return dict(self.context.auth_headers)
        return {}
    
    def _get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies from context for post-login attacks"""
        if hasattr(self.context, 'auth_cookies') and self.context.auth_cookies:
            return dict(self.context.auth_cookies)
        if hasattr(self.context, 'cookies') and self.context.cookies:
            return dict(self.context.cookies)
        return {}
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for scope checking"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
    def _is_in_scope(self, url: str) -> bool:
        """
        Check if URL is within target scope (STRICT domain matching).
        
        Subdomains are NOT included - each subdomain counts as a separate
        subscription token. Only the exact domain entered is in scope.
        www.example.com and example.com are treated as the same domain.
        """
        if not url or not self._target_domain:
            return False
        try:
            from core.scope import ScopeManager
            return ScopeManager(self.context.target_url).is_in_scope(url)
        except ImportError:
            # Fallback to strict matching
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            target_domain = self._target_domain
            # Strip www. prefix for both
            if url_domain.startswith('www.'):
                url_domain = url_domain[4:]
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
            return url_domain == target_domain
    
    def _format_request(self, method: str, url: str, headers: Dict, body: str = "") -> str:
        """Format request like Burp Suite"""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        
        lines = [f"{method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if body:
            lines.append(body)
        return "\n".join(lines)
    
    def _format_response(self, status: int, headers: Dict, body: str) -> str:
        """Format response like Burp Suite"""
        lines = [f"HTTP/1.1 {status}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        # Truncate body if too long
        if len(body) > 1500:
            body = body[:1500] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    async def scan(self) -> List[ScanResult]:
        """Run XSS scans on all endpoints"""
        self.findings = []
        
        # Filter endpoints with parameters or forms
        testable_endpoints = [
            ep for ep in self.context.endpoints
            if ep.get('params') or ep.get('type') == 'form' or '?' in ep.get('url', '')
        ]
        
        js_mode = "enabled" if (self.browser and self.use_js_rendering) else "disabled"
        logger.info(f"Testing {len(testable_endpoints)} endpoints for XSS (JS rendering: {js_mode})")
        
        # Get auth configuration for post-login attacks
        auth_headers = self._get_auth_headers()
        auth_cookies = self._get_auth_cookies()
        
        session_kwargs = {}
        if auth_cookies:
            session_kwargs['cookies'] = auth_cookies
            logger.info(f"[XSS] Using {len(auth_cookies)} auth cookies for authenticated testing")
        if auth_headers:
            session_kwargs['headers'] = auth_headers
            logger.info(f"[XSS] Using {len(auth_headers)} auth headers for authenticated testing")
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            for endpoint in testable_endpoints:
                await self._test_endpoint(session, endpoint)
                await asyncio.sleep(1 / self.rate_limit)
        
        # If browser is available, run DOM XSS checks with actual JavaScript execution
        if self.browser and self.use_js_rendering:
            logger.info("Running browser-based DOM XSS detection...")
            await self._test_dom_xss_with_browser(testable_endpoints)
        
        return self.findings
    
    async def _test_dom_xss_with_browser(self, endpoints: List[Dict]):
        """Test for DOM-based XSS using actual browser JavaScript execution"""
        if not self.browser or not self.browser.page:
            logger.debug("Browser not available for DOM XSS testing")
            return
        
        for endpoint in endpoints:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            # Extract URL parameters if not in params dict
            if '?' in url and not params:
                query = url.split('?', 1)[1]
                for p in query.split('&'):
                    if '=' in p:
                        key, _ = p.split('=', 1)
                        params[key] = 'text'
            
            for param_name in params:
                for payload in self.DOM_XSS_PAYLOADS:
                    try:
                        result = await self.browser.check_xss_in_dom(url, payload, param_name)
                        
                        if result.get('vulnerable'):
                            self._add_finding(
                                category="A07",
                                severity="critical",  # DOM XSS with confirmed execution is critical
                                title=f"Confirmed DOM XSS in {param_name}",
                                description=f"JavaScript execution confirmed in browser. The XSS payload triggered an alert dialog, proving client-side code execution.",
                                url=url,
                                method="GET",
                                parameter=param_name,
                                evidence=f"Browser Alert Triggered: {result.get('dialog_message', 'XSS')}\nPayload: {payload}",
                                remediation="Sanitize all user input before inserting into DOM. Use textContent instead of innerHTML. Implement Content-Security-Policy with script-src restrictions.",
                                cwe_id="CWE-79",
                                poc=f"Payload: {payload}\n\nTo reproduce:\n1. Navigate to {url}\n2. Inject payload into parameter '{param_name}'\n3. Browser will execute JavaScript and show alert dialog",
                                reasoning=f"CONFIRMED EXECUTION: Jarwis injected the XSS payload and the browser's JavaScript engine executed it, triggering an alert dialog. This proves the vulnerability is exploitable and can be used to steal cookies, hijack sessions, or perform actions as the victim user.",
                                request_data=f"URL with payload: {result.get('test_url', url)}",
                                response_data=result.get('page_content', '')[:1000] if result.get('page_content') else ''
                            )
                            break  # One confirmed DOM XSS per parameter is enough
                            
                    except Exception as e:
                        logger.debug(f"DOM XSS browser test failed for {param_name}: {e}")
                
                await asyncio.sleep(0.5)  # Rate limit browser tests
    
    async def _test_endpoint(self, session: aiohttp.ClientSession, endpoint: Dict):
        """Test a single endpoint for XSS"""
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        params = endpoint.get('params', {})
        
        # Extract URL parameters if not in params dict
        if '?' in url and not params:
            query = url.split('?', 1)[1]
            for p in query.split('&'):
                if '=' in p:
                    key, _ = p.split('=', 1)
                    params[key] = 'text'
        
        for param_name in params:
            await self._test_reflected_xss(session, url, method, param_name)
            await self._test_dom_xss(session, url, method, param_name)
    
    async def _test_reflected_xss(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ):
        """Test for reflected XSS"""
        # First test with markers to check reflection
        for marker in self.XSS_MARKERS:
            try:
                test_url, test_data = self._inject_payload(url, method, param, marker)
                
                async with session.request(
                    method,
                    test_url,
                    data=test_data if method == 'POST' else None,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    if marker in body:
                        # Marker reflected - now test actual payloads
                        await self._test_xss_payloads(session, url, method, param)
                        return
                        
            except Exception as e:
                logger.debug(f"XSS marker test failed: {e}")
    
    async def _test_xss_payloads(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ):
        """Test actual XSS payloads with proper verification"""
        for i, payload in enumerate(self.XSS_PAYLOADS[:6]):
            # VERBOSE LOGGING: Show each payload being tested
            logger.info(f"[XSS] Testing payload {i+1}/6 on {param}: {payload[:50]}{'...' if len(payload) > 50 else ''}")
            
            try:
                test_url, test_data = self._inject_payload(url, method, param, payload)
                request_body = f"{param}={payload}" if test_data else ""
                
                async with session.request(
                    method,
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    data=test_data if method == 'POST' else None,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    resp_headers = dict(response.headers)
                    status = response.status
                    
                    # Check if payload is reflected without encoding
                    if payload in body:
                        # Verify it's in an executable context
                        if self._is_executable_context(body, payload):
                            # Format request/response like Burp Suite
                            request_str = self._format_request(method, test_url, self.DEFAULT_HEADERS, request_body)
                            response_str = self._format_response(status, resp_headers, body)
                            
                            self._add_finding(
                                category="A07",
                                severity="high" if '<script' in payload else "medium",
                                title=f"Reflected XSS in {param}",
                                description=f"Cross-site scripting payload reflected in response without proper encoding. The payload appears in an executable HTML context.",
                                url=url,
                                method=method,
                                parameter=param,
                                evidence=f"Payload: {payload}\nContext: Executable HTML context (script tag, event handler, or HTML attribute)",
                                remediation="Encode all user input before rendering. Use Content-Security-Policy headers. Apply context-aware output encoding (HTML, JavaScript, URL, CSS).",
                                cwe_id="CWE-79",
                                poc=f"Payload: {payload}\n\nTo reproduce:\n1. Navigate to {url}\n2. Inject payload into parameter '{param}'\n3. Observe unencoded reflection in HTML response",
                                reasoning=f"VERIFIED: Jarwis injected the XSS payload '{payload[:50]}' into the '{param}' parameter and confirmed it was reflected in an executable context. The payload was NOT HTML-encoded, meaning browsers will execute the JavaScript code. This enables session hijacking, credential theft, and malicious actions on behalf of victims.",
                                request_data=request_str,
                                response_data=response_str
                            )
                            return
                    
                    # Check for partial reflection (encoded)
                    encoded_payload = html.escape(payload)
                    if encoded_payload in body and payload not in body:
                        logger.info(f"[XSS] Payload HTML-encoded (safe) at {url} param {param}")
                    elif payload not in body:
                        logger.debug(f"[XSS] Payload not reflected at {url} param {param}")
                        
            except Exception as e:
                logger.debug(f"XSS payload test failed: {e}")
    
    async def _test_dom_xss(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ):
        """Test for DOM-based XSS patterns"""
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                body = await response.text()
                
                # DOM XSS sink patterns
                dom_sinks = [
                    r'document\.write\s*\([^)]*location',
                    r'innerHTML\s*=\s*[^;]*location',
                    r'outerHTML\s*=\s*[^;]*location',
                    r'eval\s*\([^)]*location',
                    r'\.html\s*\([^)]*location',  # jQuery
                    r'document\.location\s*=',
                    r'window\.location\s*=',
                ]
                
                for pattern in dom_sinks:
                    if re.search(pattern, body, re.IGNORECASE):
                        self._add_finding(
                            category="A07",
                            severity="medium",
                            title=f"Potential DOM XSS Pattern",
                            description=f"JavaScript code contains patterns that may lead to DOM-based XSS",
                            url=url,
                            method="GET",
                            parameter=param,
                            evidence=f"Pattern: {pattern}",
                            remediation="Avoid using user input directly in DOM manipulation. Use safe APIs like textContent.",
                            cwe_id="CWE-79"
                        )
                        return
                        
        except Exception as e:
            logger.debug(f"DOM XSS check failed: {e}")
    
    def _is_executable_context(self, body: str, payload: str) -> bool:
        """Check if payload is in an executable context"""
        # Find payload position
        pos = body.find(payload)
        if pos == -1:
            return False
        
        # Get surrounding context
        start = max(0, pos - 100)
        end = min(len(body), pos + len(payload) + 100)
        context = body[start:end]
        
        # Check for script context
        if '<script' in payload and '</script>' in payload:
            return True
        
        # Check for event handler context
        if 'onerror=' in payload or 'onload=' in payload:
            # Verify we're inside a tag
            before = body[:pos]
            last_open = before.rfind('<')
            last_close = before.rfind('>')
            if last_open > last_close:
                return True
        
        # Check for href/src context
        if 'javascript:' in payload:
            return 'href=' in context or 'src=' in context
        
        return False
    
    def _inject_payload(self, url: str, method: str, param: str, payload: str) -> tuple:
        """Inject payload into the appropriate location"""
        from urllib.parse import quote
        
        encoded_payload = quote(payload, safe='')
        
        if method == 'GET':
            if '?' in url:
                base, query = url.split('?', 1)
                params = {}
                for p in query.split('&'):
                    if '=' in p:
                        k, v = p.split('=', 1)
                        params[k] = v
                params[param] = encoded_payload
                new_query = '&'.join(f"{k}={v}" for k, v in params.items())
                return f"{base}?{new_query}", None
            else:
                return f"{url}?{param}={encoded_payload}", None
        else:
            return url, {param: payload}
    
    def _add_finding(self, **kwargs):
        """Add a finding to the results (only if in scope)"""
        url = kwargs.get('url', '')
        if url and not self._is_in_scope(url):
            logger.debug(f"Skipping out-of-scope finding: {url}")
            return
        
        self._finding_id += 1
        finding = ScanResult(id=f"XSS-{self._finding_id:04d}", **kwargs)
        self.findings.append(finding)
        logger.info(f"Found: {finding.title} at {finding.url}")
