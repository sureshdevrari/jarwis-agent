"""
JARWIS AGI PEN TEST - XSS Reflected Scanner (Advanced)
Professional-grade Cross-Site Scripting detection with browser-based verification
Uses comprehensive payload database and Chromium for real XSS execution detection

Features:
- Loads payloads from external file for easy updates
- Tests all input fields discovered by crawler (forms, query params, headers)
- Browser-based XSS execution verification (alert/prompt/confirm detection)
- DOM manipulation detection
- Context-aware payload selection
- Support for encoded/obfuscated payloads
- WAF bypass techniques
- Detailed evidence collection with Burp-style request/response
"""

import asyncio
import logging
import re
import html
import os
import json
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from urllib.parse import urlparse, urlencode, parse_qs, urljoin, quote, unquote
from pathlib import Path
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
    """XSS scan finding result"""
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
    confidence: str = "high"  # high, medium, low
    context: str = ""  # html, attribute, javascript, url, etc.


@dataclass
class XSSTestResult:
    """Result of a single XSS test"""
    vulnerable: bool = False
    payload: str = ""
    reflected: bool = False
    executed: bool = False
    dialog_triggered: bool = False
    dialog_message: str = ""
    dom_modified: bool = False
    context: str = ""
    evidence: str = ""
    test_url: str = ""
    response_body: str = ""
    status_code: int = 0


class XSSReflectedScanner:
    """
    Advanced XSS Reflected Scanner with Browser-Based Verification
    
    Professional penetration testing approach:
    1. Load comprehensive payload database
    2. Discover all input vectors from crawler data
    3. Test each input with context-aware payloads
    4. Verify XSS execution using Chromium browser
    5. Collect evidence with request/response data
    """
    
    # Unique markers for detection
    JARWIS_MARKERS = [
        'JARWIS_XSS_MARKER_12345',
        'JARWIS_XSS_TEST_TAG',
        'JARWIS_REFLECTION_PROBE_67890',
    ]
    
    # Context detection patterns
    CONTEXT_PATTERNS = {
        'html_tag': re.compile(r'<[^>]*$|^[^<]*>'),
        'html_attribute': re.compile(r'=["\']?[^"\'<>]*$'),
        'javascript_string': re.compile(r'["\'][^"\']*$'),
        'javascript_template': re.compile(r'`[^`]*$'),
        'url_param': re.compile(r'[?&][^=]*=$'),
        'css_value': re.compile(r':\s*[^;]*$'),
    }
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 JARWIS-XSS-Scanner/2.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'keep-alive',
        'Cache-Control': 'no-cache',
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Set by PreLoginAttacks for browser-based verification
        self.use_browser_verification = config.get('xss_browser_verification', True)
        
        # Load payloads
        self.payloads: List[str] = []
        self.priority_payloads: List[str] = []  # Fast detection payloads
        self._load_payloads()
        
        # Track tested combinations to avoid duplicates
        self._tested_combinations: Set[str] = set()
        
        # Statistics
        self.stats = {
            'endpoints_tested': 0,
            'parameters_tested': 0,
            'payloads_sent': 0,
            'reflections_found': 0,
            'xss_confirmed': 0,
        }
    
    def _load_payloads(self):
        """Load XSS payloads from external file"""
        payload_file = Path(__file__).parent.parent.parent / 'config' / 'payloads' / 'xss_payloads.txt'
        
        try:
            if payload_file.exists():
                with open(payload_file, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        # Skip comments and empty lines
                        if line and not line.startswith('#'):
                            self.payloads.append(line)
                logger.info(f"Loaded {len(self.payloads)} XSS payloads from {payload_file}")
            else:
                logger.warning(f"Payload file not found: {payload_file}, using built-in payloads")
                self._use_builtin_payloads()
        except Exception as e:
            logger.error(f"Error loading payloads: {e}")
            self._use_builtin_payloads()
        
        # Set priority payloads for fast initial detection
        self.priority_payloads = [
            '<script>alert("JARWIS_XSS_MARKER_12345")</script>',
            '"><script>alert("JARWIS_XSS_MARKER_12345")</script>',
            '<img src=x onerror="alert(\'JARWIS_XSS_MARKER_12345\')">',
            '"><img src=x onerror=alert("JARWIS_XSS_MARKER_12345")>',
            '<svg onload="alert(\'JARWIS_XSS_MARKER_12345\')">',
            '"><svg onload=alert("JARWIS_XSS_MARKER_12345")>',
            'JARWIS_XSS_REFLECTION_PROBE_67890',  # Simple reflection test
            '<JARWIS_XSS_TEST_TAG>test</JARWIS_XSS_TEST_TAG>',
        ]
    
    def _use_builtin_payloads(self):
        """Fallback to built-in payloads"""
        self.payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><svg onload=alert(1)>',
            "'-alert(1)-'",
            '"-alert(1)-"',
            '<body onload=alert(1)>',
            '<input onfocus=alert(1) autofocus>',
            '{{constructor.constructor("alert(1)")()}}',
            '${alert(1)}',
            'javascript:alert(1)',
        ]
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for scope checking"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within target scope"""
        if not url or not self._target_domain:
            return False
        try:
            from core.scope import ScopeManager
            return ScopeManager(self.context.target_url).is_in_scope(url)
        except ImportError:
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            target = self._target_domain
            if url_domain.startswith('www.'):
                url_domain = url_domain[4:]
            if target.startswith('www.'):
                target = target[4:]
            return url_domain == target
    
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
        if body:
            lines.append(f"Content-Length: {len(body)}")
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
        if len(body) > 2000:
            body = body[:2000] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    def _get_next_finding_id(self) -> str:
        """Generate unique finding ID"""
        self._finding_id += 1
        return f"XSS-REFLECTED-{self._finding_id:04d}"
    
    async def scan(self) -> List[ScanResult]:
        """
        Run comprehensive XSS reflected scan on all discovered endpoints
        """
        self.findings = []
        logger.info("=" * 60)
        logger.info("JARWIS XSS REFLECTED SCANNER - Starting comprehensive scan")
        logger.info("=" * 60)
        
        # Collect all testable inputs from crawler data
        input_vectors = await self._collect_input_vectors()
        
        logger.info(f"Discovered {len(input_vectors)} input vectors to test")
        logger.info(f"Loaded {len(self.payloads)} XSS payloads")
        logger.info(f"Browser verification: {'ENABLED' if (self.browser and self.use_browser_verification) else 'DISABLED'}")
        
        # Phase 1: Quick reflection test with priority payloads
        logger.info("\n[Phase 1] Quick reflection detection...")
        await self._phase1_reflection_scan(input_vectors)
        
        # Phase 2: Browser-based XSS execution verification
        if self.browser and self.use_browser_verification:
            logger.info("\n[Phase 2] Browser-based XSS execution verification...")
            await self._phase2_browser_verification(input_vectors)
        
        # Phase 3: Deep scan with comprehensive payloads
        logger.info("\n[Phase 3] Deep payload testing...")
        await self._phase3_deep_scan(input_vectors)
        
        # Log statistics
        logger.info("\n" + "=" * 60)
        logger.info("XSS SCAN COMPLETE - Statistics:")
        logger.info(f"  Endpoints tested: {self.stats['endpoints_tested']}")
        logger.info(f"  Parameters tested: {self.stats['parameters_tested']}")
        logger.info(f"  Payloads sent: {self.stats['payloads_sent']}")
        logger.info(f"  Reflections found: {self.stats['reflections_found']}")
        logger.info(f"  XSS CONFIRMED: {self.stats['xss_confirmed']}")
        logger.info(f"  Total findings: {len(self.findings)}")
        logger.info("=" * 60)
        
        return self.findings
    
    async def _collect_input_vectors(self) -> List[Dict]:
        """
        Collect all input vectors from crawler data including:
        - URL query parameters
        - Form fields (including profile sections)
        - Request headers that might be reflected
        - JSON body parameters
        """
        input_vectors = []
        seen_urls = set()
        
        for endpoint in self.context.endpoints:
            url = endpoint.get('url', '')
            if not url or not self._is_in_scope(url):
                continue
            
            method = endpoint.get('method', 'GET').upper()
            params = endpoint.get('params', {})
            headers = endpoint.get('headers', {})
            post_data = endpoint.get('post_data', '')
            endpoint_type = endpoint.get('type', 'page')
            
            # Create unique key to avoid duplicates
            url_key = f"{method}:{urlparse(url).path}"
            if url_key in seen_urls:
                continue
            seen_urls.add(url_key)
            
            # Extract query parameters from URL
            parsed = urlparse(url)
            if parsed.query:
                query_params = parse_qs(parsed.query)
                for param_name in query_params:
                    input_vectors.append({
                        'url': url,
                        'method': 'GET',
                        'param_name': param_name,
                        'param_type': 'query',
                        'original_value': query_params[param_name][0] if query_params[param_name] else '',
                        'endpoint_type': endpoint_type,
                    })
            
            # Extract form parameters
            if params:
                for param_name, param_type in params.items():
                    input_vectors.append({
                        'url': url,
                        'method': method,
                        'param_name': param_name,
                        'param_type': 'form' if method == 'POST' else 'query',
                        'original_value': '',
                        'endpoint_type': endpoint_type,
                        'input_type': param_type,
                    })
            
            # Parse POST data for JSON parameters
            if post_data:
                try:
                    json_data = json.loads(post_data) if isinstance(post_data, str) else post_data
                    if isinstance(json_data, dict):
                        for key in json_data:
                            input_vectors.append({
                                'url': url,
                                'method': 'POST',
                                'param_name': key,
                                'param_type': 'json',
                                'original_value': str(json_data[key]),
                                'endpoint_type': 'api',
                            })
                except:
                    # Try form-encoded data
                    if '=' in post_data:
                        for pair in post_data.split('&'):
                            if '=' in pair:
                                key, val = pair.split('=', 1)
                                input_vectors.append({
                                    'url': url,
                                    'method': 'POST',
                                    'param_name': unquote(key),
                                    'param_type': 'form',
                                    'original_value': unquote(val),
                                    'endpoint_type': endpoint_type,
                                })
            
            # Check for header injection opportunities
            reflectable_headers = ['User-Agent', 'Referer', 'X-Forwarded-For', 'X-Custom-Header']
            for header in reflectable_headers:
                input_vectors.append({
                    'url': url,
                    'method': method,
                    'param_name': header,
                    'param_type': 'header',
                    'original_value': headers.get(header, ''),
                    'endpoint_type': endpoint_type,
                })
        
        return input_vectors
    
    async def _phase1_reflection_scan(self, input_vectors: List[Dict]):
        """
        Phase 1: Quick scan to detect reflection points
        Uses simple markers to find where input is reflected
        """
        async with aiohttp.ClientSession() as session:
            for vector in input_vectors[:100]:  # Limit for phase 1
                marker = 'JARWIS_XSS_REFLECTION_PROBE_67890'
                result = await self._test_single_injection(session, vector, marker)
                
                if result.reflected:
                    self.stats['reflections_found'] += 1
                    logger.info(f"  [!] Reflection found: {vector['param_name']} @ {vector['url']}")
                    
                    # Mark this vector as priority for phase 2
                    vector['has_reflection'] = True
                
                await asyncio.sleep(1 / self.rate_limit)
    
    async def _phase2_browser_verification(self, input_vectors: List[Dict]):
        """
        Phase 2: Use Chromium browser to verify XSS execution
        Only tests vectors that showed reflection in phase 1
        """
        if not self.browser or not self.browser.page:
            logger.warning("Browser not available for XSS verification")
            return
        
        reflective_vectors = [v for v in input_vectors if v.get('has_reflection')]
        logger.info(f"Testing {len(reflective_vectors)} reflective inputs with browser")
        
        for vector in reflective_vectors:
            for payload in self.priority_payloads[:6]:  # Use top priority payloads
                result = await self._test_xss_with_browser(vector, payload)
                
                if result.executed or result.dialog_triggered:
                    self.stats['xss_confirmed'] += 1
                    self._add_confirmed_xss_finding(vector, result)
                    break  # One confirmed XSS per parameter is enough
                
                await asyncio.sleep(0.5)
    
    async def _phase3_deep_scan(self, input_vectors: List[Dict]):
        """
        Phase 3: Deep scan with comprehensive payloads
        Tests all vectors with full payload list
        """
        # Select payloads based on config (limit to avoid too many requests)
        max_payloads = self.config.get('xss_max_payloads', 50)
        test_payloads = self.payloads[:max_payloads]
        
        async with aiohttp.ClientSession() as session:
            for vector in input_vectors:
                self.stats['endpoints_tested'] += 1
                self.stats['parameters_tested'] += 1
                
                # Skip if already confirmed vulnerable
                combo_key = f"{vector['url']}:{vector['param_name']}"
                if combo_key in self._tested_combinations:
                    continue
                
                for payload in test_payloads:
                    self.stats['payloads_sent'] += 1
                    result = await self._test_single_injection(session, vector, payload)
                    
                    if result.reflected:
                        # Check if payload appears unencoded (potential XSS)
                        if self._is_dangerous_reflection(result.response_body, payload):
                            self._add_reflection_finding(vector, result, payload)
                            self._tested_combinations.add(combo_key)
                            break
                    
                    await asyncio.sleep(1 / self.rate_limit)
    
    async def _test_single_injection(
        self, 
        session: aiohttp.ClientSession, 
        vector: Dict, 
        payload: str
    ) -> XSSTestResult:
        """
        Test a single payload injection
        """
        result = XSSTestResult(payload=payload)
        
        try:
            url = vector['url']
            method = vector['method']
            param_name = vector['param_name']
            param_type = vector['param_type']
            
            headers = dict(self.DEFAULT_HEADERS)
            data = None
            
            if param_type == 'query':
                # Inject into URL query parameter
                parsed = urlparse(url)
                params = parse_qs(parsed.query) if parsed.query else {}
                params[param_name] = [payload]
                new_query = urlencode(params, doseq=True)
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                result.test_url = test_url
                
                async with session.get(
                    test_url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    result.response_body = await response.text()
                    result.status_code = response.status
            
            elif param_type == 'form':
                # Inject into POST form data
                data = {param_name: payload}
                result.test_url = url
                
                async with session.post(
                    url,
                    headers=headers,
                    data=data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    result.response_body = await response.text()
                    result.status_code = response.status
            
            elif param_type == 'json':
                # Inject into JSON body
                headers['Content-Type'] = 'application/json'
                json_data = {param_name: payload}
                result.test_url = url
                
                async with session.post(
                    url,
                    headers=headers,
                    json=json_data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    result.response_body = await response.text()
                    result.status_code = response.status
            
            elif param_type == 'header':
                # Inject into HTTP header
                headers[param_name] = payload
                result.test_url = url
                
                async with session.get(
                    url,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    result.response_body = await response.text()
                    result.status_code = response.status
            
            # Check if payload is reflected
            if payload in result.response_body:
                result.reflected = True
                result.evidence = f"Payload reflected in response at position {result.response_body.find(payload)}"
            
            # Check for partial reflection (HTML-encoded but structure intact)
            elif html.escape(payload) in result.response_body:
                result.reflected = True
                result.evidence = "Payload reflected but HTML-encoded"
                result.context = "html_encoded"
            
            # Check for marker reflection
            for marker in self.JARWIS_MARKERS:
                if marker in payload and marker in result.response_body:
                    result.reflected = True
                    result.evidence = f"Marker '{marker}' reflected in response"
                    break
            
            # Detect context
            if result.reflected:
                result.context = self._detect_reflection_context(result.response_body, payload)
        
        except asyncio.TimeoutError:
            logger.debug(f"Timeout testing {vector['param_name']}")
        except Exception as e:
            logger.debug(f"Error testing {vector['param_name']}: {e}")
        
        return result
    
    async def _test_xss_with_browser(self, vector: Dict, payload: str) -> XSSTestResult:
        """
        Test XSS payload using Chromium browser for real execution detection
        """
        result = XSSTestResult(payload=payload)
        
        if not self.browser or not self.browser.page:
            return result
        
        try:
            url = vector['url']
            param_name = vector['param_name']
            param_type = vector['param_type']
            
            # Build test URL
            if param_type in ('query', 'form'):
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                if '?' in url:
                    test_url = f"{url}&{param_name}={quote(payload)}"
                else:
                    test_url = f"{base_url}?{param_name}={quote(payload)}"
            else:
                test_url = url
            
            result.test_url = test_url
            
            # Set up dialog detection
            dialogs_detected = []
            
            async def handle_dialog(dialog):
                dialogs_detected.append({
                    'type': dialog.type,
                    'message': dialog.message
                })
                await dialog.dismiss()
            
            self.browser.page.on('dialog', handle_dialog)
            
            try:
                # Navigate to test URL
                await self.browser.page.goto(test_url, wait_until='networkidle', timeout=15000)
                await asyncio.sleep(1.5)  # Wait for delayed XSS
                
                # Check for dialogs
                if dialogs_detected:
                    result.dialog_triggered = True
                    result.executed = True
                    result.dialog_message = dialogs_detected[0].get('message', '')
                    result.evidence = f"JavaScript dialog triggered: {dialogs_detected}"
                
                # Get page content to check reflection
                result.response_body = await self.browser.page.content()
                
                # Check if payload is in DOM
                if payload in result.response_body:
                    result.reflected = True
                    if not result.executed:
                        result.evidence = "Payload reflected in DOM (execution not confirmed)"
                
                # Check for DOM modifications by our payload
                dom_check = await self.browser.page.evaluate('''() => {
                    // Check for injected elements
                    const injected = document.querySelector('[onerror], [onload], [onclick]');
                    const scripts = document.querySelectorAll('script');
                    const svgs = document.querySelectorAll('svg[onload]');
                    return {
                        hasEventHandlers: !!injected,
                        scriptCount: scripts.length,
                        hasSvgPayload: svgs.length > 0
                    };
                }''')
                
                if dom_check.get('hasEventHandlers') or dom_check.get('hasSvgPayload'):
                    result.dom_modified = True
                    if not result.executed:
                        result.evidence = f"Dangerous DOM elements injected: {dom_check}"
            
            finally:
                self.browser.page.remove_listener('dialog', handle_dialog)
        
        except Exception as e:
            logger.debug(f"Browser XSS test error: {e}")
        
        return result
    
    def _detect_reflection_context(self, response: str, payload: str) -> str:
        """Detect the context where payload is reflected"""
        try:
            pos = response.find(payload)
            if pos == -1:
                return "unknown"
            
            # Get surrounding context
            start = max(0, pos - 100)
            end = min(len(response), pos + len(payload) + 100)
            context = response[start:end]
            
            # Check context patterns
            if re.search(r'<script[^>]*>[^<]*$', context[:pos-start], re.IGNORECASE):
                return "javascript"
            elif re.search(r'<[^>]+=["\']?[^"\'<>]*$', context[:pos-start]):
                return "attribute"
            elif re.search(r'<style[^>]*>[^<]*$', context[:pos-start], re.IGNORECASE):
                return "css"
            elif re.search(r'<!--[^>]*$', context[:pos-start]):
                return "comment"
            else:
                return "html"
        except:
            return "unknown"
    
    def _is_dangerous_reflection(self, response: str, payload: str) -> bool:
        """
        Check if the reflection is dangerous (not properly encoded)
        """
        if not payload or payload not in response:
            return False
        
        # Dangerous if payload appears unencoded
        dangerous_chars = ['<', '>', '"', "'", 'onerror', 'onload', 'onclick', 'javascript:', 'script']
        
        for char in dangerous_chars:
            if char in payload and char in response:
                # Verify it's actually our payload, not coincidence
                pos = response.find(payload)
                if pos != -1:
                    return True
        
        return False
    
    def _add_confirmed_xss_finding(self, vector: Dict, result: XSSTestResult):
        """Add a confirmed XSS vulnerability finding"""
        severity = "critical" if result.dialog_triggered else "high"
        
        finding = ScanResult(
            id=self._get_next_finding_id(),
            category="A07",  # OWASP A07:2021 - Cross-Site Scripting
            severity=severity,
            title=f"Confirmed Reflected XSS in '{vector['param_name']}'",
            description=(
                f"A reflected Cross-Site Scripting (XSS) vulnerability was confirmed in the "
                f"'{vector['param_name']}' parameter. The injected JavaScript payload was executed "
                f"in the browser context, proving the vulnerability is exploitable."
            ),
            url=vector['url'],
            method=vector['method'],
            parameter=vector['param_name'],
            evidence=result.evidence,
            remediation=(
                "1. Implement proper output encoding/escaping based on context (HTML, JavaScript, URL, CSS)\n"
                "2. Use Content-Security-Policy headers to restrict script execution\n"
                "3. Set HttpOnly and Secure flags on sensitive cookies\n"
                "4. Use a web application firewall (WAF) with XSS rule sets\n"
                "5. Implement input validation with allowlists where possible"
            ),
            cwe_id="CWE-79",
            poc=(
                f"Payload: {result.payload}\n\n"
                f"Test URL: {result.test_url}\n\n"
                f"To reproduce:\n"
                f"1. Navigate to {vector['url']}\n"
                f"2. Inject the payload into the '{vector['param_name']}' parameter\n"
                f"3. Observe JavaScript execution (alert dialog)"
            ),
            reasoning=(
                f"CONFIRMED EXECUTION: The XSS payload was injected and executed in the browser. "
                f"{'A JavaScript alert dialog was triggered, ' if result.dialog_triggered else ''}"
                f"proving the application does not properly sanitize user input before reflecting "
                f"it in the response. This vulnerability can be exploited to steal cookies, "
                f"hijack sessions, deface websites, or perform actions on behalf of victims."
            ),
            request_data=self._format_request(vector['method'], result.test_url, self.DEFAULT_HEADERS),
            response_data=self._format_response(result.status_code, {}, result.response_body[:1500] if result.response_body else ''),
            confidence="high",
            context=result.context
        )
        
        self.findings.append(finding)
        logger.warning(f"  [CRITICAL] Confirmed XSS: {vector['param_name']} @ {vector['url']}")
    
    def _add_reflection_finding(self, vector: Dict, result: XSSTestResult, payload: str):
        """Add a reflection-based XSS finding (not browser-verified)"""
        context = result.context
        
        # Determine severity based on context
        if context == "javascript":
            severity = "high"
        elif context in ("attribute", "html"):
            severity = "high"
        else:
            severity = "medium"
        
        finding = ScanResult(
            id=self._get_next_finding_id(),
            category="A07",
            severity=severity,
            title=f"Reflected XSS (Unverified) in '{vector['param_name']}'",
            description=(
                f"A potential reflected XSS vulnerability was detected in the '{vector['param_name']}' "
                f"parameter. The payload was reflected in the response without proper encoding in a "
                f"'{context}' context. Manual verification recommended."
            ),
            url=vector['url'],
            method=vector['method'],
            parameter=vector['param_name'],
            evidence=result.evidence,
            remediation=(
                "1. Implement context-aware output encoding\n"
                "2. Use Content-Security-Policy headers\n"
                "3. Validate and sanitize all user input\n"
                "4. Use framework-provided XSS protection features"
            ),
            cwe_id="CWE-79",
            poc=f"Payload: {payload}\nTest URL: {result.test_url}",
            reasoning=(
                f"The payload was reflected in the response in a '{context}' context without "
                f"proper encoding. While browser execution was not verified, this pattern "
                f"indicates a high likelihood of exploitable XSS."
            ),
            request_data=self._format_request(vector['method'], result.test_url, self.DEFAULT_HEADERS),
            response_data=self._format_response(result.status_code, {}, result.response_body[:1000] if result.response_body else ''),
            confidence="medium",
            context=context
        )
        
        self.findings.append(finding)
        logger.info(f"  [!] Potential XSS: {vector['param_name']} @ {vector['url']} (context: {context})")


# Alias for compatibility
ReflectedXSSScanner = XSSReflectedScanner
