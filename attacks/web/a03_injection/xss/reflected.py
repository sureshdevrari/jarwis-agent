"""
XSS Reflected Scanner
======================

Detects Non-Persistent (Reflected) Cross-Site Scripting vulnerabilities.

Reflected XSS occurs when user input is immediately returned by the server
in the response without proper sanitization. The payload executes in the
victim's browser when they click a malicious link.

Detection Flow:
1. Test reflection - Check if parameter values appear in response
2. Detect context - Identify where in HTML the value is reflected
3. Inject context-specific payloads
4. Verify executable context (prevent false positives)
5. Optional: Browser verification for JS execution
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse, parse_qs, urlencode, quote
import aiohttp

from .base import XSSBase, XSSResult, XSSContext

logger = logging.getLogger(__name__)


class XSSReflected(XSSBase):
    """
    Scanner for XSS Reflected vulnerabilities.
    
    Sub-type: reflected
    OWASP: A03:2021 - Injection
    CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation)
    """
    
    SUB_TYPE = "reflected"
    TITLE_FORMAT = "XSS Reflected - {param}"
    
    # Reflected-specific payloads optimized for immediate execution
    REFLECTED_PAYLOADS = [
        # Basic script injection
        '<script>alert("JARWIS_XSS_R1")</script>',
        '"><script>alert("JARWIS_XSS_R2")</script>',
        "'-alert('JARWIS_XSS_R3')-'",
        
        # Event handler injection
        '<img src=x onerror=alert("JARWIS_XSS_R4")>',
        '"><img src=x onerror=alert("JARWIS_XSS_R5")>',
        "' onerror='alert(1)'",
        '" onfocus="alert(1)" autofocus="',
        
        # SVG injection
        '<svg onload=alert("JARWIS_XSS_R6")>',
        '"><svg/onload=alert("JARWIS_XSS_R7")>',
        
        # Double encoding bypass
        '%3Cscript%3Ealert("JARWIS_XSS_R8")%3C/script%3E',
        
        # Filter bypass techniques
        '<ScRiPt>alert("JARWIS_XSS_R9")</ScRiPt>',
        '<scr<script>ipt>alert("JARWIS_XSS_R10")</scr</script>ipt>',
        '<<script>script>alert("XSS")<</script>/script>',
        
        # No quotes/parentheses
        '<img src=x onerror=alert`XSS`>',
        '<svg onload=alert`XSS`>',
        
        # JavaScript protocol
        'javascript:alert("JARWIS_XSS_R11")',
        
        # Data URI
        'data:text/html,<script>alert("JARWIS_XSS_R12")</script>',
    ]
    
    # Markers to detect in response
    JARWIS_MARKERS = [
        'JARWIS_XSS_R1', 'JARWIS_XSS_R2', 'JARWIS_XSS_R3', 'JARWIS_XSS_R4',
        'JARWIS_XSS_R5', 'JARWIS_XSS_R6', 'JARWIS_XSS_R7', 'JARWIS_XSS_R8',
        'JARWIS_XSS_R9', 'JARWIS_XSS_R10', 'JARWIS_XSS_R11', 'JARWIS_XSS_R12',
    ]
    
    def __init__(self, config: dict, context):
        super().__init__(config, context)
        self.test_reflection_first = config.get('test_reflection_first', True)
        self.use_browser_verification = config.get('browser_verification', False)
    
    async def scan(self) -> List[XSSResult]:
        """Run XSS Reflected scan against target"""
        logger.info(f"Starting XSS Reflected scan for {self.context.target_url}")
        
        # Get URLs to test from context
        urls_to_test = await self._get_test_urls()
        
        async with aiohttp.ClientSession() as session:
            tasks = []
            for url, method in urls_to_test:
                tasks.append(self._scan_url(session, url, method))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for result in results:
                if isinstance(result, list):
                    self.findings.extend(result)
                elif isinstance(result, Exception):
                    logger.error(f"Scan task error: {result}")
        
        logger.info(f"XSS Reflected scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    async def _get_test_urls(self) -> List[tuple]:
        """Get URLs with parameters to test"""
        urls = []
        
        # Primary target
        if '?' in self.context.target_url:
            urls.append((self.context.target_url, 'GET'))
        
        # From crawl results
        if hasattr(self.context, 'crawl_results'):
            for page in self.context.crawl_results:
                if '?' in page.get('url', ''):
                    urls.append((page['url'], page.get('method', 'GET')))
        
        # From request store
        if hasattr(self.context, 'request_store'):
            for req in self.context.request_store.get_all():
                if req.get('params'):
                    urls.append((req['url'], req.get('method', 'GET')))
        
        # Deduplicate
        seen = set()
        unique = []
        for url, method in urls:
            key = f"{method}:{url}"
            if key not in seen and self._is_in_scope(url):
                seen.add(key)
                unique.append((url, method))
        
        return unique
    
    async def _scan_url(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        method: str
    ) -> List[XSSResult]:
        """Scan a single URL for reflected XSS"""
        findings = []
        
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params.keys():
                result = await self._test_parameter(session, url, method, param)
                if result:
                    findings.append(result)
                    
                # Rate limiting
                await asyncio.sleep(1 / self.rate_limit)
                
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
        
        return findings
    
    async def _test_parameter(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ) -> Optional[XSSResult]:
        """Test a single parameter for reflected XSS"""
        
        # Step 1: Test if parameter is reflected
        if self.test_reflection_first:
            reflected, baseline_body = await self._test_reflection(session, url, method, param)
            if not reflected:
                logger.debug(f"Parameter {param} not reflected, skipping")
                return None
            
            # Detect context for smart payload selection
            probe_idx = baseline_body.find('jarwis_xss_probe_12345')
            context = self._detect_context(baseline_body, probe_idx)
            payloads = self._get_payloads_for_context(context)
            payloads.extend(self.REFLECTED_PAYLOADS)  # Add reflected-specific payloads
        else:
            payloads = self.REFLECTED_PAYLOADS
            context = XSSContext.UNKNOWN
        
        # Step 2: Test each payload
        for payload in payloads:
            try:
                result = await self._test_payload(session, url, method, param, payload)
                if result:
                    result.context = context
                    return result
                    
            except Exception as e:
                logger.debug(f"Payload test error: {e}")
        
        return None
    
    async def _test_payload(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        payload: str
    ) -> Optional[XSSResult]:
        """Test a specific payload against a parameter"""
        
        # Inject payload
        test_url = self._inject_payload(url, param, payload)
        
        try:
            async with session.request(
                method,
                test_url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                body = await response.text()
                status = response.status
                resp_headers = dict(response.headers)
                
                # Check if payload is in response
                if payload not in body:
                    # Check for partial matches (some chars encoded)
                    if not any(marker in body for marker in self.JARWIS_MARKERS):
                        return None
                
                # CRITICAL: Verify executable context to prevent false positives
                if not self._is_executable_context(body, payload):
                    logger.debug(f"Payload reflected but not in executable context")
                    return None
                
                # Optional: Browser verification
                verified_execution = False
                if self.use_browser_verification and self.browser:
                    verified_execution = await self._browser_verify(test_url, payload)
                
                # Build finding
                return XSSResult(
                    id=self._generate_finding_id("XSS-REFLECTED"),
                    category="A03:2021 - Injection",
                    sub_type=self.SUB_TYPE,
                    severity="high",
                    title=self.TITLE_FORMAT.format(param=param),
                    description=self._build_description(param, payload),
                    url=url,
                    method=method,
                    parameter=param,
                    payload=payload,
                    evidence=self._extract_evidence(body, payload),
                    poc=self._build_poc(test_url, param, payload),
                    reasoning=self._build_reasoning(payload, body),
                    request_data=self._format_request(method, test_url, self.DEFAULT_HEADERS),
                    response_data=self._format_response(status, resp_headers, body),
                    confidence=0.85 if not verified_execution else 0.95,
                    verified_execution=verified_execution,
                    verification_status="verified" if verified_execution else "pending",
                    cwe_id="CWE-79",
                    remediation=self._build_remediation(),
                )
                
        except Exception as e:
            logger.error(f"Payload test error: {e}")
            return None
    
    def _build_description(self, param: str, payload: str) -> str:
        """Build vulnerability description"""
        return f"""A Reflected Cross-Site Scripting (XSS) vulnerability was identified in the '{param}' parameter.

The application reflects user-supplied input in the HTTP response without proper sanitization or encoding. An attacker can exploit this to execute arbitrary JavaScript in the context of the victim's browser session.

**Attack Vector:** The attacker crafts a malicious URL containing the XSS payload and tricks a victim into clicking it. When the victim visits the link, the payload executes in their browser.

**Impact:**
- Session hijacking (steal cookies/tokens)
- Credential theft (fake login forms)
- Malware distribution
- Defacement
- Phishing attacks
"""
    
    def _extract_evidence(self, body: str, payload: str) -> str:
        """Extract evidence snippet around the reflected payload"""
        pos = body.find(payload)
        if pos == -1:
            return "Payload markers detected in response"
        
        start = max(0, pos - 100)
        end = min(len(body), pos + len(payload) + 100)
        snippet = body[start:end]
        
        if start > 0:
            snippet = "..." + snippet
        if end < len(body):
            snippet = snippet + "..."
        
        return f"Reflected payload found in response:\n\n{snippet}"
    
    def _build_poc(self, url: str, param: str, payload: str) -> str:
        """Build Proof of Concept"""
        return f"""### Proof of Concept

**Vulnerable URL:**
```
{url}
```

**Vulnerable Parameter:** `{param}`

**Payload Used:**
```
{payload}
```

**Steps to Reproduce:**
1. Open a browser (with JavaScript enabled)
2. Navigate to the vulnerable URL with the payload
3. Observe JavaScript execution (alert box or developer console)

**Automated POC (curl):**
```bash
curl -s "{url}" | grep -o "JARWIS_XSS"
```
"""
    
    def _build_reasoning(self, payload: str, body: str) -> str:
        """Build verification reasoning"""
        reasons = []
        
        if payload in body:
            reasons.append(f"✓ Full payload reflected in response body")
        
        if '<script' in payload.lower() and '<script' in body.lower():
            reasons.append("✓ Script tag payload rendered in HTML context")
        
        if 'onerror=' in payload.lower() or 'onload=' in payload.lower():
            if 'onerror=' in body.lower() or 'onload=' in body.lower():
                reasons.append("✓ Event handler payload rendered without encoding")
        
        if not self._is_json_context(body):
            reasons.append("✓ Response is HTML (not JSON API)")
        
        return "\n".join(reasons) if reasons else "Payload reflected with execution potential"
    
    def _is_json_context(self, body: str) -> bool:
        """Check if response is JSON"""
        stripped = body.strip()
        return stripped.startswith('{') or stripped.startswith('[')
    
    def _build_remediation(self) -> str:
        """Build remediation guidance"""
        return """### Remediation

**1. Output Encoding (Primary Defense):**
Apply context-aware output encoding:
- HTML context: Encode `<`, `>`, `&`, `"`, `'`
- JavaScript context: Use JavaScript Unicode encoding
- URL context: Use URL encoding

**2. Input Validation:**
- Validate and sanitize all user input
- Use whitelist validation where possible
- Reject or strip suspicious patterns

**3. Content Security Policy:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```

**4. HTTPOnly Cookies:**
Set the `HttpOnly` flag on session cookies to prevent theft via XSS.

**5. Use Security Libraries:**
- Python: `markupsafe.escape()`
- JavaScript: `DOMPurify`
- Java: OWASP Java Encoder

**References:**
- OWASP XSS Prevention Cheat Sheet
- CWE-79: Improper Neutralization of Input During Web Page Generation
"""
    
    async def _browser_verify(self, url: str, payload: str) -> bool:
        """Verify XSS execution using headless browser"""
        if not self.browser:
            return False
        
        try:
            # This would use playwright/selenium to verify actual execution
            # Implementation depends on browser integration
            page = await self.browser.new_page()
            
            # Set up dialog handler to detect alert()
            dialog_triggered = False
            async def handle_dialog(dialog):
                nonlocal dialog_triggered
                dialog_triggered = True
                await dialog.dismiss()
            
            page.on('dialog', handle_dialog)
            
            await page.goto(url, timeout=10000)
            await asyncio.sleep(1)  # Wait for any async execution
            
            await page.close()
            return dialog_triggered
            
        except Exception as e:
            logger.debug(f"Browser verification error: {e}")
            return False
