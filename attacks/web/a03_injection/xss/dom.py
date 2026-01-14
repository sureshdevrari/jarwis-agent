"""
XSS DOM-based Scanner
======================

Detects DOM-based Cross-Site Scripting vulnerabilities.

DOM XSS occurs when client-side JavaScript takes user-controllable input
(sources) and passes it to dangerous functions (sinks) without sanitization.
The payload never touches the server - it executes entirely in the browser.

Sources (user-controllable inputs):
- document.location, document.URL, document.referrer
- window.location.hash, window.location.search
- window.name, document.cookie
- Web Storage (localStorage, sessionStorage)
- postMessage data

Sinks (dangerous functions):
- innerHTML, outerHTML, document.write()
- eval(), setTimeout(), setInterval()
- Function(), new Function()
- location.href, location.assign()

Detection Flow:
1. Identify pages with JavaScript
2. Analyze JS for source-to-sink data flows
3. Test with DOM-specific payloads in fragment/hash
4. Use headless browser to verify execution
5. Trace execution path for evidence
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urlencode, quote
from dataclasses import dataclass
import aiohttp

from .base import XSSBase, XSSResult, XSSContext

logger = logging.getLogger(__name__)


@dataclass
class DOMSink:
    """Represents a potential DOM XSS sink"""
    sink_type: str  # innerHTML, eval, document.write, etc.
    source_type: str  # hash, search, referrer, etc.
    line_number: int
    code_snippet: str


class XSSDom(XSSBase):
    """
    Scanner for DOM-based XSS vulnerabilities.
    
    Sub-type: dom
    OWASP: A03:2021 - Injection
    CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation)
    
    Requires: Headless browser for full verification
    """
    
    SUB_TYPE = "dom"
    TITLE_FORMAT = "XSS DOM-based - {sink_type}"
    
    # DOM XSS Sources - User controllable inputs
    SOURCES = {
        'location.hash': r'location\.hash',
        'location.search': r'location\.search',
        'location.href': r'location\.href',
        'document.URL': r'document\.URL',
        'document.documentURI': r'document\.documentURI',
        'document.referrer': r'document\.referrer',
        'window.name': r'window\.name',
        'document.cookie': r'document\.cookie',
        'localStorage': r'localStorage\.getItem',
        'sessionStorage': r'sessionStorage\.getItem',
        'postMessage': r'addEventListener\s*\(\s*[\'"]message[\'"]',
    }
    
    # DOM XSS Sinks - Dangerous functions
    SINKS = {
        'innerHTML': r'\.innerHTML\s*=',
        'outerHTML': r'\.outerHTML\s*=',
        'document.write': r'document\.write\s*\(',
        'document.writeln': r'document\.writeln\s*\(',
        'eval': r'eval\s*\(',
        'setTimeout': r'setTimeout\s*\([^,]*[\'"`]',  # With string argument
        'setInterval': r'setInterval\s*\([^,]*[\'"`]',
        'Function': r'new\s+Function\s*\(',
        'location.href': r'location\.href\s*=',
        'location.assign': r'location\.assign\s*\(',
        'location.replace': r'location\.replace\s*\(',
        'insertAdjacentHTML': r'\.insertAdjacentHTML\s*\(',
        'jQuery.html': r'\$\([^)]+\)\.html\s*\(',
        'jQuery.append': r'\$\([^)]+\)\.append\s*\(',
        'jQuery.prepend': r'\$\([^)]+\)\.prepend\s*\(',
    }
    
    # DOM-specific payloads
    DOM_PAYLOADS = [
        # Hash-based
        '#<img src=x onerror=alert("JARWIS_DOM_1")>',
        '#"><img src=x onerror=alert("JARWIS_DOM_2")>',
        '#<script>alert("JARWIS_DOM_3")</script>',
        '#"><script>alert("JARWIS_DOM_4")</script>',
        '#javascript:alert("JARWIS_DOM_5")',
        
        # Search/Query-based
        '?q=<img src=x onerror=alert("JARWIS_DOM_6")>',
        '?search="><script>alert("JARWIS_DOM_7")</script>',
        '?redirect=javascript:alert("JARWIS_DOM_8")',
        
        # Polyglot payloads
        '#jaVasCript:/*-/*`/*\\`/*\'/*"/**/(/* */oNcLiCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e',
    ]
    
    # Markers to look for
    DOM_MARKERS = [f'JARWIS_DOM_{i}' for i in range(1, 10)]
    
    def __init__(self, config: dict, context):
        super().__init__(config, context)
        self.browser = context.browser if hasattr(context, 'browser') else None
        self.detected_sinks: List[DOMSink] = []
    
    async def scan(self) -> List[XSSResult]:
        """Run DOM XSS scan against target"""
        logger.info(f"Starting XSS DOM scan for {self.context.target_url}")
        
        # Get URLs to test
        urls_to_test = await self._get_test_urls()
        
        async with aiohttp.ClientSession() as session:
            for url in urls_to_test:
                # Step 1: Static analysis of JavaScript
                sinks = await self._analyze_javascript(session, url)
                self.detected_sinks.extend(sinks)
                
                # Step 2: Dynamic testing with payloads
                await self._test_dom_payloads(session, url, sinks)
                
                await asyncio.sleep(1 / self.rate_limit)
        
        logger.info(f"XSS DOM scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    async def _get_test_urls(self) -> List[str]:
        """Get URLs to test for DOM XSS"""
        urls = [self.context.target_url]
        
        # From crawl results
        if hasattr(self.context, 'crawl_results'):
            for page in self.context.crawl_results:
                url = page.get('url', '')
                if self._is_in_scope(url) and url not in urls:
                    urls.append(url)
        
        return urls
    
    async def _analyze_javascript(
        self,
        session: aiohttp.ClientSession,
        url: str
    ) -> List[DOMSink]:
        """Analyze page JavaScript for source-to-sink patterns"""
        sinks = []
        
        try:
            async with session.get(
                url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                body = await response.text()
                
                # Extract inline JavaScript
                inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE)
                
                # Extract external script URLs
                external_scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE)
                
                # Analyze inline scripts
                for script in inline_scripts:
                    sinks.extend(self._find_sinks_in_js(script, "inline"))
                
                # Analyze external scripts
                for script_url in external_scripts:
                    if self._is_in_scope(script_url) or script_url.startswith('/'):
                        full_url = self._resolve_url(url, script_url)
                        try:
                            async with session.get(full_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as js_resp:
                                js_code = await js_resp.text()
                                sinks.extend(self._find_sinks_in_js(js_code, script_url))
                        except:
                            pass
                            
        except Exception as e:
            logger.error(f"JavaScript analysis error: {e}")
        
        return sinks
    
    def _find_sinks_in_js(self, js_code: str, source_file: str) -> List[DOMSink]:
        """Find dangerous source-to-sink patterns in JavaScript"""
        sinks = []
        lines = js_code.split('\n')
        
        for line_num, line in enumerate(lines, 1):
            # Check each sink pattern
            for sink_name, sink_pattern in self.SINKS.items():
                if re.search(sink_pattern, line):
                    # Check if any source is used nearby
                    context_start = max(0, line_num - 10)
                    context_end = min(len(lines), line_num + 5)
                    context = '\n'.join(lines[context_start:context_end])
                    
                    for source_name, source_pattern in self.SOURCES.items():
                        if re.search(source_pattern, context):
                            sinks.append(DOMSink(
                                sink_type=sink_name,
                                source_type=source_name,
                                line_number=line_num,
                                code_snippet=line.strip()[:200]
                            ))
                            break
        
        return sinks
    
    def _resolve_url(self, base_url: str, relative_url: str) -> str:
        """Resolve relative URL to absolute"""
        if relative_url.startswith('http'):
            return relative_url
        
        parsed = urlparse(base_url)
        
        if relative_url.startswith('//'):
            return f"{parsed.scheme}:{relative_url}"
        elif relative_url.startswith('/'):
            return f"{parsed.scheme}://{parsed.netloc}{relative_url}"
        else:
            base_path = '/'.join(parsed.path.split('/')[:-1])
            return f"{parsed.scheme}://{parsed.netloc}{base_path}/{relative_url}"
    
    async def _test_dom_payloads(
        self,
        session: aiohttp.ClientSession,
        url: str,
        sinks: List[DOMSink]
    ) -> None:
        """Test DOM XSS payloads"""
        
        if not self.browser:
            # Without browser, we can only do static analysis
            for sink in sinks:
                # Report potential DOM XSS based on code analysis
                finding = self._create_potential_finding(url, sink)
                if finding:
                    self.findings.append(finding)
            return
        
        # With browser - dynamic testing
        for payload in self.DOM_PAYLOADS:
            result = await self._browser_test_payload(url, payload)
            if result:
                self.findings.append(result)
                break  # One confirmed is enough
    
    async def _browser_test_payload(self, url: str, payload: str) -> Optional[XSSResult]:
        """Test DOM XSS payload using headless browser"""
        if not self.browser:
            return None
        
        try:
            # Construct test URL
            if payload.startswith('#'):
                test_url = url.split('#')[0] + payload
            elif payload.startswith('?'):
                test_url = url.split('?')[0] + payload
            else:
                test_url = url + payload
            
            page = await self.browser.new_page()
            
            # Set up alert detection
            alert_triggered = False
            alert_message = ""
            
            async def handle_dialog(dialog):
                nonlocal alert_triggered, alert_message
                alert_triggered = True
                alert_message = dialog.message
                await dialog.dismiss()
            
            page.on('dialog', handle_dialog)
            
            # Also check for console errors that might indicate blocked XSS
            console_messages = []
            page.on('console', lambda msg: console_messages.append(msg.text))
            
            # Navigate and wait
            await page.goto(test_url, timeout=15000, wait_until='networkidle')
            await asyncio.sleep(1)
            
            await page.close()
            
            if alert_triggered:
                return XSSResult(
                    id=self._generate_finding_id("XSS-DOM"),
                    category="A03:2021 - Injection",
                    sub_type=self.SUB_TYPE,
                    severity="high",
                    title=self.TITLE_FORMAT.format(sink_type="JavaScript Execution"),
                    description=self._build_description(payload, alert_message),
                    url=url,
                    method="GET",
                    parameter="DOM",
                    payload=payload,
                    evidence=f"Alert triggered with message: {alert_message}",
                    poc=self._build_poc(test_url, payload),
                    reasoning="✓ JavaScript alert() executed successfully via DOM manipulation",
                    request_data=f"GET {test_url}",
                    response_data="(DOM XSS - payload executed client-side)",
                    confidence=0.95,  # Browser confirmed execution
                    verified_execution=True,
                    verification_status="verified",
                    cwe_id="CWE-79",
                    remediation=self._build_remediation(),
                )
                
        except Exception as e:
            logger.debug(f"Browser test error: {e}")
        
        return None
    
    def _create_potential_finding(self, url: str, sink: DOMSink) -> Optional[XSSResult]:
        """Create finding for potential DOM XSS based on static analysis"""
        
        return XSSResult(
            id=self._generate_finding_id("XSS-DOM-POTENTIAL"),
            category="A03:2021 - Injection",
            sub_type=self.SUB_TYPE,
            severity="medium",  # Lower confidence without browser verification
            title=self.TITLE_FORMAT.format(sink_type=sink.sink_type),
            description=self._build_description_static(sink),
            url=url,
            method="GET",
            parameter=sink.source_type,
            payload="(static analysis - no payload injected)",
            evidence=f"Dangerous pattern detected:\n```javascript\n{sink.code_snippet}\n```",
            poc=self._build_poc_static(url, sink),
            reasoning=f"✓ Source ({sink.source_type}) flows to sink ({sink.sink_type})\n✓ Requires browser verification for confirmation",
            request_data=f"GET {url}",
            response_data="(Static analysis finding - code review recommended)",
            confidence=0.60,  # Lower without runtime verification
            verified_execution=False,
            verification_status="pending",  # Needs manual verification
            cwe_id="CWE-79",
            remediation=self._build_remediation(),
        )
    
    def _build_description(self, payload: str, alert_message: str) -> str:
        """Build description for confirmed DOM XSS"""
        return f"""A DOM-based Cross-Site Scripting (XSS) vulnerability was confirmed.

The application's client-side JavaScript takes user-controllable input and passes it to a dangerous DOM manipulation function without proper sanitization.

**Key Characteristics:**
- Payload executes entirely in the browser (client-side)
- Server logs may not show the attack (harder to detect)
- Exploitable via URL fragment (#) which isn't sent to server

**Confirmed Execution:**
Alert message: `{alert_message}`

**Impact:**
- Session hijacking
- Credential theft
- Keylogging
- Webcam/microphone access (with user permission)
- Cryptocurrency mining
"""
    
    def _build_description_static(self, sink: DOMSink) -> str:
        """Build description for potential DOM XSS from static analysis"""
        return f"""A potential DOM-based XSS vulnerability was detected through static code analysis.

**Source:** `{sink.source_type}` - User controllable input
**Sink:** `{sink.sink_type}` - Dangerous DOM function

The JavaScript code appears to pass user-controllable data to a dangerous function that can execute arbitrary code or modify the DOM unsafely.

**Code Pattern Detected (line {sink.line_number}):**
```javascript
{sink.code_snippet}
```

**⚠️ Requires Manual Verification:**
This finding is based on static analysis. Browser testing is recommended to confirm exploitability.
"""
    
    def _build_poc(self, test_url: str, payload: str) -> str:
        """Build PoC for confirmed DOM XSS"""
        return f"""### Proof of Concept

**Vulnerable URL:**
```
{test_url}
```

**Payload:**
```
{payload}
```

**Steps to Reproduce:**
1. Open the vulnerable URL in a browser with JavaScript enabled
2. The alert box will appear automatically
3. Check browser's Developer Console for additional execution evidence

**JavaScript Verification:**
```javascript
// Check if location.hash is used unsafely
console.log("Hash:", location.hash);
console.log("Search:", location.search);
```
"""
    
    def _build_poc_static(self, url: str, sink: DOMSink) -> str:
        """Build PoC for potential DOM XSS"""
        test_payloads = {
            'location.hash': f'{url}#<img src=x onerror=alert(1)>',
            'location.search': f'{url}?q=<img src=x onerror=alert(1)>',
            'document.referrer': '(Requires crafted referring page)',
            'localStorage': '(Requires prior localStorage poisoning)',
        }
        
        suggested_url = test_payloads.get(sink.source_type, f'{url}#<script>alert(1)</script>')
        
        return f"""### Proof of Concept (Requires Manual Testing)

**Vulnerable Code Pattern:**
```javascript
// Line {sink.line_number}
{sink.code_snippet}
```

**Source:** `{sink.source_type}` → **Sink:** `{sink.sink_type}`

**Suggested Test URL:**
```
{suggested_url}
```

**Testing Steps:**
1. Open the test URL in a browser with Developer Tools open
2. Check Console for errors or execution evidence
3. If alert doesn't trigger, try variations:
   - Different quote styles
   - URL encoding
   - Case variations

**JavaScript Console Test:**
```javascript
// Manually test the sink
document.getElementById('target').innerHTML = '<img src=x onerror=alert(1)>';
```
"""
    
    def _build_remediation(self) -> str:
        """Build remediation guidance for DOM XSS"""
        return """### Remediation

**1. Avoid Dangerous Sinks:**
```javascript
// BAD - vulnerable to DOM XSS
element.innerHTML = userInput;

// GOOD - safe text insertion
element.textContent = userInput;

// GOOD - safe DOM creation
const node = document.createTextNode(userInput);
element.appendChild(node);
```

**2. Sanitize Before Using innerHTML:**
```javascript
// Use DOMPurify for HTML sanitization
import DOMPurify from 'dompurify';
element.innerHTML = DOMPurify.sanitize(userInput);
```

**3. Avoid eval() and Related Functions:**
```javascript
// BAD - code execution
eval(userInput);
setTimeout(userInput, 1000);
new Function(userInput)();

// GOOD - use safe alternatives
JSON.parse(userInput);  // For JSON data
setTimeout(() => safeFunction(), 1000);
```

**4. Validate URL Inputs:**
```javascript
// BAD - open redirect / javascript: execution
location.href = userInput;

// GOOD - validate URL scheme
const url = new URL(userInput, location.origin);
if (url.protocol === 'https:' || url.protocol === 'http:') {
    location.href = url.href;
}
```

**5. Content Security Policy:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'
```
Blocks inline scripts and eval().

**6. Use Trusted Types (Modern Browsers):**
```javascript
// Enforce type safety for DOM sinks
if (window.trustedTypes?.createPolicy) {
    const policy = trustedTypes.createPolicy('default', {
        createHTML: (input) => DOMPurify.sanitize(input),
    });
}
```

**References:**
- OWASP DOM-based XSS Prevention Cheat Sheet
- Google Trusted Types documentation
- CWE-79: Improper Neutralization of Input During Web Page Generation
"""
