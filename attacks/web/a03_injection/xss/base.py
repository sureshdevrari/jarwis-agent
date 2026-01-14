"""
XSS Base Class - Shared logic for all XSS sub-types
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs, quote
from enum import Enum
import aiohttp

logger = logging.getLogger(__name__)


class XSSContext(Enum):
    """Context where XSS payload is injected"""
    HTML_TEXT = "html_text"           # Inside HTML text content
    HTML_ATTRIBUTE = "html_attribute"  # Inside an HTML attribute value
    HTML_COMMENT = "html_comment"      # Inside HTML comment
    JAVASCRIPT = "javascript"          # Inside <script> tag or JS context
    URL = "url"                        # Inside href/src URL
    CSS = "css"                        # Inside <style> or style attribute
    JSON = "json"                      # Inside JSON response
    UNKNOWN = "unknown"


@dataclass
class XSSResult:
    """Result from XSS scan - includes sub-type identification"""
    id: str
    category: str = "A03:2021 - Injection"
    sub_type: str = ""  # "reflected", "stored", "dom"
    severity: str = "high"
    title: str = ""
    description: str = ""
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    remediation: str = "Implement proper output encoding based on context. Use Content-Security-Policy headers."
    cwe_id: str = "CWE-79"
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""
    confidence: float = 0.0
    context: XSSContext = XSSContext.UNKNOWN
    verified_execution: bool = False  # True if browser confirmed JS execution
    verification_status: str = "pending"


class XSSBase:
    """
    Base class for all XSS scanners.
    
    Provides shared functionality:
    - Payload management
    - Context detection
    - Request/response formatting
    - Scope checking
    - Rate limiting
    """
    
    # Common payloads used by all XSS types
    REFLECTION_PROBES = [
        'jarwis_xss_probe_12345',
        '<jarwis_test>',
    ]
    
    # Payloads organized by context
    PAYLOADS_BY_CONTEXT = {
        XSSContext.HTML_TEXT: [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            '<body onload=alert("XSS")>',
            '<marquee onstart=alert("XSS")>',
        ],
        XSSContext.HTML_ATTRIBUTE: [
            '" onmouseover="alert(\'XSS\')"',
            "' onmouseover='alert(\"XSS\")'",
            '" onfocus="alert(\'XSS\')" autofocus="',
            "' onclick='alert(1)'",
            '" onload="alert(1)"',
        ],
        XSSContext.JAVASCRIPT: [
            "'-alert('XSS')-'",
            '";alert("XSS");//',
            "';alert('XSS');//",
            '</script><script>alert("XSS")</script>',
            '\\";alert("XSS");//',
        ],
        XSSContext.URL: [
            'javascript:alert("XSS")',
            'data:text/html,<script>alert("XSS")</script>',
            'vbscript:msgbox("XSS")',
        ],
    }
    
    # Generic payloads for unknown context
    GENERIC_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        "'-alert('XSS')-'",
        '<img src=x onerror=alert("XSS")>',
        '"><img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        '"><svg/onload=alert("XSS")>',
        '{{constructor.constructor("alert(1)")()}}',
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.findings: List[XSSResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # For DOM XSS verification
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
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
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            target = self._target_domain
            # Strip www. for comparison
            if url_domain.startswith('www.'):
                url_domain = url_domain[4:]
            if target.startswith('www.'):
                target = target[4:]
            return url_domain == target
        except:
            return False
    
    def _detect_context(self, response_body: str, injection_point: int) -> XSSContext:
        """Detect the context where payload will be injected"""
        if injection_point < 0:
            return XSSContext.UNKNOWN
        
        # Get surrounding content
        start = max(0, injection_point - 200)
        before = response_body[start:injection_point].lower()
        
        # Check for JavaScript context
        if '<script' in before and '</script>' not in before:
            return XSSContext.JAVASCRIPT
        
        # Check for HTML attribute context
        attr_pattern = r'["\'][^"\']*$'
        if re.search(attr_pattern, before):
            # Inside an attribute value
            return XSSContext.HTML_ATTRIBUTE
        
        # Check for URL context
        if 'href=' in before[-50:] or 'src=' in before[-50:]:
            return XSSContext.URL
        
        # Check for HTML comment
        if '<!--' in before and '-->' not in before:
            return XSSContext.HTML_COMMENT
        
        # Check for CSS context
        if '<style' in before and '</style>' not in before:
            return XSSContext.CSS
        
        # Default to HTML text
        return XSSContext.HTML_TEXT
    
    def _get_payloads_for_context(self, context: XSSContext) -> List[str]:
        """Get appropriate payloads for the detected context"""
        if context in self.PAYLOADS_BY_CONTEXT:
            return self.PAYLOADS_BY_CONTEXT[context]
        return self.GENERIC_PAYLOADS
    
    def _is_executable_context(self, body: str, payload: str) -> bool:
        """
        Check if payload is in an executable context.
        Critical for preventing false positives.
        """
        pos = body.find(payload)
        if pos == -1:
            return False
        
        before = body[:pos]
        
        # FALSE POSITIVE CHECKS
        
        # Inside HTML comment
        if before.rfind('<!--') > before.rfind('-->'):
            return False
        
        # Inside JSON (as string value)
        body_stripped = body.strip()
        if body_stripped.startswith('{') or body_stripped.startswith('['):
            if f'"{payload}"' in body or f"'{payload}'" in body:
                return False
        
        # Inside <textarea>
        if before.lower().rfind('<textarea') > before.lower().rfind('</textarea'):
            return False
        
        # Inside <input value="">
        value_pattern = r'value\s*=\s*["\'][^"\']*$'
        if re.search(value_pattern, before[-100:], re.IGNORECASE):
            if '"' not in payload and "'" not in payload and '>' not in payload:
                return False
        
        # HTML entity encoded
        encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
        if encoded in body and payload not in body:
            return False
        
        # TRUE POSITIVE CHECKS
        
        # Script tag payload
        if '<script' in payload.lower() and '</script>' in payload.lower():
            return True
        
        # Event handler in tag context
        if 'onerror=' in payload.lower() or 'onload=' in payload.lower():
            if before.rfind('<') > before.rfind('>'):
                return True
        
        # SVG/IMG with event handler
        if '<svg' in payload.lower() or '<img' in payload.lower():
            if 'onload=' in payload.lower() or 'onerror=' in payload.lower():
                return True
        
        return False
    
    def _format_request(self, method: str, url: str, headers: Dict, body: str = "") -> str:
        """Format request in Burp Suite style"""
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
        """Format response in Burp Suite style"""
        lines = [f"HTTP/1.1 {status}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if len(body) > 1500:
            body = body[:1500] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    def _generate_finding_id(self, prefix: str) -> str:
        """Generate unique finding ID"""
        self._finding_id += 1
        return f"{prefix}-{self._finding_id:04d}"
    
    async def _test_reflection(
        self, 
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ) -> Tuple[bool, Optional[str]]:
        """Test if parameter value is reflected in response"""
        for probe in self.REFLECTION_PROBES:
            try:
                test_url = self._inject_payload(url, param, probe)
                async with session.get(
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    if probe in body:
                        return True, body
            except Exception as e:
                logger.debug(f"Reflection test error: {e}")
        return False, None
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        encoded = quote(payload, safe='')
        
        if '?' in url:
            base, query = url.split('?', 1)
            params = {}
            for p in query.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    params[k] = v
            params[param] = encoded
            return f"{base}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
        else:
            return f"{url}?{param}={encoded}"
    
    async def scan(self) -> List[XSSResult]:
        """Override in subclasses"""
        raise NotImplementedError("Subclasses must implement scan()")
