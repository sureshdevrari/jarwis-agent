"""
Jarwis AGI Pen Test - Clickjacking Scanner
Detects Clickjacking/UI Redress vulnerabilities (A01:2021 - Broken Access Control)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
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


class ClickjackingScanner:
    """
    Scans for Clickjacking vulnerabilities
    OWASP A01:2021 - Broken Access Control
    
    Checks:
    - X-Frame-Options header
    - Content-Security-Policy frame-ancestors
    - Frame-breaking JavaScript
    - Double framing bypass
    """
    
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
        logger.info("Starting Clickjacking scan...")
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
            
            # Check main page
            await self._check_clickjacking(session, base_url)
            
            # Check sensitive pages
            sensitive_paths = [
                '/login', '/signin', '/account', '/settings',
                '/profile', '/admin', '/dashboard', '/transfer',
                '/payment', '/checkout', '/delete', '/password',
            ]
            
            for path in sensitive_paths:
                url = urljoin(base_url, path)
                await self._check_clickjacking(session, url)
            
            # Check discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:15]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._check_clickjacking(session, ep_url)
        
        logger.info(f"Clickjacking scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_clickjacking(self, session: aiohttp.ClientSession, url: str):
        """Check URL for clickjacking protection"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    return
                
                resp_headers = dict(response.headers)
                body = await response.text()
                
                # Check X-Frame-Options
                xfo = resp_headers.get('X-Frame-Options', '').upper()
                
                # Check CSP frame-ancestors
                csp = resp_headers.get('Content-Security-Policy', '')
                has_frame_ancestors = 'frame-ancestors' in csp.lower()
                
                # Determine protection level
                protection_level = self._assess_protection(xfo, csp, body)
                
                if protection_level == 'none':
                    result = ScanResult(
                        id=f"CLICKJACK-NONE-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="medium",
                        title="Clickjacking Vulnerability - No Protection",
                        description="Page can be embedded in an iframe from any origin.",
                        url=url,
                        method="GET",
                        evidence="Missing X-Frame-Options and CSP frame-ancestors",
                        remediation="Add X-Frame-Options: DENY or CSP frame-ancestors 'self'",
                        cwe_id="CWE-1021",
                        poc=self._generate_poc(url),
                        reasoning="No framing protection headers present"
                    )
                    self.results.append(result)
                    
                elif protection_level == 'weak':
                    result = ScanResult(
                        id=f"CLICKJACK-WEAK-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="low",
                        title="Weak Clickjacking Protection",
                        description="Page has incomplete clickjacking protection.",
                        url=url,
                        method="GET",
                        evidence=f"X-Frame-Options: {xfo}, CSP: {csp[:100] if csp else 'none'}",
                        remediation="Use both X-Frame-Options: DENY and CSP frame-ancestors 'none'",
                        cwe_id="CWE-1021",
                        reasoning="Protection may be bypassable"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Clickjacking check error: {e}")
    
    def _assess_protection(self, xfo: str, csp: str, body: str) -> str:
        """Assess clickjacking protection level"""
        
        has_xfo = xfo in ['DENY', 'SAMEORIGIN']
        has_csp_fa = 'frame-ancestors' in csp.lower()
        has_js_framebusting = self._check_framebusting_js(body)
        
        if has_xfo and has_csp_fa:
            return 'strong'
        elif has_xfo or has_csp_fa:
            return 'moderate'
        elif has_js_framebusting:
            return 'weak'  # JS can be bypassed
        else:
            return 'none'
    
    def _check_framebusting_js(self, body: str) -> bool:
        """Check for JavaScript frame-busting code"""
        
        framebusting_patterns = [
            r'if\s*\(\s*top\s*!=\s*self\s*\)',
            r'if\s*\(\s*parent\s*!=\s*window\s*\)',
            r'if\s*\(\s*top\.location\s*!=',
            r'if\s*\(\s*self\s*!=\s*top\s*\)',
            r'top\.location\s*=\s*self\.location',
            r'window\.top\.location\s*=',
        ]
        
        for pattern in framebusting_patterns:
            import re
            if re.search(pattern, body, re.IGNORECASE):
                return True
        
        return False
    
    def _generate_poc(self, target_url: str) -> str:
        """Generate clickjacking PoC HTML"""
        return f'''<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC</title>
    <style>
        iframe {{
            position: absolute;
            top: 0; left: 0;
            width: 100%; height: 100%;
            opacity: 0.5;
            z-index: 2;
        }}
        .decoy {{
            position: absolute;
            top: 50%; left: 50%;
            transform: translate(-50%, -50%);
            z-index: 1;
        }}
    </style>
</head>
<body>
    <div class="decoy">
        <h1>Click here to win a prize!</h1>
        <button>CLAIM PRIZE</button>
    </div>
    <iframe src="{target_url}"></iframe>
</body>
</html>'''


class DoubleClickjackingScanner:
    """
    Scans for Double Clickjacking vulnerabilities
    Newer attack that bypasses frame-ancestors through user interaction
    """
    
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
        logger.info("Starting Double Clickjacking scan...")
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
            
            # Check pages with sensitive actions
            sensitive_paths = [
                '/settings', '/account', '/profile',
                '/admin', '/oauth/authorize', '/consent',
                '/permissions', '/grant', '/approve',
            ]
            
            for path in sensitive_paths:
                url = urljoin(base_url, path)
                await self._check_double_click_vuln(session, url)
        
        logger.info(f"Double clickjacking scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_double_click_vuln(self, session: aiohttp.ClientSession, url: str):
        """Check for double clickjacking vulnerability"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    return
                
                body = await response.text()
                
                # Check for OAuth/permission grant pages
                oauth_indicators = [
                    'authorize', 'consent', 'allow', 'grant',
                    'permission', 'approve', 'accept',
                ]
                
                if any(ind in body.lower() for ind in oauth_indicators):
                    # Check if page has protective measures
                    has_protection = self._check_double_click_protection(response.headers, body)
                    
                    if not has_protection:
                        result = ScanResult(
                            id=f"DBLCLICK-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="medium",
                            title="Potential Double Clickjacking on Consent Page",
                            description="OAuth/consent page may be vulnerable to double clickjacking.",
                            url=url,
                            method="GET",
                            evidence="Consent page without popup protection",
                            remediation="Open consent pages in popups. Add user interaction checks.",
                            cwe_id="CWE-1021",
                            reasoning="Consent pages are high-value double clickjacking targets"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Double clickjacking check error: {e}")
    
    def _check_double_click_protection(self, headers: dict, body: str) -> bool:
        """Check for double clickjacking protections"""
        
        # Check for popup-only enforcement
        if 'Content-Security-Policy' in headers:
            csp = headers['Content-Security-Policy']
            if "navigate-to 'none'" in csp or "sandbox" in csp:
                return True
        
        # Check for JavaScript popup detection
        popup_detection = [
            'window.opener',
            'window.parent',
            'window.top',
            'document.referrer',
        ]
        
        import re
        for pattern in popup_detection:
            if re.search(rf'{pattern}.*(?:null|undefined|===|!==)', body):
                return True
        
        return False


class UIRedressScanner:
    """
    Scans for various UI Redress attacks
    OWASP A01:2021 - Broken Access Control
    """
    
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
        logger.info("Starting UI Redress scan...")
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
            
            # Check for drag-and-drop vulnerabilities
            await self._check_drag_drop(session, base_url)
            
            # Check for cursor hijacking
            await self._check_cursor_hijack(session, base_url)
        
        logger.info(f"UI redress scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_drag_drop(self, session: aiohttp.ClientSession, url: str):
        """Check for drag-and-drop attack surface"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    return
                
                body = await response.text()
                
                # Check for file drop zones
                drop_indicators = [
                    'ondrop', 'ondragover', 'ondragenter',
                    'dropzone', 'draggable', 'file-drop',
                ]
                
                if any(ind in body.lower() for ind in drop_indicators):
                    # Check framing protection
                    xfo = response.headers.get('X-Frame-Options', '')
                    csp = response.headers.get('Content-Security-Policy', '')
                    
                    if not xfo and 'frame-ancestors' not in csp:
                        result = ScanResult(
                            id=f"DRAGDROP-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="low",
                            title="Potential Drag-and-Drop UI Redress",
                            description="File drop zone can be framed for UI redress attacks.",
                            url=url,
                            method="GET",
                            evidence="Drop zone without framing protection",
                            remediation="Add X-Frame-Options. Validate drag operations.",
                            cwe_id="CWE-1021",
                            reasoning="Drop zones are attack surface for drag-jacking"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Drag-drop check error: {e}")
    
    async def _check_cursor_hijack(self, session: aiohttp.ClientSession, url: str):
        """Check for cursor hijacking vulnerability"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                if response.status != 200:
                    return
                
                body = await response.text()
                
                # Check for custom cursor CSS
                import re
                cursor_patterns = [
                    r'cursor:\s*url\([^)]+\)',
                    r'cursor:\s*none',
                ]
                
                for pattern in cursor_patterns:
                    if re.search(pattern, body, re.IGNORECASE):
                        # Check framing protection
                        xfo = response.headers.get('X-Frame-Options', '')
                        
                        if not xfo:
                            result = ScanResult(
                                id=f"CURSOR-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="info",
                                title="Custom Cursor in Frameable Page",
                                description="Page uses custom cursor and can be framed.",
                                url=url,
                                method="GET",
                                evidence=f"Pattern: {pattern}",
                                remediation="Add X-Frame-Options. Avoid custom cursors on sensitive pages.",
                                cwe_id="CWE-1021",
                                reasoning="Custom cursors can mislead user clicks"
                            )
                            self.results.append(result)
                            return
                        
        except Exception as e:
            logger.debug(f"Cursor hijack check error: {e}")
