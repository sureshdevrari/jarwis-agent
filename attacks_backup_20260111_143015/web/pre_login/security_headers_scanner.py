"""
Jarwis AGI Pen Test - Security Headers & CSP Scanner
Detects missing/misconfigured security headers (A05:2021 - Security Misconfiguration)
Based on OWASP best practices - adapted for 2025
"""

import asyncio
import logging
import re
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


class SecurityHeadersScanner:
    """
    Scans for missing or misconfigured security headers
    OWASP A05:2021 - Security Misconfiguration
    
    Checks:
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - X-Content-Type-Options
    - Strict-Transport-Security (HSTS)
    - X-XSS-Protection
    - Referrer-Policy
    - Permissions-Policy
    - Cache-Control
    - Cross-Origin headers (COOP, COEP, CORP)
    """
    
    # Required security headers and their checks
    SECURITY_HEADERS = {
        'Strict-Transport-Security': {
            'required': True,
            'severity': 'medium',
            'description': 'HSTS forces browsers to use HTTPS',
            'remediation': 'Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'check_value': lambda v: 'max-age=' in v.lower() if v else False,
            'cwe_id': 'CWE-311',
        },
        'Content-Security-Policy': {
            'required': True,
            'severity': 'high',
            'description': 'CSP prevents XSS and data injection attacks',
            'remediation': "Add header: Content-Security-Policy: default-src 'self'",
            'check_value': lambda v: v and len(v) > 10,
            'cwe_id': 'CWE-1021',
        },
        'X-Frame-Options': {
            'required': True,
            'severity': 'medium',
            'description': 'Prevents clickjacking attacks',
            'remediation': 'Add header: X-Frame-Options: DENY or SAMEORIGIN',
            'check_value': lambda v: v.upper() in ['DENY', 'SAMEORIGIN'] if v else False,
            'cwe_id': 'CWE-1021',
        },
        'X-Content-Type-Options': {
            'required': True,
            'severity': 'low',
            'description': 'Prevents MIME type sniffing',
            'remediation': 'Add header: X-Content-Type-Options: nosniff',
            'check_value': lambda v: v.lower() == 'nosniff' if v else False,
            'cwe_id': 'CWE-16',
        },
        'X-XSS-Protection': {
            'required': False,  # Deprecated but still checked
            'severity': 'info',
            'description': 'Legacy XSS filter (deprecated)',
            'remediation': 'Use CSP instead. If needed: X-XSS-Protection: 1; mode=block',
            'check_value': lambda v: '1' in v if v else False,
            'cwe_id': 'CWE-79',
        },
        'Referrer-Policy': {
            'required': True,
            'severity': 'low',
            'description': 'Controls referrer information in requests',
            'remediation': 'Add header: Referrer-Policy: strict-origin-when-cross-origin',
            'check_value': lambda v: v and v.lower() != 'unsafe-url',
            'cwe_id': 'CWE-200',
        },
        'Permissions-Policy': {
            'required': False,
            'severity': 'low',
            'description': 'Controls browser features like camera, geolocation',
            'remediation': 'Add header: Permissions-Policy: geolocation=(), camera=()',
            'check_value': lambda v: v is not None,
            'cwe_id': 'CWE-250',
        },
        'Cross-Origin-Opener-Policy': {
            'required': False,
            'severity': 'low',
            'description': 'Prevents cross-origin window access',
            'remediation': 'Add header: Cross-Origin-Opener-Policy: same-origin',
            'check_value': lambda v: v is not None,
            'cwe_id': 'CWE-346',
        },
        'Cross-Origin-Resource-Policy': {
            'required': False,
            'severity': 'low',
            'description': 'Prevents cross-origin resource sharing',
            'remediation': 'Add header: Cross-Origin-Resource-Policy: same-origin',
            'check_value': lambda v: v is not None,
            'cwe_id': 'CWE-346',
        },
    }
    
    # Dangerous header values
    DANGEROUS_VALUES = {
        'Access-Control-Allow-Origin': ['*'],
        'Access-Control-Allow-Credentials': ['true'],  # Dangerous with wildcard origin
        'X-Powered-By': ['*'],  # Any value is information disclosure
        'Server': ['*'],  # Detailed version info
    }
    
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
        logger.info("Starting Security Headers scan...")
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
            await self._check_headers(session, base_url)
            
            # Check discovered endpoints
            if hasattr(self.context, 'endpoints'):
                checked_hosts = {urlparse(base_url).netloc}
                
                for endpoint in self.context.endpoints[:10]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        host = urlparse(ep_url).netloc
                        if host not in checked_hosts:
                            await self._check_headers(session, ep_url)
                            checked_hosts.add(host)
        
        logger.info(f"Security headers scan complete. Found {len(self.results)} issues")
        return self.results
    
    async def _check_headers(self, session: aiohttp.ClientSession, url: str):
        """Check security headers for a URL"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers, allow_redirects=True) as response:
                resp_headers = dict(response.headers)
                
                # Check for missing required headers
                for header_name, config in self.SECURITY_HEADERS.items():
                    header_value = resp_headers.get(header_name)
                    
                    if config['required']:
                        if header_value is None:
                            result = ScanResult(
                                id=f"HEADER-MISSING-{len(self.results)+1}",
                                category="A05:2021 - Security Misconfiguration",
                                severity=config['severity'],
                                title=f"Missing Security Header: {header_name}",
                                description=config['description'],
                                url=url,
                                method="GET",
                                parameter=header_name,
                                evidence=f"Header '{header_name}' not present",
                                remediation=config['remediation'],
                                cwe_id=config['cwe_id'],
                                reasoning="Required security header is missing"
                            )
                            self.results.append(result)
                            
                        elif not config['check_value'](header_value):
                            result = ScanResult(
                                id=f"HEADER-WEAK-{len(self.results)+1}",
                                category="A05:2021 - Security Misconfiguration",
                                severity=config['severity'],
                                title=f"Weak Security Header: {header_name}",
                                description=f"Header value may be insufficient: {header_value}",
                                url=url,
                                method="GET",
                                parameter=header_name,
                                evidence=f"Value: {header_value}",
                                remediation=config['remediation'],
                                cwe_id=config['cwe_id'],
                                reasoning="Header present but may not provide adequate protection"
                            )
                            self.results.append(result)
                
                # Check for dangerous header values
                await self._check_dangerous_headers(url, resp_headers)
                
                # Check for information disclosure headers
                await self._check_info_disclosure(url, resp_headers)
                
        except Exception as e:
            logger.debug(f"Header check error: {e}")
    
    async def _check_dangerous_headers(self, url: str, headers: dict):
        """Check for dangerous header configurations"""
        
        # Wildcard CORS with credentials
        acao = headers.get('Access-Control-Allow-Origin')
        acac = headers.get('Access-Control-Allow-Credentials')
        
        if acao == '*' and acac and acac.lower() == 'true':
            result = ScanResult(
                id=f"HEADER-CORS-{len(self.results)+1}",
                category="A01:2021 - Broken Access Control",
                severity="high",
                title="Dangerous CORS Configuration",
                description="Wildcard origin with credentials is insecure.",
                url=url,
                method="GET",
                evidence="Access-Control-Allow-Origin: * with Allow-Credentials: true",
                remediation="Specify allowed origins. Never use * with credentials.",
                cwe_id="CWE-942",
                reasoning="Allows any origin to make credentialed requests"
            )
            self.results.append(result)
    
    async def _check_info_disclosure(self, url: str, headers: dict):
        """Check for information disclosure headers"""
        
        # X-Powered-By
        powered_by = headers.get('X-Powered-By')
        if powered_by:
            result = ScanResult(
                id=f"HEADER-INFO-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="low",
                title="Technology Disclosure: X-Powered-By",
                description=f"Server reveals technology: {powered_by}",
                url=url,
                method="GET",
                parameter="X-Powered-By",
                evidence=f"X-Powered-By: {powered_by}",
                remediation="Remove X-Powered-By header.",
                cwe_id="CWE-200",
                reasoning="Technology disclosure aids attackers"
            )
            self.results.append(result)
        
        # Detailed Server header
        server = headers.get('Server')
        if server and re.search(r'\d+\.\d+', server):
            result = ScanResult(
                id=f"HEADER-SERVER-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="low",
                title="Server Version Disclosure",
                description=f"Server header reveals version: {server}",
                url=url,
                method="GET",
                parameter="Server",
                evidence=f"Server: {server}",
                remediation="Minimize server header information.",
                cwe_id="CWE-200",
                reasoning="Version disclosure enables targeted attacks"
            )
            self.results.append(result)


class CSPAnalyzer:
    """
    Analyzes Content-Security-Policy for weaknesses
    OWASP A05:2021 - Security Misconfiguration
    """
    
    # Dangerous CSP directives
    DANGEROUS_DIRECTIVES = {
        "unsafe-inline": ("high", "Allows inline scripts, defeating CSP XSS protection"),
        "unsafe-eval": ("high", "Allows eval(), enabling code injection"),
        "unsafe-hashes": ("medium", "Allows specific inline scripts by hash"),
        "data:": ("medium", "Allows data: URIs which can contain scripts"),
        "*": ("high", "Wildcard allows loading from any source"),
        "blob:": ("medium", "Allows blob: URIs which can be manipulated"),
        "'strict-dynamic'": ("info", "Dynamic script loading - review required"),
    }
    
    # Directives that should be present
    RECOMMENDED_DIRECTIVES = [
        'default-src', 'script-src', 'style-src', 'img-src',
        'connect-src', 'font-src', 'object-src', 'media-src',
        'frame-ancestors', 'base-uri', 'form-action',
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
        logger.info("Starting CSP Analysis scan...")
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
            
            await self._analyze_csp(session, base_url)
        
        logger.info(f"CSP analysis complete. Found {len(self.results)} issues")
        return self.results
    
    async def _analyze_csp(self, session: aiohttp.ClientSession, url: str):
        """Analyze CSP header"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                csp = response.headers.get('Content-Security-Policy')
                csp_report = response.headers.get('Content-Security-Policy-Report-Only')
                
                if not csp and not csp_report:
                    result = ScanResult(
                        id=f"CSP-MISSING-{len(self.results)+1}",
                        category="A05:2021 - Security Misconfiguration",
                        severity="high",
                        title="Missing Content-Security-Policy",
                        description="No CSP header present. Site vulnerable to XSS.",
                        url=url,
                        method="GET",
                        remediation="Implement CSP: default-src 'self'; script-src 'self'",
                        cwe_id="CWE-1021",
                        reasoning="CSP is critical for XSS prevention"
                    )
                    self.results.append(result)
                    return
                
                # Analyze CSP
                csp_to_analyze = csp or csp_report
                self._parse_and_analyze(url, csp_to_analyze, report_only=bool(csp_report and not csp))
                
        except Exception as e:
            logger.debug(f"CSP analysis error: {e}")
    
    def _parse_and_analyze(self, url: str, csp: str, report_only: bool = False):
        """Parse and analyze CSP directives"""
        
        # Check if only report-only
        if report_only:
            result = ScanResult(
                id=f"CSP-REPORT-ONLY-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="medium",
                title="CSP in Report-Only Mode",
                description="CSP is only reporting, not enforcing policies.",
                url=url,
                method="GET",
                evidence="Content-Security-Policy-Report-Only header used",
                remediation="Use Content-Security-Policy header to enforce policy.",
                cwe_id="CWE-1021",
                reasoning="Report-only mode doesn't block attacks"
            )
            self.results.append(result)
        
        # Parse directives
        directives = {}
        for directive in csp.split(';'):
            directive = directive.strip()
            if directive:
                parts = directive.split(None, 1)
                if len(parts) == 2:
                    directives[parts[0].lower()] = parts[1]
                elif len(parts) == 1:
                    directives[parts[0].lower()] = ''
        
        # Check for dangerous values
        for directive, value in directives.items():
            for dangerous, (severity, desc) in self.DANGEROUS_DIRECTIVES.items():
                if dangerous in value:
                    result = ScanResult(
                        id=f"CSP-WEAK-{len(self.results)+1}",
                        category="A05:2021 - Security Misconfiguration",
                        severity=severity,
                        title=f"Weak CSP: {dangerous} in {directive}",
                        description=desc,
                        url=url,
                        method="GET",
                        parameter=directive,
                        evidence=f"{directive} {value}",
                        remediation=f"Remove '{dangerous}' from {directive}.",
                        cwe_id="CWE-1021",
                        reasoning=f"'{dangerous}' weakens CSP protection"
                    )
                    self.results.append(result)
        
        # Check for missing important directives
        if 'default-src' not in directives and 'script-src' not in directives:
            result = ScanResult(
                id=f"CSP-INCOMPLETE-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="medium",
                title="Incomplete CSP: Missing default-src or script-src",
                description="CSP doesn't restrict script sources.",
                url=url,
                method="GET",
                evidence=f"Directives: {list(directives.keys())}",
                remediation="Add default-src or script-src directive.",
                cwe_id="CWE-1021",
                reasoning="Scripts can be loaded from any source"
            )
            self.results.append(result)
        
        # Check for missing frame-ancestors
        if 'frame-ancestors' not in directives:
            result = ScanResult(
                id=f"CSP-FRAMING-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="low",
                title="CSP Missing frame-ancestors",
                description="CSP doesn't prevent framing (clickjacking).",
                url=url,
                method="GET",
                remediation="Add frame-ancestors 'self' to CSP.",
                cwe_id="CWE-1021",
                reasoning="Site can be framed by attackers"
            )
            self.results.append(result)


class CookieSecurityScanner:
    """
    Scans for cookie security issues
    OWASP A05:2021 - Security Misconfiguration
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
        logger.info("Starting Cookie Security scan...")
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
            
            await self._check_cookies(session, base_url)
        
        logger.info(f"Cookie security scan complete. Found {len(self.results)} issues")
        return self.results
    
    async def _check_cookies(self, session: aiohttp.ClientSession, url: str):
        """Check cookie security attributes"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                # Get all Set-Cookie headers
                set_cookies = response.headers.getall('Set-Cookie', [])
                
                for cookie_header in set_cookies:
                    self._analyze_cookie(url, cookie_header)
                    
        except Exception as e:
            logger.debug(f"Cookie check error: {e}")
    
    def _analyze_cookie(self, url: str, cookie_header: str):
        """Analyze individual cookie for security issues"""
        
        cookie_lower = cookie_header.lower()
        
        # Extract cookie name
        cookie_name = cookie_header.split('=')[0].strip()
        
        # Sensitive cookie names
        sensitive_cookies = ['session', 'auth', 'token', 'jwt', 'user', 'login', 'id']
        is_sensitive = any(s in cookie_name.lower() for s in sensitive_cookies)
        
        # Check for missing HttpOnly
        if 'httponly' not in cookie_lower:
            severity = 'high' if is_sensitive else 'medium'
            result = ScanResult(
                id=f"COOKIE-HTTPONLY-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity=severity,
                title=f"Cookie Missing HttpOnly: {cookie_name}",
                description="Cookie accessible via JavaScript, vulnerable to XSS theft.",
                url=url,
                method="GET",
                parameter=cookie_name,
                evidence=f"Cookie: {cookie_header[:100]}",
                remediation="Add HttpOnly flag to cookie.",
                cwe_id="CWE-1004",
                reasoning="XSS can steal cookie without HttpOnly"
            )
            self.results.append(result)
        
        # Check for missing Secure flag
        if url.startswith('https') and 'secure' not in cookie_lower:
            severity = 'high' if is_sensitive else 'medium'
            result = ScanResult(
                id=f"COOKIE-SECURE-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity=severity,
                title=f"Cookie Missing Secure Flag: {cookie_name}",
                description="Cookie can be sent over unencrypted HTTP.",
                url=url,
                method="GET",
                parameter=cookie_name,
                evidence=f"Cookie: {cookie_header[:100]}",
                remediation="Add Secure flag to cookie.",
                cwe_id="CWE-614",
                reasoning="Cookie vulnerable to interception over HTTP"
            )
            self.results.append(result)
        
        # Check for missing SameSite
        if 'samesite' not in cookie_lower:
            result = ScanResult(
                id=f"COOKIE-SAMESITE-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="medium" if is_sensitive else "low",
                title=f"Cookie Missing SameSite: {cookie_name}",
                description="Cookie may be vulnerable to CSRF attacks.",
                url=url,
                method="GET",
                parameter=cookie_name,
                evidence=f"Cookie: {cookie_header[:100]}",
                remediation="Add SameSite=Strict or SameSite=Lax.",
                cwe_id="CWE-1275",
                reasoning="Without SameSite, cookie sent with cross-site requests"
            )
            self.results.append(result)
        
        # Check for SameSite=None without Secure
        if 'samesite=none' in cookie_lower and 'secure' not in cookie_lower:
            result = ScanResult(
                id=f"COOKIE-SAMESITE-NONE-{len(self.results)+1}",
                category="A05:2021 - Security Misconfiguration",
                severity="high",
                title=f"SameSite=None Without Secure: {cookie_name}",
                description="SameSite=None requires Secure flag.",
                url=url,
                method="GET",
                parameter=cookie_name,
                evidence=f"Cookie: {cookie_header[:100]}",
                remediation="Add Secure flag when using SameSite=None.",
                cwe_id="CWE-1275",
                reasoning="Invalid cookie configuration"
            )
            self.results.append(result)
