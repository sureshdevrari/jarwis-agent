"""
Jarwis AGI Pen Test - Host Header Injection Scanner
Detects Host Header vulnerabilities (A05:2021 - Security Misconfiguration)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
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


class HostHeaderInjectionScanner:
    """
    Scans for Host Header Injection vulnerabilities
    OWASP A05:2021 - Security Misconfiguration
    CWE-644: Improper Neutralization of HTTP Headers
    
    Attack vectors:
    - Password reset poisoning
    - Cache poisoning
    - Access to internal hosts
    - Web cache deception
    - SSRF via Host header
    """
    
    # Headers to test for host injection
    HOST_HEADERS = [
        'Host',
        'X-Forwarded-Host',
        'X-Host',
        'X-Forwarded-Server',
        'X-HTTP-Host-Override',
        'Forwarded',
        'X-Original-URL',
        'X-Rewrite-URL',
    ]
    
    # Payloads for host header injection
    HOST_PAYLOADS = [
        ('evil.com', 'External domain'),
        ('evil.com:443', 'External domain with port'),
        ('evil.com:80', 'External domain HTTP port'),
        ('localhost', 'Localhost'),
        ('127.0.0.1', 'Localhost IP'),
        ('internal.company.com', 'Internal hostname'),
        ('169.254.169.254', 'AWS metadata IP'),
        ('{original}.evil.com', 'Subdomain of attacker'),
        ('evil.com#{original}', 'Fragment injection'),
        ('evil.com?{original}', 'Query injection'),
        ('evil.com/{original}', 'Path injection'),
        ('{original}@evil.com', 'Username injection'),
        ('{original}:password@evil.com', 'Credentials injection'),
        ('{original}%00.evil.com', 'Null byte injection'),
        ('{original}%0d%0aX-Injected: header', 'CRLF injection'),
    ]
    
    # Endpoints likely to use Host header
    PASSWORD_RESET_ENDPOINTS = [
        '/password/reset', '/forgot-password', '/reset-password',
        '/password-reset', '/forgot_password', '/reset_password',
        '/account/reset', '/user/reset', '/auth/reset',
        '/password/forgot', '/password/recover', '/recover',
        '/api/password/reset', '/api/forgot-password',
        '/api/v1/password/reset', '/api/v2/password/reset',
    ]
    
    EMAIL_ENDPOINTS = [
        '/contact', '/email', '/send-email', '/sendmail',
        '/invite', '/share', '/send-invite', '/email-friend',
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.browser = None
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Host Header Injection scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            logger.warning("No target URL configured")
            return self.results
        
        parsed = urlparse(base_url)
        original_host = parsed.netloc
        
        # Collect URLs to test
        urls_to_test = set()
        urls_to_test.add(base_url)
        
        # Add password reset endpoints (prime target for host injection)
        for endpoint in self.PASSWORD_RESET_ENDPOINTS:
            urls_to_test.add(urljoin(base_url, endpoint))
        
        # Add email endpoints
        for endpoint in self.EMAIL_ENDPOINTS:
            urls_to_test.add(urljoin(base_url, endpoint))
        
        # Add discovered endpoints
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints[:30]:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if url:
                    urls_to_test.add(url)
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url in urls_to_test:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    await self._test_host_injection(session, url, original_host)
                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")
        
        logger.info(f"Host Header scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_host_injection(self, session: aiohttp.ClientSession, url: str, original_host: str):
        """Test URL for host header injection"""
        
        # Get baseline response
        try:
            baseline_headers = {**self.DEFAULT_HEADERS, 'Host': original_host}
            async with session.get(url, headers=baseline_headers) as baseline_resp:
                baseline_body = await baseline_resp.text()
                baseline_status = baseline_resp.status
        except Exception:
            return
        
        # Test each header with payloads
        for header_name in self.HOST_HEADERS:
            for payload_template, description in self.HOST_PAYLOADS[:8]:  # Limit payloads
                try:
                    # Replace {original} with actual host
                    payload = payload_template.replace('{original}', original_host)
                    
                    # Build test headers
                    test_headers = {**self.DEFAULT_HEADERS}
                    
                    if header_name == 'Host':
                        test_headers['Host'] = payload
                    elif header_name == 'Forwarded':
                        test_headers['Forwarded'] = f'host={payload}'
                    else:
                        test_headers['Host'] = original_host  # Keep original
                        test_headers[header_name] = payload
                    
                    async with session.get(url, headers=test_headers) as response:
                        status = response.status
                        body = await response.text()
                        resp_headers = dict(response.headers)
                        
                        # Check for host injection indicators
                        vuln_found = False
                        evidence = ""
                        severity = "info"
                        
                        # Check if injected host appears in response
                        evil_domain = payload.split('/')[0].split('@')[-1].split(':')[0]
                        if evil_domain in body and evil_domain != original_host:
                            vuln_found = True
                            evidence = f"Injected host '{evil_domain}' reflected in response body"
                            severity = "high"
                        
                        # Check for host in links/redirects
                        link_patterns = [
                            rf'href=["\']https?://{re.escape(evil_domain)}[^"\']*["\']',
                            rf'action=["\']https?://{re.escape(evil_domain)}[^"\']*["\']',
                            rf'src=["\']https?://{re.escape(evil_domain)}[^"\']*["\']',
                        ]
                        for pattern in link_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                vuln_found = True
                                evidence = f"Injected host in HTML attribute: {pattern}"
                                severity = "high"
                                break
                        
                        # Check Location header for redirect poisoning
                        location = resp_headers.get('Location', '')
                        if evil_domain in location:
                            vuln_found = True
                            evidence = f"Injected host in redirect: {location}"
                            severity = "critical"
                        
                        # Check for password reset link poisoning indicators
                        reset_patterns = [
                            rf'password.+reset.+{re.escape(evil_domain)}',
                            rf'reset.+link.+{re.escape(evil_domain)}',
                            rf'{re.escape(evil_domain)}.+token',
                            rf'verify.+{re.escape(evil_domain)}',
                        ]
                        for pattern in reset_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                vuln_found = True
                                evidence = f"Password reset link poisoning detected"
                                severity = "critical"
                                break
                        
                        # Check for cache control headers (cache poisoning)
                        cache_control = resp_headers.get('Cache-Control', '')
                        if vuln_found and 'public' in cache_control.lower():
                            evidence += " | Response is cacheable (cache poisoning risk)"
                            severity = "critical"
                        
                        if vuln_found:
                            result = ScanResult(
                                id=f"HOST-INJECT-{len(self.results)+1}",
                                category="A05:2021 - Security Misconfiguration",
                                severity=severity,
                                title=f"Host Header Injection via {header_name}",
                                description=f"The application trusts the {header_name} header and uses it to generate URLs or links. This can lead to password reset poisoning, cache poisoning, or SSRF.",
                                url=url,
                                method="GET",
                                parameter=header_name,
                                evidence=evidence,
                                remediation="Configure the application to use a static host value. Do not trust client-supplied Host headers. Use a whitelist of allowed hosts.",
                                cwe_id="CWE-644",
                                poc=f"curl -H '{header_name}: {payload}' '{url}'",
                                reasoning=f"Injected host ({payload}) reflected/used by application. Attack: {description}",
                                request_data=f"GET {url}\n{header_name}: {payload}",
                                response_data=f"Status: {status}\n{evidence}"
                            )
                            self.results.append(result)
                            logger.info(f"Found Host Injection: {header_name} on {url}")
                            return  # Found vuln, move to next URL
                            
                except Exception as e:
                    logger.debug(f"Error testing header: {e}")


class CRLFInjectionScanner:
    """
    Scans for CRLF (Carriage Return Line Feed) Injection
    OWASP A03:2021 - Injection
    CWE-93: CRLF Injection
    
    Can lead to:
    - HTTP Response Splitting
    - Header injection
    - XSS via header injection
    - Cache poisoning
    - Session fixation
    """
    
    # CRLF payloads
    CRLF_PAYLOADS = [
        # Basic CRLF
        ('%0d%0aX-Injected: header', 'URL encoded CRLF'),
        ('%0aX-Injected: header', 'LF only'),
        ('%0dX-Injected: header', 'CR only'),
        ('\r\nX-Injected: header', 'Raw CRLF'),
        
        # Double encoding
        ('%250d%250aX-Injected: header', 'Double encoded CRLF'),
        
        # Unicode encoding
        ('%E5%98%8A%E5%98%8DX-Injected: header', 'Unicode CRLF'),
        
        # Header injection for XSS
        ('%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert(1)</script>', 'XSS via CRLF'),
        
        # Session fixation
        ('%0d%0aSet-Cookie: session=malicious', 'Cookie injection'),
        
        # Cache poisoning
        ('%0d%0aX-Cache-Poisoned: true', 'Cache header injection'),
        
        # Location header
        ('%0d%0aLocation: https://evil.com', 'Redirect injection'),
    ]
    
    # Parameters to test
    INJECTABLE_PARAMS = [
        'url', 'redirect', 'return', 'next', 'path', 'callback',
        'file', 'page', 'name', 'title', 'message', 'content',
        'ref', 'referrer', 'source', 'lang', 'language', 'locale',
        'id', 'item', 'product', 'category', 'search', 'q',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.browser = None
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting CRLF Injection scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        urls_to_test = [base_url]
        
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints[:30]:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if url:
                    urls_to_test.append(url)
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url in urls_to_test:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    await self._test_crlf(session, url)
                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")
        
        logger.info(f"CRLF scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_crlf(self, session: aiohttp.ClientSession, url: str):
        """Test URL for CRLF injection"""
        parsed = urlparse(url)
        
        for param in self.INJECTABLE_PARAMS[:10]:
            for payload, description in self.CRLF_PAYLOADS[:5]:
                try:
                    # Build test URL
                    if '?' in url:
                        test_url = f"{url}&{param}={payload}"
                    else:
                        test_url = f"{url}?{param}={payload}"
                    
                    async with session.get(test_url, allow_redirects=False) as response:
                        status = response.status
                        headers = dict(response.headers)
                        
                        # Check if our injected header appears
                        if 'X-Injected' in headers:
                            result = ScanResult(
                                id=f"CRLF-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="high",
                                title=f"CRLF Injection in {param}",
                                description="The application is vulnerable to CRLF injection allowing HTTP response splitting and header injection.",
                                url=test_url,
                                method="GET",
                                parameter=param,
                                evidence=f"Injected header 'X-Injected' found in response",
                                remediation="Sanitize all user input used in HTTP headers. Remove or encode CR (\\r) and LF (\\n) characters.",
                                cwe_id="CWE-93",
                                poc=f"curl -v '{test_url}'",
                                reasoning=f"CRLF injection successful via {description}"
                            )
                            self.results.append(result)
                            return
                        
                        # Check for Set-Cookie injection
                        if 'Set-Cookie' in headers:
                            cookie = headers.get('Set-Cookie', '')
                            if 'malicious' in cookie or 'session=malicious' in cookie:
                                result = ScanResult(
                                    id=f"CRLF-{len(self.results)+1}",
                                    category="A03:2021 - Injection",
                                    severity="critical",
                                    title=f"CRLF Cookie Injection in {param}",
                                    description="CRLF injection allows setting arbitrary cookies (session fixation).",
                                    url=test_url,
                                    method="GET",
                                    parameter=param,
                                    evidence=f"Injected cookie found: {cookie}",
                                    remediation="Sanitize CR/LF characters from all user input.",
                                    cwe_id="CWE-93",
                                    poc=f"curl -v '{test_url}'",
                                    reasoning="Session fixation via CRLF cookie injection"
                                )
                                self.results.append(result)
                                return
                            
                except Exception as e:
                    logger.debug(f"CRLF test error: {e}")
