"""
Jarwis AGI Pen Test - Open Redirect Scanner
Detects Open Redirect vulnerabilities (A01:2021 - Broken Access Control)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse, urljoin, quote
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


class OpenRedirectScanner:
    """
    Scans for Open Redirect vulnerabilities
    OWASP A01:2021 - Broken Access Control
    CWE-601: URL Redirection to Untrusted Site ('Open Redirect')
    
    Based on Web Hacking 101 real-world bug bounty reports:
    - Shopify login redirect bypass
    - HackerOne redirect vulnerabilities
    - Google OAuth redirect issues
    """
    
    # Parameters commonly used for redirects
    REDIRECT_PARAMS = [
        'url', 'redirect', 'redirect_url', 'redirect_uri', 'redir', 'return',
        'return_url', 'return_to', 'returnTo', 'returnUrl', 'next', 'next_url',
        'target', 'target_url', 'dest', 'destination', 'go', 'goto', 'link',
        'linkurl', 'out', 'out_url', 'forward', 'forward_url', 'to', 'toUrl',
        'continue', 'continue_url', 'continueTo', 'ref', 'referer', 'referrer',
        'back', 'back_url', 'backUrl', 'callback', 'callback_url', 'cb',
        'jump', 'jump_url', 'path', 'path_url', 'uri', 'u', 'r', 'n',
        'RelayState', 'SAMLRequest', 'SAMLResponse', 'service', 'targetUrl',
        'checkout_url', 'login_url', 'logout_url', 'image_url', 'file_url',
        'site', 'site_url', 'view', 'page', 'feed', 'host', 'port',
        'data', 'request', 'file', 'document', 'folder', 'root', 'pg',
        'window', 'q', 'load_url', 'error_url', 'success_url', 'fail_url'
    ]
    
    # Payloads for testing open redirects - 2025 bypass techniques
    REDIRECT_PAYLOADS = [
        # Basic external domain
        ('https://evil.com', 'Basic external redirect'),
        ('http://evil.com', 'HTTP external redirect'),
        ('//evil.com', 'Protocol-relative redirect'),
        
        # URL encoding bypasses
        ('%2F%2Fevil.com', 'URL encoded double slash'),
        ('/%2F/evil.com', 'Mixed encoding'),
        ('/\\/evil.com', 'Backslash bypass'),
        
        # @ symbol bypasses (username in URL)
        ('https://trusted.com@evil.com', 'Username in URL bypass'),
        ('https://trusted.com%40evil.com', 'Encoded @ bypass'),
        ('//trusted.com@evil.com', 'Protocol-relative @ bypass'),
        
        # Dot bypasses
        ('https://evil.com/.trusted.com', 'Dot prefix bypass'),
        ('https://evil.com%00.trusted.com', 'Null byte bypass'),
        
        # Subdomain confusion
        ('https://trusted.com.evil.com', 'Subdomain of attacker'),
        ('https://trustedcom.evil.com', 'Missing dot subdomain'),
        
        # CRLF injection in redirect
        ('https://evil.com%0d%0aLocation:%20https://evil.com', 'CRLF injection'),
        
        # Data URI (for JS execution)
        ('data:text/html,<script>alert(1)</script>', 'Data URI XSS'),
        
        # JavaScript protocol
        ('javascript:alert(1)', 'JavaScript protocol'),
        ('javascript://evil.com/%0aalert(1)', 'JS protocol bypass'),
        
        # Path-based confusion
        ('/\\evil.com', 'Backslash before domain'),
        ('////evil.com', 'Multiple slashes'),
        ('\\/\\/evil.com', 'Escaped slashes'),
        
        # Case manipulation
        ('HTTPS://EVIL.COM', 'Uppercase bypass'),
        ('hTtPs://eViL.cOm', 'Mixed case bypass'),
        
        # Whitespace bypasses
        (' https://evil.com', 'Leading space'),
        ('https://evil.com ', 'Trailing space'),
        ('\thttps://evil.com', 'Tab character'),
        ('%09https://evil.com', 'URL encoded tab'),
        ('%20https://evil.com', 'URL encoded space'),
        
        # Unicode bypasses
        ('https://evil。com', 'Unicode dot'),
        ('https://ⓔⓥⓘⓛ.com', 'Unicode letters'),
        
        # Fragment abuse
        ('https://trusted.com#@evil.com', 'Fragment @ bypass'),
        
        # Port confusion
        ('https://evil.com:443', 'Port in URL'),
        ('https://evil.com:80', 'HTTP port on HTTPS'),
        
        # IPv6/IPv4 confusion
        ('http://[::ffff:evil.com]', 'IPv6 mapped'),
        
        # Double URL encoding
        ('%252F%252Fevil.com', 'Double encoded slashes'),
    ]
    
    # Endpoints commonly vulnerable to open redirect
    VULNERABLE_ENDPOINTS = [
        '/login', '/signin', '/sign-in', '/auth', '/authenticate',
        '/logout', '/signout', '/sign-out', 
        '/register', '/signup', '/sign-up',
        '/oauth', '/oauth2', '/authorize', '/callback',
        '/sso', '/saml', '/cas', '/openid',
        '/redirect', '/go', '/out', '/external',
        '/link', '/url', '/redir', '/jump',
        '/return', '/next', '/continue',
        '/verify', '/confirm', '/validate',
        '/password/reset', '/forgot-password', '/reset-password',
        '/email/verify', '/account/verify',
        '/checkout', '/payment', '/pay', '/cart'
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
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
        """Main scan method - tests for open redirects"""
        logger.info("Starting Open Redirect vulnerability scan...")
        self.results = []
        
        # Get target URL and discovered endpoints
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            logger.warning("No target URL configured for Open Redirect scan")
            return self.results
        
        # Parse base URL
        parsed = urlparse(base_url)
        base_domain = parsed.netloc
        
        # Collect URLs to test from context
        urls_to_test = set()
        urls_to_test.add(base_url)
        
        # Add discovered endpoints from crawler
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints:
                if isinstance(endpoint, dict):
                    urls_to_test.add(endpoint.get('url', ''))
                else:
                    urls_to_test.add(str(endpoint))
        
        # Add common vulnerable endpoints
        for endpoint in self.VULNERABLE_ENDPOINTS:
            urls_to_test.add(urljoin(base_url, endpoint))
        
        # Create connector for HTTPS
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            headers=self.DEFAULT_HEADERS,
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Test each URL
            for url in urls_to_test:
                if not url:
                    continue
                    
                try:
                    # Rate limiting
                    await asyncio.sleep(1 / self.rate_limit)
                    
                    # Test with different parameters
                    await self._test_url_for_redirect(session, url, base_domain)
                    
                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")
        
        logger.info(f"Open Redirect scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_url_for_redirect(self, session: aiohttp.ClientSession, url: str, base_domain: str):
        """Test a URL for open redirect vulnerabilities"""
        parsed = urlparse(url)
        
        # Test existing parameters
        if parsed.query:
            params = parse_qs(parsed.query)
            for param_name in params:
                if any(rp in param_name.lower() for rp in self.REDIRECT_PARAMS):
                    await self._test_parameter(session, url, param_name, base_domain)
        
        # Test by adding redirect parameters
        for param_name in self.REDIRECT_PARAMS[:20]:  # Limit to top 20
            await self._test_parameter(session, url, param_name, base_domain)
    
    async def _test_parameter(self, session: aiohttp.ClientSession, url: str, param_name: str, base_domain: str):
        """Test a specific parameter for open redirect"""
        parsed = urlparse(url)
        
        for payload, description in self.REDIRECT_PAYLOADS[:15]:  # Limit payloads per param
            try:
                # Build test URL
                existing_params = parse_qs(parsed.query)
                existing_params[param_name] = [payload]
                new_query = urlencode(existing_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                # Send request without following redirects
                async with session.get(test_url, allow_redirects=False) as response:
                    status = response.status
                    headers = response.headers
                    
                    # Check for redirect response
                    if status in [301, 302, 303, 307, 308]:
                        location = headers.get('Location', '')
                        
                        if self._is_external_redirect(location, base_domain, payload):
                            # Found open redirect!
                            result = ScanResult(
                                id=f"OPEN-REDIRECT-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="medium",
                                title=f"Open Redirect via {param_name} parameter",
                                description=f"The application redirects to an external domain when the {param_name} parameter is manipulated. This can be used for phishing attacks or OAuth token theft.",
                                url=test_url,
                                method="GET",
                                parameter=param_name,
                                evidence=f"Redirect to: {location}",
                                remediation="Validate redirect URLs against a whitelist of allowed domains. Never redirect to URLs provided entirely by user input.",
                                cwe_id="CWE-601",
                                poc=f"curl -I '{test_url}'",
                                reasoning=f"Server returned {status} redirect to external location: {location}. Bypass technique: {description}",
                                request_data=f"GET {test_url}",
                                response_data=f"HTTP {status}\nLocation: {location}"
                            )
                            self.results.append(result)
                            logger.info(f"Found Open Redirect: {param_name} -> {location}")
                            return  # Found vuln for this param, move on
                    
                    # Also check for meta refresh or JavaScript redirects in body
                    elif status == 200:
                        body = await response.text()
                        
                        # Check for meta refresh
                        meta_match = re.search(
                            r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\'][\d;]*url=([^"\']+)["\']',
                            body, re.IGNORECASE
                        )
                        if meta_match:
                            redirect_url = meta_match.group(1)
                            if self._is_external_redirect(redirect_url, base_domain, payload):
                                result = ScanResult(
                                    id=f"OPEN-REDIRECT-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="medium",
                                    title=f"Open Redirect via Meta Refresh ({param_name})",
                                    description=f"The application uses meta refresh to redirect to an external domain.",
                                    url=test_url,
                                    method="GET",
                                    parameter=param_name,
                                    evidence=f"Meta refresh to: {redirect_url}",
                                    remediation="Validate redirect URLs against a whitelist.",
                                    cwe_id="CWE-601",
                                    poc=f"curl '{test_url}'",
                                    reasoning=f"Meta refresh redirect to external domain detected"
                                )
                                self.results.append(result)
                                return
                        
                        # Check for JavaScript redirect
                        js_patterns = [
                            r'window\.location\s*=\s*["\']([^"\']+)["\']',
                            r'location\.href\s*=\s*["\']([^"\']+)["\']',
                            r'location\.replace\s*\(["\']([^"\']+)["\']\)',
                        ]
                        for pattern in js_patterns:
                            js_match = re.search(pattern, body, re.IGNORECASE)
                            if js_match:
                                redirect_url = js_match.group(1)
                                if self._is_external_redirect(redirect_url, base_domain, payload):
                                    result = ScanResult(
                                        id=f"OPEN-REDIRECT-{len(self.results)+1}",
                                        category="A01:2021 - Broken Access Control",
                                        severity="medium",
                                        title=f"Open Redirect via JavaScript ({param_name})",
                                        description=f"The application uses JavaScript to redirect to an external domain.",
                                        url=test_url,
                                        method="GET",
                                        parameter=param_name,
                                        evidence=f"JavaScript redirect to: {redirect_url}",
                                        remediation="Validate redirect URLs against a whitelist.",
                                        cwe_id="CWE-601",
                                        poc=f"curl '{test_url}'",
                                        reasoning=f"JavaScript redirect to external domain detected"
                                    )
                                    self.results.append(result)
                                    return
                            
            except asyncio.TimeoutError:
                pass
            except Exception as e:
                logger.debug(f"Error testing payload: {e}")
    
    def _is_external_redirect(self, location: str, base_domain: str, payload: str) -> bool:
        """Check if redirect location is external"""
        if not location:
            return False
        
        # Normalize location
        location = location.strip()
        
        # Check if it starts with our payload
        if 'evil.com' in location.lower():
            return True
        
        # Parse location URL
        try:
            parsed = urlparse(location)
            redirect_domain = parsed.netloc.lower()
            
            # If no netloc, might be protocol-relative
            if not redirect_domain and location.startswith('//'):
                redirect_domain = location[2:].split('/')[0].lower()
            
            # Check if redirect is to external domain
            if redirect_domain and redirect_domain != base_domain.lower():
                # Make sure it's not just a path
                if '.' in redirect_domain:
                    return True
                    
        except Exception:
            pass
        
        return False
