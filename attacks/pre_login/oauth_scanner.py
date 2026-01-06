"""
Jarwis AGI Pen Test - OAuth Security Scanner
Tests for OAuth/SSO implementation vulnerabilities:
- OAuth state parameter bypass (CSRF)
- Open redirect via redirect_uri
- Token leakage via referrer
- Insufficient redirect_uri validation
- Authorization code interception
- PKCE bypass attempts
- OAuth misconfiguration detection

OWASP Category: A07:2021 - Identification and Authentication Failures
"""

import asyncio
import logging
import re
import secrets
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
import aiohttp

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


class OAuthSecurityScanner:
    """
    Scans for OAuth/SSO implementation vulnerabilities
    
    Based on OAuth security best practices and common misconfigurations:
    1. Missing/weak state parameter (CSRF)
    2. Open redirect via redirect_uri manipulation
    3. Redirect_uri validation bypass
    4. Authorization code leakage
    5. Missing PKCE for mobile/SPA
    6. Token exposure in URLs/logs
    """
    
    # Common OAuth endpoints
    OAUTH_ENDPOINTS = [
        '/oauth/authorize',
        '/oauth2/authorize',
        '/auth/authorize',
        '/authorize',
        '/api/oauth/authorize',
        '/connect/authorize',
        '/oauth/auth',
        '/api/auth/oauth',
        '/auth/google',
        '/auth/github',
        '/auth/microsoft',
        '/oauth/google',
        '/oauth/github',
        '/oauth/microsoft',
        '/api/oauth/google',
        '/api/oauth/github',
        '/api/oauth/microsoft',
        '/login/oauth/authorize',
    ]
    
    # OAuth callback endpoints
    CALLBACK_ENDPOINTS = [
        '/oauth/callback',
        '/oauth2/callback',
        '/auth/callback',
        '/callback',
        '/api/oauth/callback',
        '/oauth/google/callback',
        '/oauth/github/callback',
        '/oauth/microsoft/callback',
        '/api/oauth/google/callback',
        '/api/oauth/github/callback',
        '/api/oauth/microsoft/callback',
        '/login/oauth2/code',
    ]
    
    # Redirect URI bypass payloads
    REDIRECT_BYPASS_PAYLOADS = [
        # Path traversal
        '/../evil.com',
        '/..;/evil.com',
        '/.evil.com',
        '/%2e%2e/evil.com',
        # Subdomain confusion
        '.evil.com',
        '@evil.com',
        # URL parsing tricks
        '//evil.com',
        '///evil.com',
        '////evil.com',
        '\\/evil.com',
        '/\\evil.com',
        # Parameter pollution
        '?redirect=https://evil.com',
        '#@evil.com',
        # Scheme tricks
        'javascript:alert(1)',
        'data:text/html,<script>alert(1)</script>',
        # Null byte
        '%00evil.com',
        # Unicode tricks
        '/evilãEUR‚com',
        '/evil%E3%80%82com',
    ]
    
    # Evil domains for testing
    EVIL_DOMAINS = [
        'evil.com',
        'attacker.com',
        'burpcollaborator.net',
        'ngrok.io',
        'localhost.evil.com',
    ]

    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    async def scan(self) -> List[ScanResult]:
        """Run all OAuth security tests"""
        logger.info("Starting OAuth Security Scanner...")
        
        endpoints = getattr(self.context, 'endpoints', []) or []
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url and endpoints:
            parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found for OAuth security scanning")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            await asyncio.gather(
                self._test_state_parameter(session, base_url),
                self._test_redirect_uri_bypass(session, base_url),
                self._test_open_redirect(session, base_url),
                self._test_token_exposure(session, base_url),
                self._test_pkce_missing(session, base_url),
                self._test_oauth_misconfiguration(session, base_url),
                return_exceptions=True
            )
        
        logger.info(f"OAuth Security Scanner completed. Found {len(self.results)} issues.")
        return self.results

    async def _test_state_parameter(self, session: aiohttp.ClientSession, base_url: str):
        """Test for missing or weak OAuth state parameter (CSRF protection)"""
        
        for oauth_ep in self.OAUTH_ENDPOINTS:
            url = urljoin(base_url, oauth_ep)
            
            try:
                async with session.get(url, allow_redirects=False) as response:
                    if response.status == 404:
                        continue
                    
                    # Check if this is an OAuth initiation endpoint
                    if response.status in [200, 302, 307]:
                        # Get redirect location if present
                        location = response.headers.get('Location', '')
                        resp_text = await response.text()
                        
                        # Check for state parameter in redirect or response
                        has_state = False
                        
                        if location:
                            parsed = urlparse(location)
                            params = parse_qs(parsed.query)
                            has_state = 'state' in params
                            
                            # Test 1: Check if state is missing
                            if not has_state:
                                self.results.append(ScanResult(
                                    id=f"OAUTH-NO-STATE-{len(self.results)}",
                                    category="A07:2021",
                                    severity="high",
                                    title="OAuth Missing State Parameter",
                                    description="OAuth flow does not include state parameter, vulnerable to CSRF attacks",
                                    url=url,
                                    method="GET",
                                    parameter="state",
                                    evidence=f"Redirect to OAuth provider lacks state: {location[:100]}...",
                                    remediation="Always include a cryptographically random state parameter. Validate it on callback.",
                                    cwe_id="CWE-352",
                                    poc=f"OAuth flow at {url} has no CSRF protection",
                                    reasoning="Missing state parameter allows attacker to force victim to authenticate with attacker's account"
                                ))
                            else:
                                # Test 2: Check if state is predictable/weak
                                state_value = params['state'][0]
                                if self._is_weak_state(state_value):
                                    self.results.append(ScanResult(
                                        id=f"OAUTH-WEAK-STATE-{len(self.results)}",
                                        category="A07:2021",
                                        severity="medium",
                                        title="OAuth Weak State Parameter",
                                        description=f"OAuth state parameter appears predictable: {state_value[:20]}...",
                                        url=url,
                                        method="GET",
                                        parameter="state",
                                        evidence=f"State value: {state_value}",
                                        remediation="Use cryptographically secure random values (256 bits) for state parameter",
                                        cwe_id="CWE-330",
                                        poc="State parameter can be predicted or brute-forced",
                                        reasoning="Weak state values can be guessed, defeating CSRF protection"
                                    ))
                        
                        # Check for state in hidden form fields
                        if 'state' not in resp_text.lower() and 'oauth' in resp_text.lower():
                            # OAuth form without state
                            pass  # Already covered by redirect check
                            
            except Exception as e:
                logger.debug(f"OAuth state test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    def _is_weak_state(self, state: str) -> bool:
        """Check if state parameter is weak/predictable"""
        # Too short
        if len(state) < 16:
            return True
        
        # Sequential numbers
        if state.isdigit():
            return True
        
        # Timestamp-like
        if re.match(r'^\d{10,13}$', state):
            return True
        
        # Common patterns
        weak_patterns = ['state', 'csrf', 'token', '12345']
        if any(p in state.lower() for p in weak_patterns):
            return True
        
        return False

    async def _test_redirect_uri_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test for redirect_uri validation bypass"""
        
        parsed_base = urlparse(base_url)
        target_domain = parsed_base.netloc
        
        for oauth_ep in self.OAUTH_ENDPOINTS:
            url = urljoin(base_url, oauth_ep)
            
            # First get the legitimate OAuth URL
            try:
                async with session.get(url, allow_redirects=False) as response:
                    if response.status == 404:
                        continue
                    
                    location = response.headers.get('Location', '')
                    if not location:
                        continue
            except:
                continue
            
            # Try bypass payloads
            for bypass in self.REDIRECT_BYPASS_PAYLOADS:
                for evil_domain in self.EVIL_DOMAINS[:2]:
                    # Construct malicious redirect_uri
                    test_redirect = f"{base_url}{bypass.replace('evil.com', evil_domain)}"
                    
                    params = {
                        'redirect_uri': test_redirect,
                        'response_type': 'code',
                        'client_id': 'test',
                        'scope': 'openid profile email',
                        'state': secrets.token_urlsafe(16)
                    }
                    
                    try:
                        test_url = f"{url}?{urlencode(params)}"
                        async with session.get(test_url, allow_redirects=False) as response:
                            # Check if malicious redirect_uri was accepted
                            if response.status in [302, 307]:
                                redirect_location = response.headers.get('Location', '')
                                
                                # Check if evil domain appears in redirect
                                if evil_domain in redirect_location or bypass in redirect_location:
                                    self.results.append(ScanResult(
                                        id=f"OAUTH-REDIRECT-BYPASS-{len(self.results)}",
                                        category="A07:2021",
                                        severity="critical",
                                        title="OAuth redirect_uri Validation Bypass",
                                        description=f"Malicious redirect_uri accepted using bypass: {bypass}",
                                        url=url,
                                        method="GET",
                                        parameter="redirect_uri",
                                        evidence=f"Payload: {bypass} â†' Redirect to: {redirect_location[:100]}...",
                                        remediation="Implement strict whitelist validation for redirect_uri. Use exact match, not prefix/suffix matching.",
                                        cwe_id="CWE-601",
                                        poc=f"redirect_uri={test_redirect}",
                                        reasoning="redirect_uri bypass allows stealing authorization codes via attacker-controlled domain"
                                    ))
                                    return
                            
                            # Check if request was not rejected (should be 400 for invalid redirect)
                            elif response.status == 200:
                                resp_text = await response.text()
                                if 'error' not in resp_text.lower():
                                    self.results.append(ScanResult(
                                        id=f"OAUTH-REDIRECT-WEAK-{len(self.results)}",
                                        category="A07:2021",
                                        severity="high",
                                        title="OAuth redirect_uri Validation Weakness",
                                        description=f"Invalid redirect_uri not properly rejected",
                                        url=url,
                                        method="GET",
                                        parameter="redirect_uri",
                                        evidence=f"Payload: {bypass} â†' Status: {response.status}",
                                        remediation="Reject invalid redirect_uri with 400 error. Validate before any other processing.",
                                        cwe_id="CWE-601",
                                        poc=f"redirect_uri={test_redirect}",
                                        reasoning="Weak validation may allow certain bypass techniques to work"
                                    ))
                                    
                    except Exception as e:
                        logger.debug(f"Redirect URI bypass test error: {e}")
                    
                    await asyncio.sleep(0.1)
            
            break  # Only test first OAuth endpoint found

    async def _test_open_redirect(self, session: aiohttp.ClientSession, base_url: str):
        """Test for open redirect in OAuth callback handling"""
        
        for callback_ep in self.CALLBACK_ENDPOINTS:
            url = urljoin(base_url, callback_ep)
            
            try:
                # Check if callback endpoint exists
                async with session.get(url) as response:
                    if response.status == 404:
                        continue
            except:
                continue
            
            # Test open redirect via various parameters
            redirect_params = [
                'redirect', 'redirect_uri', 'return', 'returnTo', 'return_to',
                'next', 'url', 'target', 'destination', 'redir', 'redirect_url',
                'continue', 'forward', 'goto', 'to', 'RelayState'
            ]
            
            for param in redirect_params:
                for evil_domain in self.EVIL_DOMAINS[:2]:
                    evil_url = f"https://{evil_domain}/steal"
                    
                    test_params = {
                        param: evil_url,
                        'code': 'fake_code_12345',
                        'state': secrets.token_urlsafe(16)
                    }
                    
                    try:
                        test_url = f"{url}?{urlencode(test_params)}"
                        async with session.get(test_url, allow_redirects=False) as response:
                            if response.status in [302, 307]:
                                location = response.headers.get('Location', '')
                                
                                if evil_domain in location:
                                    self.results.append(ScanResult(
                                        id=f"OAUTH-OPEN-REDIRECT-{len(self.results)}",
                                        category="A07:2021",
                                        severity="high",
                                        title="Open Redirect in OAuth Callback",
                                        description=f"OAuth callback allows open redirect via '{param}' parameter",
                                        url=url,
                                        method="GET",
                                        parameter=param,
                                        evidence=f"Redirected to: {location}",
                                        remediation="Validate all redirect destinations against whitelist. Only allow redirects to same-origin URLs.",
                                        cwe_id="CWE-601",
                                        poc=f"{param}=https://{evil_domain}/steal",
                                        reasoning="Open redirect can be used for phishing or token theft"
                                    ))
                                    return
                                    
                    except Exception as e:
                        logger.debug(f"Open redirect test error: {e}")
                    
                    await asyncio.sleep(0.05)
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_token_exposure(self, session: aiohttp.ClientSession, base_url: str):
        """Test for token exposure in URLs, logs, or referrer headers"""
        
        # Check for implicit flow (tokens in URL fragments - detected in crawl)
        endpoints = getattr(self.context, 'endpoints', []) or []
        
        for ep in endpoints:
            ep_url = ep if isinstance(ep, str) else ep.get('url', '')
            
            # Check for tokens in URL
            token_patterns = [
                r'[?&#]access_token=([a-zA-Z0-9_.-]+)',
                r'[?&#]token=([a-zA-Z0-9_.-]+)',
                r'[?&#]id_token=([a-zA-Z0-9_.-]+)',
                r'[?&#]refresh_token=([a-zA-Z0-9_.-]+)',
                r'[?&#]code=([a-zA-Z0-9_.-]+)',
            ]
            
            for pattern in token_patterns:
                match = re.search(pattern, ep_url)
                if match:
                    token_type = pattern.split('=')[0].strip('[?&#]')
                    token_value = match.group(1)
                    
                    severity = 'critical' if 'access_token' in token_type else 'high'
                    
                    self.results.append(ScanResult(
                        id=f"OAUTH-TOKEN-IN-URL-{len(self.results)}",
                        category="A07:2021",
                        severity=severity,
                        title=f"OAuth {token_type} Exposed in URL",
                        description=f"Sensitive token '{token_type}' found in URL, exposed in browser history, logs, and Referer header",
                        url=ep_url[:100],
                        method="GET",
                        parameter=token_type,
                        evidence=f"Token: {token_value[:20]}...",
                        remediation="Use Authorization Code flow with PKCE instead of Implicit flow. Tokens should be in POST body or Authorization header.",
                        cwe_id="CWE-598",
                        poc=f"{token_type} visible in URL",
                        reasoning="URL tokens leak via browser history, server logs, and HTTP Referer headers"
                    ))
                    break
        
        # Check OAuth endpoints for implicit flow response_type
        for oauth_ep in self.OAUTH_ENDPOINTS[:3]:
            url = urljoin(base_url, oauth_ep)
            
            implicit_params = {
                'response_type': 'token',
                'client_id': 'test',
                'redirect_uri': base_url,
                'scope': 'openid'
            }
            
            try:
                test_url = f"{url}?{urlencode(implicit_params)}"
                async with session.get(test_url, allow_redirects=False) as response:
                    if response.status != 400:  # Should reject implicit flow
                        self.results.append(ScanResult(
                            id=f"OAUTH-IMPLICIT-FLOW-{len(self.results)}",
                            category="A07:2021",
                            severity="medium",
                            title="OAuth Implicit Flow Enabled",
                            description="Server accepts response_type=token (implicit flow), which exposes tokens in URLs",
                            url=url,
                            method="GET",
                            parameter="response_type",
                            evidence=f"response_type=token not rejected (status: {response.status})",
                            remediation="Disable implicit flow. Use Authorization Code with PKCE for all client types.",
                            cwe_id="CWE-598",
                            poc="response_type=token",
                            reasoning="Implicit flow is deprecated due to token exposure in URL fragments"
                        ))
                        return
            except:
                pass
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_pkce_missing(self, session: aiohttp.ClientSession, base_url: str):
        """Test for missing PKCE (Proof Key for Code Exchange)"""
        
        for oauth_ep in self.OAUTH_ENDPOINTS[:5]:
            url = urljoin(base_url, oauth_ep)
            
            # Request without PKCE
            no_pkce_params = {
                'response_type': 'code',
                'client_id': 'test',
                'redirect_uri': urljoin(base_url, '/callback'),
                'scope': 'openid profile',
                'state': secrets.token_urlsafe(16)
            }
            
            try:
                test_url = f"{url}?{urlencode(no_pkce_params)}"
                async with session.get(test_url, allow_redirects=False) as response:
                    if response.status == 404:
                        continue
                    
                    # If OAuth flow proceeds without code_challenge, PKCE is not enforced
                    if response.status in [302, 307, 200]:
                        location = response.headers.get('Location', '')
                        resp_text = await response.text()
                        
                        # Check if it's proceeding to auth (not error about missing PKCE)
                        if response.status in [302, 307]:
                            # Check if redirecting to actual OAuth provider
                            if 'google' in location or 'github' in location or 'microsoft' in location:
                                self.results.append(ScanResult(
                                    id=f"OAUTH-NO-PKCE-{len(self.results)}",
                                    category="A07:2021",
                                    severity="medium",
                                    title="OAuth PKCE Not Required",
                                    description="OAuth flow proceeds without PKCE (code_challenge), vulnerable to authorization code interception",
                                    url=url,
                                    method="GET",
                                    parameter="code_challenge",
                                    evidence="OAuth redirect accepted without code_challenge parameter",
                                    remediation="Require PKCE (code_challenge) for all OAuth flows, especially for SPAs and mobile apps.",
                                    cwe_id="CWE-287",
                                    poc="Request without code_challenge parameter succeeds",
                                    reasoning="Without PKCE, authorization codes can be stolen and exchanged by attackers"
                                ))
                                return
                        elif 'code_challenge' not in resp_text.lower() and 'error' not in resp_text.lower():
                            self.results.append(ScanResult(
                                id=f"OAUTH-PKCE-NOT-ENFORCED-{len(self.results)}",
                                category="A07:2021",
                                severity="medium",
                                title="OAuth PKCE Not Enforced",
                                description="OAuth implementation does not appear to require PKCE",
                                url=url,
                                method="GET",
                                parameter="code_challenge",
                                evidence=f"No PKCE requirement detected",
                                remediation="Enforce PKCE for all clients. Reject requests without valid code_challenge.",
                                cwe_id="CWE-287",
                                poc="OAuth flow works without PKCE parameters",
                                reasoning="PKCE protects against authorization code interception attacks"
                            ))
                            return
                            
            except Exception as e:
                logger.debug(f"PKCE test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_oauth_misconfiguration(self, session: aiohttp.ClientSession, base_url: str):
        """Test for OAuth misconfiguration disclosure"""
        
        # OpenID Connect discovery endpoints
        discovery_endpoints = [
            '/.well-known/openid-configuration',
            '/.well-known/oauth-authorization-server',
            '/oauth/.well-known/openid-configuration',
            '/api/.well-known/openid-configuration',
        ]
        
        for discovery_ep in discovery_endpoints:
            url = urljoin(base_url, discovery_ep)
            
            try:
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
                    
                    try:
                        config = await response.json()
                    except:
                        continue
                    
                    # Check for insecure configurations
                    issues = []
                    
                    # Check for implicit flow support
                    response_types = config.get('response_types_supported', [])
                    if 'token' in response_types:
                        issues.append("Implicit flow (token) is enabled")
                    
                    # Check for missing PKCE support
                    code_challenge_methods = config.get('code_challenge_methods_supported', [])
                    if not code_challenge_methods:
                        issues.append("PKCE not supported")
                    
                    # Check for insecure token endpoints
                    if config.get('token_endpoint_auth_methods_supported'):
                        auth_methods = config['token_endpoint_auth_methods_supported']
                        if 'none' in auth_methods:
                            issues.append("Token endpoint allows 'none' authentication")
                    
                    # Check for exposed client IDs
                    if config.get('client_id') or config.get('client_ids'):
                        issues.append("Client IDs exposed in discovery document")
                    
                    if issues:
                        self.results.append(ScanResult(
                            id=f"OAUTH-MISCONFIG-{len(self.results)}",
                            category="A05:2021",
                            severity="medium",
                            title="OAuth Configuration Issues Detected",
                            description=f"OpenID Connect discovery reveals configuration issues: {', '.join(issues)}",
                            url=url,
                            method="GET",
                            parameter="openid-configuration",
                            evidence=f"Issues: {issues}",
                            remediation="Disable deprecated flows (implicit). Require PKCE. Use secure token endpoint authentication.",
                            cwe_id="CWE-16",
                            poc=f"Discovery endpoint: {url}",
                            reasoning="OAuth misconfigurations can lead to token theft and authentication bypass"
                        ))
                    else:
                        # Still log info about discovery endpoint
                        self.results.append(ScanResult(
                            id=f"OAUTH-DISCOVERY-{len(self.results)}",
                            category="A05:2021",
                            severity="info",
                            title="OAuth Discovery Endpoint Found",
                            description="OpenID Connect discovery endpoint is publicly accessible",
                            url=url,
                            method="GET",
                            parameter="openid-configuration",
                            evidence=f"Discovery document found with {len(config)} configuration items",
                            remediation="Review OAuth configuration for security best practices",
                            cwe_id="CWE-200",
                            poc=f"curl {url}",
                            reasoning="Discovery endpoints reveal OAuth implementation details"
                        ))
                    
                    return  # Found discovery, stop searching
                    
            except Exception as e:
                logger.debug(f"OAuth discovery test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)


# Export for scanner registration
__all__ = ['OAuthSecurityScanner', 'ScanResult']
