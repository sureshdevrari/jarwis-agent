"""
Jarwis AGI Pen Test - Session Security Scanner
Tests for session management vulnerabilities:
- Session timeout issues (too long, no timeout)
- Session token entropy analysis
- Concurrent session handling (single-session bypass)
- Session cookie security flags (HttpOnly, Secure, SameSite)
- Session invalidation on logout/password change
- Session token in URL (session hijacking risk)

OWASP Category: A07:2021 - Identification and Authentication Failures
"""

import asyncio
import logging
import re
import math
import string
import hashlib
from typing import Dict, List, Optional, Set
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs
from collections import Counter
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


class SessionSecurityScanner:
    """
    Scans for Session Management vulnerabilities (A07:2021)
    
    Tests based on defensive measures implemented in Jarwis:
    1. Session token entropy (weak random generation)
    2. Cookie security flags (HttpOnly, Secure, SameSite)
    3. Session timeout validation
    4. Concurrent session handling
    5. Session invalidation on sensitive actions
    6. Session tokens in URLs
    7. Session fixation vectors
    """
    
    # Common session cookie names
    SESSION_COOKIE_NAMES = [
        'session', 'sessionid', 'session_id', 'sid',
        'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId',
        'connect.sid', 'express.sid', 'laravel_session',
        'CFID', 'CFTOKEN', 'rack.session', 'user_session',
        '_session_id', 'sess', 'token', 'access_token',
        'auth_token', 'jwt', 'id_token', 'refresh_token'
    ]
    
    # Sensitive endpoints that should invalidate sessions
    SENSITIVE_ENDPOINTS = [
        '/logout', '/signout', '/api/auth/logout',
        '/password/change', '/change-password', '/api/password/change',
        '/settings/security', '/account/security', '/api/security/revoke',
    ]

    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    async def scan(self) -> List[ScanResult]:
        """Run all session security tests"""
        logger.info("Starting Session Security Scanner...")
        
        endpoints = getattr(self.context, 'endpoints', []) or []
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url and endpoints:
            parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found for session security scanning")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            await asyncio.gather(
                self._test_cookie_security_flags(session, base_url),
                self._test_session_token_entropy(session, base_url),
                self._test_session_in_url(session, base_url, endpoints),
                self._test_concurrent_sessions(session, base_url),
                self._test_session_timeout(session, base_url),
                self._test_logout_invalidation(session, base_url),
                return_exceptions=True
            )
        
        logger.info(f"Session Security Scanner completed. Found {len(self.results)} issues.")
        return self.results

    async def _test_cookie_security_flags(self, session: aiohttp.ClientSession, base_url: str):
        """Test for missing security flags on session cookies"""
        
        try:
            async with session.get(base_url) as response:
                cookies = response.cookies
                set_cookie_headers = response.headers.getall('Set-Cookie', [])
                
                for cookie_header in set_cookie_headers:
                    cookie_name = cookie_header.split('=')[0].strip()
                    cookie_lower = cookie_header.lower()
                    
                    is_session_cookie = any(
                        name.lower() in cookie_name.lower() 
                        for name in self.SESSION_COOKIE_NAMES
                    )
                    
                    if not is_session_cookie:
                        continue
                    
                    # Check for missing HttpOnly flag
                    if 'httponly' not in cookie_lower:
                        self.results.append(ScanResult(
                            id=f"SESSION-NO-HTTPONLY-{len(self.results)}",
                            category="A07:2021",
                            severity="medium",
                            title="Session Cookie Missing HttpOnly Flag",
                            description=f"Session cookie '{cookie_name}' is accessible to JavaScript, enabling XSS-based session theft",
                            url=base_url,
                            method="GET",
                            parameter=f"Cookie: {cookie_name}",
                            evidence=f"Set-Cookie: {cookie_header[:100]}...",
                            remediation="Add 'HttpOnly' flag to all session cookies to prevent JavaScript access",
                            cwe_id="CWE-1004",
                            poc="document.cookie in browser console can access this cookie",
                            reasoning="Missing HttpOnly allows XSS attacks to steal session tokens via document.cookie"
                        ))
                    
                    # Check for missing Secure flag (if HTTPS)
                    if base_url.startswith('https') and 'secure' not in cookie_lower:
                        self.results.append(ScanResult(
                            id=f"SESSION-NO-SECURE-{len(self.results)}",
                            category="A07:2021",
                            severity="high",
                            title="Session Cookie Missing Secure Flag",
                            description=f"Session cookie '{cookie_name}' can be transmitted over unencrypted HTTP connections",
                            url=base_url,
                            method="GET",
                            parameter=f"Cookie: {cookie_name}",
                            evidence=f"Set-Cookie: {cookie_header[:100]}...",
                            remediation="Add 'Secure' flag to ensure cookies are only sent over HTTPS",
                            cwe_id="CWE-614",
                            poc="Cookie can be intercepted via MITM if user visits HTTP version of site",
                            reasoning="Without Secure flag, session cookies can be intercepted on insecure networks"
                        ))
                    
                    # Check for missing or weak SameSite attribute
                    if 'samesite' not in cookie_lower:
                        self.results.append(ScanResult(
                            id=f"SESSION-NO-SAMESITE-{len(self.results)}",
                            category="A07:2021",
                            severity="medium",
                            title="Session Cookie Missing SameSite Attribute",
                            description=f"Session cookie '{cookie_name}' lacks SameSite attribute, potentially enabling CSRF attacks",
                            url=base_url,
                            method="GET",
                            parameter=f"Cookie: {cookie_name}",
                            evidence=f"Set-Cookie: {cookie_header[:100]}...",
                            remediation="Add 'SameSite=Strict' or 'SameSite=Lax' to session cookies",
                            cwe_id="CWE-1275",
                            poc="Cookie will be sent on cross-site requests, enabling CSRF",
                            reasoning="Missing SameSite allows cookies to be sent on cross-origin requests"
                        ))
                    elif 'samesite=none' in cookie_lower:
                        self.results.append(ScanResult(
                            id=f"SESSION-SAMESITE-NONE-{len(self.results)}",
                            category="A07:2021",
                            severity="medium",
                            title="Session Cookie Uses SameSite=None",
                            description=f"Session cookie '{cookie_name}' uses SameSite=None, allowing cross-site requests",
                            url=base_url,
                            method="GET",
                            parameter=f"Cookie: {cookie_name}",
                            evidence=f"Set-Cookie: {cookie_header[:100]}...",
                            remediation="Use 'SameSite=Strict' or 'SameSite=Lax' unless cross-site functionality is required",
                            cwe_id="CWE-1275",
                            poc="Cookie will be sent on cross-site requests",
                            reasoning="SameSite=None provides no CSRF protection"
                        ))
                        
        except Exception as e:
            logger.debug(f"Cookie security test error: {e}")

    async def _test_session_token_entropy(self, session: aiohttp.ClientSession, base_url: str):
        """Analyze session token randomness/entropy"""
        
        collected_tokens: List[str] = []
        
        # Collect multiple session tokens
        for _ in range(5):
            try:
                jar = aiohttp.CookieJar(unsafe=True)
                async with aiohttp.ClientSession(cookie_jar=jar, timeout=self.timeout) as fresh_session:
                    async with fresh_session.get(base_url) as response:
                        for cookie_name in self.SESSION_COOKIE_NAMES:
                            for cookie in fresh_session.cookie_jar:
                                if cookie.key.lower() == cookie_name.lower():
                                    collected_tokens.append(cookie.value)
                                    break
            except:
                pass
            
            await asyncio.sleep(0.5)
        
        if len(collected_tokens) < 3:
            return
        
        # Analyze token entropy
        for token in collected_tokens:
            # Check token length (should be at least 128 bits = 16 bytes = 32 hex chars)
            if len(token) < 16:
                self.results.append(ScanResult(
                    id=f"SESSION-SHORT-TOKEN-{len(self.results)}",
                    category="A07:2021",
                    severity="high",
                    title="Session Token Too Short",
                    description=f"Session token length ({len(token)} chars) is too short for adequate security",
                    url=base_url,
                    method="GET",
                    parameter="Session Token",
                    evidence=f"Token: {token[:20]}... (length: {len(token)})",
                    remediation="Use session tokens of at least 128 bits (32 hex characters) of entropy",
                    cwe_id="CWE-330",
                    poc="Short tokens are vulnerable to brute force attacks",
                    reasoning=f"Token of {len(token)} chars has insufficient entropy for security"
                ))
                break
            
            # Check for sequential/predictable patterns
            if self._is_predictable(token):
                self.results.append(ScanResult(
                    id=f"SESSION-PREDICTABLE-TOKEN-{len(self.results)}",
                    category="A07:2021",
                    severity="critical",
                    title="Predictable Session Token Pattern",
                    description="Session tokens show predictable patterns, enabling session prediction attacks",
                    url=base_url,
                    method="GET",
                    parameter="Session Token",
                    evidence=f"Tokens show predictable pattern: {token[:30]}...",
                    remediation="Use cryptographically secure random number generator (CSPRNG) for token generation",
                    cwe_id="CWE-330",
                    poc="Tokens can be predicted based on observable patterns",
                    reasoning="Predictable tokens allow attackers to guess valid session IDs"
                ))
                break
        
        # Check for token similarity (weak PRNG)
        if len(collected_tokens) >= 3:
            similarity = self._calculate_token_similarity(collected_tokens)
            if similarity > 0.5:  # More than 50% similar
                self.results.append(ScanResult(
                    id=f"SESSION-LOW-ENTROPY-{len(self.results)}",
                    category="A07:2021",
                    severity="high",
                    title="Low Session Token Entropy",
                    description=f"Session tokens show {similarity*100:.0f}% similarity, indicating weak random generation",
                    url=base_url,
                    method="GET",
                    parameter="Session Token",
                    evidence=f"Token similarity: {similarity*100:.0f}%",
                    remediation="Use a cryptographically secure random generator. Each token should be completely unique.",
                    cwe_id="CWE-331",
                    poc="Collected tokens show high similarity suggesting weak PRNG",
                    reasoning="High token similarity suggests use of weak pseudo-random number generator"
                ))

    def _is_predictable(self, token: str) -> bool:
        """Check if token shows predictable patterns"""
        # Check for sequential numbers
        if token.isdigit():
            return True
        
        # Check for timestamp-like patterns (common mistake)
        if re.match(r'^\d{10,13}', token):
            return True
        
        # Check for base64 encoded sequential data
        try:
            import base64
            decoded = base64.b64decode(token + '==').decode('utf-8', errors='ignore')
            if any(char.isdigit() for char in decoded[:10]):
                digits = ''.join(c for c in decoded if c.isdigit())
                if len(digits) > 5:
                    return True
        except:
            pass
        
        # Check for repeating patterns
        if len(set(token)) < len(token) / 4:
            return True
        
        return False

    def _calculate_token_similarity(self, tokens: List[str]) -> float:
        """Calculate average similarity between tokens"""
        if len(tokens) < 2:
            return 0.0
        
        similarities = []
        for i, t1 in enumerate(tokens):
            for t2 in tokens[i+1:]:
                # Calculate character-level similarity
                min_len = min(len(t1), len(t2))
                matching = sum(1 for a, b in zip(t1[:min_len], t2[:min_len]) if a == b)
                similarities.append(matching / min_len if min_len > 0 else 0)
        
        return sum(similarities) / len(similarities) if similarities else 0.0

    async def _test_session_in_url(self, session: aiohttp.ClientSession, base_url: str, endpoints: list):
        """Check for session tokens in URLs"""
        
        session_url_patterns = [
            r'[?&;]sessionid=([a-zA-Z0-9_-]+)',
            r'[?&;]session=([a-zA-Z0-9_-]+)',
            r'[?&;]sid=([a-zA-Z0-9_-]+)',
            r'[?&;]PHPSESSID=([a-zA-Z0-9_-]+)',
            r'[?&;]JSESSIONID=([a-zA-Z0-9_-]+)',
            r'[?&;]token=([a-zA-Z0-9_-]+)',
            r'[?&;]auth_token=([a-zA-Z0-9_-]+)',
            r';jsessionid=([a-zA-Z0-9_-]+)',
        ]
        
        for ep in endpoints:
            ep_url = ep if isinstance(ep, str) else ep.get('url', '')
            
            for pattern in session_url_patterns:
                match = re.search(pattern, ep_url, re.IGNORECASE)
                if match:
                    token = match.group(1)
                    self.results.append(ScanResult(
                        id=f"SESSION-IN-URL-{len(self.results)}",
                        category="A07:2021",
                        severity="high",
                        title="Session Token Exposed in URL",
                        description="Session token is passed via URL parameter, exposing it in browser history, logs, and referrer headers",
                        url=ep_url,
                        method="GET",
                        parameter=pattern.split('=')[0].strip('[?&;]'),
                        evidence=f"Token in URL: {ep_url[:100]}...",
                        remediation="Pass session tokens via cookies or Authorization headers, never in URLs",
                        cwe_id="CWE-598",
                        poc="Session token visible in URL, captured in server logs and browser history",
                        reasoning="URL-based session tokens leak through Referer headers, browser history, and server logs"
                    ))
                    return

    async def _test_concurrent_sessions(self, session: aiohttp.ClientSession, base_url: str):
        """Test if multiple concurrent sessions are allowed when they shouldn't be"""
        
        # Look for login endpoint
        login_endpoints = [
            '/login', '/signin', '/auth/login', '/api/auth/login',
            '/api/login', '/authenticate'
        ]
        
        for login_ep in login_endpoints:
            url = urljoin(base_url, login_ep)
            
            try:
                # Check if endpoint exists
                async with session.get(url) as response:
                    if response.status == 404:
                        continue
                
                # Try to get session info endpoint
                session_info_urls = [
                    urljoin(base_url, '/api/auth/sessions'),
                    urljoin(base_url, '/api/sessions'),
                    urljoin(base_url, '/api/user/sessions'),
                    urljoin(base_url, '/account/sessions'),
                ]
                
                for info_url in session_info_urls:
                    async with session.get(info_url) as response:
                        if response.status == 200:
                            text = await response.text()
                            # Check for session count indicators
                            if '"sessions"' in text or '"active_sessions"' in text:
                                self.results.append(ScanResult(
                                    id=f"SESSION-CONCURRENT-INFO-{len(self.results)}",
                                    category="A07:2021",
                                    severity="info",
                                    title="Session Management Endpoint Discovered",
                                    description="Application has session management endpoint - verify concurrent session limits",
                                    url=info_url,
                                    method="GET",
                                    parameter="sessions",
                                    evidence=f"Session info endpoint found at {info_url}",
                                    remediation="Ensure concurrent session limits are enforced and users can terminate other sessions",
                                    cwe_id="CWE-613",
                                    poc=f"Check {info_url} for session management capabilities",
                                    reasoning="Session management should include ability to view and revoke active sessions"
                                ))
                                return
                        
            except Exception as e:
                logger.debug(f"Concurrent session test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_session_timeout(self, session: aiohttp.ClientSession, base_url: str):
        """Test for excessive session timeout or missing timeout"""
        
        try:
            async with session.get(base_url) as response:
                cookies = response.cookies
                set_cookie_headers = response.headers.getall('Set-Cookie', [])
                
                for cookie_header in set_cookie_headers:
                    cookie_name = cookie_header.split('=')[0].strip()
                    cookie_lower = cookie_header.lower()
                    
                    is_session_cookie = any(
                        name.lower() in cookie_name.lower() 
                        for name in self.SESSION_COOKIE_NAMES
                    )
                    
                    if not is_session_cookie:
                        continue
                    
                    # Check for very long expiry
                    max_age_match = re.search(r'max-age=(\d+)', cookie_lower)
                    expires_match = re.search(r'expires=([^;]+)', cookie_lower)
                    
                    if max_age_match:
                        max_age = int(max_age_match.group(1))
                        days = max_age / 86400
                        
                        if days > 30:
                            self.results.append(ScanResult(
                                id=f"SESSION-LONG-EXPIRY-{len(self.results)}",
                                category="A07:2021",
                                severity="medium",
                                title="Excessive Session Cookie Lifetime",
                                description=f"Session cookie '{cookie_name}' has lifetime of {days:.0f} days",
                                url=base_url,
                                method="GET",
                                parameter=f"Cookie: {cookie_name}",
                                evidence=f"Max-Age: {max_age} seconds ({days:.0f} days)",
                                remediation="Limit session lifetime to 8-24 hours for regular sessions. Use shorter timeouts for sensitive applications.",
                                cwe_id="CWE-613",
                                poc=f"Session remains valid for {days:.0f} days after creation",
                                reasoning="Long session lifetimes increase the window for session hijacking"
                            ))
                    
                    # Check for missing expiry (session cookie is OK, but verify)
                    if 'max-age' not in cookie_lower and 'expires' not in cookie_lower:
                        # This is a session cookie (expires when browser closes)
                        # Generally OK but worth noting for persistent auth tokens
                        if 'token' in cookie_name.lower() or 'jwt' in cookie_name.lower():
                            self.results.append(ScanResult(
                                id=f"SESSION-NO-EXPIRY-{len(self.results)}",
                                category="A07:2021",
                                severity="low",
                                title="Auth Token Without Explicit Expiry",
                                description=f"Token cookie '{cookie_name}' lacks explicit expiry time",
                                url=base_url,
                                method="GET",
                                parameter=f"Cookie: {cookie_name}",
                                evidence=f"Set-Cookie: {cookie_header[:100]}...",
                                remediation="Set explicit expiry for authentication tokens to enforce session limits",
                                cwe_id="CWE-613",
                                poc="Token persists until browser is closed",
                                reasoning="Tokens should have explicit expiry for security policy enforcement"
                            ))
                            
        except Exception as e:
            logger.debug(f"Session timeout test error: {e}")

    async def _test_logout_invalidation(self, session: aiohttp.ClientSession, base_url: str):
        """Test if session tokens are properly invalidated on logout"""
        
        logout_endpoints = [
            '/logout', '/signout', '/auth/logout', '/api/auth/logout',
            '/api/logout', '/session/destroy', '/api/session/destroy'
        ]
        
        for logout_ep in logout_endpoints:
            url = urljoin(base_url, logout_ep)
            
            try:
                # Check if logout endpoint exists
                async with session.post(url, allow_redirects=False) as response:
                    if response.status in [200, 302, 307]:
                        # Check if Set-Cookie clears the session
                        set_cookies = response.headers.getall('Set-Cookie', [])
                        
                        session_cleared = False
                        for cookie in set_cookies:
                            if any(name.lower() in cookie.lower() for name in self.SESSION_COOKIE_NAMES):
                                # Check if cookie is being cleared
                                if 'max-age=0' in cookie.lower() or 'expires=thu, 01 jan 1970' in cookie.lower():
                                    session_cleared = True
                                    break
                        
                        if not session_cleared and set_cookies:
                            self.results.append(ScanResult(
                                id=f"SESSION-LOGOUT-NO-INVALIDATE-{len(self.results)}",
                                category="A07:2021",
                                severity="medium",
                                title="Logout May Not Invalidate Session",
                                description="Logout endpoint may not properly clear session cookies",
                                url=url,
                                method="POST",
                                parameter="Session Cookie",
                                evidence=f"Logout returned {response.status} but session cookies not explicitly cleared",
                                remediation="Clear all session cookies with Max-Age=0 on logout. Also invalidate server-side session.",
                                cwe_id="CWE-613",
                                poc="Session token may remain valid after logout",
                                reasoning="Incomplete logout allows session reuse after user believes they've logged out"
                            ))
                        
                        # Found logout endpoint, stop searching
                        return
                        
            except Exception as e:
                logger.debug(f"Logout test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)


# Export for scanner registration
__all__ = ['SessionSecurityScanner', 'ScanResult']
