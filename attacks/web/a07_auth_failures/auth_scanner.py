"""
Jarwis AGI Pen Test - Authentication & Session Scanner
Detects authentication and session management vulnerabilities
OWASP A07:2021 - Identification and Authentication Failures
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import hashlib
import base64
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, quote
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


class AuthenticationScanner:
    """
    Scans for authentication vulnerabilities
    OWASP A07:2021 - Identification and Authentication Failures
    
    Checks:
    - Default credentials
    - Password policy bypass
    - Username enumeration
    - Brute force protection
    - Account lockout
    - Session fixation
    - Credential stuffing protection
    """
    
    # Common default credentials
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('admin', '123456'),
        ('admin', 'admin123'),
        ('administrator', 'administrator'),
        ('root', 'root'),
        ('root', 'password'),
        ('user', 'user'),
        ('test', 'test'),
        ('guest', 'guest'),
        ('demo', 'demo'),
        ('operator', 'operator'),
        ('admin', 'Admin123'),
        ('admin', 'Password1'),
    ]
    
    # Common login endpoints
    LOGIN_ENDPOINTS = [
        '/login', '/signin', '/auth', '/authenticate',
        '/api/login', '/api/auth', '/api/signin',
        '/api/v1/login', '/api/v1/auth',
        '/user/login', '/users/login', '/account/login',
        '/admin/login', '/admin', '/administrator',
        '/wp-login.php', '/wp-admin',
    ]
    
    # Common form fields
    USERNAME_FIELDS = ['username', 'user', 'email', 'login', 'name', 'user_id', 'uid']
    PASSWORD_FIELDS = ['password', 'pass', 'pwd', 'passwd', 'secret']
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 5)  # Lower for auth testing
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Authentication scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Find login pages
            login_urls = await self._find_login_pages(session, base_url)
            
            for login_url in login_urls[:3]:  # Test top 3 login pages
                # Test default credentials
                await self._test_default_credentials(session, login_url)
                
                # Test username enumeration
                await self._test_username_enumeration(session, login_url)
                
                # Test brute force protection
                await self._test_brute_force_protection(session, login_url)
                
                # Test login over HTTP
                await self._test_login_security(session, login_url)
        
        logger.info(f"Authentication scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _find_login_pages(self, session: aiohttp.ClientSession, base_url: str) -> List[str]:
        """Find login pages"""
        found_logins = []
        
        for endpoint in self.LOGIN_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(url) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        # Check for login form indicators
                        login_indicators = ['password', 'login', 'signin', 'submit', 'auth']
                        if any(ind in body.lower() for ind in login_indicators):
                            found_logins.append(url)
                            
            except Exception as e:
                logger.debug(f"Login page check error: {e}")
        
        return found_logins
    
    async def _test_default_credentials(self, session: aiohttp.ClientSession, login_url: str):
        """Test for default credentials"""
        
        for username, password in self.DEFAULT_CREDENTIALS[:5]:  # Limit attempts
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Try common form field combinations
                for user_field in self.USERNAME_FIELDS[:3]:
                    for pass_field in self.PASSWORD_FIELDS[:2]:
                        data = {
                            user_field: username,
                            pass_field: password
                        }
                        
                        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                        
                        async with session.post(login_url, data=data, headers=headers, allow_redirects=False) as response:
                            body = await response.text()
                            
                            # Check for successful login indicators
                            success_indicators = [
                                'dashboard', 'welcome', 'logout', 'profile',
                                'successfully logged', 'login successful'
                            ]
                            
                            failure_indicators = [
                                'invalid', 'incorrect', 'failed', 'error',
                                'wrong password', 'try again'
                            ]
                            
                            # Check for redirect to dashboard
                            is_redirect = response.status in [301, 302, 303]
                            location = response.headers.get('Location', '')
                            
                            if any(s in body.lower() for s in success_indicators) or \
                               (is_redirect and any(s in location.lower() for s in ['dashboard', 'home', 'admin', 'panel'])):
                                result = ScanResult(
                                    id=f"AUTH-DEFAULT-{len(self.results)+1}",
                                    category="A07:2021 - Auth Failures",
                                    severity="critical",
                                    title=f"Default Credentials: {username}",
                                    description=f"Login successful with default credentials.",
                                    url=login_url,
                                    method="POST",
                                    parameter=user_field,
                                    evidence=f"Credentials: {username}:{password}",
                                    remediation="Change default credentials. Enforce password policy.",
                                    cwe_id="CWE-798",
                                    poc=f"{user_field}={username}&{pass_field}={password}",
                                    reasoning="Default credentials allowed login"
                                )
                                self.results.append(result)
                                return
                                
            except Exception as e:
                logger.debug(f"Default credentials test error: {e}")
    
    async def _test_username_enumeration(self, session: aiohttp.ClientSession, login_url: str):
        """Test for username enumeration"""
        
        try:
            # Test with valid-looking username
            valid_user_data = {
                'username': 'admin',
                'password': 'wrongpassword123'
            }
            
            # Test with definitely invalid username
            invalid_user_data = {
                'username': 'definitely_not_a_real_user_xyz123',
                'password': 'wrongpassword123'
            }
            
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.post(login_url, data=valid_user_data, headers=headers) as valid_resp:
                valid_body = await valid_resp.text()
                valid_status = valid_resp.status
                valid_len = len(valid_body)
            
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.post(login_url, data=invalid_user_data, headers=headers) as invalid_resp:
                invalid_body = await invalid_resp.text()
                invalid_status = invalid_resp.status
                invalid_len = len(invalid_body)
            
            # Check for different error messages
            diff_messages = [
                ('user not found', 'password'),
                ('invalid user', 'invalid password'),
                ('username does not exist', 'password incorrect'),
                ('no account', 'wrong password'),
            ]
            
            for user_msg, pass_msg in diff_messages:
                if user_msg in invalid_body.lower() and pass_msg in valid_body.lower():
                    result = ScanResult(
                        id=f"AUTH-ENUM-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="medium",
                        title="Username Enumeration via Error Messages",
                        description="Different error messages reveal valid usernames.",
                        url=login_url,
                        method="POST",
                        evidence=f"Invalid user: '{user_msg}', Valid user: '{pass_msg}'",
                        remediation="Use generic error messages: 'Invalid credentials'.",
                        cwe_id="CWE-204",
                        reasoning="Error messages differ based on username validity"
                    )
                    self.results.append(result)
                    return
            
            # Check for response length/timing differences
            if abs(valid_len - invalid_len) > 50:
                result = ScanResult(
                    id=f"AUTH-ENUM-{len(self.results)+1}",
                    category="A07:2021 - Auth Failures",
                    severity="low",
                    title="Potential Username Enumeration via Response Length",
                    description="Response length differs between valid and invalid usernames.",
                    url=login_url,
                    method="POST",
                    evidence=f"Valid user: {valid_len} bytes, Invalid: {invalid_len} bytes",
                    remediation="Return identical responses for valid and invalid usernames.",
                    cwe_id="CWE-204",
                    reasoning=f"Response differs by {abs(valid_len - invalid_len)} bytes"
                )
                self.results.append(result)
                
        except Exception as e:
            logger.debug(f"Username enumeration test error: {e}")
    
    async def _test_brute_force_protection(self, session: aiohttp.ClientSession, login_url: str):
        """Test for brute force protection"""
        
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            success_count = 0
            
            # Send multiple failed login attempts
            for i in range(10):
                data = {
                    'username': 'testuser',
                    'password': f'wrongpassword{i}'
                }
                
                await asyncio.sleep(0.2)  # Fast requests
                
                async with session.post(login_url, data=data, headers=headers) as response:
                    if response.status != 429:  # Not rate limited
                        success_count += 1
            
            if success_count >= 10:
                result = ScanResult(
                    id=f"AUTH-BRUTE-{len(self.results)+1}",
                    category="A07:2021 - Auth Failures",
                    severity="high",
                    title="Missing Brute Force Protection",
                    description="No rate limiting or account lockout after failed attempts.",
                    url=login_url,
                    method="POST",
                    evidence=f"{success_count}/10 rapid requests succeeded",
                    remediation="Implement rate limiting, CAPTCHA, and account lockout.",
                    cwe_id="CWE-307",
                    reasoning="No 429 responses after 10 rapid login attempts"
                )
                self.results.append(result)
                
        except Exception as e:
            logger.debug(f"Brute force protection test error: {e}")
    
    async def _test_login_security(self, session: aiohttp.ClientSession, login_url: str):
        """Test login page security"""
        
        parsed = urlparse(login_url)
        
        # Check for HTTP login
        if parsed.scheme == 'http':
            result = ScanResult(
                id=f"AUTH-HTTP-{len(self.results)+1}",
                category="A07:2021 - Auth Failures",
                severity="high",
                title="Login Page Over HTTP",
                description="Credentials transmitted without encryption.",
                url=login_url,
                method="GET",
                evidence="Login form uses HTTP instead of HTTPS",
                remediation="Use HTTPS for all authentication pages.",
                cwe_id="CWE-319",
                reasoning="Credentials can be intercepted in transit"
            )
            self.results.append(result)


class SessionManagementScanner:
    """
    Scans for session management vulnerabilities
    OWASP A07:2021 - Identification and Authentication Failures
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
        logger.info("Starting Session Management scan...")
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
            
            # Check session token entropy
            await self._check_session_entropy(session, base_url)
            
            # Check session fixation
            await self._check_session_fixation(session, base_url)
            
            # Check session in URL
            await self._check_session_in_url(session, base_url)
        
        logger.info(f"Session management scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_session_entropy(self, session: aiohttp.ClientSession, url: str):
        """Check session token entropy"""
        
        session_tokens = []
        
        try:
            # Collect multiple session tokens
            for _ in range(5):
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(url) as response:
                    cookies = response.cookies
                    
                    for name, cookie in cookies.items():
                        if any(s in name.lower() for s in ['session', 'sid', 'token', 'auth', 'id']):
                            session_tokens.append(cookie.value)
            
            if len(session_tokens) >= 2:
                # Check token length
                avg_length = sum(len(t) for t in session_tokens) / len(session_tokens)
                
                if avg_length < 20:
                    result = ScanResult(
                        id=f"SESSION-SHORT-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="medium",
                        title="Short Session Token",
                        description=f"Session tokens are only {avg_length:.0f} characters.",
                        url=url,
                        method="GET",
                        evidence=f"Sample token: {session_tokens[0][:30]}",
                        remediation="Use at least 128-bit random session identifiers.",
                        cwe_id="CWE-330",
                        reasoning="Short tokens are easier to brute force"
                    )
                    self.results.append(result)
                
                # Check for predictable patterns
                if self._check_predictable(session_tokens):
                    result = ScanResult(
                        id=f"SESSION-PREDICT-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="high",
                        title="Predictable Session Tokens",
                        description="Session tokens show predictable patterns.",
                        url=url,
                        method="GET",
                        evidence=f"Tokens: {', '.join(session_tokens[:3])}",
                        remediation="Use cryptographically secure random number generator.",
                        cwe_id="CWE-330",
                        reasoning="Token patterns suggest weak randomness"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Session entropy check error: {e}")
    
    def _check_predictable(self, tokens: List[str]) -> bool:
        """Check if tokens show predictable patterns"""
        
        if len(tokens) < 2:
            return False
        
        # Check for sequential numbers
        try:
            nums = [int(re.search(r'\d+', t).group()) for t in tokens if re.search(r'\d+', t)]
            if len(nums) >= 2:
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                if len(set(diffs)) == 1:  # All same difference
                    return True
        except:
            pass
        
        # Check for similar prefixes
        if len(tokens) >= 3:
            prefix_len = 0
            for i in range(min(len(t) for t in tokens)):
                if all(t[i] == tokens[0][i] for t in tokens):
                    prefix_len += 1
                else:
                    break
            
            if prefix_len > len(tokens[0]) * 0.8:  # >80% same
                return True
        
        return False
    
    async def _check_session_fixation(self, session: aiohttp.ClientSession, url: str):
        """Check for session fixation vulnerability"""
        
        try:
            # Get initial session
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url) as response1:
                initial_cookies = dict(response1.cookies)
                initial_session = None
                
                for name, value in initial_cookies.items():
                    if any(s in name.lower() for s in ['session', 'sid']):
                        initial_session = (name, value)
                        break
            
            if initial_session:
                # In a real test, we would simulate login and check if session changes
                # For passive detection, we check if session is set before auth
                result = ScanResult(
                    id=f"SESSION-PREAUTH-{len(self.results)+1}",
                    category="A07:2021 - Auth Failures",
                    severity="info",
                    title="Session Created Before Authentication",
                    description="Session cookie is set before login. Verify it changes on auth.",
                    url=url,
                    method="GET",
                    evidence=f"Pre-auth session: {initial_session[0]}",
                    remediation="Regenerate session ID after successful authentication.",
                    cwe_id="CWE-384",
                    reasoning="Pre-auth session may enable session fixation"
                )
                self.results.append(result)
                
        except Exception as e:
            logger.debug(f"Session fixation check error: {e}")
    
    async def _check_session_in_url(self, session: aiohttp.ClientSession, url: str):
        """Check for session ID in URL"""
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url, allow_redirects=True) as response:
                final_url = str(response.url)
                
                # Check for session-like parameters in URL
                session_patterns = [
                    r'[?&]session[_-]?id=',
                    r'[?&]sid=',
                    r'[?&]token=',
                    r'[?&]auth=',
                    r'[?&]jsessionid=',
                    r';jsessionid=',
                    r'[?&]phpsessid=',
                ]
                
                for pattern in session_patterns:
                    if re.search(pattern, final_url, re.IGNORECASE):
                        result = ScanResult(
                            id=f"SESSION-URL-{len(self.results)+1}",
                            category="A07:2021 - Auth Failures",
                            severity="high",
                            title="Session ID in URL",
                            description="Session identifier is exposed in URL.",
                            url=final_url,
                            method="GET",
                            evidence=f"Pattern found: {pattern}",
                            remediation="Use cookies for session management. Never expose sessions in URLs.",
                            cwe_id="CWE-598",
                            reasoning="Session in URL can leak via referrer, logs, history"
                        )
                        self.results.append(result)
                        return
                
                # Check response body for links with session
                body = await response.text()
                for pattern in session_patterns:
                    if re.search(r'href="[^"]*' + pattern, body, re.IGNORECASE):
                        result = ScanResult(
                            id=f"SESSION-LINK-{len(self.results)+1}",
                            category="A07:2021 - Auth Failures",
                            severity="medium",
                            title="Session ID in Links",
                            description="Links contain session identifiers.",
                            url=url,
                            method="GET",
                            evidence=f"Pattern in links: {pattern}",
                            remediation="Use cookies instead of URL-based sessions.",
                            cwe_id="CWE-598",
                            reasoning="Session in links may leak"
                        )
                        self.results.append(result)
                        return
                        
        except Exception as e:
            logger.debug(f"Session in URL check error: {e}")


class PasswordResetScanner:
    """
    Scans for password reset vulnerabilities
    OWASP A07:2021 - Identification and Authentication Failures
    """
    
    # Common password reset endpoints
    RESET_ENDPOINTS = [
        '/reset', '/reset-password', '/forgot-password', '/forgot',
        '/password/reset', '/password/forgot', '/account/reset',
        '/api/reset-password', '/api/forgot-password',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 5)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Password Reset scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Find and test reset pages
            for endpoint in self.RESET_ENDPOINTS:
                url = urljoin(base_url, endpoint)
                await self._test_reset_endpoint(session, url)
        
        logger.info(f"Password reset scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_reset_endpoint(self, session: aiohttp.ClientSession, url: str):
        """Test password reset endpoint"""
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            # Check if endpoint exists
            async with session.get(url) as response:
                if response.status != 200:
                    return
                
                body = await response.text()
                
                # Check for email/username input
                if 'email' not in body.lower() and 'username' not in body.lower():
                    return
            
            # Test for user enumeration
            await self._test_reset_enumeration(session, url)
            
            # Test for host header injection
            await self._test_host_header_poison(session, url)
            
        except Exception as e:
            logger.debug(f"Password reset test error: {e}")
    
    async def _test_reset_enumeration(self, session: aiohttp.ClientSession, url: str):
        """Test for user enumeration via password reset"""
        
        try:
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            
            # Test with valid-looking email
            valid_data = {'email': 'admin@test.com'}
            
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.post(url, data=valid_data, headers=headers) as valid_resp:
                valid_body = await valid_resp.text()
            
            # Test with invalid email
            invalid_data = {'email': 'definitely_not_real_xyz@nowhere.invalid'}
            
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.post(url, data=invalid_data, headers=headers) as invalid_resp:
                invalid_body = await invalid_resp.text()
            
            # Check for different responses
            if 'not found' in invalid_body.lower() and 'not found' not in valid_body.lower():
                result = ScanResult(
                    id=f"RESET-ENUM-{len(self.results)+1}",
                    category="A07:2021 - Auth Failures",
                    severity="medium",
                    title="User Enumeration via Password Reset",
                    description="Password reset reveals valid usernames/emails.",
                    url=url,
                    method="POST",
                    evidence="Different responses for valid/invalid emails",
                    remediation="Return same message for all reset requests.",
                    cwe_id="CWE-204",
                    reasoning="Response reveals email existence"
                )
                self.results.append(result)
                
        except Exception as e:
            logger.debug(f"Reset enumeration test error: {e}")
    
    async def _test_host_header_poison(self, session: aiohttp.ClientSession, url: str):
        """Test for host header injection in password reset"""
        
        try:
            # Inject malicious host header
            evil_host = 'evil.attacker.com'
            
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Host': evil_host,
                'X-Forwarded-Host': evil_host,
            }
            
            data = {'email': 'test@example.com'}
            
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.post(url, data=data, headers=headers) as response:
                body = await response.text()
                
                # Check if evil host appears in response
                if evil_host in body:
                    result = ScanResult(
                        id=f"RESET-HOST-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="high",
                        title="Host Header Injection in Password Reset",
                        description="Reset link can be poisoned with attacker's host.",
                        url=url,
                        method="POST",
                        parameter="Host",
                        evidence=f"Evil host reflected: {evil_host}",
                        remediation="Don't use Host header for reset link generation.",
                        cwe_id="CWE-20",
                        poc=f"Host: {evil_host}",
                        reasoning="Reset email could contain attacker-controlled link"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Host header poison test error: {e}")
