"""
Jarwis AGI Pen Test - Response Swap Attack Scanner (Complete Rewrite)
Tests for authentication bypass via MITM response replacement

=== ATTACK UNDERSTANDING ===

The Attack Flow:
1. Attacker logs into their own account (attacker@email.com) â†' Gets valid JWT for attacker
2. Attacker attempts login as victim@email.com with WRONG password
3. Server sends FAILED response (401/403/error)
4. MITM proxy intercepts and replaces with attacker's SUCCESS response
5. Frontend receives "success" response with attacker's JWT token

=== WHAT MAKES IT A VULNERABILITY ===

VULNERABLE (Critical):
- After response swap, frontend displays VICTIM's profile/data
- JWT token from attacker is accepted as valid for victim's session
- Server doesn't validate that JWT user matches the login attempt user

NOT VULNERABLE (Expected Behavior):
- After response swap, frontend displays ATTACKER's profile/data
- This is correct - you're using your own valid JWT
- The JWT is bound to the user who generated it

=== PROPER TESTING REQUIREMENTS ===

To properly test this, we need:
1. Valid test credentials (to get legitimate JWT)
2. Second test account OR ability to test with different email
3. Endpoints that return user-identifying information

OWASP Category: A07:2021 - Identification and Authentication Failures
CWE: CWE-287 (Improper Authentication), CWE-384 (Session Fixation)
"""

import asyncio
import logging
import re
import json
import base64
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin
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


@dataclass
class AuthToken:
    """Represents a captured authentication token"""
    token: str
    token_type: str  # jwt, session, bearer, opaque
    user_id: Optional[str] = None
    email: Optional[str] = None
    claims: Dict[str, Any] = field(default_factory=dict)
    raw_response: str = ""


@dataclass
class TestCredentials:
    """Test account credentials"""
    email: str
    password: str
    user_id: Optional[str] = None


class ResponseSwapScanner:
    """
    Comprehensive Response Swap Attack Scanner
    
    This scanner properly tests for MITM response manipulation vulnerabilities
    by understanding that the attack only works when:
    
    1. Attacker has a valid JWT from their own account
    2. Swapping responses causes victim to be logged into WRONG account
    
    Test Cases:
    
    TC1: Token Binding Test
        - Login with valid creds â†' Get JWT
        - Decode JWT to get user identity
        - Make authenticated request
        - Verify response returns same user as JWT
        
    TC2: Cross-User Token Test (requires 2 test accounts)
        - Login as User A â†' Get JWT_A
        - Use JWT_A to access User B's resources
        - If successful, token binding is weak
        
    TC3: Response Structure Analysis
        - Compare success vs failure response structures
        - Check if user identity is in response (not just token)
        - Determine if frontend could be fooled
        
    TC4: Session-Token Consistency
        - After login, check if server validates user on every request
        - Test if token can be used across different sessions
        
    TC5: OTP/MFA Bypass via Response Swap
        - Send wrong OTP â†' Server returns failure
        - If we swap with success, would MFA be bypassed?
        - Check if server maintains OTP verification state server-side
    """
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=15)
        
        # Get test credentials from config (REQUIRED for proper testing)
        auth_config = config.get('auth', {})
        self.test_credentials = self._load_test_credentials(auth_config)
        
        # Store captured tokens
        self.captured_tokens: List[AuthToken] = []
        
        # Vulnerability indicators
        self.vuln_indicators = {
            'frontend_trust': False,  # Frontend blindly trusts response
            'weak_token_binding': False,  # Token not tied to user
            'no_server_session': False,  # No server-side session validation
            'otp_bypass_possible': False,  # OTP can be bypassed
        }
    
    def _load_test_credentials(self, auth_config: dict) -> List[TestCredentials]:
        """Load test credentials from config"""
        creds = []
        
        # Primary test account
        if auth_config.get('username') and auth_config.get('password'):
            creds.append(TestCredentials(
                email=auth_config.get('username'),
                password=auth_config.get('password')
            ))
        
        # Secondary test account (for cross-user testing)
        if auth_config.get('test_account_2'):
            acc2 = auth_config['test_account_2']
            creds.append(TestCredentials(
                email=acc2.get('username', ''),
                password=acc2.get('password', '')
            ))
        
        return creds
    
    async def scan(self) -> List[ScanResult]:
        """Run comprehensive response swap attack tests"""
        logger.info("Starting Response Swap Attack Scanner...")
        logger.info("=" * 60)
        
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url:
            endpoints = getattr(self.context, 'endpoints', []) or []
            if endpoints:
                parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
                base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # Step 1: Discover authentication endpoints
            logger.info("[1/6] Discovering authentication endpoints...")
            auth_endpoints = await self._discover_endpoints(session, base_url)
            
            if not auth_endpoints.get('login'):
                logger.warning("No login endpoint found. Limited testing possible.")
                await self._passive_analysis(session, base_url)
                return self.results
            
            # Step 2: Analyze response patterns (without login)
            logger.info("[2/6] Analyzing response patterns...")
            await self._analyze_patterns(session, base_url, auth_endpoints)
            
            # Step 3: If we have test credentials, do active testing
            if self.test_credentials:
                logger.info("[3/6] Performing active authentication tests...")
                await self._active_token_testing(session, base_url, auth_endpoints)
                
                # Step 4: Test token binding
                logger.info("[4/6] Testing token-to-user binding...")
                await self._test_token_binding(session, base_url, auth_endpoints)
                
                # Step 5: Test OTP bypass if applicable
                logger.info("[5/6] Testing OTP/MFA bypass scenarios...")
                await self._test_otp_bypass(session, base_url, auth_endpoints)
                
            else:
                logger.warning("No test credentials configured. Using passive analysis only.")
                logger.info("Add auth.username and auth.password to config for full testing.")
                await self._passive_vulnerability_inference(session, base_url, auth_endpoints)
            
            # Step 6: Generate comprehensive findings
            logger.info("[6/6] Generating vulnerability assessment...")
            await self._generate_assessment(base_url, auth_endpoints)
        
        logger.info(f"Response Swap Scanner completed. Found {len(self.results)} issues.")
        return self.results
    
    async def _discover_endpoints(self, session: aiohttp.ClientSession, base_url: str) -> Dict[str, str]:
        """Discover login, OTP, and profile endpoints"""
        endpoints = {}
        
        # Common endpoint patterns
        patterns = {
            'login': ['/login', '/signin', '/auth/login', '/api/auth/login', '/api/login', '/api/v1/login'],
            'otp': ['/verify-otp', '/otp/verify', '/api/auth/verify-otp', '/mfa/verify', '/2fa/verify'],
            'profile': ['/me', '/profile', '/api/me', '/api/user', '/api/profile', '/api/v1/me'],
            'logout': ['/logout', '/signout', '/api/auth/logout', '/api/logout'],
        }
        
        for endpoint_type, paths in patterns.items():
            for path in paths:
                url = urljoin(base_url, path)
                try:
                    # Check with OPTIONS first
                    async with session.options(url) as resp:
                        if resp.status != 404:
                            endpoints[endpoint_type] = path
                            break
                    
                    # Try HEAD for GET endpoints
                    if endpoint_type in ['profile', 'logout']:
                        async with session.head(url) as resp:
                            if resp.status != 404:
                                endpoints[endpoint_type] = path
                                break
                    else:
                        # POST endpoints - try with empty body
                        async with session.post(url, json={}) as resp:
                            if resp.status != 404:
                                endpoints[endpoint_type] = path
                                break
                                
                except Exception as e:
                    logger.debug(f"Endpoint check error for {url}: {e}")
                
                await asyncio.sleep(0.02)
        
        logger.info(f"Discovered endpoints: {endpoints}")
        return endpoints
    
    async def _analyze_patterns(self, session: aiohttp.ClientSession, base_url: str, endpoints: Dict[str, str]):
        """Analyze success vs failure response patterns"""
        login_url = urljoin(base_url, endpoints.get('login', '/login'))
        
        # Get failure response
        failure_response = None
        try:
            async with session.post(login_url, json={
                'email': 'fake_test_nonexistent_12345@nowhere.invalid',
                'password': 'definitelywrongpassword123!@#'
            }) as resp:
                failure_response = {
                    'status': resp.status,
                    'body': await resp.text(),
                    'headers': dict(resp.headers),
                    'content_type': resp.content_type
                }
        except Exception as e:
            logger.debug(f"Failed to get failure response: {e}")
            return
        
        # Analyze failure response structure
        self._analyze_response_structure(failure_response, is_success=False)
    
    def _analyze_response_structure(self, response: Dict, is_success: bool = False):
        """Analyze response to understand what frontend receives"""
        body = response.get('body', '')
        status = response.get('status', 0)
        
        # Try to parse as JSON
        try:
            data = json.loads(body)
            
            # Check what fields are present
            user_identifying_fields = ['user_id', 'userId', 'email', 'username', 'id', 'sub']
            token_fields = ['token', 'access_token', 'accessToken', 'jwt', 'session']
            
            has_user_info = any(field in str(data).lower() for field in user_identifying_fields)
            has_token = any(field in str(data) for field in token_fields)
            
            logger.info(f"Response analysis - Status: {status}, Has user info: {has_user_info}, Has token: {has_token}")
            
            if is_success and has_token and not has_user_info:
                # Token returned but no user info - frontend must trust token blindly
                self.vuln_indicators['frontend_trust'] = True
                
        except json.JSONDecodeError:
            logger.debug("Response is not JSON")
    
    async def _active_token_testing(self, session: aiohttp.ClientSession, base_url: str, endpoints: Dict[str, str]):
        """Perform active testing with real credentials"""
        if not self.test_credentials:
            return
        
        login_url = urljoin(base_url, endpoints.get('login', '/login'))
        profile_url = urljoin(base_url, endpoints.get('profile', '/me'))
        
        creds = self.test_credentials[0]
        
        # Step 1: Login and get valid token
        logger.info(f"Attempting login with test account: {creds.email}")
        
        login_payload = {
            'email': creds.email,
            'password': creds.password
        }
        
        # Also try username variant
        login_payloads = [
            {'email': creds.email, 'password': creds.password},
            {'username': creds.email, 'password': creds.password},
        ]
        
        token = None
        success_response = None
        
        for payload in login_payloads:
            try:
                async with session.post(login_url, json=payload) as resp:
                    body = await resp.text()
                    
                    if resp.status == 200:
                        success_response = {
                            'status': resp.status,
                            'body': body,
                            'headers': dict(resp.headers)
                        }
                        
                        # Extract token
                        token = self._extract_token(body)
                        if token:
                            self.captured_tokens.append(token)
                            logger.info(f"Successfully captured token of type: {token.token_type}")
                            break
                            
            except Exception as e:
                logger.debug(f"Login attempt failed: {e}")
        
        if not token:
            logger.warning("Could not obtain valid token. Limited testing possible.")
            return
        
        # Step 2: Use token to access profile and verify user identity
        await self._verify_token_user_binding(session, profile_url, token)
        
        # Step 3: If we have second test account, test cross-user token usage
        if len(self.test_credentials) >= 2:
            await self._cross_user_token_test(session, base_url, endpoints, token)
    
    def _extract_token(self, body: str) -> Optional[AuthToken]:
        """Extract authentication token from response"""
        try:
            data = json.loads(body)
        except json.JSONDecodeError:
            return None
        
        # Look for token in common locations
        token_fields = [
            ('access_token', 'jwt'),
            ('accessToken', 'jwt'),
            ('token', 'jwt'),
            ('jwt', 'jwt'),
            ('id_token', 'jwt'),
            ('session', 'session'),
            ('sessionId', 'session'),
        ]
        
        token_value = None
        token_type = 'opaque'
        
        for field, t_type in token_fields:
            if field in data:
                token_value = data[field]
                token_type = t_type
                break
            # Check nested
            if 'data' in data and field in data['data']:
                token_value = data['data'][field]
                token_type = t_type
                break
        
        if not token_value:
            return None
        
        # Try to decode JWT claims
        claims = {}
        user_id = None
        email = None
        
        if token_type == 'jwt' and '.' in token_value:
            try:
                # Decode JWT payload
                parts = token_value.split('.')
                if len(parts) >= 2:
                    payload = parts[1]
                    # Add padding
                    padding = 4 - len(payload) % 4
                    if padding != 4:
                        payload += '=' * padding
                    
                    decoded = base64.urlsafe_b64decode(payload)
                    claims = json.loads(decoded)
                    
                    # Extract user identity from claims
                    user_id = claims.get('sub') or claims.get('user_id') or claims.get('userId')
                    email = claims.get('email') or claims.get('username')
                    
                    logger.info(f"JWT claims - User ID: {user_id}, Email: {email}")
                    
            except Exception as e:
                logger.debug(f"JWT decode error: {e}")
        
        return AuthToken(
            token=token_value,
            token_type=token_type,
            user_id=user_id,
            email=email,
            claims=claims,
            raw_response=body
        )
    
    async def _verify_token_user_binding(self, session: aiohttp.ClientSession, profile_url: str, token: AuthToken):
        """Verify that token is properly bound to user identity"""
        headers = {
            'Authorization': f'Bearer {token.token}',
            'Content-Type': 'application/json'
        }
        
        try:
            async with session.get(profile_url, headers=headers) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    try:
                        data = json.loads(body)
                        
                        # Get user identity from profile response
                        profile_user_id = data.get('id') or data.get('user_id') or data.get('userId')
                        profile_email = data.get('email') or data.get('username')
                        
                        # Compare with token claims
                        if token.user_id and profile_user_id:
                            if str(token.user_id) == str(profile_user_id):
                                logger.info("[OK] Token user ID matches profile user ID (secure)")
                            else:
                                logger.warning("[FAIL] Token user ID MISMATCH with profile - VULNERABILITY!")
                                self.vuln_indicators['weak_token_binding'] = True
                                
                        if token.email and profile_email:
                            if token.email.lower() == profile_email.lower():
                                logger.info("[OK] Token email matches profile email (secure)")
                            else:
                                logger.warning("[FAIL] Token email MISMATCH with profile - VULNERABILITY!")
                                self.vuln_indicators['weak_token_binding'] = True
                                
                    except json.JSONDecodeError:
                        pass
                        
        except Exception as e:
            logger.debug(f"Profile verification error: {e}")
    
    async def _cross_user_token_test(self, session: aiohttp.ClientSession, base_url: str, 
                                      endpoints: Dict[str, str], token_a: AuthToken):
        """Test if User A's token can access User B's resources"""
        if len(self.test_credentials) < 2:
            return
        
        creds_b = self.test_credentials[1]
        login_url = urljoin(base_url, endpoints.get('login', '/login'))
        profile_url = urljoin(base_url, endpoints.get('profile', '/me'))
        
        # Login as User B to get their user ID
        try:
            async with session.post(login_url, json={
                'email': creds_b.email,
                'password': creds_b.password
            }) as resp:
                if resp.status == 200:
                    body = await resp.text()
                    token_b = self._extract_token(body)
                    
                    if token_b:
                        logger.info(f"Got User B token. User A ID: {token_a.user_id}, User B ID: {token_b.user_id}")
                        
                        # Now use User A's token to access profile
                        headers = {'Authorization': f'Bearer {token_a.token}'}
                        
                        async with session.get(profile_url, headers=headers) as profile_resp:
                            if profile_resp.status == 200:
                                profile_data = await profile_resp.text()
                                profile_json = json.loads(profile_data)
                                
                                returned_id = profile_json.get('id') or profile_json.get('user_id')
                                
                                if str(returned_id) == str(token_a.user_id):
                                    logger.info("[OK] Token properly bound - Returns User A's profile (SECURE)")
                                elif str(returned_id) == str(token_b.user_id):
                                    logger.critical("[FAIL] CRITICAL: Token accepted for wrong user!")
                                    self._report_critical_vulnerability(
                                        "Cross-User Token Acceptance",
                                        f"User A's token ({token_a.email}) returns User B's ({creds_b.email}) profile",
                                        profile_url
                                    )
                                    
        except Exception as e:
            logger.debug(f"Cross-user test error: {e}")
    
    async def _test_token_binding(self, session: aiohttp.ClientSession, base_url: str, endpoints: Dict[str, str]):
        """Test various aspects of token binding security"""
        if not self.captured_tokens:
            return
        
        token = self.captured_tokens[0]
        profile_url = urljoin(base_url, endpoints.get('profile', '/me'))
        
        # Test 1: Token modification attacks
        await self._test_token_modification(session, profile_url, token)
        
        # Test 2: Check if server has independent session tracking
        await self._test_server_session(session, base_url, endpoints, token)
    
    async def _test_token_modification(self, session: aiohttp.ClientSession, profile_url: str, token: AuthToken):
        """Test if modified tokens are accepted"""
        if token.token_type != 'jwt':
            return
        
        # Try changing the user ID in JWT (won't have valid signature)
        modified_payloads = []
        
        if token.claims and token.user_id:
            # Create modified claims
            modified_claims = token.claims.copy()
            modified_claims['sub'] = 'attacker_id_12345'
            
            # Re-encode (without valid signature - this tests if signature is verified)
            parts = token.token.split('.')
            if len(parts) == 3:
                # Create new payload
                new_payload = base64.urlsafe_b64encode(
                    json.dumps(modified_claims).encode()
                ).decode().rstrip('=')
                
                # Test: header.new_payload.original_signature
                modified_token = f"{parts[0]}.{new_payload}.{parts[2]}"
                modified_payloads.append(('modified_payload', modified_token))
                
                # Test: None algorithm (if vulnerable)
                header = {"alg": "none", "typ": "JWT"}
                none_header = base64.urlsafe_b64encode(
                    json.dumps(header).encode()
                ).decode().rstrip('=')
                none_token = f"{none_header}.{new_payload}."
                modified_payloads.append(('alg_none', none_token))
        
        for attack_name, mod_token in modified_payloads:
            headers = {'Authorization': f'Bearer {mod_token}'}
            try:
                async with session.get(profile_url, headers=headers) as resp:
                    if resp.status == 200:
                        body = await resp.text()
                        try:
                            data = json.loads(body)
                            if data.get('id') or data.get('user_id'):
                                logger.critical(f"[FAIL] CRITICAL: Modified token ({attack_name}) accepted!")
                                self._report_critical_vulnerability(
                                    f"JWT {attack_name} Attack Success",
                                    f"Server accepted modified JWT token using {attack_name} attack",
                                    profile_url,
                                    cwe="CWE-347"
                                )
                        except:
                            pass
                    else:
                        logger.info(f"[OK] Modified token ({attack_name}) correctly rejected")
            except Exception as e:
                logger.debug(f"Token modification test error: {e}")
            
            await asyncio.sleep(0.1)
    
    async def _test_server_session(self, session: aiohttp.ClientSession, base_url: str, 
                                    endpoints: Dict[str, str], token: AuthToken):
        """Test if server maintains independent session state"""
        logout_url = urljoin(base_url, endpoints.get('logout', '/logout'))
        profile_url = urljoin(base_url, endpoints.get('profile', '/me'))
        
        headers = {'Authorization': f'Bearer {token.token}'}
        
        # First verify token works
        try:
            async with session.get(profile_url, headers=headers) as resp:
                if resp.status != 200:
                    return  # Token not working
        except:
            return
        
        # Now logout
        try:
            async with session.post(logout_url, headers=headers) as resp:
                pass
        except:
            pass
        
        await asyncio.sleep(0.5)
        
        # Try using token again after logout
        try:
            async with session.get(profile_url, headers=headers) as resp:
                if resp.status == 200:
                    logger.warning("Token still valid after logout - check token expiry")
                    
                    # This might not be a vulnerability if JWT is stateless with short expiry
                    # But it does mean response swap attacks are more viable
                    self.results.append(ScanResult(
                        id="RESP-SWAP-004",
                        category="A07:2021",
                        severity="medium",
                        title="Token Valid After Logout",
                        description="JWT token remains valid after logout. This enables response swap attacks as captured tokens can be reused.",
                        url=profile_url,
                        method="GET",
                        reasoning="Server uses stateless JWT without blacklist. Captured tokens remain valid until expiry.",
                        remediation="Implement token blacklist or use short token expiry with refresh tokens"
                    ))
                else:
                    logger.info("[OK] Token invalidated after logout (server-side session)")
                    
        except Exception as e:
            logger.debug(f"Post-logout test error: {e}")
    
    async def _test_otp_bypass(self, session: aiohttp.ClientSession, base_url: str, endpoints: Dict[str, str]):
        """Test OTP/MFA bypass via response manipulation"""
        otp_url = endpoints.get('otp')
        if not otp_url:
            # Try to discover
            otp_patterns = ['/verify-otp', '/otp/verify', '/mfa/verify', '/2fa/verify']
            for pattern in otp_patterns:
                url = urljoin(base_url, pattern)
                try:
                    async with session.post(url, json={'otp': '123456'}) as resp:
                        if resp.status != 404:
                            otp_url = pattern
                            break
                except:
                    pass
        
        if not otp_url:
            logger.info("No OTP endpoint found")
            return
        
        full_url = urljoin(base_url, otp_url)
        
        # Test OTP with wrong code
        try:
            async with session.post(full_url, json={'otp': '000000'}) as resp:
                status = resp.status
                body = await resp.text()
                
                # Analyze response
                if status in [400, 401, 403]:
                    # Check if response contains server-side state tracking
                    try:
                        data = json.loads(body)
                        
                        # If response contains attempts remaining, session state exists
                        if 'attempts' in str(data).lower() or 'remaining' in str(data).lower():
                            logger.info("[OK] OTP has server-side attempt tracking")
                        else:
                            # Check if OTP verification could be bypassed
                            logger.warning("OTP endpoint found - manual response swap testing recommended")
                            
                            self.results.append(ScanResult(
                                id="RESP-SWAP-005",
                                category="A07:2021",
                                severity="info",
                                title="OTP Endpoint Detected - Manual Testing Required",
                                description=f"OTP verification endpoint found at {otp_url}. Response swap attack may bypass OTP if server doesn't track verification state independently.",
                                url=full_url,
                                method="POST",
                                reasoning="If server only checks response status and doesn't maintain OTP-verified state, swapping failed OTP response with success could bypass MFA.",
                                remediation="Ensure OTP verification sets server-side session flag that is checked on subsequent requests.",
                                poc=self._generate_otp_bypass_poc(full_url)
                            ))
                            
                    except json.JSONDecodeError:
                        pass
                        
        except Exception as e:
            logger.debug(f"OTP test error: {e}")
    
    def _generate_otp_bypass_poc(self, otp_url: str) -> str:
        """Generate proof of concept for OTP bypass"""
        return f'''OTP Response Swap Attack PoC:

1. CAPTURE - Intercept a valid OTP success response:
   POST {otp_url}
   {{"otp": "VALID_OTP"}}
   
   Captured Success Response:
   {{"success": true, "message": "OTP verified", "verified": true}}

2. ATTACK - Submit wrong OTP while MITM is active:
   POST {otp_url}
   {{"otp": "000000"}}
   
   Server Response (intercepted): {{"error": "Invalid OTP"}}
   MITM Replaces With: {{"success": true, "message": "OTP verified", "verified": true}}

3. RESULT:
   If vulnerable: Frontend accepts fake success, skips to dashboard
   If secure: Server rejects subsequent requests (OTP not verified server-side)

MITM Proxy Command:
   mitmproxy -s response_swap_addon.py --set otp_url="{otp_url}"
'''
    
    async def _passive_vulnerability_inference(self, session: aiohttp.ClientSession, 
                                                base_url: str, endpoints: Dict[str, str]):
        """Analyze for vulnerabilities without credentials"""
        login_url = urljoin(base_url, endpoints.get('login', '/login'))
        
        # Get failure response
        try:
            async with session.post(login_url, json={
                'email': 'test_scan_account@nonexistent.invalid',
                'password': 'wrongpassword'
            }) as resp:
                status = resp.status
                body = await resp.text()
                
                # Analyze error response structure
                try:
                    data = json.loads(body)
                    
                    # Check if response reveals information useful for attack
                    analysis_points = []
                    
                    # 1. Does response contain user-identifying info?
                    if 'email' in str(data).lower() or 'user' in str(data).lower():
                        analysis_points.append("Response contains user-related fields")
                    
                    # 2. What's the response structure?
                    if 'success' in data or 'status' in data:
                        analysis_points.append("Boolean success field in response")
                    
                    if 'error' in data or 'message' in data:
                        analysis_points.append("Error/message field in response")
                    
                    if analysis_points:
                        self.results.append(ScanResult(
                            id="RESP-SWAP-PASSIVE-001",
                            category="A07:2021",
                            severity="info",
                            title="Response Pattern Analysis (Passive)",
                            description=f"Login endpoint analyzed. Pattern observations: {'; '.join(analysis_points)}",
                            url=login_url,
                            method="POST",
                            evidence=f"Response structure: {json.dumps(list(data.keys()))}",
                            reasoning="Response pattern analyzed for potential swap attack vectors. Configure test credentials for active testing.",
                            remediation="Ensure JWT/session tokens are cryptographically bound to user identity and verified on every request."
                        ))
                        
                except json.JSONDecodeError:
                    pass
                    
        except Exception as e:
            logger.debug(f"Passive analysis error: {e}")
    
    async def _passive_analysis(self, session: aiohttp.ClientSession, base_url: str):
        """Minimal passive analysis when no endpoints found"""
        self.results.append(ScanResult(
            id="RESP-SWAP-PASSIVE-002",
            category="A07:2021",
            severity="info",
            title="Response Swap Analysis - Limited",
            description="No authentication endpoints discovered. Manual testing recommended.",
            url=base_url,
            method="GET",
            reasoning="Could not find standard login/auth endpoints. Application may use non-standard paths.",
            remediation="Manually identify authentication endpoints and configure in scan config."
        ))
    
    async def _generate_assessment(self, base_url: str, endpoints: Dict[str, str]):
        """Generate final vulnerability assessment based on all findings"""
        
        # Check indicators and generate appropriate findings
        if self.vuln_indicators['weak_token_binding']:
            self._report_critical_vulnerability(
                "Weak Token-to-User Binding",
                "Server does not properly bind authentication tokens to user identity. Response swap attacks can allow login as different user.",
                base_url
            )
        
        if self.vuln_indicators['frontend_trust']:
            self.results.append(ScanResult(
                id="RESP-SWAP-003",
                category="A07:2021",
                severity="high",
                title="Frontend Trusts Response Without Validation",
                description="Frontend appears to trust authentication response without additional server-side validation. Response swap attack may succeed.",
                url=base_url,
                method="POST",
                reasoning="Success response contains token but no user-identifying information. Frontend may accept any valid-looking token.",
                remediation="Include user identity in signed token claims. Validate user on every protected request.",
                poc=self._generate_response_swap_poc(endpoints.get('login', '/login'))
            ))
        
        if self.vuln_indicators['otp_bypass_possible']:
            self.results.append(ScanResult(
                id="RESP-SWAP-006",
                category="A07:2021",
                severity="high",
                title="OTP Bypass via Response Manipulation Possible",
                description="OTP verification may be bypassed by swapping failure response with success.",
                url=base_url,
                method="POST",
                reasoning="OTP verification state not tracked server-side. Frontend-only verification can be bypassed.",
                remediation="Set server-side flag when OTP is verified. Check this flag on protected endpoints."
            ))
        
        # If no issues found but testing was limited
        if not self.results and not self.test_credentials:
            self.results.append(ScanResult(
                id="RESP-SWAP-INFO-001",
                category="A07:2021",
                severity="info",
                title="Response Swap Testing Incomplete - Credentials Required",
                description="Full response swap attack testing requires valid test credentials. Configure auth.username and auth.password in scan config.",
                url=base_url,
                method="N/A",
                reasoning="Active testing of token binding and cross-user attacks requires authentication.",
                remediation="Add test credentials to config for comprehensive security testing."
            ))
    
    def _report_critical_vulnerability(self, title: str, description: str, url: str, cwe: str = "CWE-287"):
        """Report a critical vulnerability"""
        self.results.append(ScanResult(
            id=f"RESP-SWAP-CRIT-{len(self.results)+1:03d}",
            category="A07:2021",
            severity="critical",
            title=title,
            description=description,
            url=url,
            method="POST",
            cwe_id=cwe,
            reasoning="Token/session not properly bound to user identity. Attacker can use their token to access other users.",
            remediation="Implement cryptographic binding between tokens and user identity. Validate user on every request."
        ))
    
    def _generate_response_swap_poc(self, login_path: str) -> str:
        """Generate PoC for response swap attack"""
        return f'''Response Swap Attack Proof of Concept:

PREREQUISITES:
1. Attacker has valid account (attacker@email.com)
2. MITM proxy (mitmproxy/Burp) between client and server

ATTACK STEPS:

1. CAPTURE - Login as attacker, save success response:
   POST {login_path}
   {{"email": "attacker@email.com", "password": "attacker_password"}}
   
   SAVE Response: {{"success": true, "token": "eyJhbG...<attacker_jwt>"}}

2. SETUP MITM - Configure proxy to replace responses:
   Rule: IF response.status != 200 AND request.path = "{login_path}"
         THEN replace response.body with captured success

3. EXECUTE - Try login as victim with wrong password:
   POST {login_path}
   {{"email": "victim@email.com", "password": "wrong_password"}}
   
   Server returns: 401 {{"error": "Invalid credentials"}}
   MITM replaces: 200 {{"success": true, "token": "eyJhbG...<attacker_jwt>"}}

4. VERIFY VULNERABILITY:
   - If victim's dashboard shows VICTIM's data: NOT VULNERABLE
     (Token is properly bound, attacker only sees their own data)
   - If victim's dashboard shows ATTACKER's data: PARTIALLY VULNERABLE
     (Token accepted but returns attacker's data)
   - If victim's dashboard shows other user's data: CRITICAL VULNERABILITY
     (No token validation, complete auth bypass)

MITM COMMAND:
   mitmproxy -s response_swap_addon.py --set target="{login_path}"
'''


# Export for module
__all__ = ['ResponseSwapScanner', 'ScanResult']
