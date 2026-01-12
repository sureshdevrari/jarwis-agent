"""
Jarwis AGI Pen Test - Mobile IDOR Scanner

Detects Insecure Direct Object Reference (IDOR) vulnerabilities in mobile APIs.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M1 - Improper Credential Usage
                          M3 - Insecure Authentication/Authorization
CWE-639: Authorization Bypass Through User-Controlled Key

Mobile-specific considerations:
- Mobile apps often cache user IDs client-side
- JWT tokens may contain user identifiers
- Object IDs may be exposed in API paths
- API versioning may bypass authorization
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from attacks.mobile.base_mobile_scanner import (
    BaseMobileScanner,
    MobileFinding,
    Severity,
    Confidence
)
from core.mobile_http_client import MobileHTTPClient, MobileAttackResponse
from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


class MobileIDORScanner(BaseMobileScanner):
    """
    IDOR Scanner for Mobile APIs
    
    Detects authorization bypass vulnerabilities where attackers
    can access other users' data by modifying object references.
    
    Attack vectors:
    - Numeric ID enumeration (id=1, id=2, id=3)
    - UUID manipulation
    - Token substitution (use token from user A for user B's data)
    - Path-based IDOR (/api/users/{id}/profile)
    - GraphQL node/relay ID tampering
    """
    
    # Scanner identification
    scanner_name = "mobile_idor"
    attack_type = "idor"
    vuln_type = "idor"  # Maps to VULN_REGISTRY
    owasp_category = "M3"  # Insecure Authentication/Authorization
    cwe_id = "CWE-639"
    
    # IDOR-prone parameter patterns
    IDOR_PARAMS = [
        'id', 'user_id', 'userId', 'uid', 'user', 'account',
        'accountId', 'account_id', 'profile', 'profileId',
        'doc', 'docId', 'document', 'documentId', 'file', 'fileId',
        'order', 'orderId', 'order_id', 'transaction', 'transactionId',
        'message', 'messageId', 'msg', 'msgId', 'chat', 'chatId',
        'invoice', 'invoiceId', 'payment', 'paymentId',
        'customer', 'customerId', 'client', 'clientId',
        'owner', 'ownerId', 'author', 'authorId',
        'record', 'recordId', 'item', 'itemId', 'product', 'productId'
    ]
    
    # UUID pattern
    UUID_PATTERN = re.compile(
        r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
    )
    
    # Numeric ID pattern
    NUMERIC_ID_PATTERN = re.compile(r'^[0-9]+$')
    
    # Path-based ID patterns
    PATH_ID_PATTERNS = [
        r'/users?/(\d+)',
        r'/profiles?/(\d+)',
        r'/accounts?/(\d+)',
        r'/orders?/(\d+)',
        r'/documents?/(\d+)',
        r'/files?/(\d+)',
        r'/messages?/(\d+)',
        r'/api/v\d+/[^/]+/(\d+)',
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        test_user_token: Optional[str] = None,
        alt_user_ids: Optional[List[str]] = None,
        **kwargs
    ):
        """
        Initialize Mobile IDOR Scanner.
        
        Args:
            http_client: Mobile HTTP client
            request_store: Mobile request store
            test_user_token: Auth token for a different test user (for token swap)
            alt_user_ids: Alternative user IDs to test
        """
        super().__init__(http_client, request_store, **kwargs)
        self.test_user_token = test_user_token
        self.alt_user_ids = alt_user_ids or ['1', '2', '999', '0', '-1', 'admin']
        
        # Track IDs we've already seen
        self._seen_ids: Dict[str, set] = {}
    
    def get_payloads(self) -> List[str]:
        """Return ID manipulation payloads."""
        return self.alt_user_ids
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request should be tested for IDOR."""
        # Look for IDOR-prone parameters
        if request.parameters:
            param_names = [p.lower() for p in request.parameters.keys()]
            for idor_param in self.IDOR_PARAMS:
                if idor_param.lower() in param_names:
                    return True
        
        # Check URL path for ID patterns
        for pattern in self.PATH_ID_PATTERNS:
            if re.search(pattern, request.url, re.IGNORECASE):
                return True
        
        # Check for UUID in URL
        if self.UUID_PATTERN.search(request.url):
            return True
        
        return False
    
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a request for IDOR vulnerabilities.
        
        Flow:
        1. Identify potential object references (IDs, UUIDs)
        2. Get baseline response with original ID
        3. Attempt ID manipulation attacks
        4. Check if we can access other users' data
        5. Test token substitution if available
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        # Must get a successful response to compare
        if baseline.status_code >= 400:
            return findings
        
        # 1. Test parameter-based IDOR
        param_findings = await self._test_parameter_idor(request, baseline)
        findings.extend(param_findings)
        
        # 2. Test path-based IDOR
        path_findings = await self._test_path_idor(request, baseline)
        findings.extend(path_findings)
        
        # 3. Test token substitution (if we have alt token)
        if self.test_user_token:
            token_findings = await self._test_token_substitution(request, baseline)
            findings.extend(token_findings)
        
        return findings
    
    async def _test_parameter_idor(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> List[MobileFinding]:
        """Test IDOR via parameter manipulation."""
        findings = []
        
        if not request.parameters:
            return findings
        
        for param_name, original_value in request.parameters.items():
            # Check if this is an IDOR-prone parameter
            param_lower = param_name.lower()
            is_idor_param = any(
                idor_p.lower() in param_lower for idor_p in self.IDOR_PARAMS
            )
            
            # Also check if value looks like an ID
            is_id_value = (
                self.NUMERIC_ID_PATTERN.match(str(original_value)) or
                self.UUID_PATTERN.match(str(original_value))
            )
            
            if not (is_idor_param or is_id_value):
                continue
            
            # Generate alternative IDs to test
            test_ids = self._generate_alt_ids(str(original_value))
            
            for alt_id in test_ids:
                if alt_id == original_value:
                    continue
                
                # Send request with modified ID
                response = await self.send_payload(
                    request=request,
                    payload=alt_id,
                    location=self._get_param_location(request, param_name),
                    parameter_name=param_name
                )
                
                if not response:
                    continue
                
                # Analyze for IDOR
                is_idor, evidence = self._analyze_idor_response(
                    baseline, response, param_name, original_value, alt_id
                )
                
                if is_idor:
                    findings.append(self.create_finding(
                        request=request,
                        response=response,
                        payload=alt_id,
                        evidence=evidence,
                        confidence=Confidence.HIGH,
                        severity=Severity.HIGH,
                        title=f"IDOR via '{param_name}' parameter",
                        description=(
                            f"The '{param_name}' parameter can be manipulated to access "
                            f"other users' data. Original ID '{original_value}' was changed "
                            f"to '{alt_id}' and returned valid data that belongs to another "
                            f"user. This violates authorization controls."
                        ),
                        parameter=param_name
                    ))
                    break  # One finding per parameter
        
        return findings
    
    async def _test_path_idor(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> List[MobileFinding]:
        """Test IDOR via URL path manipulation."""
        findings = []
        
        for pattern in self.PATH_ID_PATTERNS:
            match = re.search(pattern, request.url, re.IGNORECASE)
            if not match:
                continue
            
            original_id = match.group(1)
            original_span = match.span(1)
            
            # Generate alternative IDs
            test_ids = self._generate_alt_ids(original_id)
            
            for alt_id in test_ids:
                if alt_id == original_id:
                    continue
                
                # Construct new URL with modified ID
                new_url = (
                    request.url[:original_span[0]] +
                    alt_id +
                    request.url[original_span[1]:]
                )
                
                # Send request with modified URL
                response = await self._send_modified_url_request(request, new_url)
                
                if not response:
                    continue
                
                # Analyze for IDOR
                is_idor, evidence = self._analyze_idor_response(
                    baseline, response, 'url_path', original_id, alt_id
                )
                
                if is_idor:
                    findings.append(self.create_finding(
                        request=request,
                        response=response,
                        payload=alt_id,
                        evidence=evidence,
                        confidence=Confidence.HIGH,
                        severity=Severity.HIGH,
                        title=f"IDOR via URL path",
                        description=(
                            f"The object ID in the URL path can be manipulated to access "
                            f"other users' data. Changed ID from '{original_id}' to "
                            f"'{alt_id}' in path and received valid data."
                        ),
                        parameter='url_path_id'
                    ))
                    break
        
        return findings
    
    async def _test_token_substitution(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> List[MobileFinding]:
        """Test IDOR via auth token substitution."""
        findings = []
        
        if not self.test_user_token:
            return findings
        
        # Save original auth
        original_auth = self.http_client.auth_header
        
        try:
            # Set alternative user's token
            self.http_client.set_auth_header(
                f"Bearer {self.test_user_token}"
            )
            
            # Replay same request with different token
            response = await self.http_client.send_attack_from_request(
                stored_request=request
            )
            
            if not response:
                return findings
            
            # Check if we accessed the original user's data with different token
            if response.status_code == 200:
                # Compare responses to see if we got same data
                if self._responses_similar(baseline, response):
                    findings.append(self.create_finding(
                        request=request,
                        response=response,
                        payload="[token_substitution]",
                        evidence=(
                            f"Request successful with different user's token. "
                            f"Both responses returned {response.status_code} with "
                            f"similar content ({len(response.body or '')} bytes)."
                        ),
                        confidence=Confidence.MEDIUM,
                        severity=Severity.CRITICAL,
                        title="IDOR via Token Substitution",
                        description=(
                            f"Using a different user's authentication token allows "
                            f"accessing this user's data. This indicates missing "
                            f"or broken object-level authorization."
                        ),
                        parameter='authorization_token'
                    ))
        finally:
            # Restore original auth
            if original_auth:
                self.http_client.set_auth_header(original_auth)
        
        return findings
    
    def _generate_alt_ids(self, original_id: str) -> List[str]:
        """Generate alternative IDs to test."""
        test_ids = []
        
        # If numeric ID
        if self.NUMERIC_ID_PATTERN.match(original_id):
            id_int = int(original_id)
            test_ids = [
                str(id_int + 1),      # Next ID
                str(id_int - 1),      # Previous ID
                '1',                   # First ID
                '0',                   # Edge case
                str(id_int * 2),      # Random other
            ]
        # If UUID
        elif self.UUID_PATTERN.match(original_id):
            # Flip some bytes to create similar but different UUID
            uuid_parts = original_id.split('-')
            uuid_parts[0] = uuid_parts[0][:7] + ('0' if uuid_parts[0][7] != '0' else '1')
            test_ids = ['-'.join(uuid_parts)]
        else:
            # Try our configured alt IDs
            test_ids = self.alt_user_ids.copy()
        
        return test_ids[:5]  # Limit to 5 tests
    
    def _get_param_location(
        self,
        request: StoredMobileRequest,
        param_name: str
    ) -> str:
        """Determine parameter location."""
        if '?' in request.url and param_name in request.url:
            return 'query'
        if request.body and param_name in request.body:
            return 'body'
        return 'query' if request.method.upper() == 'GET' else 'body'
    
    def _analyze_idor_response(
        self,
        baseline: MobileAttackResponse,
        response: MobileAttackResponse,
        param_name: str,
        original_id: str,
        alt_id: str
    ) -> Tuple[bool, str]:
        """Analyze response to determine if IDOR exists."""
        
        # 403/401 = authorization working correctly
        if response.status_code in [401, 403]:
            return False, "Access denied (authorization working)"
        
        # 404 = object not found (may or may not be IDOR)
        if response.status_code == 404:
            return False, "Object not found"
        
        # 200 with valid data = potential IDOR
        if response.status_code == 200:
            # Check if response contains actual data
            body = response.body or ""
            
            # Check for common indicators of valid data
            indicators = [
                len(body) > 50,  # Has content
                response.json() is not None,  # Valid JSON
                alt_id in body,  # Contains the accessed ID
            ]
            
            if any(indicators):
                # Check if response differs from baseline (different user's data)
                if not self._responses_similar(baseline, response):
                    evidence = (
                        f"Changed '{param_name}' from '{original_id}' to '{alt_id}'. "
                        f"Received {response.status_code} with different data "
                        f"({len(body)} bytes). This appears to be another user's data."
                    )
                    return True, evidence
        
        return False, ""
    
    def _responses_similar(
        self,
        response1: MobileAttackResponse,
        response2: MobileAttackResponse
    ) -> bool:
        """Check if two responses are similar (same data)."""
        # Same status code required
        if response1.status_code != response2.status_code:
            return False
        
        # Compare content length (within 10%)
        len1 = len(response1.body or '')
        len2 = len(response2.body or '')
        if len1 > 0 and len2 > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            if diff_ratio > 0.1:
                return False
        
        # Compare JSON structure if applicable
        json1 = response1.json()
        json2 = response2.json()
        if json1 and json2:
            return json.dumps(json1, sort_keys=True) == json.dumps(json2, sort_keys=True)
        
        return (response1.body or '') == (response2.body or '')
    
    async def _send_modified_url_request(
        self,
        request: StoredMobileRequest,
        new_url: str
    ) -> Optional[MobileAttackResponse]:
        """Send request with modified URL."""
        try:
            # Use http_client directly
            return await self.http_client.send_attack(
                url=new_url,
                method=request.method,
                headers=dict(request.headers) if request.headers else {},
                body=request.body
            )
        except Exception as e:
            logger.debug(f"Error sending modified URL request: {e}")
            return None
