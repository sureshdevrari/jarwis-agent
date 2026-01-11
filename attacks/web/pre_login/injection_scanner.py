"""
Jarwis AGI Pen Test - Injection Scanner
SQL Injection, Command Injection, NoSQL Injection detection
Uses OWASP Detection Logic for evidence-based detection
Enhanced with JavaScript rendering support for SPA applications
"""

import asyncio
import logging
import re
import subprocess
import time
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import aiohttp

# Import detection engine
try:
    from core.detection_logic import OWASPDetectionEngine, detection_engine
except ImportError:
    from ...core.detection_logic import OWASPDetectionEngine, detection_engine

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
    poc: str = ""  # Proof of Concept payload
    reasoning: str = ""  # Why this is detected as vulnerability
    request_data: str = ""  # Full request with headers (Burp-style)
    response_data: str = ""  # Full response with headers (Burp-style)


class InjectionScanner:
    """Scans for injection vulnerabilities (A03:2021)"""
    
    # SQL Injection payloads
    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "1' AND '1'='1",
        "1 OR 1=1",
        "1' OR '1'='1",
        "admin'--",
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL,NULL--",
        "1; DROP TABLE users--",
        "1' AND SLEEP(5)--",
        "1' WAITFOR DELAY '0:0:5'--",
    ]
    
    # SQL Error patterns - stricter patterns to reduce false positives
    SQLI_ERRORS = [
        (r"You have an error in your SQL syntax", "MySQL syntax error"),
        (r"Warning.*mysql_", "PHP MySQL warning"),
        (r"MySqlException", "MySQL exception"),
        (r"com\.mysql\.jdbc", "MySQL JDBC error"),
        (r"PostgreSQL.*ERROR", "PostgreSQL error"),
        (r"pg_query\(\).*failed", "PostgreSQL query error"),
        (r"ORA-\d{5}", "Oracle error code"),
        (r"Microsoft OLE DB Provider for SQL Server", "MSSQL OLE DB error"),
        (r"Unclosed quotation mark after the character string", "MSSQL syntax error"),
        (r"\[SQLITE_ERROR\]", "SQLite error"),
        (r"sqlite3\.OperationalError", "SQLite Python error"),
        (r"SQLSTATE\[", "PDO SQL error"),
        (r"SQL command not properly ended", "SQL syntax error"),
        (r"quoted string not properly terminated", "SQL quote error"),
        (r"Syntax error.*in query expression", "MS Access error"),
    ]
    
    # Command Injection payloads
    CMDI_PAYLOADS = [
        "; ls -la",
        "| ls -la",
        "& dir",
        "| cat /etc/passwd",
        "; cat /etc/passwd",
        "$(whoami)",
        "`whoami`",
        "| ping -c 3 127.0.0.1",
    ]
    
    # NoSQL Injection payloads
    NOSQLI_PAYLOADS = [
        '{"$gt":""}',
        '{"$ne":""}',
        '{"$regex":".*"}',
        "'; return this.password; var dummy='",
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Will be set by PreLoginAttacks if available
        self.use_js_rendering = config.get('js_rendering', True)  # Enable by default
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for scope checking"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
    def _is_in_scope(self, url: str) -> bool:
        """
        Check if URL is within target scope (STRICT domain matching).
        
        Subdomains are NOT included - each subdomain counts as a separate
        subscription token. Only the exact domain entered is in scope.
        www.example.com and example.com are treated as the same domain.
        """
        if not url or not self._target_domain:
            return False
        try:
            from core.scope import ScopeManager
            return ScopeManager(self.context.target_url).is_in_scope(url)
        except ImportError:
            # Fallback to strict matching
            from urllib.parse import urlparse
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            target_domain = self._target_domain
            # Strip www. prefix for both
            if url_domain.startswith('www.'):
                url_domain = url_domain[4:]
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
            return url_domain == target_domain
    
    def _format_request(self, method: str, url: str, headers: Dict, body: str = "") -> str:
        """Format request like Burp Suite"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        
        lines = [f"{method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if body:
            lines.append(body)
        return "\n".join(lines)
    
    def _format_response(self, status: int, headers: Dict, body: str) -> str:
        """Format response like Burp Suite"""
        lines = [f"HTTP/1.1 {status}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        # Truncate body if too long
        if len(body) > 1500:
            body = body[:1500] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    async def scan(self) -> List[ScanResult]:
        """Run injection scans on all endpoints"""
        self.findings = []
        
        # Filter endpoints with parameters
        testable_endpoints = [
            ep for ep in self.context.endpoints
            if ep.get('params') or '?' in ep.get('url', '')
        ]
        
        js_mode = "enabled" if (self.browser and self.use_js_rendering) else "disabled"
        logger.info(f"Testing {len(testable_endpoints)} endpoints for injection (JS rendering: {js_mode})")
        
        # If browser available, extract dynamic endpoints from JavaScript
        if self.browser and self.use_js_rendering:
            try:
                dynamic_endpoints = await self.browser.extract_dynamic_endpoints()
                for ep in dynamic_endpoints:
                    if ep.get('url') and ep not in testable_endpoints:
                        testable_endpoints.append(ep)
                logger.info(f"Added {len(dynamic_endpoints)} endpoints from JavaScript analysis")
            except Exception as e:
                logger.debug(f"Failed to extract JS endpoints: {e}")
        
        async with aiohttp.ClientSession() as session:
            for endpoint in testable_endpoints:
                await self._test_endpoint(session, endpoint)
                await asyncio.sleep(1 / self.rate_limit)
        
        return self.findings
    
    async def _get_rendered_response(self, url: str, method: str = 'GET', data: dict = None) -> Optional[str]:
        """Get JavaScript-rendered page content if browser available"""
        if not self.browser or not self.use_js_rendering:
            return None
        
        try:
            if method == 'POST' and data:
                result = await self.browser.render_with_payload(url, method, data)
            else:
                result = await self.browser.render_page(url)
            return result.get('html', '')
        except Exception as e:
            logger.debug(f"JS rendering failed for {url}: {e}")
            return None
    
    async def _test_endpoint(self, session: aiohttp.ClientSession, endpoint: Dict):
        """Test a single endpoint for injection vulnerabilities"""
        url = endpoint.get('url', '')
        method = endpoint.get('method', 'GET')
        params = endpoint.get('params', {})
        
        # Test each parameter
        for param_name in params:
            # SQL Injection
            await self._test_sqli(session, url, method, param_name)
            
            # Command Injection
            await self._test_cmdi(session, url, method, param_name)
            
            # NoSQL Injection
            await self._test_nosqli(session, url, method, param_name)
    
    async def _test_sqli(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ):
        """Test for SQL injection with proper verification"""
        # First, get baseline response
        baseline_url, baseline_data = self._inject_payload(url, method, param, "normalvalue123")
        baseline_body = ""
        try:
            async with session.request(
                method,
                baseline_url,
                headers=self.DEFAULT_HEADERS,
                data=baseline_data if method == 'POST' else None,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                baseline_body = await response.text()
        except:
            pass
        
        for i, payload in enumerate(self.SQLI_PAYLOADS[:5]):
            # VERBOSE LOGGING: Show each SQLi payload being tested
            logger.info(f"[SQLi] Testing payload {i+1}/5 on {param}: {payload}")
            
            try:
                test_url, test_data = self._inject_payload(url, method, param, payload)
                request_body = f"{param}={payload}" if test_data else ""
                
                async with session.request(
                    method,
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    data=test_data if method == 'POST' else None,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    resp_headers = dict(response.headers)
                    status = response.status
                    
                    # Check for SQL errors with strict verification
                    for pattern, error_name in self.SQLI_ERRORS:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            # VERIFICATION: Error must not appear in baseline
                            if not re.search(pattern, baseline_body, re.IGNORECASE):
                                # Format request and response like Burp
                                request_str = self._format_request(method, test_url, self.DEFAULT_HEADERS, request_body)
                                response_str = self._format_response(status, resp_headers, body)
                                
                                self._add_finding(
                                    category="A03",
                                    severity="high",
                                    title=f"SQL Injection in {param}",
                                    description=f"SQL database error '{error_name}' detected when injecting payload into {param} parameter. The error only appears with the malicious payload, confirming the vulnerability.",
                                    url=url,
                                    method=method,
                                    parameter=param,
                                    evidence=f"Error Type: {error_name}\nMatched Pattern: {pattern}\nMatched Text: {match.group(0)[:100]}",
                                    remediation="Use parameterized queries or prepared statements. Never concatenate user input directly into SQL queries.",
                                    cwe_id="CWE-89",
                                    poc=f"Payload: {payload}\n\nTo reproduce:\n1. Navigate to {url}\n2. Inject payload '{payload}' into parameter '{param}'\n3. Observe SQL error in response",
                                    reasoning=f"VERIFIED: Jarwis injected the SQL payload '{payload}' and detected a database-specific error message '{error_name}'. This error does NOT appear in normal responses (baseline tested), confirming the application directly embeds user input into SQL queries without sanitization.",
                                    request_data=request_str,
                                    response_data=response_str
                                )
                                return  # Found confirmed SQLi
                        
            except Exception as e:
                logger.debug(f"SQLi test failed for {url}: {e}")
    
    async def _test_cmdi(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ):
        """Test for command injection"""
        for i, payload in enumerate(self.CMDI_PAYLOADS[:3]):
            # VERBOSE LOGGING: Show each command injection payload
            logger.info(f"[CMDi] Testing payload {i+1}/3 on {param}: {payload}")
            
            try:
                test_url, test_data = self._inject_payload(url, method, param, payload)
                
                async with session.request(
                    method,
                    test_url,
                    data=test_data if method == 'POST' else None,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    # Check for command output
                    cmd_indicators = [
                        'root:x:0:0',  # /etc/passwd
                        'bin/bash',
                        'Volume Serial Number',  # Windows dir
                        'total ',  # ls output
                    ]
                    
                    for indicator in cmd_indicators:
                        if indicator in body:
                            self._add_finding(
                                category="A03",
                                severity="critical",
                                title=f"Command Injection in {param}",
                                description=f"OS command execution detected in {param} parameter",
                                url=url,
                                method=method,
                                parameter=param,
                                evidence=f"Payload: {payload}\nIndicator: {indicator}",
                                remediation="Avoid passing user input to system commands. Use allowlists if necessary.",
                                cwe_id="CWE-78",
                                poc=f"{method} {test_url}\nPayload: {payload}",
                                reasoning=f"Jarwis injected the OS command payload '{payload}' and detected system command output containing '{indicator}'. This proves the application is executing user-controlled input as operating system commands, which is a critical vulnerability allowing full system compromise.",
                                request_data=f"{method} {test_url}\nParameter: {param}={payload}",
                                response_snippet=body[:500] if len(body) > 500 else body
                            )
                            return
                            
            except Exception as e:
                logger.debug(f"CMDi test failed for {url}: {e}")
    
    async def _test_nosqli(
        self,
        session: aiohttp.ClientSession,
        url: str,
        method: str,
        param: str
    ):
        """Test for NoSQL injection"""
        for payload in self.NOSQLI_PAYLOADS:
            try:
                test_url, test_data = self._inject_payload(url, method, param, payload)
                
                async with session.request(
                    method,
                    test_url,
                    data=test_data if method == 'POST' else None,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    
                    # NoSQL errors
                    nosql_errors = [
                        'MongoError',
                        'MongoDB',
                        'CouchDB',
                        'RethinkDB',
                    ]
                    
                    for error in nosql_errors:
                        if error in body:
                            self._add_finding(
                                category="A03",
                                severity="high",
                                title=f"NoSQL Injection in {param}",
                                description=f"NoSQL error detected in {param} parameter",
                                url=url,
                                method=method,
                                parameter=param,
                                evidence=f"Payload: {payload}\nError: {error}",
                                remediation="Validate and sanitize all user input. Use typed queries.",
                                cwe_id="CWE-943",
                                poc=f"{method} {test_url}\nPayload: {payload}",
                                reasoning=f"Jarwis injected the NoSQL payload '{payload}' and detected a database error containing '{error}'. This indicates the application is vulnerable to NoSQL injection, allowing attackers to bypass authentication or extract data from the database.",
                                request_data=f"{method} {test_url}\nParameter: {param}={payload}",
                                response_snippet=body[:500] if len(body) > 500 else body
                            )
                            return
                            
            except Exception as e:
                logger.debug(f"NoSQLi test failed for {url}: {e}")
    
    def _inject_payload(
        self,
        url: str,
        method: str,
        param: str,
        payload: str
    ) -> tuple:
        """Inject payload into the appropriate location"""
        if method == 'GET':
            if '?' in url:
                base, query = url.split('?', 1)
                params = dict(p.split('=', 1) for p in query.split('&') if '=' in p)
                params[param] = payload
                new_query = '&'.join(f"{k}={v}" for k, v in params.items())
                return f"{base}?{new_query}", None
            else:
                return f"{url}?{param}={payload}", None
        else:
            return url, {param: payload}
    
    def _add_finding(self, **kwargs):
        """Add a finding to the results (only if in scope)"""
        url = kwargs.get('url', '')
        if url and not self._is_in_scope(url):
            logger.debug(f"Skipping out-of-scope finding: {url}")
            return
        
        self._finding_id += 1
        finding = ScanResult(
            id=f"INJ-{self._finding_id:04d}",
            **kwargs
        )
        self.findings.append(finding)
        logger.info(f"Found: {finding.title} at {finding.url}")
    
    async def run_sqlmap(self, url: str, param: str) -> Optional[Dict]:
        """Run sqlmap for deeper SQL injection testing"""
        try:
            cmd = [
                'sqlmap',
                '-u', f"{url}?{param}=1",
                '--batch',
                '--level', str(self.config.get('owasp', {}).get('injection', {}).get('sqlmap_level', 2)),
                '--risk', str(self.config.get('owasp', {}).get('injection', {}).get('sqlmap_risk', 2)),
                '--output-dir', '/tmp/sqlmap_output',
                '--forms',
                '--crawl=0'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if 'vulnerable' in result.stdout.lower():
                return {
                    'vulnerable': True,
                    'output': result.stdout
                }
            
            return {'vulnerable': False}
            
        except Exception as e:
            logger.error(f"sqlmap execution failed: {e}")
            return None
