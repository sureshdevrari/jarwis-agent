"""
SQLi Base Class - Shared logic for all SQL Injection sub-types
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, quote
from enum import Enum
import aiohttp

logger = logging.getLogger(__name__)


class DatabaseType(Enum):
    """Detected database type"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    MSSQL = "mssql"
    ORACLE = "oracle"
    SQLITE = "sqlite"
    UNKNOWN = "unknown"


@dataclass
class SQLiResult:
    """Result from SQLi scan - includes sub-type identification"""
    id: str
    category: str = "A03:2021 - Injection"
    sub_type: str = ""  # "error_based", "blind_boolean", "blind_time", "union_based"
    severity: str = "critical"  # SQLi is always critical
    title: str = ""
    description: str = ""
    url: str = ""
    method: str = "GET"
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = "CWE-89"
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""
    confidence: float = 0.0
    database_type: DatabaseType = DatabaseType.UNKNOWN
    extracted_data: str = ""  # Any data extracted via SQLi
    verification_status: str = "pending"


class SQLiBase:
    """
    Base class for all SQL Injection scanners.
    
    Provides shared functionality:
    - Payload management
    - Database fingerprinting
    - Error pattern detection
    - Request/response formatting
    """
    
    # Database-specific error patterns for fingerprinting
    DB_ERROR_PATTERNS = {
        DatabaseType.MYSQL: [
            r'SQL syntax.*?MySQL',
            r'mysql_fetch',
            r'mysql_num_rows',
            r'MySQL Query fail',
            r'You have an error in your SQL syntax',
            r'Warning.*?mysql_',
            r'MySqlClient\.',
            r'valid MySQL result',
        ],
        DatabaseType.POSTGRESQL: [
            r'PostgreSQL.*?ERROR',
            r'Warning.*?\bpg_',
            r'valid PostgreSQL result',
            r'Npgsql\.',
            r'PG::SyntaxError',
            r'org\.postgresql\.util\.PSQLException',
            r'ERROR:\s+syntax error at or near',
        ],
        DatabaseType.MSSQL: [
            r'Driver.*?SQL[\-\_\ ]*Server',
            r'OLE DB.*?SQL Server',
            r'Unclosed quotation mark after the character string',
            r'Microsoft SQL Native Client error',
            r'SQLServer JDBC Driver',
            r'com\.microsoft\.sqlserver\.jdbc',
            r'Incorrect syntax near',
            r'\bSQLServer\b',
        ],
        DatabaseType.ORACLE: [
            r'\bORA-[0-9]{5}',
            r'Oracle error',
            r'Oracle.*?Driver',
            r'Warning.*?\boci_',
            r'OracleException',
            r'quoted string not properly terminated',
        ],
        DatabaseType.SQLITE: [
            r'SQLite/JDBCDriver',
            r'SQLite\.Exception',
            r'System\.Data\.SQLite\.SQLiteException',
            r'Warning.*?sqlite_',
            r'sqlite3\.OperationalError',
            r'SQLite error',
            r'SQLITE_ERROR',
        ],
    }
    
    # Generic SQL error patterns
    GENERIC_SQL_ERRORS = [
        r'SQL syntax',
        r'sql error',
        r'syntax error',
        r'mysql error',
        r'unexpected end of SQL',
        r'quoted string not properly terminated',
        r'Unclosed quotation mark',
        r'unterminated string',
        r'Invalid query',
        r'SQLException',
        r'SqlException',
        r'ODBC.*?Driver',
        r'JDBC.*?Driver',
        r'database error',
        r'DB Error',
    ]
    
    # SQLi detection probes
    DETECTION_PROBES = [
        "'",           # Single quote
        '"',           # Double quote
        "''",          # Double single quote
        '`',           # Backtick
        "' OR '1'='1", # Classic boolean
        "1' AND '1'='1",
        "1 AND 1=1",
        "1 OR 1=1",
        "1' ORDER BY 1--",
        "' UNION SELECT NULL--",
    ]
    
    # Common bypass techniques
    BYPASS_TECHNIQUES = {
        'comment_injection': ['--', '#', '/**/'],
        'case_variation': ['UniOn', 'sElEcT', 'oR'],
        'encoding': ['%27', '%22', '%2527'],  # URL encoded
        'double_encoding': ['%2527', '%2522'],
        'unicode': ['\u0027', '\u0022'],
    }
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.findings: List[SQLiResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(context.target_url)
        self._baseline_responses: Dict[str, str] = {}
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within target scope"""
        if not url or not self._target_domain:
            return False
        try:
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            target = self._target_domain
            if url_domain.startswith('www.'):
                url_domain = url_domain[4:]
            if target.startswith('www.'):
                target = target[4:]
            return url_domain == target
        except:
            return False
    
    def _detect_database(self, response_body: str) -> DatabaseType:
        """Detect database type from error messages"""
        for db_type, patterns in self.DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return db_type
        return DatabaseType.UNKNOWN
    
    def _has_sql_error(self, response_body: str) -> Tuple[bool, Optional[str]]:
        """Check if response contains SQL error messages"""
        # Check database-specific errors
        for db_type, patterns in self.DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, response_body, re.IGNORECASE)
                if match:
                    return True, match.group(0)
        
        # Check generic errors
        for pattern in self.GENERIC_SQL_ERRORS:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return True, match.group(0)
        
        return False, None
    
    def _is_sql_injection_false_positive(
        self, 
        baseline_body: str, 
        injected_body: str,
        error_message: str
    ) -> bool:
        """
        Check for false positives.
        Returns True if this looks like a false positive.
        """
        # If error was already in baseline, it's a false positive
        if error_message and error_message in baseline_body:
            return True
        
        # If response is identical, likely false positive
        if baseline_body == injected_body:
            return True
        
        # Check for generic error pages (not SQL-specific)
        false_positive_patterns = [
            r'404 not found',
            r'page not found',
            r'access denied',
            r'forbidden',
            r'invalid request',
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, injected_body, re.IGNORECASE):
                if not self._has_sql_error(injected_body)[0]:
                    return True
        
        return False
    
    def _inject_payload(self, url: str, param: str, payload: str) -> str:
        """Inject payload into URL parameter"""
        encoded = quote(payload, safe='')
        
        if '?' in url:
            base, query = url.split('?', 1)
            params = {}
            for p in query.split('&'):
                if '=' in p:
                    k, v = p.split('=', 1)
                    params[k] = v
            params[param] = encoded
            return f"{base}?{'&'.join(f'{k}={v}' for k, v in params.items())}"
        else:
            return f"{url}?{param}={encoded}"
    
    def _format_request(self, method: str, url: str, headers: Dict, body: str = "") -> str:
        """Format request in Burp Suite style"""
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
        """Format response in Burp Suite style"""
        lines = [f"HTTP/1.1 {status}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if len(body) > 1500:
            body = body[:1500] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    def _generate_finding_id(self, prefix: str) -> str:
        """Generate unique finding ID"""
        self._finding_id += 1
        return f"{prefix}-{self._finding_id:04d}"
    
    async def _get_baseline(
        self, 
        session: aiohttp.ClientSession,
        url: str,
        method: str = "GET"
    ) -> Tuple[int, str, Dict]:
        """Get baseline response for comparison"""
        try:
            async with session.request(
                method,
                url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                body = await response.text()
                return response.status, body, dict(response.headers)
        except Exception as e:
            logger.error(f"Baseline request error: {e}")
            return 0, "", {}
    
    def _build_remediation(self) -> str:
        """Build SQL injection remediation guidance"""
        return """### Remediation

**1. Use Parameterized Queries (Primary Defense):**
```python
# Python - SAFE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))

# Java - SAFE
PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
stmt.setInt(1, userId);

# PHP - SAFE
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$userId]);
```

**2. Use ORM Frameworks:**
```python
# SQLAlchemy - SAFE
User.query.filter_by(id=user_id).first()

# Django ORM - SAFE
User.objects.get(id=user_id)
```

**3. Input Validation:**
- Validate data type (integer, email, etc.)
- Whitelist acceptable characters
- Reject suspicious patterns

**4. Least Privilege:**
- Use read-only database accounts where possible
- Limit database permissions per application

**5. Error Handling:**
- Never expose SQL errors to users
- Log errors server-side only
- Return generic error messages

**6. Web Application Firewall:**
- Deploy WAF rules to block SQLi patterns
- Monitor and alert on suspicious queries

**References:**
- OWASP SQL Injection Prevention Cheat Sheet
- CWE-89: SQL Injection
"""
    
    async def scan(self) -> List[SQLiResult]:
        """Override in subclasses"""
        raise NotImplementedError("Subclasses must implement scan()")
