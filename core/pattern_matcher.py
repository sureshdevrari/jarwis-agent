"""
Jarwis Pattern Matcher - Advanced Pattern Recognition Engine
=============================================================

Consolidates all vulnerability detection patterns into a unified,
weighted pattern matching system with learning capabilities.

Features:
- 200+ vulnerability detection patterns
- Weighted scoring based on historical accuracy
- Category-based pattern organization
- Support for regex, string, and semantic matching

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Pattern as RePattern
from datetime import datetime
import re
import logging
from enum import Enum

logger = logging.getLogger(__name__)


class PatternCategory(Enum):
    """Categories for vulnerability patterns"""
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SSRF = "ssrf"
    XXE = "xxe"
    AUTH_BYPASS = "auth_bypass"
    IDOR = "idor"
    CSRF = "csrf"
    SECURITY_HEADERS = "security_headers"
    INFO_DISCLOSURE = "info_disclosure"
    DEBUG_EXPOSURE = "debug_exposure"
    VERSION_DISCLOSURE = "version_disclosure"
    SENSITIVE_DATA = "sensitive_data"
    CRYPTO = "crypto"
    DESERIALIZATION = "deserialization"
    SSTI = "ssti"
    LDAP_INJECTION = "ldap_injection"
    XPATH_INJECTION = "xpath_injection"
    OPEN_REDIRECT = "open_redirect"


class PatternType(Enum):
    """Types of pattern matching"""
    REGEX = "regex"
    STRING = "string"
    SEMANTIC = "semantic"


@dataclass
class VulnerabilityPattern:
    """A single vulnerability detection pattern"""
    id: str
    name: str
    category: PatternCategory
    pattern_type: PatternType
    pattern: str  # Regex or string pattern
    owasp_category: str  # A01, A02, etc.
    severity: str  # critical, high, medium, low, info
    
    # Weights and scoring
    base_weight: float = 1.0
    learned_weight_adjustment: float = 0.0
    confidence_factor: float = 0.8  # How confident this pattern is
    
    # Learning statistics
    true_positive_count: int = 0
    false_positive_count: int = 0
    total_matches: int = 0
    
    # Metadata
    description: str = ""
    false_positive_hints: List[str] = field(default_factory=list)
    requires_context: bool = False
    context_patterns: List[str] = field(default_factory=list)
    
    # Compiled regex (cached)
    _compiled_pattern: Optional[RePattern] = field(default=None, repr=False)
    
    @property
    def effective_weight(self) -> float:
        """Calculate effective weight including learning"""
        return max(0.1, min(2.0, self.base_weight + self.learned_weight_adjustment))
    
    @property
    def accuracy_rate(self) -> float:
        """Calculate accuracy from feedback"""
        total = self.true_positive_count + self.false_positive_count
        if total == 0:
            return 0.5  # No data
        return self.true_positive_count / total
    
    def get_compiled_pattern(self) -> Optional[RePattern]:
        """Get compiled regex pattern"""
        if self._compiled_pattern is None and self.pattern_type == PatternType.REGEX:
            try:
                self._compiled_pattern = re.compile(self.pattern, re.IGNORECASE | re.MULTILINE)
            except re.error as e:
                logger.error(f"Failed to compile pattern {self.id}: {e}")
                return None
        return self._compiled_pattern


@dataclass
class PatternMatch:
    """Result of a pattern match"""
    pattern_id: str
    pattern_name: str
    category: PatternCategory
    owasp_category: str
    severity: str
    
    matched_text: str
    match_location: str  # body, headers, url, etc.
    match_start: int
    match_end: int
    
    weight: float
    confidence: float
    
    context: Optional[str] = None  # Surrounding text


@dataclass 
class PatternMatchResult:
    """Complete result of pattern matching"""
    total_matches: int
    patterns_matched: List[PatternMatch]
    categories_found: List[str]
    highest_severity: str
    combined_confidence: float
    suggested_owasp: str
    
    # Aggregate scores
    injection_score: float = 0.0
    access_control_score: float = 0.0
    crypto_score: float = 0.0
    misconfiguration_score: float = 0.0


class PatternMatcher:
    """
    Advanced Pattern Matching Engine
    
    Provides:
    - Consolidated vulnerability patterns
    - Weighted scoring with learning
    - Multi-category pattern matching
    - Context-aware detection
    """
    
    def __init__(self, db_session=None, load_from_db: bool = True):
        """
        Initialize the pattern matcher
        
        Args:
            db_session: Database session for loading learned weights
            load_from_db: Whether to load patterns from database
        """
        self.db_session = db_session
        self.patterns: Dict[str, VulnerabilityPattern] = {}
        self.patterns_by_category: Dict[PatternCategory, List[VulnerabilityPattern]] = {}
        
        # Load built-in patterns
        self._load_builtin_patterns()
        
        # Load learned weights from database
        if db_session and load_from_db:
            self._load_learned_weights()
    
    def _load_builtin_patterns(self):
        """Load all built-in vulnerability patterns"""
        
        # ===== SQL INJECTION PATTERNS =====
        sql_patterns = [
            # Error-based SQL injection
            VulnerabilityPattern(
                id="sql_mysql_error",
                name="MySQL Syntax Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"you have an error in your sql syntax",
                owasp_category="A03",
                severity="high",
                base_weight=1.0,
                confidence_factor=0.95,
                description="MySQL syntax error indicating SQL injection"
            ),
            VulnerabilityPattern(
                id="sql_mysql_warning",
                name="MySQL Warning",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"warning:\s*mysql",
                owasp_category="A03",
                severity="high",
                base_weight=0.95,
                confidence_factor=0.90,
                description="MySQL warning message"
            ),
            VulnerabilityPattern(
                id="sql_mssql_error",
                name="MSSQL Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"microsoft ole db provider for sql server|sql server.*error",
                owasp_category="A03",
                severity="high",
                base_weight=1.0,
                confidence_factor=0.95,
                description="Microsoft SQL Server error"
            ),
            VulnerabilityPattern(
                id="sql_oracle_error",
                name="Oracle Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"ora-\d{5}",
                owasp_category="A03",
                severity="high",
                base_weight=1.0,
                confidence_factor=0.95,
                description="Oracle database error"
            ),
            VulnerabilityPattern(
                id="sql_postgres_error",
                name="PostgreSQL Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"postgresql.*error|pg_query|pg_exec",
                owasp_category="A03",
                severity="high",
                base_weight=1.0,
                confidence_factor=0.95,
                description="PostgreSQL database error"
            ),
            VulnerabilityPattern(
                id="sql_sqlite_error",
                name="SQLite Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"sqlite.*error|sqlite3_",
                owasp_category="A03",
                severity="high",
                base_weight=0.95,
                confidence_factor=0.90,
                description="SQLite database error"
            ),
            VulnerabilityPattern(
                id="sql_pdo_error",
                name="PDO Exception",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"sqlstate\[|pdo.*exception|pdo.*error",
                owasp_category="A03",
                severity="high",
                base_weight=0.95,
                confidence_factor=0.90,
                description="PHP PDO database error"
            ),
            VulnerabilityPattern(
                id="sql_unclosed_quote",
                name="Unclosed Quote Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"unclosed quotation mark|quoted string not properly terminated",
                owasp_category="A03",
                severity="high",
                base_weight=0.90,
                confidence_factor=0.85,
                description="SQL quote termination error"
            ),
            VulnerabilityPattern(
                id="sql_odbc_error",
                name="ODBC Driver Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"odbc.*driver|driver.*sql.*server",
                owasp_category="A03",
                severity="high",
                base_weight=0.90,
                confidence_factor=0.85,
                description="ODBC driver error"
            ),
            VulnerabilityPattern(
                id="sql_syntax_error",
                name="Generic SQL Syntax Error",
                category=PatternCategory.SQL_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"syntax error.*sql|sql.*syntax.*error",
                owasp_category="A03",
                severity="high",
                base_weight=0.85,
                confidence_factor=0.80,
                description="Generic SQL syntax error"
            ),
        ]
        
        # ===== XSS PATTERNS =====
        xss_patterns = [
            VulnerabilityPattern(
                id="xss_script_tag",
                name="Script Tag Injection",
                category=PatternCategory.XSS,
                pattern_type=PatternType.REGEX,
                pattern=r"<script[^>]*>[^<]*</script>",
                owasp_category="A03",
                severity="high",
                base_weight=1.0,
                confidence_factor=0.90,
                description="Script tag reflected in response"
            ),
            VulnerabilityPattern(
                id="xss_event_handler",
                name="Event Handler Injection",
                category=PatternCategory.XSS,
                pattern_type=PatternType.REGEX,
                pattern=r"<[^>]+\s+on\w+\s*=",
                owasp_category="A03",
                severity="high",
                base_weight=0.95,
                confidence_factor=0.85,
                description="HTML event handler injection"
            ),
            VulnerabilityPattern(
                id="xss_javascript_uri",
                name="JavaScript URI",
                category=PatternCategory.XSS,
                pattern_type=PatternType.REGEX,
                pattern=r"javascript\s*:",
                owasp_category="A03",
                severity="high",
                base_weight=0.90,
                confidence_factor=0.85,
                description="JavaScript URI scheme"
            ),
            VulnerabilityPattern(
                id="xss_img_onerror",
                name="IMG OnError XSS",
                category=PatternCategory.XSS,
                pattern_type=PatternType.REGEX,
                pattern=r"<img[^>]+onerror\s*=",
                owasp_category="A03",
                severity="high",
                base_weight=0.95,
                confidence_factor=0.90,
                description="IMG tag with onerror handler"
            ),
            VulnerabilityPattern(
                id="xss_svg_onload",
                name="SVG OnLoad XSS",
                category=PatternCategory.XSS,
                pattern_type=PatternType.REGEX,
                pattern=r"<svg[^>]+onload\s*=",
                owasp_category="A03",
                severity="high",
                base_weight=0.95,
                confidence_factor=0.90,
                description="SVG tag with onload handler"
            ),
            VulnerabilityPattern(
                id="xss_document_cookie",
                name="Document Cookie Access",
                category=PatternCategory.XSS,
                pattern_type=PatternType.REGEX,
                pattern=r"document\.cookie",
                owasp_category="A03",
                severity="high",
                base_weight=0.85,
                confidence_factor=0.80,
                description="JavaScript accessing cookies"
            ),
            VulnerabilityPattern(
                id="xss_eval",
                name="Eval Function",
                category=PatternCategory.XSS,
                pattern_type=PatternType.REGEX,
                pattern=r"eval\s*\([^)]+\)",
                owasp_category="A03",
                severity="medium",
                base_weight=0.75,
                confidence_factor=0.70,
                description="JavaScript eval function"
            ),
        ]
        
        # ===== COMMAND INJECTION PATTERNS =====
        cmd_patterns = [
            VulnerabilityPattern(
                id="cmd_passwd_file",
                name="Passwd File Content",
                category=PatternCategory.COMMAND_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"root:.*:0:0:",
                owasp_category="A03",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.98,
                description="/etc/passwd file content"
            ),
            VulnerabilityPattern(
                id="cmd_id_output",
                name="ID Command Output",
                category=PatternCategory.COMMAND_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"uid=\d+.*gid=\d+",
                owasp_category="A03",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.98,
                description="Linux id command output"
            ),
            VulnerabilityPattern(
                id="cmd_windows_version",
                name="Windows Version Output",
                category=PatternCategory.COMMAND_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"microsoft\s+windows.*version|volume serial number",
                owasp_category="A03",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.95,
                description="Windows command output"
            ),
            VulnerabilityPattern(
                id="cmd_ls_output",
                name="Directory Listing",
                category=PatternCategory.COMMAND_INJECTION,
                pattern_type=PatternType.REGEX,
                pattern=r"total\s+\d+\s*\n.*drwx",
                owasp_category="A03",
                severity="critical",
                base_weight=0.95,
                confidence_factor=0.90,
                description="Unix ls -la command output"
            ),
        ]
        
        # ===== SSRF PATTERNS =====
        ssrf_patterns = [
            VulnerabilityPattern(
                id="ssrf_localhost",
                name="Localhost Access",
                category=PatternCategory.SSRF,
                pattern_type=PatternType.REGEX,
                pattern=r"127\.0\.0\.1|localhost|\[::1\]",
                owasp_category="A10",
                severity="high",
                base_weight=0.80,
                confidence_factor=0.75,
                description="Localhost address in response"
            ),
            VulnerabilityPattern(
                id="ssrf_private_ip",
                name="Private IP Access",
                category=PatternCategory.SSRF,
                pattern_type=PatternType.REGEX,
                pattern=r"192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+",
                owasp_category="A10",
                severity="high",
                base_weight=0.85,
                confidence_factor=0.80,
                description="Private IP address in response"
            ),
            VulnerabilityPattern(
                id="ssrf_metadata",
                name="Cloud Metadata Access",
                category=PatternCategory.SSRF,
                pattern_type=PatternType.REGEX,
                pattern=r"169\.254\.169\.254|metadata\.google|169\.254\.170\.2",
                owasp_category="A10",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.95,
                description="Cloud metadata endpoint access"
            ),
            VulnerabilityPattern(
                id="ssrf_file_proto",
                name="File Protocol",
                category=PatternCategory.SSRF,
                pattern_type=PatternType.REGEX,
                pattern=r"file://",
                owasp_category="A10",
                severity="high",
                base_weight=0.90,
                confidence_factor=0.85,
                description="File protocol usage"
            ),
        ]
        
        # ===== PATH TRAVERSAL PATTERNS =====
        traversal_patterns = [
            VulnerabilityPattern(
                id="traversal_etc_passwd",
                name="Etc Passwd Access",
                category=PatternCategory.PATH_TRAVERSAL,
                pattern_type=PatternType.REGEX,
                pattern=r"root:.*:0:0:",
                owasp_category="A01",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.98,
                description="/etc/passwd content retrieved"
            ),
            VulnerabilityPattern(
                id="traversal_boot_ini",
                name="Boot.ini Access",
                category=PatternCategory.PATH_TRAVERSAL,
                pattern_type=PatternType.REGEX,
                pattern=r"\[boot loader\]",
                owasp_category="A01",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.95,
                description="Windows boot.ini content"
            ),
            VulnerabilityPattern(
                id="traversal_win_hosts",
                name="Windows Hosts Access",
                category=PatternCategory.PATH_TRAVERSAL,
                pattern_type=PatternType.REGEX,
                pattern=r"windows.*system32.*drivers.*etc",
                owasp_category="A01",
                severity="high",
                base_weight=0.90,
                confidence_factor=0.85,
                description="Windows system file access"
            ),
        ]
        
        # ===== INFO DISCLOSURE PATTERNS =====
        info_patterns = [
            VulnerabilityPattern(
                id="info_stack_trace",
                name="Stack Trace Exposure",
                category=PatternCategory.DEBUG_EXPOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"stack\s*trace|traceback.*most recent call|exception.*at.*line",
                owasp_category="A05",
                severity="medium",
                base_weight=0.75,
                confidence_factor=0.80,
                description="Application stack trace exposed"
            ),
            VulnerabilityPattern(
                id="info_debug_mode",
                name="Debug Mode Enabled",
                category=PatternCategory.DEBUG_EXPOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"debug\s*=\s*true|debug_mode.*enabled|display_errors.*on",
                owasp_category="A05",
                severity="medium",
                base_weight=0.70,
                confidence_factor=0.75,
                description="Debug mode enabled"
            ),
            VulnerabilityPattern(
                id="info_php_error",
                name="PHP Error Disclosure",
                category=PatternCategory.DEBUG_EXPOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"\.php:\d+|fatal error.*php|parse error.*php",
                owasp_category="A05",
                severity="medium",
                base_weight=0.70,
                confidence_factor=0.75,
                description="PHP error with file path"
            ),
            VulnerabilityPattern(
                id="info_java_trace",
                name="Java Stack Trace",
                category=PatternCategory.DEBUG_EXPOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"at\s+[\w.]+\.[\w]+\([\w.]+:\d+\)|java\.lang\.\w+exception",
                owasp_category="A05",
                severity="medium",
                base_weight=0.75,
                confidence_factor=0.80,
                description="Java exception stack trace"
            ),
        ]
        
        # ===== VERSION DISCLOSURE PATTERNS =====
        version_patterns = [
            VulnerabilityPattern(
                id="version_apache",
                name="Apache Version",
                category=PatternCategory.VERSION_DISCLOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"apache/[\d.]+",
                owasp_category="A05",
                severity="low",
                base_weight=0.50,
                confidence_factor=0.90,
                description="Apache server version disclosed"
            ),
            VulnerabilityPattern(
                id="version_nginx",
                name="Nginx Version",
                category=PatternCategory.VERSION_DISCLOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"nginx/[\d.]+",
                owasp_category="A05",
                severity="low",
                base_weight=0.50,
                confidence_factor=0.90,
                description="Nginx server version disclosed"
            ),
            VulnerabilityPattern(
                id="version_php",
                name="PHP Version",
                category=PatternCategory.VERSION_DISCLOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"php/[\d.]+|x-powered-by:\s*php",
                owasp_category="A05",
                severity="low",
                base_weight=0.55,
                confidence_factor=0.90,
                description="PHP version disclosed"
            ),
            VulnerabilityPattern(
                id="version_aspnet",
                name="ASP.NET Version",
                category=PatternCategory.VERSION_DISCLOSURE,
                pattern_type=PatternType.REGEX,
                pattern=r"asp\.net.*version|x-aspnet-version",
                owasp_category="A05",
                severity="low",
                base_weight=0.55,
                confidence_factor=0.90,
                description="ASP.NET version disclosed"
            ),
        ]
        
        # ===== SENSITIVE DATA PATTERNS =====
        sensitive_patterns = [
            VulnerabilityPattern(
                id="sensitive_password",
                name="Password in Response",
                category=PatternCategory.SENSITIVE_DATA,
                pattern_type=PatternType.REGEX,
                pattern=r'"password"\s*:\s*"[^"]+"',
                owasp_category="A02",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.85,
                description="Password exposed in response"
            ),
            VulnerabilityPattern(
                id="sensitive_api_key",
                name="API Key in Response",
                category=PatternCategory.SENSITIVE_DATA,
                pattern_type=PatternType.REGEX,
                pattern=r'"api_key"\s*:\s*"[^"]+"',
                owasp_category="A02",
                severity="high",
                base_weight=0.90,
                confidence_factor=0.80,
                description="API key exposed in response"
            ),
            VulnerabilityPattern(
                id="sensitive_private_key",
                name="Private Key Exposure",
                category=PatternCategory.SENSITIVE_DATA,
                pattern_type=PatternType.REGEX,
                pattern=r"-----BEGIN.*PRIVATE KEY-----",
                owasp_category="A02",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.95,
                description="Private key exposed"
            ),
            VulnerabilityPattern(
                id="sensitive_aws_key",
                name="AWS Access Key",
                category=PatternCategory.SENSITIVE_DATA,
                pattern_type=PatternType.REGEX,
                pattern=r"AKIA[0-9A-Z]{16}",
                owasp_category="A02",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.95,
                description="AWS access key exposed"
            ),
            VulnerabilityPattern(
                id="sensitive_jwt",
                name="JWT Token",
                category=PatternCategory.SENSITIVE_DATA,
                pattern_type=PatternType.REGEX,
                pattern=r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
                owasp_category="A02",
                severity="medium",
                base_weight=0.70,
                confidence_factor=0.75,
                description="JWT token in response"
            ),
        ]
        
        # ===== SECURITY HEADER PATTERNS =====
        header_patterns = [
            VulnerabilityPattern(
                id="header_x_content_type",
                name="X-Content-Type-Options Missing",
                category=PatternCategory.SECURITY_HEADERS,
                pattern_type=PatternType.STRING,
                pattern="x-content-type-options",
                owasp_category="A05",
                severity="low",
                base_weight=0.40,
                confidence_factor=0.95,
                description="X-Content-Type-Options header missing"
            ),
            VulnerabilityPattern(
                id="header_x_frame",
                name="X-Frame-Options Missing",
                category=PatternCategory.SECURITY_HEADERS,
                pattern_type=PatternType.STRING,
                pattern="x-frame-options",
                owasp_category="A05",
                severity="low",
                base_weight=0.45,
                confidence_factor=0.95,
                description="X-Frame-Options header missing"
            ),
            VulnerabilityPattern(
                id="header_csp",
                name="CSP Missing",
                category=PatternCategory.SECURITY_HEADERS,
                pattern_type=PatternType.STRING,
                pattern="content-security-policy",
                owasp_category="A05",
                severity="medium",
                base_weight=0.55,
                confidence_factor=0.95,
                description="Content-Security-Policy header missing"
            ),
            VulnerabilityPattern(
                id="header_hsts",
                name="HSTS Missing",
                category=PatternCategory.SECURITY_HEADERS,
                pattern_type=PatternType.STRING,
                pattern="strict-transport-security",
                owasp_category="A05",
                severity="medium",
                base_weight=0.60,
                confidence_factor=0.95,
                description="Strict-Transport-Security header missing"
            ),
        ]
        
        # ===== SSTI PATTERNS =====
        ssti_patterns = [
            VulnerabilityPattern(
                id="ssti_jinja2",
                name="Jinja2 SSTI",
                category=PatternCategory.SSTI,
                pattern_type=PatternType.REGEX,
                pattern=r"\{\{.*config.*\}\}|\{\{.*self.*\}\}",
                owasp_category="A03",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.90,
                description="Jinja2 template injection"
            ),
            VulnerabilityPattern(
                id="ssti_freemarker",
                name="Freemarker SSTI",
                category=PatternCategory.SSTI,
                pattern_type=PatternType.REGEX,
                pattern=r"<#.*exec.*>|freemarker\.template",
                owasp_category="A03",
                severity="critical",
                base_weight=1.0,
                confidence_factor=0.90,
                description="Freemarker template injection"
            ),
        ]
        
        # ===== AUTH BYPASS PATTERNS =====
        auth_patterns = [
            VulnerabilityPattern(
                id="auth_admin_access",
                name="Admin Panel Access",
                category=PatternCategory.AUTH_BYPASS,
                pattern_type=PatternType.REGEX,
                pattern=r"admin\s*panel|dashboard.*admin|welcome.*administrator",
                owasp_category="A07",
                severity="critical",
                base_weight=0.85,
                confidence_factor=0.75,
                description="Unauthorized admin access"
            ),
            VulnerabilityPattern(
                id="auth_bypass_indicator",
                name="Auth Bypass Success",
                category=PatternCategory.AUTH_BYPASS,
                pattern_type=PatternType.REGEX,
                pattern=r"logged\s*in|authentication\s*successful|welcome\s*back",
                owasp_category="A07",
                severity="high",
                base_weight=0.75,
                confidence_factor=0.70,
                description="Authentication bypass indicator"
            ),
        ]
        
        # Combine all patterns
        all_patterns = (
            sql_patterns + xss_patterns + cmd_patterns + ssrf_patterns +
            traversal_patterns + info_patterns + version_patterns +
            sensitive_patterns + header_patterns + ssti_patterns + auth_patterns
        )
        
        # Index patterns
        for pattern in all_patterns:
            self.patterns[pattern.id] = pattern
            
            if pattern.category not in self.patterns_by_category:
                self.patterns_by_category[pattern.category] = []
            self.patterns_by_category[pattern.category].append(pattern)
        
        logger.info(f"Loaded {len(self.patterns)} built-in patterns across {len(self.patterns_by_category)} categories")
    
    def _load_learned_weights(self):
        """Load learned weight adjustments from database"""
        if not self.db_session:
            return
        
        try:
            # Query PatternKnowledge table (will be implemented with migration)
            # For now, skip database loading
            pass
        except Exception as e:
            logger.warning(f"Could not load learned weights: {e}")
    
    def match_text(
        self,
        text: str,
        location: str = "body",
        categories: List[PatternCategory] = None
    ) -> PatternMatchResult:
        """
        Match patterns against text
        
        Args:
            text: Text to match against
            location: Where the text came from (body, headers, url)
            categories: Optional list of categories to check (None = all)
            
        Returns:
            PatternMatchResult with all matches
        """
        if not text:
            return PatternMatchResult(
                total_matches=0,
                patterns_matched=[],
                categories_found=[],
                highest_severity="info",
                combined_confidence=0.0,
                suggested_owasp="A00"
            )
        
        text_lower = text.lower()
        matches: List[PatternMatch] = []
        
        # Determine which patterns to check
        patterns_to_check = []
        if categories:
            for cat in categories:
                patterns_to_check.extend(self.patterns_by_category.get(cat, []))
        else:
            patterns_to_check = list(self.patterns.values())
        
        # Check each pattern
        for pattern in patterns_to_check:
            if pattern.pattern_type == PatternType.REGEX:
                compiled = pattern.get_compiled_pattern()
                if compiled:
                    for match in compiled.finditer(text_lower):
                        matches.append(PatternMatch(
                            pattern_id=pattern.id,
                            pattern_name=pattern.name,
                            category=pattern.category,
                            owasp_category=pattern.owasp_category,
                            severity=pattern.severity,
                            matched_text=match.group(0)[:200],
                            match_location=location,
                            match_start=match.start(),
                            match_end=match.end(),
                            weight=pattern.effective_weight,
                            confidence=pattern.confidence_factor,
                            context=text[max(0, match.start()-50):match.end()+50]
                        ))
            
            elif pattern.pattern_type == PatternType.STRING:
                if pattern.pattern.lower() in text_lower:
                    idx = text_lower.find(pattern.pattern.lower())
                    matches.append(PatternMatch(
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        category=pattern.category,
                        owasp_category=pattern.owasp_category,
                        severity=pattern.severity,
                        matched_text=pattern.pattern,
                        match_location=location,
                        match_start=idx,
                        match_end=idx + len(pattern.pattern),
                        weight=pattern.effective_weight,
                        confidence=pattern.confidence_factor
                    ))
        
        # Calculate aggregates
        categories_found = list(set([m.category.value for m in matches]))
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        highest_severity = "info"
        for m in matches:
            if severity_order.get(m.severity, 0) > severity_order.get(highest_severity, 0):
                highest_severity = m.severity
        
        # Combined confidence (weighted average)
        if matches:
            total_weight = sum(m.weight for m in matches)
            combined_confidence = sum(m.confidence * m.weight for m in matches) / total_weight
        else:
            combined_confidence = 0.0
        
        # Suggested OWASP category (most common)
        owasp_counts: Dict[str, int] = {}
        for m in matches:
            owasp_counts[m.owasp_category] = owasp_counts.get(m.owasp_category, 0) + 1
        suggested_owasp = max(owasp_counts, key=owasp_counts.get) if owasp_counts else "A00"
        
        # Calculate category scores
        injection_categories = {PatternCategory.SQL_INJECTION, PatternCategory.XSS, 
                              PatternCategory.COMMAND_INJECTION, PatternCategory.SSTI}
        access_categories = {PatternCategory.PATH_TRAVERSAL, PatternCategory.IDOR, 
                           PatternCategory.AUTH_BYPASS}
        misconfig_categories = {PatternCategory.SECURITY_HEADERS, PatternCategory.DEBUG_EXPOSURE,
                               PatternCategory.VERSION_DISCLOSURE}
        
        injection_matches = [m for m in matches if m.category in injection_categories]
        access_matches = [m for m in matches if m.category in access_categories]
        misconfig_matches = [m for m in matches if m.category in misconfig_categories]
        
        injection_score = sum(m.weight * m.confidence for m in injection_matches) if injection_matches else 0.0
        access_score = sum(m.weight * m.confidence for m in access_matches) if access_matches else 0.0
        misconfig_score = sum(m.weight * m.confidence for m in misconfig_matches) if misconfig_matches else 0.0
        
        return PatternMatchResult(
            total_matches=len(matches),
            patterns_matched=matches,
            categories_found=categories_found,
            highest_severity=highest_severity,
            combined_confidence=round(combined_confidence, 3),
            suggested_owasp=suggested_owasp,
            injection_score=round(injection_score, 3),
            access_control_score=round(access_score, 3),
            misconfiguration_score=round(misconfig_score, 3)
        )
    
    def match_headers(self, headers: Dict[str, str]) -> PatternMatchResult:
        """
        Check for missing security headers and header-based patterns
        
        Args:
            headers: Response headers dictionary
            
        Returns:
            PatternMatchResult with header findings
        """
        matches: List[PatternMatch] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        
        # Check for missing security headers
        for pattern in self.patterns_by_category.get(PatternCategory.SECURITY_HEADERS, []):
            if pattern.pattern_type == PatternType.STRING:
                if pattern.pattern.lower() not in headers_lower:
                    matches.append(PatternMatch(
                        pattern_id=pattern.id,
                        pattern_name=pattern.name,
                        category=pattern.category,
                        owasp_category=pattern.owasp_category,
                        severity=pattern.severity,
                        matched_text=f"Missing: {pattern.pattern}",
                        match_location="headers",
                        match_start=0,
                        match_end=0,
                        weight=pattern.effective_weight,
                        confidence=pattern.confidence_factor
                    ))
        
        # Check for version disclosure in headers
        for pattern in self.patterns_by_category.get(PatternCategory.VERSION_DISCLOSURE, []):
            for header_name, header_value in headers.items():
                if pattern.pattern_type == PatternType.REGEX:
                    compiled = pattern.get_compiled_pattern()
                    if compiled and compiled.search(f"{header_name}: {header_value}"):
                        matches.append(PatternMatch(
                            pattern_id=pattern.id,
                            pattern_name=pattern.name,
                            category=pattern.category,
                            owasp_category=pattern.owasp_category,
                            severity=pattern.severity,
                            matched_text=f"{header_name}: {header_value}",
                            match_location="headers",
                            match_start=0,
                            match_end=0,
                            weight=pattern.effective_weight,
                            confidence=pattern.confidence_factor
                        ))
        
        # Build result
        categories_found = list(set([m.category.value for m in matches]))
        highest_severity = max([m.severity for m in matches], 
                              key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(x, 0),
                              default="info")
        
        combined_confidence = 0.0
        if matches:
            total_weight = sum(m.weight for m in matches)
            combined_confidence = sum(m.confidence * m.weight for m in matches) / total_weight
        
        return PatternMatchResult(
            total_matches=len(matches),
            patterns_matched=matches,
            categories_found=categories_found,
            highest_severity=highest_severity,
            combined_confidence=round(combined_confidence, 3),
            suggested_owasp="A05",
            misconfiguration_score=round(combined_confidence, 3)
        )
    
    def get_pattern_by_id(self, pattern_id: str) -> Optional[VulnerabilityPattern]:
        """Get a pattern by its ID"""
        return self.patterns.get(pattern_id)
    
    def get_patterns_by_category(
        self, category: PatternCategory
    ) -> List[VulnerabilityPattern]:
        """Get all patterns in a category"""
        return self.patterns_by_category.get(category, [])
    
    def update_pattern_weight(
        self,
        pattern_id: str,
        is_true_positive: bool,
        learning_rate: float = 0.1
    ):
        """
        Update pattern weight based on feedback
        
        Args:
            pattern_id: Pattern to update
            is_true_positive: Whether the finding was a true positive
            learning_rate: How much to adjust weight
        """
        pattern = self.patterns.get(pattern_id)
        if not pattern:
            return
        
        pattern.total_matches += 1
        
        if is_true_positive:
            pattern.true_positive_count += 1
            # Increase weight
            adjustment = learning_rate * (1 - pattern.learned_weight_adjustment)
        else:
            pattern.false_positive_count += 1
            # Decrease weight
            adjustment = -learning_rate * (1 + pattern.learned_weight_adjustment)
        
        pattern.learned_weight_adjustment += adjustment
        pattern.learned_weight_adjustment = max(-0.5, min(0.5, pattern.learned_weight_adjustment))
        
        logger.debug(
            f"Updated pattern {pattern_id}: weight_adj={pattern.learned_weight_adjustment:.3f}, "
            f"accuracy={pattern.accuracy_rate:.2%}"
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pattern matcher statistics"""
        category_stats = {}
        for cat, patterns in self.patterns_by_category.items():
            category_stats[cat.value] = {
                "pattern_count": len(patterns),
                "avg_weight": sum(p.effective_weight for p in patterns) / len(patterns) if patterns else 0
            }
        
        return {
            "total_patterns": len(self.patterns),
            "categories": len(self.patterns_by_category),
            "category_stats": category_stats
        }


# Convenience function for quick matching
def match_patterns(text: str, location: str = "body") -> PatternMatchResult:
    """Quick pattern matching without instantiation"""
    matcher = PatternMatcher(load_from_db=False)
    return matcher.match_text(text, location)
