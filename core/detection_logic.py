"""
JARWIS AGI PEN TEST - OWASP Top 10 Detection Logic
Evidence-based vulnerability detection using request/response analysis
Based on: OWASP Top 10 Detection Guide
"""

import re
import json
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, field
from urllib.parse import urlparse, parse_qs


@dataclass
class DetectionResult:
    """Result of detection analysis"""
    detected: bool
    category: str  # OWASP category (A01-A10)
    confidence: str  # high, medium, low
    evidence: List[str] = field(default_factory=list)
    reasoning: str = ""
    indicators: Dict = field(default_factory=dict)


class OWASPDetectionEngine:
    """
    Evidence-based detection engine for OWASP Top 10 vulnerabilities.
    Analyzes request/response pairs to identify security issues with proper evidence.
    """
    
    # ============== A01: Broken Access Control ==============
    IDOR_PATTERNS = [
        r'/user[s]?/(\d+)',
        r'/account[s]?/(\d+)',
        r'/profile[s]?/(\d+)',
        r'/order[s]?/(\d+)',
        r'/invoice[s]?/(\d+)',
        r'/document[s]?/(\d+)',
        r'/file[s]?/(\d+)',
        r'/record[s]?/(\d+)',
        r'\?id=(\d+)',
        r'\?user_id=(\d+)',
        r'\?account_id=(\d+)',
        r'\?order_id=(\d+)',
    ]
    
    ADMIN_ENDPOINTS = [
        '/admin', '/administrator', '/manage', '/dashboard',
        '/control', '/console', '/panel', '/backend',
        '/wp-admin', '/admin.php', '/manager',
    ]
    
    SENSITIVE_DATA_PATTERNS = [
        (r'"password"\s*:\s*"[^"]+"', 'Password in response'),
        (r'"credit_card"\s*:\s*"[\d\-]+"', 'Credit card in response'),
        (r'"ssn"\s*:\s*"[\d\-]+"', 'SSN in response'),
        (r'"api_key"\s*:\s*"[^"]+"', 'API key in response'),
        (r'"secret"\s*:\s*"[^"]+"', 'Secret in response'),
        (r'"token"\s*:\s*"[A-Za-z0-9\-_.]+"', 'Token in response'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email addresses exposed'),
    ]
    
    # ============== A02: Cryptographic Failures ==============
    WEAK_TLS_PATTERNS = [
        'TLSv1.0', 'TLSv1.1', 'SSLv2', 'SSLv3',
    ]
    
    PLAINTEXT_SENSITIVE_PATTERNS = [
        (r'password=([^&\s]+)', 'Password in plaintext URL'),
        (r'token=([^&\s]+)', 'Token in plaintext URL'),
        (r'api_key=([^&\s]+)', 'API key in plaintext URL'),
        (r'secret=([^&\s]+)', 'Secret in plaintext URL'),
    ]
    
    # ============== A03: Injection ==============
    SQL_ERROR_PATTERNS = [
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
        (r"mysql_fetch_array\(\)", "MySQL fetch error"),
        (r"mysql_num_rows\(\)", "MySQL rows error"),
        (r"Division by zero", "SQL division error"),
    ]
    
    XSS_REFLECTION_INDICATORS = [
        (r'<script[^>]*>.*?</script>', 'Script tag reflected'),
        (r'<img[^>]+onerror\s*=', 'IMG onerror reflected'),
        (r'<svg[^>]+onload\s*=', 'SVG onload reflected'),
        (r'javascript:', 'JavaScript protocol reflected'),
        (r'on\w+\s*=\s*["\'][^"\']*["\']', 'Event handler reflected'),
    ]
    
    COMMAND_INJECTION_INDICATORS = [
        (r'root:.*:0:0:', '/etc/passwd content'),
        (r'uid=\d+\(.*\)\s+gid=\d+', 'id command output'),
        (r'Volume Serial Number', 'Windows dir output'),
        (r'Directory of [A-Z]:\\', 'Windows directory listing'),
        (r'total \d+\n.*drwx', 'Unix ls output'),
        (r'PING.*bytes of data', 'Ping command output'),
    ]
    
    # ============== A05: Security Misconfiguration ==============
    SECURITY_HEADERS = {
        'Content-Security-Policy': {
            'missing_severity': 'medium',
            'description': 'Prevents XSS and data injection attacks'
        },
        'X-Frame-Options': {
            'missing_severity': 'medium',
            'description': 'Prevents clickjacking attacks'
        },
        'X-Content-Type-Options': {
            'missing_severity': 'low',
            'description': 'Prevents MIME type sniffing'
        },
        'Referrer-Policy': {
            'missing_severity': 'low',
            'description': 'Controls referrer information leakage'
        },
        'Strict-Transport-Security': {
            'missing_severity': 'medium',
            'description': 'Enforces HTTPS connections'
        },
        'X-XSS-Protection': {
            'missing_severity': 'low',
            'description': 'Legacy XSS filter (modern browsers)'
        },
        'Permissions-Policy': {
            'missing_severity': 'low',
            'description': 'Controls browser features access'
        },
    }
    
    DEBUG_INDICATORS = [
        (r'Traceback \(most recent call last\)', 'Python traceback'),
        (r'<b>Fatal error</b>:', 'PHP fatal error'),
        (r'<b>Warning</b>:', 'PHP warning'),
        (r'<b>Notice</b>:', 'PHP notice'),
        (r'Stack trace:', 'Stack trace exposed'),
        (r'Exception in thread', 'Java exception'),
        (r'at [\w\.]+\([\w\.]+:\d+\)', 'Java stack frame'),
        (r'DEBUG\s*=\s*True', 'Debug mode enabled'),
        (r'\.php on line \d+', 'PHP error with line number'),
        (r'Microsoft.*Exception', 'ASP.NET exception'),
    ]
    
    # ============== A06: Vulnerable Components ==============
    VERSION_DISCLOSURE_PATTERNS = [
        (r'Server:\s*Apache/([\d\.]+)', 'Apache version'),
        (r'Server:\s*nginx/([\d\.]+)', 'Nginx version'),
        (r'X-Powered-By:\s*PHP/([\d\.]+)', 'PHP version'),
        (r'X-AspNet-Version:\s*([\d\.]+)', 'ASP.NET version'),
        (r'Server:\s*Microsoft-IIS/([\d\.]+)', 'IIS version'),
        (r'X-Powered-By:\s*Express', 'Express.js framework'),
        (r'X-Drupal-Cache', 'Drupal CMS'),
        (r'X-Generator:\s*WordPress\s*([\d\.]+)?', 'WordPress version'),
        (r'jquery[.-]?([\d\.]+)\.min\.js', 'jQuery version'),
        (r'bootstrap[.-]?([\d\.]+)\.min\.js', 'Bootstrap version'),
    ]
    
    # ============== A07: Auth Failures ==============
    AUTH_BYPASS_INDICATORS = [
        (r'welcome.*admin', 'Admin access without proper auth'),
        (r'dashboard', 'Dashboard access indicator'),
        (r'logout', 'Authenticated state indicator'),
        (r'my.?account', 'Account access indicator'),
    ]
    
    BRUTE_FORCE_INDICATORS = [
        'No rate limiting detected',
        'No account lockout',
        'Same error for valid/invalid users',
    ]
    
    # ============== A10: SSRF ==============
    SSRF_INDICATORS = [
        (r'127\.0\.0\.1', 'Localhost IP in response'),
        (r'localhost', 'Localhost in response'),
        (r'192\.168\.\d+\.\d+', 'Private IP (192.168.x.x)'),
        (r'10\.\d+\.\d+\.\d+', 'Private IP (10.x.x.x)'),
        (r'172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+', 'Private IP (172.16-31.x.x)'),
        (r'internal', 'Internal service reference'),
        (r'metadata', 'Cloud metadata reference'),
        (r'169\.254\.169\.254', 'AWS metadata IP'),
    ]

    def __init__(self):
        self.findings = []
    
    def analyze_access_control(
        self,
        request_url: str,
        request_method: str,
        request_headers: Dict,
        response_status: int,
        response_body: str,
        has_auth_token: bool = False
    ) -> DetectionResult:
        """
        A01: Broken Access Control Detection
        
        Logic: If resource access succeeds without proper role/session â†' Broken Access Control
        """
        evidence = []
        indicators = {}
        
        # Check for IDOR patterns
        for pattern in self.IDOR_PATTERNS:
            match = re.search(pattern, request_url, re.IGNORECASE)
            if match:
                indicators['idor_pattern'] = match.group(0)
                evidence.append(f"Potential IDOR pattern detected: {match.group(0)}")
        
        # Check for admin endpoint access without auth
        parsed = urlparse(request_url)
        path_lower = parsed.path.lower()
        
        for admin_path in self.ADMIN_ENDPOINTS:
            if admin_path in path_lower:
                indicators['admin_endpoint'] = admin_path
                if response_status == 200 and not has_auth_token:
                    evidence.append(f"Admin endpoint {admin_path} accessible without authentication")
        
        # Check for sensitive data in response
        for pattern, desc in self.SENSITIVE_DATA_PATTERNS:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"{desc} detected in response")
                indicators['sensitive_data'] = True
        
        # Determine if access control is broken
        detected = False
        reasoning = ""
        
        if response_status == 200 and not has_auth_token and indicators.get('admin_endpoint'):
            detected = True
            reasoning = f"Unauthorized access to admin endpoint {indicators['admin_endpoint']} - received 200 OK without authentication token"
        elif indicators.get('sensitive_data') and not has_auth_token:
            detected = True
            reasoning = "Sensitive data exposed to unauthenticated user"
        
        return DetectionResult(
            detected=detected,
            category="A01:2021 - Broken Access Control",
            confidence="high" if detected and len(evidence) > 1 else "medium",
            evidence=evidence,
            reasoning=reasoning,
            indicators=indicators
        )
    
    def analyze_injection(
        self,
        request_url: str,
        request_body: str,
        response_body: str,
        payload_sent: str
    ) -> DetectionResult:
        """
        A03: Injection Detection (SQLi, XSS, CMDi)
        
        Logic: If payload modifies backend behavior or reflects â†' Injection
        """
        evidence = []
        indicators = {}
        detected = False
        reasoning = ""
        injection_type = ""
        
        # Check for SQL errors
        for pattern, desc in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                evidence.append(f"SQL Error detected: {desc}")
                indicators['sql_error'] = match.group(0)[:200]
                detected = True
                injection_type = "SQL Injection"
                reasoning = f"SQL syntax error triggered by payload. Error: {desc}"
                break
        
        # Check for XSS reflection
        if not detected and payload_sent:
            # Check if payload is reflected unencoded
            if payload_sent in response_body:
                for pattern, desc in self.XSS_REFLECTION_INDICATORS:
                    if re.search(pattern, response_body, re.IGNORECASE):
                        evidence.append(f"XSS payload reflected: {desc}")
                        indicators['xss_reflection'] = payload_sent[:100]
                        detected = True
                        injection_type = "Cross-Site Scripting (XSS)"
                        reasoning = f"Payload reflected in response without encoding. {desc}"
                        break
        
        # Check for command injection
        if not detected:
            for pattern, desc in self.COMMAND_INJECTION_INDICATORS:
                if re.search(pattern, response_body, re.IGNORECASE):
                    evidence.append(f"Command execution detected: {desc}")
                    indicators['cmd_injection'] = desc
                    detected = True
                    injection_type = "Command Injection"
                    reasoning = f"OS command output detected in response: {desc}"
                    break
        
        return DetectionResult(
            detected=detected,
            category=f"A03:2021 - Injection ({injection_type})" if injection_type else "A03:2021 - Injection",
            confidence="high" if detected else "low",
            evidence=evidence,
            reasoning=reasoning,
            indicators=indicators
        )
    
    def analyze_security_headers(
        self,
        response_headers: Dict,
        is_https: bool = True
    ) -> DetectionResult:
        """
        A05: Security Misconfiguration Detection
        
        Logic: Server misconfigured if defaults or debug exposed
        """
        evidence = []
        missing_headers = []
        indicators = {}
        
        # Check for missing security headers
        for header, info in self.SECURITY_HEADERS.items():
            header_found = False
            for h in response_headers.keys():
                if h.lower() == header.lower():
                    header_found = True
                    break
            
            if not header_found:
                missing_headers.append({
                    'header': header,
                    'severity': info['missing_severity'],
                    'description': info['description']
                })
                evidence.append(f"Missing header: {header} - {info['description']}")
        
        indicators['missing_headers'] = missing_headers
        
        # Check HSTS specifically for HTTPS
        if is_https:
            hsts_found = any(h.lower() == 'strict-transport-security' for h in response_headers.keys())
            if not hsts_found:
                evidence.append("HTTPS without HSTS header - vulnerable to downgrade attacks")
        
        # Determine severity based on missing headers
        critical_missing = sum(1 for h in missing_headers if h['severity'] in ['high', 'critical'])
        medium_missing = sum(1 for h in missing_headers if h['severity'] == 'medium')
        
        detected = len(missing_headers) > 0
        
        if critical_missing > 0:
            confidence = "high"
        elif medium_missing >= 2:
            confidence = "medium"
        else:
            confidence = "low"
        
        return DetectionResult(
            detected=detected,
            category="A05:2021 - Security Misconfiguration",
            confidence=confidence,
            evidence=evidence,
            reasoning=f"Missing {len(missing_headers)} security headers" if detected else "",
            indicators=indicators
        )
    
    def analyze_debug_exposure(
        self,
        response_body: str,
        response_headers: Dict
    ) -> DetectionResult:
        """
        A05: Debug/Error Information Exposure
        
        Logic: Stack traces or debug info exposed
        """
        evidence = []
        indicators = {}
        
        for pattern, desc in self.DEBUG_INDICATORS:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                evidence.append(f"Debug information exposed: {desc}")
                indicators['debug_pattern'] = desc
        
        detected = len(evidence) > 0
        
        return DetectionResult(
            detected=detected,
            category="A05:2021 - Security Misconfiguration (Debug Exposure)",
            confidence="high" if detected else "low",
            evidence=evidence,
            reasoning="Application exposes debug information or stack traces" if detected else "",
            indicators=indicators
        )
    
    def analyze_version_disclosure(
        self,
        response_headers: Dict,
        response_body: str
    ) -> DetectionResult:
        """
        A06: Vulnerable and Outdated Components Detection
        
        Logic: Version match with known CVE database
        """
        evidence = []
        versions_found = []
        indicators = {}
        
        # Check headers
        headers_str = "\n".join([f"{k}: {v}" for k, v in response_headers.items()])
        
        for pattern, desc in self.VERSION_DISCLOSURE_PATTERNS:
            match = re.search(pattern, headers_str, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else "unknown"
                versions_found.append({'component': desc, 'version': version})
                evidence.append(f"{desc}: {version}")
        
        # Check body for JS library versions
        for pattern, desc in self.VERSION_DISCLOSURE_PATTERNS:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else "unknown"
                versions_found.append({'component': desc, 'version': version})
                evidence.append(f"{desc}: {version} (in page content)")
        
        indicators['versions'] = versions_found
        detected = len(versions_found) > 0
        
        return DetectionResult(
            detected=detected,
            category="A06:2021 - Vulnerable and Outdated Components",
            confidence="medium" if detected else "low",
            evidence=evidence,
            reasoning="Server/component versions disclosed - enables targeted attacks" if detected else "",
            indicators=indicators
        )
    
    def analyze_ssrf(
        self,
        request_url: str,
        request_body: str,
        response_body: str
    ) -> DetectionResult:
        """
        A10: Server-Side Request Forgery Detection
        
        Logic: Backend makes internal calls from user input
        """
        evidence = []
        indicators = {}
        
        # Check if URL parameter contains internal addresses
        parsed = urlparse(request_url)
        query_params = parse_qs(parsed.query)
        
        url_params = ['url', 'uri', 'path', 'dest', 'redirect', 'next', 'data', 'reference', 'site', 'html', 'val', 'validate', 'domain', 'callback', 'return', 'page', 'feed', 'host', 'port', 'to', 'out', 'view', 'dir']
        
        for param in url_params:
            if param in query_params:
                indicators['url_param'] = param
                evidence.append(f"URL parameter '{param}' detected - potential SSRF vector")
        
        # Check response for internal service indicators
        for pattern, desc in self.SSRF_INDICATORS:
            if re.search(pattern, response_body, re.IGNORECASE):
                evidence.append(f"Internal service indicator: {desc}")
                indicators['internal_response'] = True
        
        detected = indicators.get('url_param') and indicators.get('internal_response')
        
        return DetectionResult(
            detected=detected,
            category="A10:2021 - Server-Side Request Forgery (SSRF)",
            confidence="high" if detected else "low",
            evidence=evidence,
            reasoning="User-controlled URL parameter returned internal service data" if detected else "",
            indicators=indicators
        )
    
    def analyze_auth_failure(
        self,
        login_attempts: List[Dict],
        response_times: List[float]
    ) -> DetectionResult:
        """
        A07: Identification and Authentication Failures
        
        Logic: Weak auth control detection
        """
        evidence = []
        indicators = {}
        
        # Check for consistent response times (timing attack possible)
        if response_times and len(response_times) >= 3:
            avg_time = sum(response_times) / len(response_times)
            variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
            
            if variance < 0.01:  # Very consistent times
                evidence.append("Consistent response times for valid/invalid users - timing attack possible")
                indicators['timing_attack'] = True
        
        # Check if error messages are identical
        if login_attempts:
            error_messages = set()
            for attempt in login_attempts:
                if attempt.get('error_message'):
                    error_messages.add(attempt['error_message'])
            
            if len(error_messages) == 1:
                evidence.append("Identical error messages for all login failures - user enumeration prevented")
            elif len(error_messages) > 1:
                evidence.append("Different error messages detected - potential user enumeration")
                indicators['user_enumeration'] = True
        
        # Check for rate limiting
        if len(login_attempts) >= 5:
            blocked = any(a.get('blocked') for a in login_attempts)
            if not blocked:
                evidence.append("No rate limiting detected after multiple failed attempts")
                indicators['no_rate_limit'] = True
        
        detected = indicators.get('user_enumeration') or indicators.get('no_rate_limit')
        
        return DetectionResult(
            detected=detected,
            category="A07:2021 - Identification and Authentication Failures",
            confidence="medium" if detected else "low",
            evidence=evidence,
            reasoning="Authentication mechanism has weaknesses" if detected else "",
            indicators=indicators
        )
    
    def generate_evidence_report(
        self,
        request_data: str,
        response_data: str,
        detection: DetectionResult
    ) -> str:
        """Generate comprehensive evidence report for a finding"""
        
        report = []
        report.append("=" * 60)
        report.append(f"VULNERABILITY: {detection.category}")
        report.append(f"CONFIDENCE: {detection.confidence.upper()}")
        report.append("=" * 60)
        report.append("")
        
        report.append("REASONING:")
        report.append(detection.reasoning)
        report.append("")
        
        report.append("EVIDENCE:")
        for i, ev in enumerate(detection.evidence, 1):
            report.append(f"  {i}. {ev}")
        report.append("")
        
        if detection.indicators:
            report.append("TECHNICAL INDICATORS:")
            for key, value in detection.indicators.items():
                report.append(f"  - {key}: {value}")
            report.append("")
        
        report.append("REQUEST:")
        report.append("-" * 40)
        report.append(request_data[:2000] if len(request_data) > 2000 else request_data)
        report.append("")
        
        report.append("RESPONSE (truncated):")
        report.append("-" * 40)
        report.append(response_data[:1000] if len(response_data) > 1000 else response_data)
        
        return "\n".join(report)


# Singleton instance for easy access
detection_engine = OWASPDetectionEngine()
