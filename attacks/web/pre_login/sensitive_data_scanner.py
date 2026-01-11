"""
Jarwis AGI Pen Test - Sensitive Data Scanner
Detects sensitive data exposure (A02:2021)
Enhanced with JavaScript rendering support for SPA applications
"""

import asyncio
import logging
import re
from typing import Dict, List, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse
import aiohttp

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
    request_data: str = ""  # Full request details (Burp-style)
    response_data: str = ""  # Full response details (Burp-style)


class SensitiveDataScanner:
    """Scans for sensitive data exposure with reduced false positives"""
    
    # Patterns with stricter validation to reduce false positives
    # Format: (pattern, severity, min_matches, validation_func)
    PATTERNS = {
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
            'severity': 'high',
            'min_entropy': True,  # Must have reasonable entropy
            'description': 'Credit card number',
            'cwe': 'CWE-312'
        },
        'ssn': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'severity': 'critical',
            'context_keywords': ['ssn', 'social', 'security'],  # Must appear near keyword
            'description': 'Social Security Number',
            'cwe': 'CWE-359'
        },
        'api_key': {
            'pattern': r'(?:api[_-]?key|apikey|api_secret|secret_key)["\s:=]+["\']?([a-zA-Z0-9_-]{20,64})["\']?',
            'severity': 'high',
            'min_entropy': True,
            'description': 'API key or secret',
            'cwe': 'CWE-798'
        },
        'aws_key': {
            'pattern': r'\bAKIA[0-9A-Z]{16}\b',
            'severity': 'critical',
            'description': 'AWS Access Key ID',
            'cwe': 'CWE-798'
        },
        'aws_secret': {
            'pattern': r'(?:aws_secret|secret_access_key)["\s:=]+["\']?([A-Za-z0-9/+=]{40})["\']?',
            'severity': 'critical',
            'description': 'AWS Secret Access Key',
            'cwe': 'CWE-798'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----',
            'severity': 'critical',
            'description': 'Private key material',
            'cwe': 'CWE-321'
        },
        'password_field': {
            'pattern': r'["\']?(?:password|passwd|pwd|secret|credential)["\']?\s*[=:]\s*["\']([^"\']{4,50})["\']',
            'severity': 'high',
            'min_entropy': True,
            'description': 'Hardcoded password',
            'cwe': 'CWE-798'
        },
        'jwt': {
            'pattern': r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b',
            'severity': 'medium',
            'description': 'JSON Web Token (potentially sensitive claims)',
            'cwe': 'CWE-200'
        },
        'bearer_token': {
            'pattern': r'[Bb]earer\s+([a-zA-Z0-9_.-]{20,})',
            'severity': 'high',
            'description': 'Bearer authentication token',
            'cwe': 'CWE-522'
        },
        'github_token': {
            'pattern': r'\b(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})\b',
            'severity': 'critical',
            'description': 'GitHub Personal Access Token',
            'cwe': 'CWE-798'
        },
        'slack_token': {
            'pattern': r'\bxox[baprs]-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b',
            'severity': 'high',
            'description': 'Slack API Token',
            'cwe': 'CWE-798'
        },
    }
    
    # Exclude patterns - reduce false positives
    EXCLUDE_PATTERNS = [
        r'example\.com',
        r'test@test',
        r'user@example',
        r'placeholder',
        r'sample',
        r'demo',
        r'localhost',
        r'0\.0\.0\.0',
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
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self.custom_patterns = config.get('owasp', {}).get('sensitive_data', {}).get('patterns', [])
        self._reported_missing_headers = set()  # Track URLs with reported missing headers
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Will be set by PreLoginAttacks if available
        self.use_js_rendering = config.get('js_rendering', True)  # Enable by default
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for scope checking"""
        try:
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
    
    def _calculate_entropy(self, s: str) -> float:
        """Calculate Shannon entropy to detect random strings vs. structured data"""
        import math
        if not s:
            return 0
        entropy = 0
        for char in set(s):
            p = s.count(char) / len(s)
            entropy -= p * math.log2(p)
        return entropy
    
    def _is_excluded(self, match: str, content: str) -> bool:
        """Check if match should be excluded (false positive)"""
        for pattern in self.EXCLUDE_PATTERNS:
            if re.search(pattern, match, re.IGNORECASE):
                return True
            # Check surrounding context
            idx = content.find(match)
            if idx != -1:
                context = content[max(0, idx-50):idx+len(match)+50]
                if re.search(pattern, context, re.IGNORECASE):
                    return True
        return False
    
    async def scan(self) -> List[ScanResult]:
        """Scan responses for sensitive data"""
        self.findings = []
        
        async with aiohttp.ClientSession() as session:
            for endpoint in self.context.endpoints[:100]:
                await self._scan_endpoint(session, endpoint)
                await asyncio.sleep(0.1)
        
        return self.findings
    
    async def _scan_endpoint(self, session: aiohttp.ClientSession, endpoint: Dict):
        """Scan a single endpoint with proper verification"""
        try:
            url = endpoint.get('url', '')
            
            async with session.get(
                url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as response:
                content = await response.text()
                resp_headers = dict(response.headers)
                status = response.status
                
                request_str = self._format_request("GET", url, self.DEFAULT_HEADERS)
                response_str = self._format_response(status, resp_headers, content)
                
                self._check_patterns(url, content, request_str, response_str)
                self._check_headers(url, resp_headers)
                
        except Exception as e:
            logger.debug(f"Scan failed for {endpoint.get('url')}: {e}")
    
    def _check_patterns(self, url: str, content: str, request_str: str, response_str: str):
        """Check content against sensitive patterns with verification"""
        for name, config in self.PATTERNS.items():
            pattern = config['pattern']
            severity = config['severity']
            
            matches = re.findall(pattern, content, re.IGNORECASE)
            
            # Filter valid matches
            valid_matches = []
            for match in matches:
                # Handle tuple matches from regex groups
                if isinstance(match, tuple):
                    match = match[0] if match else ""
                
                if not match or len(match) < 4:
                    continue
                    
                # Check exclusion list
                if self._is_excluded(match, content):
                    continue
                
                # Check entropy for high-entropy patterns
                if config.get('min_entropy') and self._calculate_entropy(match) < 3.0:
                    continue
                
                # Check context keywords if required
                if 'context_keywords' in config:
                    idx = content.lower().find(match.lower())
                    if idx != -1:
                        context = content[max(0, idx-100):idx+len(match)+100].lower()
                        if not any(kw in context for kw in config['context_keywords']):
                            continue
                
                valid_matches.append(match)
            
            if valid_matches:
                # Redact actual values
                redacted = [m[:6] + '***' + m[-2:] if len(m) > 10 else m[:4] + '***' for m in valid_matches[:3]]
                
                self._add_finding(
                    category="A02",
                    severity=severity,
                    title=f"Sensitive Data Exposure: {config['description']}",
                    description=f"Found {len(valid_matches)} instance(s) of {config['description']} in response. This data should not be exposed in HTTP responses.",
                    url=url,
                    method="GET",
                    evidence=f"Pattern: {name}\nFound {len(valid_matches)} matches (redacted): {redacted}",
                    remediation="Remove sensitive data from responses. Use encryption for data at rest and in transit. Implement proper access controls.",
                    cwe_id=config['cwe'],
                    poc=f"To reproduce:\n1. Request GET {url}\n2. Search response for pattern: {pattern[:50]}...\n3. Find sensitive data in response body",
                    reasoning=f"VERIFIED: Jarwis detected {len(valid_matches)} instance(s) of {config['description']} in the response from '{url}'. The pattern passed validation checks (entropy, context, exclusion filters). Exposing this data can lead to credential theft, unauthorized access, or compliance violations.",
                    request_data=request_str,
                    response_data=response_str
                )
    
    def _check_headers(self, url: str, headers: Dict):
        """Check headers for security issues - only report once per host"""
        # Extract host from URL
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        
        # Skip if we've already reported for this host
        if host in self._reported_missing_headers:
            return
        
        # Check for missing security headers
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY|SAMEORIGIN',
            'Strict-Transport-Security': 'max-age',
            'Content-Security-Policy': '.',
        }
        
        missing_headers = []
        for header, expected_pattern in security_headers.items():
            if header not in headers:
                missing_headers.append(header)
        
        # Only report if 3+ critical headers missing, and only once per host
        if len(missing_headers) >= 3:
            self._reported_missing_headers.add(host)
            self._add_finding(
                category="A05",
                severity="info",
                title=f"Missing Security Headers ({host})",
                description=f"Multiple security headers are missing from responses on {host}",
                url=url,
                method="GET",
                evidence=f"Missing headers: {', '.join(missing_headers)}",
                remediation="Add security headers: " + ', '.join(missing_headers),
                cwe_id="CWE-693"
            )
    
    def _add_finding(self, **kwargs):
        """Add a finding to the results (only if in scope)"""
        url = kwargs.get('url', '')
        if url and not self._is_in_scope(url):
            logger.debug(f"Skipping out-of-scope finding: {url}")
            return
        
        self._finding_id += 1
        finding = ScanResult(id=f"DATA-{self._finding_id:04d}", **kwargs)
        self.findings.append(finding)
        logger.info(f"Found: {finding.title}")
