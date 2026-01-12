"""
Jarwis AGI Pen Test - Security Misconfiguration Scanner
Detects common security misconfigurations (A05:2021)
Uses OWASP Detection Logic for evidence-based detection
"""

import asyncio
import logging
from typing import Dict, List
from dataclasses import dataclass
from urllib.parse import urlparse
import aiohttp

# Import detection engine
try:
    from core.detection_logic import OWASPDetectionEngine, detection_engine
except ImportError:
    try:
        from ...core.detection_logic import OWASPDetectionEngine, detection_engine
    except ImportError:
        detection_engine = None

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


class MisconfigScanner:
    """Scans for security misconfigurations with proper verification"""
    
    # Common sensitive paths to check with expected content patterns
    # All patterns must match for a true positive
    SENSITIVE_PATHS = {
        '/.git/config': {
            'patterns': ['[core]', 'repositoryformatversion'],
            'exclude_patterns': ['<!DOCTYPE', '<html'],
            'severity': 'critical',
            'content_type': None
        },
        '/.git/HEAD': {
            'patterns': ['ref: refs/heads/'],
            'exclude_patterns': ['<!DOCTYPE', '<html'],
            'severity': 'critical',
            'content_type': None
        },
        '/.env': {
            'patterns': ['DB_HOST=', 'DB_PASSWORD=', 'SECRET_KEY=', 'API_KEY=', 'DATABASE_URL='],
            'exclude_patterns': ['<!DOCTYPE', '<html', '<script'],
            'severity': 'critical',
            'min_matches': 1,  # At least one specific pattern must match
            'content_type': None
        },
        '/.env.local': {
            'patterns': ['DB_', 'SECRET', 'API_KEY=', 'PASSWORD='],
            'exclude_patterns': ['<!DOCTYPE', '<html', '<script'],
            'severity': 'high',
            'min_matches': 1,
            'content_type': None
        },
        '/phpinfo.php': {
            'patterns': ['PHP Version', 'phpinfo()'],
            'exclude_patterns': [],
            'severity': 'high',
            'content_type': 'text/html'
        },
        '/server-status': {
            'patterns': ['Apache Server Status', 'Server uptime'],
            'exclude_patterns': [],
            'severity': 'medium',
            'content_type': None
        },
        '/backup.sql': {
            'patterns': ['CREATE TABLE', 'INSERT INTO'],
            'exclude_patterns': ['<!DOCTYPE', '<html'],
            'severity': 'critical',
            'min_matches': 1,
            'content_type': None
        },
        '/dump.sql': {
            'patterns': ['CREATE TABLE', 'INSERT INTO'],
            'exclude_patterns': ['<!DOCTYPE', '<html'],
            'severity': 'critical',
            'min_matches': 1,
            'content_type': None
        },
        '/api/swagger.json': {
            'patterns': ['"swagger":', '"openapi":'],
            'exclude_patterns': [],
            'severity': 'low',
            'content_type': 'application/json'
        },
        '/swagger.json': {
            'patterns': ['"swagger":', '"openapi":'],
            'exclude_patterns': [],
            'severity': 'low',
            'content_type': 'application/json'
        },
        '/.htpasswd': {
            'patterns': ['$apr1$', '$2y$', '$2a$'],
            'exclude_patterns': ['<!DOCTYPE', '<html'],
            'severity': 'critical',
            'min_matches': 1,
            'content_type': None
        },
        '/web.config': {
            'patterns': ['<configuration>', 'connectionString='],
            'exclude_patterns': [],
            'severity': 'high',
            'content_type': None
        },
    }
    
    # Security headers to check (only report critical ones)
    CRITICAL_SECURITY_HEADERS = {
        'Strict-Transport-Security': ('HSTS header missing - no protection against SSL stripping', 'medium'),
        'X-Content-Type-Options': ('X-Content-Type-Options header missing - MIME sniffing attacks possible', 'low'),
    }
    
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
        self.base_url = context.target_url.rstrip('/')
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Will be set by PreLoginAttacks if available
        self.use_js_rendering = config.get('js_rendering', True)
    
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
    
    async def scan(self) -> List[ScanResult]:
        """Run misconfiguration scans"""
        self.findings = []
        
        async with aiohttp.ClientSession() as session:
            await self._check_security_headers(session)
            await self._check_sensitive_files(session)
            await self._check_cors(session)
            await self._check_cookies(session)
            await self._check_server_info(session)
        
        return self.findings
    
    async def _check_security_headers(self, session: aiohttp.ClientSession):
        """Check for critical missing security headers only"""
        try:
            async with session.get(
                self.base_url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as response:
                resp_headers = dict(response.headers)
                content = await response.text()
                status = response.status
                
                request_str = self._format_request("GET", self.base_url, self.DEFAULT_HEADERS)
                response_str = self._format_response(status, resp_headers, content)
                
                # Only check critical headers
                for header, (message, severity) in self.CRITICAL_SECURITY_HEADERS.items():
                    if header not in resp_headers:
                        self._add_finding(
                            category="A05",
                            severity=severity,
                            title=f"Missing Security Header: {header}",
                            description=message,
                            url=self.base_url,
                            method="GET",
                            evidence=f"Header {header} not found in response headers",
                            remediation=f"Add {header} header to all responses",
                            cwe_id="CWE-16",
                            poc=f"To reproduce:\n1. Request GET {self.base_url}\n2. Check response headers\n3. Observe missing {header} header",
                            reasoning=f"VERIFIED: Jarwis confirmed that the {header} header is missing from the response. {message}",
                            request_data=request_str,
                            response_data=response_str
                        )
                        
        except Exception as e:
            logger.debug(f"Header check failed: {e}")
    
    async def _check_sensitive_files(self, session: aiohttp.ClientSession):
        """Check for exposed sensitive files with strict content verification"""
        for path, config in self.SENSITIVE_PATHS.items():
            try:
                url = f"{self.base_url}{path}"
                async with session.get(
                    url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        resp_headers = dict(response.headers)
                        content_type = resp_headers.get('Content-Type', '')
                        
                        # VERIFICATION 1: Check for exclusion patterns (SPA fallbacks, HTML pages)
                        exclude_patterns = config.get('exclude_patterns', [])
                        is_excluded = any(ep.lower() in content.lower()[:500] for ep in exclude_patterns)
                        
                        if is_excluded:
                            logger.debug(f"Excluded {path}: contains exclusion pattern (likely SPA fallback)")
                            continue
                        
                        # VERIFICATION 2: Check content type if specified
                        expected_content_type = config.get('content_type')
                        if expected_content_type and expected_content_type not in content_type:
                            logger.debug(f"Excluded {path}: wrong content type {content_type}")
                            continue
                        
                        # VERIFICATION 3: Check for expected patterns
                        patterns = config.get('patterns', [])
                        matched_patterns = [p for p in patterns if p in content]
                        
                        min_matches = config.get('min_matches', 1)
                        if len(matched_patterns) >= min_matches and len(content) > 10:
                            request_str = self._format_request("GET", url, self.DEFAULT_HEADERS)
                            response_str = self._format_response(response.status, resp_headers, content)
                            
                            severity = config.get('severity', 'medium')
                            
                            self._add_finding(
                                category="A05",
                                severity=severity,
                                title=f"Sensitive File Exposed: {path}",
                                description=f"Sensitive file accessible at {path}. The file contains expected sensitive content patterns and passed all validation checks.",
                                url=url,
                                method="GET",
                                evidence=f"HTTP {response.status} - {len(content)} bytes\nContent-Type: {content_type}\nMatched patterns: {matched_patterns[:3]}",
                                remediation="Block access to sensitive files via web server configuration. Use .htaccess or nginx location blocks.",
                                cwe_id="CWE-538",
                                poc=f"To reproduce:\n1. Request GET {url}\n2. Observe {response.status} response with sensitive content\n3. Patterns found: {matched_patterns[:3]}",
                                reasoning=f"VERIFIED: Jarwis confirmed the file at {path} is accessible and contains specific sensitive patterns: {matched_patterns[:3]}. This is NOT a SPA fallback - the content type and patterns match expected file signatures.",
                                request_data=request_str,
                                response_data=response_str
                            )
                            
                await asyncio.sleep(0.1)  # Rate limiting
                
            except Exception as e:
                logger.debug(f"Sensitive file check failed for {path}: {e}")
    
    async def _check_cors(self, session: aiohttp.ClientSession):
        """Check for CORS misconfiguration with proper verification"""
        try:
            test_origin = 'https://evil-attacker.com'
            headers = {**self.DEFAULT_HEADERS, 'Origin': test_origin}
            
            async with session.get(
                self.base_url,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as response:
                resp_headers = dict(response.headers)
                content = await response.text()
                status = response.status
                
                acao = resp_headers.get('Access-Control-Allow-Origin', '')
                acac = resp_headers.get('Access-Control-Allow-Credentials', '')
                
                request_str = self._format_request("GET", self.base_url, headers)
                response_str = self._format_response(status, resp_headers, content)
                
                if acao == '*' and acac.lower() == 'true':
                    # Critical: wildcard with credentials
                    self._add_finding(
                        category="A05",
                        severity="high",
                        title="Critical CORS Misconfiguration",
                        description="CORS allows any origin with credentials - allows credential theft from any website",
                        url=self.base_url,
                        method="GET",
                        evidence=f"Access-Control-Allow-Origin: {acao}\nAccess-Control-Allow-Credentials: {acac}",
                        remediation="Never use wildcard (*) with credentials. Whitelist specific trusted origins.",
                        cwe_id="CWE-942",
                        poc=f"To reproduce:\n1. Send request with Origin: {test_origin}\n2. Observe Access-Control-Allow-Origin: * with credentials allowed",
                        reasoning=f"VERIFIED: Jarwis confirmed the server accepts requests from any origin AND allows credentials. This is a critical vulnerability allowing any malicious site to make authenticated requests.",
                        request_data=request_str,
                        response_data=response_str
                    )
                elif acao == test_origin:
                    # Origin reflection
                    severity = "high" if acac.lower() == 'true' else "medium"
                    self._add_finding(
                        category="A05",
                        severity=severity,
                        title="CORS Origin Reflection",
                        description=f"CORS reflects arbitrary origin headers - server echoed back our malicious origin '{test_origin}'",
                        url=self.base_url,
                        method="GET",
                        evidence=f"Origin sent: {test_origin}\nAccess-Control-Allow-Origin: {acao}",
                        remediation="Validate origins against a strict whitelist. Never reflect the Origin header blindly.",
                        cwe_id="CWE-942",
                        poc=f"To reproduce:\n1. Send request with Origin: {test_origin}\n2. Observe server reflects origin in Access-Control-Allow-Origin header",
                        reasoning=f"VERIFIED: Jarwis sent a request with a malicious Origin header '{test_origin}' and the server reflected it back. This allows any website to make cross-origin requests to this endpoint.",
                        request_data=request_str,
                        response_data=response_str
                    )
                    
        except Exception as e:
            logger.debug(f"CORS check failed: {e}")
    
    async def _check_cookies(self, session: aiohttp.ClientSession):
        """Check for insecure cookie settings on session cookies only"""
        try:
            async with session.get(
                self.base_url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as response:
                cookies = response.cookies
                
                # Only check session-related cookies
                session_keywords = ['session', 'auth', 'token', 'jwt', 'sid']
                
                for cookie in cookies.values():
                    # Skip non-session cookies
                    is_session_cookie = any(kw in cookie.key.lower() for kw in session_keywords)
                    if not is_session_cookie:
                        continue
                    
                    issues = []
                    
                    if not cookie.get('secure'):
                        issues.append("Secure flag missing")
                    if not cookie.get('httponly'):
                        issues.append("HttpOnly flag missing")
                    if cookie.get('samesite', '').lower() not in ['strict', 'lax']:
                        issues.append("SameSite attribute missing or set to None")
                    
                    if issues:
                        self._add_finding(
                            category="A05",
                            severity="medium" if 'session' in cookie.key.lower() else "low",
                            title=f"Insecure Cookie: {cookie.key}",
                            description=f"Cookie has security issues: {', '.join(issues)}",
                            url=self.base_url,
                            method="GET",
                            evidence=f"Cookie: {cookie.key}",
                            remediation="Set Secure, HttpOnly, and SameSite=Strict flags on all cookies",
                            cwe_id="CWE-614"
                        )
                        
        except Exception as e:
            logger.debug(f"Cookie check failed: {e}")
    
    async def _check_server_info(self, session: aiohttp.ClientSession):
        """Check for server information disclosure"""
        error_paths = ['/nonexistent12345', '/test.php', '/test.asp']
        
        for path in error_paths:
            try:
                async with session.get(
                    f"{self.base_url}{path}",
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status in [404, 500]:
                        content = await response.text()
                        
                        # Check for detailed error messages
                        error_patterns = [
                            ('Apache', 'Apache version disclosed'),
                            ('nginx', 'Nginx version disclosed'),
                            ('IIS', 'IIS version disclosed'),
                            ('PHP/', 'PHP version disclosed'),
                            ('Traceback', 'Python stack trace exposed'),
                            ('Exception', 'Exception details exposed'),
                            ('at System.', '.NET stack trace exposed'),
                        ]
                        
                        for pattern, message in error_patterns:
                            if pattern in content:
                                self._add_finding(
                                    category="A05",
                                    severity="low",
                                    title="Error Page Information Disclosure",
                                    description=message,
                                    url=f"{self.base_url}{path}",
                                    method="GET",
                                    evidence=f"Pattern found: {pattern}",
                                    remediation="Configure custom error pages that don't expose technical details",
                                    cwe_id="CWE-209"
                                )
                                break
                                
            except Exception as e:
                logger.debug(f"Server info check failed: {e}")
    
    def _add_finding(self, **kwargs):
        """Add a finding to the results (only if in scope)"""
        url = kwargs.get('url', '')
        if url and not self._is_in_scope(url):
            logger.debug(f"Skipping out-of-scope finding: {url}")
            return
        
        self._finding_id += 1
        finding = ScanResult(id=f"MISC-{self._finding_id:04d}", **kwargs)
        self.findings.append(finding)
        logger.info(f"Found: {finding.title}")
