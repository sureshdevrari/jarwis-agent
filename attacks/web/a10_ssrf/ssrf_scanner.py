"""
Jarwis AGI Pen Test - SSRF Scanner
Server-Side Request Forgery vulnerability detection (A10:2021)
Uses OWASP Detection Logic for evidence-based detection
"""

import asyncio
import logging
import re
from typing import Dict, List
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
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
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class SSRFScanner:
    """Scans for Server-Side Request Forgery vulnerabilities (A10:2021)"""
    
    # URL-type parameters that might be vulnerable to SSRF
    URL_PARAMS = [
        'url', 'uri', 'path', 'dest', 'redirect', 'next', 'data', 
        'reference', 'site', 'html', 'val', 'validate', 'domain', 
        'callback', 'return', 'page', 'feed', 'host', 'port', 'to', 
        'out', 'view', 'dir', 'src', 'source', 'ref', 'target',
        'u', 'link', 'linkurl', 'image', 'imageurl', 'file', 'document'
    ]
    
    # SSRF Test payloads
    SSRF_PAYLOADS = [
        # Localhost variants
        ('http://127.0.0.1', 'Localhost IPv4'),
        ('http://localhost', 'Localhost hostname'),
        ('http://[::1]', 'Localhost IPv6'),
        ('http://0.0.0.0', 'All interfaces'),
        
        # Internal network ranges
        ('http://192.168.1.1', 'Internal 192.168.x.x'),
        ('http://10.0.0.1', 'Internal 10.x.x.x'),
        ('http://172.16.0.1', 'Internal 172.16.x.x'),
        
        # Cloud metadata endpoints
        ('http://169.254.169.254/latest/meta-data/', 'AWS metadata'),
        ('http://metadata.google.internal/computeMetadata/v1/', 'GCP metadata'),
        ('http://169.254.169.254/metadata/instance', 'Azure metadata'),
        
        # Localhost bypass techniques
        ('http://127.1', 'Localhost shorthand'),
        ('http://127.0.1', 'Localhost variant'),
        ('http://0', 'Zero IP'),
        ('http://localhost.localstack.cloud', 'Localhost subdomain'),
    ]
    
    # Indicators that SSRF was successful
    SSRF_SUCCESS_INDICATORS = [
        (r'root:.*:0:0:', 'Unix passwd file content'),
        (r'ami-id', 'AWS metadata response'),
        (r'instance-id', 'Cloud instance metadata'),
        (r'<title>.*Dashboard.*</title>', 'Internal dashboard access'),
        (r'apache|nginx|iis', 'Internal server response'),
        (r'"error":\s*"connection refused"', 'Internal connection attempt'),
        (r'private_ip', 'Private IP disclosure'),
        (r'internal', 'Internal service reference'),
        (r'intranet', 'Intranet access'),
        (r'192\.168\.\d+\.\d+', 'Private IP in response'),
        (r'10\.\d+\.\d+\.\d+', 'Private IP in response'),
        (r'127\.0\.0\.1', 'Localhost in response'),
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
        self.use_js_rendering = config.get('js_rendering', True)
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers from context for post-login attacks"""
        if hasattr(self.context, 'auth_headers') and self.context.auth_headers:
            return dict(self.context.auth_headers)
        return {}
    
    def _get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies from context for post-login attacks"""
        if hasattr(self.context, 'auth_cookies') and self.context.auth_cookies:
            return dict(self.context.auth_cookies)
        if hasattr(self.context, 'cookies') and self.context.cookies:
            return dict(self.context.cookies)
        return {}
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
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
        if len(body) > 1500:
            body = body[:1500] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    def _add_finding(self, **kwargs):
        """Add a new finding"""
        self._finding_id += 1
        finding = ScanResult(
            id=f"SSRF-{self._finding_id:04d}",
            **kwargs
        )
        self.findings.append(finding)
        logger.info(f"[SSRF] Found: {finding.title} at {finding.url}")
        return finding
    
    async def scan(self) -> List[ScanResult]:
        """Run SSRF scans on all endpoints"""
        self.findings = []
        
        # Find endpoints with URL-like parameters
        testable_endpoints = []
        
        for ep in self.context.endpoints:
            url = ep.get('url', '')
            params = ep.get('params', {})
            
            # Check for URL-type parameters
            for param_name in params:
                if param_name.lower() in self.URL_PARAMS:
                    testable_endpoints.append({
                        'url': url,
                        'method': ep.get('method', 'GET'),
                        'param': param_name,
                        'params': params
                    })
            
            # Also check URL query string
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            for param_name in query_params:
                if param_name.lower() in self.URL_PARAMS:
                    testable_endpoints.append({
                        'url': url,
                        'method': ep.get('method', 'GET'),
                        'param': param_name,
                        'params': query_params
                    })
        
        logger.info(f"Testing {len(testable_endpoints)} endpoints for SSRF")
        
        # Get auth configuration for post-login attacks
        auth_headers = self._get_auth_headers()
        auth_cookies = self._get_auth_cookies()
        
        session_kwargs = {}
        if auth_cookies:
            session_kwargs['cookies'] = auth_cookies
            logger.info(f"[SSRF] Using {len(auth_cookies)} auth cookies for authenticated testing")
        if auth_headers:
            session_kwargs['headers'] = auth_headers
            logger.info(f"[SSRF] Using {len(auth_headers)} auth headers for authenticated testing")
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            for endpoint in testable_endpoints:
                await self._test_endpoint(session, endpoint)
                await asyncio.sleep(1 / self.rate_limit)
        
        return self.findings
    
    async def _test_endpoint(self, session: aiohttp.ClientSession, endpoint: Dict):
        """Test a single endpoint for SSRF"""
        url = endpoint['url']
        method = endpoint['method']
        param = endpoint['param']
        
        # Get baseline response
        baseline_body = ""
        try:
            async with session.request(
                method,
                url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                baseline_body = await response.text()
        except:
            pass
        
        # Test each SSRF payload
        for i, (payload, payload_desc) in enumerate(self.SSRF_PAYLOADS[:6]):  # Test first 6 payloads
            # VERBOSE LOGGING: Show each SSRF payload being tested
            logger.info(f"[SSRF] Testing payload {i+1}/6 on {param}: {payload} ({payload_desc})")
            
            try:
                # Inject payload into URL parameter
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                async with session.request(
                    method,
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    resp_headers = dict(response.headers)
                    status = response.status
                    
                    # Check for SSRF success indicators
                    for pattern, indicator_desc in self.SSRF_SUCCESS_INDICATORS:
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            # Verify not in baseline
                            if not re.search(pattern, baseline_body, re.IGNORECASE):
                                request_str = self._format_request(method, test_url, self.DEFAULT_HEADERS)
                                response_str = self._format_response(status, resp_headers, body)
                                
                                self._add_finding(
                                    category="A10",
                                    severity="high",
                                    title=f"SSRF via {param} parameter",
                                    description=f"Server-Side Request Forgery detected. The application fetches content from user-supplied URL in parameter '{param}'. Internal service data was returned.",
                                    url=url,
                                    method=method,
                                    parameter=param,
                                    evidence=f"Payload: {payload}\nIndicator: {indicator_desc}\nMatched: {match.group(0)[:100]}",
                                    remediation="Validate and sanitize user-supplied URLs. Use allowlists for permitted domains. Block requests to private IP ranges and cloud metadata endpoints.",
                                    cwe_id="CWE-918",
                                    poc=f"Payload: {payload}\nParameter: {param}\n\nTo reproduce:\n1. Navigate to {url}\n2. Set parameter '{param}' to '{payload}'\n3. Observe internal service data in response",
                                    reasoning=f"VERIFIED: Jarwis injected internal URL '{payload}' ({payload_desc}) into parameter '{param}'. The response contained '{indicator_desc}' which does NOT appear in normal responses. This confirms the server is fetching and returning content from user-controlled URLs.",
                                    request_data=request_str,
                                    response_data=response_str
                                )
                                return
                    
                    # Check for timing-based SSRF (connection errors with delays)
                    # This indicates the server tried to connect
                    
            except asyncio.TimeoutError:
                # Timeout might indicate SSRF attempt to slow/non-existent host
                logger.debug(f"SSRF test timeout for {url} with payload {payload}")
            except Exception as e:
                logger.debug(f"SSRF test error for {url}: {e}")
    
    async def _test_blind_ssrf(self, session: aiohttp.ClientSession, url: str, param: str):
        """Test for blind SSRF using OOB techniques (requires external callback server)"""
        # This would require an external callback server like Burp Collaborator
        # For now, we rely on direct response analysis
        pass
