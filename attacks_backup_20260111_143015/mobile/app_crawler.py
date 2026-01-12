"""
Jarwis AGI - Mobile App Crawler
Comprehensive crawling and endpoint discovery for mobile applications

Features:
- MITM traffic capture for API discovery
- Static endpoint extraction from APK/IPA
- Authentication-aware crawling
- Attack surface mapping
- GET/POST method detection
- Vulnerability correlation with endpoints
"""

import os
import re
import json
import asyncio
import logging
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Callable
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class CrawledEndpoint:
    """A discovered API endpoint from crawling"""
    id: str
    url: str
    method: str  # GET, POST, PUT, DELETE, PATCH
    path: str
    base_url: str
    
    # Request details
    query_params: Dict[str, str] = field(default_factory=dict)
    body_params: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    
    # Response details
    response_status: int = 0
    response_content_type: str = ""
    response_size: int = 0
    
    # Auth info
    requires_auth: bool = False
    auth_type: str = ""  # bearer, cookie, api_key, basic
    auth_header: str = ""
    
    # Discovery metadata
    source: str = ""  # static, traffic, hybrid
    discovered_at: str = ""
    confidence: float = 1.0
    
    # Vulnerability info
    vulnerabilities: List[Dict] = field(default_factory=list)
    is_vulnerable: bool = False
    risk_score: int = 0  # 0-100


@dataclass  
class CrawlResult:
    """Complete crawl result for a mobile app"""
    app_name: str
    platform: str
    scan_id: str
    
    # Endpoints
    endpoints: List[CrawledEndpoint] = field(default_factory=list)
    total_endpoints: int = 0
    
    # Categorized endpoints
    get_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    post_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    auth_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    admin_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    payment_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    user_data_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    
    # Vulnerable endpoints
    vulnerable_endpoints: List[CrawledEndpoint] = field(default_factory=list)
    
    # Base URLs discovered
    base_urls: List[str] = field(default_factory=list)
    
    # Attack surface summary
    attack_surface: Dict = field(default_factory=dict)
    
    # Traffic stats
    total_requests_captured: int = 0
    unique_apis: int = 0
    authenticated_requests: int = 0


class MobileAppCrawler:
    """
    Mobile Application Crawler
    Discovers all API endpoints through static analysis and traffic interception
    """
    
    # API endpoint patterns
    API_PATTERNS = [
        r'/api/',
        r'/v\d+/',
        r'/rest/',
        r'/graphql',
        r'/query',
        r'/mobile/',
        r'/app/',
        r'/service/',
        r'/backend/',
        r'/gateway/',
    ]
    
    # Sensitive endpoint categories
    ENDPOINT_CATEGORIES = {
        'auth': ['/login', '/logout', '/auth', '/token', '/oauth', '/register', '/signup', 
                 '/verify', '/forgot', '/reset', '/password', '/session', '/refresh'],
        'user': ['/user', '/profile', '/account', '/me', '/settings', '/preferences'],
        'payment': ['/payment', '/pay', '/card', '/wallet', '/transaction', '/order', 
                    '/checkout', '/billing', '/subscription', '/invoice'],
        'admin': ['/admin', '/dashboard', '/manage', '/internal', '/config', '/system'],
        'data': ['/data', '/export', '/download', '/report', '/analytics', '/stats'],
        'upload': ['/upload', '/file', '/image', '/media', '/attachment', '/document'],
    }
    
    # High-risk parameters
    SENSITIVE_PARAMS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'api_key', 'apikey',
        'auth', 'session', 'cookie', 'credit_card', 'card_number', 'cvv',
        'ssn', 'social_security', 'bank', 'account', 'routing'
    ]
    
    def __init__(self, config: dict = None, callback: Callable = None):
        self.config = config or {}
        self.callback = callback
        self.discovered_endpoints: Dict[str, CrawledEndpoint] = {}
        self.traffic_log: List[Dict] = []
        self.base_urls: Set[str] = set()
        self._endpoint_counter = 0
        
    def log(self, log_type: str, message: str, details: str = None):
        """Log with callback"""
        if self.callback:
            self.callback(log_type, message, details)
        logger.info(f"[{log_type}] {message}")
    
    async def crawl(self, app_path: str, extracted_path: str = None, 
                    traffic_log_path: str = None, platform: str = "android") -> CrawlResult:
        """
        Comprehensive crawl of mobile application
        
        Args:
            app_path: Path to APK/IPA file
            extracted_path: Path to extracted app contents
            traffic_log_path: Path to MITM traffic log
            platform: 'android' or 'ios'
            
        Returns:
            CrawlResult with all discovered endpoints
        """
        app_name = Path(app_path).stem
        scan_id = f"CRAWL-{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        self.log('phase', '[!]   Starting Mobile App Crawl')
        
        result = CrawlResult(
            app_name=app_name,
            platform=platform,
            scan_id=scan_id
        )
        
        # Phase 1: Static endpoint extraction
        if extracted_path:
            self.log('info', 'Extracting endpoints from app source...')
            await self._crawl_static_sources(Path(extracted_path), platform)
            self.log('info', f'Found {len(self.discovered_endpoints)} endpoints from static analysis')
        
        # Phase 2: Traffic log analysis
        if traffic_log_path and os.path.exists(traffic_log_path):
            self.log('info', 'Analyzing captured traffic...')
            await self._analyze_traffic_log(traffic_log_path)
            self.log('info', f'Total endpoints after traffic analysis: {len(self.discovered_endpoints)}')
        
        # Phase 3: Live traffic capture (if MITM is running)
        await self._capture_live_traffic()
        
        # Build result
        result.endpoints = list(self.discovered_endpoints.values())
        result.total_endpoints = len(result.endpoints)
        result.base_urls = list(self.base_urls)
        
        # Categorize endpoints
        self._categorize_endpoints(result)
        
        # Build attack surface
        result.attack_surface = self._build_attack_surface(result)
        
        self.log('success', f'[OK]  Crawl complete: {result.total_endpoints} endpoints discovered')
        self.log('info', f'   GET: {len(result.get_endpoints)}, POST: {len(result.post_endpoints)}')
        self.log('info', f'   Auth endpoints: {len(result.auth_endpoints)}')
        self.log('info', f'   Vulnerable: {len(result.vulnerable_endpoints)}')
        
        return result
    
    async def _crawl_static_sources(self, extracted_path: Path, platform: str):
        """Extract endpoints from statically extracted app files"""
        
        # File extensions to scan based on platform
        if platform == 'android':
            extensions = {'.java', '.kt', '.json', '.xml', '.smali', '.properties'}
        else:  # iOS
            extensions = {'.swift', '.m', '.h', '.json', '.plist', '.strings'}
        
        # Common patterns for both
        extensions.update({'.js', '.ts', '.html', '.yml', '.yaml'})
        
        files_scanned = 0
        
        for root, dirs, files in os.walk(extracted_path):
            # Skip unnecessary directories
            skip_dirs = {'node_modules', '.git', '__MACOSX', 'build', 'gradle'}
            dirs[:] = [d for d in dirs if d not in skip_dirs]
            
            for filename in files:
                file_path = Path(root) / filename
                if file_path.suffix.lower() in extensions:
                    await self._scan_file_for_endpoints(file_path)
                    files_scanned += 1
        
        self.log('detail', f'Scanned {files_scanned} files for API endpoints')
    
    async def _scan_file_for_endpoints(self, file_path: Path):
        """Scan a single file for API endpoints"""
        try:
            content = file_path.read_text(errors='ignore')
            
            # Find full URLs
            url_pattern = r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
            urls = re.findall(url_pattern, content)
            
            for url in urls:
                # Skip non-API URLs
                if self._should_skip_url(url):
                    continue
                
                parsed = urlparse(url)
                
                # Check if it looks like an API endpoint
                if self._is_api_endpoint(parsed.path):
                    self._add_endpoint(
                        url=url,
                        method=self._guess_method(url, content),
                        source="static",
                        file_path=str(file_path)
                    )
            
            # Find API paths without full URLs
            path_patterns = [
                r'["\'](/api/[a-zA-Z0-9/_-]+)["\']',
                r'["\'](/v\d+/[a-zA-Z0-9/_-]+)["\']',
                r'["\'](/rest/[a-zA-Z0-9/_-]+)["\']',
                r'["\'](/graphql)["\']',
                r'["\'](/mobile/[a-zA-Z0-9/_-]+)["\']',
            ]
            
            for pattern in path_patterns:
                matches = re.findall(pattern, content)
                for path in matches:
                    self._add_endpoint(
                        url=path,
                        method=self._guess_method(path, content),
                        source="static",
                        file_path=str(file_path)
                    )
            
            # Find Retrofit/OkHttp/URLSession patterns (Android/iOS)
            await self._extract_framework_endpoints(content, file_path)
            
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
    
    async def _extract_framework_endpoints(self, content: str, file_path: Path):
        """Extract endpoints from mobile framework annotations"""
        
        # Retrofit annotations (Android)
        retrofit_patterns = [
            (r'@GET\s*\(\s*["\']([^"\']+)["\']\s*\)', 'GET'),
            (r'@POST\s*\(\s*["\']([^"\']+)["\']\s*\)', 'POST'),
            (r'@PUT\s*\(\s*["\']([^"\']+)["\']\s*\)', 'PUT'),
            (r'@DELETE\s*\(\s*["\']([^"\']+)["\']\s*\)', 'DELETE'),
            (r'@PATCH\s*\(\s*["\']([^"\']+)["\']\s*\)', 'PATCH'),
        ]
        
        for pattern, method in retrofit_patterns:
            matches = re.findall(pattern, content)
            for path in matches:
                self._add_endpoint(
                    url=path,
                    method=method,
                    source="retrofit",
                    file_path=str(file_path)
                )
        
        # Alamofire/URLSession patterns (iOS)
        ios_patterns = [
            (r'\.get\s*\(\s*["\']([^"\']+)["\']', 'GET'),
            (r'\.post\s*\(\s*["\']([^"\']+)["\']', 'POST'),
            (r'\.put\s*\(\s*["\']([^"\']+)["\']', 'PUT'),
            (r'\.delete\s*\(\s*["\']([^"\']+)["\']', 'DELETE'),
            (r'URLRequest\s*\(\s*url:\s*["\']([^"\']+)["\']', 'GET'),
        ]
        
        for pattern, method in ios_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for path in matches:
                self._add_endpoint(
                    url=path,
                    method=method,
                    source="ios_framework",
                    file_path=str(file_path)
                )
    
    async def _analyze_traffic_log(self, traffic_log_path: str):
        """Analyze MITM traffic log for endpoints"""
        try:
            # Support JSONL format
            if traffic_log_path.endswith('.jsonl'):
                with open(traffic_log_path, 'r') as f:
                    for line in f:
                        try:
                            entry = json.loads(line.strip())
                            await self._process_traffic_entry(entry)
                        except json.JSONDecodeError:
                            continue
            else:
                # Regular JSON
                with open(traffic_log_path, 'r') as f:
                    traffic = json.load(f)
                    if isinstance(traffic, list):
                        for entry in traffic:
                            await self._process_traffic_entry(entry)
                    elif isinstance(traffic, dict):
                        for entry in traffic.get('requests', []):
                            await self._process_traffic_entry(entry)
                            
        except Exception as e:
            logger.error(f"Error reading traffic log: {e}")
    
    async def _process_traffic_entry(self, entry: Dict):
        """Process a single traffic log entry"""
        if 'response' in entry:
            # This is a response entry, skip for endpoint discovery
            return
        
        url = entry.get('url', '')
        if not url:
            return
        
        method = entry.get('method', 'GET')
        headers = entry.get('headers', {})
        
        parsed = urlparse(url)
        
        # Skip non-API requests
        if self._should_skip_url(url):
            return
        
        endpoint = self._add_endpoint(
            url=url,
            method=method,
            source="traffic",
            headers=headers
        )
        
        if endpoint:
            # Extract query params
            if parsed.query:
                endpoint.query_params = dict(parse_qs(parsed.query))
            
            # Extract body params
            body = entry.get('body_preview', entry.get('body', ''))
            if body and method in ['POST', 'PUT', 'PATCH']:
                endpoint.body_params = self._parse_body(body, headers.get('content-type', ''))
            
            # Check for auth
            self._detect_auth(endpoint, headers)
            
            # Response info
            if 'status' in entry:
                endpoint.response_status = entry['status']
        
        self.traffic_log.append(entry)
    
    async def _capture_live_traffic(self):
        """Capture any live traffic from running MITM proxy"""
        traffic_file = Path("reports/mobile_traffic.jsonl")
        
        if traffic_file.exists():
            self.log('info', 'Processing live traffic capture...')
            await self._analyze_traffic_log(str(traffic_file))
    
    def _add_endpoint(self, url: str, method: str = "GET", source: str = "unknown",
                      headers: Dict = None, file_path: str = None) -> Optional[CrawledEndpoint]:
        """Add an endpoint to discovered list"""
        headers = headers or {}
        
        # Parse URL
        parsed = urlparse(url)
        
        if parsed.scheme and parsed.netloc:
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            path = parsed.path
            full_url = url
        else:
            # Just a path
            base_url = ""
            path = url
            full_url = url
        
        # Create unique key
        endpoint_key = f"{method}:{path}"
        
        # Update existing or add new
        if endpoint_key in self.discovered_endpoints:
            existing = self.discovered_endpoints[endpoint_key]
            # Upgrade confidence if found in traffic
            if source == "traffic":
                existing.confidence = 1.0
                existing.source = "hybrid" if existing.source == "static" else source
            return existing
        
        # Create new endpoint
        self._endpoint_counter += 1
        endpoint_id = f"EP-{self._endpoint_counter:05d}"
        
        endpoint = CrawledEndpoint(
            id=endpoint_id,
            url=full_url,
            method=method,
            path=path,
            base_url=base_url,
            headers=headers,
            source=source,
            discovered_at=datetime.now().isoformat(),
            confidence=1.0 if source == "traffic" else 0.8
        )
        
        if base_url:
            self.base_urls.add(base_url)
        
        self.discovered_endpoints[endpoint_key] = endpoint
        return endpoint
    
    def _detect_auth(self, endpoint: CrawledEndpoint, headers: Dict):
        """Detect authentication from headers"""
        auth_headers = {
            'authorization': 'bearer',
            'x-auth-token': 'token',
            'x-api-key': 'api_key',
            'cookie': 'cookie',
            'x-access-token': 'token',
            'x-session-id': 'session'
        }
        
        for header, auth_type in auth_headers.items():
            if header in headers or header.lower() in headers:
                endpoint.requires_auth = True
                endpoint.auth_type = auth_type
                endpoint.auth_header = header
                break
    
    def _should_skip_url(self, url: str) -> bool:
        """Check if URL should be skipped"""
        skip_patterns = [
            'google.com/analytics',
            'googleapis.com',
            'facebook.com',
            'facebook.net',
            'twitter.com',
            'crashlytics',
            'firebase.google.com',
            'firebaseio.com',
            'schemas.android.com',
            'www.w3.org',
            'apple.com/DTD',
            'xmlns',
            '.png', '.jpg', '.gif', '.css', '.ico', '.svg',
            '.woff', '.ttf', '.eot',
            'cdn.', 'static.',
        ]
        return any(pattern in url.lower() for pattern in skip_patterns)
    
    def _is_api_endpoint(self, path: str) -> bool:
        """Check if path looks like an API endpoint"""
        return any(re.search(pattern, path, re.IGNORECASE) for pattern in self.API_PATTERNS)
    
    def _guess_method(self, path: str, context: str = "") -> str:
        """Guess HTTP method from path and context"""
        path_lower = path.lower()
        context_lower = context.lower() if context else ""
        
        # Check context around the path
        post_indicators = ['create', 'add', 'new', 'register', 'signup', 'login', 'upload', 'submit']
        put_indicators = ['update', 'edit', 'modify', 'change']
        delete_indicators = ['delete', 'remove', 'cancel']
        
        if any(ind in path_lower for ind in delete_indicators):
            return "DELETE"
        if any(ind in path_lower for ind in put_indicators):
            return "PUT"
        if any(ind in path_lower for ind in post_indicators):
            return "POST"
        
        # Check context
        if 'POST' in context_lower[:100]:
            return "POST"
        
        return "GET"
    
    def _parse_body(self, body: str, content_type: str) -> Dict:
        """Parse request body to extract parameters"""
        params = {}
        
        if not body:
            return params
        
        try:
            if 'json' in content_type.lower():
                data = json.loads(body)
                if isinstance(data, dict):
                    params = {k: type(v).__name__ for k, v in data.items()}
            elif 'form' in content_type.lower():
                for pair in body.split('&'):
                    if '=' in pair:
                        key, _ = pair.split('=', 1)
                        params[key] = 'string'
        except:
            pass
        
        return params
    
    def _categorize_endpoints(self, result: CrawlResult):
        """Categorize endpoints by type"""
        for endpoint in result.endpoints:
            path_lower = endpoint.path.lower()
            
            # By method
            if endpoint.method == 'GET':
                result.get_endpoints.append(endpoint)
            elif endpoint.method in ['POST', 'PUT', 'PATCH']:
                result.post_endpoints.append(endpoint)
            
            # By category
            for category, patterns in self.ENDPOINT_CATEGORIES.items():
                if any(p in path_lower for p in patterns):
                    if category == 'auth':
                        result.auth_endpoints.append(endpoint)
                    elif category == 'admin':
                        result.admin_endpoints.append(endpoint)
                    elif category == 'payment':
                        result.payment_endpoints.append(endpoint)
                    elif category == 'user':
                        result.user_data_endpoints.append(endpoint)
                    break
    
    def _build_attack_surface(self, result: CrawlResult) -> Dict:
        """Build attack surface summary"""
        return {
            'total_endpoints': result.total_endpoints,
            'get_requests': len(result.get_endpoints),
            'post_requests': len(result.post_endpoints),
            'authenticated_endpoints': len([e for e in result.endpoints if e.requires_auth]),
            'unauthenticated_endpoints': len([e for e in result.endpoints if not e.requires_auth]),
            'auth_endpoints': len(result.auth_endpoints),
            'admin_endpoints': len(result.admin_endpoints),
            'payment_endpoints': len(result.payment_endpoints),
            'user_data_endpoints': len(result.user_data_endpoints),
            'vulnerable_endpoints': len(result.vulnerable_endpoints),
            'base_urls': result.base_urls,
            'high_risk_areas': self._identify_high_risk(result),
        }
    
    def _identify_high_risk(self, result: CrawlResult) -> List[Dict]:
        """Identify high-risk areas in the attack surface"""
        risks = []
        
        # Unauthenticated sensitive endpoints
        for endpoint in result.endpoints:
            if not endpoint.requires_auth:
                if any(p in endpoint.path.lower() for p in ['/admin', '/user', '/payment', '/account']):
                    risks.append({
                        'endpoint': endpoint.path,
                        'method': endpoint.method,
                        'risk': 'Sensitive endpoint without authentication',
                        'severity': 'high'
                    })
        
        # Sensitive parameters in URLs
        for endpoint in result.get_endpoints:
            for param in endpoint.query_params.keys():
                if any(s in param.lower() for s in self.SENSITIVE_PARAMS):
                    risks.append({
                        'endpoint': endpoint.path,
                        'method': endpoint.method,
                        'risk': f'Sensitive parameter "{param}" in URL',
                        'severity': 'medium'
                    })
        
        return risks
    
    def correlate_vulnerabilities(self, result: CrawlResult, findings: List[Dict]) -> CrawlResult:
        """Correlate findings with endpoints to show where vulnerabilities are"""
        
        for finding in findings:
            finding_url = finding.get('url', finding.get('affected_component', ''))
            
            for endpoint in result.endpoints:
                # Match by URL or path
                if finding_url and (finding_url in endpoint.url or finding_url in endpoint.path):
                    endpoint.vulnerabilities.append({
                        'id': finding.get('id'),
                        'title': finding.get('title'),
                        'severity': finding.get('severity'),
                        'category': finding.get('category')
                    })
                    endpoint.is_vulnerable = True
                    
                    # Calculate risk score
                    severity_scores = {'critical': 40, 'high': 30, 'medium': 20, 'low': 10}
                    endpoint.risk_score += severity_scores.get(finding.get('severity', 'low'), 5)
        
        # Build vulnerable endpoints list
        result.vulnerable_endpoints = [e for e in result.endpoints if e.is_vulnerable]
        result.vulnerable_endpoints.sort(key=lambda x: x.risk_score, reverse=True)
        
        return result
    
    def export_endpoints(self, result: CrawlResult, format: str = "json") -> str:
        """Export crawl results"""
        
        if format == "json":
            export_data = {
                'app_name': result.app_name,
                'platform': result.platform,
                'scan_id': result.scan_id,
                'total_endpoints': result.total_endpoints,
                'attack_surface': result.attack_surface,
                'endpoints': [
                    {
                        'id': e.id,
                        'url': e.url,
                        'method': e.method,
                        'path': e.path,
                        'requires_auth': e.requires_auth,
                        'auth_type': e.auth_type,
                        'source': e.source,
                        'vulnerabilities': e.vulnerabilities,
                        'is_vulnerable': e.is_vulnerable,
                        'risk_score': e.risk_score
                    }
                    for e in result.endpoints
                ],
                'vulnerable_endpoints': [
                    {
                        'path': e.path,
                        'method': e.method,
                        'risk_score': e.risk_score,
                        'vulnerabilities': e.vulnerabilities
                    }
                    for e in result.vulnerable_endpoints
                ]
            }
            return json.dumps(export_data, indent=2)
        
        elif format == "html":
            return self._generate_endpoints_html(result)
        
        return ""
    
    def _generate_endpoints_html(self, result: CrawlResult) -> str:
        """Generate HTML table of endpoints"""
        rows = ""
        
        for endpoint in sorted(result.endpoints, key=lambda x: (-x.risk_score, x.path)):
            vuln_badges = ""
            if endpoint.vulnerabilities:
                for v in endpoint.vulnerabilities:
                    sev = v.get('severity', 'info')
                    vuln_badges += f'<span class="badge {sev}">{v.get("title", "Vuln")}</span>'
            
            auth_badge = f'<span class="badge auth">{endpoint.auth_type}</span>' if endpoint.requires_auth else '<span class="badge no-auth">No Auth</span>'
            
            row_class = "vulnerable" if endpoint.is_vulnerable else ""
            
            rows += f'''
            <tr class="{row_class}">
                <td><span class="method {endpoint.method.lower()}">{endpoint.method}</span></td>
                <td class="path">{endpoint.path}</td>
                <td>{auth_badge}</td>
                <td>{endpoint.source}</td>
                <td>{vuln_badges or '<span class="safe">Safe</span>'}</td>
                <td class="risk-score">{endpoint.risk_score}</td>
            </tr>
            '''
        
        return f'''
        <div class="endpoints-section">
            <h3>[!]   API Endpoints ({result.total_endpoints})</h3>
            <div class="attack-surface-summary">
                <div class="stat"><strong>{len(result.get_endpoints)}</strong> GET</div>
                <div class="stat"><strong>{len(result.post_endpoints)}</strong> POST</div>
                <div class="stat"><strong>{len(result.auth_endpoints)}</strong> Auth</div>
                <div class="stat vulnerable-stat"><strong>{len(result.vulnerable_endpoints)}</strong> Vulnerable</div>
            </div>
            <table class="endpoints-table">
                <thead>
                    <tr>
                        <th>Method</th>
                        <th>Endpoint</th>
                        <th>Auth</th>
                        <th>Source</th>
                        <th>Vulnerabilities</th>
                        <th>Risk</th>
                    </tr>
                </thead>
                <tbody>
                    {rows}
                </tbody>
            </table>
        </div>
        '''


# Factory function
def create_app_crawler(config: dict = None, callback: Callable = None) -> MobileAppCrawler:
    """Create a mobile app crawler instance"""
    return MobileAppCrawler(config=config, callback=callback)
