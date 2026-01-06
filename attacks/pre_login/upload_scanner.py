"""
Jarwis AGI Pen Test - File Upload Scanner
Tests for insecure file upload vulnerabilities
"""

import asyncio
import logging
import io
from typing import Dict, List
from dataclasses import dataclass
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


class UploadScanner:
    """Tests file upload functionality for security issues"""
    
    # Test files with various bypass techniques
    TEST_FILES = [
        {
            'name': 'test.php',
            'content': b'<?php echo "TEST"; ?>',
            'content_type': 'application/x-php',
            'severity': 'critical',
            'description': 'PHP file upload'
        },
        {
            'name': 'test.php5',
            'content': b'<?php echo "TEST"; ?>',
            'content_type': 'application/x-php',
            'severity': 'critical',
            'description': 'PHP5 extension bypass'
        },
        {
            'name': 'test.phtml',
            'content': b'<?php echo "TEST"; ?>',
            'content_type': 'application/x-php',
            'severity': 'critical', 
            'description': 'PHTML extension bypass'
        },
        {
            'name': 'test.jpg.php',
            'content': b'GIF89a; <?php echo "TEST"; ?>',
            'content_type': 'image/jpeg',
            'severity': 'critical',
            'description': 'Double extension bypass with magic bytes'
        },
        {
            'name': 'test.php.jpg',
            'content': b'<?php echo "TEST"; ?>',
            'content_type': 'image/jpeg',
            'severity': 'high',
            'description': 'Reverse double extension'
        },
        {
            'name': 'test.svg',
            'content': b'<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>',
            'content_type': 'image/svg+xml',
            'severity': 'high',
            'description': 'SVG with XSS payload'
        },
        {
            'name': 'test.html',
            'content': b'<script>alert(1)</script>',
            'content_type': 'text/html',
            'severity': 'high',
            'description': 'HTML file upload'
        },
        {
            'name': '../../../tmp/test.txt',
            'content': b'path traversal test',
            'content_type': 'text/plain',
            'severity': 'critical',
            'description': 'Path traversal in filename'
        },
        {
            'name': 'test.asp',
            'content': b'<% Response.Write("TEST") %>',
            'content_type': 'application/x-asp',
            'severity': 'critical',
            'description': 'ASP file upload'
        },
        {
            'name': 'test.jsp',
            'content': b'<%= "TEST" %>',
            'content_type': 'application/x-jsp',
            'severity': 'critical',
            'description': 'JSP file upload'
        },
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Will be set by PreLoginAttacks if available
        self.use_js_rendering = config.get('js_rendering', True)
    
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
    
    async def scan(self) -> List[ScanResult]:
        """Test all upload endpoints"""
        self.findings = []
        
        upload_endpoints = self.context.upload_endpoints
        logger.info(f"Testing {len(upload_endpoints)} upload endpoints")
        
        async with aiohttp.ClientSession() as session:
            for endpoint in upload_endpoints:
                await self._test_upload_endpoint(session, endpoint)
        
        return self.findings
    
    async def _test_upload_endpoint(self, session: aiohttp.ClientSession, endpoint: Dict):
        """Test a single upload endpoint"""
        url = endpoint.get('url', '')
        
        for test_file in self.TEST_FILES:
            await self._try_upload(session, url, test_file)
            await asyncio.sleep(0.2)  # Rate limiting
    
    async def _try_upload(self, session: aiohttp.ClientSession, url: str, test_file: Dict):
        """Attempt to upload a test file"""
        try:
            # Create multipart form data
            data = aiohttp.FormData()
            data.add_field(
                'file',
                io.BytesIO(test_file['content']),
                filename=test_file['name'],
                content_type=test_file['content_type']
            )
            
            async with session.post(
                url,
                data=data,
                timeout=aiohttp.ClientTimeout(total=30),
                ssl=False
            ) as response:
                status = response.status
                body = await response.text()
                
                # Check if upload was accepted
                if status in [200, 201]:
                    # Look for success indicators
                    success_indicators = [
                        'success', 'uploaded', 'file_url', 'path',
                        test_file['name'].split('.')[0]
                    ]
                    
                    if any(ind in body.lower() for ind in success_indicators):
                        self._add_finding(
                            category="A01",
                            severity=test_file['severity'],
                            title=f"Insecure File Upload: {test_file['description']}",
                            description=f"Server accepted upload of {test_file['name']}",
                            url=url,
                            method="POST",
                            parameter="file",
                            evidence=f"Filename: {test_file['name']}, Status: {status}",
                            remediation="Validate file types, use allowlist of extensions, store outside webroot",
                            cwe_id="CWE-434"
                        )
                        
                        # Try to access uploaded file
                        await self._verify_upload(session, url, body, test_file)
                        
        except Exception as e:
            logger.debug(f"Upload test failed for {url}: {e}")
    
    async def _verify_upload(self, session: aiohttp.ClientSession, upload_url: str, response_body: str, test_file: Dict):
        """Try to verify if uploaded file is accessible"""
        # Common upload paths
        possible_paths = [
            f"/uploads/{test_file['name']}",
            f"/files/{test_file['name']}",
            f"/media/{test_file['name']}",
            f"/static/uploads/{test_file['name']}",
        ]
        
        base_url = '/'.join(upload_url.split('/')[:3])
        
        for path in possible_paths:
            try:
                async with session.get(
                    f"{base_url}{path}",
                    timeout=aiohttp.ClientTimeout(total=5),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        if 'TEST' in content or '<script>' in content:
                            self._add_finding(
                                category="A01",
                                severity="critical",
                                title="Uploaded File Executable/Accessible",
                                description=f"Malicious file accessible at {path}",
                                url=f"{base_url}{path}",
                                method="GET",
                                evidence=f"Content contains expected payload",
                                remediation="Block execution of uploaded files, serve from different domain",
                                cwe_id="CWE-434"
                            )
                            return
            except:
                pass
    
    def _add_finding(self, **kwargs):
        """Add a finding to the results (only if in scope)"""
        url = kwargs.get('url', '')
        if url and not self._is_in_scope(url):
            logger.debug(f"Skipping out-of-scope finding: {url}")
            return
        
        self._finding_id += 1
        finding = ScanResult(id=f"UPLOAD-{self._finding_id:04d}", **kwargs)
        self.findings.append(finding)
        logger.info(f"Found: {finding.title}")
