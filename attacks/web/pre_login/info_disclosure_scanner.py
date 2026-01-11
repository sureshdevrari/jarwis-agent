"""
Jarwis AGI Pen Test - Information Disclosure Scanner
Detects Information Disclosure vulnerabilities (A05:2021 - Security Misconfiguration)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Set
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


class InformationDisclosureScanner:
    """
    Scans for Information Disclosure vulnerabilities
    OWASP A05:2021 - Security Misconfiguration
    
    Attack vectors:
    - Error message disclosure
    - Debug mode detection
    - Stack traces
    - Version information
    - Internal IPs/paths
    - Comments in HTML/JS
    - Backup files
    - Configuration files
    - Git/SVN exposure
    - Directory listing
    - API documentation exposure
    """
    
    # Sensitive file paths
    SENSITIVE_FILES = [
        # Configuration files
        '/.env', '/config.json', '/config.yaml', '/config.yml', '/config.xml',
        '/settings.json', '/settings.yaml', '/app.config', '/web.config',
        '/appsettings.json', '/appsettings.Development.json',
        '/config/database.yml', '/config/secrets.yml',
        '/wp-config.php', '/wp-config.php.bak', '/wp-config.php.old',
        '/configuration.php', '/LocalSettings.php',
        
        # Backup files
        '/backup.sql', '/backup.zip', '/backup.tar.gz', '/backup.tar',
        '/database.sql', '/db.sql', '/dump.sql', '/data.sql',
        '/site.zip', '/www.zip', '/public.zip', '/html.zip',
        
        # Git/SVN
        '/.git/config', '/.git/HEAD', '/.gitignore', '/.git/logs/HEAD',
        '/.svn/entries', '/.svn/wc.db',
        '/.hg/hgrc', '/.bzr/branch/branch.conf',
        
        # Environment/secrets
        '/.env.local', '/.env.production', '/.env.development', '/.env.backup',
        '/secrets.json', '/credentials.json', '/passwords.txt',
        '/.aws/credentials', '/.ssh/id_rsa', '/.ssh/id_rsa.pub',
        
        # IDE/editor files
        '/.idea/workspace.xml', '/.vscode/settings.json',
        '/package.json', '/package-lock.json', '/composer.json',
        '/Gemfile', '/requirements.txt', '/Pipfile',
        
        # Debug/test files
        '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
        '/server-status', '/server-info',
        
        # API docs
        '/swagger.json', '/swagger.yaml', '/openapi.json', '/openapi.yaml',
        '/api-docs', '/api/docs', '/api/swagger', '/api/openapi',
        '/docs', '/documentation', '/api-documentation',
        
        # Logs
        '/logs', '/log', '/debug.log', '/error.log', '/access.log',
        '/logs/error.log', '/logs/debug.log', '/var/log/apache/error.log',
        
        # Admin/internal
        '/admin', '/administrator', '/admin.php', '/wp-admin',
        '/phpmyadmin', '/pma', '/adminer.php',
        '/metrics', '/health', '/status', '/actuator',
        '/actuator/env', '/actuator/configprops', '/actuator/heapdump',
    ]
    
    # Patterns that indicate information disclosure
    DISCLOSURE_PATTERNS = [
        # Error messages
        (r'Exception in thread|Stack trace:|Traceback \(most recent call last\)', 'Stack Trace', 'high'),
        (r'Fatal error:|Parse error:|Warning:', 'PHP Error', 'medium'),
        (r'java\.(lang|io|sql)\.[A-Z]', 'Java Exception', 'medium'),
        (r'at [a-zA-Z]+\.[a-zA-Z]+\([a-zA-Z]+\.java:\d+\)', 'Java Stack Trace', 'high'),
        (r'Microsoft OLE DB Provider|ODBC Driver', 'Database Error', 'high'),
        (r'mysql_fetch|pg_query|sqlite_|mssql_', 'Database Function Error', 'high'),
        (r'SQL syntax.*MySQL|ORA-\d+:|PLS-\d+:', 'SQL Error', 'high'),
        (r'Syntax error.*line \d+', 'Syntax Error', 'medium'),
        
        # Paths
        (r'/var/www/|/home/\w+/|/usr/local/|C:\\\\[Ii]netpub|C:\\\\Users\\\\', 'Internal Path', 'medium'),
        (r'/app/|/opt/|/srv/', 'Server Path', 'low'),
        
        # Internal IPs
        (r'(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})', 'Internal IP', 'medium'),
        
        # Versions
        (r'Apache/[\d\.]+|nginx/[\d\.]+|IIS/[\d\.]+', 'Server Version', 'low'),
        (r'PHP/[\d\.]+|Python/[\d\.]+|Ruby/[\d\.]+', 'Language Version', 'low'),
        (r'X-Powered-By: .*', 'X-Powered-By Header', 'low'),
        
        # Debug info
        (r'"debug"\s*:\s*true|DEBUG\s*=\s*True|FLASK_DEBUG', 'Debug Mode', 'high'),
        (r'xdebug|Xdebug|XDEBUG', 'Xdebug Enabled', 'high'),
        
        # Credentials
        (r'password\s*[=:]\s*["\'][^"\']+["\']', 'Password in Response', 'critical'),
        (r'api[_-]?key\s*[=:]\s*["\'][^"\']+["\']', 'API Key in Response', 'critical'),
        (r'secret[_-]?key\s*[=:]\s*["\'][^"\']+["\']', 'Secret Key in Response', 'critical'),
        (r'access[_-]?token\s*[=:]\s*["\'][^"\']+["\']', 'Access Token in Response', 'critical'),
        (r'-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----', 'Private Key', 'critical'),
        (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 'critical'),
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
        self.checked_patterns: Set[str] = set()
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Information Disclosure scan...")
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
            
            # Check sensitive files
            await self._check_sensitive_files(session, base_url)
            
            # Check response headers
            await self._check_headers(session, base_url)
            
            # Analyze responses for patterns
            await self._check_patterns(session, base_url)
            
            # Check discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if url:
                        await self._analyze_response(session, url)
        
        logger.info(f"Information disclosure scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_sensitive_files(self, session: aiohttp.ClientSession, base_url: str):
        """Check for exposed sensitive files"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        for file_path in self.SENSITIVE_FILES:
            url = urljoin(base_url, file_path)
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(url, headers=headers, allow_redirects=False) as response:
                    if response.status == 200:
                        body = await response.text()
                        content_type = response.headers.get('Content-Type', '')
                        
                        # Determine severity based on file type
                        severity, description = self._categorize_file(file_path, body)
                        
                        if severity:
                            result = ScanResult(
                                id=f"INFODIS-FILE-{len(self.results)+1}",
                                category="A05:2021 - Security Misconfiguration",
                                severity=severity,
                                title=f"Sensitive File Exposed: {file_path}",
                                description=description,
                                url=url,
                                method="GET",
                                evidence=f"Status: 200, Content-Type: {content_type}",
                                remediation="Remove or restrict access to sensitive files. Use proper web server configuration.",
                                cwe_id="CWE-538",
                                poc=f"curl '{url}'",
                                reasoning=f"Sensitive file {file_path} is publicly accessible"
                            )
                            self.results.append(result)
                            
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
    
    def _categorize_file(self, file_path: str, content: str) -> tuple:
        """Categorize file and return severity"""
        # Critical files
        if any(x in file_path for x in ['.env', 'credentials', 'secrets', 'password']):
            if any(x in content.lower() for x in ['password', 'secret', 'key', 'token']):
                return 'critical', f"Credentials file exposed containing secrets"
        
        # Git exposure
        if '.git' in file_path:
            return 'high', "Git repository exposed - source code can be reconstructed"
        
        # Backup files
        if any(x in file_path for x in ['.sql', '.bak', '.backup', '.zip', '.tar']):
            return 'high', "Backup file exposed - may contain sensitive data"
        
        # Config files
        if any(x in file_path for x in ['config', 'settings', 'appsettings']):
            return 'medium', "Configuration file exposed - may reveal internal settings"
        
        # API documentation
        if any(x in file_path for x in ['swagger', 'openapi', 'api-docs']):
            return 'low', "API documentation exposed - reveals API structure"
        
        # Package files
        if any(x in file_path for x in ['package.json', 'composer.json', 'requirements.txt']):
            return 'low', "Dependency file exposed - reveals technology stack"
        
        # Debug/Admin
        if any(x in file_path for x in ['phpinfo', 'debug', 'admin', 'actuator']):
            return 'high', "Debug/Admin endpoint exposed"
        
        return None, None
    
    async def _check_headers(self, session: aiohttp.ClientSession, base_url: str):
        """Check response headers for information disclosure"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(base_url, headers=headers) as response:
                # Check for revealing headers
                revealing_headers = {
                    'Server': 'Server Version',
                    'X-Powered-By': 'Technology Stack',
                    'X-AspNet-Version': 'ASP.NET Version',
                    'X-AspNetMvc-Version': 'ASP.NET MVC Version',
                    'X-Runtime': 'Runtime Information',
                    'X-Version': 'Application Version',
                    'X-Debug': 'Debug Mode',
                }
                
                for header_name, disclosure_type in revealing_headers.items():
                    if header_name in response.headers:
                        value = response.headers[header_name]
                        
                        result = ScanResult(
                            id=f"INFODIS-HEADER-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity="low",
                            title=f"Information Disclosure: {disclosure_type}",
                            description=f"Response header {header_name} reveals {disclosure_type}",
                            url=base_url,
                            method="GET",
                            parameter=header_name,
                            evidence=f"{header_name}: {value}",
                            remediation=f"Remove or suppress the {header_name} header in production.",
                            cwe_id="CWE-200",
                            reasoning=f"Header {header_name} reveals internal information"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Header check error: {e}")
    
    async def _check_patterns(self, session: aiohttp.ClientSession, base_url: str):
        """Trigger and check for error patterns"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        # URLs designed to trigger errors
        error_urls = [
            f"{base_url}/'",  # SQL-like
            f"{base_url}/<script>",  # XSS-like
            f"{base_url}/../../../etc/passwd",  # Path traversal
            f"{base_url}/%00",  # Null byte
            f"{base_url}/{{{{7*7}}}}",  # SSTI
            f"{base_url}/?id=-1",  # Negative ID
            f"{base_url}/?debug=1",  # Debug param
            f"{base_url}/?test=<script>alert(1)</script>",  # XSS
        ]
        
        for url in error_urls:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(url, headers=headers) as response:
                    body = await response.text()
                    await self._check_body_patterns(url, body, response.status)
                    
            except Exception as e:
                logger.debug(f"Pattern check error: {e}")
    
    async def _check_body_patterns(self, url: str, body: str, status: int):
        """Check response body for disclosure patterns"""
        for pattern, name, severity in self.DISCLOSURE_PATTERNS:
            # Avoid duplicate findings
            pattern_key = f"{pattern}:{url}"
            if pattern_key in self.checked_patterns:
                continue
            
            matches = re.findall(pattern, body, re.IGNORECASE)
            if matches:
                self.checked_patterns.add(pattern_key)
                
                evidence = matches[0] if isinstance(matches[0], str) else str(matches[0])
                evidence = evidence[:200]  # Truncate
                
                result = ScanResult(
                    id=f"INFODIS-PATTERN-{len(self.results)+1}",
                    category="A05:2021 - Security Misconfiguration",
                    severity=severity,
                    title=f"Information Disclosure: {name}",
                    description=f"Response contains {name} which reveals sensitive information.",
                    url=url,
                    method="GET",
                    evidence=evidence,
                    remediation="Configure proper error handling. Don't expose internal details in production.",
                    cwe_id="CWE-200",
                    reasoning=f"Pattern for {name} found in response"
                )
                self.results.append(result)
    
    async def _analyze_response(self, session: aiohttp.ClientSession, url: str):
        """Analyze a specific URL response for disclosure"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url, headers=headers) as response:
                body = await response.text()
                
                # Check for patterns
                await self._check_body_patterns(url, body, response.status)
                
                # Check for HTML comments with sensitive info
                comments = re.findall(r'<!--(.*?)-->', body, re.DOTALL)
                for comment in comments:
                    if any(x in comment.lower() for x in ['todo', 'fixme', 'password', 'key', 'secret', 'admin', 'debug']):
                        result = ScanResult(
                            id=f"INFODIS-COMMENT-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity="low",
                            title="Sensitive HTML Comment",
                            description="HTML comment contains potentially sensitive information.",
                            url=url,
                            method="GET",
                            evidence=comment[:200],
                            remediation="Remove sensitive comments before deploying to production.",
                            cwe_id="CWE-615",
                            reasoning="HTML comment contains sensitive keywords"
                        )
                        self.results.append(result)
                        break
                        
        except Exception as e:
            logger.debug(f"Response analysis error: {e}")


class DirectoryListingScanner:
    """
    Scans for Directory Listing vulnerabilities
    OWASP A05:2021 - Security Misconfiguration
    """
    
    # Common directories to check
    DIRECTORIES = [
        '/images/', '/img/', '/uploads/', '/files/', '/documents/',
        '/assets/', '/static/', '/media/', '/content/', '/data/',
        '/backup/', '/backups/', '/temp/', '/tmp/', '/cache/',
        '/logs/', '/log/', '/scripts/', '/js/', '/css/',
        '/includes/', '/inc/', '/lib/', '/libs/', '/modules/',
        '/admin/', '/private/', '/internal/', '/test/', '/dev/',
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
        logger.info("Starting Directory Listing scan...")
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
            
            for directory in self.DIRECTORIES:
                url = urljoin(base_url, directory)
                await self._check_directory(session, url)
        
        logger.info(f"Directory listing scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_directory(self, session: aiohttp.ClientSession, url: str):
        """Check if directory listing is enabled"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    body = await response.text()
                    
                    # Check for directory listing indicators
                    listing_indicators = [
                        'Index of /',
                        'Directory listing for',
                        '<title>Index of',
                        'Parent Directory',
                        '[To Parent Directory]',
                        'Directory Listing',
                        '<h1>Index of',
                    ]
                    
                    if any(ind in body for ind in listing_indicators):
                        # Count files/directories
                        file_count = len(re.findall(r'<a[^>]+href="[^"]+">([^<]+)</a>', body))
                        
                        result = ScanResult(
                            id=f"DIRLIST-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity="medium",
                            title=f"Directory Listing Enabled: {url}",
                            description=f"Directory listing is enabled, exposing {file_count} items.",
                            url=url,
                            method="GET",
                            evidence="Directory listing page detected",
                            remediation="Disable directory listing in web server configuration.",
                            cwe_id="CWE-548",
                            poc=f"Navigate to {url}",
                            reasoning="Directory contents are publicly browsable"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Directory check error: {e}")
