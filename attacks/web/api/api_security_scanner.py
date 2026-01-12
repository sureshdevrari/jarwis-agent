"""
Jarwis AGI Pen Test - API Security Scanner
Detects API-specific vulnerabilities (A02:2021 - Cryptographic Failures, A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
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


class APISecurityScanner:
    """
    Scans for API security vulnerabilities
    OWASP API Security Top 10
    
    Attack vectors:
    - Broken Object Level Authorization (BOLA)
    - Broken Authentication
    - Excessive Data Exposure
    - Lack of Resources & Rate Limiting
    - Broken Function Level Authorization
    - Mass Assignment
    - Security Misconfiguration
    - Injection
    - Improper Assets Management
    - Insufficient Logging & Monitoring
    """
    
    # Common API prefixes and versioning patterns
    API_PATHS = [
        '/api', '/api/v1', '/api/v2', '/api/v3',
        '/v1', '/v2', '/v3', '/rest', '/graphql',
        '/api/rest', '/json', '/data',
    ]
    
    # Dangerous HTTP methods
    DANGEROUS_METHODS = ['PUT', 'DELETE', 'PATCH', 'OPTIONS', 'TRACE']
    
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
        logger.info("Starting API Security scan...")
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
            
            # Test API versions
            await self._test_api_versioning(session, base_url)
            
            # Test HTTP methods
            await self._test_http_methods(session, base_url)
            
            # Test excessive data exposure
            await self._test_data_exposure(session, base_url)
            
            # Test rate limiting
            await self._test_rate_limiting(session, base_url)
            
            # Test content type security
            await self._test_content_type(session, base_url)
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if url and '/api' in url.lower():
                        await self._test_api_endpoint(session, url)
        
        logger.info(f"API security scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_api_versioning(self, session: aiohttp.ClientSession, base_url: str):
        """Test for old/deprecated API versions"""
        headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
        
        # Check for version patterns
        version_patterns = [
            ('/api/v0/', '/api/v1/'),
            ('/api/v1/', '/api/v2/'),
            ('/api/v2/', '/api/v3/'),
            ('/v1/', '/v2/'),
            ('/api/beta/', '/api/v1/'),
            ('/api/dev/', '/api/v1/'),
            ('/api/test/', '/api/v1/'),
            ('/api/internal/', '/api/v1/'),
        ]
        
        for old_version, new_version in version_patterns:
            old_url = urljoin(base_url, old_version)
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(old_url, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        # Check if it's a valid API response
                        try:
                            data = json.loads(body)
                            if isinstance(data, (dict, list)):
                                result = ScanResult(
                                    id=f"API-VERSION-{len(self.results)+1}",
                                    category="A09:2021 - Security Logging Failures",
                                    severity="medium",
                                    title=f"Deprecated API Version Active: {old_version}",
                                    description="Old API version is still accessible and may lack security updates.",
                                    url=old_url,
                                    method="GET",
                                    evidence=f"API {old_version} returns valid response",
                                    remediation="Disable deprecated API versions. Force migration to latest.",
                                    cwe_id="CWE-1104",
                                    reasoning="Deprecated API version is still functional"
                                )
                                self.results.append(result)
                        except json.JSONDecodeError:
                            pass
                            
            except Exception as e:
                logger.debug(f"API versioning test error: {e}")
    
    async def _test_http_methods(self, session: aiohttp.ClientSession, base_url: str):
        """Test for dangerous HTTP methods"""
        
        test_endpoints = [base_url]
        for path in self.API_PATHS:
            test_endpoints.append(urljoin(base_url, path))
        
        for url in test_endpoints:
            # Test OPTIONS to discover allowed methods
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.options(url) as response:
                    allow_header = response.headers.get('Allow', '')
                    access_control = response.headers.get('Access-Control-Allow-Methods', '')
                    
                    allowed_methods = set()
                    if allow_header:
                        allowed_methods.update(m.strip().upper() for m in allow_header.split(','))
                    if access_control:
                        allowed_methods.update(m.strip().upper() for m in access_control.split(','))
                    
                    # Check for TRACE method
                    if 'TRACE' in allowed_methods:
                        result = ScanResult(
                            id=f"API-TRACE-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity="low",
                            title="HTTP TRACE Method Enabled",
                            description="TRACE method is enabled which can be used for XST attacks.",
                            url=url,
                            method="OPTIONS",
                            evidence=f"Allowed methods: {', '.join(allowed_methods)}",
                            remediation="Disable TRACE method on web server.",
                            cwe_id="CWE-16",
                            reasoning="TRACE method found in allowed methods"
                        )
                        self.results.append(result)
                    
                    # Check for dangerous methods without auth
                    dangerous_found = [m for m in ['DELETE', 'PUT', 'PATCH'] if m in allowed_methods]
                    if dangerous_found:
                        # Try to use these methods without auth
                        for method in dangerous_found:
                            await self._test_method_auth(session, url, method)
                            
            except Exception as e:
                logger.debug(f"HTTP methods test error: {e}")
    
    async def _test_method_auth(self, session: aiohttp.ClientSession, url: str, method: str):
        """Test if dangerous method requires authentication"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            # Try method without authentication
            if method == 'DELETE':
                async with session.delete(url) as response:
                    if response.status not in [401, 403, 405]:
                        result = ScanResult(
                            id=f"API-METHOD-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="high",
                            title=f"Unauthenticated {method} Method Allowed",
                            description=f"HTTP {method} method works without authentication.",
                            url=url,
                            method=method,
                            evidence=f"Status: {response.status}",
                            remediation="Require authentication for all state-changing methods.",
                            cwe_id="CWE-862",
                            reasoning=f"{method} method did not require authentication"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Method auth test error: {e}")
    
    async def _test_data_exposure(self, session: aiohttp.ClientSession, base_url: str):
        """Test for excessive data exposure"""
        headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
        
        # Common endpoints that might expose too much data
        data_endpoints = [
            '/api/users', '/api/user', '/api/me', '/api/profile',
            '/api/accounts', '/api/customers', '/api/orders',
            '/api/admin/users', '/api/internal/users',
        ]
        
        sensitive_fields = [
            'password', 'hash', 'salt', 'secret', 'token', 'api_key',
            'private_key', 'credit_card', 'ssn', 'social_security',
            'bank_account', 'routing_number', 'pin'
        ]
        
        for endpoint in data_endpoints:
            url = urljoin(base_url, endpoint)
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        # Check for sensitive fields
                        exposed_fields = []
                        for field in sensitive_fields:
                            if f'"{field}"' in body.lower() or f"'{field}'" in body.lower():
                                exposed_fields.append(field)
                        
                        if exposed_fields:
                            result = ScanResult(
                                id=f"API-DATA-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="high",
                                title="Excessive Data Exposure",
                                description=f"API exposes sensitive fields: {', '.join(exposed_fields)}",
                                url=url,
                                method="GET",
                                evidence=f"Sensitive fields found: {', '.join(exposed_fields)}",
                                remediation="Implement response filtering. Only return necessary fields.",
                                cwe_id="CWE-200",
                                reasoning="Sensitive fields exposed in API response"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Data exposure test error: {e}")
    
    async def _test_rate_limiting(self, session: aiohttp.ClientSession, base_url: str):
        """Test for lack of rate limiting"""
        headers = {'User-Agent': 'Mozilla/5.0'}
        
        # Test a login-like endpoint
        login_endpoints = [
            '/api/login', '/api/auth', '/api/authenticate',
            '/login', '/auth', '/api/v1/login', '/api/users/login',
        ]
        
        for endpoint in login_endpoints:
            url = urljoin(base_url, endpoint)
            success_count = 0
            
            try:
                # Send many requests quickly
                for i in range(20):
                    async with session.post(
                        url, 
                        json={'email': f'test{i}@example.com', 'password': 'test'},
                        headers=headers
                    ) as response:
                        if response.status != 429:  # 429 = Too Many Requests
                            success_count += 1
                
                if success_count >= 20:
                    result = ScanResult(
                        id=f"API-RATE-{len(self.results)+1}",
                        category="A04:2021 - Insecure Design",
                        severity="medium",
                        title="Missing Rate Limiting on Login Endpoint",
                        description="No rate limiting detected on authentication endpoint.",
                        url=url,
                        method="POST",
                        evidence=f"{success_count}/20 requests succeeded without rate limit",
                        remediation="Implement rate limiting on sensitive endpoints.",
                        cwe_id="CWE-307",
                        reasoning="No 429 responses after 20 rapid requests"
                    )
                    self.results.append(result)
                    return
                    
            except Exception as e:
                logger.debug(f"Rate limiting test error: {e}")
    
    async def _test_content_type(self, session: aiohttp.ClientSession, base_url: str):
        """Test content type security issues"""
        
        api_url = urljoin(base_url, '/api')
        
        # Test for content type confusion
        payloads = [
            # JSON to XML confusion
            {
                'content_type': 'application/xml',
                'body': '<?xml version="1.0"?><root><test>value</test></root>',
            },
            # Form data to JSON confusion
            {
                'content_type': 'application/x-www-form-urlencoded',
                'body': 'test=value&admin=true',
            },
        ]
        
        for payload in payloads:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                headers = {
                    'Content-Type': payload['content_type'],
                    'User-Agent': 'Mozilla/5.0'
                }
                
                async with session.post(api_url, data=payload['body'], headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        if 'error' not in body.lower():
                            result = ScanResult(
                                id=f"API-CONTENT-{len(self.results)+1}",
                                category="A05:2021 - Security Misconfiguration",
                                severity="low",
                                title=f"API Accepts {payload['content_type']}",
                                description="API accepts multiple content types which may lead to parsing confusion.",
                                url=api_url,
                                method="POST",
                                parameter="Content-Type",
                                evidence=f"Accepted: {payload['content_type']}",
                                remediation="Strictly validate Content-Type header.",
                                cwe_id="CWE-436",
                                reasoning="Unexpected content type was processed"
                            )
                            self.results.append(result)
                            
            except Exception as e:
                logger.debug(f"Content type test error: {e}")
    
    async def _test_api_endpoint(self, session: aiohttp.ClientSession, url: str):
        """Test individual API endpoint"""
        headers = {'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'}
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url, headers=headers) as response:
                # Check for stack traces in errors
                if response.status >= 400:
                    body = await response.text()
                    
                    error_patterns = [
                        'stack trace', 'traceback', 'exception',
                        'at line', 'syntax error', 'undefined'
                    ]
                    
                    if any(p in body.lower() for p in error_patterns):
                        result = ScanResult(
                            id=f"API-ERROR-{len(self.results)+1}",
                            category="A05:2021 - Security Misconfiguration",
                            severity="low",
                            title="API Error Information Disclosure",
                            description="API error response contains debug information.",
                            url=url,
                            method="GET",
                            evidence=body[:300],
                            remediation="Return generic error messages in production.",
                            cwe_id="CWE-209",
                            reasoning="Debug information in error response"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"API endpoint test error: {e}")


class NoSQLInjectionScanner:
    """
    Scans for NoSQL Injection vulnerabilities
    OWASP A03:2021 - Injection
    """
    
    # NoSQL injection payloads
    NOSQL_PAYLOADS = [
        # MongoDB operators
        {'$gt': ''},
        {'$ne': ''},
        {'$regex': '.*'},
        {'$where': '1==1'},
        {'$or': [{'a': 1}, {'b': 2}]},
        
        # String-based
        "' || '1'=='1",
        "';return true;var a='",
        "{$gt: ''}",
        "[$ne]=1",
        
        # JSON injection
        '{"$gt": ""}',
        '{"$ne": null}',
        '{"$regex": ".*"}',
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
        logger.info("Starting NoSQL Injection scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Common endpoints
        endpoints = [
            '/api/login', '/api/users', '/api/search', '/api/find',
            '/login', '/search', '/users', '/api/v1/login',
        ]
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for endpoint in endpoints:
                url = urljoin(base_url, endpoint)
                await self._test_nosql_injection(session, url)
            
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:20]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._test_nosql_injection(session, ep_url)
        
        logger.info(f"NoSQL injection scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_nosql_injection(self, session: aiohttp.ClientSession, url: str):
        """Test for NoSQL injection"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Test with JSON payloads
        json_payloads = [
            {'username': {'$gt': ''}, 'password': {'$gt': ''}},
            {'username': {'$ne': ''}, 'password': {'$ne': ''}},
            {'username': {'$regex': '.*'}, 'password': {'$regex': '.*'}},
            {'$where': 'this.username == this.password'},
            {'username': 'admin', 'password': {'$ne': ''}},
        ]
        
        for payload in json_payloads:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.post(url, json=payload, headers=headers) as response:
                    body = await response.text()
                    
                    # Check for success indicators
                    success_indicators = ['token', 'session', 'welcome', 'success', 'logged']
                    
                    if response.status == 200 and any(s in body.lower() for s in success_indicators):
                        result = ScanResult(
                            id=f"NOSQL-{len(self.results)+1}",
                            category="A03:2021 - Injection",
                            severity="critical",
                            title="NoSQL Injection",
                            description="NoSQL injection vulnerability allows authentication bypass.",
                            url=url,
                            method="POST",
                            evidence=f"Login successful with operator: {list(payload.values())[0]}",
                            remediation="Sanitize inputs. Don't pass user input directly to queries.",
                            cwe_id="CWE-943",
                            poc=json.dumps(payload),
                            reasoning="MongoDB operator bypassed authentication"
                        )
                        self.results.append(result)
                        return
                        
            except Exception as e:
                logger.debug(f"NoSQL injection test error: {e}")
