"""
Jarwis AGI Pen Test - API Scanner
API security testing including Swagger, GraphQL, and REST endpoints
"""

import asyncio
import logging
import json
from typing import Dict, List, Optional
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


class APIScanner:
    """Scans APIs for security issues"""
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self.base_url = context.target_url.rstrip('/')
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Will be set by PreLoginAttacks if available
        self.use_js_rendering = config.get('js_rendering', True)
    
    def _get_auth_headers(self) -> Dict:
        """Get authentication headers from context"""
        if hasattr(self.context, 'auth_headers') and self.context.auth_headers:
            return dict(self.context.auth_headers)
        return {}
    
    def _get_auth_cookies(self) -> Dict:
        """Get authentication cookies from context"""
        if hasattr(self.context, 'auth_cookies') and self.context.auth_cookies:
            return dict(self.context.auth_cookies)
        if hasattr(self.context, 'cookies') and self.context.cookies:
            return dict(self.context.cookies)
        return {}
    
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
    
    async def run(self) -> List[ScanResult]:
        """Run all API scans"""
        self.findings = []
        
        # Get auth configuration for post-login attacks
        session_kwargs = {}
        auth_cookies = self._get_auth_cookies()
        auth_headers = self._get_auth_headers()
        if auth_cookies:
            session_kwargs['cookies'] = auth_cookies
        if auth_headers:
            session_kwargs['headers'] = auth_headers
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            # Discover API documentation
            swagger_spec = await self._discover_swagger(session)
            if swagger_spec:
                await self._test_swagger_endpoints(session, swagger_spec)
            
            # Test GraphQL
            await self._test_graphql(session)
            
            # Test rate limiting
            await self._test_rate_limiting(session)
            
            # Test authentication bypass
            await self._test_auth_bypass(session)
        
        return self.findings
    
    async def _discover_swagger(self, session: aiohttp.ClientSession) -> Optional[Dict]:
        """Discover and parse Swagger/OpenAPI specification"""
        paths = self.config.get('swagger_paths', [
            '/swagger.json', '/api/swagger.json', '/openapi.json',
            '/api-docs', '/v1/swagger.json', '/v2/swagger.json',
            '/swagger/v1/swagger.json', '/api/v1/swagger.json'
        ])
        
        for path in paths:
            try:
                url = f"{self.base_url}{path}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        try:
                            spec = json.loads(content)
                            if 'paths' in spec or 'swagger' in spec or 'openapi' in spec:
                                self._add_finding(
                                    category="A05",
                                    severity="info",
                                    title="API Documentation Exposed",
                                    description=f"Swagger/OpenAPI specification found at {path}",
                                    url=url,
                                    method="GET",
                                    evidence=f"API version: {spec.get('info', {}).get('version', 'unknown')}",
                                    remediation="Consider restricting API documentation access in production",
                                    cwe_id="CWE-200"
                                )
                                return spec
                        except json.JSONDecodeError:
                            pass
            except Exception as e:
                logger.debug(f"Swagger discovery failed for {path}: {e}")
        
        return None
    
    async def _test_swagger_endpoints(self, session: aiohttp.ClientSession, spec: Dict):
        """Test endpoints defined in Swagger spec"""
        paths = spec.get('paths', {})
        base_path = spec.get('basePath', '')
        
        for path, methods in list(paths.items())[:20]:  # Limit to 20 endpoints
            for method, details in methods.items():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE']:
                    endpoint_url = f"{self.base_url}{base_path}{path}"
                    
                    # Test without authentication
                    await self._test_endpoint_auth(session, endpoint_url, method.upper(), details)
    
    async def _test_endpoint_auth(self, session: aiohttp.ClientSession, url: str, method: str, details: Dict):
        """Test if endpoint requires authentication"""
        try:
            async with session.request(
                method, url,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=False
            ) as response:
                if response.status == 200:
                    # Check if this should require auth
                    if details.get('security') or any(x in url.lower() for x in ['admin', 'user', 'private', 'internal']):
                        self._add_finding(
                            category="A01",
                            severity="high",
                            title="Unauthenticated API Access",
                            description=f"API endpoint accessible without authentication",
                            url=url,
                            method=method,
                            evidence=f"HTTP {response.status} without credentials",
                            remediation="Implement proper authentication for all sensitive endpoints",
                            cwe_id="CWE-306"
                        )
        except Exception as e:
            logger.debug(f"Auth test failed for {url}: {e}")
    
    async def _test_graphql(self, session: aiohttp.ClientSession):
        """Test GraphQL endpoints"""
        graphql_paths = self.config.get('graphql_paths', ['/graphql', '/api/graphql'])
        
        for path in graphql_paths:
            url = f"{self.base_url}{path}"
            
            # Test introspection
            introspection_query = {
                "query": "{ __schema { types { name fields { name } } } }"
            }
            
            try:
                async with session.post(
                    url,
                    json=introspection_query,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.json()
                        if 'data' in content and '__schema' in content.get('data', {}):
                            self._add_finding(
                                category="A05",
                                severity="medium",
                                title="GraphQL Introspection Enabled",
                                description="GraphQL introspection allows schema discovery",
                                url=url,
                                method="POST",
                                evidence="Introspection query returned schema",
                                remediation="Disable introspection in production",
                                cwe_id="CWE-200"
                            )
                            
                            # Test for common issues
                            await self._test_graphql_issues(session, url)
                            
            except Exception as e:
                logger.debug(f"GraphQL test failed for {url}: {e}")
    
    async def _test_graphql_issues(self, session: aiohttp.ClientSession, url: str):
        """Test for common GraphQL security issues"""
        # Query depth attack
        deep_query = {"query": "{ users { posts { comments { author { posts { title } } } } } }"}
        
        try:
            async with session.post(url, json=deep_query, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                if response.status == 200:
                    self._add_finding(
                        category="A05",
                        severity="low",
                        title="GraphQL Query Depth Not Limited",
                        description="Deep nested queries may be possible",
                        url=url,
                        method="POST",
                        evidence="Deep query executed without error",
                        remediation="Implement query depth limiting",
                        cwe_id="CWE-400"
                    )
        except:
            pass
    
    async def _test_rate_limiting(self, session: aiohttp.ClientSession):
        """Test for missing rate limiting"""
        if not self.config.get('test_rate_limit', True):
            return
        
        # Test first API endpoint
        api_endpoints = [ep for ep in self.context.api_endpoints[:1]]
        
        for endpoint in api_endpoints:
            url = endpoint.get('url', self.base_url)
            
            # Send 50 rapid requests
            success_count = 0
            for _ in range(50):
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as response:
                        if response.status == 200:
                            success_count += 1
                except:
                    break
            
            if success_count >= 50:
                self._add_finding(
                    category="A05",
                    severity="medium",
                    title="Missing Rate Limiting",
                    description="API endpoint accepts unlimited requests",
                    url=url,
                    method="GET",
                    evidence=f"{success_count}/50 requests succeeded",
                    remediation="Implement rate limiting (e.g., 100 requests per minute)",
                    cwe_id="CWE-799"
                )
    
    async def _test_auth_bypass(self, session: aiohttp.ClientSession):
        """Test for authentication bypass techniques"""
        if not self.config.get('test_auth_bypass', True):
            return
        
        # Test common auth bypass headers
        bypass_headers = [
            {'X-Original-URL': '/admin'},
            {'X-Rewrite-URL': '/admin'},
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Custom-IP-Authorization': '127.0.0.1'},
        ]
        
        admin_paths = ['/admin', '/api/admin', '/admin/users']
        
        for path in admin_paths:
            url = f"{self.base_url}{path}"
            
            for headers in bypass_headers:
                try:
                    async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                        if response.status == 200:
                            self._add_finding(
                                category="A01",
                                severity="critical",
                                title="Authentication Bypass via Headers",
                                description=f"Admin endpoint accessible with bypass header",
                                url=url,
                                method="GET",
                                evidence=f"Headers: {headers}",
                                remediation="Properly validate authentication at application level",
                                cwe_id="CWE-287"
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
        finding = ScanResult(id=f"API-{self._finding_id:04d}", **kwargs)
        self.findings.append(finding)
        logger.info(f"Found: {finding.title}")
