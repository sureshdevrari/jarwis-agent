"""
Jarwis AGI Pen Test - Post-Login IDOR Scanner
Detects IDOR vulnerabilities in authenticated contexts
OWASP A01:2021 - Broken Access Control
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
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


class PostLoginIDORScanner:
    """
    Authenticated IDOR (Insecure Direct Object Reference) Scanner
    OWASP A01:2021 - Broken Access Control
    
    Requires authenticated session to test access control
    across different user contexts.
    """
    
    # ID patterns to detect and manipulate
    ID_PATTERNS = [
        r'/(\d+)(?:/|$|\?)',  # Numeric IDs in path
        r'[?&]id=(\d+)',  # id= parameter
        r'[?&]user_?id=(\d+)',  # user_id parameter
        r'[?&]order_?id=(\d+)',  # order_id parameter
        r'[?&]account_?id=(\d+)',  # account_id parameter
        r'[?&]doc(?:ument)?_?id=(\d+)',  # document_id parameter
        r'[?&]file_?id=(\d+)',  # file_id parameter
        r'/users?/(\d+)',  # /user/123
        r'/accounts?/(\d+)',  # /account/123
        r'/orders?/(\d+)',  # /order/123
        r'/invoices?/(\d+)',  # /invoice/123
        r'/profiles?/(\d+)',  # /profile/123
    ]
    
    # GUID pattern
    GUID_PATTERN = r'[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}'
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        # Get auth cookies/tokens from context
        self.auth_headers = getattr(context, 'auth_headers', {})
        self.auth_cookies = getattr(context, 'auth_cookies', {})
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Post-Login IDOR scan...")
        self.results = []
        
        if not self.auth_headers and not self.auth_cookies:
            logger.warning("No authentication context available for IDOR scan")
            return self.results
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        # Build cookies string
        cookies = '; '.join([f'{k}={v}' for k, v in self.auth_cookies.items()])
        
        headers = {
            'User-Agent': 'Mozilla/5.0 Jarwis-Scanner/1.0',
            'Cookie': cookies,
            **self.auth_headers
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=headers
        ) as session:
            
            # Test discovered endpoints
            endpoints = getattr(self.context, 'endpoints', [])
            
            for endpoint in endpoints[:30]:
                ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                
                if ep_url:
                    await self._test_idor(session, ep_url)
        
        logger.info(f"Post-Login IDOR scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_idor(self, session: aiohttp.ClientSession, url: str):
        """Test for IDOR vulnerability by manipulating IDs"""
        
        # First, get the original response as baseline
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(url) as response:
                original_status = response.status
                original_body = await response.text()
                original_len = len(original_body)
        except Exception as e:
            logger.debug(f"IDOR baseline error: {e}")
            return
        
        # Only test endpoints that return data (200)
        if original_status != 200:
            return
        
        # Find IDs in the URL
        for pattern in self.ID_PATTERNS:
            matches = re.findall(pattern, url)
            
            for match in matches:
                original_id = match
                
                # Generate test IDs
                test_ids = self._generate_test_ids(original_id)
                
                for test_id in test_ids:
                    try:
                        await asyncio.sleep(1 / self.rate_limit)
                        
                        # Replace ID in URL
                        test_url = re.sub(
                            pattern.replace(r'(\d+)', original_id),
                            pattern.replace(r'(\d+)', test_id),
                            url
                        )
                        
                        # Simpler replacement
                        test_url = url.replace(original_id, test_id)
                        
                        async with session.get(test_url) as response:
                            test_status = response.status
                            test_body = await response.text()
                            test_len = len(test_body)
                        
                        # Check for IDOR indicators
                        if self._is_idor_vulnerable(
                            original_status, test_status,
                            original_body, test_body,
                            original_len, test_len
                        ):
                            result = ScanResult(
                                id=f"POSTLOGIN-IDOR-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="high",
                                title="IDOR - Unauthorized Resource Access",
                                description="Authenticated user can access another user's resources by changing ID.",
                                url=url,
                                method="GET",
                                parameter=f"ID: {original_id} -> {test_id}",
                                evidence=f"Different resource accessed with ID {test_id}",
                                poc=f"Changed {original_id} to {test_id}",
                                remediation="Implement proper authorization checks. Verify user owns requested resource.",
                                cwe_id="CWE-639",
                                reasoning="Successfully accessed different resource by manipulating ID"
                            )
                            self.results.append(result)
                            return  # Found IDOR, stop testing this endpoint
                            
                    except Exception as e:
                        logger.debug(f"IDOR test error: {e}")
    
    def _generate_test_ids(self, original_id: str) -> List[str]:
        """Generate test IDs to probe for IDOR"""
        test_ids = []
        
        try:
            num_id = int(original_id)
            # Adjacent IDs
            test_ids.extend([str(num_id - 1), str(num_id + 1)])
            # Common IDs
            test_ids.extend(['1', '2', '0', str(num_id + 100)])
        except ValueError:
            # Non-numeric ID (GUID, etc.)
            test_ids.append('00000000-0000-0000-0000-000000000001')
        
        return test_ids
    
    def _is_idor_vulnerable(
        self, orig_status, test_status,
        orig_body, test_body,
        orig_len, test_len
    ) -> bool:
        """Determine if response indicates IDOR vulnerability"""
        
        # Both 200 but different content = likely IDOR
        if orig_status == 200 and test_status == 200:
            # Check if content is different (different user's data)
            if orig_body != test_body and test_len > 100:
                # Make sure it's not just a generic page
                if abs(orig_len - test_len) > 50:
                    return True
        
        return False


class PostLoginPrivilegeEscalation:
    """
    Privilege Escalation Scanner for authenticated sessions
    OWASP A01:2021 - Broken Access Control
    
    Tests for vertical privilege escalation (user -> admin)
    """
    
    # Admin endpoints to probe
    ADMIN_ENDPOINTS = [
        '/admin', '/admin/', '/administrator', '/admin/dashboard',
        '/admin/users', '/admin/settings', '/admin/config',
        '/manage', '/management', '/internal', '/dashboard/admin',
        '/api/admin', '/api/v1/admin', '/api/admin/users',
        '/api/users/all', '/api/settings', '/api/config',
    ]
    
    # Privilege escalation parameters
    PRIV_ESC_PARAMS = {
        'role': ['admin', 'administrator', 'superuser', 'root'],
        'is_admin': ['true', '1', 'yes'],
        'admin': ['true', '1', 'yes'],
        'permission': ['admin', 'all', '*'],
        'access_level': ['admin', 'full', '10', '100'],
        'user_type': ['admin', 'superuser', 'staff'],
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
        self.auth_headers = getattr(context, 'auth_headers', {})
        self.auth_cookies = getattr(context, 'auth_cookies', {})
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Privilege Escalation scan...")
        self.results = []
        
        if not self.auth_headers and not self.auth_cookies:
            logger.warning("No authentication context available")
            return self.results
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        cookies = '; '.join([f'{k}={v}' for k, v in self.auth_cookies.items()])
        
        headers = {
            'User-Agent': 'Mozilla/5.0 Jarwis-Scanner/1.0',
            'Cookie': cookies,
            **self.auth_headers
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=headers
        ) as session:
            
            # Test admin endpoints
            await self._test_admin_endpoints(session, base_url)
            
            # Test privilege escalation via parameters
            await self._test_priv_esc_params(session, base_url)
        
        logger.info(f"Privilege Escalation scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_admin_endpoints(self, session: aiohttp.ClientSession, base_url: str):
        """Test if normal user can access admin endpoints"""
        
        for endpoint in self.ADMIN_ENDPOINTS:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                url = urljoin(base_url, endpoint)
                
                async with session.get(url) as response:
                    status = response.status
                    body = await response.text()
                    
                    # Check for successful admin access
                    if status == 200:
                        admin_indicators = [
                            'dashboard', 'admin panel', 'user management',
                            'settings', 'configuration', 'edit user', 'delete user'
                        ]
                        
                        if any(ind.lower() in body.lower() for ind in admin_indicators):
                            result = ScanResult(
                                id=f"PRIVESC-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="critical",
                                title="Privilege Escalation - Admin Access",
                                description=f"Normal user accessed admin endpoint: {endpoint}",
                                url=url,
                                method="GET",
                                evidence="Admin indicators found in response",
                                remediation="Implement role-based access control. Verify user privileges.",
                                cwe_id="CWE-269",
                                reasoning="Authenticated user accessed admin-only endpoint"
                            )
                            self.results.append(result)
                            
            except Exception as e:
                logger.debug(f"Admin endpoint test error: {e}")
    
    async def _test_priv_esc_params(self, session: aiohttp.ClientSession, base_url: str):
        """Test privilege escalation via parameter manipulation"""
        
        endpoints = getattr(self.context, 'endpoints', [])
        
        for endpoint in endpoints[:10]:
            ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
            
            if not ep_url or 'profile' not in ep_url.lower() and 'user' not in ep_url.lower():
                continue
            
            for param_name, values in self.PRIV_ESC_PARAMS.items():
                for value in values:
                    try:
                        await asyncio.sleep(1 / self.rate_limit)
                        
                        # Test via POST
                        data = {param_name: value}
                        
                        async with session.post(ep_url, data=data) as response:
                            status = response.status
                            body = await response.text()
                            
                            # Check for privilege escalation indicators
                            if status in [200, 302]:
                                success_indicators = [
                                    'updated', 'success', 'saved', 'admin'
                                ]
                                
                                if any(ind in body.lower() for ind in success_indicators):
                                    result = ScanResult(
                                        id=f"PRIVESC-PARAM-{len(self.results)+1}",
                                        category="A01:2021 - Broken Access Control",
                                        severity="critical",
                                        title="Privilege Escalation via Parameter",
                                        description=f"Role escalation possible via {param_name}={value}",
                                        url=ep_url,
                                        method="POST",
                                        parameter=f"{param_name}={value}",
                                        evidence="Success response with admin parameter",
                                        remediation="Ignore client-provided role parameters. Server-side authorization.",
                                        cwe_id="CWE-269",
                                        reasoning="Potential privilege escalation via mass assignment"
                                    )
                                    self.results.append(result)
                                    
                    except Exception as e:
                        logger.debug(f"Priv esc param test error: {e}")


class PostLoginDataExfiltration:
    """
    Data Exfiltration Scanner for authenticated sessions
    OWASP A01:2021 - Broken Access Control
    
    Tests for bulk data export and excessive data exposure
    """
    
    # Endpoints that might expose bulk data
    EXPORT_ENDPOINTS = [
        '/export', '/download', '/export/csv', '/export/pdf',
        '/api/export', '/api/download', '/backup', '/dump',
        '/users/export', '/data/export', '/report/export',
        '/api/users', '/api/all', '/api/list',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)  # Longer timeout for exports
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.auth_headers = getattr(context, 'auth_headers', {})
        self.auth_cookies = getattr(context, 'auth_cookies', {})
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Data Exfiltration scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        cookies = '; '.join([f'{k}={v}' for k, v in self.auth_cookies.items()])
        
        headers = {
            'User-Agent': 'Mozilla/5.0 Jarwis-Scanner/1.0',
            'Cookie': cookies,
            **self.auth_headers
        }
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout),
            headers=headers
        ) as session:
            
            # Test export endpoints
            await self._test_export_endpoints(session, base_url)
            
            # Test API pagination abuse
            await self._test_pagination_abuse(session, base_url)
        
        logger.info(f"Data Exfiltration scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_export_endpoints(self, session: aiohttp.ClientSession, base_url: str):
        """Test data export endpoints"""
        
        for endpoint in self.EXPORT_ENDPOINTS:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                url = urljoin(base_url, endpoint)
                
                async with session.get(url) as response:
                    status = response.status
                    content_type = response.headers.get('Content-Type', '')
                    content_disp = response.headers.get('Content-Disposition', '')
                    body = await response.read()
                    
                    # Check for data export
                    if status == 200 and len(body) > 1000:
                        export_types = ['csv', 'json', 'xml', 'xlsx', 'pdf']
                        
                        if any(t in content_type.lower() or t in content_disp.lower() for t in export_types):
                            result = ScanResult(
                                id=f"DATAEXFIL-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="high",
                                title="Bulk Data Export Accessible",
                                description=f"Export endpoint accessible: {endpoint}",
                                url=url,
                                method="GET",
                                evidence=f"Export data size: {len(body)} bytes",
                                remediation="Limit export to user's own data. Implement rate limiting.",
                                cwe_id="CWE-359",
                                reasoning="Bulk data export may expose other users' data"
                            )
                            self.results.append(result)
                            
            except Exception as e:
                logger.debug(f"Export endpoint test error: {e}")
    
    async def _test_pagination_abuse(self, session: aiohttp.ClientSession, base_url: str):
        """Test for pagination abuse to extract all data"""
        
        endpoints = getattr(self.context, 'endpoints', [])
        
        for endpoint in endpoints[:10]:
            ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
            
            if not ep_url or 'api' not in ep_url.lower():
                continue
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Try to get all records
                test_params = [
                    {'limit': '10000', 'offset': '0'},
                    {'page_size': '10000', 'page': '1'},
                    {'per_page': '10000'},
                    {'count': '10000'},
                ]
                
                for params in test_params:
                    url = f"{ep_url}?{urlencode(params)}"
                    
                    async with session.get(url) as response:
                        if response.status == 200:
                            body = await response.text()
                            
                            # Check for large response (potential data leak)
                            if len(body) > 50000:
                                result = ScanResult(
                                    id=f"PAGINATION-ABUSE-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="medium",
                                    title="Pagination Bypass - Bulk Data Access",
                                    description="Large pagination limit accepted, exposing bulk data.",
                                    url=url,
                                    method="GET",
                                    parameter=str(params),
                                    evidence=f"Response size: {len(body)} bytes",
                                    remediation="Enforce maximum page size. Rate limit bulk requests.",
                                    cwe_id="CWE-200",
                                    reasoning="Unrestricted pagination allows data enumeration"
                                )
                                self.results.append(result)
                                return
                                
            except Exception as e:
                logger.debug(f"Pagination abuse test error: {e}")
