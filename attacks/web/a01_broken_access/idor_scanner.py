"""
Jarwis AGI Pen Test - Advanced IDOR Scanner
Detects Insecure Direct Object Reference vulnerabilities (A01:2021 - Broken Access Control)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
import uuid
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
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


class IDORScanner:
    """
    Advanced scanner for Insecure Direct Object Reference vulnerabilities
    OWASP A01:2021 - Broken Access Control
    CWE-639: Authorization Bypass Through User-Controlled Key
    
    Attack vectors:
    - Numeric ID manipulation (increment/decrement)
    - UUID/GUID manipulation
    - Encoded ID manipulation (base64, hex)
    - Hashed ID prediction
    - Filename manipulation
    - Parameter pollution for IDOR
    - Path-based IDOR
    - JSON body IDOR
    """
    
    # Common IDOR-prone parameters
    IDOR_PARAMS = [
        'id', 'user_id', 'userId', 'uid', 'account_id', 'accountId',
        'order_id', 'orderId', 'invoice_id', 'invoiceId',
        'file_id', 'fileId', 'doc_id', 'docId', 'document_id',
        'record_id', 'recordId', 'item_id', 'itemId',
        'profile_id', 'profileId', 'customer_id', 'customerId',
        'report_id', 'reportId', 'ticket_id', 'ticketId',
        'transaction_id', 'transactionId', 'payment_id', 'paymentId',
        'message_id', 'messageId', 'thread_id', 'threadId',
        'project_id', 'projectId', 'team_id', 'teamId',
        'org_id', 'orgId', 'organization_id', 'company_id',
        'no', 'num', 'number', 'ref', 'reference', 'key'
    ]
    
    # Common IDOR-prone endpoints
    IDOR_ENDPOINTS = [
        '/api/user/{id}', '/api/users/{id}', '/api/profile/{id}',
        '/api/account/{id}', '/api/order/{id}', '/api/orders/{id}',
        '/api/invoice/{id}', '/api/file/{id}', '/api/document/{id}',
        '/api/report/{id}', '/api/message/{id}', '/api/ticket/{id}',
        '/user/{id}', '/users/{id}', '/profile/{id}', '/account/{id}',
        '/download/{id}', '/files/{id}', '/documents/{id}',
        '/v1/user/{id}', '/v1/users/{id}', '/v2/user/{id}',
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
        self.known_ids: Dict[str, List] = {}  # Store discovered IDs
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers from context for post-login attacks"""
        if hasattr(self.context, 'auth_headers') and self.context.auth_headers:
            return dict(self.context.auth_headers)
        return {}
    
    def _get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies from context for post-login attacks"""
        if hasattr(self.context, 'auth_cookies') and self.context.auth_cookies:
            return dict(self.context.auth_cookies)
        if hasattr(self.context, 'cookies') and self.context.cookies:
            return dict(self.context.cookies)
        return {}
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Advanced IDOR scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        # Get auth configuration for post-login attacks
        auth_headers = self._get_auth_headers()
        auth_cookies = self._get_auth_cookies()
        
        session_kwargs = {
            'connector': connector,
            'timeout': aiohttp.ClientTimeout(total=self.timeout)
        }
        
        if auth_cookies:
            session_kwargs['cookies'] = auth_cookies
            logger.info(f"[IDOR] Using {len(auth_cookies)} auth cookies for authenticated testing")
        if auth_headers:
            session_kwargs['headers'] = auth_headers
            logger.info(f"[IDOR] Using {len(auth_headers)} auth headers for authenticated testing")
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            
            # Test common IDOR endpoints
            for endpoint_pattern in self.IDOR_ENDPOINTS:
                await self._test_idor_endpoint(session, base_url, endpoint_pattern)
            
            # Test discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:50]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    method = endpoint.get('method', 'GET') if isinstance(endpoint, dict) else 'GET'
                    
                    if ep_url:
                        await self._test_url_for_idor(session, ep_url, method)
        
        logger.info(f"Advanced IDOR scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_idor_endpoint(self, session: aiohttp.ClientSession, 
                                   base_url: str, endpoint_pattern: str):
        """Test a potential IDOR endpoint with ID patterns"""
        headers = {
            'User-Agent': 'Mozilla/5.0',
            'Accept': 'application/json, text/html'
        }
        
        # Test with different ID types
        test_ids = [
            # Numeric
            ('1', 'numeric'),
            ('2', 'numeric'),
            ('100', 'numeric'),
            ('1000', 'numeric'),
            
            # UUID
            ('00000000-0000-0000-0000-000000000001', 'uuid'),
            ('00000000-0000-0000-0000-000000000002', 'uuid'),
            
            # Base64 encoded
            ('MQ==', 'base64'),  # "1"
            ('Mg==', 'base64'),  # "2"
            
            # Hex
            ('0x1', 'hex'),
            ('0x2', 'hex'),
        ]
        
        baseline_response = None
        baseline_id = None
        
        for test_id, id_type in test_ids:
            url = urljoin(base_url, endpoint_pattern.replace('{id}', test_id))
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        if baseline_response is None:
                            baseline_response = body
                            baseline_id = test_id
                        else:
                            # Compare responses
                            if body != baseline_response and len(body) > 50:
                                # Different content - potential IDOR
                                result = ScanResult(
                                    id=f"IDOR-ENUM-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="high",
                                    title=f"IDOR - Object Enumeration ({id_type})",
                                    description=f"Different responses for IDs {baseline_id} and {test_id} indicate accessible objects.",
                                    url=url,
                                    method="GET",
                                    parameter="id",
                                    evidence=f"Response sizes: {len(baseline_response)} vs {len(body)}",
                                    remediation="Implement authorization checks. Use indirect references.",
                                    cwe_id="CWE-639",
                                    poc=f"Access {url} with different IDs",
                                    reasoning="Different objects accessible by changing ID"
                                )
                                self.results.append(result)
                                return
                                
            except Exception as e:
                logger.debug(f"IDOR endpoint test error: {e}")
    
    async def _test_url_for_idor(self, session: aiohttp.ClientSession, url: str, method: str):
        """Test a specific URL for IDOR vulnerabilities"""
        parsed = urlparse(url)
        
        # Check URL path for IDs
        path_ids = self._extract_ids_from_path(parsed.path)
        if path_ids:
            await self._test_path_idor(session, url, path_ids, method)
        
        # Check query parameters for IDs
        query_params = parse_qs(parsed.query)
        for param, values in query_params.items():
            if param.lower() in [p.lower() for p in self.IDOR_PARAMS]:
                for value in values:
                    if self._looks_like_id(value):
                        await self._test_param_idor(session, url, param, value, method)
    
    def _extract_ids_from_path(self, path: str) -> List[tuple]:
        """Extract potential IDs from URL path"""
        ids = []
        parts = path.split('/')
        
        for i, part in enumerate(parts):
            if self._looks_like_id(part):
                ids.append((i, part))
        
        return ids
    
    def _looks_like_id(self, value: str) -> bool:
        """Check if a value looks like an ID"""
        if not value:
            return False
        
        # Numeric
        if value.isdigit():
            return True
        
        # UUID
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if re.match(uuid_pattern, value.lower()):
            return True
        
        # Hex (MongoDB ObjectId, etc.)
        if re.match(r'^[0-9a-f]{24}$', value.lower()):
            return True
        
        # Base64 encoded
        if re.match(r'^[A-Za-z0-9+/]+=*$', value) and len(value) <= 50:
            return True
        
        # Short alphanumeric (could be encoded ID)
        if re.match(r'^[A-Za-z0-9]{6,20}$', value):
            return True
        
        return False
    
    def _generate_alternative_ids(self, original_id: str) -> List[tuple]:
        """Generate alternative IDs to test"""
        alternatives = []
        
        # Numeric manipulation
        if original_id.isdigit():
            num = int(original_id)
            alternatives.extend([
                (str(num + 1), 'increment'),
                (str(num - 1), 'decrement'),
                (str(num + 10), 'increment_10'),
                ('1', 'first'),
                ('0', 'zero'),
            ])
        
        # UUID manipulation
        uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
        if re.match(uuid_pattern, original_id.lower()):
            # Try incrementing last part
            parts = original_id.split('-')
            try:
                last_num = int(parts[-1], 16)
                new_last = format(last_num + 1, '012x')
                alternatives.append(('-'.join(parts[:-1] + [new_last]), 'uuid_increment'))
            except ValueError:
                pass
            
            # Try common test UUIDs
            alternatives.extend([
                ('00000000-0000-0000-0000-000000000001', 'uuid_first'),
                ('00000000-0000-0000-0000-000000000000', 'uuid_zero'),
            ])
        
        # MongoDB ObjectId manipulation
        if re.match(r'^[0-9a-f]{24}$', original_id.lower()):
            # Try incrementing
            try:
                num = int(original_id, 16)
                alternatives.append((format(num + 1, '024x'), 'objectid_increment'))
            except ValueError:
                pass
        
        # Base64 manipulation
        if re.match(r'^[A-Za-z0-9+/]+=*$', original_id):
            try:
                import base64
                decoded = base64.b64decode(original_id).decode()
                if decoded.isdigit():
                    alternatives.append((
                        base64.b64encode(str(int(decoded) + 1).encode()).decode(),
                        'base64_increment'
                    ))
            except Exception:
                pass
        
        return alternatives
    
    async def _test_path_idor(self, session: aiohttp.ClientSession, 
                              url: str, path_ids: List[tuple], method: str):
        """Test IDOR in URL path"""
        parsed = urlparse(url)
        path_parts = parsed.path.split('/')
        
        for idx, original_id in path_ids:
            alternatives = self._generate_alternative_ids(original_id)
            
            for alt_id, manipulation_type in alternatives:
                # Replace ID in path
                new_parts = path_parts.copy()
                new_parts[idx] = alt_id
                new_path = '/'.join(new_parts)
                
                new_url = urlunparse((
                    parsed.scheme, parsed.netloc, new_path,
                    parsed.params, parsed.query, parsed.fragment
                ))
                
                try:
                    await asyncio.sleep(1 / self.rate_limit)
                    
                    headers = {'User-Agent': 'Mozilla/5.0'}
                    
                    async with session.get(new_url, headers=headers) as response:
                        if response.status == 200:
                            body = await response.text()
                            
                            # Check for sensitive data indicators
                            sensitive_indicators = [
                                'email', 'phone', 'address', 'name', 'balance',
                                'credit', 'card', 'ssn', 'password', 'secret'
                            ]
                            
                            if any(s in body.lower() for s in sensitive_indicators):
                                result = ScanResult(
                                    id=f"IDOR-PATH-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="critical",
                                    title=f"IDOR - Path Manipulation ({manipulation_type})",
                                    description=f"Changing ID in path from '{original_id}' to '{alt_id}' reveals other user's data.",
                                    url=new_url,
                                    method=method,
                                    parameter=f"path[{idx}]",
                                    evidence=f"Sensitive data found in response to modified ID",
                                    remediation="Verify user owns the requested resource before returning data.",
                                    cwe_id="CWE-639",
                                    poc=f"Original: {url}\nModified: {new_url}",
                                    reasoning=f"Path ID manipulation ({manipulation_type}) returned sensitive data"
                                )
                                self.results.append(result)
                                return
                                
                except Exception as e:
                    logger.debug(f"Path IDOR test error: {e}")
    
    async def _test_param_idor(self, session: aiohttp.ClientSession,
                               url: str, param: str, original_value: str, method: str):
        """Test IDOR in query/body parameters"""
        alternatives = self._generate_alternative_ids(original_value)
        
        parsed = urlparse(url)
        
        for alt_value, manipulation_type in alternatives:
            # Modify query parameter
            query_params = parse_qs(parsed.query)
            query_params[param] = [alt_value]
            new_query = urlencode(query_params, doseq=True)
            
            new_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                headers = {'User-Agent': 'Mozilla/5.0'}
                
                async with session.get(new_url, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        # Compare with original
                        original_response = await self._get_original_response(session, url)
                        
                        if body != original_response and len(body) > 100:
                            result = ScanResult(
                                id=f"IDOR-PARAM-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="high",
                                title=f"IDOR - Parameter Manipulation ({param})",
                                description=f"Changing '{param}' from '{original_value}' to '{alt_value}' returns different data.",
                                url=new_url,
                                method=method,
                                parameter=param,
                                evidence=f"Different response for different ID values",
                                remediation="Implement proper authorization checks on resource access.",
                                cwe_id="CWE-639",
                                poc=f"Modify {param}={original_value} to {param}={alt_value}",
                                reasoning=f"Parameter manipulation ({manipulation_type}) returned different object"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Param IDOR test error: {e}")
    
    async def _get_original_response(self, session: aiohttp.ClientSession, url: str) -> str:
        """Get original response for comparison"""
        try:
            headers = {'User-Agent': 'Mozilla/5.0'}
            async with session.get(url, headers=headers) as response:
                return await response.text()
        except Exception:
            return ""


class MassAssignmentScanner:
    """
    Scans for Mass Assignment vulnerabilities
    OWASP A01:2021 - Broken Access Control
    
    Attack vectors:
    - Adding admin/role fields
    - Modifying protected attributes
    - Updating other users' data
    """
    
    # Dangerous fields to inject
    DANGEROUS_FIELDS = [
        ('role', 'admin'),
        ('isAdmin', True),
        ('is_admin', True),
        ('admin', True),
        ('verified', True),
        ('is_verified', True),
        ('approved', True),
        ('active', True),
        ('balance', 99999),
        ('credits', 99999),
        ('user_id', 1),
        ('userId', 1),
        ('account_type', 'premium'),
        ('accountType', 'enterprise'),
        ('permissions', ['admin', 'superuser']),
        ('access_level', 999),
        ('accessLevel', 'admin'),
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
        logger.info("Starting Mass Assignment scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Common update endpoints
        update_endpoints = [
            '/api/user', '/api/users', '/api/profile', '/api/account',
            '/api/settings', '/api/me', '/api/update', '/api/register',
            '/user/update', '/profile/update', '/account/settings'
        ]
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for endpoint in update_endpoints:
                url = urljoin(base_url, endpoint)
                await self._test_mass_assignment(session, url)
        
        logger.info(f"Mass assignment scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_mass_assignment(self, session: aiohttp.ClientSession, url: str):
        """Test for mass assignment vulnerability"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Base payload (legitimate fields)
        base_payload = {
            'name': 'TestUser',
            'email': 'test@example.com'
        }
        
        # Test each dangerous field
        for field_name, field_value in self.DANGEROUS_FIELDS:
            test_payload = {**base_payload, field_name: field_value}
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Try PUT/PATCH/POST
                for method_func, method_name in [
                    (session.put, 'PUT'),
                    (session.patch, 'PATCH'),
                    (session.post, 'POST')
                ]:
                    async with method_func(url, json=test_payload, headers=headers) as response:
                        if response.status in [200, 201]:
                            body = await response.text()
                            
                            # Check if the field was accepted
                            if field_name in body or str(field_value) in body:
                                result = ScanResult(
                                    id=f"MASSASSIGN-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="critical",
                                    title=f"Mass Assignment - {field_name}",
                                    description=f"Server accepts and processes '{field_name}' field which should be protected.",
                                    url=url,
                                    method=method_name,
                                    parameter=field_name,
                                    evidence=f"Field '{field_name}' appears in response",
                                    remediation="Whitelist allowed fields. Never bind user input directly to models.",
                                    cwe_id="CWE-915",
                                    poc=json.dumps(test_payload),
                                    reasoning="Protected field was accepted in request"
                                )
                                self.results.append(result)
                                return
                                
            except Exception as e:
                logger.debug(f"Mass assignment test error: {e}")
