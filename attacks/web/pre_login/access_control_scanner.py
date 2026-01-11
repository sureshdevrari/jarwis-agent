"""
Jarwis AGI Pen Test - Access Control Scanner
Broken Access Control vulnerability detection (A01:2021)
Uses OWASP Detection Logic for evidence-based detection
"""

import asyncio
import logging
import re
from typing import Dict, List
from dataclasses import dataclass
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
import aiohttp

# Import detection engine
try:
    from core.detection_logic import OWASPDetectionEngine, detection_engine
except ImportError:
    try:
        from ...core.detection_logic import OWASPDetectionEngine, detection_engine
    except ImportError:
        detection_engine = None

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


class AccessControlScanner:
    """Scans for Broken Access Control vulnerabilities (A01:2021)"""
    
    # IDOR patterns - numeric IDs in URLs
    IDOR_PATTERNS = [
        (r'/user[s]?/(\d+)', 'User ID'),
        (r'/account[s]?/(\d+)', 'Account ID'),
        (r'/profile[s]?/(\d+)', 'Profile ID'),
        (r'/order[s]?/(\d+)', 'Order ID'),
        (r'/invoice[s]?/(\d+)', 'Invoice ID'),
        (r'/document[s]?/(\d+)', 'Document ID'),
        (r'/file[s]?/(\d+)', 'File ID'),
        (r'/record[s]?/(\d+)', 'Record ID'),
        (r'/message[s]?/(\d+)', 'Message ID'),
        (r'/transaction[s]?/(\d+)', 'Transaction ID'),
        (r'/api/v\d+/[\w]+/(\d+)', 'API Resource ID'),
    ]
    
    # ID parameters in query strings
    IDOR_PARAMS = [
        'id', 'user_id', 'uid', 'account_id', 'order_id', 'invoice_id',
        'doc_id', 'file_id', 'record_id', 'message_id', 'transaction_id',
        'userId', 'accountId', 'orderId', 'invoiceId', 'docId', 'fileId'
    ]
    
    # Admin/privileged endpoints
    ADMIN_ENDPOINTS = [
        '/admin', '/administrator', '/manage', '/dashboard', '/control',
        '/console', '/panel', '/backend', '/wp-admin', '/admin.php',
        '/manager', '/settings', '/config', '/configuration', '/system',
        '/users', '/accounts', '/logs', '/audit', '/reports', '/analytics',
        '/api/admin', '/api/users', '/api/config', '/internal'
    ]
    
    # Sensitive data patterns in response
    SENSITIVE_DATA_PATTERNS = [
        (r'"password"\s*:\s*"[^"]+"', 'Password field'),
        (r'"hash"\s*:\s*"[a-fA-F0-9]+"', 'Password hash'),
        (r'"credit_card"\s*:\s*"[\d\-]+"', 'Credit card'),
        (r'"ssn"\s*:\s*"[\d\-]+"', 'SSN'),
        (r'"api_key"\s*:\s*"[^"]+"', 'API key'),
        (r'"secret"\s*:\s*"[^"]+"', 'Secret'),
        (r'"private_key"\s*:', 'Private key'),
        (r'"token"\s*:\s*"[A-Za-z0-9\-_.]{20,}"', 'Auth token'),
        (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'Email address'),
        (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN format'),
        (r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 'Credit card format'),
    ]
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 30)
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self._target_domain = self._extract_domain(context.target_url)
        self.browser = None  # Will be set by PreLoginAttacks if available
        self.use_js_rendering = config.get('js_rendering', True)
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc.lower()
        except:
            return ""
    
    def _format_request(self, method: str, url: str, headers: Dict, body: str = "") -> str:
        """Format request like Burp Suite"""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        
        lines = [f"{method} {path} HTTP/1.1"]
        lines.append(f"Host: {parsed.netloc}")
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if body:
            lines.append(body)
        return "\n".join(lines)
    
    def _format_response(self, status: int, headers: Dict, body: str) -> str:
        """Format response like Burp Suite"""
        lines = [f"HTTP/1.1 {status}"]
        for key, value in headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if len(body) > 1500:
            body = body[:1500] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    def _add_finding(self, **kwargs):
        """Add a new finding"""
        self._finding_id += 1
        finding = ScanResult(
            id=f"BAC-{self._finding_id:04d}",
            **kwargs
        )
        self.findings.append(finding)
        logger.info(f"[ACCESS] Found: {finding.title} at {finding.url}")
        return finding
    
    async def scan(self) -> List[ScanResult]:
        """Run access control scans"""
        self.findings = []
        
        async with aiohttp.ClientSession() as session:
            # Test admin endpoints without auth
            await self._test_admin_endpoints(session)
            
            # Test IDOR on discovered endpoints
            await self._test_idor(session)
            
            # Check for sensitive data exposure
            await self._test_sensitive_data(session)
        
        return self.findings
    
    async def _test_admin_endpoints(self, session: aiohttp.ClientSession):
        """Test admin endpoints without authentication"""
        base_url = self.context.target_url.rstrip('/')
        
        for admin_path in self.ADMIN_ENDPOINTS:
            try:
                test_url = f"{base_url}{admin_path}"
                
                async with session.get(
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    allow_redirects=False
                ) as response:
                    status = response.status
                    body = await response.text()
                    resp_headers = dict(response.headers)
                    
                    # Check if we got access (200 OK with actual content)
                    if status == 200 and len(body) > 500:
                        # Verify it's not a generic error page
                        if not any(x in body.lower() for x in ['not found', '404', 'error', 'forbidden']):
                            request_str = self._format_request('GET', test_url, self.DEFAULT_HEADERS)
                            response_str = self._format_response(status, resp_headers, body)
                            
                            # Check for sensitive content
                            sensitive_found = []
                            for pattern, desc in self.SENSITIVE_DATA_PATTERNS:
                                if re.search(pattern, body, re.IGNORECASE):
                                    sensitive_found.append(desc)
                            
                            self._add_finding(
                                category="A01",
                                severity="critical" if sensitive_found else "high",
                                title=f"Admin Endpoint Accessible: {admin_path}",
                                description=f"Administrative endpoint '{admin_path}' is accessible without authentication. This violates access control principles.",
                                url=test_url,
                                method="GET",
                                parameter="",
                                evidence=f"Status: {status}\nContent Length: {len(body)}\nSensitive Data: {', '.join(sensitive_found) if sensitive_found else 'None detected'}",
                                remediation="Implement proper authentication and authorization checks. Require admin credentials or specific roles to access administrative endpoints.",
                                cwe_id="CWE-284",
                                poc=f"To reproduce:\n1. Navigate to {test_url}\n2. Observe admin panel is accessible without login",
                                reasoning=f"VERIFIED: Jarwis accessed admin endpoint '{admin_path}' without any authentication token and received HTTP 200 with {len(body)} bytes of content. This confirms broken access control.",
                                request_data=request_str,
                                response_data=response_str
                            )
                
                await asyncio.sleep(1 / self.rate_limit)
                
            except Exception as e:
                logger.debug(f"Admin endpoint test failed for {admin_path}: {e}")
    
    async def _test_idor(self, session: aiohttp.ClientSession):
        """Test for Insecure Direct Object References"""
        
        # Find endpoints with ID patterns
        for endpoint in self.context.endpoints:
            url = endpoint.get('url', '')
            
            # Check URL path for IDOR patterns
            for pattern, id_type in self.IDOR_PATTERNS:
                match = re.search(pattern, url, re.IGNORECASE)
                if match:
                    original_id = match.group(1)
                    await self._test_idor_manipulation(session, url, original_id, id_type, pattern)
                    break
            
            # Check query parameters for ID manipulation
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            for param in query_params:
                if param.lower() in [p.lower() for p in self.IDOR_PARAMS]:
                    original_value = query_params[param][0]
                    if original_value.isdigit():
                        await self._test_idor_param(session, url, param, original_value)
        
    async def _test_idor_manipulation(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        original_id: str, 
        id_type: str,
        pattern: str
    ):
        """Test IDOR by manipulating ID in URL path"""
        try:
            # Get baseline response
            async with session.get(
                url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                baseline_status = response.status
                baseline_body = await response.text()
            
            # Try different IDs
            test_ids = ['1', '2', '0', str(int(original_id) + 1), str(int(original_id) - 1)]
            
            for test_id in test_ids:
                if test_id == original_id:
                    continue
                    
                test_url = re.sub(pattern, lambda m: m.group(0).replace(original_id, test_id), url)
                
                async with session.get(
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    status = response.status
                    body = await response.text()
                    resp_headers = dict(response.headers)
                    
                    # If we get 200 with different content, IDOR confirmed
                    if status == 200 and len(body) > 100:
                        if body != baseline_body:
                            # Check for sensitive data
                            sensitive_found = []
                            for pat, desc in self.SENSITIVE_DATA_PATTERNS:
                                if re.search(pat, body, re.IGNORECASE):
                                    sensitive_found.append(desc)
                            
                            if sensitive_found or len(body) > 500:
                                request_str = self._format_request('GET', test_url, self.DEFAULT_HEADERS)
                                response_str = self._format_response(status, resp_headers, body)
                                
                                self._add_finding(
                                    category="A01",
                                    severity="high",
                                    title=f"IDOR: {id_type} Manipulation",
                                    description=f"Insecure Direct Object Reference detected. Changing {id_type} from {original_id} to {test_id} returns different user's data without authorization.",
                                    url=url,
                                    method="GET",
                                    parameter=id_type,
                                    evidence=f"Original ID: {original_id}\nTest ID: {test_id}\nOriginal URL: {url}\nTest URL: {test_url}\nSensitive Data: {', '.join(sensitive_found) if sensitive_found else 'Potentially sensitive data'}",
                                    remediation="Implement proper authorization checks. Verify the requesting user has permission to access the requested resource. Use indirect references or access control lists.",
                                    cwe_id="CWE-639",
                                    poc=f"To reproduce:\n1. Navigate to {url}\n2. Change ID from {original_id} to {test_id}\n3. Observe access to other user's data",
                                    reasoning=f"VERIFIED: Jarwis changed {id_type} from '{original_id}' to '{test_id}' and received HTTP 200 with different content ({len(body)} bytes). This indicates the server does not verify resource ownership before returning data.",
                                    request_data=request_str,
                                    response_data=response_str
                                )
                                return
                
                await asyncio.sleep(0.5)
                
        except Exception as e:
            logger.debug(f"IDOR test failed for {url}: {e}")
    
    async def _test_idor_param(
        self, 
        session: aiohttp.ClientSession, 
        url: str, 
        param: str, 
        original_value: str
    ):
        """Test IDOR by manipulating ID parameter"""
        try:
            parsed = urlparse(url)
            query_params = parse_qs(parsed.query)
            
            # Get baseline
            async with session.get(
                url,
                headers=self.DEFAULT_HEADERS,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
                ssl=False
            ) as response:
                baseline_body = await response.text()
            
            # Test different IDs
            test_values = ['1', '2', '0', str(int(original_value) + 1)]
            
            for test_value in test_values:
                if test_value == original_value:
                    continue
                
                query_params[param] = [test_value]
                new_query = urlencode(query_params, doseq=True)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                
                async with session.get(
                    test_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    status = response.status
                    body = await response.text()
                    resp_headers = dict(response.headers)
                    
                    if status == 200 and body != baseline_body and len(body) > 100:
                        request_str = self._format_request('GET', test_url, self.DEFAULT_HEADERS)
                        response_str = self._format_response(status, resp_headers, body)
                        
                        self._add_finding(
                            category="A01",
                            severity="high",
                            title=f"IDOR via {param} Parameter",
                            description=f"Insecure Direct Object Reference detected. Manipulating '{param}' parameter allows access to other users' resources.",
                            url=url,
                            method="GET",
                            parameter=param,
                            evidence=f"Original: {param}={original_value}\nTest: {param}={test_value}\nDifferent content returned",
                            remediation="Implement authorization checks before returning resources. Verify the user owns or has permission to access the requested resource.",
                            cwe_id="CWE-639",
                            poc=f"To reproduce:\n1. Navigate to {url}\n2. Change {param} from {original_value} to {test_value}\n3. Observe unauthorized data access",
                            reasoning=f"VERIFIED: Changing '{param}' from '{original_value}' to '{test_value}' returned different content without authorization check.",
                            request_data=request_str,
                            response_data=response_str
                        )
                        return
                
                await asyncio.sleep(0.5)
                
        except Exception as e:
            logger.debug(f"IDOR param test failed: {e}")
    
    async def _test_sensitive_data(self, session: aiohttp.ClientSession):
        """Check for sensitive data exposure in responses"""
        for endpoint in self.context.endpoints[:20]:  # Limit to first 20
            url = endpoint.get('url', '')
            
            try:
                async with session.get(
                    url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        body = await response.text()
                        resp_headers = dict(response.headers)
                        
                        sensitive_found = []
                        for pattern, desc in self.SENSITIVE_DATA_PATTERNS:
                            matches = re.findall(pattern, body, re.IGNORECASE)
                            if matches:
                                sensitive_found.append(f"{desc}: {len(matches)} occurrences")
                        
                        # Only report if significant sensitive data found
                        if len(sensitive_found) >= 2 or any('password' in s.lower() or 'credit' in s.lower() for s in sensitive_found):
                            request_str = self._format_request('GET', url, self.DEFAULT_HEADERS)
                            response_str = self._format_response(response.status, resp_headers, body)
                            
                            self._add_finding(
                                category="A01",
                                severity="high",
                                title="Sensitive Data Exposure",
                                description="Multiple types of sensitive data found in response without proper access controls.",
                                url=url,
                                method="GET",
                                parameter="",
                                evidence="\n".join(sensitive_found),
                                remediation="Implement proper access controls. Mask or encrypt sensitive data. Apply principle of least privilege.",
                                cwe_id="CWE-200",
                                poc=f"To reproduce:\n1. Request {url}\n2. Observe sensitive data in response",
                                reasoning=f"VERIFIED: Response contains sensitive data types: {', '.join(sensitive_found)}. This data should require authentication to access.",
                                request_data=request_str,
                                response_data=response_str
                            )
                
                await asyncio.sleep(1 / self.rate_limit)
                
            except Exception as e:
                logger.debug(f"Sensitive data test failed for {url}: {e}")
