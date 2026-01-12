"""
Jarwis AGI Pen Test - Post-Login CSRF Scanner
Detects CSRF vulnerabilities in authenticated contexts
OWASP A01:2021 - Broken Access Control
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import aiohttp
import ssl
from bs4 import BeautifulSoup

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


class PostLoginCSRFScanner:
    """
    Authenticated CSRF Scanner
    OWASP A01:2021 - Broken Access Control
    
    Tests for CSRF in authenticated state-changing operations:
    - Password change
    - Email change
    - Profile update
    - Account deletion
    - Settings modification
    """
    
    # Sensitive endpoints that require CSRF protection
    SENSITIVE_ENDPOINTS = [
        # Account management
        '/change-password', '/update-password', '/password/change',
        '/change-email', '/update-email', '/email/change',
        '/delete-account', '/account/delete', '/deactivate',
        '/update-profile', '/profile/update', '/settings/update',
        
        # Financial
        '/transfer', '/send-money', '/payment', '/withdraw',
        '/deposit', '/transaction', '/checkout',
        
        # Admin actions
        '/admin/create-user', '/admin/delete-user', '/admin/update',
        '/api/users/create', '/api/users/delete', '/api/settings',
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
        self.auth_headers = getattr(context, 'auth_headers', {})
        self.auth_cookies = getattr(context, 'auth_cookies', {})
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Post-Login CSRF scan...")
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
            
            # Test sensitive endpoints
            await self._test_sensitive_endpoints(session, base_url)
            
            # Test discovered forms
            await self._test_forms(session, base_url)
        
        logger.info(f"Post-Login CSRF scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_sensitive_endpoints(self, session: aiohttp.ClientSession, base_url: str):
        """Test sensitive endpoints for CSRF protection"""
        
        for endpoint in self.SENSITIVE_ENDPOINTS:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                url = urljoin(base_url, endpoint)
                
                # First GET the page
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
                    
                    body = await response.text()
                    
                    # Check for forms
                    soup = BeautifulSoup(body, 'html.parser')
                    forms = soup.find_all('form', method=re.compile('post', re.I))
                    
                    for form in forms:
                        has_csrf = self._has_csrf_protection(form, body)
                        
                        if not has_csrf:
                            result = ScanResult(
                                id=f"POSTLOGIN-CSRF-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="high",
                                title="Missing CSRF Protection on Sensitive Form",
                                description=f"Form at {endpoint} lacks CSRF token.",
                                url=url,
                                method="POST",
                                evidence="No CSRF token found in form",
                                poc=self._generate_csrf_poc(url, form),
                                remediation="Add CSRF tokens to all state-changing forms.",
                                cwe_id="CWE-352",
                                reasoning="Sensitive form without CSRF protection"
                            )
                            self.results.append(result)
                            
            except Exception as e:
                logger.debug(f"CSRF endpoint test error: {e}")
    
    async def _test_forms(self, session: aiohttp.ClientSession, base_url: str):
        """Test discovered forms for CSRF"""
        
        endpoints = getattr(self.context, 'endpoints', [])
        
        for endpoint in endpoints[:20]:
            ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
            
            if not ep_url:
                continue
            
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(ep_url) as response:
                    if response.status != 200:
                        continue
                    
                    body = await response.text()
                    soup = BeautifulSoup(body, 'html.parser')
                    
                    # Find all POST forms
                    forms = soup.find_all('form', method=re.compile('post', re.I))
                    
                    for form in forms:
                        # Check if form has sensitive inputs
                        if self._is_sensitive_form(form):
                            has_csrf = self._has_csrf_protection(form, body)
                            
                            if not has_csrf:
                                action = form.get('action', ep_url)
                                if not action.startswith('http'):
                                    action = urljoin(ep_url, action)
                                
                                result = ScanResult(
                                    id=f"POSTLOGIN-CSRF-FORM-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="medium",
                                    title="CSRF Vulnerability in Form",
                                    description="Sensitive form lacks CSRF protection.",
                                    url=action,
                                    method="POST",
                                    evidence="Form with sensitive inputs, no CSRF token",
                                    poc=self._generate_csrf_poc(action, form),
                                    remediation="Implement CSRF tokens.",
                                    cwe_id="CWE-352",
                                    reasoning="Form with password/email inputs lacks CSRF"
                                )
                                self.results.append(result)
                                
            except Exception as e:
                logger.debug(f"Form CSRF test error: {e}")
    
    def _has_csrf_protection(self, form, body: str) -> bool:
        """Check if form has CSRF protection"""
        
        # Check for hidden CSRF token
        csrf_names = [
            'csrf', 'csrf_token', '_csrf', 'csrftoken', 'csrfmiddlewaretoken',
            '_token', 'authenticity_token', 'antiforgery', '__RequestVerificationToken',
            'xsrf', '_xsrf', 'xsrf_token'
        ]
        
        for name in csrf_names:
            # Check form inputs
            if form.find('input', {'name': re.compile(name, re.I)}):
                return True
            
            # Check meta tags
            if re.search(rf'<meta[^>]+name=["\']?{name}["\']?', body, re.I):
                return True
        
        # Check for SameSite cookie
        # This is harder to detect without actual request analysis
        
        return False
    
    def _is_sensitive_form(self, form) -> bool:
        """Check if form handles sensitive data"""
        
        sensitive_inputs = [
            'password', 'email', 'amount', 'money', 'transfer',
            'delete', 'deactivate', 'admin', 'role', 'permission'
        ]
        
        inputs = form.find_all('input')
        
        for inp in inputs:
            name = inp.get('name', '').lower()
            input_type = inp.get('type', '').lower()
            
            if input_type == 'password':
                return True
            
            if any(s in name for s in sensitive_inputs):
                return True
        
        return False
    
    def _generate_csrf_poc(self, action: str, form) -> str:
        """Generate CSRF PoC HTML"""
        
        inputs = form.find_all('input')
        hidden_inputs = ""
        
        for inp in inputs:
            name = inp.get('name', '')
            value = inp.get('value', 'test')
            if name:
                hidden_inputs += f'    <input type="hidden" name="{name}" value="{value}">\n'
        
        poc = f"""<html>
<body>
<form action="{action}" method="POST" id="csrf_form">
{hidden_inputs}</form>
<script>document.getElementById('csrf_form').submit();</script>
</body>
</html>"""
        
        return poc


class PostLoginSensitiveActionScanner:
    """
    Scans for unprotected sensitive actions in authenticated context
    """
    
    # Sensitive actions to test
    SENSITIVE_ACTIONS = {
        'password_change': {
            'endpoints': ['/change-password', '/password', '/account/password'],
            'required_fields': ['current_password', 'old_password'],
        },
        'email_change': {
            'endpoints': ['/change-email', '/email', '/account/email'],
            'required_fields': ['password', 'current_password'],
        },
        'account_delete': {
            'endpoints': ['/delete-account', '/account/delete', '/deactivate'],
            'required_fields': ['password', 'confirmation'],
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
        self.auth_headers = getattr(context, 'auth_headers', {})
        self.auth_cookies = getattr(context, 'auth_cookies', {})
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Sensitive Action scan...")
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
            
            for action_name, action_config in self.SENSITIVE_ACTIONS.items():
                await self._test_action(session, base_url, action_name, action_config)
        
        logger.info(f"Sensitive Action scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_action(
        self, session: aiohttp.ClientSession, base_url: str,
        action_name: str, action_config: dict
    ):
        """Test a sensitive action for missing verification"""
        
        for endpoint in action_config['endpoints']:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                url = urljoin(base_url, endpoint)
                
                # GET the form first
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
                    
                    body = await response.text()
                    
                    # Check if required verification fields are present
                    has_verification = any(
                        field in body.lower() 
                        for field in action_config['required_fields']
                    )
                    
                    if not has_verification:
                        # Try submitting without verification
                        test_data = {}
                        
                        if action_name == 'password_change':
                            test_data = {'new_password': 'test123', 'confirm_password': 'test123'}
                        elif action_name == 'email_change':
                            test_data = {'new_email': 'test@test.com'}
                        
                        async with session.post(url, data=test_data) as post_response:
                            post_body = await post_response.text()
                            
                            # Check for success without verification
                            if post_response.status in [200, 302]:
                                if 'error' not in post_body.lower() and 'invalid' not in post_body.lower():
                                    result = ScanResult(
                                        id=f"SENSITIVE-ACTION-{len(self.results)+1}",
                                        category="A07:2021 - Auth Failures",
                                        severity="high",
                                        title=f"{action_name.replace('_', ' ').title()} Without Verification",
                                        description=f"{action_name} does not require current password.",
                                        url=url,
                                        method="POST",
                                        evidence="Action accepted without password verification",
                                        remediation="Require current password for sensitive actions.",
                                        cwe_id="CWE-306",
                                        reasoning="Missing authentication for critical function"
                                    )
                                    self.results.append(result)
                                    
            except Exception as e:
                logger.debug(f"Sensitive action test error: {e}")
