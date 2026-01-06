"""
Jarwis AGI Pen Test - POST Method Scanner
Comprehensive form analysis and POST endpoint testing for pre-login phase

This scanner:
1. Discovers all forms on the page using selectors
2. Analyzes form fields (email, password, name, phone, address, upload, etc.)
3. Generates intelligent test data based on field semantics
4. Submits forms to capture request/response headers via MITM
5. Tests for vulnerabilities in POST endpoints

Works with both web and mobile API testing frameworks.
"""

import asyncio
import logging
import re
import json
import random
import string
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin
import aiohttp

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """Represents a form input field"""
    name: str
    field_type: str  # text, email, password, tel, file, textarea, select, etc.
    selector: str  # CSS selector to locate this field
    id: str = ""
    placeholder: str = ""
    label: str = ""
    required: bool = False
    pattern: str = ""
    min_length: int = 0
    max_length: int = 0
    options: List[str] = field(default_factory=list)  # For select fields
    accept: str = ""  # For file inputs


@dataclass
class DiscoveredForm:
    """Represents a discovered HTML form"""
    id: str
    action: str
    method: str
    enctype: str  # application/x-www-form-urlencoded, multipart/form-data
    fields: List[FormField] = field(default_factory=list)
    selector: str = ""  # CSS selector for the form
    page_url: str = ""
    has_file_upload: bool = False
    form_type: str = ""  # login, register, contact, search, checkout, profile, etc.


@dataclass
class PostRequestCapture:
    """Captured POST request and response"""
    id: str
    url: str
    method: str = "POST"
    
    # Request details (Burp-style)
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    content_type: str = ""
    form_data: Dict[str, Any] = field(default_factory=dict)
    
    # Response details
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_time_ms: float = 0
    
    # Metadata
    form_id: str = ""
    timestamp: str = ""


@dataclass 
class ScanResult:
    """Vulnerability finding from POST method scanning"""
    id: str
    category: str  # OWASP category
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    url: str
    method: str = "POST"
    parameter: str = ""
    evidence: str = ""
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""
    remediation: str = ""
    cwe_id: str = ""


class SmartFormDataGenerator:
    """
    Intelligent form data generator that analyzes field semantics
    and generates appropriate test data for security testing
    """
    
    # Field type patterns for semantic detection
    FIELD_PATTERNS = {
        'email': [r'email', r'e-mail', r'mail', r'user.*mail'],
        'password': [r'password', r'passwd', r'pwd', r'secret', r'pass'],
        'confirm_password': [r'confirm.*pass', r'pass.*confirm', r'retype.*pass', r'repeat.*pass', r're-?enter.*pass'],
        'username': [r'username', r'user.*name', r'login', r'userid', r'user_?id'],
        'name': [r'^name$', r'full.*name', r'your.*name', r'display.*name'],
        'first_name': [r'first.*name', r'fname', r'given.*name', r'forename'],
        'last_name': [r'last.*name', r'lname', r'surname', r'family.*name'],
        'phone': [r'phone', r'mobile', r'cell', r'tel', r'contact.*number'],
        'address': [r'address', r'street', r'addr'],
        'address_line2': [r'address.*2', r'apt', r'suite', r'unit', r'line.*2'],
        'city': [r'city', r'town', r'locality'],
        'state': [r'state', r'province', r'region'],
        'zip': [r'zip', r'postal', r'postcode', r'pin.*code'],
        'country': [r'country', r'nation'],
        'dob': [r'dob', r'birth.*date', r'date.*birth', r'birthday'],
        'age': [r'^age$', r'your.*age'],
        'ssn': [r'ssn', r'social.*security', r'national.*id', r'aadhar', r'pan'],
        'credit_card': [r'card.*number', r'credit.*card', r'cc.*num', r'payment.*card'],
        'cvv': [r'cvv', r'cvc', r'security.*code', r'card.*code'],
        'expiry': [r'expir', r'exp.*date', r'valid.*until'],
        'company': [r'company', r'organization', r'org.*name', r'business'],
        'website': [r'website', r'url', r'web.*address', r'homepage'],
        'message': [r'message', r'comment', r'feedback', r'inquiry', r'description', r'content', r'body'],
        'subject': [r'subject', r'title', r'topic', r'heading'],
        'file': [r'file', r'upload', r'document', r'attachment', r'photo', r'image', r'avatar', r'picture'],
        'captcha': [r'captcha', r'verify', r'human', r'recaptcha'],
        'otp': [r'otp', r'verification.*code', r'pin', r'code', r'token'],
        'amount': [r'amount', r'quantity', r'qty', r'price', r'total', r'value'],
        'date': [r'date', r'when'],
        'time': [r'time', r'hour'],
        'gender': [r'gender', r'sex'],
        'bio': [r'bio', r'about', r'profile', r'introduction'],
        'terms': [r'terms', r'agree', r'accept', r'consent', r'policy'],
        'newsletter': [r'newsletter', r'subscribe', r'marketing', r'promo'],
        'search': [r'search', r'query', r'q', r'keyword', r'find'],
        'coupon': [r'coupon', r'promo.*code', r'discount', r'voucher'],
        'referral': [r'referral', r'referred', r'invite.*code'],
    }
    
    # Test data for each field type
    TEST_DATA = {
        'email': 'test@jarwis.ai',
        'password': 'JarwisTest@123',
        'confirm_password': 'JarwisTest@123',
        'username': 'jarwis_tester',
        'name': 'Jarwis Security Tester',
        'first_name': 'Jarwis',
        'last_name': 'Tester',
        'phone': '+1234567890',
        'address': '123 Security Lane',
        'address_line2': 'Suite 100',
        'city': 'Cyberville',
        'state': 'California',
        'zip': '90210',
        'country': 'United States',
        'dob': '1990-01-15',
        'age': '30',
        'ssn': '123-45-6789',
        'credit_card': '4111111111111111',
        'cvv': '123',
        'expiry': '12/2030',
        'company': 'Jarwis Security Corp',
        'website': 'https://jarwis.ai',
        'message': 'This is a security test message from Jarwis penetration testing framework.',
        'subject': 'Security Test',
        'captcha': 'test_captcha',
        'otp': '123456',
        'amount': '100',
        'date': '2026-01-15',
        'time': '14:30',
        'gender': 'Other',
        'bio': 'Security researcher and penetration tester.',
        'terms': 'on',
        'newsletter': 'on',
        'search': 'test query',
        'coupon': 'TESTCODE',
        'referral': 'JARWIS2026',
        'default': 'test_value',
    }
    
    # Malicious payloads for vulnerability testing
    INJECTION_PAYLOADS = {
        'sqli': ["' OR '1'='1", "'; DROP TABLE users--", "1' AND '1'='1"],
        'xss': ['<script>alert("XSS")</script>', '"><img src=x onerror=alert(1)>', '<svg onload=alert(1)>'],
        'command': ['; ls -la', '| cat /etc/passwd', '$(whoami)'],
        'path_traversal': ['../../../etc/passwd', '..\\..\\..\\windows\\system32\\config\\sam'],
        'ssrf': ['http://localhost', 'http://127.0.0.1', 'http://169.254.169.254'],
        'xxe': ['<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'],
        'ldap': ['*', '*)(&', '*)(uid=*))(|(uid=*'],
        'ssti': ['{{7*7}}', '${7*7}', '<%=7*7%>'],
        'nosql': ['{"$gt": ""}', '{"$ne": null}', '{"$where": "sleep(5000)"}'],
    }
    
    def __init__(self):
        self._random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    def detect_field_type(self, field: FormField) -> str:
        """Detect the semantic type of a form field"""
        # Combine all identifiers for matching
        identifiers = ' '.join([
            field.name.lower(),
            field.id.lower(),
            field.placeholder.lower(),
            field.label.lower(),
            field.field_type.lower()
        ])
        
        # Check against patterns
        for field_type, patterns in self.FIELD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, identifiers, re.IGNORECASE):
                    return field_type
        
        # Fallback to HTML input type
        if field.field_type in ['email', 'password', 'tel', 'url', 'number', 'date', 'file']:
            return field.field_type
        
        return 'default'
    
    def generate_value(self, field: FormField, unique: bool = True) -> str:
        """Generate appropriate test value for a field"""
        field_semantic = self.detect_field_type(field)
        base_value = self.TEST_DATA.get(field_semantic, self.TEST_DATA['default'])
        
        # Make email unique if needed
        if field_semantic == 'email' and unique:
            base_value = f"test_{self._random_suffix}@jarwis.ai"
        
        # Make username unique
        if field_semantic == 'username' and unique:
            base_value = f"jarwis_tester_{self._random_suffix}"
        
        return base_value
    
    def generate_form_data(self, form: DiscoveredForm, unique: bool = True) -> Dict[str, Any]:
        """Generate complete form data for all fields"""
        data = {}
        
        for field in form.fields:
            if field.field_type == 'file':
                continue  # Handle file uploads separately
            
            if field.field_type == 'select' and field.options:
                # Pick a non-empty option
                data[field.name] = field.options[0] if field.options else 'option1'
            elif field.field_type == 'checkbox':
                data[field.name] = 'on'
            elif field.field_type == 'radio':
                data[field.name] = field.options[0] if field.options else 'option1'
            elif field.field_type == 'hidden':
                # Keep hidden field values as-is if present
                pass
            else:
                data[field.name] = self.generate_value(field, unique)
        
        return data
    
    def generate_attack_data(self, form: DiscoveredForm, attack_type: str) -> List[Dict[str, Any]]:
        """Generate attack payloads for each field"""
        attack_sets = []
        payloads = self.INJECTION_PAYLOADS.get(attack_type, [])
        
        base_data = self.generate_form_data(form)
        
        for field in form.fields:
            if field.field_type in ['file', 'hidden', 'submit', 'button']:
                continue
            
            for payload in payloads[:3]:  # Limit payloads per field
                attack_data = base_data.copy()
                attack_data[field.name] = payload
                attack_sets.append({
                    'data': attack_data,
                    'target_field': field.name,
                    'payload': payload,
                    'attack_type': attack_type
                })
        
        return attack_sets


class PostMethodScanner:
    """
    POST Method Scanner for discovering and testing POST endpoints
    
    Features:
    - Form discovery and analysis using CSS selectors
    - Intelligent form data generation
    - Request/Response capture (Burp-style)
    - Vulnerability testing on POST endpoints
    - Works for both pre-login and post-login phases
    """
    
    DEFAULT_HEADERS = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    def __init__(self, config: dict, context, browser_controller=None):
        self.config = config
        self.context = context
        self.browser = browser_controller
        self.data_generator = SmartFormDataGenerator()
        self.discovered_forms: List[DiscoveredForm] = []
        self.captured_requests: List[PostRequestCapture] = []
        self.findings: List[ScanResult] = []
        self._finding_id = 0
        self._capture_id = 0
        
        # Extract target domain for scope checking
        target_url = config.get('target', {}).get('url', '')
        self._target_domain = urlparse(target_url).netloc.lower() if target_url else ""
        
    def _is_in_scope(self, url: str) -> bool:
        """Check if URL is within target scope"""
        if not url or not self._target_domain:
            return True
        try:
            parsed = urlparse(url)
            url_domain = parsed.netloc.lower()
            target = self._target_domain
            # Strip www.
            if url_domain.startswith('www.'):
                url_domain = url_domain[4:]
            if target.startswith('www.'):
                target = target[4:]
            return url_domain == target
        except:
            return True
    
    async def scan(self) -> List[ScanResult]:
        """Run the complete POST method scan"""
        self.findings = []
        
        logger.info("Starting POST Method Scanner")
        
        # Phase 1: Discover forms via browser if available
        if self.browser:
            await self._discover_forms_via_browser()
        
        # Phase 2: Discover POST endpoints from context
        await self._discover_post_endpoints()
        
        # Phase 3: Submit forms and capture traffic
        await self._submit_forms_and_capture()
        
        # Phase 4: Test discovered POST endpoints for vulnerabilities
        await self._test_vulnerabilities()
        
        logger.info(f"POST Method Scanner complete: {len(self.findings)} findings")
        
        return self.findings
    
    async def _discover_forms_via_browser(self):
        """Discover forms on the page using browser automation"""
        if not self.browser or not self.browser.page:
            return
        
        logger.info("Discovering forms via browser...")
        
        try:
            # JavaScript to extract all form details
            forms_data = await self.browser.page.evaluate('''() => {
                const forms = [];
                
                document.querySelectorAll('form').forEach((form, formIndex) => {
                    const formData = {
                        id: form.id || `form_${formIndex}`,
                        action: form.action || window.location.href,
                        method: (form.method || 'GET').toUpperCase(),
                        enctype: form.enctype || 'application/x-www-form-urlencoded',
                        selector: form.id ? `#${form.id}` : `form:nth-of-type(${formIndex + 1})`,
                        fields: []
                    };
                    
                    // Get all input fields
                    form.querySelectorAll('input, textarea, select').forEach((input, inputIndex) => {
                        // Skip submit/button types for data collection
                        if (['submit', 'button', 'reset', 'image'].includes(input.type)) return;
                        
                        const field = {
                            name: input.name || input.id || `field_${inputIndex}`,
                            field_type: input.type || input.tagName.toLowerCase(),
                            selector: input.id ? `#${input.id}` : 
                                      input.name ? `[name="${input.name}"]` :
                                      `${input.tagName.toLowerCase()}:nth-of-type(${inputIndex + 1})`,
                            id: input.id || '',
                            placeholder: input.placeholder || '',
                            required: input.required || false,
                            pattern: input.pattern || '',
                            minLength: input.minLength || 0,
                            maxLength: input.maxLength || 0,
                            accept: input.accept || '',
                            options: [],
                            label: ''
                        };
                        
                        // Get label if exists
                        if (input.id) {
                            const label = document.querySelector(`label[for="${input.id}"]`);
                            if (label) field.label = label.textContent.trim();
                        }
                        
                        // Get options for select elements
                        if (input.tagName.toLowerCase() === 'select') {
                            input.querySelectorAll('option').forEach(opt => {
                                if (opt.value) field.options.push(opt.value);
                            });
                        }
                        
                        // Get radio/checkbox options
                        if (['radio', 'checkbox'].includes(input.type) && input.value) {
                            field.options.push(input.value);
                        }
                        
                        formData.fields.push(field);
                    });
                    
                    forms.push(formData);
                });
                
                return forms;
            }''')
            
            # Convert to DiscoveredForm objects
            for form_data in forms_data:
                if form_data['method'] != 'POST':
                    continue
                
                fields = [
                    FormField(
                        name=f['name'],
                        field_type=f['field_type'],
                        selector=f['selector'],
                        id=f.get('id', ''),
                        placeholder=f.get('placeholder', ''),
                        label=f.get('label', ''),
                        required=f.get('required', False),
                        pattern=f.get('pattern', ''),
                        min_length=f.get('minLength', 0),
                        max_length=f.get('maxLength', 0),
                        options=f.get('options', []),
                        accept=f.get('accept', '')
                    )
                    for f in form_data['fields']
                ]
                
                form = DiscoveredForm(
                    id=form_data['id'],
                    action=form_data['action'],
                    method=form_data['method'],
                    enctype=form_data['enctype'],
                    fields=fields,
                    selector=form_data['selector'],
                    page_url=self.browser.page.url,
                    has_file_upload=any(f.field_type == 'file' for f in fields),
                    form_type=self._detect_form_type(form_data)
                )
                
                self.discovered_forms.append(form)
                logger.info(f"Discovered {form.form_type} form: {form.id} with {len(fields)} fields")
            
        except Exception as e:
            logger.warning(f"Browser form discovery failed: {e}")
    
    def _detect_form_type(self, form_data: dict) -> str:
        """Detect the purpose of a form based on fields"""
        field_names = ' '.join([f['name'].lower() for f in form_data['fields']])
        action = form_data['action'].lower()
        
        if any(x in field_names for x in ['password', 'login', 'signin']):
            if 'confirm' in field_names or 'register' in action or 'signup' in action:
                return 'register'
            return 'login'
        elif any(x in field_names for x in ['message', 'comment', 'inquiry', 'feedback']):
            return 'contact'
        elif any(x in field_names for x in ['search', 'query', 'keyword']):
            return 'search'
        elif any(x in field_names for x in ['card', 'payment', 'checkout', 'billing']):
            return 'payment'
        elif any(x in field_names for x in ['address', 'shipping', 'profile']):
            return 'profile'
        elif 'file' in field_names or 'upload' in action:
            return 'upload'
        else:
            return 'general'
    
    async def _discover_post_endpoints(self):
        """Discover POST endpoints from context (crawler results)"""
        endpoints = getattr(self.context, 'endpoints', [])
        if isinstance(endpoints, dict):
            endpoints = endpoints.get('endpoints', [])
        
        for ep in endpoints:
            if isinstance(ep, dict) and ep.get('method', '').upper() == 'POST':
                # Create a form from discovered POST endpoint
                params = ep.get('params', {})
                fields = [
                    FormField(
                        name=name,
                        field_type=ftype if isinstance(ftype, str) else 'text',
                        selector=f'[name="{name}"]'
                    )
                    for name, ftype in params.items()
                ]
                
                form = DiscoveredForm(
                    id=f"api_{len(self.discovered_forms)}",
                    action=ep.get('url', ''),
                    method='POST',
                    enctype='application/x-www-form-urlencoded',
                    fields=fields,
                    has_file_upload=ep.get('has_upload', False),
                    form_type='api'
                )
                
                # Avoid duplicates
                if not any(f.action == form.action for f in self.discovered_forms):
                    self.discovered_forms.append(form)
    
    async def _submit_forms_and_capture(self):
        """Submit discovered forms and capture request/response"""
        logger.info(f"Submitting {len(self.discovered_forms)} discovered forms...")
        
        async with aiohttp.ClientSession(headers=self.DEFAULT_HEADERS) as session:
            for form in self.discovered_forms[:50]:  # Limit to 50 forms
                if not self._is_in_scope(form.action):
                    continue
                
                try:
                    await self._submit_form(session, form)
                except Exception as e:
                    logger.debug(f"Form submission failed for {form.action}: {e}")
                
                await asyncio.sleep(0.1)  # Rate limiting
    
    async def _submit_form(self, session: aiohttp.ClientSession, form: DiscoveredForm):
        """Submit a single form and capture the traffic"""
        # Generate form data
        form_data = self.data_generator.generate_form_data(form)
        
        if not form_data and not form.fields:
            # For API endpoints without discovered fields, use common params
            form_data = self._get_common_params_for_form_type(form.form_type)
        
        self._capture_id += 1
        capture = PostRequestCapture(
            id=f"POST-{self._capture_id:04d}",
            url=form.action,
            form_data=form_data,
            form_id=form.id,
            timestamp=datetime.now().isoformat()
        )
        
        # Determine content type
        if form.enctype == 'multipart/form-data' or form.has_file_upload:
            # Use FormData for multipart
            form_obj = aiohttp.FormData()
            for key, value in form_data.items():
                form_obj.add_field(key, str(value))
            data = form_obj
            capture.content_type = 'multipart/form-data'
        elif 'json' in form.enctype or form.form_type == 'api':
            # Try JSON for API endpoints
            data = json.dumps(form_data)
            capture.content_type = 'application/json'
            capture.request_body = data
        else:
            # URL-encoded form data
            data = form_data
            capture.content_type = 'application/x-www-form-urlencoded'
            capture.request_body = '&'.join(f"{k}={v}" for k, v in form_data.items())
        
        try:
            start_time = datetime.now()
            
            headers = dict(self.DEFAULT_HEADERS)
            if capture.content_type == 'application/json':
                headers['Content-Type'] = 'application/json'
            
            async with session.post(
                form.action,
                data=data if capture.content_type != 'application/json' else None,
                json=form_data if capture.content_type == 'application/json' else None,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False,
                allow_redirects=True
            ) as response:
                end_time = datetime.now()
                
                capture.response_status = response.status
                capture.response_headers = dict(response.headers)
                capture.response_body = await response.text()
                capture.response_time_ms = (end_time - start_time).total_seconds() * 1000
                capture.request_headers = headers
                
                self.captured_requests.append(capture)
                
                logger.debug(f"Captured POST to {form.action}: {response.status}")
                
        except Exception as e:
            logger.debug(f"POST request failed: {e}")
            capture.response_status = 0
            self.captured_requests.append(capture)
    
    def _get_common_params_for_form_type(self, form_type: str) -> Dict[str, str]:
        """Get common parameters based on form type"""
        params = {
            'login': {'username': 'test@jarwis.ai', 'password': 'JarwisTest@123', 'email': 'test@jarwis.ai'},
            'register': {'username': 'jarwis_test', 'email': 'test@jarwis.ai', 'password': 'JarwisTest@123', 'confirm_password': 'JarwisTest@123', 'name': 'Jarwis Tester'},
            'contact': {'name': 'Jarwis Tester', 'email': 'test@jarwis.ai', 'message': 'Security test message', 'subject': 'Test'},
            'search': {'q': 'test', 'query': 'test', 'search': 'test'},
            'payment': {'amount': '100', 'card': '4111111111111111', 'cvv': '123', 'expiry': '12/30'},
            'profile': {'name': 'Jarwis Tester', 'email': 'test@jarwis.ai', 'phone': '+1234567890', 'address': '123 Test St'},
            'upload': {'title': 'Test Upload', 'description': 'Test file'},
            'general': {'name': 'test', 'value': 'test', 'data': 'test'},
            'api': {'data': 'test', 'id': '1', 'action': 'test'}
        }
        return params.get(form_type, params['general'])
    
    async def _test_vulnerabilities(self):
        """Test discovered POST endpoints for vulnerabilities"""
        logger.info("Testing POST endpoints for vulnerabilities...")
        
        async with aiohttp.ClientSession(headers=self.DEFAULT_HEADERS) as session:
            for form in self.discovered_forms[:30]:
                if not self._is_in_scope(form.action):
                    continue
                
                # Test for SQL Injection
                await self._test_sqli(session, form)
                
                # Test for XSS
                await self._test_xss(session, form)
                
                # Test for sensitive data in response
                await self._check_sensitive_data(form)
                
                await asyncio.sleep(0.05)
    
    async def _test_sqli(self, session: aiohttp.ClientSession, form: DiscoveredForm):
        """Test form for SQL injection"""
        attack_sets = self.data_generator.generate_attack_data(form, 'sqli')
        
        for attack in attack_sets[:3]:
            try:
                async with session.post(
                    form.action,
                    data=attack['data'],
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    content = await response.text()
                    
                    sql_errors = [
                        'sql syntax', 'mysql', 'postgresql', 'sqlite', 'ora-',
                        'syntax error', 'unclosed quotation', 'sqlstate',
                        'microsoft sql server', 'jdbc', 'odbc'
                    ]
                    
                    if any(err in content.lower() for err in sql_errors):
                        self._add_finding(
                            category="A03",
                            severity="critical",
                            title=f"SQL Injection in POST form",
                            description=f"SQL error triggered in field '{attack['target_field']}'",
                            url=form.action,
                            parameter=attack['target_field'],
                            evidence=f"Payload: {attack['payload']}",
                            poc=f"POST {form.action}\nData: {json.dumps(attack['data'])}",
                            reasoning=f"SQL error message detected after injecting payload",
                            remediation="Use parameterized queries. Never concatenate user input into SQL.",
                            cwe_id="CWE-89"
                        )
                        return  # One finding per form
            except:
                pass
    
    async def _test_xss(self, session: aiohttp.ClientSession, form: DiscoveredForm):
        """Test form for XSS vulnerabilities"""
        attack_sets = self.data_generator.generate_attack_data(form, 'xss')
        
        for attack in attack_sets[:3]:
            try:
                async with session.post(
                    form.action,
                    data=attack['data'],
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    content = await response.text()
                    
                    # Check if payload is reflected without encoding
                    if attack['payload'] in content:
                        self._add_finding(
                            category="A03",
                            severity="high",
                            title=f"XSS in POST form",
                            description=f"XSS payload reflected without encoding in field '{attack['target_field']}'",
                            url=form.action,
                            parameter=attack['target_field'],
                            evidence=f"Payload reflected: {attack['payload'][:50]}",
                            poc=f"POST {form.action}\nData: {json.dumps(attack['data'])}",
                            reasoning="XSS payload appears unencoded in response",
                            remediation="Encode all output. Use Content-Security-Policy headers.",
                            cwe_id="CWE-79"
                        )
                        return
            except:
                pass
    
    async def _check_sensitive_data(self, form: DiscoveredForm):
        """Check captured responses for sensitive data exposure"""
        for capture in self.captured_requests:
            if capture.form_id != form.id:
                continue
            
            patterns = [
                (r'password["\s:=]+["\']?([^\s"\']{4,})', 'Password in response'),
                (r'secret["\s:=]+["\']?([^\s"\']{8,})', 'Secret key in response'),
                (r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{20,})', 'API key in response'),
                (r'private[_-]?key', 'Private key reference'),
                (r'bearer\s+[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT token exposed'),
            ]
            
            for pattern, desc in patterns:
                if re.search(pattern, capture.response_body, re.IGNORECASE):
                    self._add_finding(
                        category="A02",
                        severity="high",
                        title=f"Sensitive Data Exposure: {desc}",
                        description=f"{desc} detected in POST response",
                        url=capture.url,
                        evidence=f"Pattern matched in response",
                        remediation="Never return sensitive data in responses. Mask sensitive fields.",
                        cwe_id="CWE-200"
                    )
    
    def _add_finding(self, **kwargs):
        """Add a vulnerability finding"""
        self._finding_id += 1
        finding = ScanResult(
            id=f"POST-{self._finding_id:04d}",
            method="POST",
            **kwargs
        )
        self.findings.append(finding)
    
    def get_captured_traffic(self) -> List[Dict]:
        """Get all captured POST request/response pairs (Burp-style)"""
        traffic = []
        for capture in self.captured_requests:
            traffic.append({
                'id': capture.id,
                'url': capture.url,
                'method': 'POST',
                'request': {
                    'headers': capture.request_headers,
                    'body': capture.request_body,
                    'content_type': capture.content_type,
                    'form_data': capture.form_data
                },
                'response': {
                    'status': capture.response_status,
                    'headers': capture.response_headers,
                    'body': capture.response_body[:2000] if capture.response_body else '',
                    'time_ms': capture.response_time_ms
                },
                'timestamp': capture.timestamp
            })
        return traffic
    
    def get_discovered_forms(self) -> List[Dict]:
        """Get all discovered forms with their details"""
        return [
            {
                'id': form.id,
                'action': form.action,
                'method': form.method,
                'type': form.form_type,
                'fields': [
                    {
                        'name': f.name,
                        'type': f.field_type,
                        'selector': f.selector,
                        'required': f.required
                    }
                    for f in form.fields
                ],
                'has_file_upload': form.has_file_upload
            }
            for form in self.discovered_forms
        ]


# For backward compatibility
class PostMethodAttackScanner(PostMethodScanner):
    """Alias for PostMethodScanner"""
    pass
