"""
Jarwis AGI Pen Test - Mobile POST Method Scanner
Comprehensive form analysis and POST endpoint testing for mobile applications

This scanner:
1. Discovers all UI forms/input screens in mobile apps
2. Analyzes input fields (email, password, phone, OTP, address, etc.)
3. Generates intelligent test data based on field semantics
4. Uses Frida/MITM to capture POST request/response headers
5. Tests for vulnerabilities in mobile API POST endpoints

Works with both Android and iOS mobile testing frameworks.
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
class MobileInputField:
    """Represents a mobile app input field"""
    name: str
    field_type: str  # text, email, password, phone, number, date, etc.
    resource_id: str = ""  # Android resource ID
    accessibility_id: str = ""  # iOS accessibility identifier
    hint: str = ""
    content_desc: str = ""
    input_type: int = 0  # Android inputType
    is_password: bool = False
    is_editable: bool = True
    bounds: Dict = field(default_factory=dict)


@dataclass
class MobileForm:
    """Represents a mobile app form/screen"""
    id: str
    screen_name: str
    api_endpoint: str = ""  # API endpoint this form submits to
    method: str = "POST"
    fields: List[MobileInputField] = field(default_factory=list)
    form_type: str = ""  # login, register, profile, payment, etc.
    submit_button_id: str = ""
    platform: str = ""  # android, ios


@dataclass
class MobilePostCapture:
    """Captured mobile POST request and response"""
    id: str
    url: str
    method: str = "POST"
    
    # Request details
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: str = ""
    content_type: str = ""
    form_data: Dict[str, Any] = field(default_factory=dict)
    
    # Response details
    response_status: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    
    # Mobile-specific
    platform: str = ""
    screen_name: str = ""
    auth_token: str = ""
    timestamp: str = ""


@dataclass
class MobileScanResult:
    """Vulnerability finding from mobile POST scanning"""
    id: str
    category: str  # OWASP Mobile category
    severity: str
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


class MobileFormDataGenerator:
    """
    Intelligent form data generator for mobile apps
    Analyzes field semantics and generates appropriate test data
    """
    
    # Android inputType mappings
    ANDROID_INPUT_TYPES = {
        1: 'text',
        2: 'text',  # TYPE_CLASS_NUMBER
        3: 'phone',
        4: 'datetime',
        32: 'email',  # TYPE_TEXT_VARIATION_EMAIL_ADDRESS
        128: 'password',  # TYPE_TEXT_VARIATION_PASSWORD
        129: 'password',  # TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
        144: 'password',  # TYPE_TEXT_VARIATION_WEB_PASSWORD
        97: 'email',  # TYPE_TEXT_VARIATION_WEB_EMAIL_ADDRESS
        33: 'email',
        18: 'password',
        225: 'password',
    }
    
    # Field detection patterns
    FIELD_PATTERNS = {
        'email': [r'email', r'e-mail', r'mail'],
        'password': [r'password', r'passwd', r'pwd', r'secret'],
        'confirm_password': [r'confirm', r'retype', r'repeat', r're.?enter'],
        'phone': [r'phone', r'mobile', r'cell', r'tel', r'contact'],
        'otp': [r'otp', r'code', r'verification', r'pin', r'token'],
        'name': [r'name', r'full.?name'],
        'first_name': [r'first', r'fname', r'given'],
        'last_name': [r'last', r'lname', r'surname', r'family'],
        'username': [r'username', r'user.?name', r'login', r'userid'],
        'address': [r'address', r'street', r'addr'],
        'city': [r'city', r'town'],
        'zip': [r'zip', r'postal', r'pincode'],
        'card_number': [r'card', r'credit', r'cc.?num'],
        'cvv': [r'cvv', r'cvc', r'security.?code'],
        'expiry': [r'expir', r'valid'],
        'amount': [r'amount', r'quantity', r'price', r'total'],
        'message': [r'message', r'comment', r'note', r'description'],
        'search': [r'search', r'query', r'find'],
        'dob': [r'dob', r'birth', r'birthday'],
        'gender': [r'gender', r'sex'],
        'referral': [r'referral', r'invite', r'promo'],
    }
    
    # Test data for mobile fields
    TEST_DATA = {
        'email': 'test@jarwis.ai',
        'password': 'JarwisTest@123',
        'confirm_password': 'JarwisTest@123',
        'phone': '+1234567890',
        'otp': '123456',
        'name': 'Jarwis Tester',
        'first_name': 'Jarwis',
        'last_name': 'Tester',
        'username': 'jarwis_tester',
        'address': '123 Security Lane',
        'city': 'Cyberville',
        'zip': '90210',
        'card_number': '4111111111111111',
        'cvv': '123',
        'expiry': '12/30',
        'amount': '100',
        'message': 'Security test message from Jarwis.',
        'search': 'test',
        'dob': '1990-01-15',
        'gender': 'Other',
        'referral': 'JARWIS2026',
        'default': 'test_value',
    }
    
    # Attack payloads for mobile API testing
    ATTACK_PAYLOADS = {
        'sqli': ["' OR '1'='1", "'; DROP TABLE--", "1' AND '1'='1"],
        'xss': ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>'],
        'nosql': ['{"$gt": ""}', '{"$ne": null}'],
        'ssrf': ['http://localhost', 'http://127.0.0.1', 'http://169.254.169.254'],
        'idor': ['1', '0', '-1', '999999'],
    }
    
    def __init__(self):
        self._random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
    
    def detect_field_type_android(self, field: MobileInputField) -> str:
        """Detect field type from Android inputType"""
        if field.is_password:
            return 'password'
        
        # Check inputType
        input_type = self.ANDROID_INPUT_TYPES.get(field.input_type)
        if input_type:
            return input_type
        
        # Check resource_id, hint, content_desc
        identifiers = ' '.join([
            field.resource_id.lower(),
            field.hint.lower(),
            field.content_desc.lower(),
            field.name.lower()
        ])
        
        return self._match_patterns(identifiers)
    
    def detect_field_type_ios(self, field: MobileInputField) -> str:
        """Detect field type from iOS accessibility"""
        if field.is_password:
            return 'password'
        
        identifiers = ' '.join([
            field.accessibility_id.lower(),
            field.hint.lower(),
            field.name.lower()
        ])
        
        return self._match_patterns(identifiers)
    
    def _match_patterns(self, identifiers: str) -> str:
        """Match identifiers against field patterns"""
        for field_type, patterns in self.FIELD_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, identifiers, re.IGNORECASE):
                    return field_type
        return 'default'
    
    def generate_value(self, field: MobileInputField, platform: str = 'android') -> str:
        """Generate appropriate test value for a mobile field"""
        if platform == 'android':
            field_type = self.detect_field_type_android(field)
        else:
            field_type = self.detect_field_type_ios(field)
        
        base_value = self.TEST_DATA.get(field_type, self.TEST_DATA['default'])
        
        # Make email/username unique
        if field_type == 'email':
            base_value = f"test_{self._random_suffix}@jarwis.ai"
        elif field_type == 'username':
            base_value = f"jarwis_tester_{self._random_suffix}"
        
        return base_value
    
    def generate_form_data(self, form: MobileForm) -> Dict[str, str]:
        """Generate complete form data for mobile form"""
        data = {}
        
        for field in form.fields:
            if not field.is_editable:
                continue
            
            value = self.generate_value(field, form.platform)
            data[field.name or field.resource_id or field.accessibility_id] = value
        
        return data
    
    def generate_attack_data(self, form: MobileForm, attack_type: str) -> List[Dict]:
        """Generate attack payloads for mobile form testing"""
        attack_sets = []
        payloads = self.ATTACK_PAYLOADS.get(attack_type, [])
        base_data = self.generate_form_data(form)
        
        for field in form.fields:
            if not field.is_editable:
                continue
            
            field_key = field.name or field.resource_id or field.accessibility_id
            
            for payload in payloads[:3]:
                attack_data = base_data.copy()
                attack_data[field_key] = payload
                attack_sets.append({
                    'data': attack_data,
                    'target_field': field_key,
                    'payload': payload,
                    'attack_type': attack_type
                })
        
        return attack_sets


class MobilePostMethodScanner:
    """
    Mobile POST Method Scanner for Android and iOS apps
    
    Features:
    - Discovers input screens and forms in mobile apps
    - Analyzes input fields using Android inputTypes / iOS accessibility
    - Generates intelligent test data
    - Captures POST request/response via Frida hooks or MITM proxy
    - Tests mobile API endpoints for vulnerabilities
    """
    
    DEFAULT_HEADERS = {
        'User-Agent': 'JarwisMobileScanner/1.0',
        'Accept': 'application/json',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    
    # Frida script for UI form discovery (Android)
    FRIDA_FORM_DISCOVERY_SCRIPT = '''
Java.perform(function() {
    // Find all EditText fields on current screen
    var EditText = Java.use('android.widget.EditText');
    var Button = Java.use('android.widget.Button');
    var Activity = Java.use('android.app.Activity');
    
    var fields = [];
    var buttons = [];
    
    // Hook to capture form submissions
    var classes = ['android.widget.EditText', 'androidx.appcompat.widget.AppCompatEditText'];
    
    classes.forEach(function(className) {
        try {
            var EditTextClass = Java.use(className);
            
            EditTextClass.getText.implementation = function() {
                var result = this.getText();
                var hint = this.getHint();
                var inputType = this.getInputType();
                var resourceId = '';
                
                try {
                    var id = this.getId();
                    if (id > 0) {
                        resourceId = this.getResources().getResourceEntryName(id);
                    }
                } catch(e) {}
                
                send({
                    type: 'form_field',
                    className: className,
                    text: result ? result.toString() : '',
                    hint: hint ? hint.toString() : '',
                    inputType: inputType,
                    resourceId: resourceId,
                    isPassword: (inputType & 128) != 0 || (inputType & 144) != 0
                });
                
                return result;
            };
        } catch(e) {}
    });
    
    // Hook button clicks to capture form submissions
    try {
        var View = Java.use('android.view.View');
        View.performClick.implementation = function() {
            var resourceId = '';
            try {
                var id = this.getId();
                if (id > 0) {
                    resourceId = this.getResources().getResourceEntryName(id);
                }
            } catch(e) {}
            
            send({
                type: 'button_click',
                resourceId: resourceId,
                className: this.getClass().getName()
            });
            
            return this.performClick();
        };
    } catch(e) {}
    
    send({type: 'form_discovery_ready'});
});
'''
    
    def __init__(self, config: dict = None, context = None, callback = None):
        self.config = config or {}
        self.context = context
        self.callback = callback
        self.data_generator = MobileFormDataGenerator()
        self.discovered_forms: List[MobileForm] = []
        self.captured_requests: List[MobilePostCapture] = []
        self.findings: List[MobileScanResult] = []
        self._finding_id = 0
        self._capture_id = 0
        
        # Platform detection
        self.platform = config.get('platform', 'android') if config else 'android'
    
    def log(self, log_type: str, message: str, details: str = None):
        """Log with callback"""
        if self.callback:
            try:
                self.callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    async def scan(self, endpoints: List[Dict] = None) -> List[MobileScanResult]:
        """Run the complete mobile POST method scan"""
        self.findings = []
        
        self.log('phase', '[MOBILE] Starting Mobile POST Method Scanner')
        
        # Phase 1: Build forms from discovered endpoints
        if endpoints:
            await self._build_forms_from_endpoints(endpoints)
        elif self.context:
            endpoints = getattr(self.context, 'endpoints', [])
            await self._build_forms_from_endpoints(endpoints)
        
        # Phase 2: Submit forms and capture traffic
        await self._submit_forms_and_capture()
        
        # Phase 3: Test for vulnerabilities
        await self._test_vulnerabilities()
        
        self.log('success', f'[OK] Mobile POST scan complete: {len(self.findings)} findings')
        
        return self.findings
    
    async def _build_forms_from_endpoints(self, endpoints: List[Dict]):
        """Build MobileForm objects from discovered API endpoints"""
        self.log('info', f'Building forms from {len(endpoints)} endpoints')
        
        for i, ep in enumerate(endpoints):
            if isinstance(ep, dict):
                method = ep.get('method', 'GET').upper()
                if method != 'POST':
                    continue
                
                url = ep.get('url', '')
                params = ep.get('params', {})
                headers = ep.get('headers', {})
                
                # Create fields from params
                fields = []
                for name, value in params.items():
                    field = MobileInputField(
                        name=name,
                        field_type='text',
                        resource_id=name,
                        is_editable=True
                    )
                    fields.append(field)
                
                # Detect form type from URL
                form_type = self._detect_form_type_from_url(url)
                
                form = MobileForm(
                    id=f"mobile_form_{i}",
                    screen_name=form_type,
                    api_endpoint=url,
                    method='POST',
                    fields=fields,
                    form_type=form_type,
                    platform=self.platform
                )
                
                self.discovered_forms.append(form)
        
        self.log('info', f'Built {len(self.discovered_forms)} POST forms')
    
    def _detect_form_type_from_url(self, url: str) -> str:
        """Detect form type from API endpoint URL"""
        url_lower = url.lower()
        
        if any(x in url_lower for x in ['/login', '/signin', '/auth']):
            return 'login'
        elif any(x in url_lower for x in ['/register', '/signup', '/create-account']):
            return 'register'
        elif any(x in url_lower for x in ['/profile', '/user', '/account', '/settings']):
            return 'profile'
        elif any(x in url_lower for x in ['/payment', '/checkout', '/order', '/pay']):
            return 'payment'
        elif any(x in url_lower for x in ['/otp', '/verify', '/confirm']):
            return 'otp'
        elif any(x in url_lower for x in ['/search', '/query', '/find']):
            return 'search'
        elif any(x in url_lower for x in ['/upload', '/file', '/image', '/photo']):
            return 'upload'
        elif any(x in url_lower for x in ['/contact', '/feedback', '/message']):
            return 'contact'
        else:
            return 'api'
    
    async def _submit_forms_and_capture(self):
        """Submit discovered forms and capture request/response"""
        self.log('info', f'Submitting {len(self.discovered_forms)} forms...')
        
        async with aiohttp.ClientSession(headers=self.DEFAULT_HEADERS) as session:
            for form in self.discovered_forms[:50]:
                try:
                    await self._submit_form(session, form)
                except Exception as e:
                    logger.debug(f"Form submission failed: {e}")
                
                await asyncio.sleep(0.1)
    
    async def _submit_form(self, session: aiohttp.ClientSession, form: MobileForm):
        """Submit a single form and capture traffic"""
        # Generate form data
        form_data = self.data_generator.generate_form_data(form)
        
        if not form_data:
            form_data = self._get_default_data_for_type(form.form_type)
        
        self._capture_id += 1
        capture = MobilePostCapture(
            id=f"MOBILE-POST-{self._capture_id:04d}",
            url=form.api_endpoint,
            form_data=form_data,
            platform=self.platform,
            screen_name=form.screen_name,
            timestamp=datetime.now().isoformat()
        )
        
        try:
            headers = dict(self.DEFAULT_HEADERS)
            headers['Content-Type'] = 'application/json'
            
            async with session.post(
                form.api_endpoint,
                json=form_data,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=15),
                ssl=False
            ) as response:
                capture.response_status = response.status
                capture.response_headers = dict(response.headers)
                capture.response_body = await response.text()
                capture.request_headers = headers
                capture.request_body = json.dumps(form_data)
                capture.content_type = 'application/json'
                
                self.captured_requests.append(capture)
                
                self.log('info', f'Captured POST to {form.api_endpoint}: {response.status}')
                
        except Exception as e:
            logger.debug(f"POST request failed: {e}")
            capture.response_status = 0
            self.captured_requests.append(capture)
    
    def _get_default_data_for_type(self, form_type: str) -> Dict[str, str]:
        """Get default data based on form type"""
        data_map = {
            'login': {'email': 'test@jarwis.ai', 'password': 'JarwisTest@123'},
            'register': {'email': 'test@jarwis.ai', 'password': 'JarwisTest@123', 'name': 'Jarwis Tester', 'phone': '+1234567890'},
            'profile': {'name': 'Jarwis Tester', 'email': 'test@jarwis.ai', 'phone': '+1234567890'},
            'payment': {'amount': '100', 'card_number': '4111111111111111', 'cvv': '123', 'expiry': '12/30'},
            'otp': {'otp': '123456', 'code': '123456'},
            'search': {'query': 'test', 'q': 'test'},
            'upload': {'title': 'Test', 'description': 'Test upload'},
            'contact': {'name': 'Jarwis', 'email': 'test@jarwis.ai', 'message': 'Test message'},
            'api': {'data': 'test', 'action': 'test'}
        }
        return data_map.get(form_type, data_map['api'])
    
    async def _test_vulnerabilities(self):
        """Test mobile API endpoints for vulnerabilities"""
        self.log('info', 'Testing mobile POST endpoints for vulnerabilities...')
        
        async with aiohttp.ClientSession(headers=self.DEFAULT_HEADERS) as session:
            for form in self.discovered_forms[:30]:
                # Test SQL Injection
                await self._test_sqli(session, form)
                
                # Test NoSQL Injection (common in mobile backends)
                await self._test_nosql(session, form)
                
                # Test IDOR
                await self._test_idor(session, form)
                
                # Check for sensitive data exposure
                await self._check_sensitive_data(form)
                
                await asyncio.sleep(0.05)
    
    async def _test_sqli(self, session: aiohttp.ClientSession, form: MobileForm):
        """Test for SQL injection"""
        attack_sets = self.data_generator.generate_attack_data(form, 'sqli')
        
        for attack in attack_sets[:3]:
            try:
                async with session.post(
                    form.api_endpoint,
                    json=attack['data'],
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    content = await response.text()
                    
                    sql_errors = ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'ora-']
                    
                    if any(err in content.lower() for err in sql_errors):
                        self._add_finding(
                            category="M1",
                            severity="critical",
                            title=f"SQL Injection in Mobile API",
                            description=f"SQL error in field '{attack['target_field']}'",
                            url=form.api_endpoint,
                            parameter=attack['target_field'],
                            evidence=f"Payload: {attack['payload']}",
                            poc=f"POST {form.api_endpoint}\nData: {json.dumps(attack['data'])}",
                            remediation="Use parameterized queries.",
                            cwe_id="CWE-89"
                        )
                        return
            except:
                pass
    
    async def _test_nosql(self, session: aiohttp.ClientSession, form: MobileForm):
        """Test for NoSQL injection (MongoDB, etc.)"""
        attack_sets = self.data_generator.generate_attack_data(form, 'nosql')
        
        for attack in attack_sets[:2]:
            try:
                async with session.post(
                    form.api_endpoint,
                    json=attack['data'],
                    timeout=aiohttp.ClientTimeout(total=10),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for unexpected success or data
                        if len(content) > 100:
                            self._add_finding(
                                category="M1",
                                severity="high",
                                title=f"Potential NoSQL Injection",
                                description=f"NoSQL operator accepted in field '{attack['target_field']}'",
                                url=form.api_endpoint,
                                parameter=attack['target_field'],
                                evidence=f"Payload: {attack['payload']}",
                                remediation="Sanitize MongoDB operators. Use allowlists for query fields.",
                                cwe_id="CWE-943"
                            )
                            return
            except:
                pass
    
    async def _test_idor(self, session: aiohttp.ClientSession, form: MobileForm):
        """Test for IDOR in mobile APIs"""
        # Check for ID parameters in endpoint
        id_patterns = [r'/(\d+)', r'[?&]id=(\d+)', r'[?&]user_id=(\d+)']
        
        for pattern in id_patterns:
            match = re.search(pattern, form.api_endpoint)
            if match:
                original_id = match.group(1)
                
                for test_id in ['1', '0', str(int(original_id) + 1)]:
                    test_url = re.sub(pattern, match.group(0).replace(original_id, test_id), form.api_endpoint)
                    
                    try:
                        form_data = self.data_generator.generate_form_data(form)
                        
                        async with session.post(
                            test_url,
                            json=form_data,
                            timeout=aiohttp.ClientTimeout(total=10),
                            ssl=False
                        ) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                if len(content) > 50 and 'error' not in content.lower()[:100]:
                                    self._add_finding(
                                        category="M6",
                                        severity="high",
                                        title=f"IDOR in Mobile API",
                                        description=f"ID manipulation accepted: {original_id} -> {test_id}",
                                        url=test_url,
                                        evidence=f"Modified ID returned valid data",
                                        remediation="Implement proper authorization checks.",
                                        cwe_id="CWE-639"
                                    )
                                    return
                    except:
                        pass
    
    async def _check_sensitive_data(self, form: MobileForm):
        """Check captured responses for sensitive data"""
        for capture in self.captured_requests:
            if capture.url != form.api_endpoint:
                continue
            
            patterns = [
                (r'password["\s:]+["\']?([^\s"\']{4,})', 'Password exposed'),
                (r'token["\s:]+["\']?([a-zA-Z0-9_-]{20,})', 'Token exposed'),
                (r'secret["\s:]+["\']?([^\s"\']{8,})', 'Secret exposed'),
                (r'private_key', 'Private key reference'),
                (r'firebase.*["\']([a-zA-Z0-9_-]{30,})["\']', 'Firebase key exposed'),
            ]
            
            for pattern, desc in patterns:
                if re.search(pattern, capture.response_body, re.IGNORECASE):
                    self._add_finding(
                        category="M2",
                        severity="high",
                        title=f"Sensitive Data Exposure: {desc}",
                        description=f"{desc} in mobile API response",
                        url=capture.url,
                        evidence="Pattern matched in response",
                        remediation="Never return sensitive data in API responses.",
                        cwe_id="CWE-200"
                    )
    
    def _add_finding(self, **kwargs):
        """Add a vulnerability finding"""
        self._finding_id += 1
        finding = MobileScanResult(
            id=f"MOBILE-POST-{self._finding_id:04d}",
            method="POST",
            **kwargs
        )
        self.findings.append(finding)
    
    def get_captured_traffic(self) -> List[Dict]:
        """Get all captured POST request/response pairs"""
        traffic = []
        for capture in self.captured_requests:
            traffic.append({
                'id': capture.id,
                'url': capture.url,
                'method': 'POST',
                'platform': capture.platform,
                'screen': capture.screen_name,
                'request': {
                    'headers': capture.request_headers,
                    'body': capture.request_body,
                    'content_type': capture.content_type,
                    'form_data': capture.form_data
                },
                'response': {
                    'status': capture.response_status,
                    'headers': capture.response_headers,
                    'body': capture.response_body[:2000] if capture.response_body else ''
                },
                'timestamp': capture.timestamp
            })
        return traffic
    
    def get_discovered_forms(self) -> List[Dict]:
        """Get all discovered mobile forms"""
        return [
            {
                'id': form.id,
                'screen': form.screen_name,
                'endpoint': form.api_endpoint,
                'type': form.form_type,
                'platform': form.platform,
                'fields': [
                    {
                        'name': f.name or f.resource_id or f.accessibility_id,
                        'type': f.field_type,
                        'is_password': f.is_password
                    }
                    for f in form.fields
                ]
            }
            for form in self.discovered_forms
        ]
