"""
JARWIS AGI PEN TEST - Intelligent Form Filler
==============================================

Generates contextual test data for form fields based on field names, types,
and patterns. Handles CSRF token extraction and multi-step form detection.

This is critical for the crawl phase to discover POST endpoints by actually
submitting forms with realistic test data.
"""

import logging
import random
import string
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


@dataclass
class FormField:
    """Represents a discovered form field"""
    name: str
    field_type: str  # text, email, password, number, tel, date, file, hidden, etc.
    selector: str  # CSS selector to locate the field
    required: bool = False
    max_length: Optional[int] = None
    min_length: Optional[int] = None
    pattern: Optional[str] = None
    placeholder: Optional[str] = None
    current_value: Optional[str] = None
    options: List[str] = field(default_factory=list)  # For select/radio/checkbox


@dataclass  
class FormData:
    """Complete form information for submission"""
    action: str
    method: str
    fields: List[FormField]
    enctype: str = "application/x-www-form-urlencoded"
    submit_selector: Optional[str] = None
    csrf_token_name: Optional[str] = None
    csrf_token_value: Optional[str] = None
    is_login_form: bool = False
    is_search_form: bool = False
    is_registration_form: bool = False
    is_file_upload: bool = False


class FormFiller:
    """
    Intelligent form filler that generates contextual test data.
    
    Features:
    - Field name/type pattern matching for appropriate data
    - CSRF token detection and extraction
    - Multi-step form awareness
    - Rate limiting support
    - Consistent test data generation (reproducible)
    """
    
    # Test data patterns
    TEST_EMAIL = "jarwis.scanner@test-security.com"
    TEST_PHONE = "+1-555-123-4567"
    TEST_PASSWORD = "JarwisTest123!@#"
    TEST_USERNAME = "jarwis_test_user"
    TEST_NAME = "Jarwis Security"
    TEST_FIRST_NAME = "Jarwis"
    TEST_LAST_NAME = "Scanner"
    TEST_ADDRESS = "123 Security Lane"
    TEST_CITY = "CyberCity"
    TEST_STATE = "CA"
    TEST_ZIP = "90210"
    TEST_COUNTRY = "United States"
    TEST_COMPANY = "Jarwis Security Inc"
    TEST_WEBSITE = "https://jarwis-security.test"
    TEST_CREDIT_CARD = "4111111111111111"  # Standard test card
    TEST_CVV = "123"
    TEST_SSN = "000-00-0000"  # Invalid SSN pattern
    
    # Common CSRF token field names
    CSRF_FIELD_NAMES = [
        'csrf', 'csrf_token', 'csrftoken', '_csrf', '__csrf',
        'csrfmiddlewaretoken', '_token', 'authenticity_token',
        'xsrf', 'xsrf_token', '_xsrf', '__RequestVerificationToken',
        'antiforgery', '__antiforgery', 'formtoken', 'form_token',
        'security_token', 'secure_token', 'verification_token'
    ]
    
    # Field patterns for smart data generation
    FIELD_PATTERNS = {
        # Email patterns
        r'(e[\-_]?mail|email|e_mail)': 'email',
        # Phone patterns
        r'(phone|tel|mobile|cell|fax)': 'phone',
        # Password patterns
        r'(pass|pwd|password|passwd|secret)': 'password',
        # Username patterns
        r'(user|uname|username|login|account)': 'username',
        # Name patterns
        r'(first[\-_]?name|fname|given[\-_]?name)': 'first_name',
        r'(last[\-_]?name|lname|surname|family[\-_]?name)': 'last_name',
        r'(full[\-_]?name|name|display[\-_]?name)': 'full_name',
        # Address patterns
        r'(address|street|addr|line1)': 'address',
        r'(city|town|locality)': 'city',
        r'(state|province|region)': 'state',
        r'(zip|postal|postcode|pin[\-_]?code)': 'zip',
        r'(country|nation)': 'country',
        # Number patterns
        r'(amount|price|cost|total|quantity|qty)': 'amount',
        r'(age|years)': 'age',
        # Date patterns
        r'(date|dob|birth|birthday)': 'date',
        r'(start[\-_]?date|from[\-_]?date|begin)': 'start_date',
        r'(end[\-_]?date|to[\-_]?date|until)': 'end_date',
        # Credit card patterns
        r'(card|cc|credit|debit)[\-_]?(num|number)?': 'credit_card',
        r'(cvv|cvc|csv|security[\-_]?code)': 'cvv',
        r'(expir|exp[\-_]?(date|month|year))': 'expiry',
        # Search patterns
        r'(search|query|q|keyword|term|find)': 'search',
        # URL patterns
        r'(url|link|website|homepage|site)': 'url',
        # Company patterns
        r'(company|organization|org|business|employer)': 'company',
        # Message/text patterns
        r'(message|comment|feedback|description|content|text|body|note)': 'text',
        # SSN patterns
        r'(ssn|social|tax[\-_]?id)': 'ssn',
    }
    
    def __init__(self, seed: Optional[int] = None):
        """
        Initialize the form filler.
        
        Args:
            seed: Random seed for reproducible test data
        """
        if seed is not None:
            random.seed(seed)
        
        self._session_id = self._generate_session_id()
    
    def _generate_session_id(self) -> str:
        """Generate a unique session ID for this form filler instance"""
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    
    def get_field_category(self, field_name: str, field_type: str = 'text') -> str:
        """
        Determine the category of a field based on its name and type.
        
        Args:
            field_name: The name/id of the field
            field_type: HTML input type
            
        Returns:
            Category string for appropriate data generation
        """
        field_name_lower = field_name.lower() if field_name else ''
        
        # First check HTML type
        if field_type == 'email':
            return 'email'
        elif field_type == 'password':
            return 'password'
        elif field_type == 'tel':
            return 'phone'
        elif field_type == 'number':
            return 'number'
        elif field_type == 'date':
            return 'date'
        elif field_type == 'url':
            return 'url'
        elif field_type == 'file':
            return 'file'
        elif field_type == 'hidden':
            return 'hidden'
        
        # Then check field name patterns
        for pattern, category in self.FIELD_PATTERNS.items():
            if re.search(pattern, field_name_lower, re.IGNORECASE):
                return category
        
        # Default to generic text
        return 'text'
    
    def generate_value(
        self, 
        field_name: str, 
        field_type: str = 'text',
        max_length: Optional[int] = None,
        options: Optional[List[str]] = None
    ) -> str:
        """
        Generate an appropriate test value for a form field.
        
        Args:
            field_name: Name of the field
            field_type: HTML input type
            max_length: Maximum allowed length
            options: Available options for select/radio fields
            
        Returns:
            Generated test value
        """
        # If options are provided (select, radio), pick the first non-empty one
        if options and len(options) > 0:
            valid_options = [o for o in options if o and o.strip()]
            if valid_options:
                return valid_options[0]
        
        category = self.get_field_category(field_name, field_type)
        
        value = self._generate_by_category(category)
        
        # Truncate if max_length specified
        if max_length and len(value) > max_length:
            value = value[:max_length]
        
        return value
    
    def _generate_by_category(self, category: str) -> str:
        """Generate value based on category"""
        
        generators = {
            'email': lambda: self.TEST_EMAIL,
            'phone': lambda: self.TEST_PHONE,
            'password': lambda: self.TEST_PASSWORD,
            'username': lambda: f"{self.TEST_USERNAME}_{self._session_id}",
            'first_name': lambda: self.TEST_FIRST_NAME,
            'last_name': lambda: self.TEST_LAST_NAME,
            'full_name': lambda: self.TEST_NAME,
            'address': lambda: self.TEST_ADDRESS,
            'city': lambda: self.TEST_CITY,
            'state': lambda: self.TEST_STATE,
            'zip': lambda: self.TEST_ZIP,
            'country': lambda: self.TEST_COUNTRY,
            'company': lambda: self.TEST_COMPANY,
            'url': lambda: self.TEST_WEBSITE,
            'credit_card': lambda: self.TEST_CREDIT_CARD,
            'cvv': lambda: self.TEST_CVV,
            'ssn': lambda: self.TEST_SSN,
            'amount': lambda: str(random.randint(1, 999)),
            'number': lambda: str(random.randint(1, 100)),
            'age': lambda: str(random.randint(18, 65)),
            'date': lambda: self._generate_date(),
            'start_date': lambda: self._generate_date(days_offset=-30),
            'end_date': lambda: self._generate_date(days_offset=30),
            'expiry': lambda: self._generate_expiry(),
            'search': lambda: f"JARWIS_TEST_{self._session_id}",
            'text': lambda: f"JARWIS_SECURITY_TEST_{self._session_id}",
            'hidden': lambda: "",  # Don't modify hidden fields
            'file': lambda: "",  # File upload handled separately
        }
        
        generator = generators.get(category, lambda: f"test_{self._session_id}")
        return generator()
    
    def _generate_date(self, days_offset: int = 0) -> str:
        """Generate a date string in YYYY-MM-DD format"""
        target_date = datetime.now() + timedelta(days=days_offset)
        return target_date.strftime('%Y-%m-%d')
    
    def _generate_expiry(self) -> str:
        """Generate credit card expiry in MM/YY format"""
        future_date = datetime.now() + timedelta(days=365 * 2)
        return future_date.strftime('%m/%y')
    
    def is_csrf_field(self, field_name: str) -> bool:
        """Check if a field is a CSRF token field"""
        if not field_name:
            return False
        
        field_name_lower = field_name.lower()
        return any(csrf_name in field_name_lower for csrf_name in self.CSRF_FIELD_NAMES)
    
    def extract_csrf_token(self, form: FormData) -> Optional[Tuple[str, str]]:
        """
        Extract CSRF token from a form.
        
        Returns:
            Tuple of (token_name, token_value) or None
        """
        for field in form.fields:
            if self.is_csrf_field(field.name):
                if field.current_value:
                    return (field.name, field.current_value)
        return None
    
    def fill_form(self, form: FormData) -> Dict[str, str]:
        """
        Generate all values for a form.
        
        Args:
            form: FormData object with field information
            
        Returns:
            Dict mapping field selectors to values
        """
        values = {}
        
        for field in form.fields:
            # Skip CSRF fields - keep their existing values
            if self.is_csrf_field(field.name):
                if field.current_value:
                    values[field.selector] = field.current_value
                continue
            
            # Skip hidden fields unless they have specific patterns
            if field.field_type == 'hidden':
                if field.current_value:
                    values[field.selector] = field.current_value
                continue
            
            # Skip file inputs (handled separately)
            if field.field_type == 'file':
                continue
            
            # Generate appropriate value
            value = self.generate_value(
                field_name=field.name,
                field_type=field.field_type,
                max_length=field.max_length,
                options=field.options
            )
            
            if value:
                values[field.selector] = value
        
        return values
    
    def detect_form_type(self, form: FormData) -> str:
        """
        Detect the type of form (login, registration, search, etc.)
        
        Returns:
            Form type string
        """
        field_names = [f.name.lower() for f in form.fields if f.name]
        field_types = [f.field_type for f in form.fields]
        
        # Check for login form
        has_password = 'password' in field_types or any('pass' in n for n in field_names)
        has_username_or_email = any(
            any(p in n for p in ['user', 'email', 'login', 'uname']) 
            for n in field_names
        ) or 'email' in field_types
        
        if has_password and has_username_or_email and len(form.fields) <= 5:
            return 'login'
        
        # Check for registration form
        if has_password and any('confirm' in n or 'repeat' in n for n in field_names):
            return 'registration'
        
        # Check for search form
        if any(p in n for n in field_names for p in ['search', 'query', 'q', 'keyword']):
            return 'search'
        
        # Check for contact/feedback form
        if any(p in n for n in field_names for p in ['message', 'comment', 'feedback', 'subject']):
            return 'contact'
        
        # Check for checkout/payment form
        if any(p in n for n in field_names for p in ['card', 'credit', 'payment', 'billing']):
            return 'payment'
        
        # Check for file upload form
        if 'file' in field_types:
            return 'upload'
        
        return 'generic'
    
    def should_submit_form(self, form: FormData) -> bool:
        """
        Determine if a form should be submitted during crawling.
        
        Some forms (like logout, delete, cancel subscription) should be skipped.
        
        Returns:
            True if form should be submitted
        """
        # Check action URL for dangerous patterns
        dangerous_actions = [
            'logout', 'signout', 'sign-out', 'log-out',
            'delete', 'remove', 'unsubscribe', 'cancel',
            'deactivate', 'disable', 'terminate'
        ]
        
        action_lower = (form.action or '').lower()
        if any(pattern in action_lower for pattern in dangerous_actions):
            logger.debug(f"Skipping dangerous form action: {form.action}")
            return False
        
        # Check for delete/dangerous buttons
        if form.submit_selector:
            submit_lower = form.submit_selector.lower()
            if any(pattern in submit_lower for pattern in dangerous_actions):
                return False
        
        return True


class FormExtractor:
    """
    Extract detailed form information from a page using Playwright.
    """
    
    # JavaScript code to extract all forms with full details
    EXTRACT_FORMS_JS = '''() => {
        const forms = [];
        
        document.querySelectorAll('form').forEach((form, formIndex) => {
            const formData = {
                action: form.action || window.location.href,
                method: (form.method || 'GET').toUpperCase(),
                enctype: form.enctype || 'application/x-www-form-urlencoded',
                id: form.id || null,
                name: form.name || null,
                fields: [],
                submit_selector: null
            };
            
            // Extract all input fields
            form.querySelectorAll('input, textarea, select').forEach((input, inputIndex) => {
                const field = {
                    name: input.name || input.id || '',
                    field_type: input.type || (input.tagName === 'TEXTAREA' ? 'textarea' : 'text'),
                    selector: buildSelector(input, formIndex, inputIndex),
                    required: input.required || false,
                    max_length: input.maxLength > 0 ? input.maxLength : null,
                    min_length: input.minLength > 0 ? input.minLength : null,
                    pattern: input.pattern || null,
                    placeholder: input.placeholder || null,
                    current_value: input.value || '',
                    options: []
                };
                
                // Handle select options
                if (input.tagName === 'SELECT') {
                    field.field_type = 'select';
                    Array.from(input.options).forEach(opt => {
                        if (opt.value) {
                            field.options.push(opt.value);
                        }
                    });
                }
                
                // Handle radio/checkbox
                if (input.type === 'radio' || input.type === 'checkbox') {
                    field.current_value = input.checked ? input.value : '';
                }
                
                formData.fields.push(field);
            });
            
            // Find submit button
            const submitButton = form.querySelector('input[type="submit"], button[type="submit"], button:not([type])');
            if (submitButton) {
                formData.submit_selector = buildSubmitSelector(submitButton, formIndex);
            }
            
            forms.push(formData);
        });
        
        // Helper to build unique selector
        function buildSelector(el, formIndex, inputIndex) {
            if (el.id) {
                return '#' + CSS.escape(el.id);
            }
            if (el.name) {
                const formSelector = `form:nth-of-type(${formIndex + 1})`;
                return `${formSelector} [name="${el.name}"]`;
            }
            return `form:nth-of-type(${formIndex + 1}) ${el.tagName.toLowerCase()}:nth-of-type(${inputIndex + 1})`;
        }
        
        function buildSubmitSelector(el, formIndex) {
            if (el.id) {
                return '#' + CSS.escape(el.id);
            }
            const formSelector = `form:nth-of-type(${formIndex + 1})`;
            if (el.type === 'submit') {
                return `${formSelector} input[type="submit"]`;
            }
            return `${formSelector} button[type="submit"], ${formSelector} button:not([type])`;
        }
        
        return forms;
    }'''
    
    # JavaScript to find buttons outside forms (JavaScript click handlers)
    EXTRACT_BUTTONS_JS = '''() => {
        const buttons = [];
        
        // Find all clickable elements that might trigger AJAX
        const clickables = document.querySelectorAll(
            'button:not([type="submit"]):not(form button), ' +
            '[role="button"], ' +
            '[onclick], ' +
            'a[href="javascript:"], ' +
            'a[href="#"]:not([data-toggle]), ' +
            '.btn:not(form .btn), ' +
            '[class*="button"]:not(form [class*="button"])'
        );
        
        clickables.forEach((el, index) => {
            // Skip invisible elements
            if (el.offsetParent === null) return;
            
            // Skip elements that are likely navigation
            const text = (el.innerText || '').toLowerCase().trim();
            const skipPatterns = ['home', 'about', 'contact', 'login', 'logout', 'sign'];
            if (skipPatterns.some(p => text.startsWith(p))) return;
            
            buttons.push({
                selector: buildButtonSelector(el, index),
                text: text.slice(0, 50),
                tag: el.tagName,
                has_onclick: !!el.onclick || el.hasAttribute('onclick'),
                href: el.getAttribute('href') || null
            });
        });
        
        function buildButtonSelector(el, index) {
            if (el.id) {
                return '#' + CSS.escape(el.id);
            }
            if (el.className && typeof el.className === 'string') {
                const classes = el.className.split(' ').filter(c => c && !c.includes(':'));
                if (classes.length > 0) {
                    return el.tagName.toLowerCase() + '.' + classes.slice(0, 2).join('.');
                }
            }
            return `${el.tagName.toLowerCase()}:nth-of-type(${index + 1})`;
        }
        
        return buttons;
    }'''

    @staticmethod
    async def extract_forms(page) -> List[FormData]:
        """
        Extract all forms from a page.
        
        Args:
            page: Playwright page object
            
        Returns:
            List of FormData objects
        """
        try:
            raw_forms = await page.evaluate(FormExtractor.EXTRACT_FORMS_JS)
            
            forms = []
            for raw_form in raw_forms:
                fields = [
                    FormField(
                        name=f.get('name', ''),
                        field_type=f.get('field_type', 'text'),
                        selector=f.get('selector', ''),
                        required=f.get('required', False),
                        max_length=f.get('max_length'),
                        min_length=f.get('min_length'),
                        pattern=f.get('pattern'),
                        placeholder=f.get('placeholder'),
                        current_value=f.get('current_value'),
                        options=f.get('options', [])
                    )
                    for f in raw_form.get('fields', [])
                ]
                
                form = FormData(
                    action=raw_form.get('action', ''),
                    method=raw_form.get('method', 'GET'),
                    enctype=raw_form.get('enctype', 'application/x-www-form-urlencoded'),
                    fields=fields,
                    submit_selector=raw_form.get('submit_selector'),
                    is_file_upload=any(f.field_type == 'file' for f in fields)
                )
                
                forms.append(form)
            
            return forms
            
        except Exception as e:
            logger.error(f"Failed to extract forms: {e}")
            return []
    
    @staticmethod
    async def extract_buttons(page) -> List[Dict[str, Any]]:
        """
        Extract clickable buttons outside of forms (JS event handlers).
        
        Args:
            page: Playwright page object
            
        Returns:
            List of button information dicts
        """
        try:
            return await page.evaluate(FormExtractor.EXTRACT_BUTTONS_JS)
        except Exception as e:
            logger.error(f"Failed to extract buttons: {e}")
            return []


# Convenience function for quick form filling
def generate_form_data(field_name: str, field_type: str = 'text') -> str:
    """
    Quick helper to generate test data for a single field.
    
    Args:
        field_name: Name of the field
        field_type: HTML input type
        
    Returns:
        Generated test value
    """
    filler = FormFiller()
    return filler.generate_value(field_name, field_type)
