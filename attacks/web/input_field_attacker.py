"""
InputFieldAttacker - Unified Input Field Vulnerability Scanner

Extends BaseAttackScanner to test ALL input fields (forms, search boxes,
login pages) with comprehensive payloads for multiple vulnerability types.
Operates through MITM for complete traffic capture.
"""

import asyncio
import logging
import re
import time
from typing import List, Dict, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from attacks.web.base_attack_scanner import BaseAttackScanner, AttackResult
from attacks.payloads import get_payload_manager, PayloadCategory
from core.http_helper import JarwisHTTPClient

logger = logging.getLogger(__name__)


class VulnerabilityType(Enum):
    """Types of vulnerabilities to test."""
    SQLI = "sql_injection"
    XSS = "cross_site_scripting"
    SSTI = "server_side_template_injection"
    CMDI = "command_injection"
    LFI = "local_file_inclusion"
    NOSQL = "nosql_injection"
    HTML_INJECTION = "html_injection"
    OPEN_REDIRECT = "open_redirect"


@dataclass
class InputField:
    """Represents an input field to test."""
    name: str
    field_type: str  # text, password, email, search, textarea, hidden, etc.
    form_action: str
    form_method: str
    current_value: str = ""
    required: bool = False
    max_length: Optional[int] = None
    pattern: Optional[str] = None
    other_fields: Dict[str, str] = field(default_factory=dict)


@dataclass
class FormContext:
    """Context about a form for attack planning."""
    url: str
    action: str
    method: str
    fields: List[InputField]
    is_login_form: bool = False
    is_search_form: bool = False
    is_registration_form: bool = False
    csrf_token: Optional[str] = None
    enctype: str = "application/x-www-form-urlencoded"


class InputFieldAttacker(BaseAttackScanner):
    """
    Comprehensive input field vulnerability scanner.
    
    Tests all discovered input fields with contextually appropriate payloads:
    - Login forms: Auth bypass SQLi, password-based XSS
    - Search forms: All injection types (SQLi, XSS, SSTI, CMDi)
    - Registration forms: XSS in stored fields, SQLi
    - Generic inputs: XSS, SQLi, template injection
    
    Features:
    - MITM-first architecture (all traffic captured)
    - Payload library integration (2000+ payloads)
    - Smart payload selection based on field context
    - Rate limiting to avoid detection
    - Response analysis for vulnerability confirmation
    """
    
    scanner_name = "input_field_attacker"
    scanner_description = "Comprehensive input field vulnerability scanner"
    
    # Detection patterns for various vulnerability types
    SQLI_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"ORA-\d{5}",
        r"Oracle.*Driver",
        r"SQL Server.*Driver",
        r"SQLite.*error",
        r"SQLSTATE\[\w+\]",
        r"syntax error.*statement",
        r"Unclosed quotation mark",
        r"quoted string not properly terminated",
        r"mysql_fetch_array\(\)",
        r"You have an error in your SQL syntax",
        r"supplied argument is not a valid MySQL",
    ]
    
    XSS_REFLECTION_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<img[^>]*onerror",
        r"<svg[^>]*onload",
        r"<body[^>]*onload",
        r"alert\s*\(",
        r"confirm\s*\(",
        r"prompt\s*\(",
        r"document\.cookie",
        r"document\.domain",
    ]
    
    SSTI_DETECTION_PATTERNS = [
        r"49",  # 7*7
        r"\{\{.*config.*\}\}",
        r"jinja2",
        r"twig",
        r"freemarker",
        r"velocity",
        r"__class__",
        r"__mro__",
        r"__subclasses__",
        r"Exception in template",
        r"TemplateSyntaxError",
    ]
    
    CMDI_PATTERNS = [
        r"uid=\d+.*gid=\d+",  # id command output
        r"root:.*:0:0:",  # /etc/passwd
        r"(Linux|Darwin|Windows)",  # uname/OS detection
        r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b.*\bnetmask\b",  # ifconfig
        r"Volume Serial Number",  # Windows dir
        r"Directory of",  # Windows dir
    ]
    
    LFI_PATTERNS = [
        r"root:.*:0:0:",  # /etc/passwd
        r"\[boot loader\]",  # Windows boot.ini
        r"\[fonts\]",  # Windows win.ini
        r"\[extensions\]",  # Windows win.ini
        r"<\?php",  # PHP source code
    ]
    
    def __init__(
        self,
        http_client: JarwisHTTPClient,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize InputFieldAttacker.
        
        Args:
            http_client: MITM-aware HTTP client
            config: Scanner configuration
        """
        super().__init__(http_client, config)
        
        self.payload_manager = get_payload_manager()
        self.tested_combinations: Set[str] = set()
        self.vulnerabilities_found: List[AttackResult] = []
        
        # Configuration
        self.config = config or {}
        self.max_payloads_per_type = self.config.get("max_payloads_per_type", 50)
        self.delay_between_requests = self.config.get("delay_ms", 100) / 1000.0
        self.test_authenticated = self.config.get("test_authenticated", True)
        self.follow_redirects = self.config.get("follow_redirects", True)
        self.timeout = self.config.get("timeout", 30)
        
        # Compile patterns
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Pre-compile regex patterns for performance."""
        self.sqli_patterns_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.SQLI_ERROR_PATTERNS
        ]
        self.xss_patterns_compiled = [
            re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.XSS_REFLECTION_PATTERNS
        ]
        self.ssti_patterns_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.SSTI_DETECTION_PATTERNS
        ]
        self.cmdi_patterns_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.CMDI_PATTERNS
        ]
        self.lfi_patterns_compiled = [
            re.compile(p, re.IGNORECASE) for p in self.LFI_PATTERNS
        ]
    
    async def scan_form(
        self,
        form: FormContext,
        vuln_types: Optional[List[VulnerabilityType]] = None
    ) -> List[AttackResult]:
        """
        Scan a form for vulnerabilities.
        
        Args:
            form: Form context with fields and metadata
            vuln_types: Specific vulnerability types to test (None = all applicable)
            
        Returns:
            List of discovered vulnerabilities
        """
        results = []
        
        # Determine which vulnerability types to test
        if vuln_types is None:
            vuln_types = self._select_vuln_types(form)
        
        logger.info(
            f"Scanning form at {form.action} with {len(form.fields)} fields "
            f"for {[v.value for v in vuln_types]}"
        )
        
        for field_obj in form.fields:
            # Skip non-injectable fields
            if field_obj.field_type in ["submit", "button", "image", "reset", "file"]:
                continue
            
            for vuln_type in vuln_types:
                field_results = await self._test_field(form, field_obj, vuln_type)
                results.extend(field_results)
                
                # Add delay between tests
                if self.delay_between_requests > 0:
                    await asyncio.sleep(self.delay_between_requests)
        
        return results
    
    def _select_vuln_types(self, form: FormContext) -> List[VulnerabilityType]:
        """Select appropriate vulnerability types based on form context."""
        types = [VulnerabilityType.XSS]  # Always test XSS
        
        if form.is_login_form:
            types.extend([
                VulnerabilityType.SQLI,
                VulnerabilityType.NOSQL,
            ])
        elif form.is_search_form:
            types.extend([
                VulnerabilityType.SQLI,
                VulnerabilityType.SSTI,
                VulnerabilityType.CMDI,
                VulnerabilityType.LFI,
            ])
        elif form.is_registration_form:
            types.extend([
                VulnerabilityType.SQLI,
                VulnerabilityType.HTML_INJECTION,
            ])
        else:
            # Generic form - test common types
            types.extend([
                VulnerabilityType.SQLI,
                VulnerabilityType.SSTI,
            ])
        
        return types
    
    async def _test_field(
        self,
        form: FormContext,
        field_obj: InputField,
        vuln_type: VulnerabilityType
    ) -> List[AttackResult]:
        """
        Test a specific field for a specific vulnerability type.
        
        Args:
            form: The form context
            field_obj: The field to test
            vuln_type: The vulnerability type to test for
            
        Returns:
            List of discovered vulnerabilities
        """
        results = []
        
        # Get payloads for this vulnerability type and field context
        payloads = self._get_payloads_for_field(field_obj, vuln_type)
        
        if not payloads:
            return results
        
        # Generate unique key to avoid duplicate testing
        test_key = f"{form.action}:{field_obj.name}:{vuln_type.value}"
        if test_key in self.tested_combinations:
            return results
        self.tested_combinations.add(test_key)
        
        logger.debug(
            f"Testing field '{field_obj.name}' for {vuln_type.value} "
            f"with {len(payloads)} payloads"
        )
        
        for payload in payloads:
            try:
                result = await self._send_payload_and_analyze(
                    form, field_obj, payload, vuln_type
                )
                if result:
                    results.append(result)
                    logger.warning(
                        f"VULNERABILITY FOUND: {vuln_type.value} in field "
                        f"'{field_obj.name}' at {form.action}"
                    )
                    # Optional: Stop after first finding per field/type
                    if self.config.get("stop_on_first", False):
                        break
                        
            except Exception as e:
                logger.debug(f"Error testing payload: {e}")
            
            # Rate limiting
            await asyncio.sleep(self.delay_between_requests)
        
        return results
    
    def _get_payloads_for_field(
        self,
        field_obj: InputField,
        vuln_type: VulnerabilityType
    ) -> List[str]:
        """Get contextually appropriate payloads for a field."""
        limit = self.max_payloads_per_type
        
        if vuln_type == VulnerabilityType.SQLI:
            # For password fields, use auth bypass payloads
            if field_obj.field_type == "password" or "pass" in field_obj.name.lower():
                return self.payload_manager.get_auth_bypass_payloads(limit=limit)
            # For ID-like fields, use numeric injection
            if any(x in field_obj.name.lower() for x in ["id", "uid", "num"]):
                return self.payload_manager.get_sqli_payloads(
                    types=["error_based", "union_based"], limit=limit
                )
            return self.payload_manager.get_sqli_payloads(limit=limit)
        
        elif vuln_type == VulnerabilityType.XSS:
            # For stored contexts, use all types
            # For reflected, focus on basic and filter bypass
            return self.payload_manager.get_xss_payloads(limit=limit)
        
        elif vuln_type == VulnerabilityType.SSTI:
            return self.payload_manager.get_ssti_payloads(limit=limit)
        
        elif vuln_type == VulnerabilityType.CMDI:
            return self.payload_manager.get_cmdi_payloads(limit=limit)
        
        elif vuln_type == VulnerabilityType.LFI:
            return self.payload_manager.get_lfi_payloads(limit=limit)
        
        elif vuln_type == VulnerabilityType.NOSQL:
            return self.payload_manager.get_nosql_payloads(limit=limit)
        
        elif vuln_type == VulnerabilityType.HTML_INJECTION:
            return self.payload_manager.get_xss_payloads(
                types=["html_injection"], limit=limit
            )
        
        return []
    
    async def _send_payload_and_analyze(
        self,
        form: FormContext,
        field_obj: InputField,
        payload: str,
        vuln_type: VulnerabilityType
    ) -> Optional[AttackResult]:
        """
        Send a payload and analyze the response.
        
        Args:
            form: Form context
            field_obj: Target field
            payload: The payload to send
            vuln_type: Expected vulnerability type
            
        Returns:
            AttackResult if vulnerable, None otherwise
        """
        # Build form data
        data = dict(field_obj.other_fields)
        data[field_obj.name] = payload
        
        # Add CSRF token if present
        if form.csrf_token:
            # Find CSRF field name (common patterns)
            csrf_names = ["csrf_token", "_token", "csrfmiddlewaretoken", "_csrf"]
            for name in csrf_names:
                if name not in data:
                    data[name] = form.csrf_token
                    break
        
        # Determine URL
        url = form.action if form.action.startswith("http") else urljoin(form.url, form.action)
        
        # Send request through MITM
        start_time = time.time()
        
        try:
            if form.method.upper() == "GET":
                response = await self.send_payload(
                    url=url,
                    method="GET",
                    params=data,
                    timeout=self.timeout
                )
            else:
                if form.enctype == "multipart/form-data":
                    response = await self.send_payload(
                        url=url,
                        method="POST",
                        files=data,
                        timeout=self.timeout
                    )
                else:
                    response = await self.send_payload(
                        url=url,
                        method="POST",
                        data=data,
                        timeout=self.timeout
                    )
        except Exception as e:
            logger.debug(f"Request failed: {e}")
            return None
        
        elapsed_time = time.time() - start_time
        response_text = response.text if hasattr(response, 'text') else str(response.content)
        
        # Analyze response based on vulnerability type
        is_vulnerable, evidence = self._analyze_response(
            response_text, 
            response.status_code if hasattr(response, 'status_code') else 200,
            elapsed_time,
            payload,
            vuln_type
        )
        
        if is_vulnerable:
            return AttackResult(
                scanner_name=self.scanner_name,
                vulnerability_type=vuln_type.value,
                severity=self._get_severity(vuln_type),
                url=url,
                parameter=field_obj.name,
                payload=payload,
                evidence=evidence,
                request_data={
                    "method": form.method,
                    "data": data,
                    "field_type": field_obj.field_type,
                },
                response_snippet=response_text[:500] if response_text else "",
                confidence=0.8,
                remediation=self._get_remediation(vuln_type),
            )
        
        return None
    
    def _analyze_response(
        self,
        response_text: str,
        status_code: int,
        elapsed_time: float,
        payload: str,
        vuln_type: VulnerabilityType
    ) -> Tuple[bool, str]:
        """
        Analyze response to determine if vulnerability exists.
        
        Returns:
            Tuple of (is_vulnerable, evidence)
        """
        if vuln_type == VulnerabilityType.SQLI:
            # Check for SQL error patterns
            for pattern in self.sqli_patterns_compiled:
                match = pattern.search(response_text)
                if match:
                    return True, f"SQL error detected: {match.group()}"
            
            # Time-based detection
            if "sleep" in payload.lower() or "waitfor" in payload.lower():
                if elapsed_time > 4.5:  # Expected 5 second delay
                    return True, f"Time-based SQLi detected (response time: {elapsed_time:.2f}s)"
        
        elif vuln_type == VulnerabilityType.XSS:
            # Check if payload is reflected unencoded
            if payload in response_text:
                # Verify it's in a potentially dangerous context
                for pattern in self.xss_patterns_compiled:
                    if pattern.search(response_text):
                        return True, f"XSS payload reflected: {payload[:50]}"
        
        elif vuln_type == VulnerabilityType.SSTI:
            # Check for template evaluation (7*7=49)
            if "{{7*7}}" in payload or "${7*7}" in payload:
                if "49" in response_text and "7*7" not in response_text:
                    return True, "Template expression evaluated (7*7=49)"
            
            for pattern in self.ssti_patterns_compiled:
                if pattern.search(response_text):
                    return True, f"SSTI indicator detected"
        
        elif vuln_type == VulnerabilityType.CMDI:
            for pattern in self.cmdi_patterns_compiled:
                match = pattern.search(response_text)
                if match:
                    return True, f"Command execution detected: {match.group()[:50]}"
            
            # Time-based
            if "sleep" in payload.lower():
                if elapsed_time > 4.5:
                    return True, f"Time-based CMDi detected (response time: {elapsed_time:.2f}s)"
        
        elif vuln_type == VulnerabilityType.LFI:
            for pattern in self.lfi_patterns_compiled:
                match = pattern.search(response_text)
                if match:
                    return True, f"File content detected: {match.group()[:50]}"
        
        elif vuln_type == VulnerabilityType.NOSQL:
            # Look for authentication bypass or data leakage
            if status_code == 200 and any(x in payload for x in ["$ne", "$gt", "$regex"]):
                # This needs context-aware detection
                pass
        
        elif vuln_type == VulnerabilityType.HTML_INJECTION:
            # Check for injected HTML elements
            if "<" in payload and ">" in payload:
                html_tags = re.findall(r'<(\w+)[^>]*>', payload)
                for tag in html_tags:
                    if f"<{tag}" in response_text:
                        return True, f"HTML tag reflected: <{tag}>"
        
        return False, ""
    
    def _get_severity(self, vuln_type: VulnerabilityType) -> str:
        """Get severity level for vulnerability type."""
        severity_map = {
            VulnerabilityType.SQLI: "critical",
            VulnerabilityType.CMDI: "critical",
            VulnerabilityType.LFI: "high",
            VulnerabilityType.SSTI: "critical",
            VulnerabilityType.XSS: "high",
            VulnerabilityType.NOSQL: "high",
            VulnerabilityType.HTML_INJECTION: "medium",
            VulnerabilityType.OPEN_REDIRECT: "medium",
        }
        return severity_map.get(vuln_type, "medium")
    
    def _get_remediation(self, vuln_type: VulnerabilityType) -> str:
        """Get remediation advice for vulnerability type."""
        remediation_map = {
            VulnerabilityType.SQLI: (
                "Use parameterized queries or prepared statements. "
                "Never concatenate user input directly into SQL queries. "
                "Implement input validation and use an ORM."
            ),
            VulnerabilityType.XSS: (
                "Encode all user input before rendering in HTML context. "
                "Use Content-Security-Policy headers. "
                "Implement input validation and sanitization."
            ),
            VulnerabilityType.SSTI: (
                "Never pass user input directly to template engines. "
                "Use sandboxed template environments. "
                "Disable dangerous template features."
            ),
            VulnerabilityType.CMDI: (
                "Avoid system calls with user input. "
                "Use safe APIs instead of shell commands. "
                "If unavoidable, strictly whitelist allowed characters."
            ),
            VulnerabilityType.LFI: (
                "Never use user input in file paths directly. "
                "Use a whitelist of allowed files. "
                "Implement proper access controls."
            ),
            VulnerabilityType.NOSQL: (
                "Use ODM/ORM properly. "
                "Validate and sanitize all user input. "
                "Avoid using $where with user input."
            ),
            VulnerabilityType.HTML_INJECTION: (
                "Encode HTML entities in user input. "
                "Use Content-Security-Policy. "
                "Sanitize input before storage."
            ),
        }
        return remediation_map.get(vuln_type, "Implement proper input validation and encoding.")
    
    async def scan_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: Optional[str] = None,
        **kwargs
    ) -> List[AttackResult]:
        """
        Scan a captured HTTP request for vulnerabilities.
        
        This method is called by the orchestrator for each captured request.
        
        Args:
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body
            
        Returns:
            List of discovered vulnerabilities
        """
        results = []
        
        # Parse URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Test URL parameters
        for param_name, values in params.items():
            for vuln_type in [VulnerabilityType.SQLI, VulnerabilityType.XSS]:
                field = InputField(
                    name=param_name,
                    field_type="text",
                    form_action=url.split("?")[0],
                    form_method="GET",
                    current_value=values[0] if values else "",
                    other_fields={k: v[0] for k, v in params.items() if k != param_name}
                )
                
                form = FormContext(
                    url=url,
                    action=url.split("?")[0],
                    method="GET",
                    fields=[field]
                )
                
                field_results = await self._test_field(form, field, vuln_type)
                results.extend(field_results)
        
        # Test POST body if present
        if body and method == "POST":
            content_type = headers.get("Content-Type", "")
            
            if "application/x-www-form-urlencoded" in content_type:
                body_params = parse_qs(body)
                for param_name, values in body_params.items():
                    for vuln_type in [VulnerabilityType.SQLI, VulnerabilityType.XSS]:
                        field = InputField(
                            name=param_name,
                            field_type="text",
                            form_action=url,
                            form_method="POST",
                            current_value=values[0] if values else "",
                            other_fields={k: v[0] for k, v in body_params.items() if k != param_name}
                        )
                        
                        form = FormContext(
                            url=url,
                            action=url,
                            method="POST",
                            fields=[field]
                        )
                        
                        field_results = await self._test_field(form, field, vuln_type)
                        results.extend(field_results)
        
        return results
    
    def get_payloads(self) -> List[str]:
        """Get all payloads (for base class compatibility)."""
        all_payloads = []
        all_payloads.extend(self.payload_manager.get_sqli_payloads(limit=100))
        all_payloads.extend(self.payload_manager.get_xss_payloads(limit=100))
        return all_payloads
    
    def detect_vulnerability(self, response: Any, payload: str) -> bool:
        """Detect vulnerability (for base class compatibility)."""
        if hasattr(response, 'text'):
            text = response.text
        else:
            text = str(response)
        
        # Quick check for common vulnerability indicators
        for pattern in self.sqli_patterns_compiled:
            if pattern.search(text):
                return True
        
        if payload in text:
            for pattern in self.xss_patterns_compiled:
                if pattern.search(text):
                    return True
        
        return False
