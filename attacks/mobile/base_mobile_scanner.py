"""
Jarwis AGI Pen Test - Base Mobile Scanner

Base class for all mobile security scanners.
Enforces the hacker methodology:

1. Read captured requests from MobileRequestStoreDB
2. Modify request (inject payload like Burp Repeater)
3. Send through MobileHTTPClient (routes to MITM)
4. Analyze response for vulnerability patterns
5. Create finding with full PoC data

ALL mobile scanners MUST extend this class.

Usage:
    class MobileSQLiScanner(BaseMobileScanner):
        scanner_name = "mobile_sqli"
        attack_type = "sqli"
        owasp_category = "M7:2024"
        
        async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
            for payload in self.get_payloads():
                response = await self.send_payload(request, payload, "body", "username")
                if self.detect_sqli(response):
                    return [self.create_finding(request, response, payload)]
            return []
"""

import asyncio
import logging
import re
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple, Pattern
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse

from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest
from core.mobile_http_client import MobileHTTPClient, MobileAttackResponse

# Import vulnerability metadata
try:
    from attacks.vulnerability_metadata import get_vuln_meta, get_disclosure_days, VULN_REGISTRY
except ImportError:
    get_vuln_meta = lambda x: None
    get_disclosure_days = lambda x: 30
    VULN_REGISTRY = {}

logger = logging.getLogger(__name__)


@dataclass
class MobileFinding:
    """Represents a discovered mobile vulnerability"""
    id: str
    scanner_name: str
    attack_type: str
    
    # Target
    url: str
    method: str
    parameter: str = ""
    
    # Vulnerability details
    severity: str = "medium"
    confidence: str = "medium"
    title: str = ""
    description: str = ""
    
    # Mobile context
    app_package: str = ""
    platform: str = "android"
    frida_hook: str = ""
    
    # Evidence
    payload: str = ""
    evidence: str = ""
    request_data: str = ""      # Full HTTP request for PoC
    response_data: str = ""     # Response snippet
    
    # Response analysis
    status_code: int = 0
    response_time_ms: float = 0
    
    # Metadata
    timestamp: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    
    # Vulnerability metadata from registry
    impact: str = ""
    disclosure_days: int = 0
    cvss_score: float = 0.0
    compliance_refs: List[str] = field(default_factory=list)
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.id:
            content = f"{self.scanner_name}:{self.url}:{self.parameter}:{self.payload}"
            self.id = hashlib.md5(content.encode()).hexdigest()[:16]
    
    def to_dict(self) -> dict:
        return asdict(self)


class Severity:
    """Severity level constants"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence:
    """Confidence level constants"""
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    TENTATIVE = "tentative"


class BaseMobileScanner(ABC):
    """
    Base class for all mobile attack scanners.
    
    Enforces the correct methodology:
    - All requests from MobileRequestStoreDB
    - All attacks through MobileHTTPClient (MITM)
    - Request-level checkpointing
    - Standardized finding format
    - Rate limiting and error handling
    """
    
    # Subclasses MUST define these
    scanner_name: str = "base_mobile_scanner"
    attack_type: str = "unknown"
    owasp_category: str = ""  # M1:2024 - M10:2024 (OWASP Mobile Top 10)
    cwe_id: str = ""
    
    # Scanner behavior
    requires_auth: bool = False    # Only scan authenticated requests
    skip_static: bool = True       # Skip static resources
    max_payloads: int = 50         # Max payloads per parameter
    request_delay: float = 0.1     # Delay between requests
    
    # OWASP Mobile Top 10 2024 categories
    OWASP_MOBILE = {
        'M1': 'Improper Credential Usage',
        'M2': 'Inadequate Supply Chain Security',
        'M3': 'Insecure Authentication/Authorization',
        'M4': 'Insufficient Input/Output Validation',
        'M5': 'Insecure Communication',
        'M6': 'Inadequate Privacy Controls',
        'M7': 'Insufficient Binary Protections',
        'M8': 'Security Misconfiguration',
        'M9': 'Insecure Data Storage',
        'M10': 'Insufficient Cryptography'
    }
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        checkpoint: Optional[Any] = None,
        max_findings: int = 100,
        stop_on_first: bool = False
    ):
        """
        Initialize mobile scanner.
        
        Args:
            http_client: MobileHTTPClient for sending attacks through MITM
            request_store: MobileRequestStoreDB for reading captured requests
            checkpoint: Optional checkpoint for resume capability
            max_findings: Stop after this many findings
            stop_on_first: Stop after first finding per endpoint
        """
        self.http_client = http_client
        self.request_store = request_store
        self.checkpoint = checkpoint
        self.max_findings = max_findings
        self.stop_on_first = stop_on_first
        
        # Findings storage
        self.findings: List[MobileFinding] = []
        
        # Stats
        self._stats = {
            'requests_scanned': 0,
            'payloads_sent': 0,
            'findings_count': 0,
            'errors': 0,
            'skipped': 0
        }
        
        # Baseline cache
        self._baseline_cache: Dict[str, MobileAttackResponse] = {}
        
        logger.info(f"Initialized {self.scanner_name} scanner")
    
    # ========== Abstract Methods ==========
    
    @abstractmethod
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a single request for vulnerabilities.
        
        Subclasses MUST implement this method.
        
        Args:
            request: Captured mobile request to test
            
        Returns:
            List of findings (empty if no vulnerabilities)
        """
        pass
    
    @abstractmethod
    def get_payloads(self) -> List[str]:
        """
        Get list of attack payloads.
        
        Subclasses MUST implement this.
        """
        pass
    
    # ========== Main Entry Point ==========
    
    async def run(
        self,
        authenticated_only: bool = None,
        has_params_only: bool = True,
        max_requests: int = None
    ) -> List[MobileFinding]:
        """
        Run scanner on all applicable requests.
        
        Args:
            authenticated_only: Only scan authenticated requests
            has_params_only: Only scan requests with parameters
            max_requests: Maximum requests to scan
            
        Returns:
            List of all findings
        """
        authenticated_only = authenticated_only if authenticated_only is not None else self.requires_auth
        
        logger.info(f"Starting {self.scanner_name} scan (auth_only={authenticated_only})")
        
        scanned = 0
        async for request in self.request_store.iter_unprocessed(self.scanner_name):
            # Check limits
            if max_requests and scanned >= max_requests:
                break
            if len(self.findings) >= self.max_findings:
                logger.info(f"Reached max findings limit ({self.max_findings})")
                break
            
            # Skip if doesn't meet criteria
            if authenticated_only and not request.has_auth_token:
                self._stats['skipped'] += 1
                continue
            
            if has_params_only and not request.has_injectable_params():
                self._stats['skipped'] += 1
                continue
            
            if self.skip_static and self._is_static_resource(request.url):
                self._stats['skipped'] += 1
                continue
            
            # Mark as processing
            await self.request_store.mark_processing(request.id, self.scanner_name)
            
            try:
                # Scan the request
                findings = await self.scan_request(request)
                
                if findings:
                    self.findings.extend(findings)
                    self._stats['findings_count'] += len(findings)
                    logger.info(f"Found {len(findings)} vulnerabilities in {request.url}")
                
                # Mark completed
                await self.request_store.mark_completed(
                    request.id, 
                    self.scanner_name,
                    findings_count=len(findings)
                )
                
            except Exception as e:
                logger.error(f"Error scanning {request.url}: {e}")
                self._stats['errors'] += 1
                await self.request_store.mark_failed(request.id, self.scanner_name, str(e))
            
            self._stats['requests_scanned'] += 1
            scanned += 1
            
            # Delay between requests
            if self.request_delay > 0:
                await asyncio.sleep(self.request_delay)
        
        logger.info(f"{self.scanner_name} scan complete: {self._stats}")
        return self.findings
    
    # ========== Helper Methods ==========
    
    def _is_static_resource(self, url: str) -> bool:
        """Check if URL is a static resource"""
        static_extensions = {
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.map', '.webp'
        }
        parsed = urlparse(url)
        path_lower = parsed.path.lower()
        return any(path_lower.endswith(ext) for ext in static_extensions)
    
    async def get_baseline(self, request: StoredMobileRequest) -> Optional[MobileAttackResponse]:
        """
        Get baseline response for comparison-based detection.
        
        Caches baseline per request ID to avoid redundant requests.
        """
        if request.id in self._baseline_cache:
            return self._baseline_cache[request.id]
        
        response, error = await self.http_client.send_baseline(request)
        
        if response:
            self._baseline_cache[request.id] = response
        
        return response
    
    async def send_payload(
        self,
        request: StoredMobileRequest,
        payload: str,
        location: str,
        parameter_name: str
    ) -> Optional[MobileAttackResponse]:
        """
        Send a payload through the target request.
        
        Args:
            request: Original request to modify
            payload: Attack payload
            location: Where to inject (query, body, header, cookie)
            parameter_name: Which parameter to modify
            
        Returns:
            Attack response or None on error
        """
        response, error = await self.http_client.send_attack_from_request(
            request=request,
            payload=payload,
            payload_location=location,
            parameter_name=parameter_name,
            scanner_name=self.scanner_name,
            attack_type=self.attack_type
        )
        
        if error:
            logger.debug(f"Payload error: {error}")
            return None
        
        self._stats['payloads_sent'] += 1
        return response
    
    def create_finding(
        self,
        request: StoredMobileRequest,
        response: MobileAttackResponse,
        payload: str,
        evidence: str,
        confidence: str = Confidence.MEDIUM,
        severity: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        parameter: Optional[str] = None
    ) -> MobileFinding:
        """
        Create a standardized mobile finding with vulnerability metadata.
        
        Automatically populates impact, disclosure_days, compliance from VULN_REGISTRY.
        """
        # Get vulnerability metadata
        vuln_meta = get_vuln_meta(self.attack_type)
        
        # Populate from metadata or defaults
        impact = ""
        disclosure_days = 30
        cvss_score = 0.0
        compliance_refs = []
        remediation = ""
        references = []
        
        if vuln_meta:
            impact = vuln_meta.impact
            disclosure_days = vuln_meta.disclosure_days
            cvss_score = vuln_meta.cvss_base
            compliance_refs = list(vuln_meta.compliance)
            remediation = vuln_meta.remediation
            references = list(vuln_meta.references)
        else:
            final_severity = severity or self._infer_severity(confidence)
            disclosure_days = get_disclosure_days(final_severity)
        
        # Build request data for PoC
        request_data = self._build_request_data(request, payload)
        
        return MobileFinding(
            id="",  # Auto-generated
            scanner_name=self.scanner_name,
            attack_type=self.attack_type,
            url=request.url,
            method=request.method,
            parameter=parameter or "",
            severity=severity or self._infer_severity(confidence),
            confidence=confidence,
            title=title or f"{self.attack_type.upper()} vulnerability detected",
            description=description or f"Potential {self.attack_type} vulnerability found",
            app_package=request.app_package,
            platform=request.platform,
            frida_hook=request.frida_hook,
            payload=payload,
            evidence=evidence[:500],
            request_data=request_data,
            response_data=response.body[:2000] if response.body else "",
            status_code=response.status_code,
            response_time_ms=response.response_time_ms,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            impact=impact,
            disclosure_days=disclosure_days,
            cvss_score=cvss_score,
            compliance_refs=compliance_refs,
            remediation=remediation,
            references=references
        )
    
    def _infer_severity(self, confidence: str) -> str:
        """Infer severity from confidence and attack type"""
        # High-severity attacks
        if self.attack_type in ['sqli', 'rce', 'ssrf', 'xxe', 'ssti', 'auth_bypass']:
            return Severity.CRITICAL if confidence in [Confidence.CONFIRMED, Confidence.HIGH] else Severity.HIGH
        
        # Medium-severity
        if self.attack_type in ['xss', 'csrf', 'idor', 'lfi', 'nosql']:
            return Severity.HIGH if confidence in [Confidence.CONFIRMED, Confidence.HIGH] else Severity.MEDIUM
        
        # Lower severity
        return Severity.MEDIUM if confidence in [Confidence.CONFIRMED, Confidence.HIGH] else Severity.LOW
    
    def _build_request_data(self, request: StoredMobileRequest, payload: str) -> str:
        """Build full HTTP request for PoC documentation"""
        try:
            parsed = urlparse(request.url)
            lines = [f"{request.method} {parsed.path or '/'} HTTP/1.1"]
            lines.append(f"Host: {parsed.netloc}")
            
            # Add headers
            for key, value in request.headers.items():
                if key.lower() not in ['host', 'content-length']:
                    lines.append(f"{key}: {value}")
            
            # Add blank line and body
            lines.append("")
            if request.body:
                lines.append(str(request.body))
            
            return "\n".join(lines)
        except Exception:
            return f"{request.method} {request.url}"
    
    # ========== Pattern Matching Helpers ==========
    
    def check_patterns(
        self,
        content: str,
        patterns: List[str],
        is_regex: bool = True
    ) -> Tuple[bool, str]:
        """
        Check content against patterns.
        
        Returns:
            Tuple of (matched, matching_pattern)
        """
        for pattern in patterns:
            try:
                if is_regex:
                    match = re.search(pattern, content, re.IGNORECASE)
                    if match:
                        return True, match.group(0)
                else:
                    if pattern.lower() in content.lower():
                        return True, pattern
            except re.error:
                if pattern.lower() in content.lower():
                    return True, pattern
        
        return False, ""
    
    def check_time_based(
        self,
        response: MobileAttackResponse,
        baseline_time_ms: float,
        delay_seconds: float = 5.0,
        tolerance: float = 0.8
    ) -> bool:
        """
        Check if response time indicates time-based injection.
        
        Args:
            response: Attack response
            baseline_time_ms: Normal response time
            delay_seconds: Injected delay
            tolerance: Required delay accuracy (0.8 = 80%)
            
        Returns:
            True if time-based injection likely
        """
        expected_delay_ms = delay_seconds * 1000
        actual_delay_ms = response.response_time_ms - baseline_time_ms
        
        return actual_delay_ms >= (expected_delay_ms * tolerance)
    
    def check_reflection(
        self,
        response: MobileAttackResponse,
        payload: str,
        context: str = "body"
    ) -> Tuple[bool, str]:
        """
        Check if payload is reflected in response.
        
        Args:
            response: Attack response
            payload: Injected payload
            context: Where to check (body, headers)
            
        Returns:
            Tuple of (reflected, reflection_context)
        """
        if context == "body" and response.body:
            if payload in response.body:
                # Find surrounding context
                idx = response.body.find(payload)
                start = max(0, idx - 50)
                end = min(len(response.body), idx + len(payload) + 50)
                return True, response.body[start:end]
        
        elif context == "headers":
            for header, value in response.headers.items():
                if payload in value:
                    return True, f"{header}: {value}"
        
        return False, ""
    
    def compare_responses(
        self,
        response1: MobileAttackResponse,
        response2: MobileAttackResponse,
        check_length: bool = True,
        check_status: bool = True,
        length_threshold: float = 0.1  # 10% difference
    ) -> Tuple[bool, str]:
        """
        Compare two responses for differences.
        
        Used for boolean-based blind injection detection.
        
        Returns:
            Tuple of (different, reason)
        """
        differences = []
        
        if check_status and response1.status_code != response2.status_code:
            differences.append(f"Status: {response1.status_code} vs {response2.status_code}")
        
        if check_length:
            len1, len2 = response1.body_length, response2.body_length
            if len1 > 0 and len2 > 0:
                ratio = abs(len1 - len2) / max(len1, len2)
                if ratio > length_threshold:
                    differences.append(f"Length: {len1} vs {len2} ({ratio:.1%} diff)")
        
        return bool(differences), "; ".join(differences)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return dict(self._stats)
    
    def get_injectable_params(self, request: StoredMobileRequest) -> List[Tuple[str, str, str]]:
        """
        Get list of injectable parameters from a request.
        
        Returns:
            List of (param_name, location, current_value) tuples
        """
        params = []
        
        # Query parameters
        parsed = urlparse(request.url)
        if parsed.query:
            from urllib.parse import parse_qs
            query_params = parse_qs(parsed.query, keep_blank_values=True)
            for name, values in query_params.items():
                value = values[0] if values else ""
                params.append((name, "query", value))
        
        # Body parameters (JSON)
        if request.body:
            content_type = request.content_type.lower()
            if 'json' in content_type:
                try:
                    import json
                    body_data = json.loads(request.body)
                    if isinstance(body_data, dict):
                        for name, value in body_data.items():
                            if isinstance(value, (str, int, float)):
                                params.append((name, "body", str(value)))
                except:
                    pass
            elif 'form' in content_type:
                from urllib.parse import parse_qs
                form_params = parse_qs(request.body, keep_blank_values=True)
                for name, values in form_params.items():
                    value = values[0] if values else ""
                    params.append((name, "body", value))
        
        return params
