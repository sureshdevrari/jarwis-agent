"""
Jarwis AGI Pen Test - Shared Scanner Base Class

Unified base class for both web and mobile API attack scanners.
This provides a common interface and reduces code duplication between
attacks/web/base_attack_scanner.py and attacks/mobile/base_mobile_scanner.py.

Usage:
    from attacks.shared.base_scanner import BaseAPIScanner, Finding, Severity, Confidence
    
    class MySQLiScanner(BaseAPIScanner):
        scanner_name = "sqli"
        attack_type = "sqli"
        
        async def scan_request(self, request) -> List[Finding]:
            # Implementation
            pass
"""

import asyncio
import logging
import re
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple, TypeVar, Generic
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from enum import Enum

logger = logging.getLogger(__name__)


# ============== Enums ==============

class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    """Finding confidence levels"""
    CONFIRMED = "confirmed"  # 100% sure - exploited successfully
    HIGH = "high"            # Strong indicators
    MEDIUM = "medium"        # Moderate indicators
    LOW = "low"              # Weak indicators, needs manual verification
    TENTATIVE = "tentative"  # Possible, but could be false positive


# ============== Data Classes ==============

@dataclass
class Finding:
    """
    Unified finding representation for both web and mobile scans.
    
    Contains all fields needed for professional security reports.
    """
    id: str = ""
    scanner_name: str = ""
    attack_type: str = ""
    
    # Target details
    url: str = ""
    method: str = ""
    parameter: str = ""
    
    # Vulnerability details
    severity: str = "medium"
    confidence: str = "medium"
    title: str = ""
    description: str = ""
    
    # Evidence
    payload: str = ""
    evidence: str = ""
    request_data: str = ""      # Full HTTP request for PoC
    response_data: str = ""     # Response snippet
    request_snippet: str = ""   # Short request excerpt
    response_snippet: str = ""  # Short response excerpt
    
    # Response analysis
    status_code: int = 0
    response_time_ms: float = 0
    
    # Metadata
    timestamp: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    
    # Platform-specific (web/mobile)
    platform: str = "web"  # "web" or "mobile"
    app_package: str = ""  # For mobile: com.example.app
    frida_hook: str = ""   # For mobile: Frida script used
    
    # Vulnerability metadata for reporting
    impact: str = ""
    disclosure_days: int = 0
    cvss_score: float = 0.0
    compliance_refs: List[str] = field(default_factory=list)
    
    # Remediation
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


# Type variables for generic request/response types
TRequest = TypeVar('TRequest')
TResponse = TypeVar('TResponse')


# ============== Base Scanner Class ==============

class BaseAPIScanner(ABC, Generic[TRequest, TResponse]):
    """
    Unified base class for all API attack scanners (web and mobile).
    
    This provides a common interface for:
    - SQL Injection
    - NoSQL Injection
    - XSS
    - Command Injection
    - SSTI
    - XXE
    - SSRF
    - IDOR
    - And more...
    
    Subclasses must implement:
    - scan_request() - Main scanning logic
    - get_payloads() - Return attack payloads
    - is_applicable() - Check if scanner applies to request
    - send_payload() - Send modified request
    """
    
    # Subclasses MUST define these
    scanner_name: str = "base_api_scanner"
    attack_type: str = "unknown"
    owasp_category: str = ""  # A01-A10 for web, M1-M10 for mobile
    cwe_id: str = ""
    platform: str = "shared"  # "web", "mobile", or "shared"
    
    # Scanner behavior settings
    default_timeout: int = 30
    default_rate_limit: float = 10.0  # Requests per second
    max_retries: int = 2
    max_payloads_per_param: int = 10  # Limit payloads per parameter
    max_findings: int = 100           # Stop after this many findings
    stop_on_first: bool = False       # Stop after first finding per endpoint
    
    # OWASP categories for reference
    OWASP_WEB_TOP10 = {
        'A01': 'Broken Access Control',
        'A02': 'Cryptographic Failures',
        'A03': 'Injection',
        'A04': 'Insecure Design',
        'A05': 'Security Misconfiguration',
        'A06': 'Vulnerable Components',
        'A07': 'Authentication Failures',
        'A08': 'Data Integrity Failures',
        'A09': 'Logging Failures',
        'A10': 'SSRF'
    }
    
    OWASP_MOBILE_TOP10 = {
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
        http_client: Any,
        request_store: Any,
        checkpoint: Optional[Any] = None,
        config: Optional[Dict[str, Any]] = None,
        **kwargs
    ):
        """
        Initialize scanner with required dependencies.
        
        Args:
            http_client: HTTP client for sending requests (web or mobile)
            request_store: Request store for reading captured traffic
            checkpoint: Optional checkpoint for resume capability
            config: Scanner configuration
        """
        self.http_client = http_client
        self.request_store = request_store
        self.checkpoint = checkpoint
        self.config = config or {}
        
        # Override settings from config
        self.max_payloads_per_param = kwargs.get(
            'max_payloads_per_param', 
            self.config.get('max_payloads_per_param', self.max_payloads_per_param)
        )
        self.max_findings = kwargs.get(
            'max_findings',
            self.config.get('max_findings', self.max_findings)
        )
        self.stop_on_first = kwargs.get(
            'stop_on_first',
            self.config.get('stop_on_first', self.stop_on_first)
        )
        
        # Runtime state
        self.findings: List[Finding] = []
        self._cancelled = False
        self._stats = {
            'requests_scanned': 0,
            'payloads_sent': 0,
            'vulnerabilities_found': 0,
            'errors': 0,
            'skipped': 0
        }
        
        # Rate limiting
        self._rate_limit = self.config.get('rate_limit', self.default_rate_limit)
        self._last_request_time = 0.0
        
        # Baseline cache for comparison
        self._baseline_cache: Dict[str, Any] = {}
        
        logger.info(f"Initialized {self.scanner_name} scanner (platform: {self.platform})")
    
    # ============== Abstract Methods (MUST implement) ==============
    
    @abstractmethod
    async def scan_request(self, request: TRequest) -> List[Finding]:
        """
        Scan a single request for vulnerabilities.
        
        This is the main method subclasses implement.
        
        Args:
            request: The stored request to test
            
        Returns:
            List of findings (empty if no vulnerabilities found)
        """
        pass
    
    @abstractmethod
    def get_payloads(self) -> List[str]:
        """
        Get list of attack payloads for this scanner.
        
        Returns:
            List of payload strings to inject
        """
        pass
    
    @abstractmethod
    def is_applicable(self, request: TRequest) -> bool:
        """
        Check if this scanner is applicable to the request.
        
        Args:
            request: Request to check
            
        Returns:
            True if scanner should test this request
        """
        pass
    
    @abstractmethod
    async def send_payload(
        self,
        request: TRequest,
        payload: str,
        location: str,
        param_name: str
    ) -> Optional[TResponse]:
        """
        Send a request with an injected payload.
        
        Args:
            request: Original request to modify
            payload: Payload to inject
            location: Where to inject (query, body, header, path)
            param_name: Name of parameter to inject into
            
        Returns:
            Response from the server, or None on error
        """
        pass
    
    # ============== Optional Abstract Methods ==============
    
    async def get_baseline(self, request: TRequest) -> Optional[TResponse]:
        """
        Get baseline response for comparison.
        
        Override this if you need custom baseline logic.
        
        Args:
            request: Original request
            
        Returns:
            Baseline response for comparison
        """
        # Default: use cached baseline or send original request
        request_id = getattr(request, 'id', str(id(request)))
        
        if request_id in self._baseline_cache:
            return self._baseline_cache[request_id]
        
        try:
            response = await self.http_client.send(request)
            self._baseline_cache[request_id] = response
            return response
        except Exception as e:
            logger.warning(f"[{self.scanner_name}] Failed to get baseline: {e}")
            return None
    
    # ============== Common Helper Methods ==============
    
    def create_finding(
        self,
        request: TRequest,
        response: TResponse,
        payload: str,
        title: str = "",
        description: str = "",
        severity: Severity = Severity.MEDIUM,
        confidence: Confidence = Confidence.MEDIUM,
        evidence: str = "",
        **extra_fields
    ) -> Finding:
        """
        Create a standardized finding object.
        
        Args:
            request: The vulnerable request
            response: The response showing vulnerability
            payload: The payload that triggered the vulnerability
            title: Finding title
            description: Detailed description
            severity: Severity level
            confidence: Confidence level
            evidence: Evidence string
            **extra_fields: Additional finding fields
            
        Returns:
            Finding object
        """
        # Extract common fields from request
        url = getattr(request, 'url', str(request))
        method = getattr(request, 'method', 'GET')
        
        # Extract response data
        status_code = getattr(response, 'status_code', 0)
        response_time_ms = getattr(response, 'response_time_ms', 0)
        response_body = getattr(response, 'body', '')
        
        # Build request/response data for PoC
        request_data = self._format_request_data(request, payload)
        response_data = self._format_response_data(response)
        
        finding = Finding(
            scanner_name=self.scanner_name,
            attack_type=self.attack_type,
            url=url,
            method=method,
            parameter=extra_fields.get('parameter', ''),
            severity=severity.value if isinstance(severity, Severity) else severity,
            confidence=confidence.value if isinstance(confidence, Confidence) else confidence,
            title=title or f"{self.attack_type.upper()} in {url}",
            description=description,
            payload=payload,
            evidence=evidence or self._extract_evidence(response, payload),
            request_data=request_data,
            response_data=response_data[:2000],  # Limit size
            status_code=status_code,
            response_time_ms=response_time_ms,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            platform=self.platform,
            **extra_fields
        )
        
        return finding
    
    def _format_request_data(self, request: TRequest, payload: str) -> str:
        """Format request data for PoC display."""
        try:
            url = getattr(request, 'url', '')
            method = getattr(request, 'method', 'GET')
            headers = getattr(request, 'headers', {})
            body = getattr(request, 'body', '')
            
            lines = [f"{method} {url}"]
            for key, value in headers.items():
                lines.append(f"{key}: {value}")
            lines.append("")
            if body:
                lines.append(body[:500])
            lines.append("")
            lines.append(f"X-Jarwis-Payload: {payload}")
            
            return "\n".join(lines)
        except Exception:
            return f"Request with payload: {payload}"
    
    def _format_response_data(self, response: TResponse) -> str:
        """Format response data for PoC display."""
        try:
            status = getattr(response, 'status_code', 0)
            headers = getattr(response, 'headers', {})
            body = getattr(response, 'body', '')
            
            lines = [f"HTTP/1.1 {status}"]
            for key, value in list(headers.items())[:10]:
                lines.append(f"{key}: {value}")
            lines.append("")
            if body:
                body_str = body if isinstance(body, str) else str(body)
                lines.append(body_str[:1000])
            
            return "\n".join(lines)
        except Exception:
            return "Response data unavailable"
    
    def _extract_evidence(self, response: TResponse, payload: str) -> str:
        """Extract evidence from response showing vulnerability."""
        try:
            body = getattr(response, 'body', '')
            body_str = body if isinstance(body, str) else str(body)
            
            # Find payload in response
            if payload in body_str:
                idx = body_str.find(payload)
                start = max(0, idx - 50)
                end = min(len(body_str), idx + len(payload) + 50)
                return f"...{body_str[start:end]}..."
            
            return body_str[:200] if body_str else ""
        except Exception:
            return ""
    
    async def _rate_limit_wait(self):
        """Wait to respect rate limiting."""
        if self._rate_limit <= 0:
            return
        
        min_interval = 1.0 / self._rate_limit
        elapsed = asyncio.get_event_loop().time() - self._last_request_time
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = asyncio.get_event_loop().time()
    
    def cancel(self):
        """Cancel the running scan."""
        self._cancelled = True
        logger.info(f"[{self.scanner_name}] Cancellation requested")
    
    def get_stats(self) -> Dict[str, int]:
        """Get scanner statistics."""
        return self._stats.copy()
    
    # ============== URL/Parameter Manipulation Helpers ==============
    
    @staticmethod
    def inject_into_url_param(url: str, param_name: str, payload: str) -> str:
        """Inject payload into URL query parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        if param_name in params:
            params[param_name] = [payload]
        else:
            params[param_name] = [payload]
        
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
        
        return new_url
    
    @staticmethod
    def inject_into_json_body(body: str, field_name: str, payload: str) -> str:
        """Inject payload into JSON body field."""
        import json
        try:
            data = json.loads(body)
            if isinstance(data, dict) and field_name in data:
                data[field_name] = payload
            return json.dumps(data)
        except (json.JSONDecodeError, TypeError):
            return body
    
    @staticmethod
    def inject_into_form_body(body: str, field_name: str, payload: str) -> str:
        """Inject payload into form-urlencoded body field."""
        params = parse_qs(body, keep_blank_values=True)
        if field_name in params:
            params[field_name] = [payload]
        return urlencode(params, doseq=True)
    
    # ============== Pattern Matching Helpers ==============
    
    @staticmethod
    def search_patterns(text: str, patterns: List[str]) -> Optional[str]:
        """Search text for any of the given regex patterns."""
        for pattern in patterns:
            try:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    return match.group(0)
            except re.error:
                continue
        return None
    
    @staticmethod
    def contains_any(text: str, substrings: List[str], case_sensitive: bool = False) -> bool:
        """Check if text contains any of the substrings."""
        if not case_sensitive:
            text = text.lower()
            substrings = [s.lower() for s in substrings]
        return any(s in text for s in substrings)


# ============== Convenience Exports ==============

__all__ = [
    'BaseAPIScanner',
    'Finding',
    'Severity',
    'Confidence',
]
