"""
Jarwis AGI Pen Test - Base Attack Scanner

This is the new unified interface ALL attack scanners must implement.
It enforces the correct hacker methodology:

1. Read stored requests from RequestStoreDB
2. Modify request headers/body (like Burp Suite Repeater)
3. Send modified request THROUGH MITM via JarwisHTTPClient
4. Analyze response for vulnerability patterns
5. Report findings with evidence

ALL scanners must extend this class and use self.http_client for requests.
Direct use of aiohttp is NOT allowed.

Usage:
    class SQLInjectionScanner(BaseAttackScanner):
        scanner_name = "sql_injection"
        attack_type = "sqli"
        
        async def scan_request(self, request: StoredRequest) -> List[Finding]:
            # Modify and test the request
            for payload in self.PAYLOADS:
                response = await self.send_payload(request, payload, "query")
                if self.detect_vulnerability(response):
                    return [self.create_finding(request, response, payload)]
            return []
"""

import asyncio
import logging
import re
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple, Pattern
from dataclasses import dataclass, field, asdict
from datetime import datetime
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse
from enum import Enum

from core.jarwis_http_client import JarwisHTTPClient, AttackResponse
from core.request_store_db import RequestStoreDB, StoredRequest
from core.scan_checkpoint import RequestLevelCheckpoint
from core.token_manager import TokenManager

# Import vulnerability metadata registry
try:
    from attacks.vulnerability_metadata import get_vuln_meta, get_disclosure_days, VULN_REGISTRY
except ImportError:
    get_vuln_meta = lambda x: None
    get_disclosure_days = lambda x: 30
    VULN_REGISTRY = {}

logger = logging.getLogger(__name__)


class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(Enum):
    """Finding confidence levels"""
    CONFIRMED = "confirmed"  # 100% sure - exploited successfully
    HIGH = "high"           # Strong indicators
    MEDIUM = "medium"       # Moderate indicators
    LOW = "low"             # Weak indicators, needs manual verification
    TENTATIVE = "tentative" # Possible, but could be false positive


@dataclass
class Finding:
    """Represents a discovered vulnerability"""
    id: str
    scanner_name: str
    attack_type: str
    
    # Target details
    url: str
    method: str
    parameter: str = ""
    
    # Vulnerability details
    severity: str = "medium"
    confidence: str = "medium"
    title: str = ""
    description: str = ""
    
    # Evidence
    payload: str = ""
    evidence: str = ""
    request_snippet: str = ""
    response_snippet: str = ""
    
    # Response analysis
    status_code: int = 0
    response_time_ms: float = 0
    
    # Metadata
    timestamp: str = ""
    cwe_id: str = ""
    owasp_category: str = ""
    
    # Remediation
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    
    # NEW: Vulnerability metadata for reporting
    impact: str = ""
    disclosure_days: int = 0
    cvss_score: float = 0.0
    compliance_refs: List[str] = field(default_factory=list)
    
    # Full request/response for PoC
    request_data: str = ""
    response_data: str = ""
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.id:
            import hashlib
            content = f"{self.scanner_name}:{self.url}:{self.parameter}:{self.payload}"
            self.id = hashlib.md5(content.encode()).hexdigest()[:16]
    
    def to_dict(self) -> dict:
        return asdict(self)


class BaseAttackScanner(ABC):
    """
    Base class for all attack scanners.
    
    Enforces the correct methodology:
    - All requests go through JarwisHTTPClient (routed to MITM)
    - Request-level checkpointing for resume
    - Standardized finding format
    - Rate limiting and error handling
    """
    
    # Subclasses MUST define these
    scanner_name: str = "base_scanner"
    attack_type: str = "unknown"
    owasp_category: str = ""
    cwe_id: str = ""
    
    # Default settings (can be overridden)
    default_timeout: int = 30
    default_rate_limit: float = 10.0  # Requests per second
    max_retries: int = 2
    max_payloads_per_param: int = 10  # Limit payloads to avoid DoS
    
    def __init__(
        self,
        http_client: JarwisHTTPClient,
        request_store: RequestStoreDB,
        checkpoint: Optional[RequestLevelCheckpoint] = None,
        token_manager: Optional[TokenManager] = None,
        config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize scanner with required dependencies.
        
        Args:
            http_client: Proxy-aware HTTP client (REQUIRED - routes through MITM)
            request_store: Database-backed request storage
            checkpoint: Request-level checkpoint for resume (optional)
            token_manager: Auth token manager (optional, for post-login)
            config: Scanner configuration
        """
        self.http_client = http_client
        self.request_store = request_store
        self.checkpoint = checkpoint
        self.token_manager = token_manager
        self.config = config or {}
        
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
        self._last_request_time = 0
        
        logger.info(f"Initialized scanner: {self.scanner_name}")
    
    # ========== Abstract methods - MUST be implemented ==========
    
    @abstractmethod
    async def scan_request(self, request: StoredRequest) -> List[Finding]:
        """
        Scan a single request for vulnerabilities.
        
        This is the main method subclasses implement.
        Use self.send_payload() to send modified requests.
        
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
    def detect_vulnerability(
        self,
        response: AttackResponse,
        payload: str,
        original_response: Optional[AttackResponse] = None
    ) -> Tuple[bool, str, str]:
        """
        Analyze response to detect vulnerability.
        
        Args:
            response: Response from attack request
            payload: The payload that was sent
            original_response: Original response for comparison (optional)
            
        Returns:
            Tuple of (is_vulnerable, evidence, confidence)
        """
        pass
    
    # ========== Main execution methods ==========
    
    async def run(self, post_login: bool = False) -> List[Finding]:
        """
        Run the scanner on all applicable requests.
        
        Args:
            post_login: Whether to scan post-login requests
            
        Returns:
            List of all findings
        """
        self.findings = []
        self._cancelled = False
        
        logger.info(f"[{self.scanner_name}] Starting scan (post_login={post_login})")
        
        try:
            # Iterate through requests in batches
            batch_count = 0
            async for request in self.request_store.iter_requests(
                post_login=post_login,
                scanner_name=self.scanner_name  # Skip already processed
            ):
                if self._cancelled:
                    logger.info(f"[{self.scanner_name}] Scan cancelled")
                    break
                
                # Skip if already processed (belt and suspenders with checkpoint)
                if self.checkpoint and self.checkpoint.is_processed(self.scanner_name, request.id):
                    self._stats['skipped'] += 1
                    continue
                
                # Skip non-applicable requests
                if not self.is_applicable(request):
                    if self.checkpoint:
                        await self.checkpoint.mark_skipped(
                            self.scanner_name, request.id, "not_applicable"
                        )
                    self._stats['skipped'] += 1
                    continue
                
                # Mark as in-progress for checkpoint
                if self.checkpoint:
                    await self.checkpoint.mark_in_progress(self.scanner_name, request.id)
                
                try:
                    # Scan the request
                    request_findings = await self.scan_request(request)
                    
                    if request_findings:
                        self.findings.extend(request_findings)
                        self._stats['vulnerabilities_found'] += len(request_findings)
                    
                    self._stats['requests_scanned'] += 1
                    
                    # Mark completed
                    if self.checkpoint:
                        await self.checkpoint.mark_completed(self.scanner_name, request.id)
                    
                except Exception as e:
                    self._stats['errors'] += 1
                    logger.error(f"[{self.scanner_name}] Error scanning {request.url}: {e}")
                    
                    if self.checkpoint:
                        await self.checkpoint.mark_failed(
                            self.scanner_name, request.id, str(e)
                        )
                
                batch_count += 1
                
                # Log progress periodically
                if batch_count % 50 == 0:
                    logger.info(
                        f"[{self.scanner_name}] Progress: {batch_count} requests, "
                        f"{self._stats['vulnerabilities_found']} findings"
                    )
            
            # Flush checkpoint
            if self.checkpoint:
                await self.checkpoint.flush()
            
            logger.info(
                f"[{self.scanner_name}] Completed. "
                f"Scanned: {self._stats['requests_scanned']}, "
                f"Findings: {self._stats['vulnerabilities_found']}, "
                f"Errors: {self._stats['errors']}"
            )
            
            return self.findings
            
        except Exception as e:
            logger.error(f"[{self.scanner_name}] Scanner failed: {e}")
            raise
    
    def cancel(self):
        """Cancel the running scan"""
        self._cancelled = True
        logger.info(f"[{self.scanner_name}] Cancellation requested")
    
    # ========== Helper methods for subclasses ==========
    
    def is_applicable(self, request: StoredRequest) -> bool:
        """
        Check if this scanner is applicable to the request.
        
        Override in subclasses for specific filtering.
        Default: applicable to requests with parameters.
        """
        # Skip static resources
        if request.endpoint_type == 'static':
            return False
        
        # Default: need parameters to test
        return bool(request.parameters)
    
    async def send_payload(
        self,
        request: StoredRequest,
        payload: str,
        location: str = "query",
        parameter_name: Optional[str] = None,
        additional_headers: Optional[Dict[str, str]] = None
    ) -> Optional[AttackResponse]:
        """
        Send a modified request with the payload injected.
        
        This is the main method for sending attack requests.
        It routes through MITM via JarwisHTTPClient.
        
        Args:
            request: Original request to modify
            payload: Payload to inject
            location: Where to inject - query, body, header, path, cookie
            parameter_name: Which parameter to inject into (uses first if not specified)
            additional_headers: Extra headers to add
            
        Returns:
            AttackResponse or None on error
        """
        self._stats['payloads_sent'] += 1
        
        # Build modified URL/body
        modified_url = request.url
        modified_body = request.body
        modified_headers = dict(request.headers)
        
        if additional_headers:
            modified_headers.update(additional_headers)
        
        # Inject payload based on location
        if location == "query":
            modified_url = self._inject_in_query(request.url, payload, parameter_name, request.parameters)
        elif location == "body":
            modified_body = self._inject_in_body(request.body, payload, parameter_name, request.parameters, request.content_type)
        elif location == "header":
            if parameter_name:
                modified_headers[parameter_name] = payload
        elif location == "path":
            modified_url = self._inject_in_path(request.url, payload)
        elif location == "cookie":
            modified_headers['Cookie'] = self._inject_in_cookie(request.cookies, payload, parameter_name)
        
        # Add Jarwis attack headers for MITM identification
        modified_headers['X-Jarwis-Attack'] = '1'
        modified_headers['X-Jarwis-Scanner'] = self.scanner_name
        modified_headers['X-Jarwis-Attack-Type'] = self.attack_type
        modified_headers['X-Jarwis-Request-Id'] = request.id
        modified_headers['X-Jarwis-Payload'] = payload[:200]  # Truncate for header safety
        
        # Send through MITM
        response, error = await self.http_client.send_attack(
            url=modified_url,
            method=request.method,
            headers=modified_headers,
            body=modified_body,
            scanner_name=self.scanner_name,
            attack_type=self.attack_type,
            original_request_id=request.id,
            payload=payload,
            payload_location=location,
            parameter_name=parameter_name or "unknown"
        )
        
        if error:
            logger.warning(f"[{self.scanner_name}] Request failed: {error}")
            return None
        
        return response
    
    async def send_baseline_request(self, request: StoredRequest) -> Optional[AttackResponse]:
        """
        Send the original request without modification to get baseline response.
        
        Useful for comparison-based detection (e.g., time-based, content-based).
        """
        response, error = await self.http_client.send_attack(
            url=request.url,
            method=request.method,
            headers=request.headers,
            body=request.body,
            scanner_name=self.scanner_name,
            attack_type="baseline",
            original_request_id=request.id
        )
        
        return response
    
    def _inject_in_query(
        self,
        url: str,
        payload: str,
        param_name: Optional[str],
        parameters: Dict[str, str]
    ) -> str:
        """Inject payload into URL query parameter"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        
        # Choose parameter to inject
        target_param = param_name
        if not target_param and parameters:
            target_param = list(parameters.keys())[0]
        
        if target_param:
            params[target_param] = [payload]
        
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment
        ))
    
    def _inject_in_body(
        self,
        body: str,
        payload: str,
        param_name: Optional[str],
        parameters: Dict[str, str],
        content_type: str
    ) -> str:
        """Inject payload into request body"""
        import json
        
        if 'application/json' in content_type:
            try:
                data = json.loads(body) if body else {}
                target_param = param_name or (list(data.keys())[0] if data else None)
                if target_param:
                    data[target_param] = payload
                return json.dumps(data)
            except:
                pass
        
        elif 'x-www-form-urlencoded' in content_type:
            params = parse_qs(body, keep_blank_values=True)
            target_param = param_name or (list(params.keys())[0] if params else None)
            if target_param:
                params[target_param] = [payload]
            return urlencode(params, doseq=True)
        
        # Fallback: append to body
        return body + payload if body else payload
    
    def _inject_in_path(self, url: str, payload: str) -> str:
        """Inject payload into URL path"""
        parsed = urlparse(url)
        # Append to path
        new_path = parsed.path.rstrip('/') + '/' + payload
        return urlunparse((
            parsed.scheme, parsed.netloc, new_path,
            parsed.params, parsed.query, parsed.fragment
        ))
    
    def _inject_in_cookie(
        self,
        cookies: Dict[str, str],
        payload: str,
        cookie_name: Optional[str]
    ) -> str:
        """Inject payload into cookie"""
        modified = dict(cookies)
        target = cookie_name or (list(cookies.keys())[0] if cookies else 'test')
        modified[target] = payload
        return '; '.join(f"{k}={v}" for k, v in modified.items())
    
    def create_finding(
        self,
        request: StoredRequest,
        response: AttackResponse,
        payload: str,
        evidence: str,
        confidence: str = "medium",
        severity: Optional[str] = None,
        title: Optional[str] = None,
        description: Optional[str] = None,
        parameter: Optional[str] = None
    ) -> Finding:
        """
        Create a standardized finding with auto-populated vulnerability metadata.
        
        Helper method for subclasses to create findings with consistent format.
        Automatically populates impact, disclosure_days, compliance_refs from VULN_REGISTRY.
        """
        # Get vulnerability metadata from registry
        vuln_meta = get_vuln_meta(self.attack_type)
        
        # Populate from metadata or use defaults
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
            # Fallback: calculate disclosure days from severity
            final_severity = severity or self._infer_severity(confidence)
            disclosure_days = get_disclosure_days(final_severity)
        
        # Build full request data for PoC
        request_data = self._build_request_data(request, payload)
        response_data = response.body[:2000] if response.body else ""
        
        return Finding(
            id="",  # Will be auto-generated
            scanner_name=self.scanner_name,
            attack_type=self.attack_type,
            url=request.url,
            method=request.method,
            parameter=parameter or "",
            severity=severity or self._infer_severity(confidence),
            confidence=confidence,
            title=title or f"{self.attack_type.upper()} vulnerability detected",
            description=description or f"Potential {self.attack_type} vulnerability found",
            payload=payload,
            evidence=evidence[:500],  # Limit evidence size
            request_snippet=f"{request.method} {request.url}",
            response_snippet=response.body[:200] if response.body else "",
            status_code=response.status_code,
            response_time_ms=response.response_time_ms,
            cwe_id=self.cwe_id,
            owasp_category=self.owasp_category,
            # New vulnerability metadata
            impact=impact,
            disclosure_days=disclosure_days,
            cvss_score=cvss_score,
            compliance_refs=compliance_refs,
            remediation=remediation,
            references=references,
            request_data=request_data,
            response_data=response_data
        )
    
    def _build_request_data(self, request: StoredRequest, payload: str) -> str:
        """Build full HTTP request string for PoC documentation."""
        try:
            parsed = urlparse(request.url)
            lines = [f"{request.method} {parsed.path or '/'} HTTP/1.1"]
            lines.append(f"Host: {parsed.netloc}")
            
            # Add headers
            if request.headers:
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
    
    def _infer_severity(self, confidence: str) -> str:
        """Infer severity from confidence and attack type"""
        # High-severity attack types
        if self.attack_type in ['sqli', 'rce', 'ssrf', 'xxe', 'ssti']:
            return 'critical' if confidence in ['confirmed', 'high'] else 'high'
        
        # Medium-severity
        if self.attack_type in ['xss', 'csrf', 'idor', 'lfi']:
            return 'high' if confidence in ['confirmed', 'high'] else 'medium'
        
        # Lower severity
        return 'medium' if confidence in ['confirmed', 'high'] else 'low'
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scanner statistics"""
        return dict(self._stats)
    
    # ========== Pattern matching helpers ==========
    
    def check_patterns(
        self,
        content: str,
        patterns: List[str],
        is_regex: bool = True
    ) -> Tuple[bool, str]:
        """
        Check content against a list of patterns.
        
        Args:
            content: Content to search
            patterns: List of patterns (regex or literal)
            is_regex: Whether patterns are regex
            
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
                # Invalid regex, try as literal
                if pattern.lower() in content.lower():
                    return True, pattern
        
        return False, ""
    
    def check_time_based(
        self,
        response: AttackResponse,
        baseline_time_ms: float,
        delay_seconds: float = 5.0,
        tolerance: float = 0.8
    ) -> bool:
        """
        Check for time-based vulnerability by comparing response times.
        
        Args:
            response: Response to check
            baseline_time_ms: Normal response time
            delay_seconds: Expected delay from payload
            tolerance: Acceptable variance (0.8 = 80%)
            
        Returns:
            True if response time indicates successful delay
        """
        expected_delay_ms = delay_seconds * 1000
        actual_delay_ms = response.response_time_ms - baseline_time_ms
        
        # Check if delay matches expected with tolerance
        min_expected = expected_delay_ms * tolerance
        max_expected = expected_delay_ms * (1 + (1 - tolerance))
        
        return min_expected <= actual_delay_ms <= max_expected
    
    def check_reflection(
        self,
        response: AttackResponse,
        payload: str,
        encoded: bool = False
    ) -> Tuple[bool, str]:
        """
        Check if payload is reflected in response.
        
        Args:
            response: Response to check
            payload: Payload to look for
            encoded: Whether to check for encoded versions
            
        Returns:
            Tuple of (reflected, evidence)
        """
        if not response.body:
            return False, ""
        
        # Check exact match
        if payload in response.body:
            start = response.body.find(payload)
            evidence = response.body[max(0, start-20):start+len(payload)+20]
            return True, evidence
        
        if encoded:
            # Check HTML-encoded
            import html
            html_encoded = html.escape(payload)
            if html_encoded in response.body:
                return True, f"HTML encoded: {html_encoded}"
            
            # Check URL-encoded
            from urllib.parse import quote
            url_encoded = quote(payload)
            if url_encoded in response.body:
                return True, f"URL encoded: {url_encoded}"
        
        return False, ""
