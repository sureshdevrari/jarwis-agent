"""
Jarwis AGI Pen Test - Mobile Deep Link Hijacking Scanner
Detects deep link vulnerabilities in mobile applications
Based on OWASP Mobile Top 10 - M1:2024 - Improper Credential Usage
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import aiohttp
import ssl

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    id: str
    category: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class DeepLinkHijackingScanner:
    """
    Scans for deep link/app link hijacking vulnerabilities
    OWASP Mobile M1:2024 - Improper Credential Usage
    
    Attack vectors:
    - Unverified deep links
    - Intent hijacking (Android)
    - Universal Links bypass (iOS)
    - OAuth callback hijacking
    - Custom scheme vulnerabilities
    """
    
    # Common deep link patterns
    DEEP_LINK_PATTERNS = [
        # OAuth callbacks
        '/oauth/callback', '/auth/callback', '/login/callback',
        '/oauth2/callback', '/connect/callback', '/signin-callback',
        
        # Password reset
        '/reset-password', '/password/reset', '/forgot-password/verify',
        
        # Email verification
        '/verify-email', '/email/verify', '/confirm-email',
        
        # Magic links
        '/magic-link', '/passwordless', '/login-link',
        
        # Payment callbacks
        '/payment/callback', '/checkout/callback', '/order/confirm',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Deep Link Hijacking scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Check main page for app links
            await self._check_app_association_files(session, base_url)
            
            # Check OAuth/callback endpoints
            await self._check_callback_endpoints(session, base_url)
            
            # Check discovered endpoints
            endpoints = getattr(self.context, 'endpoints', [])
            for endpoint in endpoints[:20]:
                ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if ep_url and self._is_deep_link_candidate(ep_url):
                    await self._test_deep_link(session, ep_url)
        
        logger.info(f"Deep Link scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_app_association_files(self, session: aiohttp.ClientSession, base_url: str):
        """Check for app association/verification files"""
        
        association_files = [
            '/.well-known/assetlinks.json',  # Android App Links
            '/.well-known/apple-app-site-association',  # iOS Universal Links
            '/apple-app-site-association',  # iOS (legacy)
        ]
        
        for path in association_files:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                url = urljoin(base_url, path)
                
                async with session.get(url) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        # Analyze Android assetlinks.json
                        if 'assetlinks' in path:
                            await self._analyze_android_assetlinks(url, body)
                        
                        # Analyze iOS AASA
                        if 'apple' in path:
                            await self._analyze_ios_aasa(url, body)
                            
            except Exception as e:
                logger.debug(f"Association file check error: {e}")
    
    async def _analyze_android_assetlinks(self, url: str, body: str):
        """Analyze Android assetlinks.json for vulnerabilities"""
        
        try:
            data = json.loads(body)
            
            for link in data:
                target = link.get('target', {})
                namespace = target.get('namespace', '')
                package = target.get('package_name', '')
                fingerprints = target.get('sha256_cert_fingerprints', [])
                
                # Check for missing or weak fingerprints
                if not fingerprints:
                    result = ScanResult(
                        id=f"DEEPLINK-ANDROID-{len(self.results)+1}",
                        category="M1:2024 - Improper Credential Usage",
                        severity="high",
                        title="Android App Links Missing Certificate Fingerprint",
                        description="assetlinks.json doesn't verify app signature.",
                        url=url,
                        method="GET",
                        evidence=f"Package: {package}, No fingerprints",
                        remediation="Add sha256_cert_fingerprints to verify app signature.",
                        cwe_id="CWE-295",
                        reasoning="Any app with same package name can intercept links"
                    )
                    self.results.append(result)
                
                # Check for wildcard paths (if present)
                relation = link.get('relation', [])
                if 'delegate_permission/common.handle_all_urls' in relation:
                    result = ScanResult(
                        id=f"DEEPLINK-ANDROID-INFO-{len(self.results)+1}",
                        category="M1:2024 - Improper Credential Usage",
                        severity="info",
                        title="Android App Links Configured",
                        description="App links properly configured.",
                        url=url,
                        method="GET",
                        evidence=f"Package: {package}",
                        remediation="Ensure certificate fingerprints are current.",
                        cwe_id="CWE-295",
                        reasoning="App links configuration detected"
                    )
                    self.results.append(result)
                    
        except json.JSONDecodeError:
            logger.debug("Invalid assetlinks.json")
    
    async def _analyze_ios_aasa(self, url: str, body: str):
        """Analyze iOS AASA for vulnerabilities"""
        
        try:
            # Remove any BOM or whitespace
            body = body.strip().lstrip('\ufeff')
            data = json.loads(body)
            
            # Check applinks configuration
            applinks = data.get('applinks', {})
            apps = applinks.get('apps', [])
            details = applinks.get('details', [])
            
            # apps should be empty array in modern AASA
            if apps:
                result = ScanResult(
                    id=f"DEEPLINK-IOS-{len(self.results)+1}",
                    category="M1:2024 - Improper Credential Usage",
                    severity="medium",
                    title="iOS AASA Using Legacy Format",
                    description="AASA uses deprecated 'apps' array.",
                    url=url,
                    method="GET",
                    evidence="Legacy format detected",
                    remediation="Update to modern AASA format.",
                    cwe_id="CWE-1104",
                    reasoning="Legacy format may have security gaps"
                )
                self.results.append(result)
            
            # Check for wildcard paths
            for detail in details:
                paths = detail.get('paths', [])
                components = detail.get('components', [])
                
                if '*' in str(paths) or '/*' in paths:
                    result = ScanResult(
                        id=f"DEEPLINK-IOS-WILDCARD-{len(self.results)+1}",
                        category="M1:2024 - Improper Credential Usage",
                        severity="low",
                        title="iOS AASA Uses Wildcard Paths",
                        description="Wildcard paths in AASA may expose unintended endpoints.",
                        url=url,
                        method="GET",
                        evidence=f"Paths: {paths}",
                        remediation="Use specific paths instead of wildcards.",
                        cwe_id="CWE-200",
                        reasoning="Wildcard may expose sensitive endpoints to app"
                    )
                    self.results.append(result)
                    
        except json.JSONDecodeError:
            logger.debug("Invalid AASA JSON")
    
    async def _check_callback_endpoints(self, session: aiohttp.ClientSession, base_url: str):
        """Check OAuth and other callback endpoints"""
        
        for path in self.DEEP_LINK_PATTERNS:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                url = urljoin(base_url, path)
                
                # Test with manipulated parameters
                test_params = [
                    f'{url}?redirect_uri=https://evil.com/callback',
                    f'{url}?callback=https://evil.com/steal',
                    f'{url}?next=https://evil.com/',
                ]
                
                for test_url in test_params:
                    async with session.get(test_url, allow_redirects=False) as response:
                        location = response.headers.get('Location', '')
                        
                        if 'evil.com' in location:
                            result = ScanResult(
                                id=f"DEEPLINK-REDIRECT-{len(self.results)+1}",
                                category="M1:2024 - Improper Credential Usage",
                                severity="high",
                                title="Open Redirect in Callback Endpoint",
                                description="Callback endpoint allows arbitrary redirect.",
                                url=test_url,
                                method="GET",
                                evidence=f"Redirects to: {location}",
                                poc=test_url,
                                remediation="Whitelist allowed redirect URLs.",
                                cwe_id="CWE-601",
                                reasoning="Can redirect auth tokens to attacker"
                            )
                            self.results.append(result)
                            return
                            
            except Exception as e:
                logger.debug(f"Callback endpoint test error: {e}")
    
    def _is_deep_link_candidate(self, url: str) -> bool:
        """Check if URL is a deep link candidate"""
        deep_link_keywords = [
            'callback', 'redirect', 'oauth', 'auth', 'login',
            'verify', 'confirm', 'reset', 'magic', 'link'
        ]
        return any(kw in url.lower() for kw in deep_link_keywords)
    
    async def _test_deep_link(self, session: aiohttp.ClientSession, url: str):
        """Test individual deep link for vulnerabilities"""
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            # Test parameter pollution
            if '?' in url:
                test_url = f"{url}&redirect_uri=https://evil.com"
            else:
                test_url = f"{url}?redirect_uri=https://evil.com"
            
            async with session.get(test_url, allow_redirects=False) as response:
                location = response.headers.get('Location', '')
                body = await response.text()
                
                # Check for redirect or token leak
                if 'evil.com' in location or 'evil.com' in body:
                    result = ScanResult(
                        id=f"DEEPLINK-{len(self.results)+1}",
                        category="M1:2024 - Improper Credential Usage",
                        severity="medium",
                        title="Deep Link Parameter Injection",
                        description="Deep link accepts injected redirect parameter.",
                        url=test_url,
                        method="GET",
                        evidence="Injected parameter reflected in response",
                        remediation="Validate and whitelist redirect parameters.",
                        cwe_id="CWE-601",
                        reasoning="Can hijack deep link flow"
                    )
                    self.results.append(result)
                    
        except Exception as e:
            logger.debug(f"Deep link test error: {e}")


class MobileAPISecurityScanner:
    """
    Scans mobile API endpoints for security issues
    OWASP Mobile M3:2024 - Insecure Communication
    """
    
    # Mobile-specific headers
    MOBILE_HEADERS = [
        'X-Device-ID', 'X-App-Version', 'X-Platform',
        'X-Installation-ID', 'X-Push-Token', 'X-Device-Token',
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting Mobile API Security scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Check for mobile API endpoints
            await self._check_mobile_apis(session, base_url)
            
            # Check for certificate pinning bypass
            await self._check_pinning_bypass(session, base_url)
        
        logger.info(f"Mobile API scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _check_mobile_apis(self, session: aiohttp.ClientSession, base_url: str):
        """Check for mobile-specific API vulnerabilities"""
        
        mobile_endpoints = [
            '/api/mobile', '/api/v1/mobile', '/mobile/api',
            '/api/device/register', '/api/push/register',
            '/api/app/config', '/api/settings/mobile',
        ]
        
        for endpoint in mobile_endpoints:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                url = urljoin(base_url, endpoint)
                
                # Test with manipulated device headers
                headers = {
                    'User-Agent': 'Mozilla/5.0',
                    'X-Device-ID': 'test-device-123',
                    'X-App-Version': '1.0.0',
                    'X-Platform': 'android',
                }
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        
                        # Check for sensitive config exposure
                        sensitive_keys = [
                            'api_key', 'secret', 'password', 'token',
                            'firebase', 'google_maps_key', 'stripe'
                        ]
                        
                        for key in sensitive_keys:
                            if key in body.lower():
                                result = ScanResult(
                                    id=f"MOBILE-API-{len(self.results)+1}",
                                    category="M3:2024 - Insecure Communication",
                                    severity="high",
                                    title="Mobile API Exposes Sensitive Config",
                                    description=f"Mobile API endpoint exposes {key}.",
                                    url=url,
                                    method="GET",
                                    evidence=f"Key found: {key}",
                                    remediation="Don't expose secrets in mobile API responses.",
                                    cwe_id="CWE-200",
                                    reasoning="Sensitive data in mobile config endpoint"
                                )
                                self.results.append(result)
                                break
                                
            except Exception as e:
                logger.debug(f"Mobile API check error: {e}")
    
    async def _check_pinning_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Check if API can be accessed without certificate pinning"""
        
        # If we can reach the API, pinning might be bypassable
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            async with session.get(base_url) as response:
                if response.status == 200:
                    # Check for pinning-related headers
                    headers = dict(response.headers)
                    
                    # HPKP is deprecated, but check for other indicators
                    if 'Public-Key-Pins' in headers:
                        result = ScanResult(
                            id=f"MOBILE-PINNING-{len(self.results)+1}",
                            category="M3:2024 - Insecure Communication",
                            severity="info",
                            title="HTTP Public Key Pinning Detected",
                            description="HPKP header present (deprecated).",
                            url=base_url,
                            method="GET",
                            evidence="Public-Key-Pins header",
                            remediation="Implement certificate pinning in mobile app.",
                            cwe_id="CWE-295",
                            reasoning="HPKP is deprecated, use app-level pinning"
                        )
                        self.results.append(result)
                        
        except Exception as e:
            logger.debug(f"Pinning check error: {e}")
