"""
Jarwis AGI Pen Test - Mobile Security Scanner
Tests for mobile app security issues (applicable to mobile backends):
- SSL Pinning bypass detection
- API security for mobile backends
- Certificate validation issues
- Mobile-specific authentication weaknesses
- Insecure data transmission
- Device binding bypass
- Root/Jailbreak detection bypass

OWASP Mobile Top 10: M3 (Insecure Communication), M4 (Insecure Authentication)
"""

import asyncio
import logging
import re
import ssl
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import aiohttp

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


class MobileSecurityScanner:
    """
    Scans for Mobile Backend Security vulnerabilities
    
    Tests for:
    1. SSL/TLS configuration weaknesses
    2. Certificate pinning bypass indicators
    3. Mobile-specific API vulnerabilities
    4. Device binding/attestation bypass
    5. Root/Jailbreak detection bypass
    6. Insecure mobile authentication patterns
    """
    
    # Mobile-specific API endpoints
    MOBILE_API_PATTERNS = [
        '/api/mobile/',
        '/mobile/api/',
        '/v1/mobile/',
        '/m/api/',
        '/app/api/',
        '/api/app/',
    ]
    
    # Device/App-related endpoints
    DEVICE_ENDPOINTS = [
        '/api/device/register',
        '/api/device/verify',
        '/device/register',
        '/api/app/register',
        '/api/attestation/verify',
        '/api/safetynet/verify',
        '/api/devicecheck/verify',
        '/api/integrity/verify',
    ]
    
    # Mobile-specific headers
    MOBILE_HEADERS = {
        'User-Agent': 'JarwisScan/1.0 (Mobile Security Scanner)',
        'X-App-Version': '1.0.0',
        'X-Platform': 'Android',
        'X-Device-ID': 'test-device-12345',
    }
    
    # Root/Jailbreak bypass headers
    ROOT_BYPASS_HEADERS = [
        {'X-Rooted': 'false'},
        {'X-Jailbroken': 'false'},
        {'X-Device-Secure': 'true'},
        {'X-Integrity-Status': 'passed'},
        {'X-SafetyNet-Verified': 'true'},
        {'X-DeviceCheck-Passed': 'true'},
    ]

    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    async def scan(self) -> List[ScanResult]:
        """Run all mobile security tests"""
        logger.info("Starting Mobile Security Scanner...")
        
        endpoints = getattr(self.context, 'endpoints', []) or []
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url and endpoints:
            parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found for mobile security scanning")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            await asyncio.gather(
                self._test_ssl_configuration(base_url),
                self._test_mobile_api_discovery(session, base_url),
                self._test_device_binding_bypass(session, base_url),
                self._test_root_detection_bypass(session, base_url),
                self._test_mobile_auth_weaknesses(session, base_url),
                self._test_certificate_transparency(session, base_url),
                return_exceptions=True
            )
        
        logger.info(f"Mobile Security Scanner completed. Found {len(self.results)} issues.")
        return self.results

    async def _test_ssl_configuration(self, base_url: str):
        """Test SSL/TLS configuration for mobile security"""
        
        parsed = urlparse(base_url)
        if parsed.scheme != 'https':
            self.results.append(ScanResult(
                id=f"MOBILE-NO-HTTPS-{len(self.results)}",
                category="M3:2024",
                severity="critical",
                title="Mobile Backend Not Using HTTPS",
                description="Mobile API backend is not using HTTPS, all data transmitted in clear text",
                url=base_url,
                method="N/A",
                parameter="protocol",
                evidence=f"Scheme: {parsed.scheme}",
                remediation="Enable HTTPS with TLS 1.2+ on all mobile API endpoints",
                cwe_id="CWE-319",
                poc="Traffic can be captured with network sniffer",
                reasoning="HTTP traffic can be intercepted and modified by attackers on same network"
            ))
            return
        
        hostname = parsed.netloc.split(':')[0]
        port = int(parsed.port) if parsed.port else 443
        
        try:
            # Test TLS versions and cipher suites
            weak_protocols = []
            
            # Test SSLv3 (should fail)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                ctx.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=ctx),
                    timeout=5
                )
                writer.close()
                weak_protocols.append('SSLv3')
            except:
                pass
            
            # Test TLS 1.0 (should fail for mobile)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=ctx),
                    timeout=5
                )
                writer.close()
                weak_protocols.append('TLS 1.0')
            except:
                pass
            
            # Test TLS 1.1 (should fail for mobile)
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_1)
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(hostname, port, ssl=ctx),
                    timeout=5
                )
                writer.close()
                weak_protocols.append('TLS 1.1')
            except:
                pass
            
            if weak_protocols:
                self.results.append(ScanResult(
                    id=f"MOBILE-WEAK-TLS-{len(self.results)}",
                    category="M3:2024",
                    severity="high",
                    title="Weak TLS Versions Supported",
                    description=f"Server supports deprecated TLS versions: {', '.join(weak_protocols)}",
                    url=base_url,
                    method="N/A",
                    parameter="TLS Version",
                    evidence=f"Weak protocols: {weak_protocols}",
                    remediation="Disable TLS 1.0, TLS 1.1, and SSLv3. Only allow TLS 1.2 and TLS 1.3",
                    cwe_id="CWE-326",
                    poc=f"Server accepts connection with {weak_protocols[0]}",
                    reasoning="Weak TLS versions have known vulnerabilities (BEAST, POODLE)"
                ))
            
            # Get certificate info
            ctx = ssl.create_default_context()
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port, ssl=ctx),
                timeout=5
            )
            
            ssl_object = writer.get_extra_info('ssl_object')
            if ssl_object:
                cert = ssl_object.getpeercert()
                cipher = ssl_object.cipher()
                
                # Check cipher strength
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = ['RC4', 'DES', 'MD5', '3DES', 'NULL', 'EXPORT', 'anon']
                    if any(weak in cipher_name for weak in weak_ciphers):
                        self.results.append(ScanResult(
                            id=f"MOBILE-WEAK-CIPHER-{len(self.results)}",
                            category="M3:2024",
                            severity="high",
                            title="Weak Cipher Suite in Use",
                            description=f"Server using weak cipher: {cipher_name}",
                            url=base_url,
                            method="N/A",
                            parameter="Cipher Suite",
                            evidence=f"Cipher: {cipher_name}",
                            remediation="Configure server to use strong ciphers only (ECDHE, AES-GCM)",
                            cwe_id="CWE-327",
                            poc=f"Connected with weak cipher {cipher_name}",
                            reasoning="Weak ciphers can be broken, exposing encrypted data"
                        ))
            
            writer.close()
            
        except asyncio.TimeoutError:
            logger.debug("SSL test timed out")
        except Exception as e:
            logger.debug(f"SSL configuration test error: {e}")

    async def _test_mobile_api_discovery(self, session: aiohttp.ClientSession, base_url: str):
        """Discover mobile-specific API endpoints"""
        
        discovered_endpoints = []
        
        for pattern in self.MOBILE_API_PATTERNS:
            url = urljoin(base_url, pattern)
            
            try:
                async with session.get(url, headers=self.MOBILE_HEADERS) as response:
                    if response.status != 404:
                        discovered_endpoints.append(url)
                        
                        # Check for API documentation exposure
                        resp_text = await response.text()
                        if 'swagger' in resp_text.lower() or 'openapi' in resp_text.lower():
                            self.results.append(ScanResult(
                                id=f"MOBILE-API-DOC-EXPOSED-{len(self.results)}",
                                category="M3:2024",
                                severity="medium",
                                title="Mobile API Documentation Exposed",
                                description="Mobile API documentation is publicly accessible",
                                url=url,
                                method="GET",
                                parameter="N/A",
                                evidence="Swagger/OpenAPI documentation found",
                                remediation="Restrict API documentation to authenticated users or internal networks",
                                cwe_id="CWE-200",
                                poc=f"curl {url}",
                                reasoning="API documentation helps attackers understand attack surface"
                            ))
                            
            except:
                pass
            
            await asyncio.sleep(0.1)
        
        if discovered_endpoints:
            self.results.append(ScanResult(
                id=f"MOBILE-API-DISCOVERED-{len(self.results)}",
                category="M3:2024",
                severity="info",
                title="Mobile API Endpoints Discovered",
                description=f"Found {len(discovered_endpoints)} mobile-specific API endpoints",
                url=base_url,
                method="GET",
                parameter="N/A",
                evidence=f"Endpoints: {discovered_endpoints[:5]}",
                remediation="Ensure all mobile API endpoints have proper authentication and authorization",
                cwe_id="CWE-200",
                poc="Mobile API endpoint enumeration",
                reasoning="Mobile APIs may have different security posture than web APIs"
            ))

    async def _test_device_binding_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test for device binding/attestation bypass"""
        
        for endpoint in self.DEVICE_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            
            try:
                # Test 1: Missing device attestation
                async with session.post(url, json={}, headers=self.MOBILE_HEADERS) as response:
                    if response.status != 404:
                        resp_text = await response.text()
                        
                        # Check if device verification can be bypassed
                        if response.status == 200:
                            self.results.append(ScanResult(
                                id=f"MOBILE-DEVICE-NO-VERIFY-{len(self.results)}",
                                category="M4:2024",
                                severity="high",
                                title="Device Verification Missing or Weak",
                                description=f"Device verification endpoint accepts empty/fake attestation",
                                url=url,
                                method="POST",
                                parameter="attestation",
                                evidence=f"Empty request accepted with status {response.status}",
                                remediation="Implement robust device attestation (SafetyNet, DeviceCheck, App Attest)",
                                cwe_id="CWE-287",
                                poc="Send empty attestation payload",
                                reasoning="Weak device verification allows app cloning and tampering"
                            ))
                            continue
                
                # Test 2: Fake attestation token
                fake_attestations = [
                    {'attestation_token': 'fake_token_12345'},
                    {'safetynet_token': 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake'},
                    {'device_check_token': 'fake_device_check'},
                    {'integrity_token': 'fake_integrity_token'},
                    {'app_attest_token': 'fake_app_attest'},
                ]
                
                for fake_data in fake_attestations:
                    async with session.post(url, json=fake_data, headers=self.MOBILE_HEADERS) as response:
                        if response.status == 200:
                            self.results.append(ScanResult(
                                id=f"MOBILE-FAKE-ATTEST-{len(self.results)}",
                                category="M4:2024",
                                severity="critical",
                                title="Fake Attestation Token Accepted",
                                description="Device attestation accepts fake/invalid tokens",
                                url=url,
                                method="POST",
                                parameter=list(fake_data.keys())[0],
                                evidence=f"Fake token accepted: {list(fake_data.keys())[0]}",
                                remediation="Validate attestation tokens server-side with Google/Apple APIs",
                                cwe_id="CWE-287",
                                poc=f"Submit fake attestation token",
                                reasoning="Invalid attestation acceptance allows running on rooted/jailbroken devices"
                            ))
                            return
                    
                    await asyncio.sleep(0.05)
                    
            except Exception as e:
                logger.debug(f"Device binding test error for {url}: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_root_detection_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test for root/jailbreak detection bypass"""
        
        # Find mobile API or auth endpoints
        test_endpoints = [
            '/api/auth/login',
            '/api/mobile/auth',
            '/api/app/init',
            '/mobile/login',
            '/api/v1/auth/login',
        ]
        
        for endpoint in test_endpoints:
            url = urljoin(base_url, endpoint)
            
            try:
                # First test without root bypass headers
                async with session.post(
                    url, 
                    json={'email': 'test@test.com', 'password': 'test'},
                    headers=self.MOBILE_HEADERS
                ) as response:
                    if response.status == 404:
                        continue
                    
                    base_status = response.status
                    base_text = await response.text()
                
                # Check if there's root detection by response difference
                root_detected = 'root' in base_text.lower() or 'jailbreak' in base_text.lower()
                
                if root_detected:
                    # Now try bypass headers
                    for bypass_header in self.ROOT_BYPASS_HEADERS:
                        test_headers = {**self.MOBILE_HEADERS, **bypass_header}
                        
                        async with session.post(
                            url,
                            json={'email': 'test@test.com', 'password': 'test'},
                            headers=test_headers
                        ) as response2:
                            resp_text = await response2.text()
                            
                            # Check if bypass worked
                            if 'root' not in resp_text.lower() and 'jailbreak' not in resp_text.lower():
                                header_name = list(bypass_header.keys())[0]
                                self.results.append(ScanResult(
                                    id=f"MOBILE-ROOT-BYPASS-{len(self.results)}",
                                    category="M4:2024",
                                    severity="high",
                                    title="Root/Jailbreak Detection Bypass",
                                    description=f"Root detection can be bypassed via {header_name} header",
                                    url=url,
                                    method="POST",
                                    parameter=header_name,
                                    evidence=f"Header {header_name}: {bypass_header[header_name]} bypassed detection",
                                    remediation="Don't trust client-provided headers for security decisions. Use device attestation.",
                                    cwe_id="CWE-290",
                                    poc=f"Add header {header_name}: {bypass_header[header_name]}",
                                    reasoning="Header-based root detection is trivially bypassed"
                                ))
                                return
                        
                        await asyncio.sleep(0.05)
                        
            except Exception as e:
                logger.debug(f"Root detection test error for {url}: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_mobile_auth_weaknesses(self, session: aiohttp.ClientSession, base_url: str):
        """Test for mobile-specific authentication weaknesses"""
        
        mobile_auth_endpoints = [
            '/api/auth/device-login',
            '/api/mobile/auth/biometric',
            '/api/auth/pin',
            '/api/auth/pattern',
            '/mobile/login/fingerprint',
            '/api/auth/touch-id',
            '/api/auth/face-id',
        ]
        
        for endpoint in mobile_auth_endpoints:
            url = urljoin(base_url, endpoint)
            
            try:
                async with session.post(url, json={}, headers=self.MOBILE_HEADERS) as response:
                    if response.status == 404:
                        continue
                    
                    resp_text = await response.text()
                    
                    # Test 1: Biometric bypass via empty assertion
                    if 'biometric' in endpoint or 'fingerprint' in endpoint or 'touch-id' in endpoint:
                        bypass_payloads = [
                            {'biometric_verified': True},
                            {'biometric_result': 'success'},
                            {'fingerprint_match': True},
                            {'local_auth_passed': True},
                        ]
                        
                        for payload in bypass_payloads:
                            async with session.post(url, json=payload, headers=self.MOBILE_HEADERS) as resp2:
                                if resp2.status == 200:
                                    self.results.append(ScanResult(
                                        id=f"MOBILE-BIO-BYPASS-{len(self.results)}",
                                        category="M4:2024",
                                        severity="critical",
                                        title="Biometric Authentication Bypass",
                                        description="Biometric authentication can be bypassed via client-side assertion",
                                        url=url,
                                        method="POST",
                                        parameter=list(payload.keys())[0],
                                        evidence=f"Payload {payload} accepted",
                                        remediation="Never trust client-side biometric results. Use secure enclave attestation.",
                                        cwe_id="CWE-287",
                                        poc=f"Send {payload}",
                                        reasoning="Client-asserted biometric results can be forged"
                                    ))
                                    return
                            
                            await asyncio.sleep(0.05)
                    
                    # Test 2: PIN brute force (no lockout)
                    if 'pin' in endpoint:
                        success_count = 0
                        for i in range(20):
                            pin = f"{i:04d}"
                            async with session.post(
                                url,
                                json={'pin': pin, 'device_id': 'test'},
                                headers=self.MOBILE_HEADERS
                            ) as pin_resp:
                                if pin_resp.status != 429:
                                    success_count += 1
                            await asyncio.sleep(0.02)
                        
                        if success_count >= 20:
                            self.results.append(ScanResult(
                                id=f"MOBILE-PIN-BRUTEFORCE-{len(self.results)}",
                                category="M4:2024",
                                severity="high",
                                title="PIN Brute Force Possible",
                                description="PIN authentication lacks lockout, enabling brute force",
                                url=url,
                                method="POST",
                                parameter="pin",
                                evidence=f"{success_count} PIN attempts without lockout",
                                remediation="Implement account lockout after 3-5 failed PIN attempts",
                                cwe_id="CWE-307",
                                poc="Try all 10000 PIN combinations",
                                reasoning="4-digit PIN has only 10000 combinations, easily brute forced without lockout"
                            ))
                            return
                            
            except Exception as e:
                logger.debug(f"Mobile auth test error for {url}: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_certificate_transparency(self, session: aiohttp.ClientSession, base_url: str):
        """Check for certificate transparency and pinning indicators"""
        
        try:
            # Check for public key pinning headers
            async with session.get(base_url) as response:
                headers = response.headers
                
                # Check for deprecated HPKP (Public Key Pins)
                if 'Public-Key-Pins' in headers or 'Public-Key-Pins-Report-Only' in headers:
                    self.results.append(ScanResult(
                        id=f"MOBILE-HPKP-DEPRECATED-{len(self.results)}",
                        category="M3:2024",
                        severity="low",
                        title="Deprecated HPKP Header Present",
                        description="Server uses deprecated HTTP Public Key Pinning",
                        url=base_url,
                        method="GET",
                        parameter="Public-Key-Pins",
                        evidence="HPKP header present",
                        remediation="HPKP is deprecated. Use Certificate Transparency instead.",
                        cwe_id="CWE-295",
                        poc="HPKP header in response",
                        reasoning="HPKP is deprecated and can cause availability issues"
                    ))
                
                # Check for Expect-CT header
                if 'Expect-CT' not in headers:
                    self.results.append(ScanResult(
                        id=f"MOBILE-NO-EXPECT-CT-{len(self.results)}",
                        category="M3:2024",
                        severity="low",
                        title="Missing Expect-CT Header",
                        description="Server doesn't enforce Certificate Transparency",
                        url=base_url,
                        method="GET",
                        parameter="Expect-CT",
                        evidence="No Expect-CT header",
                        remediation="Add Expect-CT header to enforce Certificate Transparency logging",
                        cwe_id="CWE-295",
                        poc="Check response headers",
                        reasoning="CT helps detect misissued certificates"
                    ))
                
                # Check for HSTS (critical for mobile)
                if 'Strict-Transport-Security' not in headers:
                    self.results.append(ScanResult(
                        id=f"MOBILE-NO-HSTS-{len(self.results)}",
                        category="M3:2024",
                        severity="medium",
                        title="Missing HSTS Header",
                        description="HTTP Strict Transport Security not enabled",
                        url=base_url,
                        method="GET",
                        parameter="Strict-Transport-Security",
                        evidence="No HSTS header",
                        remediation="Add HSTS header with long max-age (31536000) and includeSubDomains",
                        cwe_id="CWE-319",
                        poc="SSL stripping possible without HSTS",
                        reasoning="HSTS prevents SSL stripping attacks on mobile devices"
                    ))
                    
        except Exception as e:
            logger.debug(f"Certificate transparency test error: {e}")


# Export for scanner registration
__all__ = ['MobileSecurityScanner', 'ScanResult']
