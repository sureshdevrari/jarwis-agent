"""
Jarwis AGI Pen Test - Rate Limit Bypass Scanner
Tests for rate limiting bypass vulnerabilities:
- Missing rate limiting on sensitive endpoints
- Rate limit bypass via headers (X-Forwarded-For rotation)
- Rate limit bypass via parameter pollution
- Distributed rate limit bypass (concurrent requests)
- Time-based rate limit reset exploitation
- API key rate limit bypass

OWASP Category: A07:2021 - Identification and Authentication Failures
"""

import asyncio
import logging
import time
import random
import string
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


class RateLimitBypassScanner:
    """
    Scans for Rate Limiting Bypass vulnerabilities
    
    Based on security measures implemented in Jarwis database/security.py:
    - Tests if rate limits can be bypassed via IP spoofing headers
    - Tests if sensitive endpoints lack rate limiting
    - Tests for race conditions in rate limit checking
    - Tests for parameter-based rate limit bypass
    """
    
    # Endpoints that MUST have rate limiting
    CRITICAL_ENDPOINTS = [
        # Authentication
        ('/login', 'POST'),
        ('/signin', 'POST'),
        ('/auth/login', 'POST'),
        ('/api/auth/login', 'POST'),
        ('/api/login', 'POST'),
        # Password reset
        ('/forgot-password', 'POST'),
        ('/password-reset', 'POST'),
        ('/api/auth/forgot-password', 'POST'),
        ('/api/password/reset', 'POST'),
        # OTP/MFA
        ('/verify-otp', 'POST'),
        ('/mfa/verify', 'POST'),
        ('/api/auth/verify-otp', 'POST'),
        # Registration (spam prevention)
        ('/register', 'POST'),
        ('/signup', 'POST'),
        ('/api/auth/register', 'POST'),
        # Contact/Feedback (spam prevention)
        ('/contact', 'POST'),
        ('/api/contact', 'POST'),
        ('/feedback', 'POST'),
    ]
    
    # IP spoofing headers to try
    IP_SPOOF_HEADERS = [
        'X-Forwarded-For',
        'X-Real-IP',
        'X-Client-IP',
        'X-Originating-IP',
        'CF-Connecting-IP',
        'True-Client-IP',
        'X-Forwarded',
        'Forwarded-For',
        'X-Remote-IP',
        'X-Remote-Addr',
        'Client-IP',
        'X-Host',
        'X-Forwarded-Host',
    ]
    
    # Common bypass techniques
    BYPASS_TECHNIQUES = [
        # Case variation
        {'x-forwarded-for': '127.0.0.1'},
        {'X-FORWARDED-FOR': '127.0.0.1'},
        {'x-Forwarded-For': '127.0.0.1'},
        # Multiple IPs
        {'X-Forwarded-For': '1.2.3.4, 127.0.0.1'},
        {'X-Forwarded-For': '127.0.0.1, 1.2.3.4'},
        # Port variation
        {'X-Forwarded-For': '127.0.0.1:80'},
        {'X-Forwarded-For': '127.0.0.1:443'},
        # IPv6
        {'X-Forwarded-For': '::1'},
        {'X-Forwarded-For': '::ffff:127.0.0.1'},
        # Multiple headers
        {'X-Forwarded-For': '1.2.3.4', 'X-Real-IP': '127.0.0.1'},
        # URL encoding
        {'X-Forwarded-For': '127%2e0%2e0%2e1'},
    ]

    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    async def scan(self) -> List[ScanResult]:
        """Run all rate limit bypass tests"""
        logger.info("Starting Rate Limit Bypass Scanner...")
        
        endpoints = getattr(self.context, 'endpoints', []) or []
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url and endpoints:
            parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found for rate limit bypass scanning")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            await asyncio.gather(
                self._test_missing_rate_limits(session, base_url),
                self._test_header_bypass(session, base_url),
                self._test_parameter_bypass(session, base_url),
                self._test_race_condition(session, base_url),
                self._test_api_key_bypass(session, base_url),
                return_exceptions=True
            )
        
        logger.info(f"Rate Limit Bypass Scanner completed. Found {len(self.results)} issues.")
        return self.results

    async def _test_missing_rate_limits(self, session: aiohttp.ClientSession, base_url: str):
        """Test for missing rate limits on critical endpoints"""
        
        for endpoint, method in self.CRITICAL_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            
            # First check if endpoint exists
            try:
                async with session.options(url) as response:
                    if response.status == 404:
                        continue
            except:
                pass
            
            # Send burst of requests to trigger rate limiting
            success_count = 0
            rate_limited = False
            
            test_data = {
                'email': 'test@example.com',
                'password': 'TestPassword123',
                'username': 'testuser'
            }
            
            for i in range(20):
                try:
                    if method == 'POST':
                        async with session.post(url, json=test_data, allow_redirects=False) as response:
                            if response.status == 429:
                                rate_limited = True
                                break
                            elif response.status in [200, 400, 401, 422]:
                                success_count += 1
                    else:
                        async with session.get(url, allow_redirects=False) as response:
                            if response.status == 429:
                                rate_limited = True
                                break
                            elif response.status in [200, 400, 401, 422]:
                                success_count += 1
                except:
                    pass
                
                # Small delay to avoid self-DoS
                await asyncio.sleep(0.05)
            
            if success_count >= 20 and not rate_limited:
                severity = 'high' if 'login' in endpoint or 'otp' in endpoint else 'medium'
                self.results.append(ScanResult(
                    id=f"RATE-LIMIT-MISSING-{len(self.results)}",
                    category="A07:2021",
                    severity=severity,
                    title=f"No Rate Limiting on {endpoint}",
                    description=f"Critical endpoint {endpoint} lacks rate limiting, enabling brute force attacks",
                    url=url,
                    method=method,
                    parameter="Request Rate",
                    evidence=f"Made {success_count} requests without triggering rate limit (429)",
                    remediation=f"Implement rate limiting: max 5 requests per minute for {endpoint}",
                    cwe_id="CWE-307",
                    poc=f"Sent {success_count} rapid requests without rate limiting",
                    reasoning="Missing rate limits allow credential stuffing and brute force attacks"
                ))
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_header_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test if rate limits can be bypassed via IP spoofing headers"""
        
        # Find a rate-limited endpoint first
        login_url = None
        for endpoint, method in self.CRITICAL_ENDPOINTS[:5]:
            url = urljoin(base_url, endpoint)
            try:
                async with session.post(url, json={'test': 'test'}) as response:
                    if response.status != 404:
                        login_url = url
                        break
            except:
                pass
        
        if not login_url:
            return
        
        # First, trigger rate limiting normally
        for _ in range(25):
            try:
                await session.post(login_url, json={'email': 'test@test.com', 'password': 'wrong'})
            except:
                pass
            await asyncio.sleep(0.05)
        
        # Check if we're rate limited
        try:
            async with session.post(login_url, json={'email': 'test@test.com', 'password': 'wrong'}) as response:
                if response.status != 429:
                    # Not rate limited, can't test bypass
                    return
        except:
            return
        
        # Now try bypass techniques
        for bypass_headers in self.BYPASS_TECHNIQUES:
            # Generate random IP for fresh rate limit bucket
            random_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            
            test_headers = bypass_headers.copy()
            for key in test_headers:
                if test_headers[key] == '127.0.0.1' or test_headers[key].startswith('1.2.3.4'):
                    test_headers[key] = random_ip
            
            try:
                async with session.post(
                    login_url,
                    json={'email': 'test@test.com', 'password': 'wrong'},
                    headers=test_headers
                ) as response:
                    if response.status != 429:
                        # Rate limit bypassed!
                        header_names = ', '.join(test_headers.keys())
                        self.results.append(ScanResult(
                            id=f"RATE-LIMIT-HEADER-BYPASS-{len(self.results)}",
                            category="A07:2021",
                            severity="high",
                            title="Rate Limit Bypass via Header Spoofing",
                            description=f"Rate limiting can be bypassed using {header_names} header(s)",
                            url=login_url,
                            method="POST",
                            parameter=header_names,
                            evidence=f"After triggering rate limit, request with {header_names} succeeded (status: {response.status})",
                            remediation="Use the actual client IP for rate limiting. Don't trust X-Forwarded-For without validation. Implement rate limiting at network edge.",
                            cwe_id="CWE-307",
                            poc=f"curl -H '{header_names}: {random_ip}' -X POST {login_url}",
                            reasoning="Trusting client-provided headers for rate limiting allows trivial bypass"
                        ))
                        return  # Found bypass, stop testing
            except:
                pass
            
            await asyncio.sleep(0.1)

    async def _test_parameter_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test if rate limits can be bypassed via parameter pollution"""
        
        login_endpoints = [
            '/api/auth/login',
            '/login',
            '/api/login',
        ]
        
        for endpoint in login_endpoints:
            url = urljoin(base_url, endpoint)
            
            try:
                # First verify endpoint exists
                async with session.post(url, json={'email': 'test@test.com', 'password': 'test'}) as response:
                    if response.status == 404:
                        continue
            except:
                continue
            
            # Trigger rate limit
            for _ in range(25):
                try:
                    await session.post(url, json={'email': 'test@test.com', 'password': 'wrong'})
                except:
                    pass
                await asyncio.sleep(0.03)
            
            # Verify rate limited
            try:
                async with session.post(url, json={'email': 'test@test.com', 'password': 'wrong'}) as response:
                    if response.status != 429:
                        continue
            except:
                continue
            
            # Try bypass via parameter variation
            bypass_payloads = [
                # Add null bytes
                {'email': 'test@test.com\x00', 'password': 'wrong'},
                # Case variation
                {'Email': 'test@test.com', 'Password': 'wrong'},
                # Extra parameters
                {'email': 'test@test.com', 'password': 'wrong', '_': str(int(time.time()))},
                # URL with query param
                {'email': 'test@test.com', 'password': 'wrong', 'nocache': random.randint(1, 99999)},
                # Array parameter
                {'email[]': 'test@test.com', 'password': 'wrong'},
                # Different content type as query params
            ]
            
            for payload in bypass_payloads:
                try:
                    async with session.post(url, json=payload) as response:
                        if response.status != 429:
                            self.results.append(ScanResult(
                                id=f"RATE-LIMIT-PARAM-BYPASS-{len(self.results)}",
                                category="A07:2021",
                                severity="high",
                                title="Rate Limit Bypass via Parameter Pollution",
                                description="Rate limiting can be bypassed by modifying request parameters",
                                url=url,
                                method="POST",
                                parameter="Request Body",
                                evidence=f"Modified payload bypassed rate limit (status: {response.status})",
                                remediation="Normalize request parameters before rate limit checking. Use consistent request fingerprinting.",
                                cwe_id="CWE-307",
                                poc=f"Rate limit based on unnormalized parameters",
                                reasoning="Inconsistent parameter parsing allows rate limit bucket escape"
                            ))
                            break
                except:
                    pass
                
                await asyncio.sleep(0.05)
            
            break  # Only test one endpoint

    async def _test_race_condition(self, session: aiohttp.ClientSession, base_url: str):
        """Test for race conditions in rate limit checking"""
        
        # Find a rate-limited endpoint
        test_url = None
        for endpoint, method in self.CRITICAL_ENDPOINTS[:3]:
            url = urljoin(base_url, endpoint)
            try:
                async with session.post(url, json={'test': 'test'}) as response:
                    if response.status != 404:
                        test_url = url
                        break
            except:
                pass
        
        if not test_url:
            return
        
        async def single_request():
            """Make a single request"""
            try:
                async with session.post(
                    test_url,
                    json={'email': 'race@test.com', 'password': 'test123'},
                    timeout=aiohttp.ClientTimeout(total=5)
                ) as response:
                    return response.status
            except:
                return None
        
        # Send concurrent requests to trigger race condition
        # If rate limit allows 5 requests, we might be able to sneak in more
        tasks = [single_request() for _ in range(50)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successful requests (not 429)
        success_count = sum(1 for r in results if r and r != 429 and not isinstance(r, Exception))
        rate_limited_count = sum(1 for r in results if r == 429)
        
        # If we got significantly more successes than expected, there's a race condition
        # Assume rate limit should be around 5-10 per window
        expected_max = 15
        
        if success_count > expected_max and rate_limited_count > 0:
            self.results.append(ScanResult(
                id=f"RATE-LIMIT-RACE-{len(self.results)}",
                category="A07:2021",
                severity="high",
                title="Rate Limit Race Condition",
                description=f"Rate limiting has race condition - {success_count} of 50 concurrent requests succeeded",
                url=test_url,
                method="POST",
                parameter="Concurrent Requests",
                evidence=f"Sent 50 concurrent requests: {success_count} succeeded, {rate_limited_count} rate-limited",
                remediation="Use atomic rate limit checking (Redis INCR, database transactions). Check rate limit BEFORE processing request.",
                cwe_id="CWE-362",
                poc="Send 50+ concurrent requests to bypass rate limit",
                reasoning="Non-atomic rate limit checking allows exceeding limits via race condition"
            ))

    async def _test_api_key_bypass(self, session: aiohttp.ClientSession, base_url: str):
        """Test if using API keys bypasses rate limits entirely"""
        
        api_endpoints = [
            '/api/v1/',
            '/api/',
            '/v1/api/',
        ]
        
        for api_base in api_endpoints:
            url = urljoin(base_url, api_base)
            
            try:
                # Check endpoint exists
                async with session.get(url) as response:
                    if response.status == 404:
                        continue
            except:
                continue
            
            # Test various API key headers
            api_key_headers = [
                {'X-API-Key': 'test-api-key-12345'},
                {'Authorization': 'Api-Key test-api-key-12345'},
                {'API-Key': 'test-api-key-12345'},
                {'X-API-Token': 'test-api-key-12345'},
                {'apikey': 'test-api-key-12345'},
            ]
            
            for api_headers in api_key_headers:
                # Send burst with API key
                success_count = 0
                for _ in range(30):
                    try:
                        async with session.get(url, headers=api_headers) as response:
                            if response.status != 429:
                                success_count += 1
                    except:
                        pass
                    await asyncio.sleep(0.02)
                
                if success_count >= 30:
                    header_name = list(api_headers.keys())[0]
                    self.results.append(ScanResult(
                        id=f"RATE-LIMIT-API-KEY-{len(self.results)}",
                        category="A07:2021",
                        severity="medium",
                        title="API Key May Bypass Rate Limits",
                        description=f"Requests with {header_name} header may not be rate limited",
                        url=url,
                        method="GET",
                        parameter=header_name,
                        evidence=f"{success_count} requests with API key header succeeded without rate limiting",
                        remediation="Apply rate limits to API key authenticated requests. Different limits for different tiers.",
                        cwe_id="CWE-307",
                        poc=f"curl -H '{header_name}: any-value' {url} (repeated)",
                        reasoning="API keys should still be subject to rate limiting to prevent abuse"
                    ))
                    return
            
            break  # Only test first available API endpoint


# Export for scanner registration
__all__ = ['RateLimitBypassScanner', 'ScanResult']
