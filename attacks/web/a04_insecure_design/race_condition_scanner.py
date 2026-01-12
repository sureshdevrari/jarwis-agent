"""
Jarwis AGI Pen Test - Race Condition Scanner
Detects Race Condition / TOCTOU vulnerabilities (A04:2021 - Insecure Design)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import time
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


class RaceConditionScanner:
    """
    Scans for Race Condition (TOCTOU) vulnerabilities
    OWASP A04:2021 - Insecure Design
    CWE-362: Concurrent Execution using Shared Resource
    
    Attack vectors:
    - Coupon/promo code multiple use
    - Balance overdraft
    - Reward abuse
    - Invite code abuse
    - Like/vote inflation
    - File upload race
    - Password reset race
    - Session race
    """
    
    # Endpoints likely to have race conditions
    VULNERABLE_ENDPOINTS = {
        'balance': ['/api/transfer', '/api/withdraw', '/api/redeem', '/api/payment'],
        'coupon': ['/api/coupon', '/api/promo', '/api/discount', '/api/voucher', '/api/code'],
        'vote': ['/api/vote', '/api/like', '/api/upvote', '/api/favorite', '/api/rate'],
        'invite': ['/api/invite', '/api/referral', '/api/join'],
        'claim': ['/api/claim', '/api/reward', '/api/bonus', '/api/gift'],
        'limit': ['/api/limit', '/api/quota', '/api/cap'],
    }
    
    # Number of concurrent requests
    CONCURRENT_REQUESTS = 20
    
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
        logger.info("Starting Race Condition scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        # Collect endpoints
        endpoints_to_test = set()
        for category, paths in self.VULNERABLE_ENDPOINTS.items():
            for path in paths:
                endpoints_to_test.add((urljoin(base_url, path), category))
        
        # Add discovered endpoints
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints[:30]:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                method = endpoint.get('method', 'GET') if isinstance(endpoint, dict) else 'GET'
                
                if method == 'POST' and url:
                    # Check if URL matches vulnerable patterns
                    for category, paths in self.VULNERABLE_ENDPOINTS.items():
                        for path in paths:
                            if path.lower() in url.lower():
                                endpoints_to_test.add((url, category))
                                break
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=50)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url, category in endpoints_to_test:
                await self._test_race_condition(session, url, category)
        
        logger.info(f"Race condition scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_race_condition(self, session: aiohttp.ClientSession, url: str, category: str):
        """Test a URL for race conditions"""
        
        # First, check if endpoint exists and get expected behavior
        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0'
            }
            
            # Add auth if available
            if hasattr(self.context, 'cookies'):
                cookies = self.context.cookies
            else:
                cookies = {}
            
            # Test different payloads based on category
            payloads = self._get_payloads(category)
            
            for payload in payloads:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Send concurrent requests
                tasks = []
                for _ in range(self.CONCURRENT_REQUESTS):
                    task = self._send_request(session, url, payload, headers, cookies)
                    tasks.append(task)
                
                # Execute all requests concurrently
                start_time = time.time()
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                elapsed = time.time() - start_time
                
                # Analyze responses
                await self._analyze_responses(url, category, responses, payload, elapsed)
                
        except Exception as e:
            logger.debug(f"Race condition test error for {url}: {e}")
    
    def _get_payloads(self, category: str) -> List[dict]:
        """Get test payloads based on category"""
        payloads = {
            'balance': [
                {'amount': 100, 'to': 'test_account'},
                {'amount': 1, 'action': 'withdraw'},
            ],
            'coupon': [
                {'code': 'TESTCODE'},
                {'coupon': 'DISCOUNT10'},
                {'promo_code': 'SAVE20'},
            ],
            'vote': [
                {'item_id': 1, 'action': 'like'},
                {'post_id': 1, 'type': 'upvote'},
            ],
            'invite': [
                {'code': 'INVITE123'},
                {'referral_code': 'REF123'},
            ],
            'claim': [
                {'reward_id': 1},
                {'bonus_type': 'daily'},
            ],
            'limit': [
                {'action': 'check_limit'},
            ],
        }
        return payloads.get(category, [{'test': 'value'}])
    
    async def _send_request(self, session: aiohttp.ClientSession, url: str, 
                           payload: dict, headers: dict, cookies: dict) -> dict:
        """Send a single request and capture response"""
        try:
            async with session.post(url, json=payload, headers=headers, cookies=cookies) as response:
                body = await response.text()
                return {
                    'status': response.status,
                    'body': body,
                    'headers': dict(response.headers),
                    'success': True
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    async def _analyze_responses(self, url: str, category: str, 
                                 responses: List, payload: dict, elapsed: float):
        """Analyze responses for race condition indicators"""
        successful_responses = [r for r in responses if isinstance(r, dict) and r.get('success')]
        
        if len(successful_responses) < 2:
            return
        
        # Count success responses (2xx status codes)
        success_count = sum(1 for r in successful_responses if 200 <= r['status'] < 300)
        
        # Analyze based on category
        if category == 'coupon':
            # Check if coupon was applied multiple times
            if success_count > 1:
                applied_count = sum(1 for r in successful_responses 
                                   if 'success' in r['body'].lower() or 
                                   'applied' in r['body'].lower() or
                                   'redeemed' in r['body'].lower())
                
                if applied_count > 1:
                    result = ScanResult(
                        id=f"RACE-COUPON-{len(self.results)+1}",
                        category="A04:2021 - Insecure Design",
                        severity="high",
                        title="Race Condition - Multiple Coupon Redemption",
                        description=f"Coupon code was successfully applied {applied_count} times using race condition.",
                        url=url,
                        method="POST",
                        parameter="code",
                        evidence=f"{success_count} successful responses out of {self.CONCURRENT_REQUESTS}",
                        remediation="Implement atomic transactions with proper locking. Use database-level constraints.",
                        cwe_id="CWE-362",
                        poc=f"Send {self.CONCURRENT_REQUESTS} concurrent POST requests to {url}",
                        reasoning="Multiple concurrent requests succeeded where only one should"
                    )
                    self.results.append(result)
        
        elif category == 'balance':
            # Check for balance manipulation
            if success_count > 1:
                result = ScanResult(
                    id=f"RACE-BALANCE-{len(self.results)+1}",
                    category="A04:2021 - Insecure Design",
                    severity="critical",
                    title="Race Condition - Balance/Transaction Abuse",
                    description="Multiple balance transactions succeeded simultaneously. Possible double-spend vulnerability.",
                    url=url,
                    method="POST",
                    evidence=f"{success_count} successful transactions out of {self.CONCURRENT_REQUESTS}",
                    remediation="Use database transactions with proper isolation. Implement optimistic locking.",
                    cwe_id="CWE-362",
                    poc=f"Send {self.CONCURRENT_REQUESTS} concurrent withdrawal/transfer requests",
                    reasoning="Multiple financial transactions processed concurrently"
                )
                self.results.append(result)
        
        elif category == 'vote':
            # Check for vote manipulation
            if success_count > 1:
                result = ScanResult(
                    id=f"RACE-VOTE-{len(self.results)+1}",
                    category="A04:2021 - Insecure Design",
                    severity="medium",
                    title="Race Condition - Vote/Like Manipulation",
                    description="Multiple votes/likes registered simultaneously for same user.",
                    url=url,
                    method="POST",
                    evidence=f"{success_count} successful votes out of {self.CONCURRENT_REQUESTS}",
                    remediation="Check vote existence before insert atomically. Use unique constraints.",
                    cwe_id="CWE-362",
                    poc=f"Send {self.CONCURRENT_REQUESTS} concurrent vote requests",
                    reasoning="Multiple votes registered for single action"
                )
                self.results.append(result)
        
        elif category == 'claim':
            # Check for reward abuse
            if success_count > 1:
                result = ScanResult(
                    id=f"RACE-CLAIM-{len(self.results)+1}",
                    category="A04:2021 - Insecure Design",
                    severity="high",
                    title="Race Condition - Reward/Claim Abuse",
                    description="Multiple rewards claimed simultaneously.",
                    url=url,
                    method="POST",
                    evidence=f"{success_count} successful claims out of {self.CONCURRENT_REQUESTS}",
                    remediation="Implement proper locking for one-time rewards.",
                    cwe_id="CWE-362",
                    poc=f"Send {self.CONCURRENT_REQUESTS} concurrent claim requests",
                    reasoning="Multiple rewards/bonuses claimed via race condition"
                )
                self.results.append(result)
        
        # Generic race condition detection
        elif success_count > 1:
            # Check for inconsistent responses (potential race condition indicator)
            unique_bodies = set(r['body'][:100] for r in successful_responses)
            
            if len(unique_bodies) > 1:
                result = ScanResult(
                    id=f"RACE-GENERIC-{len(self.results)+1}",
                    category="A04:2021 - Insecure Design",
                    severity="medium",
                    title="Potential Race Condition Detected",
                    description="Concurrent requests returned inconsistent results, indicating possible race condition.",
                    url=url,
                    method="POST",
                    evidence=f"{len(unique_bodies)} unique responses from {self.CONCURRENT_REQUESTS} requests",
                    remediation="Review endpoint for shared state access. Implement proper synchronization.",
                    cwe_id="CWE-362",
                    reasoning="Inconsistent responses from concurrent requests"
                )
                self.results.append(result)


class LimitBypassScanner:
    """
    Scans for Rate Limit and Restriction Bypass vulnerabilities
    OWASP A04:2021 - Insecure Design
    
    Attack vectors:
    - Concurrent request bypass
    - Header manipulation bypass (X-Forwarded-For)
    - Case sensitivity bypass
    - Unicode bypass
    - Parameter pollution bypass
    """
    
    # Rate limited endpoints to test
    RATE_LIMITED_ENDPOINTS = [
        '/api/login',
        '/api/register',
        '/api/reset-password',
        '/api/forgot-password',
        '/api/verify',
        '/api/otp',
        '/api/send-code',
        '/auth/login',
        '/auth/signup',
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
        logger.info("Starting Rate Limit Bypass scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        endpoints_to_test = [urljoin(base_url, ep) for ep in self.RATE_LIMITED_ENDPOINTS]
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            for url in endpoints_to_test:
                await self._test_rate_limit_bypass(session, url)
        
        logger.info(f"Rate limit bypass scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _test_rate_limit_bypass(self, session: aiohttp.ClientSession, url: str):
        """Test various rate limit bypass techniques"""
        
        # First, check if endpoint exists
        try:
            async with session.post(url, json={'test': 'test'}) as response:
                if response.status == 404:
                    return
        except Exception:
            return
        
        # Test IP-based bypass via headers
        bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Forwarded-For': '8.8.8.8'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Client-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'True-Client-IP': '127.0.0.1'},
            {'CF-Connecting-IP': '8.8.8.8'},
            {'X-Cluster-Client-IP': '127.0.0.1'},
        ]
        
        for bypass_header in bypass_headers:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Send multiple requests with bypass header
                headers = {
                    **bypass_header,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0'
                }
                
                success_count = 0
                for _ in range(10):
                    async with session.post(url, json={'test': 'test'}, headers=headers) as response:
                        if response.status != 429:
                            success_count += 1
                
                # If all requests succeeded without rate limiting
                if success_count == 10:
                    result = ScanResult(
                        id=f"RATELIMIT-BYPASS-{len(self.results)+1}",
                        category="A04:2021 - Insecure Design",
                        severity="high",
                        title=f"Rate Limit Bypass via {list(bypass_header.keys())[0]}",
                        description=f"Rate limiting can be bypassed by manipulating {list(bypass_header.keys())[0]} header.",
                        url=url,
                        method="POST",
                        parameter=list(bypass_header.keys())[0],
                        evidence=f"{success_count}/10 requests succeeded without rate limit",
                        remediation="Don't trust client-provided IP headers for rate limiting. Use connection IP.",
                        cwe_id="CWE-770",
                        poc=f"Add header: {list(bypass_header.keys())[0]}: {list(bypass_header.values())[0]}",
                        reasoning="Header manipulation bypassed rate limiting"
                    )
                    self.results.append(result)
                    return
                    
            except Exception as e:
                logger.debug(f"Rate limit bypass test error: {e}")
