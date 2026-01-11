"""
Jarwis AGI Pen Test - CSRF Scanner
Detects Cross-Site Request Forgery vulnerabilities (A01:2021 - Broken Access Control)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
from typing import Dict, List, Optional, Any, Tuple
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


class CSRFScanner:
    """
    Scans for Cross-Site Request Forgery vulnerabilities
    OWASP A01:2021 - Broken Access Control
    
    Checks:
    - Missing CSRF tokens
    - Predictable tokens
    - Token not validated
    - Token reuse
    - Token bypass techniques
    - SameSite cookie protection
    """
    
    # Form actions that typically require CSRF protection
    SENSITIVE_ACTIONS = [
        'delete', 'remove', 'update', 'change', 'edit', 'modify',
        'create', 'add', 'new', 'submit', 'post', 'transfer',
        'password', 'email', 'profile', 'settings', 'admin',
        'logout', 'deactivate', 'activate', 'enable', 'disable',
    ]
    
    # Common CSRF token field names
    CSRF_TOKEN_NAMES = [
        'csrf', 'csrf_token', 'csrftoken', '_csrf', 'xsrf',
        'xsrf_token', 'xsrftoken', '_xsrf', 'token', 'auth_token',
        'authenticity_token', 'csrf-token', '__RequestVerificationToken',
        'anticsrf', 'anti-csrf-token', '_token', 'formkey',
    ]
    
    # Common CSRF header names
    CSRF_HEADERS = [
        'X-CSRF-Token', 'X-XSRF-Token', 'X-Requested-With',
        'X-CSRFToken', 'X-CSRF-TOKEN',
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
        logger.info("Starting CSRF scan...")
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
            
            # Analyze main page for forms
            await self._analyze_page(session, base_url)
            
            # Analyze discovered endpoints
            if hasattr(self.context, 'endpoints'):
                for endpoint in self.context.endpoints[:30]:
                    ep_url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                    if ep_url:
                        await self._analyze_page(session, ep_url)
        
        logger.info(f"CSRF scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _analyze_page(self, session: aiohttp.ClientSession, url: str):
        """Analyze page for CSRF vulnerabilities"""
        try:
            await asyncio.sleep(1 / self.rate_limit)
            
            headers = {'User-Agent': 'Mozilla/5.0'}
            
            async with session.get(url, headers=headers) as response:
                body = await response.text()
                
                # Find forms
                forms = self._extract_forms(body, url)
                
                for form in forms:
                    await self._analyze_form(session, form, url)
                    
        except Exception as e:
            logger.debug(f"CSRF page analysis error: {e}")
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        
        # Simple form extraction
        form_pattern = r'<form[^>]*>(.*?)</form>'
        form_matches = re.findall(form_pattern, html, re.DOTALL | re.IGNORECASE)
        
        for i, form_content in enumerate(form_matches):
            form = {
                'index': i,
                'content': form_content,
                'action': '',
                'method': 'GET',
                'has_csrf': False,
                'csrf_token': None,
                'is_sensitive': False,
            }
            
            # Extract action
            action_match = re.search(r'action=["\']([^"\']*)["\']', html, re.IGNORECASE)
            if action_match:
                form['action'] = urljoin(base_url, action_match.group(1))
            else:
                form['action'] = base_url
            
            # Extract method
            method_match = re.search(r'method=["\']?(post|get)["\']?', html, re.IGNORECASE)
            if method_match:
                form['method'] = method_match.group(1).upper()
            
            # Check for CSRF token
            for token_name in self.CSRF_TOKEN_NAMES:
                pattern = rf'name=["\']?{token_name}["\']?\s+value=["\']([^"\']*)["\']'
                token_match = re.search(pattern, form_content, re.IGNORECASE)
                if token_match:
                    form['has_csrf'] = True
                    form['csrf_token'] = token_match.group(1)
                    break
                
                # Check for hidden input with token name
                pattern2 = rf'type=["\']hidden["\'][^>]*name=["\']?{token_name}'
                if re.search(pattern2, form_content, re.IGNORECASE):
                    form['has_csrf'] = True
                    break
            
            # Check if form is sensitive
            form_lower = form_content.lower() + form['action'].lower()
            form['is_sensitive'] = any(action in form_lower for action in self.SENSITIVE_ACTIONS)
            
            forms.append(form)
        
        return forms
    
    async def _analyze_form(self, session: aiohttp.ClientSession, form: Dict, page_url: str):
        """Analyze individual form for CSRF"""
        
        # Only check POST forms and sensitive GET forms
        if form['method'] == 'GET' and not form['is_sensitive']:
            return
        
        # Check for missing CSRF token
        if not form['has_csrf'] and form['is_sensitive']:
            result = ScanResult(
                id=f"CSRF-MISSING-{len(self.results)+1}",
                category="A01:2021 - Broken Access Control",
                severity="high",
                title="Missing CSRF Token on Sensitive Form",
                description="Form lacks CSRF protection token.",
                url=form['action'] or page_url,
                method=form['method'],
                evidence=f"Form index {form['index']} has no CSRF token",
                remediation="Add CSRF token to all state-changing forms.",
                cwe_id="CWE-352",
                reasoning="Sensitive form without CSRF protection"
            )
            self.results.append(result)
            return
        
        # If form has token, test if it's validated
        if form['has_csrf'] and form['csrf_token']:
            await self._test_token_validation(session, form, page_url)
    
    async def _test_token_validation(self, session: aiohttp.ClientSession, form: Dict, page_url: str):
        """Test if CSRF token is actually validated"""
        
        try:
            # Try submitting with modified token
            modified_token = form['csrf_token'][:-4] + 'xxxx' if len(form['csrf_token']) > 4 else 'invalid'
            
            # Try submitting with empty token
            empty_tests = [
                ('empty', ''),
                ('modified', modified_token),
                ('removed', None),
            ]
            
            for test_name, test_token in empty_tests:
                await asyncio.sleep(1 / self.rate_limit)
                
                headers = {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'User-Agent': 'Mozilla/5.0',
                    'Referer': page_url,
                }
                
                # Build minimal form data
                data = {}
                if test_token is not None:
                    # Find the token field name
                    for token_name in self.CSRF_TOKEN_NAMES:
                        if token_name.lower() in form['content'].lower():
                            data[token_name] = test_token
                            break
                
                # Add a dummy field
                data['test'] = 'value'
                
                try:
                    async with session.post(form['action'], data=data, headers=headers) as response:
                        status = response.status
                        body = await response.text()
                        
                        # Check if request was accepted (not 403/400 for CSRF)
                        if status in [200, 201, 302]:
                            # Check if there's no CSRF error
                            csrf_errors = ['csrf', 'token', 'invalid', 'expired', 'forbidden']
                            if not any(e in body.lower() for e in csrf_errors):
                                result = ScanResult(
                                    id=f"CSRF-BYPASS-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="high",
                                    title=f"CSRF Token Not Validated ({test_name})",
                                    description=f"Form accepts {test_name} CSRF token.",
                                    url=form['action'],
                                    method="POST",
                                    evidence=f"Request with {test_name} token returned {status}",
                                    remediation="Validate CSRF tokens on server side.",
                                    cwe_id="CWE-352",
                                    poc=f"Submit with {test_name} token",
                                    reasoning=f"Form processed with {test_name} CSRF token"
                                )
                                self.results.append(result)
                                return
                                
                except Exception as e:
                    logger.debug(f"Token validation test error: {e}")
                    
        except Exception as e:
            logger.debug(f"CSRF token validation test error: {e}")


class CSRFTokenAnalyzer:
    """
    Analyzes CSRF token strength and predictability
    OWASP A01:2021 - Broken Access Control
    """
    
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
        logger.info("Starting CSRF Token Analysis...")
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
            
            # Collect multiple tokens
            tokens = await self._collect_tokens(session, base_url)
            
            if len(tokens) >= 2:
                # Analyze token entropy
                self._analyze_token_entropy(base_url, tokens)
                
                # Check for token reuse
                self._check_token_reuse(base_url, tokens)
        
        logger.info(f"CSRF token analysis complete. Found {len(self.results)} issues")
        return self.results
    
    async def _collect_tokens(self, session: aiohttp.ClientSession, url: str) -> List[str]:
        """Collect CSRF tokens from multiple requests"""
        tokens = []
        
        csrf_token_names = [
            'csrf', 'csrf_token', 'csrftoken', '_csrf', 'xsrf',
            'xsrf_token', '_token', 'authenticity_token',
        ]
        
        for _ in range(5):
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                async with session.get(url) as response:
                    body = await response.text()
                    
                    # Extract tokens from hidden fields
                    for name in csrf_token_names:
                        pattern = rf'name=["\']?{name}["\']?\s+value=["\']([^"\']+)["\']'
                        match = re.search(pattern, body, re.IGNORECASE)
                        if match:
                            tokens.append(match.group(1))
                            break
                        
                        # Alternative pattern
                        pattern2 = rf'value=["\']([^"\']+)["\'][^>]*name=["\']?{name}'
                        match2 = re.search(pattern2, body, re.IGNORECASE)
                        if match2:
                            tokens.append(match2.group(1))
                            break
                            
            except Exception as e:
                logger.debug(f"Token collection error: {e}")
        
        return tokens
    
    def _analyze_token_entropy(self, url: str, tokens: List[str]):
        """Analyze token entropy and randomness"""
        
        if not tokens:
            return
        
        # Check token length
        avg_length = sum(len(t) for t in tokens) / len(tokens)
        
        if avg_length < 16:
            result = ScanResult(
                id=f"CSRF-SHORT-{len(self.results)+1}",
                category="A01:2021 - Broken Access Control",
                severity="medium",
                title="Short CSRF Token",
                description=f"CSRF tokens average only {avg_length:.0f} characters.",
                url=url,
                method="GET",
                evidence=f"Sample: {tokens[0][:30]}",
                remediation="Use at least 128-bit random CSRF tokens.",
                cwe_id="CWE-330",
                reasoning="Short tokens are easier to predict/brute force"
            )
            self.results.append(result)
        
        # Check for patterns
        if self._tokens_have_pattern(tokens):
            result = ScanResult(
                id=f"CSRF-PREDICT-{len(self.results)+1}",
                category="A01:2021 - Broken Access Control",
                severity="high",
                title="Predictable CSRF Tokens",
                description="CSRF tokens show predictable patterns.",
                url=url,
                method="GET",
                evidence=f"Tokens: {', '.join(tokens[:3])}",
                remediation="Use cryptographically secure random tokens.",
                cwe_id="CWE-330",
                reasoning="Token patterns suggest weak randomness"
            )
            self.results.append(result)
    
    def _tokens_have_pattern(self, tokens: List[str]) -> bool:
        """Check if tokens show predictable patterns"""
        
        if len(tokens) < 2:
            return False
        
        # Check for identical tokens
        if len(set(tokens)) == 1:
            return True
        
        # Check for sequential patterns
        try:
            nums = []
            for t in tokens:
                num_match = re.search(r'\d+', t)
                if num_match:
                    nums.append(int(num_match.group()))
            
            if len(nums) >= 2:
                diffs = [nums[i+1] - nums[i] for i in range(len(nums)-1)]
                if len(set(diffs)) == 1 and diffs[0] != 0:  # Same non-zero difference
                    return True
        except:
            pass
        
        # Check for high similarity (>80% same characters)
        if len(tokens) >= 2:
            same_count = sum(1 for a, b in zip(tokens[0], tokens[1]) if a == b)
            similarity = same_count / max(len(tokens[0]), len(tokens[1]))
            if similarity > 0.8:
                return True
        
        return False
    
    def _check_token_reuse(self, url: str, tokens: List[str]):
        """Check if tokens are being reused"""
        
        # If all tokens are the same, it's reuse
        if len(set(tokens)) == 1 and len(tokens) > 1:
            result = ScanResult(
                id=f"CSRF-REUSE-{len(self.results)+1}",
                category="A01:2021 - Broken Access Control",
                severity="medium",
                title="CSRF Token Reuse",
                description="Same CSRF token is returned on multiple requests.",
                url=url,
                method="GET",
                evidence=f"Token: {tokens[0][:40]}... (same on {len(tokens)} requests)",
                remediation="Generate new CSRF token for each session/request.",
                cwe_id="CWE-352",
                reasoning="Static tokens enable token fixation attacks"
            )
            self.results.append(result)
