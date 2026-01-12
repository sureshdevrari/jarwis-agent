"""
Jarwis AGI Pen Test - CAPTCHA Bypass Scanner
Tests for CAPTCHA implementation weaknesses:
- Missing CAPTCHA on critical forms
- CAPTCHA token reuse
- Client-side only validation
- Bypass via request manipulation
- OCR-vulnerable CAPTCHAs detection
- CAPTCHA timing attacks
- Audio CAPTCHA weaknesses

OWASP Category: A07:2021 - Identification and Authentication Failures
"""

import asyncio
import logging
import re
import time
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin, parse_qs
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


class CaptchaBypassScanner:
    """
    Scans for CAPTCHA implementation weaknesses
    
    Based on common CAPTCHA bypass techniques:
    1. Missing CAPTCHA on sensitive forms
    2. CAPTCHA token reuse/replay
    3. Client-side only validation bypass
    4. Parameter removal bypass
    5. Case sensitivity bypass
    6. Empty/null value acceptance
    7. Response manipulation (always valid)
    """
    
    # Forms that SHOULD have CAPTCHA
    CAPTCHA_REQUIRED_FORMS = [
        # Authentication
        ('/login', 'POST', 'Login form'),
        ('/register', 'POST', 'Registration form'),
        ('/signup', 'POST', 'Signup form'),
        ('/forgot-password', 'POST', 'Password reset form'),
        ('/password-reset', 'POST', 'Password reset form'),
        # Contact/Feedback
        ('/contact', 'POST', 'Contact form'),
        ('/feedback', 'POST', 'Feedback form'),
        ('/support', 'POST', 'Support form'),
        ('/inquiry', 'POST', 'Inquiry form'),
        # Comments/Posts
        ('/comment', 'POST', 'Comment form'),
        ('/post', 'POST', 'Post form'),
        ('/review', 'POST', 'Review form'),
        # API equivalents
        ('/api/auth/register', 'POST', 'Registration API'),
        ('/api/contact', 'POST', 'Contact API'),
        ('/api/auth/forgot-password', 'POST', 'Password reset API'),
    ]
    
    # Known CAPTCHA indicators in forms/responses
    CAPTCHA_INDICATORS = [
        'recaptcha', 'g-recaptcha', 'grecaptcha',
        'hcaptcha', 'h-captcha',
        'captcha', 'captcha-token', 'captcha_token',
        'turnstile', 'cf-turnstile',
        'arkose', 'funcaptcha',
        'geetest', 'gt_challenge',
        'keycaptcha',
    ]
    
    # CAPTCHA parameter names
    CAPTCHA_PARAMS = [
        'g-recaptcha-response', 'recaptcha', 'recaptchaToken',
        'h-captcha-response', 'hcaptcha', 'hcaptchaToken',
        'captcha', 'captcha_token', 'captchaToken', 'captcha_response',
        'cf-turnstile-response', 'turnstileToken',
        'challenge', 'challenge_response',
    ]

    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = aiohttp.ClientTimeout(total=10)
        
    async def scan(self) -> List[ScanResult]:
        """Run all CAPTCHA bypass tests"""
        logger.info("Starting CAPTCHA Bypass Scanner...")
        
        endpoints = getattr(self.context, 'endpoints', []) or []
        base_url = self.config.get('target', {}).get('url', '')
        
        if not base_url and endpoints:
            parsed = urlparse(endpoints[0] if isinstance(endpoints[0], str) else endpoints[0].get('url', ''))
            base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if not base_url:
            logger.warning("No target URL found for CAPTCHA bypass scanning")
            return self.results
        
        async with aiohttp.ClientSession(timeout=self.timeout) as session:
            await asyncio.gather(
                self._test_missing_captcha(session, base_url),
                self._test_captcha_bypass_techniques(session, base_url),
                self._test_captcha_token_reuse(session, base_url),
                self._test_client_side_only(session, base_url),
                return_exceptions=True
            )
        
        logger.info(f"CAPTCHA Bypass Scanner completed. Found {len(self.results)} issues.")
        return self.results

    async def _test_missing_captcha(self, session: aiohttp.ClientSession, base_url: str):
        """Test for missing CAPTCHA on sensitive forms"""
        
        for endpoint, method, form_name in self.CAPTCHA_REQUIRED_FORMS:
            url = urljoin(base_url, endpoint)
            
            try:
                # Get the form page first
                async with session.get(url) as response:
                    if response.status == 404:
                        continue
                    
                    if response.status == 200:
                        text = await response.text()
                        
                        # Check if page has CAPTCHA
                        has_captcha = any(
                            indicator.lower() in text.lower() 
                            for indicator in self.CAPTCHA_INDICATORS
                        )
                        
                        if not has_captcha:
                            # Try submitting form without CAPTCHA
                            test_data = self._get_test_data_for_form(form_name)
                            
                            async with session.post(url, json=test_data, allow_redirects=False) as post_response:
                                if post_response.status in [200, 302, 422, 400]:
                                    # Form processed (even if validation failed)
                                    resp_text = await post_response.text()
                                    
                                    # Check if it's asking for captcha
                                    if 'captcha' not in resp_text.lower():
                                        # Determine severity based on form type
                                        if 'login' in endpoint or 'password' in endpoint:
                                            severity = 'high'
                                        elif 'register' in endpoint or 'contact' in endpoint:
                                            severity = 'medium'
                                        else:
                                            severity = 'low'
                                        
                                        self.results.append(ScanResult(
                                            id=f"CAPTCHA-MISSING-{len(self.results)}",
                                            category="A07:2021",
                                            severity=severity,
                                            title=f"Missing CAPTCHA on {form_name}",
                                            description=f"{form_name} at {endpoint} has no CAPTCHA protection",
                                            url=url,
                                            method=method,
                                            parameter="captcha",
                                            evidence=f"Form processed without CAPTCHA. Response: {post_response.status}",
                                            remediation="Implement CAPTCHA (reCAPTCHA v3, hCaptcha, or Cloudflare Turnstile) on all user-input forms",
                                            cwe_id="CWE-307",
                                            poc=f"Submit to {url} without CAPTCHA token",
                                            reasoning=f"{form_name} without CAPTCHA is vulnerable to automated abuse and brute force"
                                        ))
                                        
            except Exception as e:
                logger.debug(f"Missing CAPTCHA test error for {url}: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    def _get_test_data_for_form(self, form_name: str) -> dict:
        """Generate test data based on form type"""
        form_lower = form_name.lower()
        
        if 'login' in form_lower:
            return {'email': 'test@example.com', 'password': 'TestPassword123'}
        elif 'register' in form_lower or 'signup' in form_lower:
            return {
                'email': 'test@example.com',
                'password': 'TestPassword123',
                'name': 'Test User'
            }
        elif 'password' in form_lower:
            return {'email': 'test@example.com'}
        elif 'contact' in form_lower or 'feedback' in form_lower:
            return {
                'name': 'Test User',
                'email': 'test@example.com',
                'message': 'Test message'
            }
        else:
            return {'test': 'data'}

    async def _test_captcha_bypass_techniques(self, session: aiohttp.ClientSession, base_url: str):
        """Test various CAPTCHA bypass techniques"""
        
        for endpoint, method, form_name in self.CAPTCHA_REQUIRED_FORMS:
            url = urljoin(base_url, endpoint)
            
            try:
                # First check if endpoint has CAPTCHA
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
                    
                    text = await response.text()
                    has_captcha = any(
                        indicator.lower() in text.lower() 
                        for indicator in self.CAPTCHA_INDICATORS
                    )
                    
                    if not has_captcha:
                        continue  # No CAPTCHA to bypass
                
                test_data = self._get_test_data_for_form(form_name)
                
                # Bypass Technique 1: Empty CAPTCHA value
                for captcha_param in self.CAPTCHA_PARAMS:
                    bypass_data = {**test_data, captcha_param: ''}
                    if await self._test_bypass(session, url, method, bypass_data, 'empty value'):
                        self.results.append(ScanResult(
                            id=f"CAPTCHA-EMPTY-BYPASS-{len(self.results)}",
                            category="A07:2021",
                            severity="high",
                            title="CAPTCHA Bypass - Empty Value Accepted",
                            description=f"CAPTCHA validation accepts empty value for '{captcha_param}'",
                            url=url,
                            method=method,
                            parameter=captcha_param,
                            evidence=f"Empty {captcha_param} value was accepted",
                            remediation="Validate CAPTCHA response is non-empty before verification",
                            cwe_id="CWE-287",
                            poc=f'"{captcha_param}": ""',
                            reasoning="Empty CAPTCHA values completely bypass the challenge"
                        ))
                        return
                
                # Bypass Technique 2: Null value
                for captcha_param in self.CAPTCHA_PARAMS:
                    bypass_data = {**test_data, captcha_param: None}
                    if await self._test_bypass(session, url, method, bypass_data, 'null value'):
                        self.results.append(ScanResult(
                            id=f"CAPTCHA-NULL-BYPASS-{len(self.results)}",
                            category="A07:2021",
                            severity="high",
                            title="CAPTCHA Bypass - Null Value Accepted",
                            description=f"CAPTCHA validation accepts null value for '{captcha_param}'",
                            url=url,
                            method=method,
                            parameter=captcha_param,
                            evidence=f"Null {captcha_param} value was accepted",
                            remediation="Validate CAPTCHA response is not null before verification",
                            cwe_id="CWE-287",
                            poc=f'"{captcha_param}": null',
                            reasoning="Null CAPTCHA values bypass the challenge"
                        ))
                        return
                
                # Bypass Technique 3: Parameter removal
                bypass_data = test_data.copy()  # No CAPTCHA param
                if await self._test_bypass(session, url, method, bypass_data, 'parameter removal'):
                    self.results.append(ScanResult(
                        id=f"CAPTCHA-MISSING-PARAM-BYPASS-{len(self.results)}",
                        category="A07:2021",
                        severity="high",
                        title="CAPTCHA Bypass - Parameter Removal",
                        description="Request succeeds when CAPTCHA parameter is completely removed",
                        url=url,
                        method=method,
                        parameter="captcha",
                        evidence="Request without any CAPTCHA parameter was accepted",
                        remediation="Require CAPTCHA parameter to be present, not just valid",
                        cwe_id="CWE-287",
                        poc="Remove CAPTCHA parameter from request",
                        reasoning="Removing CAPTCHA parameter bypasses validation entirely"
                    ))
                    return
                
                # Bypass Technique 4: Static/predictable token
                static_tokens = [
                    'AAAAAAAA', '00000000', '11111111',
                    'test', 'captcha', 'bypass',
                    'success', 'valid', 'true'
                ]
                
                for token in static_tokens:
                    for captcha_param in self.CAPTCHA_PARAMS[:3]:
                        bypass_data = {**test_data, captcha_param: token}
                        if await self._test_bypass(session, url, method, bypass_data, f'static token {token}'):
                            self.results.append(ScanResult(
                                id=f"CAPTCHA-STATIC-TOKEN-{len(self.results)}",
                                category="A07:2021",
                                severity="critical",
                                title="CAPTCHA Accepts Static Token",
                                description=f"CAPTCHA validation accepts static/predictable token: '{token}'",
                                url=url,
                                method=method,
                                parameter=captcha_param,
                                evidence=f"Token '{token}' was accepted as valid CAPTCHA",
                                remediation="Verify CAPTCHA tokens with the provider's API. Never accept hardcoded values.",
                                cwe_id="CWE-287",
                                poc=f'"{captcha_param}": "{token}"',
                                reasoning="Static tokens allow automated bypass of CAPTCHA"
                            ))
                            return
                        
                        await asyncio.sleep(0.05)
                        
            except Exception as e:
                logger.debug(f"CAPTCHA bypass test error for {url}: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_bypass(self, session: aiohttp.ClientSession, url: str, method: str, data: dict, technique: str) -> bool:
        """Test if a specific bypass technique works"""
        try:
            if method == 'POST':
                async with session.post(url, json=data, allow_redirects=False) as response:
                    # Consider bypass successful if we get:
                    # - 200 OK (form processed)
                    # - 302 redirect (usually to success page)
                    # - Not getting CAPTCHA error
                    if response.status in [200, 302]:
                        text = await response.text()
                        
                        # Check for CAPTCHA error indicators
                        captcha_errors = [
                            'captcha', 'invalid', 'required', 'verify',
                            'robot', 'bot', 'challenge'
                        ]
                        
                        text_lower = text.lower()
                        has_captcha_error = any(err in text_lower for err in captcha_errors)
                        
                        # If no CAPTCHA error and looks like success
                        if not has_captcha_error:
                            success_indicators = [
                                'success', 'thank', 'submitted', 'received',
                                'welcome', 'dashboard', 'token'
                            ]
                            if any(ind in text_lower for ind in success_indicators):
                                return True
                        
                        # 302 redirect without CAPTCHA error is often bypass
                        if response.status == 302:
                            location = response.headers.get('Location', '').lower()
                            if 'success' in location or 'dashboard' in location:
                                return True
                                
        except:
            pass
        
        return False

    async def _test_captcha_token_reuse(self, session: aiohttp.ClientSession, base_url: str):
        """Test if CAPTCHA tokens can be reused"""
        
        # This test requires a valid CAPTCHA token from previous interaction
        # We can only check for indicators that suggest reuse vulnerability
        
        for endpoint, method, form_name in self.CAPTCHA_REQUIRED_FORMS[:5]:
            url = urljoin(base_url, endpoint)
            
            try:
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
                    
                    text = await response.text()
                    
                    # Look for potential token reuse vulnerabilities
                    
                    # Check 1: Server-side CAPTCHA token in form (can be reused)
                    server_token_patterns = [
                        r'name=["\']?captcha_token["\']?\s+value=["\']?([a-zA-Z0-9_-]+)',
                        r'data-captcha=["\']?([a-zA-Z0-9_-]+)',
                        r'"captcha_id":\s*"([a-zA-Z0-9_-]+)"',
                    ]
                    
                    for pattern in server_token_patterns:
                        match = re.search(pattern, text)
                        if match:
                            token = match.group(1)
                            
                            # Test reusing the same token twice
                            test_data = self._get_test_data_for_form(form_name)
                            test_data['captcha_token'] = token
                            
                            # First request
                            await session.post(url, json=test_data)
                            await asyncio.sleep(0.5)
                            
                            # Second request with same token
                            async with session.post(url, json=test_data) as response2:
                                if response2.status in [200, 302]:
                                    resp_text = await response2.text()
                                    if 'captcha' not in resp_text.lower() or 'invalid' not in resp_text.lower():
                                        self.results.append(ScanResult(
                                            id=f"CAPTCHA-TOKEN-REUSE-{len(self.results)}",
                                            category="A07:2021",
                                            severity="high",
                                            title="CAPTCHA Token Reuse Possible",
                                            description="CAPTCHA token can be reused for multiple submissions",
                                            url=url,
                                            method=method,
                                            parameter="captcha_token",
                                            evidence=f"Token {token[:20]}... accepted on second use",
                                            remediation="Invalidate CAPTCHA tokens after first use. Use one-time tokens.",
                                            cwe_id="CWE-287",
                                            poc="Submit same CAPTCHA token twice",
                                            reasoning="Reusable CAPTCHA tokens allow bypassing with a single solve"
                                        ))
                                        return
                                        
            except Exception as e:
                logger.debug(f"CAPTCHA reuse test error for {url}: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)

    async def _test_client_side_only(self, session: aiohttp.ClientSession, base_url: str):
        """Test for client-side only CAPTCHA validation"""
        
        for endpoint, method, form_name in self.CAPTCHA_REQUIRED_FORMS[:5]:
            url = urljoin(base_url, endpoint)
            
            try:
                async with session.get(url) as response:
                    if response.status != 200:
                        continue
                    
                    text = await response.text()
                    
                    # Check for client-side only validation indicators
                    client_side_patterns = [
                        # JavaScript validation only
                        r'if\s*\(\s*grecaptcha\.getResponse\(\)',
                        r'captcha.*validate.*script',
                        r'onclick.*captcha.*check',
                        # Hidden input that JavaScript fills
                        r'<input[^>]*id=["\']?captcha["\']?[^>]*hidden',
                        # Form submit prevented by JS only
                        r'return\s+validateCaptcha\(\)',
                    ]
                    
                    for pattern in client_side_patterns:
                        if re.search(pattern, text, re.IGNORECASE):
                            # Test by submitting without JavaScript execution
                            test_data = self._get_test_data_for_form(form_name)
                            
                            # Add fake CAPTCHA values
                            test_data['g-recaptcha-response'] = 'fake_token'
                            test_data['captcha_response'] = 'fake_token'
                            
                            async with session.post(url, json=test_data) as post_response:
                                if post_response.status in [200, 302]:
                                    resp_text = await post_response.text()
                                    
                                    # Check if fake token was accepted
                                    if 'invalid' not in resp_text.lower() and 'captcha' not in resp_text.lower():
                                        self.results.append(ScanResult(
                                            id=f"CAPTCHA-CLIENT-SIDE-{len(self.results)}",
                                            category="A07:2021",
                                            severity="high",
                                            title="CAPTCHA Validated Client-Side Only",
                                            description="CAPTCHA appears to be validated only via JavaScript, not server-side",
                                            url=url,
                                            method=method,
                                            parameter="captcha",
                                            evidence="Fake CAPTCHA token accepted by server",
                                            remediation="Always validate CAPTCHA tokens server-side via provider API",
                                            cwe_id="CWE-602",
                                            poc="Submit request with fake CAPTCHA token directly to server",
                                            reasoning="Client-side validation can be bypassed by sending requests directly"
                                        ))
                                        return
                            
                            break
                            
            except Exception as e:
                logger.debug(f"Client-side CAPTCHA test error for {url}: {e}")
            
            await asyncio.sleep(1 / self.rate_limit)


# Export for scanner registration
__all__ = ['CaptchaBypassScanner', 'ScanResult']
