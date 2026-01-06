"""
JARWIS AGI PEN TEST - HTTP Helper
Utilities for making requests and capturing full request/response details
Enhanced with JavaScript rendering support for modern web applications
"""

import aiohttp
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class HTTPExchange:
    """Represents a complete HTTP request/response exchange"""
    # Request details
    request_method: str
    request_url: str
    request_headers: Dict[str, str]
    request_body: str
    
    # Response details
    response_status: int
    response_status_text: str
    response_headers: Dict[str, str]
    response_body: str
    response_time_ms: float
    
    # Metadata
    timestamp: str
    
    def format_request(self) -> str:
        """Format request like Burp Suite"""
        lines = [f"{self.request_method} {self.request_url} HTTP/1.1"]
        for key, value in self.request_headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        if self.request_body:
            lines.append(self.request_body)
        return "\n".join(lines)
    
    def format_response(self) -> str:
        """Format response like Burp Suite"""
        lines = [f"HTTP/1.1 {self.response_status} {self.response_status_text}"]
        for key, value in self.response_headers.items():
            lines.append(f"{key}: {value}")
        lines.append("")
        # Truncate body if too long
        body = self.response_body
        if len(body) > 2000:
            body = body[:2000] + f"\n\n... [TRUNCATED - {len(self.response_body)} bytes total]"
        lines.append(body)
        return "\n".join(lines)


class HTTPClient:
    """HTTP client that captures full request/response details"""
    
    def __init__(self, timeout: int = 30):
        self.timeout = timeout
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Jarwis-Scanner/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        }
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict] = None,
        data: Optional[Dict] = None,
        cookies: Optional[Dict] = None,
        json_data: Optional[Dict] = None,
        allow_redirects: bool = True
    ) -> Tuple[HTTPExchange, bool]:
        """
        Make an HTTP request and return full exchange details.
        Returns (HTTPExchange, success_bool)
        """
        import time
        
        request_headers = {**self.default_headers}
        if headers:
            request_headers.update(headers)
        
        request_body = ""
        if data:
            request_body = "&".join(f"{k}={v}" for k, v in data.items())
            request_headers['Content-Type'] = 'application/x-www-form-urlencoded'
        elif json_data:
            import json
            request_body = json.dumps(json_data)
            request_headers['Content-Type'] = 'application/json'
        
        try:
            start_time = time.time()
            
            async with aiohttp.ClientSession(cookies=cookies) as session:
                async with session.request(
                    method,
                    url,
                    headers=request_headers,
                    data=data,
                    json=json_data,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False,
                    allow_redirects=allow_redirects
                ) as response:
                    response_time = (time.time() - start_time) * 1000
                    response_body = await response.text()
                    
                    exchange = HTTPExchange(
                        request_method=method,
                        request_url=url,
                        request_headers=request_headers,
                        request_body=request_body,
                        response_status=response.status,
                        response_status_text=response.reason or "",
                        response_headers=dict(response.headers),
                        response_body=response_body,
                        response_time_ms=response_time,
                        timestamp=datetime.now().isoformat()
                    )
                    
                    return exchange, True
                    
        except Exception as e:
            logger.debug(f"HTTP request failed: {e}")
            # Return empty exchange on failure
            exchange = HTTPExchange(
                request_method=method,
                request_url=url,
                request_headers=request_headers,
                request_body=request_body,
                response_status=0,
                response_status_text=str(e),
                response_headers={},
                response_body="",
                response_time_ms=0,
                timestamp=datetime.now().isoformat()
            )
            return exchange, False


def verify_sqli_response(response_body: str, response_headers: Dict) -> Tuple[bool, str]:
    """
    Verify if SQL injection is actually present by analyzing response.
    Returns (is_vulnerable, evidence_reason)
    """
    import re
    
    # SQL error patterns that CONFIRM vulnerability (not false positives)
    sqli_confirmations = [
        (r"You have an error in your SQL syntax", "MySQL syntax error"),
        (r"mysql_fetch", "MySQL fetch error"),
        (r"Warning.*mysql_", "MySQL warning"),
        (r"MySqlException", "MySQL exception"),
        (r"com\.mysql\.jdbc", "MySQL JDBC error"),
        (r"PostgreSQL.*ERROR", "PostgreSQL error"),
        (r"pg_query\(\)", "PostgreSQL query error"),
        (r"pg_exec\(\)", "PostgreSQL exec error"),
        (r"ORA-\d{5}", "Oracle error code"),
        (r"Oracle.*Driver", "Oracle driver error"),
        (r"Microsoft OLE DB Provider for SQL Server", "MSSQL OLE DB error"),
        (r"Unclosed quotation mark after the character string", "MSSQL syntax error"),
        (r"Microsoft SQL Native Client error", "MSSQL native client error"),
        (r"\[SQLITE_ERROR\]", "SQLite error"),
        (r"sqlite3\.OperationalError", "SQLite operational error"),
        (r"SQL command not properly ended", "SQL syntax error"),
        (r"quoted string not properly terminated", "SQL quote error"),
        (r"SQL Server.*error", "SQL Server error"),
        (r"SQLSTATE\[", "PDO SQL error"),
    ]
    
    for pattern, reason in sqli_confirmations:
        if re.search(pattern, response_body, re.IGNORECASE):
            return True, f"Confirmed: {reason} - Pattern '{pattern}' matched in response"
    
    return False, ""


def verify_xss_response(payload: str, response_body: str, response_headers: Dict) -> Tuple[bool, str]:
    """
    Verify if XSS is actually exploitable by analyzing response.
    Returns (is_vulnerable, evidence_reason)
    """
    # Check Content-Type - XSS only works in HTML contexts
    content_type = response_headers.get('Content-Type', '').lower()
    if 'application/json' in content_type or 'text/plain' in content_type:
        return False, "Response is not HTML - XSS not exploitable"
    
    # Check if payload is reflected WITHOUT encoding
    if payload not in response_body:
        return False, "Payload not reflected in response"
    
    # Check for XSS protection headers
    xss_protection = response_headers.get('X-XSS-Protection', '')
    csp = response_headers.get('Content-Security-Policy', '')
    
    # Verify payload is in executable context (not in comments, not encoded)
    import html
    encoded_payload = html.escape(payload)
    if encoded_payload in response_body and payload not in response_body:
        return False, "Payload is HTML-encoded - not exploitable"
    
    # Check if in script context or event handler
    dangerous_contexts = [
        f'<script>{payload}',
        f'<script type="text/javascript">{payload}',
        f'onerror="{payload}',
        f"onerror='{payload}",
        f'onclick="{payload}',
        f'onload="{payload}',
    ]
    
    for context in dangerous_contexts:
        if context.lower() in response_body.lower():
            return True, f"XSS confirmed: Payload found in executable context"
    
    # If payload is reflected and contains script tags that appear in response
    if '<script' in payload.lower() and payload in response_body:
        return True, f"XSS confirmed: Script tag payload reflected without encoding"
    
    if 'onerror=' in payload.lower() or 'onload=' in payload.lower():
        if payload in response_body:
            return True, f"XSS confirmed: Event handler payload reflected without encoding"
    
    return False, "Payload reflected but not in executable context"


def verify_idor_response(
    original_response: str, 
    modified_response: str,
    original_id: str,
    test_id: str
) -> Tuple[bool, str]:
    """
    Verify if IDOR is actually present by comparing responses.
    Returns (is_vulnerable, evidence_reason)
    """
    # If responses are identical, likely not IDOR (same error page)
    if original_response == modified_response:
        return False, "Responses are identical - likely same error page"
    
    # If modified response is too short, might be error
    if len(modified_response) < 50:
        return False, "Response too short - likely error page"
    
    # Check if we got a different user's data (ID appears in response)
    if test_id in modified_response and original_id not in modified_response:
        return True, f"IDOR confirmed: Response contains test ID {test_id} but not original ID {original_id}"
    
    # Check for user-specific data patterns
    import re
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails_orig = set(re.findall(email_pattern, original_response))
    emails_mod = set(re.findall(email_pattern, modified_response))
    
    if emails_mod and emails_mod != emails_orig:
        return True, f"IDOR confirmed: Different user emails in response"
    
    # Check for significant content difference
    if abs(len(original_response) - len(modified_response)) > 100:
        # Significant size difference suggests different data
        return True, f"IDOR likely: Response size differs significantly ({len(original_response)} vs {len(modified_response)} bytes)"
    
    return False, "Could not confirm IDOR - responses too similar"


def verify_sensitive_data(pattern_name: str, match: str, response_body: str, url: str) -> Tuple[bool, str]:
    """
    Verify if sensitive data finding is a true positive.
    Returns (is_vulnerable, evidence_reason)
    """
    import re
    
    # Filter out common false positives
    false_positive_patterns = {
        'email': [
            r'example\.com',
            r'test\.com',
            r'localhost',
            r'placeholder',
            r'schema\.org',
            r'w3\.org',
            r'jquery',
            r'angular',
            r'react',
            r'\.min\.js',
            r'\.css$',
        ],
        'api_key': [
            r'^[a-f0-9]{32}$',  # MD5 hashes
            r'^[a-f0-9]{40}$',  # SHA1 hashes
            r'^[a-f0-9]{64}$',  # SHA256 hashes
            r'example',
            r'placeholder',
            r'your[_-]?api[_-]?key',
        ],
        'password': [
            r'type\s*=\s*["\']?password',  # HTML input type
            r'password[_-]?field',
            r'confirm[_-]?password',
            r'new[_-]?password',
        ],
    }
    
    # Check for false positives
    fp_patterns = false_positive_patterns.get(pattern_name, [])
    for fp in fp_patterns:
        if re.search(fp, match, re.IGNORECASE) or re.search(fp, url, re.IGNORECASE):
            return False, f"False positive: matched exclusion pattern {fp}"
    
    # Additional validation for specific types
    if pattern_name == 'credit_card':
        # Luhn algorithm check
        def luhn_check(card_number):
            digits = [int(d) for d in card_number if d.isdigit()]
            if len(digits) < 13:
                return False
            checksum = 0
            for i, digit in enumerate(reversed(digits)):
                if i % 2 == 1:
                    digit *= 2
                    if digit > 9:
                        digit -= 9
                checksum += digit
            return checksum % 10 == 0
        
        if not luhn_check(match):
            return False, "Failed Luhn check - not a valid credit card"
    
    if pattern_name == 'ssn':
        # SSN should not be 000-00-0000 or 123-45-6789
        if match in ['000-00-0000', '123-45-6789', '111-11-1111']:
            return False, "Common test/fake SSN"
    
    return True, f"Verified: {pattern_name} found in response"

# ========== JavaScript Rendering Client for Modern Web Apps ==========

class JSRenderingClient:
    """
    HTTP client that uses Playwright for JavaScript rendering.
    Essential for testing modern SPAs and JavaScript-heavy applications.
    """
    
    def __init__(self, browser_controller=None):
        """
        Initialize with an existing browser controller or create requests without JS.
        
        Args:
            browser_controller: Optional BrowserController instance for JS rendering
        """
        self.browser = browser_controller
        self._http_client = HTTPClient()
    
    async def get_rendered(self, url: str, wait_time: float = 2.0) -> Dict:
        """
        Fetch a URL with full JavaScript rendering.
        
        Returns:
            Dict with 'html', 'text', 'status', 'js_rendered' flag
        """
        if self.browser and self.browser.page:
            result = await self.browser.render_page(url)
            result['js_rendered'] = True
            return result
        else:
            # Fallback to regular HTTP if no browser available
            exchange, success = await self._http_client.request('GET', url)
            return {
                'html': exchange.response_body,
                'text': exchange.response_body,
                'status': exchange.response_status,
                'headers': exchange.response_headers,
                'js_rendered': False
            }
    
    async def post_rendered(self, url: str, data: Dict, wait_time: float = 2.0) -> Dict:
        """
        Submit a POST request with JavaScript rendering of the response.
        """
        if self.browser and self.browser.page:
            result = await self.browser.render_with_payload(url, 'POST', data, wait_time=wait_time)
            result['js_rendered'] = True
            return result
        else:
            exchange, success = await self._http_client.request('POST', url, data=data)
            return {
                'html': exchange.response_body,
                'text': exchange.response_body,
                'status': exchange.response_status,
                'js_rendered': False
            }
    
    async def check_xss_dom(self, url: str, payload: str, param: str) -> Dict:
        """
        Check for DOM-based XSS using actual browser execution.
        """
        if self.browser and self.browser.page:
            return await self.browser.check_xss_in_dom(url, payload, param)
        return {'vulnerable': False, 'error': 'No browser available for DOM XSS check'}
    
    async def extract_js_endpoints(self) -> List[Dict]:
        """
        Extract API endpoints from JavaScript code in the current page.
        """
        if self.browser and self.browser.page:
            return await self.browser.extract_dynamic_endpoints()
        return []
    
    async def get_page_storage(self) -> Dict:
        """
        Get localStorage, sessionStorage, and cookies from the browser.
        """
        if self.browser and self.browser.page:
            return await self.browser.get_page_state()
        return {}


def create_js_client(browser_controller=None) -> JSRenderingClient:
    """Factory function to create a JSRenderingClient"""
    return JSRenderingClient(browser_controller)