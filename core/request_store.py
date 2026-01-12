"""
Jarwis AGI Pen Test - Request/Response Store
Stores captured requests and responses from MITM proxy for attack modules to use.
This is the central data store that all attack modules read from.
"""

import json
import os
import logging
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class CapturedRequest:
    """Represents a captured HTTP request from MITM proxy"""
    id: str
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: str = ""
    content_type: str = ""
    
    # Authentication context
    has_auth_token: bool = False
    auth_token_type: str = ""  # jwt, session, bearer, api_key, etc.
    auth_token_value: str = ""
    
    # Request metadata
    is_post_login: bool = False
    endpoint_type: str = ""  # api, form, ajax, static, etc.
    parameters: Dict[str, str] = field(default_factory=dict)  # Query/body params


@dataclass
class CapturedResponse:
    """Represents a captured HTTP response from MITM proxy"""
    request_id: str  # Links to CapturedRequest
    status_code: int
    headers: Dict[str, str]
    body: str = ""
    content_type: str = ""
    content_length: int = 0
    timestamp: str = ""
    
    # Response analysis
    has_sensitive_data: bool = False
    sensitive_data_types: List[str] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)


class RequestStore:
    """
    Central store for all captured requests and responses.
    Attack modules read from here to get targets for testing.
    
    Flow:
    1. MITM Proxy captures requests/responses during crawl
    2. Stored here (pre-login and post-login separately)
    3. Attack modules iterate through stored requests
    4. Modified requests sent via MITM proxy
    5. Responses analyzed for vulnerabilities
    """
    
    def __init__(self, scan_id: str, storage_dir: str = "temp/scans"):
        self.scan_id = scan_id
        self.storage_dir = Path(storage_dir) / scan_id
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # In-memory stores
        self.pre_login_requests: Dict[str, CapturedRequest] = {}
        self.pre_login_responses: Dict[str, CapturedResponse] = {}
        
        self.post_login_requests: Dict[str, CapturedRequest] = {}
        self.post_login_responses: Dict[str, CapturedResponse] = {}
        
        # Authentication tokens for post-login
        self.auth_tokens: Dict[str, str] = {}  # token_type -> token_value
        self.token_expiry: Dict[str, datetime] = {}  # token_type -> expiry time
        self.token_refresh_callbacks: Dict[str, Any] = {}  # token_type -> refresh callback
        self.refresh_threshold_seconds: int = 60  # Refresh when < 60s remaining
        
        # File paths
        self.pre_login_file = self.storage_dir / "pre_login_requests.json"
        self.post_login_file = self.storage_dir / "post_login_requests.json"
        
        logger.info(f"RequestStore initialized for scan: {scan_id}")
    
    def _generate_request_id(self, url: str, method: str, body: str = "") -> str:
        """Generate unique ID for a request"""
        content = f"{method}:{url}:{body[:100]}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def add_request(
        self, 
        url: str, 
        method: str, 
        headers: Dict[str, str],
        body: str = "",
        is_post_login: bool = False
    ) -> str:
        """Add a captured request to the store"""
        
        request_id = self._generate_request_id(url, method, body)
        
        # Extract cookies from headers
        cookies = {}
        cookie_header = headers.get('Cookie', headers.get('cookie', ''))
        if cookie_header:
            for part in cookie_header.split(';'):
                if '=' in part:
                    key, value = part.strip().split('=', 1)
                    cookies[key] = value
        
        # Detect authentication tokens
        has_auth, token_type, token_value = self._detect_auth_token(headers, cookies)
        
        # Parse parameters
        parameters = self._parse_parameters(url, body, headers.get('Content-Type', ''))
        
        request = CapturedRequest(
            id=request_id,
            url=url,
            method=method.upper(),
            headers=headers,
            body=body,
            cookies=cookies,
            timestamp=datetime.now().isoformat(),
            content_type=headers.get('Content-Type', ''),
            has_auth_token=has_auth,
            auth_token_type=token_type,
            auth_token_value=token_value,
            is_post_login=is_post_login,
            endpoint_type=self._detect_endpoint_type(url, headers),
            parameters=parameters
        )
        
        if is_post_login:
            self.post_login_requests[request_id] = request
        else:
            self.pre_login_requests[request_id] = request
        
        logger.debug(f"Added {'post' if is_post_login else 'pre'}-login request: {method} {url}")
        return request_id
    
    def add_response(
        self,
        request_id: str,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        is_post_login: bool = False
    ):
        """Add a captured response to the store"""
        
        # Detect sensitive data in response
        has_sensitive, sensitive_types = self._detect_sensitive_data(body)
        error_messages = self._extract_error_messages(body, status_code)
        
        response = CapturedResponse(
            request_id=request_id,
            status_code=status_code,
            headers=headers,
            body=body,
            content_type=headers.get('Content-Type', ''),
            content_length=len(body),
            timestamp=datetime.now().isoformat(),
            has_sensitive_data=has_sensitive,
            sensitive_data_types=sensitive_types,
            error_messages=error_messages
        )
        
        if is_post_login:
            self.post_login_responses[request_id] = response
        else:
            self.pre_login_responses[request_id] = response
        
        logger.debug(f"Added response for request {request_id}: {status_code}")
    
    def _detect_auth_token(self, headers: Dict[str, str], cookies: Dict[str, str]) -> tuple:
        """Detect authentication token type and value"""
        
        # Check Authorization header
        auth_header = headers.get('Authorization', headers.get('authorization', ''))
        
        if auth_header:
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                # Check if JWT (has 3 parts separated by dots)
                if token.count('.') == 2:
                    return True, 'jwt', token
                return True, 'bearer', token
            elif auth_header.startswith('Basic '):
                return True, 'basic', auth_header[6:]
            elif auth_header.startswith('ApiKey ') or auth_header.startswith('Api-Key '):
                return True, 'api_key', auth_header.split(' ', 1)[1]
        
        # Check for API key headers
        for header_name in ['X-API-Key', 'X-Api-Key', 'Api-Key', 'apikey']:
            if header_name.lower() in [h.lower() for h in headers]:
                return True, 'api_key', headers.get(header_name, '')
        
        # Check cookies for session tokens
        session_cookie_names = ['session', 'sessionid', 'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId', 'token', 'auth_token']
        for cookie_name in session_cookie_names:
            if cookie_name in cookies or cookie_name.lower() in [c.lower() for c in cookies]:
                return True, 'session_cookie', cookies.get(cookie_name, '')
        
        return False, '', ''
    
    def _detect_endpoint_type(self, url: str, headers: Dict[str, str]) -> str:
        """Detect type of endpoint"""
        
        url_lower = url.lower()
        content_type = headers.get('Content-Type', '').lower()
        accept = headers.get('Accept', '').lower()
        
        if '/api/' in url_lower or 'application/json' in content_type or 'application/json' in accept:
            return 'api'
        if 'x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type:
            return 'form'
        if 'xmlhttprequest' in headers.get('X-Requested-With', '').lower():
            return 'ajax'
        if any(ext in url_lower for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico']):
            return 'static'
        if any(ext in url_lower for ext in ['.html', '.htm', '.php', '.asp', '.jsp']):
            return 'page'
        
        return 'unknown'
    
    def _parse_parameters(self, url: str, body: str, content_type: str) -> Dict[str, str]:
        """Parse parameters from URL and body"""
        from urllib.parse import urlparse, parse_qs
        
        params = {}
        
        # Parse URL query parameters
        parsed = urlparse(url)
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                params[key] = values[0] if values else ''
        
        # Parse body parameters
        if body:
            if 'application/x-www-form-urlencoded' in content_type:
                for key, values in parse_qs(body).items():
                    params[key] = values[0] if values else ''
            elif 'application/json' in content_type:
                try:
                    json_body = json.loads(body)
                    if isinstance(json_body, dict):
                        for key, value in json_body.items():
                            params[key] = str(value) if not isinstance(value, (dict, list)) else json.dumps(value)
                except:
                    pass
        
        return params
    
    def _detect_sensitive_data(self, body: str) -> tuple:
        """Detect sensitive data in response body"""
        import re
        
        sensitive_types = []
        
        patterns = {
            'email': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
            'api_key': r'(?:api[_-]?key|apikey)["\s:=]+["\']?([a-zA-Z0-9_-]{20,})["\']?',
            'password': r'"password"\s*:\s*"[^"]+"',
            'token': r'"(?:access_)?token"\s*:\s*"[^"]+"',
        }
        
        body_lower = body.lower()
        
        for data_type, pattern in patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                sensitive_types.append(data_type)
        
        return len(sensitive_types) > 0, sensitive_types
    
    def _extract_error_messages(self, body: str, status_code: int) -> List[str]:
        """Extract error messages from response"""
        import re
        
        errors = []
        
        if status_code >= 400:
            # Look for common error patterns
            error_patterns = [
                r'error["\s:]+["\']([^"\']+)["\']',
                r'message["\s:]+["\']([^"\']+)["\']',
                r'<error>([^<]+)</error>',
                r'Exception:\s*(.+?)(?:\n|$)',
                r'Error:\s*(.+?)(?:\n|$)',
            ]
            
            for pattern in error_patterns:
                matches = re.findall(pattern, body, re.IGNORECASE)
                errors.extend(matches[:3])  # Limit to 3 per pattern
        
        return errors[:10]  # Limit total errors
    
    def get_all_requests(self, post_login: bool = False) -> List[CapturedRequest]:
        """Get all requests for attack modules to process"""
        store = self.post_login_requests if post_login else self.pre_login_requests
        return list(store.values())
    
    def get_request(self, request_id: str, post_login: bool = False) -> Optional[CapturedRequest]:
        """Get a specific request by ID"""
        store = self.post_login_requests if post_login else self.pre_login_requests
        return store.get(request_id)
    
    def get_response(self, request_id: str, post_login: bool = False) -> Optional[CapturedResponse]:
        """Get response for a request"""
        store = self.post_login_responses if post_login else self.pre_login_responses
        return store.get(request_id)
    
    def get_requests_by_type(self, endpoint_type: str, post_login: bool = False) -> List[CapturedRequest]:
        """Get requests filtered by endpoint type (api, form, ajax, etc.)"""
        requests = self.get_all_requests(post_login)
        return [r for r in requests if r.endpoint_type == endpoint_type]
    
    def get_requests_with_params(self, post_login: bool = False) -> List[CapturedRequest]:
        """Get requests that have parameters (good attack targets)"""
        requests = self.get_all_requests(post_login)
        return [r for r in requests if r.parameters]
    
    def get_post_requests(self, post_login: bool = False) -> List[CapturedRequest]:
        """Get only POST requests (state-changing operations)"""
        requests = self.get_all_requests(post_login)
        return [r for r in requests if r.method == 'POST']
    
    def update_auth_token(self, token_type: str, token_value: str):
        """Update authentication token (for token refresh)"""
        self.auth_tokens[token_type] = token_value
        logger.info(f"Updated {token_type} token")
    
    def get_current_auth_token(self, token_type: str = 'jwt') -> Optional[str]:
        """Get current authentication token"""
        return self.auth_tokens.get(token_type)
    
    def get_auth_headers(self) -> Dict[str, str]:
        """
        Get authentication headers for making HTTP requests.
        
        Returns a dict suitable for passing to aiohttp requests with
        Authorization header if JWT/Bearer tokens are present.
        
        Returns:
            Dict with Authorization header if tokens exist, empty otherwise
        """
        headers = {}
        
        # Check for JWT or bearer token
        for token_type in ['jwt', 'bearer', 'access_token']:
            token = self.auth_tokens.get(token_type)
            if token:
                headers['Authorization'] = f'Bearer {token}'
                break
        
        # Check for API key
        api_key = self.auth_tokens.get('api_key')
        if api_key and 'Authorization' not in headers:
            headers['X-API-Key'] = api_key
        
        return headers
    
    def get_auth_cookies(self) -> Dict[str, str]:
        """
        Get authentication cookies for making HTTP requests.
        
        Returns a dict suitable for passing to aiohttp.ClientSession(cookies=...)
        
        Returns:
            Dict with session cookies if present, empty otherwise
        """
        cookies = {}
        
        # Session cookie types to include
        session_types = ['session_cookie', 'session', 'sessionid', 'JSESSIONID', 'PHPSESSID', 'ASP.NET_SessionId', 'token', 'auth_token', 'sid']
        
        for token_type, token_value in self.auth_tokens.items():
            if token_type in session_types or 'session' in token_type.lower() or 'cookie' in token_type.lower():
                # Use a normalized name for common session cookie
                cookie_name = token_type if token_type not in ['session_cookie'] else 'session'
                cookies[cookie_name] = token_value
        
        return cookies
    
    def get_authenticated_session_kwargs(self) -> Dict[str, Any]:
        """
        Get kwargs for creating an authenticated aiohttp.ClientSession.
        
        Usage:
            session_kwargs = request_store.get_authenticated_session_kwargs()
            async with aiohttp.ClientSession(**session_kwargs) as session:
                # session now has auth cookies and headers
                
        Returns:
            Dict with 'cookies' and 'headers' keys ready for ClientSession
        """
        auth_headers = self.get_auth_headers()
        auth_cookies = self.get_auth_cookies()
        
        result = {}
        if auth_cookies:
            result['cookies'] = auth_cookies
        if auth_headers:
            result['headers'] = auth_headers
            
        logger.debug(f"Auth session kwargs: {len(auth_cookies)} cookies, {len(auth_headers)} headers")
        return result
    
    def has_authentication(self) -> bool:
        """Check if any authentication tokens are stored"""
        return len(self.auth_tokens) > 0
    
    # =========================================================================
    # Token Refresh Support
    # =========================================================================
    
    def set_token_with_expiry(
        self, 
        token_type: str, 
        token_value: str, 
        expires_in: Optional[int] = None,
        expiry_time: Optional[datetime] = None
    ):
        """
        Set a token with explicit expiry information.
        
        Args:
            token_type: Type of token (jwt, bearer, session_cookie, api_key)
            token_value: The actual token value
            expires_in: Seconds until token expires (optional)
            expiry_time: Explicit expiry datetime (optional)
        """
        self.auth_tokens[token_type] = token_value
        
        if expiry_time:
            self.token_expiry[token_type] = expiry_time
        elif expires_in:
            self.token_expiry[token_type] = datetime.now() + timedelta(seconds=expires_in)
        elif token_type in ['jwt', 'bearer', 'access_token']:
            # Try to extract expiry from JWT
            expiry = self._extract_jwt_expiry(token_value)
            if expiry:
                self.token_expiry[token_type] = expiry
        
        logger.info(f"Set {token_type} token with expiry: {self.token_expiry.get(token_type, 'unknown')}")
    
    def _extract_jwt_expiry(self, token: str) -> Optional[datetime]:
        """Extract expiry time from JWT token"""
        import base64
        try:
            # JWT format: header.payload.signature
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode payload (add padding if needed)
            payload_b64 = parts[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += '=' * padding
            
            payload = json.loads(base64.urlsafe_b64decode(payload_b64))
            
            if 'exp' in payload:
                return datetime.fromtimestamp(payload['exp'])
            
            return None
        except Exception as e:
            logger.debug(f"Failed to extract JWT expiry: {e}")
            return None
    
    def is_token_expiring(self, token_type: str = 'jwt') -> bool:
        """Check if token is expiring soon (within threshold)"""
        if token_type not in self.token_expiry:
            return False
        
        expiry = self.token_expiry[token_type]
        remaining = (expiry - datetime.now()).total_seconds()
        
        return remaining < self.refresh_threshold_seconds
    
    def is_token_expired(self, token_type: str = 'jwt') -> bool:
        """Check if token is already expired"""
        if token_type not in self.token_expiry:
            return False
        
        return datetime.now() >= self.token_expiry[token_type]
    
    def get_token_remaining_seconds(self, token_type: str = 'jwt') -> Optional[int]:
        """Get seconds remaining until token expires"""
        if token_type not in self.token_expiry:
            return None
        
        remaining = (self.token_expiry[token_type] - datetime.now()).total_seconds()
        return max(0, int(remaining))
    
    def set_refresh_callback(self, token_type: str, callback):
        """
        Set a callback function to refresh a token when it expires.
        
        The callback should be an async function that returns (new_token, expires_in).
        
        Args:
            token_type: Type of token to refresh
            callback: Async function returning (token_value, expires_in_seconds)
        """
        self.token_refresh_callbacks[token_type] = callback
        logger.info(f"Set refresh callback for {token_type} token")
    
    async def refresh_token_if_needed(self, token_type: str = 'jwt') -> bool:
        """
        Refresh token if it's expiring soon.
        
        Returns True if refresh was successful or not needed.
        Returns False if refresh failed.
        """
        if not self.is_token_expiring(token_type):
            return True
        
        if token_type not in self.token_refresh_callbacks:
            logger.warning(f"Token {token_type} expiring but no refresh callback set")
            return False
        
        try:
            logger.info(f"Refreshing {token_type} token...")
            callback = self.token_refresh_callbacks[token_type]
            
            import asyncio
            if asyncio.iscoroutinefunction(callback):
                result = await callback()
            else:
                result = callback()
            
            if result:
                new_token, expires_in = result
                self.set_token_with_expiry(token_type, new_token, expires_in=expires_in)
                logger.info(f"Successfully refreshed {token_type} token")
                return True
            
        except Exception as e:
            logger.error(f"Failed to refresh {token_type} token: {e}")
        
        return False
    
    def get_all_auth_info(self) -> Dict[str, Any]:
        """
        Get comprehensive auth information for debugging/logging.
        
        Returns:
            Dict with tokens, expiry info, and status
        """
        info = {
            'has_auth': self.has_authentication(),
            'token_types': list(self.auth_tokens.keys()),
            'tokens_with_expiry': list(self.token_expiry.keys()),
            'expiring_soon': [],
            'expired': [],
        }
        
        for token_type in self.auth_tokens:
            if self.is_token_expired(token_type):
                info['expired'].append(token_type)
            elif self.is_token_expiring(token_type):
                info['expiring_soon'].append(token_type)
                remaining = self.get_token_remaining_seconds(token_type)
                info[f'{token_type}_remaining_seconds'] = remaining
        
        return info
    
    def save_to_disk(self):
        """Save captured data to disk"""
        
        pre_login_data = {
            'requests': [asdict(r) for r in self.pre_login_requests.values()],
            'responses': [asdict(r) for r in self.pre_login_responses.values()]
        }
        
        post_login_data = {
            'requests': [asdict(r) for r in self.post_login_requests.values()],
            'responses': [asdict(r) for r in self.post_login_responses.values()],
            'auth_tokens': self.auth_tokens
        }
        
        with open(self.pre_login_file, 'w') as f:
            json.dump(pre_login_data, f, indent=2)
        
        with open(self.post_login_file, 'w') as f:
            json.dump(post_login_data, f, indent=2)
        
        logger.info(f"Saved {len(self.pre_login_requests)} pre-login and {len(self.post_login_requests)} post-login requests")
    
    def cleanup(self):
        """Clean up temporary files after scan"""
        import shutil
        
        try:
            shutil.rmtree(self.storage_dir)
            logger.info(f"Cleaned up scan data: {self.scan_id}")
        except Exception as e:
            logger.warning(f"Failed to cleanup: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about captured data"""
        return {
            'pre_login': {
                'total_requests': len(self.pre_login_requests),
                'get_requests': len([r for r in self.pre_login_requests.values() if r.method == 'GET']),
                'post_requests': len([r for r in self.pre_login_requests.values() if r.method == 'POST']),
                'api_endpoints': len([r for r in self.pre_login_requests.values() if r.endpoint_type == 'api']),
                'form_endpoints': len([r for r in self.pre_login_requests.values() if r.endpoint_type == 'form']),
            },
            'post_login': {
                'total_requests': len(self.post_login_requests),
                'get_requests': len([r for r in self.post_login_requests.values() if r.method == 'GET']),
                'post_requests': len([r for r in self.post_login_requests.values() if r.method == 'POST']),
                'api_endpoints': len([r for r in self.post_login_requests.values() if r.endpoint_type == 'api']),
                'form_endpoints': len([r for r in self.post_login_requests.values() if r.endpoint_type == 'form']),
                'has_auth_tokens': len(self.auth_tokens) > 0,
                'auth_token_types': list(self.auth_tokens.keys()),
            }
        }
    
    def load_from_traffic_log(self, log_path: Path, is_post_login: bool = False) -> int:
        """
        Load captured traffic from MITM proxy traffic log file.
        
        This is the bridge between MITM proxy (writes to file) and RequestStore.
        Should be called after crawling to ensure all captured data is available.
        
        Args:
            log_path: Path to traffic_log.json from MITM proxy
            is_post_login: Whether this is post-login traffic
            
        Returns:
            Number of requests loaded
        """
        if not log_path.exists():
            logger.warning(f"Traffic log not found: {log_path}")
            return 0
        
        try:
            with open(log_path) as f:
                traffic = json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Failed to read traffic log: {e}")
            return 0
        
        # Track requests and match with responses
        request_map = {}  # flow_id -> request_entry
        loaded_count = 0
        
        # First pass: collect all entries
        for entry in traffic:
            flow_id = entry.get('id')
            entry_type = entry.get('type')
            
            if entry_type == 'request':
                request_map[flow_id] = entry
            elif entry_type == 'response' and flow_id in request_map:
                request_map[flow_id]['response'] = entry
        
        # Second pass: add to store
        for flow_id, req_entry in request_map.items():
            try:
                url = req_entry.get('url', '')
                method = req_entry.get('method', 'GET')
                headers = req_entry.get('headers', {})
                body = req_entry.get('body', '')
                
                # Skip static assets
                if self._is_static_asset(url):
                    continue
                
                # Add request
                request_id = self.add_request(
                    url=url,
                    method=method,
                    headers=headers,
                    body=body,
                    is_post_login=is_post_login
                )
                
                # Add response if available
                if 'response' in req_entry:
                    resp = req_entry['response']
                    self.add_response(
                        request_id=request_id,
                        status_code=resp.get('status', 0),
                        headers=resp.get('headers', {}),
                        body=resp.get('body', ''),
                        is_post_login=is_post_login
                    )
                
                loaded_count += 1
                
            except Exception as e:
                logger.error(f"Error loading traffic entry: {e}")
                continue
        
        logger.info(f"Loaded {loaded_count} {'post' if is_post_login else 'pre'}-login requests from traffic log")
        return loaded_count
    
    def _is_static_asset(self, url: str) -> bool:
        """Check if URL is a static asset that should be skipped"""
        static_extensions = [
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', 
            '.ico', '.woff', '.woff2', '.ttf', '.eot', '.map'
        ]
        url_lower = url.lower().split('?')[0]  # Remove query string
        return any(url_lower.endswith(ext) for ext in static_extensions)
    
    def populate_from_browser_endpoints(
        self, 
        endpoints: List[Dict], 
        is_post_login: bool = False
    ) -> int:
        """
        Populate RequestStore from browser-discovered endpoints.
        
        This is a FALLBACK when MITM proxy is not available or didn't capture traffic.
        Browser crawl discovers endpoints (forms, API URLs, links) that can be used
        as attack targets even without captured request/response data.
        
        Args:
            endpoints: List of endpoint dicts from BrowserController.crawl()
                      Each has: url, method, params, type, has_upload, headers, etc.
            is_post_login: Whether these are post-login endpoints
            
        Returns:
            Number of endpoints added
        """
        added_count = 0
        
        for ep in endpoints:
            try:
                url = ep.get('url', '')
                if not url:
                    continue
                
                # Skip static assets
                if self._is_static_asset(url):
                    continue
                
                method = ep.get('method', 'GET').upper()
                params = ep.get('params', {})
                ep_type = ep.get('type', 'page')
                headers = ep.get('headers', {})
                
                # Generate fake headers if not provided
                if not headers:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Jarwis-Scanner/1.0',
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'en-US,en;q=0.5',
                    }
                
                # Build body from params for POST requests
                body = ''
                if method == 'POST' and params:
                    # Simple form-encoded body
                    from urllib.parse import urlencode
                    body = urlencode(params)
                    headers['Content-Type'] = 'application/x-www-form-urlencoded'
                
                # Generate unique request ID
                request_id = self._generate_request_id(url, method, body)
                
                # Check if already exists
                store = self.post_login_requests if is_post_login else self.pre_login_requests
                if request_id in store:
                    continue
                
                # Create request object
                request = CapturedRequest(
                    id=request_id,
                    url=url,
                    method=method,
                    headers=headers,
                    body=body,
                    cookies={},
                    timestamp=datetime.now().isoformat(),
                    content_type=headers.get('Content-Type', ''),
                    has_auth_token=is_post_login,  # Assume post-login has auth
                    auth_token_type='session' if is_post_login else '',
                    auth_token_value='',
                    is_post_login=is_post_login,
                    endpoint_type=ep_type,
                    parameters=params
                )
                
                if is_post_login:
                    self.post_login_requests[request_id] = request
                else:
                    self.pre_login_requests[request_id] = request
                
                added_count += 1
                
            except Exception as e:
                logger.warning(f"Error adding endpoint {ep.get('url', '?')}: {e}")
                continue
        
        logger.info(f"Populated {added_count} {'post' if is_post_login else 'pre'}-login endpoints from browser crawl")
        return added_count
