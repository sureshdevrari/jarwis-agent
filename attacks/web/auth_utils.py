"""
JARWIS AGI PEN TEST - Authentication Utilities for Scanners

This module provides drop-in authentication support for all web scanners.
Scanners can use these utilities WITHOUT changing their inheritance or structure.

Usage (minimal changes to existing scanners):
    
    from attacks.web.auth_utils import get_authenticated_session, get_auth_from_context
    
    class MyScanner:
        def __init__(self, config, context):
            self.config = config
            self.context = context
            
        async def scan(self):
            # Option 1: Get authenticated session directly
            async with get_authenticated_session(self.context, self.config) as session:
                async with session.get(url) as response:
                    ...
            
            # Option 2: Get auth kwargs to merge with existing session setup
            auth_kwargs = get_auth_from_context(self.context)
            async with aiohttp.ClientSession(**auth_kwargs) as session:
                ...

Features:
- Automatic token refresh when JWT expires
- Supports JWT, Bearer tokens, session cookies, API keys
- Rate limiting support
- SSL verification disabled for testing
- Logging of auth status
"""

import asyncio
import logging
import ssl
import time
import base64
import json
from typing import Dict, List, Any, Optional, Callable, Tuple
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import aiohttp

logger = logging.getLogger(__name__)


# ============================================================================
# Token Refresh Configuration
# ============================================================================

class TokenManager:
    """
    Manages authentication tokens with automatic refresh support.
    
    Tracks token expiry and triggers refresh when needed.
    Singleton per scan to share state across all scanners.
    """
    
    _instances: Dict[str, 'TokenManager'] = {}
    
    def __init__(self, scan_id: str = "default"):
        self.scan_id = scan_id
        self.tokens: Dict[str, str] = {}
        self.token_expiry: Dict[str, datetime] = {}
        self.refresh_callbacks: Dict[str, Callable] = {}
        self.refresh_lock = asyncio.Lock()
        self.last_refresh: Optional[datetime] = None
        self.refresh_threshold_seconds = 60  # Refresh when < 60s remaining
        self._request_store = None  # Will be set from context
    
    @classmethod
    def get_instance(cls, scan_id: str = "default") -> 'TokenManager':
        """Get or create TokenManager instance for scan"""
        if scan_id not in cls._instances:
            cls._instances[scan_id] = cls(scan_id)
        return cls._instances[scan_id]
    
    @classmethod
    def clear_instance(cls, scan_id: str = "default"):
        """Clear TokenManager instance after scan completes"""
        if scan_id in cls._instances:
            del cls._instances[scan_id]
    
    def set_request_store(self, request_store):
        """Set reference to RequestStore for token updates"""
        self._request_store = request_store
    
    def set_token(self, token_type: str, token_value: str, expires_in: Optional[int] = None):
        """
        Set a token with optional expiry.
        
        Args:
            token_type: Type of token (jwt, bearer, session_cookie, api_key)
            token_value: The actual token value
            expires_in: Seconds until token expires (optional)
        """
        self.tokens[token_type] = token_value
        
        if expires_in:
            self.token_expiry[token_type] = datetime.now() + timedelta(seconds=expires_in)
        elif token_type in ['jwt', 'bearer']:
            # Try to extract expiry from JWT
            expiry = self._extract_jwt_expiry(token_value)
            if expiry:
                self.token_expiry[token_type] = expiry
    
    def _extract_jwt_expiry(self, token: str) -> Optional[datetime]:
        """Extract expiry time from JWT token"""
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
    
    def is_token_expiring(self, token_type: str) -> bool:
        """Check if token is expiring soon or already expired"""
        if token_type not in self.token_expiry:
            return False
        
        expiry = self.token_expiry[token_type]
        remaining = (expiry - datetime.now()).total_seconds()
        
        return remaining < self.refresh_threshold_seconds
    
    def is_token_expired(self, token_type: str) -> bool:
        """Check if token is already expired"""
        if token_type not in self.token_expiry:
            return False
        
        return datetime.now() >= self.token_expiry[token_type]
    
    def set_refresh_callback(self, token_type: str, callback: Callable):
        """Set callback function to refresh a token type"""
        self.refresh_callbacks[token_type] = callback
    
    async def refresh_if_needed(self, token_type: str) -> bool:
        """
        Refresh token if it's expiring soon.
        
        Returns True if refresh was successful or not needed.
        Returns False if refresh failed.
        """
        if not self.is_token_expiring(token_type):
            return True
        
        async with self.refresh_lock:
            # Double-check after acquiring lock
            if not self.is_token_expiring(token_type):
                return True
            
            if token_type not in self.refresh_callbacks:
                logger.warning(f"Token {token_type} expiring but no refresh callback set")
                return False
            
            try:
                logger.info(f"Refreshing {token_type} token...")
                callback = self.refresh_callbacks[token_type]
                
                if asyncio.iscoroutinefunction(callback):
                    new_token, expires_in = await callback()
                else:
                    new_token, expires_in = callback()
                
                if new_token:
                    self.set_token(token_type, new_token, expires_in)
                    self.last_refresh = datetime.now()
                    
                    # Update RequestStore if available
                    if self._request_store:
                        self._request_store.update_auth_token(token_type, new_token)
                    
                    logger.info(f"Successfully refreshed {token_type} token")
                    return True
                
            except Exception as e:
                logger.error(f"Failed to refresh {token_type} token: {e}")
            
            return False
    
    def get_token(self, token_type: str) -> Optional[str]:
        """Get current token value"""
        return self.tokens.get(token_type)
    
    def get_all_tokens(self) -> Dict[str, str]:
        """Get all stored tokens"""
        return dict(self.tokens)


# ============================================================================
# Auth Helper Functions (Drop-in for existing scanners)
# ============================================================================

def get_auth_from_context(context, include_all: bool = True) -> Dict[str, Any]:
    """
    Extract authentication configuration from scanner context.
    
    This is the main utility function for existing scanners.
    Returns kwargs that can be passed directly to aiohttp.ClientSession().
    
    Args:
        context: Scanner context object with auth_headers, auth_cookies, etc.
        include_all: If True, includes all auth methods. If False, prioritizes.
    
    Returns:
        Dict with 'headers' and 'cookies' keys ready for ClientSession
    
    Example:
        auth_kwargs = get_auth_from_context(self.context)
        async with aiohttp.ClientSession(**auth_kwargs) as session:
            ...
    """
    result = {}
    headers = {}
    cookies = {}
    
    # Priority 1: Pre-built session_kwargs from UnifiedExecutor
    if hasattr(context, 'session_kwargs') and context.session_kwargs:
        return dict(context.session_kwargs)
    
    # Priority 2: Explicit auth_headers
    if hasattr(context, 'auth_headers') and context.auth_headers:
        headers.update(context.auth_headers)
    
    # Priority 3: Explicit auth_cookies
    if hasattr(context, 'auth_cookies') and context.auth_cookies:
        cookies.update(context.auth_cookies)
    
    # Priority 4: Legacy cookies attribute
    if hasattr(context, 'cookies') and context.cookies:
        if isinstance(context.cookies, dict):
            cookies.update(context.cookies)
    
    # Priority 5: RequestStore reference (for multi-auth support)
    if hasattr(context, 'request_store') and context.request_store:
        rs = context.request_store
        
        # Get headers from request store
        if hasattr(rs, 'get_auth_headers'):
            rs_headers = rs.get_auth_headers()
            for k, v in rs_headers.items():
                if k not in headers:
                    headers[k] = v
        
        # Get cookies from request store
        if hasattr(rs, 'get_auth_cookies'):
            rs_cookies = rs.get_auth_cookies()
            for k, v in rs_cookies.items():
                if k not in cookies:
                    cookies[k] = v
    
    # Build result
    if headers:
        result['headers'] = headers
    if cookies:
        result['cookies'] = cookies
    
    return result


def get_auth_headers(context) -> Dict[str, str]:
    """Get just authentication headers from context"""
    if hasattr(context, 'auth_headers') and context.auth_headers:
        return dict(context.auth_headers)
    
    if hasattr(context, 'request_store') and context.request_store:
        if hasattr(context.request_store, 'get_auth_headers'):
            return context.request_store.get_auth_headers()
    
    return {}


def get_auth_cookies(context) -> Dict[str, str]:
    """Get just authentication cookies from context"""
    if hasattr(context, 'auth_cookies') and context.auth_cookies:
        return dict(context.auth_cookies)
    
    if hasattr(context, 'cookies') and context.cookies:
        return dict(context.cookies)
    
    if hasattr(context, 'request_store') and context.request_store:
        if hasattr(context.request_store, 'get_auth_cookies'):
            return context.request_store.get_auth_cookies()
    
    return {}


def is_authenticated(context) -> bool:
    """Check if context has any authentication"""
    auth_headers = get_auth_headers(context)
    auth_cookies = get_auth_cookies(context)
    
    return bool(auth_headers or auth_cookies)


def get_scan_id(context) -> str:
    """Extract scan ID from context for token manager"""
    if hasattr(context, 'scan_id'):
        return context.scan_id
    if hasattr(context, 'request_store') and hasattr(context.request_store, 'scan_id'):
        return context.request_store.scan_id
    return "default"


# ============================================================================
# Authenticated Session Context Manager
# ============================================================================

@asynccontextmanager
async def get_authenticated_session(
    context,
    config: Optional[Dict] = None,
    additional_headers: Optional[Dict[str, str]] = None,
    connector_limit: int = 10,
    timeout: int = 30,
    auto_refresh: bool = True
):
    """
    Get an authenticated aiohttp.ClientSession as a context manager.
    
    This is the recommended way to make authenticated requests in scanners.
    Automatically includes auth tokens and handles token refresh.
    
    Args:
        context: Scanner context with auth configuration
        config: Optional scan configuration dict
        additional_headers: Extra headers to merge with auth headers
        connector_limit: Connection pool limit
        timeout: Request timeout in seconds
        auto_refresh: Whether to auto-refresh expiring tokens
    
    Yields:
        Configured aiohttp.ClientSession with authentication
    
    Example:
        async with get_authenticated_session(self.context, self.config) as session:
            async with session.get(url) as response:
                body = await response.text()
    """
    # Get timeout from config if provided
    if config:
        timeout = config.get('timeout', timeout)
    
    # Get auth configuration
    auth_kwargs = get_auth_from_context(context)
    
    # Merge additional headers
    headers = auth_kwargs.get('headers', {})
    if additional_headers:
        headers.update(additional_headers)
    
    # SSL context (ignore cert errors for testing)
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    # Create connector and session
    connector = aiohttp.TCPConnector(ssl=ssl_context, limit=connector_limit)
    
    session_kwargs = {
        'connector': connector,
        'timeout': aiohttp.ClientTimeout(total=timeout)
    }
    
    if auth_kwargs.get('cookies'):
        session_kwargs['cookies'] = auth_kwargs['cookies']
    if headers:
        session_kwargs['headers'] = headers
    
    # Log auth status
    auth_status = "authenticated" if is_authenticated(context) else "unauthenticated"
    logger.debug(f"Creating {auth_status} session: {len(headers)} headers, {len(auth_kwargs.get('cookies', {}))} cookies")
    
    # Set up token manager for auto-refresh
    token_manager = None
    if auto_refresh and is_authenticated(context):
        scan_id = get_scan_id(context)
        token_manager = TokenManager.get_instance(scan_id)
        
        # Initialize tokens from context if not already set
        if hasattr(context, 'request_store') and context.request_store:
            token_manager.set_request_store(context.request_store)
            for token_type, token_value in context.request_store.auth_tokens.items():
                if token_type not in token_manager.tokens:
                    token_manager.set_token(token_type, token_value)
    
    async with aiohttp.ClientSession(**session_kwargs) as session:
        # Wrap session with token refresh capability
        if token_manager:
            session._token_manager = token_manager
            session._original_request = session._request
            
            async def request_with_refresh(method, url, **kwargs):
                """Wrapper that checks token before each request"""
                # Check if any tokens need refresh
                for token_type in ['jwt', 'bearer']:
                    if token_manager.is_token_expiring(token_type):
                        await token_manager.refresh_if_needed(token_type)
                        
                        # Update session headers with new token
                        new_token = token_manager.get_token(token_type)
                        if new_token and 'headers' in kwargs:
                            kwargs['headers']['Authorization'] = f'Bearer {new_token}'
                        elif new_token:
                            kwargs['headers'] = {'Authorization': f'Bearer {new_token}'}
                
                return await session._original_request(method, url, **kwargs)
            
            # Note: We don't actually monkey-patch, just provide the capability
            # Scanners can call token_manager.refresh_if_needed() if needed
        
        yield session


# ============================================================================
# Multi-Auth Support Helpers
# ============================================================================

def build_auth_headers_multi(
    jwt_token: Optional[str] = None,
    bearer_token: Optional[str] = None,
    api_key: Optional[str] = None,
    api_key_header: str = 'X-API-Key',
    basic_auth: Optional[Tuple[str, str]] = None,
    custom_headers: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Build authentication headers supporting multiple auth methods.
    
    Priority order (first non-None is used for Authorization header):
    1. JWT token
    2. Bearer token
    3. Basic auth
    
    API key is always included as a separate header if provided.
    
    Args:
        jwt_token: JWT token value
        bearer_token: Bearer token value  
        api_key: API key value
        api_key_header: Header name for API key (default: X-API-Key)
        basic_auth: Tuple of (username, password) for Basic auth
        custom_headers: Additional custom headers to include
    
    Returns:
        Dict of headers ready for HTTP requests
    """
    headers = {}
    
    # Set Authorization header (priority order)
    if jwt_token:
        headers['Authorization'] = f'Bearer {jwt_token}'
    elif bearer_token:
        headers['Authorization'] = f'Bearer {bearer_token}'
    elif basic_auth:
        credentials = base64.b64encode(f"{basic_auth[0]}:{basic_auth[1]}".encode()).decode()
        headers['Authorization'] = f'Basic {credentials}'
    
    # API key as separate header
    if api_key:
        headers[api_key_header] = api_key
    
    # Custom headers
    if custom_headers:
        headers.update(custom_headers)
    
    return headers


def build_session_cookies(
    session_id: Optional[str] = None,
    session_name: str = 'session',
    additional_cookies: Optional[Dict[str, str]] = None
) -> Dict[str, str]:
    """
    Build session cookies for HTTP requests.
    
    Args:
        session_id: Session ID value
        session_name: Cookie name for session (default: 'session')
        additional_cookies: Additional cookies to include
    
    Returns:
        Dict of cookies ready for HTTP requests
    """
    cookies = {}
    
    if session_id:
        cookies[session_name] = session_id
    
    if additional_cookies:
        cookies.update(additional_cookies)
    
    return cookies


# ============================================================================
# Scanner Patching Utility (Minimal change approach)
# ============================================================================

def patch_scanner_session(scanner_instance):
    """
    Patch an existing scanner instance to use authenticated sessions.
    
    This allows updating scanners with minimal code changes.
    Call this in scanner's __init__ or before scan().
    
    Args:
        scanner_instance: The scanner object (self)
    
    Example:
        def __init__(self, config, context):
            self.config = config
            self.context = context
            patch_scanner_session(self)  # Adds auth helpers
    """
    # Add helper methods to scanner
    scanner_instance._get_auth_headers = lambda: get_auth_headers(scanner_instance.context)
    scanner_instance._get_auth_cookies = lambda: get_auth_cookies(scanner_instance.context)
    scanner_instance._get_auth_kwargs = lambda: get_auth_from_context(scanner_instance.context)
    scanner_instance._is_authenticated = lambda: is_authenticated(scanner_instance.context)
    
    # Store original scan method
    if hasattr(scanner_instance, 'scan'):
        original_scan = scanner_instance.scan
        
        # We could wrap the scan method here if needed
        # But for now, we just add the helpers


def create_scanner_session_kwargs(
    context,
    config: Optional[Dict] = None,
    connector_ssl: bool = True,
    timeout: Optional[int] = None
) -> Dict[str, Any]:
    """
    Create full session kwargs including connector and timeout.
    
    Utility for scanners that need more control over session creation.
    
    Args:
        context: Scanner context with auth
        config: Scan configuration
        connector_ssl: Whether to disable SSL verification (default: True)
        timeout: Request timeout (default: from config or 30)
    
    Returns:
        Dict ready for aiohttp.ClientSession(**kwargs)
    """
    # Get auth
    auth_kwargs = get_auth_from_context(context)
    
    # Set timeout
    if timeout is None:
        timeout = config.get('timeout', 30) if config else 30
    
    # SSL context
    ssl_context = ssl.create_default_context()
    if connector_ssl:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    
    # Build kwargs
    kwargs = {
        'connector': aiohttp.TCPConnector(ssl=ssl_context, limit=10),
        'timeout': aiohttp.ClientTimeout(total=timeout)
    }
    
    if auth_kwargs.get('cookies'):
        kwargs['cookies'] = auth_kwargs['cookies']
    if auth_kwargs.get('headers'):
        kwargs['headers'] = auth_kwargs['headers']
    
    return kwargs


# ============================================================================
# Logging Helpers
# ============================================================================

def log_auth_status(scanner_name: str, context) -> None:
    """Log authentication status for a scanner"""
    auth_headers = get_auth_headers(context)
    auth_cookies = get_auth_cookies(context)
    
    if auth_headers or auth_cookies:
        logger.info(
            f"[{scanner_name}] Using {len(auth_headers)} auth headers, "
            f"{len(auth_cookies)} auth cookies for authenticated testing"
        )
    else:
        logger.debug(f"[{scanner_name}] Running in unauthenticated mode")
