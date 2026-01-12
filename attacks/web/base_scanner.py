"""
JARWIS AGI PEN TEST - Base Scanner with Authentication Support

This module provides base classes and mixins for web scanners that need
to make authenticated HTTP requests during post-login testing.

Usage:
    from attacks.web.base_scanner import AuthenticatedScannerMixin
    
    class MyScanner(AuthenticatedScannerMixin):
        def __init__(self, config, context):
            super().__init__(config, context)
            
        async def scan(self):
            # Get an authenticated session
            async with self.get_authenticated_session() as session:
                # All requests now include auth tokens
                async with session.get(url) as response:
                    ...
"""

import asyncio
import logging
import ssl
from typing import Dict, List, Any, Optional
from contextlib import asynccontextmanager
import aiohttp

logger = logging.getLogger(__name__)


class AuthenticatedScannerMixin:
    """
    Mixin that provides authenticated HTTP session support for scanners.
    
    Scanners inheriting from this mixin can use get_authenticated_session()
    to get an aiohttp.ClientSession that automatically includes:
    - Authorization headers (Bearer tokens, API keys)
    - Session cookies (JSESSIONID, PHPSESSID, etc.)
    
    This ensures post-login attacks actually reach authenticated endpoints
    instead of getting 401/403 responses.
    """
    
    def __init__(self, config: dict, context):
        """
        Initialize scanner with config and context.
        
        Args:
            config: Scan configuration dictionary
            context: ScanContext with endpoints, auth_headers, auth_cookies, etc.
        """
        self.config = config
        self.context = context
        self.results: List[Any] = []
        
        # Common settings
        self.timeout = config.get('timeout', 15)
        self.rate_limit = config.get('rate_limit', 10)
        
        # SSL context (ignore cert errors for testing)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers from context"""
        if hasattr(self.context, 'auth_headers') and self.context.auth_headers:
            return dict(self.context.auth_headers)
        return {}
    
    def _get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies from context"""
        if hasattr(self.context, 'auth_cookies') and self.context.auth_cookies:
            return dict(self.context.auth_cookies)
        # Fallback to legacy cookies attribute
        if hasattr(self.context, 'cookies') and self.context.cookies:
            return dict(self.context.cookies)
        return {}
    
    def _get_session_kwargs(self) -> Dict[str, Any]:
        """Get kwargs for authenticated ClientSession"""
        if hasattr(self.context, 'session_kwargs') and self.context.session_kwargs:
            return dict(self.context.session_kwargs)
        
        # Build from auth_headers and auth_cookies
        kwargs = {}
        auth_headers = self._get_auth_headers()
        auth_cookies = self._get_auth_cookies()
        
        if auth_cookies:
            kwargs['cookies'] = auth_cookies
        if auth_headers:
            kwargs['headers'] = auth_headers
        
        return kwargs
    
    def is_authenticated(self) -> bool:
        """Check if this is an authenticated scan context"""
        if hasattr(self.context, 'is_authenticated'):
            return self.context.is_authenticated
        return bool(self._get_auth_headers() or self._get_auth_cookies())
    
    @asynccontextmanager
    async def get_authenticated_session(
        self, 
        additional_headers: Optional[Dict[str, str]] = None,
        connector_limit: int = 10
    ):
        """
        Get an authenticated aiohttp.ClientSession.
        
        This context manager returns a session configured with:
        - Auth headers (Authorization: Bearer ...)
        - Session cookies
        - SSL verification disabled
        - Appropriate timeouts
        
        Usage:
            async with self.get_authenticated_session() as session:
                async with session.get(url) as response:
                    body = await response.text()
        
        Args:
            additional_headers: Extra headers to merge with auth headers
            connector_limit: Connection pool limit
            
        Yields:
            Configured aiohttp.ClientSession
        """
        # Get auth configuration
        auth_headers = self._get_auth_headers()
        auth_cookies = self._get_auth_cookies()
        
        # Merge with additional headers
        headers = {}
        if auth_headers:
            headers.update(auth_headers)
        if additional_headers:
            headers.update(additional_headers)
        
        # Log auth status for debugging
        if self.is_authenticated():
            logger.debug(
                f"[{self.__class__.__name__}] Creating authenticated session: "
                f"{len(auth_headers)} headers, {len(auth_cookies)} cookies"
            )
        
        # Create connector and session
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=connector_limit)
        
        session_kwargs = {
            'connector': connector,
            'timeout': aiohttp.ClientTimeout(total=self.timeout)
        }
        
        if auth_cookies:
            session_kwargs['cookies'] = auth_cookies
        if headers:
            session_kwargs['headers'] = headers
        
        async with aiohttp.ClientSession(**session_kwargs) as session:
            yield session
    
    async def authenticated_request(
        self,
        method: str,
        url: str,
        session: Optional[aiohttp.ClientSession] = None,
        **kwargs
    ) -> aiohttp.ClientResponse:
        """
        Make a single authenticated request.
        
        If session is provided, uses that session.
        Otherwise creates a temporary authenticated session.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            session: Optional existing session to use
            **kwargs: Additional args for the request (data, json, headers, etc.)
            
        Returns:
            aiohttp.ClientResponse
        """
        if session:
            # Use provided session
            request_method = getattr(session, method.lower())
            return await request_method(url, **kwargs)
        else:
            # Create temporary session
            async with self.get_authenticated_session() as temp_session:
                request_method = getattr(temp_session, method.lower())
                return await request_method(url, **kwargs)
    
    def get_target_url(self) -> str:
        """Get base target URL from config"""
        target_url = self.config.get('target', {}).get('url', '')
        if not target_url:
            target_url = self.config.get('target_url', '')
        if not target_url and hasattr(self.context, 'target_url'):
            target_url = self.context.target_url
        return target_url
    
    def get_endpoints(self) -> List[Dict]:
        """Get endpoints from context"""
        if hasattr(self.context, 'endpoints'):
            return self.context.endpoints
        return []
    
    async def rate_limit_delay(self):
        """Apply rate limiting delay between requests"""
        if self.rate_limit > 0:
            await asyncio.sleep(1 / self.rate_limit)


class BaseScanner(AuthenticatedScannerMixin):
    """
    Base class for all web vulnerability scanners.
    
    Provides:
    - Authenticated HTTP session support
    - Common configuration access
    - Rate limiting
    - Result collection
    
    Subclasses should implement the scan() method.
    """
    
    def __init__(self, config: dict, context):
        super().__init__(config, context)
    
    async def scan(self) -> List[Any]:
        """
        Main scan method. Override in subclasses.
        
        Returns:
            List of vulnerability findings
        """
        raise NotImplementedError("Subclasses must implement scan()")
