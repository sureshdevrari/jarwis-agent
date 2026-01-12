"""
Jarwis AGI Pen Test - Token Manager

Handles authentication token lifecycle for post-login scanning:
- Token storage and retrieval
- Automatic expiry detection
- Token refresh via re-login
- Background refresh loop to keep tokens alive

This ensures attacks never fail due to expired tokens.

Usage:
    manager = TokenManager(
        login_url="https://target.com/login",
        credentials={"username": "test", "password": "test123"}
    )
    
    await manager.start()  # Starts background refresh loop
    
    # Get current valid token
    token = await manager.get_valid_token()
    
    # When done
    await manager.stop()
"""

import asyncio
import aiohttp
import ssl
import jwt
import logging
import re
import json
from typing import Dict, Optional, Any, Callable, Tuple, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


class AuthMethod(Enum):
    """Supported authentication methods"""
    USERNAME_PASSWORD = "username_password"
    API_KEY = "api_key"
    OAUTH2_CLIENT_CREDENTIALS = "oauth2_client_credentials"
    OAUTH2_PASSWORD = "oauth2_password"
    SESSION_COOKIE = "session_cookie"
    CUSTOM = "custom"


@dataclass
class TokenInfo:
    """Information about an authentication token"""
    token_type: str  # jwt, bearer, api_key, session_cookie
    token_value: str
    
    # Expiry tracking
    expires_at: Optional[datetime] = None
    issued_at: Optional[datetime] = None
    
    # For refresh
    refresh_token: Optional[str] = None
    
    # Where this token should be placed
    header_name: str = "Authorization"
    header_prefix: str = "Bearer"  # "Bearer", "Token", "", etc.
    cookie_name: Optional[str] = None  # If token goes in cookie
    
    # Metadata
    last_used: Optional[datetime] = None
    refresh_count: int = 0
    
    def __post_init__(self):
        self.issued_at = datetime.now()
        self.last_used = datetime.now()
    
    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """Check if token is expired or will expire soon"""
        if not self.expires_at:
            return False
        return datetime.now() >= (self.expires_at - timedelta(seconds=buffer_seconds))
    
    def time_until_expiry(self) -> Optional[timedelta]:
        """Get time remaining until expiry"""
        if not self.expires_at:
            return None
        return self.expires_at - datetime.now()
    
    def get_header_value(self) -> str:
        """Get formatted header value"""
        if self.header_prefix:
            return f"{self.header_prefix} {self.token_value}"
        return self.token_value


class TokenManager:
    """
    Manages authentication tokens for post-login scanning.
    
    Responsibilities:
    - Store and track tokens
    - Detect token expiry (JWT parsing, tracking 401s)
    - Refresh tokens via re-login or refresh endpoint
    - Run background loop to keep tokens alive
    - Notify subscribers when tokens are refreshed
    """
    
    def __init__(
        self,
        auth_method: AuthMethod = AuthMethod.USERNAME_PASSWORD,
        login_url: Optional[str] = None,
        refresh_url: Optional[str] = None,
        credentials: Optional[Dict[str, str]] = None,
        custom_login_handler: Optional[Callable] = None,
        refresh_buffer_seconds: int = 60,
        auto_refresh: bool = True,
        refresh_check_interval: int = 30
    ):
        """
        Initialize TokenManager.
        
        Args:
            auth_method: How to authenticate (username/password, API key, etc.)
            login_url: URL to submit login credentials
            refresh_url: URL for token refresh (if different from login)
            credentials: Login credentials dict
            custom_login_handler: Custom async function for login
            refresh_buffer_seconds: Refresh this many seconds before expiry
            auto_refresh: Whether to run background refresh loop
            refresh_check_interval: How often to check for expiry (seconds)
        """
        self.auth_method = auth_method
        self.login_url = login_url
        self.refresh_url = refresh_url or login_url
        self.credentials = credentials or {}
        self.custom_login_handler = custom_login_handler
        self.refresh_buffer_seconds = refresh_buffer_seconds
        self.auto_refresh = auto_refresh
        self.refresh_check_interval = refresh_check_interval
        
        # Token storage
        self._tokens: Dict[str, TokenInfo] = {}
        self._primary_token_type: str = "jwt"
        
        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssl_context = ssl.create_default_context()
        self._ssl_context.check_hostname = False
        self._ssl_context.verify_mode = ssl.CERT_NONE
        
        # Background task
        self._refresh_task: Optional[asyncio.Task] = None
        self._running = False
        
        # Callbacks
        self._on_token_refreshed: List[Callable] = []
        self._on_refresh_failed: List[Callable] = []
        
        # Stats
        self.stats = {
            'total_refreshes': 0,
            'failed_refreshes': 0,
            'last_refresh_time': None,
            'last_refresh_error': None
        }
        
        logger.info(f"TokenManager initialized - Method: {auth_method.value}")
    
    async def start(self):
        """Start the token manager and background refresh loop"""
        if self._running:
            return
        
        # Create session
        connector = aiohttp.TCPConnector(ssl=self._ssl_context, limit=5)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=30)
        )
        
        self._running = True
        
        # Start background refresh if enabled
        if self.auto_refresh:
            self._refresh_task = asyncio.create_task(self._refresh_loop())
            logger.info("Token refresh background loop started")
    
    async def stop(self):
        """Stop the token manager and cleanup"""
        self._running = False
        
        if self._refresh_task:
            self._refresh_task.cancel()
            try:
                await self._refresh_task
            except asyncio.CancelledError:
                pass
            self._refresh_task = None
        
        if self._session:
            await self._session.close()
            self._session = None
        
        logger.info("TokenManager stopped")
    
    def add_token(
        self,
        token_type: str,
        token_value: str,
        expires_at: Optional[datetime] = None,
        refresh_token: Optional[str] = None,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer",
        cookie_name: Optional[str] = None,
        is_primary: bool = False
    ):
        """
        Add or update a token.
        
        Args:
            token_type: Type identifier (jwt, bearer, session, api_key)
            token_value: The actual token string
            expires_at: When the token expires
            refresh_token: Token for refreshing (OAuth2)
            header_name: HTTP header to put token in
            header_prefix: Prefix before token value
            cookie_name: Cookie name if token goes in cookie
            is_primary: Whether this is the main auth token
        """
        # Try to extract expiry from JWT if not provided
        if not expires_at and token_type in ['jwt', 'bearer']:
            expires_at = self._extract_jwt_expiry(token_value)
        
        token_info = TokenInfo(
            token_type=token_type,
            token_value=token_value,
            expires_at=expires_at,
            refresh_token=refresh_token,
            header_name=header_name,
            header_prefix=header_prefix,
            cookie_name=cookie_name
        )
        
        self._tokens[token_type] = token_info
        
        if is_primary:
            self._primary_token_type = token_type
        
        expiry_str = expires_at.isoformat() if expires_at else "unknown"
        logger.info(f"Token added: {token_type} (expires: {expiry_str})")
    
    def _extract_jwt_expiry(self, token: str) -> Optional[datetime]:
        """Extract expiry from JWT token"""
        try:
            # Decode without verification to get claims
            # Note: We don't verify signature since we just want expiry
            parts = token.split('.')
            if len(parts) != 3:
                return None
            
            # Decode payload (add padding if needed)
            import base64
            payload = parts[1]
            padding = 4 - len(payload) % 4
            if padding != 4:
                payload += '=' * padding
            
            decoded = json.loads(base64.urlsafe_b64decode(payload))
            
            if 'exp' in decoded:
                return datetime.fromtimestamp(decoded['exp'])
            
        except Exception as e:
            logger.debug(f"Could not extract JWT expiry: {e}")
        
        return None
    
    def get_token(self, token_type: Optional[str] = None) -> Optional[TokenInfo]:
        """Get a token by type (or primary token)"""
        if token_type:
            return self._tokens.get(token_type)
        return self._tokens.get(self._primary_token_type)
    
    async def get_valid_token(self, token_type: Optional[str] = None) -> Optional[TokenInfo]:
        """
        Get a valid (non-expired) token, refreshing if needed.
        
        This is the main method scanners should use.
        """
        token = self.get_token(token_type)
        
        if not token:
            # No token stored - try to login
            success = await self.refresh_token(token_type or self._primary_token_type)
            if success:
                token = self.get_token(token_type)
        
        elif token.is_expired(self.refresh_buffer_seconds):
            # Token expired or expiring soon - refresh
            logger.info(f"Token {token.token_type} is expiring - refreshing")
            success = await self.refresh_token(token.token_type)
            if success:
                token = self.get_token(token_type)
        
        return token
    
    def get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for all tokens"""
        headers = {}
        for token_type, token_info in self._tokens.items():
            if token_info.cookie_name:
                continue  # Cookie tokens don't go in headers
            headers[token_info.header_name] = token_info.get_header_value()
        return headers
    
    def get_auth_cookies(self) -> Dict[str, str]:
        """Get authentication cookies for all cookie-based tokens"""
        cookies = {}
        for token_type, token_info in self._tokens.items():
            if token_info.cookie_name:
                cookies[token_info.cookie_name] = token_info.token_value
        return cookies
    
    async def refresh_token(self, token_type: str) -> bool:
        """
        Refresh a specific token by re-authenticating.
        
        Returns True on success, False on failure.
        """
        try:
            logger.info(f"Refreshing token: {token_type}")
            
            # Check for refresh token first
            token_info = self._tokens.get(token_type)
            if token_info and token_info.refresh_token:
                success = await self._refresh_with_refresh_token(token_info)
                if success:
                    self.stats['total_refreshes'] += 1
                    self.stats['last_refresh_time'] = datetime.now().isoformat()
                    self._notify_token_refreshed(token_type)
                    return True
            
            # Fall back to full re-login
            if self.custom_login_handler:
                result = await self.custom_login_handler()
                if result:
                    self.stats['total_refreshes'] += 1
                    self.stats['last_refresh_time'] = datetime.now().isoformat()
                    self._notify_token_refreshed(token_type)
                    return True
            
            elif self.auth_method == AuthMethod.USERNAME_PASSWORD:
                success = await self._login_username_password()
                if success:
                    self.stats['total_refreshes'] += 1
                    self.stats['last_refresh_time'] = datetime.now().isoformat()
                    self._notify_token_refreshed(token_type)
                    return True
            
            elif self.auth_method == AuthMethod.OAUTH2_PASSWORD:
                success = await self._login_oauth2_password()
                if success:
                    self.stats['total_refreshes'] += 1
                    self.stats['last_refresh_time'] = datetime.now().isoformat()
                    self._notify_token_refreshed(token_type)
                    return True
            
            self.stats['failed_refreshes'] += 1
            return False
            
        except Exception as e:
            self.stats['failed_refreshes'] += 1
            self.stats['last_refresh_error'] = str(e)
            logger.error(f"Token refresh failed: {e}")
            self._notify_refresh_failed(token_type, str(e))
            return False
    
    async def _refresh_with_refresh_token(self, token_info: TokenInfo) -> bool:
        """Use refresh token to get new access token"""
        if not self.refresh_url or not token_info.refresh_token:
            return False
        
        try:
            async with self._session.post(
                self.refresh_url,
                json={"refresh_token": token_info.refresh_token},
                ssl=self._ssl_context
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    new_token = data.get('access_token') or data.get('token')
                    new_refresh = data.get('refresh_token')
                    
                    if new_token:
                        self.add_token(
                            token_type=token_info.token_type,
                            token_value=new_token,
                            refresh_token=new_refresh or token_info.refresh_token,
                            header_name=token_info.header_name,
                            header_prefix=token_info.header_prefix,
                            cookie_name=token_info.cookie_name
                        )
                        token_info.refresh_count += 1
                        logger.info(f"Token refreshed via refresh_token (count: {token_info.refresh_count})")
                        return True
        
        except Exception as e:
            logger.warning(f"Refresh token flow failed: {e}")
        
        return False
    
    async def _login_username_password(self) -> bool:
        """Login with username/password and extract token"""
        if not self.login_url or not self.credentials:
            logger.error("Missing login_url or credentials")
            return False
        
        try:
            # Common field names
            username = self.credentials.get('username') or self.credentials.get('email') or self.credentials.get('user')
            password = self.credentials.get('password') or self.credentials.get('pass')
            
            if not username or not password:
                logger.error("Missing username or password in credentials")
                return False
            
            # Try JSON login first
            login_data = {"username": username, "password": password}
            
            async with self._session.post(
                self.login_url,
                json=login_data,
                ssl=self._ssl_context
            ) as response:
                
                # Check for token in response body
                if response.status == 200:
                    try:
                        data = await response.json()
                        
                        # Look for common token fields
                        token = (
                            data.get('token') or 
                            data.get('access_token') or 
                            data.get('jwt') or
                            data.get('accessToken') or
                            data.get('data', {}).get('token') or
                            data.get('data', {}).get('accessToken')
                        )
                        
                        refresh_token = (
                            data.get('refresh_token') or 
                            data.get('refreshToken') or
                            data.get('data', {}).get('refreshToken')
                        )
                        
                        if token:
                            self.add_token(
                                token_type='jwt' if '.' in token and token.count('.') == 2 else 'bearer',
                                token_value=token,
                                refresh_token=refresh_token,
                                is_primary=True
                            )
                            logger.info("Login successful - token extracted from JSON response")
                            return True
                    except:
                        pass
                
                # Check for session cookie
                cookies = response.cookies
                for cookie_name in ['session', 'sessionid', 'JSESSIONID', 'PHPSESSID', 'token', 'auth']:
                    if cookie_name in cookies or cookie_name.lower() in [c.lower() for c in cookies]:
                        cookie_value = str(cookies.get(cookie_name))
                        self.add_token(
                            token_type='session_cookie',
                            token_value=cookie_value,
                            cookie_name=cookie_name,
                            is_primary=True
                        )
                        logger.info(f"Login successful - session cookie extracted: {cookie_name}")
                        return True
                
                # Check Authorization header in response
                auth_header = response.headers.get('Authorization')
                if auth_header:
                    self.add_token(
                        token_type='bearer',
                        token_value=auth_header.replace('Bearer ', ''),
                        is_primary=True
                    )
                    logger.info("Login successful - token from Authorization header")
                    return True
        
        except Exception as e:
            logger.error(f"Username/password login failed: {e}")
        
        return False
    
    async def _login_oauth2_password(self) -> bool:
        """OAuth2 Resource Owner Password Credentials flow"""
        if not self.login_url or not self.credentials:
            return False
        
        try:
            data = {
                'grant_type': 'password',
                'username': self.credentials.get('username'),
                'password': self.credentials.get('password'),
                'client_id': self.credentials.get('client_id', ''),
                'client_secret': self.credentials.get('client_secret', ''),
            }
            
            async with self._session.post(
                self.login_url,
                data=data,  # OAuth2 typically uses form-encoded
                ssl=self._ssl_context
            ) as response:
                if response.status == 200:
                    resp_data = await response.json()
                    
                    access_token = resp_data.get('access_token')
                    refresh_token = resp_data.get('refresh_token')
                    expires_in = resp_data.get('expires_in')
                    
                    if access_token:
                        expires_at = None
                        if expires_in:
                            expires_at = datetime.now() + timedelta(seconds=int(expires_in))
                        
                        self.add_token(
                            token_type='bearer',
                            token_value=access_token,
                            expires_at=expires_at,
                            refresh_token=refresh_token,
                            is_primary=True
                        )
                        logger.info("OAuth2 password grant successful")
                        return True
        
        except Exception as e:
            logger.error(f"OAuth2 password grant failed: {e}")
        
        return False
    
    async def _refresh_loop(self):
        """Background loop that checks and refreshes tokens"""
        while self._running:
            try:
                await asyncio.sleep(self.refresh_check_interval)
                
                if not self._running:
                    break
                
                # Check all tokens for expiry
                for token_type, token_info in list(self._tokens.items()):
                    if token_info.is_expired(self.refresh_buffer_seconds):
                        logger.info(f"Auto-refreshing expiring token: {token_type}")
                        await self.refresh_token(token_type)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in refresh loop: {e}")
    
    def on_token_refreshed(self, callback: Callable):
        """Register callback for when token is refreshed"""
        self._on_token_refreshed.append(callback)
    
    def on_refresh_failed(self, callback: Callable):
        """Register callback for when refresh fails"""
        self._on_refresh_failed.append(callback)
    
    def _notify_token_refreshed(self, token_type: str):
        """Notify callbacks of successful refresh"""
        token = self._tokens.get(token_type)
        for callback in self._on_token_refreshed:
            try:
                if asyncio.iscoroutinefunction(callback):
                    asyncio.create_task(callback(token_type, token))
                else:
                    callback(token_type, token)
            except Exception as e:
                logger.error(f"Token refresh callback error: {e}")
    
    def _notify_refresh_failed(self, token_type: str, error: str):
        """Notify callbacks of failed refresh"""
        for callback in self._on_refresh_failed:
            try:
                if asyncio.iscoroutinefunction(callback):
                    asyncio.create_task(callback(token_type, error))
                else:
                    callback(token_type, error)
            except Exception as e:
                logger.error(f"Refresh failed callback error: {e}")
    
    def force_expiry(self, token_type: str):
        """Force a token to appear expired (for testing)"""
        token = self._tokens.get(token_type)
        if token:
            token.expires_at = datetime.now() - timedelta(seconds=1)
            logger.info(f"Forced expiry on token: {token_type}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get token manager statistics"""
        stats = dict(self.stats)
        stats['tokens'] = {}
        
        for token_type, token_info in self._tokens.items():
            remaining = token_info.time_until_expiry()
            stats['tokens'][token_type] = {
                'is_expired': token_info.is_expired(0),
                'expires_in_seconds': remaining.total_seconds() if remaining else None,
                'refresh_count': token_info.refresh_count
            }
        
        return stats
