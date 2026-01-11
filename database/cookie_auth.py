"""
HttpOnly Cookie Authentication for Jarwis API
Secure cookie-based JWT token management

Security Features:
- HttpOnly: Prevents JavaScript access (XSS protection)
- Secure: Only sent over HTTPS in production
- SameSite: Prevents CSRF attacks
- Path-scoped: Limits cookie exposure

Created by BKD Labs
"""

import os
from datetime import timedelta
from typing import Optional, Tuple
from fastapi import Request, Response

# Environment detection
IS_PRODUCTION = os.getenv("ENVIRONMENT", "development") == "production"
COOKIE_DOMAIN = os.getenv("COOKIE_DOMAIN", None)  # None = current domain only

# Cookie names
ACCESS_TOKEN_COOKIE = "jarwis_access"
REFRESH_TOKEN_COOKIE = "jarwis_refresh"


class CookieConfig:
    """Cookie security configuration"""
    # HttpOnly: True = JavaScript cannot access (XSS protection)
    httponly: bool = True
    
    # Secure: True = Only sent over HTTPS
    # In development (localhost), browsers allow secure=False
    secure: bool = IS_PRODUCTION
    
    # SameSite: 'lax' for normal use, 'strict' for high security
    # 'lax' allows GET requests from external links
    # 'strict' blocks all cross-site requests
    samesite: str = "lax"
    
    # Path: Limit cookie to API paths
    path: str = "/"
    
    # Domain: None = current domain only (most secure)
    domain: Optional[str] = COOKIE_DOMAIN


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
    access_expires_minutes: int = 15,
    refresh_expires_days: int = 7
) -> None:
    """
    Set HttpOnly cookies for JWT tokens.
    
    Args:
        response: FastAPI Response object
        access_token: JWT access token
        refresh_token: JWT refresh token
        access_expires_minutes: Access token lifetime in minutes
        refresh_expires_days: Refresh token lifetime in days
    """
    config = CookieConfig()
    
    # Access token cookie (short-lived)
    response.set_cookie(
        key=ACCESS_TOKEN_COOKIE,
        value=access_token,
        max_age=access_expires_minutes * 60,  # Convert to seconds
        httponly=config.httponly,
        secure=config.secure,
        samesite=config.samesite,
        path=config.path,
        domain=config.domain
    )
    
    # Refresh token cookie (longer-lived)
    response.set_cookie(
        key=REFRESH_TOKEN_COOKIE,
        value=refresh_token,
        max_age=refresh_expires_days * 24 * 60 * 60,  # Convert to seconds
        httponly=config.httponly,
        secure=config.secure,
        samesite=config.samesite,
        path=config.path,
        domain=config.domain
    )


def clear_auth_cookies(response: Response) -> None:
    """
    Clear authentication cookies on logout.
    
    Args:
        response: FastAPI Response object
    """
    config = CookieConfig()
    
    # Delete access token cookie
    response.delete_cookie(
        key=ACCESS_TOKEN_COOKIE,
        path=config.path,
        domain=config.domain,
        secure=config.secure,
        httponly=config.httponly,
        samesite=config.samesite
    )
    
    # Delete refresh token cookie
    response.delete_cookie(
        key=REFRESH_TOKEN_COOKIE,
        path=config.path,
        domain=config.domain,
        secure=config.secure,
        httponly=config.httponly,
        samesite=config.samesite
    )


def get_token_from_cookie(request: Request, token_type: str = "access") -> Optional[str]:
    """
    Extract JWT token from HttpOnly cookie.
    
    Args:
        request: FastAPI Request object
        token_type: 'access' or 'refresh'
        
    Returns:
        Token string or None if not found
    """
    cookie_name = ACCESS_TOKEN_COOKIE if token_type == "access" else REFRESH_TOKEN_COOKIE
    return request.cookies.get(cookie_name)


def get_tokens_from_cookies(request: Request) -> Tuple[Optional[str], Optional[str]]:
    """
    Extract both tokens from cookies.
    
    Args:
        request: FastAPI Request object
        
    Returns:
        Tuple of (access_token, refresh_token)
    """
    access_token = request.cookies.get(ACCESS_TOKEN_COOKIE)
    refresh_token = request.cookies.get(REFRESH_TOKEN_COOKIE)
    return access_token, refresh_token
