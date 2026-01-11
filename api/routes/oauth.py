"""
OAuth2 Social Login Routes for Jarwis API
Handles Google, GitHub, and Microsoft authentication
Now with HttpOnly cookie support for secure token storage
"""

import os
import secrets
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import httpx
from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel

from database.connection import get_db
from database.models import User
from database.auth import (
    create_access_token, create_refresh_token, 
    store_refresh_token, get_user_by_email, auth_settings
)
from database.cookie_auth import set_auth_cookies

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/oauth", tags=["OAuth"])

# ============== OAuth Configuration ==============

# Frontend URL for redirects
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")

# OAuth Provider Settings
OAUTH_PROVIDERS = {
    "google": {
        "client_id": os.getenv("GOOGLE_CLIENT_ID", ""),
        "client_secret": os.getenv("GOOGLE_CLIENT_SECRET", ""),
        "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://www.googleapis.com/oauth2/v2/userinfo",
        "scope": "openid email profile",
    },
    "github": {
        "client_id": os.getenv("GITHUB_CLIENT_ID", ""),
        "client_secret": os.getenv("GITHUB_CLIENT_SECRET", ""),
        "auth_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "emails_url": "https://api.github.com/user/emails",
        "scope": "read:user user:email",
    },
    "microsoft": {
        "client_id": os.getenv("MICROSOFT_CLIENT_ID", ""),
        "client_secret": os.getenv("MICROSOFT_CLIENT_SECRET", ""),
        "tenant": os.getenv("MICROSOFT_TENANT_ID", "common"),
        "auth_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/v1.0/me",
        "scope": "openid email profile User.Read",
    },
}

# Store for OAuth state tokens (in production, use Redis)
# State tokens expire after 10 minutes for security
oauth_states: dict = {}
OAUTH_STATE_EXPIRY_MINUTES = 10


def cleanup_expired_states():
    """Remove expired OAuth state tokens"""
    now = datetime.utcnow()
    expired = [
        state for state, data in oauth_states.items()
        if now - data.get("created", now) > timedelta(minutes=OAUTH_STATE_EXPIRY_MINUTES)
    ]
    for state in expired:
        del oauth_states[state]


def validate_and_consume_state(state: str) -> bool:
    """
    Validate OAuth state token and consume it (one-time use).
    Returns True if valid, False otherwise.
    """
    cleanup_expired_states()
    
    if not state or state not in oauth_states:
        return False
    
    state_data = oauth_states.get(state)
    if not state_data:
        return False
    
    # Check if expired
    created = state_data.get("created", datetime.utcnow())
    if datetime.utcnow() - created > timedelta(minutes=OAUTH_STATE_EXPIRY_MINUTES):
        del oauth_states[state]
        return False
    
    # Consume the state (one-time use)
    del oauth_states[state]
    return True


# ============== Response Models ==============

class OAuthURLResponse(BaseModel):
    """OAuth authorization URL response"""
    url: str
    state: str


class OAuthStatusResponse(BaseModel):
    """OAuth provider status"""
    provider: str
    configured: bool
    

# ============== Helper Functions ==============

# Which OAuth providers have callbacks fully configured in their respective consoles
# Set to comma-separated list of enabled providers, e.g., "google,github,microsoft"
OAUTH_ENABLED_PROVIDERS = os.getenv("OAUTH_ENABLED_PROVIDERS", "google").lower().split(",")


def is_provider_configured(provider: str) -> bool:
    """Check if OAuth provider is configured AND enabled"""
    if provider not in OAUTH_PROVIDERS:
        return False
    
    # Check if provider is in the enabled list (callback configured in provider console)
    if provider.lower() not in [p.strip() for p in OAUTH_ENABLED_PROVIDERS]:
        return False
    
    config = OAUTH_PROVIDERS[provider]
    return bool(config.get("client_id") and config.get("client_secret"))


def get_callback_url(request: Request, provider: str) -> str:
    """Get OAuth callback URL"""
    # Use the request's base URL or configured URL
    base_url = os.getenv("API_BASE_URL", str(request.base_url).rstrip('/'))
    return f"{base_url}/api/oauth/{provider}/callback"


async def get_or_create_oauth_user(
    db: AsyncSession,
    email: str,
    name: Optional[str],
    provider: str,
    provider_id: str,
    avatar_url: Optional[str] = None
) -> User:
    """Get existing user or create new one from OAuth data"""
    # Check if user exists
    user = await get_user_by_email(db, email)
    
    if user:
        # Update OAuth info
        if not user.oauth_provider:
            user.oauth_provider = provider
            user.oauth_id = provider_id
        if avatar_url and not user.avatar_url:
            user.avatar_url = avatar_url
        user.last_login = datetime.utcnow()
        await db.commit()
        await db.refresh(user)
        return user
    
    # Create new user
    username = email.split('@')[0]
    # Make username unique if needed
    from database.auth import get_user_by_username
    existing = await get_user_by_username(db, username)
    if existing:
        username = f"{username}_{secrets.token_hex(4)}"
    
    user = User(
        id=uuid4(),
        email=email,
        username=username,
        full_name=name or username,
        hashed_password="",  # No password for OAuth users
        is_active=True,
        is_verified=False,  # OAuth users need admin approval
        oauth_provider=provider,
        oauth_id=provider_id,
        avatar_url=avatar_url,
        approval_status="pending",  # Require admin approval
        plan="free",  # Default plan until admin assigns
        created_at=datetime.utcnow(),
        last_login=datetime.utcnow(),
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


def create_auth_tokens_for_user(user: User, db: AsyncSession) -> dict:
    """Create access and refresh tokens for a user"""
    access_token = create_access_token(user.id)
    refresh_token, refresh_expires = create_refresh_token(user.id)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "refresh_expires": refresh_expires,
        "token_type": "bearer",
        "expires_in": auth_settings.access_token_expire_minutes * 60,
    }


# ============== OAuth Status Routes ==============

@router.get("/providers")
async def get_oauth_providers():
    """Get list of configured OAuth providers"""
    return {
        "providers": [
            {
                "name": "google",
                "configured": is_provider_configured("google"),
                "label": "Google",
            },
            {
                "name": "github", 
                "configured": is_provider_configured("github"),
                "label": "GitHub",
            },
            {
                "name": "microsoft",
                "configured": is_provider_configured("microsoft"),
                "label": "Microsoft",
            },
        ]
    }


# ============== Google OAuth ==============

@router.get("/google/login")
async def google_login(request: Request):
    """Initiate Google OAuth flow"""
    if not is_provider_configured("google"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Google OAuth is not configured"
        )
    
    config = OAUTH_PROVIDERS["google"]
    state = secrets.token_urlsafe(32)
    oauth_states[state] = {"provider": "google", "created": datetime.utcnow()}
    logger.info(f"Created OAuth state for Google: {state[:20]}... Total states: {len(oauth_states)}")
    
    callback_url = get_callback_url(request, "google")
    logger.info(f"Google OAuth callback URL: {callback_url}")
    
    params = {
        "client_id": config["client_id"],
        "redirect_uri": callback_url,
        "scope": config["scope"],
        "response_type": "code",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    
    auth_url = f"{config['auth_url']}?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url=auth_url)


@router.get("/google/callback")
async def google_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Handle Google OAuth callback"""
    logger.info(f"Google OAuth callback received - state: {state[:20] if state else 'None'}..., code: {'present' if code else 'None'}")
    logger.info(f"Available states in memory: {list(oauth_states.keys())[:5]}")
    
    if error:
        logger.warning(f"Google OAuth error: {error}")
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error={error}")
    
    # Validate and consume state token (CSRF protection)
    state_valid = validate_and_consume_state(state)
    logger.info(f"State validation result: {state_valid}")
    
    if not code or not state_valid:
        logger.warning(f"Invalid or expired OAuth state token for Google callback. State in dict: {state in oauth_states if state else False}")
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error=invalid_state")
    
    config = OAUTH_PROVIDERS["google"]
    callback_url = get_callback_url(request, "google")
    
    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            config["token_url"],
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            },
        )
        
        if token_response.status_code != 200:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=token_exchange_failed")
        
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        # Get user info
        userinfo_response = await client.get(
            config["userinfo_url"],
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        if userinfo_response.status_code != 200:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=userinfo_failed")
        
        userinfo = userinfo_response.json()
    
    # Create or get user
    user = await get_or_create_oauth_user(
        db,
        email=userinfo.get("email"),
        name=userinfo.get("name"),
        provider="google",
        provider_id=userinfo.get("id"),
        avatar_url=userinfo.get("picture"),
    )
    
    # Check approval status FIRST - don't issue tokens to pending users
    approval_status = getattr(user, 'approval_status', 'pending')
    
    if approval_status != 'approved':
        # Pending or rejected users go to pending-approval page WITHOUT tokens
        logger.info(f"OAuth user {user.email} has approval_status={approval_status}, redirecting to pending-approval")
        redirect_url = (
            f"{FRONTEND_URL}/pending-approval"
            f"?email={user.email}"
            f"&provider=google"
            f"&status={approval_status}"
        )
        return RedirectResponse(url=redirect_url)
    
    # Only approved users get tokens
    auth_tokens = create_auth_tokens_for_user(user, db)
    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=auth_tokens["refresh_token"],
        expires_at=auth_tokens["refresh_expires"]
    )
    
    logger.info(f"OAuth user {user.email} is approved, issuing tokens")
    
    # Create redirect response and set HttpOnly cookies
    redirect_url = (
        f"{FRONTEND_URL}/oauth/callback"
        f"?access_token={auth_tokens['access_token']}"
        f"&refresh_token={auth_tokens['refresh_token']}"
        f"&provider=google"
    )
    response = RedirectResponse(url=redirect_url)
    
    # Set HttpOnly cookies for secure token storage
    set_auth_cookies(
        response=response,
        access_token=auth_tokens['access_token'],
        refresh_token=auth_tokens['refresh_token'],
        access_expires_minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_expires_days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    return response


# ============== GitHub OAuth ==============

@router.get("/github/login")
async def github_login(request: Request):
    """Initiate GitHub OAuth flow"""
    if not is_provider_configured("github"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GitHub OAuth is not configured"
        )
    
    config = OAUTH_PROVIDERS["github"]
    state = secrets.token_urlsafe(32)
    oauth_states[state] = {"provider": "github", "created": datetime.utcnow()}
    
    callback_url = get_callback_url(request, "github")
    
    params = {
        "client_id": config["client_id"],
        "redirect_uri": callback_url,
        "scope": config["scope"],
        "state": state,
    }
    
    auth_url = f"{config['auth_url']}?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url=auth_url)


@router.get("/github/callback")
async def github_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Handle GitHub OAuth callback"""
    if error:
        logger.warning(f"GitHub OAuth error: {error}")
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error={error}")
    
    # Validate and consume state token (CSRF protection)
    if not code or not validate_and_consume_state(state):
        logger.warning(f"Invalid or expired OAuth state token for GitHub callback")
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error=invalid_state")
    
    config = OAUTH_PROVIDERS["github"]
    callback_url = get_callback_url(request, "github")
    
    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            config["token_url"],
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "redirect_uri": callback_url,
            },
            headers={"Accept": "application/json"},
        )
        
        if token_response.status_code != 200:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=token_exchange_failed")
        
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        if not access_token:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=no_access_token")
        
        # Get user info
        userinfo_response = await client.get(
            config["userinfo_url"],
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        
        if userinfo_response.status_code != 200:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=userinfo_failed")
        
        userinfo = userinfo_response.json()
        
        # Get user email (might need separate request for GitHub)
        email = userinfo.get("email")
        if not email:
            emails_response = await client.get(
                config["emails_url"],
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
            )
            if emails_response.status_code == 200:
                emails = emails_response.json()
                primary_email = next(
                    (e for e in emails if e.get("primary") and e.get("verified")),
                    emails[0] if emails else None
                )
                if primary_email:
                    email = primary_email.get("email")
        
        if not email:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=no_email")
    
    # Create or get user
    user = await get_or_create_oauth_user(
        db,
        email=email,
        name=userinfo.get("name") or userinfo.get("login"),
        provider="github",
        provider_id=str(userinfo.get("id")),
        avatar_url=userinfo.get("avatar_url"),
    )
    
    # Check approval status FIRST - don't issue tokens to pending users
    approval_status = getattr(user, 'approval_status', 'pending')
    
    if approval_status != 'approved':
        # Pending or rejected users go to pending-approval page WITHOUT tokens
        logger.info(f"OAuth user {user.email} has approval_status={approval_status}, redirecting to pending-approval")
        redirect_url = (
            f"{FRONTEND_URL}/pending-approval"
            f"?email={user.email}"
            f"&provider=github"
            f"&status={approval_status}"
        )
        return RedirectResponse(url=redirect_url)
    
    # Only approved users get tokens
    auth_tokens = create_auth_tokens_for_user(user, db)
    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=auth_tokens["refresh_token"],
        expires_at=auth_tokens["refresh_expires"]
    )
    
    logger.info(f"OAuth user {user.email} is approved, issuing tokens")
    
    # Create redirect response and set HttpOnly cookies
    redirect_url = (
        f"{FRONTEND_URL}/oauth/callback"
        f"?access_token={auth_tokens['access_token']}"
        f"&refresh_token={auth_tokens['refresh_token']}"
        f"&provider=github"
    )
    response = RedirectResponse(url=redirect_url)
    
    # Set HttpOnly cookies for secure token storage
    set_auth_cookies(
        response=response,
        access_token=auth_tokens['access_token'],
        refresh_token=auth_tokens['refresh_token'],
        access_expires_minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_expires_days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    return response


# ============== Microsoft OAuth ==============

@router.get("/microsoft/login")
async def microsoft_login(request: Request):
    """Initiate Microsoft OAuth flow"""
    if not is_provider_configured("microsoft"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Microsoft OAuth is not configured"
        )
    
    config = OAUTH_PROVIDERS["microsoft"]
    state = secrets.token_urlsafe(32)
    oauth_states[state] = {"provider": "microsoft", "created": datetime.utcnow()}
    
    callback_url = get_callback_url(request, "microsoft")
    tenant = config.get("tenant", "common")
    auth_url = config["auth_url"].format(tenant=tenant)
    
    params = {
        "client_id": config["client_id"],
        "redirect_uri": callback_url,
        "scope": config["scope"],
        "response_type": "code",
        "state": state,
        "response_mode": "query",
    }
    
    full_auth_url = f"{auth_url}?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url=full_auth_url)


@router.get("/microsoft/callback")
async def microsoft_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    """Handle Microsoft OAuth callback"""
    if error:
        logger.warning(f"Microsoft OAuth error: {error}")
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error={error}")
    
    # Validate and consume state token (CSRF protection)
    if not code or not validate_and_consume_state(state):
        logger.warning(f"Invalid or expired OAuth state token for Microsoft callback")
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error=invalid_state")
    
    config = OAUTH_PROVIDERS["microsoft"]
    callback_url = get_callback_url(request, "microsoft")
    tenant = config.get("tenant", "common")
    token_url = config["token_url"].format(tenant=tenant)
    
    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_response = await client.post(
            token_url,
            data={
                "client_id": config["client_id"],
                "client_secret": config["client_secret"],
                "code": code,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
                "scope": config["scope"],
            },
        )
        
        if token_response.status_code != 200:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=token_exchange_failed")
        
        tokens = token_response.json()
        access_token = tokens.get("access_token")
        
        # Get user info from Microsoft Graph
        userinfo_response = await client.get(
            config["userinfo_url"],
            headers={"Authorization": f"Bearer {access_token}"},
        )
        
        if userinfo_response.status_code != 200:
            return RedirectResponse(url=f"{FRONTEND_URL}/login?error=userinfo_failed")
        
        userinfo = userinfo_response.json()
    
    email = userinfo.get("mail") or userinfo.get("userPrincipalName")
    if not email:
        return RedirectResponse(url=f"{FRONTEND_URL}/login?error=no_email")
    
    # Create or get user
    user = await get_or_create_oauth_user(
        db,
        email=email,
        name=userinfo.get("displayName"),
        provider="microsoft",
        provider_id=userinfo.get("id"),
    )
    
    # Check approval status FIRST - don't issue tokens to pending users
    approval_status = getattr(user, 'approval_status', 'pending')
    
    if approval_status != 'approved':
        # Pending or rejected users go to pending-approval page WITHOUT tokens
        logger.info(f"OAuth user {user.email} has approval_status={approval_status}, redirecting to pending-approval")
        redirect_url = (
            f"{FRONTEND_URL}/pending-approval"
            f"?email={user.email}"
            f"&provider=microsoft"
            f"&status={approval_status}"
        )
        return RedirectResponse(url=redirect_url)
    
    # Only approved users get tokens
    auth_tokens = create_auth_tokens_for_user(user, db)
    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=auth_tokens["refresh_token"],
        expires_at=auth_tokens["refresh_expires"]
    )
    
    logger.info(f"OAuth user {user.email} is approved, issuing tokens")
    
    # Create redirect response and set HttpOnly cookies
    redirect_url = (
        f"{FRONTEND_URL}/oauth/callback"
        f"?access_token={auth_tokens['access_token']}"
        f"&refresh_token={auth_tokens['refresh_token']}"
        f"&provider=microsoft"
    )
    response = RedirectResponse(url=redirect_url)
    
    # Set HttpOnly cookies for secure token storage
    set_auth_cookies(
        response=response,
        access_token=auth_tokens['access_token'],
        refresh_token=auth_tokens['refresh_token'],
        access_expires_minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_expires_days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    return response
