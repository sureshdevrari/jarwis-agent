"""
FastAPI Dependencies for Authentication
Includes subscription validation and refresh token enforcement.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from fastapi import Depends, HTTPException, status, Header, Request
from fastapi.security import OAuth2PasswordBearer, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.auth import (
    decode_token, 
    get_user_by_id, 
    verify_api_key,
    auth_settings,
    hash_token
)
from database.subscription import get_plan_config, has_feature
from database.models import RefreshToken


# OAuth2 scheme for JWT tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)

# API Key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def has_valid_session(db: AsyncSession, user_id: UUID) -> bool:
    """
    Check if user has at least one valid (non-revoked, non-expired) refresh token.
    This ensures that access tokens become invalid when all sessions are revoked.
    Prevents attackers from using captured JWT tokens after user logs out.
    """
    from sqlalchemy import select
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > datetime.utcnow()
        ).limit(1)
    )
    return result.scalar_one_or_none() is not None


def validate_token_freshness(payload: dict) -> bool:
    """
    Validate that the token was issued recently enough.
    Tokens older than 15 minutes require a refresh.
    """
    issued_at = payload.get("iat")
    if not issued_at:
        return False
    
    # Convert to datetime if it's a timestamp
    if isinstance(issued_at, (int, float)):
        issued_time = datetime.utcfromtimestamp(issued_at)
    else:
        issued_time = issued_at
    
    # Check if token is older than the access token expiry
    age_minutes = (datetime.utcnow() - issued_time).total_seconds() / 60
    return age_minutes <= auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_header),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current authenticated user from JWT token or API key.
    Raises HTTPException if not authenticated.
    
    SECURITY: Also validates that user has an active session (non-revoked refresh token).
    This prevents attackers from using captured JWT tokens after session logout.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    session_invalid_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Session has been terminated. Please login again.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Try API key first (API keys don't require session validation)
    if api_key:
        result = await verify_api_key(db, api_key)
        if result:
            _, user = result
            return user
    
    # Try JWT token - REQUIRED for dashboard access
    if not token:
        raise credentials_exception
    
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    
    # Verify token type - must be access token
    if payload.get("type") != "access":
        raise credentials_exception
    
    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_exception
    
    try:
        user_uuid = UUID(user_id)
        user = await get_user_by_id(db, user_uuid)
    except ValueError:
        raise credentials_exception
    
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated"
        )
    
    # SECURITY: Verify user has a valid session (at least one non-revoked refresh token)
    # This prevents use of captured JWT tokens after logout or session revocation
    if not await has_valid_session(db, user_uuid):
        raise session_invalid_exception
    
    return user


async def get_current_user_optional(
    token: Optional[str] = Depends(oauth2_scheme),
    api_key: Optional[str] = Depends(api_key_header),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """
    Get current user if authenticated, otherwise return None.
    Does not raise exception for unauthenticated requests.
    """
    try:
        return await get_current_user(token, api_key, db)
    except HTTPException:
        return None


async def get_current_active_user(
    current_user: User = Depends(get_current_user)
) -> User:
    """Get current active user"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


async def get_current_verified_user(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current verified user"""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Email not verified. Please verify your email first."
        )
    return current_user


async def get_current_superuser(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Get current superuser"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required"
        )
    return current_user


def require_scopes(*scopes: str):
    """
    Dependency factory for checking API key scopes.
    Usage: Depends(require_scopes("scans:read", "scans:write"))
    """
    async def check_scopes(
        api_key: Optional[str] = Depends(api_key_header),
        token: Optional[str] = Depends(oauth2_scheme),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        # JWT tokens have full access
        if token and not api_key:
            return await get_current_user(token, None, db)
        
        # Check API key scopes
        if api_key:
            result = await verify_api_key(db, api_key)
            if result:
                api_key_obj, user = result
                key_scopes = api_key_obj.scopes or {}
                
                # Check if all required scopes are present
                for scope in scopes:
                    if not key_scopes.get(scope, False):
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"API key missing required scope: {scope}"
                        )
                return user
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    return check_scopes


def require_feature(feature_key: str):
    """
    Dependency factory for checking subscription features.
    Prevents users from accessing features not included in their plan.
    Usage: Depends(require_feature("mobile_pentest"))
    """
    async def check_feature(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        plan = current_user.plan or "free"
        
        if not has_feature(plan, feature_key):
            plan_config = get_plan_config(plan)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "feature_not_available",
                    "message": f"This feature is not available on your {plan_config['display_name']} plan. Please upgrade.",
                    "feature": feature_key,
                    "current_plan": plan,
                    "upgrade_url": "/pricing"
                }
            )
        return current_user
    
    return check_feature


def require_subscription_active():
    """
    Dependency to ensure user has an active (non-expired) subscription.
    Free users are always considered active.
    """
    async def check_subscription(
        current_user: User = Depends(get_current_active_user)
    ) -> User:
        plan = current_user.plan or "free"
        
        # Free users are always active
        if plan == "free":
            return current_user
        
        # Check subscription expiry for paid plans
        if current_user.subscription_end:
            if current_user.subscription_end < datetime.utcnow():
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail={
                        "error": "subscription_expired",
                        "message": "Your subscription has expired. Please renew to continue using premium features.",
                        "expired_at": current_user.subscription_end.isoformat(),
                        "upgrade_url": "/pricing"
                    }
                )
        
        return current_user
    
    return check_subscription


async def get_user_with_subscription_check(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """
    Get user and validate their subscription is active.
    This should be used for all protected endpoints.
    """
    plan = current_user.plan or "free"
    
    # Check subscription expiry for paid plans
    if plan != "free" and current_user.subscription_end:
        if current_user.subscription_end < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "subscription_expired",
                    "message": "Your subscription has expired. Please renew to continue.",
                    "upgrade_url": "/pricing"
                }
            )
    
    return current_user