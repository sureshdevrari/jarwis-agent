"""
Authentication Utilities
JWT token generation, password hashing, and user verification
"""

import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple
from uuid import UUID

from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from database.models import User, RefreshToken, APIKey
from database.config import settings


# ============== Configuration ==============

class AuthSettings(BaseModel):
    """Auth configuration"""
    SECRET_KEY: str = "jarwis-super-secret-key-change-in-production-2026"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 5  # Short-lived access token (5 mins for security)
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    REFRESH_TOKEN_ROTATION_MINUTES: int = 5  # Rotate refresh token every 5 mins
    SESSION_INACTIVITY_MINUTES: int = 180  # 3 hours inactivity timeout


auth_settings = AuthSettings()

# Password hasher using Argon2 (more secure and modern than bcrypt)
ph = PasswordHasher()


# ============== Password Functions ==============

def hash_password(password: str) -> str:
    """Hash a password using Argon2"""
    return ph.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    try:
        ph.verify(hashed_password, plain_password)
        return True
    except VerifyMismatchError:
        return False


# ============== Token Functions ==============

def create_access_token(
    user_id: str, 
    expires_delta: Optional[timedelta] = None,
    expires_minutes: Optional[int] = None,
    additional_claims: Optional[dict] = None
) -> str:
    """Create a JWT access token
    
    Args:
        user_id: The user ID to encode in the token
        expires_delta: Optional timedelta for expiration (takes precedence)
        expires_minutes: Optional minutes until expiration (if expires_delta not set)
        additional_claims: Optional dict of additional claims to include in token
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    elif expires_minutes:
        expire = datetime.utcnow() + timedelta(minutes=expires_minutes)
    else:
        expire = datetime.utcnow() + timedelta(minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "type": "access",
        "iat": datetime.utcnow()
    }
    
    # Add any additional claims
    if additional_claims:
        payload.update(additional_claims)
    
    return jwt.encode(payload, auth_settings.SECRET_KEY, algorithm=auth_settings.ALGORITHM)


def create_refresh_token(user_id: str) -> Tuple[str, datetime]:
    """Create a refresh token and return (token, expiry)"""
    expire = datetime.utcnow() + timedelta(days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "type": "refresh",
        "iat": datetime.utcnow(),
        "jti": secrets.token_urlsafe(32)  # Unique token ID
    }
    
    token = jwt.encode(payload, auth_settings.SECRET_KEY, algorithm=auth_settings.ALGORITHM)
    return token, expire


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT token"""
    try:
        payload = jwt.decode(
            token, 
            auth_settings.SECRET_KEY, 
            algorithms=[auth_settings.ALGORITHM]
        )
        return payload
    except JWTError:
        return None


def hash_token(token: str) -> str:
    """Hash a token for storage"""
    return hashlib.sha256(token.encode()).hexdigest()


# ============== API Key Functions ==============

def generate_api_key() -> str:
    """Generate a new API key"""
    return f"jw_{secrets.token_urlsafe(32)}"


def hash_api_key(api_key: str) -> str:
    """Hash an API key for storage"""
    return hashlib.sha256(api_key.encode()).hexdigest()


# ============== Database Auth Functions ==============

async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
    """Get user by email"""
    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
    """Get user by username"""
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: UUID) -> Optional[User]:
    """Get user by ID"""
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def authenticate_user(db: AsyncSession, email_or_username: str, password: str) -> Optional[User]:
    """Authenticate user with email/username and password"""
    # Try email first
    user = await get_user_by_email(db, email_or_username)
    
    # If not found by email, try username
    if not user:
        user = await get_user_by_username(db, email_or_username)
    
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


async def create_user(
    db: AsyncSession, 
    email: str, 
    username: str, 
    password: str,
    full_name: Optional[str] = None,
    approval_status: str = "email_unverified"
) -> User:
    """Create a new user"""
    user = User(
        email=email,
        username=username,
        hashed_password=hash_password(password),
        full_name=full_name,
        approval_status=approval_status
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def store_refresh_token(
    db: AsyncSession,
    user_id: UUID,
    token: str,
    expires_at: datetime,
    device_info: Optional[str] = None,
    ip_address: Optional[str] = None
) -> RefreshToken:
    """Store a refresh token in the database"""
    refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_token(token),
        expires_at=expires_at,
        device_info=device_info,
        ip_address=ip_address
    )
    db.add(refresh_token)
    await db.commit()
    return refresh_token


async def verify_refresh_token(db: AsyncSession, token: str) -> Optional[RefreshToken]:
    """Verify a refresh token exists and is valid"""
    token_hash = hash_token(token)
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash,
            RefreshToken.is_revoked == False,
            RefreshToken.expires_at > datetime.utcnow()
        )
    )
    return result.scalar_one_or_none()


async def revoke_refresh_token(db: AsyncSession, token: str) -> bool:
    """Revoke a refresh token"""
    token_hash = hash_token(token)
    result = await db.execute(
        select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    )
    refresh_token = result.scalar_one_or_none()
    if refresh_token:
        refresh_token.is_revoked = True
        await db.commit()
        return True
    return False


async def revoke_all_user_tokens(db: AsyncSession, user_id: UUID) -> int:
    """Revoke all refresh tokens for a user"""
    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.user_id == user_id,
            RefreshToken.is_revoked == False
        )
    )
    tokens = result.scalars().all()
    count = 0
    for token in tokens:
        token.is_revoked = True
        count += 1
    await db.commit()
    return count


async def verify_api_key(db: AsyncSession, api_key: str) -> Optional[Tuple[APIKey, User]]:
    """Verify an API key and return the key and associated user"""
    key_hash = hash_api_key(api_key)
    result = await db.execute(
        select(APIKey, User).join(User).where(
            APIKey.key_hash == key_hash,
            APIKey.is_active == True,
            User.is_active == True
        )
    )
    row = result.first()
    if row:
        api_key_obj, user = row
        # Check expiry
        if api_key_obj.expires_at and api_key_obj.expires_at < datetime.utcnow():
            return None
        # Update usage
        api_key_obj.last_used_at = datetime.utcnow()
        api_key_obj.usage_count += 1
        await db.commit()
        return api_key_obj, user
    return None
