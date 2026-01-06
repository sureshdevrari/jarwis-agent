"""
Authentication Routes for Jarwis API
Handles login, signup, token refresh, and user management

Security Features:
- Brute force protection: 5 failed attempts in 5 mins = 15 min block
- Hard block: 20 failed attempts in 1 min = 1 hour block
- Input validation and sanitization
- Rate limiting per IP
"""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr, Field

from database.connection import get_db
from database.models import User
from database.schemas import (
    UserCreate, UserResponse, Token, LoginRequest,
    RefreshRequest, PasswordChange, MessageResponse
)
from database.auth import (
    authenticate_user, create_user, create_access_token, 
    create_refresh_token, decode_token, hash_password,
    verify_password, store_refresh_token, verify_refresh_token,
    revoke_refresh_token, revoke_all_user_tokens, get_user_by_email,
    get_user_by_username, get_user_by_id, auth_settings
)
from database.dependencies import get_current_user, get_current_active_user
from database.security import (
    check_brute_force, record_login_result, get_client_ip,
    InputValidator, security_store
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


# ============== Request/Response Models ==============

class RegisterRequest(BaseModel):
    """Registration request"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8, max_length=100)
    full_name: Optional[str] = None
    company: Optional[str] = None


class LoginResponse(BaseModel):
    """Login response with user info"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse
    requires_2fa: bool = False  # Indicates if 2FA verification is needed


class TwoFactorRequiredResponse(BaseModel):
    """Response when 2FA verification is required"""
    requires_2fa: bool = True
    two_factor_token: str  # Temporary token for 2FA verification
    channel: str  # 'email' or 'sms'
    recipient_masked: str  # Masked email/phone where code was sent
    expires_in: int = 300  # Token validity in seconds
    message: str = "Two-factor authentication required"


class UserProfileResponse(BaseModel):
    """User profile with role info"""
    id: UUID
    email: str
    username: str
    full_name: Optional[str] = None
    company: Optional[str] = None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    plan: str
    role: str  # computed: user, admin, super_admin
    approval_status: str  # pending, approved, rejected
    created_at: datetime
    last_login: Optional[datetime] = None


# ============== Auth Endpoints ==============

@router.post("/register", response_model=MessageResponse)
async def register(
    data: RegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Register a new user account"""
    client_ip = get_client_ip(request)
    
    # Rate limit registration attempts
    is_blocked, reason, remaining = await security_store.is_blocked(client_ip)
    if is_blocked:
        logger.warning(f"Blocked registration attempt from {client_ip}: {reason}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many requests. Please try again in {remaining} seconds."
        )
    
    # Validate username format
    valid, error = InputValidator.validate_username(data.username)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Validate password strength
    valid, error = InputValidator.validate_password(data.password)
    if not valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error
        )
    
    # Check for SQL injection in input fields
    for field_name, field_value in [("email", data.email), ("username", data.username), ("full_name", data.full_name or "")]:
        if InputValidator.check_sql_injection(field_value):
            logger.warning(f"SQL injection attempt in {field_name} from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid characters in {field_name}"
            )
    
    # Check if email already exists
    existing_email = await get_user_by_email(db, data.email)
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists"
        )
    
    # Check if username already exists
    existing_username = await get_user_by_username(db, data.username)
    if existing_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This username is already taken"
        )
    
    # Sanitize input
    sanitized_full_name = InputValidator.sanitize_string(data.full_name) if data.full_name else None
    sanitized_company = InputValidator.sanitize_string(data.company) if data.company else None
    
    # Create user
    user = await create_user(
        db=db,
        email=data.email,
        username=data.username,
        password=data.password,
        full_name=sanitized_full_name
    )
    
    # Update company if provided
    if sanitized_company:
        user.company = sanitized_company
        await db.commit()
    
    logger.info(f"New user registered: {data.email} from {client_ip}")
    
    return MessageResponse(
        message="Account created successfully! Please verify your email to complete registration.",
        success=True
    )


class EmailVerifiedRequest(BaseModel):
    """Request to mark email as verified"""
    email: EmailStr


@router.post("/email-verified", response_model=MessageResponse)
async def mark_email_verified(
    data: EmailVerifiedRequest,
    db: AsyncSession = Depends(get_db)
):
    """
    Mark user's email as verified and update status to pending approval.
    Called from frontend after Firebase email verification is successful.
    """
    user = await get_user_by_email(db, data.email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Only update if currently email_unverified
    if user.approval_status == "email_unverified":
        user.approval_status = "pending"
        user.is_verified = False  # Still needs admin approval
        await db.commit()
        return MessageResponse(
            message="Email verified! Your account is now pending admin approval.",
            success=True
        )
    elif user.approval_status == "pending":
        return MessageResponse(
            message="Email already verified. Waiting for admin approval.",
            success=True
        )
    elif user.approval_status == "approved":
        return MessageResponse(
            message="Your account is already approved!",
            success=True
        )
    else:
        return MessageResponse(
            message=f"Account status: {user.approval_status}",
            success=True
        )


@router.post("/login", response_model=LoginResponse)
async def login(
    data: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Login with email/username and password.
    
    Security:
    - 5 failed attempts in 5 minutes: 15 minute block
    - 20 failed attempts in 1 minute: 1 hour block
    """
    client_ip = get_client_ip(request)
    
    # Check brute force protection BEFORE authentication
    is_blocked, reason, remaining = await check_brute_force(client_ip, data.email)
    if is_blocked:
        logger.warning(f"Brute force block triggered for {data.email} from {client_ip}: {reason}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=reason,
            headers={"Retry-After": str(remaining)}
        )
    
    # Attempt authentication
    user = await authenticate_user(db, data.email, data.password)
    
    if not user:
        # Record failed attempt
        await record_login_result(client_ip, data.email, success=False)
        
        # Check if this failure triggers a block
        is_now_blocked, block_reason, _ = await check_brute_force(client_ip, data.email)
        
        if is_now_blocked:
            logger.warning(f"Account locked after failed attempt: {data.email} from {client_ip}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=block_reason
            )
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email/username or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not user.is_active:
        await record_login_result(client_ip, data.email, success=False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated"
        )
    
    # Record successful login
    await record_login_result(client_ip, data.email, success=True)
    
    # SINGLE SESSION ENFORCEMENT: Revoke all existing refresh tokens for this user
    # This ensures only one active session per account - prevents session hijacking
    # Attackers who captured old JWT tokens will be invalidated
    await revoke_all_user_tokens(db, user.id)
    
    # Create tokens
    access_token = create_access_token(str(user.id))
    refresh_token, refresh_expires = create_refresh_token(str(user.id))
    
    # Store refresh token
    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_at=refresh_expires,
        device_info=request.headers.get("User-Agent"),
        ip_address=client_ip
    )
    
    # Update last login
    user.last_login = datetime.utcnow()
    await db.commit()
    
    logger.info(f"Successful login: {user.email} from {client_ip}")
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user)
    )


@router.post("/login/form", response_model=LoginResponse)
async def login_form(
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Login with OAuth2 form (for Swagger UI).
    Same security protections as regular login.
    """
    client_ip = get_client_ip(request) if request else "unknown"
    
    # Check brute force protection
    is_blocked, reason, remaining = await check_brute_force(client_ip, form_data.username)
    if is_blocked:
        logger.warning(f"Brute force block on form login: {form_data.username} from {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=reason,
            headers={"Retry-After": str(remaining)}
        )
    
    # OAuth2 form uses 'username' field but we use email
    user = await authenticate_user(db, form_data.username, form_data.password)
    
    if not user:
        await record_login_result(client_ip, form_data.username, success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not user.is_active:
        await record_login_result(client_ip, form_data.username, success=False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated"
        )
    
    # Record successful login
    await record_login_result(client_ip, form_data.username, success=True)
    
    # SINGLE SESSION ENFORCEMENT: Revoke all existing refresh tokens for this user
    await revoke_all_user_tokens(db, user.id)
    
    # Create tokens
    access_token = create_access_token(str(user.id))
    refresh_token, refresh_expires = create_refresh_token(str(user.id))
    
    # Store refresh token
    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_at=refresh_expires,
        device_info=request.headers.get("User-Agent") if request else None,
        ip_address=client_ip
    )
    
    # Update last login
    user.last_login = datetime.utcnow()
    await db.commit()
    
    logger.info(f"Successful form login: {user.email} from {client_ip}")
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user)
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    data: RefreshRequest,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token using refresh token"""
    # Verify refresh token
    stored_token = await verify_refresh_token(db, data.refresh_token)
    if not stored_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Decode the token to get user ID
    payload = decode_token(data.refresh_token)
    if not payload or payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user_id = payload.get("sub")
    
    # Revoke old refresh token
    await revoke_refresh_token(db, data.refresh_token)
    
    # Create new tokens
    new_access_token = create_access_token(user_id)
    new_refresh_token, refresh_expires = create_refresh_token(user_id)
    
    # Store new refresh token
    await store_refresh_token(
        db=db,
        user_id=UUID(user_id),
        token=new_refresh_token,
        expires_at=refresh_expires,
        device_info=request.headers.get("User-Agent"),
        ip_address=request.client.host if request.client else None
    )
    
    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    data: RefreshRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Logout and immediately invalidate ALL sessions for this user.
    This ensures the JWT token cannot be used even if captured.
    """
    # Revoke ALL refresh tokens for this user - immediately invalidates session
    # This makes has_valid_session() return False, blocking any requests with old JWT
    count = await revoke_all_user_tokens(db, current_user.id)
    return MessageResponse(message=f"Logged out successfully. {count} session(s) terminated.")


@router.post("/logout/all", response_model=MessageResponse)
async def logout_all(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Logout from all devices (revoke all refresh tokens)"""
    count = await revoke_all_user_tokens(db, current_user.id)
    return MessageResponse(message=f"Logged out from {count} device(s)")


@router.get("/me", response_model=UserProfileResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user profile"""
    # Determine role
    if current_user.is_superuser:
        role = "super_admin"
    else:
        role = "user"
    
    # Determine approval status based on is_verified
    if current_user.is_verified:
        approval_status = "approved"
    else:
        approval_status = "pending"
    
    return UserProfileResponse(
        id=current_user.id,
        email=current_user.email,
        username=current_user.username,
        full_name=current_user.full_name,
        company=current_user.company,
        is_active=current_user.is_active,
        is_verified=current_user.is_verified,
        is_superuser=current_user.is_superuser,
        plan=current_user.plan,
        role=role,
        approval_status=approval_status,
        created_at=current_user.created_at,
        last_login=current_user.last_login
    )


@router.put("/me", response_model=UserProfileResponse)
async def update_current_user_profile(
    full_name: Optional[str] = None,
    company: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Update current user profile"""
    if full_name is not None:
        current_user.full_name = full_name
    if company is not None:
        current_user.company = company
    
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(current_user)
    
    # Return updated profile
    return await get_current_user_profile(current_user)


@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    data: PasswordChange,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Change current user's password"""
    # Verify current password
    if not verify_password(data.current_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect"
        )
    
    # Update password
    current_user.hashed_password = hash_password(data.new_password)
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    
    # Revoke all refresh tokens (force re-login on all devices)
    await revoke_all_user_tokens(db, current_user.id)
    
    return MessageResponse(message="Password changed successfully. Please login again.")
