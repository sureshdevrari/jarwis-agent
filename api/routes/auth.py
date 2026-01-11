"""
Authentication Routes for Jarwis API
Handles login, signup, token refresh, and user management

Security Features:
- HttpOnly cookie-based JWT tokens (XSS protection)
- Brute force protection: 5 failed attempts in 5 mins = 15 min block
- Hard block: 20 failed attempts in 1 min = 1 hour block
- Input validation and sanitization
- Rate limiting per IP
"""

from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Request, Response
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
from database.cookie_auth import set_auth_cookies, clear_auth_cookies, get_token_from_cookie

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
    """Login response with user info (or 2FA required)"""
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int = 0
    user: Optional[UserResponse] = None
    # 2FA fields
    two_factor_required: bool = False
    two_factor_token: Optional[str] = None
    two_factor_method: Optional[str] = None
    message: Optional[str] = None


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
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Login with email/username and password.
    Sets HttpOnly cookies for secure token storage.
    
    Security:
    - HttpOnly cookies prevent XSS token theft
    - 5 failed attempts in 5 minutes: 15 minute block
    - 20 failed attempts in 1 minute: 1 hour block
    - If 2FA is enabled, returns two_factor_required flag
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
    
    # Check if 2FA is enabled for this user
    if user.two_factor_enabled:
        # Record that password was verified but 2FA pending
        await record_login_result(client_ip, data.email, success=False, reason="2fa_pending")
        
        # Create a short-lived 2FA session token (5 minutes)
        two_factor_token = create_access_token(
            str(user.id), 
            expires_minutes=5,
            additional_claims={"purpose": "2fa_verification"}
        )
        
        logger.info(f"2FA required for: {user.email} from {client_ip}")
        
        return {
            "two_factor_required": True,
            "two_factor_token": two_factor_token,
            "two_factor_method": user.two_factor_method or "email",
            "message": "Two-factor authentication required",
            "user": None,
            "access_token": None,
            "refresh_token": None,
            "token_type": "bearer",
            "expires_in": 0
        }
    
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
    
    # Record login history and register session
    record_login_history(str(user.id), request, success=True)
    register_session(str(user.id), request, refresh_expires)
    
    logger.info(f"Successful login: {user.email} from {client_ip}")
    
    # Set HttpOnly cookies for secure token storage (XSS protection)
    set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_expires_days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user)
    )


class TwoFactorLoginRequest(BaseModel):
    """Request to complete 2FA login"""
    two_factor_token: str
    code: str
    use_backup_code: bool = False


@router.post("/login/2fa", response_model=LoginResponse)
async def login_with_2fa(
    data: TwoFactorLoginRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db)
):
    """
    Complete login with 2FA code after initial password verification.
    Uses the temporary 2FA token from the initial login response.
    """
    client_ip = get_client_ip(request)
    
    try:
        # Verify the 2FA token
        payload = jwt.decode(
            data.two_factor_token,
            auth_settings.SECRET_KEY,
            algorithms=[auth_settings.ALGORITHM]
        )
        
        # Validate it's a 2FA verification token
        if payload.get("purpose") != "2fa_verification":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA token"
            )
        
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA token"
            )
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="2FA token expired. Please login again."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid 2FA token"
        )
    
    # Get user
    from sqlalchemy import select
    from database.models import User
    
    stmt = select(User).where(User.id == int(user_id))
    result = await db.execute(stmt)
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    # Verify 2FA code (using OTP system)
    from database.otp import verify_and_delete_otp
    
    if data.use_backup_code:
        # Verify backup code
        import hashlib
        code_hash = hashlib.sha256(data.code.encode()).hexdigest()
        backup_codes = user.backup_codes or []
        
        if code_hash not in backup_codes:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid backup code"
            )
        
        # Remove used backup code
        backup_codes.remove(code_hash)
        user.backup_codes = backup_codes
        await db.commit()
        
        logger.info(f"2FA login completed with backup code: {user.email}")
    else:
        # Verify OTP code
        is_valid = await verify_and_delete_otp(db, str(user.id), data.code)
        
        if not is_valid:
            await record_login_result(client_ip, user.email, success=False, reason="invalid_2fa")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired verification code"
            )
    
    # Record successful login
    await record_login_result(client_ip, user.email, success=True)
    
    # Revoke existing tokens and create new ones
    await revoke_all_user_tokens(db, user.id)
    
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
    
    # Record login history
    record_login_history(str(user.id), request, success=True, method="2fa")
    register_session(str(user.id), request, refresh_expires)
    
    logger.info(f"2FA login completed: {user.email} from {client_ip}")
    
    # Set HttpOnly cookies
    set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_expires_days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user)
    )


@router.post("/login/form", response_model=LoginResponse)
async def login_form(
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    request: Request = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Login with OAuth2 form (for Swagger UI).
    Same security protections as regular login.
    Sets HttpOnly cookies for secure token storage.
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
    
    # Set HttpOnly cookies for secure token storage (XSS protection)
    set_auth_cookies(
        response=response,
        access_token=access_token,
        refresh_token=refresh_token,
        access_expires_minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_expires_days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserResponse.model_validate(user)
    )


@router.post("/refresh", response_model=Token)
async def refresh_token_endpoint(
    request: Request,
    response: Response,
    data: RefreshRequest = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Refresh access token using refresh token.
    Reads refresh token from HttpOnly cookie or request body.
    """
    # Get refresh token from cookie (preferred) or request body (fallback)
    refresh_token_value = get_token_from_cookie(request, "refresh")
    if not refresh_token_value and data:
        refresh_token_value = data.refresh_token
    
    if not refresh_token_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token provided"
        )
    
    # Verify refresh token
    stored_token = await verify_refresh_token(db, refresh_token_value)
    if not stored_token:
        # Clear invalid cookies
        clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Decode the token to get user ID
    payload = decode_token(refresh_token_value)
    if not payload or payload.get("type") != "refresh":
        clear_auth_cookies(response)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )
    
    user_id = payload.get("sub")
    
    # Revoke old refresh token
    await revoke_refresh_token(db, refresh_token_value)
    
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
    
    # Set new HttpOnly cookies
    set_auth_cookies(
        response=response,
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        access_expires_minutes=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        refresh_expires_days=auth_settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    
    return Token(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
        expires_in=auth_settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(
    response: Response,
    data: RefreshRequest = None,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Logout and immediately invalidate ALL sessions for this user.
    Clears HttpOnly cookies and revokes all tokens.
    This ensures the JWT token cannot be used even if captured.
    """
    # Revoke ALL refresh tokens for this user - immediately invalidates session
    # This makes has_valid_session() return False, blocking any requests with old JWT
    count = await revoke_all_user_tokens(db, current_user.id)
    
    # Clear HttpOnly cookies
    clear_auth_cookies(response)
    
    return MessageResponse(message=f"Logged out successfully. {count} session(s) terminated.")


@router.post("/logout/all", response_model=MessageResponse)
async def logout_all(
    response: Response,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """Logout from all devices (revoke all refresh tokens and clear cookies)"""
    count = await revoke_all_user_tokens(db, current_user.id)
    
    # Clear HttpOnly cookies
    clear_auth_cookies(response)
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
    
    # Use actual approval_status from database, fallback to computed value
    approval_status = getattr(current_user, 'approval_status', None)
    if not approval_status:
        # Fallback for legacy users without approval_status field
        approval_status = "approved" if current_user.is_verified else "pending"
    
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


# ============== Session & Login History Endpoints ==============

# In-memory storage for login history (in production, use database table)
login_history_store: dict = {}
active_sessions_store: dict = {}


@router.get("/login-history")
async def get_login_history(
    limit: int = 10,
    current_user: User = Depends(get_current_active_user)
):
    """
    Get login history for the current user.
    Returns recent login attempts with device/location info.
    """
    user_id = str(current_user.id)
    history = login_history_store.get(user_id, [])
    
    # Sort by date descending and limit
    sorted_history = sorted(history, key=lambda x: x.get('timestamp', ''), reverse=True)[:limit]
    
    return {
        'success': True,
        'data': {
            'history': sorted_history,
            'total': len(history)
        }
    }


@router.get("/sessions")
async def get_active_sessions(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get active sessions for the current user.
    Shows devices where user is currently logged in.
    """
    user_id = str(current_user.id)
    sessions = active_sessions_store.get(user_id, [])
    
    # Filter to only active sessions
    now = datetime.utcnow()
    active = [s for s in sessions if s.get('expires_at', now) > now]
    
    return {
        'success': True,
        'data': {
            'sessions': active,
            'count': len(active)
        }
    }


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Revoke a specific session (logout from that device)"""
    user_id = str(current_user.id)
    sessions = active_sessions_store.get(user_id, [])
    
    # Find and remove the session
    active_sessions_store[user_id] = [s for s in sessions if s.get('session_id') != session_id]
    
    return {
        'success': True,
        'message': 'Session revoked successfully'
    }


def record_login_history(user_id: str, request: Request, success: bool = True, method: str = "password"):
    """Record a login attempt to history (called from login endpoint)
    
    Args:
        user_id: The user ID
        request: The request object
        success: Whether login was successful
        method: Login method used ('password', '2fa', 'oauth')
    """
    if user_id not in login_history_store:
        login_history_store[user_id] = []
    
    # Parse user agent for device info
    user_agent = request.headers.get('user-agent', 'Unknown')
    device = 'Unknown Device'
    if 'Windows' in user_agent:
        device = 'Windows'
    elif 'Mac' in user_agent:
        device = 'Mac'
    elif 'iPhone' in user_agent:
        device = 'iPhone'
    elif 'Android' in user_agent:
        device = 'Android'
    elif 'Linux' in user_agent:
        device = 'Linux'
    
    # Extract browser
    browser = 'Unknown Browser'
    if 'Chrome' in user_agent and 'Edg' not in user_agent:
        browser = 'Chrome'
    elif 'Firefox' in user_agent:
        browser = 'Firefox'
    elif 'Safari' in user_agent and 'Chrome' not in user_agent:
        browser = 'Safari'
    elif 'Edg' in user_agent:
        browser = 'Edge'
    
    login_entry = {
        'timestamp': datetime.utcnow().isoformat(),
        'ip_address': get_client_ip(request),
        'device': f"{browser} on {device}",
        'location': 'Unknown',  # Would need GeoIP service
        'success': success,
        'method': method,
    }
    
    login_history_store[user_id].append(login_entry)
    
    # Keep only last 50 entries
    if len(login_history_store[user_id]) > 50:
        login_history_store[user_id] = login_history_store[user_id][-50:]


def register_session(user_id: str, request: Request, token_expires: datetime):
    """Register a new active session"""
    import uuid
    
    if user_id not in active_sessions_store:
        active_sessions_store[user_id] = []
    
    user_agent = request.headers.get('user-agent', 'Unknown')
    
    session = {
        'session_id': str(uuid.uuid4()),
        'created_at': datetime.utcnow().isoformat(),
        'expires_at': token_expires,
        'ip_address': get_client_ip(request),
        'user_agent': user_agent[:100],  # Truncate long user agents
        'is_current': True,
    }
    
    # Mark other sessions as not current
    for s in active_sessions_store[user_id]:
        s['is_current'] = False
    
    active_sessions_store[user_id].append(session)
    
    # Keep only last 10 sessions
    if len(active_sessions_store[user_id]) > 10:
        active_sessions_store[user_id] = active_sessions_store[user_id][-10:]
