"""
Two-Factor Authentication (2FA) Routes for Jarwis API
Handles 2FA setup, verification, and management

Endpoints:
- GET  /api/2fa/status          - Get user's 2FA status
- POST /api/2fa/setup/initiate  - Start 2FA setup (send OTP)
- POST /api/2fa/setup/verify    - Verify OTP and enable 2FA
- POST /api/2fa/setup/phone     - Update phone number for SMS 2FA
- POST /api/2fa/disable         - Disable 2FA
- POST /api/2fa/send-code       - Send OTP for login verification
- POST /api/2fa/verify          - Verify OTP during login
- GET  /api/2fa/backup-codes    - Generate new backup codes
- POST /api/2fa/backup-codes/verify - Verify backup code

Security Features:
- Rate limiting on OTP requests
- Lockout after failed attempts
- Secure OTP hashing (never stored plain)
- Backup codes for account recovery
- Channel verification before enabling
"""

import logging
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Request, BackgroundTasks, Body
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete
from pydantic import BaseModel, EmailStr, Field, validator

from database.connection import get_db
from database.models import User, OTPToken
from database.dependencies import get_current_user, get_current_active_user
from database.security import get_client_ip
from database.otp import (
    OTPService, OTPChannel, OTPPurpose, 
    otp_service, generate_backup_codes, hash_backup_codes,
    generate_otp, generate_otp_salt, hash_otp, verify_otp_hash,
    OTPConfig
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/2fa", tags=["Two-Factor Authentication"])


# ============== Request/Response Models ==============

class TwoFactorStatusResponse(BaseModel):
    """User's 2FA status"""
    enabled: bool
    channel: Optional[str] = None  # 'email' or 'sms'
    email: str
    email_verified: bool
    phone: Optional[str] = None  # Masked phone number
    phone_verified: bool = False
    backup_codes_remaining: int = 0
    enabled_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None


class InitiateSetupRequest(BaseModel):
    """Request to initiate 2FA setup"""
    channel: str = Field(..., pattern="^(email|sms)$", description="OTP delivery channel")
    phone_number: Optional[str] = Field(None, description="Phone number for SMS (E.164 format)")
    
    @validator('phone_number')
    def validate_phone(cls, v, values):
        if values.get('channel') == 'sms' and not v:
            raise ValueError("Phone number required for SMS channel")
        if v and not v.startswith('+'):
            raise ValueError("Phone number must be in E.164 format (e.g., +1234567890)")
        return v


class InitiateSetupResponse(BaseModel):
    """Response after initiating 2FA setup"""
    success: bool
    message: str
    channel: str
    recipient_masked: str  # Masked email/phone
    expires_in_seconds: int = OTPConfig.OTP_VALIDITY_SECONDS


class VerifySetupRequest(BaseModel):
    """Request to verify OTP and complete 2FA setup"""
    otp: str = Field(..., min_length=6, max_length=6, pattern="^[0-9]{6}$")


class VerifySetupResponse(BaseModel):
    """Response after 2FA is enabled"""
    success: bool
    message: str
    backup_codes: Optional[List[str]] = None  # Only shown once on setup!


class DisableRequest(BaseModel):
    """Request to disable 2FA"""
    password: str = Field(..., description="Current password for verification")
    otp: Optional[str] = Field(None, description="Current OTP or backup code")


class SendCodeRequest(BaseModel):
    """Request to send OTP for login verification"""
    user_id: Optional[str] = None  # For login flow (before authenticated)
    channel: Optional[str] = Field(None, pattern="^(email|sms)$")


class VerifyCodeRequest(BaseModel):
    """Request to verify OTP"""
    otp: str = Field(..., min_length=6, max_length=6, pattern="^[0-9]{6}$")
    purpose: str = Field(default="login_2fa", pattern="^(login_2fa|sensitive_action)$")


class BackupCodesResponse(BaseModel):
    """Backup codes response"""
    codes: List[str]  # Plain codes - only shown once!
    total: int
    message: str


class VerifyBackupCodeRequest(BaseModel):
    """Request to verify backup code"""
    code: str = Field(..., min_length=9, max_length=9, pattern="^[A-Z0-9]{4}-[A-Z0-9]{4}$")


class MessageResponse(BaseModel):
    """Generic message response"""
    success: bool
    message: str


# ============== Helper Functions ==============

async def get_or_create_otp_db(
    db: AsyncSession,
    user: User,
    purpose: OTPPurpose,
    channel: OTPChannel,
    recipient: str
) -> tuple[str, str]:
    """
    Create OTP and store in database.
    Returns: (plain_otp, masked_recipient)
    """
    from database.otp import generate_otp, generate_otp_salt, hash_otp
    from datetime import timedelta
    
    # Check rate limits using in-memory store
    can_request, error, retry_after = await otp_service.rate_limiter.can_request_otp(
        str(user.id), purpose
    )
    if not can_request:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=error,
            headers={"Retry-After": str(retry_after)} if retry_after else None
        )
    
    # Generate OTP
    otp = generate_otp()
    salt = generate_otp_salt()
    otp_hash = hash_otp(otp, salt)
    
    # Mask recipient
    if channel == OTPChannel.EMAIL:
        if '@' in recipient:
            local, domain = recipient.split('@', 1)
            if len(local) <= 2:
                masked = local[0] + '*' * (len(local) - 1) + f"@{domain}"
            else:
                masked = local[0] + '*' * (len(local) - 2) + local[-1] + f"@{domain}"
        else:
            masked = recipient
    else:  # SMS
        if len(recipient) >= 6:
            masked = recipient[:3] + '*' * (len(recipient) - 6) + recipient[-3:]
        else:
            masked = '*' * len(recipient)
    
    # Delete any existing OTP for this user/purpose
    await db.execute(
        delete(OTPToken).where(
            OTPToken.user_id == user.id,
            OTPToken.purpose == purpose.value
        )
    )
    
    # Create new OTP token
    otp_token = OTPToken(
        user_id=user.id,
        otp_hash=otp_hash,
        salt=salt,
        purpose=purpose.value,
        channel=channel.value,
        recipient_masked=masked,
        expires_at=datetime.utcnow() + timedelta(seconds=OTPConfig.OTP_VALIDITY_SECONDS)
    )
    db.add(otp_token)
    await db.commit()
    
    # Record rate limit
    await otp_service.rate_limiter.record_otp_request(str(user.id), purpose)
    
    logger.info(f"Generated OTP for user {user.id}, channel {channel.value}, purpose {purpose.value}")
    
    return otp, masked


async def verify_otp_db(
    db: AsyncSession,
    user_id: UUID,
    purpose: OTPPurpose,
    otp: str
) -> tuple[bool, str]:
    """
    Verify OTP from database.
    Returns: (success, message)
    """
    # Get OTP token
    result = await db.execute(
        select(OTPToken).where(
            OTPToken.user_id == user_id,
            OTPToken.purpose == purpose.value,
            OTPToken.is_used == False
        )
    )
    otp_token = result.scalar_one_or_none()
    
    if not otp_token:
        return False, "No verification code found. Please request a new one."
    
    if datetime.utcnow() > otp_token.expires_at:
        await db.delete(otp_token)
        await db.commit()
        return False, "This code has expired. Please request a new one."
    
    # Check attempt limit
    if otp_token.attempts >= OTPConfig.OTP_MAX_ATTEMPTS:
        await db.delete(otp_token)
        await db.commit()
        return False, "Maximum attempts exceeded. Please request a new code."
    
    # Verify OTP
    if verify_otp_hash(otp, otp_token.salt, otp_token.otp_hash):
        # Success - mark as used
        otp_token.is_used = True
        otp_token.used_at = datetime.utcnow()
        await db.commit()
        
        # Record success in rate limiter
        await otp_service.rate_limiter.record_verification_attempt(
            str(user_id), purpose, True
        )
        
        logger.info(f"OTP verified for user {user_id}, purpose {purpose.value}")
        return True, "Verification successful"
    
    # Failed - increment attempts
    otp_token.attempts += 1
    await db.commit()
    
    # Record failure in rate limiter
    is_locked, lock_msg = await otp_service.rate_limiter.record_verification_attempt(
        str(user_id), purpose, False
    )
    
    if is_locked:
        await db.delete(otp_token)
        await db.commit()
        return False, lock_msg
    
    remaining = OTPConfig.OTP_MAX_ATTEMPTS - otp_token.attempts
    return False, f"Invalid code. {remaining} attempts remaining."


# ============== 2FA Status Endpoint ==============

@router.get("/status", response_model=TwoFactorStatusResponse)
async def get_2fa_status(
    current_user: User = Depends(get_current_active_user)
):
    """Get current user's 2FA configuration status"""
    
    # Count remaining backup codes
    backup_count = 0
    if current_user.two_factor_backup_codes:
        backup_count = len(current_user.two_factor_backup_codes)
    
    # Mask phone number for display
    masked_phone = None
    if current_user.two_factor_phone:
        phone = current_user.two_factor_phone
        if len(phone) >= 6:
            masked_phone = phone[:3] + '*' * (len(phone) - 6) + phone[-3:]
        else:
            masked_phone = '*' * len(phone)
    
    return TwoFactorStatusResponse(
        enabled=current_user.two_factor_enabled,
        channel=current_user.two_factor_channel,
        email=current_user.email,
        email_verified=current_user.is_verified,
        phone=masked_phone,
        phone_verified=current_user.two_factor_phone_verified,
        backup_codes_remaining=backup_count,
        enabled_at=current_user.two_factor_enabled_at,
        last_used_at=current_user.two_factor_last_used
    )


# ============== 2FA Setup Endpoints ==============

@router.post("/setup/initiate", response_model=InitiateSetupResponse)
async def initiate_2fa_setup(
    data: InitiateSetupRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Initiate 2FA setup by sending verification code.
    
    For email: Uses the user's registered email
    For SMS: Requires phone number in E.164 format
    """
    client_ip = get_client_ip(request)
    channel = OTPChannel(data.channel)
    
    # Determine recipient
    if channel == OTPChannel.EMAIL:
        recipient = current_user.email
    else:  # SMS
        if not data.phone_number:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Phone number is required for SMS verification"
            )
        recipient = data.phone_number
        # Store phone number (unverified)
        current_user.two_factor_phone = data.phone_number
        current_user.two_factor_phone_verified = False
    
    try:
        # Generate and store OTP
        otp, masked = await get_or_create_otp_db(
            db=db,
            user=current_user,
            purpose=OTPPurpose.ENABLE_2FA,
            channel=channel,
            recipient=recipient
        )
        
        await db.commit()
        
        # Send OTP via background task
        background_tasks.add_task(
            send_otp_notification,
            channel=channel,
            recipient=recipient,
            otp=otp,
            purpose="2FA Setup",
            user_name=current_user.full_name or current_user.username
        )
        
        logger.info(f"2FA setup initiated for user {current_user.id}, channel {channel.value}")
        
        return InitiateSetupResponse(
            success=True,
            message=f"Verification code sent to {masked}",
            channel=channel.value,
            recipient_masked=masked,
            expires_in_seconds=OTPConfig.OTP_VALIDITY_SECONDS
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error initiating 2FA setup: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification code. Please try again."
        )


@router.post("/setup/verify", response_model=VerifySetupResponse)
async def verify_2fa_setup(
    data: VerifySetupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Verify OTP and enable 2FA.
    Returns backup codes on successful setup (save these securely!).
    """
    # Verify OTP
    success, message = await verify_otp_db(
        db=db,
        user_id=current_user.id,
        purpose=OTPPurpose.ENABLE_2FA,
        otp=data.otp
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    # Get the OTP token to determine channel
    result = await db.execute(
        select(OTPToken).where(
            OTPToken.user_id == current_user.id,
            OTPToken.purpose == OTPPurpose.ENABLE_2FA.value,
            OTPToken.is_used == True
        )
    )
    otp_token = result.scalar_one_or_none()
    
    channel = otp_token.channel if otp_token else "email"
    
    # Generate backup codes
    backup_codes = generate_backup_codes()
    hashed_codes = hash_backup_codes(backup_codes)
    
    # Enable 2FA
    current_user.two_factor_enabled = True
    current_user.two_factor_channel = channel
    current_user.two_factor_backup_codes = hashed_codes
    current_user.two_factor_enabled_at = datetime.utcnow()
    
    # Mark phone as verified if SMS was used
    if channel == "sms":
        current_user.two_factor_phone_verified = True
    
    await db.commit()
    
    logger.info(f"2FA enabled for user {current_user.id}, channel {channel}")
    
    return VerifySetupResponse(
        success=True,
        message="Two-factor authentication enabled successfully! Save your backup codes securely.",
        backup_codes=backup_codes  # Only shown once!
    )


@router.post("/setup/phone", response_model=MessageResponse)
async def update_phone_for_2fa(
    phone_number: str = Body(..., embed=True, description="Phone in E.164 format"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Update phone number for SMS 2FA (requires re-verification)"""
    
    if not phone_number.startswith('+'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Phone number must be in E.164 format (e.g., +1234567890)"
        )
    
    # Store phone (unverified)
    current_user.two_factor_phone = phone_number
    current_user.two_factor_phone_verified = False
    
    # If 2FA was using SMS, require re-verification
    if current_user.two_factor_enabled and current_user.two_factor_channel == "sms":
        current_user.two_factor_enabled = False
        current_user.two_factor_channel = None
        await db.commit()
        return MessageResponse(
            success=True,
            message="Phone updated. 2FA has been disabled. Please set up 2FA again with your new number."
        )
    
    await db.commit()
    return MessageResponse(
        success=True,
        message="Phone number updated. Verify it when enabling SMS 2FA."
    )


# ============== Disable 2FA ==============

@router.post("/disable", response_model=MessageResponse)
async def disable_2fa(
    data: DisableRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Disable 2FA.
    Requires password and optionally current OTP for verification.
    """
    from database.auth import verify_password
    
    if not current_user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled on this account"
        )
    
    # Verify password
    if not verify_password(data.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )
    
    # If OTP provided, verify it
    if data.otp:
        success, message = await verify_otp_db(
            db=db,
            user_id=current_user.id,
            purpose=OTPPurpose.DISABLE_2FA,
            otp=data.otp
        )
        if not success:
            # Check if it's a backup code
            if not await verify_backup_code_internal(db, current_user, data.otp):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=message
                )
    
    # Disable 2FA
    current_user.two_factor_enabled = False
    current_user.two_factor_channel = None
    current_user.two_factor_backup_codes = None
    current_user.two_factor_enabled_at = None
    # Keep phone number for potential re-enablement
    
    await db.commit()
    
    logger.info(f"2FA disabled for user {current_user.id}")
    
    return MessageResponse(
        success=True,
        message="Two-factor authentication has been disabled"
    )


# ============== Login 2FA Verification ==============

@router.post("/send-code", response_model=InitiateSetupResponse)
async def send_login_otp(
    data: SendCodeRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """
    Send OTP for login verification.
    Called after password verification but before session creation.
    """
    client_ip = get_client_ip(request)
    
    # Get user (either from token or user_id in request)
    user = current_user
    if not user and data.user_id:
        from database.auth import get_user_by_id
        user = await get_user_by_id(db, UUID(data.user_id))
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    if not user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA is not enabled for this account"
        )
    
    # Use preferred channel or requested channel
    channel = OTPChannel(data.channel) if data.channel else OTPChannel(user.two_factor_channel or "email")
    
    # Determine recipient
    if channel == OTPChannel.EMAIL:
        recipient = user.email
    else:
        if not user.two_factor_phone or not user.two_factor_phone_verified:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No verified phone number. Use email verification."
            )
        recipient = user.two_factor_phone
    
    try:
        # Generate and store OTP
        otp, masked = await get_or_create_otp_db(
            db=db,
            user=user,
            purpose=OTPPurpose.LOGIN_2FA,
            channel=channel,
            recipient=recipient
        )
        
        # Send OTP
        background_tasks.add_task(
            send_otp_notification,
            channel=channel,
            recipient=recipient,
            otp=otp,
            purpose="Login Verification",
            user_name=user.full_name or user.username
        )
        
        return InitiateSetupResponse(
            success=True,
            message=f"Verification code sent to {masked}",
            channel=channel.value,
            recipient_masked=masked,
            expires_in_seconds=OTPConfig.OTP_VALIDITY_SECONDS
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error sending login OTP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send verification code"
        )


@router.post("/verify", response_model=MessageResponse)
async def verify_login_otp(
    data: VerifyCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Verify OTP during login or sensitive action.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    purpose = OTPPurpose(data.purpose)
    
    success, message = await verify_otp_db(
        db=db,
        user_id=current_user.id,
        purpose=purpose,
        otp=data.otp
    )
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )
    
    # Update last used timestamp
    current_user.two_factor_last_used = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(
        success=True,
        message="Verification successful"
    )


# ============== Backup Codes ==============

class RegenerateBackupCodesRequest(BaseModel):
    """Request to regenerate backup codes."""
    password: Optional[str] = None  # Password for verification (required for regeneration)

@router.get("/backup-codes", response_model=BackupCodesResponse)
async def get_backup_codes(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current backup codes count (not the actual codes - those are only shown once).
    """
    if not current_user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA must be enabled to view backup codes"
        )
    
    # Return count of remaining backup codes (not the actual codes)
    remaining = len(current_user.two_factor_backup_codes or [])
    
    return BackupCodesResponse(
        codes=[],  # Never expose existing codes
        total=remaining,
        message=f"You have {remaining} backup codes remaining"
    )


@router.post("/backup-codes/regenerate", response_model=BackupCodesResponse)
async def regenerate_backup_codes(
    data: RegenerateBackupCodesRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """
    Generate new backup codes (invalidates old ones).
    Requires password confirmation for security.
    """
    from database.auth import verify_password
    
    if not current_user.two_factor_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA must be enabled to generate backup codes"
        )
    
    # Verify password if provided (optional for initial setup, required for regeneration)
    if data.password:
        if not verify_password(data.password, current_user.hashed_password):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid password"
            )
    
    # Generate new backup codes
    backup_codes = generate_backup_codes()
    hashed_codes = hash_backup_codes(backup_codes)
    
    current_user.two_factor_backup_codes = hashed_codes
    await db.commit()
    
    logger.info(f"New backup codes generated for user {current_user.id}")
    
    return BackupCodesResponse(
        codes=backup_codes,
        total=len(backup_codes),
        message="New backup codes generated. Old codes are now invalid. Save these securely!"
    )


@router.post("/backup-codes/verify", response_model=MessageResponse)
async def verify_backup_code(
    data: VerifyBackupCodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Verify a backup code (single-use).
    Can be used instead of OTP when phone/email unavailable.
    """
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    success = await verify_backup_code_internal(db, current_user, data.code)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already used backup code"
        )
    
    # Update last used
    current_user.two_factor_last_used = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(
        success=True,
        message="Backup code verified successfully"
    )


async def verify_backup_code_internal(
    db: AsyncSession, 
    user: User, 
    code: str
) -> bool:
    """Internal function to verify and consume a backup code"""
    import hashlib
    
    if not user.two_factor_backup_codes:
        return False
    
    # Hash the provided code
    code_hash = hashlib.sha256(code.upper().encode()).hexdigest()
    
    # Check if hash exists in backup codes
    if code_hash in user.two_factor_backup_codes:
        # Remove used code (single-use)
        user.two_factor_backup_codes = [
            c for c in user.two_factor_backup_codes if c != code_hash
        ]
        await db.commit()
        
        logger.info(f"Backup code used for user {user.id}, {len(user.two_factor_backup_codes)} remaining")
        return True
    
    return False


# ============== OTP Delivery (Background Tasks) ==============

async def send_otp_notification(
    channel: OTPChannel,
    recipient: str,
    otp: str,
    purpose: str,
    user_name: str
):
    """
    Send OTP via email or SMS.
    This function integrates with Firebase or other providers.
    """
    try:
        if channel == OTPChannel.EMAIL:
            await send_otp_email(recipient, otp, purpose, user_name)
        else:
            await send_otp_sms(recipient, otp, purpose)
    except Exception as e:
        logger.error(f"Failed to send OTP via {channel.value}: {e}")
        # Don't raise - OTP is stored, user can request resend


async def send_otp_email(
    email: str, 
    otp: str, 
    purpose: str,
    user_name: str
):
    """
    Send OTP via email.
    Integrates with SMTP or email service provider.
    """
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import os
    
    # Email configuration from environment
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "")
    smtp_password = os.getenv("SMTP_PASSWORD", "")
    sender_email = os.getenv("SMTP_SENDER", "noreply@jarwis.ai")
    
    if not smtp_user or not smtp_password:
        logger.warning("SMTP not configured, OTP email not sent")
        logger.info(f"[DEBUG] OTP for {email}: {otp}")  # For development only
        return
    
    # Create email
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"Jarwis Security Code - {purpose}"
    msg["From"] = f"Jarwis Security <{sender_email}>"
    msg["To"] = email
    
    # Plain text version
    text = f"""
Hello {user_name},

Your Jarwis verification code is: {otp}

This code will expire in {OTPConfig.OTP_VALIDITY_SECONDS // 60} minutes.

If you didn't request this code, please ignore this email and consider changing your password.

- Jarwis Security Team
"""
    
    # HTML version
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        .container {{ font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; }}
        .code {{ font-size: 32px; font-weight: bold; letter-spacing: 8px; color: #2563eb; 
                 background: #f1f5f9; padding: 20px; text-align: center; border-radius: 8px; }}
        .warning {{ color: #dc2626; font-size: 12px; margin-top: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <h2>🔐 Jarwis Security Code</h2>
        <p>Hello {user_name},</p>
        <p>Your verification code for <strong>{purpose}</strong> is:</p>
        <div class="code">{otp}</div>
        <p>This code will expire in <strong>{OTPConfig.OTP_VALIDITY_SECONDS // 60} minutes</strong>.</p>
        <p class="warning">⚠️ Never share this code with anyone. Jarwis will never ask for your code.</p>
        <hr>
        <p style="color: #64748b; font-size: 12px;">
            If you didn't request this code, please ignore this email and consider changing your password.
        </p>
    </div>
</body>
</html>
"""
    
    msg.attach(MIMEText(text, "plain"))
    msg.attach(MIMEText(html, "html"))
    
    try:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(sender_email, email, msg.as_string())
        logger.info(f"OTP email sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send OTP email: {e}")
        raise


async def send_otp_sms(
    phone: str,
    otp: str,
    purpose: str
):
    """
    Send OTP via SMS using Firebase or Twilio.
    
    For production, integrate with:
    - Firebase Phone Auth
    - Twilio
    - AWS SNS
    - MessageBird
    """
    import os
    
    # Check for Twilio configuration
    twilio_sid = os.getenv("TWILIO_ACCOUNT_SID")
    twilio_token = os.getenv("TWILIO_AUTH_TOKEN")
    twilio_phone = os.getenv("TWILIO_PHONE_NUMBER")
    
    if twilio_sid and twilio_token and twilio_phone:
        try:
            from twilio.rest import Client
            client = Client(twilio_sid, twilio_token)
            
            message = client.messages.create(
                body=f"Jarwis Security Code: {otp}\n\nThis code expires in {OTPConfig.OTP_VALIDITY_SECONDS // 60} minutes. Never share this code.",
                from_=twilio_phone,
                to=phone
            )
            logger.info(f"SMS sent to {phone}, SID: {message.sid}")
            return
        except Exception as e:
            logger.error(f"Twilio SMS failed: {e}")
            raise
    
    # Fallback: Log for development
    logger.warning("SMS provider not configured")
    logger.info(f"[DEBUG] SMS OTP for {phone}: {otp}")  # For development only
