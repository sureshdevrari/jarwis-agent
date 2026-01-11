"""
Authentication Response Schemas

All auth-related request/response models.
"""

from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from uuid import UUID


# ==================== User ====================
class UserResponse(BaseModel):
    """User profile response"""
    id: UUID
    email: str
    username: str
    full_name: Optional[str] = None
    company: Optional[str] = None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    plan: str
    role: str  # user, admin, super_admin
    approval_status: str  # pending, approved, rejected
    created_at: datetime
    last_login: Optional[datetime] = None
    
    class Config:
        from_attributes = True


# ==================== Tokens ====================
class TokenResponse(BaseModel):
    """Token pair response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900  # 15 minutes in seconds


class LoginResponse(BaseModel):
    """Login success response"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = 900
    user: UserResponse
    requires_2fa: bool = False


class TwoFactorRequiredResponse(BaseModel):
    """Response when 2FA verification is required"""
    requires_2fa: bool = True
    two_factor_token: str
    channel: str  # 'email' or 'sms'
    recipient_masked: str  # Masked email/phone
    expires_in: int = 300  # 5 minutes
    message: str = "Two-factor authentication required"


# ==================== Requests ====================
class RegisterRequest(BaseModel):
    """Registration request"""
    email: EmailStr
    username: str = Field(..., min_length=3, max_length=100)
    password: str = Field(..., min_length=8, max_length=100)
    full_name: Optional[str] = None
    company: Optional[str] = None


class LoginRequest(BaseModel):
    """Login request"""
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    """Token refresh request"""
    refresh_token: str


class PasswordChangeRequest(BaseModel):
    """Password change request"""
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=100)


class TwoFactorVerifyRequest(BaseModel):
    """2FA verification request"""
    two_factor_token: str
    code: str = Field(..., min_length=6, max_length=6)
