"""
OTP (One-Time Password) Service for Two-Factor Authentication
Implements secure OTP generation, storage, and verification

Security Features:
- TOTP-like OTP with configurable validity window
- Rate limiting: Max 5 OTP requests per 10 minutes per user
- OTP lockout: 5 failed attempts = 15 minute lockout
- Cryptographically secure random OTP generation
- OTP hashing with salt (never store plain OTP)
- Single-use OTPs (auto-invalidate after verification)
- Automatic expiry and cleanup
"""

import secrets
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, Tuple, List
from enum import Enum
from collections import defaultdict
import asyncio

from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ============== Configuration ==============

class OTPConfig:
    """OTP security configuration"""
    # OTP settings
    OTP_LENGTH: int = 6  # 6-digit code
    OTP_VALIDITY_SECONDS: int = 300  # 5 minutes
    OTP_MAX_ATTEMPTS: int = 5  # Failed attempts before lockout
    OTP_LOCKOUT_SECONDS: int = 900  # 15 minutes lockout
    
    # Rate limiting
    MAX_OTP_REQUESTS_PER_WINDOW: int = 5  # Max OTP requests
    OTP_REQUEST_WINDOW_SECONDS: int = 600  # 10 minute window
    
    # Resend cooldown
    OTP_RESEND_COOLDOWN_SECONDS: int = 60  # 1 minute between resends
    
    # Backup codes
    BACKUP_CODE_COUNT: int = 10
    BACKUP_CODE_LENGTH: int = 8


class OTPChannel(str, Enum):
    """OTP delivery channels"""
    EMAIL = "email"
    SMS = "sms"


class OTPPurpose(str, Enum):
    """Purpose of the OTP"""
    LOGIN_2FA = "login_2fa"
    ENABLE_2FA = "enable_2fa"
    DISABLE_2FA = "disable_2fa"
    CHANGE_PHONE = "change_phone"
    CHANGE_EMAIL = "change_email"
    SENSITIVE_ACTION = "sensitive_action"


# ============== In-Memory Rate Limiting Store ==============

@dataclass
class OTPAttempt:
    """Record of an OTP verification attempt"""
    timestamp: float
    success: bool


@dataclass
class OTPRateLimitRecord:
    """Rate limit tracking per user"""
    request_timestamps: List[float] = field(default_factory=list)
    failed_attempts: List[float] = field(default_factory=list)
    lockout_until: Optional[float] = None
    last_sent: Optional[float] = None


class OTPRateLimitStore:
    """In-memory store for OTP rate limiting"""
    
    def __init__(self):
        self._records: Dict[str, OTPRateLimitRecord] = defaultdict(OTPRateLimitRecord)
        self._lock = asyncio.Lock()
    
    def _get_user_key(self, user_id: str, purpose: OTPPurpose) -> str:
        """Generate unique key for user + purpose"""
        return f"{user_id}:{purpose.value}"
    
    async def can_request_otp(
        self, 
        user_id: str, 
        purpose: OTPPurpose
    ) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Check if user can request a new OTP.
        Returns: (allowed, error_reason, retry_after_seconds)
        """
        async with self._lock:
            key = self._get_user_key(user_id, purpose)
            record = self._records[key]
            now = datetime.now().timestamp()
            
            # Check lockout
            if record.lockout_until and now < record.lockout_until:
                remaining = int(record.lockout_until - now)
                return False, "Too many failed attempts. Account locked.", remaining
            
            # Check resend cooldown
            if record.last_sent:
                cooldown_ends = record.last_sent + OTPConfig.OTP_RESEND_COOLDOWN_SECONDS
                if now < cooldown_ends:
                    remaining = int(cooldown_ends - now)
                    return False, f"Please wait before requesting another code", remaining
            
            # Check rate limit
            window_start = now - OTPConfig.OTP_REQUEST_WINDOW_SECONDS
            record.request_timestamps = [
                ts for ts in record.request_timestamps 
                if ts > window_start
            ]
            
            if len(record.request_timestamps) >= OTPConfig.MAX_OTP_REQUESTS_PER_WINDOW:
                oldest = min(record.request_timestamps)
                retry_after = int(oldest + OTPConfig.OTP_REQUEST_WINDOW_SECONDS - now)
                return False, "Too many OTP requests. Please try again later.", retry_after
            
            return True, None, None
    
    async def record_otp_request(self, user_id: str, purpose: OTPPurpose):
        """Record that an OTP was requested"""
        async with self._lock:
            key = self._get_user_key(user_id, purpose)
            record = self._records[key]
            now = datetime.now().timestamp()
            record.request_timestamps.append(now)
            record.last_sent = now
    
    async def record_verification_attempt(
        self, 
        user_id: str, 
        purpose: OTPPurpose, 
        success: bool
    ) -> Tuple[bool, Optional[str]]:
        """
        Record OTP verification attempt.
        Returns: (is_locked_out, lock_reason)
        """
        async with self._lock:
            key = self._get_user_key(user_id, purpose)
            record = self._records[key]
            now = datetime.now().timestamp()
            
            if success:
                # Clear failed attempts on success
                record.failed_attempts = []
                record.lockout_until = None
                return False, None
            
            # Record failed attempt
            record.failed_attempts.append(now)
            
            # Clean old attempts (outside lockout window)
            lockout_window = now - OTPConfig.OTP_LOCKOUT_SECONDS
            record.failed_attempts = [
                ts for ts in record.failed_attempts 
                if ts > lockout_window
            ]
            
            # Check if should lock out
            if len(record.failed_attempts) >= OTPConfig.OTP_MAX_ATTEMPTS:
                record.lockout_until = now + OTPConfig.OTP_LOCKOUT_SECONDS
                logger.warning(f"OTP lockout triggered for user {user_id}")
                return True, f"Too many failed attempts. Locked for {OTPConfig.OTP_LOCKOUT_SECONDS // 60} minutes."
            
            remaining = OTPConfig.OTP_MAX_ATTEMPTS - len(record.failed_attempts)
            return False, f"{remaining} attempts remaining"
    
    async def clear_user(self, user_id: str, purpose: OTPPurpose):
        """Clear rate limit data for a user"""
        async with self._lock:
            key = self._get_user_key(user_id, purpose)
            if key in self._records:
                del self._records[key]


# Global rate limit store
otp_rate_limit_store = OTPRateLimitStore()


# ============== OTP Generation & Hashing ==============

def generate_otp(length: int = OTPConfig.OTP_LENGTH) -> str:
    """
    Generate cryptographically secure OTP.
    Uses secrets module for CSPRNG.
    """
    # Generate numeric OTP
    otp = ''.join(secrets.choice('0123456789') for _ in range(length))
    return otp


def generate_otp_salt() -> str:
    """Generate a random salt for OTP hashing"""
    return secrets.token_hex(16)


def hash_otp(otp: str, salt: str) -> str:
    """
    Hash OTP with salt using SHA-256.
    Never store plain OTP in database.
    """
    combined = f"{salt}:{otp}"
    return hashlib.sha256(combined.encode()).hexdigest()


def verify_otp_hash(otp: str, salt: str, stored_hash: str) -> bool:
    """Verify OTP against stored hash"""
    computed_hash = hash_otp(otp, salt)
    # Use constant-time comparison to prevent timing attacks
    return secrets.compare_digest(computed_hash, stored_hash)


def generate_backup_codes(
    count: int = OTPConfig.BACKUP_CODE_COUNT,
    length: int = OTPConfig.BACKUP_CODE_LENGTH
) -> List[str]:
    """
    Generate backup recovery codes for 2FA.
    Format: XXXX-XXXX (alphanumeric)
    """
    codes = []
    chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # Exclude confusing chars (0, O, I, 1)
    
    for _ in range(count):
        code_part1 = ''.join(secrets.choice(chars) for _ in range(length // 2))
        code_part2 = ''.join(secrets.choice(chars) for _ in range(length // 2))
        codes.append(f"{code_part1}-{code_part2}")
    
    return codes


def hash_backup_codes(codes: List[str]) -> List[str]:
    """Hash backup codes for storage"""
    return [hashlib.sha256(code.encode()).hexdigest() for code in codes]


# ============== OTP Data Models ==============

@dataclass
class OTPRecord:
    """OTP record for verification"""
    user_id: str
    purpose: OTPPurpose
    channel: OTPChannel
    otp_hash: str
    salt: str
    recipient: str  # Email or phone (masked for display)
    created_at: datetime
    expires_at: datetime
    attempts: int = 0
    is_used: bool = False
    
    def is_expired(self) -> bool:
        """Check if OTP has expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if OTP is still valid for verification"""
        return not self.is_used and not self.is_expired()


class TwoFactorSettings(BaseModel):
    """User's 2FA settings"""
    enabled: bool = False
    preferred_channel: OTPChannel = OTPChannel.EMAIL
    email_verified: bool = False
    phone_verified: bool = False
    phone_number: Optional[str] = None  # E.164 format
    backup_codes_generated: bool = False
    backup_codes_remaining: int = 0
    last_used_at: Optional[datetime] = None
    enabled_at: Optional[datetime] = None


# ============== OTP In-Memory Store (Replace with DB in production) ==============

class OTPStore:
    """
    In-memory OTP storage.
    In production, use database table with proper indexing.
    """
    
    def __init__(self):
        self._otps: Dict[str, OTPRecord] = {}
        self._lock = asyncio.Lock()
    
    def _get_key(self, user_id: str, purpose: OTPPurpose) -> str:
        """Generate unique key"""
        return f"{user_id}:{purpose.value}"
    
    async def store_otp(self, record: OTPRecord):
        """Store OTP record (replaces any existing for same user+purpose)"""
        async with self._lock:
            key = self._get_key(record.user_id, record.purpose)
            # Invalidate any existing OTP for this user+purpose
            self._otps[key] = record
            logger.debug(f"Stored OTP for user {record.user_id}, purpose {record.purpose}")
    
    async def get_otp(self, user_id: str, purpose: OTPPurpose) -> Optional[OTPRecord]:
        """Get OTP record"""
        async with self._lock:
            key = self._get_key(user_id, purpose)
            return self._otps.get(key)
    
    async def mark_used(self, user_id: str, purpose: OTPPurpose):
        """Mark OTP as used"""
        async with self._lock:
            key = self._get_key(user_id, purpose)
            if key in self._otps:
                self._otps[key].is_used = True
    
    async def increment_attempts(self, user_id: str, purpose: OTPPurpose) -> int:
        """Increment attempt count and return new count"""
        async with self._lock:
            key = self._get_key(user_id, purpose)
            if key in self._otps:
                self._otps[key].attempts += 1
                return self._otps[key].attempts
            return 0
    
    async def delete_otp(self, user_id: str, purpose: OTPPurpose):
        """Delete OTP record"""
        async with self._lock:
            key = self._get_key(user_id, purpose)
            if key in self._otps:
                del self._otps[key]
    
    async def cleanup_expired(self):
        """Remove expired OTPs"""
        async with self._lock:
            now = datetime.utcnow()
            expired_keys = [
                key for key, record in self._otps.items()
                if record.expires_at < now
            ]
            for key in expired_keys:
                del self._otps[key]
            if expired_keys:
                logger.debug(f"Cleaned up {len(expired_keys)} expired OTPs")


# Global OTP store
otp_store = OTPStore()


# ============== OTP Service ==============

class OTPService:
    """
    Main OTP service for 2FA operations.
    Coordinates OTP generation, storage, and verification.
    """
    
    def __init__(
        self,
        store: OTPStore = otp_store,
        rate_limiter: OTPRateLimitStore = otp_rate_limit_store
    ):
        self.store = store
        self.rate_limiter = rate_limiter
    
    async def generate_and_store_otp(
        self,
        user_id: str,
        purpose: OTPPurpose,
        channel: OTPChannel,
        recipient: str  # Email or phone
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Generate and store a new OTP.
        
        Returns: (success, otp_or_error, masked_recipient)
        - On success: (True, plain_otp, masked_recipient)
        - On failure: (False, error_message, None)
        """
        # Check rate limits
        can_request, error, retry_after = await self.rate_limiter.can_request_otp(
            user_id, purpose
        )
        if not can_request:
            return False, error, None
        
        # Generate OTP
        otp = generate_otp()
        salt = generate_otp_salt()
        otp_hash = hash_otp(otp, salt)
        
        # Mask recipient for display
        masked = self._mask_recipient(recipient, channel)
        
        # Create record
        now = datetime.utcnow()
        record = OTPRecord(
            user_id=user_id,
            purpose=purpose,
            channel=channel,
            otp_hash=otp_hash,
            salt=salt,
            recipient=masked,
            created_at=now,
            expires_at=now + timedelta(seconds=OTPConfig.OTP_VALIDITY_SECONDS)
        )
        
        # Store
        await self.store.store_otp(record)
        await self.rate_limiter.record_otp_request(user_id, purpose)
        
        logger.info(f"Generated OTP for user {user_id}, channel {channel}, purpose {purpose}")
        
        return True, otp, masked
    
    async def verify_otp(
        self,
        user_id: str,
        purpose: OTPPurpose,
        otp: str
    ) -> Tuple[bool, str]:
        """
        Verify an OTP.
        
        Returns: (success, message)
        """
        # Get stored OTP
        record = await self.store.get_otp(user_id, purpose)
        
        if not record:
            return False, "No verification code found. Please request a new one."
        
        if record.is_used:
            return False, "This code has already been used. Please request a new one."
        
        if record.is_expired():
            return False, "This code has expired. Please request a new one."
        
        # Verify the OTP
        if verify_otp_hash(otp, record.salt, record.otp_hash):
            # Success - mark as used
            await self.store.mark_used(user_id, purpose)
            await self.rate_limiter.record_verification_attempt(user_id, purpose, True)
            logger.info(f"OTP verified successfully for user {user_id}, purpose {purpose}")
            return True, "Verification successful"
        
        # Failed verification
        attempts = await self.store.increment_attempts(user_id, purpose)
        is_locked, lock_msg = await self.rate_limiter.record_verification_attempt(
            user_id, purpose, False
        )
        
        if is_locked:
            await self.store.delete_otp(user_id, purpose)
            return False, lock_msg
        
        remaining = OTPConfig.OTP_MAX_ATTEMPTS - attempts
        if remaining <= 0:
            await self.store.delete_otp(user_id, purpose)
            return False, "Maximum attempts exceeded. Please request a new code."
        
        return False, f"Invalid code. {remaining} attempts remaining."
    
    async def revoke_otp(self, user_id: str, purpose: OTPPurpose):
        """Revoke any existing OTP for user"""
        await self.store.delete_otp(user_id, purpose)
        logger.info(f"Revoked OTP for user {user_id}, purpose {purpose}")
    
    def _mask_recipient(self, recipient: str, channel: OTPChannel) -> str:
        """Mask email or phone for display"""
        if channel == OTPChannel.EMAIL:
            if '@' in recipient:
                local, domain = recipient.split('@', 1)
                if len(local) <= 2:
                    masked_local = local[0] + '*' * (len(local) - 1)
                else:
                    masked_local = local[0] + '*' * (len(local) - 2) + local[-1]
                return f"{masked_local}@{domain}"
            return recipient
        
        elif channel == OTPChannel.SMS:
            # Phone: +1234567890 -> +1***890
            if len(recipient) >= 4:
                return recipient[:3] + '*' * (len(recipient) - 6) + recipient[-3:]
            return '*' * len(recipient)
        
        return recipient


# Global OTP service instance
otp_service = OTPService()
