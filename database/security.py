"""
Security Module for Jarwis API
Implements brute force protection, rate limiting, and IP blocking

Security Rules:
- 5 failed login attempts within 5 minutes: Block for 15 minutes (soft block)
- 20 failed login attempts within 1 minute: Block for 1 hour (hard block)
- Rate limiting on all endpoints based on subscription tier
- Input sanitization and validation
- File upload security checks
"""

import asyncio
import hashlib
import logging
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Set
from functools import wraps

from fastapi import HTTPException, Request, status
from pydantic import BaseModel

logger = logging.getLogger(__name__)


# ============== Configuration ==============

@dataclass
class SecurityConfig:
    """Security configuration constants"""
    # Brute force protection thresholds
    SOFT_BLOCK_ATTEMPTS: int = 10  # Failed attempts for soft block (increased from 5)
    SOFT_BLOCK_WINDOW_SECONDS: int = 300  # 5 minutes window
    SOFT_BLOCK_DURATION_SECONDS: int = 600  # 10 minutes block (reduced from 15)
    
    HARD_BLOCK_ATTEMPTS: int = 30  # Failed attempts for hard block (increased from 20)
    HARD_BLOCK_WINDOW_SECONDS: int = 60  # 1 minute window
    HARD_BLOCK_DURATION_SECONDS: int = 1800  # 30 minutes block (reduced from 1 hour)
    
    # Rate limiting (requests per minute per tier)
    RATE_LIMITS: Dict[str, int] = field(default_factory=lambda: {
        "anonymous": 30,     # 30 requests per minute for anonymous
        "free": 60,          # 60 requests per minute for free tier
        "individual": 120,   # 120 requests per minute 
        "professional": 300, # 300 requests per minute
        "enterprise": 1000,  # 1000 requests per minute
    })
    
    # File upload security
    MAX_FILE_SIZE_MB: int = 10
    ALLOWED_FILE_EXTENSIONS: Set[str] = field(default_factory=lambda: {
        '.txt', '.log', '.json', '.xml', '.html', '.har', '.md', '.csv',
        '.pdf', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'
    })
    DANGEROUS_FILE_EXTENSIONS: Set[str] = field(default_factory=lambda: {
        '.exe', '.bat', '.cmd', '.com', '.msi', '.vbs', '.vbe', '.js',
        '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.ps1', '.psc1', '.scr',
        '.reg', '.jar', '.py', '.sh', '.bash', '.php', '.asp', '.aspx',
        '.dll', '.so', '.dylib'
    })
    
    # Password policy
    MIN_PASSWORD_LENGTH: int = 8
    MAX_PASSWORD_LENGTH: int = 128
    REQUIRE_UPPERCASE: bool = True
    REQUIRE_LOWERCASE: bool = True
    REQUIRE_DIGIT: bool = True
    REQUIRE_SPECIAL: bool = False


CONFIG = SecurityConfig()


# ============== Data Structures ==============

@dataclass
class LoginAttempt:
    """Record of a login attempt"""
    timestamp: float
    ip_address: str
    email: str
    success: bool


@dataclass
class BlockRecord:
    """Record of a blocked IP/email"""
    blocked_at: float
    unblock_at: float
    reason: str
    attempts: int


@dataclass
class RateLimitRecord:
    """Rate limit tracking per IP"""
    requests: List[float] = field(default_factory=list)
    

# ============== In-Memory Storage ==============
# In production, use Redis for distributed rate limiting

class SecurityStore:
    """Thread-safe in-memory security storage"""
    
    def __init__(self):
        self._login_attempts: Dict[str, List[LoginAttempt]] = defaultdict(list)
        self._ip_blocks: Dict[str, BlockRecord] = {}
        self._email_blocks: Dict[str, BlockRecord] = {}
        self._rate_limits: Dict[str, RateLimitRecord] = defaultdict(RateLimitRecord)
        self._lock = asyncio.Lock()
    
    def _cleanup_old_attempts(self, key: str, max_age_seconds: int = 3600):
        """Remove attempts older than max_age"""
        now = time.time()
        cutoff = now - max_age_seconds
        self._login_attempts[key] = [
            a for a in self._login_attempts[key] 
            if a.timestamp > cutoff
        ]
    
    def _cleanup_rate_limits(self, key: str, window_seconds: int = 60):
        """Remove rate limit records older than window"""
        now = time.time()
        cutoff = now - window_seconds
        if key in self._rate_limits:
            self._rate_limits[key].requests = [
                t for t in self._rate_limits[key].requests
                if t > cutoff
            ]
    
    async def record_login_attempt(
        self, 
        ip_address: str, 
        email: str, 
        success: bool
    ) -> None:
        """Record a login attempt"""
        async with self._lock:
            attempt = LoginAttempt(
                timestamp=time.time(),
                ip_address=ip_address,
                email=email.lower(),
                success=success
            )
            
            # Store by both IP and email
            ip_key = f"ip:{ip_address}"
            email_key = f"email:{email.lower()}"
            
            self._login_attempts[ip_key].append(attempt)
            self._login_attempts[email_key].append(attempt)
            
            # Cleanup old attempts
            self._cleanup_old_attempts(ip_key)
            self._cleanup_old_attempts(email_key)
            
            if success:
                # On successful login, clear failed attempts for this IP/email combo
                logger.info(f"Successful login from {ip_address} for {email}")
            else:
                logger.warning(f"Failed login attempt from {ip_address} for {email}")
    
    async def get_failed_attempts_count(
        self, 
        identifier: str, 
        window_seconds: int
    ) -> int:
        """Get count of failed login attempts within time window"""
        async with self._lock:
            now = time.time()
            cutoff = now - window_seconds
            
            attempts = self._login_attempts.get(identifier, [])
            failed_count = sum(
                1 for a in attempts 
                if not a.success and a.timestamp > cutoff
            )
            return failed_count
    
    async def block_identifier(
        self, 
        identifier: str, 
        duration_seconds: int, 
        reason: str,
        attempts: int
    ) -> None:
        """Block an IP or email"""
        async with self._lock:
            now = time.time()
            
            if identifier.startswith("ip:"):
                self._ip_blocks[identifier] = BlockRecord(
                    blocked_at=now,
                    unblock_at=now + duration_seconds,
                    reason=reason,
                    attempts=attempts
                )
            else:
                self._email_blocks[identifier] = BlockRecord(
                    blocked_at=now,
                    unblock_at=now + duration_seconds,
                    reason=reason,
                    attempts=attempts
                )
            
            logger.warning(f"Blocked {identifier} for {duration_seconds}s: {reason}")
    
    async def is_blocked(self, ip_address: str, email: str = None) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Check if IP or email is blocked.
        Returns: (is_blocked, reason, seconds_remaining)
        """
        async with self._lock:
            now = time.time()
            
            # Check IP block
            ip_key = f"ip:{ip_address}"
            if ip_key in self._ip_blocks:
                block = self._ip_blocks[ip_key]
                if now < block.unblock_at:
                    remaining = int(block.unblock_at - now)
                    return True, block.reason, remaining
                else:
                    # Block expired, remove it
                    del self._ip_blocks[ip_key]
            
            # Check email block
            if email:
                email_key = f"email:{email.lower()}"
                if email_key in self._email_blocks:
                    block = self._email_blocks[email_key]
                    if now < block.unblock_at:
                        remaining = int(block.unblock_at - now)
                        return True, block.reason, remaining
                    else:
                        del self._email_blocks[email_key]
            
            return False, None, None
    
    async def check_rate_limit(
        self, 
        ip_address: str, 
        tier: str = "anonymous"
    ) -> Tuple[bool, int, int]:
        """
        Check rate limit for an IP.
        Returns: (is_allowed, current_count, limit)
        """
        async with self._lock:
            now = time.time()
            key = f"rate:{ip_address}"
            
            self._cleanup_rate_limits(key)
            
            limit = CONFIG.RATE_LIMITS.get(tier, CONFIG.RATE_LIMITS["anonymous"])
            current = len(self._rate_limits[key].requests)
            
            if current >= limit:
                return False, current, limit
            
            # Record this request
            self._rate_limits[key].requests.append(now)
            return True, current + 1, limit
    
    async def clear_blocks_for_email(self, email: str) -> None:
        """Clear all blocks for an email (e.g., after password reset)"""
        async with self._lock:
            email_key = f"email:{email.lower()}"
            if email_key in self._email_blocks:
                del self._email_blocks[email_key]
            if email_key in self._login_attempts:
                del self._login_attempts[email_key]


# Global security store instance
security_store = SecurityStore()


# ============== Security Functions ==============

async def check_brute_force(
    ip_address: str, 
    email: str
) -> Tuple[bool, Optional[str], Optional[int]]:
    """
    Check if login should be blocked due to brute force protection.
    Returns: (is_blocked, reason, seconds_remaining)
    """
    # First check existing blocks
    is_blocked, reason, remaining = await security_store.is_blocked(ip_address, email)
    if is_blocked:
        return True, reason, remaining
    
    ip_key = f"ip:{ip_address}"
    email_key = f"email:{email.lower()}"
    
    # Check hard block threshold (20 attempts in 1 minute)
    ip_hard_failures = await security_store.get_failed_attempts_count(
        ip_key, CONFIG.HARD_BLOCK_WINDOW_SECONDS
    )
    
    if ip_hard_failures >= CONFIG.HARD_BLOCK_ATTEMPTS:
        await security_store.block_identifier(
            ip_key,
            CONFIG.HARD_BLOCK_DURATION_SECONDS,
            f"Too many login attempts ({ip_hard_failures} in 1 minute)",
            ip_hard_failures
        )
        return True, "Too many login attempts. Please try again in 1 hour.", CONFIG.HARD_BLOCK_DURATION_SECONDS
    
    # Check soft block threshold (5 attempts in 5 minutes)
    ip_soft_failures = await security_store.get_failed_attempts_count(
        ip_key, CONFIG.SOFT_BLOCK_WINDOW_SECONDS
    )
    
    if ip_soft_failures >= CONFIG.SOFT_BLOCK_ATTEMPTS:
        await security_store.block_identifier(
            ip_key,
            CONFIG.SOFT_BLOCK_DURATION_SECONDS,
            f"Multiple failed login attempts ({ip_soft_failures} in 5 minutes)",
            ip_soft_failures
        )
        return True, "Too many failed attempts. Please try again in 15 minutes.", CONFIG.SOFT_BLOCK_DURATION_SECONDS
    
    # Also check by email for account-specific protection
    email_failures = await security_store.get_failed_attempts_count(
        email_key, CONFIG.SOFT_BLOCK_WINDOW_SECONDS
    )
    
    if email_failures >= CONFIG.SOFT_BLOCK_ATTEMPTS:
        await security_store.block_identifier(
            email_key,
            CONFIG.SOFT_BLOCK_DURATION_SECONDS,
            f"Multiple failed login attempts for this account ({email_failures})",
            email_failures
        )
        return True, "Account temporarily locked due to multiple failed attempts. Please try again in 15 minutes or reset your password.", CONFIG.SOFT_BLOCK_DURATION_SECONDS
    
    return False, None, None


async def record_login_result(
    ip_address: str, 
    email: str, 
    success: bool,
    reason: str = None
) -> None:
    """Record a login attempt result
    
    Args:
        ip_address: The client IP address
        email: The email/username attempted
        success: Whether login succeeded
        reason: Optional reason for failure (e.g., '2fa_pending', 'invalid_2fa')
    """
    await security_store.record_login_attempt(ip_address, email, success)


# ============== Input Validation ==============

class InputValidator:
    """Input validation and sanitization utilities"""
    
    # SQL injection patterns
    SQL_PATTERNS = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE|TRUNCATE)\b)",
        r"(--|#|/\*|\*/)",
        r"(\bOR\b.*=.*)",
        r"(\bAND\b.*=.*)",
        r"(;.*\b(SELECT|INSERT|UPDATE|DELETE|DROP)\b)",
        r"(\b(EXEC|EXECUTE)\b\s*\()",
        r"(xp_|sp_)",
    ]
    
    # XSS patterns
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript:",
        r"on\w+\s*=",
        r"<iframe[^>]*>",
        r"<object[^>]*>",
        r"<embed[^>]*>",
        r"<svg[^>]*onload",
    ]
    
    # Command injection patterns
    CMD_PATTERNS = [
        r"[;&|`$]",
        r"\b(cat|ls|rm|mv|cp|wget|curl|bash|sh|nc|netcat)\b",
        r"\.\./",  # Path traversal
    ]
    
    @staticmethod
    def sanitize_string(value: str, max_length: int = 1000) -> str:
        """Sanitize a string input"""
        if not value:
            return value
        
        # Truncate to max length
        value = value[:max_length]
        
        # Remove null bytes
        value = value.replace('\x00', '')
        
        # Normalize whitespace
        value = ' '.join(value.split())
        
        return value
    
    @staticmethod
    def check_sql_injection(value: str) -> bool:
        """Check if value contains SQL injection patterns"""
        if not value:
            return False
        
        value_upper = value.upper()
        for pattern in InputValidator.SQL_PATTERNS:
            if re.search(pattern, value_upper, re.IGNORECASE):
                logger.warning(f"SQL injection pattern detected: {pattern}")
                return True
        return False
    
    @staticmethod
    def check_xss(value: str) -> bool:
        """Check if value contains XSS patterns"""
        if not value:
            return False
        
        for pattern in InputValidator.XSS_PATTERNS:
            if re.search(pattern, value, re.IGNORECASE):
                logger.warning(f"XSS pattern detected: {pattern}")
                return True
        return False
    
    @staticmethod
    def check_command_injection(value: str) -> bool:
        """Check if value contains command injection patterns"""
        if not value:
            return False
        
        for pattern in InputValidator.CMD_PATTERNS:
            if re.search(pattern, value):
                logger.warning(f"Command injection pattern detected: {pattern}")
                return True
        return False
    
    @staticmethod
    def validate_email(email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_username(username: str) -> Tuple[bool, Optional[str]]:
        """Validate username format"""
        if not username:
            return False, "Username is required"
        
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        
        if len(username) > 100:
            return False, "Username must be less than 100 characters"
        
        # Only allow alphanumeric, underscore, hyphen
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscores, and hyphens"
        
        # Check for injection attempts
        if InputValidator.check_sql_injection(username):
            return False, "Invalid characters in username"
        
        return True, None
    
    @staticmethod
    def validate_password(password: str) -> Tuple[bool, Optional[str]]:
        """Validate password strength"""
        if not password:
            return False, "Password is required"
        
        if len(password) < CONFIG.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {CONFIG.MIN_PASSWORD_LENGTH} characters"
        
        if len(password) > CONFIG.MAX_PASSWORD_LENGTH:
            return False, f"Password must be less than {CONFIG.MAX_PASSWORD_LENGTH} characters"
        
        if CONFIG.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        if CONFIG.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        if CONFIG.REQUIRE_DIGIT and not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
        
        if CONFIG.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        # Check for common weak passwords
        weak_passwords = {
            'password', 'password1', 'password123', '12345678', 'qwerty123',
            'letmein', 'welcome', 'admin123', 'login123'
        }
        if password.lower() in weak_passwords:
            return False, "Password is too common. Please choose a stronger password."
        
        return True, None
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL format and safety"""
        if not url:
            return False, "URL is required"
        
        # Basic URL pattern
        url_pattern = r'^https?://[a-zA-Z0-9][a-zA-Z0-9\-\.]*[a-zA-Z0-9]\.[a-zA-Z]{2,}(:[0-9]+)?(/.*)?$'
        if not re.match(url_pattern, url):
            return False, "Invalid URL format"
        
        # Check for localhost/internal IPs (SSRF prevention)
        internal_patterns = [
            r'localhost',
            r'127\.0\.0\.',
            r'192\.168\.',
            r'10\.',
            r'172\.(1[6-9]|2[0-9]|3[01])\.',
            r'0\.0\.0\.0',
            r'\[::1\]',
            r'169\.254\.',  # Link-local
        ]
        
        for pattern in internal_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return False, "Scanning internal/private addresses is not allowed"
        
        return True, None


# ============== File Upload Security ==============

class FileUploadValidator:
    """File upload security validation"""
    
    # Magic bytes for file type verification
    MAGIC_BYTES = {
        b'\x89PNG\r\n\x1a\n': 'png',
        b'\xff\xd8\xff': 'jpeg',
        b'GIF87a': 'gif',
        b'GIF89a': 'gif',
        b'%PDF': 'pdf',
        b'PK\x03\x04': 'zip',  # Also used by docx, xlsx, etc.
    }
    
    @staticmethod
    def validate_file_extension(filename: str) -> Tuple[bool, Optional[str]]:
        """Validate file extension"""
        if not filename:
            return False, "Filename is required"
        
        # Get extension
        ext = ''
        if '.' in filename:
            ext = '.' + filename.rsplit('.', 1)[-1].lower()
        
        if not ext:
            return False, "File must have an extension"
        
        if ext in CONFIG.DANGEROUS_FILE_EXTENSIONS:
            return False, f"File type '{ext}' is not allowed for security reasons"
        
        if ext not in CONFIG.ALLOWED_FILE_EXTENSIONS:
            return False, f"File type '{ext}' is not supported"
        
        return True, None
    
    @staticmethod
    def validate_file_size(size_bytes: int) -> Tuple[bool, Optional[str]]:
        """Validate file size"""
        max_bytes = CONFIG.MAX_FILE_SIZE_MB * 1024 * 1024
        
        if size_bytes > max_bytes:
            return False, f"File size exceeds maximum of {CONFIG.MAX_FILE_SIZE_MB}MB"
        
        if size_bytes == 0:
            return False, "File is empty"
        
        return True, None
    
    @staticmethod
    def validate_file_content(content: bytes, filename: str) -> Tuple[bool, Optional[str]]:
        """Validate file content for malicious patterns"""
        # Check for null bytes in text files
        text_extensions = {'.txt', '.log', '.json', '.xml', '.html', '.md', '.csv'}
        ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        
        if ext in text_extensions:
            if b'\x00' in content:
                return False, "File contains invalid null bytes"
            
            # Check for embedded scripts in text files
            content_str = content.decode('utf-8', errors='ignore')
            if InputValidator.check_xss(content_str):
                logger.warning(f"XSS content detected in uploaded file: {filename}")
                # Don't block, but log it - the content might be legitimate test data
        
        # For binary files, verify magic bytes
        if ext in {'.png', '.jpg', '.jpeg', '.gif', '.pdf'}:
            valid_magic = False
            for magic, expected_type in FileUploadValidator.MAGIC_BYTES.items():
                if content.startswith(magic):
                    valid_magic = True
                    break
            
            # Warn but don't block - could be legitimate edge cases
            if not valid_magic:
                logger.warning(f"File {filename} has unexpected magic bytes")
        
        return True, None
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize filename to prevent path traversal"""
        if not filename:
            return "unnamed_file"
        
        # Remove path separators
        filename = filename.replace('/', '_').replace('\\', '_')
        
        # Remove null bytes
        filename = filename.replace('\x00', '')
        
        # Remove control characters
        filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
        
        # Limit length
        if len(filename) > 255:
            ext = ''
            if '.' in filename:
                ext = filename.rsplit('.', 1)[-1]
            filename = filename[:200] + '.' + ext
        
        return filename


# ============== HTTP Security Headers ==============

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store, no-cache, must-revalidate, proxy-revalidate",
    "Pragma": "no-cache",
}


def get_security_headers() -> Dict[str, str]:
    """Get security headers to add to responses"""
    return SECURITY_HEADERS.copy()


# ============== Helper Functions ==============

def get_client_ip(request: Request) -> str:
    """Get client IP address from request, handling proxies"""
    # Check for forwarded headers (when behind proxy/load balancer)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Get the first IP in the chain (original client)
        return forwarded.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct client IP
    if request.client:
        return request.client.host
    
    return "unknown"


def hash_sensitive_data(data: str) -> str:
    """Hash sensitive data for logging"""
    return hashlib.sha256(data.encode()).hexdigest()[:16]
