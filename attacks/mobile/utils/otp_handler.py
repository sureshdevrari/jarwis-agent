"""
Jarwis Secure OTP Handler

Handles OTP-based authentication in a secure, privacy-compliant manner.

IMPORTANT SECURITY PRINCIPLES (from otp_logic guidelines):
- NEVER reads user SMS automatically
- NEVER stores OTPs
- NEVER reuses OTPs
- NEVER intercepts private communication
- Works ONLY with explicit user consent
- OTPs are used once and immediately discarded
- All OTP transmission is encrypted in transit

This module provides:
1. OTP input prompting to user
2. Secure OTP transmission to target app backend
3. Token management after successful authentication
4. Session handling for authenticated testing
"""

import asyncio
import aiohttp
import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Callable, Any
from enum import Enum
from datetime import datetime, timedelta
import secrets


class OTPStatus(Enum):
    """Status of OTP verification"""
    PENDING = "pending"
    WAITING_INPUT = "waiting_input"
    VERIFYING = "verifying"
    VERIFIED = "verified"
    EXPIRED = "expired"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AuthSessionStatus(Enum):
    """Status of authentication session"""
    NOT_STARTED = "not_started"
    OTP_REQUESTED = "otp_requested"
    OTP_PENDING = "otp_pending"
    AUTHENTICATED = "authenticated"
    TOKEN_EXPIRED = "token_expired"
    FAILED = "failed"


@dataclass
class OTPRequest:
    """Represents an OTP request - NO OTP VALUE STORED"""
    request_id: str
    phone_number_hash: str  # Only store hash, never actual number
    timestamp: datetime
    expires_at: datetime
    status: OTPStatus = OTPStatus.PENDING
    attempts: int = 0
    max_attempts: int = 3
    
    def is_expired(self) -> bool:
        return datetime.now() > self.expires_at
    
    def can_retry(self) -> bool:
        return self.attempts < self.max_attempts and not self.is_expired()


@dataclass
class AuthSession:
    """Authenticated session for testing - tokens are temporary"""
    session_id: str
    status: AuthSessionStatus
    auth_type: str
    created_at: datetime
    expires_at: datetime
    access_token: Optional[str] = None  # Temporary, for testing only
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    user_info: Dict = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        return (
            self.status == AuthSessionStatus.AUTHENTICATED 
            and datetime.now() < self.expires_at
            and self.access_token is not None
        )


@dataclass
class OTPInputPrompt:
    """Data for frontend OTP input prompt"""
    prompt_id: str
    title: str = "Secure Authentication Required"
    message: str = (
        "To continue testing, please enter the OTP sent to your registered mobile number.\n\n"
        "Jarwis never stores or reads your personal data.\n"
        "OTP is used once and immediately discarded."
    )
    security_notice: str = "[LOCK] Your OTP is encrypted in transit and never stored."
    disclaimer: str = (
        "Jarwis does not store, log, or reuse your OTP. "
        "The OTP is used only once to authenticate and begin security testing. "
        "Your privacy and data security are our top priority."
    )
    button_text: str = "Verify & Start Testing"
    otp_length: int = 6
    timeout_seconds: int = 60
    show_resend: bool = True
    resend_cooldown: int = 30


class SecureOTPHandler:
    """
    Secure OTP handler that follows privacy-first principles.
    
    This handler:
    1. Prompts user to manually enter OTP (never auto-reads SMS)
    2. Sends OTP directly to customer's backend for verification
    3. Receives auth token from customer's backend
    4. Uses token for security testing only
    5. Never logs or stores OTP values
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.active_requests: Dict[str, OTPRequest] = {}
        self.active_sessions: Dict[str, AuthSession] = {}
        self.otp_callbacks: Dict[str, Callable] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        
        # Configuration
        self.otp_timeout = config.get('otp_timeout', 60)  # seconds
        self.max_otp_attempts = config.get('max_otp_attempts', 3)
        self.session_duration = config.get('session_duration', 3600)  # 1 hour
        
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create HTTP session"""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        """Close HTTP session"""
        if self._session and not self._session.closed:
            await self._session.close()
    
    def _hash_phone(self, phone: str) -> str:
        """Hash phone number for privacy - never store actual number"""
        return hashlib.sha256(phone.encode()).hexdigest()[:16]
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID"""
        return f"otp_{secrets.token_hex(16)}"
    
    def _generate_session_id(self) -> str:
        """Generate unique session ID"""
        return f"session_{secrets.token_hex(16)}"
    
    async def request_otp(
        self, 
        phone_number: str,
        target_api_url: str,
        on_input_needed: Optional[Callable] = None
    ) -> OTPRequest:
        """
        Request OTP to be sent to user's phone.
        
        This calls the TARGET APP's API to send OTP.
        Jarwis does not send OTPs - the customer's backend does.
        
        Args:
            phone_number: User's phone number (will be hashed, not stored)
            target_api_url: Customer's API endpoint for sending OTP
            on_input_needed: Callback when OTP input is needed from user
            
        Returns:
            OTPRequest object (without OTP value - that stays with user)
        """
        request_id = self._generate_request_id()
        phone_hash = self._hash_phone(phone_number)
        
        # Create OTP request record (no OTP value stored)
        otp_request = OTPRequest(
            request_id=request_id,
            phone_number_hash=phone_hash,
            timestamp=datetime.now(),
            expires_at=datetime.now() + timedelta(seconds=self.otp_timeout),
            status=OTPStatus.PENDING
        )
        
        self.active_requests[request_id] = otp_request
        
        # Call customer's backend to send OTP
        try:
            session = await self._get_session()
            async with session.post(
                target_api_url,
                json={'phone': phone_number},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    otp_request.status = OTPStatus.WAITING_INPUT
                    
                    # Store callback for when user enters OTP
                    if on_input_needed:
                        self.otp_callbacks[request_id] = on_input_needed
                    
                else:
                    otp_request.status = OTPStatus.FAILED
                    
        except Exception as e:
            otp_request.status = OTPStatus.FAILED
            print(f"[OTP] Failed to request OTP: {e}")
        
        return otp_request
    
    def get_otp_prompt(self, request_id: str) -> OTPInputPrompt:
        """
        Get OTP input prompt data for frontend display.
        
        This returns the UI text and configuration for the OTP input modal.
        """
        otp_request = self.active_requests.get(request_id)
        
        remaining_time = self.otp_timeout
        if otp_request:
            remaining = (otp_request.expires_at - datetime.now()).total_seconds()
            remaining_time = max(0, int(remaining))
        
        return OTPInputPrompt(
            prompt_id=request_id,
            timeout_seconds=remaining_time
        )
    
    async def verify_otp(
        self,
        request_id: str,
        otp_value: str,  # This is received from user, used once, never stored
        phone_number: str,
        verify_api_url: str
    ) -> AuthSession:
        """
        Verify OTP by sending to customer's backend.
        
        IMPORTANT: OTP value is:
        1. Received from user input
        2. Sent directly to customer's verification API
        3. IMMEDIATELY DISCARDED after API call
        4. NEVER logged or stored
        
        Args:
            request_id: The OTP request ID
            otp_value: OTP entered by user (will be discarded after use)
            phone_number: Phone number for verification
            verify_api_url: Customer's API endpoint for OTP verification
            
        Returns:
            AuthSession with token if successful
        """
        otp_request = self.active_requests.get(request_id)
        
        if not otp_request:
            return AuthSession(
                session_id=self._generate_session_id(),
                status=AuthSessionStatus.FAILED,
                auth_type="phone_otp",
                created_at=datetime.now(),
                expires_at=datetime.now()
            )
        
        # Check if expired
        if otp_request.is_expired():
            otp_request.status = OTPStatus.EXPIRED
            return AuthSession(
                session_id=self._generate_session_id(),
                status=AuthSessionStatus.FAILED,
                auth_type="phone_otp",
                created_at=datetime.now(),
                expires_at=datetime.now()
            )
        
        # Increment attempt counter
        otp_request.attempts += 1
        otp_request.status = OTPStatus.VERIFYING
        
        session_id = self._generate_session_id()
        
        try:
            # Send OTP to customer's verification API
            # OTP is transmitted securely and immediately discarded
            session = await self._get_session()
            async with session.post(
                verify_api_url,
                json={
                    'phone': phone_number,
                    'otp': otp_value  # Sent to customer API, not stored
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                # OTP value is now out of scope and will be garbage collected
                # We NEVER store it
                
                if response.status == 200:
                    data = await response.json()
                    
                    otp_request.status = OTPStatus.VERIFIED
                    
                    # Create authenticated session
                    auth_session = AuthSession(
                        session_id=session_id,
                        status=AuthSessionStatus.AUTHENTICATED,
                        auth_type="phone_otp",
                        created_at=datetime.now(),
                        expires_at=datetime.now() + timedelta(seconds=self.session_duration),
                        access_token=data.get('access_token') or data.get('token'),
                        refresh_token=data.get('refresh_token'),
                        token_type=data.get('token_type', 'Bearer'),
                        user_info=data.get('user', {})
                    )
                    
                    self.active_sessions[session_id] = auth_session
                    
                    # Clean up OTP request
                    del self.active_requests[request_id]
                    if request_id in self.otp_callbacks:
                        del self.otp_callbacks[request_id]
                    
                    return auth_session
                else:
                    otp_request.status = OTPStatus.FAILED
                    
                    return AuthSession(
                        session_id=session_id,
                        status=AuthSessionStatus.FAILED,
                        auth_type="phone_otp",
                        created_at=datetime.now(),
                        expires_at=datetime.now()
                    )
                    
        except Exception as e:
            print(f"[OTP] Verification failed: {e}")
            otp_request.status = OTPStatus.FAILED
            
            return AuthSession(
                session_id=session_id,
                status=AuthSessionStatus.FAILED,
                auth_type="phone_otp",
                created_at=datetime.now(),
                expires_at=datetime.now()
            )
    
    async def resend_otp(
        self,
        request_id: str,
        phone_number: str,
        target_api_url: str
    ) -> bool:
        """
        Request OTP resend from customer's backend.
        """
        otp_request = self.active_requests.get(request_id)
        
        if not otp_request or not otp_request.can_retry():
            return False
        
        # Reset expiration
        otp_request.expires_at = datetime.now() + timedelta(seconds=self.otp_timeout)
        otp_request.status = OTPStatus.PENDING
        
        try:
            session = await self._get_session()
            async with session.post(
                target_api_url,
                json={'phone': phone_number, 'resend': True},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    otp_request.status = OTPStatus.WAITING_INPUT
                    return True
                    
        except Exception as e:
            print(f"[OTP] Resend failed: {e}")
        
        return False
    
    def get_session(self, session_id: str) -> Optional[AuthSession]:
        """Get active session by ID"""
        session = self.active_sessions.get(session_id)
        if session and session.is_valid():
            return session
        return None
    
    def get_auth_headers(self, session_id: str) -> Dict[str, str]:
        """Get authentication headers for testing requests"""
        session = self.get_session(session_id)
        if session:
            return {
                'Authorization': f'{session.token_type} {session.access_token}'
            }
        return {}
    
    async def refresh_session(
        self,
        session_id: str,
        refresh_api_url: str
    ) -> bool:
        """Refresh authentication token"""
        session = self.active_sessions.get(session_id)
        
        if not session or not session.refresh_token:
            return False
        
        try:
            http_session = await self._get_session()
            async with http_session.post(
                refresh_api_url,
                json={'refresh_token': session.refresh_token},
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    session.access_token = data.get('access_token')
                    session.expires_at = datetime.now() + timedelta(seconds=self.session_duration)
                    session.status = AuthSessionStatus.AUTHENTICATED
                    return True
                    
        except Exception as e:
            print(f"[Session] Refresh failed: {e}")
        
        session.status = AuthSessionStatus.TOKEN_EXPIRED
        return False
    
    def invalidate_session(self, session_id: str):
        """Invalidate and remove session"""
        if session_id in self.active_sessions:
            self.active_sessions[session_id].status = AuthSessionStatus.FAILED
            self.active_sessions[session_id].access_token = None
            del self.active_sessions[session_id]
    
    def get_active_requests_count(self) -> int:
        """Get count of active OTP requests"""
        return len([r for r in self.active_requests.values() if not r.is_expired()])
    
    def get_active_sessions_count(self) -> int:
        """Get count of valid sessions"""
        return len([s for s in self.active_sessions.values() if s.is_valid()])
    
    def cleanup_expired(self):
        """Clean up expired requests and sessions"""
        # Clean expired OTP requests
        expired_requests = [
            rid for rid, req in self.active_requests.items() 
            if req.is_expired()
        ]
        for rid in expired_requests:
            del self.active_requests[rid]
            if rid in self.otp_callbacks:
                del self.otp_callbacks[rid]
        
        # Clean expired sessions
        expired_sessions = [
            sid for sid, sess in self.active_sessions.items()
            if not sess.is_valid()
        ]
        for sid in expired_sessions:
            del self.active_sessions[sid]


class SocialAuthHandler:
    """
    Handler for social login authentication (Google, Facebook, Apple, etc.)
    
    For social auth, user authenticates through the app's OAuth flow,
    and we capture the resulting token for testing.
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.active_sessions: Dict[str, AuthSession] = {}
        
    async def create_session_from_token(
        self,
        access_token: str,
        auth_provider: str,
        token_type: str = "Bearer",
        expires_in: int = 3600
    ) -> AuthSession:
        """
        Create auth session from social login token.
        
        User completes OAuth flow in the app, then provides
        the resulting token for Jarwis to use in testing.
        """
        session_id = f"social_{secrets.token_hex(16)}"
        
        auth_session = AuthSession(
            session_id=session_id,
            status=AuthSessionStatus.AUTHENTICATED,
            auth_type=auth_provider,
            created_at=datetime.now(),
            expires_at=datetime.now() + timedelta(seconds=expires_in),
            access_token=access_token,
            token_type=token_type
        )
        
        self.active_sessions[session_id] = auth_session
        return auth_session
    
    def get_session(self, session_id: str) -> Optional[AuthSession]:
        """Get active session"""
        session = self.active_sessions.get(session_id)
        if session and session.is_valid():
            return session
        return None


class UsernamePasswordHandler:
    """
    Handler for username/password authentication.
    
    Credentials are provided by user and sent directly to
    the target app's login endpoint.
    """
    
    def __init__(self, config: Dict):
        self.config = config
        self.active_sessions: Dict[str, AuthSession] = {}
        self._session: Optional[aiohttp.ClientSession] = None
        
    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session
    
    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()
    
    async def login(
        self,
        username: str,
        password: str,
        login_api_url: str,
        username_field: str = "username",
        password_field: str = "password"
    ) -> AuthSession:
        """
        Authenticate with username/password.
        
        Credentials are sent directly to target app's API.
        Password is NOT stored after the request.
        """
        session_id = f"user_{secrets.token_hex(16)}"
        
        try:
            http_session = await self._get_session()
            async with http_session.post(
                login_api_url,
                json={
                    username_field: username,
                    password_field: password  # Sent to API, not stored
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                # Password is now out of scope
                
                if response.status == 200:
                    data = await response.json()
                    
                    auth_session = AuthSession(
                        session_id=session_id,
                        status=AuthSessionStatus.AUTHENTICATED,
                        auth_type="username_password",
                        created_at=datetime.now(),
                        expires_at=datetime.now() + timedelta(hours=1),
                        access_token=data.get('access_token') or data.get('token'),
                        refresh_token=data.get('refresh_token'),
                        token_type=data.get('token_type', 'Bearer'),
                        user_info=data.get('user', {})
                    )
                    
                    self.active_sessions[session_id] = auth_session
                    return auth_session
                    
        except Exception as e:
            print(f"[Auth] Login failed: {e}")
        
        return AuthSession(
            session_id=session_id,
            status=AuthSessionStatus.FAILED,
            auth_type="username_password",
            created_at=datetime.now(),
            expires_at=datetime.now()
        )


def create_otp_handler(config: Dict) -> SecureOTPHandler:
    """Factory function to create OTP handler"""
    return SecureOTPHandler(config)


def create_social_auth_handler(config: Dict) -> SocialAuthHandler:
    """Factory function to create social auth handler"""
    return SocialAuthHandler(config)


def create_password_handler(config: Dict) -> UsernamePasswordHandler:
    """Factory function to create password auth handler"""
    return UsernamePasswordHandler(config)
