"""
Manual Auth Service - Handles social login / manual authentication for scans

This service manages:
1. Manual login sessions (for social login targets like Google/Facebook/LinkedIn/Apple)
2. Phone OTP authentication flow
3. Session capture after manual login

Flow for Social Login:
1. User starts scan with auth_method = "social_login"
2. Scanner opens target login page in visible browser window
3. Scan pauses, status = "waiting_for_manual_auth"
4. User manually logs in (clicks Google/Facebook button, completes OAuth)
5. User clicks "I'm logged in" button in Jarwis dashboard
6. Scanner captures session cookies/tokens
7. Scan continues with authenticated session

Flow for Phone OTP:
1. User starts scan with auth_method = "phone_otp" and phone_number
2. Scanner enters phone number on target, triggers OTP
3. Scan pauses, status = "waiting_for_otp"  
4. User enters OTP received on their phone
5. Scanner submits OTP, captures session
6. Scan continues

Flow for Manual Session:
1. User provides session_cookie or session_token directly
2. Scanner uses provided session without login flow
3. No pause needed
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ManualAuthStatus(str, Enum):
    """Status of manual authentication"""
    NOT_STARTED = "not_started"
    WAITING = "waiting"           # Waiting for user to complete login
    COMPLETED = "completed"       # User confirmed login complete
    FAILED = "failed"            # Login failed or timed out
    CANCELLED = "cancelled"      # User cancelled


@dataclass
class ManualAuthState:
    """State for a manual authentication session"""
    status: ManualAuthStatus = ManualAuthStatus.NOT_STARTED
    auth_method: Optional[str] = None  # social_login, phone_otp, manual_session
    
    # Target app info
    login_url: Optional[str] = None
    social_providers: List[str] = field(default_factory=list)  # google, facebook, etc.
    
    # Timing
    waiting_since: Optional[str] = None
    timeout_seconds: int = 600  # 10 minutes for manual login
    
    # For phone OTP
    phone_number: Optional[str] = None
    phone_masked: Optional[str] = None
    
    # Captured session (after successful login)
    session_cookies: Optional[Dict[str, str]] = None
    session_token: Optional[str] = None
    
    # Error handling
    error_message: Optional[str] = None
    
    # Instructions for user
    instructions: Optional[str] = None


class ManualAuthService:
    """
    Centralized manual authentication management.
    
    Usage:
        from services.manual_auth_service import manual_auth_service
        
        # Start manual auth (called by scanner)
        manual_auth_service.start_waiting(
            scan_id, 
            auth_method="social_login",
            login_url="https://example.com/login",
            social_providers=["google", "facebook"]
        )
        
        # Check status (called by API/frontend)
        state = manual_auth_service.get_state(scan_id)
        
        # Confirm login complete (called by user via API)
        manual_auth_service.confirm_login_complete(scan_id, cookies={...})
        
        # Wait for completion (called by scanner)
        result = await manual_auth_service.wait_for_auth(scan_id, timeout=600)
    """
    
    def __init__(self):
        self._store: Dict[str, ManualAuthState] = {}
        self._events: Dict[str, asyncio.Event] = {}
        self._lock = asyncio.Lock()
    
    def _get_state(self, scan_id: str) -> ManualAuthState:
        """Get or create auth state for a scan"""
        if scan_id not in self._store:
            self._store[scan_id] = ManualAuthState()
        return self._store[scan_id]
    
    def _get_event(self, scan_id: str) -> asyncio.Event:
        """Get or create async event for a scan"""
        if scan_id not in self._events:
            self._events[scan_id] = asyncio.Event()
        return self._events[scan_id]
    
    def _mask_phone(self, phone: str) -> str:
        """Mask phone number for privacy"""
        if not phone:
            return "***"
        if len(phone) > 4:
            return "***" + phone[-4:]
        return "***"
    
    def _generate_instructions(self, auth_method: str, social_providers: List[str] = None) -> str:
        """Generate user-friendly instructions"""
        if auth_method == "social_login":
            providers_text = ", ".join(social_providers) if social_providers else "social provider"
            return (
                f"Please log in to the target application using {providers_text}. "
                "A browser window will open. Complete the login process, then click "
                "'I'm Logged In' below to continue the scan."
            )
        elif auth_method == "phone_otp":
            return (
                "An OTP has been sent to your phone. Enter the code you received "
                "to continue the authenticated scan."
            )
        elif auth_method == "email_magic_link":
            return (
                "A login link has been sent to your email. Click the link in a new tab, "
                "complete the login, then click 'I'm Logged In' to continue."
            )
        elif auth_method == "manual_session":
            return (
                "Please provide your session cookie or authentication token. "
                "You can get this from your browser's developer tools."
            )
        return "Please complete the authentication to continue scanning."
    
    def start_waiting(
        self,
        scan_id: str,
        auth_method: str,
        login_url: str = None,
        social_providers: List[str] = None,
        phone_number: str = None,
        timeout_seconds: int = 600
    ) -> ManualAuthState:
        """
        Start waiting for manual authentication.
        Called by the scanner when it needs user to log in manually.
        """
        state = self._get_state(scan_id)
        state.status = ManualAuthStatus.WAITING
        state.auth_method = auth_method
        state.login_url = login_url
        state.social_providers = social_providers or []
        state.phone_number = phone_number
        state.phone_masked = self._mask_phone(phone_number) if phone_number else None
        state.waiting_since = datetime.utcnow().isoformat()
        state.timeout_seconds = timeout_seconds
        state.instructions = self._generate_instructions(auth_method, social_providers)
        state.error_message = None
        
        # Reset event
        event = self._get_event(scan_id)
        event.clear()
        
        logger.info(f"Scan {scan_id} waiting for manual auth: {auth_method}")
        return state
    
    def get_state(self, scan_id: str) -> ManualAuthState:
        """Get current authentication state"""
        return self._get_state(scan_id)
    
    def is_waiting(self, scan_id: str) -> bool:
        """Check if scan is waiting for manual auth"""
        state = self._get_state(scan_id)
        return state.status == ManualAuthStatus.WAITING
    
    def get_time_remaining(self, scan_id: str) -> int:
        """Get remaining time for auth (seconds)"""
        state = self._get_state(scan_id)
        if not state.waiting_since:
            return 0
        
        try:
            waiting_since = datetime.fromisoformat(state.waiting_since)
            elapsed = (datetime.utcnow() - waiting_since).total_seconds()
            remaining = max(0, state.timeout_seconds - int(elapsed))
            return remaining
        except (ValueError, TypeError):
            return 0
    
    def confirm_login_complete(
        self,
        scan_id: str,
        cookies: Dict[str, str] = None,
        token: str = None
    ) -> bool:
        """
        User confirms they have completed login.
        Called by API when user clicks "I'm Logged In".
        """
        state = self._get_state(scan_id)
        
        if state.status != ManualAuthStatus.WAITING:
            logger.warning(f"Scan {scan_id} not waiting for auth, status: {state.status}")
            return False
        
        state.status = ManualAuthStatus.COMPLETED
        state.session_cookies = cookies
        state.session_token = token
        
        # Signal the waiting scanner
        event = self._get_event(scan_id)
        event.set()
        
        logger.info(f"Scan {scan_id} manual auth confirmed complete")
        return True
    
    def set_failed(self, scan_id: str, error_message: str = None) -> None:
        """Mark authentication as failed"""
        state = self._get_state(scan_id)
        state.status = ManualAuthStatus.FAILED
        state.error_message = error_message or "Authentication failed"
        
        # Signal to unblock any waiters
        event = self._get_event(scan_id)
        event.set()
        
        logger.warning(f"Scan {scan_id} manual auth failed: {error_message}")
    
    def cancel(self, scan_id: str) -> None:
        """Cancel manual authentication"""
        state = self._get_state(scan_id)
        state.status = ManualAuthStatus.CANCELLED
        state.error_message = "Authentication cancelled by user"
        
        event = self._get_event(scan_id)
        event.set()
        
        logger.info(f"Scan {scan_id} manual auth cancelled")
    
    async def wait_for_auth(
        self,
        scan_id: str,
        timeout: int = 600
    ) -> Optional[ManualAuthState]:
        """
        Wait for user to complete manual authentication.
        Called by scanner to block until user logs in.
        
        Returns:
            ManualAuthState with captured session if successful, None if timeout/failed
        """
        state = self._get_state(scan_id)
        event = self._get_event(scan_id)
        
        try:
            await asyncio.wait_for(event.wait(), timeout=timeout)
            
            if state.status == ManualAuthStatus.COMPLETED:
                logger.info(f"Scan {scan_id} manual auth completed successfully")
                return state
            else:
                logger.warning(f"Scan {scan_id} manual auth ended with status: {state.status}")
                return None
                
        except asyncio.TimeoutError:
            state.status = ManualAuthStatus.FAILED
            state.error_message = "Authentication timed out"
            logger.warning(f"Scan {scan_id} manual auth timed out after {timeout}s")
            return None
    
    def clear_state(self, scan_id: str) -> None:
        """Clear all state for a scan"""
        if scan_id in self._store:
            del self._store[scan_id]
        if scan_id in self._events:
            del self._events[scan_id]
        logger.debug(f"Cleared manual auth state for scan {scan_id}")
    
    def cleanup_old_states(self, max_age_hours: int = 24) -> int:
        """Clean up old auth states"""
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        removed = 0
        
        scan_ids = list(self._store.keys())
        for scan_id in scan_ids:
            state = self._store[scan_id]
            if state.waiting_since:
                try:
                    waiting = datetime.fromisoformat(state.waiting_since)
                    if waiting < cutoff:
                        self.clear_state(scan_id)
                        removed += 1
                except (ValueError, TypeError):
                    pass
        
        return removed


# Global singleton instance
manual_auth_service = ManualAuthService()


# Convenience functions for import
def get_manual_auth_state(scan_id: str) -> ManualAuthState:
    """Get manual auth state for a scan"""
    return manual_auth_service.get_state(scan_id)


def start_manual_auth_waiting(
    scan_id: str,
    auth_method: str,
    **kwargs
) -> ManualAuthState:
    """Start waiting for manual auth"""
    return manual_auth_service.start_waiting(scan_id, auth_method, **kwargs)


def confirm_manual_auth_complete(
    scan_id: str,
    cookies: Dict[str, str] = None,
    token: str = None
) -> bool:
    """Confirm manual auth is complete"""
    return manual_auth_service.confirm_login_complete(scan_id, cookies, token)


async def wait_for_manual_auth(scan_id: str, timeout: int = 600) -> Optional[ManualAuthState]:
    """Wait for manual auth to complete"""
    return await manual_auth_service.wait_for_auth(scan_id, timeout)
