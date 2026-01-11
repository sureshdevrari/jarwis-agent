"""
OTP Service - Handles all OTP-related business logic

This service manages:
1. Scan OTP state (when target websites require 2FA)
2. User 2FA (for Jarwis platform authentication)

Extracted from api/routes/scan_otp.py to prevent circular imports
and allow core/browser.py to use OTP logic without importing routes.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class OTPState:
    """State for a single OTP session"""
    waiting_for_otp: bool = False
    otp_value: Optional[str] = None
    otp_submitted_at: Optional[str] = None
    otp_type: Optional[str] = None  # email, sms, authenticator
    otp_contact: Optional[str] = None  # masked email/phone
    waiting_since: Optional[str] = None
    timeout_seconds: int = 300  # 5 minutes default
    attempts: int = 0
    max_attempts: int = 3
    error_message: Optional[str] = None
    two_fa_enabled: bool = False
    two_fa_config: Optional[Dict[str, Any]] = None


class OTPService:
    """
    Centralized OTP management service.
    
    Usage:
        from services.otp_service import otp_service
        
        # Set waiting state (called by scanner)
        otp_service.set_waiting(scan_id, "email", "j***@example.com")
        
        # Submit OTP (called by API route)
        otp_service.submit_otp(scan_id, "123456")
        
        # Wait for OTP (called by scanner)
        otp = await otp_service.wait_for_otp(scan_id, timeout=300)
    """
    
    def __init__(self):
        self._store: Dict[str, OTPState] = {}
        self._lock = asyncio.Lock()
    
    def _get_state(self, scan_id: str) -> OTPState:
        """Get or create OTP state for a scan"""
        if scan_id not in self._store:
            self._store[scan_id] = OTPState()
        return self._store[scan_id]
    
    def _mask_contact(self, contact: str, otp_type: str) -> str:
        """Mask email or phone for privacy"""
        if not contact:
            return "***"
        
        if otp_type == "email":
            parts = contact.split("@")
            if len(parts) == 2:
                username = parts[0]
                domain = parts[1]
                masked_user = username[0] + "***" if len(username) > 1 else "***"
                return f"{masked_user}@{domain}"
        elif otp_type in ("sms", "phone"):
            if len(contact) > 4:
                return "***" + contact[-4:]
        
        return "***"
    
    def set_waiting(
        self,
        scan_id: str,
        otp_type: str,
        contact: str,
        timeout_seconds: int = 300
    ) -> None:
        """
        Mark a scan as waiting for OTP.
        Called by the scanner when target website requires 2FA.
        """
        state = self._get_state(scan_id)
        state.waiting_for_otp = True
        state.otp_type = otp_type
        state.otp_contact = self._mask_contact(contact, otp_type)
        state.waiting_since = datetime.utcnow().isoformat()
        state.timeout_seconds = timeout_seconds
        state.otp_value = None
        state.error_message = None
        
        logger.info(f"Scan {scan_id} waiting for OTP ({otp_type})")
    
    def submit_otp(self, scan_id: str, otp: str) -> bool:
        """
        Submit OTP for a waiting scan.
        Called by API route when user submits OTP.
        
        Returns:
            True if OTP was accepted, False if scan wasn't waiting
        """
        state = self._get_state(scan_id)
        
        if not state.waiting_for_otp:
            logger.warning(f"OTP submitted for scan {scan_id} but not waiting")
            return False
        
        state.otp_value = otp
        state.otp_submitted_at = datetime.utcnow().isoformat()
        state.attempts += 1
        
        logger.info(f"OTP submitted for scan {scan_id} (attempt {state.attempts})")
        return True
    
    def get_status(self, scan_id: str) -> Dict[str, Any]:
        """Get current OTP status for a scan"""
        state = self._get_state(scan_id)
        
        # Check for timeout
        is_timed_out = False
        if state.waiting_since:
            waiting_since = datetime.fromisoformat(state.waiting_since)
            elapsed = (datetime.utcnow() - waiting_since).total_seconds()
            is_timed_out = elapsed > state.timeout_seconds
        
        return {
            "scan_id": scan_id,
            "waiting_for_otp": state.waiting_for_otp and not is_timed_out,
            "otp_type": state.otp_type,
            "otp_contact": state.otp_contact,
            "waiting_since": state.waiting_since,
            "timeout_seconds": state.timeout_seconds,
            "attempts": state.attempts,
            "max_attempts": state.max_attempts,
            "is_timed_out": is_timed_out,
            "error_message": state.error_message,
        }
    
    def set_error(self, scan_id: str, error_message: str) -> None:
        """Set error message for OTP (e.g., invalid code)"""
        state = self._get_state(scan_id)
        state.error_message = error_message
        logger.warning(f"OTP error for scan {scan_id}: {error_message}")
    
    def clear_state(self, scan_id: str) -> None:
        """Clear OTP state after successful authentication or cancellation"""
        state = self._get_state(scan_id)
        state.waiting_for_otp = False
        state.otp_value = None
        state.error_message = None
        logger.info(f"OTP state cleared for scan {scan_id}")
    
    def reset_for_retry(self, scan_id: str) -> None:
        """Reset OTP for retry (keeps waiting state, clears value)"""
        state = self._get_state(scan_id)
        state.otp_value = None
        state.error_message = None
        state.waiting_since = datetime.utcnow().isoformat()
        logger.info(f"OTP reset for retry on scan {scan_id}")
    
    async def wait_for_otp(
        self,
        scan_id: str,
        timeout: int = 300,
        poll_interval: float = 1.0
    ) -> Optional[str]:
        """
        Wait for OTP to be submitted.
        Called by scanner to block until user submits OTP.
        
        Args:
            scan_id: The scan ID
            timeout: Maximum wait time in seconds
            poll_interval: How often to check for OTP
            
        Returns:
            The OTP value if submitted, None if timeout
        """
        state = self._get_state(scan_id)
        start_time = datetime.utcnow()
        
        while True:
            # Check if OTP was submitted
            if state.otp_value:
                otp = state.otp_value
                state.otp_value = None  # Clear after reading
                return otp
            
            # Check timeout
            elapsed = (datetime.utcnow() - start_time).total_seconds()
            if elapsed >= timeout:
                logger.warning(f"OTP timeout for scan {scan_id}")
                state.waiting_for_otp = False
                state.error_message = "OTP timeout - no code submitted"
                return None
            
            # Check max attempts
            if state.attempts >= state.max_attempts:
                logger.warning(f"Max OTP attempts reached for scan {scan_id}")
                state.waiting_for_otp = False
                state.error_message = "Maximum OTP attempts exceeded"
                return None
            
            await asyncio.sleep(poll_interval)
    
    def set_2fa_config(self, scan_id: str, config: Dict[str, Any]) -> None:
        """Store 2FA configuration for a scan"""
        state = self._get_state(scan_id)
        state.two_fa_enabled = True
        state.two_fa_config = config
    
    def get_2fa_config(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get 2FA configuration for a scan"""
        state = self._get_state(scan_id)
        return state.two_fa_config if state.two_fa_enabled else None
    
    def cleanup_old_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up old OTP sessions to prevent memory leaks"""
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        removed = 0
        
        scan_ids = list(self._store.keys())
        for scan_id in scan_ids:
            state = self._store[scan_id]
            if state.waiting_since:
                try:
                    waiting_since = datetime.fromisoformat(state.waiting_since)
                    if waiting_since < cutoff:
                        del self._store[scan_id]
                        removed += 1
                except (ValueError, TypeError):
                    pass
        
        if removed > 0:
            logger.info(f"Cleaned up {removed} old OTP sessions")
        
        return removed


# Global singleton instance
otp_service = OTPService()


# Convenience functions for backward compatibility
def get_scan_otp_state(scan_id: str) -> Dict[str, Any]:
    """Get OTP state (backward compatible)"""
    return otp_service.get_status(scan_id)


def set_scan_waiting_for_otp(
    scan_id: str,
    otp_type: str,
    contact: str,
    timeout_seconds: int = 300
) -> None:
    """Set scan waiting for OTP (backward compatible)"""
    otp_service.set_waiting(scan_id, otp_type, contact, timeout_seconds)


def submit_otp_for_scan(scan_id: str, otp: str) -> bool:
    """Submit OTP (backward compatible)"""
    return otp_service.submit_otp(scan_id, otp)


async def wait_for_otp(scan_id: str, timeout: int = 300) -> Optional[str]:
    """Wait for OTP (backward compatible)"""
    return await otp_service.wait_for_otp(scan_id, timeout)


def set_otp_error(scan_id: str, error_message: str) -> None:
    """Set OTP error (backward compatible)"""
    otp_service.set_error(scan_id, error_message)


def clear_scan_otp_state(scan_id: str) -> None:
    """Clear OTP state (backward compatible)"""
    otp_service.clear_state(scan_id)


def reset_otp_for_retry(scan_id: str) -> None:
    """Reset OTP for retry (backward compatible)"""
    otp_service.reset_for_retry(scan_id)
