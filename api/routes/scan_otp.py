"""
Scan OTP Routes - Handle 2FA OTP for Target Website Scanning

This module handles the 2FA workflow when scanning websites that require
two-factor authentication. The scanner waits for the user to provide OTP
when the target website sends a 2FA code.

Endpoints:
- GET  /api/scan-otp/{scan_id}/status    - Check if scan is waiting for OTP
- POST /api/scan-otp/{scan_id}/submit    - Submit OTP to continue scanning
- GET  /api/scan-otp/{scan_id}/2fa-config - Get 2FA configuration for a scan

Flow:
1. User starts scan with 2FA config (type: email/sms, contact info)
2. Scanner attempts login on target website
3. Target website triggers 2FA (sends code to user's email/phone)
4. Scanner pauses and sets status to "waiting_for_otp"
5. Frontend polls /status endpoint to detect waiting state
6. User receives OTP on their email/phone from target website
7. User enters OTP in frontend and clicks "Send"
8. Frontend calls /submit endpoint with OTP
9. Scanner receives OTP and continues authentication
10. Scan proceeds to authenticated testing phase
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_active_user
from database import crud

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan-otp", tags=["Scan OTP"])


# ============== Global OTP Store ==============
# In-memory store for scan OTP handling
# In production, this should be Redis or similar
scan_otp_store: dict = {}


def get_scan_otp_state(scan_id: str) -> dict:
    """Get or create OTP state for a scan"""
    if scan_id not in scan_otp_store:
        scan_otp_store[scan_id] = {
            "waiting_for_otp": False,
            "otp_value": None,
            "otp_submitted_at": None,
            "otp_type": None,  # email, sms, authenticator
            "otp_contact": None,  # masked email/phone
            "waiting_since": None,
            "timeout_seconds": 300,  # 5 minutes default
            "attempts": 0,
            "max_attempts": 3,
            "error_message": None,
            "2fa_enabled": False,
            "2fa_config": None
        }
    return scan_otp_store[scan_id]


def set_scan_waiting_for_otp(
    scan_id: str, 
    otp_type: str, 
    contact: str,
    timeout_seconds: int = 300
):
    """Called by scanner when target website requires OTP"""
    state = get_scan_otp_state(scan_id)
    state["waiting_for_otp"] = True
    state["otp_type"] = otp_type
    state["otp_contact"] = mask_contact(contact, otp_type)
    state["waiting_since"] = datetime.utcnow().isoformat()
    state["timeout_seconds"] = timeout_seconds
    state["otp_value"] = None
    state["error_message"] = None
    logger.info(f"Scan {scan_id} waiting for OTP ({otp_type})")


def submit_otp_for_scan(scan_id: str, otp: str) -> bool:
    """Submit OTP for a waiting scan"""
    state = get_scan_otp_state(scan_id)
    if not state["waiting_for_otp"]:
        return False
    
    state["otp_value"] = otp
    state["otp_submitted_at"] = datetime.utcnow().isoformat()
    state["attempts"] += 1
    logger.info(f"OTP submitted for scan {scan_id}")
    return True


def get_submitted_otp(scan_id: str) -> Optional[str]:
    """Get submitted OTP (called by scanner)"""
    state = get_scan_otp_state(scan_id)
    return state.get("otp_value")


def clear_scan_otp_state(scan_id: str):
    """Clear OTP state after successful authentication"""
    if scan_id in scan_otp_store:
        scan_otp_store[scan_id]["waiting_for_otp"] = False
        scan_otp_store[scan_id]["otp_value"] = None
        logger.info(f"OTP state cleared for scan {scan_id}")


def set_otp_error(scan_id: str, error_message: str):
    """Set error message when OTP fails"""
    state = get_scan_otp_state(scan_id)
    state["error_message"] = error_message
    state["otp_value"] = None  # Clear invalid OTP


def mask_contact(contact: str, contact_type: str) -> str:
    """Mask email or phone number for privacy"""
    if not contact:
        return "***"
    
    if contact_type == "email":
        parts = contact.split("@")
        if len(parts) == 2:
            username = parts[0]
            domain = parts[1]
            if len(username) > 2:
                masked_username = username[0] + "*" * (len(username) - 2) + username[-1]
            else:
                masked_username = username[0] + "*"
            return f"{masked_username}@{domain}"
    elif contact_type in ["sms", "phone"]:
        if len(contact) > 4:
            return "*" * (len(contact) - 4) + contact[-4:]
    
    return contact[:2] + "***"


# ============== Request/Response Models ==============

class OTPStatusResponse(BaseModel):
    """OTP waiting status for a scan"""
    scan_id: str
    waiting_for_otp: bool
    otp_type: Optional[str] = None  # email, sms, authenticator
    otp_contact: Optional[str] = None  # Masked email/phone
    waiting_since: Optional[str] = None
    timeout_seconds: int = 300
    time_remaining: int = 0
    attempts: int = 0
    max_attempts: int = 3
    error_message: Optional[str] = None
    message: str = ""


class SubmitOTPRequest(BaseModel):
    """Submit OTP for a scan"""
    otp: str = Field(..., min_length=4, max_length=8, description="OTP code from target website")


class SubmitOTPResponse(BaseModel):
    """Response after OTP submission"""
    success: bool
    message: str
    scan_id: str


class TwoFactorConfigResponse(BaseModel):
    """2FA configuration for a scan"""
    enabled: bool
    type: str  # none, email, sms, authenticator
    email: Optional[str] = None  # Masked
    phone: Optional[str] = None  # Masked


# ============== API Endpoints ==============

@router.get("/{scan_id}/status", response_model=OTPStatusResponse)
async def get_otp_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if a scan is waiting for OTP.
    
    Frontend should poll this endpoint while scan is running to detect
    when the target website's 2FA is triggered.
    
    - **scan_id**: The scan ID to check
    
    Returns the OTP waiting status including:
    - Whether scan is waiting for OTP
    - Type of OTP (email, sms, authenticator)
    - Masked contact info
    - Time remaining before timeout
    - Error message if previous OTP failed
    """
    # Verify scan belongs to user
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    state = get_scan_otp_state(scan_id)
    
    # Calculate time remaining
    time_remaining = 0
    if state["waiting_for_otp"] and state["waiting_since"]:
        try:
            waiting_since = datetime.fromisoformat(state["waiting_since"])
            elapsed = (datetime.utcnow() - waiting_since).total_seconds()
            time_remaining = max(0, state["timeout_seconds"] - int(elapsed))
        except:
            time_remaining = state["timeout_seconds"]
    
    # Build status message
    message = ""
    if state["waiting_for_otp"]:
        if state["otp_type"] == "email":
            message = f"Please check your email ({state['otp_contact']}) for the verification code from the target website"
        elif state["otp_type"] == "sms":
            message = f"Please check your phone ({state['otp_contact']}) for the SMS verification code from the target website"
        elif state["otp_type"] == "authenticator":
            message = "Please enter the code from your authenticator app for the target website"
        else:
            message = "The target website requires a verification code. Please enter the OTP you received."
    elif state["error_message"]:
        message = state["error_message"]
    else:
        message = "Scan is not waiting for OTP"
    
    return OTPStatusResponse(
        scan_id=scan_id,
        waiting_for_otp=state["waiting_for_otp"],
        otp_type=state.get("otp_type"),
        otp_contact=state.get("otp_contact"),
        waiting_since=state.get("waiting_since"),
        timeout_seconds=state["timeout_seconds"],
        time_remaining=time_remaining,
        attempts=state["attempts"],
        max_attempts=state["max_attempts"],
        error_message=state.get("error_message"),
        message=message
    )


@router.post("/{scan_id}/submit", response_model=SubmitOTPResponse)
async def submit_otp(
    scan_id: str,
    request: SubmitOTPRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Submit OTP to continue a waiting scan.
    
    When the target website sends a 2FA code to the user's email/phone,
    the user enters the code here to allow the scanner to continue.
    
    - **scan_id**: The scan ID waiting for OTP
    - **otp**: The verification code received from the target website
    """
    # Verify scan belongs to user
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    state = get_scan_otp_state(scan_id)
    
    # Check if scan is waiting for OTP
    if not state["waiting_for_otp"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is not waiting for OTP"
        )
    
    # Check attempt limit
    if state["attempts"] >= state["max_attempts"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Maximum OTP attempts exceeded. Please restart the scan."
        )
    
    # Check timeout
    if state["waiting_since"]:
        try:
            waiting_since = datetime.fromisoformat(state["waiting_since"])
            elapsed = (datetime.utcnow() - waiting_since).total_seconds()
            if elapsed > state["timeout_seconds"]:
                raise HTTPException(
                    status_code=status.HTTP_408_REQUEST_TIMEOUT,
                    detail="OTP timeout. Please restart the scan."
                )
        except ValueError:
            pass
    
    # Submit the OTP
    success = submit_otp_for_scan(scan_id, request.otp)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to submit OTP"
        )
    
    logger.info(f"OTP submitted for scan {scan_id} by user {current_user.email}")
    
    return SubmitOTPResponse(
        success=True,
        message="OTP submitted successfully. Scanner will continue authentication.",
        scan_id=scan_id
    )


@router.get("/{scan_id}/2fa-config", response_model=TwoFactorConfigResponse)
async def get_2fa_config(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get 2FA configuration for a scan.
    
    Returns the 2FA settings configured when the scan was started.
    """
    # Verify scan belongs to user
    scan = await crud.get_scan_by_id(db, scan_id, current_user.id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Get 2FA config from scan config
    config = scan.config or {}
    two_factor = config.get("two_factor", {})
    
    return TwoFactorConfigResponse(
        enabled=two_factor.get("enabled", False),
        type=two_factor.get("type", "none"),
        email=mask_contact(two_factor.get("email", ""), "email") if two_factor.get("email") else None,
        phone=mask_contact(two_factor.get("phone", ""), "sms") if two_factor.get("phone") else None
    )


# ============== Helper Functions for Scanner ==============

async def wait_for_otp(
    scan_id: str,
    otp_type: str,
    contact: str,
    timeout_seconds: int = 300,
    poll_interval: float = 2.0
) -> Optional[str]:
    """
    Wait for user to submit OTP.
    
    Called by the scanner when target website requires 2FA.
    This function blocks until OTP is submitted or timeout occurs.
    
    Args:
        scan_id: The scan ID
        otp_type: Type of OTP (email, sms, authenticator)
        contact: Email or phone number to display
        timeout_seconds: Maximum time to wait
        poll_interval: How often to check for OTP
        
    Returns:
        The OTP value if submitted, None if timeout
    """
    # Set scan as waiting for OTP
    set_scan_waiting_for_otp(scan_id, otp_type, contact, timeout_seconds)
    
    start_time = datetime.utcnow()
    
    while True:
        # Check timeout
        elapsed = (datetime.utcnow() - start_time).total_seconds()
        if elapsed > timeout_seconds:
            logger.warning(f"OTP timeout for scan {scan_id} after {timeout_seconds}s")
            clear_scan_otp_state(scan_id)
            return None
        
        # Check if OTP was submitted
        otp = get_submitted_otp(scan_id)
        if otp:
            logger.info(f"OTP received for scan {scan_id}")
            return otp
        
        # Wait before next poll
        await asyncio.sleep(poll_interval)


def reset_otp_for_retry(scan_id: str):
    """Reset OTP state for retry after failed attempt"""
    state = get_scan_otp_state(scan_id)
    state["otp_value"] = None
    state["waiting_for_otp"] = True
    state["waiting_since"] = datetime.utcnow().isoformat()
