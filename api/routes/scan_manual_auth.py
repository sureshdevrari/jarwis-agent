"""
Manual Auth Routes - Handle social login / manual authentication for scans

Endpoints for when target app uses social login (Google/Facebook/etc) or
phone OTP and user needs to authenticate manually.

Endpoints:
- GET  /api/scan-auth/{scan_id}/status  - Check if scan is waiting for manual auth
- POST /api/scan-auth/{scan_id}/confirm - User confirms login is complete
- POST /api/scan-auth/{scan_id}/cancel  - User cancels manual auth
- POST /api/scan-auth/{scan_id}/session - User provides session manually

Flow:
1. Scan starts with auth_method = "social_login" or "phone_otp"
2. Scanner detects login page, opens visible browser, pauses scan
3. Frontend polls /status to detect waiting state
4. User logs in manually in browser window (clicks Google button, etc)
5. User clicks "I'm Logged In" button → calls /confirm
6. Scanner captures cookies from browser, continues scan
"""

import logging
from typing import Optional, Dict, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_active_user
from database import crud

from services.manual_auth_service import (
    manual_auth_service,
    ManualAuthStatus,
    ManualAuthState,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan-auth", tags=["Scan Manual Auth"])


# ============== Request/Response Models ==============

class ManualAuthStatusResponse(BaseModel):
    """Status of manual authentication for a scan"""
    scan_id: str
    waiting_for_manual_auth: bool
    status: str  # not_started, waiting, completed, failed, cancelled
    auth_method: Optional[str] = None  # social_login, phone_otp, manual_session
    login_url: Optional[str] = None
    social_providers: list = []
    phone_masked: Optional[str] = None
    waiting_since: Optional[str] = None
    timeout_seconds: int = 600
    time_remaining: int = 0
    instructions: Optional[str] = None
    error_message: Optional[str] = None


class ConfirmAuthRequest(BaseModel):
    """User confirms they completed login"""
    # Optional: user can provide captured cookies/token if they have them
    cookies: Optional[Dict[str, str]] = None
    token: Optional[str] = None


class ConfirmAuthResponse(BaseModel):
    """Response after confirming auth"""
    success: bool
    message: str
    scan_id: str


class ProvideSessionRequest(BaseModel):
    """User provides session cookie/token directly"""
    session_cookie: Optional[str] = Field(None, description="Session cookie value (e.g., from browser)")
    session_token: Optional[str] = Field(None, description="Auth token (e.g., JWT, Bearer token)")
    cookie_name: Optional[str] = Field("session", description="Name of the cookie to set")


class ProvideSessionResponse(BaseModel):
    """Response after providing session"""
    success: bool
    message: str
    scan_id: str


# ============== API Endpoints ==============

@router.get("/{scan_id}/status", response_model=ManualAuthStatusResponse)
async def get_manual_auth_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if a scan is waiting for manual authentication.
    
    Frontend should poll this endpoint during scanning to detect when
    manual login is needed (for social login / OTP targets).
    """
    # Verify scan belongs to user
    scan = await crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if str(scan.user_id) != str(current_user.id) and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to view this scan"
        )
    
    state = manual_auth_service.get_state(scan_id)
    time_remaining = manual_auth_service.get_time_remaining(scan_id)
    
    return ManualAuthStatusResponse(
        scan_id=scan_id,
        waiting_for_manual_auth=(state.status == ManualAuthStatus.WAITING),
        status=state.status.value if state.status else "not_started",
        auth_method=state.auth_method,
        login_url=state.login_url,
        social_providers=state.social_providers or [],
        phone_masked=state.phone_masked,
        waiting_since=state.waiting_since,
        timeout_seconds=state.timeout_seconds,
        time_remaining=time_remaining,
        instructions=state.instructions,
        error_message=state.error_message,
    )


@router.post("/{scan_id}/confirm", response_model=ConfirmAuthResponse)
async def confirm_auth_complete(
    scan_id: str,
    request: ConfirmAuthRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User confirms they have completed manual login.
    
    Call this after the user has logged into the target application
    via social login (Google button, Facebook button, etc.) or phone OTP.
    The scanner will then capture the session and continue.
    """
    # Verify scan belongs to user
    scan = await crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if str(scan.user_id) != str(current_user.id) and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify this scan"
        )
    
    # Check if scan is actually waiting
    if not manual_auth_service.is_waiting(scan_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Scan is not waiting for manual authentication"
        )
    
    # Confirm login complete
    success = manual_auth_service.confirm_login_complete(
        scan_id,
        cookies=request.cookies,
        token=request.token
    )
    
    if success:
        logger.info(f"Manual auth confirmed for scan {scan_id} by user {current_user.email}")
        return ConfirmAuthResponse(
            success=True,
            message="Login confirmed. Scan will continue with authenticated session.",
            scan_id=scan_id
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to confirm login. Scan may have timed out."
        )


@router.post("/{scan_id}/cancel", response_model=ConfirmAuthResponse)
async def cancel_manual_auth(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Cancel manual authentication and continue scan unauthenticated.
    
    Use this if the user decides not to log in or encounters issues.
    The scan will continue testing unauthenticated surfaces only.
    """
    # Verify scan belongs to user
    scan = await crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if str(scan.user_id) != str(current_user.id) and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify this scan"
        )
    
    manual_auth_service.cancel(scan_id)
    
    logger.info(f"Manual auth cancelled for scan {scan_id} by user {current_user.email}")
    
    return ConfirmAuthResponse(
        success=True,
        message="Authentication cancelled. Scan will continue without authentication.",
        scan_id=scan_id
    )


@router.post("/{scan_id}/session", response_model=ProvideSessionResponse)
async def provide_session(
    scan_id: str,
    request: ProvideSessionRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    User provides session cookie/token directly.
    
    For advanced users who want to provide their own session credentials
    instead of logging in through the browser. Useful for:
    - Apps where automated login capture doesn't work
    - When user already has a valid session
    - API-only targets
    """
    # Verify scan belongs to user
    scan = await crud.get_scan_by_id(db, scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    if str(scan.user_id) != str(current_user.id) and not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to modify this scan"
        )
    
    if not request.session_cookie and not request.session_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide either session_cookie or session_token"
        )
    
    # Build cookies dict
    cookies = None
    if request.session_cookie:
        cookie_name = request.cookie_name or "session"
        cookies = {cookie_name: request.session_cookie}
    
    # Confirm with provided session
    success = manual_auth_service.confirm_login_complete(
        scan_id,
        cookies=cookies,
        token=request.session_token
    )
    
    if success:
        logger.info(f"Session provided for scan {scan_id} by user {current_user.email}")
        return ProvideSessionResponse(
            success=True,
            message="Session credentials received. Scan will use provided authentication.",
            scan_id=scan_id
        )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Failed to apply session. Scan may not be in waiting state."
        )
