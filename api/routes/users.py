"""
User Management API Routes
Profile management, user updates, account deletion
"""

import os
import hashlib
import json
import zipfile
import io
from datetime import datetime
from typing import Optional, List

from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, Body
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, Field, HttpUrl

from database.connection import get_db
from database.models import User, ScanHistory, Finding, LoginHistory
from database.schemas import UserResponse, UserUpdate, MessageResponse
from database.auth import get_user_by_email, get_user_by_username, hash_password, verify_password
from database.dependencies import get_current_active_user, get_current_superuser
from database.subscription import (
    get_user_usage_stats, 
    check_subscription_limit, 
    SubscriptionAction,
    get_plan_config,
    PLAN_CONFIG
)
from services.subscription_manager import SubscriptionManager
from database import crud

router = APIRouter(prefix="/api/users", tags=["Users"])


# ============== Profile Request/Response Models ==============

class ProfileUpdateRequest(BaseModel):
    """Extended profile update request"""
    full_name: Optional[str] = Field(None, max_length=255)
    company: Optional[str] = Field(None, max_length=255)
    bio: Optional[str] = Field(None, max_length=1000)
    job_title: Optional[str] = Field(None, max_length=100)
    linkedin_url: Optional[str] = Field(None, max_length=500)
    twitter_url: Optional[str] = Field(None, max_length=500)
    github_url: Optional[str] = Field(None, max_length=500)
    timezone: Optional[str] = Field(None, max_length=50)
    language: Optional[str] = Field(None, max_length=10)


class NotificationSettingsRequest(BaseModel):
    """Notification settings update"""
    email_enabled: bool = True
    email_scan_completed: bool = True
    email_vulnerability_found: bool = True
    email_weekly_digest: bool = False
    push_enabled: bool = False
    slack_enabled: bool = False
    slack_webhook_url: Optional[str] = None


class ScanPreferencesRequest(BaseModel):
    """Scan preferences update"""
    default_scan_type: str = "web"
    auto_scan_on_domain_add: bool = False
    detailed_logs: bool = True
    save_scan_history: bool = True
    default_report_format: str = "html"  # html, pdf, json


class DeleteAccountRequest(BaseModel):
    """Delete account request (requires password)"""
    password: str = Field(..., min_length=1)
    confirm_phrase: Optional[str] = None  # Optional: "DELETE MY ACCOUNT"


@router.get("/me", response_model=UserResponse)
async def get_my_profile(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current user's profile.
    """
    return current_user


@router.patch("/me", response_model=UserResponse)
async def update_my_profile(
    update_data: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update current user's profile.
    
    - **full_name**: Optional new full name
    - **company**: Optional new company
    - **email**: Optional new email (must be unique)
    """
    # Check if email is being changed and if it's taken
    if update_data.email and update_data.email != current_user.email:
        existing = await get_user_by_email(db, update_data.email)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )
    
    # Update user
    update_dict = update_data.model_dump(exclude_unset=True)
    user = await crud.update_user(db, current_user, **update_dict)
    
    return user


@router.delete("/me", response_model=MessageResponse)
async def delete_my_account(
    data: DeleteAccountRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete current user's account.
    Requires password confirmation.
    This action is irreversible!
    """
    # Verify password
    if not verify_password(data.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )
    
    await crud.delete_user(db, current_user)
    
    return MessageResponse(
        message="Account deleted successfully",
        success=True
    )


# ============== Extended Profile Endpoints ==============

@router.put("/me/profile", response_model=UserResponse)
async def update_extended_profile(
    profile: ProfileUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update extended profile fields (bio, job_title, social links, etc.)
    """
    update_fields = profile.model_dump(exclude_unset=True)
    
    # Validate URLs if provided
    for url_field in ['linkedin_url', 'twitter_url', 'github_url']:
        url_value = update_fields.get(url_field)
        if url_value:
            if not url_value.startswith(('http://', 'https://')):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"{url_field} must be a valid URL starting with http:// or https://"
                )
    
    # Update fields
    for field, value in update_fields.items():
        if hasattr(current_user, field):
            setattr(current_user, field, value)
    
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(current_user)
    
    return current_user


@router.post("/me/avatar")
async def upload_avatar(
    avatar: UploadFile = File(...),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload profile avatar image.
    
    - Max size: 2MB
    - Allowed formats: JPEG, PNG, GIF, WebP
    """
    # Validate file size (2MB max)
    MAX_SIZE = 2 * 1024 * 1024  # 2MB
    content = await avatar.read()
    
    if len(content) > MAX_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File too large. Maximum size is 2MB."
        )
    
    # Validate file type by checking magic bytes
    allowed_types = {
        b'\xff\xd8\xff': 'image/jpeg',
        b'\x89PNG\r\n\x1a\n': 'image/png',
        b'GIF87a': 'image/gif',
        b'GIF89a': 'image/gif',
        b'RIFF': 'image/webp',  # WebP starts with RIFF
    }
    
    file_type = None
    for magic, mime in allowed_types.items():
        if content.startswith(magic):
            file_type = mime
            break
    
    if not file_type:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Allowed: JPEG, PNG, GIF, WebP"
        )
    
    # Generate unique filename using hash
    file_hash = hashlib.sha256(content).hexdigest()[:16]
    ext = file_type.split('/')[-1]
    if ext == 'jpeg':
        ext = 'jpg'
    filename = f"avatar_{current_user.id}_{file_hash}.{ext}"
    
    # Save to uploads directory
    upload_dir = os.path.join("data", "uploads", "avatars")
    os.makedirs(upload_dir, exist_ok=True)
    file_path = os.path.join(upload_dir, filename)
    
    with open(file_path, 'wb') as f:
        f.write(content)
    
    # Update user avatar URL
    avatar_url = f"/api/uploads/avatars/{filename}"
    current_user.avatar_url = avatar_url
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    
    return {
        "success": True,
        "avatar_url": avatar_url,
        "message": "Avatar uploaded successfully"
    }


@router.put("/me/notifications")
async def update_notification_settings(
    settings: NotificationSettingsRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update notification preferences.
    """
    current_user.notification_settings = settings.model_dump()
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    
    return {
        "success": True,
        "message": "Notification settings updated",
        "settings": current_user.notification_settings
    }


@router.get("/me/notifications")
async def get_notification_settings(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current notification preferences.
    """
    defaults = {
        "email_enabled": True,
        "email_scan_completed": True,
        "email_vulnerability_found": True,
        "email_weekly_digest": False,
        "push_enabled": False,
        "slack_enabled": False,
        "slack_webhook_url": None
    }
    
    settings = current_user.notification_settings or {}
    return {**defaults, **settings}


@router.put("/me/preferences")
async def update_scan_preferences(
    preferences: ScanPreferencesRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update scan preferences.
    """
    current_user.scan_preferences = preferences.model_dump()
    current_user.updated_at = datetime.utcnow()
    await db.commit()
    
    return {
        "success": True,
        "message": "Scan preferences updated",
        "preferences": current_user.scan_preferences
    }


@router.get("/me/preferences")
async def get_scan_preferences(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get current scan preferences.
    """
    defaults = {
        "default_scan_type": "web",
        "auto_scan_on_domain_add": False,
        "detailed_logs": True,
        "save_scan_history": True,
        "default_report_format": "html"
    }
    
    preferences = current_user.scan_preferences or {}
    return {**defaults, **preferences}


@router.get("/me/export")
async def export_user_data(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Export all user data (GDPR compliance).
    Returns a ZIP file containing JSON exports of all user data.
    """
    # Gather user profile data
    profile_data = {
        "id": str(current_user.id),
        "email": current_user.email,
        "username": current_user.username,
        "full_name": current_user.full_name,
        "company": current_user.company,
        "bio": current_user.bio,
        "job_title": current_user.job_title,
        "plan": current_user.plan,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        "notification_settings": current_user.notification_settings,
        "scan_preferences": current_user.scan_preferences,
    }
    
    # Gather scan history
    result = await db.execute(
        select(ScanHistory).where(ScanHistory.user_id == current_user.id)
    )
    scans = result.scalars().all()
    scans_data = []
    for scan in scans:
        scans_data.append({
            "scan_id": scan.scan_id,
            "target_url": scan.target_url,
            "scan_type": scan.scan_type,
            "status": scan.status,
            "started_at": scan.started_at.isoformat() if scan.started_at else None,
            "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            "findings_count": scan.findings_count,
        })
    
    # Gather login history
    result = await db.execute(
        select(LoginHistory).where(LoginHistory.user_id == current_user.id).order_by(LoginHistory.created_at.desc()).limit(100)
    )
    logins = result.scalars().all()
    logins_data = []
    for login in logins:
        logins_data.append({
            "ip_address": login.ip_address,
            "device_type": login.device_type,
            "browser": login.browser,
            "location": login.location,
            "success": login.success,
            "created_at": login.created_at.isoformat() if login.created_at else None,
        })
    
    # Create ZIP file in memory
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr('profile.json', json.dumps(profile_data, indent=2))
        zip_file.writestr('scans.json', json.dumps(scans_data, indent=2))
        zip_file.writestr('login_history.json', json.dumps(logins_data, indent=2))
        zip_file.writestr('README.txt', f"""
Jarwis Data Export
==================
Exported for: {current_user.email}
Date: {datetime.utcnow().isoformat()}

Contents:
- profile.json: Your profile information
- scans.json: Your scan history
- login_history.json: Recent login activity

For questions, contact support@jarwis.ai
""")
    
    zip_buffer.seek(0)
    
    return StreamingResponse(
        zip_buffer,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=jarwis_export_{current_user.username}_{datetime.utcnow().strftime('%Y%m%d')}.zip"
        }
    )


@router.delete("/me/data")
async def delete_all_user_data(
    data: DeleteAccountRequest,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete all user scan data while keeping the account.
    Requires password confirmation.
    """
    # Verify password
    if not verify_password(data.password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid password"
        )
    
    # Delete all scans (cascade will delete findings)
    from sqlalchemy import delete
    await db.execute(
        delete(ScanHistory).where(ScanHistory.user_id == current_user.id)
    )
    
    # Delete login history
    await db.execute(
        delete(LoginHistory).where(LoginHistory.user_id == current_user.id)
    )
    
    # Reset scan count
    current_user.scans_this_month = 0
    
    await db.commit()
    
    return MessageResponse(
        message="All scan data has been deleted",
        success=True
    )


@router.get("/me/stats")
async def get_my_stats(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user's scan statistics.
    """
    scans, total = await crud.get_user_scans(db, current_user.id, limit=1000)
    
    # Calculate stats
    completed = sum(1 for s in scans if s.status == "completed")
    running = sum(1 for s in scans if s.status == "running")
    total_findings = sum(s.findings_count for s in scans)
    total_critical = sum(s.critical_count for s in scans)
    total_high = sum(s.high_count for s in scans)
    
    return {
        "total_scans": total,
        "completed_scans": completed,
        "running_scans": running,
        "total_findings": total_findings,
        "critical_findings": total_critical,
        "high_findings": total_high,
        "member_since": current_user.created_at.isoformat(),
        "plan": current_user.plan
    }


# ============== Subscription Endpoints ==============

@router.get("/me/subscription")
async def get_my_subscription(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get current user's subscription details, usage stats, and plan limits.
    This endpoint provides all information needed for the frontend to display
    plan limitations and feature availability.
    
    Uses SubscriptionManager for accurate ScanHistory-based counting.
    """
    # Use SubscriptionManager for accurate usage stats
    sub_manager = SubscriptionManager(db, current_user)
    usage_stats = await sub_manager.get_usage_stats()
    
    # Also sync the User.scans_this_month counter with actual count
    await sub_manager.sync_usage_counter()
    
    return usage_stats


@router.get("/me/subscription/check/{action}")
async def check_subscription_action(
    action: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Check if user can perform a specific action based on their subscription.
    Returns whether the action is allowed and any error message if not.
    
    Valid actions:
    - start_scan
    - add_website
    - add_team_member
    - api_testing
    - credential_scan
    - mobile_pentest
    - chatbot
    - compliance
    - generate_api_key
    """
    try:
        action_enum = SubscriptionAction(action)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid action: {action}. Valid actions: {[a.value for a in SubscriptionAction]}"
        )
    
    allowed, error_message = await check_subscription_limit(db, current_user, action_enum)
    
    return {
        "action": action,
        "allowed": allowed,
        "message": error_message,
        "plan": current_user.plan,
        "upgrade_url": "/pricing" if not allowed else None
    }


@router.get("/me/features")
async def get_my_features(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get list of features available to the current user based on their plan.
    """
    plan = current_user.plan or "free"
    config = get_plan_config(plan)
    
    features = config.get("features", {})
    feature_list = []
    
    feature_names = {
        "api_testing": "API Security Testing",
        "credential_scanning": "Credential & Secret Scanning",
        "mobile_pentest": "Mobile App Pentesting",
        "chatbot_access": "AI Security Chatbot",
        "compliance_audits": "Compliance Audits (SOC2, PCI-DSS)",
        "advanced_reporting": "Advanced Reporting (PDF, SARIF)",
        "priority_support": "Priority Support",
        "api_key_access": "API Key Access",
        "custom_integrations": "Custom Integrations",
        "sso": "SSO / SAML Integration",
    }
    
    for key, available in features.items():
        feature_list.append({
            "id": key,
            "name": feature_names.get(key, key.replace("_", " ").title()),
            "available": available,
            "required_plan": _get_min_plan_for_feature(key) if not available else None
        })
    
    return {
        "plan": plan,
        "plan_name": config.get("display_name", "Free"),
        "features": feature_list
    }


@router.get("/subscription/plans")
async def get_all_plans():
    """
    Get all available subscription plans with their limits and features.
    Public endpoint for pricing page.
    """
    plans = []
    for plan_id, config in PLAN_CONFIG.items():
        plans.append({
            "id": plan_id,
            "name": config.get("display_name", plan_id.title()),
            "price_monthly": config.get("price_monthly"),
            "price_per_scan": config.get("price_per_scan"),
            "limits": config.get("limits", {}),
            "features": config.get("features", {}),
        })
    return {"plans": plans}


def _get_min_plan_for_feature(feature: str) -> str:
    """Get the minimum plan required for a feature"""
    plan_order = ["free", "individual", "professional", "enterprise"]
    
    for plan in plan_order:
        config = PLAN_CONFIG.get(plan, {})
        if config.get("features", {}).get(feature, False):
            return plan
    
    return "enterprise"


# ============== Admin Routes ==============

@router.get("/", response_model=list[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db)
):
    """
    List all users (admin only).
    """
    users = await crud.get_users(db, skip=skip, limit=limit)
    return users


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    current_user: User = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db)
):
    """
    Get a specific user by ID (admin only).
    """
    from uuid import UUID
    
    try:
        user = await crud.get_user_by_id(db, UUID(user_id))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return user


@router.patch("/{user_id}/deactivate", response_model=MessageResponse)
async def deactivate_user(
    user_id: str,
    current_user: User = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db)
):
    """
    Deactivate a user account (admin only).
    """
    from uuid import UUID
    from database.auth import get_user_by_id, revoke_all_user_tokens
    
    try:
        user = await get_user_by_id(db, UUID(user_id))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot deactivate your own account"
        )
    
    user.is_active = False
    await db.commit()
    
    # Revoke all tokens
    await revoke_all_user_tokens(db, user.id)
    
    return MessageResponse(
        message=f"User {user.username} has been deactivated",
        success=True
    )


@router.patch("/{user_id}/activate", response_model=MessageResponse)
async def activate_user(
    user_id: str,
    current_user: User = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db)
):
    """
    Activate a user account (admin only).
    """
    from uuid import UUID
    from database.auth import get_user_by_id
    
    try:
        user = await get_user_by_id(db, UUID(user_id))
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid user ID format"
        )
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_active = True
    await db.commit()
    
    return MessageResponse(
        message=f"User {user.username} has been activated",
        success=True
    )
