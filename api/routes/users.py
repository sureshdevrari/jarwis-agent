"""
User Management API Routes
Profile management, user updates, account deletion
"""

from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.schemas import UserResponse, UserUpdate, MessageResponse
from database.auth import get_user_by_email, get_user_by_username, hash_password
from database.dependencies import get_current_active_user, get_current_superuser
from database.subscription import (
    get_user_usage_stats, 
    check_subscription_limit, 
    SubscriptionAction,
    get_plan_config,
    PLAN_CONFIG
)
from database import crud

router = APIRouter(prefix="/api/users", tags=["Users"])


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
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Delete current user's account.
    This action is irreversible!
    """
    await crud.delete_user(db, current_user)
    
    return MessageResponse(
        message="Account deleted successfully",
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
    """
    usage_stats = await get_user_usage_stats(db, current_user)
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
