"""
Subscription Enforcement Module
Handles plan limits, feature access, and usage tracking.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any, Tuple
from uuid import UUID as PyUUID

from fastapi import HTTPException, status, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_

from database.models import User, ScanHistory
from database.connection import get_db


class PlanType(str, Enum):
    """Available subscription plans"""
    FREE = "free"
    INDIVIDUAL = "individual"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class SubscriptionAction(str, Enum):
    """Actions that require subscription limit checks"""
    START_SCAN = "start_scan"
    ADD_WEBSITE = "add_website"
    ADD_TEAM_MEMBER = "add_team_member"
    ACCESS_API_TESTING = "api_testing"
    ACCESS_CREDENTIAL_SCAN = "credential_scan"
    ACCESS_MOBILE_PENTEST = "mobile_pentest"
    ACCESS_CLOUD_SCAN = "cloud_scanning"
    ACCESS_CHATBOT = "chatbot"
    ACCESS_COMPLIANCE = "compliance"
    GENERATE_API_KEY = "generate_api_key"


# Plan configuration with limits and features
PLAN_CONFIG: Dict[str, Dict[str, Any]] = {
    "free": {
        "display_name": "Free Trial",
        "price_monthly": 0,
        "limits": {
            "max_websites_per_month": 1,
            "max_scans_per_month": 3,
            "max_pages_per_scan": 25,
            "max_team_members": 1,
            "dashboard_access_days": 7,
        },
        "features": {
            "api_testing": False,
            "credential_scanning": False,
            "mobile_pentest": False,
            "cloud_scanning": False,  # No cloud for free
            "chatbot_access": False,
            "compliance_audits": False,
            "advanced_reporting": False,
            "priority_support": False,
            "api_key_access": False,
            "custom_integrations": False,
            "sso": False,
        }
    },
    "individual": {
        "display_name": "Individual",
        "price_per_scan": 20,  # Pay per scan
        "limits": {
            "max_websites_per_month": 1,  # Individual can only scan 1 website
            "max_scans_per_month": 5,
            "max_pages_per_scan": 100,
            "max_team_members": 1,
            "dashboard_access_days": 30,
        },
        "features": {
            "api_testing": False,  # No API testing for individual
            "credential_scanning": False,
            "mobile_pentest": False,  # No mobile for individual
            "cloud_scanning": False,  # No cloud for individual
            "chatbot_access": False,
            "compliance_audits": False,
            "advanced_reporting": False,  # Basic reporting only
            "priority_support": False,
            "api_key_access": False,
            "custom_integrations": False,
            "sso": False,
        }
    },
    "professional": {
        "display_name": "Professional",
        "price_monthly": 999,
        "limits": {
            "max_websites_per_month": 50,
            "max_scans_per_month": 100,
            "max_pages_per_scan": 500,
            "max_team_members": 10,
            "dashboard_access_days": 365,
        },
        "features": {
            "api_testing": True,
            "credential_scanning": True,
            "mobile_pentest": True,
            "cloud_scanning": True,  # Pro includes cloud scanning
            "chatbot_access": True,
            "compliance_audits": False,
            "advanced_reporting": True,
            "priority_support": True,
            "api_key_access": True,
            "custom_integrations": False,
            "sso": False,
        }
    },
    "enterprise": {
        "display_name": "Enterprise",
        "price_monthly": None,  # Custom pricing
        "limits": {
            "max_websites_per_month": 999999,  # Unlimited
            "max_scans_per_month": 999999,  # Unlimited
            "max_pages_per_scan": 10000,
            "max_team_members": 999999,  # Unlimited
            "dashboard_access_days": 999999,  # Unlimited
        },
        "features": {
            "api_testing": True,
            "credential_scanning": True,
            "mobile_pentest": True,
            "cloud_scanning": True,  # Enterprise includes cloud scanning
            "chatbot_access": True,
            "compliance_audits": True,
            "advanced_reporting": True,
            "priority_support": True,
            "api_key_access": True,
            "custom_integrations": True,
            "sso": True,
        }
    }
}


def get_plan_config(plan: str) -> Dict[str, Any]:
    """Get configuration for a specific plan"""
    return PLAN_CONFIG.get(plan, PLAN_CONFIG["free"])


def get_plan_limit(plan: str, limit_key: str) -> int:
    """Get a specific limit value for a plan"""
    config = get_plan_config(plan)
    return config.get("limits", {}).get(limit_key, 0)


def has_feature(plan: str, feature_key: str) -> bool:
    """Check if a plan has a specific feature"""
    config = get_plan_config(plan)
    return config.get("features", {}).get(feature_key, False)


async def get_user_scan_count_this_month(
    db: AsyncSession, 
    user_id: PyUUID
) -> int:
    """Get the number of scans a user has started this month"""
    # First day of current month
    today = datetime.utcnow()
    first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    result = await db.execute(
        select(func.count(ScanHistory.id)).where(
            and_(
                ScanHistory.user_id == user_id,
                ScanHistory.started_at >= first_of_month
            )
        )
    )
    return result.scalar() or 0


async def get_user_website_count_this_month(
    db: AsyncSession, 
    user_id: PyUUID
) -> int:
    """Get the number of unique websites a user has scanned this month"""
    today = datetime.utcnow()
    first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    result = await db.execute(
        select(func.count(func.distinct(ScanHistory.target_url))).where(
            and_(
                ScanHistory.user_id == user_id,
                ScanHistory.started_at >= first_of_month
            )
        )
    )
    return result.scalar() or 0


async def check_subscription_limit(
    db: AsyncSession,
    user: User,
    action: SubscriptionAction,
    increment: int = 1
) -> Tuple[bool, Optional[str]]:
    """
    Check if user can perform an action based on their subscription.
    
    Returns:
        Tuple[bool, Optional[str]]: (allowed, error_message)
    """
    plan = user.plan or "free"
    config = get_plan_config(plan)
    limits = config.get("limits", {})
    features = config.get("features", {})
    
    # Check subscription validity for paid plans
    if plan != "free":
        if user.subscription_end and user.subscription_end < datetime.utcnow():
            return False, "Your subscription has expired. Please renew to continue."
    
    # Feature-based checks
    feature_checks = {
        SubscriptionAction.ACCESS_API_TESTING: ("api_testing", "API Testing"),
        SubscriptionAction.ACCESS_CREDENTIAL_SCAN: ("credential_scanning", "Credential Scanning"),
        SubscriptionAction.ACCESS_MOBILE_PENTEST: ("mobile_pentest", "Mobile Pentesting"),
        SubscriptionAction.ACCESS_CLOUD_SCAN: ("cloud_scanning", "Cloud Scanning"),
        SubscriptionAction.ACCESS_CHATBOT: ("chatbot_access", "AI Chatbot"),
        SubscriptionAction.ACCESS_COMPLIANCE: ("compliance_audits", "Compliance Audits"),
        SubscriptionAction.GENERATE_API_KEY: ("api_key_access", "API Key Access"),
    }
    
    if action in feature_checks:
        feature_key, feature_name = feature_checks[action]
        if not features.get(feature_key, False):
            return False, f"{feature_name} is not available on your {config['display_name']} plan. Please upgrade."
        return True, None
    
    # Usage-based checks
    if action == SubscriptionAction.START_SCAN:
        current_count = await get_user_scan_count_this_month(db, user.id)
        max_scans = limits.get("max_scans_per_month", 3)
        
        if current_count + increment > max_scans:
            remaining = max(0, max_scans - current_count)
            return False, (
                f"You've reached your monthly scan limit ({current_count}/{max_scans}). "
                f"You have {remaining} scans remaining. Upgrade for more scans."
            )
        return True, None
    
    if action == SubscriptionAction.ADD_WEBSITE:
        current_count = await get_user_website_count_this_month(db, user.id)
        max_websites = limits.get("max_websites_per_month", 1)
        
        if current_count + increment > max_websites:
            return False, (
                f"You've reached your monthly website limit ({current_count}/{max_websites}). "
                "Upgrade for more websites."
            )
        return True, None
    
    if action == SubscriptionAction.ADD_TEAM_MEMBER:
        max_members = limits.get("max_team_members", 1)
        if max_members <= 1:
            return False, "Team collaboration is not available on your plan. Upgrade to Professional or Enterprise."
        # Would need to count current team members here
        return True, None
    
    return True, None


async def enforce_subscription_limit(
    db: AsyncSession,
    user: User,
    action: SubscriptionAction,
    increment: int = 1
) -> None:
    """
    Enforce subscription limit - raises HTTPException if limit exceeded.
    Use this in API endpoints to block unauthorized actions.
    """
    allowed, error_message = await check_subscription_limit(db, user, action, increment)
    
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "subscription_limit_exceeded",
                "message": error_message,
                "action": action.value,
                "plan": user.plan,
                "upgrade_url": "/pricing"
            }
        )


async def get_user_usage_stats(
    db: AsyncSession,
    user: User
) -> Dict[str, Any]:
    """Get current usage statistics for a user"""
    plan = user.plan or "free"
    config = get_plan_config(plan)
    limits = config.get("limits", {})
    features = config.get("features", {})
    
    # Get current usage
    scans_this_month = await get_user_scan_count_this_month(db, user.id)
    websites_this_month = await get_user_website_count_this_month(db, user.id)
    
    return {
        "plan": {
            "id": plan,
            "name": config.get("display_name", "Free"),
            "is_active": True if plan == "free" else (
                user.subscription_end is None or 
                user.subscription_end > datetime.utcnow()
            ),
            "expires_at": user.subscription_end.isoformat() if user.subscription_end else None,
        },
        "usage": {
            "scans": {
                "used": scans_this_month,
                "limit": limits.get("max_scans_per_month", 3),
                "remaining": max(0, limits.get("max_scans_per_month", 3) - scans_this_month),
            },
            "websites": {
                "used": websites_this_month,
                "limit": limits.get("max_websites_per_month", 1),
                "remaining": max(0, limits.get("max_websites_per_month", 1) - websites_this_month),
            },
            "team_members": {
                "used": 1,  # Would need to count actual team members
                "limit": limits.get("max_team_members", 1),
            },
        },
        "limits": limits,
        "features": features,
        "billing_cycle_start": datetime.utcnow().replace(day=1).isoformat(),
        "billing_cycle_end": (
            datetime.utcnow().replace(day=1) + timedelta(days=32)
        ).replace(day=1, hour=0, minute=0, second=0, microsecond=0).isoformat(),
    }


# FastAPI dependency for subscription enforcement
def require_feature(feature: str):
    """
    Dependency factory for requiring a specific feature.
    Usage: Depends(require_feature("api_testing"))
    """
    async def check_feature(
        user: User = Depends(get_current_user_from_deps),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        plan = user.plan or "free"
        if not has_feature(plan, feature):
            config = get_plan_config(plan)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "feature_not_available",
                    "message": f"This feature is not available on your {config['display_name']} plan.",
                    "feature": feature,
                    "plan": plan,
                    "upgrade_url": "/pricing"
                }
            )
        return user
    return check_feature


def require_scan_quota():
    """
    Dependency for checking scan quota before starting a scan.
    """
    async def check_quota(
        user: User = Depends(get_current_user_from_deps),
        db: AsyncSession = Depends(get_db)
    ) -> User:
        await enforce_subscription_limit(db, user, SubscriptionAction.START_SCAN)
        return user
    return check_quota


# Import here to avoid circular imports
def get_current_user_from_deps():
    from database.dependencies import get_current_user
    return Depends(get_current_user)


async def increment_usage_counter(
    db: AsyncSession,
    user_id: PyUUID,
    counter: str = "scans"
) -> None:
    """
    Increment a usage counter for the user.
    This is called after a scan successfully starts.
    """
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if user and counter == "scans":
        user.scans_this_month = (user.scans_this_month or 0) + 1
        await db.commit()


async def decrement_usage_counter(
    db: AsyncSession,
    user_id: PyUUID,
    counter: str = "scans"
) -> None:
    """
    Decrement a usage counter for the user (rollback).
    This is called when a scan fails to refund the credit.
    """
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if user and counter == "scans":
        # Only decrement if greater than 0
        if (user.scans_this_month or 0) > 0:
            user.scans_this_month = user.scans_this_month - 1
            await db.commit()


async def reset_monthly_counters(db: AsyncSession) -> int:
    """
    Reset monthly usage counters for all users.
    Should be run as a scheduled task at the start of each month.
    Returns count of users updated.
    """
    from sqlalchemy import update
    
    result = await db.execute(
        update(User).values(scans_this_month=0)
    )
    await db.commit()
    return result.rowcount
