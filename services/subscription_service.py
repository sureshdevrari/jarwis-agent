"""
Subscription Service

Centralized subscription management and enforcement.
Provides a clean interface for checking limits and features.
"""

import logging
from typing import Optional, Dict, Any, Tuple
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

from shared.constants import PLAN_LIMITS, PlanLimits
from database.models import User

logger = logging.getLogger(__name__)


class SubscriptionError(Exception):
    """Raised when subscription limit is exceeded"""
    def __init__(self, error_type: str, message: str, details: dict = None):
        self.error_type = error_type
        self.message = message
        self.details = details or {}
        super().__init__(message)


class SubscriptionService:
    """
    Subscription management service.
    
    Centralizes all subscription-related logic:
    - Checking plan limits
    - Enforcing usage quotas
    - Feature access control
    """
    
    @staticmethod
    def get_plan(plan_id: str) -> Optional[PlanLimits]:
        """Get plan configuration by ID"""
        return PLAN_LIMITS.get(plan_id.lower())
    
    @staticmethod
    def get_user_plan(user: User) -> PlanLimits:
        """Get the plan for a user, defaulting to free"""
        plan_id = getattr(user, 'plan', 'free') or 'free'
        return PLAN_LIMITS.get(plan_id.lower(), PLAN_LIMITS['free'])
    
    @classmethod
    def can_start_scan(cls, user: User, current_scan_count: int) -> Tuple[bool, Optional[str]]:
        """
        Check if user can start a new scan.
        
        Returns:
            Tuple of (can_start, error_message)
        """
        plan = cls.get_user_plan(user)
        
        if current_scan_count >= plan.max_scans_per_month:
            return False, f"Monthly scan limit reached ({plan.max_scans_per_month} scans). Upgrade your plan for more scans."
        
        return True, None
    
    @classmethod
    def can_use_feature(cls, user: User, feature: str) -> Tuple[bool, Optional[str]]:
        """
        Check if user's plan includes a specific feature.
        
        Args:
            user: The user to check
            feature: Feature name (e.g., 'mobile_app_testing', 'cloud_scanning')
            
        Returns:
            Tuple of (has_feature, error_message)
        """
        plan = cls.get_user_plan(user)
        features = plan.features
        
        # Map feature names to feature attributes
        feature_map = {
            'mobile': 'mobile_app_testing',
            'mobile_app_testing': 'mobile_app_testing',
            'cloud': 'cloud_scanning',
            'cloud_scanning': 'cloud_scanning',
            'api_testing': 'api_testing',
            'credential_scanning': 'credential_scanning',
            'authenticated_scanning': 'authenticated_scanning',
            'chatbot': 'chatbot_access',
            'chatbot_access': 'chatbot_access',
            'compliance_reports': 'compliance_reports',
            'ci_cd': 'ci_cd_integration',
            'webhooks': 'webhooks',
            'sso': 'sso_integration',
            'scheduled_scans': 'scheduled_scans',
        }
        
        attr_name = feature_map.get(feature, feature)
        has_feature = getattr(features, attr_name, False)
        
        if not has_feature:
            return False, f"Feature '{feature}' is not available in your {plan.name} plan. Please upgrade to access this feature."
        
        return True, None
    
    @classmethod
    def can_use_tokens(cls, user: User, current_usage: int, requested: int) -> Tuple[bool, Optional[str]]:
        """
        Check if user has enough tokens remaining.
        
        Returns:
            Tuple of (can_use, error_message)
        """
        plan = cls.get_user_plan(user)
        remaining = plan.tokens_per_month - current_usage
        
        if remaining < requested:
            return False, f"Insufficient tokens. You have {remaining:,} tokens remaining this month. Upgrade for more."
        
        return True, None
    
    @classmethod
    def get_usage_summary(cls, user: User, scans_used: int, tokens_used: int) -> Dict[str, Any]:
        """Get usage summary for dashboard display"""
        plan = cls.get_user_plan(user)
        
        return {
            "plan": plan.name,
            "plan_id": plan.id,
            "scans": {
                "used": scans_used,
                "limit": plan.max_scans_per_month,
                "remaining": max(0, plan.max_scans_per_month - scans_used),
                "unlimited": plan.max_scans_per_month >= 999999
            },
            "tokens": {
                "used": tokens_used,
                "limit": plan.tokens_per_month,
                "remaining": max(0, plan.tokens_per_month - tokens_used),
                "unlimited": plan.tokens_per_month >= 999999
            },
            "features": {
                "mobile_scanning": plan.features.mobile_app_testing,
                "cloud_scanning": plan.features.cloud_scanning,
                "api_testing": plan.features.api_testing,
                "authenticated_scanning": plan.features.authenticated_scanning,
                "chatbot": plan.features.chatbot_access,
            }
        }
    
    @classmethod
    async def enforce_scan_limit(
        cls, 
        db: AsyncSession, 
        user: User,
        scan_type: str = "web"
    ) -> None:
        """
        Enforce scan limits, raising exception if exceeded.
        
        Raises:
            SubscriptionError: If limit exceeded or feature not available
        """
        # Import here to avoid circular imports
        from database import crud
        
        # Check feature access for non-web scans
        if scan_type == "mobile":
            can_use, error = cls.can_use_feature(user, "mobile_app_testing")
            if not can_use:
                raise SubscriptionError(
                    "feature_not_available",
                    error,
                    {"feature": "mobile_app_testing", "plan": user.plan}
                )
        elif scan_type == "cloud":
            can_use, error = cls.can_use_feature(user, "cloud_scanning")
            if not can_use:
                raise SubscriptionError(
                    "feature_not_available",
                    error,
                    {"feature": "cloud_scanning", "plan": user.plan}
                )
        
        # Check scan count
        current_count = await crud.get_user_scan_count_this_month(db, user.id)
        can_scan, error = cls.can_start_scan(user, current_count)
        
        if not can_scan:
            plan = cls.get_user_plan(user)
            raise SubscriptionError(
                "subscription_limit_exceeded",
                error,
                {
                    "limit_type": "scans",
                    "current": current_count,
                    "limit": plan.max_scans_per_month,
                    "plan": user.plan
                }
            )
    
    @classmethod
    async def enforce_token_limit(
        cls,
        db: AsyncSession,
        user: User,
        requested_tokens: int
    ) -> None:
        """
        Enforce token limits, raising exception if exceeded.
        
        Raises:
            SubscriptionError: If insufficient tokens
        """
        # Import here to avoid circular imports
        from database import crud
        
        current_usage = await crud.get_user_token_usage_this_month(db, user.id)
        can_use, error = cls.can_use_tokens(user, current_usage, requested_tokens)
        
        if not can_use:
            plan = cls.get_user_plan(user)
            raise SubscriptionError(
                "token_limit_exceeded",
                error,
                {
                    "limit_type": "tokens",
                    "current": current_usage,
                    "requested": requested_tokens,
                    "limit": plan.tokens_per_month,
                    "plan": user.plan
                }
            )


# Global instance
subscription_service = SubscriptionService()
