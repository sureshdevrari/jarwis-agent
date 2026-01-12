"""
Subscription Manager Service
============================
Centralized subscription management for all scan-related limits and features.
This is the SINGLE POINT of enforcement for subscription limits.

Usage:
    from services.subscription_manager import SubscriptionManager
    
    # Check if user can start a scan
    manager = SubscriptionManager(db, user)
    await manager.check_scan_quota()  # Raises HTTPException if exceeded
    
    # Deduct a scan after it starts
    await manager.deduct_scan(scan_id)
    
    # Refund a scan if it fails
    await manager.refund_scan(scan_id)
    
    # Get usage stats for billing page
    stats = await manager.get_usage_stats()
"""

import logging
from typing import Optional, Dict, Any, Tuple
from datetime import datetime, timedelta
from uuid import UUID as PyUUID

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, update

from database.models import User, ScanHistory
from shared.plans import PlanManager, PlanId, FeatureId, LimitId, UNLIMITED

logger = logging.getLogger(__name__)


class SubscriptionLimitError(Exception):
    """Raised when a subscription limit is exceeded"""
    def __init__(
        self, 
        error_type: str, 
        message: str, 
        plan: str,
        current_usage: int = 0,
        limit: int = 0,
        upgrade_url: str = "/pricing"
    ):
        self.error_type = error_type
        self.message = message
        self.plan = plan
        self.current_usage = current_usage
        self.limit = limit
        self.upgrade_url = upgrade_url
        super().__init__(message)
    
    def to_http_exception(self) -> HTTPException:
        """Convert to FastAPI HTTPException"""
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": self.error_type,
                "message": self.message,
                "plan": self.plan,
                "current_usage": self.current_usage,
                "limit": self.limit,
                "upgrade_url": self.upgrade_url,
            }
        )


class SubscriptionManager:
    """
    Centralized subscription management.
    
    Handles:
    - Scan quota checking and enforcement
    - Feature access control
    - Usage tracking (scan counts from ScanHistory - source of truth)
    - Refund logic for failed scans
    
    IMPORTANT: This class uses ScanHistory as the source of truth for scan counts,
    NOT User.scans_this_month counter (which can get out of sync).
    """
    
    def __init__(self, db: AsyncSession, user: User):
        self.db = db
        self.user = user
        self.plan_id = user.plan or PlanId.FREE.value
        self.plan = PlanManager.get_plan(self.plan_id)
    
    # =========================================================================
    # SCAN QUOTA MANAGEMENT
    # =========================================================================
    
    async def get_scans_used_this_month(self) -> int:
        """
        Get the actual number of scans used this month from ScanHistory.
        
        This is the SOURCE OF TRUTH for scan counts.
        
        Counts:
        - Completed scans
        - Running/queued scans  
        - Failed/stopped scans that were blocked from refund (abuse prevention)
        
        Does NOT count:
        - Failed scans that were refunded
        - Stopped scans that were refunded
        """
        today = datetime.utcnow()
        first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        result = await self.db.execute(
            select(func.count(ScanHistory.id)).where(
                and_(
                    ScanHistory.user_id == self.user.id,
                    ScanHistory.started_at >= first_of_month,
                    # Only count scans that should use quota:
                    or_(
                        # Active/completed scans always count
                        ScanHistory.status.in_(['completed', 'running', 'queued']),
                        # Failed/stopped scans count only if refund was blocked
                        and_(
                            ScanHistory.status.in_(['error', 'stopped']),
                            ScanHistory.refund_blocked == True
                        )
                    )
                )
            )
        )
        return result.scalar() or 0
    
    async def get_scan_limit(self) -> int:
        """Get the user's monthly scan limit from their plan"""
        return self.plan.limits.max_scans_per_month
    
    async def get_scans_remaining(self) -> int:
        """Get remaining scans this month"""
        limit = await self.get_scan_limit()
        if limit == UNLIMITED:
            return UNLIMITED
        used = await self.get_scans_used_this_month()
        return max(0, limit - used)
    
    async def check_scan_quota(self, increment: int = 1) -> Tuple[bool, Optional[str]]:
        """
        Check if user can start a new scan.
        
        Args:
            increment: Number of scans to check for (usually 1)
            
        Returns:
            Tuple of (allowed, error_message)
        """
        # Check subscription expiry for paid plans
        if self.plan_id not in [PlanId.FREE.value, PlanId.TRIAL.value]:
            if self.user.subscription_end and self.user.subscription_end < datetime.utcnow():
                return False, "Your subscription has expired. Please renew to continue."
        
        limit = await self.get_scan_limit()
        
        # Unlimited plan
        if limit == UNLIMITED:
            return True, None
        
        used = await self.get_scans_used_this_month()
        
        if used + increment > limit:
            remaining = max(0, limit - used)
            return False, (
                f"You've reached your monthly scan limit ({used}/{limit}). "
                f"You have {remaining} scans remaining. "
                "Upgrade your plan for more scans."
            )
        
        return True, None
    
    async def enforce_scan_quota(self, increment: int = 1) -> None:
        """
        Enforce scan quota - raises HTTPException if exceeded.
        Use this in API endpoints before starting a scan.
        """
        allowed, error_message = await self.check_scan_quota(increment)
        
        if not allowed:
            raise SubscriptionLimitError(
                error_type="scan_limit_exceeded",
                message=error_message,
                plan=self.plan_id,
                current_usage=await self.get_scans_used_this_month(),
                limit=await self.get_scan_limit(),
            ).to_http_exception()
    
    async def deduct_scan(self, scan_id: str) -> bool:
        """
        Record that a scan has been started.
        
        Note: The actual deduction happens automatically because we count
        from ScanHistory. This method is here for explicit tracking
        and can update User.scans_this_month for backward compatibility.
        
        Returns:
            True if deduction was successful
        """
        # Update User.scans_this_month for backward compatibility with UI
        # The real source of truth is ScanHistory
        self.user.scans_this_month = await self.get_scans_used_this_month()
        await self.db.commit()
        
        logger.info(f"Scan {scan_id} deducted for user {self.user.id}. "
                   f"Usage: {self.user.scans_this_month}/{await self.get_scan_limit()}")
        return True
    
    async def refund_scan(self, scan_id: str, reason: str = "scan_failed") -> bool:
        """
        Refund a scan credit if the scan failed/was stopped.
        
        This works by NOT counting the scan in get_scans_used_this_month()
        since failed scans with refund_blocked=False are excluded.
        
        Args:
            scan_id: The scan to refund
            reason: Reason for refund (for logging)
            
        Returns:
            True if refund was processed
        """
        # The refund is automatic because failed scans without refund_blocked
        # are not counted in get_scans_used_this_month()
        
        # Update User.scans_this_month for backward compatibility
        self.user.scans_this_month = await self.get_scans_used_this_month()
        await self.db.commit()
        
        logger.info(f"Scan {scan_id} refunded for user {self.user.id} (reason: {reason}). "
                   f"Usage: {self.user.scans_this_month}/{await self.get_scan_limit()}")
        return True
    
    async def block_refund(self, scan_id: str, reason: str = "abuse_detected") -> bool:
        """
        Block refund for a scan (abuse prevention).
        
        When refund_blocked=True, the scan counts against limit even if failed/stopped.
        
        Args:
            scan_id: The scan to block refund for
            reason: Reason for blocking (for logging/audit)
            
        Returns:
            True if block was successful
        """
        result = await self.db.execute(
            select(ScanHistory).where(
                and_(
                    ScanHistory.scan_id == scan_id,
                    ScanHistory.user_id == self.user.id
                )
            )
        )
        scan = result.scalar_one_or_none()
        
        if scan:
            scan.refund_blocked = True
            await self.db.commit()
            logger.warning(f"Refund blocked for scan {scan_id} (reason: {reason})")
            return True
        
        return False
    
    # =========================================================================
    # FEATURE ACCESS CONTROL
    # =========================================================================
    
    def has_feature(self, feature_id: str) -> bool:
        """Check if user's plan includes a specific feature"""
        return PlanManager.has_feature(self.plan_id, feature_id)
    
    def check_feature(self, feature_id: str, feature_name: str = None) -> Tuple[bool, Optional[str]]:
        """
        Check if user can access a feature.
        
        Returns:
            Tuple of (allowed, error_message)
        """
        if self.has_feature(feature_id):
            return True, None
        
        display_name = feature_name or feature_id.replace("_", " ").title()
        return False, (
            f"{display_name} is not available on your {self.plan.display_name} plan. "
            "Please upgrade to access this feature."
        )
    
    def enforce_feature(self, feature_id: str, feature_name: str = None) -> None:
        """
        Enforce feature access - raises HTTPException if not available.
        """
        allowed, error_message = self.check_feature(feature_id, feature_name)
        
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail={
                    "error": "feature_not_available",
                    "message": error_message,
                    "feature": feature_id,
                    "plan": self.plan_id,
                    "upgrade_url": "/pricing",
                }
            )
    
    # =========================================================================
    # USAGE STATISTICS
    # =========================================================================
    
    async def get_websites_used_this_month(self) -> int:
        """Get the number of unique websites scanned this month"""
        today = datetime.utcnow()
        first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        result = await self.db.execute(
            select(func.count(func.distinct(ScanHistory.target_url))).where(
                and_(
                    ScanHistory.user_id == self.user.id,
                    ScanHistory.started_at >= first_of_month
                )
            )
        )
        return result.scalar() or 0
    
    async def get_usage_stats(self) -> Dict[str, Any]:
        """
        Get comprehensive usage statistics for billing page.
        
        This is the authoritative source for usage display.
        """
        scans_used = await self.get_scans_used_this_month()
        scans_limit = await self.get_scan_limit()
        websites_used = await self.get_websites_used_this_month()
        websites_limit = self.plan.limits.max_websites_per_month
        
        # Calculate billing cycle
        today = datetime.utcnow()
        billing_start = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        next_month = (billing_start + timedelta(days=32)).replace(day=1)
        
        return {
            "plan": {
                "id": self.plan_id,
                "name": self.plan.display_name,
                "is_active": self._is_plan_active(),
                "expires_at": self.user.subscription_end.isoformat() if self.user.subscription_end else None,
            },
            "usage": {
                "scans": {
                    "used": scans_used,
                    "limit": scans_limit,
                    "remaining": UNLIMITED if scans_limit == UNLIMITED else max(0, scans_limit - scans_used),
                    "unlimited": scans_limit == UNLIMITED,
                },
                "websites": {
                    "used": websites_used,
                    "limit": websites_limit,
                    "remaining": UNLIMITED if websites_limit == UNLIMITED else max(0, websites_limit - websites_used),
                    "unlimited": websites_limit == UNLIMITED,
                },
                "team_members": {
                    "used": 1,  # TODO: Count actual team members
                    "limit": self.plan.limits.max_team_members,
                    "unlimited": self.plan.limits.max_team_members == UNLIMITED,
                },
            },
            "limits": {
                "max_scans_per_month": scans_limit,
                "max_websites_per_month": websites_limit,
                "max_pages_per_scan": self.plan.limits.max_pages_per_scan,
                "max_team_members": self.plan.limits.max_team_members,
            },
            "features": {
                "api_testing": self.has_feature("api_testing"),
                "credential_scanning": self.has_feature("credential_scanning"),
                "mobile_pentest": self.has_feature("mobile_pentest"),
                "network_scan": self.has_feature("network_scan"),
                "cloud_scanning": self.has_feature("cloud_scanning"),
                "sast_scanning": self.has_feature("sast_scanning"),
                "chatbot_access": self.has_feature("chatbot_access"),
                "scheduled_scans": self.has_feature("scheduled_scans"),
            },
            "billing_cycle": {
                "start": billing_start.isoformat(),
                "end": next_month.isoformat(),
            },
        }
    
    def _is_plan_active(self) -> bool:
        """Check if user's subscription is active"""
        if self.plan_id in [PlanId.FREE.value, PlanId.TRIAL.value]:
            return True
        
        if self.user.subscription_end is None:
            return True
        
        return self.user.subscription_end > datetime.utcnow()
    
    # =========================================================================
    # SYNC UTILITIES
    # =========================================================================
    
    async def sync_usage_counter(self) -> int:
        """
        Sync User.scans_this_month with actual ScanHistory count.
        
        Call this if you suspect the counter is out of sync.
        Returns the corrected count.
        """
        actual_count = await self.get_scans_used_this_month()
        
        if self.user.scans_this_month != actual_count:
            logger.warning(
                f"User {self.user.id} scan counter out of sync: "
                f"counter={self.user.scans_this_month}, actual={actual_count}"
            )
            self.user.scans_this_month = actual_count
            await self.db.commit()
        
        return actual_count


# =============================================================================
# FASTAPI DEPENDENCIES
# =============================================================================

def get_subscription_manager(db: AsyncSession, user: User) -> SubscriptionManager:
    """Factory function to create SubscriptionManager"""
    return SubscriptionManager(db, user)


async def require_scan_quota(db: AsyncSession, user: User) -> User:
    """
    FastAPI dependency that enforces scan quota.
    
    Usage:
        @router.post("/scan")
        async def start_scan(
            user: User = Depends(require_scan_quota)
        ):
            ...
    """
    manager = SubscriptionManager(db, user)
    await manager.enforce_scan_quota()
    return user


def require_feature(feature_id: str, feature_name: str = None):
    """
    FastAPI dependency factory for requiring a specific feature.
    
    Usage:
        @router.post("/mobile/scan")
        async def mobile_scan(
            user: User = Depends(require_feature("mobile_pentest", "Mobile Pentesting"))
        ):
            ...
    """
    async def check_feature(db: AsyncSession, user: User) -> User:
        manager = SubscriptionManager(db, user)
        manager.enforce_feature(feature_id, feature_name)
        return user
    
    return check_feature


# =============================================================================
# STANDALONE FUNCTIONS (Backward Compatibility)
# =============================================================================

async def get_user_scan_count_this_month(db: AsyncSession, user_id: PyUUID) -> int:
    """
    Get scan count for a user this month.
    
    Backward compatible function - use SubscriptionManager.get_scans_used_this_month()
    for new code.
    """
    today = datetime.utcnow()
    first_of_month = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    
    result = await db.execute(
        select(func.count(ScanHistory.id)).where(
            and_(
                ScanHistory.user_id == user_id,
                ScanHistory.started_at >= first_of_month,
                or_(
                    ScanHistory.status.in_(['completed', 'running', 'queued']),
                    and_(
                        ScanHistory.status.in_(['error', 'stopped']),
                        ScanHistory.refund_blocked == True
                    )
                )
            )
        )
    )
    return result.scalar() or 0


async def sync_all_user_counters(db: AsyncSession) -> int:
    """
    Sync all users' scans_this_month counters with actual ScanHistory counts.
    
    Run this as a maintenance task if counters get out of sync.
    Returns count of users updated.
    """
    result = await db.execute(select(User))
    users = result.scalars().all()
    
    updated = 0
    for user in users:
        manager = SubscriptionManager(db, user)
        actual_count = await manager.get_scans_used_this_month()
        
        if user.scans_this_month != actual_count:
            user.scans_this_month = actual_count
            updated += 1
    
    await db.commit()
    logger.info(f"Synced scan counters for {updated} users")
    return updated
