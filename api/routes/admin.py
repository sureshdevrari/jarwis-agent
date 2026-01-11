"""
Admin Routes for User Management
Provides endpoints for admin panel operations
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy import select, func, desc
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel, EmailStr

from database.connection import get_db
from database.models import User, ScanHistory
from database.schemas import UserResponse, MessageResponse
from database.dependencies import get_current_superuser, get_current_active_user


router = APIRouter(prefix="/api/admin", tags=["Admin"])


# ============== Request/Response Models ==============

class UserListResponse(BaseModel):
    """Paginated user list response"""
    users: List[dict]
    total: int
    page: int
    per_page: int


class UserUpdateRequest(BaseModel):
    """Admin update user request"""
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    is_superuser: Optional[bool] = None
    plan: Optional[str] = None


class ApproveUserRequest(BaseModel):
    """Request to approve user with plan selection"""
    plan: str = "free"  # free, individual, professional, enterprise


class SetPlanRequest(BaseModel):
    """Request to set user plan"""
    plan: str


class AdminUserResponse(BaseModel):
    """Detailed user info for admin"""
    id: UUID
    email: str
    username: str
    full_name: Optional[str] = None
    company: Optional[str] = None
    is_active: bool
    is_verified: bool
    is_superuser: bool
    plan: str
    role: str
    approval_status: str
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    scans_count: int = 0


class DashboardStats(BaseModel):
    """Admin dashboard statistics"""
    total_users: int
    pending_users: int
    approved_users: int
    total_scans: int
    active_scans: int


# ============== Helper Functions ==============

def get_user_role(user: User) -> str:
    """Determine user role"""
    if user.is_superuser:
        return "super_admin"
    return "user"


def get_approval_status(user: User) -> str:
    """Determine approval status - uses actual approval_status field"""
    if not user.is_active:
        return "disabled"
    # Use actual approval_status from database
    if user.approval_status:
        return user.approval_status
    # Fallback for legacy users
    if user.is_verified:
        return "approved"
    return "pending"


# ============== Admin Check ==============

async def check_admin_access(
    current_user: User = Depends(get_current_active_user)
) -> User:
    """Check if user has admin access (superuser or verified admin)"""
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


# ============== Dashboard ==============

@router.get("/dashboard", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """Get admin dashboard statistics"""
    # Total users
    total_result = await db.execute(select(func.count(User.id)))
    total_users = total_result.scalar_one()
    
    # Pending users (not verified)
    pending_result = await db.execute(
        select(func.count(User.id)).where(User.is_verified == False)
    )
    pending_users = pending_result.scalar_one()
    
    # Approved users (verified)
    approved_result = await db.execute(
        select(func.count(User.id)).where(User.is_verified == True)
    )
    approved_users = approved_result.scalar_one()
    
    # Total scans
    scans_result = await db.execute(select(func.count(ScanHistory.id)))
    total_scans = scans_result.scalar_one()
    
    # Active scans
    active_result = await db.execute(
        select(func.count(ScanHistory.id)).where(
            ScanHistory.status.in_(["queued", "running"])
        )
    )
    active_scans = active_result.scalar_one()
    
    return DashboardStats(
        total_users=total_users,
        pending_users=pending_users,
        approved_users=approved_users,
        total_scans=total_scans,
        active_scans=active_scans
    )


# ============== User Management ==============

@router.get("/users", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: Optional[str] = Query(None, description="pending, approved, disabled, email_unverified"),
    search: Optional[str] = Query(None, description="Search email or username"),
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """List all users with pagination and filters"""
    # Base query - exclude email_unverified users by default (unless specifically requested)
    query = select(User)
    count_query = select(func.count(User.id))
    
    # Apply status filter using actual approval_status field
    if status_filter == "pending":
        # Only show users with approval_status = "pending" (verified email, awaiting admin approval)
        query = query.where(User.approval_status == "pending", User.is_active == True)
        count_query = count_query.where(User.approval_status == "pending", User.is_active == True)
    elif status_filter == "approved":
        query = query.where(User.approval_status == "approved")
        count_query = count_query.where(User.approval_status == "approved")
    elif status_filter == "disabled":
        query = query.where(User.is_active == False)
        count_query = count_query.where(User.is_active == False)
    elif status_filter == "email_unverified":
        # Special filter to see users who haven't verified email yet
        query = query.where(User.approval_status == "email_unverified")
        count_query = count_query.where(User.approval_status == "email_unverified")
    elif status_filter is None:
        # By default, exclude email_unverified users from the main list
        query = query.where(User.approval_status != "email_unverified")
        count_query = count_query.where(User.approval_status != "email_unverified")
    
    # Apply search filter
    if search:
        search_pattern = f"%{search}%"
        query = query.where(
            (User.email.ilike(search_pattern)) | 
            (User.username.ilike(search_pattern)) |
            (User.full_name.ilike(search_pattern))
        )
        count_query = count_query.where(
            (User.email.ilike(search_pattern)) | 
            (User.username.ilike(search_pattern)) |
            (User.full_name.ilike(search_pattern))
        )
    
    # Get total count
    total_result = await db.execute(count_query)
    total = total_result.scalar_one()
    
    # Apply pagination and ordering
    offset = (page - 1) * per_page
    query = query.order_by(desc(User.created_at)).offset(offset).limit(per_page)
    
    # Execute query
    result = await db.execute(query)
    users = result.scalars().all()
    
    # Format response
    users_data = []
    for user in users:
        # Get scan count for each user
        scan_count_result = await db.execute(
            select(func.count(ScanHistory.id)).where(ScanHistory.user_id == user.id)
        )
        scan_count = scan_count_result.scalar_one()
        
        users_data.append({
            "id": str(user.id),
            "email": user.email,
            "username": user.username,
            "full_name": user.full_name,
            "company": user.company,
            "is_active": user.is_active,
            "is_verified": user.is_verified,
            "is_superuser": user.is_superuser,
            "plan": user.plan,
            "role": get_user_role(user),
            "approval_status": get_approval_status(user),
            "oauth_provider": user.oauth_provider,
            "avatar_url": user.avatar_url,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "scans_count": scan_count
        })
    
    return UserListResponse(
        users=users_data,
        total=total,
        page=page,
        per_page=per_page
    )


@router.get("/users/{user_id}", response_model=AdminUserResponse)
async def get_user_details(
    user_id: UUID,
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """Get detailed user information"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Get scan count
    scan_count_result = await db.execute(
        select(func.count(ScanHistory.id)).where(ScanHistory.user_id == user.id)
    )
    scan_count = scan_count_result.scalar_one()
    
    return AdminUserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        company=user.company,
        is_active=user.is_active,
        is_verified=user.is_verified,
        is_superuser=user.is_superuser,
        plan=user.plan,
        role=get_user_role(user),
        approval_status=get_approval_status(user),
        created_at=user.created_at,
        updated_at=user.updated_at,
        last_login=user.last_login,
        scans_count=scan_count
    )


@router.put("/users/{user_id}", response_model=AdminUserResponse)
async def update_user(
    user_id: UUID,
    data: UserUpdateRequest,
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """Update user (admin only)"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent self-demotion for superusers
    if user.id == current_user.id and data.is_superuser == False:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own superuser status"
        )
    
    # Apply updates
    if data.is_active is not None:
        user.is_active = data.is_active
    if data.is_verified is not None:
        user.is_verified = data.is_verified
    if data.is_superuser is not None:
        user.is_superuser = data.is_superuser
    if data.plan is not None:
        user.plan = data.plan
    
    user.updated_at = datetime.utcnow()
    await db.commit()
    await db.refresh(user)
    
    return await get_user_details(user_id, current_user, db)


# Plan features configuration
PLAN_FEATURES = {
    "free": {
        "max_websites": 0,  # Admin assigns after approval
        "max_scans_per_month": 0,  # Admin assigns quota
        "max_users": 1,
        "dashboard_access_days": 7,
        "has_api_testing": False,
        "has_credential_scanning": False,
        "has_chatbot_access": False,
        "has_mobile_pentest": False,
        "has_cloud_scanning": False,
        "has_network_scanning": False,
        "has_compliance_audits": False,
        "has_dedicated_support": False,
    },
    "individual": {
        "max_websites": 1,  # 1 website only
        "max_scans_per_month": 1,
        "max_users": 1,
        "dashboard_access_days": 7,
        "has_api_testing": False,  # No API testing
        "has_credential_scanning": False,  # No credential-based scanning
        "has_chatbot_access": False,  # No Jarwis AGI
        "has_mobile_pentest": False,  # Web only
        "has_cloud_scanning": False,  # Web only
        "has_network_scanning": False,  # Web only
        "has_compliance_audits": False,
        "has_dedicated_support": False,
    },
    "professional": {
        "max_websites": 10,
        "max_scans_per_month": 10,
        "max_users": 3,
        "dashboard_access_days": 0,  # Until plan active
        "has_api_testing": True,
        "has_credential_scanning": True,
        "has_chatbot_access": True,
        "has_mobile_pentest": True,
        "has_cloud_scanning": True,
        "has_network_scanning": True,
        "has_compliance_audits": True,
        "has_dedicated_support": False,
    },
    "enterprise": {
        "max_websites": 999999,
        "max_scans_per_month": 999999,
        "max_users": 999999,
        "dashboard_access_days": 0,  # Until plan active (365 days for compliance)
        "has_api_testing": True,
        "has_credential_scanning": True,
        "has_chatbot_access": True,
        "has_mobile_pentest": True,
        "has_cloud_scanning": True,
        "has_network_scanning": True,
        "has_compliance_audits": True,
        "has_dedicated_support": True,
    },
}


def apply_plan_features(user: User, plan: str, custom_scan_quota: int = None) -> None:
    """Apply plan features to user
    
    Args:
        user: User object to update
        plan: Plan name (free, individual, professional, enterprise)
        custom_scan_quota: For free users, admin can set custom scan quota
    """
    features = PLAN_FEATURES.get(plan, PLAN_FEATURES["free"])
    user.plan = plan
    user.max_websites = features["max_websites"]
    user.max_users = features["max_users"]
    user.dashboard_access_days = features["dashboard_access_days"]
    user.has_api_testing = features["has_api_testing"]
    user.has_credential_scanning = features["has_credential_scanning"]
    user.has_chatbot_access = features["has_chatbot_access"]
    user.has_mobile_pentest = features["has_mobile_pentest"]
    user.has_compliance_audits = features["has_dedicated_support"]
    user.has_dedicated_support = features["has_dedicated_support"]
    
    # Set scan quota - for free users, use custom_scan_quota if provided
    if custom_scan_quota is not None and plan == "free":
        user.max_scans_per_month = custom_scan_quota
    else:
        user.max_scans_per_month = features.get("max_scans_per_month", 0)
    
    # Set cloud and network scanning (check if user model has these fields)
    if hasattr(user, 'has_cloud_scanning'):
        user.has_cloud_scanning = features.get("has_cloud_scanning", False)
    if hasattr(user, 'has_network_scanning'):
        user.has_network_scanning = features.get("has_network_scanning", False)


@router.post("/users/{user_id}/approve", response_model=MessageResponse)
async def approve_user(
    user_id: UUID,
    request: ApproveUserRequest = None,
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """Approve a pending user with plan assignment"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User is already approved"
        )
    
    # Get plan from request or default to free
    plan = request.plan if request else "free"
    if plan not in PLAN_FEATURES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan. Must be one of: {', '.join(PLAN_FEATURES.keys())}"
        )
    
    # Apply plan features and approve user
    apply_plan_features(user, plan)
    user.is_verified = True
    user.approval_status = "approved"
    user.updated_at = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(message=f"User {user.email} has been approved with {plan} plan")


@router.post("/users/{user_id}/reject", response_model=MessageResponse)
async def reject_user(
    user_id: UUID,
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """Reject/disable a user"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot disable your own account"
        )
    
    user.is_active = False
    user.updated_at = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(message=f"User {user.email} has been disabled")


@router.post("/users/{user_id}/reset-status", response_model=MessageResponse)
async def reset_user_status(
    user_id: UUID,
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """Reset user to pending status"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_verified = False
    user.is_active = True
    user.updated_at = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(message=f"User {user.email} status has been reset to pending")


@router.delete("/users/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: UUID,
    current_user: User = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db)
):
    """Delete a user (superuser only)"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    email = user.email
    await db.delete(user)
    await db.commit()
    
    return MessageResponse(message=f"User {email} has been deleted")


@router.post("/users/{user_id}/make-admin", response_model=MessageResponse)
async def make_admin(
    user_id: UUID,
    current_user: User = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db)
):
    """Promote user to admin (superuser only)"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    user.is_superuser = True
    user.is_verified = True
    user.updated_at = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(message=f"User {user.email} is now an admin")


@router.post("/users/{user_id}/remove-admin", response_model=MessageResponse)
async def remove_admin(
    user_id: UUID,
    current_user: User = Depends(get_current_superuser),
    db: AsyncSession = Depends(get_db)
):
    """Demote admin to regular user (superuser only)"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot remove your own admin status"
        )
    
    user.is_superuser = False
    user.updated_at = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(message=f"User {user.email} is no longer an admin")


@router.post("/users/{user_id}/set-plan", response_model=MessageResponse)
async def set_user_plan(
    user_id: UUID,
    request: SetPlanRequest,
    current_user: User = Depends(check_admin_access),
    db: AsyncSession = Depends(get_db)
):
    """Set or change user plan (admin only)"""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    if request.plan not in PLAN_FEATURES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid plan. Must be one of: {', '.join(PLAN_FEATURES.keys())}"
        )
    
    old_plan = user.plan
    apply_plan_features(user, request.plan)
    user.updated_at = datetime.utcnow()
    await db.commit()
    
    return MessageResponse(
        message=f"User {user.email} plan changed from {old_plan} to {request.plan}"
    )


@router.get("/plans")
async def get_available_plans(
    current_user: User = Depends(check_admin_access)
):
    """Get list of available plans and their features"""
    return {
        "plans": [
            {
                "id": plan_id,
                "name": plan_id.title(),
                "features": features
            }
            for plan_id, features in PLAN_FEATURES.items()
        ]
    }
