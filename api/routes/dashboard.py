"""
Dashboard API Routes - Unified Security Console Endpoints
Provides aggregated dashboard data for enterprise UI
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, Dict, Any

from database.dependencies import get_db, get_current_user
from database.models import User
from services.dashboard_service import DashboardService
from shared.schemas.common import MessageResponse

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/security-score")
async def get_security_score(
    days: int = Query(30, ge=1, le=365, description="Look-back period in days"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get overall security score (0-100) with platform breakdown
    
    Returns:
        - score: Overall security score (0-100, higher is better)
        - grade: Letter grade (A-F)
        - delta: Change from previous period
        - breakdown: Per-platform scores
        - trend: improving/stable/declining
        - vulnerability counts by severity
    """
    try:
        result = await DashboardService.calculate_security_score(
            db=db,
            user_id=current_user.id,
            days=days
        )
        
        return {
            "success": True,
            "message": "Security score calculated successfully",
            "data": result
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to calculate security score: {str(e)}",
            "data": None
        }


@router.get("/risk-heatmap")
async def get_risk_heatmap(
    days: int = Query(30, ge=1, le=365, description="Look-back period in days"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get risk heatmap matrix: Platform × Severity
    
    Returns clickable matrix for vulnerability filtering:
        - matrix: Array of platform rows with severity counts
        - totals: Aggregated counts per severity
    """
    try:
        result = await DashboardService.get_risk_heatmap(
            db=db,
            user_id=current_user.id,
            days=days
        )
        
        return {
            "success": True,
            "message": "Risk heatmap generated successfully",
            "data": result
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to generate risk heatmap: {str(e)}",
            "data": None
        }


@router.get("/platform-breakdown")
async def get_platform_breakdown(
    days: int = Query(30, ge=1, le=365, description="Look-back period in days"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get platform risk breakdown for horizontal bar visualization
    
    Returns:
        - platforms: Array of platform data with risk scores
        - Each platform includes: risk_score, vulnerability_count, scan_count, last_scan
    """
    try:
        result = await DashboardService.get_platform_breakdown(
            db=db,
            user_id=current_user.id,
            days=days
        )
        
        return {
            "success": True,
            "message": "Platform breakdown generated successfully",
            "data": result
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to generate platform breakdown: {str(e)}",
            "data": None
        }


@router.get("/scan-stats")
async def get_scan_stats(
    days: int = Query(30, ge=1, le=365, description="Look-back period in days"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get aggregated scan statistics across all platforms
    
    Returns:
        - total_scans: Total scan count
        - completed/running/failed counts
        - scans_by_type: Breakdown by platform
        - avg_scan_duration_seconds
        - total_vulnerabilities
    """
    try:
        result = await DashboardService.get_scan_stats(
            db=db,
            user_id=current_user.id,
            days=days
        )
        
        return {
            "success": True,
            "message": "Scan statistics retrieved successfully",
            "data": result
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to retrieve scan statistics: {str(e)}",
            "data": None
        }


@router.get("/overview")
async def get_dashboard_overview(
    days: int = Query(30, ge=1, le=365, description="Look-back period in days"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get complete dashboard overview (combines all metrics in one call)
    
    Optimized endpoint for master dashboard that returns:
        - security_score
        - risk_heatmap
        - platform_breakdown
        - scan_stats
    
    Use this for initial page load to reduce round trips.
    """
    try:
        security_score = await DashboardService.calculate_security_score(db, current_user.id, days)
        risk_heatmap = await DashboardService.get_risk_heatmap(db, current_user.id, days)
        platform_breakdown = await DashboardService.get_platform_breakdown(db, current_user.id, days)
        scan_stats = await DashboardService.get_scan_stats(db, current_user.id, days)
        recent_scans = await DashboardService.get_recent_scans(db, current_user.id, limit=5)
        top_vulns = await DashboardService.get_top_vulnerabilities(db, current_user.id, limit=5)
        
        return {
            "success": True,
            "message": "Dashboard overview retrieved successfully",
            "data": {
                "security_score": security_score,
                "risk_heatmap": risk_heatmap,
                "platform_breakdown": platform_breakdown,
                "scan_stats": scan_stats,
                "recent_scans": recent_scans,
                "top_vulnerabilities": top_vulns
            }
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to retrieve dashboard overview: {str(e)}",
            "data": None
        }


@router.get("/recent-scans")
async def get_recent_scans(
    limit: int = Query(10, ge=1, le=50, description="Number of scans to return"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get recent scans for the dashboard table
    
    Returns:
        - scans: Array of recent scan objects with status, target, findings count
    """
    try:
        result = await DashboardService.get_recent_scans(
            db=db,
            user_id=current_user.id,
            limit=limit
        )
        
        return {
            "success": True,
            "message": "Recent scans retrieved successfully",
            "data": result
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to retrieve recent scans: {str(e)}",
            "data": []
        }


@router.get("/top-vulnerabilities")
async def get_top_vulnerabilities(
    limit: int = Query(10, ge=1, le=50, description="Number of vulnerabilities to return"),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Get top vulnerabilities by severity for the dashboard
    
    Returns:
        - vulnerabilities: Array of vulnerability objects sorted by severity
    """
    try:
        result = await DashboardService.get_top_vulnerabilities(
            db=db,
            user_id=current_user.id,
            limit=limit
        )
        
        return {
            "success": True,
            "message": "Top vulnerabilities retrieved successfully",
            "data": result
        }
    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to retrieve top vulnerabilities: {str(e)}",
            "data": []
        }
