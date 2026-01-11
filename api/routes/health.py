"""
Jarwis Health Check API Routes
==============================

Provides endpoints for monitoring system health, scanner availability,
and diagnostic information.

Endpoints:
- GET /api/health              - Basic health check
- GET /api/health/scanners     - Scanner availability status
- GET /api/health/detailed     - Full system diagnostics
- POST /api/health/validate    - Force re-validation of scanners
"""

import logging
import platform
import sys
from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.dependencies import get_current_active_user, get_current_user_optional, get_current_superuser
from database.models import User

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/health", tags=["Health"])


# ============== Response Models ==============

class BasicHealthResponse(BaseModel):
    """Basic health check response"""
    status: str  # healthy, degraded, unhealthy
    timestamp: str
    version: str = "1.0.0"


class ScannerHealthResponse(BaseModel):
    """Scanner health check response"""
    overall_status: str
    last_checked: str = None
    scan_types: Dict[str, Any]
    total_scanners: int
    healthy_count: int
    degraded_count: int
    unavailable_count: int


class DetailedHealthResponse(BaseModel):
    """Detailed system health response"""
    status: str
    timestamp: str
    system: Dict[str, Any]
    database: Dict[str, Any]
    scanners: Dict[str, Any]
    directories: Dict[str, Any]


# ============== Endpoints ==============

@router.get("/", response_model=BasicHealthResponse)
async def basic_health_check():
    """
    Basic health check endpoint.
    
    Returns simple status for load balancers and uptime monitors.
    Does not require authentication.
    """
    return BasicHealthResponse(
        status="healthy",
        timestamp=datetime.utcnow().isoformat(),
        version="1.0.0"
    )


@router.get("/scanners", response_model=ScannerHealthResponse)
async def scanner_health_check(
    current_user: User = Depends(get_current_user_optional)
):
    """
    Check health of all scanner components.
    
    Returns which scan types are available and which have issues.
    Useful for frontend to know which scan types to enable.
    """
    try:
        from attacks.unified_registry import scanner_registry
        
        # Validate all scanners (sync method)
        scanner_registry.validate_all()
        
        # Get summary
        summary = scanner_registry.get_health_summary()
        
        return ScannerHealthResponse(
            overall_status=summary.get("overall_status", "unknown"),
            last_checked=summary.get("last_checked"),
            scan_types=summary.get("scan_types", {}),
            total_scanners=summary.get("total_scanners", 0),
            healthy_count=summary.get("healthy_count", 0),
            degraded_count=summary.get("degraded_count", 0),
            unavailable_count=summary.get("unavailable_count", 0)
        )
        
    except ImportError:
        # Registry not available - return basic info
        return ScannerHealthResponse(
            overall_status="unknown",
            last_checked=None,
            scan_types={
                "web": {"status": "unknown", "available": True},
                "mobile": {"status": "unknown", "available": True},
                "network": {"status": "unknown", "available": True},
                "cloud": {"status": "unknown", "available": True},
            },
            total_scanners=0,
            healthy_count=0,
            degraded_count=0,
            unavailable_count=0
        )
    except Exception as e:
        logger.error(f"Scanner health check failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Health check failed: {str(e)}"
        )


@router.get("/detailed")
async def detailed_health_check(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Detailed system health check.
    
    Requires authentication. Returns comprehensive system diagnostics.
    """
    from pathlib import Path
    import os
    
    result = {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "system": {},
        "database": {},
        "scanners": {},
        "directories": {},
        "environment": {}
    }
    
    # System info
    result["system"] = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "python_version": sys.version,
        "hostname": platform.node(),
    }
    
    # Database check
    try:
        from sqlalchemy import text
        await db.execute(text("SELECT 1"))
        result["database"] = {
            "status": "connected",
            "message": "Database connection successful"
        }
    except Exception as e:
        result["database"] = {
            "status": "error",
            "message": str(e)
        }
        result["status"] = "degraded"
    
    # Scanner health
    try:
        from attacks.unified_registry import scanner_registry
        await scanner_registry.validate_all()
        result["scanners"] = scanner_registry.get_health_summary()
        
        if result["scanners"].get("overall_status") != "healthy":
            result["status"] = "degraded"
    except Exception as e:
        result["scanners"] = {
            "status": "error",
            "message": str(e)
        }
        result["status"] = "degraded"
    
    # Directory checks
    directories = ["uploads", "reports", "logs", "temp"]
    for dir_name in directories:
        dir_path = Path(dir_name)
        result["directories"][dir_name] = {
            "exists": dir_path.exists(),
            "writable": os.access(dir_path, os.W_OK) if dir_path.exists() else False
        }
        if not dir_path.exists() or not os.access(dir_path, os.W_OK):
            result["status"] = "degraded"
    
    # Environment checks (hide sensitive values)
    env_vars = [
        "DATABASE_URL", "SECRET_KEY", "GOOGLE_GEMINI_API_KEY",
        "OPENAI_API_KEY", "OLLAMA_HOST"
    ]
    for var in env_vars:
        value = os.environ.get(var)
        if value:
            result["environment"][var] = "configured"
        else:
            result["environment"][var] = "not set"
    
    return result


@router.post("/validate")
async def force_validate_scanners(
    current_user: User = Depends(get_current_active_user)
):
    """
    Force re-validation of all scanners.
    
    Clears cache and re-imports all scanner modules.
    Useful after code changes or deployments.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only superusers can force validation"
        )
    
    try:
        from attacks.unified_registry import scanner_registry
        
        # Clear cache
        scanner_registry.clear_cache()
        
        # Re-validate
        results = await scanner_registry.validate_all()
        summary = scanner_registry.get_health_summary()
        
        return {
            "status": "validated",
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": summary.get("overall_status"),
            "total_scanners": summary.get("total_scanners"),
            "healthy": summary.get("healthy_count"),
            "degraded": summary.get("degraded_count"),
            "unavailable": summary.get("unavailable_count"),
            "details": results
        }
        
    except Exception as e:
        logger.error(f"Force validation failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Validation failed: {str(e)}"
        )


@router.get("/scan-type/{scan_type}")
async def check_scan_type_availability(
    scan_type: str,
    current_user: User = Depends(get_current_user_optional)
):
    """
    Check if a specific scan type is available.
    
    Returns detailed status for web, mobile, network, or cloud.
    """
    valid_types = ["web", "mobile", "network", "cloud"]
    if scan_type not in valid_types:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid scan type. Must be one of: {valid_types}"
        )
    
    try:
        from attacks.unified_registry import scanner_registry
        
        # Validate all (ensures data is fresh)
        await scanner_registry.validate_all()
        summary = scanner_registry.get_health_summary()
        
        type_info = summary.get("scan_types", {}).get(scan_type, {})
        
        return {
            "scan_type": scan_type,
            "available": type_info.get("available", False),
            "status": type_info.get("status", "unknown"),
            "scanners": type_info.get("scanners", []),
            "message": _get_availability_message(scan_type, type_info)
        }
        
    except ImportError:
        return {
            "scan_type": scan_type,
            "available": True,  # Assume available if registry not loaded
            "status": "unknown",
            "scanners": [],
            "message": "Scanner registry not available, status unknown"
        }


def _get_availability_message(scan_type: str, type_info: dict) -> str:
    """Generate user-friendly message about scan type availability"""
    if type_info.get("available", False):
        return f"{scan_type.title()} scanning is ready"
    
    unavailable = type_info.get("unavailable", 0)
    if unavailable > 0:
        return f"{scan_type.title()} scanning unavailable: {unavailable} required scanner(s) failed to load"
    
    degraded = type_info.get("degraded", 0)
    if degraded > 0:
        return f"{scan_type.title()} scanning available with limited features"
    
    return f"{scan_type.title()} scan status unknown"
