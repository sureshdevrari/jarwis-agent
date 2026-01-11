"""
Jarwis AGI - Mobile Scan API Routes
Start mobile app scans, get results, manage scan lifecycle

Following layered architecture:
- Routes handle HTTP only (parse request, call service, return response)
- ALL business logic is in services/mobile_service.py
"""

import os
import uuid as uuid_lib
import logging
from datetime import datetime
from typing import Optional
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, UploadFile, File, Form
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_active_user
from database.subscription import (
    enforce_subscription_limit,
    SubscriptionAction,
    increment_usage_counter
)
from services.mobile_service import MobileScanService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan/mobile", tags=["Mobile Security Scans"])


# ========== Pydantic Models ==========

class MobileScanConfig(BaseModel):
    """Mobile scan configuration"""
    app_name: Optional[str] = None
    platform: str = Field(default="android", pattern="^(android|ios)$")
    ssl_pinning_bypass: bool = True
    frida_scripts: bool = True
    intercept_traffic: bool = True
    notes: Optional[str] = None


class MobileScanResponse(BaseModel):
    """Mobile scan response"""
    scan_id: str
    status: str
    message: str
    platform: Optional[str] = None


class MobileScanStatusResponse(BaseModel):
    """Mobile scan status response"""
    scan_id: str
    status: str
    progress: int
    phase: str
    app_name: str
    platform: str
    findings_count: int
    started_at: str
    completed_at: Optional[str] = None


# ========== Endpoints ==========

@router.post("/start", response_model=MobileScanResponse, status_code=status.HTTP_201_CREATED)
async def start_mobile_scan(
    background_tasks: BackgroundTasks,
    app_file: UploadFile = File(...),
    app_name: str = Form(None),
    platform: str = Form("android"),
    ssl_pinning_bypass: bool = Form(True),
    frida_scripts: bool = Form(True),
    intercept_traffic: bool = Form(True),
    notes: str = Form(None),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new mobile application security scan.
    
    Upload an APK (Android) or IPA (iOS) file for security testing.
    
    - **app_file**: APK or IPA file to scan
    - **app_name**: Optional name for the app
    - **platform**: Platform type (android/ios)
    - **ssl_pinning_bypass**: Enable SSL pinning bypass via Frida
    - **frida_scripts**: Enable Frida runtime instrumentation
    - **intercept_traffic**: Enable traffic interception
    """
    # ========== SUBSCRIPTION ENFORCEMENT ==========
    await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_MOBILE_PENTEST)
    await enforce_subscription_limit(db, current_user, SubscriptionAction.START_SCAN)
    # ==============================================
    
    # Validate file type
    filename = app_file.filename.lower()
    if platform == "android" and not filename.endswith(".apk"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Android apps must be APK files"
        )
    if platform == "ios" and not filename.endswith(".ipa"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="iOS apps must be IPA files"
        )
    
    # Create uploads directory (using data/uploads for new structure)
    scan_id = str(uuid_lib.uuid4())[:8]
    # Support both old (uploads/mobile) and new (data/uploads/mobile) paths
    data_upload_dir = Path("data/uploads/mobile")
    if data_upload_dir.parent.exists():
        upload_dir = data_upload_dir / scan_id
    else:
        upload_dir = Path("uploads/mobile") / scan_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Save uploaded file
    file_path = upload_dir / app_file.filename
    try:
        with open(file_path, "wb") as buffer:
            content = await app_file.read()
            buffer.write(content)
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file"
        )
    
    # Determine app name
    final_app_name = app_name or app_file.filename.rsplit(".", 1)[0]
    
    # Increment usage counter (reserve scan slot before starting)
    await increment_usage_counter(db, current_user.id, "scans")
    
    # Start mobile scan via service
    result = await MobileScanService.start_mobile_scan(
        db=db,
        user=current_user,
        app_file_path=str(file_path),
        app_name=final_app_name,
        platform=platform,
        config={
            "ssl_pinning_bypass": ssl_pinning_bypass,
            "frida_scripts": frida_scripts,
            "intercept_traffic": intercept_traffic,
            "notes": notes
        }
    )
    
    # Start scan execution in background
    background_tasks.add_task(
        MobileScanService.execute_mobile_scan,
        scan_id=result["scan_id"],
        user_id=current_user.id
    )
    
    return MobileScanResponse(
        scan_id=result["scan_id"],
        status=result["status"],
        message=result["message"],
        platform=result.get("platform")
    )


@router.get("/{scan_id}/status", response_model=MobileScanStatusResponse)
async def get_mobile_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get status of a mobile scan"""
    try:
        status_data = await MobileScanService.get_scan_status(
            db, scan_id, current_user.id
        )
        return MobileScanStatusResponse(**status_data)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.get("/{scan_id}/logs")
async def get_mobile_scan_logs(
    scan_id: str,
    since: Optional[str] = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get logs for a mobile scan"""
    try:
        return await MobileScanService.get_scan_logs(
            db, scan_id, current_user.id, since
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


@router.post("/{scan_id}/stop")
async def stop_mobile_scan(
    scan_id: str,
    confirmed: bool = False,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Stop a running mobile scan"""
    if not confirmed:
        return {
            "message": "Are you sure you want to stop this scan?",
            "confirm_required": True,
            "scan_id": scan_id
        }
    
    try:
        return await MobileScanService.stop_mobile_scan(
            db, scan_id, current_user.id
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@router.get("/")
async def list_mobile_scans(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List all mobile scans for the current user"""
    return await MobileScanService.list_mobile_scans(
        db, current_user.id, skip=0, limit=100
    )


@router.get("/{scan_id}/findings")
async def get_mobile_scan_findings(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get findings for a mobile scan"""
    from database.models import ScanHistory, Finding
    from sqlalchemy import select
    
    # Get scan from database
    scan_result = await db.execute(
        select(ScanHistory).where(
            ScanHistory.scan_id == scan_id,
            ScanHistory.user_id == current_user.id
        )
    )
    scan = scan_result.scalar_one_or_none()
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mobile scan not found"
        )
    
    # Get findings
    findings_result = await db.execute(
        select(Finding).where(Finding.scan_id == scan.id)
    )
    findings = [{
        'id': str(f.id),
        'finding_id': f.finding_id,
        'category': f.category,
        'severity': f.severity,
        'title': f.title,
        'description': f.description,
        'url': f.url,
        'method': f.method,
        'parameter': f.parameter,
        'evidence': f.evidence,
        'poc': f.poc,
        'reasoning': f.reasoning,
        'ai_verified': f.ai_verified,
        'is_false_positive': f.is_false_positive,
    } for f in findings_result.scalars().all()]
    
    return {
        'scan_id': scan_id,
        'findings': findings,
        'summary': {
            'total': len(findings),
            'critical': len([f for f in findings if f.get('severity') == 'critical']),
            'high': len([f for f in findings if f.get('severity') == 'high']),
            'medium': len([f for f in findings if f.get('severity') == 'medium']),
            'low': len([f for f in findings if f.get('severity') == 'low']),
            'info': len([f for f in findings if f.get('severity') == 'info']),
        }
    }
