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

# Agent requirement enforcement
from core.universal_agent_server import require_agent_connection, get_agent_for_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scan/mobile", tags=["Mobile Security Scans"])


# ========== Pydantic Models ==========

class MobileUploadResponse(BaseModel):
    """Response for mobile app upload"""
    file_id: str
    filename: str
    file_size: int
    platform: str
    app_info: Optional[dict] = None
    device_status: Optional[dict] = None  # Device/emulator info
    installation_status: Optional[dict] = None  # APK installation result
    message: str


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


class EmulatorStatusResponse(BaseModel):
    """Emulator status response"""
    running: bool
    device_id: str = ""
    sdk_installed: bool = False
    emulator_installed: bool = False
    frida_installed: bool = False
    message: str = ""


class EmulatorActionResponse(BaseModel):
    """Response for emulator start/stop actions"""
    success: bool
    running: bool
    device_id: str = ""
    message: str


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

@router.post("/upload", response_model=MobileUploadResponse, status_code=status.HTTP_201_CREATED)
async def upload_mobile_app(
    app_file: UploadFile = File(...),
    platform: str = Form("android"),
    auto_start_emulator: bool = Form(False),  # Auto-start emulator if not running
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload a mobile app file (APK/XAPK/IPA) for later scanning.
    
    This is step 1 of the two-step upload flow. Upload the file first,
    then start the scan with the returned file_id.
    
    - **auto_start_emulator**: If true, will auto-start emulator if not running (takes 30-60s)
    
    Returns file info including extracted app metadata.
    """
    # ========== DEVELOPER ACCOUNT CHECK ==========
    from shared.constants import is_developer_account
    is_dev_account = is_developer_account(current_user.email)
    
    if is_dev_account:
        logger.info(f"🔧 DEVELOPER ACCOUNT: {current_user.email} - bypassing subscription limits for mobile upload")
    # ==============================================
    
    # ========== SUBSCRIPTION ENFORCEMENT ==========
    if not is_dev_account:
        await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_MOBILE_PENTEST)
    # ==============================================
    
    # Validate file type
    filename = app_file.filename.lower()
    if platform == "android" and not (filename.endswith(".apk") or filename.endswith(".xapk")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Android apps must be APK or XAPK files"
        )
    if platform == "ios" and not filename.endswith(".ipa"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="iOS apps must be IPA files"
        )
    
    # Generate unique file_id for this upload
    file_id = str(uuid_lib.uuid4())[:12]
    
    # Create uploads directory
    data_upload_dir = Path("data/uploads/mobile")
    if data_upload_dir.parent.exists():
        upload_dir = data_upload_dir / file_id
    else:
        upload_dir = Path("uploads/mobile") / file_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    
    # Save uploaded file
    file_path = upload_dir / app_file.filename
    try:
        content = await app_file.read()
        file_size = len(content)
        with open(file_path, "wb") as buffer:
            buffer.write(content)
        logger.info(f"✅ Mobile app uploaded: {file_path} ({file_size / (1024*1024):.2f} MB)")
    except Exception as e:
        logger.error(f"Failed to save uploaded file: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save uploaded file"
        )
    
    # Try to extract app info (package name, version, etc.)
    app_info = None
    package_name = None
    try:
        if platform == "android":
            from attacks.mobile.static.static_analyzer import StaticAnalyzer
            analyzer = StaticAnalyzer(config={})
            analysis_result = analyzer.analyze(str(file_path))
            if analysis_result and "manifest" in analysis_result:
                manifest = analysis_result["manifest"]
                package_name = manifest.get("package")
                app_info = {
                    "package_name": package_name,
                    "version_name": manifest.get("version_name"),
                    "version_code": manifest.get("version_code"),
                    "min_sdk": manifest.get("min_sdk"),
                    "target_sdk": manifest.get("target_sdk"),
                    "permissions_count": len(manifest.get("permissions", []))
                }
    except Exception as e:
        logger.warning(f"Could not extract app info: {e}")
        # Non-fatal - continue without app info
    
    # Check device/emulator status and try to pre-install APK
    device_status = None
    installation_status = None
    message = "App uploaded successfully."
    emulator_auto_started = False
    
    try:
        if platform == "android":
            from attacks.mobile.platform.android.emulator_manager import EmulatorManager
            emulator = EmulatorManager()
            status = emulator.get_status()
            
            # Auto-start emulator if requested and not running
            if auto_start_emulator and not status.get("running"):
                if status.get("sdk_installed") and status.get("emulator_installed"):
                    logger.info("🚀 Auto-starting Android emulator...")
                    try:
                        start_success = await emulator.start_emulator(headless=False, wait=True)
                        if start_success:
                            status = emulator.get_status()  # Refresh status
                            emulator_auto_started = True
                            logger.info(f"✅ Emulator auto-started: {status.get('device_id')}")
                        else:
                            logger.warning("⚠️ Failed to auto-start emulator")
                    except Exception as auto_start_err:
                        logger.warning(f"⚠️ Could not auto-start emulator: {auto_start_err}")
                else:
                    logger.warning("⚠️ Cannot auto-start emulator - SDK/emulator not installed")
            
            device_status = {
                "connected": status.get("running", False),
                "device_id": status.get("device_id", ""),
                "sdk_installed": status.get("sdk_installed", False),
                "frida_ready": status.get("frida_installed", False),
                "auto_started": emulator_auto_started
            }
            
            if status.get("running") and status.get("device_id"):
                # Device/emulator is connected - try to install APK
                logger.info(f"📱 Device detected: {status.get('device_id')} - installing APK...")
                
                try:
                    # Install APK on device
                    install_success = await emulator.install_apk(str(file_path))
                    
                    if install_success:
                        installation_status = {
                            "installed": True,
                            "device_id": status.get("device_id"),
                            "package_name": package_name,
                            "error": None
                        }
                        message = f"App uploaded and installed on {status.get('device_id')}! Ready for scanning."
                        logger.info(f"✅ APK installed successfully on {status.get('device_id')}")
                    else:
                        installation_status = {
                            "installed": False,
                            "device_id": status.get("device_id"),
                            "package_name": package_name,
                            "error": "Installation failed - will retry during scan"
                        }
                        message = "App uploaded. Installation failed but will retry when scan starts."
                        logger.warning(f"⚠️ APK installation failed, will retry during scan")
                except Exception as install_err:
                    installation_status = {
                        "installed": False,
                        "device_id": status.get("device_id"),
                        "package_name": package_name,
                        "error": str(install_err)[:100]
                    }
                    message = f"App uploaded. Pre-installation failed: {str(install_err)[:50]}. Will retry during scan."
                    logger.warning(f"⚠️ APK pre-installation error: {install_err}")
            else:
                message = "App uploaded. No device connected - app will be installed when scan starts."
                logger.info(f"📱 No device connected - skipping pre-installation")
    except Exception as e:
        logger.warning(f"Could not check device status: {e}")
        message = "App uploaded. Could not check device status."
    
    return MobileUploadResponse(
        file_id=file_id,
        filename=app_file.filename,
        file_size=file_size,
        platform=platform,
        app_info=app_info,
        device_status=device_status,
        installation_status=installation_status,
        message=message
    )


@router.post("/start", response_model=MobileScanResponse, status_code=status.HTTP_201_CREATED)
async def start_mobile_scan(
    background_tasks: BackgroundTasks,
    app_file: UploadFile = File(None),  # Optional if file_id is provided
    file_id: str = Form(None),  # Use file_id from previous upload
    app_name: str = Form(None),
    platform: str = Form("android"),
    ssl_pinning_bypass: bool = Form(True),
    frida_scripts: bool = Form(True),
    intercept_traffic: bool = Form(True),
    notes: str = Form(None),
    # Authentication fields for dynamic testing
    auth_enabled: bool = Form(False),
    auth_type: str = Form("email_password"),
    username: str = Form(None),
    password: str = Form(None),
    phone: str = Form(None),
    login_api_url: str = Form(None),  # User-provided login endpoint (auto-discovered if empty)
    # 2FA fields
    two_factor_enabled: bool = Form(False),
    two_factor_type: str = Form("sms"),  # sms, email, authenticator
    # Emulator/behavior options
    keep_emulator_on_failure: bool = Form(True),  # Keep emulator running if scan fails
    keep_emulator_on_complete: bool = Form(True),  # Keep emulator running after scan
    continue_on_auth_failure: bool = Form(True),  # Continue with unauthenticated scan if auth fails
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new mobile application security scan.
    
    Provide either:
    - **file_id**: ID from previous /upload call (preferred for large files)
    - **app_file**: APK/XAPK/IPA file to scan (direct upload)
    
    - **app_name**: Optional name for the app
    - **platform**: Platform type (android/ios)
    - **ssl_pinning_bypass**: Enable SSL pinning bypass via Frida
    - **frida_scripts**: Enable Frida runtime instrumentation
    - **intercept_traffic**: Enable traffic interception
    - **login_api_url**: Custom login API endpoint (optional, auto-discovered from traffic if empty)
    - **keep_emulator_on_failure**: Keep emulator running if scan fails (default: True)
    - **keep_emulator_on_complete**: Keep emulator running after scan completes (default: True)
    - **continue_on_auth_failure**: Continue unauthenticated if authentication fails (default: True)
    """
    # ========== DEVELOPER ACCOUNT CHECK ==========
    from shared.constants import is_developer_account
    is_dev_account = is_developer_account(current_user.email)
    
    if is_dev_account:
        logger.info(f"🔧 DEVELOPER ACCOUNT: {current_user.email} - bypassing subscription limits for mobile scan")
    # ==============================================
    
    # ========== SUBSCRIPTION ENFORCEMENT ==========
    if not is_dev_account:
        await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_MOBILE_PENTEST)
        await enforce_subscription_limit(db, current_user, SubscriptionAction.START_SCAN)
    # ==============================================
    
    # ========== AGENT REQUIREMENT CHECK ==========
    # Mobile scans require a connected Jarwis Agent with mobile capabilities
    # Developer accounts bypass this check for testing
    agent_id = None
    if not is_dev_account:
        # Dynamic testing requires mobile_dynamic, static can use mobile_static
        scan_type = "mobile_dynamic" if frida_scripts or intercept_traffic else "mobile_static"
        await require_agent_connection(current_user.id, scan_type)
        # Get agent_id for tracking which agent runs this scan
        agent_info = get_agent_for_user(current_user.id, scan_type)
        agent_id = agent_info.get("agent_id")
    # =============================================
    
    # Either file_id or app_file must be provided
    if not file_id and not app_file:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Either file_id (from /upload) or app_file must be provided"
        )
    
    # If file_id is provided, find the previously uploaded file
    if file_id:
        # Look for the file in upload directories
        data_upload_dir = Path("data/uploads/mobile") / file_id
        old_upload_dir = Path("uploads/mobile") / file_id
        
        if data_upload_dir.exists():
            upload_dir = data_upload_dir
        elif old_upload_dir.exists():
            upload_dir = old_upload_dir
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Upload with file_id '{file_id}' not found. Please upload again."
            )
        
        # Find the app file in the directory
        app_files = list(upload_dir.glob("*.apk")) + list(upload_dir.glob("*.xapk")) + list(upload_dir.glob("*.ipa"))
        if not app_files:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Uploaded app file not found in upload directory"
            )
        
        file_path = app_files[0]
        filename = file_path.name.lower()
        scan_id = str(uuid_lib.uuid4())[:8]
        logger.info(f"Using previously uploaded file: {file_path}")
    else:
        # Direct file upload (original flow)
        # Validate file type
        filename = app_file.filename.lower()
        if platform == "android" and not (filename.endswith(".apk") or filename.endswith(".xapk")):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Android apps must be APK or XAPK files"
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
    final_app_name = app_name or Path(file_path).stem
    
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
            "notes": notes,
            # Authentication config for dynamic testing
            "auth_enabled": auth_enabled,
            "auth_type": auth_type,
            "username": username,
            "password": password,
            "phone": phone,
            "login_api_url": login_api_url,  # User-provided login URL
            # 2FA config
            "two_factor_enabled": two_factor_enabled,
            "two_factor_type": two_factor_type,
            # Emulator/behavior options
            "keep_emulator_on_failure": keep_emulator_on_failure,
            "keep_emulator_on_complete": keep_emulator_on_complete,
            "continue_on_auth_failure": continue_on_auth_failure,
        }
    )
    
    # Start scan execution in background
    background_tasks.add_task(
        MobileScanService.execute_mobile_scan,
        scan_id=result["scan_id"],
        user_id=current_user.id,
        agent_id=agent_id  # Pass agent_id for distributed execution
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


# ========== Emulator Control Endpoints ==========

@router.get("/emulator/status", response_model=EmulatorStatusResponse)
async def get_emulator_status(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get Android emulator/device status.
    Returns whether emulator is running, SDK installed, etc.
    """
    try:
        from attacks.mobile.platform.android.emulator_manager import EmulatorManager
        emulator = EmulatorManager()
        status = emulator.get_status()
        
        return EmulatorStatusResponse(
            running=status.get("running", False),
            device_id=status.get("device_id", ""),
            sdk_installed=status.get("sdk_installed", False),
            emulator_installed=status.get("emulator_installed", False),
            frida_installed=status.get("frida_installed", False),
            message="Emulator is running" if status.get("running") else "No emulator running"
        )
    except Exception as e:
        logger.error(f"Failed to get emulator status: {e}")
        return EmulatorStatusResponse(
            running=False,
            message=f"Error checking status: {str(e)[:100]}"
        )


@router.post("/emulator/start", response_model=EmulatorActionResponse)
async def start_emulator(
    headless: bool = False,
    current_user: User = Depends(get_current_active_user)
):
    """
    Start the Android emulator.
    
    - **headless**: Run without GUI window (for servers)
    
    Note: This may take 30-60 seconds for the emulator to fully boot.
    """
    try:
        from attacks.mobile.platform.android.emulator_manager import EmulatorManager
        emulator = EmulatorManager()
        
        # Check if already running
        status = emulator.get_status()
        if status.get("running"):
            return EmulatorActionResponse(
                success=True,
                running=True,
                device_id=status.get("device_id", ""),
                message="Emulator is already running"
            )
        
        # Check if SDK is installed
        if not status.get("sdk_installed"):
            return EmulatorActionResponse(
                success=False,
                running=False,
                message="Android SDK not installed. Please run SETUP_ANDROID_EMULATOR.bat first."
            )
        
        if not status.get("emulator_installed"):
            return EmulatorActionResponse(
                success=False,
                running=False,
                message="Android emulator not installed. Please run SETUP_ANDROID_EMULATOR.bat first."
            )
        
        logger.info(f"🚀 Starting Android emulator (headless={headless})...")
        
        # Start the emulator
        success = await emulator.start_emulator(headless=headless, wait=True)
        
        if success:
            new_status = emulator.get_status()
            logger.info(f"✅ Emulator started: {new_status.get('device_id')}")
            return EmulatorActionResponse(
                success=True,
                running=True,
                device_id=new_status.get("device_id", ""),
                message="Emulator started successfully!"
            )
        else:
            return EmulatorActionResponse(
                success=False,
                running=False,
                message="Failed to start emulator. Check if AVD exists and SDK is properly configured."
            )
            
    except Exception as e:
        logger.error(f"Failed to start emulator: {e}")
        return EmulatorActionResponse(
            success=False,
            running=False,
            message=f"Error starting emulator: {str(e)[:100]}"
        )


@router.post("/emulator/stop", response_model=EmulatorActionResponse)
async def stop_emulator(
    current_user: User = Depends(get_current_active_user)
):
    """
    Stop the running Android emulator.
    """
    try:
        from attacks.mobile.platform.android.emulator_manager import EmulatorManager
        emulator = EmulatorManager()
        
        # Check if running
        status = emulator.get_status()
        if not status.get("running"):
            return EmulatorActionResponse(
                success=True,
                running=False,
                message="Emulator is not running"
            )
        
        logger.info("🛑 Stopping Android emulator...")
        
        success = await emulator.stop_emulator()
        
        if success:
            logger.info("✅ Emulator stopped")
            return EmulatorActionResponse(
                success=True,
                running=False,
                message="Emulator stopped successfully"
            )
        else:
            return EmulatorActionResponse(
                success=False,
                running=True,
                device_id=status.get("device_id", ""),
                message="Failed to stop emulator"
            )
            
    except Exception as e:
        logger.error(f"Failed to stop emulator: {e}")
        return EmulatorActionResponse(
            success=False,
            running=False,
            message=f"Error stopping emulator: {str(e)[:100]}"
        )
