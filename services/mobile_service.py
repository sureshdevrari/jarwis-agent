"""
Mobile Service

Mobile scan orchestration and management.
Coordinates between API routes, mobile scanners, and database.

Following layered architecture:
- Services CAN import: core/*, database/*, shared/*
- Services CANNOT import: api/routes/*
"""

import logging
import uuid
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from shared.schemas.scanner_results import MobileFinding
from database import crud
from database.connection import AsyncSessionLocal

# Import WebSocket broadcast functions for real-time frontend updates
try:
    from api.websocket import (
        broadcast_scan_progress,
        broadcast_scan_status,
        broadcast_scan_log,
        broadcast_scan_complete,
        broadcast_scan_error,
        broadcast_finding
    )
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False

logger = logging.getLogger(__name__)


class MobileScanService:
    """
    Mobile scan orchestration service.
    
    Responsibilities:
    - Validate mobile scan requests
    - Coordinate with mobile orchestrators
    - Track scan progress in database (no in-memory state)
    - Generate mobile security reports
    """
    
    @classmethod
    def _setup_android_environment(cls):
        """
        Ensure Android SDK environment variables are properly configured.
        This is critical for the mobile orchestrator to find ADB and emulator.
        """
        import os
        
        # Check if already configured
        if os.environ.get("ANDROID_SDK_ROOT") and os.path.exists(os.environ["ANDROID_SDK_ROOT"]):
            return
        
        # Common SDK locations on Windows
        sdk_paths = [
            "C:/Android/Sdk",
            "C:/Android/sdk",
            os.path.expanduser("~/AppData/Local/Android/Sdk"),
            os.path.expanduser("~/.jarwis/android-sdk"),
        ]
        
        # Find valid SDK path
        sdk_root = None
        for path in sdk_paths:
            if os.path.exists(path):
                sdk_root = path
                break
        
        if sdk_root:
            os.environ["ANDROID_SDK_ROOT"] = sdk_root
            os.environ["ANDROID_HOME"] = sdk_root
            logger.info(f"Set ANDROID_SDK_ROOT to {sdk_root}")
            
            # Add platform-tools and emulator to PATH
            platform_tools = os.path.join(sdk_root, "platform-tools")
            emulator_path = os.path.join(sdk_root, "emulator")
            
            current_path = os.environ.get("PATH", "")
            paths_to_add = []
            
            if os.path.exists(platform_tools) and platform_tools not in current_path:
                paths_to_add.append(platform_tools)
            if os.path.exists(emulator_path) and emulator_path not in current_path:
                paths_to_add.append(emulator_path)
            
            if paths_to_add:
                os.environ["PATH"] = os.pathsep.join(paths_to_add) + os.pathsep + current_path
            
            # Set AVD home if not set
            if not os.environ.get("ANDROID_AVD_HOME"):
                avd_paths = [
                    "C:/Android/avd",
                    os.path.expanduser("~/.android/avd"),
                ]
                for avd_path in avd_paths:
                    if os.path.exists(avd_path):
                        os.environ["ANDROID_AVD_HOME"] = avd_path
                        logger.info(f"Set ANDROID_AVD_HOME to {avd_path}")
                        break
        else:
            logger.warning("Android SDK not found in standard locations")
    
    @classmethod
    async def start_mobile_scan(
        cls,
        db: AsyncSession,
        user,
        app_file_path: str,
        app_name: str,
        platform: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Start a new mobile application security scan.
        
        Args:
            db: Database session
            user: Current user
            app_file_path: Path to saved APK/IPA file
            app_name: Application name
            platform: "android" or "ios"
            config: Scan configuration (ssl_pinning_bypass, frida_scripts, etc.)
            
        Returns:
            Dict with scan_id, status, message
            
        Raises:
            ValueError: If validation fails
        """
        # NOTE: Subscription checks are done in the API route via dependencies
        # This keeps the service layer focused on business logic
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())[:8]
        
        # Create scan record in database
        scan = await crud.create_scan(
            db=db,
            user_id=user.id,
            scan_id=scan_id,
            target_url=f"mobile://{app_name}",
            scan_type="mobile",
            config={
                "app_name": app_name,
                "platform": platform,
                "app_file": app_file_path,
                **config
            }
        )
        
        logger.info(
            f"Mobile scan {scan_id} created for {app_name} ({platform}) "
            f"by user {user.email}"
        )
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "message": f"Mobile scan started for {app_name}",
            "platform": platform
        }
    
    @classmethod
    async def execute_mobile_scan(
        cls,
        scan_id: str,
        user_id: str
    ):
        """
        Execute mobile scan in background.
        
        This is the main orchestration logic that was previously in
        api/routes/mobile.py run_mobile_scan() function.
        
        Follows the 9-phase mobile scan flow from mobile_orchestrator.py.
        """
        # Import scan_progress for tracking
        from api.routes.scans import scan_progress
        
        # Register with MobileProcessRegistry
        mobile_process = None
        try:
            from core.mobile_process_registry import MobileProcessRegistry
            mobile_process = await MobileProcessRegistry.register(
                scan_id=scan_id,
                user_id=user_id,
                platform="android"  # Will be updated once we know the actual platform
            )
            logger.info(f"[{scan_id}] Registered with MobileProcessRegistry")
        except ImportError:
            logger.warning(f"[{scan_id}] MobileProcessRegistry not available")
        except Exception as e:
            logger.error(f"[{scan_id}] Failed to register with MobileProcessRegistry: {e}")
        
        # Initialize scan_progress entry for live monitoring
        scan_progress[scan_id] = {
            "scan_id": scan_id,
            "status": "running",
            "progress": 0,
            "phase": "initializing",
            "scan_type": "mobile",
            "started_at": datetime.now().isoformat(),
            "should_stop": False
        }
        
        async with AsyncSessionLocal() as db:
            scan = await crud.get_scan_by_id(db, scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                scan_progress.pop(scan_id, None)
                return
            
            try:
                await cls._update_scan_progress(
                    db, scan, "running", 5, "Initializing"
                )
                scan_progress[scan_id]["progress"] = 5
                scan_progress[scan_id]["phase"] = "Initializing"
                
                # Broadcast initialization via WebSocket
                if HAS_WEBSOCKET:
                    await broadcast_scan_status(scan_id, "running", "Mobile scan initializing")
                    await broadcast_scan_progress(
                        scan_id=scan_id,
                        progress=5,
                        phase="Initializing",
                        message="Preparing mobile security scan",
                        findings_count=0
                    )
                
                app_file = scan.config.get("app_file", "")
                platform = scan.config.get("platform", "android")
                config = scan.config
                
                # Update platform in registry
                if mobile_process:
                    mobile_process.platform = platform
                
                logger.info(f"[{scan_id}] Starting mobile scan for {app_file}")
                
                # Try full orchestrator first
                use_orchestrator = True
                findings = []
                endpoints = []
                
                if use_orchestrator:
                    try:
                        findings, endpoints = await cls._run_full_orchestrator(
                            db, scan, app_file, platform, config, mobile_process
                        )
                    except ImportError as e:
                        logger.warning(
                            f"[{scan_id}] Orchestrator not available: {e}. "
                            "Falling back to basic scanning."
                        )
                        use_orchestrator = False
                    except Exception as e:
                        logger.error(
                            f"[{scan_id}] Orchestrator error: {e}. "
                            "Falling back to basic scanning.",
                            exc_info=True
                        )
                        use_orchestrator = False
                        
                        # Notify frontend about fallback to basic mode
                        if HAS_WEBSOCKET:
                            await broadcast_scan_log(
                                scan_id=scan_id,
                                level="warning",
                                message=f"Full dynamic testing unavailable: {str(e)[:100]}. Running static analysis only.",
                                phase="Fallback"
                            )
                
                # Fallback to basic static analysis
                if not use_orchestrator:
                    # Broadcast fallback mode notification
                    if HAS_WEBSOCKET:
                        await broadcast_scan_progress(
                            scan_id=scan_id,
                            progress=10,
                            phase="Static Analysis",
                            message="No device/emulator detected. Running static analysis only.",
                            findings_count=0
                        )
                    
                    findings = await cls._run_basic_scan(
                        db, scan, app_file, platform, config
                    )
                
                # Generate report
                await cls._update_scan_progress(
                    db, scan, "running", 90, "Generating report"
                )
                scan_progress[scan_id]["progress"] = 90
                scan_progress[scan_id]["phase"] = "Generating report"
                
                # Broadcast report generation phase
                if HAS_WEBSOCKET:
                    await broadcast_scan_progress(
                        scan_id=scan_id,
                        progress=90,
                        phase="Generating report",
                        message="Creating security assessment report",
                        findings_count=len(findings)
                    )
                
                # Calculate severity counts
                severity_counts = cls._calculate_severity_counts(findings)
                
                # Generate PDF report
                report_paths = {}
                try:
                    report_paths = await cls._generate_mobile_report(
                        scan, findings, config
                    )
                    logger.info(f"[{scan_id}] Report generated: {report_paths}")
                except Exception as report_err:
                    logger.error(f"[{scan_id}] Report generation failed: {report_err}")
                
                # Update scan with results
                await crud.update_scan_results(
                    db, scan,
                    findings_count=len(findings),
                    severity_counts=severity_counts,
                    report_paths=report_paths
                )
                
                # Complete scan
                await cls._update_scan_progress(
                    db, scan, "completed", 100, "Completed"
                )
                scan_progress[scan_id]["status"] = "completed"
                scan_progress[scan_id]["progress"] = 100
                
                # Broadcast completion via WebSocket
                if HAS_WEBSOCKET:
                    duration = int((datetime.now() - datetime.fromisoformat(
                        scan_progress[scan_id].get("started_at", datetime.now().isoformat())
                    )).total_seconds())
                    
                    await broadcast_scan_complete(
                        scan_id=scan_id,
                        findings_count=len(findings),
                        duration_seconds=duration,
                        summary={
                            "severity_counts": severity_counts,
                            "report_paths": report_paths,
                            "scan_type": "mobile",
                            "platform": platform
                        }
                    )
                
                logger.info(
                    f"[{scan_id}] Mobile scan completed! "
                    f"Found {len(findings)} vulnerabilities"
                )
                
            except Exception as e:
                logger.error(f"[{scan_id}] Mobile scan error: {e}", exc_info=True)
                await cls._update_scan_progress(
                    db, scan, "failed", scan.progress, f"Error: {str(e)}"
                )
                scan_progress[scan_id]["status"] = "failed"
                
                # Broadcast error via WebSocket
                if HAS_WEBSOCKET:
                    await broadcast_scan_error(
                        scan_id=scan_id,
                        error=str(e)[:200],
                        recoverable=False
                    )
                
                # Refund scan credit on error
                try:
                    from database.subscription import decrement_usage_counter
                    await decrement_usage_counter(db, user_id, "scans")
                    logger.info(f"[{scan_id}] Scan credit refunded due to error")
                except Exception as refund_error:
                    logger.warning(
                        f"[{scan_id}] Failed to refund scan credit: {refund_error}"
                    )
            finally:
                # Cleanup registry
                try:
                    from core.mobile_process_registry import MobileProcessRegistry
                    await MobileProcessRegistry.unregister(scan_id)
                except:
                    pass
                
                # Remove from scan_progress after a short delay for UI updates
                await asyncio.sleep(5)
                scan_progress.pop(scan_id, None)
    
    @classmethod
    async def _run_full_orchestrator(
        cls,
        db: AsyncSession,
        scan,
        app_file: str,
        platform: str,
        config: Dict,
        mobile_process = None
    ) -> tuple:
        """
        Run the full MobilePenTestOrchestrator.
        
        Args:
            mobile_process: Optional MobileScanProcess from registry for tracking
        
        Returns:
            Tuple of (findings, endpoints)
        """
        import os
        from attacks.mobile.orchestration.mobile_orchestrator import (
            MobilePenTestOrchestrator,
            MobileScanConfig
        )
        
        # Ensure Android SDK environment is properly configured
        cls._setup_android_environment()
        
        logger.info(f"[{scan.scan_id}] Initializing Mobile Pentest Orchestrator")
        
        # Build orchestrator config
        orchestrator_config = MobileScanConfig(
            app_path=app_file,
            platform=platform,
            frida_bypass_enabled=config.get("ssl_pinning_bypass", True),
            use_emulator=True,
            headless=False,
            mitm_enabled=config.get("intercept_traffic", True),
            crawl_enabled=True,
            attacks_enabled=True,
            ai_analysis=False,
            generate_report=True,
            # Authentication config for dynamic testing
            auth_enabled=config.get("auth_enabled", False),
            auth_type=config.get("auth_type", ""),
            username=config.get("username", ""),
            password=config.get("password", ""),
            phone=config.get("phone", ""),
            login_api_url=config.get("login_api_url", ""),  # User-provided login URL
            continue_on_auth_failure=config.get("continue_on_auth_failure", True),
            # 2FA config
            two_factor_enabled=config.get("two_factor_enabled", False),
            two_factor_type=config.get("two_factor_type", "sms"),
            # Emulator behavior
            keep_emulator_on_failure=config.get("keep_emulator_on_failure", True),
            keep_emulator_on_complete=config.get("keep_emulator_on_complete", True),
        )
        
        # Create orchestrator
        orchestrator = MobilePenTestOrchestrator(orchestrator_config)
        
        # Register orchestrator with MobileProcessRegistry
        if mobile_process:
            try:
                from core.mobile_process_registry import MobileProcessRegistry
                await MobileProcessRegistry.update(
                    scan.scan_id,
                    orchestrator=orchestrator
                )
                logger.info(f"[{scan.scan_id}] Orchestrator registered with MobileProcessRegistry")
            except Exception as e:
                logger.warning(f"[{scan.scan_id}] Failed to register orchestrator: {e}")
        
        # Set callbacks
        def log_callback(log_type: str, message: str, details: str = None):
            logger.info(f"[{scan.scan_id}] {message}")
            if details:
                logger.debug(f"[{scan.scan_id}]   {details}")
        
        async def progress_callback(phase: str, progress: int, message: str):
            await cls._update_scan_progress(db, scan, "running", progress, phase)
            # Also update scan_progress dict for live monitoring
            try:
                from api.routes.scans import scan_progress
                if scan.scan_id in scan_progress:
                    scan_progress[scan.scan_id]["progress"] = progress
                    scan_progress[scan.scan_id]["phase"] = phase
            except:
                pass
            
            # Broadcast via WebSocket for real-time frontend updates
            if HAS_WEBSOCKET:
                try:
                    await broadcast_scan_progress(
                        scan_id=scan.scan_id,
                        progress=progress,
                        phase=phase,
                        message=message,
                        findings_count=0,
                        current_task=message
                    )
                except Exception as ws_err:
                    logger.debug(f"[{scan.scan_id}] WebSocket broadcast error: {ws_err}")
        
        orchestrator.set_log_callback(log_callback)
        orchestrator.set_progress_callback(progress_callback)
        
        logger.info(f"[{scan.scan_id}] Starting full mobile penetration test")
        
        # Run orchestrator
        results = await orchestrator.run()
        
        # After run, update registry with emulator reference
        if mobile_process and orchestrator.emulator:
            try:
                from core.mobile_process_registry import MobileProcessRegistry
                await MobileProcessRegistry.update(
                    scan.scan_id,
                    emulator_manager=orchestrator.emulator,
                    emulator_pid=orchestrator.emulator.status.emulator_pid,
                    device_id=orchestrator.emulator.status.device_id
                )
            except Exception as e:
                logger.debug(f"[{scan.scan_id}] Failed to update emulator in registry: {e}")
        
        # Run orchestrator
        results = await orchestrator.run()
        
        if results.get("status") != "completed":
            raise RuntimeError(
                f"Orchestrator failed: {results.get('error', 'Unknown error')}"
            )
        
        # Extract findings
        vulnerabilities = results.get("vulnerabilities", [])
        endpoints = results.get("endpoints", [])
        
        # Convert to MobileFinding schema
        findings = []
        for vuln in vulnerabilities:
            findings.append({
                "id": vuln.get("id", ""),
                "category": vuln.get("category", ""),
                "severity": vuln.get("severity", "medium"),
                "title": vuln.get("title", ""),
                "description": vuln.get("description", ""),
                "evidence": vuln.get("evidence", ""),
                "remediation": vuln.get("remediation", "")
            })
        
        summary = results.get("summary", {})
        logger.info(
            f"[{scan.scan_id}] Orchestrator completed: "
            f"{summary.get('total_vulnerabilities', 0)} vulnerabilities, "
            f"{summary.get('total_endpoints', 0)} endpoints"
        )
        
        return findings, endpoints
    
    @classmethod
    async def _run_basic_scan(
        cls,
        db: AsyncSession,
        scan,
        app_file: str,
        platform: str,
        config: Dict
    ) -> List[Dict]:
        """
        Run basic static-only mobile scan as fallback.
        
        Returns:
            List of findings
        """
        findings = []
        scan_id = scan.scan_id
        
        logger.info(f"[{scan_id}] Running basic mobile security scan (static analysis only)")
        
        # Broadcast that we're in basic mode
        if HAS_WEBSOCKET:
            await broadcast_scan_log(
                scan_id=scan_id,
                level="warning",
                message="Running in BASIC mode (static analysis only). No device/emulator detected.",
                phase="Basic Scan"
            )
        
        # Add info finding about limited scan mode
        findings.append({
            "id": "INFO-BASIC-MODE",
            "category": "M10",
            "severity": "info",
            "title": "Basic Scan Mode - Full Dynamic Testing Unavailable",
            "description": (
                "This scan ran in BASIC mode (static analysis only) because:\n"
                "1. No Android emulator or device was detected, OR\n"
                "2. Frida server is not running on the device, OR\n"
                "3. Required mobile testing modules failed to load.\n\n"
                "For FULL dynamic testing with API interception, SSL bypass, and runtime analysis:\n"
                "- Connect an Android device/emulator with USB debugging enabled\n"
                "- Install and run Frida server on the device\n"
                "- Ensure ADB is in your system PATH"
            ),
            "remediation": "Run scripts/setup_emulator.py for automated emulator setup",
            "evidence": f"App file: {app_file}",
            "cwe_id": "CWE-0",
        })
        
        # Phase 1: Static Analysis
        await cls._update_scan_progress(
            db, scan, "running", 15, "Static Analysis"
        )
        
        # Broadcast static analysis phase
        if HAS_WEBSOCKET:
            await broadcast_scan_progress(
                scan_id=scan_id,
                progress=15,
                phase="Static Analysis",
                message="Analyzing APK/IPA for security issues",
                findings_count=len(findings)
            )
        
        try:
            from attacks.mobile.static.static_analyzer import StaticAnalyzer
            
            logger.info(f"[{scan.scan_id}] Running static analysis on {app_file}")
            analyzer = StaticAnalyzer(config={})
            
            # analyze() returns (AppMetadata, List[StaticAnalysisResult])
            metadata, static_results = await analyzer.analyze(app_file)
            
            # Convert StaticAnalysisResult to dict format
            for result in static_results:
                findings.append({
                    "id": result.id,
                    "category": result.category,
                    "severity": result.severity,
                    "title": result.title,
                    "description": result.description,
                    "file_path": result.file_path,
                    "line_number": result.line_number,
                    "code_snippet": result.code_snippet,
                    "evidence": result.evidence,
                    "remediation": result.recommendation,
                })
            
            logger.info(
                f"[{scan_id}] Static analysis found "
                f"{len(static_results)} issues"
            )
            
            # Add metadata info finding
            if metadata.package_name:
                findings.append({
                    "id": "INFO-APP-META",
                    "category": "info",
                    "severity": "info",
                    "title": f"App Metadata: {metadata.package_name}",
                    "description": (
                        f"Package: {metadata.package_name}\n"
                        f"Version: {metadata.version_name} ({metadata.version_code})\n"
                        f"Platform: {metadata.platform}\n"
                        f"Permissions: {len(metadata.permissions)}\n"
                        f"API Endpoints Found: {len(metadata.api_endpoints)}"
                    ),
                    "evidence": str(metadata.permissions[:10]) if metadata.permissions else "No permissions",
                })
            
            # Broadcast findings update
            if HAS_WEBSOCKET:
                await broadcast_scan_progress(
                    scan_id=scan_id,
                    progress=40,
                    phase="Static Analysis Complete",
                    message=f"Found {len(static_results)} issues in static analysis",
                    findings_count=len(findings)
                )
                
        except ImportError:
            logger.warning(
                f"[{scan_id}] Static analyzer module not available"
            )
            if HAS_WEBSOCKET:
                await broadcast_scan_log(
                    scan_id=scan_id,
                    level="warning",
                    message="Static analyzer module not available",
                    phase="Static Analysis"
                )
        except Exception as e:
            logger.error(
                f"[{scan_id}] Static analysis error: {e}",
                exc_info=True
            )
            if HAS_WEBSOCKET:
                await broadcast_scan_log(
                    scan_id=scan_id,
                    level="error",
                    message=f"Static analysis error: {str(e)[:100]}",
                    phase="Static Analysis"
                )
        
        # Phase 2-5: Info messages for advanced features
        await cls._update_scan_progress(
            db, scan, "running", 60, "Checking Dynamic Analysis Requirements"
        )
        
        # Broadcast device check phase
        if HAS_WEBSOCKET:
            await broadcast_scan_progress(
                scan_id=scan_id,
                progress=60,
                phase="Device Check",
                message="Checking for Android device/emulator availability",
                findings_count=len(findings)
            )
        
        # Add a small delay so user can see progress
        import asyncio
        await asyncio.sleep(2)
        
        # Check for emulator/device availability
        device_available = False
        try:
            import subprocess
            result = subprocess.run(['adb', 'devices'], capture_output=True, text=True, timeout=5)
            devices = [l.split('\t')[0] for l in result.stdout.split('\n')[1:] if '\tdevice' in l]
            device_available = len(devices) > 0
            if device_available:
                device_msg = f"Android Device Detected: {devices[0]} (but orchestrator failed)"
                findings.append({
                    "id": "INFO-DEVICE-DETECTED",
                    "category": "M10",
                    "severity": "info",
                    "title": f"Android Device Detected: {devices[0]}",
                    "description": (
                        f"An Android device/emulator was detected ({devices[0]}), but the "
                        "full orchestrator failed to start. This may be due to missing Frida "
                        "server on the device or module import errors."
                    ),
                    "remediation": "Check the server logs for detailed error messages",
                    "evidence": f"Detected devices: {', '.join(devices)}",
                    "cwe_id": "CWE-0",
                })
                if HAS_WEBSOCKET:
                    await broadcast_scan_log(
                        scan_id=scan_id,
                        level="info",
                        message=device_msg,
                        phase="Device Check"
                    )
        except Exception as e:
            findings.append({
                "id": "INFO-NO-DEVICE",
                "category": "M10",
                "severity": "info",
                "title": "No Android Device/Emulator Detected",
                "description": (
                    f"ADB check failed: {str(e)}\n\n"
                    "To enable dynamic testing, you need:\n"
                    "1. Android SDK with ADB in PATH\n"
                    "2. An emulator running or physical device connected\n"
                    "3. USB debugging enabled on the device"
                ),
                "remediation": "Install Android SDK and connect a device/emulator",
                "evidence": f"ADB error: {str(e)}",
                "cwe_id": "CWE-0",
            })
            if HAS_WEBSOCKET:
                await broadcast_scan_log(
                    scan_id=scan_id,
                    level="warning",
                    message=f"No device detected: {str(e)[:50]}",
                    phase="Device Check"
                )
        
        await cls._update_scan_progress(
            db, scan, "running", 80, "Finalizing Results"
        )
        
        # Broadcast finalizing phase
        if HAS_WEBSOCKET:
            await broadcast_scan_progress(
                scan_id=scan_id,
                progress=80,
                phase="Finalizing",
                message="Preparing scan results",
                findings_count=len(findings)
            )
        
        await asyncio.sleep(1)
        
        logger.info(
            f"[{scan_id}] Basic scan completed. "
            "For full testing, connect an Android device with Frida."
        )
        
        return findings
    
    @classmethod
    async def stop_mobile_scan(
        cls,
        db: AsyncSession,
        scan_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Stop a running mobile scan.
        
        This method:
        1. Signals the scan to stop via MobileProcessRegistry
        2. Force cleans up all processes (emulator, Frida, MITM, etc.)
        3. Updates the database status
        4. Refunds the scan credit
        
        Returns:
            Dict with success status and message
        """
        scan = await crud.get_scan_by_id(db, scan_id, user_id)
        
        if not scan:
            raise ValueError("Mobile scan not found")
        
        if scan.status not in ["running", "queued"]:
            raise ValueError("Scan is not running")
        
        logger.info(f"[{scan_id}] Stopping mobile scan - terminating processes...")
        
        # 1. Signal stop and force cleanup via MobileProcessRegistry
        cleanup_success = False
        try:
            from core.mobile_process_registry import MobileProcessRegistry
            
            # Signal the scan to stop (cooperative cancellation)
            await MobileProcessRegistry.signal_stop(scan_id)
            
            # Force cleanup all processes
            cleanup_success = await MobileProcessRegistry.force_cleanup_by_scan_id(scan_id)
            
            if cleanup_success:
                logger.info(f"[{scan_id}] Mobile processes cleaned up successfully")
            else:
                logger.warning(f"[{scan_id}] Scan not found in registry, may already be stopped")
        except ImportError:
            logger.warning(f"[{scan_id}] MobileProcessRegistry not available")
        except Exception as e:
            logger.error(f"[{scan_id}] Error during process cleanup: {e}")
        
        # 2. Update scan status to stopped
        await crud.update_scan_status(db, scan, "stopped")
        
        # 3. Refund scan credit
        try:
            from database.subscription import decrement_usage_counter
            await decrement_usage_counter(db, user_id, "scans")
            logger.info(f"[{scan_id}] Scan credit refunded (stopped by user)")
        except Exception as e:
            logger.warning(f"[{scan_id}] Failed to refund scan credit: {e}")
        
        return {
            "message": "Mobile scan stopped",
            "scan_id": scan_id,
            "success": True,
            "processes_cleaned": cleanup_success
        }
    
    @classmethod
    async def get_scan_status(
        cls,
        db: AsyncSession,
        scan_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Get detailed mobile scan status.
        
        Returns:
            Dict with scan status, progress, phase, findings count
        """
        scan = await crud.get_scan_by_id(db, scan_id, user_id)
        
        if not scan:
            raise ValueError("Mobile scan not found")
        
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "progress": scan.progress,
            "phase": scan.phase or "",
            "app_name": scan.config.get("app_name", ""),
            "platform": scan.config.get("platform", "android"),
            "findings_count": scan.findings_count,
            "started_at": scan.started_at.isoformat() if scan.started_at else "",
            "completed_at": (
                scan.completed_at.isoformat() if scan.completed_at else None
            )
        }
    
    @classmethod
    async def get_scan_logs(
        cls,
        db: AsyncSession,
        scan_id: str,
        user_id: str,
        since: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get logs for a mobile scan.
        
        Note: In the new architecture, logs are tracked via database
        scan status updates, not in-memory dictionaries.
        
        Returns:
            Dict with scan_id, status, and log messages
        """
        scan = await crud.get_scan_by_id(db, scan_id, user_id)
        
        if not scan:
            raise ValueError("Mobile scan not found")
        
        # For now, return scan progress as logs
        # TODO: Implement proper log storage in database
        logs = [
            {
                "timestamp": scan.started_at.isoformat() if scan.started_at else "",
                "level": "info",
                "message": f"Scan started for {scan.config.get('app_name', 'app')}"
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "level": "info",
                "message": f"Current phase: {scan.phase or 'Unknown'}"
            }
        ]
        
        if scan.completed_at:
            logs.append({
                "timestamp": scan.completed_at.isoformat(),
                "level": "info",
                "message": f"Scan completed with {scan.findings_count} findings"
            })
        
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "logs": logs
        }
    
    @classmethod
    async def list_mobile_scans(
        cls,
        db: AsyncSession,
        user_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        List all mobile scans for a user.
        
        Returns:
            Dict with scans list and total count
        """
        scans, total = await crud.get_user_scans(
            db=db,
            user_id=user_id,
            skip=skip,
            limit=limit,
            scan_type="mobile"
        )
        
        return {
            "scans": [
                {
                    "id": str(s.id),
                    "scan_id": s.scan_id,
                    "status": s.status,
                    "app_name": s.config.get("app_name", ""),
                    "platform": s.config.get("platform", "android"),
                    "progress": s.progress,
                    "findings_count": s.findings_count,
                    "started_at": (
                        s.started_at.isoformat() if s.started_at else None
                    ),
                    "completed_at": (
                        s.completed_at.isoformat() if s.completed_at else None
                    ),
                }
                for s in scans
            ],
            "total": total
        }
    
    # ========== Helper Methods ==========
    
    @classmethod
    async def _update_scan_progress(
        cls,
        db: AsyncSession,
        scan,
        status: str,
        progress: int,
        phase: str
    ):
        """Update scan progress in database"""
        await crud.update_scan_status(db, scan, status, progress, phase)
    
    @staticmethod
    def _calculate_severity_counts(findings: List[Dict]) -> Dict[str, int]:
        """Calculate finding counts by severity"""
        return {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
            "info": len([f for f in findings if f.get("severity") == "info"]),
        }
    
    @classmethod
    async def _generate_mobile_report(
        cls,
        scan,
        findings: List[Dict],
        config: Dict
    ) -> Dict[str, str]:
        """
        Generate PDF and HTML reports for mobile scan.
        
        Uses the same ReportGenerator as web scans.
        
        Returns:
            Dict with report paths: {"pdf": "...", "html": "...", "json": "..."}
        """
        from pathlib import Path
        
        try:
            from core.reporters import ReportGenerator
        except ImportError:
            logger.warning(f"[{scan.scan_id}] ReportGenerator not available")
            return {}
        
        # Determine output directory
        reports_dir = Path("data/reports/mobile")
        reports_dir.mkdir(parents=True, exist_ok=True)
        
        app_name = config.get("app_name", "mobile_app")
        platform = config.get("platform", "android")
        
        # Create report generator
        generator = ReportGenerator(
            output_dir=str(reports_dir),
            formats=["html", "json", "pdf"]
        )
        
        # Prepare report context
        class ReportContext:
            def __init__(self):
                self.endpoints = []
                self.cookies = []
                self.forms = []
                self.tokens = []
        
        context = ReportContext()
        
        # Prepare config for report
        report_config = {
            "target": {
                "url": f"mobile://{app_name}",
                "name": app_name
            },
            "scan_type": "mobile",
            "platform": platform,
            "scan_id": scan.scan_id,
            "app_file": config.get("app_file", ""),
            "auth_enabled": config.get("auth_enabled", False),
        }
        
        # Generate reports
        try:
            generated_paths = await generator.generate(
                findings=findings,
                context=context,
                config=report_config,
                executive_summary=f"Mobile Security Assessment for {app_name} ({platform})"
            )
            
            # Parse generated paths
            report_paths = {}
            for path in generated_paths:
                if path.endswith(".pdf"):
                    report_paths["pdf"] = path
                elif path.endswith(".html"):
                    report_paths["html"] = path
                elif path.endswith(".json"):
                    report_paths["json"] = path
            
            logger.info(f"[{scan.scan_id}] Generated reports: {list(report_paths.keys())}")
            return report_paths
            
        except Exception as e:
            logger.error(f"[{scan.scan_id}] Report generation error: {e}", exc_info=True)
            return {}


# ========== OTP/Auth Dashboard Integration ==========
# In-memory storage for pending OTPs and auth confirmations
# In production, this should use Redis or database
_pending_otps: Dict[str, str] = {}
_auth_confirmations: Dict[str, bool] = {}
_otp_lock = asyncio.Lock()


async def submit_otp(request_id: str, otp_value: str) -> bool:
    """
    Submit OTP from dashboard for a pending auth request.
    
    Called by API route when user enters OTP in dashboard.
    OTP is stored temporarily and picked up by orchestrator.
    """
    async with _otp_lock:
        _pending_otps[request_id] = otp_value
        logger.info(f"[OTP] Stored OTP for request {request_id}")
    return True


async def get_pending_otp(request_id: str) -> Optional[str]:
    """
    Get pending OTP for a request (called by orchestrator).
    
    OTP is removed after retrieval (one-time use).
    """
    async with _otp_lock:
        otp = _pending_otps.pop(request_id, None)
        if otp:
            logger.info(f"[OTP] Retrieved OTP for request {request_id}")
        return otp


async def confirm_auth(request_id: str) -> bool:
    """
    Confirm manual auth completion from dashboard.
    
    Called by API route when user clicks "I've logged in" in dashboard.
    """
    async with _otp_lock:
        _auth_confirmations[request_id] = True
        logger.info(f"[AUTH] Confirmed auth for request {request_id}")
    return True


async def get_auth_confirmation(request_id: str) -> bool:
    """
    Check if auth was confirmed (called by orchestrator).
    
    Confirmation is removed after check (one-time use).
    """
    async with _otp_lock:
        confirmed = _auth_confirmations.pop(request_id, False)
        if confirmed:
            logger.info(f"[AUTH] Retrieved confirmation for request {request_id}")
        return confirmed


async def get_auth_status(scan_id: str) -> Dict[str, Any]:
    """
    Get current auth status for a scan.
    
    Returns auth_status and any pending OTP request info.
    """
    from api.routes.scans import scan_progress
    
    progress = scan_progress.get(scan_id, {})
    
    return {
        "scan_id": scan_id,
        "auth_status": progress.get("auth_status", "not_started"),
        "auth_request_id": progress.get("otp_request_id", ""),
        "auth_type": progress.get("auth_type", ""),
        "timeout_remaining": progress.get("auth_timeout_remaining", 0)
    }

