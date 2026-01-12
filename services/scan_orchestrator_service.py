"""
Scan Orchestrator Service

Unified service that combines business logic (validation, subscriptions, domains)
with scan lifecycle management (state, progress, checkpoints).

This merges the orchestrator INTO the services layer (Layer 3) for a cleaner
architecture with fewer hops.

Architecture:
    API Routes (Layer 2)
        ↓
    ScanOrchestratorService (Layer 3) ← THIS FILE
        ↓
    Core Engines (Layer 4) - WebScanRunner, NetworkScanRunner, etc.

Usage:
    from services.scan_orchestrator_service import scan_orchestrator_service
    
    result = await scan_orchestrator_service.start_scan(
        db=db,
        user=current_user,
        scan_type="web",
        target_url="https://example.com",
        config=scan_config
    )
"""

import os
import asyncio
import logging
import uuid
import ipaddress
import socket
from typing import Dict, Any, Optional, List, Callable, Awaitable
from datetime import datetime
from dataclasses import dataclass, field
from urllib.parse import urlparse

from sqlalchemy.ext.asyncio import AsyncSession

from services.scan_state_machine import ScanStateMachine, ScanStatus, validate_status_transition
from services.subscription_service import SubscriptionService, SubscriptionError
from services.otp_service import otp_service
from services.domain_service import domain_service

logger = logging.getLogger(__name__)


# Feature flag for gradual rollout
USE_UNIFIED_ORCHESTRATOR = os.getenv("USE_UNIFIED_ORCHESTRATOR", "false").lower() == "true"


class ScanOrchestratorError(Exception):
    """Base exception for scan orchestrator service"""
    pass


class ValidationError(ScanOrchestratorError):
    """Raised when validation fails"""
    pass


class AuthorizationError(ScanOrchestratorError):
    """Raised when user is not authorized"""
    pass


class StateTransitionError(ScanOrchestratorError):
    """Raised when an invalid state transition is attempted"""
    pass


@dataclass
class ScanRequest:
    """
    Validated scan request data.
    
    This is the input format for start_scan().
    """
    target_url: str
    scan_type: str = "web"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    
    # Two-factor config
    two_factor_enabled: bool = False
    two_factor_config: Optional[Dict[str, Any]] = None
    
    # Auth method config
    auth_config: Optional[Dict[str, Any]] = None
    
    # Attack configuration
    attacks_config: Optional[Dict[str, Any]] = None


@dataclass
class ScanResult:
    """
    Result from a completed scan.
    """
    scan_id: str
    status: str
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    report_path: Optional[str] = None
    error_message: Optional[str] = None
    duration_seconds: float = 0


@dataclass
class ScanProgress:
    """
    Current progress of a scan.
    """
    scan_id: str
    status: str
    progress: int = 0
    phase: str = "initializing"
    message: str = ""
    findings_count: int = 0
    started_at: Optional[datetime] = None
    logs: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class ActiveScanContext:
    """
    Context for an active/running scan.
    Used for stop/pause operations.
    """
    scan_id: str
    started_at: datetime
    _stop_requested: bool = False
    
    def request_stop(self) -> None:
        """Request graceful stop of the scan"""
        self._stop_requested = True
    
    def should_stop(self) -> bool:
        """Check if stop has been requested"""
        return self._stop_requested


class ScanOrchestratorService:
    """
    Unified scan orchestrator service.
    
    Combines:
    - Business logic (validation, subscriptions, domain verification)
    - Lifecycle management (state machine, progress tracking)
    - Engine coordination (delegates to appropriate runner)
    
    This is the SINGLE entry point for all scan operations from API routes.
    """
    
    # In-memory progress tracking (use Redis in production)
    _progress: Dict[str, ScanProgress] = {}
    
    # Active scans for stop/pause operations
    _active_scans: Dict[str, ActiveScanContext] = {}
    
    # SSRF protection lists
    BLOCKED_HOSTNAMES = [
        "localhost", "127.0.0.1", "0.0.0.0", "::1",
        "metadata.google.internal", "169.254.169.254"
    ]
    
    BLOCKED_IP_RANGES = [
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("169.254.0.0/16"),
    ]
    
    # =========================================================================
    # PUBLIC API - Called from routes
    # =========================================================================
    
    async def start_scan(
        self,
        db: AsyncSession,
        user,
        request: ScanRequest,
    ) -> Dict[str, Any]:
        """
        Start a new scan with full validation.
        
        This is the main entry point from API routes.
        
        Steps:
        1. Validate target URL (SSRF protection)
        2. Check subscription limits
        3. Verify domain ownership (for credential scans)
        4. Create scan record in database
        5. Initialize progress tracking
        6. Launch scan execution in background
        
        Args:
            db: Database session
            user: Current authenticated user
            request: Validated scan request
            
        Returns:
            Dict with scan_id, status, message
            
        Raises:
            ValidationError: If validation fails
            SubscriptionError: If plan limits exceeded
            AuthorizationError: If domain not verified
        """
        # 1. Validate target URL
        self._validate_target_url(request.target_url)
        
        # 2. Check subscription limits
        await SubscriptionService.enforce_scan_limit(db, user, request.scan_type)
        
        # 3. Check domain verification for credential-based scans
        if request.username and request.password:
            await self._verify_domain_for_credentials(request.target_url, user)
        
        # 4. Generate scan ID and create DB record
        scan_id = str(uuid.uuid4())
        
        from database import crud
        
        # Build config dict
        scan_config = request.config or {}
        if request.two_factor_enabled:
            scan_config["two_factor"] = request.two_factor_config
        if request.auth_config:
            scan_config["auth"] = request.auth_config
        if request.attacks_config:
            scan_config["attacks"] = request.attacks_config
        
        scan = await crud.create_scan(
            db,
            user_id=user.id,
            scan_id=scan_id,
            target_url=request.target_url,
            scan_type=request.scan_type,
            config=scan_config
        )
        
        # 5. Initialize progress tracking
        self._progress[scan_id] = ScanProgress(
            scan_id=scan_id,
            status="queued",
            progress=0,
            phase="Initializing",
            started_at=datetime.utcnow(),
        )
        
        # 6. Setup 2FA if needed
        if request.two_factor_enabled and request.two_factor_config:
            otp_service.set_2fa_config(scan_id, request.two_factor_config)
        
        logger.info(f"Scan {scan_id} created for {request.target_url} by {user.email}")
        
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": "Scan queued successfully",
            "scan_type": request.scan_type,
        }
    
    async def run_scan(
        self,
        scan_id: str,
        target_url: str,
        scan_type: str,
        user_id: int,
        login_url: Optional[str] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        two_factor_config: Optional[Dict[str, Any]] = None,
        auth_config: Optional[Dict[str, Any]] = None,
        attacks_config: Optional[Dict[str, Any]] = None,
    ) -> ScanResult:
        """
        Execute a scan (called as background task).
        
        This method:
        1. Updates state to RUNNING
        2. Creates appropriate engine/runner
        3. Executes scan with progress tracking
        4. Handles completion/error states
        5. Returns results
        
        Args:
            scan_id: Unique scan identifier
            target_url: Target to scan
            scan_type: Type of scan (web, network, cloud, sast, mobile)
            user_id: ID of user who initiated scan
            login_url: Optional login page URL
            username: Optional login username
            password: Optional login password
            two_factor_config: Optional 2FA configuration
            auth_config: Optional auth method configuration
            attacks_config: Optional attack selection config
            
        Returns:
            ScanResult with findings and summary
        """
        from database.connection import get_async_session
        
        start_time = datetime.utcnow()
        
        # Get fresh database session
        async with get_async_session() as db:
            try:
                # Update status to running
                await self._update_status(db, scan_id, ScanStatus.RUNNING.value)
                self._update_progress(scan_id, status="running", phase="Starting scan")
                
                # Build runner config
                runner_config = await self._build_runner_config(
                    db=db,
                    scan_id=scan_id,
                    target_url=target_url,
                    scan_type=scan_type,
                    user_id=user_id,
                    login_url=login_url,
                    username=username,
                    password=password,
                    two_factor_config=two_factor_config,
                    auth_config=auth_config,
                    attacks_config=attacks_config,
                )
                
                # Execute with appropriate runner
                result = await self._execute_scan(
                    db=db,
                    scan_id=scan_id,
                    scan_type=scan_type,
                    runner_config=runner_config,
                )
                
                # Calculate duration
                duration = (datetime.utcnow() - start_time).total_seconds()
                
                # Update final status
                await self._update_status(db, scan_id, ScanStatus.COMPLETED.value)
                self._update_progress(
                    scan_id,
                    status="completed",
                    progress=100,
                    phase="Completed"
                )
                
                return ScanResult(
                    scan_id=scan_id,
                    status="completed",
                    findings_count=result.get("findings_count", 0),
                    critical_count=result.get("critical_count", 0),
                    high_count=result.get("high_count", 0),
                    medium_count=result.get("medium_count", 0),
                    low_count=result.get("low_count", 0),
                    info_count=result.get("info_count", 0),
                    report_path=result.get("report_path"),
                    duration_seconds=duration,
                )
                
            except asyncio.CancelledError:
                logger.warning(f"Scan {scan_id} was cancelled")
                await self._update_status(db, scan_id, ScanStatus.CANCELLED.value)
                self._update_progress(scan_id, status="cancelled", phase="Cancelled")
                raise
                
            except Exception as e:
                logger.exception(f"Scan {scan_id} failed: {e}")
                await self._update_status(db, scan_id, ScanStatus.ERROR.value)
                self._update_progress(
                    scan_id,
                    status="error",
                    phase="Failed",
                    message=str(e)
                )
                
                return ScanResult(
                    scan_id=scan_id,
                    status="error",
                    error_message=str(e),
                    duration_seconds=(datetime.utcnow() - start_time).total_seconds(),
                )
            
            finally:
                # Cleanup
                if scan_id in self._active_scans:
                    del self._active_scans[scan_id]
                otp_service.clear_state(scan_id)
    
    async def stop_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        user,
    ) -> Dict[str, Any]:
        """
        Stop a running scan.
        
        Args:
            db: Database session
            scan_id: Scan to stop
            user: Current user (for authorization)
            
        Returns:
            Dict with status message
            
        Raises:
            ValidationError: If scan not found or already stopped
            AuthorizationError: If user not authorized
        """
        from database import crud
        
        # Get scan
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            raise ValidationError("Scan not found")
        
        # Check authorization
        if str(scan.user_id) != str(user.id) and not user.is_superuser:
            raise AuthorizationError("Not authorized to stop this scan")
        
        # Check current status
        if scan.status in ("completed", "failed", "stopped", "cancelled"):
            raise ValidationError(f"Scan already {scan.status}")
        
        # Request stop
        if scan_id in self._active_scans:
            self._active_scans[scan_id].request_stop()
        
        # Update status
        await self._update_status(db, scan_id, ScanStatus.STOPPED.value)
        self._update_progress(scan_id, status="stopped", phase="Stopped by user")
        
        # Clear OTP state
        otp_service.clear_state(scan_id)
        
        logger.info(f"Scan {scan_id} stopped by {user.email}")
        
        return {"message": "Scan stopped successfully", "scan_id": scan_id}
    
    async def pause_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        user,
    ) -> Dict[str, Any]:
        """Pause a running scan for later resumption."""
        from database import crud
        
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            raise ValidationError("Scan not found")
        
        if str(scan.user_id) != str(user.id) and not user.is_superuser:
            raise AuthorizationError("Not authorized to pause this scan")
        
        if scan.status != "running":
            raise ValidationError(f"Cannot pause scan in {scan.status} state")
        
        await self._update_status(db, scan_id, ScanStatus.PAUSED.value)
        self._update_progress(scan_id, status="paused", phase="Paused")
        
        logger.info(f"Scan {scan_id} paused by {user.email}")
        
        return {"message": "Scan paused successfully", "scan_id": scan_id}
    
    async def resume_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        user,
    ) -> Dict[str, Any]:
        """Resume a paused scan from checkpoint."""
        from database import crud
        
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            raise ValidationError("Scan not found")
        
        if str(scan.user_id) != str(user.id) and not user.is_superuser:
            raise AuthorizationError("Not authorized to resume this scan")
        
        if scan.status not in ("paused", "error"):
            raise ValidationError(f"Cannot resume scan in {scan.status} state")
        
        logger.info(f"Scan {scan_id} resuming by {user.email}")
        
        # The actual resume will be handled by run_scan with resume=True
        return {
            "message": "Scan resume initiated",
            "scan_id": scan_id,
            "resume": True,
        }
    
    def get_progress(self, scan_id: str) -> Optional[ScanProgress]:
        """Get current progress for a scan."""
        return self._progress.get(scan_id)
    
    def get_all_progress(self) -> Dict[str, ScanProgress]:
        """Get progress for all tracked scans."""
        return self._progress.copy()
    
    # =========================================================================
    # VALIDATION METHODS
    # =========================================================================
    
    def _validate_target_url(self, url: str) -> None:
        """
        Validate target URL with SSRF protection.
        
        Raises:
            ValidationError: If URL is invalid or targets internal resources
        """
        if not url:
            raise ValidationError("Target URL is required")
        
        try:
            parsed = urlparse(url)
            
            if not parsed.scheme or not parsed.netloc:
                raise ValidationError("Invalid URL format")
            
            if parsed.scheme.lower() not in ["http", "https"]:
                raise ValidationError("Only HTTP/HTTPS URLs are allowed")
            
            hostname = parsed.netloc.split(":")[0].lower()
            
            # Check blocked hostnames
            if hostname in self.BLOCKED_HOSTNAMES:
                raise ValidationError(f"Target '{hostname}' is not allowed")
            
            # Check if it's an IP address
            try:
                ip = ipaddress.ip_address(hostname)
                for blocked in self.BLOCKED_IP_RANGES:
                    if ip in blocked:
                        raise ValidationError("Target is in a private/reserved IP range")
            except ValueError:
                # It's a hostname, resolve it
                try:
                    resolved = socket.gethostbyname(hostname)
                    ip = ipaddress.ip_address(resolved)
                    for blocked in self.BLOCKED_IP_RANGES:
                        if ip in blocked:
                            raise ValidationError("Target resolves to a private IP address")
                except socket.gaierror:
                    raise ValidationError(f"Cannot resolve hostname '{hostname}'")
                    
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Invalid URL: {str(e)}")
    
    async def _verify_domain_for_credentials(self, target_url: str, user) -> None:
        """
        Verify domain ownership for credential-based scanning.
        
        Raises:
            AuthorizationError: If domain not verified
        """
        from core.scope import ScopeManager
        
        scope = ScopeManager(target_url)
        target_domain = scope.get_domain_for_subscription()
        
        # Check if user has developer plan (bypasses verification for testing)
        if hasattr(user, 'plan') and user.plan == 'developer':
            logger.debug(f"Developer plan bypasses domain verification for {target_domain}")
            return
        
        if not domain_service.is_domain_verified(target_domain, user.id):
            raise AuthorizationError(
                f"Domain '{target_domain}' must be verified before credential-based scanning. "
                "Please verify domain ownership first in Settings → Domains."
            )
    
    # =========================================================================
    # SCAN EXECUTION
    # =========================================================================
    
    async def _build_runner_config(
        self,
        db: AsyncSession,
        scan_id: str,
        target_url: str,
        scan_type: str,
        user_id: int,
        login_url: Optional[str],
        username: Optional[str],
        password: Optional[str],
        two_factor_config: Optional[Dict[str, Any]],
        auth_config: Optional[Dict[str, Any]],
        attacks_config: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build configuration dict for the scan runner."""
        from database import crud
        
        # Get scan record for additional config
        scan = await crud.get_scan_by_id(db, scan_id)
        scan_config = scan.config if scan and scan.config else {}
        
        # Build runner config
        runner_config = {
            "scan_id": scan_id,
            "target": {
                "url": target_url,
                "scope": scan_config.get("scope", []),
            },
            "scan_type": scan_type,
            "user_id": user_id,
            
            # Authentication
            "auth": {
                "login_url": login_url,
                "username": username,
                "password": password,
                "method": auth_config.get("method") if auth_config else "username_password",
                **(auth_config or {}),
            },
            
            # 2FA
            "two_factor": two_factor_config or {},
            
            # Attacks
            "attacks": attacks_config or scan_config.get("attacks", {}),
            
            # Scan profile settings
            "rate_limit": scan_config.get("rate_limit", 10),
            "timeout": scan_config.get("timeout", 30),
            "max_pages": scan_config.get("max_pages", 100),
            "max_depth": scan_config.get("max_depth", 4),
            "report_formats": scan_config.get("report_formats", ["html", "json"]),
            
            # Proxy settings
            "proxy": scan_config.get("proxy", {"enabled": True, "port": 8085}),
            
            # Checkpoint/resume
            "can_resume": scan_config.get("can_resume", True),
        }
        
        # Apply scan profile presets
        profile = scan_config.get("scan_profile", "full")
        runner_config = self._apply_scan_profile(runner_config, profile)
        
        return runner_config
    
    def _apply_scan_profile(self, config: Dict[str, Any], profile: str) -> Dict[str, Any]:
        """Apply scan profile presets."""
        profiles = {
            "quick": {"max_pages": 25, "max_depth": 2},
            "full": {"max_pages": 100, "max_depth": 4},
            "api": {"max_pages": 50, "max_depth": 3},
            "authenticated": {"max_pages": 150, "max_depth": 5},
        }
        
        if profile in profiles:
            config.update(profiles[profile])
        
        return config
    
    async def _execute_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        scan_type: str,
        runner_config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Execute scan using appropriate runner.
        
        Delegates to domain-specific runners based on scan_type.
        """
        # Create status callback for progress updates
        async def status_callback(
            phase: str,
            progress: int,
            message: str = "",
            findings_count: int = 0,
        ):
            self._update_progress(
                scan_id,
                status="running",
                progress=progress,
                phase=phase,
                message=message,
            )
            await self._broadcast_progress(scan_id)
        
        # Route to appropriate runner
        if scan_type == "web":
            return await self._run_web_scan(db, scan_id, runner_config, status_callback)
        elif scan_type == "network":
            return await self._run_network_scan(db, scan_id, runner_config, status_callback)
        elif scan_type == "cloud":
            return await self._run_cloud_scan(db, scan_id, runner_config, status_callback)
        elif scan_type == "sast":
            return await self._run_sast_scan(db, scan_id, runner_config, status_callback)
        elif scan_type == "mobile":
            return await self._run_mobile_scan(db, scan_id, runner_config, status_callback)
        else:
            raise ValidationError(f"Unknown scan type: {scan_type}")
    
    async def _run_web_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        config: Dict[str, Any],
        status_callback,
    ) -> Dict[str, Any]:
        """Execute web scan using WebScanRunner."""
        try:
            from core.web_scan_runner import WebScanRunner
            
            runner = WebScanRunner(config, status_callback)
            result = await runner.run()
            
            return {
                "findings_count": result.get("total_findings", 0),
                "critical_count": result.get("critical", 0),
                "high_count": result.get("high", 0),
                "medium_count": result.get("medium", 0),
                "low_count": result.get("low", 0),
                "info_count": result.get("info", 0),
                "report_path": result.get("report_path"),
            }
            
        except ImportError:
            # Fall back to legacy PenTestRunner
            from core.runner import PenTestRunner
            
            runner = PenTestRunner(config)
            result = await runner.run()
            
            return {
                "findings_count": len(result.get("findings", [])),
                "report_path": result.get("report_path"),
            }
    
    async def _run_network_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        config: Dict[str, Any],
        status_callback,
    ) -> Dict[str, Any]:
        """Execute network scan using NetworkScanRunner."""
        from core.network_scan_runner import NetworkScanRunner
        
        runner = NetworkScanRunner(config, status_callback)
        result = await runner.run()
        
        return {
            "findings_count": result.get("total_findings", 0),
            "critical_count": result.get("critical", 0),
            "high_count": result.get("high", 0),
            "medium_count": result.get("medium", 0),
            "low_count": result.get("low", 0),
            "report_path": result.get("report_path"),
        }
    
    async def _run_cloud_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        config: Dict[str, Any],
        status_callback,
    ) -> Dict[str, Any]:
        """Execute cloud scan using CloudScanRunner."""
        from core.cloud_scan_runner import CloudScanRunner
        
        runner = CloudScanRunner(config, status_callback)
        result = await runner.run()
        
        return {
            "findings_count": result.get("total_findings", 0),
            "critical_count": result.get("critical", 0),
            "high_count": result.get("high", 0),
            "medium_count": result.get("medium", 0),
            "low_count": result.get("low", 0),
            "report_path": result.get("report_path"),
        }
    
    async def _run_sast_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        config: Dict[str, Any],
        status_callback,
    ) -> Dict[str, Any]:
        """Execute SAST scan using SASTScanRunner."""
        from core.sast_scan_runner import SASTScanRunner
        
        runner = SASTScanRunner(config, status_callback)
        result = await runner.run()
        
        return {
            "findings_count": result.get("total_findings", 0),
            "critical_count": result.get("critical", 0),
            "high_count": result.get("high", 0),
            "medium_count": result.get("medium", 0),
            "low_count": result.get("low", 0),
            "report_path": result.get("report_path"),
        }
    
    async def _run_mobile_scan(
        self,
        db: AsyncSession,
        scan_id: str,
        config: Dict[str, Any],
        status_callback,
    ) -> Dict[str, Any]:
        """Execute mobile scan using MobileAttackEngine."""
        from core.mobile_attack_engine import MobileAttackEngine
        
        runner = MobileAttackEngine(config, status_callback)
        result = await runner.run()
        
        return {
            "findings_count": result.get("total_findings", 0),
            "critical_count": result.get("critical", 0),
            "high_count": result.get("high", 0),
            "medium_count": result.get("medium", 0),
            "low_count": result.get("low", 0),
            "report_path": result.get("report_path"),
        }
    
    # =========================================================================
    # STATE & PROGRESS MANAGEMENT
    # =========================================================================
    
    async def _update_status(
        self,
        db: AsyncSession,
        scan_id: str,
        status: str,
    ) -> None:
        """Update scan status in database."""
        from database import crud
        
        await crud.update_scan_status(db, scan_id, status)
        logger.debug(f"Scan {scan_id} status updated to {status}")
    
    def _update_progress(
        self,
        scan_id: str,
        status: Optional[str] = None,
        progress: Optional[int] = None,
        phase: Optional[str] = None,
        message: Optional[str] = None,
    ) -> None:
        """Update in-memory progress tracking."""
        if scan_id not in self._progress:
            self._progress[scan_id] = ScanProgress(
                scan_id=scan_id,
                status="unknown",
            )
        
        prog = self._progress[scan_id]
        
        if status:
            prog.status = status
        if progress is not None:
            prog.progress = progress
        if phase:
            prog.phase = phase
        if message:
            prog.message = message
            prog.logs.append({
                "timestamp": datetime.utcnow().isoformat(),
                "message": message,
            })
    
    async def _broadcast_progress(self, scan_id: str) -> None:
        """Broadcast progress update via WebSocket."""
        try:
            from api.websocket import broadcast_scan_progress
            
            prog = self._progress.get(scan_id)
            if prog:
                await broadcast_scan_progress(
                    scan_id=scan_id,
                    progress=prog.progress,
                    phase=prog.phase,
                    message=prog.message,
                )
        except Exception as e:
            logger.debug(f"WebSocket broadcast failed: {e}")
    
    def cleanup_old_progress(self, max_age_hours: int = 24) -> int:
        """Clean up old progress entries."""
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        removed = 0
        
        scan_ids = list(self._progress.keys())
        for scan_id in scan_ids:
            prog = self._progress[scan_id]
            if prog.started_at and prog.started_at < cutoff:
                del self._progress[scan_id]
                removed += 1
        
        return removed


# Singleton instance
scan_orchestrator_service = ScanOrchestratorService()
