"""
Unified Scan Orchestrator - Central Management for All Scan Types

This is the single entry point for all scan orchestration, providing:
- State machine enforcement (via ScanStateMachine)
- Unified progress tracking (via ProgressTracker)
- Checkpoint/resume capability (via ScanCheckpoint)
- Engine factory pattern for scan type selection
- WebSocket broadcasting
- Database persistence

The orchestrator WRAPS existing runners without modifying them,
following the Strangler Fig pattern for safe migration.

Usage:
    from core.scan_orchestrator import ScanOrchestrator
    
    orchestrator = ScanOrchestrator(
        scan_id="abc123",
        scan_type="web",
        user_id=user.id,
        config=scan_config,
        db=db_session,
    )
    
    result = await orchestrator.run()
"""

import asyncio
import logging
import uuid
from typing import Dict, Any, Optional, Type, Callable, Awaitable, List, TYPE_CHECKING
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum

# Type checking imports (avoid circular imports at runtime)
if TYPE_CHECKING:
    from core.jarwis_http_client import JarwisHTTPClient
    from core.token_manager import TokenManager
    from core.request_store_db import RequestStoreDB
    from core.scan_checkpoint import RequestLevelCheckpoint

# Internal imports
from services.scan_state_machine import (
    ScanStateMachine, 
    ScanStatus, 
    validate_status_transition
)
from core.engine_protocol import (
    EngineType,
    EngineResult,
    ProgressUpdate,
    ScanEngineProtocol,
    ScanEngineAdapter,
)
from core.progress_tracker import ProgressTracker, ScanProgress

logger = logging.getLogger(__name__)


class OrchestratorError(Exception):
    """Base exception for orchestrator errors"""
    pass


class InvalidStateTransition(OrchestratorError):
    """Raised when an invalid state transition is attempted"""
    pass


class EngineNotFound(OrchestratorError):
    """Raised when no engine is registered for a scan type"""
    pass


class ScanCancelled(OrchestratorError):
    """Raised when a scan is cancelled during execution"""
    pass


@dataclass
class ScanContext:
    """
    Context passed to engines and maintained during scan lifecycle.
    
    This provides engines with everything they need without coupling
    them to the orchestrator implementation.
    """
    scan_id: str
    scan_type: str
    user_id: Optional[int]
    config: Dict[str, Any]
    
    # Runtime state
    started_at: Optional[datetime] = None
    current_phase: str = "initializing"
    
    # Stop flag for cancellation
    _stop_requested: bool = False
    
    def request_stop(self) -> None:
        """Request graceful stop of the scan"""
        self._stop_requested = True
    
    def should_stop(self) -> bool:
        """Check if stop has been requested"""
        return self._stop_requested


class ScanOrchestrator:
    """
    Unified orchestrator for all scan types.
    
    Responsibilities:
    - State machine transitions (queued → running → completed)
    - Progress tracking (single source of truth)
    - Checkpoint/resume for all scan types
    - Engine selection and lifecycle management
    - Error handling and recovery
    - WebSocket broadcasting
    
    The orchestrator delegates actual scanning to domain-specific engines
    (WebScanRunner, NetworkOrchestrator, CloudScanRunner, etc.)
    """
    
    # Registry of engine factories by scan type
    # Populated by register_engine() or on first use
    _engine_registry: Dict[str, Callable[..., ScanEngineProtocol]] = {}
    
    # Default engine mappings (loaded lazily)
    _default_engines = {
        "web": "core.engines.web_engine.WebEngineAdapter",
        "network": "core.engines.network_engine.NetworkEngineAdapter",
        "cloud": "core.engines.cloud_engine.CloudEngineAdapter",
        "sast": "core.engines.sast_engine.SASTEngineAdapter",
        "mobile": "core.engines.mobile_engine.MobileEngineAdapter",
    }
    
    # Track active scans (for stop/status queries)
    _active_scans: Dict[str, 'ScanOrchestrator'] = {}
    
    def __init__(
        self,
        scan_id: str,
        scan_type: str,
        config: Dict[str, Any],
        user_id: Optional[int] = None,
        db: Optional[Any] = None,  # AsyncSession
        resume: bool = False,
    ):
        """
        Initialize the scan orchestrator.
        
        Args:
            scan_id: Unique identifier for this scan
            scan_type: Type of scan (web, network, cloud, sast, mobile)
            config: Scan configuration dictionary
            user_id: ID of user who initiated the scan
            db: Database session for persistence
            resume: Whether to attempt resuming from checkpoint
        """
        self.scan_id = scan_id
        self.scan_type = scan_type.lower()
        self.config = config
        self.user_id = user_id
        self.db = db
        self.resume = resume
        
        # State management
        self.state_machine = ScanStateMachine()
        self._current_status = ScanStatus.QUEUED.value
        
        # Context for engines
        self.context = ScanContext(
            scan_id=scan_id,
            scan_type=self.scan_type,
            user_id=user_id,
            config=config,
        )
        
        # Progress tracking
        self.progress_tracker = ProgressTracker(
            scan_id=scan_id,
            scan_type=self.scan_type,
            target=config.get("target_url") or config.get("target") or "",
            db_callback=self._db_update_callback if db else None,
            ws_enabled=True,
        )
        
        # Checkpoint management (optional)
        self._checkpoint = None
        self._load_checkpoint_if_resuming()
        
        # Engine instance (created on run())
        self._engine: Optional[ScanEngineProtocol] = None
        
        # Result
        self._result: Optional[EngineResult] = None
        
        # Register as active
        ScanOrchestrator._active_scans[scan_id] = self
        
        logger.info(f"Orchestrator initialized: scan_id={scan_id}, type={scan_type}")
    
    def _load_checkpoint_if_resuming(self) -> None:
        """Load checkpoint if resuming a previous scan"""
        if not self.resume:
            return
        
        try:
            from core.scan_checkpoint import ScanCheckpoint
            self._checkpoint = ScanCheckpoint(self.scan_id)
            state = self._checkpoint.load()
            
            if state:
                logger.info(f"Loaded checkpoint for scan {self.scan_id}: phase={state.current_phase}")
                self.context.current_phase = state.current_phase
        except ImportError:
            logger.debug("Checkpoint module not available")
        except Exception as e:
            logger.warning(f"Failed to load checkpoint: {e}")
    
    async def _db_update_callback(self, scan_id: str, data: Dict[str, Any]) -> None:
        """Callback to update scan in database"""
        if not self.db:
            return
        
        try:
            from database import crud
            await crud.update_scan_status(
                self.db,
                scan_id,
                status=data.get("status"),
                progress=data.get("progress"),
                phase=data.get("phase"),
            )
        except Exception as e:
            logger.error(f"Database update failed: {e}")
    
    @classmethod
    def register_engine(
        cls, 
        scan_type: str, 
        factory: Callable[..., ScanEngineProtocol]
    ) -> None:
        """
        Register an engine factory for a scan type.
        
        Args:
            scan_type: Type identifier (web, network, etc.)
            factory: Callable that creates engine instances
        """
        cls._engine_registry[scan_type.lower()] = factory
        logger.info(f"Registered engine for scan type: {scan_type}")
    
    @classmethod
    def get_active_scan(cls, scan_id: str) -> Optional['ScanOrchestrator']:
        """Get an active orchestrator by scan_id"""
        return cls._active_scans.get(scan_id)
    
    @classmethod
    def get_all_active(cls) -> Dict[str, 'ScanOrchestrator']:
        """Get all active orchestrators"""
        return cls._active_scans.copy()
    
    def _create_engine(self) -> ScanEngineProtocol:
        """Create the appropriate engine for this scan type"""
        # Check registry first
        if self.scan_type in self._engine_registry:
            factory = self._engine_registry[self.scan_type]
            return factory(self.config, self.context)
        
        # Try to load default engine
        if self.scan_type in self._default_engines:
            module_path = self._default_engines[self.scan_type]
            try:
                # Dynamic import
                module_name, class_name = module_path.rsplit(".", 1)
                module = __import__(module_name, fromlist=[class_name])
                engine_class = getattr(module, class_name)
                return engine_class(self.config, self.context)
            except (ImportError, AttributeError) as e:
                logger.warning(f"Failed to load engine {module_path}: {e}")
                # Fall through to legacy adapter
        
        # Fall back to legacy runner wrapper
        return self._create_legacy_adapter()
    
    def _create_legacy_adapter(self) -> ScanEngineProtocol:
        """
        Create an adapter that wraps existing legacy runners.
        
        This allows gradual migration - existing runners work immediately
        without modification.
        """
        from core.engines.legacy_adapter import LegacyEngineAdapter
        return LegacyEngineAdapter(self.scan_type, self.config, self.context)
    
    def _transition_status(self, target_status: str) -> None:
        """
        Transition to a new status with validation.
        
        Raises:
            InvalidStateTransition: If transition is not valid
        """
        is_valid, message = validate_status_transition(
            self._current_status, 
            target_status, 
            self.scan_id
        )
        
        if not is_valid:
            raise InvalidStateTransition(message)
        
        old_status = self._current_status
        self._current_status = target_status
        logger.info(f"Scan {self.scan_id}: {old_status} → {target_status}")
    
    async def _handle_progress(self, update: ProgressUpdate) -> None:
        """Handle progress update from engine"""
        await self.progress_tracker.update(
            progress=update.progress,
            phase=update.phase,
            message=update.message,
            current_task=update.current_task,
            findings_count=update.findings_count,
        )
    
    async def _check_should_stop(self) -> bool:
        """Check if scan should stop (for engine callback)"""
        return self.context.should_stop()
    
    async def run(self) -> EngineResult:
        """
        Execute the scan.
        
        This is the main entry point. It:
        1. Transitions to RUNNING state
        2. Creates and configures the engine
        3. Runs the engine
        4. Handles completion/error states
        5. Returns results
        
        Returns:
            EngineResult with findings and summary
            
        Raises:
            InvalidStateTransition: If cannot transition to RUNNING
            EngineNotFound: If no engine available for scan type
            ScanCancelled: If scan was stopped during execution
        """
        start_time = datetime.utcnow()
        self.context.started_at = start_time
        
        try:
            # Transition: queued → running
            self._transition_status(ScanStatus.RUNNING.value)
            await self.progress_tracker.set_started()
            
            # Create engine
            self._engine = self._create_engine()
            
            # Configure engine callbacks
            self._engine.set_progress_callback(self._handle_progress)
            self._engine.set_stop_check(self._check_should_stop)
            
            logger.info(f"Starting {self.scan_type} scan: {self.scan_id}")
            
            # Run the engine
            self._result = await self._engine.run()
            
            # Check if stopped
            if self.context.should_stop():
                self._transition_status(ScanStatus.STOPPED.value)
                await self.progress_tracker.set_stopped()
                raise ScanCancelled(f"Scan {self.scan_id} was stopped")
            
            # Determine final status
            if self._result.status == "error":
                self._transition_status(ScanStatus.ERROR.value)
                await self.progress_tracker.set_error(
                    self._result.error_message or "Unknown error"
                )
            else:
                self._transition_status(ScanStatus.COMPLETED.value)
                await self.progress_tracker.set_completed(
                    findings_count=len(self._result.findings)
                )
            
            # Calculate duration
            end_time = datetime.utcnow()
            self._result.started_at = start_time
            self._result.completed_at = end_time
            self._result.duration_seconds = (end_time - start_time).total_seconds()
            
            logger.info(
                f"Scan {self.scan_id} completed: "
                f"status={self._result.status}, "
                f"findings={len(self._result.findings)}, "
                f"duration={self._result.duration_seconds:.1f}s"
            )
            
            return self._result
            
        except ScanCancelled:
            raise
        except InvalidStateTransition as e:
            logger.error(f"State transition error: {e}")
            raise
        except Exception as e:
            logger.exception(f"Scan {self.scan_id} failed with error: {e}")
            
            # Try to transition to error state
            try:
                self._transition_status(ScanStatus.ERROR.value)
            except InvalidStateTransition:
                pass
            
            await self.progress_tracker.set_error(str(e))
            
            # Return error result
            return EngineResult(
                status="error",
                error_message=str(e),
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
        finally:
            # Cleanup
            await self._cleanup()
    
    async def stop(self) -> bool:
        """
        Request graceful stop of the scan.
        
        Returns:
            True if stop was requested, False if scan not active
        """
        if not self.state_machine.is_active_status(self._current_status):
            logger.warning(f"Cannot stop scan {self.scan_id}: not active (status={self._current_status})")
            return False
        
        logger.info(f"Stop requested for scan {self.scan_id}")
        self.context.request_stop()
        return True
    
    async def pause(self) -> bool:
        """
        Pause the scan (if supported by engine).
        
        Returns:
            True if paused, False if not supported or not active
        """
        if self._current_status != ScanStatus.RUNNING.value:
            return False
        
        try:
            self._transition_status(ScanStatus.PAUSED.value)
            await self.progress_tracker.update(status="paused", phase="paused")
            return True
        except InvalidStateTransition:
            return False
    
    async def resume_scan(self) -> bool:
        """
        Resume a paused scan.
        
        Returns:
            True if resumed, False if not paused
        """
        if self._current_status != ScanStatus.PAUSED.value:
            return False
        
        try:
            self._transition_status(ScanStatus.RUNNING.value)
            await self.progress_tracker.update(status="running")
            return True
        except InvalidStateTransition:
            return False
    
    def get_status(self) -> str:
        """Get current scan status"""
        return self._current_status
    
    def get_progress(self) -> ScanProgress:
        """Get current progress state"""
        return self.progress_tracker.get_state()
    
    def get_result(self) -> Optional[EngineResult]:
        """Get scan result (None if not completed)"""
        return self._result
    
    async def _cleanup(self) -> None:
        """Cleanup resources after scan completion"""
        # Flush progress updates
        await self.progress_tracker.flush()
        
        # Remove from active scans
        ScanOrchestrator._active_scans.pop(self.scan_id, None)
        
        logger.debug(f"Cleanup completed for scan {self.scan_id}")


# Convenience function for creating and running scans
async def run_scan(
    scan_type: str,
    config: Dict[str, Any],
    user_id: Optional[int] = None,
    db: Optional[Any] = None,
    scan_id: Optional[str] = None,
) -> EngineResult:
    """
    Convenience function to create orchestrator and run scan.
    
    Args:
        scan_type: Type of scan (web, network, cloud, sast, mobile)
        config: Scan configuration
        user_id: User ID
        db: Database session
        scan_id: Optional custom scan ID (generated if not provided)
    
    Returns:
        EngineResult with scan results
    """
    if not scan_id:
        scan_id = f"{scan_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    
    orchestrator = ScanOrchestrator(
        scan_id=scan_id,
        scan_type=scan_type,
        config=config,
        user_id=user_id,
        db=db,
    )
    
    return await orchestrator.run()


# Function to stop a running scan
async def stop_scan(scan_id: str) -> bool:
    """
    Stop a running scan by ID.
    
    Args:
        scan_id: ID of scan to stop
    
    Returns:
        True if stop requested, False if scan not found or not active
    """
    orchestrator = ScanOrchestrator.get_active_scan(scan_id)
    if orchestrator:
        return await orchestrator.stop()
    return False


__all__ = [
    "ScanOrchestrator",
    "ScanContext",
    "OrchestratorError",
    "InvalidStateTransition",
    "EngineNotFound",
    "ScanCancelled",
    "run_scan",
    "stop_scan",
    "WebAttackOrchestrator",
]


# =============================================================================
# WebAttackOrchestrator - New MITM-first attack methodology
# =============================================================================

class WebAttackOrchestrator:
    """
    Unified Web Attack Orchestrator implementing correct hacker methodology.
    
    This orchestrator ensures ALL attacks flow through MITM proxy, following
    the Burp Suite Repeater pattern:
    
    Phase 1 (Pre-login Crawl):
        1. Start MITM proxy
        2. Crawl target through MITM → capture all requests
        3. Store captured requests in RequestStoreDB
        
    Phase 2 (Attack with Auth):
        4. Login to get auth tokens (TokenManager handles refresh)
        5. For each stored request:
            6. Load request from store
            7. Modify headers/body (like Burp Repeater)
            8. Send modified request THROUGH MITM
            9. Analyze response for vulnerability patterns
            10. Report findings with evidence
    
    Usage:
        orchestrator = WebAttackOrchestrator(
            scan_id="abc123",
            target_url="https://example.com",
            auth_config={"username": "...", "password": "..."},
            proxy_port=mitm_proxy.port  # Use allocated port from MITMPortManager
        )
        findings = await orchestrator.run_full_scan()
    """
    
    def __init__(
        self,
        scan_id: str,
        target_url: str,
        config: Optional[Dict[str, Any]] = None,
        auth_config: Optional[Dict[str, Any]] = None,
        proxy_port: int = None,  # None = auto-allocate via MITMPortManager
        db_path: Optional[str] = None,
        checkpoint_dir: Optional[str] = None
    ):
        """
        Initialize the web attack orchestrator.
        
        Args:
            scan_id: Unique identifier for this scan
            target_url: Target URL to scan
            config: Scan configuration
            auth_config: Authentication configuration for post-login scanning
            proxy_port: Port for MITM proxy (None = auto-allocate, or use allocated port)
            db_path: Path for SQLite request store (default: data/requests_{scan_id}.db)
            checkpoint_dir: Directory for checkpoint files
        """
        self.scan_id = scan_id
        self.target_url = target_url
        self.config = config or {}
        self.auth_config = auth_config
        self.proxy_port = proxy_port or 8080  # Default fallback
        
        # Set up paths
        self.db_path = db_path or f"data/requests_{scan_id}.db"
        self.checkpoint_dir = checkpoint_dir or f"data/checkpoints/{scan_id}"
        
        # Components (initialized lazily)
        self._http_client: Optional['JarwisHTTPClient'] = None
        self._token_manager: Optional['TokenManager'] = None
        self._request_store: Optional['RequestStoreDB'] = None
        self._checkpoint: Optional['RequestLevelCheckpoint'] = None
        self._mitm_process = None
        
        # Scanner instances
        self._scanners: List[Any] = []
        
        # State
        self._initialized = False
        self._cancelled = False
        self._findings: List[Any] = []
        self._stats = {
            'requests_captured': 0,
            'requests_scanned': 0,
            'vulnerabilities_found': 0,
            'scanners_run': 0,
            'errors': 0
        }
        
        logger.info(f"WebAttackOrchestrator created: scan_id={scan_id}, target={target_url}")
    
    async def initialize(self) -> None:
        """Initialize all components (call before run)."""
        if self._initialized:
            return
        
        logger.info(f"[{self.scan_id}] Initializing components...")
        
        # Import here to avoid circular imports
        from core.jarwis_http_client import JarwisHTTPClient
        from core.request_store_db import RequestStoreDB
        from core.scan_checkpoint import RequestLevelCheckpoint
        
        # Initialize request store (SQLite-backed)
        self._request_store = RequestStoreDB(self.db_path)
        await self._request_store.initialize()
        
        # Initialize checkpoint for resume capability
        self._checkpoint = RequestLevelCheckpoint(
            scan_id=self.scan_id,
            checkpoint_dir=self.checkpoint_dir
        )
        await self._checkpoint.load()
        
        # Initialize HTTP client (routes through MITM)
        self._http_client = JarwisHTTPClient(
            proxy_host="127.0.0.1",
            proxy_port=self.proxy_port,
            ssl_verify=False
        )
        await self._http_client.initialize()
        
        # Initialize token manager if auth configured
        if self.auth_config:
            from core.token_manager import TokenManager
            self._token_manager = TokenManager(
                auth_config=self.auth_config,
                http_client=self._http_client
            )
        
        self._initialized = True
        logger.info(f"[{self.scan_id}] Components initialized")
    
    async def cleanup(self) -> None:
        """Clean up resources."""
        logger.info(f"[{self.scan_id}] Cleaning up...")
        
        if self._http_client:
            await self._http_client.close()
        
        if self._request_store:
            await self._request_store.close()
        
        if self._checkpoint:
            await self._checkpoint.flush()
        
        if self._token_manager:
            await self._token_manager.stop()
        
        if self._mitm_process:
            self._mitm_process.terminate()
        
        self._initialized = False
        logger.info(f"[{self.scan_id}] Cleanup complete")
    
    async def start_mitm_proxy(self) -> bool:
        """Start the MITM proxy for traffic capture."""
        import subprocess
        import sys
        
        logger.info(f"[{self.scan_id}] Starting MITM proxy on port {self.proxy_port}...")
        
        try:
            # Start mitmproxy with our addon (in temp/ to avoid triggering uvicorn --reload)
            cmd = [
                sys.executable, "-m", "mitmproxy",
                "--mode", "regular",
                "--listen-port", str(self.proxy_port),
                "--set", "ssl_insecure=true",
                "-s", "temp/mitm_addon.py"
            ]
            
            self._mitm_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            # Wait for proxy to be ready
            await asyncio.sleep(2)
            
            if self._mitm_process.poll() is None:
                logger.info(f"[{self.scan_id}] MITM proxy started successfully")
                return True
            else:
                logger.error(f"[{self.scan_id}] MITM proxy failed to start")
                return False
                
        except Exception as e:
            logger.error(f"[{self.scan_id}] Failed to start MITM: {e}")
            return False
    
    async def run_crawl_phase(self) -> int:
        """
        Phase 1: Crawl the target and capture requests.
        
        Returns:
            Number of requests captured
        """
        logger.info(f"[{self.scan_id}] Starting crawl phase...")
        
        # Use existing crawler but route through our proxy
        from core.browser import BrowserManager
        
        browser = BrowserManager(
            proxy=f"http://127.0.0.1:{self.proxy_port}"
        )
        
        try:
            await browser.start()
            
            # Crawl the target
            endpoints = await browser.crawl(
                self.target_url,
                max_pages=self.config.get('max_pages', 100),
                depth=self.config.get('crawl_depth', 3)
            )
            
            # Captured requests are already in MITM log, import them
            captured = await self._import_mitm_captures()
            self._stats['requests_captured'] = captured
            
            logger.info(f"[{self.scan_id}] Crawl complete: {captured} requests captured")
            return captured
            
        finally:
            await browser.close()
    
    async def _import_mitm_captures(self) -> int:
        """Import captured requests from MITM log to RequestStore."""
        import json
        from pathlib import Path
        
        log_path = Path(f"logs/mitm_crawl_{self.scan_id}.jsonl")
        if not log_path.exists():
            return 0
        
        count = 0
        with open(log_path, 'r') as f:
            for line in f:
                try:
                    data = json.loads(line)
                    await self._request_store.store_request(
                        url=data['url'],
                        method=data['method'],
                        headers=data.get('headers', {}),
                        body=data.get('body', ''),
                        cookies=data.get('cookies', {}),
                        post_login=False
                    )
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to import request: {e}")
        
        return count
    
    async def run_auth_phase(self) -> bool:
        """
        Authenticate and start token refresh.
        
        Returns:
            True if authentication successful
        """
        if not self._token_manager:
            logger.info(f"[{self.scan_id}] No auth configured, skipping")
            return True
        
        logger.info(f"[{self.scan_id}] Starting authentication...")
        
        success = await self._token_manager.authenticate()
        if success:
            # Start background token refresh
            await self._token_manager.start_refresh_loop()
            logger.info(f"[{self.scan_id}] Authentication successful")
        else:
            logger.error(f"[{self.scan_id}] Authentication failed")
        
        return success
    
    def register_scanner(self, scanner_class: type) -> None:
        """Register a scanner class to run during attack phase."""
        self._scanners.append(scanner_class)
        logger.debug(f"Registered scanner: {scanner_class.__name__}")
    
    def register_all_scanners(self) -> None:
        """Register all available web scanners."""
        from attacks.registry import ScannerRegistry, ScanType
        
        for scanner_info in ScannerRegistry.get_scanners(ScanType.WEB):
            try:
                scanner_class = ScannerRegistry.get_scanner_class(scanner_info.name)
                if scanner_class:
                    self._scanners.append(scanner_class)
            except Exception as e:
                logger.warning(f"Failed to load scanner {scanner_info.name}: {e}")
        
        logger.info(f"Registered {len(self._scanners)} web scanners")
    
    async def run_attack_phase(self, post_login: bool = False) -> List[Any]:
        """
        Phase 2: Run all registered scanners on captured requests.
        
        Args:
            post_login: Whether to scan post-login requests
            
        Returns:
            List of all findings
        """
        logger.info(f"[{self.scan_id}] Starting attack phase (post_login={post_login})...")
        
        all_findings = []
        
        for scanner_class in self._scanners:
            if self._cancelled:
                break
            
            try:
                # Create scanner instance with our components
                scanner = scanner_class(
                    http_client=self._http_client,
                    request_store=self._request_store,
                    checkpoint=self._checkpoint,
                    token_manager=self._token_manager,
                    config=self.config
                )
                
                logger.info(f"[{self.scan_id}] Running scanner: {scanner.scanner_name}")
                
                # Run scanner
                findings = await scanner.run(post_login=post_login)
                all_findings.extend(findings)
                
                self._stats['scanners_run'] += 1
                self._stats['vulnerabilities_found'] += len(findings)
                
                logger.info(
                    f"[{self.scan_id}] {scanner.scanner_name} complete: "
                    f"{len(findings)} findings"
                )
                
            except Exception as e:
                self._stats['errors'] += 1
                logger.error(f"[{self.scan_id}] Scanner {scanner_class.__name__} failed: {e}")
        
        self._findings.extend(all_findings)
        return all_findings
    
    async def run_full_scan(self) -> Dict[str, Any]:
        """
        Run the complete scan workflow.
        
        Returns:
            Dict with findings and statistics
        """
        start_time = datetime.utcnow()
        
        try:
            # Initialize
            await self.initialize()
            
            # Start MITM
            await self.start_mitm_proxy()
            
            # Phase 1: Crawl
            await self.run_crawl_phase()
            
            # Auth
            await self.run_auth_phase()
            
            # Register scanners if none registered
            if not self._scanners:
                self.register_all_scanners()
            
            # Phase 2: Attack (pre-login requests)
            await self.run_attack_phase(post_login=False)
            
            # Phase 2: Attack (post-login requests if auth configured)
            if self._token_manager:
                await self.run_attack_phase(post_login=True)
            
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            return {
                'scan_id': self.scan_id,
                'target': self.target_url,
                'status': 'completed',
                'findings': [f.to_dict() if hasattr(f, 'to_dict') else f for f in self._findings],
                'findings_count': len(self._findings),
                'statistics': self._stats,
                'started_at': start_time.isoformat(),
                'completed_at': end_time.isoformat(),
                'duration_seconds': duration
            }
            
        except Exception as e:
            logger.exception(f"[{self.scan_id}] Scan failed: {e}")
            return {
                'scan_id': self.scan_id,
                'target': self.target_url,
                'status': 'error',
                'error': str(e),
                'findings': [f.to_dict() if hasattr(f, 'to_dict') else f for f in self._findings],
                'statistics': self._stats
            }
        finally:
            await self.cleanup()
    
    def cancel(self) -> None:
        """Cancel the running scan."""
        self._cancelled = True
        logger.info(f"[{self.scan_id}] Cancellation requested")
