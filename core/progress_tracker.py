"""
Unified Progress Tracker - Single Source of Truth for Scan Progress

Consolidates progress tracking from multiple locations:
- In-memory state (for fast access)
- Database persistence (for reliability)
- WebSocket broadcasting (for real-time updates)

This replaces the fragmented progress tracking scattered across:
- api/routes/scans.py (scan_progress dict)
- services/sast_service.py (_progress dict)
- core/cloud_scan_runner.py (CloudScanContext)
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Callable, Awaitable
from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ProgressPhase(str, Enum):
    """Common phases across all scan types"""
    # Universal phases
    INITIALIZING = "initializing"
    RUNNING = "running"
    COMPLETING = "completing"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"
    
    # Web-specific
    PRE_LOGIN_CRAWL = "pre_login_crawl"
    AUTHENTICATION = "authentication"
    POST_LOGIN_CRAWL = "post_login_crawl"
    PRE_LOGIN_ATTACKS = "pre_login_attacks"
    POST_LOGIN_ATTACKS = "post_login_attacks"
    
    # Network-specific
    DISCOVERY = "discovery"
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    VULN_SCAN = "vuln_scan"
    SSL_AUDIT = "ssl_audit"
    
    # Cloud-specific
    CLOUD_DISCOVERY = "cloud_discovery"
    CSPM_SCAN = "cspm_scan"
    IAC_ANALYSIS = "iac_analysis"
    CONTAINER_SCAN = "container_scan"
    RUNTIME_DETECTION = "runtime_detection"
    ATTACK_PATH_ANALYSIS = "attack_path_analysis"
    
    # SAST-specific
    CLONE_REPO = "clone_repo"
    SECRET_SCAN = "secret_scan"
    DEPENDENCY_SCAN = "dependency_scan"
    CODE_ANALYSIS = "code_analysis"
    
    # Report generation
    GENERATING_REPORT = "generating_report"


@dataclass
class ScanProgress:
    """Complete progress state for a scan"""
    scan_id: str
    status: str = "queued"
    progress: int = 0  # 0-100
    phase: str = "initializing"
    message: str = ""
    current_task: str = ""
    
    # Timing
    started_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    estimated_completion: Optional[datetime] = None
    
    # Findings count (updated during scan)
    findings_count: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Scan metadata
    scan_type: str = "web"
    target: str = ""
    
    # Phase history (for debugging/monitoring)
    phase_history: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "progress": self.progress,
            "phase": self.phase,
            "message": self.message,
            "current_task": self.current_task,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "findings_count": self.findings_count,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "scan_type": self.scan_type,
            "target": self.target,
        }


# Type for database update callback
DbUpdateCallback = Callable[[str, Dict[str, Any]], Awaitable[None]]


class ProgressTracker:
    """
    Unified progress tracker with multiple output channels.
    
    Features:
    - In-memory state for fast access
    - Batched database updates (throttled to prevent SQLite locking)
    - WebSocket broadcasting for real-time UI updates
    - Thread-safe operations
    """
    
    # Class-level storage for all active scans (singleton pattern)
    _instances: Dict[str, 'ProgressTracker'] = {}
    _global_progress: Dict[str, ScanProgress] = {}
    _lock = asyncio.Lock()
    
    # Throttle settings
    DB_UPDATE_INTERVAL = 2.0  # Minimum seconds between DB updates
    WS_BROADCAST_INTERVAL = 0.5  # Minimum seconds between WebSocket broadcasts
    
    def __init__(
        self,
        scan_id: str,
        scan_type: str = "web",
        target: str = "",
        db_callback: Optional[DbUpdateCallback] = None,
        ws_enabled: bool = True
    ):
        """
        Initialize progress tracker for a scan.
        
        Args:
            scan_id: Unique scan identifier
            scan_type: Type of scan (web, network, cloud, sast, mobile)
            target: Target URL/host/repo
            db_callback: Optional callback for database updates
            ws_enabled: Whether to broadcast via WebSocket
        """
        self.scan_id = scan_id
        self.scan_type = scan_type
        self.target = target
        self._db_callback = db_callback
        self._ws_enabled = ws_enabled
        
        # Throttling state
        self._last_db_update = 0.0
        self._last_ws_broadcast = 0.0
        self._pending_db_update = False
        
        # Initialize progress state
        self._progress = ScanProgress(
            scan_id=scan_id,
            scan_type=scan_type,
            target=target,
            started_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        # Register globally
        ProgressTracker._global_progress[scan_id] = self._progress
        ProgressTracker._instances[scan_id] = self
    
    @classmethod
    def get(cls, scan_id: str) -> Optional['ProgressTracker']:
        """Get existing progress tracker by scan_id"""
        return cls._instances.get(scan_id)
    
    @classmethod
    def get_progress(cls, scan_id: str) -> Optional[ScanProgress]:
        """Get progress state by scan_id (without tracker instance)"""
        return cls._global_progress.get(scan_id)
    
    @classmethod
    def get_all_active(cls) -> Dict[str, ScanProgress]:
        """Get all active scan progress states"""
        return {
            scan_id: progress
            for scan_id, progress in cls._global_progress.items()
            if progress.status in ("queued", "running", "paused")
        }
    
    async def update(
        self,
        progress: Optional[int] = None,
        phase: Optional[str] = None,
        status: Optional[str] = None,
        message: Optional[str] = None,
        current_task: Optional[str] = None,
        findings_count: Optional[int] = None,
        critical_count: Optional[int] = None,
        high_count: Optional[int] = None,
        medium_count: Optional[int] = None,
        low_count: Optional[int] = None,
        info_count: Optional[int] = None,
        force_broadcast: bool = False,
    ) -> None:
        """
        Update progress state and optionally broadcast.
        
        Only changed values need to be provided. Broadcasts are throttled
        unless force_broadcast is True.
        """
        now = datetime.utcnow()
        old_phase = self._progress.phase
        
        # Update only provided values
        if progress is not None:
            self._progress.progress = max(0, min(100, progress))
        if phase is not None:
            self._progress.phase = phase
        if status is not None:
            self._progress.status = status
        if message is not None:
            self._progress.message = message
        if current_task is not None:
            self._progress.current_task = current_task
        if findings_count is not None:
            self._progress.findings_count = findings_count
        if critical_count is not None:
            self._progress.critical_count = critical_count
        if high_count is not None:
            self._progress.high_count = high_count
        if medium_count is not None:
            self._progress.medium_count = medium_count
        if low_count is not None:
            self._progress.low_count = low_count
        if info_count is not None:
            self._progress.info_count = info_count
        
        self._progress.updated_at = now
        
        # Track phase transitions
        if phase and phase != old_phase:
            self._progress.phase_history.append({
                "phase": phase,
                "timestamp": now.isoformat(),
                "progress": self._progress.progress
            })
        
        # Broadcast via WebSocket (throttled)
        if self._ws_enabled:
            await self._broadcast_ws(force=force_broadcast)
        
        # Update database (throttled)
        await self._update_db(force=force_broadcast)
    
    async def _broadcast_ws(self, force: bool = False) -> None:
        """Broadcast progress via WebSocket (throttled)"""
        import time
        now = time.time()
        
        if not force and (now - self._last_ws_broadcast) < self.WS_BROADCAST_INTERVAL:
            return
        
        self._last_ws_broadcast = now
        
        try:
            from api.websocket import broadcast_scan_progress
            await broadcast_scan_progress(
                scan_id=self.scan_id,
                progress=self._progress.progress,
                phase=self._progress.phase,
                message=self._progress.message,
                findings_count=self._progress.findings_count,
                current_task=self._progress.current_task,
            )
        except ImportError:
            logger.debug("WebSocket module not available")
        except Exception as e:
            logger.warning(f"Failed to broadcast progress: {e}")
    
    async def _update_db(self, force: bool = False) -> None:
        """Update database with current progress (throttled)"""
        import time
        now = time.time()
        
        if not force and (now - self._last_db_update) < self.DB_UPDATE_INTERVAL:
            self._pending_db_update = True
            return
        
        self._last_db_update = now
        self._pending_db_update = False
        
        if self._db_callback:
            try:
                await self._db_callback(self.scan_id, {
                    "status": self._progress.status,
                    "progress": self._progress.progress,
                    "phase": self._progress.phase,
                    "findings_count": self._progress.findings_count,
                    "critical_count": self._progress.critical_count,
                    "high_count": self._progress.high_count,
                    "medium_count": self._progress.medium_count,
                    "low_count": self._progress.low_count,
                })
            except Exception as e:
                logger.error(f"Failed to update database: {e}")
    
    async def set_started(self) -> None:
        """Mark scan as started"""
        self._progress.started_at = datetime.utcnow()
        await self.update(status="running", phase="initializing", progress=0, force_broadcast=True)
    
    async def set_completed(self, findings_count: int = 0) -> None:
        """Mark scan as completed"""
        await self.update(
            status="completed",
            phase="completed",
            progress=100,
            findings_count=findings_count,
            force_broadcast=True
        )
    
    async def set_error(self, error_message: str) -> None:
        """Mark scan as errored"""
        await self.update(
            status="error",
            phase="error",
            message=error_message,
            force_broadcast=True
        )
    
    async def set_stopped(self) -> None:
        """Mark scan as stopped by user"""
        await self.update(
            status="stopped",
            phase="stopped",
            message="Scan stopped by user",
            force_broadcast=True
        )
    
    async def increment_finding(self, severity: str) -> None:
        """Increment finding count by severity"""
        severity = severity.lower()
        self._progress.findings_count += 1
        
        if severity == "critical":
            self._progress.critical_count += 1
        elif severity == "high":
            self._progress.high_count += 1
        elif severity == "medium":
            self._progress.medium_count += 1
        elif severity == "low":
            self._progress.low_count += 1
        else:
            self._progress.info_count += 1
        
        await self._broadcast_ws()
    
    def get_state(self) -> ScanProgress:
        """Get current progress state"""
        return self._progress
    
    def get_dict(self) -> Dict[str, Any]:
        """Get current progress as dictionary"""
        return self._progress.to_dict()
    
    async def flush(self) -> None:
        """Flush any pending updates to database"""
        if self._pending_db_update:
            await self._update_db(force=True)
    
    async def cleanup(self) -> None:
        """Cleanup tracker when scan is done"""
        await self.flush()
        
        # Keep in global state for a while (for status queries)
        # Could add TTL-based cleanup here
        ProgressTracker._instances.pop(self.scan_id, None)
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Sync cleanup - schedule async cleanup
        asyncio.create_task(self.cleanup())


__all__ = [
    "ProgressPhase",
    "ScanProgress",
    "ProgressTracker",
    "DbUpdateCallback",
]
