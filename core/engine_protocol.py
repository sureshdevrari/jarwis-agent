"""
Scan Engine Protocol - Interface for Domain-Specific Scan Engines

Defines the contract that all scan engines (Web, Network, Cloud, SAST, Mobile)
must implement to work with the unified ScanOrchestrator.

The protocol pattern allows existing runners to be wrapped without modification,
following the Strangler Fig refactoring pattern.
"""

from typing import Protocol, Dict, Any, List, Optional, Callable, Awaitable, runtime_checkable
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class EngineType(str, Enum):
    """Supported scan engine types"""
    WEB = "web"
    NETWORK = "network"
    CLOUD = "cloud"
    SAST = "sast"
    MOBILE = "mobile"


@dataclass
class EngineResult:
    """
    Standardized result from any scan engine.
    
    All engines return this format, regardless of their internal structure.
    The orchestrator uses this to update database and broadcast results.
    """
    status: str  # completed, error, stopped
    findings: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None
    
    # Timing
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    
    # Statistics
    total_requests: int = 0
    total_endpoints: int = 0
    scanners_run: int = 0
    scanners_failed: int = 0
    
    # Severity counts
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Report paths (if generated)
    report_paths: Dict[str, str] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "status": self.status,
            "findings_count": len(self.findings),
            "summary": self.summary,
            "error_message": self.error_message,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": self.duration_seconds,
            "total_requests": self.total_requests,
            "total_endpoints": self.total_endpoints,
            "scanners_run": self.scanners_run,
            "scanners_failed": self.scanners_failed,
            "severity_counts": {
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count,
                "info": self.info_count,
            },
            "report_paths": self.report_paths,
        }


@dataclass
class ProgressUpdate:
    """Standardized progress update from engines"""
    progress: int  # 0-100
    phase: str
    message: str = ""
    current_task: str = ""
    findings_count: int = 0


# Type aliases for callbacks
ProgressCallback = Callable[[ProgressUpdate], Awaitable[None]]
StopCheck = Callable[[], Awaitable[bool]]
LogCallback = Callable[[str, str], None]  # (level, message)


@runtime_checkable
class ScanEngineProtocol(Protocol):
    """
    Protocol (interface) that all scan engines must implement.
    
    This uses Python's Protocol for structural subtyping - any class
    that implements these methods is considered a valid ScanEngine,
    even without explicit inheritance.
    
    Existing runners (WebScanRunner, CloudScanRunner, etc.) can be
    wrapped with adapters that implement this protocol.
    """
    
    async def run(self) -> EngineResult:
        """
        Execute the scan and return results.
        
        The engine should:
        1. Execute domain-specific scanning logic
        2. Call progress_callback periodically
        3. Check stop_check to support cancellation
        4. Return EngineResult with findings and summary
        
        Returns:
            EngineResult with status, findings, and metadata
        """
        ...
    
    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """
        Set callback for progress updates.
        
        The engine should call this callback at meaningful intervals
        (e.g., phase transitions, every N% progress).
        
        Args:
            callback: Async function that receives ProgressUpdate
        """
        ...
    
    def set_stop_check(self, callback: StopCheck) -> None:
        """
        Set callback to check if scan should stop.
        
        The engine should periodically call this and gracefully
        terminate if it returns True.
        
        Args:
            callback: Async function that returns True if scan should stop
        """
        ...


class ScanEngineAdapter:
    """
    Base adapter class for wrapping existing runners.
    
    Subclass this to create adapters for existing runners that
    don't implement ScanEngineProtocol directly.
    
    Example:
        class WebEngineAdapter(ScanEngineAdapter):
            def __init__(self, config, ...):
                self._runner = WebScanRunner(config, ...)
            
            async def run(self) -> EngineResult:
                result = await self._runner.run()
                return self._convert_to_engine_result(result)
    """
    
    def __init__(self):
        self._progress_callback: Optional[ProgressCallback] = None
        self._stop_check: Optional[StopCheck] = None
        self._log_callback: Optional[LogCallback] = None
    
    def set_progress_callback(self, callback: ProgressCallback) -> None:
        """Set progress callback"""
        self._progress_callback = callback
    
    def set_stop_check(self, callback: StopCheck) -> None:
        """Set stop check callback"""
        self._stop_check = callback
    
    def set_log_callback(self, callback: LogCallback) -> None:
        """Set log callback"""
        self._log_callback = callback
    
    async def _report_progress(self, update: ProgressUpdate) -> None:
        """Report progress if callback is set"""
        if self._progress_callback:
            await self._progress_callback(update)
    
    async def _should_stop(self) -> bool:
        """Check if scan should stop"""
        if self._stop_check:
            return await self._stop_check()
        return False
    
    def _log(self, level: str, message: str) -> None:
        """Log message if callback is set"""
        if self._log_callback:
            self._log_callback(level, message)
    
    async def run(self) -> EngineResult:
        """Execute scan - must be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement run()")


# Factory type for creating engines
EngineFactory = Callable[[Dict[str, Any]], ScanEngineProtocol]


__all__ = [
    "EngineType",
    "EngineResult",
    "ProgressUpdate",
    "ProgressCallback",
    "StopCheck",
    "LogCallback",
    "ScanEngineProtocol",
    "ScanEngineAdapter",
    "EngineFactory",
]
