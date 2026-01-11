"""
Jarwis AGI Pen Test - Scan Recovery Manager

Monitors scan health, detects failures, and auto-recovers from last checkpoint.
Provides self-healing capabilities for the scanning infrastructure.

Usage:
    manager = ScanRecoveryManager(scan_id)
    
    # Start monitoring a scan
    manager.start_monitoring(web_scan_runner)
    
    # Manager will automatically:
    # - Detect stuck/crashed scans
    # - Find root cause from logs
    # - Restart from last checkpoint
"""

import asyncio
import logging
import os
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
import json

from .scan_checkpoint import ScanCheckpoint, ScanPhase, ScanState
from .preflight_validator import PreflightValidator, ValidationResult

logger = logging.getLogger(__name__)


class FailureType(Enum):
    """Types of scan failures"""
    TIMEOUT = "timeout"
    CRASH = "crash"
    DEPENDENCY_MISSING = "dependency_missing"
    NETWORK_ERROR = "network_error"
    AUTHENTICATION_FAILED = "authentication_failed"
    TARGET_UNREACHABLE = "target_unreachable"
    MEMORY_EXHAUSTED = "memory_exhausted"
    SCANNER_ERROR = "scanner_error"
    UNKNOWN = "unknown"


@dataclass
class FailureDiagnosis:
    """Diagnosis of a scan failure"""
    failure_type: FailureType
    root_cause: str
    affected_component: str
    auto_recoverable: bool
    fix_suggestion: str
    fix_action: Optional[Callable] = None
    confidence: float = 0.0  # 0.0 to 1.0


@dataclass
class RecoveryAttempt:
    """Record of a recovery attempt"""
    attempt_number: int
    timestamp: str
    failure_diagnosis: FailureDiagnosis
    action_taken: str
    success: bool
    error: Optional[str] = None


@dataclass
class ScanHealthStatus:
    """Current health status of a scan"""
    scan_id: str
    is_healthy: bool
    last_heartbeat: Optional[str] = None
    current_phase: Optional[str] = None
    progress_percent: int = 0
    seconds_since_progress: float = 0
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class ScanRecoveryManager:
    """
    Manages scan health monitoring and automatic recovery.
    
    Features:
    - Heartbeat monitoring to detect stuck scans
    - Failure diagnosis from logs and state
    - Automatic recovery from checkpoints
    - Retry with fixes applied
    - Notification of unrecoverable failures
    """
    
    # Default thresholds
    HEARTBEAT_TIMEOUT_SECONDS = 120  # Default: 2 minutes no progress
    MAX_RECOVERY_ATTEMPTS = 3
    PHASE_TIMEOUT_SECONDS = 600  # Default: 10 minutes max per phase
    
    # Phase-specific heartbeat timeouts (longer for attack phases)
    PHASE_HEARTBEAT_TIMEOUTS = {
        'preflight': 60,           # 1 minute for preflight checks
        'crawl': 180,              # 3 minutes for crawling
        'authentication': 120,     # 2 minutes for login
        'post_login_crawl': 180,   # 3 minutes for post-login crawl
        'pre_login_attacks': 600,  # 10 minutes for attack phase
        'post_login_attacks': 600, # 10 minutes for authenticated attacks
        'reporting': 300,          # 5 minutes for report generation
    }
    
    def __init__(self, scan_id: str, config: Dict[str, Any] = None):
        self.scan_id = scan_id
        self.config = config or {}
        self.checkpoint = ScanCheckpoint(scan_id)
        
        self._last_heartbeat = datetime.now()
        self._last_phase = None
        self._last_progress = 0
        self._recovery_attempts: List[RecoveryAttempt] = []
        self._is_monitoring = False
        self._monitor_task: Optional[asyncio.Task] = None
        
        # Callbacks
        self.on_recovery_needed: Optional[Callable] = None
        self.on_recovery_success: Optional[Callable] = None
        self.on_recovery_failed: Optional[Callable] = None
        self.on_scan_abandoned: Optional[Callable] = None
    
    def heartbeat(self, phase: str = None, progress: int = None):
        """
        Record a heartbeat from the scan.
        Call this periodically from the scan runner.
        """
        self._last_heartbeat = datetime.now()
        if phase:
            self._last_phase = phase
        if progress is not None:
            self._last_progress = progress
    
    def _get_phase_timeout(self, phase: str) -> int:
        """Get the heartbeat timeout for a specific phase"""
        return self.PHASE_HEARTBEAT_TIMEOUTS.get(phase, self.HEARTBEAT_TIMEOUT_SECONDS)
    
    def get_health_status(self) -> ScanHealthStatus:
        """Get current health status of the scan"""
        now = datetime.now()
        seconds_since = (now - self._last_heartbeat).total_seconds()
        
        # Use phase-specific timeout
        phase_timeout = self._get_phase_timeout(self._last_phase)
        
        warnings = []
        errors = []
        is_healthy = True
        
        if seconds_since > phase_timeout:
            is_healthy = False
            errors.append(f"No heartbeat for {seconds_since:.0f}s (phase '{self._last_phase}' timeout: {phase_timeout}s)")
        elif seconds_since > phase_timeout / 2:
            warnings.append(f"Heartbeat delayed: {seconds_since:.0f}s (phase timeout: {phase_timeout}s)")
        
        return ScanHealthStatus(
            scan_id=self.scan_id,
            is_healthy=is_healthy,
            last_heartbeat=self._last_heartbeat.isoformat(),
            current_phase=self._last_phase,
            progress_percent=self._last_progress,
            seconds_since_progress=seconds_since,
            warnings=warnings,
            errors=errors
        )
    
    async def start_monitoring(self, check_interval: float = 30.0):
        """Start background health monitoring"""
        if self._is_monitoring:
            return
        
        self._is_monitoring = True
        self._monitor_task = asyncio.create_task(
            self._monitor_loop(check_interval)
        )
        logger.info(f"Started health monitoring for scan {self.scan_id}")
    
    def stop_monitoring(self):
        """Stop background health monitoring"""
        self._is_monitoring = False
        if self._monitor_task:
            self._monitor_task.cancel()
            self._monitor_task = None
        logger.info(f"Stopped health monitoring for scan {self.scan_id}")
    
    async def _monitor_loop(self, interval: float):
        """Background monitoring loop"""
        while self._is_monitoring:
            try:
                await asyncio.sleep(interval)
                
                status = self.get_health_status()
                
                if not status.is_healthy:
                    logger.warning(f"Scan {self.scan_id} appears unhealthy: {status.errors}")
                    
                    # Attempt recovery
                    if len(self._recovery_attempts) < self.MAX_RECOVERY_ATTEMPTS:
                        await self.attempt_recovery()
                    else:
                        logger.error(f"Max recovery attempts reached for scan {self.scan_id}")
                        if self.on_scan_abandoned:
                            await self._call_callback(self.on_scan_abandoned, self.scan_id)
                        self.stop_monitoring()
                        
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
    
    async def diagnose_failure(self) -> FailureDiagnosis:
        """Analyze logs and state to determine failure root cause"""
        
        # Check for common failure patterns
        diagnostics = [
            self._check_dependency_issues,
            self._check_network_issues,
            self._check_memory_issues,
            self._check_timeout_issues,
            self._check_scanner_errors,
        ]
        
        best_diagnosis = None
        highest_confidence = 0.0
        
        for check_fn in diagnostics:
            try:
                diagnosis = await check_fn()
                if diagnosis and diagnosis.confidence > highest_confidence:
                    highest_confidence = diagnosis.confidence
                    best_diagnosis = diagnosis
            except Exception as e:
                logger.debug(f"Diagnostic check failed: {e}")
        
        if best_diagnosis:
            return best_diagnosis
        
        # Default unknown diagnosis
        return FailureDiagnosis(
            failure_type=FailureType.UNKNOWN,
            root_cause="Unable to determine root cause",
            affected_component="unknown",
            auto_recoverable=True,  # Try recovery anyway
            fix_suggestion="Restart from last checkpoint",
            confidence=0.1
        )
    
    async def _check_dependency_issues(self) -> Optional[FailureDiagnosis]:
        """Check for missing dependencies"""
        validator = PreflightValidator(self.config)
        result = await validator.validate_all()
        
        critical_issues = result.get_critical_issues()
        if critical_issues:
            issue = critical_issues[0]
            return FailureDiagnosis(
                failure_type=FailureType.DEPENDENCY_MISSING,
                root_cause=issue.message,
                affected_component=issue.component,
                auto_recoverable=issue.auto_fixable,
                fix_suggestion=issue.fix_suggestion,
                fix_action=lambda: validator.auto_fix(issue) if issue.auto_fixable else None,
                confidence=0.9
            )
        return None
    
    async def _check_network_issues(self) -> Optional[FailureDiagnosis]:
        """Check for network connectivity issues"""
        target_url = self.config.get('target', {}).get('url', '')
        if not target_url:
            return None
        
        import socket
        from urllib.parse import urlparse
        
        try:
            parsed = urlparse(target_url)
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            
            if result != 0:
                return FailureDiagnosis(
                    failure_type=FailureType.TARGET_UNREACHABLE,
                    root_cause=f"Cannot connect to {host}:{port}",
                    affected_component="network",
                    auto_recoverable=True,  # Retry might work
                    fix_suggestion="Wait and retry - target may be temporarily unavailable",
                    confidence=0.85
                )
        except Exception as e:
            return FailureDiagnosis(
                failure_type=FailureType.NETWORK_ERROR,
                root_cause=str(e),
                affected_component="network",
                auto_recoverable=True,
                fix_suggestion="Check network connectivity",
                confidence=0.7
            )
        
        return None
    
    async def _check_memory_issues(self) -> Optional[FailureDiagnosis]:
        """Check for memory exhaustion"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            
            if memory.percent > 95:
                return FailureDiagnosis(
                    failure_type=FailureType.MEMORY_EXHAUSTED,
                    root_cause=f"Memory usage at {memory.percent}%",
                    affected_component="system",
                    auto_recoverable=False,
                    fix_suggestion="Free up system memory or reduce concurrent scanners",
                    confidence=0.95
                )
            elif memory.percent > 85:
                return FailureDiagnosis(
                    failure_type=FailureType.MEMORY_EXHAUSTED,
                    root_cause=f"High memory usage: {memory.percent}%",
                    affected_component="system",
                    auto_recoverable=True,
                    fix_suggestion="Reduce max_concurrent_scanners setting",
                    confidence=0.6
                )
        except ImportError:
            pass  # psutil not available
        
        return None
    
    async def _check_timeout_issues(self) -> Optional[FailureDiagnosis]:
        """Check for timeout-related issues"""
        status = self.get_health_status()
        
        if status.seconds_since_progress > self.PHASE_TIMEOUT_SECONDS:
            return FailureDiagnosis(
                failure_type=FailureType.TIMEOUT,
                root_cause=f"Phase {status.current_phase} running for {status.seconds_since_progress:.0f}s",
                affected_component=status.current_phase or "unknown_phase",
                auto_recoverable=True,
                fix_suggestion="Skip current phase and continue to next",
                confidence=0.8
            )
        
        return None
    
    async def _check_scanner_errors(self) -> Optional[FailureDiagnosis]:
        """Check for scanner-specific errors"""
        try:
            from .unified_executor import UnifiedExecutor
            
            problematic = UnifiedExecutor.get_problematic_scanners()
            if problematic:
                return FailureDiagnosis(
                    failure_type=FailureType.SCANNER_ERROR,
                    root_cause=f"Multiple scanner failures: {', '.join(problematic[:5])}",
                    affected_component="scanners",
                    auto_recoverable=True,
                    fix_suggestion="Reset circuit breakers and retry with problematic scanners disabled",
                    confidence=0.75
                )
        except Exception:
            pass
        
        return None
    
    async def attempt_recovery(self) -> bool:
        """
        Attempt to recover the scan from failure.
        
        Returns:
            True if recovery was successful
        """
        attempt_num = len(self._recovery_attempts) + 1
        logger.info(f"Attempting recovery #{attempt_num} for scan {self.scan_id}")
        
        # Notify callback
        if self.on_recovery_needed:
            await self._call_callback(self.on_recovery_needed, self.scan_id, attempt_num)
        
        # Diagnose failure
        diagnosis = await self.diagnose_failure()
        logger.info(f"Diagnosis: {diagnosis.failure_type.value} - {diagnosis.root_cause}")
        
        # Record attempt
        attempt = RecoveryAttempt(
            attempt_number=attempt_num,
            timestamp=datetime.now().isoformat(),
            failure_diagnosis=diagnosis,
            action_taken="",
            success=False
        )
        
        try:
            # Apply fix if available
            if diagnosis.fix_action and diagnosis.auto_recoverable:
                logger.info(f"Applying auto-fix: {diagnosis.fix_suggestion}")
                await self._apply_fix(diagnosis)
                attempt.action_taken = f"Applied fix: {diagnosis.fix_suggestion}"
            
            # Get resume point from checkpoint
            if self.checkpoint.can_resume():
                resume_phase, resume_data = self.checkpoint.get_resume_point()
                logger.info(f"Resuming from phase: {resume_phase}")
                attempt.action_taken += f" | Resuming from {resume_phase}"
                
                # Reset heartbeat
                self._last_heartbeat = datetime.now()
                self._last_phase = resume_phase
                
                attempt.success = True
                self._recovery_attempts.append(attempt)
                
                if self.on_recovery_success:
                    await self._call_callback(
                        self.on_recovery_success, 
                        self.scan_id, 
                        resume_phase
                    )
                
                return True
            else:
                attempt.action_taken = "No checkpoint available - cannot resume"
                attempt.success = False
                
        except Exception as e:
            attempt.error = str(e)
            attempt.success = False
            logger.error(f"Recovery attempt failed: {e}")
        
        self._recovery_attempts.append(attempt)
        
        if self.on_recovery_failed:
            await self._call_callback(self.on_recovery_failed, self.scan_id, attempt)
        
        return False
    
    async def _apply_fix(self, diagnosis: FailureDiagnosis):
        """Apply a fix based on diagnosis"""
        if diagnosis.fix_action:
            result = diagnosis.fix_action()
            if asyncio.iscoroutine(result):
                await result
        
        # Type-specific fixes
        if diagnosis.failure_type == FailureType.SCANNER_ERROR:
            # Reset circuit breakers
            try:
                from .unified_executor import UnifiedExecutor
                UnifiedExecutor.reset_circuit_breaker()
                logger.info("Reset all circuit breakers")
            except Exception as e:
                logger.warning(f"Could not reset circuit breakers: {e}")
        
        elif diagnosis.failure_type == FailureType.MEMORY_EXHAUSTED:
            # Reduce concurrent scanners
            if 'max_concurrent_scanners' in self.config:
                current = self.config['max_concurrent_scanners']
                self.config['max_concurrent_scanners'] = max(1, current // 2)
                logger.info(f"Reduced concurrent scanners from {current} to {self.config['max_concurrent_scanners']}")
    
    async def _call_callback(self, callback: Callable, *args):
        """Safely call a callback"""
        try:
            result = callback(*args)
            if asyncio.iscoroutine(result):
                await result
        except Exception as e:
            logger.error(f"Callback error: {e}")
    
    def get_recovery_history(self) -> List[Dict[str, Any]]:
        """Get history of recovery attempts"""
        return [
            {
                "attempt": a.attempt_number,
                "timestamp": a.timestamp,
                "failure_type": a.failure_diagnosis.failure_type.value,
                "root_cause": a.failure_diagnosis.root_cause,
                "action_taken": a.action_taken,
                "success": a.success,
                "error": a.error
            }
            for a in self._recovery_attempts
        ]
    
    def get_summary(self) -> Dict[str, Any]:
        """Get recovery manager summary"""
        status = self.get_health_status()
        return {
            "scan_id": self.scan_id,
            "is_monitoring": self._is_monitoring,
            "health_status": {
                "is_healthy": status.is_healthy,
                "current_phase": status.current_phase,
                "progress": status.progress_percent,
                "seconds_since_progress": status.seconds_since_progress
            },
            "recovery_attempts": len(self._recovery_attempts),
            "max_attempts": self.MAX_RECOVERY_ATTEMPTS,
            "can_recover": len(self._recovery_attempts) < self.MAX_RECOVERY_ATTEMPTS
        }


class GlobalRecoveryMonitor:
    """
    Monitors all active scans for health issues.
    Singleton pattern for global monitoring.
    """
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self._managers: Dict[str, ScanRecoveryManager] = {}
        self._initialized = True
    
    def register_scan(self, scan_id: str, config: Dict[str, Any] = None) -> ScanRecoveryManager:
        """Register a scan for monitoring"""
        manager = ScanRecoveryManager(scan_id, config)
        self._managers[scan_id] = manager
        return manager
    
    def unregister_scan(self, scan_id: str):
        """Unregister a scan from monitoring"""
        if scan_id in self._managers:
            self._managers[scan_id].stop_monitoring()
            del self._managers[scan_id]
    
    def get_manager(self, scan_id: str) -> Optional[ScanRecoveryManager]:
        """Get recovery manager for a scan"""
        return self._managers.get(scan_id)
    
    def get_all_health_status(self) -> Dict[str, ScanHealthStatus]:
        """Get health status of all monitored scans"""
        return {
            scan_id: manager.get_health_status()
            for scan_id, manager in self._managers.items()
        }
    
    def get_unhealthy_scans(self) -> List[str]:
        """Get list of unhealthy scan IDs"""
        unhealthy = []
        for scan_id, manager in self._managers.items():
            if not manager.get_health_status().is_healthy:
                unhealthy.append(scan_id)
        return unhealthy


def get_global_monitor() -> GlobalRecoveryMonitor:
    """Get the global recovery monitor instance"""
    return GlobalRecoveryMonitor()
