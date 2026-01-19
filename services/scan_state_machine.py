"""
Scan State Machine Service
Enforces valid state transitions for scan status.

Enterprise-level pattern for managing long-running operations with:
- State validation
- Audit trail
- Error recovery
"""

from typing import Optional, Tuple
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class ScanStatus(str, Enum):
    """Valid scan statuses"""
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    WAITING_FOR_MANUAL_AUTH = "waiting_for_manual_auth"
    WAITING_FOR_OTP = "waiting_for_otp"
    COMPLETED = "completed"
    ERROR = "error"
    STOPPED = "stopped"
    CANCELLED = "cancelled"
    STALLED = "stalled"  # Scan appears stuck (no updates for extended period)
    AGENT_DISCONNECTED = "agent_disconnected"  # Agent lost connection mid-scan


# Valid state transitions - defines what transitions are allowed from each state
VALID_TRANSITIONS = {
    ScanStatus.QUEUED: [
        ScanStatus.RUNNING,
        ScanStatus.CANCELLED,
        ScanStatus.ERROR,
    ],
    ScanStatus.RUNNING: [
        ScanStatus.PAUSED,
        ScanStatus.COMPLETED,
        ScanStatus.ERROR,
        ScanStatus.STOPPED,
        ScanStatus.STALLED,  # Auto-transition when scan appears stuck
        ScanStatus.WAITING_FOR_MANUAL_AUTH,
        ScanStatus.WAITING_FOR_OTP,
        ScanStatus.AGENT_DISCONNECTED,  # Agent disconnected mid-scan
    ],
    ScanStatus.PAUSED: [
        ScanStatus.RUNNING,
        ScanStatus.STOPPED,
        ScanStatus.ERROR,
    ],
    ScanStatus.WAITING_FOR_MANUAL_AUTH: [
        ScanStatus.RUNNING,
        ScanStatus.ERROR,
        ScanStatus.STOPPED,
    ],
    ScanStatus.WAITING_FOR_OTP: [
        ScanStatus.RUNNING,
        ScanStatus.ERROR,
        ScanStatus.STOPPED,
    ],
    ScanStatus.COMPLETED: [],  # Terminal state - no transitions allowed
    ScanStatus.ERROR: [
        ScanStatus.QUEUED,  # Can retry
    ],
    ScanStatus.STOPPED: [
        ScanStatus.QUEUED,  # Can resume
    ],
    ScanStatus.CANCELLED: [],  # Terminal state
    ScanStatus.STALLED: [
        ScanStatus.QUEUED,  # Can retry stalled scans
        ScanStatus.ERROR,   # Can mark as failed
    ],
    ScanStatus.AGENT_DISCONNECTED: [
        ScanStatus.QUEUED,  # Can resume when agent reconnects
        ScanStatus.ERROR,   # Can mark as failed
    ],
}


class ScanStateMachine:
    """
    State machine for scan status management.
    
    Ensures only valid state transitions occur and provides
    audit logging for all state changes.
    """
    
    @staticmethod
    def get_valid_statuses() -> list:
        """Get all valid status values"""
        return [s.value for s in ScanStatus]
    
    @staticmethod
    def is_valid_status(status: str) -> bool:
        """Check if a status string is valid"""
        return status in ScanStateMachine.get_valid_statuses()
    
    @staticmethod
    def normalize_status(status: str) -> str:
        """
        Normalize status string to valid enum value.
        Handles common variations (e.g., 'failed' -> 'error').
        """
        status_lower = status.lower().strip()
        
        # Map common variations
        status_map = {
            "failed": ScanStatus.ERROR.value,
            "failure": ScanStatus.ERROR.value,
            "complete": ScanStatus.COMPLETED.value,
            "done": ScanStatus.COMPLETED.value,
            "initializing": ScanStatus.RUNNING.value,
            "started": ScanStatus.RUNNING.value,
            "pending": ScanStatus.QUEUED.value,
            "waiting": ScanStatus.PAUSED.value,
            "manual_auth": ScanStatus.WAITING_FOR_MANUAL_AUTH.value,
            "otp_required": ScanStatus.WAITING_FOR_OTP.value,
        }
        
        return status_map.get(status_lower, status_lower)
    
    @staticmethod
    def can_transition(current_status: str, target_status: str) -> bool:
        """
        Check if transition from current_status to target_status is valid.
        
        Args:
            current_status: Current scan status
            target_status: Target status to transition to
            
        Returns:
            True if transition is valid, False otherwise
        """
        # Normalize statuses
        current = ScanStateMachine.normalize_status(current_status)
        target = ScanStateMachine.normalize_status(target_status)
        
        # Same status is always allowed (idempotent)
        if current == target:
            return True
        
        try:
            current_enum = ScanStatus(current)
            target_enum = ScanStatus(target)
        except ValueError:
            logger.warning(f"Invalid status values: current={current}, target={target}")
            return False
        
        valid_targets = VALID_TRANSITIONS.get(current_enum, [])
        return target_enum in valid_targets
    
    @staticmethod
    def validate_transition(
        current_status: str, 
        target_status: str, 
        scan_id: str = None
    ) -> Tuple[bool, str]:
        """
        Validate a state transition and return detailed result.
        
        Args:
            current_status: Current scan status
            target_status: Target status to transition to
            scan_id: Optional scan ID for logging
            
        Returns:
            Tuple of (is_valid, message)
        """
        current = ScanStateMachine.normalize_status(current_status)
        target = ScanStateMachine.normalize_status(target_status)
        
        if current == target:
            return True, f"Status unchanged: {target}"
        
        if not ScanStateMachine.is_valid_status(current):
            return False, f"Invalid current status: {current_status}"
        
        if not ScanStateMachine.is_valid_status(target):
            return False, f"Invalid target status: {target_status}"
        
        if ScanStateMachine.can_transition(current, target):
            msg = f"Valid transition: {current} -> {target}"
            if scan_id:
                logger.info(f"Scan {scan_id}: {msg}")
            return True, msg
        else:
            current_enum = ScanStatus(current)
            valid_targets = [s.value for s in VALID_TRANSITIONS.get(current_enum, [])]
            msg = f"Invalid transition: {current} -> {target}. Valid targets: {valid_targets}"
            if scan_id:
                logger.warning(f"Scan {scan_id}: {msg}")
            return False, msg
    
    @staticmethod
    def is_terminal_status(status: str) -> bool:
        """Check if status is a terminal state (no further transitions)"""
        normalized = ScanStateMachine.normalize_status(status)
        try:
            status_enum = ScanStatus(normalized)
            return len(VALID_TRANSITIONS.get(status_enum, [])) == 0
        except ValueError:
            return False
    
    @staticmethod
    def is_active_status(status: str) -> bool:
        """Check if scan is actively running"""
        normalized = ScanStateMachine.normalize_status(status)
        return normalized in [
            ScanStatus.RUNNING.value,
            ScanStatus.WAITING_FOR_MANUAL_AUTH.value,
            ScanStatus.WAITING_FOR_OTP.value,
        ]
    
    @staticmethod
    def is_retryable(status: str) -> bool:
        """Check if scan can be retried from this status"""
        normalized = ScanStateMachine.normalize_status(status)
        return normalized in [
            ScanStatus.ERROR.value,
            ScanStatus.STOPPED.value,
            ScanStatus.STALLED.value,  # Stalled scans can also be retried
        ]
    
    @staticmethod
    def get_allowed_transitions(current_status: str) -> list:
        """Get list of allowed target statuses from current status"""
        normalized = ScanStateMachine.normalize_status(current_status)
        try:
            current_enum = ScanStatus(normalized)
            return [s.value for s in VALID_TRANSITIONS.get(current_enum, [])]
        except ValueError:
            return []


# Export convenience functions
def validate_status_transition(
    current: str, 
    target: str, 
    scan_id: str = None
) -> Tuple[bool, str]:
    """
    Validate a status transition.
    
    Returns:
        Tuple of (is_valid, message)
    """
    return ScanStateMachine.validate_transition(current, target, scan_id)


def can_retry_scan(status: str) -> bool:
    """Check if a scan with this status can be retried"""
    return ScanStateMachine.is_retryable(status)


def is_scan_active(status: str) -> bool:
    """Check if scan is currently active/running"""
    return ScanStateMachine.is_active_status(status)
