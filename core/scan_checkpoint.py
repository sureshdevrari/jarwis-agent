"""
Jarwis AGI Pen Test - Scan Checkpoint System

Enables scan state persistence and resume capability.
Saves checkpoint after each phase so scans can resume from last successful phase.

Usage:
    checkpoint = ScanCheckpoint(scan_id)
    checkpoint.save_phase("crawl", context_data)
    
    # Later, to resume:
    checkpoint = ScanCheckpoint(scan_id)
    if checkpoint.can_resume():
        last_phase, data = checkpoint.get_last_checkpoint()
"""

import json
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class ScanPhase(Enum):
    """Scan execution phases in order"""
    PREFLIGHT = "preflight"
    CRAWL = "crawl"
    PRE_LOGIN_ATTACKS = "pre_login_attacks"
    AUTHENTICATION = "authentication"
    POST_LOGIN_CRAWL = "post_login_crawl"
    POST_LOGIN_ATTACKS = "post_login_attacks"
    REPORTING = "reporting"
    COMPLETED = "completed"
    
    @classmethod
    def get_order(cls) -> List[str]:
        return [phase.value for phase in cls]
    
    @classmethod
    def get_next_phase(cls, current: str) -> Optional[str]:
        order = cls.get_order()
        try:
            idx = order.index(current)
            if idx + 1 < len(order):
                return order[idx + 1]
        except ValueError:
            pass
        return None


@dataclass
class PhaseCheckpoint:
    """Checkpoint data for a single phase"""
    phase: str
    status: str  # success, failed, skipped
    started_at: str
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    error_message: Optional[str] = None
    retry_count: int = 0
    data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanState:
    """Complete scan state for checkpoint/resume"""
    scan_id: str
    target_url: str
    config: Dict[str, Any]
    current_phase: str
    phases: Dict[str, PhaseCheckpoint]
    
    # Collected data that persists across phases
    discovered_endpoints: List[str] = field(default_factory=list)
    discovered_forms: List[Dict] = field(default_factory=list)
    captured_requests: List[Dict] = field(default_factory=list)
    cookies: Dict[str, str] = field(default_factory=dict)
    auth_tokens: Dict[str, str] = field(default_factory=dict)
    
    # Findings collected so far
    findings: List[Dict] = field(default_factory=list)
    
    # Metadata
    created_at: str = ""
    updated_at: str = ""
    resume_count: int = 0
    total_scanners_run: int = 0
    total_scanners_failed: int = 0


class ScanCheckpoint:
    """
    Manages scan checkpoints for resume capability.
    
    Features:
    - Saves state after each phase completion
    - Supports resuming from last successful phase
    - Tracks retry counts per phase
    - Persists findings incrementally
    """
    
    CHECKPOINT_DIR = "temp/scans"
    CHECKPOINT_FILE = "checkpoint.json"
    FINDINGS_FILE = "findings.json"
    REQUESTS_FILE = "requests.json"
    
    def __init__(self, scan_id: str, base_dir: str = None):
        self.scan_id = scan_id
        self.base_dir = Path(base_dir or self.CHECKPOINT_DIR)
        self.scan_dir = self.base_dir / scan_id
        self.checkpoint_path = self.scan_dir / self.CHECKPOINT_FILE
        self.findings_path = self.scan_dir / self.FINDINGS_FILE
        self.requests_path = self.scan_dir / self.REQUESTS_FILE
        
        self._state: Optional[ScanState] = None
        self._ensure_directory()
    
    def _ensure_directory(self):
        """Create checkpoint directory if needed"""
        self.scan_dir.mkdir(parents=True, exist_ok=True)
    
    def initialize(self, target_url: str, config: Dict[str, Any]) -> ScanState:
        """Initialize a new scan checkpoint"""
        now = datetime.utcnow().isoformat()
        
        self._state = ScanState(
            scan_id=self.scan_id,
            target_url=target_url,
            config=config,
            current_phase=ScanPhase.PREFLIGHT.value,
            phases={},
            created_at=now,
            updated_at=now
        )
        
        self._save()
        logger.info(f"Initialized checkpoint for scan {self.scan_id}")
        return self._state
    
    def load(self) -> Optional[ScanState]:
        """Load existing checkpoint from disk"""
        if not self.checkpoint_path.exists():
            return None
        
        try:
            with open(self.checkpoint_path, 'r') as f:
                data = json.load(f)
            
            # Reconstruct PhaseCheckpoint objects
            phases = {}
            for phase_name, phase_data in data.get('phases', {}).items():
                phases[phase_name] = PhaseCheckpoint(**phase_data)
            data['phases'] = phases
            
            self._state = ScanState(**data)
            logger.info(f"Loaded checkpoint for scan {self.scan_id}, phase: {self._state.current_phase}")
            return self._state
            
        except Exception as e:
            logger.error(f"Failed to load checkpoint: {e}")
            return None
    
    def _save(self):
        """Save current state to disk"""
        if not self._state:
            return
        
        self._state.updated_at = datetime.utcnow().isoformat()
        
        # Convert to dict for JSON serialization
        data = asdict(self._state)
        
        # Convert ScanPhase enum keys to strings in phases dict
        if 'phases' in data:
            data['phases'] = {
                (k.value if isinstance(k, ScanPhase) else str(k)): v 
                for k, v in data['phases'].items()
            }
        
        # Atomic write with temp file
        temp_path = self.checkpoint_path.with_suffix('.tmp')
        try:
            with open(temp_path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            temp_path.replace(self.checkpoint_path)
        except Exception as e:
            logger.error(f"Failed to save checkpoint: {e}")
            if temp_path.exists():
                temp_path.unlink()
            raise
    
    def start_phase(self, phase: str) -> PhaseCheckpoint:
        """Mark a phase as started"""
        if not self._state:
            raise ValueError("Checkpoint not initialized. Call initialize() first.")
        
        checkpoint = PhaseCheckpoint(
            phase=phase,
            status="running",
            started_at=datetime.utcnow().isoformat()
        )
        
        self._state.phases[phase] = checkpoint
        self._state.current_phase = phase
        self._save()
        
        logger.info(f"Started phase: {phase}")
        return checkpoint
    
    def complete_phase(
        self, 
        phase: str, 
        status: str = "success",
        data: Dict[str, Any] = None,
        error_message: str = None
    ):
        """Mark a phase as completed"""
        if not self._state or phase not in self._state.phases:
            logger.warning(f"Cannot complete unknown phase: {phase}")
            return
        
        checkpoint = self._state.phases[phase]
        checkpoint.status = status
        checkpoint.completed_at = datetime.utcnow().isoformat()
        checkpoint.error_message = error_message
        checkpoint.data = data or {}
        
        # Calculate duration
        started = datetime.fromisoformat(checkpoint.started_at)
        completed = datetime.fromisoformat(checkpoint.completed_at)
        checkpoint.duration_seconds = (completed - started).total_seconds()
        
        # Update current phase to next if successful
        if status == "success":
            next_phase = ScanPhase.get_next_phase(phase)
            if next_phase:
                self._state.current_phase = next_phase
        
        self._save()
        logger.info(f"Completed phase: {phase} with status: {status}")
    
    def increment_retry(self, phase: str) -> int:
        """Increment retry count for a phase"""
        if not self._state or phase not in self._state.phases:
            return 0
        
        self._state.phases[phase].retry_count += 1
        self._save()
        return self._state.phases[phase].retry_count
    
    def can_resume(self) -> bool:
        """Check if scan can be resumed"""
        state = self.load()
        if not state:
            return False
        
        # Can resume if not completed and has at least one successful phase
        if state.current_phase == ScanPhase.COMPLETED.value:
            return False
        
        return len(state.phases) > 0
    
    def get_resume_point(self) -> Tuple[str, Dict[str, Any]]:
        """Get the phase to resume from and its data"""
        if not self._state:
            self.load()
        
        if not self._state:
            return ScanPhase.PREFLIGHT.value, {}
        
        # Find last successful phase
        order = ScanPhase.get_order()
        last_successful = None
        
        for phase_name in order:
            if phase_name in self._state.phases:
                phase = self._state.phases[phase_name]
                if phase.status == "success":
                    last_successful = phase_name
                elif phase.status == "failed":
                    # Resume from the failed phase
                    self._state.resume_count += 1
                    self._save()
                    return phase_name, phase.data
        
        # Resume from next phase after last successful
        if last_successful:
            next_phase = ScanPhase.get_next_phase(last_successful)
            if next_phase:
                self._state.resume_count += 1
                self._save()
                return next_phase, self._state.phases[last_successful].data
        
        return ScanPhase.PREFLIGHT.value, {}
    
    # === Data persistence methods ===
    
    def add_endpoints(self, endpoints: List[str]):
        """Add discovered endpoints"""
        if self._state:
            existing = set(self._state.discovered_endpoints)
            existing.update(endpoints)
            self._state.discovered_endpoints = list(existing)
            self._save()
    
    def add_forms(self, forms: List[Dict]):
        """Add discovered forms"""
        if self._state:
            self._state.discovered_forms.extend(forms)
            self._save()
    
    def add_requests(self, requests: List[Dict]):
        """Add captured requests (also saves to separate file for large datasets)"""
        if self._state:
            self._state.captured_requests.extend(requests)
            
            # Also save to separate file to prevent checkpoint bloat
            try:
                existing = []
                if self.requests_path.exists():
                    with open(self.requests_path, 'r') as f:
                        existing = json.load(f)
                existing.extend(requests)
                with open(self.requests_path, 'w') as f:
                    json.dump(existing, f, indent=2, default=str)
            except Exception as e:
                logger.warning(f"Failed to save requests file: {e}")
            
            self._save()
    
    def set_cookies(self, cookies: Dict[str, str]):
        """Update session cookies"""
        if self._state:
            self._state.cookies.update(cookies)
            self._save()
    
    def set_auth_tokens(self, tokens: Dict[str, str]):
        """Update auth tokens"""
        if self._state:
            self._state.auth_tokens.update(tokens)
            self._save()
    
    def add_findings(self, findings: List[Dict]):
        """
        Add findings incrementally.
        Saves to both checkpoint and separate findings file.
        """
        if not self._state:
            return
        
        # Deduplicate by finding ID
        existing_ids = {f.get('id') for f in self._state.findings}
        new_findings = [f for f in findings if f.get('id') not in existing_ids]
        
        if not new_findings:
            return
        
        self._state.findings.extend(new_findings)
        
        # Save to separate findings file (for large result sets)
        try:
            all_findings = []
            if self.findings_path.exists():
                with open(self.findings_path, 'r') as f:
                    all_findings = json.load(f)
            
            all_findings.extend(new_findings)
            
            with open(self.findings_path, 'w') as f:
                json.dump(all_findings, f, indent=2, default=str)
                
            logger.info(f"Saved {len(new_findings)} new findings (total: {len(all_findings)})")
            
        except Exception as e:
            logger.warning(f"Failed to save findings file: {e}")
        
        self._save()
    
    def get_findings(self) -> List[Dict]:
        """Get all findings collected so far"""
        # Try findings file first (more complete)
        if self.findings_path.exists():
            try:
                with open(self.findings_path, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        
        # Fall back to checkpoint data
        if self._state:
            return self._state.findings
        
        return []
    
    def update_scanner_stats(self, run: int = 0, failed: int = 0):
        """Update scanner execution statistics"""
        if self._state:
            self._state.total_scanners_run += run
            self._state.total_scanners_failed += failed
            self._save()
    
    def get_state(self) -> Optional[ScanState]:
        """Get current state"""
        return self._state
    
    def cleanup(self):
        """Remove checkpoint files (after successful completion)"""
        try:
            if self.scan_dir.exists():
                shutil.rmtree(self.scan_dir)
                logger.info(f"Cleaned up checkpoint for scan {self.scan_id}")
        except Exception as e:
            logger.warning(f"Failed to cleanup checkpoint: {e}")
    
    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of checkpoint state"""
        if not self._state:
            self.load()
        
        if not self._state:
            return {"status": "not_found"}
        
        phases_summary = {}
        for name, phase in self._state.phases.items():
            phases_summary[name] = {
                "status": phase.status,
                "duration": phase.duration_seconds,
                "retries": phase.retry_count
            }
        
        return {
            "scan_id": self.scan_id,
            "target_url": self._state.target_url,
            "current_phase": self._state.current_phase,
            "phases": phases_summary,
            "resume_count": self._state.resume_count,
            "total_findings": len(self._state.findings),
            "total_endpoints": len(self._state.discovered_endpoints),
            "total_requests": len(self._state.captured_requests),
            "created_at": self._state.created_at,
            "updated_at": self._state.updated_at
        }
