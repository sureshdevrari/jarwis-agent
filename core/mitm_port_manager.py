"""
JARWIS AGI PEN TEST - MITM Port Manager

Centralized port allocation for multi-tenant MITM proxy instances.
Enables parallel scans for multiple companies/domains simultaneously.

Features:
- Dynamic port allocation from configurable range (8080-8180)
- Per-scan port tracking with scan_id
- Thread-safe singleton pattern
- Automatic port release on scan completion
- Port availability checking before allocation
- Cleanup of orphaned ports on startup

Usage:
    from core.mitm_port_manager import MITMPortManager
    
    port_manager = MITMPortManager.get_instance()
    
    # Allocate port for a scan
    port = port_manager.allocate(scan_id="abc123", scope=["*.company.com"])
    
    # Get info about allocated port
    info = port_manager.get_scan_info(scan_id)
    
    # Release when scan completes
    port_manager.release(scan_id)
"""

import socket
import threading
import logging
import atexit
from typing import Dict, Optional, List, Set
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class ScanPortInfo:
    """Information about an allocated port for a scan"""
    scan_id: str
    port: int
    scope: List[str]
    allocated_at: datetime
    traffic_log_path: Path
    
    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "port": self.port,
            "scope": self.scope,
            "allocated_at": self.allocated_at.isoformat(),
            "traffic_log_path": str(self.traffic_log_path)
        }


class MITMPortManager:
    """
    Singleton port manager for MITM proxy instances.
    
    Allocates unique ports from a configurable range for each scan,
    enabling parallel scans without port conflicts.
    
    Port Range: 8080-8180 (100 concurrent scans)
    Traffic Logs: ~/.jarwis/mitm_logs/traffic_{scan_id}.json
    """
    
    _instance: Optional['MITMPortManager'] = None
    _lock = threading.Lock()
    
    # Port allocation range
    DEFAULT_PORT_START = 8080
    DEFAULT_PORT_END = 8180
    
    # Log directory
    LOG_DIR = Path.home() / ".jarwis" / "mitm_logs"
    
    def __new__(cls) -> 'MITMPortManager':
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._initialized = False
        return cls._instance
    
    def __init__(
        self,
        port_start: int = None,
        port_end: int = None
    ):
        # Only initialize once
        if self._initialized:
            return
        
        self.port_start = port_start or self.DEFAULT_PORT_START
        self.port_end = port_end or self.DEFAULT_PORT_END
        
        # Thread-safe data structures
        self._allocations: Dict[str, ScanPortInfo] = {}  # scan_id -> ScanPortInfo
        self._allocated_ports: Set[int] = set()  # Quick lookup
        self._port_to_scan: Dict[int, str] = {}  # port -> scan_id (reverse lookup)
        self._data_lock = threading.Lock()
        
        # Ensure log directory exists
        self.LOG_DIR.mkdir(parents=True, exist_ok=True)
        
        # Register cleanup on exit
        atexit.register(self._cleanup_all)
        
        self._initialized = True
        logger.info(f"MITMPortManager initialized: ports {self.port_start}-{self.port_end}")
    
    @classmethod
    def get_instance(cls) -> 'MITMPortManager':
        """Get the singleton instance"""
        return cls()
    
    def allocate(
        self,
        scan_id: str,
        scope: List[str] = None
    ) -> int:
        """
        Allocate a port for a scan.
        
        Args:
            scan_id: Unique identifier for the scan
            scope: List of scope patterns (e.g., ["*.company.com", "api.company.com"])
        
        Returns:
            Allocated port number
        
        Raises:
            RuntimeError: If no ports are available
            ValueError: If scan_id already has an allocation
        """
        scope = scope or []
        
        with self._data_lock:
            # Check if scan already has allocation
            if scan_id in self._allocations:
                existing = self._allocations[scan_id]
                logger.warning(f"Scan {scan_id} already has port {existing.port} allocated")
                return existing.port
            
            # Find available port
            port = self._find_available_port()
            if port is None:
                raise RuntimeError(
                    f"No available ports in range {self.port_start}-{self.port_end}. "
                    f"Currently {len(self._allocated_ports)} ports in use."
                )
            
            # Create traffic log path
            traffic_log_path = self.LOG_DIR / f"traffic_{scan_id}.json"
            
            # Create allocation record
            info = ScanPortInfo(
                scan_id=scan_id,
                port=port,
                scope=scope,
                allocated_at=datetime.utcnow(),
                traffic_log_path=traffic_log_path
            )
            
            # Register allocation
            self._allocations[scan_id] = info
            self._allocated_ports.add(port)
            self._port_to_scan[port] = scan_id
            
            logger.info(f"Allocated port {port} for scan {scan_id} (scope: {scope})")
            return port
    
    def release(self, scan_id: str) -> bool:
        """
        Release a port allocation for a scan.
        
        Args:
            scan_id: Scan identifier to release
        
        Returns:
            True if released, False if not found
        """
        with self._data_lock:
            if scan_id not in self._allocations:
                logger.warning(f"No allocation found for scan {scan_id}")
                return False
            
            info = self._allocations.pop(scan_id)
            self._allocated_ports.discard(info.port)
            self._port_to_scan.pop(info.port, None)
            
            logger.info(f"Released port {info.port} for scan {scan_id}")
            return True
    
    def get_scan_info(self, scan_id: str) -> Optional[ScanPortInfo]:
        """Get allocation info for a scan"""
        with self._data_lock:
            return self._allocations.get(scan_id)
    
    def get_port_for_scan(self, scan_id: str) -> Optional[int]:
        """Get the allocated port for a scan"""
        info = self.get_scan_info(scan_id)
        return info.port if info else None
    
    def get_scan_for_port(self, port: int) -> Optional[str]:
        """Get the scan_id using a specific port"""
        with self._data_lock:
            return self._port_to_scan.get(port)
    
    def get_traffic_log_path(self, scan_id: str) -> Optional[Path]:
        """Get the traffic log path for a scan"""
        info = self.get_scan_info(scan_id)
        return info.traffic_log_path if info else None
    
    def get_scope(self, scan_id: str) -> List[str]:
        """Get the scope patterns for a scan"""
        info = self.get_scan_info(scan_id)
        return info.scope if info else []
    
    def get_all_allocations(self) -> Dict[str, Dict]:
        """Get all current allocations (for diagnostics)"""
        with self._data_lock:
            return {
                scan_id: info.to_dict()
                for scan_id, info in self._allocations.items()
            }
    
    def get_stats(self) -> Dict:
        """Get port manager statistics"""
        with self._data_lock:
            return {
                "port_range": f"{self.port_start}-{self.port_end}",
                "total_ports": self.port_end - self.port_start,
                "allocated_count": len(self._allocated_ports),
                "available_count": (self.port_end - self.port_start) - len(self._allocated_ports),
                "allocations": list(self._allocations.keys())
            }
    
    def _find_available_port(self) -> Optional[int]:
        """Find an available port in the range"""
        for port in range(self.port_start, self.port_end):
            if port in self._allocated_ports:
                continue
            
            # Check if port is actually available on the system
            if self._is_port_available(port):
                return port
        
        return None
    
    def _is_port_available(self, port: int) -> bool:
        """Check if a port is available for binding"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex(('127.0.0.1', port))
            sock.close()
            # If connect fails (result != 0), port is available
            return result != 0
        except Exception:
            return True  # Assume available if we can't check
    
    def _cleanup_all(self):
        """Cleanup all allocations on shutdown"""
        with self._data_lock:
            count = len(self._allocations)
            if count > 0:
                logger.info(f"Cleaning up {count} port allocations on shutdown")
                self._allocations.clear()
                self._allocated_ports.clear()
                self._port_to_scan.clear()
    
    def cleanup_stale_allocations(self, max_age_hours: int = 24) -> int:
        """
        Cleanup allocations older than max_age_hours.
        
        Returns:
            Number of allocations cleaned up
        """
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        cleaned = 0
        
        with self._data_lock:
            stale_scans = [
                scan_id
                for scan_id, info in self._allocations.items()
                if info.allocated_at < cutoff
            ]
            
            for scan_id in stale_scans:
                info = self._allocations.pop(scan_id)
                self._allocated_ports.discard(info.port)
                self._port_to_scan.pop(info.port, None)
                cleaned += 1
                logger.info(f"Cleaned up stale allocation: scan {scan_id}, port {info.port}")
        
        return cleaned


# Convenience function
def get_port_manager() -> MITMPortManager:
    """Get the global MITM port manager instance"""
    return MITMPortManager.get_instance()


__all__ = ['MITMPortManager', 'ScanPortInfo', 'get_port_manager']
