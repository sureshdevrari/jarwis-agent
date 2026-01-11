"""
Scan Service

Scan orchestration and management.
Coordinates between API routes, core scanner, and database.
"""

import logging
import uuid
from typing import Optional, Dict, Any, List
from datetime import datetime
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession

from shared.constants import ScanTypes
from services.subscription_service import SubscriptionService, SubscriptionError
from services.otp_service import otp_service
from services.domain_service import domain_service

logger = logging.getLogger(__name__)


@dataclass
class ScanConfig:
    """Scan configuration"""
    target_url: str
    scan_type: str = "web"
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    config: Optional[Dict[str, Any]] = None


class ScanService:
    """
    Scan orchestration service.
    
    Responsibilities:
    - Validate scan requests
    - Check subscription limits
    - Start/stop scans
    - Track scan progress
    - Generate reports
    """
    
    # In-memory progress tracking (use Redis in production)
    _progress: Dict[str, Dict[str, Any]] = {}
    
    @classmethod
    async def validate_and_start_scan(
        cls,
        db: AsyncSession,
        user,
        config: ScanConfig
    ) -> Dict[str, Any]:
        """
        Validate scan request and start scan.
        
        Returns:
            Dict with scan_id and status
            
        Raises:
            SubscriptionError: If subscription limits exceeded
            ValueError: If validation fails
        """
        # 1. Validate URL
        from core.scope import ScopeManager
        
        if not config.target_url:
            raise ValueError("Target URL is required")
        
        # 2. Check SSRF protection
        is_safe, error = cls._is_safe_target(config.target_url)
        if not is_safe:
            raise ValueError(f"Invalid target: {error}")
        
        # 3. Check subscription limits
        await SubscriptionService.enforce_scan_limit(
            db, user, config.scan_type
        )
        
        # 4. Check domain verification for credential scans
        if config.username and config.password:
            scope = ScopeManager(config.target_url)
            target_domain = scope.get_domain_for_subscription()
            
            if not domain_service.is_domain_verified(target_domain, user.id):
                raise ValueError(
                    f"Domain {target_domain} must be verified for credential-based scanning. "
                    "Please verify domain ownership first."
                )
        
        # 5. Create scan record
        scan_id = str(uuid.uuid4())
        
        # Store scan in database
        from database import crud
        scan = await crud.create_scan(
            db,
            user_id=user.id,
            scan_id=scan_id,
            target_url=config.target_url,
            scan_type=config.scan_type,
            config=config.config or {}
        )
        
        # 6. Initialize progress tracking
        cls._progress[scan_id] = {
            "status": "pending",
            "progress": 0,
            "current_phase": "Initializing",
            "logs": [],
            "started_at": datetime.utcnow().isoformat()
        }
        
        # 7. Setup 2FA if credentials provided
        if config.config and config.config.get("2fa_enabled"):
            otp_service.set_2fa_config(scan_id, config.config.get("2fa_config", {}))
        
        logger.info(f"Scan {scan_id} created for {config.target_url} by user {user.email}")
        
        return {
            "scan_id": scan_id,
            "status": "pending",
            "message": "Scan queued successfully"
        }
    
    @classmethod
    def _is_safe_target(cls, url: str) -> tuple:
        """Check if target URL is safe (not internal/private)"""
        import ipaddress
        import socket
        from urllib.parse import urlparse
        
        BLOCKED_HOSTNAMES = [
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
            "metadata.google.internal", "169.254.169.254"
        ]
        
        BLOCKED_RANGES = [
            ipaddress.ip_network("127.0.0.0/8"),
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
            ipaddress.ip_network("169.254.0.0/16"),
        ]
        
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                return False, "Invalid URL format"
            
            if parsed.scheme.lower() not in ["http", "https"]:
                return False, "Only HTTP/HTTPS allowed"
            
            hostname = parsed.netloc.split(":")[0].lower()
            
            if hostname in BLOCKED_HOSTNAMES:
                return False, f"Hostname '{hostname}' not allowed"
            
            # Check if it's an IP
            try:
                ip = ipaddress.ip_address(hostname)
                for blocked in BLOCKED_RANGES:
                    if ip in blocked:
                        return False, "Target is in private IP range"
            except ValueError:
                # It's a hostname, try to resolve
                try:
                    resolved = socket.gethostbyname(hostname)
                    ip = ipaddress.ip_address(resolved)
                    for blocked in BLOCKED_RANGES:
                        if ip in blocked:
                            return False, "Target resolves to private IP"
                except socket.gaierror:
                    return False, f"Cannot resolve hostname '{hostname}'"
            
            return True, None
            
        except Exception as e:
            return False, str(e)
    
    @classmethod
    def get_progress(cls, scan_id: str) -> Optional[Dict[str, Any]]:
        """Get current scan progress"""
        return cls._progress.get(scan_id)
    
    @classmethod
    def update_progress(
        cls,
        scan_id: str,
        status: str = None,
        progress: int = None,
        phase: str = None,
        log: str = None
    ) -> None:
        """Update scan progress"""
        if scan_id not in cls._progress:
            cls._progress[scan_id] = {"logs": []}
        
        state = cls._progress[scan_id]
        
        if status:
            state["status"] = status
        if progress is not None:
            state["progress"] = progress
        if phase:
            state["current_phase"] = phase
        if log:
            state["logs"].append({
                "timestamp": datetime.utcnow().isoformat(),
                "message": log
            })
    
    @classmethod
    async def stop_scan(cls, db: AsyncSession, scan_id: str, user) -> Dict[str, Any]:
        """Stop a running scan"""
        from database import crud
        
        # Get scan
        scan = await crud.get_scan_by_id(db, scan_id)
        if not scan:
            raise ValueError("Scan not found")
        
        if str(scan.user_id) != str(user.id) and not user.is_superuser:
            raise PermissionError("Not authorized to stop this scan")
        
        if scan.status in ("completed", "failed", "stopped"):
            raise ValueError(f"Scan already {scan.status}")
        
        # Update status
        await crud.update_scan_status(db, scan_id, "stopped")
        
        # Clear OTP state
        otp_service.clear_state(scan_id)
        
        # Update progress
        cls.update_progress(scan_id, status="stopped", log="Scan stopped by user")
        
        logger.info(f"Scan {scan_id} stopped by {user.email}")
        
        return {"message": "Scan stopped successfully", "scan_id": scan_id}
    
    @classmethod
    def cleanup_old_progress(cls, max_age_hours: int = 24) -> int:
        """Clean up old progress entries"""
        from datetime import timedelta
        
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        removed = 0
        
        scan_ids = list(cls._progress.keys())
        for scan_id in scan_ids:
            state = cls._progress[scan_id]
            if "started_at" in state:
                try:
                    started = datetime.fromisoformat(state["started_at"])
                    if started < cutoff:
                        del cls._progress[scan_id]
                        removed += 1
                except (ValueError, TypeError):
                    pass
        
        return removed


# Global instance
scan_service = ScanService()
