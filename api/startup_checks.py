"""
API Startup Health Checks

Validates system health before allowing API to accept requests.
Prevents broken deployments from going live.
"""

import asyncio
import logging
import socket
from pathlib import Path
from typing import Dict, Tuple, List

logger = logging.getLogger(__name__)

# Service ports to validate before startup
SERVICE_PORTS = [
    (8000, "Backend API"),
    (3000, "Frontend"),
    (8080, "MITM Proxy"),
    (9999, "OOB Callback HTTP"),
    (5353, "OOB Callback DNS"),
]


class StartupHealthCheck:
    """Validates system health on API startup"""
    
    @staticmethod
    async def run_all_checks() -> Dict[str, bool]:
        """
        Run all health checks.
        
        Returns:
            Dict mapping check name to success status
        """
        checks = {
            "database": StartupHealthCheck._check_database(),
            "scanner_registry": StartupHealthCheck._check_scanners(),
            "file_system": StartupHealthCheck._check_file_system(),
            "contracts": StartupHealthCheck._check_contracts(),
            "ports": StartupHealthCheck._check_service_ports(),
        }
        
        results = {}
        for name, coro in checks.items():
            try:
                success, message = await coro
                results[name] = success
                
                if success:
                    logger.info(f"✅ {name}: {message}")
                else:
                    logger.error(f"❌ {name}: {message}")
                    
            except Exception as e:
                logger.error(f"💥 {name} check crashed: {e}")
                results[name] = False
        
        return results
    
    @staticmethod
    async def _check_service_ports() -> Tuple[bool, str]:
        """Check if required service ports are available or in use by our services"""
        conflicts = []
        running_services = []
        
        for port, service_name in SERVICE_PORTS:
            status = StartupHealthCheck._check_port_status(port)
            if status == "in_use":
                # Port 8000 being in use is expected (we're starting!)
                if port == 8000:
                    continue
                # Check if it's our service or a conflict
                conflicts.append(f"{service_name}:{port}")
            elif status == "available":
                # Port is free - service not running yet (expected during startup)
                pass
        
        if conflicts:
            return False, f"Port conflicts detected: {', '.join(conflicts)}"
        
        return True, "All service ports available"
    
    @staticmethod
    def _check_port_status(port: int) -> str:
        """Check if a port is in use or available"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    return "in_use"
                return "available"
        except Exception:
            return "available"
    
    @staticmethod
    def check_all_services_running() -> Dict[str, dict]:
        """
        Check status of all services on their designated ports.
        Returns dict with service status for health endpoint.
        """
        results = {}
        for port, service_name in SERVICE_PORTS:
            status = StartupHealthCheck._check_port_status(port)
            results[service_name] = {
                "port": port,
                "status": "running" if status == "in_use" else "stopped",
                "healthy": status == "in_use" if service_name == "Backend API" else True
            }
        return results
    
    @staticmethod
    async def _check_database() -> Tuple[bool, str]:
        """Check database connectivity"""
        try:
            from database.connection import get_db
            from sqlalchemy import text
            
            async for db in get_db():
                await db.execute(text("SELECT 1"))
                break
            
            return True, "Database connection OK"
        except Exception as e:
            return False, f"Database error: {e}"
    
    @staticmethod
    async def _check_scanners() -> Tuple[bool, str]:
        """Check scanner modules can be imported using unified registry"""
        try:
            # Use unified scanner registry for comprehensive checks
            from attacks.unified_registry import scanner_registry
            
            # Validate all registered scanners
            results = scanner_registry.validate_all()
            summary = scanner_registry.get_health_summary()
            
            # Also check legacy pre_login/post_login imports
            from attacks.web.pre_login import PreLoginAttacks
            from attacks.web.post_login import PostLoginAttacks
            
            # Get status counts
            healthy = summary.get("healthy", 0)
            degraded = summary.get("degraded", 0)
            unavailable = summary.get("unavailable", 0)
            total = summary.get("total", 0)
            
            # Build message with details
            messages = []
            for scan_type, result in results.items():
                status = result.get("status", "unknown")
                if status in ("degraded", "unavailable"):
                    scanners = result.get("scanners", {})
                    failed = [name for name, info in scanners.items() 
                              if info.get("status") != "healthy"]
                    if failed:
                        messages.append(f"{scan_type}: {', '.join(failed)} unavailable")
            
            # Determine overall status
            if unavailable > 0:
                # Some scan types completely unavailable
                detail = "; ".join(messages) if messages else f"{unavailable} scan types unavailable"
                return False, f"Scanner issues: {detail}"
            elif degraded > 0:
                # Partial availability
                return True, f"{healthy}/{total} scan types healthy, {degraded} degraded"
            else:
                return True, f"All {total} scan types healthy"
                
        except ImportError as e:
            # Unified registry not available, fall back to basic check
            try:
                from attacks.web.pre_login import PreLoginAttacks
                from attacks.web.post_login import PostLoginAttacks
                
                # Count scanner files
                scanner_dir = Path("attacks/web/pre_login")
                scanner_files = list(scanner_dir.glob("*_scanner.py"))
                count = len(scanner_files)
                
                if count < 10:
                    return False, f"Only {count} scanner files found"
                
                return True, f"{count} scanner files available (basic check)"
            except Exception as e2:
                return False, f"Scanner import error: {e2}"
        except Exception as e:
            return False, f"Scanner registry error: {e}"
    
    @staticmethod
    async def _check_file_system() -> Tuple[bool, str]:
        """Check critical directories exist and are writable"""
        try:
            critical_dirs = ["uploads", "reports", "logs"]
            
            for dir_name in critical_dirs:
                dir_path = Path(dir_name)
                dir_path.mkdir(exist_ok=True)
                
                # Test write
                test_file = dir_path / ".health_check"
                test_file.write_text("OK")
                test_file.unlink()
            
            return True, "File system OK"
        except Exception as e:
            return False, f"File system error: {e}"
    
    @staticmethod
    async def _check_contracts() -> Tuple[bool, str]:
        """Check frontend contracts exist"""
        try:
            contracts = [
                Path("jarwisfrontend/src/config/endpoints.generated.js"),
                Path("jarwisfrontend/src/config/planLimits.generated.js"),
            ]
            
            missing = []
            for contract in contracts:
                if not contract.exists():
                    missing.append(contract.name)
                elif contract.stat().st_size < 100:
                    missing.append(f"{contract.name} (too small)")
            
            if missing:
                return False, f"Contract issues: {', '.join(missing)}"
            
            return True, "Contracts in sync"
        except Exception as e:
            return False, f"Contract check error: {e}"
