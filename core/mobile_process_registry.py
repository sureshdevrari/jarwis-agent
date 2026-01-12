"""
Mobile Process Registry
Tracks and manages mobile scan processes (emulators, Frida, etc.) for cleanup and lifecycle management.
Similar to BrowserController._instances for web scans.
"""

import logging
import asyncio
import subprocess
from typing import Dict, Optional, Any, List
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class MobileScanProcess:
    """Represents a mobile scan with its associated processes"""
    scan_id: str
    user_id: str
    orchestrator: Optional[Any] = None  # MobilePenTestOrchestrator reference
    emulator_manager: Optional[Any] = None  # EmulatorManager reference
    emulator_pid: Optional[int] = None  # PID of emulator process
    frida_pid: Optional[int] = None  # PID of frida-server on device
    mitm_proxy: Optional[Any] = None  # MITM proxy reference
    device_id: Optional[str] = None  # e.g., "emulator-5554"
    platform: str = "android"  # android or ios
    should_stop: bool = False  # Flag to signal stop


class MobileProcessRegistry:
    """
    Registry for tracking mobile scan processes.
    Enables proper cleanup when scans stop, crash, or on graceful shutdown.
    """
    
    _instances: Dict[str, MobileScanProcess] = {}
    _lock = asyncio.Lock()
    
    @classmethod
    async def register(
        cls,
        scan_id: str,
        user_id: str,
        platform: str = "android"
    ) -> MobileScanProcess:
        """
        Register a new mobile scan.
        Returns the MobileScanProcess for tracking resources.
        """
        async with cls._lock:
            process = MobileScanProcess(
                scan_id=scan_id,
                user_id=user_id,
                platform=platform
            )
            cls._instances[scan_id] = process
            logger.info(f"[MobileRegistry] Registered scan {scan_id}")
            return process
    
    @classmethod
    async def get(cls, scan_id: str) -> Optional[MobileScanProcess]:
        """Get a registered mobile scan process"""
        return cls._instances.get(scan_id)
    
    @classmethod
    async def update(
        cls,
        scan_id: str,
        **kwargs
    ) -> Optional[MobileScanProcess]:
        """
        Update a registered scan's process references.
        
        Usage:
            await MobileProcessRegistry.update(
                scan_id,
                orchestrator=orchestrator,
                emulator_manager=manager,
                emulator_pid=pid
            )
        """
        async with cls._lock:
            process = cls._instances.get(scan_id)
            if process:
                for key, value in kwargs.items():
                    if hasattr(process, key):
                        setattr(process, key, value)
                logger.debug(f"[MobileRegistry] Updated scan {scan_id}: {kwargs.keys()}")
            return process
    
    @classmethod
    async def signal_stop(cls, scan_id: str) -> bool:
        """Signal a scan to stop (cooperative cancellation)"""
        process = cls._instances.get(scan_id)
        if process:
            process.should_stop = True
            logger.info(f"[MobileRegistry] Stop signal sent to {scan_id}")
            return True
        return False
    
    @classmethod
    async def force_cleanup_by_scan_id(cls, scan_id: str) -> bool:
        """
        Force cleanup all processes for a specific scan.
        Called when stop is requested or on crash recovery.
        """
        async with cls._lock:
            process = cls._instances.get(scan_id)
            if not process:
                logger.warning(f"[MobileRegistry] Scan {scan_id} not found for cleanup")
                return False
            
            logger.info(f"[MobileRegistry] Force cleanup for scan {scan_id}")
            
            # 1. Stop orchestrator if running
            if process.orchestrator:
                try:
                    if hasattr(process.orchestrator, '_cleanup'):
                        await process.orchestrator._cleanup()
                    process.orchestrator._running = False
                    logger.info(f"[MobileRegistry] Orchestrator cleanup done for {scan_id}")
                except Exception as e:
                    logger.error(f"[MobileRegistry] Orchestrator cleanup error: {e}")
            
            # 2. Stop emulator via EmulatorManager
            if process.emulator_manager:
                try:
                    await process.emulator_manager.stop_emulator()
                    logger.info(f"[MobileRegistry] Emulator stopped for {scan_id}")
                except Exception as e:
                    logger.error(f"[MobileRegistry] Emulator stop error: {e}")
            
            # 3. Kill emulator by PID if manager failed
            if process.emulator_pid:
                await cls._kill_process_by_pid(process.emulator_pid, "emulator")
            
            # 4. Kill Frida server on device
            if process.device_id:
                await cls._kill_frida_on_device(process.device_id)
            
            # 5. Stop MITM proxy
            if process.mitm_proxy:
                try:
                    if hasattr(process.mitm_proxy, 'shutdown'):
                        await process.mitm_proxy.shutdown()
                    elif hasattr(process.mitm_proxy, 'stop'):
                        await process.mitm_proxy.stop()
                    logger.info(f"[MobileRegistry] MITM proxy stopped for {scan_id}")
                except Exception as e:
                    logger.error(f"[MobileRegistry] MITM proxy stop error: {e}")
            
            # 6. Unregister
            del cls._instances[scan_id]
            logger.info(f"[MobileRegistry] Scan {scan_id} cleaned up and unregistered")
            return True
    
    @classmethod
    async def unregister(cls, scan_id: str) -> bool:
        """Remove a scan from registry (after normal completion)"""
        async with cls._lock:
            if scan_id in cls._instances:
                del cls._instances[scan_id]
                logger.info(f"[MobileRegistry] Unregistered scan {scan_id}")
                return True
            return False
    
    @classmethod
    async def cleanup_all(cls) -> int:
        """
        Cleanup ALL registered mobile scans.
        Called during graceful shutdown.
        Returns count of cleaned scans.
        """
        scan_ids = list(cls._instances.keys())
        count = 0
        
        for scan_id in scan_ids:
            try:
                await cls.force_cleanup_by_scan_id(scan_id)
                count += 1
            except Exception as e:
                logger.error(f"[MobileRegistry] Cleanup failed for {scan_id}: {e}")
        
        logger.info(f"[MobileRegistry] Cleaned up {count} mobile scans during shutdown")
        return count
    
    @classmethod
    def get_active_scans(cls) -> List[str]:
        """Get list of active scan IDs"""
        return list(cls._instances.keys())
    
    @classmethod
    async def _kill_process_by_pid(cls, pid: int, process_name: str = "process") -> bool:
        """Kill a process by PID (fallback when normal stop fails)"""
        try:
            import platform as plat
            if plat.system() == "Windows":
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    capture_output=True,
                    timeout=10
                )
            else:
                subprocess.run(
                    ["kill", "-9", str(pid)],
                    capture_output=True,
                    timeout=10
                )
            logger.info(f"[MobileRegistry] Killed {process_name} PID {pid}")
            return True
        except Exception as e:
            logger.error(f"[MobileRegistry] Failed to kill {process_name} PID {pid}: {e}")
            return False
    
    @classmethod
    async def _kill_frida_on_device(cls, device_id: str) -> bool:
        """Kill frida-server on Android device/emulator"""
        try:
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "pkill", "-f", "frida-server"],
                capture_output=True,
                timeout=10
            )
            logger.info(f"[MobileRegistry] Killed frida-server on {device_id}")
            return True
        except Exception as e:
            logger.error(f"[MobileRegistry] Failed to kill frida-server on {device_id}: {e}")
            return False
    
    @classmethod
    def is_running(cls, scan_id: str) -> bool:
        """Check if a scan is currently registered/running"""
        return scan_id in cls._instances
    
    @classmethod
    def should_stop(cls, scan_id: str) -> bool:
        """Check if a scan has been signaled to stop"""
        process = cls._instances.get(scan_id)
        return process.should_stop if process else True
