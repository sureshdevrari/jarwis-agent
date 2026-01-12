"""
Legacy Engine Adapter - Wraps Existing Runners for Orchestrator Compatibility

This adapter dynamically wraps existing scan runners (WebScanRunner, CloudScanRunner, etc.)
to work with the unified ScanOrchestrator without modifying them.

This enables:
- Immediate compatibility with existing runners
- Gradual migration to native ScanEngineProtocol implementations
- Zero changes to existing runner code

Usage:
    adapter = LegacyEngineAdapter("web", config, context)
    result = await adapter.run()
"""

import asyncio
import logging
from typing import Dict, Any, Optional, Callable, Awaitable, List
from datetime import datetime

from core.engine_protocol import (
    EngineResult,
    ProgressUpdate,
    ScanEngineAdapter,
    ProgressCallback,
    StopCheck,
)

logger = logging.getLogger(__name__)


class LegacyEngineAdapter(ScanEngineAdapter):
    """
    Adapter that wraps existing legacy scan runners.
    
    Supports:
    - WebScanRunner (core/web_scan_runner.py)
    - NetworkOrchestrator (attacks/network/orchestrator.py)
    - CloudScanRunner (core/cloud_scan_runner.py)
    - SASTScanRunner (core/sast_scan_runner.py)
    - MobilePenTestOrchestrator (attacks/mobile/)
    
    The adapter:
    1. Creates the appropriate runner based on scan_type
    2. Wires up progress callbacks
    3. Converts runner results to EngineResult format
    """
    
    # Mapping of scan types to runner imports
    RUNNER_MAP = {
        "web": {
            "module": "core.web_scan_runner",
            "class": "WebScanRunner",
        },
        "network": {
            "module": "attacks.network.orchestrator",
            "class": "NetworkOrchestrator",
        },
        "cloud": {
            "module": "core.cloud_scan_runner",
            "class": "CloudScanRunner",
        },
        "sast": {
            "module": "core.sast_scan_runner",
            "class": "SASTScanRunner",
        },
        "mobile": {
            "module": "attacks.mobile.mobile_orchestrator",
            "class": "MobilePenTestOrchestrator",
        },
    }
    
    def __init__(
        self,
        scan_type: str,
        config: Dict[str, Any],
        context: Any,  # ScanContext from orchestrator
    ):
        """
        Initialize the legacy adapter.
        
        Args:
            scan_type: Type of scan (web, network, cloud, sast, mobile)
            config: Scan configuration
            context: ScanContext from the orchestrator
        """
        super().__init__()
        
        self.scan_type = scan_type.lower()
        self.config = config
        self.context = context
        self.scan_id = context.scan_id
        
        # Runner instance (created lazily)
        self._runner = None
        self._runner_class = None
        
        # Load the runner class
        self._load_runner_class()
    
    def _load_runner_class(self) -> None:
        """Dynamically load the runner class for this scan type"""
        if self.scan_type not in self.RUNNER_MAP:
            raise ValueError(f"Unknown scan type: {self.scan_type}")
        
        runner_info = self.RUNNER_MAP[self.scan_type]
        module_name = runner_info["module"]
        class_name = runner_info["class"]
        
        try:
            module = __import__(module_name, fromlist=[class_name])
            self._runner_class = getattr(module, class_name)
            logger.debug(f"Loaded runner class: {module_name}.{class_name}")
        except (ImportError, AttributeError) as e:
            logger.error(f"Failed to load runner {module_name}.{class_name}: {e}")
            raise
    
    def _create_runner(self) -> Any:
        """Create the runner instance with appropriate configuration"""
        if self.scan_type == "web":
            return self._create_web_runner()
        elif self.scan_type == "network":
            return self._create_network_runner()
        elif self.scan_type == "cloud":
            return self._create_cloud_runner()
        elif self.scan_type == "sast":
            return self._create_sast_runner()
        elif self.scan_type == "mobile":
            return self._create_mobile_runner()
        else:
            raise ValueError(f"No runner creation logic for: {self.scan_type}")
    
    def _create_web_runner(self) -> Any:
        """Create WebScanRunner with proper configuration"""
        # Create status callback that reports to orchestrator
        async def status_callback(status: str, progress: int, phase: str):
            if self._progress_callback:
                await self._progress_callback(ProgressUpdate(
                    progress=progress or 0,
                    phase=phase or "running",
                    message=status,
                ))
        
        runner = self._runner_class(
            config=self.config,
            status_callback=status_callback,
            resume_from_checkpoint=False,  # Orchestrator handles checkpoints
        )
        
        # Inject scan_id from orchestrator
        runner.scan_id = self.scan_id
        
        return runner
    
    def _create_network_runner(self) -> Any:
        """Create NetworkOrchestrator with proper configuration"""
        # Network orchestrator has different initialization
        target = self.config.get("target") or self.config.get("targets", [""])[0]
        profile = self.config.get("profile", "standard")
        
        runner = self._runner_class(
            target=target,
            profile=profile,
            config=self.config,
        )
        
        return runner
    
    def _create_cloud_runner(self) -> Any:
        """Create CloudScanRunner with proper configuration"""
        providers = self.config.get("providers", ["aws"])
        credentials = self.config.get("credentials", {})
        
        runner = self._runner_class(
            providers=providers,
            credentials=credentials,
            config=self.config,
        )
        
        return runner
    
    def _create_sast_runner(self) -> Any:
        """Create SASTScanRunner with proper configuration"""
        runner = self._runner_class(
            config=self.config,
            progress_state={},  # Shared progress state
        )
        
        # Wire up callbacks
        if self._progress_callback:
            def progress_cb(progress: int, phase: str):
                asyncio.create_task(self._progress_callback(ProgressUpdate(
                    progress=progress,
                    phase=phase,
                    message="",
                )))
            runner.set_progress_callback(progress_cb)
        
        if self._stop_check:
            runner.set_stop_check(self._stop_check)
        
        return runner
    
    def _create_mobile_runner(self) -> Any:
        """Create MobilePenTestOrchestrator with proper configuration"""
        runner = self._runner_class(
            config=self.config,
        )
        return runner
    
    async def run(self) -> EngineResult:
        """
        Execute the scan using the legacy runner.
        
        Returns:
            EngineResult with findings and summary
        """
        start_time = datetime.utcnow()
        
        try:
            # Create the runner
            self._runner = self._create_runner()
            
            logger.info(f"Running legacy {self.scan_type} scan via adapter")
            
            # Report initial progress
            if self._progress_callback:
                await self._progress_callback(ProgressUpdate(
                    progress=0,
                    phase="initializing",
                    message=f"Starting {self.scan_type} scan",
                ))
            
            # Run the scan
            raw_result = await self._run_with_stop_check()
            
            # Convert to EngineResult
            result = self._convert_result(raw_result, start_time)
            
            return result
            
        except Exception as e:
            logger.exception(f"Legacy adapter error: {e}")
            return EngineResult(
                status="error",
                error_message=str(e),
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
    
    async def _run_with_stop_check(self) -> Dict[str, Any]:
        """Run the scanner with periodic stop checks"""
        # Most legacy runners have their own run() method
        if hasattr(self._runner, 'run'):
            if asyncio.iscoroutinefunction(self._runner.run):
                return await self._runner.run()
            else:
                # Run sync method in executor
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(None, self._runner.run)
        else:
            raise NotImplementedError(f"Runner {type(self._runner)} has no run() method")
    
    def _convert_result(
        self, 
        raw_result: Dict[str, Any], 
        start_time: datetime
    ) -> EngineResult:
        """Convert legacy runner result to EngineResult format"""
        end_time = datetime.utcnow()
        
        # Extract status
        status = raw_result.get("status", "completed")
        if status == "failed":
            status = "error"
        
        # Extract findings (different runners use different keys)
        findings = (
            raw_result.get("findings") or
            raw_result.get("vulnerabilities") or
            raw_result.get("results") or
            []
        )
        
        # Ensure findings is a list
        if not isinstance(findings, list):
            findings = [findings] if findings else []
        
        # Count severities
        severity_counts = self._count_severities(findings)
        
        # Extract summary
        summary = raw_result.get("summary", {})
        if not summary:
            summary = {
                "total_findings": len(findings),
                "target": self.config.get("target_url") or self.config.get("target"),
                "scan_type": self.scan_type,
            }
        
        return EngineResult(
            status=status,
            findings=findings,
            summary=summary,
            error_message=raw_result.get("error"),
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            total_requests=raw_result.get("total_requests", 0),
            total_endpoints=raw_result.get("total_endpoints", 0),
            scanners_run=raw_result.get("scanners_run", 0),
            scanners_failed=raw_result.get("scanners_failed", 0),
            critical_count=severity_counts["critical"],
            high_count=severity_counts["high"],
            medium_count=severity_counts["medium"],
            low_count=severity_counts["low"],
            info_count=severity_counts["info"],
            report_paths=raw_result.get("report_paths", {}),
        )
    
    def _count_severities(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        
        for finding in findings:
            severity = str(finding.get("severity", "info")).lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["info"] += 1
        
        return counts


# Specific adapters for each scan type (optional - for custom logic)

class WebEngineAdapter(LegacyEngineAdapter):
    """Specialized adapter for web scans"""
    
    def __init__(self, config: Dict[str, Any], context: Any):
        super().__init__("web", config, context)


class NetworkEngineAdapter(LegacyEngineAdapter):
    """Specialized adapter for network scans"""
    
    def __init__(self, config: Dict[str, Any], context: Any):
        super().__init__("network", config, context)


class CloudEngineAdapter(LegacyEngineAdapter):
    """Specialized adapter for cloud scans"""
    
    def __init__(self, config: Dict[str, Any], context: Any):
        super().__init__("cloud", config, context)


class SASTEngineAdapter(LegacyEngineAdapter):
    """Specialized adapter for SAST scans"""
    
    def __init__(self, config: Dict[str, Any], context: Any):
        super().__init__("sast", config, context)


class MobileEngineAdapter(LegacyEngineAdapter):
    """Specialized adapter for mobile scans"""
    
    def __init__(self, config: Dict[str, Any], context: Any):
        super().__init__("mobile", config, context)


__all__ = [
    "LegacyEngineAdapter",
    "WebEngineAdapter",
    "NetworkEngineAdapter",
    "CloudEngineAdapter",
    "SASTEngineAdapter",
    "MobileEngineAdapter",
]
