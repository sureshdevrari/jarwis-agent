"""
Mobile Engine Adapter - Wraps MobilePenTestOrchestrator for ScanOrchestrator Compatibility

This adapter wraps the mobile orchestrator to work with the unified ScanOrchestrator
using the ScanEngineProtocol interface.

Usage:
    adapter = MobileEngineAdapter(config, context)
    result = await adapter.run()
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from core.engine_protocol import (
    EngineResult,
    ProgressUpdate,
    ScanEngineAdapter,
)

logger = logging.getLogger(__name__)


class MobileEngineAdapter(ScanEngineAdapter):
    """
    Adapter for MobilePenTestOrchestrator.
    
    Wraps the mobile orchestrator to implement ScanEngineProtocol,
    allowing it to be used with the unified ScanOrchestrator.
    """
    
    def __init__(
        self,
        config: Dict[str, Any],
        context: Any = None,  # ScanContext from orchestrator
    ):
        """
        Initialize the mobile engine adapter.
        
        Args:
            config: Scan configuration including app_path, platform, etc.
            context: Optional ScanContext from orchestrator
        """
        super().__init__()
        
        self.config = config
        self.context = context
        self.scan_id = context.scan_id if context else config.get("scan_id", "unknown")
        
        # Mobile orchestrator (created lazily)
        self._orchestrator = None
    
    def _create_orchestrator(self):
        """Create the MobilePenTestOrchestrator with config"""
        from attacks.mobile.orchestration.mobile_orchestrator import (
            MobilePenTestOrchestrator,
            MobileScanConfig
        )
        
        # Build MobileScanConfig from dict config
        orchestrator_config = MobileScanConfig(
            app_path=self.config.get("app_file") or self.config.get("app_path", ""),
            platform=self.config.get("platform", "android"),
            frida_bypass_enabled=self.config.get("ssl_pinning_bypass", True),
            use_emulator=self.config.get("use_emulator", True),
            headless=self.config.get("headless", False),
            mitm_enabled=self.config.get("intercept_traffic", True),
            crawl_enabled=self.config.get("crawl_enabled", True),
            attacks_enabled=self.config.get("attacks_enabled", True),
            ai_analysis=self.config.get("ai_analysis", False),
            generate_report=self.config.get("generate_report", True),
        )
        
        return MobilePenTestOrchestrator(orchestrator_config)
    
    async def run(self) -> EngineResult:
        """
        Execute the mobile scan using MobilePenTestOrchestrator.
        
        Returns:
            EngineResult with findings and summary
        """
        start_time = datetime.utcnow()
        
        try:
            # Create the orchestrator
            self._orchestrator = self._create_orchestrator()
            
            logger.info(f"[{self.scan_id}] Running mobile scan via MobileEngineAdapter")
            
            # Set up callbacks
            if self._progress_callback:
                async def progress_cb(phase: str, progress: int, message: str):
                    await self._progress_callback(ProgressUpdate(
                        progress=progress,
                        phase=phase,
                        message=message,
                    ))
                self._orchestrator.set_progress_callback(progress_cb)
            
            # Set up log callback
            def log_cb(log_type: str, message: str, details: str = None):
                logger.info(f"[{self.scan_id}] {message}")
                if details:
                    logger.debug(f"[{self.scan_id}]   {details}")
            
            self._orchestrator.set_log_callback(log_cb)
            
            # Report initial progress
            if self._progress_callback:
                await self._progress_callback(ProgressUpdate(
                    progress=0,
                    phase="initializing",
                    message="Starting mobile security scan",
                ))
            
            # Run the orchestrator
            raw_result = await self._orchestrator.run()
            
            # Convert to EngineResult
            result = self._convert_result(raw_result, start_time)
            
            return result
            
        except ImportError as e:
            logger.error(f"[{self.scan_id}] Mobile orchestrator not available: {e}")
            return EngineResult(
                status="error",
                error_message=f"Mobile orchestrator not available: {e}",
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
        except Exception as e:
            logger.exception(f"[{self.scan_id}] Mobile engine error: {e}")
            return EngineResult(
                status="error",
                error_message=str(e),
                started_at=start_time,
                completed_at=datetime.utcnow(),
            )
    
    def _convert_result(
        self,
        raw_result: Dict[str, Any],
        start_time: datetime
    ) -> EngineResult:
        """Convert mobile orchestrator result to EngineResult format"""
        end_time = datetime.utcnow()
        
        # Extract status
        status = raw_result.get("status", "completed")
        if status == "failed":
            status = "error"
        
        # Extract vulnerabilities/findings
        vulnerabilities = raw_result.get("vulnerabilities", [])
        findings = []
        
        for vuln in vulnerabilities:
            findings.append({
                "id": vuln.get("id", ""),
                "category": vuln.get("category", ""),
                "severity": vuln.get("severity", "medium"),
                "title": vuln.get("title", ""),
                "description": vuln.get("description", ""),
                "evidence": vuln.get("evidence", ""),
                "remediation": vuln.get("remediation", ""),
                "owasp_mobile": vuln.get("owasp_mobile", ""),
            })
        
        # Count severities
        severity_counts = self._count_severities(findings)
        
        # Extract summary
        summary = raw_result.get("summary", {})
        if not summary:
            summary = {
                "total_findings": len(findings),
                "total_endpoints": len(raw_result.get("endpoints", [])),
                "platform": self.config.get("platform", "android"),
                "scan_type": "mobile",
            }
        
        return EngineResult(
            status=status,
            findings=findings,
            summary=summary,
            error_message=raw_result.get("error"),
            started_at=start_time,
            completed_at=end_time,
            duration_seconds=(end_time - start_time).total_seconds(),
            total_endpoints=len(raw_result.get("endpoints", [])),
            critical_count=severity_counts.get("critical", 0),
            high_count=severity_counts.get("high", 0),
            medium_count=severity_counts.get("medium", 0),
            low_count=severity_counts.get("low", 0),
            info_count=severity_counts.get("info", 0),
            report_paths=raw_result.get("report_paths", {}),
        )
    
    def _count_severities(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        
        for finding in findings:
            severity = str(finding.get("severity", "medium")).lower()
            if severity in counts:
                counts[severity] += 1
            else:
                counts["medium"] += 1  # Default unknown to medium
        
        return counts
    
    async def stop(self) -> None:
        """Request graceful stop of the mobile scan"""
        if self._orchestrator and hasattr(self._orchestrator, 'stop'):
            logger.info(f"[{self.scan_id}] Stopping mobile orchestrator")
            await self._orchestrator.stop()
