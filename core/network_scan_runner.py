"""
Network Scan Runner - Core Orchestration Layer

Coordinates network scanning with:
- Preflight validation and checkpoint system
- Phase-based orchestration via attacks/network/orchestrator.py
- Progress tracking and database updates
- Report generation

This layer sits between the service layer and the attack modules.
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, List
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from services.network_service import (
    NetworkScanService,
    NetworkScanConfig,
)
from attacks.network import NetworkOrchestrator, ScanProfile
from core.network_reporter import NetworkReportGenerator

logger = logging.getLogger(__name__)


class NetworkScanRunner:
    """
    Network scan orchestrator.
    
    Responsibilities:
    - Preflight validation
    - Checkpoint/resume handling
    - Progress tracking
    - Report generation
    - Error handling and recovery
    """
    
    # Profile to ScanProfile mapping
    PROFILE_MAP = {
        'quick': ScanProfile.QUICK,
        'standard': ScanProfile.STANDARD,
        'comprehensive': ScanProfile.COMPREHENSIVE,
        'stealth': ScanProfile.STEALTH,
    }
    
    def __init__(self, config: NetworkScanConfig, db: AsyncSession):
        """Initialize scan runner"""
        self.config = config
        self.db = db
        self.logger = logger
    
    async def run(self, scan_id: str, user_id: str) -> None:
        """
        Execute network scan.
        
        Args:
            scan_id: Unique scan identifier
            user_id: User performing the scan
        """
        try:
            self.logger.info(
                f"Starting network scan: {scan_id} for user {user_id}, "
                f"targets: {self.config.targets}, profile: {self.config.profile}"
            )
            
            # Step 1: Preflight validation
            self.logger.info(f"[{scan_id}] Running preflight checks")
            await self._update_progress(scan_id, "preflight", 0.0, "Validating tools and environment")
            
            is_ready, error_msg, tool_status = await NetworkScanService.check_preflight_requirements(
                self.config
            )
            if not is_ready:
                raise ValueError(f"Preflight check failed: {error_msg}")
            
            self.logger.debug(f"Tool availability: {tool_status}")
            
            # Step 2: Load checkpoint if resuming
            self.logger.info(f"[{scan_id}] Checking for checkpoint data")
            checkpoint = await self._load_checkpoint(scan_id)
            
            if checkpoint and checkpoint.get('completed_phases'):
                self.logger.info(
                    f"[{scan_id}] Resuming scan from checkpoint, "
                    f"completed phases: {checkpoint['completed_phases']}"
                )
            
            # Step 3: Configure orchestrator
            orchestrator_config = {
                'timeout': self.config.timeout_per_host,
                'rate_limit': self.config.rate_limit,
                'mode': 'safe' if self.config.safe_checks else 'full',
            }
            
            orchestrator = NetworkOrchestrator(orchestrator_config)
            
            # Step 4: Prepare progress callback
            async def on_progress(phase: str, progress: float, message: str):
                """Progress callback from orchestrator"""
                await self._update_progress(scan_id, phase, progress, message)
            
            # Step 5: Execute scan
            profile = self.PROFILE_MAP.get(
                self.config.profile,
                ScanProfile.STANDARD
            )
            
            findings = await orchestrator.run(
                target=self.config.targets,
                profile=profile,
                credentials=self._prepare_credentials(),
                callback=on_progress
            )
            
            self.logger.info(
                f"[{scan_id}] Scan completed, found {len(findings) if findings else 0} vulnerabilities"
            )
            
            # Step 6: Save findings to database
            if findings:
                findings_list = self._format_findings(findings)
                await NetworkScanService.complete_scan(self.db, scan_id, findings_list)
            else:
                # Mark as completed with no findings
                await self._mark_completed(scan_id)
            
            # Step 7: Generate reports
            self.logger.info(f"[{scan_id}] Generating reports")
            await self._generate_reports(scan_id, findings)
            
            self.logger.info(f"[{scan_id}] Network scan completed successfully")
        
        except Exception as e:
            self.logger.error(f"[{scan_id}] Scan failed: {e}", exc_info=True)
            await self._mark_error(scan_id, str(e))
            raise
    
    async def _update_progress(
        self,
        scan_id: str,
        phase: str,
        progress: float,
        message: str,
    ) -> None:
        """Update scan progress in database"""
        try:
            await NetworkScanService.update_scan_progress(
                self.db,
                scan_id,
                phase,
                progress,
                message,
            )
        except Exception as e:
            self.logger.error(f"Failed to update progress for {scan_id}: {e}")
    
    async def _load_checkpoint(self, scan_id: str) -> Dict[str, Any]:
        """Load checkpoint data for resuming scan"""
        try:
            status_dict = await NetworkScanService.get_scan_status(
                self.db,
                None,  # No user context needed for checkpoint
                scan_id
            )
            return status_dict.get('checkpoint_data', {})
        except Exception as e:
            self.logger.warning(f"Failed to load checkpoint for {scan_id}: {e}")
            return {}
    
    async def _mark_completed(self, scan_id: str) -> None:
        """Mark scan as completed without findings"""
        await NetworkScanService.complete_scan(self.db, scan_id, [])
    
    async def _mark_error(self, scan_id: str, error_msg: str) -> None:
        """Mark scan as failed"""
        try:
            from sqlalchemy import select
            from database.models import ScanHistory
            
            query = select(ScanHistory).where(ScanHistory.id == scan_id)
            result = await self.db.execute(query)
            scan = result.scalars().first()
            
            if scan:
                scan.status = 'error'
                checkpoint = scan.checkpoint_data or {}
                checkpoint['error'] = error_msg
                checkpoint['error_at'] = datetime.utcnow().isoformat()
                scan.checkpoint_data = checkpoint
                
                self.db.add(scan)
                await self.db.commit()
        except Exception as e:
            self.logger.error(f"Failed to mark scan error: {e}")
    
    def _prepare_credentials(self) -> Dict[str, Any]:
        """Prepare credentials for orchestrator"""
        if not self.config.credentials:
            return {}
        
        return {
            'ssh': self.config.credentials.get('ssh'),
            'windows': self.config.credentials.get('windows'),
            'snmp': self.config.credentials.get('snmp'),
            'database': self.config.credentials.get('database'),
        }
    
    def _format_findings(self, orchestrator_findings: List[Any]) -> List[Dict[str, Any]]:
        """Convert orchestrator findings to database format"""
        formatted = []
        
        for finding in orchestrator_findings:
            formatted.append({
                'id': getattr(finding, 'id', None) or f"net-{len(formatted)}",
                'category': getattr(finding, 'category', 'Network'),
                'severity': getattr(finding, 'severity', 'info').lower(),
                'title': getattr(finding, 'title', ''),
                'description': getattr(finding, 'description', ''),
                'ip_address': getattr(finding, 'target', getattr(finding, 'ip_address', '')),
                'port': getattr(finding, 'port', None),
                'service': getattr(finding, 'service', ''),
                'cve_id': getattr(finding, 'cve_id', ''),
                'cvss_score': getattr(finding, 'cvss_score', 0.0),
                'evidence': getattr(finding, 'evidence', {}),
                'remediation': getattr(finding, 'remediation', ''),
                'references': getattr(finding, 'references', []),
                'tool': getattr(finding, 'tool', ''),
                'confidence': getattr(finding, 'confidence', 'medium'),
            })
        
        return formatted
    
    async def _generate_reports(self, scan_id: str, findings: List[Any]) -> None:
        """Generate reports for the network scan"""
        try:
            # Create reports directory if it doesn't exist
            reports_dir = Path("reports") / "network" / scan_id
            reports_dir.mkdir(parents=True, exist_ok=True)
            
            # Initialize reporter
            reporter = NetworkReportGenerator(
                output_dir=str(reports_dir),
                formats=['html', 'json', 'pdf']
            )
            
            # Prepare scan context
            scan_config = {
                'profile': self.config.profile,
                'ports': self.config.ports,
                'timeout': self.config.timeout_per_host,
                'rate_limit': self.config.rate_limit,
            }
            
            # Generate reports
            report_paths = await reporter.generate_network_report(
                findings=findings or [],
                scan_config=scan_config,
                scan_results={},  # TODO: Pass orchestrator results
                target=self.config.targets
            )
            
            self.logger.info(f"[{scan_id}] Generated {len(report_paths)} reports: {report_paths}")
            
            # Update scan record with report paths
            from sqlalchemy import select
            from database.models import ScanHistory
            
            query = select(ScanHistory).where(ScanHistory.id == scan_id)
            result = await self.db.execute(query)
            scan = result.scalars().first()
            
            if scan:
                for path in report_paths:
                    if path.endswith('.html'):
                        scan.report_html = path
                    elif path.endswith('.json'):
                        scan.report_json = path
                    elif path.endswith('.pdf'):
                        scan.report_pdf = path
                
                self.db.add(scan)
                await self.db.commit()
                
        except Exception as e:
            self.logger.error(f"[{scan_id}] Report generation failed: {e}", exc_info=True)
            # Don't fail the scan if reporting fails
