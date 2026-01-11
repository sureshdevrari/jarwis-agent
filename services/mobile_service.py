"""
Mobile Service

Mobile scan orchestration and management.
Coordinates between API routes, mobile scanners, and database.

Following layered architecture:
- Services CAN import: core/*, database/*, shared/*
- Services CANNOT import: api/routes/*
"""

import logging
import uuid
import asyncio
from typing import Optional, Dict, Any, List
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from shared.schemas.scanner_results import MobileFinding
from database import crud
from database.connection import AsyncSessionLocal

logger = logging.getLogger(__name__)


class MobileScanService:
    """
    Mobile scan orchestration service.
    
    Responsibilities:
    - Validate mobile scan requests
    - Coordinate with mobile orchestrators
    - Track scan progress in database (no in-memory state)
    - Generate mobile security reports
    """
    
    @classmethod
    async def start_mobile_scan(
        cls,
        db: AsyncSession,
        user,
        app_file_path: str,
        app_name: str,
        platform: str,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Start a new mobile application security scan.
        
        Args:
            db: Database session
            user: Current user
            app_file_path: Path to saved APK/IPA file
            app_name: Application name
            platform: "android" or "ios"
            config: Scan configuration (ssl_pinning_bypass, frida_scripts, etc.)
            
        Returns:
            Dict with scan_id, status, message
            
        Raises:
            ValueError: If validation fails
        """
        # NOTE: Subscription checks are done in the API route via dependencies
        # This keeps the service layer focused on business logic
        
        # Generate scan ID
        scan_id = str(uuid.uuid4())[:8]
        
        # Create scan record in database
        scan = await crud.create_scan(
            db=db,
            user_id=user.id,
            scan_id=scan_id,
            target_url=f"mobile://{app_name}",
            scan_type="mobile",
            config={
                "app_name": app_name,
                "platform": platform,
                "app_file": app_file_path,
                **config
            }
        )
        
        logger.info(
            f"Mobile scan {scan_id} created for {app_name} ({platform}) "
            f"by user {user.email}"
        )
        
        return {
            "scan_id": scan_id,
            "status": "started",
            "message": f"Mobile scan started for {app_name}",
            "platform": platform
        }
    
    @classmethod
    async def execute_mobile_scan(
        cls,
        scan_id: str,
        user_id: str
    ):
        """
        Execute mobile scan in background.
        
        This is the main orchestration logic that was previously in
        api/routes/mobile.py run_mobile_scan() function.
        
        Follows the 9-phase mobile scan flow from mobile_orchestrator.py.
        """
        async with AsyncSessionLocal() as db:
            scan = await crud.get_scan_by_id(db, scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
            
            try:
                await cls._update_scan_progress(
                    db, scan, "running", 5, "Initializing"
                )
                
                app_file = scan.config.get("app_file", "")
                platform = scan.config.get("platform", "android")
                config = scan.config
                
                logger.info(f"[{scan_id}] Starting mobile scan for {app_file}")
                
                # Try full orchestrator first
                use_orchestrator = True
                findings = []
                endpoints = []
                
                if use_orchestrator:
                    try:
                        findings, endpoints = await cls._run_full_orchestrator(
                            db, scan, app_file, platform, config
                        )
                    except ImportError as e:
                        logger.warning(
                            f"[{scan_id}] Orchestrator not available: {e}. "
                            "Falling back to basic scanning."
                        )
                        use_orchestrator = False
                    except Exception as e:
                        logger.error(
                            f"[{scan_id}] Orchestrator error: {e}. "
                            "Falling back to basic scanning.",
                            exc_info=True
                        )
                        use_orchestrator = False
                
                # Fallback to basic static analysis
                if not use_orchestrator:
                    findings = await cls._run_basic_scan(
                        db, scan, app_file, platform, config
                    )
                
                # Generate report
                await cls._update_scan_progress(
                    db, scan, "running", 90, "Generating report"
                )
                
                # Calculate severity counts
                severity_counts = cls._calculate_severity_counts(findings)
                
                # Update scan with results
                await crud.update_scan_results(
                    db, scan,
                    findings_count=len(findings),
                    severity_counts=severity_counts,
                    report_paths={}
                )
                
                # Complete scan
                await cls._update_scan_progress(
                    db, scan, "completed", 100, "Completed"
                )
                
                logger.info(
                    f"[{scan_id}] Mobile scan completed! "
                    f"Found {len(findings)} vulnerabilities"
                )
                
            except Exception as e:
                logger.error(f"[{scan_id}] Mobile scan error: {e}", exc_info=True)
                await cls._update_scan_progress(
                    db, scan, "failed", scan.progress, f"Error: {str(e)}"
                )
                
                # Refund scan credit on error
                try:
                    from database.subscription import decrement_usage_counter
                    await decrement_usage_counter(db, user_id, "scans")
                    logger.info(f"[{scan_id}] Scan credit refunded due to error")
                except Exception as refund_error:
                    logger.warning(
                        f"[{scan_id}] Failed to refund scan credit: {refund_error}"
                    )
    
    @classmethod
    async def _run_full_orchestrator(
        cls,
        db: AsyncSession,
        scan,
        app_file: str,
        platform: str,
        config: Dict
    ) -> tuple:
        """
        Run the full MobilePenTestOrchestrator.
        
        Returns:
            Tuple of (findings, endpoints)
        """
        from attacks.mobile.mobile_orchestrator import (
            MobilePenTestOrchestrator,
            MobileScanConfig
        )
        
        logger.info(f"[{scan.scan_id}] Initializing Mobile Pentest Orchestrator")
        
        # Build orchestrator config
        orchestrator_config = MobileScanConfig(
            app_path=app_file,
            platform=platform,
            frida_bypass_enabled=config.get("ssl_pinning_bypass", True),
            use_emulator=True,
            headless=False,
            mitm_enabled=config.get("intercept_traffic", True),
            crawl_enabled=True,
            attacks_enabled=True,
            ai_analysis=False,
            generate_report=True
        )
        
        # Create orchestrator
        orchestrator = MobilePenTestOrchestrator(orchestrator_config)
        
        # Set callbacks
        def log_callback(log_type: str, message: str, details: str = None):
            logger.info(f"[{scan.scan_id}] {message}")
            if details:
                logger.debug(f"[{scan.scan_id}]   {details}")
        
        async def progress_callback(phase: str, progress: int, message: str):
            await cls._update_scan_progress(db, scan, "running", progress, phase)
        
        orchestrator.set_log_callback(log_callback)
        orchestrator.set_progress_callback(progress_callback)
        
        logger.info(f"[{scan.scan_id}] Starting full mobile penetration test")
        
        # Run orchestrator
        results = await orchestrator.run()
        
        if results.get("status") != "completed":
            raise RuntimeError(
                f"Orchestrator failed: {results.get('error', 'Unknown error')}"
            )
        
        # Extract findings
        vulnerabilities = results.get("vulnerabilities", [])
        endpoints = results.get("endpoints", [])
        
        # Convert to MobileFinding schema
        findings = []
        for vuln in vulnerabilities:
            findings.append({
                "id": vuln.get("id", ""),
                "category": vuln.get("category", ""),
                "severity": vuln.get("severity", "medium"),
                "title": vuln.get("title", ""),
                "description": vuln.get("description", ""),
                "evidence": vuln.get("evidence", ""),
                "remediation": vuln.get("remediation", "")
            })
        
        summary = results.get("summary", {})
        logger.info(
            f"[{scan.scan_id}] Orchestrator completed: "
            f"{summary.get('total_vulnerabilities', 0)} vulnerabilities, "
            f"{summary.get('total_endpoints', 0)} endpoints"
        )
        
        return findings, endpoints
    
    @classmethod
    async def _run_basic_scan(
        cls,
        db: AsyncSession,
        scan,
        app_file: str,
        platform: str,
        config: Dict
    ) -> List[Dict]:
        """
        Run basic static-only mobile scan as fallback.
        
        Returns:
            List of findings
        """
        findings = []
        
        logger.info(f"[{scan.scan_id}] Running basic mobile security scan")
        
        # Phase 1: Static Analysis
        await cls._update_scan_progress(
            db, scan, "running", 15, "Static Analysis"
        )
        
        try:
            from attacks.mobile import StaticAnalyzer
            
            logger.info(f"[{scan.scan_id}] Running static analysis")
            analyzer = StaticAnalyzer(app_file)
            static_results = await analyzer.analyze()
            
            static_findings = static_results.get("findings", [])
            findings.extend(static_findings)
            
            logger.info(
                f"[{scan.scan_id}] Static analysis found "
                f"{len(static_findings)} issues"
            )
        except ImportError:
            logger.warning(
                f"[{scan.scan_id}] Static analyzer module not available"
            )
        except Exception as e:
            logger.error(
                f"[{scan.scan_id}] Static analysis error: {e}",
                exc_info=True
            )
        
        # Phase 2-5: Info messages for advanced features
        await cls._update_scan_progress(
            db, scan, "running", 60, "Advanced Analysis"
        )
        
        logger.info(
            f"[{scan.scan_id}] Advanced features (Frida, MITM, Runtime) "
            "require emulator setup. Run scripts/setup_emulator.py for full testing."
        )
        
        return findings
    
    @classmethod
    async def stop_mobile_scan(
        cls,
        db: AsyncSession,
        scan_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Stop a running mobile scan.
        
        Returns:
            Dict with success status and message
        """
        scan = await crud.get_scan_by_id(db, scan_id, user_id)
        
        if not scan:
            raise ValueError("Mobile scan not found")
        
        if scan.status not in ["running", "queued"]:
            raise ValueError("Scan is not running")
        
        # Update scan status to stopped
        await crud.update_scan_status(db, scan, "stopped")
        
        # Refund scan credit
        try:
            from database.subscription import decrement_usage_counter
            await decrement_usage_counter(db, user_id, "scans")
            logger.info(f"[{scan_id}] Scan credit refunded (stopped by user)")
        except Exception as e:
            logger.warning(f"[{scan_id}] Failed to refund scan credit: {e}")
        
        return {
            "message": "Mobile scan stopped",
            "scan_id": scan_id,
            "success": True
        }
    
    @classmethod
    async def get_scan_status(
        cls,
        db: AsyncSession,
        scan_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Get detailed mobile scan status.
        
        Returns:
            Dict with scan status, progress, phase, findings count
        """
        scan = await crud.get_scan_by_id(db, scan_id, user_id)
        
        if not scan:
            raise ValueError("Mobile scan not found")
        
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "progress": scan.progress,
            "phase": scan.phase or "",
            "app_name": scan.config.get("app_name", ""),
            "platform": scan.config.get("platform", "android"),
            "findings_count": scan.findings_count,
            "started_at": scan.started_at.isoformat() if scan.started_at else "",
            "completed_at": (
                scan.completed_at.isoformat() if scan.completed_at else None
            )
        }
    
    @classmethod
    async def get_scan_logs(
        cls,
        db: AsyncSession,
        scan_id: str,
        user_id: str,
        since: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Get logs for a mobile scan.
        
        Note: In the new architecture, logs are tracked via database
        scan status updates, not in-memory dictionaries.
        
        Returns:
            Dict with scan_id, status, and log messages
        """
        scan = await crud.get_scan_by_id(db, scan_id, user_id)
        
        if not scan:
            raise ValueError("Mobile scan not found")
        
        # For now, return scan progress as logs
        # TODO: Implement proper log storage in database
        logs = [
            {
                "timestamp": scan.started_at.isoformat() if scan.started_at else "",
                "level": "info",
                "message": f"Scan started for {scan.config.get('app_name', 'app')}"
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "level": "info",
                "message": f"Current phase: {scan.phase or 'Unknown'}"
            }
        ]
        
        if scan.completed_at:
            logs.append({
                "timestamp": scan.completed_at.isoformat(),
                "level": "info",
                "message": f"Scan completed with {scan.findings_count} findings"
            })
        
        return {
            "scan_id": scan_id,
            "status": scan.status,
            "logs": logs
        }
    
    @classmethod
    async def list_mobile_scans(
        cls,
        db: AsyncSession,
        user_id: str,
        skip: int = 0,
        limit: int = 100
    ) -> Dict[str, Any]:
        """
        List all mobile scans for a user.
        
        Returns:
            Dict with scans list and total count
        """
        scans, total = await crud.get_user_scans(
            db=db,
            user_id=user_id,
            skip=skip,
            limit=limit,
            scan_type="mobile"
        )
        
        return {
            "scans": [
                {
                    "id": str(s.id),
                    "scan_id": s.scan_id,
                    "status": s.status,
                    "app_name": s.config.get("app_name", ""),
                    "platform": s.config.get("platform", "android"),
                    "progress": s.progress,
                    "findings_count": s.findings_count,
                    "started_at": (
                        s.started_at.isoformat() if s.started_at else None
                    ),
                    "completed_at": (
                        s.completed_at.isoformat() if s.completed_at else None
                    ),
                }
                for s in scans
            ],
            "total": total
        }
    
    # ========== Helper Methods ==========
    
    @classmethod
    async def _update_scan_progress(
        cls,
        db: AsyncSession,
        scan,
        status: str,
        progress: int,
        phase: str
    ):
        """Update scan progress in database"""
        await crud.update_scan_status(db, scan, status, progress, phase)
    
    @staticmethod
    def _calculate_severity_counts(findings: List[Dict]) -> Dict[str, int]:
        """Calculate finding counts by severity"""
        return {
            "critical": len([f for f in findings if f.get("severity") == "critical"]),
            "high": len([f for f in findings if f.get("severity") == "high"]),
            "medium": len([f for f in findings if f.get("severity") == "medium"]),
            "low": len([f for f in findings if f.get("severity") == "low"]),
            "info": len([f for f in findings if f.get("severity") == "info"]),
        }
