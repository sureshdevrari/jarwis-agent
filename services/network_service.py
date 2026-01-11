"""
Network Security Scan Service

Business logic layer for network security scanning.
Coordinates between API routes, core scanner runner, and database.

Responsibilities:
- Validate network scan requests
- Check subscription limits
- Create/manage scan records in database
- Start/stop/resume scans
- Generate reports
- Track scan progress
"""

import logging
import uuid
import ipaddress
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from dataclasses import dataclass

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from database.models import ScanHistory, Finding, User
from services.subscription_service import SubscriptionService, SubscriptionError
from shared.constants import ScanTypes
from core.tool_registry import ToolRegistry

logger = logging.getLogger(__name__)


# Private network definitions
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


@dataclass
class NetworkScanConfig:
    """Network scan configuration"""
    targets: str  # Comma-separated IPs/subnets/domains
    profile: str = "standard"  # quick, standard, comprehensive, stealth
    port_range: str = "common"
    service_detection: bool = True
    vuln_scan_enabled: bool = True
    cve_check: bool = True
    ssl_audit_enabled: bool = True
    safe_checks: bool = True
    use_agent: bool = False
    agent_id: Optional[str] = None
    credentials: Optional[Dict[str, Any]] = None
    max_concurrent_hosts: int = 10
    timeout_per_host: int = 300
    rate_limit: int = 100


class NetworkScanService:
    """
    Network security scanning service.
    
    Follows layered architecture:
    - API routes call this service
    - This service calls core/network_scan_runner.py
    - Database persistence via ScanHistory model
    """
    
    @staticmethod
    def is_private_target(target: str) -> bool:
        """Check if target contains private IP addresses"""
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                return any(network.overlaps(priv) for priv in PRIVATE_NETWORKS)
            else:
                ip = ipaddress.ip_address(target)
                return any(ip in priv for priv in PRIVATE_NETWORKS)
        except ValueError:
            return False
    
    @staticmethod
    def validate_targets(targets_str: str) -> tuple[bool, str, int]:
        """
        Validate network targets.
        
        Returns:
            (is_valid, error_message, host_count)
        """
        if not targets_str or not targets_str.strip():
            return False, "Targets cannot be empty", 0
        
        total_hosts = 0
        
        for target in targets_str.split(','):
            target = target.strip()
            if not target:
                continue
            
            try:
                if '/' in target:
                    # CIDR notation
                    network = ipaddress.ip_network(target, strict=False)
                    num_hosts = network.num_addresses
                    if num_hosts > 65536:
                        return False, f"Subnet {target} contains too many hosts (max 65536)", 0
                    total_hosts += num_hosts
                else:
                    # Single IP or hostname
                    try:
                        ipaddress.ip_address(target)
                        total_hosts += 1
                    except ValueError:
                        # Assume it's a hostname, will be resolved later
                        total_hosts += 1
            except ValueError:
                return False, f"Invalid target: {target}", 0
        
        if total_hosts == 0:
            return False, "No valid targets provided", 0
        
        if total_hosts > 65536:
            return False, "Too many targets (max 65536 hosts per scan)", 0
        
        return True, "", total_hosts
    
    @staticmethod
    async def start_scan(
        db: AsyncSession,
        user: User,
        config: NetworkScanConfig
    ) -> Dict[str, Any]:
        """
        Start a new network security scan.
        
        Steps:
        1. Validate targets
        2. Check subscription limits
        3. Check for private IPs and agent requirement
        4. Create scan record in database
        5. Start async scan runner
        
        Returns:
            Dict with scan_id, status, and other metadata
            
        Raises:
            SubscriptionError: If subscription limits exceeded
            ValueError: If validation fails
            HTTPException: If request is invalid
        """
        # 1. VALIDATE TARGETS
        is_valid, error_msg, host_count = NetworkScanService.validate_targets(
            config.targets
        )
        if not is_valid:
            raise ValueError(error_msg)
        
        # 2. CHECK SUBSCRIPTION LIMITS
        try:
            await SubscriptionService.enforce_scan_limit(
                db, user, ScanTypes.NETWORK
            )
        except SubscriptionError as e:
            raise ValueError(str(e))
        
        # 3. CHECK FOR PRIVATE IPs
        has_private = False
        for target in config.targets.split(','):
            target = target.strip()
            if NetworkScanService.is_private_target(target):
                has_private = True
                break
        
        if has_private and not config.use_agent:
            raise ValueError(
                "Private IP ranges require a Jarwis Agent. "
                "Deploy an agent in your network and set use_agent=true with agent_id."
            )
        
        # Agent validation is done by API route layer
        
        # 4. CREATE SCAN RECORD IN DATABASE
        scan_id = str(uuid.uuid4())
        
        # Store network-specific config
        network_config = {
            'targets': config.targets,
            'profile': config.profile,
            'port_range': config.port_range,
            'service_detection': config.service_detection,
            'vuln_scan_enabled': config.vuln_scan_enabled,
            'cve_check': config.cve_check,
            'ssl_audit_enabled': config.ssl_audit_enabled,
            'use_agent': config.use_agent,
            'agent_id': config.agent_id,
        }
        
        scan_record = ScanHistory(
            id=scan_id,
            scan_id=scan_id,  # Set both id and scan_id to same value
            user_id=user.id,
            scan_type=ScanTypes.NETWORK,
            target_url=config.targets,  # Store targets in target_url
            status="queued",
            findings_count=0,
            critical_count=0,
            high_count=0,
            medium_count=0,
            low_count=0,
            info_count=0,
            config=network_config,
            checkpoint_data={},  # Will be updated with phase progress
        )
        
        db.add(scan_record)
        await db.commit()
        await db.refresh(scan_record)
        
        logger.info(
            f"Network scan created: {scan_id} for user {user.email}, "
            f"targets: {config.targets}, profile: {config.profile}"
        )
        
        # 5. START ASYNC SCAN RUNNER (in background task from API route)
        # This is called from api/routes/network.py via background_tasks.add_task()
        
        return {
            'scan_id': scan_id,
            'status': 'queued',
            'message': f'Network scan started for {host_count} target(s)',
            'targets_count': host_count,
            'use_agent': config.use_agent,
        }
    
    @staticmethod
    async def get_scan_status(
        db: AsyncSession,
        user: User,
        scan_id: str
    ) -> Dict[str, Any]:
        """Get status and basic info for a network scan"""
        # Query database instead of in-memory storage
        query = select(ScanHistory).where(
            and_(
                ScanHistory.id == scan_id,
                ScanHistory.user_id == user.id,
                ScanHistory.scan_type == ScanTypes.NETWORK,
            )
        )
        result = await db.execute(query)
        scan = result.scalars().first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        # Query findings count by severity
        findings_query = select(Finding).where(Finding.scan_id == scan_id)
        findings_result = await db.execute(findings_query)
        findings = findings_result.scalars().all()
        
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        for finding in findings:
            severity = finding.severity.lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Get checkpoint data for progress info
        checkpoint = scan.checkpoint_data or {}
        
        return {
            'scan_id': scan_id,
            'status': scan.status,
            'progress': checkpoint.get('progress', 0),
            'current_phase': checkpoint.get('current_phase', ''),
            'phase_message': checkpoint.get('phase_message', ''),
            'findings_count': len(findings),
            'severity': severity_counts,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
        }
    
    @staticmethod
    async def get_findings(
        db: AsyncSession,
        user: User,
        scan_id: str,
        severity: Optional[str] = None,
        page: int = 1,
        per_page: int = 50,
    ) -> Dict[str, Any]:
        """Get paginated findings from a network scan"""
        # Verify scan belongs to user
        query = select(ScanHistory).where(
            and_(
                ScanHistory.id == scan_id,
                ScanHistory.user_id == user.id,
                ScanHistory.scan_type == ScanTypes.NETWORK,
            )
        )
        result = await db.execute(query)
        scan = result.scalars().first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        # Query findings
        findings_query = select(Finding).where(Finding.scan_id == scan_id)
        
        if severity:
            findings_query = findings_query.where(Finding.severity == severity)
        
        findings_result = await db.execute(findings_query)
        all_findings = findings_result.scalars().all()
        
        # Paginate
        total = len(all_findings)
        start = (page - 1) * per_page
        end = start + per_page
        paginated = all_findings[start:end]
        
        # Convert to dict
        findings_data = []
        for finding in paginated:
            findings_data.append({
                'id': finding.id,
                'severity': finding.severity,
                'title': finding.title,
                'description': finding.description,
                'category': finding.category,
                'ip_address': finding.url,  # Network scans store IP in url field
                'port': finding.evidence.get('port') if finding.evidence else None,
                'service': finding.evidence.get('service') if finding.evidence else None,
                'cve_id': finding.evidence.get('cve_id') if finding.evidence else None,
                'cvss_score': finding.evidence.get('cvss_score') if finding.evidence else None,
            })
        
        return {
            'scan_id': scan_id,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page,
            'findings': findings_data,
        }
    
    @staticmethod
    async def stop_scan(
        db: AsyncSession,
        user: User,
        scan_id: str
    ) -> Dict[str, Any]:
        """Stop a running network scan"""
        query = select(ScanHistory).where(
            and_(
                ScanHistory.id == scan_id,
                ScanHistory.user_id == user.id,
                ScanHistory.scan_type == ScanTypes.NETWORK,
            )
        )
        result = await db.execute(query)
        scan = result.scalars().first()
        
        if not scan:
            raise ValueError("Scan not found")
        
        if scan.status in ['completed', 'error', 'stopped']:
            raise ValueError("Scan is not running")
        
        scan.status = 'stopped'
        scan.updated_at = datetime.utcnow()
        
        db.add(scan)
        await db.commit()
        
        logger.info(f"Network scan stopped: {scan_id}")
        
        return {'message': 'Scan stopped', 'scan_id': scan_id}
    
    @staticmethod
    async def list_scans(
        db: AsyncSession,
        user: User,
        limit: int = 50,
    ) -> Dict[str, Any]:
        """List all network scans for the current user"""
        query = select(ScanHistory).where(
            and_(
                ScanHistory.user_id == user.id,
                ScanHistory.scan_type == ScanTypes.NETWORK,
            )
        ).order_by(ScanHistory.created_at.desc()).limit(limit)
        
        result = await db.execute(query)
        scans = result.scalars().all()
        
        scans_data = []
        for scan in scans:
            scans_data.append({
                'scan_id': scan.id,
                'targets': scan.target_url,
                'status': scan.status,
                'findings_count': scan.findings_count,
                'severity_summary': {
                    'critical': scan.critical_count,
                    'high': scan.high_count,
                    'medium': scan.medium_count,
                    'low': scan.low_count,
                    'info': scan.info_count,
                },
                'created_at': scan.created_at.isoformat() if scan.created_at else None,
                'updated_at': scan.updated_at.isoformat() if scan.updated_at else None,
            })
        
        return {
            'scans': scans_data,
            'total': len(scans_data),
        }
    
    @staticmethod
    async def get_dashboard_summary(
        db: AsyncSession,
        user: User,
    ) -> Dict[str, Any]:
        """
        Get aggregated network security dashboard summary.
        Returns CVE stats, open ports, vulnerable services from completed scans.
        """
        # Query all completed network scans for user
        query = select(ScanHistory).where(
            and_(
                ScanHistory.user_id == user.id,
                ScanHistory.scan_type == ScanTypes.NETWORK,
                ScanHistory.status == 'completed',
            )
        )
        result = await db.execute(query)
        scans = result.scalars().all()
        
        # Aggregate findings
        cve_stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        vulnerable_services = set()
        all_findings = []
        
        for scan in scans:
            cve_stats['critical'] += scan.critical_count
            cve_stats['high'] += scan.high_count
            cve_stats['medium'] += scan.medium_count
            cve_stats['low'] += scan.low_count
            cve_stats['info'] += scan.info_count
            
            # Query findings for this scan
            findings_query = select(Finding).where(Finding.scan_id == scan.id)
            findings_result = await db.execute(findings_query)
            findings = findings_result.scalars().all()
            
            for finding in findings:
                all_findings.append(finding)
                if finding.evidence and finding.evidence.get('service'):
                    vulnerable_services.add(finding.evidence['service'])
        
        return {
            'success': True,
            'data': {
                'cve_stats': cve_stats,
                'total_cves': sum(cve_stats.values()),
                'vulnerable_services_count': len(vulnerable_services),
                'vulnerable_services': list(vulnerable_services),
                'scans_analyzed': len(scans),
                'total_findings': len(all_findings),
            }
        }
    
    @staticmethod
    async def check_preflight_requirements(
        config: NetworkScanConfig,
    ) -> tuple[bool, str, Dict[str, Any]]:
        """
        Check if required tools are available before starting scan.
        
        Logic: For each phase, at least ONE tool must be available.
        Nmap is mandatory as the core scanning tool.
        
        Returns:
            (all_available, error_msg, tool_status)
        """
        registry = ToolRegistry()  # Uses cached checks via singleton
        
        # Determine which tools are needed based on config and profile
        # Key: phase -> list of alternative tools (at least one required)
        required_phases = {
            'port_scan': ['nmap', 'masscan', 'rustscan'],  # At least one
        }
        
        # Discovery is optional for quick profile or when targeting hostnames
        if config.profile != 'quick':
            required_phases['discovery'] = ['nmap', 'netdiscover', 'arp-scan']  # nmap can do discovery
        
        if config.service_detection:
            required_phases['service_enum'] = ['nmap']  # nmap is required for service detection
        
        if config.vuln_scan_enabled:
            required_phases['vuln_scan'] = ['nuclei', 'nmap']  # At least one
        
        if config.ssl_audit_enabled:
            required_phases['ssl_audit'] = ['sslyze', 'sslscan', 'nmap']  # At least one
        
        # Check availability - at least ONE tool per phase
        tool_status = {}
        missing_phases = []
        
        for phase, tools in required_phases.items():
            phase_status = {}
            phase_has_tool = False
            
            for tool in tools:
                available = registry.is_tool_available(tool)  # Cached
                phase_status[tool] = available
                tool_status[tool] = available
                
                if available:
                    phase_has_tool = True
            
            tool_status[phase] = phase_status
            
            if not phase_has_tool:
                missing_phases.append(phase)
        
        # Nmap is mandatory
        if not registry.is_tool_available('nmap'):
            error_msg = "Nmap is required for network scanning. Install it first."
            return False, error_msg, tool_status
        
        if missing_phases:
            error_msg = (
                f"No tools available for phases: {', '.join(missing_phases)}. "
                f"Install tools using: python scripts/requiredtools.py --install"
            )
            return False, error_msg, tool_status
        
        return True, "", tool_status
    
    @staticmethod
    async def update_scan_progress(
        db: AsyncSession,
        scan_id: str,
        phase: str,
        progress: float,
        message: str,
    ) -> None:
        """Update scan progress in database (called by scan runner)"""
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalars().first()
        
        if not scan:
            logger.warning(f"Scan {scan_id} not found for progress update")
            return
        
        # Update checkpoint data
        checkpoint = scan.checkpoint_data or {}
        checkpoint['current_phase'] = phase
        checkpoint['progress'] = int(progress * 100)
        checkpoint['phase_message'] = message
        checkpoint['last_update'] = datetime.utcnow().isoformat()
        
        scan.checkpoint_data = checkpoint
        scan.updated_at = datetime.utcnow()
        
        db.add(scan)
        await db.commit()
    
    @staticmethod
    async def complete_scan(
        db: AsyncSession,
        scan_id: str,
        findings: List[Dict[str, Any]],
    ) -> None:
        """Mark scan as completed and save findings (called by scan runner)"""
        query = select(ScanHistory).where(ScanHistory.id == scan_id)
        result = await db.execute(query)
        scan = result.scalars().first()
        
        if not scan:
            logger.warning(f"Scan {scan_id} not found for completion")
            return
        
        # Update scan record
        scan.status = 'completed'
        scan.findings_count = len(findings)
        scan.updated_at = datetime.utcnow()
        
        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }
        
        # Save findings to database
        for finding_data in findings:
            severity = finding_data.get('severity', 'info').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            
            finding = Finding(
                id=str(uuid.uuid4()),
                scan_id=scan_id,
                finding_id=finding_data.get('id', str(uuid.uuid4())),
                category=finding_data.get('category', 'Network'),
                severity=severity,
                title=finding_data.get('title', ''),
                description=finding_data.get('description', ''),
                url=finding_data.get('ip_address', ''),  # Store IP in url
                evidence=finding_data.get('evidence', {}),
                parameter=finding_data.get('port', ''),
            )
            db.add(finding)
        
        # Update counts
        scan.critical_count = severity_counts['critical']
        scan.high_count = severity_counts['high']
        scan.medium_count = severity_counts['medium']
        scan.low_count = severity_counts['low']
        scan.info_count = severity_counts['info']
        
        # Update checkpoint
        checkpoint = scan.checkpoint_data or {}
        checkpoint['completed_at'] = datetime.utcnow().isoformat()
        checkpoint['completed_phases'] = checkpoint.get('completed_phases', []) + ['all']
        scan.checkpoint_data = checkpoint
        
        db.add(scan)
        await db.commit()
        
        logger.info(
            f"Network scan completed: {scan_id}, "
            f"findings: {len(findings)}, "
            f"severity: {severity_counts}"
        )
