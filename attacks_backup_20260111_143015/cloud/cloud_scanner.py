"""
Jarwis AGI - Cloud Security Scanner
Main orchestrator for multi-cloud security assessments

Supports:
- AWS (S3, IAM, EC2, Lambda, RDS, etc.)
- Azure (Storage, AD, VMs, Functions, etc.)
- GCP (GCS, IAM, Compute, Cloud Functions, etc.)
"""

import json
import asyncio
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any

logger = logging.getLogger(__name__)


@dataclass
class CloudFinding:
    """Cloud security finding"""
    id: str
    provider: str  # aws, azure, gcp
    service: str  # s3, iam, ec2, etc.
    resource_id: str
    resource_arn: str = ""
    region: str = ""
    category: str = ""  # misconfiguration, vulnerability, compliance
    severity: str = "medium"  # critical, high, medium, low, info
    title: str = ""
    description: str = ""
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    compliance: List[str] = field(default_factory=list)  # CIS, SOC2, HIPAA, etc.
    remediation_steps: List[str] = field(default_factory=list)


@dataclass
class CloudScanResult:
    """Complete cloud security scan result"""
    scan_id: str
    provider: str
    account_id: str = ""
    scan_start: str = ""
    scan_end: str = ""
    status: str = "running"
    
    # Scanned resources
    resources_scanned: int = 0
    regions_scanned: List[str] = field(default_factory=list)
    services_scanned: List[str] = field(default_factory=list)
    
    # Findings
    findings: List[Dict] = field(default_factory=list)
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    # Compliance summary
    compliance_summary: Dict = field(default_factory=dict)


class CloudSecurityScanner:
    """
    Main Cloud Security Scanner
    Orchestrates security assessments across cloud providers
    """
    
    # Common cloud misconfigurations to check
    COMMON_CHECKS = {
        "public_access": "Resources with public access",
        "encryption": "Encryption at rest and in transit",
        "logging": "Audit logging enabled",
        "mfa": "Multi-factor authentication",
        "iam_policies": "Overly permissive IAM policies",
        "network_security": "Network security groups/firewalls",
        "secrets": "Exposed secrets and credentials",
        "compliance": "Compliance framework violations"
    }
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self._verbose_callback: Optional[Callable] = None
        self._progress_callback: Optional[Callable] = None
        
        # Initialize provider-specific scanners
        self.aws_scanner = None
        self.azure_scanner = None
        self.gcp_scanner = None
    
    def set_verbose_callback(self, callback: Callable):
        """Set callback for verbose logging"""
        self._verbose_callback = callback
    
    def set_progress_callback(self, callback: Callable):
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    def _log(self, log_type: str, message: str, details: str = None):
        """Log message via callback"""
        if self._verbose_callback:
            try:
                self._verbose_callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    async def scan_aws(
        self,
        access_key: str = None,
        secret_key: str = None,
        session_token: str = None,
        regions: List[str] = None,
        services: List[str] = None
    ) -> CloudScanResult:
        """
        Scan AWS account for security issues
        
        Args:
            access_key: AWS Access Key ID (optional, uses default credentials if not provided)
            secret_key: AWS Secret Access Key
            session_token: AWS Session Token (for temporary credentials)
            regions: List of regions to scan (default: all)
            services: List of services to scan (default: all supported)
        """
        from .aws_scanner import AWSSecurityScanner
        
        self.aws_scanner = AWSSecurityScanner(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token
        )
        
        if self._verbose_callback:
            self.aws_scanner.set_verbose_callback(self._verbose_callback)
        
        return await self.aws_scanner.scan(regions=regions, services=services)
    
    async def scan_azure(
        self,
        subscription_id: str = None,
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None
    ) -> CloudScanResult:
        """
        Scan Azure subscription for security issues
        """
        from .azure_scanner import AzureSecurityScanner
        
        self.azure_scanner = AzureSecurityScanner(
            subscription_id=subscription_id,
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret
        )
        
        if self._verbose_callback:
            self.azure_scanner.set_verbose_callback(self._verbose_callback)
        
        return await self.azure_scanner.scan()
    
    async def scan_gcp(
        self,
        project_id: str = None,
        credentials_file: str = None
    ) -> CloudScanResult:
        """
        Scan GCP project for security issues
        """
        from .gcp_scanner import GCPSecurityScanner
        
        self.gcp_scanner = GCPSecurityScanner(
            project_id=project_id,
            credentials_file=credentials_file
        )
        
        if self._verbose_callback:
            self.gcp_scanner.set_verbose_callback(self._verbose_callback)
        
        return await self.gcp_scanner.scan()
    
    async def scan_multi_cloud(
        self,
        aws_config: Dict = None,
        azure_config: Dict = None,
        gcp_config: Dict = None
    ) -> Dict[str, CloudScanResult]:
        """
        Scan multiple cloud providers simultaneously
        """
        results = {}
        tasks = []
        
        if aws_config:
            tasks.append(("aws", self.scan_aws(**aws_config)))
        if azure_config:
            tasks.append(("azure", self.scan_azure(**azure_config)))
        if gcp_config:
            tasks.append(("gcp", self.scan_gcp(**gcp_config)))
        
        for provider, task in tasks:
            try:
                results[provider] = await task
            except Exception as e:
                logger.error(f"Failed to scan {provider}: {e}")
                results[provider] = CloudScanResult(
                    scan_id=f"FAILED-{provider}",
                    provider=provider,
                    status="failed"
                )
        
        return results
    
    def export_report(self, result: CloudScanResult, format: str = "json") -> str:
        """Export scan result to various formats"""
        if format == "json":
            return json.dumps(asdict(result), indent=2, default=str)
        elif format == "html":
            return self._generate_html_report(result)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_html_report(self, result: CloudScanResult) -> str:
        """Generate HTML report for cloud scan"""
        provider_colors = {
            "aws": "#FF9900",
            "azure": "#0078D4",
            "gcp": "#4285F4"
        }
        
        color = provider_colors.get(result.provider, "#667eea")
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Jarwis Cloud Security Report - {result.provider.upper()}</title>
    <style>
        body {{ font-family: 'Segoe UI', sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
        .header {{ background: linear-gradient(135deg, {color} 0%, #764ba2 100%); padding: 30px; border-radius: 10px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; }}
        .finding {{ background: #16213e; padding: 15px; margin: 10px 0; border-radius: 8px; }}
        .severity-critical {{ border-left: 4px solid #ff4757; }}
        .severity-high {{ border-left: 4px solid #ffa502; }}
        .severity-medium {{ border-left: 4px solid #ffd32a; }}
        .severity-low {{ border-left: 4px solid #3498db; }}
        h2 {{ color: {color}; }}
        .badge {{ padding: 3px 10px; border-radius: 4px; font-size: 0.8em; margin-right: 5px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>[!]   Jarwis Cloud Security Report</h1>
        <p><strong>Provider:</strong> {result.provider.upper()} | <strong>Account:</strong> {result.account_id}</p>
        <p><strong>Scan ID:</strong> {result.scan_id} | <strong>Status:</strong> {result.status}</p>
        <p><strong>Resources Scanned:</strong> {result.resources_scanned} | <strong>Regions:</strong> {', '.join(result.regions_scanned)}</p>
    </div>
    
    <div class="summary">
        <div class="summary-card"><h2 style="color:#ff4757">{result.critical_count}</h2><p>Critical</p></div>
        <div class="summary-card"><h2 style="color:#ffa502">{result.high_count}</h2><p>High</p></div>
        <div class="summary-card"><h2 style="color:#ffd32a">{result.medium_count}</h2><p>Medium</p></div>
        <div class="summary-card"><h2 style="color:#3498db">{result.low_count}</h2><p>Low</p></div>
    </div>
    
    <h2>[OK]  Findings ({result.total_findings})</h2>
"""
        
        for finding in sorted(result.findings, key=lambda x: ['critical', 'high', 'medium', 'low', 'info'].index(x.get('severity', 'info').lower())):
            severity = finding.get('severity', 'info').lower()
            html += f"""
    <div class="finding severity-{severity}">
        <strong>[{finding.get('service', 'N/A').upper()}]</strong> {finding.get('title', 'Unknown')}
        <p>{finding.get('description', '')}</p>
        <p><strong>Resource:</strong> {finding.get('resource_id', 'N/A')}</p>
        <p><strong>Region:</strong> {finding.get('region', 'N/A')}</p>
        {f"<p><strong>Recommendation:</strong> {finding.get('recommendation', '')}</p>" if finding.get('recommendation') else ""}
    </div>
"""
        
        html += """
</body>
</html>
"""
        return html
