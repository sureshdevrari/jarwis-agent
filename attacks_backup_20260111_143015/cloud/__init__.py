"""
Jarwis AGI - Cloud Security Scanner
Central Cloud Attack Module - Aggregates ALL cloud security scanners

Multi-cloud security assessment for AWS, Azure, GCP, and Kubernetes

Comprehensive cloud security scanning including:
- CSPM (Cloud Security Posture Management)
- CIEM (Cloud Identity & Entitlement Management)
- Container Security (Trivy-based CVE scanning)
- Kubernetes Security (Pod Security, RBAC, NetworkPolicy)
- IaC Security (Terraform, CloudFormation, ARM templates)
- Runtime Threat Detection (CloudTrail, Activity Logs)
- Drift Detection (IaC vs Live configuration)
- Sensitive Data Discovery (PII, PHI, Credentials)
- Multi-framework Compliance (CIS, PCI-DSS, HIPAA, SOC2, NIST)
- SBOM Generation (CycloneDX/SPDX format)

Inspired by: Wiz, Palo Alto Prisma Cloud, Aqua Security, Sysdig
"""

from typing import List, Any, Optional
import logging

from .cloud_scanner import CloudSecurityScanner
from .aws_scanner import AWSSecurityScanner, AWSScanner
from .azure_scanner import AzureSecurityScanner, AzureScanner
from .gcp_scanner import GCPSecurityScanner, GCPScanner
from .iac_scanner import IaCScanner
from .container_scanner import ContainerScanner
from .runtime_scanner import RuntimeScanner
from .ciem_scanner import CIEMScanner
from .kubernetes_scanner import KubernetesSecurityScanner
from .drift_scanner import DriftDetectionScanner
from .data_security_scanner import SensitiveDataScanner
from .compliance_mapper import ComplianceMapper
from .sbom_generator import SBOMGenerator

# Aliases for backward compatibility
IaCSecurityScanner = IaCScanner
ContainerSecurityScanner = ContainerScanner
RuntimeThreatScanner = RuntimeScanner

logger = logging.getLogger(__name__)


class CloudAttacks:
    """
    Aggregates ALL cloud security scanners.
    
    Routes to appropriate cloud provider scanner based on configuration.
    Supports multi-cloud environments.
    
    Usage:
        cloud = CloudAttacks(config, context)
        findings = await cloud.run()
        
        # Or scan specific provider
        aws_findings = await cloud.run_aws()
        azure_findings = await cloud.run_azure()
    """
    
    PROVIDERS = ['aws', 'azure', 'gcp', 'kubernetes', 'all']
    
    def __init__(self, config: dict, context):
        """
        Initialize cloud attack module.
        
        Args:
            config: Scan configuration with cloud provider credentials
            context: CloudScanContext with resource inventory
        """
        self.config = config
        self.context = context
        self.provider = config.get('cloud_provider', 'aws').lower()
        
        # Initialize scanners based on provider
        self.scanners = self._init_scanners()
    
    def _init_scanners(self) -> List[Any]:
        """Initialize cloud scanners based on provider configuration"""
        scanners = []
        cloud_config = self.config.get('cloud', {})
        
        # Determine which providers to scan
        if self.provider == 'all':
            providers = ['aws', 'azure', 'gcp']
        else:
            providers = [self.provider]
        
        # Add provider-specific scanners
        for provider in providers:
            if provider == 'aws':
                scanners.append(AWSSecurityScanner(self.config, self.context))
            elif provider == 'azure':
                scanners.append(AzureSecurityScanner(self.config, self.context))
            elif provider == 'gcp':
                scanners.append(GCPSecurityScanner(self.config, self.context))
        
        # Kubernetes scanner (if enabled)
        if cloud_config.get('kubernetes', {}).get('enabled', False) or self.provider == 'kubernetes':
            scanners.append(KubernetesSecurityScanner(self.config, self.context))
        
        # Container Security (always scan if containers detected)
        if cloud_config.get('container_scanning', {}).get('enabled', True):
            scanners.append(ContainerScanner(self.config, self.context))
        
        # IaC Security (if terraform/cloudformation files present)
        if cloud_config.get('iac_scanning', {}).get('enabled', True):
            scanners.append(IaCScanner(self.config, self.context))
        
        # CIEM (Identity & Entitlement Management)
        if cloud_config.get('ciem', {}).get('enabled', True):
            scanners.append(CIEMScanner(self.config, self.context))
        
        # Runtime Threat Detection
        if cloud_config.get('runtime_scanning', {}).get('enabled', False):
            scanners.append(RuntimeScanner(self.config, self.context))
        
        # Drift Detection
        if cloud_config.get('drift_detection', {}).get('enabled', False):
            scanners.append(DriftDetectionScanner(self.config, self.context))
        
        # Sensitive Data Discovery
        if cloud_config.get('data_security', {}).get('enabled', True):
            scanners.append(SensitiveDataScanner(self.config, self.context))
        
        return scanners
    
    async def run(self) -> List[Any]:
        """
        Run all configured cloud security scanners.
        
        Returns:
            List of all cloud security findings
        """
        results = []
        
        logger.info(f"Starting cloud security scan (provider: {self.provider})...")
        logger.info(f"Loaded {len(self.scanners)} cloud scanners")
        
        for scanner in self.scanners:
            scanner_name = scanner.__class__.__name__
            logger.info(f"Running {scanner_name}...")
            
            try:
                if hasattr(scanner, 'scan'):
                    scanner_results = await scanner.scan()
                elif hasattr(scanner, 'run'):
                    scanner_results = await scanner.run()
                elif hasattr(scanner, 'analyze'):
                    scanner_results = await scanner.analyze()
                else:
                    logger.warning(f"{scanner_name} has no scan/run/analyze method")
                    continue
                
                if scanner_results:
                    results.extend(scanner_results)
                    logger.info(f"{scanner_name}: {len(scanner_results)} findings")
                    
            except Exception as e:
                logger.error(f"{scanner_name} failed: {e}")
                continue
        
        # Map findings to compliance frameworks
        if self.config.get('cloud', {}).get('compliance_mapping', True):
            mapper = ComplianceMapper(self.config)
            results = mapper.map_findings(results)
        
        logger.info(f"Cloud scan complete: {len(results)} total findings")
        return results
    
    async def run_aws(self) -> List[Any]:
        """Run only AWS security scanning"""
        scanner = AWSSecurityScanner(self.config, self.context)
        return await scanner.scan()
    
    async def run_azure(self) -> List[Any]:
        """Run only Azure security scanning"""
        scanner = AzureSecurityScanner(self.config, self.context)
        return await scanner.scan()
    
    async def run_gcp(self) -> List[Any]:
        """Run only GCP security scanning"""
        scanner = GCPSecurityScanner(self.config, self.context)
        return await scanner.scan()
    
    async def run_kubernetes(self) -> List[Any]:
        """Run only Kubernetes security scanning"""
        scanner = KubernetesSecurityScanner(self.config, self.context)
        return await scanner.scan()
    
    def get_scanner_count(self) -> int:
        """Get count of available scanners"""
        return len(self.scanners)
    
    def get_available_attacks(self) -> List[str]:
        """Get list of available attack categories"""
        return [
            "IAM Policy Analysis",
            "S3/Blob Public Access",
            "Security Group Analysis",
            "Encryption at Rest",
            "Encryption in Transit",
            "Network Exposure",
            "Privileged Container Detection",
            "Secrets in Environment Variables",
            "Kubernetes RBAC Audit",
            "Pod Security Policies",
            "IaC Misconfigurations",
            "Drift Detection",
            "Compliance Mapping (CIS, PCI, HIPAA, SOC2)",
            "Attack Path Analysis",
        ]
    
    def generate_sbom(self) -> dict:
        """Generate Software Bill of Materials"""
        generator = SBOMGenerator(self.config)
        return generator.generate()


__all__ = [
    # Main aggregator
    'CloudAttacks',
    
    # Core CSPM Scanners
    'CloudSecurityScanner',
    'AWSSecurityScanner',
    'AzureSecurityScanner',
    'GCPSecurityScanner',
    'AWSScanner',
    'AzureScanner',
    'GCPScanner',
    
    # Layer 2: IaC Security
    'IaCScanner',
    'IaCSecurityScanner',  # Alias
    
    # Layer 3: Container Security
    'ContainerScanner',
    'ContainerSecurityScanner',  # Alias
    
    # Layer 4: Runtime Security
    'RuntimeScanner',
    'RuntimeThreatScanner',  # Alias
    
    # Wiz-style Features
    'CIEMScanner',
    'SensitiveDataScanner',
    
    # Aqua-style Features
    'KubernetesSecurityScanner',
    'SBOMGenerator',
    
    # Sysdig-style Features
    'DriftDetectionScanner',
    
    # Palo Alto-style Features
    'ComplianceMapper',
]
