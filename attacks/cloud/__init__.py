"""
Jarwis AGI - Cloud Security Scanner
Central Cloud Attack Module - Aggregates ALL cloud security scanners

Multi-cloud security assessment for AWS, Azure, GCP, and Kubernetes

NEW STRUCTURE (Recommended):
    from attacks.cloud.aws import AWSSecurityScanner
    from attacks.cloud.azure import AzureSecurityScanner
    from attacks.cloud.gcp import GCPSecurityScanner
    from attacks.cloud.kubernetes import KubernetesSecurityScanner
    from attacks.cloud.cnapp import CIEMScanner, RuntimeScanner
    
LEGACY IMPORT (Deprecated but still works):
    from attacks.cloud import AWSSecurityScanner, AzureSecurityScanner

Provider-based organization:
- aws/        - AWS-specific scanners
- azure/      - Azure-specific scanners
- gcp/        - GCP-specific scanners
- kubernetes/ - Kubernetes and container security
- cnapp/      - CNAPP features (CIEM, Runtime, SBOM, Drift, Data Security)
- shared/     - Base classes and shared utilities

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

logger = logging.getLogger(__name__)

# =============================================================================
# BACKWARD-COMPATIBLE IMPORTS FROM NEW PROVIDER LOCATIONS
# =============================================================================

# Shared/Base
from .shared.base import CloudScanner

# Alias for backward compat
CloudScannerBase = CloudScanner
from .shared.cloud_scanner import CloudSecurityScanner, CloudFinding, CloudScanResult
from .shared.iac_scanner import IaCScanner
from .shared.compliance_mapper import ComplianceMapper
from .shared.config import DEFAULT_CLOUD_CONFIG
from .shared.schemas import CloudResource, CloudScanContext
from .shared.exceptions import CloudScanError

# Aliases
CloudConfig = DEFAULT_CLOUD_CONFIG
CloudScannerError = CloudScanError

# AWS
from .aws.aws_scanner import AWSSecurityScanner, AWSScanner

# Azure
from .azure.azure_scanner import AzureSecurityScanner

# Alias for backward compat
AzureScanner = AzureSecurityScanner

# GCP
from .gcp.gcp_scanner import GCPSecurityScanner, GCPScanner

# Kubernetes
from .kubernetes.kubernetes_scanner import KubernetesSecurityScanner
from .kubernetes.container_scanner import ContainerScanner

# CNAPP Features
from .cnapp.ciem_scanner import CIEMScanner
from .cnapp.runtime_scanner import RuntimeScanner
from .cnapp.drift_scanner import DriftDetectionScanner
from .cnapp.data_security_scanner import SensitiveDataScanner
from .cnapp.sbom_generator import SBOMGenerator


# Aliases for backward compatibility
IaCSecurityScanner = IaCScanner
ContainerSecurityScanner = ContainerScanner
RuntimeThreatScanner = RuntimeScanner


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
        if cloud_config.get('kubernetes', {}).get('enabled', False):
            scanners.append(KubernetesSecurityScanner(self.config, self.context))
        
        # Container scanner (if enabled)
        if cloud_config.get('containers', {}).get('enabled', True):
            scanners.append(ContainerScanner(self.config, self.context))
        
        # IaC scanner (if enabled)
        if cloud_config.get('iac', {}).get('enabled', True):
            scanners.append(IaCScanner(self.config, self.context))
        
        # CNAPP features
        if cloud_config.get('ciem', {}).get('enabled', True):
            scanners.append(CIEMScanner(self.config, self.context))
        
        if cloud_config.get('runtime', {}).get('enabled', True):
            scanners.append(RuntimeScanner(self.config, self.context))
        
        if cloud_config.get('drift', {}).get('enabled', True):
            scanners.append(DriftDetectionScanner(self.config, self.context))
        
        if cloud_config.get('data_security', {}).get('enabled', True):
            scanners.append(SensitiveDataScanner(self.config, self.context))
        
        return scanners
    
    async def run(self) -> List[Any]:
        """Run all configured cloud scanners."""
        findings = []
        for scanner in self.scanners:
            try:
                result = await scanner.run()
                if result:
                    findings.extend(result if isinstance(result, list) else [result])
            except Exception as e:
                logger.error(f"Scanner {scanner.__class__.__name__} failed: {e}")
        return findings
    
    async def run_aws(self) -> List[Any]:
        """Run AWS-specific scanners only."""
        scanner = AWSSecurityScanner(self.config, self.context)
        return await scanner.run()
    
    async def run_azure(self) -> List[Any]:
        """Run Azure-specific scanners only."""
        scanner = AzureSecurityScanner(self.config, self.context)
        return await scanner.run()
    
    async def run_gcp(self) -> List[Any]:
        """Run GCP-specific scanners only."""
        scanner = GCPSecurityScanner(self.config, self.context)
        return await scanner.run()
    
    async def run_kubernetes(self) -> List[Any]:
        """Run Kubernetes-specific scanners only."""
        scanner = KubernetesSecurityScanner(self.config, self.context)
        return await scanner.run()


# =============================================================================
# EXPORTS
# =============================================================================

__all__ = [
    # Main Classes
    'CloudAttacks',
    'CloudSecurityScanner',
    
    # Shared
    'CloudScannerBase',
    'IaCScanner',
    'IaCSecurityScanner',
    'ComplianceMapper',
    'CloudConfig',
    'CloudFinding',
    'CloudResource',
    'CloudScannerError',
    
    # AWS
    'AWSSecurityScanner',
    'AWSScanner',
    
    # Azure
    'AzureSecurityScanner',
    'AzureScanner',
    
    # GCP
    'GCPSecurityScanner',
    'GCPScanner',
    
    # Kubernetes
    'KubernetesSecurityScanner',
    'ContainerScanner',
    'ContainerSecurityScanner',
    
    # CNAPP
    'CIEMScanner',
    'RuntimeScanner',
    'RuntimeThreatScanner',
    'DriftDetectionScanner',
    'SensitiveDataScanner',
    'SBOMGenerator',
]
