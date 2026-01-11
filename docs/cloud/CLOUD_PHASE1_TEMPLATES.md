# Cloud Architecture Phase 1 - Code Templates (Ready to Copy)

This file contains exact code templates for Phase 1 (Foundation). Copy-paste ready!

---

## File 1: `attacks/cloud/exceptions.py`

```python
"""
Jarwis AGI - Cloud Security Exceptions
Typed error handling for cloud scanning operations
"""


class CloudScanError(Exception):
    """Base exception for cloud scanning errors"""
    pass


class ProviderError(CloudScanError):
    """Error communicating with cloud provider API"""
    
    def __init__(self, provider: str, message: str, status_code: int = None):
        self.provider = provider
        self.status_code = status_code
        super().__init__(f"{provider}: {message}")


class CredentialError(CloudScanError):
    """Invalid or expired cloud credentials"""
    
    def __init__(self, provider: str, reason: str = "Invalid credentials"):
        self.provider = provider
        super().__init__(f"Credential error [{provider}]: {reason}")


class ResourceDiscoveryError(CloudScanError):
    """Failed to discover resources"""
    
    def __init__(self, provider: str, resource_type: str = "", message: str = ""):
        self.provider = provider
        self.resource_type = resource_type
        msg = f"Discovery error [{provider}]"
        if resource_type:
            msg += f" ({resource_type})"
        if message:
            msg += f": {message}"
        super().__init__(msg)


class RateLimitError(CloudScanError):
    """Cloud provider API rate limit exceeded"""
    
    def __init__(self, provider: str, retry_after: int = None):
        self.provider = provider
        self.retry_after = retry_after
        msg = f"Rate limited [{provider}]"
        if retry_after:
            msg += f" (retry after {retry_after}s)"
        super().__init__(msg)


class ConfigurationError(CloudScanError):
    """Invalid scan configuration"""
    
    def __init__(self, field: str, reason: str):
        super().__init__(f"Config error [{field}]: {reason}")


class IaCParseError(CloudScanError):
    """Failed to parse Infrastructure-as-Code (Terraform, CloudFormation, ARM)"""
    
    def __init__(self, file_path: str, line_number: int = None, message: str = ""):
        self.file_path = file_path
        self.line_number = line_number
        msg = f"IaC parse error [{file_path}]"
        if line_number:
            msg += f" line {line_number}"
        if message:
            msg += f": {message}"
        super().__init__(msg)


class ContainerScanError(CloudScanError):
    """Error scanning container images or registries"""
    
    def __init__(self, registry: str, image: str, message: str = ""):
        self.registry = registry
        self.image = image
        msg = f"Container scan error [{registry}/{image}]"
        if message:
            msg += f": {message}"
        super().__init__(msg)


class TimeoutError(CloudScanError):
    """Scan or phase execution timeout"""
    
    def __init__(self, phase: str, timeout_seconds: int):
        super().__init__(f"Timeout [{phase}] after {timeout_seconds}s")
```

---

## File 2: `attacks/cloud/schemas.py`

```python
"""
Jarwis AGI - Cloud Scanning Schemas
Unified data structures for all cloud scanners
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
from enum import Enum


# ========== Enums ==========

class CloudProvider(str, Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class SeverityLevel(str, Enum):
    """CVSS-based severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Finding categories"""
    CSPM = "cspm"  # Cloud Security Posture Management
    IAC = "iac"  # Infrastructure-as-Code
    CONTAINER = "container"  # Container & image security
    RUNTIME = "runtime"  # Runtime threat detection
    CIEM = "ciem"  # Cloud Identity & Entitlement Management
    SUPPLY_CHAIN = "supply_chain"  # Supply chain security
    COMPLIANCE = "compliance"  # Compliance violations


class DetectionLayer(str, Enum):
    """Which layer detected the finding"""
    CSPM = "cspm"
    IAC = "iac"
    CONTAINER = "container"
    RUNTIME = "runtime"
    AI = "ai"  # AI-powered analysis


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    CIS = "cis"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    NIST = "nist"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    FEDRAMP = "fedramp"


# ========== Data Classes ==========

@dataclass
class CloudResource:
    """Represents a cloud resource"""
    resource_id: str
    resource_type: str  # ec2, s3, lambda, storage_account, gcs_bucket, etc.
    provider: CloudProvider
    region: str
    name: str
    arn_or_id: str
    
    # Optional metadata
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    relationships: List[str] = field(default_factory=list)  # IDs of related resources
    
    created_at: Optional[datetime] = None
    last_modified: Optional[datetime] = None
    
    def __hash__(self):
        return hash(self.arn_or_id)


@dataclass
class CloudFinding:
    """
    Unified cloud security finding
    Used by ALL cloud scanners (AWS, Azure, GCP)
    """
    # Identification
    id: str
    provider: CloudProvider
    service: str  # s3, ec2, lambda, storage, gcs_bucket, etc.
    
    # Resource affected
    resource_id: str
    resource_arn: str
    region: str
    resource: Optional[CloudResource] = None
    
    # Severity & category
    severity: SeverityLevel
    category: FindingCategory
    title: str
    description: str
    
    # Evidence & remediation
    evidence: Dict[str, Any] = field(default_factory=dict)
    remediation: str = ""
    remediation_cli: str = ""
    remediation_steps: List[str] = field(default_factory=list)
    
    # Compliance & scoring
    compliance_frameworks: List[ComplianceFramework] = field(default_factory=list)
    cis_benchmark: str = ""  # e.g., "CIS AWS 1.2.3"
    cvss_score: float = 0.0  # 0-10
    blast_radius_score: int = 0  # 0-100 (impact if exploited)
    exploitability_score: int = 0  # 0-100 (ease of exploitation)
    
    # Attack paths
    attack_paths: List[List[str]] = field(default_factory=list)  # [[r1, r2, ...], ...]
    
    # Detection metadata
    detection_layer: DetectionLayer = DetectionLayer.CSPM
    detected_at: datetime = field(default_factory=datetime.utcnow)
    
    # Optional: CWE mapping
    cwe_id: str = ""
    cwe_title: str = ""
    
    # Optional: external references
    references: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "id": self.id,
            "provider": self.provider.value,
            "service": self.service,
            "resource_id": self.resource_id,
            "resource_arn": self.resource_arn,
            "region": self.region,
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "remediation_cli": self.remediation_cli,
            "compliance_frameworks": [f.value for f in self.compliance_frameworks],
            "cis_benchmark": self.cis_benchmark,
            "cvss_score": self.cvss_score,
            "blast_radius_score": self.blast_radius_score,
            "exploitability_score": self.exploitability_score,
            "attack_paths": self.attack_paths,
            "detection_layer": self.detection_layer.value,
            "detected_at": self.detected_at.isoformat(),
            "cwe_id": self.cwe_id,
            "cwe_title": self.cwe_title,
            "references": self.references,
        }


@dataclass
class CloudScanContext:
    """
    Maintains state across all cloud scan phases
    Shared by all scanners and phases
    """
    scan_id: str
    providers: List[CloudProvider]
    credentials: Dict[str, Any]
    config: Dict[str, Any]
    
    # Discovery results
    resources: List[CloudResource] = field(default_factory=list)
    resource_graph: Dict[str, List[str]] = field(default_factory=dict)  # Adjacency list
    
    # Scan results
    findings: List[CloudFinding] = field(default_factory=list)
    
    # Progress tracking
    phase: str = "initializing"
    progress_percent: int = 0
    current_task: str = ""
    
    # Statistics
    total_resources_scanned: int = 0
    total_checks_performed: int = 0
    
    # Timestamps
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Errors encountered
    errors: Dict[str, List[str]] = field(default_factory=dict)  # {scanner_name: [errors]}
    
    def add_finding(self, finding: CloudFinding):
        """Add finding to results"""
        self.findings.append(finding)
    
    def add_resource(self, resource: CloudResource):
        """Add discovered resource"""
        self.resources.append(resource)
        self.total_resources_scanned += 1
    
    def add_error(self, component: str, error: str):
        """Track error"""
        if component not in self.errors:
            self.errors[component] = []
        self.errors[component].append(error)
    
    def add_relationship(self, source_id: str, target_id: str):
        """Add edge to resource graph"""
        if source_id not in self.resource_graph:
            self.resource_graph[source_id] = []
        if target_id not in self.resource_graph[source_id]:
            self.resource_graph[source_id].append(target_id)
    
    def get_findings_by_severity(self, severity: SeverityLevel) -> List[CloudFinding]:
        """Filter findings by severity"""
        return [f for f in self.findings if f.severity == severity]
    
    def get_findings_by_provider(self, provider: CloudProvider) -> List[CloudFinding]:
        """Filter findings by provider"""
        return [f for f in self.findings if f.provider == provider]
    
    def get_findings_by_category(self, category: FindingCategory) -> List[CloudFinding]:
        """Filter findings by category"""
        return [f for f in self.findings if f.category == category]


@dataclass
class ScannerMetadata:
    """Metadata for a registered cloud scanner"""
    name: str  # Unique identifier: aws_cspm, azure_iac, gcp_iam, etc.
    scanner_class: type  # The scanner class
    provider: CloudProvider  # Which cloud provider(s): AWS, Azure, GCP
    layer: DetectionLayer  # Which layer: CSPM, IaC, Container, Runtime, AI
    timeout: int = 300  # Default timeout in seconds
    enabled: bool = True
    description: str = ""
    owasp_mapping: List[str] = field(default_factory=list)  # [A01, A02, ...]
    
    def __hash__(self):
        return hash(self.name)
    
    def __eq__(self, other):
        if isinstance(other, ScannerMetadata):
            return self.name == other.name
        return False


# ========== Type Aliases ==========

FindingDict = Dict[str, Any]  # Serialized finding
ResourceDict = Dict[str, Any]  # Serialized resource
ScanStatistics = Dict[str, int]  # {severity: count, ...}
```

---

## File 3: `attacks/cloud/base.py`

```python
"""
Jarwis AGI - Cloud Scanner Base Class
Abstract interface for all cloud security scanners
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging

from .schemas import CloudFinding, ScannerMetadata, CloudScanContext, CloudProvider
from .exceptions import CloudScanError, ConfigurationError

logger = logging.getLogger(__name__)


class CloudScanner(ABC):
    """
    Abstract base class for all cloud security scanners.
    
    All scanners (AWS, Azure, GCP, Container, IaC, Runtime) must inherit from this.
    Enforces consistent interface and behavior.
    
    Usage:
    ------
    class AWSCSPMScanner(CloudScanner):
        def get_metadata(self):
            return ScannerMetadata(
                name="aws_cspm",
                scanner_class=AWSCSPMScanner,
                provider=CloudProvider.AWS,
                layer=DetectionLayer.CSPM,
            )
        
        async def scan(self):
            # Implementation
            return findings
    """
    
    def __init__(self, config: Dict[str, Any], context: CloudScanContext):
        """
        Initialize scanner.
        
        Args:
            config: Scan configuration (timeouts, options, etc.)
            context: Shared CloudScanContext with credentials, resources, etc.
        """
        self.config = config
        self.context = context
        self.logger = logging.getLogger(self.__class__.__name__)
    
    @abstractmethod
    async def scan(self) -> List[CloudFinding]:
        """
        Execute security scan.
        
        Must return list of CloudFinding objects with all required fields.
        Each finding must have unified schema (see schemas.py).
        
        Returns:
            List[CloudFinding]: Security findings discovered
        
        Raises:
            CloudScanError: If scan fails
        """
        pass
    
    @abstractmethod
    def validate_config(self) -> bool:
        """
        Validate scanner configuration before running.
        
        Check for required fields, valid values, etc.
        
        Returns:
            bool: True if config is valid
        
        Raises:
            ConfigurationError: If config is invalid
        """
        pass
    
    @abstractmethod
    def get_metadata(self) -> ScannerMetadata:
        """
        Get scanner metadata.
        
        Used by registry for discovery and management.
        
        Returns:
            ScannerMetadata: Scanner metadata including name, provider, layer
        """
        pass
    
    async def setup(self):
        """
        Optional setup before scan (connect to APIs, etc.)
        Override if needed.
        """
        pass
    
    async def teardown(self):
        """
        Optional cleanup after scan (close connections, etc.)
        Override if needed.
        """
        pass
    
    def _create_finding(
        self,
        title: str,
        description: str,
        resource_id: str,
        severity: str,
        **kwargs
    ) -> CloudFinding:
        """
        Helper to create a CloudFinding with common defaults.
        
        Args:
            title: Finding title
            description: Detailed description
            resource_id: Affected resource ID
            severity: critical, high, medium, low, info
            **kwargs: Additional fields to set
        
        Returns:
            CloudFinding: Properly formatted finding
        """
        # Import here to avoid circular imports
        from .schemas import CloudFinding, SeverityLevel, FindingCategory, DetectionLayer
        from datetime import datetime
        
        metadata = self.get_metadata()
        
        finding = CloudFinding(
            id=f"{metadata.name}-{resource_id}-{datetime.utcnow().timestamp()}",
            provider=metadata.provider,
            service=kwargs.get("service", metadata.name.split("_", 1)[0]),
            resource_id=resource_id,
            resource_arn=kwargs.get("resource_arn", ""),
            region=kwargs.get("region", "unknown"),
            severity=SeverityLevel(severity),
            category=FindingCategory(kwargs.get("category", "cspm")),
            title=title,
            description=description,
            evidence=kwargs.get("evidence", {}),
            remediation=kwargs.get("remediation", ""),
            remediation_cli=kwargs.get("remediation_cli", ""),
            compliance_frameworks=kwargs.get("compliance_frameworks", []),
            cis_benchmark=kwargs.get("cis_benchmark", ""),
            cvss_score=kwargs.get("cvss_score", 0.0),
            blast_radius_score=kwargs.get("blast_radius_score", 0),
            exploitability_score=kwargs.get("exploitability_score", 0),
            attack_paths=kwargs.get("attack_paths", []),
            detection_layer=metadata.layer,
            cwe_id=kwargs.get("cwe_id", ""),
            cwe_title=kwargs.get("cwe_title", ""),
            references=kwargs.get("references", []),
        )
        
        return finding
    
    def _log_finding(self, finding: CloudFinding):
        """Log finding for debugging"""
        self.logger.info(
            f"Finding: {finding.title} "
            f"[{finding.resource_id}] "
            f"({finding.severity.value})"
        )


# ========== Registry-friendly exports ==========

__all__ = ['CloudScanner', 'ScannerMetadata']
```

---

## How to Use These Templates

### Step 1: Create the files
```bash
# In PowerShell or terminal, navigate to project root
cd D:\jarwis-ai-pentest

# Create the three files (copy-paste the code above into each)
# File 1: attacks/cloud/exceptions.py
# File 2: attacks/cloud/schemas.py  
# File 3: attacks/cloud/base.py
```

### Step 2: Run basic validation
```bash
# Check Python syntax
python -m py_compile attacks/cloud/exceptions.py
python -m py_compile attacks/cloud/schemas.py
python -m py_compile attacks/cloud/base.py

# Run type checker
mypy attacks/cloud/
```

### Step 3: Test imports
```python
# Quick test in Python REPL
from attacks.cloud.exceptions import CloudScanError, CredentialError
from attacks.cloud.schemas import CloudFinding, CloudScanContext, SeverityLevel
from attacks.cloud.base import CloudScanner, ScannerMetadata

print("✅ All imports work!")
```

### Step 4: Next phase
Once these three files are in place and working, move to **Phase 2: Registry System**

---

## File Size Reference

| File | Lines | Complexity |
|------|-------|-----------|
| exceptions.py | ~130 | Low (simple classes) |
| schemas.py | ~320 | Low (dataclasses) |
| base.py | ~180 | Medium (ABC interface) |
| **Total** | **~630** | **Easy to review** |

All three files contain **zero dependencies** on existing cloud scanning code, so they can be created independently!

