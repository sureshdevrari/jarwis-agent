from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Provider(str, Enum):
    aws = "aws"
    azure = "azure"
    gcp = "gcp"
    container = "container"
    iac = "iac"
    runtime = "runtime"
    kubernetes = "kubernetes"


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


@dataclass
class CloudResource:
    resource_id: str
    resource_type: str
    provider: Provider
    region: Optional[str]
    name: str
    arn_or_id: str = ""
    service: str = ""
    tags: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    relationships: List[str] = field(default_factory=list)


@dataclass
class CloudFinding:
    id: str
    provider: Provider
    service: str
    category: str
    severity: Severity
    title: str
    description: str
    resource_id: Optional[str] = None
    resource_arn: str = ""
    region: Optional[str] = None
    evidence: Any = ""
    remediation: str = ""
    remediation_cli: str = ""
    cis_benchmark: str = ""
    references: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    cve: List[str] = field(default_factory=list)
    compliance: Dict[str, Any] = field(default_factory=dict)
    compliance_frameworks: List[str] = field(default_factory=list)
    cvss_score: float = 0.0
    blast_radius_score: int = 0
    exploitability_score: int = 0
    attack_path: List[str] = field(default_factory=list)
    detection_layer: str = ""
    detected_at: datetime = field(default_factory=datetime.utcnow)
    context: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CloudScanContext:
    scan_id: str
    target_accounts: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    credentials: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    regions: Dict[str, List[str]] = field(default_factory=dict)
    resources: List[CloudResource] = field(default_factory=list)
    findings: List[CloudFinding] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    progress: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScannerMetadata:
    name: str
    provider: Provider
    services: List[str] = field(default_factory=list)
    enabled_by_default: bool = True
    description: str = ""


__all__ = [
    "Provider",
    "Severity",
    "CloudResource",
    "CloudFinding",
    "CloudScanContext",
    "ScannerMetadata",
]
