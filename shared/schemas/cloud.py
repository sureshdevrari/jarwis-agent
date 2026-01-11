"""
Jarwis AGI - Cloud Scan Schemas
Shared schemas for cloud security scanning across all providers
"""

from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
import uuid


class CloudProvider(str, Enum):
    """Supported cloud providers"""
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"


class AuthMode(str, Enum):
    """Authentication modes"""
    DIRECT = "direct"  # Legacy - direct credentials
    ASSUME_ROLE = "assume_role"  # AWS cross-account role
    SERVICE_PRINCIPAL = "service_principal"  # Azure
    WORKLOAD_IDENTITY = "workload_identity"  # GCP federation
    DEFAULT = "default"  # Cloud provider default chain


# ==================== AWS Schemas ====================

class AWSServiceSelection(BaseModel):
    """AWS services to scan"""
    s3: bool = Field(True, description="S3 Buckets - Encryption, public access, logging")
    iam: bool = Field(True, description="IAM - Users, roles, MFA, policies")
    ec2: bool = Field(True, description="EC2 - Security groups, instances, metadata")
    rds: bool = Field(True, description="RDS - Database encryption, public access")
    lambda_: bool = Field(True, alias="lambda", description="Lambda - Runtimes, environment variables")
    cloudtrail: bool = Field(True, description="CloudTrail - Logging configuration")
    
    class Config:
        populate_by_name = True


class AWSCredentialsLegacy(BaseModel):
    """AWS credentials - Direct mode (legacy)"""
    access_key_id: str = Field(..., description="AWS Access Key ID")
    secret_access_key: str = Field(..., description="AWS Secret Access Key")
    region: str = Field("us-east-1", description="Default AWS region")
    session_token: Optional[str] = Field(None, description="Session token for temporary credentials")


class AWSCredentialsEnterprise(BaseModel):
    """AWS credentials - Cross-account role mode (recommended)"""
    role_arn: str = Field(..., description="ARN of the IAM role to assume", 
                          pattern=r"^arn:aws:iam::\d{12}:role/.+$")
    external_id: str = Field(..., description="External ID for confused deputy protection",
                             min_length=10)
    region: str = Field("us-east-1", description="Default AWS region")


class AWSCredentials(BaseModel):
    """AWS credentials - supports both legacy and enterprise modes"""
    # Enterprise mode (recommended)
    role_arn: Optional[str] = Field(None, description="ARN of the IAM role to assume")
    external_id: Optional[str] = Field(None, description="External ID for role assumption")
    
    # Legacy mode
    access_key_id: Optional[str] = Field(None, description="AWS Access Key ID (legacy)")
    secret_access_key: Optional[str] = Field(None, description="AWS Secret Access Key (legacy)")
    session_token: Optional[str] = Field(None, description="Session token for temporary credentials")
    
    # Common
    region: str = Field("us-east-1", description="Default AWS region")
    regions: Optional[List[str]] = Field(None, description="Specific regions to scan")
    services: Optional[AWSServiceSelection] = Field(None, description="Services to scan")


# ==================== Azure Schemas ====================

class AzureServiceSelection(BaseModel):
    """Azure services to scan"""
    storage: bool = Field(True, description="Storage Accounts - Encryption, public access, HTTPS")
    vms: bool = Field(True, description="Virtual Machines - Managed disks, encryption")
    sql: bool = Field(True, description="SQL Servers - Auditing, encryption, firewall")
    network: bool = Field(True, description="Network Security - NSGs, RDP/SSH access")
    keyvaults: bool = Field(True, description="Key Vaults - Soft delete, purge protection")
    aks: bool = Field(True, description="AKS Clusters - RBAC, network policies")
    appservices: bool = Field(True, description="App Services - HTTPS, TLS, authentication")
    monitor: bool = Field(True, description="Logging & Monitoring - Activity logs, retention")


class AzureCredentials(BaseModel):
    """Azure credentials - Service Principal mode"""
    tenant_id: str = Field(..., description="Azure AD Tenant ID")
    client_id: str = Field(..., description="Application (Client) ID")
    client_secret: str = Field(..., description="Client Secret")
    subscription_id: Optional[str] = Field(None, description="Single subscription ID (legacy)")
    subscription_ids: Optional[List[str]] = Field(None, description="List of subscription IDs to scan")
    services: Optional[AzureServiceSelection] = Field(None, description="Services to scan")


# ==================== GCP Schemas ====================

class GCPServiceSelection(BaseModel):
    """GCP services to scan"""
    compute: bool = Field(True, description="Compute Engine - Instances, service accounts")
    storage: bool = Field(True, description="Cloud Storage - Bucket permissions, public access")
    iam: bool = Field(True, description="IAM - Service accounts, policies, bindings")
    sql: bool = Field(True, description="Cloud SQL - SSL, authorized networks, backups")
    gke: bool = Field(True, description="GKE - RBAC, network policies, shielded nodes")


class GCPCredentialsLegacy(BaseModel):
    """GCP credentials - Service Account JSON mode (legacy)"""
    project_id: str = Field(..., description="GCP Project ID")
    service_account_key: str = Field(..., description="Service Account JSON key content")


class GCPCredentialsEnterprise(BaseModel):
    """GCP credentials - Workload Identity Federation mode (recommended)"""
    project_id: str = Field(..., description="GCP Project ID")
    workload_identity_pool: str = Field(..., description="Workload Identity Pool ID")
    workload_identity_provider: str = Field(..., description="Workload Identity Provider ID")
    service_account_email: str = Field(..., description="Service Account email to impersonate")


class GCPCredentials(BaseModel):
    """GCP credentials - supports both legacy and enterprise modes"""
    project_id: Optional[str] = Field(None, description="Single GCP Project ID (legacy)")
    project_ids: Optional[List[str]] = Field(None, description="List of Project IDs to scan")
    
    # Legacy mode
    service_account_key: Optional[str] = Field(None, description="Service Account JSON key content")
    
    # Enterprise mode
    workload_identity_pool: Optional[str] = Field(None, description="Workload Identity Pool ID")
    workload_identity_provider: Optional[str] = Field(None, description="Workload Identity Provider ID")
    service_account_email: Optional[str] = Field(None, description="Service Account email to impersonate")
    
    services: Optional[GCPServiceSelection] = Field(None, description="Services to scan")


# ==================== Common Schemas ====================

class ComplianceFramework(str, Enum):
    """Compliance frameworks to check against"""
    CIS = "cis"
    PCI_DSS = "pci-dss"
    HIPAA = "hipaa"
    SOC2 = "soc2"
    NIST = "nist"


class CloudScanRequestV2(BaseModel):
    """Cloud scan request - v2 with service selection"""
    provider: CloudProvider = Field(..., description="Cloud provider to scan")
    credentials: Dict[str, Any] = Field(..., description="Provider-specific credentials")
    
    # Service selection (provider-specific lists are parsed from credentials)
    services: Optional[List[str]] = Field(None, description="List of services to scan")
    regions: Optional[List[str]] = Field(None, description="Regions to scan (AWS/Azure)")
    
    # Compliance
    compliance_frameworks: List[ComplianceFramework] = Field(
        default=[ComplianceFramework.CIS],
        description="Compliance frameworks to check against"
    )
    
    # Metadata
    notes: Optional[str] = Field(None, description="User notes for this scan")


class CloudScanStatus(str, Enum):
    """Cloud scan status values"""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class CloudScanResponseV2(BaseModel):
    """Cloud scan response"""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: CloudScanStatus = Field(..., description="Current scan status")
    message: str = Field(..., description="Status message")
    provider: CloudProvider = Field(..., description="Cloud provider being scanned")
    auth_mode: AuthMode = Field(..., description="Authentication mode used")
    services: List[str] = Field(..., description="Services being scanned")
    external_id: Optional[str] = Field(None, description="External ID for AWS role assumption")


class CloudServiceInfo(BaseModel):
    """Information about an available cloud service"""
    id: str
    name: str
    description: str
    is_global: bool = False  # True for services like IAM that aren't regional


class AvailableServicesResponse(BaseModel):
    """Response with available services per provider"""
    provider: CloudProvider
    services: List[CloudServiceInfo]


class OnboardingTemplateResponse(BaseModel):
    """Response with onboarding template"""
    provider: CloudProvider
    template_type: str  # cloudformation, arm, terraform, shell
    template_name: str
    template_content: str
    instructions: str


def generate_external_id() -> str:
    """Generate a unique external ID for AWS role assumption"""
    return f"jarwis-{uuid.uuid4().hex[:16]}"


# Export service lists for frontend consumption
AWS_SERVICES = {
    's3': {'name': 'S3 Buckets', 'description': 'Encryption, public access, logging', 'global': True},
    'iam': {'name': 'IAM', 'description': 'Users, roles, MFA, policies', 'global': True},
    'ec2': {'name': 'EC2', 'description': 'Security groups, instances, metadata', 'global': False},
    'rds': {'name': 'RDS', 'description': 'Database encryption, public access', 'global': False},
    'lambda': {'name': 'Lambda', 'description': 'Runtimes, environment variables', 'global': False},
    'cloudtrail': {'name': 'CloudTrail', 'description': 'Logging configuration', 'global': True},
}

AZURE_SERVICES = {
    'storage': {'name': 'Storage Accounts', 'description': 'Encryption, public access, HTTPS, TLS'},
    'vms': {'name': 'Virtual Machines', 'description': 'Managed disks, encryption, agents'},
    'sql': {'name': 'SQL Servers', 'description': 'Auditing, encryption, firewall'},
    'network': {'name': 'Network Security', 'description': 'NSGs, RDP/SSH access, DDoS'},
    'keyvaults': {'name': 'Key Vaults', 'description': 'Soft delete, purge protection, RBAC'},
    'aks': {'name': 'AKS Clusters', 'description': 'RBAC, network policies, private clusters'},
    'appservices': {'name': 'App Services', 'description': 'HTTPS, TLS, authentication'},
    'monitor': {'name': 'Logging & Monitoring', 'description': 'Activity logs, retention'},
}

GCP_SERVICES = {
    'compute': {'name': 'Compute Engine', 'description': 'Instances, service accounts, public IPs'},
    'storage': {'name': 'Cloud Storage', 'description': 'Bucket permissions, public access'},
    'iam': {'name': 'IAM', 'description': 'Service accounts, policies, bindings'},
    'sql': {'name': 'Cloud SQL', 'description': 'SSL, authorized networks, backups'},
    'gke': {'name': 'GKE', 'description': 'RBAC, network policies, shielded nodes'},
}

ALL_SERVICES = {
    'aws': AWS_SERVICES,
    'azure': AZURE_SERVICES,
    'gcp': GCP_SERVICES,
}
