"""
Jarwis AGI - GCP Security Scanner
CIS Google Cloud Platform Foundation Benchmark v1.3
"""

import json
import asyncio
import logging
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import uuid

from .base import CloudScanner
from .schemas import (
    CloudFinding,
    CloudScanContext,
    Provider,
    ScannerMetadata,
    Severity,
)
from .exceptions import (
    APIThrottlingError,
    ProviderAuthError,
    RateLimitError,
    ServicePermissionError,
)

logger = logging.getLogger(__name__)

@dataclass
class GCPFinding:
    """GCP security finding"""
    id: str
    service: str
    resource_id: str
    resource_name: str
    project_id: str
    region: str
    severity: str
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    cis_benchmark: str = ""
    remediation_cli: str = ""

class GCPSecurityScanner:
    """GCP Security Scanner - CIS v1.3"""
    
    # Available services for scanning
    AVAILABLE_SERVICES = {
        'compute': {'name': 'Compute Engine', 'description': 'Instances, service accounts, public IPs'},
        'storage': {'name': 'Cloud Storage', 'description': 'Bucket permissions, public access'},
        'iam': {'name': 'IAM', 'description': 'Service accounts, policies, bindings'},
        'sql': {'name': 'Cloud SQL', 'description': 'SSL, authorized networks, backups'},
        'gke': {'name': 'GKE', 'description': 'RBAC, network policies, shielded nodes'},
    }
    
    def __init__(
        self,
        project_id: str = None,
        project_ids: List[str] = None,  # Support multiple projects
        service_account_json: str = None,
        # Workload Identity Federation (enterprise)
        workload_identity_pool: str = None,
        workload_identity_provider: str = None,
        service_account_email: str = None,
    ):
        # Support multiple projects
        if project_ids:
            self.project_ids = project_ids
            self.project_id = project_ids[0] if project_ids else None
        else:
            self.project_ids = [project_id] if project_id else []
            self.project_id = project_id
        
        self.service_account_json = service_account_json
        self.workload_identity_pool = workload_identity_pool
        self.workload_identity_provider = workload_identity_provider
        self.service_account_email = service_account_email
        self.credentials = None
        self.findings: List[GCPFinding] = []
        self._gcp_available = False
        self._auth_mode = None
        self._init_credentials()
    
    @classmethod
    def get_available_services(cls) -> Dict[str, Dict]:
        """Return available services for UI service selection"""
        return cls.AVAILABLE_SERVICES
    
    def _init_credentials(self):
        """Initialize GCP credentials with support for multiple auth methods"""
        try:
            # Priority 1: Workload Identity Federation (enterprise)
            if self.workload_identity_pool and self.workload_identity_provider:
                self._auth_mode = 'workload_identity'
                logger.info("Using Workload Identity Federation")
                # Workload identity requires a specific credential config
                from google.auth import identity_pool
                # This would be configured via environment or config file
                # For now, fall back to default credentials
                import google.auth
                self.credentials, _ = google.auth.default()
                self._gcp_available = True
            
            # Priority 2: Service Account JSON (legacy but supported)
            elif self.service_account_json:
                self._auth_mode = 'service_account_key'
                from google.oauth2 import service_account
                info = json.loads(self.service_account_json)
                self.credentials = service_account.Credentials.from_service_account_info(info)
                if not self.project_id:
                    self.project_id = info.get('project_id')
                    if self.project_id and self.project_id not in self.project_ids:
                        self.project_ids.append(self.project_id)
                logger.info("Using Service Account JSON key")
                self._gcp_available = True
            
            # Priority 3: Default credentials (ADC)
            else:
                self._auth_mode = 'default'
                import google.auth
                self.credentials, project = google.auth.default()
                if project and not self.project_id:
                    self.project_id = project
                    if project not in self.project_ids:
                        self.project_ids.append(project)
                logger.info("Using Application Default Credentials")
                self._gcp_available = True
                
        except ImportError:
            logger.warning("GCP SDK not installed")
            self._gcp_available = False
        except Exception as e:
            logger.error(f"GCP authentication failed: {e}")
            self._gcp_available = False
    
    async def discover_resources(self) -> List[Dict]:
        resources = []
        if not self._gcp_available:
            return resources
        try:
            from google.cloud import compute_v1, storage
            # Discover Compute instances
            compute_client = compute_v1.InstancesClient(credentials=self.credentials)
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones = list(zones_client.list(project=self.project_id))
            for zone in zones:
                instances = list(compute_client.list(project=self.project_id, zone=zone.name))
                for instance in instances:
                    resources.append({
                        'id': str(instance.id),
                        'name': instance.name,
                        'type': 'compute_instance',
                        'location': zone.name,
                        'tags': dict(instance.labels) if hasattr(instance, 'labels') else {},
                        'metadata': {'machine_type': instance.machine_type, 'status': instance.status}
                    })
            # Discover Storage buckets
            storage_client = storage.Client(project=self.project_id, credentials=self.credentials)
            buckets = list(storage_client.list_buckets())
            for bucket in buckets:
                resources.append({
                    'id': bucket.name,
                    'name': bucket.name,
                    'type': 'storage_bucket',
                    'location': bucket.location,
                    'tags': dict(bucket.labels) if bucket.labels else {},
                    'metadata': {'storage_class': bucket.storage_class, 'versioning': bucket.versioning_enabled}
                })
        except Exception as e:
            logger.error(f"GCP discovery failed: {e}")
        return resources
    
    async def scan_all(self, services: List[str] = None) -> List[GCPFinding]:
        """Run GCP security checks with optional service selection
        
        Args:
            services: List of services to scan (default: all)
                     Options: compute, storage, iam, sql, gke
        """
        if not self._gcp_available:
            return [self._get_mock_finding()]
        
        # Default to all services if none specified
        if not services:
            services = list(self.AVAILABLE_SERVICES.keys())
        
        logger.info(f"Starting GCP scan for services: {services}")
        self.findings = []
        
        # Scan each project
        for proj_id in self.project_ids:
            logger.info(f"Scanning project: {proj_id}")
            self.project_id = proj_id
            
            if 'compute' in services:
                await self.check_compute_instances()
            if 'storage' in services:
                await self.check_storage_buckets()
            if 'iam' in services:
                await self.check_iam()
            if 'sql' in services:
                await self.check_sql()
            if 'gke' in services:
                await self.check_gke()
        
        return self.findings

    
    async def check_compute_instances(self):
        """Check Compute Engine security"""
        logger.info("Checking Compute instances...")
        try:
            from google.cloud import compute_v1
            compute_client = compute_v1.InstancesClient(credentials=self.credentials)
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            zones = list(zones_client.list(project=self.project_id))
            for zone in zones[:3]:  # Sample first 3 zones
                instances = list(compute_client.list(project=self.project_id, zone=zone.name))
                for instance in instances:
                    # Check default service account
                    for sa in instance.service_accounts:
                        if 'compute@developer' in sa.email:
                            self._add_finding(
                                f"gcp_compute_{instance.name}_default_sa",
                                "Compute",
                                str(instance.id),
                                instance.name,
                                zone.name,
                                "high",
                                "Instance uses default service account",
                                f"Instance {instance.name} uses default Compute SA",
                                {'sa': sa.email},
                                "Use custom SA with minimal permissions",
                                "4.1",
                                f"gcloud compute instances set-service-account {instance.name} --zone={zone.name} --service-account=custom-sa@{self.project_id}.iam.gserviceaccount.com"
                            )
                    # Check public IP
                    for nic in instance.network_interfaces:
                        if nic.access_configs:
                            self._add_finding(
                                f"gcp_compute_{instance.name}_public_ip",
                                "Compute",
                                str(instance.id),
                                instance.name,
                                zone.name,
                                "high",
                                "Instance has public IP",
                                f"Instance {instance.name} exposed to internet",
                                {'public_ip': True},
                                "Use Cloud NAT or IAP",
                                "4.9",
                                f"gcloud compute instances delete-access-config {instance.name} --zone={zone.name}"
                            )
        except Exception as e:
            logger.error(f"Compute checks failed: {e}")
    
    async def check_storage_buckets(self):
        """Check Cloud Storage security"""
        logger.info("Checking Storage buckets...")
        try:
            from google.cloud import storage
            client = storage.Client(project=self.project_id, credentials=self.credentials)
            buckets = list(client.list_buckets())
            for bucket in buckets:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                is_public = any('allUsers' in str(binding.get('members', [])) for binding in policy.bindings)
                if is_public:
                    self._add_finding(
                        f"gcp_storage_{bucket.name}_public",
                        "Storage",
                        bucket.id,
                        bucket.name,
                        bucket.location,
                        "critical",
                        "Bucket is publicly accessible",
                        f"Bucket {bucket.name} has public access",
                        {'public': True},
                        "Remove public access from IAM policy",
                        "5.1",
                        f"gsutil iam ch -d allUsers gs://{bucket.name}"
                    )
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    self._add_finding(
                        f"gcp_storage_{bucket.name}_uniform_access",
                        "Storage",
                        bucket.id,
                        bucket.name,
                        bucket.location,
                        "medium",
                        "Uniform bucket-level access not enabled",
                        f"Bucket {bucket.name} uses legacy ACLs",
                        {'uniform_access': False},
                        "Enable uniform bucket-level access",
                        "5.2",
                        f"gsutil uniformbucketlevelaccess set on gs://{bucket.name}"
                    )
        except Exception as e:
            logger.error(f"Storage checks failed: {e}")
    
    async def check_iam(self):
        """Check IAM security - service accounts, API keys, bindings"""
        logger.info("Checking IAM...")
        if not self._gcp_available:
            return
        try:
            from google.cloud import iam_admin_v1
            from google.cloud import resourcemanager_v3

            # List service accounts
            sa_client = iam_admin_v1.IAMClient(credentials=self.credentials)
            request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{self.project_id}")
            service_accounts = list(sa_client.list_service_accounts(request=request))
            for sa in service_accounts:
                # Check for user-managed keys
                keys = list(sa_client.list_service_account_keys(
                    request=iam_admin_v1.ListServiceAccountKeysRequest(name=sa.name)
                ))
                user_keys = [k for k in keys if k.key_type == iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
                if user_keys:
                    self._add_finding(
                        f"gcp_iam_{sa.email}_user_keys",
                        "IAM",
                        sa.unique_id,
                        sa.email,
                        "global",
                        "medium",
                        "Service account has user-managed keys",
                        f"SA {sa.email} has {len(user_keys)} user-managed keys which may be exposed",
                        {"key_count": len(user_keys)},
                        "Prefer Workload Identity or short-lived tokens",
                        "1.4",
                        f"gcloud iam service-accounts keys delete KEY_ID --iam-account={sa.email}"
                    )

            # Check project IAM policy for risky bindings
            rm_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            policy = rm_client.get_iam_policy(request={"resource": f"projects/{self.project_id}"})
            for binding in policy.bindings:
                if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                    self._add_finding(
                        f"gcp_iam_public_binding_{binding.role}",
                        "IAM",
                        self.project_id,
                        self.project_id,
                        "global",
                        "critical",
                        "Project has public IAM binding",
                        f"Role {binding.role} granted to allUsers or allAuthenticatedUsers",
                        {"role": binding.role, "members": list(binding.members)},
                        "Remove public bindings immediately",
                        "1.1",
                        f"gcloud projects remove-iam-policy-binding {self.project_id} --role={binding.role} --member=allUsers"
                    )
        except ImportError:
            logger.warning("google-cloud-iam not installed")
        except Exception as e:
            logger.error(f"IAM checks failed: {e}")

    async def check_sql(self):
        """Check Cloud SQL security - SSL, public IPs, backups"""
        logger.info("Checking Cloud SQL...")
        if not self._gcp_available:
            return
        try:
            from googleapiclient.discovery import build
            from google.auth import default as google_default

            creds = self.credentials or google_default()[0]
            service = build("sqladmin", "v1beta4", credentials=creds)
            instances = service.instances().list(project=self.project_id).execute().get("items", [])

            for inst in instances:
                name = inst.get("name")
                settings = inst.get("settings", {})
                ip_config = settings.get("ipConfiguration", {})

                # Check require SSL
                if not ip_config.get("requireSsl", False):
                    self._add_finding(
                        f"gcp_sql_{name}_no_ssl",
                        "SQL",
                        name,
                        name,
                        inst.get("region", "global"),
                        "high",
                        "Cloud SQL does not require SSL",
                        f"Instance {name} accepts unencrypted connections",
                        {"requireSsl": False},
                        "Enable requireSsl in IP configuration",
                        "6.1",
                        f"gcloud sql instances patch {name} --require-ssl"
                    )

                # Check authorized networks (public access)
                auth_networks = ip_config.get("authorizedNetworks", [])
                for net in auth_networks:
                    if net.get("value") == "0.0.0.0/0":
                        self._add_finding(
                            f"gcp_sql_{name}_public_access",
                            "SQL",
                            name,
                            name,
                            inst.get("region", "global"),
                            "critical",
                            "Cloud SQL allows all IPs",
                            f"Instance {name} allows connections from 0.0.0.0/0",
                            {"authorized_networks": auth_networks},
                            "Restrict to private VPC or specific IPs",
                            "6.2",
                            f"gcloud sql instances patch {name} --clear-authorized-networks"
                        )

                # Check automated backups
                backup_cfg = settings.get("backupConfiguration", {})
                if not backup_cfg.get("enabled", False):
                    self._add_finding(
                        f"gcp_sql_{name}_no_backups",
                        "SQL",
                        name,
                        name,
                        inst.get("region", "global"),
                        "medium",
                        "Cloud SQL backups disabled",
                        f"Instance {name} does not have automated backups",
                        {"backups_enabled": False},
                        "Enable automated backups",
                        "6.7",
                        f"gcloud sql instances patch {name} --backup-start-time=02:00"
                    )
        except ImportError:
            logger.warning("googleapiclient not installed for SQL checks")
        except Exception as e:
            logger.error(f"Cloud SQL checks failed: {e}")

    async def check_gke(self):
        """Check GKE security - RBAC, network policies, legacy endpoints"""
        logger.info("Checking GKE...")
        if not self._gcp_available:
            return
        try:
            from google.cloud import container_v1

            client = container_v1.ClusterManagerClient(credentials=self.credentials)
            parent = f"projects/{self.project_id}/locations/-"
            clusters = list(client.list_clusters(parent=parent).clusters)

            for cluster in clusters:
                name = cluster.name
                location = cluster.location

                # Check legacy ABAC
                if cluster.legacy_abac and cluster.legacy_abac.enabled:
                    self._add_finding(
                        f"gcp_gke_{name}_legacy_abac",
                        "GKE",
                        name,
                        name,
                        location,
                        "high",
                        "GKE cluster uses legacy ABAC",
                        f"Cluster {name} has legacy ABAC enabled instead of RBAC",
                        {"legacy_abac": True},
                        "Disable legacy ABAC and use Kubernetes RBAC",
                        "7.1",
                        f"gcloud container clusters update {name} --no-enable-legacy-authorization --zone={location}"
                    )

                # Check network policy
                if not cluster.network_policy or not cluster.network_policy.enabled:
                    self._add_finding(
                        f"gcp_gke_{name}_no_netpol",
                        "GKE",
                        name,
                        name,
                        location,
                        "medium",
                        "GKE cluster lacks network policy",
                        f"Cluster {name} does not enforce network policies",
                        {"network_policy": False},
                        "Enable network policy for pod-level segmentation",
                        "7.11",
                        f"gcloud container clusters update {name} --enable-network-policy --zone={location}"
                    )

                # Check private cluster
                if not cluster.private_cluster_config or not cluster.private_cluster_config.enable_private_nodes:
                    self._add_finding(
                        f"gcp_gke_{name}_public_nodes",
                        "GKE",
                        name,
                        name,
                        location,
                        "high",
                        "GKE nodes have public IPs",
                        f"Cluster {name} nodes are publicly accessible",
                        {"private_nodes": False},
                        "Enable private nodes to prevent direct internet access",
                        "7.15",
                        f"gcloud container clusters update {name} --enable-private-nodes --zone={location}"
                    )

                # Check Shielded GKE nodes
                if not cluster.shielded_nodes or not cluster.shielded_nodes.enabled:
                    self._add_finding(
                        f"gcp_gke_{name}_no_shielded",
                        "GKE",
                        name,
                        name,
                        location,
                        "medium",
                        "GKE Shielded nodes not enabled",
                        f"Cluster {name} does not use Shielded GKE nodes",
                        {"shielded_nodes": False},
                        "Enable Shielded GKE nodes for integrity verification",
                        "7.17",
                        f"gcloud container clusters update {name} --enable-shielded-nodes --zone={location}"
                    )
        except ImportError:
            logger.warning("google-cloud-container not installed for GKE checks")
        except Exception as e:
            logger.error(f"GKE checks failed: {e}")
    
    def _add_finding(self, id, service, resource_id, resource_name, region, severity, title, desc, evidence, rec, cis, cli):
        self.findings.append(GCPFinding(
            id=id, service=service, resource_id=resource_id, resource_name=resource_name,
            project_id=self.project_id, region=region, severity=severity, title=title,
            description=desc, evidence=evidence, recommendation=rec, cis_benchmark=cis, remediation_cli=cli
        ))
    
    def _get_mock_finding(self):
        return GCPFinding(
            id="gcp_mock", service="Mock", resource_id="mock", resource_name="mock",
            project_id=self.project_id or "mock", region="us-central1", severity="info",
            title="GCP SDK not installed", description="Install google-cloud-* packages",
            evidence={}, recommendation="pip install google-cloud-storage google-cloud-compute",
            cis_benchmark="", remediation_cli=""
        )


class GCPScanner(CloudScanner):
    """CloudScanner-based GCP scanner adapter using existing methods."""

    metadata = ScannerMetadata(
        name="gcp_core",
        provider=Provider.gcp,
        services=["compute", "storage", "iam", "sql", "gke"],
        enabled_by_default=True,
        description="Core GCP security checks (Compute, Storage, IAM, SQL, GKE)",
    )

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self._scanner = GCPSecurityScanner(
            project_id=self.config.get("project_id"),
            service_account_json=self.config.get("service_account_json"),
        )

    async def scan(self, context: CloudScanContext) -> List[CloudFinding]:
        findings = await self._safe_call(self._scanner.scan_all)
        cloud_findings: List[CloudFinding] = []
        for f in findings:
            sev = None
            try:
                sev = Severity(f.severity)
            except Exception:
                sev = Severity.info
            cloud_findings.append(
                CloudFinding(
                    id=f.id,
                    provider=Provider.gcp,
                    service=f.service.lower(),
                    category=f.cis_benchmark or "general",
                    severity=sev,
                    title=f.title,
                    description=f.description,
                    resource_id=f.resource_id,
                    region=f.region,
                    evidence=json.dumps(f.evidence) if isinstance(f.evidence, dict) else str(f.evidence),
                    remediation=f.recommendation,
                    references=[],
                    cwe=None,
                    cve=[],
                    compliance={"cis": f.cis_benchmark} if f.cis_benchmark else {},
                    context={"resource_name": f.resource_name, "project_id": f.project_id},
                )
            )
        return cloud_findings

    async def _safe_call(self, func, *args, **kwargs):
        try:
            return await self.run_limited(self.with_retry(func, *args, **kwargs))
        except Exception as e:
            mapped = self._map_error(e)
            raise mapped from e

    def _map_error(self, err: Exception):
        msg = str(err)
        if "rateLimitExceeded" in msg or "quota" in msg:
            return APIThrottlingError(msg, provider="gcp", service="global")
        if "PERMISSION_DENIED" in msg or "AccessDenied" in msg:
            return ServicePermissionError(msg, provider="gcp", service="global")
        if "UNAUTHENTICATED" in msg or "invalid_grant" in msg:
            return ProviderAuthError(msg, provider="gcp", service="global")
        if "429" in msg:
            return RateLimitError(msg, provider="gcp", service="global")
        return err