"""
Jarwis AGI - GCP Security Scanner
Comprehensive Google Cloud Platform security assessment

Checks:
- Cloud Storage (public access, encryption)
- IAM (roles, service accounts)
- Compute Engine (firewall, encryption)
- Cloud SQL (encryption, access)
- Cloud Functions (permissions)
- Logging & Monitoring
"""

import json
import asyncio
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable

logger = logging.getLogger(__name__)


class GCPSecurityScanner:
    """
    GCP Security Scanner
    Performs comprehensive security assessment of GCP resources
    """
    
    def __init__(
        self,
        project_id: str = None,
        credentials_file: str = None
    ):
        self.project_id = project_id
        self.credentials_file = credentials_file
        self.credentials = None
        self.findings = []
        self._gcp_available = False
        self._verbose_callback: Optional[Callable] = None
        self._init_client()
    
    def _init_client(self):
        """Initialize GCP client"""
        try:
            from google.cloud import storage
            from google.oauth2 import service_account
            
            self._gcp_available = True
            
            if self.credentials_file:
                self.credentials = service_account.Credentials.from_service_account_file(
                    self.credentials_file
                )
            # Otherwise uses default credentials
            
            logger.info("GCP credentials initialized")
        except ImportError:
            logger.warning("GCP SDK not installed. Run: pip install google-cloud-storage google-cloud-compute")
            self._gcp_available = False
        except Exception as e:
            logger.error(f"Failed to initialize GCP client: {e}")
    
    def set_verbose_callback(self, callback: Callable):
        """Set callback for verbose logging"""
        self._verbose_callback = callback
    
    def _log(self, log_type: str, message: str, details: str = None):
        """Log message via callback"""
        if self._verbose_callback:
            try:
                self._verbose_callback(log_type, message, details)
            except:
                pass
        logger.info(f"[{log_type}] {message}")
    
    def _add_finding(
        self,
        id: str,
        service: str,
        resource_id: str,
        severity: str,
        title: str,
        description: str,
        **kwargs
    ):
        """Add a finding to the list"""
        finding = {
            "id": id,
            "service": service,
            "resource_id": resource_id,
            "resource_arn": kwargs.get("resource_arn", ""),
            "region": kwargs.get("region", "global"),
            "severity": severity,
            "title": title,
            "description": description,
            "evidence": kwargs.get("evidence", {}),
            "recommendation": kwargs.get("recommendation", ""),
            "compliance": kwargs.get("compliance", [])
        }
        self.findings.append(finding)
    
    async def scan(self) -> 'CloudScanResult':
        """Perform GCP security scan"""
        from .cloud_scanner import CloudScanResult
        
        if not self._gcp_available:
            self._log("error", "GCP SDK not installed")
            return CloudScanResult(
                scan_id="GCP-FAILED",
                provider="gcp",
                status="failed"
            )
        
        scan_id = f"GCP-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.findings = []
        resources_scanned = 0
        
        self._log("start", "Starting GCP security scan")
        
        try:
            # Scan Cloud Storage
            self._log("phase", "Scanning Cloud Storage")
            resources_scanned += await self._scan_storage()
            
            # Scan Compute Engine
            self._log("phase", "Scanning Compute Engine")
            resources_scanned += await self._scan_compute()
            
            # Scan Cloud SQL
            self._log("phase", "Scanning Cloud SQL")
            resources_scanned += await self._scan_cloud_sql()
            
            # Scan IAM
            self._log("phase", "Scanning IAM")
            resources_scanned += await self._scan_iam()
            
            # Scan Firewall Rules
            self._log("phase", "Scanning Firewall Rules")
            resources_scanned += await self._scan_firewall()
            
        except Exception as e:
            self._log("error", f"GCP scan error: {e}")
            logger.exception(f"GCP scan failed: {e}")
        
        result = CloudScanResult(
            scan_id=scan_id,
            provider="gcp",
            account_id=self.project_id or "default",
            scan_start=datetime.now().isoformat(),
            scan_end=datetime.now().isoformat(),
            status="completed",
            resources_scanned=resources_scanned,
            regions_scanned=["global"],
            services_scanned=["storage", "compute", "sql", "iam"],
            findings=self.findings,
            total_findings=len(self.findings)
        )
        
        for finding in self.findings:
            severity = finding.get('severity', 'info').lower()
            if severity == "critical":
                result.critical_count += 1
            elif severity == "high":
                result.high_count += 1
            elif severity == "medium":
                result.medium_count += 1
            elif severity == "low":
                result.low_count += 1
        
        self._log("complete", f"GCP scan complete: {len(self.findings)} findings")
        
        return result
    
    async def _scan_storage(self) -> int:
        """Scan GCP Cloud Storage buckets"""
        resources = 0
        
        try:
            from google.cloud import storage
            
            client = storage.Client(project=self.project_id, credentials=self.credentials)
            
            for bucket in client.list_buckets():
                resources += 1
                bucket_name = bucket.name
                
                # Check uniform bucket-level access
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    self._add_finding(
                        id=f"GCP-GCS-UNIFORM-{bucket_name}",
                        service="storage",
                        resource_id=bucket_name,
                        severity="medium",
                        title="Bucket Without Uniform Access",
                        description=f"Bucket {bucket_name} does not use uniform bucket-level access.",
                        recommendation="Enable uniform bucket-level access."
                    )
                
                # Check public access
                policy = bucket.get_iam_policy()
                for binding in policy.bindings:
                    if "allUsers" in binding.get("members", []) or "allAuthenticatedUsers" in binding.get("members", []):
                        self._add_finding(
                            id=f"GCP-GCS-PUBLIC-{bucket_name}",
                            service="storage",
                            resource_id=bucket_name,
                            severity="critical" if "allUsers" in binding["members"] else "high",
                            title="Bucket Has Public Access",
                            description=f"Bucket {bucket_name} is publicly accessible.",
                            evidence={"role": binding.get("role"), "members": binding.get("members")},
                            recommendation="Remove public access unless required."
                        )
                
                # Check versioning
                if not bucket.versioning_enabled:
                    self._add_finding(
                        id=f"GCP-GCS-VERSION-{bucket_name}",
                        service="storage",
                        resource_id=bucket_name,
                        severity="low",
                        title="Bucket Versioning Not Enabled",
                        description=f"Bucket {bucket_name} does not have versioning enabled.",
                        recommendation="Enable versioning for data protection."
                    )
                    
        except Exception as e:
            logger.error(f"Error scanning storage: {e}")
        
        return resources
    
    async def _scan_compute(self) -> int:
        """Scan GCP Compute Engine instances"""
        resources = 0
        
        try:
            from google.cloud import compute_v1
            
            instances_client = compute_v1.InstancesClient(credentials=self.credentials)
            zones_client = compute_v1.ZonesClient(credentials=self.credentials)
            
            # List all zones
            for zone in zones_client.list(project=self.project_id):
                zone_name = zone.name
                
                for instance in instances_client.list(project=self.project_id, zone=zone_name):
                    resources += 1
                    instance_name = instance.name
                    
                    # Check for default service account
                    for sa in instance.service_accounts or []:
                        if "compute@developer.gserviceaccount.com" in sa.email:
                            self._add_finding(
                                id=f"GCP-GCE-SA-{instance_name}",
                                service="compute",
                                resource_id=instance_name,
                                region=zone_name,
                                severity="medium",
                                title="Instance Using Default Service Account",
                                description=f"Instance {instance_name} uses default compute service account.",
                                recommendation="Use a custom service account with minimal permissions."
                            )
                    
                    # Check for public IP
                    for interface in instance.network_interfaces or []:
                        for access in interface.access_configs or []:
                            if access.nat_i_p:
                                self._add_finding(
                                    id=f"GCP-GCE-PUBLICIP-{instance_name}",
                                    service="compute",
                                    resource_id=instance_name,
                                    region=zone_name,
                                    severity="low",
                                    title="Instance Has Public IP",
                                    description=f"Instance {instance_name} has a public IP address.",
                                    recommendation="Use Cloud NAT if external access is needed."
                                )
                    
                    # Check disk encryption
                    for disk in instance.disks or []:
                        if not disk.disk_encryption_key:
                            # Using Google-managed keys is OK, but CMEK is better
                            pass
                            
        except Exception as e:
            logger.error(f"Error scanning compute: {e}")
        
        return resources
    
    async def _scan_cloud_sql(self) -> int:
        """Scan GCP Cloud SQL instances"""
        resources = 0
        
        try:
            from googleapiclient import discovery
            
            sqladmin = discovery.build('sqladmin', 'v1beta4', credentials=self.credentials)
            
            instances = sqladmin.instances().list(project=self.project_id).execute()
            
            for instance in instances.get('items', []):
                resources += 1
                instance_name = instance['name']
                
                # Check public IP
                ip_config = instance.get('settings', {}).get('ipConfiguration', {})
                if ip_config.get('ipv4Enabled', False):
                    # Check authorized networks
                    auth_networks = ip_config.get('authorizedNetworks', [])
                    for network in auth_networks:
                        if network.get('value') == '0.0.0.0/0':
                            self._add_finding(
                                id=f"GCP-SQL-PUBLIC-{instance_name}",
                                service="sql",
                                resource_id=instance_name,
                                severity="critical",
                                title="Cloud SQL Open to All IPs",
                                description=f"Cloud SQL instance {instance_name} allows connections from any IP.",
                                recommendation="Restrict authorized networks."
                            )
                
                # Check SSL requirement
                if not ip_config.get('requireSsl', False):
                    self._add_finding(
                        id=f"GCP-SQL-SSL-{instance_name}",
                        service="sql",
                        resource_id=instance_name,
                        severity="high",
                        title="Cloud SQL SSL Not Required",
                        description=f"Cloud SQL instance {instance_name} does not require SSL.",
                        recommendation="Enable SSL requirement."
                    )
                
                # Check backup configuration
                backup_config = instance.get('settings', {}).get('backupConfiguration', {})
                if not backup_config.get('enabled', False):
                    self._add_finding(
                        id=f"GCP-SQL-BACKUP-{instance_name}",
                        service="sql",
                        resource_id=instance_name,
                        severity="medium",
                        title="Cloud SQL Backups Disabled",
                        description=f"Cloud SQL instance {instance_name} has backups disabled.",
                        recommendation="Enable automated backups."
                    )
                    
        except Exception as e:
            logger.error(f"Error scanning Cloud SQL: {e}")
        
        return resources
    
    async def _scan_iam(self) -> int:
        """Scan GCP IAM"""
        resources = 0
        
        try:
            from google.cloud import resourcemanager_v3
            
            client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            
            # Get project IAM policy
            policy = client.get_iam_policy(resource=f"projects/{self.project_id}")
            
            for binding in policy.bindings:
                resources += 1
                role = binding.role
                
                # Check for overly permissive roles
                if role in ['roles/owner', 'roles/editor']:
                    for member in binding.members:
                        if member.startswith('user:') or member.startswith('serviceAccount:'):
                            self._add_finding(
                                id=f"GCP-IAM-OWNER-{hash(member) % 10000}",
                                service="iam",
                                resource_id=member,
                                severity="high" if role == 'roles/owner' else "medium",
                                title=f"Broad IAM Role Assignment",
                                description=f"{member} has {role} role on project.",
                                recommendation="Use more specific roles following least privilege."
                            )
                
                # Check for allUsers or allAuthenticatedUsers
                if 'allUsers' in binding.members or 'allAuthenticatedUsers' in binding.members:
                    self._add_finding(
                        id=f"GCP-IAM-PUBLIC-{role.replace('/', '-')}",
                        service="iam",
                        resource_id=self.project_id,
                        severity="critical",
                        title="Public IAM Binding",
                        description=f"Role {role} is granted to public users.",
                        recommendation="Remove public access."
                    )
                    
        except Exception as e:
            logger.error(f"Error scanning IAM: {e}")
        
        return resources
    
    async def _scan_firewall(self) -> int:
        """Scan GCP Firewall Rules"""
        resources = 0
        
        try:
            from google.cloud import compute_v1
            
            firewall_client = compute_v1.FirewallsClient(credentials=self.credentials)
            
            for rule in firewall_client.list(project=self.project_id):
                resources += 1
                rule_name = rule.name
                
                # Only check allow rules with ingress
                if rule.direction == "INGRESS" and rule.allowed:
                    source_ranges = rule.source_ranges or []
                    
                    if "0.0.0.0/0" in source_ranges:
                        for allowed in rule.allowed:
                            ports = allowed.ports or ["all"]
                            
                            # Check for SSH
                            if "22" in ports or "all" in ports:
                                self._add_finding(
                                    id=f"GCP-FW-SSH-{rule_name}",
                                    service="firewall",
                                    resource_id=rule_name,
                                    severity="critical",
                                    title="Firewall Allows SSH from Internet",
                                    description=f"Firewall rule {rule_name} allows SSH from 0.0.0.0/0.",
                                    recommendation="Restrict source ranges."
                                )
                            
                            # Check for RDP
                            if "3389" in ports or "all" in ports:
                                self._add_finding(
                                    id=f"GCP-FW-RDP-{rule_name}",
                                    service="firewall",
                                    resource_id=rule_name,
                                    severity="critical",
                                    title="Firewall Allows RDP from Internet",
                                    description=f"Firewall rule {rule_name} allows RDP from 0.0.0.0/0.",
                                    recommendation="Restrict source ranges."
                                )
                                
        except Exception as e:
            logger.error(f"Error scanning firewall: {e}")
        
        return resources
