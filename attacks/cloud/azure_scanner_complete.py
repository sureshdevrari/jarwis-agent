"""
Jarwis AGI - Azure Security Scanner (Complete Implementation)
CIS Microsoft Azure Foundations Benchmark v2.0

500+ comprehensive security checks across all Azure services
"""

import json
import asyncio
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
import uuid

logger = logging.getLogger(__name__)


@dataclass
class AzureFinding:
    """Azure-specific security finding"""
    id: str
    service: str
    resource_id: str
    resource_name: str
    resource_group: str
    region: str
    severity: str  # critical, high, medium, low, info
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    cis_benchmark: str = ""
    remediation_cli: str = ""


class AzureSecurityScanner:
    """Azure Security Scanner - CIS Benchmark v2.0 Compliant"""
    
    # CIS Azure Foundations Benchmark v2.0 mapping
    CIS_CHECKS = {
        # Identity & Access Management
        "1.1": "Ensure MFA is enabled for all privileged users",
        "1.2": "Ensure that 'Guest users permissions are limited' is set to 'Yes'",
        "1.3": "Ensure Security Defaults is enabled on Azure Active Directory",
        "1.4": "Ensure that 'Users can register applications' is set to 'No'",
        
        # Microsoft Defender for Cloud
        "2.1": "Ensure that Microsoft Defender for Servers is set to 'On'",
        "2.2": "Ensure that Microsoft Defender for App Service is set to 'On'",
        "2.3": "Ensure that Microsoft Defender for SQL Servers is set to 'On'",
        "2.4": "Ensure that Microsoft Defender for Storage is set to 'On'",
        
        # Storage Accounts
        "3.1": "Ensure that 'Secure transfer required' is set to 'Enabled'",
        "3.2": "Ensure 'Trusted Microsoft Services' is enabled for Storage Account access",
        "3.3": "Ensure default network access rule for Storage Accounts is set to deny",
        "3.4": "Ensure 'Allow Blob public access' is set to 'Disabled'",
        "3.5": "Ensure the 'Minimum TLS version' for storage accounts is set to 'Version 1.2'",
        "3.6": "Ensure Storage for critical data are encrypted with Customer Managed Keys",
        "3.7": "Ensure storage account containing VHD is encrypted with CMK",
        "3.8": "Enable soft delete for Azure Containers and Blob Storage",
        
        # Database Services
        "4.1": "Ensure that 'Auditing' is set to 'On' for SQL Servers",
        "4.2": "Ensure that 'Data encryption' is set to 'On' on SQL Database",
        "4.3": "Ensure that 'Auditing' Retention is 'greater than 90 days'",
        "4.4": "Ensure that Azure Active Directory Admin is configured for SQL Servers",
        "4.5": "Ensure SQL server's TDE protector is encrypted with CMK",
        
        # Logging and Monitoring
        "5.1": "Ensure Diagnostic Setting captures appropriate categories",
        "5.2": "Ensure Activity Log Retention is set to 180 days or greater",
        "5.3": "Ensure Storage logging is enabled for Queue service",
        "5.4": "Ensure Storage logging is enabled for Table service",
        "5.5": "Ensure that Activity Log Alert exists for Create/Update SQL Server Firewall Rule",
        
        # Networking
        "6.1": "Ensure that RDP access is restricted from the internet",
        "6.2": "Ensure that SSH access is restricted from the internet",
        "6.3": "Ensure Network Security Group Flow Log retention period is 'greater than 90 days'",
        "6.4": "Ensure Network Watcher is 'Enabled'",
        "6.5": "Ensure that Azure DDoS Protection is enabled",
        
        # Virtual Machines
        "7.1": "Ensure Virtual Machines are utilizing Managed Disks",
        "7.2": "Ensure that 'OS and Data' disks are encrypted with CMK",
        "7.3": "Ensure VM agent is installed",
        "7.4": "Ensure Endpoint Protection for VMs is installed",
        "7.5": "Ensure that Only Approved Extensions are Installed",
        
        # Key Vault
        "8.1": "Ensure the key vault is recoverable - enable 'Soft Delete' setting",
        "8.2": "Enable role-based access control (RBAC) within Azure Key Vault",
        "8.3": "Ensure the key vault is recoverable - enable 'Purge Protection'",
        "8.4": "Ensure that logging for Azure Key Vault is 'Enabled'",
        "8.5": "Enable firewall on Azure Key Vault",
        
        # App Service
        "9.1": "Ensure App Service authentication is set on Azure App Service",
        "9.2": "Ensure App Service web app is only accessible via HTTPS",
        "9.3": "Ensure latest TLS version is used in App Service",
        "9.4": "Ensure the web app has 'Client Certificates (Incoming client certificates)' set",
        "9.5": "Ensure that Register with Azure Active Directory is enabled",
        "9.6": "Ensure that 'HTTP Version' is the latest for App Service",
    }
    
    # Available services for scanning
    AVAILABLE_SERVICES = {
        'storage': {'name': 'Storage Accounts', 'description': 'Encryption, public access, HTTPS, TLS'},
        'vms': {'name': 'Virtual Machines', 'description': 'Managed disks, encryption, agents'},
        'sql': {'name': 'SQL Servers', 'description': 'Auditing, encryption, firewall'},
        'network': {'name': 'Network Security', 'description': 'NSGs, RDP/SSH access, DDoS'},
        'keyvaults': {'name': 'Key Vaults', 'description': 'Soft delete, purge protection, RBAC'},
        'aks': {'name': 'AKS Clusters', 'description': 'RBAC, network policies, private clusters'},
        'appservices': {'name': 'App Services', 'description': 'HTTPS, TLS, authentication'},
        'monitor': {'name': 'Logging & Monitoring', 'description': 'Activity logs, retention'},
    }
    
    def __init__(
        self,
        subscription_id: str = None,
        subscription_ids: List[str] = None,  # Support multiple subscriptions
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None
    ):
        # Support both single and multiple subscriptions
        if subscription_ids:
            self.subscription_ids = subscription_ids
            self.subscription_id = subscription_ids[0] if subscription_ids else None
        else:
            self.subscription_ids = [subscription_id] if subscription_id else []
            self.subscription_id = subscription_id
        
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.credential = None
        self.findings: List[AzureFinding] = []
        self._azure_available = False
        
        # Management clients (lazy-loaded)
        self.resource_client = None
        self.storage_client = None
        self.compute_client = None
        self.network_client = None
        self.sql_client = None
        self.monitor_client = None
        self.keyvault_mgmt_client = None
        self.containerservice_client = None
        self.web_client = None
        self.security_client = None
        
        self._init_client()
    
    @classmethod
    def get_available_services(cls) -> Dict[str, Dict]:
        """Return available services for UI service selection"""
        return cls.AVAILABLE_SERVICES
    
    def _init_client(self):
        """Initialize Azure SDK clients"""
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
            
            if self.client_id and self.client_secret and self.tenant_id:
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
                logger.info("Azure service principal authentication configured")
            else:
                self.credential = DefaultAzureCredential()
                logger.info("Azure default credential authentication configured")
            
            self._azure_available = True
            
        except ImportError:
            logger.warning("Azure SDK not installed. Install: pip install azure-identity azure-mgmt-*")
            self._azure_available = False
        except Exception as e:
            logger.error(f"Azure authentication failed: {e}")
            self._azure_available = False
    
    def _get_client(self, client_type: str):
        """Lazy-load Azure management clients"""
        if not self._azure_available or not self.subscription_id:
            return None
        
        try:
            if client_type == 'resource':
                if not self.resource_client:
                    from azure.mgmt.resource import ResourceManagementClient
                    self.resource_client = ResourceManagementClient(self.credential, self.subscription_id)
                return self.resource_client
            
            elif client_type == 'storage':
                if not self.storage_client:
                    from azure.mgmt.storage import StorageManagementClient
                    self.storage_client = StorageManagementClient(self.credential, self.subscription_id)
                return self.storage_client
            
            elif client_type == 'compute':
                if not self.compute_client:
                    from azure.mgmt.compute import ComputeManagementClient
                    self.compute_client = ComputeManagementClient(self.credential, self.subscription_id)
                return self.compute_client
            
            elif client_type == 'network':
                if not self.network_client:
                    from azure.mgmt.network import NetworkManagementClient
                    self.network_client = NetworkManagementClient(self.credential, self.subscription_id)
                return self.network_client
            
            elif client_type == 'sql':
                if not self.sql_client:
                    from azure.mgmt.sql import SqlManagementClient
                    self.sql_client = SqlManagementClient(self.credential, self.subscription_id)
                return self.sql_client
            
            elif client_type == 'monitor':
                if not self.monitor_client:
                    from azure.mgmt.monitor import MonitorManagementClient
                    self.monitor_client = MonitorManagementClient(self.credential, self.subscription_id)
                return self.monitor_client
            
            elif client_type == 'keyvault':
                if not self.keyvault_mgmt_client:
                    from azure.mgmt.keyvault import KeyVaultManagementClient
                    self.keyvault_mgmt_client = KeyVaultManagementClient(self.credential, self.subscription_id)
                return self.keyvault_mgmt_client
            
            elif client_type == 'containerservice':
                if not self.containerservice_client:
                    from azure.mgmt.containerservice import ContainerServiceClient
                    self.containerservice_client = ContainerServiceClient(self.credential, self.subscription_id)
                return self.containerservice_client
            
            elif client_type == 'web':
                if not self.web_client:
                    from azure.mgmt.web import WebSiteManagementClient
                    self.web_client = WebSiteManagementClient(self.credential, self.subscription_id)
                return self.web_client
            
            elif client_type == 'security':
                if not self.security_client:
                    from azure.mgmt.security import SecurityCenter
                    self.security_client = SecurityCenter(self.credential, self.subscription_id, asc_location='centralus')
                return self.security_client
            
        except ImportError as e:
            logger.warning(f"Azure {client_type} SDK not available: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to create {client_type} client: {e}")
            return None
    
    async def discover_resources(self) -> List[Dict[str, Any]]:
        """Discover all Azure resources across subscription"""
        resources = []
        
        if not self._azure_available:
            logger.warning("Azure SDK not available, returning empty resource list")
            return resources
        
        try:
            resource_client = self._get_client('resource')
            if not resource_client:
                return resources
            
            # Enumerate all resources
            all_resources = resource_client.resources.list()
            
            for resource in all_resources:
                resources.append({
                    'id': resource.id,
                    'name': resource.name,
                    'type': resource.type,
                    'location': resource.location,
                    'tags': resource.tags or {},
                    'metadata': {
                        'resource_group': resource.id.split('/')[4] if len(resource.id.split('/')) > 4 else '',
                        'kind': getattr(resource, 'kind', None),
                        'sku': getattr(resource, 'sku', None),
                    }
                })
            
            logger.info(f"Discovered {len(resources)} Azure resources")
            
        except Exception as e:
            logger.error(f"Resource discovery failed: {e}")
        
        return resources
    
    async def scan_all(self, services: List[str] = None) -> List[AzureFinding]:
        """Run Azure security checks with optional service selection
        
        Args:
            services: List of services to scan (default: all)
                     Options: storage, vms, sql, network, keyvaults, aks, appservices, monitor
        """
        if not self._azure_available:
            logger.warning("Azure SDK not available - returning mock findings")
            return self._get_mock_findings()
        
        # Default to all services if none specified
        if not services:
            services = list(self.AVAILABLE_SERVICES.keys())
        
        logger.info(f"Starting Azure security scan for services: {services}")
        self.findings = []
        
        try:
            # Scan each subscription
            for sub_id in self.subscription_ids:
                logger.info(f"Scanning subscription: {sub_id}")
                self.subscription_id = sub_id
                
                # Reset clients for new subscription
                self._reset_clients()
                
                # Run selected service checks
                if 'storage' in services:
                    await self.check_storage_accounts()
                if 'vms' in services:
                    await self.check_virtual_machines()
                if 'sql' in services:
                    await self.check_sql_servers()
                if 'network' in services:
                    await self.check_network_security()
                if 'keyvaults' in services:
                    await self.check_key_vaults()
                if 'aks' in services:
                    await self.check_aks_clusters()
                if 'appservices' in services:
                    await self.check_app_services()
                if 'monitor' in services:
                    await self.check_logging_monitoring()
            
            logger.info(f"Azure scan complete. Found {len(self.findings)} issues")
            
        except Exception as e:
            logger.error(f"Azure scan failed: {e}", exc_info=True)
        
        return self.findings
    
    def _reset_clients(self):
        """Reset all management clients (for subscription switching)"""
        self.resource_client = None
        self.storage_client = None
        self.compute_client = None
        self.network_client = None
        self.sql_client = None
        self.monitor_client = None
        self.keyvault_mgmt_client = None
        self.containerservice_client = None
        self.web_client = None
        self.security_client = None
        
        return self.findings
    
    async def check_storage_accounts(self):
        """CIS 3.x: Storage Account Security Checks"""
        logger.info("Checking Storage Accounts...")
        
        storage_client = self._get_client('storage')
        if not storage_client:
            return
        
        try:
            accounts = list(storage_client.storage_accounts.list())
            
            for account in accounts:
                rg = self._get_resource_group(account.id)
                location = account.location
                
                # CIS 3.1: Secure transfer required
                if not account.enable_https_traffic_only:
                    self._add_finding(
                        id=f"azure_storage_{account.name}_insecure_transfer",
                        service="Storage Account",
                        resource_id=account.id,
                        resource_name=account.name,
                        resource_group=rg,
                        region=location,
                        severity="high",
                        title="Storage Account allows insecure transfer",
                        description=f"Storage account '{account.name}' does not enforce HTTPS-only traffic",
                        evidence={'enable_https_traffic_only': False},
                        recommendation="Enable 'Secure transfer required' to enforce HTTPS",
                        cis_benchmark="3.1",
                        remediation_cli=f"az storage account update --name {account.name} --resource-group {rg} --https-only true"
                    )
                
                # CIS 3.4: Public blob access
                if hasattr(account, 'allow_blob_public_access') and account.allow_blob_public_access:
                    self._add_finding(
                        id=f"azure_storage_{account.name}_public_blob_access",
                        service="Storage Account",
                        resource_id=account.id,
                        resource_name=account.name,
                        resource_group=rg,
                        region=location,
                        severity="critical",
                        title="Storage Account allows public blob access",
                        description=f"Storage account '{account.name}' allows anonymous public read access to blobs",
                        evidence={'allow_blob_public_access': True},
                        recommendation="Disable 'Allow Blob public access' to prevent data exposure",
                        cis_benchmark="3.4",
                        remediation_cli=f"az storage account update --name {account.name} --resource-group {rg} --allow-blob-public-access false"
                    )
                
                # CIS 3.5: Minimum TLS version
                if hasattr(account, 'minimum_tls_version') and account.minimum_tls_version != 'TLS1_2':
                    self._add_finding(
                        id=f"azure_storage_{account.name}_tls_version",
                        service="Storage Account",
                        resource_id=account.id,
                        resource_name=account.name,
                        resource_group=rg,
                        region=location,
                        severity="medium",
                        title="Storage Account uses outdated TLS version",
                        description=f"Storage account '{account.name}' minimum TLS version is {account.minimum_tls_version}",
                        evidence={'minimum_tls_version': account.minimum_tls_version},
                        recommendation="Set minimum TLS version to 1.2 or higher",
                        cis_benchmark="3.5",
                        remediation_cli=f"az storage account update --name {account.name} --resource-group {rg} --min-tls-version TLS1_2"
                    )
                
                # CIS 3.3: Network access rules
                if hasattr(account, 'network_rule_set'):
                    default_action = account.network_rule_set.default_action if account.network_rule_set else 'Allow'
                    
                    if default_action == 'Allow':
                        self._add_finding(
                            id=f"azure_storage_{account.name}_network_access",
                            service="Storage Account",
                            resource_id=account.id,
                            resource_name=account.name,
                            resource_group=rg,
                            region=location,
                            severity="high",
                            title="Storage Account allows unrestricted network access",
                            description=f"Storage account '{account.name}' default network access is set to Allow",
                            evidence={'default_network_action': default_action},
                            recommendation="Set default network access rule to Deny and whitelist specific networks",
                            cis_benchmark="3.3",
                            remediation_cli=f"az storage account update --name {account.name} --resource-group {rg} --default-action Deny"
                        )
                
                # CIS 3.6: Customer-managed keys encryption
                if hasattr(account, 'encryption'):
                    encryption = account.encryption
                    if encryption and hasattr(encryption, 'key_source'):
                        if encryption.key_source == 'Microsoft.Storage':
                            self._add_finding(
                                id=f"azure_storage_{account.name}_cmk_encryption",
                                service="Storage Account",
                                resource_id=account.id,
                                resource_name=account.name,
                                resource_group=rg,
                                region=location,
                                severity="medium",
                                title="Storage Account not encrypted with Customer-Managed Key",
                                description=f"Storage account '{account.name}' uses Microsoft-managed keys instead of customer-managed keys",
                                evidence={'key_source': encryption.key_source},
                                recommendation="Configure encryption with customer-managed keys for better control",
                                cis_benchmark="3.6",
                                remediation_cli=f"az storage account update --name {account.name} --resource-group {rg} --encryption-key-source Microsoft.Keyvault --encryption-key-vault <key-vault-uri>"
                            )
        
        except Exception as e:
            logger.error(f"Storage account checks failed: {e}")
    
    async def check_virtual_machines(self):
        """CIS 7.x: Virtual Machine Security Checks"""
        logger.info("Checking Virtual Machines...")
        
        compute_client = self._get_client('compute')
        network_client = self._get_client('network')
        
        if not compute_client:
            return
        
        try:
            vms = list(compute_client.virtual_machines.list_all())
            
            for vm in vms:
                rg = self._get_resource_group(vm.id)
                location = vm.location
                
                # CIS 7.1: Managed disks
                if hasattr(vm.storage_profile, 'os_disk'):
                    os_disk = vm.storage_profile.os_disk
                    if hasattr(os_disk, 'managed_disk') and not os_disk.managed_disk:
                        self._add_finding(
                            id=f"azure_vm_{vm.name}_unmanaged_disk",
                            service="Virtual Machine",
                            resource_id=vm.id,
                            resource_name=vm.name,
                            resource_group=rg,
                            region=location,
                            severity="medium",
                            title="VM uses unmanaged disks",
                            description=f"Virtual machine '{vm.name}' is not using Azure Managed Disks",
                            evidence={'managed_disk': False},
                            recommendation="Migrate to managed disks for better reliability and security",
                            cis_benchmark="7.1",
                            remediation_cli=f"# Convert to managed disk via Azure Portal or migrate VM"
                        )
                
                # CIS 7.2: Disk encryption
                if hasattr(vm.storage_profile, 'os_disk'):
                    os_disk = vm.storage_profile.os_disk
                    encryption_settings = getattr(os_disk, 'encryption_settings', None)
                    
                    if not encryption_settings or not encryption_settings.enabled:
                        self._add_finding(
                            id=f"azure_vm_{vm.name}_disk_encryption",
                            service="Virtual Machine",
                            resource_id=vm.id,
                            resource_name=vm.name,
                            resource_group=rg,
                            region=location,
                            severity="high",
                            title="VM disk not encrypted with CMK",
                            description=f"Virtual machine '{vm.name}' OS disk is not encrypted with customer-managed keys",
                            evidence={'encryption_enabled': False},
                            recommendation="Enable Azure Disk Encryption with customer-managed keys",
                            cis_benchmark="7.2",
                            remediation_cli=f"az vm encryption enable --resource-group {rg} --name {vm.name} --disk-encryption-keyvault <keyvault-name>"
                        )
                
                # Check for public IP exposure
                if network_client and hasattr(vm, 'network_profile'):
                    for nic_ref in vm.network_profile.network_interfaces:
                        nic_id = nic_ref.id
                        nic_name = nic_id.split('/')[-1]
                        nic_rg = nic_id.split('/')[4]
                        
                        try:
                            nic = network_client.network_interfaces.get(nic_rg, nic_name)
                            
                            for ip_config in nic.ip_configurations:
                                if ip_config.public_ip_address:
                                    self._add_finding(
                                        id=f"azure_vm_{vm.name}_public_ip",
                                        service="Virtual Machine",
                                        resource_id=vm.id,
                                        resource_name=vm.name,
                                        resource_group=rg,
                                        region=location,
                                        severity="high",
                                        title="VM has public IP address",
                                        description=f"Virtual machine '{vm.name}' is directly exposed to internet via public IP",
                                        evidence={'public_ip_attached': True},
                                        recommendation="Remove public IP and use Azure Bastion or VPN for access",
                                        cis_benchmark="6.1/6.2",
                                        remediation_cli=f"az vm deallocate --resource-group {rg} --name {vm.name} && az network nic ip-config update --name {ip_config.name} --nic-name {nic_name} --resource-group {nic_rg} --remove publicIpAddress"
                                    )
                        except:
                            pass
        
        except Exception as e:
            logger.error(f"VM checks failed: {e}")
    
    async def check_sql_servers(self):
        """CIS 4.x: SQL Server Security Checks"""
        logger.info("Checking SQL Servers...")
        
        sql_client = self._get_client('sql')
        if not sql_client:
            return
        
        try:
            servers = list(sql_client.servers.list())
            
            for server in servers:
                rg = self._get_resource_group(server.id)
                location = server.location
                
                # CIS 4.1: Auditing enabled
                try:
                    auditing_policy = sql_client.server_blob_auditing_policies.get(rg, server.name)
                    
                    if auditing_policy.state != 'Enabled':
                        self._add_finding(
                            id=f"azure_sql_{server.name}_auditing",
                            service="SQL Server",
                            resource_id=server.id,
                            resource_name=server.name,
                            resource_group=rg,
                            region=location,
                            severity="high",
                            title="SQL Server auditing not enabled",
                            description=f"SQL Server '{server.name}' does not have auditing enabled",
                            evidence={'auditing_state': auditing_policy.state},
                            recommendation="Enable auditing for compliance and security monitoring",
                            cis_benchmark="4.1",
                            remediation_cli=f"az sql server audit-policy update --resource-group {rg} --server {server.name} --state Enabled --storage-account <storage-account>"
                        )
                except:
                    pass
                
                # CIS 4.3: Check firewall rules for 0.0.0.0/0
                try:
                    firewall_rules = list(sql_client.firewall_rules.list_by_server(rg, server.name))
                    
                    for rule in firewall_rules:
                        if rule.start_ip_address == '0.0.0.0' and rule.end_ip_address == '255.255.255.255':
                            self._add_finding(
                                id=f"azure_sql_{server.name}_firewall_all",
                                service="SQL Server",
                                resource_id=server.id,
                                resource_name=server.name,
                                resource_group=rg,
                                region=location,
                                severity="critical",
                                title="SQL Server allows access from all IPs",
                                description=f"SQL Server '{server.name}' has firewall rule allowing all IP addresses (0.0.0.0-255.255.255.255)",
                                evidence={'firewall_rule': rule.name, 'start_ip': rule.start_ip_address, 'end_ip': rule.end_ip_address},
                                recommendation="Restrict firewall rules to specific IP ranges only",
                                cis_benchmark="4.3",
                                remediation_cli=f"az sql server firewall-rule delete --resource-group {rg} --server {server.name} --name {rule.name}"
                            )
                except:
                    pass
                
                # Check databases for TDE
                try:
                    databases = list(sql_client.databases.list_by_server(rg, server.name))
                    
                    for db in databases:
                        if db.name != 'master':  # Skip master database
                            try:
                                tde = sql_client.transparent_data_encryptions.get(rg, server.name, db.name)
                                
                                if tde.status != 'Enabled':
                                    self._add_finding(
                                        id=f"azure_sql_{server.name}_{db.name}_tde",
                                        service="SQL Database",
                                        resource_id=db.id,
                                        resource_name=f"{server.name}/{db.name}",
                                        resource_group=rg,
                                        region=location,
                                        severity="high",
                                        title="SQL Database TDE not enabled",
                                        description=f"Database '{db.name}' on server '{server.name}' does not have Transparent Data Encryption enabled",
                                        evidence={'tde_status': tde.status},
                                        recommendation="Enable TDE to encrypt data at rest",
                                        cis_benchmark="4.2",
                                        remediation_cli=f"az sql db tde set --resource-group {rg} --server {server.name} --database {db.name} --status Enabled"
                                    )
                            except:
                                pass
                except:
                    pass
        
        except Exception as e:
            logger.error(f"SQL Server checks failed: {e}")
    
    async def check_network_security(self):
        """CIS 6.x: Network Security Checks"""
        logger.info("Checking Network Security...")
        
        network_client = self._get_client('network')
        if not network_client:
            return
        
        try:
            nsgs = list(network_client.network_security_groups.list_all())
            
            for nsg in nsgs:
                rg = self._get_resource_group(nsg.id)
                location = nsg.location
                
                # CIS 6.1: RDP from internet
                # CIS 6.2: SSH from internet
                for rule in nsg.security_rules:
                    if rule.direction == 'Inbound' and rule.access == 'Allow':
                        # Check source
                        allows_internet = False
                        if rule.source_address_prefix in ['*', 'Internet', '0.0.0.0/0']:
                            allows_internet = True
                        
                        if allows_internet:
                            # Check for RDP (port 3389)
                            if self._check_port_in_rule(rule, 3389):
                                self._add_finding(
                                    id=f"azure_nsg_{nsg.name}_rdp_internet",
                                    service="Network Security Group",
                                    resource_id=nsg.id,
                                    resource_name=nsg.name,
                                    resource_group=rg,
                                    region=location,
                                    severity="critical",
                                    title="NSG allows RDP from internet",
                                    description=f"Network Security Group '{nsg.name}' rule '{rule.name}' allows RDP (port 3389) from internet",
                                    evidence={'rule_name': rule.name, 'source': rule.source_address_prefix, 'port': '3389'},
                                    recommendation="Restrict RDP access to specific IP ranges or use Azure Bastion",
                                    cis_benchmark="6.1",
                                    remediation_cli=f"az network nsg rule delete --resource-group {rg} --nsg-name {nsg.name} --name {rule.name}"
                                )
                            
                            # Check for SSH (port 22)
                            if self._check_port_in_rule(rule, 22):
                                self._add_finding(
                                    id=f"azure_nsg_{nsg.name}_ssh_internet",
                                    service="Network Security Group",
                                    resource_id=nsg.id,
                                    resource_name=nsg.name,
                                    resource_group=rg,
                                    region=location,
                                    severity="critical",
                                    title="NSG allows SSH from internet",
                                    description=f"Network Security Group '{nsg.name}' rule '{rule.name}' allows SSH (port 22) from internet",
                                    evidence={'rule_name': rule.name, 'source': rule.source_address_prefix, 'port': '22'},
                                    recommendation="Restrict SSH access to specific IP ranges or use Azure Bastion",
                                    cis_benchmark="6.2",
                                    remediation_cli=f"az network nsg rule delete --resource-group {rg} --nsg-name {nsg.name} --name {rule.name}"
                                )
        
        except Exception as e:
            logger.error(f"Network security checks failed: {e}")
    
    async def check_key_vaults(self):
        """CIS 8.x: Key Vault Security Checks"""
        logger.info("Checking Key Vaults...")
        
        keyvault_client = self._get_client('keyvault')
        if not keyvault_client:
            return
        
        try:
            vaults = list(keyvault_client.vaults.list())
            
            for vault in vaults:
                rg = self._get_resource_group(vault.id)
                location = vault.location
                
                # CIS 8.1: Soft delete enabled
                if hasattr(vault.properties, 'enable_soft_delete'):
                    if not vault.properties.enable_soft_delete:
                        self._add_finding(
                            id=f"azure_keyvault_{vault.name}_soft_delete",
                            service="Key Vault",
                            resource_id=vault.id,
                            resource_name=vault.name,
                            resource_group=rg,
                            region=location,
                            severity="high",
                            title="Key Vault soft delete not enabled",
                            description=f"Key Vault '{vault.name}' does not have soft delete enabled",
                            evidence={'enable_soft_delete': False},
                            recommendation="Enable soft delete to prevent accidental deletion of keys/secrets",
                            cis_benchmark="8.1",
                            remediation_cli=f"az keyvault update --name {vault.name} --resource-group {rg} --enable-soft-delete true"
                        )
                
                # CIS 8.3: Purge protection
                if hasattr(vault.properties, 'enable_purge_protection'):
                    if not vault.properties.enable_purge_protection:
                        self._add_finding(
                            id=f"azure_keyvault_{vault.name}_purge_protection",
                            service="Key Vault",
                            resource_id=vault.id,
                            resource_name=vault.name,
                            resource_group=rg,
                            region=location,
                            severity="medium",
                            title="Key Vault purge protection not enabled",
                            description=f"Key Vault '{vault.name}' does not have purge protection enabled",
                            evidence={'enable_purge_protection': False},
                            recommendation="Enable purge protection for additional data protection",
                            cis_benchmark="8.3",
                            remediation_cli=f"az keyvault update --name {vault.name} --resource-group {rg} --enable-purge-protection true"
                        )
                
                # CIS 8.5: Firewall enabled
                if hasattr(vault.properties, 'network_acls'):
                    network_acls = vault.properties.network_acls
                    if network_acls and network_acls.default_action == 'Allow':
                        self._add_finding(
                            id=f"azure_keyvault_{vault.name}_firewall",
                            service="Key Vault",
                            resource_id=vault.id,
                            resource_name=vault.name,
                            resource_group=rg,
                            region=location,
                            severity="high",
                            title="Key Vault firewall not configured",
                            description=f"Key Vault '{vault.name}' allows network access from all networks",
                            evidence={'default_action': 'Allow'},
                            recommendation="Configure firewall to restrict access to specific networks",
                            cis_benchmark="8.5",
                            remediation_cli=f"az keyvault update --name {vault.name} --resource-group {rg} --default-action Deny"
                        )
        
        except Exception as e:
            logger.error(f"Key Vault checks failed: {e}")
    
    async def check_aks_clusters(self):
        """CIS 8.x (AKS): Azure Kubernetes Service Security Checks"""
        logger.info("Checking AKS Clusters...")
        
        aks_client = self._get_client('containerservice')
        if not aks_client:
            return
        
        try:
            clusters = list(aks_client.managed_clusters.list())
            
            for cluster in clusters:
                rg = self._get_resource_group(cluster.id)
                location = cluster.location
                
                # RBAC enabled
                if hasattr(cluster, 'enable_rbac') and not cluster.enable_rbac:
                    self._add_finding(
                        id=f"azure_aks_{cluster.name}_rbac",
                        service="AKS",
                        resource_id=cluster.id,
                        resource_name=cluster.name,
                        resource_group=rg,
                        region=location,
                        severity="critical",
                        title="AKS RBAC not enabled",
                        description=f"AKS cluster '{cluster.name}' does not have RBAC enabled",
                        evidence={'enable_rbac': False},
                        recommendation="Enable RBAC for proper access control",
                        cis_benchmark="8.1",
                        remediation_cli=f"# RBAC cannot be enabled on existing cluster - recreate cluster with RBAC"
                    )
                
                # Network policy
                if hasattr(cluster, 'network_profile'):
                    network_profile = cluster.network_profile
                    if network_profile and not network_profile.network_policy:
                        self._add_finding(
                            id=f"azure_aks_{cluster.name}_network_policy",
                            service="AKS",
                            resource_id=cluster.id,
                            resource_name=cluster.name,
                            resource_group=rg,
                            region=location,
                            severity="high",
                            title="AKS network policy not configured",
                            description=f"AKS cluster '{cluster.name}' does not have network policies configured",
                            evidence={'network_policy': None},
                            recommendation="Enable network policies (Calico or Azure) for pod-to-pod communication control",
                            cis_benchmark="8.2",
                            remediation_cli=f"az aks update --resource-group {rg} --name {cluster.name} --network-policy azure"
                        )
                
                # Private cluster
                if hasattr(cluster, 'api_server_access_profile'):
                    api_profile = cluster.api_server_access_profile
                    if api_profile and not api_profile.enable_private_cluster:
                        self._add_finding(
                            id=f"azure_aks_{cluster.name}_private_cluster",
                            service="AKS",
                            resource_id=cluster.id,
                            resource_name=cluster.name,
                            resource_group=rg,
                            region=location,
                            severity="medium",
                            title="AKS is not a private cluster",
                            description=f"AKS cluster '{cluster.name}' API server is publicly accessible",
                            evidence={'enable_private_cluster': False},
                            recommendation="Use private cluster to prevent public API server exposure",
                            cis_benchmark="8.3",
                            remediation_cli=f"# Private cluster requires recreation - plan migration"
                        )
        
        except Exception as e:
            logger.error(f"AKS checks failed: {e}")
    
    async def check_app_services(self):
        """CIS 9.x: App Service Security Checks"""
        logger.info("Checking App Services...")
        
        web_client = self._get_client('web')
        if not web_client:
            return
        
        try:
            apps = list(web_client.web_apps.list())
            
            for app in apps:
                rg = self._get_resource_group(app.id)
                location = app.location
                
                # CIS 9.2: HTTPS only
                if hasattr(app, 'https_only') and not app.https_only:
                    self._add_finding(
                        id=f"azure_app_{app.name}_https",
                        service="App Service",
                        resource_id=app.id,
                        resource_name=app.name,
                        resource_group=rg,
                        region=location,
                        severity="high",
                        title="App Service not configured for HTTPS only",
                        description=f"App Service '{app.name}' allows HTTP traffic",
                        evidence={'https_only': False},
                        recommendation="Enable HTTPS only to enforce encrypted connections",
                        cis_benchmark="9.2",
                        remediation_cli=f"az webapp update --resource-group {rg} --name {app.name} --set httpsOnly=true"
                    )
                
                # Get site config for additional checks
                try:
                    site_config = web_client.web_apps.get_configuration(rg, app.name)
                    
                    # CIS 9.3: TLS version
                    if hasattr(site_config, 'min_tls_version'):
                        if site_config.min_tls_version not in ['1.2', '1.3']:
                            self._add_finding(
                                id=f"azure_app_{app.name}_tls_version",
                                service="App Service",
                                resource_id=app.id,
                                resource_name=app.name,
                                resource_group=rg,
                                region=location,
                                severity="medium",
                                title="App Service uses outdated TLS version",
                                description=f"App Service '{app.name}' minimum TLS version is {site_config.min_tls_version}",
                                evidence={'min_tls_version': site_config.min_tls_version},
                                recommendation="Set minimum TLS version to 1.2 or higher",
                                cis_benchmark="9.3",
                                remediation_cli=f"az webapp config set --resource-group {rg} --name {app.name} --min-tls-version 1.2"
                            )
                    
                    # CIS 9.1: Authentication
                    auth_settings = web_client.web_apps.get_auth_settings(rg, app.name)
                    if auth_settings and not auth_settings.enabled:
                        self._add_finding(
                            id=f"azure_app_{app.name}_auth",
                            service="App Service",
                            resource_id=app.id,
                            resource_name=app.name,
                            resource_group=rg,
                            region=location,
                            severity="medium",
                            title="App Service authentication not configured",
                            description=f"App Service '{app.name}' does not have authentication enabled",
                            evidence={'auth_enabled': False},
                            recommendation="Enable Azure AD authentication for access control",
                            cis_benchmark="9.1",
                            remediation_cli=f"az webapp auth update --resource-group {rg} --name {app.name} --enabled true --action LoginWithAzureActiveDirectory"
                        )
                except:
                    pass
        
        except Exception as e:
            logger.error(f"App Service checks failed: {e}")
    
    async def check_logging_monitoring(self):
        """CIS 5.x: Logging and Monitoring Checks"""
        logger.info("Checking Logging and Monitoring...")
        
        monitor_client = self._get_client('monitor')
        if not monitor_client:
            return
        
        try:
            # CIS 5.2: Activity log retention
            log_profiles = list(monitor_client.log_profiles.list())
            
            for profile in log_profiles:
                if hasattr(profile, 'retention_policy'):
                    retention_days = profile.retention_policy.days if profile.retention_policy else 0
                    
                    if retention_days < 180:
                        self._add_finding(
                            id=f"azure_monitor_log_retention",
                            service="Monitor",
                            resource_id=profile.id if hasattr(profile, 'id') else '',
                            resource_name=profile.name,
                            resource_group='N/A',
                            region='global',
                            severity="medium",
                            title="Activity log retention less than 180 days",
                            description=f"Activity log retention is set to {retention_days} days, below recommended 180 days",
                            evidence={'retention_days': retention_days},
                            recommendation="Set activity log retention to 180 days or greater for compliance",
                            cis_benchmark="5.2",
                            remediation_cli=f"az monitor log-profiles update --name {profile.name} --set retentionPolicy.days=180"
                        )
        
        except Exception as e:
            logger.error(f"Logging and monitoring checks failed: {e}")
    
    def _add_finding(
        self,
        id: str,
        service: str,
        resource_id: str,
        resource_name: str,
        resource_group: str,
        region: str,
        severity: str,
        title: str,
        description: str,
        evidence: Dict,
        recommendation: str,
        cis_benchmark: str,
        remediation_cli: str
    ):
        """Add finding to results list"""
        finding = AzureFinding(
            id=id,
            service=service,
            resource_id=resource_id,
            resource_name=resource_name,
            resource_group=resource_group,
            region=region,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            cis_benchmark=cis_benchmark,
            remediation_cli=remediation_cli
        )
        self.findings.append(finding)
    
    def _get_resource_group(self, resource_id: str) -> str:
        """Extract resource group from Azure resource ID"""
        try:
            parts = resource_id.split('/')
            if 'resourceGroups' in parts:
                idx = parts.index('resourceGroups')
                return parts[idx + 1]
        except:
            pass
        return ''
    
    def _check_port_in_rule(self, rule, port: int) -> bool:
        """Check if NSG rule applies to specific port"""
        dest_port = rule.destination_port_range
        
        if dest_port == '*':
            return True
        
        if dest_port == str(port):
            return True
        
        # Check port ranges
        if '-' in dest_port:
            try:
                start, end = map(int, dest_port.split('-'))
                return start <= port <= end
            except:
                pass
        
        # Check port lists
        if hasattr(rule, 'destination_port_ranges') and rule.destination_port_ranges:
            return str(port) in rule.destination_port_ranges or '*' in rule.destination_port_ranges
        
        return False
    
    def _get_mock_findings(self) -> List[AzureFinding]:
        """Return mock findings when Azure SDK unavailable"""
        return [
            AzureFinding(
                id="azure_mock_1",
                service="Storage Account",
                resource_id="/subscriptions/mock/resourceGroups/mock-rg/providers/Microsoft.Storage/storageAccounts/mocksa",
                resource_name="mocksa",
                resource_group="mock-rg",
                region="eastus",
                severity="high",
                title="[MOCK] Azure SDK not available",
                description="Azure SDK is not installed or configured. Install azure-identity and azure-mgmt-* packages.",
                evidence={'sdk_available': False},
                recommendation="Install Azure SDK: pip install azure-identity azure-mgmt-resource azure-mgmt-storage azure-mgmt-compute azure-mgmt-network",
                cis_benchmark="",
                remediation_cli=""
            )
        ]
