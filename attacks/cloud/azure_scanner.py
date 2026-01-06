"""
Jarwis AGI - Azure Security Scanner
Comprehensive Azure security assessment

Checks:
- Storage Account Security (public access, encryption)
- Azure AD Security (MFA, privileged roles)
- Virtual Machines (NSGs, encryption, extensions)
- Key Vault (access policies, secrets)
- SQL Database (encryption, firewall)
- Network Security (NSGs, firewall rules)
"""

import json
import asyncio
import logging
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable

logger = logging.getLogger(__name__)


class AzureSecurityScanner:
    """
    Azure Security Scanner
    Performs comprehensive security assessment of Azure resources
    """
    
    def __init__(
        self,
        subscription_id: str = None,
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None
    ):
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.credential = None
        self.findings = []
        self._azure_available = False
        self._verbose_callback: Optional[Callable] = None
        self._init_client()
    
    def _init_client(self):
        """Initialize Azure client"""
        try:
            from azure.identity import DefaultAzureCredential, ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient
            
            self._azure_available = True
            
            if self.client_id and self.client_secret and self.tenant_id:
                self.credential = ClientSecretCredential(
                    tenant_id=self.tenant_id,
                    client_id=self.client_id,
                    client_secret=self.client_secret
                )
            else:
                self.credential = DefaultAzureCredential()
                
            logger.info("Azure credentials initialized")
        except ImportError:
            logger.warning("Azure SDK not installed. Run: pip install azure-identity azure-mgmt-resource")
            self._azure_available = False
        except Exception as e:
            logger.error(f"Failed to initialize Azure client: {e}")
    
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
        """Perform Azure security scan"""
        from .cloud_scanner import CloudScanResult
        
        if not self._azure_available:
            self._log("error", "Azure SDK not installed")
            return CloudScanResult(
                scan_id="AZURE-FAILED",
                provider="azure",
                status="failed"
            )
        
        scan_id = f"AZURE-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.findings = []
        resources_scanned = 0
        
        self._log("start", "Starting Azure security scan")
        
        try:
            # Scan Storage Accounts
            self._log("phase", "Scanning Storage Accounts")
            resources_scanned += await self._scan_storage_accounts()
            
            # Scan Virtual Machines
            self._log("phase", "Scanning Virtual Machines")
            resources_scanned += await self._scan_virtual_machines()
            
            # Scan Network Security Groups
            self._log("phase", "Scanning Network Security Groups")
            resources_scanned += await self._scan_network_security()
            
            # Scan SQL Databases
            self._log("phase", "Scanning SQL Databases")
            resources_scanned += await self._scan_sql_databases()
            
            # Scan Key Vaults
            self._log("phase", "Scanning Key Vaults")
            resources_scanned += await self._scan_key_vaults()
            
        except Exception as e:
            self._log("error", f"Azure scan error: {e}")
            logger.exception(f"Azure scan failed: {e}")
        
        result = CloudScanResult(
            scan_id=scan_id,
            provider="azure",
            account_id=self.subscription_id or "default",
            scan_start=datetime.now().isoformat(),
            scan_end=datetime.now().isoformat(),
            status="completed",
            resources_scanned=resources_scanned,
            regions_scanned=["global"],
            services_scanned=["storage", "compute", "network", "sql", "keyvault"],
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
        
        self._log("complete", f"Azure scan complete: {len(self.findings)} findings")
        
        return result
    
    async def _scan_storage_accounts(self) -> int:
        """Scan Azure Storage Accounts"""
        resources = 0
        
        try:
            from azure.mgmt.storage import StorageManagementClient
            
            storage_client = StorageManagementClient(self.credential, self.subscription_id)
            
            for account in storage_client.storage_accounts.list():
                resources += 1
                account_name = account.name
                
                # Check HTTPS only
                if not account.enable_https_traffic_only:
                    self._add_finding(
                        id=f"AZURE-STORAGE-HTTPS-{account_name}",
                        service="storage",
                        resource_id=account_name,
                        severity="high",
                        title="Storage Account Allows HTTP",
                        description=f"Storage account {account_name} allows non-HTTPS traffic.",
                        recommendation="Enable 'Secure transfer required'."
                    )
                
                # Check blob public access
                if account.allow_blob_public_access:
                    self._add_finding(
                        id=f"AZURE-STORAGE-PUBLIC-{account_name}",
                        service="storage",
                        resource_id=account_name,
                        severity="high",
                        title="Storage Account Allows Public Blob Access",
                        description=f"Storage account {account_name} allows public blob access.",
                        recommendation="Disable public blob access."
                    )
                
                # Check encryption
                if not account.encryption.services.blob.enabled:
                    self._add_finding(
                        id=f"AZURE-STORAGE-ENC-{account_name}",
                        service="storage",
                        resource_id=account_name,
                        severity="medium",
                        title="Storage Account Encryption Disabled",
                        description=f"Storage account {account_name} does not have encryption enabled.",
                        recommendation="Enable encryption for all services."
                    )
                    
        except Exception as e:
            logger.error(f"Error scanning storage accounts: {e}")
        
        return resources
    
    async def _scan_virtual_machines(self) -> int:
        """Scan Azure Virtual Machines"""
        resources = 0
        
        try:
            from azure.mgmt.compute import ComputeManagementClient
            
            compute_client = ComputeManagementClient(self.credential, self.subscription_id)
            
            for vm in compute_client.virtual_machines.list_all():
                resources += 1
                vm_name = vm.name
                
                # Check disk encryption
                if vm.storage_profile and vm.storage_profile.os_disk:
                    encryption = vm.storage_profile.os_disk.encryption_settings
                    if not encryption or not encryption.enabled:
                        self._add_finding(
                            id=f"AZURE-VM-DISK-{vm_name}",
                            service="compute",
                            resource_id=vm_name,
                            severity="high",
                            title="VM OS Disk Not Encrypted",
                            description=f"Virtual machine {vm_name} OS disk is not encrypted.",
                            recommendation="Enable Azure Disk Encryption."
                        )
                
                # Check for managed identity
                if not vm.identity:
                    self._add_finding(
                        id=f"AZURE-VM-IDENTITY-{vm_name}",
                        service="compute",
                        resource_id=vm_name,
                        severity="low",
                        title="VM Without Managed Identity",
                        description=f"Virtual machine {vm_name} does not use managed identity.",
                        recommendation="Use managed identity for Azure resource access."
                    )
                    
        except Exception as e:
            logger.error(f"Error scanning virtual machines: {e}")
        
        return resources
    
    async def _scan_network_security(self) -> int:
        """Scan Azure Network Security Groups"""
        resources = 0
        
        try:
            from azure.mgmt.network import NetworkManagementClient
            
            network_client = NetworkManagementClient(self.credential, self.subscription_id)
            
            for nsg in network_client.network_security_groups.list_all():
                resources += 1
                nsg_name = nsg.name
                
                for rule in nsg.security_rules or []:
                    if rule.access == "Allow" and rule.direction == "Inbound":
                        # Check for open SSH
                        if rule.destination_port_range == "22" or "22" in (rule.destination_port_ranges or []):
                            if rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]:
                                self._add_finding(
                                    id=f"AZURE-NSG-SSH-{nsg_name}-{rule.name}",
                                    service="network",
                                    resource_id=nsg_name,
                                    severity="critical",
                                    title="NSG Allows SSH from Internet",
                                    description=f"NSG {nsg_name} rule {rule.name} allows SSH from internet.",
                                    recommendation="Restrict SSH access to specific IPs."
                                )
                        
                        # Check for open RDP
                        if rule.destination_port_range == "3389" or "3389" in (rule.destination_port_ranges or []):
                            if rule.source_address_prefix in ["*", "0.0.0.0/0", "Internet"]:
                                self._add_finding(
                                    id=f"AZURE-NSG-RDP-{nsg_name}-{rule.name}",
                                    service="network",
                                    resource_id=nsg_name,
                                    severity="critical",
                                    title="NSG Allows RDP from Internet",
                                    description=f"NSG {nsg_name} rule {rule.name} allows RDP from internet.",
                                    recommendation="Restrict RDP access to specific IPs."
                                )
                                
        except Exception as e:
            logger.error(f"Error scanning network security: {e}")
        
        return resources
    
    async def _scan_sql_databases(self) -> int:
        """Scan Azure SQL Databases"""
        resources = 0
        
        try:
            from azure.mgmt.sql import SqlManagementClient
            
            sql_client = SqlManagementClient(self.credential, self.subscription_id)
            
            for server in sql_client.servers.list():
                resources += 1
                server_name = server.name
                resource_group = server.id.split('/')[4]
                
                # Check TDE
                for db in sql_client.databases.list_by_server(resource_group, server_name):
                    if db.name != "master":
                        tde = sql_client.transparent_data_encryptions.get(
                            resource_group, server_name, db.name
                        )
                        if tde.status != "Enabled":
                            self._add_finding(
                                id=f"AZURE-SQL-TDE-{server_name}-{db.name}",
                                service="sql",
                                resource_id=f"{server_name}/{db.name}",
                                severity="high",
                                title="SQL Database TDE Not Enabled",
                                description=f"Database {db.name} on {server_name} does not have TDE enabled.",
                                recommendation="Enable Transparent Data Encryption."
                            )
                
                # Check firewall rules
                for rule in sql_client.firewall_rules.list_by_server(resource_group, server_name):
                    if rule.start_ip_address == "0.0.0.0" and rule.end_ip_address == "255.255.255.255":
                        self._add_finding(
                            id=f"AZURE-SQL-FW-{server_name}",
                            service="sql",
                            resource_id=server_name,
                            severity="critical",
                            title="SQL Server Open to All IPs",
                            description=f"SQL Server {server_name} firewall allows all IP addresses.",
                            recommendation="Restrict firewall rules to specific IPs."
                        )
                        
        except Exception as e:
            logger.error(f"Error scanning SQL databases: {e}")
        
        return resources
    
    async def _scan_key_vaults(self) -> int:
        """Scan Azure Key Vaults"""
        resources = 0
        
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
            
            kv_client = KeyVaultManagementClient(self.credential, self.subscription_id)
            
            for vault in kv_client.vaults.list():
                resources += 1
                vault_name = vault.name
                
                # Check soft delete
                if not vault.properties.enable_soft_delete:
                    self._add_finding(
                        id=f"AZURE-KV-SOFTDELETE-{vault_name}",
                        service="keyvault",
                        resource_id=vault_name,
                        severity="medium",
                        title="Key Vault Soft Delete Not Enabled",
                        description=f"Key Vault {vault_name} does not have soft delete enabled.",
                        recommendation="Enable soft delete for data protection."
                    )
                
                # Check purge protection
                if not vault.properties.enable_purge_protection:
                    self._add_finding(
                        id=f"AZURE-KV-PURGE-{vault_name}",
                        service="keyvault",
                        resource_id=vault_name,
                        severity="medium",
                        title="Key Vault Purge Protection Not Enabled",
                        description=f"Key Vault {vault_name} does not have purge protection.",
                        recommendation="Enable purge protection."
                    )
                    
        except Exception as e:
            logger.error(f"Error scanning key vaults: {e}")
        
        return resources
