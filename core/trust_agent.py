"""
Jarwis Trust Agent - Enterprise Security & Compliance Layer

This module provides enterprise-grade security controls for:
- Encrypted credential management with KMS/Vault integration
- Role-Based Access Control (RBAC) enforcement
- Comprehensive audit logging for compliance
- Data retention policy enforcement
- Compliance scanning (SOC2, ISO27001, GDPR, HIPAA)
- Multi-tenant data isolation

Architecture:
    TrustAgent → SecretsManager → [AWS KMS | Azure Key Vault | HashiCorp Vault]
    TrustAgent → AuditLogger → [Database | SIEM]
    TrustAgent → RBACEnforcer → Permission Matrix
"""

import asyncio
import hashlib
import json
import logging
import os
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from functools import wraps

logger = logging.getLogger(__name__)


# ============== Enums & Constants ==============

class Role(str, Enum):
    """Enterprise RBAC roles with hierarchical permissions"""
    OWNER = "owner"              # Full access, can transfer ownership
    ADMIN = "admin"              # Full access except ownership transfer
    SECURITY_ANALYST = "security_analyst"  # Run scans, view all results, manage configs
    DEVELOPER = "developer"      # Run scans on assigned targets, view own results
    AUDITOR = "auditor"          # Read-only access to all scans and audit logs
    VIEWER = "viewer"            # Read-only access to assigned scan results
    
    @property
    def level(self) -> int:
        """Permission level for hierarchy comparison"""
        return {
            Role.OWNER: 100,
            Role.ADMIN: 90,
            Role.SECURITY_ANALYST: 70,
            Role.DEVELOPER: 50,
            Role.AUDITOR: 40,
            Role.VIEWER: 10
        }.get(self, 0)


class Permission(str, Enum):
    """Granular permissions for enterprise access control"""
    # Scan permissions
    SCAN_CREATE = "scan:create"
    SCAN_VIEW_OWN = "scan:view:own"
    SCAN_VIEW_ALL = "scan:view:all"
    SCAN_DELETE = "scan:delete"
    SCAN_EXPORT = "scan:export"
    SCAN_CONFIGURE = "scan:configure"
    
    # Credential permissions
    CREDENTIAL_CREATE = "credential:create"
    CREDENTIAL_VIEW = "credential:view"
    CREDENTIAL_DELETE = "credential:delete"
    CREDENTIAL_USE = "credential:use"
    
    # Report permissions
    REPORT_VIEW = "report:view"
    REPORT_EXPORT = "report:export"
    REPORT_DELETE = "report:delete"
    
    # Audit permissions
    AUDIT_VIEW = "audit:view"
    AUDIT_EXPORT = "audit:export"
    
    # Admin permissions
    USER_MANAGE = "user:manage"
    ROLE_ASSIGN = "role:assign"
    SETTINGS_MANAGE = "settings:manage"
    AGENT_MANAGE = "agent:manage"
    TENANT_MANAGE = "tenant:manage"
    
    # Compliance permissions
    COMPLIANCE_VIEW = "compliance:view"
    COMPLIANCE_GENERATE = "compliance:generate"


class AuditAction(str, Enum):
    """Audit log action types for compliance tracking"""
    # Authentication events
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILED = "auth.login.failed"
    LOGOUT = "auth.logout"
    PASSWORD_CHANGE = "auth.password.change"
    MFA_ENABLED = "auth.mfa.enabled"
    MFA_DISABLED = "auth.mfa.disabled"
    API_KEY_CREATED = "auth.apikey.created"
    API_KEY_REVOKED = "auth.apikey.revoked"
    
    # Credential events
    CREDENTIAL_CREATED = "credential.created"
    CREDENTIAL_ACCESSED = "credential.accessed"
    CREDENTIAL_MODIFIED = "credential.modified"
    CREDENTIAL_DELETED = "credential.deleted"
    CREDENTIAL_ROTATED = "credential.rotated"
    
    # Scan events
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    SCAN_STOPPED = "scan.stopped"
    SCAN_EXPORTED = "scan.exported"
    SCAN_DELETED = "scan.deleted"
    
    # Report events
    REPORT_GENERATED = "report.generated"
    REPORT_ACCESSED = "report.accessed"
    REPORT_EXPORTED = "report.exported"
    REPORT_DELETED = "report.deleted"
    
    # Configuration events
    CONFIG_CHANGED = "config.changed"
    SETTINGS_UPDATED = "settings.updated"
    WEBHOOK_CONFIGURED = "webhook.configured"
    
    # User management events
    USER_CREATED = "user.created"
    USER_MODIFIED = "user.modified"
    USER_DELETED = "user.deleted"
    USER_SUSPENDED = "user.suspended"
    ROLE_ASSIGNED = "role.assigned"
    ROLE_REVOKED = "role.revoked"
    
    # Agent events
    AGENT_REGISTERED = "agent.registered"
    AGENT_DEREGISTERED = "agent.deregistered"
    AGENT_CONFIG_CHANGED = "agent.config.changed"
    
    # Compliance events
    COMPLIANCE_REPORT_GENERATED = "compliance.report.generated"
    DATA_EXPORTED = "data.exported"
    DATA_DELETED = "data.deleted"
    RETENTION_POLICY_APPLIED = "retention.policy.applied"


class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    SOC2_TYPE_II = "soc2_type_ii"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"
    CIS_CONTROLS = "cis_controls"


class CredentialType(str, Enum):
    """Types of credentials managed by the Trust Agent"""
    AWS_CREDENTIALS = "aws_credentials"
    AWS_ROLE = "aws_role"
    AZURE_SERVICE_PRINCIPAL = "azure_service_principal"
    GCP_SERVICE_ACCOUNT = "gcp_service_account"
    SSH_KEY = "ssh_key"
    SSH_PASSWORD = "ssh_password"
    DATABASE_CREDENTIALS = "database_credentials"
    API_TOKEN = "api_token"
    OAUTH_TOKEN = "oauth_token"
    SCM_TOKEN = "scm_token"  # Source code management


# ============== RBAC Permission Matrix ==============

ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.OWNER: set(Permission),  # All permissions
    
    Role.ADMIN: {
        Permission.SCAN_CREATE, Permission.SCAN_VIEW_ALL, Permission.SCAN_DELETE,
        Permission.SCAN_EXPORT, Permission.SCAN_CONFIGURE,
        Permission.CREDENTIAL_CREATE, Permission.CREDENTIAL_VIEW, 
        Permission.CREDENTIAL_DELETE, Permission.CREDENTIAL_USE,
        Permission.REPORT_VIEW, Permission.REPORT_EXPORT, Permission.REPORT_DELETE,
        Permission.AUDIT_VIEW, Permission.AUDIT_EXPORT,
        Permission.USER_MANAGE, Permission.ROLE_ASSIGN, Permission.SETTINGS_MANAGE,
        Permission.AGENT_MANAGE,
        Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_GENERATE,
    },
    
    Role.SECURITY_ANALYST: {
        Permission.SCAN_CREATE, Permission.SCAN_VIEW_ALL, Permission.SCAN_DELETE,
        Permission.SCAN_EXPORT, Permission.SCAN_CONFIGURE,
        Permission.CREDENTIAL_CREATE, Permission.CREDENTIAL_VIEW, Permission.CREDENTIAL_USE,
        Permission.REPORT_VIEW, Permission.REPORT_EXPORT,
        Permission.AUDIT_VIEW,
        Permission.AGENT_MANAGE,
        Permission.COMPLIANCE_VIEW, Permission.COMPLIANCE_GENERATE,
    },
    
    Role.DEVELOPER: {
        Permission.SCAN_CREATE, Permission.SCAN_VIEW_OWN, Permission.SCAN_EXPORT,
        Permission.CREDENTIAL_USE,
        Permission.REPORT_VIEW, Permission.REPORT_EXPORT,
    },
    
    Role.AUDITOR: {
        Permission.SCAN_VIEW_ALL,
        Permission.CREDENTIAL_VIEW,
        Permission.REPORT_VIEW, Permission.REPORT_EXPORT,
        Permission.AUDIT_VIEW, Permission.AUDIT_EXPORT,
        Permission.COMPLIANCE_VIEW,
    },
    
    Role.VIEWER: {
        Permission.SCAN_VIEW_OWN,
        Permission.REPORT_VIEW,
    },
}


# ============== Data Classes ==============

@dataclass
class AuditLogEntry:
    """Structured audit log entry for compliance tracking"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    # Actor information
    user_id: Optional[str] = None
    username: Optional[str] = None
    tenant_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    
    # Action information
    action: AuditAction = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    
    # Request details
    request_id: Optional[str] = None
    method: Optional[str] = None
    endpoint: Optional[str] = None
    
    # Change tracking
    previous_value: Optional[Dict] = None
    new_value: Optional[Dict] = None
    
    # Outcome
    success: bool = True
    error_message: Optional[str] = None
    
    # Metadata
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage/serialization"""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "user_id": self.user_id,
            "username": self.username,
            "tenant_id": self.tenant_id,
            "ip_address": self.ip_address,
            "user_agent": self.user_agent,
            "session_id": self.session_id,
            "action": self.action.value if self.action else None,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "request_id": self.request_id,
            "method": self.method,
            "endpoint": self.endpoint,
            "previous_value": self.previous_value,
            "new_value": self.new_value,
            "success": self.success,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


@dataclass
class EncryptedCredential:
    """Encrypted credential wrapper with metadata"""
    id: str
    name: str
    credential_type: CredentialType
    tenant_id: str
    created_by: str
    
    # Encrypted data (actual credential is encrypted)
    encrypted_data: bytes
    encryption_key_id: str
    encryption_algorithm: str = "AES-256-GCM"
    
    # Access control
    allowed_users: List[str] = field(default_factory=list)
    allowed_roles: List[Role] = field(default_factory=list)
    
    # Rotation policy
    rotation_days: int = 90
    last_rotated: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    
    # Audit
    access_count: int = 0
    last_accessed: Optional[datetime] = None
    last_accessed_by: Optional[str] = None
    
    # Timestamps
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class TenantContext:
    """Multi-tenant isolation context"""
    tenant_id: str
    tenant_name: str
    
    # Subscription/plan
    plan: str
    
    # Limits
    max_users: int
    max_scans_per_month: int
    max_credentials: int
    
    # Features
    enabled_features: Set[str] = field(default_factory=set)
    
    # Compliance requirements
    required_frameworks: Set[ComplianceFramework] = field(default_factory=set)
    
    # Data residency
    data_region: str = "us-east-1"
    encryption_key_id: Optional[str] = None
    
    # Retention
    retention_days: int = 365


@dataclass
class ComplianceEvidence:
    """Evidence record for compliance audits"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    framework: ComplianceFramework = None
    control_id: str = ""
    control_name: str = ""
    
    # Evidence details
    evidence_type: str = ""  # audit_log, config, screenshot, document
    description: str = ""
    collected_at: datetime = field(default_factory=datetime.utcnow)
    
    # Data
    data: Dict = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)
    
    # Status
    status: str = "collected"  # collected, reviewed, approved
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None


# ============== Abstract Base Classes ==============

class SecretsProvider(ABC):
    """Abstract base class for secrets management providers"""
    
    @abstractmethod
    async def encrypt(self, plaintext: bytes, key_id: str) -> Tuple[bytes, Dict]:
        """Encrypt data using the provider's KMS"""
        pass
    
    @abstractmethod
    async def decrypt(self, ciphertext: bytes, key_id: str, metadata: Dict) -> bytes:
        """Decrypt data using the provider's KMS"""
        pass
    
    @abstractmethod
    async def generate_data_key(self, key_id: str) -> Tuple[bytes, bytes]:
        """Generate a data encryption key (returns plaintext and encrypted versions)"""
        pass
    
    @abstractmethod
    async def rotate_key(self, key_id: str) -> str:
        """Rotate an encryption key, returns new key ID"""
        pass


class AuditLogProvider(ABC):
    """Abstract base class for audit log storage providers"""
    
    @abstractmethod
    async def write(self, entry: AuditLogEntry) -> None:
        """Write an audit log entry"""
        pass
    
    @abstractmethod
    async def query(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        actions: Optional[List[AuditAction]] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        limit: int = 1000
    ) -> List[AuditLogEntry]:
        """Query audit logs with filters"""
        pass
    
    @abstractmethod
    async def export(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        format: str = "json"
    ) -> bytes:
        """Export audit logs for compliance reporting"""
        pass


# ============== Secrets Manager Implementations ==============

class LocalSecretsProvider(SecretsProvider):
    """
    Local secrets provider using Fernet encryption.
    For development/testing only - use AWS KMS, Azure Key Vault, 
    or HashiCorp Vault in production.
    """
    
    def __init__(self, master_key: Optional[str] = None):
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            from cryptography.hazmat.backends import default_backend
            import base64
            
            self._fernet_available = True
            
            if master_key:
                # Derive key from master key
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"jarwis_trust_agent_salt",  # In production, use unique salt per tenant
                    iterations=100000,
                    backend=default_backend()
                )
                key = base64.urlsafe_b64encode(kdf.derive(master_key.encode()))
            else:
                # Use environment variable or generate new key
                key_env = os.environ.get("JARWIS_ENCRYPTION_KEY")
                if key_env:
                    key = key_env.encode()
                else:
                    key = Fernet.generate_key()
                    logger.warning("Generated new encryption key - credentials will be lost on restart!")
            
            self._fernet = Fernet(key)
            self._key_id = hashlib.sha256(key).hexdigest()[:16]
            
        except ImportError:
            self._fernet_available = False
            logger.error("cryptography package not installed - encryption disabled!")
    
    async def encrypt(self, plaintext: bytes, key_id: str = None) -> Tuple[bytes, Dict]:
        if not self._fernet_available:
            raise RuntimeError("Encryption not available - install cryptography package")
        
        ciphertext = self._fernet.encrypt(plaintext)
        metadata = {
            "algorithm": "Fernet",
            "key_id": self._key_id,
            "encrypted_at": datetime.utcnow().isoformat()
        }
        return ciphertext, metadata
    
    async def decrypt(self, ciphertext: bytes, key_id: str = None, metadata: Dict = None) -> bytes:
        if not self._fernet_available:
            raise RuntimeError("Encryption not available - install cryptography package")
        
        return self._fernet.decrypt(ciphertext)
    
    async def generate_data_key(self, key_id: str = None) -> Tuple[bytes, bytes]:
        if not self._fernet_available:
            raise RuntimeError("Encryption not available - install cryptography package")
        
        from cryptography.fernet import Fernet
        
        # Generate a new data key
        data_key = Fernet.generate_key()
        
        # Encrypt the data key with master key
        encrypted_data_key = self._fernet.encrypt(data_key)
        
        return data_key, encrypted_data_key
    
    async def rotate_key(self, key_id: str = None) -> str:
        # In local provider, key rotation requires re-encryption of all data
        logger.warning("Key rotation not fully implemented for local provider")
        return self._key_id


class AWSSecretsProvider(SecretsProvider):
    """AWS KMS and Secrets Manager integration"""
    
    def __init__(self, region: str = "us-east-1", kms_key_id: Optional[str] = None):
        self.region = region
        self.kms_key_id = kms_key_id
        self._client = None
    
    async def _get_client(self):
        if self._client is None:
            try:
                import boto3
                self._client = boto3.client('kms', region_name=self.region)
            except ImportError:
                raise RuntimeError("boto3 package required for AWS KMS integration")
        return self._client
    
    async def encrypt(self, plaintext: bytes, key_id: str = None) -> Tuple[bytes, Dict]:
        client = await self._get_client()
        key = key_id or self.kms_key_id
        
        response = client.encrypt(
            KeyId=key,
            Plaintext=plaintext,
            EncryptionContext={'service': 'jarwis-trust-agent'}
        )
        
        metadata = {
            "algorithm": "AWS_KMS",
            "key_id": key,
            "encrypted_at": datetime.utcnow().isoformat()
        }
        return response['CiphertextBlob'], metadata
    
    async def decrypt(self, ciphertext: bytes, key_id: str = None, metadata: Dict = None) -> bytes:
        client = await self._get_client()
        
        response = client.decrypt(
            CiphertextBlob=ciphertext,
            EncryptionContext={'service': 'jarwis-trust-agent'}
        )
        return response['Plaintext']
    
    async def generate_data_key(self, key_id: str = None) -> Tuple[bytes, bytes]:
        client = await self._get_client()
        key = key_id or self.kms_key_id
        
        response = client.generate_data_key(
            KeyId=key,
            KeySpec='AES_256',
            EncryptionContext={'service': 'jarwis-trust-agent'}
        )
        return response['Plaintext'], response['CiphertextBlob']
    
    async def rotate_key(self, key_id: str = None) -> str:
        # AWS KMS handles key rotation automatically when enabled
        logger.info(f"AWS KMS key rotation is managed by AWS for key: {key_id or self.kms_key_id}")
        return key_id or self.kms_key_id


class VaultSecretsProvider(SecretsProvider):
    """HashiCorp Vault integration"""
    
    def __init__(self, vault_url: str, token: Optional[str] = None, mount_path: str = "transit"):
        self.vault_url = vault_url
        self.token = token or os.environ.get("VAULT_TOKEN")
        self.mount_path = mount_path
        self._client = None
    
    async def _get_client(self):
        if self._client is None:
            try:
                import hvac
                self._client = hvac.Client(url=self.vault_url, token=self.token)
                if not self._client.is_authenticated():
                    raise RuntimeError("Vault authentication failed")
            except ImportError:
                raise RuntimeError("hvac package required for HashiCorp Vault integration")
        return self._client
    
    async def encrypt(self, plaintext: bytes, key_id: str) -> Tuple[bytes, Dict]:
        import base64
        client = await self._get_client()
        
        response = client.secrets.transit.encrypt_data(
            name=key_id,
            plaintext=base64.b64encode(plaintext).decode('utf-8'),
            mount_point=self.mount_path
        )
        
        metadata = {
            "algorithm": "Vault_Transit",
            "key_id": key_id,
            "key_version": response['data']['key_version'],
            "encrypted_at": datetime.utcnow().isoformat()
        }
        return response['data']['ciphertext'].encode(), metadata
    
    async def decrypt(self, ciphertext: bytes, key_id: str, metadata: Dict = None) -> bytes:
        import base64
        client = await self._get_client()
        
        response = client.secrets.transit.decrypt_data(
            name=key_id,
            ciphertext=ciphertext.decode('utf-8'),
            mount_point=self.mount_path
        )
        return base64.b64decode(response['data']['plaintext'])
    
    async def generate_data_key(self, key_id: str) -> Tuple[bytes, bytes]:
        import base64
        client = await self._get_client()
        
        response = client.secrets.transit.generate_data_key(
            name=key_id,
            key_type='plaintext',
            mount_point=self.mount_path
        )
        
        plaintext = base64.b64decode(response['data']['plaintext'])
        ciphertext = response['data']['ciphertext'].encode()
        return plaintext, ciphertext
    
    async def rotate_key(self, key_id: str) -> str:
        client = await self._get_client()
        
        client.secrets.transit.rotate_key(name=key_id, mount_point=self.mount_path)
        logger.info(f"Rotated Vault transit key: {key_id}")
        return key_id


# ============== Audit Log Implementation ==============

class DatabaseAuditLogProvider(AuditLogProvider):
    """Database-backed audit log provider"""
    
    def __init__(self, db_session_factory):
        self._session_factory = db_session_factory
        self._buffer: List[AuditLogEntry] = []
        self._buffer_size = 100
        self._flush_interval = 5.0  # seconds
        self._last_flush = time.time()
    
    async def write(self, entry: AuditLogEntry) -> None:
        """Write audit log entry with buffering for performance"""
        self._buffer.append(entry)
        
        # Flush if buffer is full or interval exceeded
        if len(self._buffer) >= self._buffer_size or \
           time.time() - self._last_flush > self._flush_interval:
            await self._flush()
    
    async def _flush(self) -> None:
        """Flush buffered entries to database"""
        if not self._buffer:
            return
        
        entries_to_flush = self._buffer.copy()
        self._buffer.clear()
        self._last_flush = time.time()
        
        try:
            # In production, this would insert into AuditLog table
            # For now, log to file/console
            for entry in entries_to_flush:
                logger.info(f"AUDIT: {entry.to_dict()}")
        except Exception as e:
            logger.error(f"Failed to flush audit logs: {e}")
            # Re-add entries to buffer for retry
            self._buffer.extend(entries_to_flush)
    
    async def query(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        actions: Optional[List[AuditAction]] = None,
        user_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        limit: int = 1000
    ) -> List[AuditLogEntry]:
        """Query audit logs - placeholder for database implementation"""
        # This would query the AuditLog table in production
        return []
    
    async def export(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        format: str = "json"
    ) -> bytes:
        """Export audit logs for compliance"""
        entries = await self.query(tenant_id, start_time, end_time)
        
        if format == "json":
            data = [e.to_dict() for e in entries]
            return json.dumps(data, indent=2, default=str).encode()
        elif format == "csv":
            # CSV export implementation
            import csv
            import io
            
            output = io.StringIO()
            if entries:
                writer = csv.DictWriter(output, fieldnames=entries[0].to_dict().keys())
                writer.writeheader()
                for entry in entries:
                    writer.writerow(entry.to_dict())
            return output.getvalue().encode()
        else:
            raise ValueError(f"Unsupported export format: {format}")


# ============== RBAC Enforcer ==============

class RBACEnforcer:
    """Role-Based Access Control enforcement"""
    
    def __init__(self, audit_logger: AuditLogProvider):
        self._audit = audit_logger
        self._role_permissions = ROLE_PERMISSIONS.copy()
    
    def has_permission(self, user_role: Role, permission: Permission) -> bool:
        """Check if a role has a specific permission"""
        if user_role not in self._role_permissions:
            return False
        return permission in self._role_permissions[user_role]
    
    def has_any_permission(self, user_role: Role, permissions: List[Permission]) -> bool:
        """Check if a role has any of the specified permissions"""
        return any(self.has_permission(user_role, p) for p in permissions)
    
    def has_all_permissions(self, user_role: Role, permissions: List[Permission]) -> bool:
        """Check if a role has all of the specified permissions"""
        return all(self.has_permission(user_role, p) for p in permissions)
    
    def get_permissions(self, user_role: Role) -> Set[Permission]:
        """Get all permissions for a role"""
        return self._role_permissions.get(user_role, set())
    
    def can_access_resource(
        self,
        user_role: Role,
        user_id: str,
        resource_owner_id: str,
        permission: Permission
    ) -> bool:
        """
        Check if user can access a specific resource.
        Handles 'own' vs 'all' permission logic.
        """
        if not self.has_permission(user_role, permission):
            return False
        
        # Check for 'view:own' vs 'view:all' patterns
        if "own" in permission.value:
            return user_id == resource_owner_id
        
        return True
    
    async def enforce(
        self,
        user_id: str,
        user_role: Role,
        permission: Permission,
        resource_type: str = None,
        resource_id: str = None,
        resource_owner_id: str = None,
        context: Dict = None
    ) -> bool:
        """
        Enforce permission check with audit logging.
        Raises PermissionError if access denied.
        """
        # Check permission
        if resource_owner_id:
            allowed = self.can_access_resource(user_role, user_id, resource_owner_id, permission)
        else:
            allowed = self.has_permission(user_role, permission)
        
        # Log the access attempt
        entry = AuditLogEntry(
            user_id=user_id,
            action=AuditAction.CONFIG_CHANGED,  # Would use specific action
            resource_type=resource_type,
            resource_id=resource_id,
            success=allowed,
            metadata={
                "permission": permission.value,
                "role": user_role.value,
                "context": context or {}
            }
        )
        
        if not allowed:
            entry.error_message = f"Permission denied: {permission.value}"
            await self._audit.write(entry)
            raise PermissionError(f"Access denied: {permission.value} required")
        
        await self._audit.write(entry)
        return True


# ============== Main Trust Agent ==============

class TrustAgent:
    """
    Central trust and compliance management for Jarwis Enterprise.
    
    Features:
    - Encrypted credential management
    - RBAC enforcement
    - Comprehensive audit logging
    - Multi-tenant isolation
    - Compliance evidence collection
    - Data retention enforcement
    """
    
    def __init__(
        self,
        secrets_provider: SecretsProvider = None,
        audit_provider: AuditLogProvider = None,
        default_key_id: str = None
    ):
        # Initialize secrets provider (defaults to local for development)
        self._secrets = secrets_provider or LocalSecretsProvider()
        self._default_key_id = default_key_id or "jarwis-master-key"
        
        # Initialize audit logging
        self._audit = audit_provider or DatabaseAuditLogProvider(None)
        
        # Initialize RBAC enforcer
        self._rbac = RBACEnforcer(self._audit)
        
        # Credential cache (encrypted credentials only)
        self._credential_cache: Dict[str, EncryptedCredential] = {}
        
        # Tenant contexts
        self._tenants: Dict[str, TenantContext] = {}
        
        logger.info("TrustAgent initialized")
    
    # ============== Credential Management ==============
    
    async def store_credential(
        self,
        name: str,
        credential_type: CredentialType,
        credential_data: Dict,
        tenant_id: str,
        created_by: str,
        allowed_users: List[str] = None,
        allowed_roles: List[Role] = None,
        rotation_days: int = 90
    ) -> str:
        """
        Securely store an encrypted credential.
        Returns the credential ID.
        """
        # Generate credential ID
        credential_id = str(uuid.uuid4())
        
        # Serialize credential data
        plaintext = json.dumps(credential_data).encode('utf-8')
        
        # Encrypt the credential
        ciphertext, metadata = await self._secrets.encrypt(
            plaintext,
            self._default_key_id
        )
        
        # Create encrypted credential record
        credential = EncryptedCredential(
            id=credential_id,
            name=name,
            credential_type=credential_type,
            tenant_id=tenant_id,
            created_by=created_by,
            encrypted_data=ciphertext,
            encryption_key_id=metadata.get('key_id', self._default_key_id),
            allowed_users=allowed_users or [created_by],
            allowed_roles=allowed_roles or [Role.ADMIN, Role.SECURITY_ANALYST],
            rotation_days=rotation_days,
            last_rotated=datetime.utcnow()
        )
        
        # Store in cache (would also persist to database)
        self._credential_cache[credential_id] = credential
        
        # Audit log
        await self._audit.write(AuditLogEntry(
            user_id=created_by,
            tenant_id=tenant_id,
            action=AuditAction.CREDENTIAL_CREATED,
            resource_type="credential",
            resource_id=credential_id,
            metadata={
                "name": name,
                "type": credential_type.value,
                "rotation_days": rotation_days
            }
        ))
        
        logger.info(f"Stored encrypted credential: {name} ({credential_id})")
        return credential_id
    
    async def get_credential(
        self,
        credential_id: str,
        user_id: str,
        user_role: Role,
        purpose: str = None
    ) -> Dict:
        """
        Retrieve and decrypt a credential with access control and audit logging.
        """
        # Get credential record
        credential = self._credential_cache.get(credential_id)
        if not credential:
            raise ValueError(f"Credential not found: {credential_id}")
        
        # Check access permission
        if user_id not in credential.allowed_users and \
           user_role not in credential.allowed_roles:
            await self._audit.write(AuditLogEntry(
                user_id=user_id,
                tenant_id=credential.tenant_id,
                action=AuditAction.CREDENTIAL_ACCESSED,
                resource_type="credential",
                resource_id=credential_id,
                success=False,
                error_message="Access denied"
            ))
            raise PermissionError(f"Access denied to credential: {credential_id}")
        
        # Decrypt the credential
        plaintext = await self._secrets.decrypt(
            credential.encrypted_data,
            credential.encryption_key_id,
            {}
        )
        
        # Update access tracking
        credential.access_count += 1
        credential.last_accessed = datetime.utcnow()
        credential.last_accessed_by = user_id
        
        # Audit log
        await self._audit.write(AuditLogEntry(
            user_id=user_id,
            tenant_id=credential.tenant_id,
            action=AuditAction.CREDENTIAL_ACCESSED,
            resource_type="credential",
            resource_id=credential_id,
            metadata={
                "purpose": purpose,
                "access_count": credential.access_count
            }
        ))
        
        return json.loads(plaintext.decode('utf-8'))
    
    async def rotate_credential(
        self,
        credential_id: str,
        new_credential_data: Dict,
        rotated_by: str
    ) -> None:
        """Rotate a credential with new data"""
        credential = self._credential_cache.get(credential_id)
        if not credential:
            raise ValueError(f"Credential not found: {credential_id}")
        
        # Store old value for audit
        old_encrypted = credential.encrypted_data
        
        # Encrypt new credential data
        plaintext = json.dumps(new_credential_data).encode('utf-8')
        ciphertext, metadata = await self._secrets.encrypt(
            plaintext,
            self._default_key_id
        )
        
        # Update credential
        credential.encrypted_data = ciphertext
        credential.encryption_key_id = metadata.get('key_id', self._default_key_id)
        credential.last_rotated = datetime.utcnow()
        credential.updated_at = datetime.utcnow()
        
        # Audit log
        await self._audit.write(AuditLogEntry(
            user_id=rotated_by,
            tenant_id=credential.tenant_id,
            action=AuditAction.CREDENTIAL_ROTATED,
            resource_type="credential",
            resource_id=credential_id,
            metadata={"previous_key_id": credential.encryption_key_id}
        ))
        
        logger.info(f"Rotated credential: {credential.name} ({credential_id})")
    
    async def delete_credential(
        self,
        credential_id: str,
        deleted_by: str
    ) -> None:
        """Securely delete a credential"""
        credential = self._credential_cache.get(credential_id)
        if not credential:
            return
        
        tenant_id = credential.tenant_id
        name = credential.name
        
        # Remove from cache
        del self._credential_cache[credential_id]
        
        # Audit log
        await self._audit.write(AuditLogEntry(
            user_id=deleted_by,
            tenant_id=tenant_id,
            action=AuditAction.CREDENTIAL_DELETED,
            resource_type="credential",
            resource_id=credential_id,
            metadata={"name": name}
        ))
        
        logger.info(f"Deleted credential: {name} ({credential_id})")
    
    # ============== RBAC Methods ==============
    
    def check_permission(self, user_role: Role, permission: Permission) -> bool:
        """Check if role has permission"""
        return self._rbac.has_permission(user_role, permission)
    
    async def enforce_permission(
        self,
        user_id: str,
        user_role: Role,
        permission: Permission,
        resource_type: str = None,
        resource_id: str = None,
        resource_owner_id: str = None,
        context: Dict = None
    ) -> bool:
        """Enforce permission with audit logging"""
        return await self._rbac.enforce(
            user_id, user_role, permission,
            resource_type, resource_id, resource_owner_id, context
        )
    
    # ============== Audit Methods ==============
    
    async def log_action(
        self,
        action: AuditAction,
        user_id: str = None,
        tenant_id: str = None,
        resource_type: str = None,
        resource_id: str = None,
        success: bool = True,
        error_message: str = None,
        metadata: Dict = None,
        request_context: Dict = None
    ) -> None:
        """Log an auditable action"""
        entry = AuditLogEntry(
            user_id=user_id,
            tenant_id=tenant_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            success=success,
            error_message=error_message,
            metadata=metadata or {},
            ip_address=request_context.get("ip_address") if request_context else None,
            user_agent=request_context.get("user_agent") if request_context else None,
            session_id=request_context.get("session_id") if request_context else None,
            request_id=request_context.get("request_id") if request_context else None
        )
        await self._audit.write(entry)
    
    async def get_audit_logs(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        actions: List[AuditAction] = None,
        user_id: str = None,
        limit: int = 1000
    ) -> List[AuditLogEntry]:
        """Query audit logs"""
        return await self._audit.query(
            tenant_id, start_time, end_time,
            actions=actions, user_id=user_id, limit=limit
        )
    
    async def export_audit_logs(
        self,
        tenant_id: str,
        start_time: datetime,
        end_time: datetime,
        format: str = "json",
        requesting_user: str = None
    ) -> bytes:
        """Export audit logs with audit trail"""
        # Log the export action
        await self.log_action(
            action=AuditAction.AUDIT_EXPORT,
            user_id=requesting_user,
            tenant_id=tenant_id,
            metadata={
                "start_time": start_time.isoformat(),
                "end_time": end_time.isoformat(),
                "format": format
            }
        )
        
        return await self._audit.export(tenant_id, start_time, end_time, format)
    
    # ============== Tenant Management ==============
    
    def register_tenant(self, context: TenantContext) -> None:
        """Register a tenant context"""
        self._tenants[context.tenant_id] = context
        logger.info(f"Registered tenant: {context.tenant_name} ({context.tenant_id})")
    
    def get_tenant(self, tenant_id: str) -> Optional[TenantContext]:
        """Get tenant context"""
        return self._tenants.get(tenant_id)
    
    # ============== Data Retention ==============
    
    async def enforce_retention_policy(
        self,
        tenant_id: str,
        dry_run: bool = True
    ) -> Dict[str, int]:
        """
        Enforce data retention policy for a tenant.
        Returns counts of items that would be/were deleted.
        """
        tenant = self.get_tenant(tenant_id)
        if not tenant:
            raise ValueError(f"Tenant not found: {tenant_id}")
        
        retention_days = tenant.retention_days
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        
        # In production, this would:
        # 1. Query for scans older than cutoff_date
        # 2. Query for reports older than cutoff_date
        # 3. Delete or archive as configured
        
        results = {
            "scans_to_delete": 0,
            "reports_to_delete": 0,
            "credentials_to_rotate": 0,
            "dry_run": dry_run
        }
        
        if not dry_run:
            await self.log_action(
                action=AuditAction.RETENTION_POLICY_APPLIED,
                tenant_id=tenant_id,
                metadata=results
            )
        
        return results


# ============== Compliance Reporter ==============

class ComplianceReporter:
    """Generate compliance reports for various frameworks"""
    
    def __init__(self, trust_agent: TrustAgent):
        self._trust = trust_agent
        
        # Control mappings for each framework
        self._control_mappings = self._load_control_mappings()
    
    def _load_control_mappings(self) -> Dict[ComplianceFramework, List[Dict]]:
        """Load compliance control mappings"""
        return {
            ComplianceFramework.SOC2_TYPE_II: [
                {"id": "CC6.1", "name": "Logical Access Controls", "category": "Access Control"},
                {"id": "CC6.6", "name": "Encryption", "category": "Data Protection"},
                {"id": "CC6.7", "name": "Data Transmission", "category": "Data Protection"},
                {"id": "CC7.2", "name": "System Monitoring", "category": "Monitoring"},
                {"id": "CC8.1", "name": "Change Management", "category": "Change Control"},
            ],
            ComplianceFramework.ISO_27001: [
                {"id": "A.9.4.1", "name": "Information Access Restriction", "category": "Access Control"},
                {"id": "A.10.1.1", "name": "Policy on Cryptographic Controls", "category": "Cryptography"},
                {"id": "A.12.4.1", "name": "Event Logging", "category": "Operations"},
                {"id": "A.18.1.4", "name": "Privacy and Protection of PII", "category": "Compliance"},
            ],
            ComplianceFramework.GDPR: [
                {"id": "Art.17", "name": "Right to Erasure", "category": "Data Subject Rights"},
                {"id": "Art.25", "name": "Data Protection by Design", "category": "Design"},
                {"id": "Art.30", "name": "Records of Processing", "category": "Documentation"},
                {"id": "Art.32", "name": "Security of Processing", "category": "Security"},
            ],
            ComplianceFramework.HIPAA: [
                {"id": "164.312(a)", "name": "Access Control", "category": "Technical Safeguards"},
                {"id": "164.312(b)", "name": "Audit Controls", "category": "Technical Safeguards"},
                {"id": "164.312(c)", "name": "Integrity", "category": "Technical Safeguards"},
                {"id": "164.312(e)", "name": "Transmission Security", "category": "Technical Safeguards"},
            ],
        }
    
    async def generate_report(
        self,
        framework: ComplianceFramework,
        tenant_id: str,
        start_date: datetime,
        end_date: datetime,
        requesting_user: str
    ) -> Dict:
        """Generate a compliance report for a specific framework"""
        
        controls = self._control_mappings.get(framework, [])
        
        # Collect evidence for each control
        evidence_list: List[ComplianceEvidence] = []
        control_statuses: Dict[str, str] = {}
        
        for control in controls:
            evidence = await self._collect_evidence(
                framework, control, tenant_id, start_date, end_date
            )
            evidence_list.extend(evidence)
            
            # Determine control status based on evidence
            if evidence:
                control_statuses[control["id"]] = "compliant"
            else:
                control_statuses[control["id"]] = "needs_review"
        
        # Calculate overall score
        compliant_count = sum(1 for s in control_statuses.values() if s == "compliant")
        total_controls = len(controls)
        compliance_score = (compliant_count / total_controls * 100) if total_controls > 0 else 0
        
        report = {
            "framework": framework.value,
            "tenant_id": tenant_id,
            "generated_at": datetime.utcnow().isoformat(),
            "generated_by": requesting_user,
            "period": {
                "start": start_date.isoformat(),
                "end": end_date.isoformat()
            },
            "summary": {
                "total_controls": total_controls,
                "compliant": compliant_count,
                "needs_review": total_controls - compliant_count,
                "compliance_score": round(compliance_score, 1)
            },
            "controls": [
                {
                    **control,
                    "status": control_statuses.get(control["id"], "needs_review")
                }
                for control in controls
            ],
            "evidence_count": len(evidence_list)
        }
        
        # Log report generation
        await self._trust.log_action(
            action=AuditAction.COMPLIANCE_REPORT_GENERATED,
            user_id=requesting_user,
            tenant_id=tenant_id,
            metadata={
                "framework": framework.value,
                "compliance_score": compliance_score
            }
        )
        
        return report
    
    async def _collect_evidence(
        self,
        framework: ComplianceFramework,
        control: Dict,
        tenant_id: str,
        start_date: datetime,
        end_date: datetime
    ) -> List[ComplianceEvidence]:
        """Collect evidence for a specific control"""
        evidence = []
        
        # This would query audit logs, scan results, configurations, etc.
        # For now, return placeholder evidence
        
        if control["category"] == "Access Control":
            evidence.append(ComplianceEvidence(
                framework=framework,
                control_id=control["id"],
                control_name=control["name"],
                evidence_type="audit_log",
                description="RBAC enforcement logs",
                data={"log_count": 0}  # Would be actual count
            ))
        
        if control["category"] == "Cryptography" or control["category"] == "Data Protection":
            evidence.append(ComplianceEvidence(
                framework=framework,
                control_id=control["id"],
                control_name=control["name"],
                evidence_type="config",
                description="Encryption configuration",
                data={"encryption_enabled": True, "algorithm": "AES-256-GCM"}
            ))
        
        return evidence


# ============== Decorators for Easy Integration ==============

def require_permission(permission: Permission):
    """Decorator to require a specific permission for a function"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract trust_agent, user_id, user_role from kwargs or args
            trust_agent = kwargs.get('trust_agent')
            user_id = kwargs.get('user_id')
            user_role = kwargs.get('user_role')
            
            if trust_agent and user_id and user_role:
                await trust_agent.enforce_permission(
                    user_id=user_id,
                    user_role=user_role,
                    permission=permission
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def audit_action(action: AuditAction, resource_type: str = None):
    """Decorator to automatically audit a function call"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            trust_agent = kwargs.get('trust_agent')
            user_id = kwargs.get('user_id')
            tenant_id = kwargs.get('tenant_id')
            
            try:
                result = await func(*args, **kwargs)
                
                if trust_agent:
                    await trust_agent.log_action(
                        action=action,
                        user_id=user_id,
                        tenant_id=tenant_id,
                        resource_type=resource_type,
                        success=True
                    )
                
                return result
                
            except Exception as e:
                if trust_agent:
                    await trust_agent.log_action(
                        action=action,
                        user_id=user_id,
                        tenant_id=tenant_id,
                        resource_type=resource_type,
                        success=False,
                        error_message=str(e)
                    )
                raise
        return wrapper
    return decorator


# ============== Factory Functions ==============

def create_trust_agent(
    provider: str = "local",
    **kwargs
) -> TrustAgent:
    """
    Factory function to create a TrustAgent with the appropriate secrets provider.
    
    Args:
        provider: One of 'local', 'aws', 'vault', 'azure'
        **kwargs: Provider-specific configuration
    
    Returns:
        Configured TrustAgent instance
    """
    if provider == "local":
        secrets = LocalSecretsProvider(kwargs.get("master_key"))
    elif provider == "aws":
        secrets = AWSSecretsProvider(
            region=kwargs.get("region", "us-east-1"),
            kms_key_id=kwargs.get("kms_key_id")
        )
    elif provider == "vault":
        secrets = VaultSecretsProvider(
            vault_url=kwargs.get("vault_url", "http://localhost:8200"),
            token=kwargs.get("token"),
            mount_path=kwargs.get("mount_path", "transit")
        )
    else:
        raise ValueError(f"Unknown secrets provider: {provider}")
    
    audit = DatabaseAuditLogProvider(kwargs.get("db_session_factory"))
    
    return TrustAgent(
        secrets_provider=secrets,
        audit_provider=audit,
        default_key_id=kwargs.get("default_key_id")
    )


# ============== Singleton Instance ==============

_trust_agent_instance: Optional[TrustAgent] = None


def get_trust_agent() -> TrustAgent:
    """Get the global TrustAgent instance"""
    global _trust_agent_instance
    
    if _trust_agent_instance is None:
        # Initialize with local provider by default
        # In production, configure via environment variables
        provider = os.environ.get("JARWIS_SECRETS_PROVIDER", "local")
        _trust_agent_instance = create_trust_agent(provider=provider)
    
    return _trust_agent_instance


def initialize_trust_agent(provider: str, **kwargs) -> TrustAgent:
    """Initialize the global TrustAgent with specific configuration"""
    global _trust_agent_instance
    _trust_agent_instance = create_trust_agent(provider=provider, **kwargs)
    return _trust_agent_instance
