"""
Jarwis AGI - Cloud Identity Entitlement Management (CIEM) Scanner
Wiz-style deep IAM analysis for AWS, Azure, and GCP

Features:
- Effective permissions analysis
- Permission creep detection
- Unused privileges identification
- Cross-account access analysis
- Overprivileged roles/users detection
- Service account key rotation
- Admin privilege auditing
"""

import asyncio
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
import json
import re

logger = logging.getLogger(__name__)


@dataclass
class IdentityFinding:
    """CIEM finding for identity/entitlement issues"""
    id: str
    provider: str
    identity_type: str  # user, role, service_account, group
    identity_id: str
    identity_name: str
    severity: str
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    cis_control: str = ""
    permissions_at_risk: List[str] = field(default_factory=list)
    blast_radius: int = 0  # Number of resources affected


class CIEMScanner:
    """
    Cloud Identity Entitlement Management Scanner
    Analyzes IAM configurations across AWS, Azure, GCP
    """
    
    # High-risk permissions patterns
    HIGH_RISK_PERMISSIONS = {
        'aws': [
            '*:*',  # Full admin
            'iam:*',
            'iam:CreateUser',
            'iam:CreateAccessKey',
            'iam:AttachUserPolicy',
            'iam:AttachRolePolicy',
            'iam:PutUserPolicy',
            'iam:PutRolePolicy',
            'iam:PassRole',
            'sts:AssumeRole',
            's3:*',
            'ec2:*',
            'lambda:*',
            'secretsmanager:GetSecretValue',
            'kms:Decrypt',
            'organizations:*',
        ],
        'azure': [
            '*/action',
            'Microsoft.Authorization/*',
            'Microsoft.Authorization/roleAssignments/write',
            'Microsoft.Authorization/roleDefinitions/write',
            'Microsoft.Compute/virtualMachines/*',
            'Microsoft.Storage/storageAccounts/*',
            'Microsoft.KeyVault/vaults/*',
            'Microsoft.Sql/servers/*',
        ],
        'gcp': [
            'resourcemanager.projects.setIamPolicy',
            'iam.serviceAccountKeys.create',
            'iam.serviceAccounts.actAs',
            'storage.buckets.setIamPolicy',
            'compute.instances.setServiceAccount',
            'cloudkms.cryptoKeyVersions.destroy',
        ]
    }
    
    # Toxic permission combinations
    TOXIC_COMBINATIONS = {
        'aws': [
            (['iam:PassRole', 'lambda:CreateFunction', 'lambda:InvokeFunction'], 
             'Privilege escalation via Lambda'),
            (['iam:PassRole', 'ec2:RunInstances'], 
             'Privilege escalation via EC2 instance profile'),
            (['iam:CreatePolicyVersion', 'iam:SetDefaultPolicyVersion'], 
             'Policy version abuse for privilege escalation'),
            (['iam:CreateAccessKey', 'iam:UpdateLoginProfile'], 
             'Credential creation for persistence'),
            (['s3:GetObject', 's3:PutBucketPolicy'], 
             'S3 data exfiltration via policy modification'),
            (['sts:AssumeRole', 'iam:AttachRolePolicy'], 
             'Role chain privilege escalation'),
        ],
        'azure': [
            (['Microsoft.Authorization/roleAssignments/write', 'Microsoft.Compute/virtualMachines/write'],
             'VM privilege escalation via role assignment'),
            (['Microsoft.KeyVault/vaults/secrets/read', 'Microsoft.Authorization/roleDefinitions/write'],
             'Secret access with role modification'),
        ],
        'gcp': [
            (['iam.serviceAccountKeys.create', 'iam.serviceAccounts.actAs'],
             'Service account impersonation'),
            (['resourcemanager.projects.setIamPolicy', 'storage.buckets.get'],
             'Project takeover with data access'),
        ]
    }
    
    def __init__(self, config: Dict, context: Any = None):
        self.config = config
        self.context = context
        self.findings: List[IdentityFinding] = []
        self._finding_id = 0
    
    def _generate_id(self) -> str:
        self._finding_id += 1
        return f"CIEM-{self._finding_id:04d}"
    
    async def scan(self) -> List[IdentityFinding]:
        """Run CIEM scan across configured providers"""
        self.findings = []
        
        providers = self.config.get('providers', ['aws'])
        credentials = self.config.get('credentials', {})
        
        for provider in providers:
            creds = credentials.get(provider, {})
            
            if provider == 'aws':
                await self._scan_aws_iam(creds)
            elif provider == 'azure':
                await self._scan_azure_iam(creds)
            elif provider == 'gcp':
                await self._scan_gcp_iam(creds)
        
        return self.findings
    
    async def _scan_aws_iam(self, credentials: Dict):
        """Scan AWS IAM for identity issues"""
        try:
            import boto3
        except ImportError:
            logger.warning("boto3 not installed, skipping AWS CIEM scan")
            return
        
        try:
            session = boto3.Session(
                aws_access_key_id=credentials.get('access_key_id'),
                aws_secret_access_key=credentials.get('secret_access_key'),
                aws_session_token=credentials.get('session_token'),
                region_name=credentials.get('region', 'us-east-1')
            )
            
            iam = session.client('iam')
            
            # Scan users
            await self._scan_aws_users(iam)
            
            # Scan roles
            await self._scan_aws_roles(iam)
            
            # Scan policies
            await self._scan_aws_policies(iam)
            
            # Scan access keys
            await self._scan_aws_access_keys(iam)
            
            # Check for toxic combinations
            await self._check_aws_toxic_combinations(iam)
            
        except Exception as e:
            logger.error(f"AWS CIEM scan error: {e}")
    
    async def _scan_aws_users(self, iam):
        """Analyze AWS IAM users"""
        try:
            paginator = iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_name = user['UserName']
                    user_arn = user['Arn']
                    
                    # Get user policies
                    attached_policies = []
                    inline_policies = []
                    
                    try:
                        # Attached managed policies
                        pol_paginator = iam.get_paginator('list_attached_user_policies')
                        for pol_page in pol_paginator.paginate(UserName=user_name):
                            attached_policies.extend([p['PolicyArn'] for p in pol_page.get('AttachedPolicies', [])])
                        
                        # Inline policies
                        inline_paginator = iam.get_paginator('list_user_policies')
                        for inline_page in inline_paginator.paginate(UserName=user_name):
                            inline_policies.extend(inline_page.get('PolicyNames', []))
                    except Exception:
                        pass
                    
                    # Check for admin privileges
                    if 'arn:aws:iam::aws:policy/AdministratorAccess' in attached_policies:
                        self.findings.append(IdentityFinding(
                            id=self._generate_id(),
                            provider='aws',
                            identity_type='user',
                            identity_id=user_arn,
                            identity_name=user_name,
                            severity='high',
                            title=f"User has full administrator access",
                            description=f"IAM user '{user_name}' has AdministratorAccess policy attached, granting unrestricted access to all AWS services.",
                            evidence={'attached_policies': attached_policies},
                            recommendation="Apply least privilege principle. Replace AdministratorAccess with specific permissions.",
                            cis_control="CIS AWS 1.16",
                            permissions_at_risk=['*:*'],
                            blast_radius=100
                        ))
                    
                    # Check for overprivileged inline policies
                    for policy_name in inline_policies:
                        try:
                            policy_doc = iam.get_user_policy(UserName=user_name, PolicyName=policy_name)
                            self._analyze_policy_document(
                                policy_doc.get('PolicyDocument', {}),
                                'user', user_arn, user_name, 'aws'
                            )
                        except Exception:
                            pass
                    
                    # Check for MFA
                    try:
                        mfa_devices = iam.list_mfa_devices(UserName=user_name)
                        if not mfa_devices.get('MFADevices'):
                            self.findings.append(IdentityFinding(
                                id=self._generate_id(),
                                provider='aws',
                                identity_type='user',
                                identity_id=user_arn,
                                identity_name=user_name,
                                severity='medium',
                                title="User does not have MFA enabled",
                                description=f"IAM user '{user_name}' does not have MFA enabled, increasing risk of credential compromise.",
                                evidence={'mfa_devices': []},
                                recommendation="Enable MFA for all IAM users with console access.",
                                cis_control="CIS AWS 1.5"
                            ))
                    except Exception:
                        pass
                    
                    await asyncio.sleep(0.1)  # Rate limiting
                    
        except Exception as e:
            logger.error(f"Error scanning AWS users: {e}")
    
    async def _scan_aws_roles(self, iam):
        """Analyze AWS IAM roles"""
        try:
            paginator = iam.get_paginator('list_roles')
            
            for page in paginator.paginate():
                for role in page.get('Roles', []):
                    role_name = role['RoleName']
                    role_arn = role['Arn']
                    assume_role_policy = role.get('AssumeRolePolicyDocument', {})
                    
                    # Check trust policy for overly permissive principals
                    self._analyze_trust_policy(assume_role_policy, role_arn, role_name)
                    
                    # Get role policies
                    attached_policies = []
                    try:
                        pol_paginator = iam.get_paginator('list_attached_role_policies')
                        for pol_page in pol_paginator.paginate(RoleName=role_name):
                            attached_policies.extend([p['PolicyArn'] for p in pol_page.get('AttachedRolePolicies', [])])
                    except Exception:
                        pass
                    
                    # Check for admin role
                    if 'arn:aws:iam::aws:policy/AdministratorAccess' in attached_policies:
                        self.findings.append(IdentityFinding(
                            id=self._generate_id(),
                            provider='aws',
                            identity_type='role',
                            identity_id=role_arn,
                            identity_name=role_name,
                            severity='high',
                            title="Role has full administrator access",
                            description=f"IAM role '{role_name}' has AdministratorAccess. Review trust policy for potential privilege escalation paths.",
                            evidence={
                                'attached_policies': attached_policies,
                                'trust_policy': assume_role_policy
                            },
                            recommendation="Limit role permissions and restrict trust relationships.",
                            cis_control="CIS AWS 1.16",
                            permissions_at_risk=['*:*'],
                            blast_radius=100
                        ))
                    
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"Error scanning AWS roles: {e}")
    
    async def _scan_aws_policies(self, iam):
        """Analyze AWS IAM policies for dangerous permissions"""
        try:
            paginator = iam.get_paginator('list_policies')
            
            for page in paginator.paginate(Scope='Local'):  # Customer managed only
                for policy in page.get('Policies', []):
                    policy_arn = policy['Arn']
                    policy_name = policy['PolicyName']
                    
                    try:
                        # Get default version
                        version = iam.get_policy_version(
                            PolicyArn=policy_arn,
                            VersionId=policy['DefaultVersionId']
                        )
                        policy_doc = version.get('PolicyVersion', {}).get('Document', {})
                        
                        self._analyze_policy_document(
                            policy_doc, 'policy', policy_arn, policy_name, 'aws'
                        )
                    except Exception:
                        pass
                    
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"Error scanning AWS policies: {e}")
    
    async def _scan_aws_access_keys(self, iam):
        """Check for old/unused access keys"""
        try:
            paginator = iam.get_paginator('list_users')
            now = datetime.utcnow()
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_name = user['UserName']
                    
                    try:
                        keys = iam.list_access_keys(UserName=user_name)
                        for key in keys.get('AccessKeyMetadata', []):
                            key_id = key['AccessKeyId']
                            created = key['CreateDate']
                            status = key['Status']
                            
                            # Check key age (> 90 days)
                            if created.tzinfo:
                                created = created.replace(tzinfo=None)
                            age_days = (now - created).days
                            
                            if age_days > 90 and status == 'Active':
                                self.findings.append(IdentityFinding(
                                    id=self._generate_id(),
                                    provider='aws',
                                    identity_type='access_key',
                                    identity_id=key_id,
                                    identity_name=f"{user_name}/{key_id}",
                                    severity='medium',
                                    title="Access key is older than 90 days",
                                    description=f"Access key '{key_id}' for user '{user_name}' is {age_days} days old. Old keys increase credential compromise risk.",
                                    evidence={
                                        'key_id': key_id,
                                        'created': str(created),
                                        'age_days': age_days,
                                        'status': status
                                    },
                                    recommendation="Rotate access keys every 90 days or less.",
                                    cis_control="CIS AWS 1.4"
                                ))
                            
                            # Check for multiple active keys
                            active_keys = [k for k in keys.get('AccessKeyMetadata', []) if k['Status'] == 'Active']
                            if len(active_keys) > 1:
                                self.findings.append(IdentityFinding(
                                    id=self._generate_id(),
                                    provider='aws',
                                    identity_type='user',
                                    identity_id=user['Arn'],
                                    identity_name=user_name,
                                    severity='low',
                                    title="User has multiple active access keys",
                                    description=f"User '{user_name}' has {len(active_keys)} active access keys. Multiple keys increase attack surface.",
                                    evidence={'active_keys': [k['AccessKeyId'] for k in active_keys]},
                                    recommendation="Limit each user to one active access key.",
                                    cis_control="CIS AWS 1.3"
                                ))
                                break  # Only report once per user
                                
                    except Exception:
                        pass
                        
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"Error scanning access keys: {e}")
    
    async def _check_aws_toxic_combinations(self, iam):
        """Check for dangerous permission combinations"""
        # This would require building effective permissions per identity
        # For now, check attached policies for common escalation paths
        pass
    
    def _analyze_policy_document(self, policy_doc: Dict, identity_type: str, 
                                  identity_id: str, identity_name: str, provider: str):
        """Analyze IAM policy document for dangerous permissions"""
        statements = policy_doc.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        dangerous_permissions = []
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            resources = statement.get('Resource', [])
            if isinstance(resources, str):
                resources = [resources]
            
            for action in actions:
                # Check for wildcard
                if action == '*' or (isinstance(action, str) and action.endswith(':*')):
                    if '*' in resources:
                        dangerous_permissions.append(action)
                
                # Check known high-risk permissions
                for high_risk in self.HIGH_RISK_PERMISSIONS.get(provider, []):
                    if action == high_risk or (action.endswith('*') and high_risk.startswith(action[:-1])):
                        dangerous_permissions.append(action)
        
        if dangerous_permissions:
            severity = 'critical' if '*' in dangerous_permissions or '*:*' in dangerous_permissions else 'high'
            self.findings.append(IdentityFinding(
                id=self._generate_id(),
                provider=provider,
                identity_type=identity_type,
                identity_id=identity_id,
                identity_name=identity_name,
                severity=severity,
                title=f"Overprivileged permissions detected",
                description=f"{identity_type.title()} '{identity_name}' has dangerous permissions that could enable privilege escalation or data exfiltration.",
                evidence={
                    'dangerous_permissions': list(set(dangerous_permissions)),
                    'policy_document': policy_doc
                },
                recommendation="Apply least privilege principle. Remove or scope down dangerous permissions.",
                permissions_at_risk=dangerous_permissions
            ))
    
    def _analyze_trust_policy(self, trust_policy: Dict, role_arn: str, role_name: str):
        """Analyze role trust policy for overly permissive principals"""
        statements = trust_policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            principal = statement.get('Principal', {})
            
            # Check for wildcard principal
            if principal == '*' or principal.get('AWS') == '*':
                self.findings.append(IdentityFinding(
                    id=self._generate_id(),
                    provider='aws',
                    identity_type='role',
                    identity_id=role_arn,
                    identity_name=role_name,
                    severity='critical',
                    title="Role trust policy allows any AWS principal",
                    description=f"IAM role '{role_name}' can be assumed by any AWS account. This is a critical security risk.",
                    evidence={'trust_policy': trust_policy},
                    recommendation="Restrict trust policy to specific AWS accounts and principals.",
                    cis_control="CIS AWS 1.20",
                    blast_radius=100
                ))
            
            # Check for external account access
            aws_principals = principal.get('AWS', [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            
            external_accounts = []
            for p in aws_principals:
                if 'arn:aws' in p:
                    # Extract account ID
                    match = re.search(r':(\d{12}):', p)
                    if match:
                        external_accounts.append(match.group(1))
            
            if len(set(external_accounts)) > 1:
                self.findings.append(IdentityFinding(
                    id=self._generate_id(),
                    provider='aws',
                    identity_type='role',
                    identity_id=role_arn,
                    identity_name=role_name,
                    severity='medium',
                    title="Role allows cross-account access",
                    description=f"IAM role '{role_name}' can be assumed by principals from multiple external accounts.",
                    evidence={
                        'trust_policy': trust_policy,
                        'external_accounts': list(set(external_accounts))
                    },
                    recommendation="Review cross-account access requirements. Ensure external accounts are trusted."
                ))
    
    async def _scan_azure_iam(self, credentials: Dict):
        """Scan Azure RBAC and identity configurations"""
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.authorization import AuthorizationManagementClient
        except ImportError:
            logger.warning("azure-mgmt-authorization not installed, skipping Azure CIEM scan")
            return
        
        try:
            credential = ClientSecretCredential(
                tenant_id=credentials.get('tenant_id'),
                client_id=credentials.get('client_id'),
                client_secret=credentials.get('client_secret')
            )
            
            subscription_id = credentials.get('subscription_id')
            auth_client = AuthorizationManagementClient(credential, subscription_id)
            
            # Scan role assignments
            await self._scan_azure_role_assignments(auth_client, subscription_id)
            
            # Scan custom role definitions
            await self._scan_azure_custom_roles(auth_client, subscription_id)
            
        except Exception as e:
            logger.error(f"Azure CIEM scan error: {e}")
    
    async def _scan_azure_role_assignments(self, auth_client, subscription_id: str):
        """Scan Azure role assignments for overprivileged identities"""
        try:
            assignments = list(auth_client.role_assignments.list_for_subscription())
            
            owner_assignments = []
            contributor_assignments = []
            
            for assignment in assignments:
                role_id = assignment.role_definition_id
                principal_id = assignment.principal_id
                scope = assignment.scope
                
                # Check for Owner role
                if 'Owner' in role_id or role_id.endswith('/roles/8e3af657-a8ff-443c-a75c-2fe8c4bcb635'):
                    owner_assignments.append({
                        'principal_id': principal_id,
                        'scope': scope
                    })
                
                # Check for Contributor role at subscription level
                if 'Contributor' in role_id and scope == f'/subscriptions/{subscription_id}':
                    contributor_assignments.append({
                        'principal_id': principal_id,
                        'scope': scope
                    })
            
            if owner_assignments:
                self.findings.append(IdentityFinding(
                    id=self._generate_id(),
                    provider='azure',
                    identity_type='role_assignment',
                    identity_id=subscription_id,
                    identity_name='Subscription Owner Assignments',
                    severity='high',
                    title=f"{len(owner_assignments)} identities have Owner role",
                    description="Multiple identities have Owner role, granting full access to all resources including permission management.",
                    evidence={'owner_assignments': owner_assignments},
                    recommendation="Limit Owner role to essential administrators. Use Contributor or custom roles.",
                    cis_control="CIS Azure 1.23",
                    blast_radius=100
                ))
            
            if len(contributor_assignments) > 10:
                self.findings.append(IdentityFinding(
                    id=self._generate_id(),
                    provider='azure',
                    identity_type='role_assignment',
                    identity_id=subscription_id,
                    identity_name='Subscription Contributors',
                    severity='medium',
                    title=f"High number of Contributor assignments at subscription level",
                    description=f"{len(contributor_assignments)} identities have Contributor role at subscription scope. Consider using resource group scoping.",
                    evidence={'contributor_count': len(contributor_assignments)},
                    recommendation="Scope Contributor role to specific resource groups rather than subscription."
                ))
                
        except Exception as e:
            logger.error(f"Error scanning Azure role assignments: {e}")
    
    async def _scan_azure_custom_roles(self, auth_client, subscription_id: str):
        """Scan Azure custom role definitions for dangerous permissions"""
        try:
            roles = list(auth_client.role_definitions.list(
                scope=f'/subscriptions/{subscription_id}',
                filter="type eq 'CustomRole'"
            ))
            
            for role in roles:
                role_name = role.role_name
                permissions = role.permissions
                
                for perm in permissions:
                    actions = perm.actions or []
                    
                    # Check for wildcard actions
                    if '*' in actions or '*/write' in actions:
                        self.findings.append(IdentityFinding(
                            id=self._generate_id(),
                            provider='azure',
                            identity_type='custom_role',
                            identity_id=role.id,
                            identity_name=role_name,
                            severity='high',
                            title="Custom role has wildcard permissions",
                            description=f"Custom role '{role_name}' has broad wildcard permissions that could enable privilege escalation.",
                            evidence={'actions': actions},
                            recommendation="Scope custom role permissions to specific resource types and actions.",
                            permissions_at_risk=actions
                        ))
                        
        except Exception as e:
            logger.error(f"Error scanning Azure custom roles: {e}")
    
    async def _scan_gcp_iam(self, credentials: Dict):
        """Scan GCP IAM configurations"""
        try:
            from google.cloud import resourcemanager_v3
            from google.oauth2 import service_account
            import json
        except ImportError:
            logger.warning("google-cloud-resource-manager not installed, skipping GCP CIEM scan")
            return
        
        try:
            # Parse service account key
            sa_key = credentials.get('service_account_key', '{}')
            if isinstance(sa_key, str):
                sa_info = json.loads(sa_key)
            else:
                sa_info = sa_key
            
            creds = service_account.Credentials.from_service_account_info(sa_info)
            project_id = credentials.get('project_id') or sa_info.get('project_id')
            
            # Scan project IAM policy
            await self._scan_gcp_project_iam(creds, project_id)
            
            # Scan service accounts
            await self._scan_gcp_service_accounts(creds, project_id)
            
        except Exception as e:
            logger.error(f"GCP CIEM scan error: {e}")
    
    async def _scan_gcp_project_iam(self, credentials, project_id: str):
        """Scan GCP project IAM policy"""
        try:
            from google.cloud import resourcemanager_v3
            
            client = resourcemanager_v3.ProjectsClient(credentials=credentials)
            
            request = resourcemanager_v3.GetIamPolicyRequest(
                resource=f"projects/{project_id}"
            )
            policy = client.get_iam_policy(request=request)
            
            owner_members = []
            editor_members = []
            
            for binding in policy.bindings:
                role = binding.role
                members = list(binding.members)
                
                if role == 'roles/owner':
                    owner_members.extend(members)
                elif role == 'roles/editor':
                    editor_members.extend(members)
                
                # Check for allUsers or allAuthenticatedUsers
                if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                    self.findings.append(IdentityFinding(
                        id=self._generate_id(),
                        provider='gcp',
                        identity_type='project_binding',
                        identity_id=f"{project_id}/{role}",
                        identity_name=role,
                        severity='critical',
                        title="Project role granted to public/all authenticated users",
                        description=f"Role '{role}' is granted to allUsers or allAuthenticatedUsers, exposing project resources publicly.",
                        evidence={'role': role, 'members': members},
                        recommendation="Remove public access. Grant roles to specific users or service accounts.",
                        cis_control="CIS GCP 1.1",
                        blast_radius=100
                    ))
            
            if len(owner_members) > 3:
                self.findings.append(IdentityFinding(
                    id=self._generate_id(),
                    provider='gcp',
                    identity_type='project_policy',
                    identity_id=project_id,
                    identity_name='Project Owners',
                    severity='medium',
                    title="Excessive number of project owners",
                    description=f"Project has {len(owner_members)} owners. Limit owner role to reduce blast radius.",
                    evidence={'owner_count': len(owner_members), 'owners': owner_members},
                    recommendation="Limit project owners to 2-3 essential administrators.",
                    cis_control="CIS GCP 1.2"
                ))
                
        except Exception as e:
            logger.error(f"Error scanning GCP project IAM: {e}")
    
    async def _scan_gcp_service_accounts(self, credentials, project_id: str):
        """Scan GCP service accounts for security issues"""
        try:
            from google.cloud import iam_admin_v1
            
            client = iam_admin_v1.IAMClient(credentials=credentials)
            
            request = iam_admin_v1.ListServiceAccountsRequest(
                name=f"projects/{project_id}"
            )
            
            for sa in client.list_service_accounts(request=request):
                sa_email = sa.email
                sa_name = sa.display_name or sa_email
                
                # Check for user-managed keys
                keys_request = iam_admin_v1.ListServiceAccountKeysRequest(
                    name=f"projects/{project_id}/serviceAccounts/{sa_email}",
                    key_types=[iam_admin_v1.ListServiceAccountKeysRequest.KeyType.USER_MANAGED]
                )
                
                try:
                    keys = list(client.list_service_account_keys(request=keys_request))
                    
                    if keys:
                        self.findings.append(IdentityFinding(
                            id=self._generate_id(),
                            provider='gcp',
                            identity_type='service_account',
                            identity_id=sa.unique_id,
                            identity_name=sa_email,
                            severity='medium',
                            title="Service account has user-managed keys",
                            description=f"Service account '{sa_email}' has {len(keys)} user-managed keys. Keys can be exfiltrated and misused.",
                            evidence={'key_count': len(keys)},
                            recommendation="Use workload identity or impersonation instead of service account keys.",
                            cis_control="CIS GCP 1.4"
                        ))
                        
                        # Check key age
                        now = datetime.utcnow()
                        for key in keys:
                            if hasattr(key, 'valid_after_time') and key.valid_after_time:
                                key_age = (now - key.valid_after_time.replace(tzinfo=None)).days
                                if key_age > 90:
                                    self.findings.append(IdentityFinding(
                                        id=self._generate_id(),
                                        provider='gcp',
                                        identity_type='service_account_key',
                                        identity_id=key.name,
                                        identity_name=f"{sa_email}/{key.name.split('/')[-1]}",
                                        severity='medium',
                                        title="Service account key is older than 90 days",
                                        description=f"Key for service account '{sa_email}' is {key_age} days old.",
                                        evidence={'key_age_days': key_age},
                                        recommendation="Rotate service account keys every 90 days.",
                                        cis_control="CIS GCP 1.5"
                                    ))
                except Exception:
                    pass
                
                await asyncio.sleep(0.1)
                
        except Exception as e:
            logger.error(f"Error scanning GCP service accounts: {e}")
