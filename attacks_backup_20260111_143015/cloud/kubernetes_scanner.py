"""
Jarwis AGI - Kubernetes Security Scanner
Comprehensive Kubernetes security assessment

Features:
- Pod Security Standards validation (Baseline, Restricted)
- RBAC misconfiguration detection
- Network Policy analysis
- Secrets management audit
- Admission control validation
- Container security context checks
- Workload hardening assessment
"""

import asyncio
import logging
import subprocess
import json
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
import yaml

logger = logging.getLogger(__name__)


@dataclass
class K8sFinding:
    """Kubernetes security finding"""
    id: str
    namespace: str
    resource_type: str
    resource_name: str
    severity: str
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    cis_control: str = ""
    pss_level: str = ""  # Pod Security Standard level violated


class KubernetesSecurityScanner:
    """
    Kubernetes Security Scanner
    Performs comprehensive K8s cluster security assessment
    """
    
    # Pod Security Standards checks
    PSS_BASELINE_VIOLATIONS = [
        ('hostNetwork', True, 'Pod uses host network'),
        ('hostPID', True, 'Pod uses host PID namespace'),
        ('hostIPC', True, 'Pod uses host IPC namespace'),
        ('privileged', True, 'Container runs in privileged mode'),
        ('allowPrivilegeEscalation', True, 'Container allows privilege escalation'),
    ]
    
    PSS_RESTRICTED_VIOLATIONS = [
        ('runAsNonRoot', False, 'Container may run as root'),
        ('readOnlyRootFilesystem', False, 'Container filesystem is writable'),
        ('runAsUser', 0, 'Container runs as root user (UID 0)'),
    ]
    
    # Dangerous capabilities
    DANGEROUS_CAPABILITIES = [
        'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE',
        'DAC_READ_SEARCH', 'NET_RAW', 'SYS_RAWIO', 'SETUID', 'SETGID'
    ]
    
    # RBAC dangerous permissions
    DANGEROUS_VERBS = ['*', 'create', 'update', 'patch', 'delete']
    DANGEROUS_RESOURCES = ['secrets', 'pods/exec', 'pods/attach', 'serviceaccounts/token']
    
    def __init__(self, config: Dict, context: Any = None):
        self.config = config
        self.context = context
        self.findings: List[K8sFinding] = []
        self._finding_id = 0
        self.kubeconfig = config.get('kubeconfig')
        self.namespaces = config.get('namespaces', [])  # Empty means all
    
    def _generate_id(self) -> str:
        self._finding_id += 1
        return f"K8S-{self._finding_id:04d}"
    
    async def scan(self) -> List[K8sFinding]:
        """Run full Kubernetes security scan"""
        self.findings = []
        
        # Check kubectl availability
        if not await self._check_kubectl():
            logger.error("kubectl not available or not configured")
            return self.findings
        
        # Get namespaces to scan
        if not self.namespaces:
            self.namespaces = await self._get_all_namespaces()
        
        # Run all security checks
        await self._scan_pod_security()
        await self._scan_rbac()
        await self._scan_network_policies()
        await self._scan_secrets()
        await self._scan_service_accounts()
        await self._scan_admission_controllers()
        await self._scan_api_server()
        
        return self.findings
    
    async def _check_kubectl(self) -> bool:
        """Check if kubectl is available and configured"""
        try:
            result = await self._run_kubectl(['version', '--client', '-o', 'json'])
            return result is not None
        except Exception:
            return False
    
    async def _run_kubectl(self, args: List[str], namespace: str = None) -> Optional[Dict]:
        """Run kubectl command and return JSON output"""
        try:
            cmd = ['kubectl']
            
            if self.kubeconfig:
                cmd.extend(['--kubeconfig', self.kubeconfig])
            
            if namespace:
                cmd.extend(['-n', namespace])
            
            cmd.extend(args)
            cmd.extend(['-o', 'json'])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return json.loads(result.stdout)
            return None
            
        except Exception as e:
            logger.debug(f"kubectl command failed: {e}")
            return None
    
    async def _get_all_namespaces(self) -> List[str]:
        """Get all namespaces in the cluster"""
        result = await self._run_kubectl(['get', 'namespaces'])
        if result and 'items' in result:
            return [ns['metadata']['name'] for ns in result['items']]
        return ['default']
    
    async def _scan_pod_security(self):
        """Scan pods for security issues"""
        for namespace in self.namespaces:
            pods = await self._run_kubectl(['get', 'pods'], namespace=namespace)
            
            if not pods or 'items' not in pods:
                continue
            
            for pod in pods['items']:
                pod_name = pod['metadata']['name']
                pod_spec = pod.get('spec', {})
                
                # Check host namespaces
                if pod_spec.get('hostNetwork'):
                    self.findings.append(K8sFinding(
                        id=self._generate_id(),
                        namespace=namespace,
                        resource_type='Pod',
                        resource_name=pod_name,
                        severity='high',
                        title="Pod uses host network namespace",
                        description=f"Pod '{pod_name}' has hostNetwork=true, allowing access to host network interfaces.",
                        evidence={'hostNetwork': True},
                        recommendation="Remove hostNetwork unless absolutely required.",
                        cis_control="CIS K8s 5.2.4",
                        pss_level="baseline"
                    ))
                
                if pod_spec.get('hostPID'):
                    self.findings.append(K8sFinding(
                        id=self._generate_id(),
                        namespace=namespace,
                        resource_type='Pod',
                        resource_name=pod_name,
                        severity='high',
                        title="Pod uses host PID namespace",
                        description=f"Pod '{pod_name}' has hostPID=true, allowing access to host processes.",
                        evidence={'hostPID': True},
                        recommendation="Remove hostPID unless absolutely required.",
                        cis_control="CIS K8s 5.2.2",
                        pss_level="baseline"
                    ))
                
                if pod_spec.get('hostIPC'):
                    self.findings.append(K8sFinding(
                        id=self._generate_id(),
                        namespace=namespace,
                        resource_type='Pod',
                        resource_name=pod_name,
                        severity='high',
                        title="Pod uses host IPC namespace",
                        description=f"Pod '{pod_name}' has hostIPC=true, allowing access to host IPC.",
                        evidence={'hostIPC': True},
                        recommendation="Remove hostIPC unless absolutely required.",
                        cis_control="CIS K8s 5.2.3",
                        pss_level="baseline"
                    ))
                
                # Check containers
                containers = pod_spec.get('containers', []) + pod_spec.get('initContainers', [])
                
                for container in containers:
                    container_name = container.get('name', 'unknown')
                    security_context = container.get('securityContext', {})
                    
                    # Check privileged mode
                    if security_context.get('privileged'):
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace=namespace,
                            resource_type='Container',
                            resource_name=f"{pod_name}/{container_name}",
                            severity='critical',
                            title="Container runs in privileged mode",
                            description=f"Container '{container_name}' in pod '{pod_name}' runs with privileged=true, granting host-level access.",
                            evidence={'privileged': True},
                            recommendation="Remove privileged mode. Use specific capabilities instead.",
                            cis_control="CIS K8s 5.2.1",
                            pss_level="baseline"
                        ))
                    
                    # Check allowPrivilegeEscalation
                    if security_context.get('allowPrivilegeEscalation', True):  # Default is true
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace=namespace,
                            resource_type='Container',
                            resource_name=f"{pod_name}/{container_name}",
                            severity='medium',
                            title="Container allows privilege escalation",
                            description=f"Container '{container_name}' allows privilege escalation (default or explicit).",
                            evidence={'allowPrivilegeEscalation': security_context.get('allowPrivilegeEscalation', 'default')},
                            recommendation="Set allowPrivilegeEscalation: false",
                            cis_control="CIS K8s 5.2.5",
                            pss_level="restricted"
                        ))
                    
                    # Check runAsNonRoot
                    if not security_context.get('runAsNonRoot'):
                        run_as_user = security_context.get('runAsUser')
                        if run_as_user is None or run_as_user == 0:
                            self.findings.append(K8sFinding(
                                id=self._generate_id(),
                                namespace=namespace,
                                resource_type='Container',
                                resource_name=f"{pod_name}/{container_name}",
                                severity='medium',
                                title="Container may run as root",
                                description=f"Container '{container_name}' does not enforce running as non-root.",
                                evidence={
                                    'runAsNonRoot': security_context.get('runAsNonRoot'),
                                    'runAsUser': run_as_user
                                },
                                recommendation="Set runAsNonRoot: true and runAsUser to a non-zero UID.",
                                cis_control="CIS K8s 5.2.6",
                                pss_level="restricted"
                            ))
                    
                    # Check capabilities
                    capabilities = security_context.get('capabilities', {})
                    add_caps = capabilities.get('add', [])
                    
                    dangerous_caps = [c for c in add_caps if c in self.DANGEROUS_CAPABILITIES]
                    if dangerous_caps:
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace=namespace,
                            resource_type='Container',
                            resource_name=f"{pod_name}/{container_name}",
                            severity='high',
                            title="Container has dangerous capabilities",
                            description=f"Container '{container_name}' has dangerous capabilities: {', '.join(dangerous_caps)}",
                            evidence={'capabilities': add_caps, 'dangerous': dangerous_caps},
                            recommendation="Remove dangerous capabilities. Use minimal required capabilities.",
                            cis_control="CIS K8s 5.2.7",
                            pss_level="baseline"
                        ))
                    
                    # Check read-only filesystem
                    if not security_context.get('readOnlyRootFilesystem'):
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace=namespace,
                            resource_type='Container',
                            resource_name=f"{pod_name}/{container_name}",
                            severity='low',
                            title="Container has writable root filesystem",
                            description=f"Container '{container_name}' has a writable root filesystem.",
                            evidence={'readOnlyRootFilesystem': False},
                            recommendation="Set readOnlyRootFilesystem: true. Use emptyDir for writable paths.",
                            cis_control="CIS K8s 5.2.8",
                            pss_level="restricted"
                        ))
                    
                    # Check for latest tag
                    image = container.get('image', '')
                    if ':latest' in image or ':' not in image:
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace=namespace,
                            resource_type='Container',
                            resource_name=f"{pod_name}/{container_name}",
                            severity='medium',
                            title="Container uses 'latest' or untagged image",
                            description=f"Container '{container_name}' uses image '{image}' without a specific version tag.",
                            evidence={'image': image},
                            recommendation="Use specific image tags/digests for reproducibility and security.",
                            cis_control="CIS K8s 5.5.1"
                        ))
            
            await asyncio.sleep(0.1)
    
    async def _scan_rbac(self):
        """Scan RBAC configurations for security issues"""
        # Scan ClusterRoles
        cluster_roles = await self._run_kubectl(['get', 'clusterroles'])
        
        if cluster_roles and 'items' in cluster_roles:
            for role in cluster_roles['items']:
                role_name = role['metadata']['name']
                rules = role.get('rules', [])
                
                for rule in rules:
                    verbs = rule.get('verbs', [])
                    resources = rule.get('resources', [])
                    
                    # Check for wildcard access
                    if '*' in verbs and '*' in resources:
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace='cluster',
                            resource_type='ClusterRole',
                            resource_name=role_name,
                            severity='critical',
                            title="ClusterRole has full wildcard access",
                            description=f"ClusterRole '{role_name}' grants * verbs on * resources (full cluster admin).",
                            evidence={'rules': rules},
                            recommendation="Apply least privilege. Scope to specific resources and verbs.",
                            cis_control="CIS K8s 5.1.1"
                        ))
                    
                    # Check for secrets access
                    if 'secrets' in resources and any(v in verbs for v in ['*', 'get', 'list', 'watch']):
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace='cluster',
                            resource_type='ClusterRole',
                            resource_name=role_name,
                            severity='high',
                            title="ClusterRole can access secrets",
                            description=f"ClusterRole '{role_name}' can read secrets across namespaces.",
                            evidence={'secrets_access': {'resources': resources, 'verbs': verbs}},
                            recommendation="Limit secrets access to specific namespaces using Roles.",
                            cis_control="CIS K8s 5.1.2"
                        ))
                    
                    # Check for pod exec access
                    if 'pods/exec' in resources or ('pods' in resources and 'exec' in rule.get('verbs', [])):
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace='cluster',
                            resource_type='ClusterRole',
                            resource_name=role_name,
                            severity='high',
                            title="ClusterRole can exec into pods",
                            description=f"ClusterRole '{role_name}' can execute commands in pods.",
                            evidence={'exec_access': True},
                            recommendation="Limit pod/exec access. Consider using audit logging.",
                            cis_control="CIS K8s 5.1.3"
                        ))
        
        # Scan ClusterRoleBindings for default service account
        bindings = await self._run_kubectl(['get', 'clusterrolebindings'])
        
        if bindings and 'items' in bindings:
            for binding in bindings['items']:
                binding_name = binding['metadata']['name']
                subjects = binding.get('subjects', [])
                role_ref = binding.get('roleRef', {})
                
                for subject in subjects:
                    if subject.get('kind') == 'ServiceAccount' and subject.get('name') == 'default':
                        self.findings.append(K8sFinding(
                            id=self._generate_id(),
                            namespace=subject.get('namespace', 'default'),
                            resource_type='ClusterRoleBinding',
                            resource_name=binding_name,
                            severity='medium',
                            title="Default ServiceAccount has ClusterRole binding",
                            description=f"Default service account in namespace '{subject.get('namespace', 'default')}' is bound to ClusterRole '{role_ref.get('name')}'.",
                            evidence={'binding': binding_name, 'role': role_ref.get('name')},
                            recommendation="Create dedicated service accounts for workloads. Don't use default.",
                            cis_control="CIS K8s 5.1.5"
                        ))
    
    async def _scan_network_policies(self):
        """Check for missing network policies"""
        for namespace in self.namespaces:
            # Skip system namespaces
            if namespace in ['kube-system', 'kube-public', 'kube-node-lease']:
                continue
            
            netpols = await self._run_kubectl(['get', 'networkpolicies'], namespace=namespace)
            
            if not netpols or not netpols.get('items'):
                pods = await self._run_kubectl(['get', 'pods'], namespace=namespace)
                if pods and pods.get('items'):
                    self.findings.append(K8sFinding(
                        id=self._generate_id(),
                        namespace=namespace,
                        resource_type='Namespace',
                        resource_name=namespace,
                        severity='medium',
                        title="Namespace has no NetworkPolicies",
                        description=f"Namespace '{namespace}' has {len(pods['items'])} pods but no NetworkPolicies. All pod-to-pod traffic is allowed.",
                        evidence={'pod_count': len(pods['items'])},
                        recommendation="Implement NetworkPolicies to restrict pod-to-pod communication.",
                        cis_control="CIS K8s 5.3.2"
                    ))
            else:
                # Check for default deny policies
                has_default_deny = False
                for netpol in netpols.get('items', []):
                    spec = netpol.get('spec', {})
                    pod_selector = spec.get('podSelector', {})
                    
                    # Default deny = empty podSelector with no ingress/egress rules
                    if not pod_selector.get('matchLabels') and not pod_selector.get('matchExpressions'):
                        if not spec.get('ingress') or not spec.get('egress'):
                            has_default_deny = True
                
                if not has_default_deny:
                    self.findings.append(K8sFinding(
                        id=self._generate_id(),
                        namespace=namespace,
                        resource_type='Namespace',
                        resource_name=namespace,
                        severity='low',
                        title="Namespace lacks default deny NetworkPolicy",
                        description=f"Namespace '{namespace}' has NetworkPolicies but no default deny policy.",
                        evidence={'network_policies': [np['metadata']['name'] for np in netpols.get('items', [])]},
                        recommendation="Add a default deny policy and explicitly allow required traffic.",
                        cis_control="CIS K8s 5.3.2"
                    ))
    
    async def _scan_secrets(self):
        """Scan secrets for security issues"""
        for namespace in self.namespaces:
            secrets = await self._run_kubectl(['get', 'secrets'], namespace=namespace)
            
            if not secrets or 'items' not in secrets:
                continue
            
            for secret in secrets['items']:
                secret_name = secret['metadata']['name']
                secret_type = secret.get('type', '')
                
                # Skip service account tokens
                if secret_type == 'kubernetes.io/service-account-token':
                    continue
                
                # Check for secrets without encryption annotation (if using external secrets)
                annotations = secret['metadata'].get('annotations', {})
                
                # Check age of secrets (stale secrets)
                creation = secret['metadata'].get('creationTimestamp')
                if creation:
                    try:
                        from datetime import datetime
                        created = datetime.fromisoformat(creation.replace('Z', '+00:00'))
                        age_days = (datetime.now(created.tzinfo) - created).days
                        
                        if age_days > 365:
                            self.findings.append(K8sFinding(
                                id=self._generate_id(),
                                namespace=namespace,
                                resource_type='Secret',
                                resource_name=secret_name,
                                severity='low',
                                title="Secret is older than 1 year",
                                description=f"Secret '{secret_name}' is {age_days} days old. Consider rotating.",
                                evidence={'age_days': age_days, 'created': creation},
                                recommendation="Rotate secrets regularly. Use external secret management.",
                                cis_control="CIS K8s 5.4.1"
                            ))
                    except Exception:
                        pass
    
    async def _scan_service_accounts(self):
        """Scan service accounts for security issues"""
        for namespace in self.namespaces:
            sas = await self._run_kubectl(['get', 'serviceaccounts'], namespace=namespace)
            
            if not sas or 'items' not in sas:
                continue
            
            for sa in sas['items']:
                sa_name = sa['metadata']['name']
                
                # Check for automountServiceAccountToken
                if sa.get('automountServiceAccountToken', True):  # Default is true
                    # Check if any pods use this SA
                    pods = await self._run_kubectl(['get', 'pods'], namespace=namespace)
                    if pods and 'items' in pods:
                        sa_pods = [p for p in pods['items'] 
                                   if p['spec'].get('serviceAccountName', 'default') == sa_name]
                        
                        if sa_pods and sa_name == 'default':
                            self.findings.append(K8sFinding(
                                id=self._generate_id(),
                                namespace=namespace,
                                resource_type='ServiceAccount',
                                resource_name=sa_name,
                                severity='medium',
                                title="Default service account token auto-mounted",
                                description=f"Default service account in namespace '{namespace}' auto-mounts tokens to {len(sa_pods)} pods.",
                                evidence={'pod_count': len(sa_pods)},
                                recommendation="Set automountServiceAccountToken: false on default SA.",
                                cis_control="CIS K8s 5.1.6"
                            ))
    
    async def _scan_admission_controllers(self):
        """Check for important admission controllers"""
        # This requires cluster-admin access to check API server flags
        # For now, we check if PodSecurityPolicy or Pod Security Admission is in use
        
        # Check for PodSecurityPolicies (deprecated but still used)
        psps = await self._run_kubectl(['get', 'podsecuritypolicies'])
        
        if not psps or not psps.get('items'):
            # Check for PodSecurity namespace labels
            namespaces = await self._run_kubectl(['get', 'namespaces'])
            pss_enabled = False
            
            if namespaces and 'items' in namespaces:
                for ns in namespaces['items']:
                    labels = ns['metadata'].get('labels', {})
                    if any(k.startswith('pod-security.kubernetes.io/') for k in labels):
                        pss_enabled = True
                        break
            
            if not pss_enabled:
                self.findings.append(K8sFinding(
                    id=self._generate_id(),
                    namespace='cluster',
                    resource_type='Cluster',
                    resource_name='admission-control',
                    severity='high',
                    title="No Pod Security enforcement detected",
                    description="Neither PodSecurityPolicies nor Pod Security Admission labels found. Pod security is not enforced.",
                    evidence={},
                    recommendation="Enable Pod Security Admission with 'restricted' or 'baseline' level.",
                    cis_control="CIS K8s 5.2.1"
                ))
    
    async def _scan_api_server(self):
        """Check API server security configurations (limited without direct access)"""
        # Check for anonymous auth by trying unauthenticated request
        try:
            result = subprocess.run(
                ['kubectl', 'auth', 'can-i', '--list', '--as=system:anonymous'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0 and 'yes' in result.stdout.lower():
                self.findings.append(K8sFinding(
                    id=self._generate_id(),
                    namespace='cluster',
                    resource_type='APIServer',
                    resource_name='anonymous-access',
                    severity='high',
                    title="Anonymous authentication may be enabled",
                    description="API server appears to allow anonymous access with some permissions.",
                    evidence={'output': result.stdout[:500]},
                    recommendation="Disable anonymous authentication: --anonymous-auth=false",
                    cis_control="CIS K8s 1.2.1"
                ))
        except Exception:
            pass
