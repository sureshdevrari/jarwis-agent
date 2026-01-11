"""
Jarwis AGI - Drift Detection Scanner
Detects configuration drift between IaC definitions and deployed cloud resources

Features:
- Terraform state vs deployed resource comparison
- CloudFormation stack drift detection
- Kubernetes manifest vs live resource comparison
- Security-relevant drift identification
- Compliance drift tracking
"""

import asyncio
import logging
import subprocess
import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DriftFinding:
    """Configuration drift finding"""
    id: str
    provider: str
    resource_type: str
    resource_id: str
    severity: str
    title: str
    description: str
    expected_config: Dict = field(default_factory=dict)
    actual_config: Dict = field(default_factory=dict)
    drift_type: str = ""  # added, removed, modified
    security_impact: str = ""
    recommendation: str = ""


class DriftDetectionScanner:
    """
    Configuration Drift Detection Scanner
    Compares IaC definitions with deployed resources
    """
    
    # Security-critical properties to monitor for drift
    SECURITY_PROPERTIES = {
        'aws': {
            'aws_security_group': ['ingress', 'egress', 'vpc_id'],
            'aws_s3_bucket': ['acl', 'versioning', 'logging', 'server_side_encryption_configuration'],
            'aws_iam_role': ['assume_role_policy', 'managed_policy_arns', 'inline_policy'],
            'aws_iam_policy': ['policy'],
            'aws_kms_key': ['key_policy', 'enable_key_rotation'],
            'aws_db_instance': ['publicly_accessible', 'storage_encrypted', 'iam_database_authentication_enabled'],
            'aws_instance': ['iam_instance_profile', 'security_groups', 'subnet_id'],
        },
        'azure': {
            'azurerm_storage_account': ['allow_blob_public_access', 'min_tls_version', 'enable_https_traffic_only'],
            'azurerm_network_security_group': ['security_rule'],
            'azurerm_key_vault': ['soft_delete_enabled', 'purge_protection_enabled', 'network_acls'],
            'azurerm_sql_server': ['public_network_access_enabled', 'administrator_login'],
        },
        'gcp': {
            'google_storage_bucket': ['uniform_bucket_level_access', 'versioning', 'logging'],
            'google_compute_firewall': ['allow', 'deny', 'source_ranges'],
            'google_compute_instance': ['service_account', 'network_interface'],
        }
    }
    
    def __init__(self, config: Dict, context: Any = None):
        self.config = config
        self.context = context
        self.findings: List[DriftFinding] = []
        self._finding_id = 0
    
    def _generate_id(self) -> str:
        self._finding_id += 1
        return f"DRIFT-{self._finding_id:04d}"
    
    async def scan(self) -> List[DriftFinding]:
        """Run drift detection scan"""
        self.findings = []
        
        iac_type = self.config.get('iac_type', 'terraform')
        iac_path = self.config.get('iac_path')
        
        if iac_type == 'terraform':
            await self._detect_terraform_drift(iac_path)
        elif iac_type == 'cloudformation':
            await self._detect_cloudformation_drift()
        elif iac_type == 'kubernetes':
            await self._detect_kubernetes_drift(iac_path)
        
        return self.findings
    
    async def _detect_terraform_drift(self, tf_path: str = None):
        """Detect drift in Terraform-managed resources"""
        if not tf_path:
            tf_path = self.config.get('terraform_path', '.')
        
        # Check if terraform is available
        try:
            result = subprocess.run(
                ['terraform', 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode != 0:
                logger.warning("Terraform not available")
                return
        except Exception:
            logger.warning("Terraform not found")
            return
        
        # Run terraform plan to detect drift
        try:
            # Initialize if needed
            init_result = subprocess.run(
                ['terraform', 'init', '-input=false'],
                cwd=tf_path,
                capture_output=True,
                text=True,
                timeout=120
            )
            
            # Run plan with detailed exit code
            plan_result = subprocess.run(
                ['terraform', 'plan', '-detailed-exitcode', '-input=false', '-no-color'],
                cwd=tf_path,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            # Exit code 2 means changes detected (drift)
            if plan_result.returncode == 2:
                await self._parse_terraform_plan_output(plan_result.stdout, tf_path)
            elif plan_result.returncode == 0:
                logger.info("No drift detected in Terraform resources")
            else:
                logger.error(f"Terraform plan failed: {plan_result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.error("Terraform plan timed out")
        except Exception as e:
            logger.error(f"Terraform drift detection error: {e}")
    
    async def _parse_terraform_plan_output(self, plan_output: str, tf_path: str):
        """Parse Terraform plan output for security-relevant drift"""
        lines = plan_output.split('\n')
        current_resource = None
        current_changes = []
        
        for line in lines:
            # Detect resource changes
            if line.strip().startswith('# '):
                if current_resource and current_changes:
                    await self._analyze_terraform_changes(current_resource, current_changes)
                
                # Parse resource identifier
                parts = line.strip('# ').split()
                if len(parts) >= 1:
                    current_resource = parts[0]
                    current_changes = []
            
            # Collect change lines
            elif current_resource and (line.strip().startswith('+') or 
                                        line.strip().startswith('-') or 
                                        line.strip().startswith('~')):
                current_changes.append(line)
        
        # Process last resource
        if current_resource and current_changes:
            await self._analyze_terraform_changes(current_resource, current_changes)
    
    async def _analyze_terraform_changes(self, resource: str, changes: List[str]):
        """Analyze if Terraform changes are security-relevant"""
        # Determine resource type
        parts = resource.split('.')
        resource_type = parts[0] if parts else resource
        resource_name = parts[1] if len(parts) > 1 else resource
        
        # Check if this resource type has security-critical properties
        provider = 'aws'  # Default, should be detected from resource type
        if resource_type.startswith('azurerm_'):
            provider = 'azure'
        elif resource_type.startswith('google_'):
            provider = 'gcp'
        
        security_props = self.SECURITY_PROPERTIES.get(provider, {}).get(resource_type, [])
        
        security_changes = []
        all_changes = {}
        
        for change in changes:
            clean_line = change.strip().lstrip('+-~ ')
            
            if '=' in clean_line:
                prop_name = clean_line.split('=')[0].strip().strip('"')
                
                all_changes[prop_name] = change
                
                # Check if it's a security property
                for sec_prop in security_props:
                    if sec_prop in prop_name or prop_name.startswith(sec_prop):
                        security_changes.append((prop_name, change))
        
        # Determine drift type
        drift_type = 'modified'
        if all(c.strip().startswith('+') for c in changes):
            drift_type = 'added'
        elif all(c.strip().startswith('-') for c in changes):
            drift_type = 'removed'
        
        # Create finding based on severity
        if security_changes:
            severity = 'high'
            title = f"Security-relevant drift in {resource_type}"
            security_impact = f"Changes to security properties: {', '.join([s[0] for s in security_changes])}"
        else:
            severity = 'low'
            title = f"Configuration drift in {resource_type}"
            security_impact = "No direct security impact detected"
        
        self.findings.append(DriftFinding(
            id=self._generate_id(),
            provider=provider,
            resource_type=resource_type,
            resource_id=resource_name,
            severity=severity,
            title=title,
            description=f"Resource '{resource}' has drifted from its IaC definition.",
            expected_config={'from_iac': True},
            actual_config={'changes': [c.strip() for c in changes[:10]]},  # First 10 changes
            drift_type=drift_type,
            security_impact=security_impact,
            recommendation="Review the changes and update IaC or resource to resolve drift."
        ))
    
    async def _detect_cloudformation_drift(self):
        """Detect drift in CloudFormation stacks"""
        credentials = self.config.get('credentials', {}).get('aws', {})
        stack_names = self.config.get('stack_names', [])
        
        try:
            import boto3
        except ImportError:
            logger.warning("boto3 not installed, skipping CloudFormation drift detection")
            return
        
        try:
            session = boto3.Session(
                aws_access_key_id=credentials.get('access_key_id'),
                aws_secret_access_key=credentials.get('secret_access_key'),
                aws_session_token=credentials.get('session_token'),
                region_name=credentials.get('region', 'us-east-1')
            )
            
            cfn = session.client('cloudformation')
            
            # Get all stacks if none specified
            if not stack_names:
                paginator = cfn.get_paginator('list_stacks')
                for page in paginator.paginate(StackStatusFilter=['CREATE_COMPLETE', 'UPDATE_COMPLETE']):
                    stack_names.extend([s['StackName'] for s in page.get('StackSummaries', [])])
            
            for stack_name in stack_names:
                await self._check_cfn_stack_drift(cfn, stack_name)
                await asyncio.sleep(1)  # Rate limiting
                
        except Exception as e:
            logger.error(f"CloudFormation drift detection error: {e}")
    
    async def _check_cfn_stack_drift(self, cfn, stack_name: str):
        """Check drift for a specific CloudFormation stack"""
        try:
            # Initiate drift detection
            response = cfn.detect_stack_drift(StackName=stack_name)
            drift_detection_id = response['StackDriftDetectionId']
            
            # Wait for drift detection to complete
            for _ in range(30):  # Max 5 minutes
                status = cfn.describe_stack_drift_detection_status(
                    StackDriftDetectionId=drift_detection_id
                )
                
                if status['DetectionStatus'] == 'DETECTION_COMPLETE':
                    break
                elif status['DetectionStatus'] == 'DETECTION_FAILED':
                    logger.error(f"Drift detection failed for stack {stack_name}")
                    return
                
                await asyncio.sleep(10)
            
            # Check drift status
            if status.get('StackDriftStatus') == 'DRIFTED':
                # Get detailed drift information
                drifts = cfn.describe_stack_resource_drifts(
                    StackName=stack_name,
                    StackResourceDriftStatusFilters=['MODIFIED', 'DELETED']
                )
                
                for drift in drifts.get('StackResourceDrifts', []):
                    resource_type = drift['ResourceType']
                    logical_id = drift['LogicalResourceId']
                    physical_id = drift.get('PhysicalResourceId', 'unknown')
                    drift_status = drift['StackResourceDriftStatus']
                    
                    # Parse property differences
                    property_diffs = []
                    if 'PropertyDifferences' in drift:
                        for diff in drift['PropertyDifferences']:
                            property_diffs.append({
                                'property': diff['PropertyPath'],
                                'expected': diff.get('ExpectedValue'),
                                'actual': diff.get('ActualValue'),
                                'difference_type': diff['DifferenceType']
                            })
                    
                    # Determine severity based on resource type
                    severity = 'medium'
                    if any(sec in resource_type for sec in ['SecurityGroup', 'IAM', 'KMS', 'S3']):
                        severity = 'high'
                    
                    self.findings.append(DriftFinding(
                        id=self._generate_id(),
                        provider='aws',
                        resource_type=resource_type,
                        resource_id=physical_id,
                        severity=severity,
                        title=f"CloudFormation resource drifted: {logical_id}",
                        description=f"Resource '{logical_id}' in stack '{stack_name}' has drifted from its template definition.",
                        expected_config={'template_logical_id': logical_id},
                        actual_config={'property_differences': property_diffs},
                        drift_type='modified' if drift_status == 'MODIFIED' else 'removed',
                        security_impact="Review changes for security implications.",
                        recommendation="Update the stack or manually correct the resource configuration."
                    ))
                    
        except Exception as e:
            logger.error(f"Error checking drift for stack {stack_name}: {e}")
    
    async def _detect_kubernetes_drift(self, manifests_path: str = None):
        """Detect drift between Kubernetes manifests and live resources"""
        if not manifests_path:
            manifests_path = self.config.get('kubernetes_manifests', '.')
        
        manifests_dir = Path(manifests_path)
        if not manifests_dir.exists():
            logger.warning(f"Kubernetes manifests path not found: {manifests_path}")
            return
        
        # Find all YAML/JSON manifests
        manifest_files = list(manifests_dir.glob('**/*.yaml')) + \
                        list(manifests_dir.glob('**/*.yml')) + \
                        list(manifests_dir.glob('**/*.json'))
        
        for manifest_file in manifest_files:
            await self._compare_k8s_manifest(manifest_file)
    
    async def _compare_k8s_manifest(self, manifest_path: Path):
        """Compare a Kubernetes manifest with live resource"""
        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not installed")
            return
        
        try:
            with open(manifest_path, 'r') as f:
                content = f.read()
            
            # Handle multi-document YAML
            docs = list(yaml.safe_load_all(content))
            
            for doc in docs:
                if not doc or not isinstance(doc, dict):
                    continue
                
                kind = doc.get('kind')
                metadata = doc.get('metadata', {})
                name = metadata.get('name')
                namespace = metadata.get('namespace', 'default')
                
                if not kind or not name:
                    continue
                
                # Get live resource
                await self._compare_k8s_resource(kind, name, namespace, doc, str(manifest_path))
                
        except Exception as e:
            logger.debug(f"Error parsing manifest {manifest_path}: {e}")
    
    async def _compare_k8s_resource(self, kind: str, name: str, namespace: str, 
                                     expected: Dict, manifest_path: str):
        """Compare expected manifest with live Kubernetes resource"""
        try:
            cmd = ['kubectl', 'get', kind, name, '-n', namespace, '-o', 'json']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                if 'NotFound' in result.stderr:
                    self.findings.append(DriftFinding(
                        id=self._generate_id(),
                        provider='kubernetes',
                        resource_type=kind,
                        resource_id=f"{namespace}/{name}",
                        severity='medium',
                        title=f"Kubernetes resource missing: {kind}/{name}",
                        description=f"Resource defined in {manifest_path} does not exist in cluster.",
                        expected_config={'manifest': manifest_path},
                        actual_config={'status': 'not_found'},
                        drift_type='removed',
                        security_impact="Resource may have been deleted outside of GitOps workflow.",
                        recommendation="Apply the manifest or remove from source control."
                    ))
                return
            
            live = json.loads(result.stdout)
            
            # Compare specs
            expected_spec = expected.get('spec', {})
            live_spec = live.get('spec', {})
            
            # Security-relevant fields to compare
            security_fields = {
                'Pod': ['containers', 'securityContext', 'serviceAccountName'],
                'Deployment': ['template'],
                'Service': ['type', 'ports'],
                'NetworkPolicy': ['ingress', 'egress', 'podSelector'],
                'Role': ['rules'],
                'ClusterRole': ['rules'],
                'RoleBinding': ['subjects', 'roleRef'],
            }
            
            fields_to_check = security_fields.get(kind, list(expected_spec.keys()))
            
            differences = []
            for field in fields_to_check:
                expected_val = expected_spec.get(field)
                live_val = live_spec.get(field)
                
                if expected_val != live_val:
                    # Deep comparison for complex objects
                    if isinstance(expected_val, dict) and isinstance(live_val, dict):
                        if json.dumps(expected_val, sort_keys=True) != json.dumps(live_val, sort_keys=True):
                            differences.append(field)
                    elif expected_val is not None:  # Only flag if expected value exists
                        differences.append(field)
            
            if differences:
                severity = 'medium'
                if kind in ['NetworkPolicy', 'Role', 'ClusterRole', 'RoleBinding', 'ClusterRoleBinding']:
                    severity = 'high'
                
                self.findings.append(DriftFinding(
                    id=self._generate_id(),
                    provider='kubernetes',
                    resource_type=kind,
                    resource_id=f"{namespace}/{name}",
                    severity=severity,
                    title=f"Kubernetes resource drifted: {kind}/{name}",
                    description=f"Resource differs from manifest in: {', '.join(differences)}",
                    expected_config={'manifest': manifest_path, 'diff_fields': differences},
                    actual_config={'live_resource': f"{namespace}/{name}"},
                    drift_type='modified',
                    security_impact=f"Changes in {', '.join(differences)} may affect security posture.",
                    recommendation="Sync the resource with the manifest using kubectl apply."
                ))
                
        except Exception as e:
            logger.debug(f"Error comparing K8s resource {kind}/{name}: {e}")
