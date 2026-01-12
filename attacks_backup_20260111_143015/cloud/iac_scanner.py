"""
Jarwis AGI - Infrastructure as Code Scanner
Scans Terraform, CloudFormation, Kubernetes, ARM templates
"""

import json
import asyncio
import logging
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any
import uuid

logger = logging.getLogger(__name__)

@dataclass
class IaCFinding:
    """IaC security finding"""
    id: str
    file_path: str
    line_number: int
    severity: str
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    remediation: str = ""

class IaCScanner:
    """Infrastructure as Code Security Scanner"""
    
    def __init__(self, iac_paths: List[str], providers: List[str]):
        self.iac_paths = iac_paths
        self.providers = providers
        self.findings: List[IaCFinding] = []
        
        # Secret patterns
        self.secret_patterns = {
            'aws_access_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret_key': r'(?i)aws(.{0,20})?[\'"][0-9a-zA-Z/+]{40}[\'"]',
            'gcp_api_key': r'AIza[0-9A-Za-z\-_]{35}',
            'generic_api_key': r'(?i)(api[_-]?key|apikey)[\'"]?\s*[:=]\s*[\'"][a-zA-Z0-9]{16,}[\'"]',
            'generic_secret': r'(?i)(secret|password|passwd|pwd)[\'"]?\s*[:=]\s*[\'"][^\'"]+',
            'private_key': r'-----BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY-----',
        }
    
    async def scan(self) -> List[Any]:  # Returns list of CloudFinding objects
        logger.info("Starting IaC scan...")
        self.findings = []
        
        for path in self.iac_paths:
            await self._scan_directory(Path(path))
        
        # Convert IaCFinding to CloudFinding format
        from attacks.cloud.schemas import CloudFinding, Provider, Severity
        cloud_findings = []
        
        for finding in self.findings:
            try:
                sev = Severity(finding.severity)
            except ValueError:
                sev = Severity.info
            cloud_findings.append(CloudFinding(
                id=finding.id,
                category="A05:2021-Security Misconfiguration",
                severity=sev,
                title=finding.title,
                description=finding.description,
                provider=Provider.iac,
                service="IaC",
                resource_id=finding.file_path,
                resource_arn=finding.file_path,
                region="global",
                evidence=finding.evidence,
                remediation=finding.recommendation,
                remediation_cli=finding.remediation,
                detection_layer="iac"
            ))
        
        return cloud_findings
    
    async def _scan_directory(self, directory: Path):
        if not directory.exists():
            logger.warning(f"IaC path does not exist: {directory}")
            return
        
        for file_path in directory.rglob("*"):
            if file_path.is_file():
                if file_path.suffix in ['.tf', '.tfvars']:
                    await self._scan_terraform(file_path)
                elif file_path.suffix in ['.yaml', '.yml'] and 'cloudformation' in file_path.name.lower():
                    await self._scan_cloudformation(file_path)
                elif file_path.suffix in ['.yaml', '.yml'] and any(k in file_path.name.lower() for k in ['k8s', 'kube', 'deployment', 'service']):
                    await self._scan_kubernetes(file_path)
                elif file_path.suffix == '.json' and 'template' in file_path.name.lower():
                    await self._scan_arm_template(file_path)
    
    async def _scan_terraform(self, file_path: Path):
        """Scan Terraform files"""
        try:
            content = file_path.read_text()
            lines = content.split('\n')
            
            # Check for secrets
            await self._check_secrets(file_path, content, lines)
            
            # Check for security group 0.0.0.0/0
            if re.search(r'cidr_blocks\s*=\s*\[.*"0\.0\.0\.0\/0"', content):
                line_num = next((i+1 for i, line in enumerate(lines) if '0.0.0.0/0' in line), 0)
                self._add_finding(
                    file_path, line_num, "high",
                    "Security group allows access from anywhere",
                    "Security group rule allows 0.0.0.0/0",
                    {'pattern': '0.0.0.0/0'},
                    "Restrict to specific IP ranges",
                    "Update cidr_blocks to specific IPs"
                )
            
            # Check for unencrypted S3 buckets
            if 'resource "aws_s3_bucket"' in content and 'server_side_encryption_configuration' not in content:
                line_num = next((i+1 for i, line in enumerate(lines) if 'aws_s3_bucket' in line), 0)
                self._add_finding(
                    file_path, line_num, "high",
                    "S3 bucket without encryption",
                    "S3 bucket does not have server-side encryption configured",
                    {},
                    "Add server_side_encryption_configuration block",
                    "Add encryption configuration to S3 bucket resource"
                )
        
        except Exception as e:
            logger.error(f"Error scanning Terraform file {file_path}: {e}")
    
    async def _scan_cloudformation(self, file_path: Path):
        """Scan CloudFormation templates"""
        try:
            import yaml
            content = file_path.read_text()
            template = yaml.safe_load(content)
            
            # Check for secrets in template
            await self._check_secrets(file_path, content, content.split('\n'))
            
            # Check resources
            resources = template.get('Resources', {})
            for resource_name, resource_def in resources.items():
                resource_type = resource_def.get('Type', '')
                
                # Check S3 bucket encryption
                if resource_type == 'AWS::S3::Bucket':
                    properties = resource_def.get('Properties', {})
                    if 'BucketEncryption' not in properties:
                        self._add_finding(
                            file_path, 0, "high",
                            f"S3 bucket {resource_name} without encryption",
                            "CloudFormation S3 bucket lacks encryption",
                            {'resource': resource_name},
                            "Add BucketEncryption property",
                            "Add BucketEncryption to bucket properties"
                        )
        
        except Exception as e:
            logger.error(f"Error scanning CloudFormation {file_path}: {e}")
    
    async def _scan_kubernetes(self, file_path: Path):
        """Scan Kubernetes manifests"""
        try:
            import yaml
            content = file_path.read_text()
            
            # Check for secrets
            await self._check_secrets(file_path, content, content.split('\n'))
            
            docs = yaml.safe_load_all(content)
            for doc in docs:
                if not doc:
                    continue
                
                kind = doc.get('kind', '')
                
                # Check for privileged containers
                if kind in ['Pod', 'Deployment', 'DaemonSet']:
                    spec = doc.get('spec', {})
                    if kind == 'Deployment':
                        spec = spec.get('template', {}).get('spec', {})
                    
                    for container in spec.get('containers', []):
                        security_context = container.get('securityContext', {})
                        if security_context.get('privileged'):
                            self._add_finding(
                                file_path, 0, "critical",
                                "Privileged container detected",
                                f"Container {container.get('name')} runs as privileged",
                                {'container': container.get('name')},
                                "Remove privileged: true unless absolutely necessary",
                                "Set privileged: false in securityContext"
                            )
        
        except Exception as e:
            logger.error(f"Error scanning Kubernetes {file_path}: {e}")
    
    async def _scan_arm_template(self, file_path: Path):
        """Scan Azure ARM templates"""
        try:
            content = file_path.read_text()
            template = json.loads(content)
            
            # Check for secrets
            await self._check_secrets(file_path, content, content.split('\n'))
            
            # Check resources
            resources = template.get('resources', [])
            for resource in resources:
                resource_type = resource.get('type', '')
                
                # Check storage account encryption
                if resource_type == 'Microsoft.Storage/storageAccounts':
                    properties = resource.get('properties', {})
                    if not properties.get('encryption'):
                        self._add_finding(
                            file_path, 0, "high",
                            "Storage account without encryption",
                            f"Storage account {resource.get('name')} lacks encryption",
                            {'resource': resource.get('name')},
                            "Add encryption property",
                            "Configure encryption in properties"
                        )
        
        except Exception as e:
            logger.error(f"Error scanning ARM template {file_path}: {e}")
    
    async def _check_secrets(self, file_path: Path, content: str, lines: List[str]):
        """Check for hardcoded secrets"""
        for secret_type, pattern in self.secret_patterns.items():
            matches = re.finditer(pattern, content)
            for match in matches:
                # Find line number
                line_num = content[:match.start()].count('\n') + 1
                
                self._add_finding(
                    file_path, line_num, "critical",
                    f"Hardcoded {secret_type.replace('_', ' ')} detected",
                    f"Found {secret_type} in IaC file",
                    {'matched_text': match.group()[:20] + '...'},
                    "Use environment variables or secret management",
                    "Remove hardcoded secret and use variables"
                )
    
    def _add_finding(self, file_path: Path, line_num: int, severity: str, title: str, desc: str, evidence: Dict, rec: str, remediation: str):
        self.findings.append(IaCFinding(
            id=f"iac_{file_path.stem}_{line_num}_{uuid.uuid4().hex[:8]}",
            file_path=str(file_path),
            line_number=line_num,
            severity=severity,
            title=title,
            description=desc,
            evidence=evidence,
            recommendation=rec,
            remediation=remediation
        ))