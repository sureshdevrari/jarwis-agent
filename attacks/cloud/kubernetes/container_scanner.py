"""
Jarwis AGI - Container Scanner
Trivy-based container vulnerability scanning
"""

import json
import asyncio
import logging
import subprocess
from dataclasses import dataclass, field
from typing import List, Dict, Any
import uuid

logger = logging.getLogger(__name__)

@dataclass
class ContainerFinding:
    """Container security finding"""
    id: str
    image: str
    vulnerability_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)

class ContainerScanner:
    """Container Security Scanner using Trivy"""
    
    def __init__(self, context, config):
        self.context = context
        self.config = config
        self.findings: List[ContainerFinding] = []
        self.trivy_available = self._check_trivy()
    
    def _check_trivy(self) -> bool:
        """Check if Trivy is installed"""
        try:
            result = subprocess.run(['trivy', '--version'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                logger.info(f"Trivy found: {result.stdout.strip()}")
                return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
            logger.warning("Trivy not found. Install: https://aquasecurity.github.io/trivy/")
        return False
    
    async def scan(self) -> List[Any]:
        """Scan container images for vulnerabilities"""
        if not self.trivy_available:
            logger.warning("Trivy not available, skipping container scanning")
            return []
        
        logger.info("Starting container scanning...")
        self.findings = []
        
        # Get container images from discovered resources
        images = self._get_images_from_resources()
        
        for image in images:
            await self._scan_image(image)
        
        # Convert to CloudFinding format
        from attacks.cloud.schemas import CloudFinding, Provider, Severity
        cloud_findings = []
        
        for finding in self.findings:
            try:
                sev = Severity(finding.severity.lower())
            except ValueError:
                sev = Severity.info
            cloud_findings.append(CloudFinding(
                id=finding.id,
                category="A06:2021-Vulnerable and Outdated Components",
                severity=sev,
                title=finding.title,
                description=finding.description,
                provider=Provider.container,
                service="Container Image",
                resource_id=finding.image,
                resource_arn=finding.image,
                region="global",
                evidence=finding.evidence,
                remediation=f"Update {finding.package_name} to {finding.fixed_version or 'latest version'}",
                remediation_cli=f"# Update base image or rebuild with patched package",
                cvss_score=self._get_cvss_score(finding.severity),
                detection_layer="container"
            ))
        
        return cloud_findings
    
    def _get_images_from_resources(self) -> List[str]:
        """Extract container images from discovered cloud resources"""
        images = set()
        
        for resource in self.context.resources:
            # AWS ECS task definitions
            if resource.resource_type == 'ecs_task_definition':
                container_defs = resource.metadata.get('container_definitions', [])
                for container in container_defs:
                    images.add(container.get('image'))
            
            # AWS Lambda container images
            elif resource.resource_type == 'lambda_function':
                package_type = resource.metadata.get('package_type')
                if package_type == 'Image':
                    images.add(resource.metadata.get('code_image_uri'))
            
            # Azure Container Instances
            elif resource.resource_type == 'azure_container_instance':
                images.add(resource.metadata.get('image'))
            
            # GKE pods
            elif resource.resource_type == 'gke_pod':
                containers = resource.metadata.get('containers', [])
                for container in containers:
                    images.add(container.get('image'))
        
        # Also check registry URLs from config
        registry_images = self.config.get('container_registries', [])
        images.update(registry_images)
        
        # Filter out None values
        return [img for img in images if img]
    
    async def _scan_image(self, image: str):
        """Scan single container image with Trivy"""
        logger.info(f"Scanning container image: {image}")
        
        try:
            # Run Trivy scan
            cmd = [
                'trivy', 'image',
                '--format', 'json',
                '--severity', 'CRITICAL,HIGH,MEDIUM',
                '--no-progress',
                image
            ]
            
            result = await asyncio.to_thread(
                subprocess.run,
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                logger.error(f"Trivy scan failed for {image}: {result.stderr}")
                return
            
            # Parse results
            scan_results = json.loads(result.stdout)
            
            for result_group in scan_results.get('Results', []):
                vulnerabilities = result_group.get('Vulnerabilities', [])
                
                for vuln in vulnerabilities:
                    self._add_finding(
                        image=image,
                        vulnerability_id=vuln.get('VulnerabilityID', ''),
                        package_name=vuln.get('PkgName', ''),
                        installed_version=vuln.get('InstalledVersion', ''),
                        fixed_version=vuln.get('FixedVersion', ''),
                        severity=vuln.get('Severity', 'UNKNOWN'),
                        title=vuln.get('Title', ''),
                        description=vuln.get('Description', ''),
                        evidence={
                            'cvss': vuln.get('CVSS', {}),
                            'references': vuln.get('References', []),
                            'published_date': vuln.get('PublishedDate', ''),
                        }
                    )
        
        except subprocess.TimeoutExpired:
            logger.error(f"Trivy scan timeout for {image}")
        except Exception as e:
            logger.error(f"Container scan failed for {image}: {e}")
    
    def _add_finding(self, image, vulnerability_id, package_name, installed_version, fixed_version, severity, title, description, evidence):
        self.findings.append(ContainerFinding(
            id=f"container_{vulnerability_id}_{uuid.uuid4().hex[:8]}",
            image=image,
            vulnerability_id=vulnerability_id,
            package_name=package_name,
            installed_version=installed_version,
            fixed_version=fixed_version,
            severity=severity,
            title=title or f"{vulnerability_id} in {package_name}",
            description=description or f"Vulnerability {vulnerability_id} found in package {package_name}",
            evidence=evidence
        ))
    
    def _get_cvss_score(self, severity: str) -> float:
        """Map severity to CVSS score"""
        severity_map = {
            'CRITICAL': 9.5,
            'HIGH': 7.5,
            'MEDIUM': 5.0,
            'LOW': 2.5,
            'UNKNOWN': 0.0
        }
        return severity_map.get(severity.upper(), 0.0)