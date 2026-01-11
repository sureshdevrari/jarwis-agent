"""
Jarwis AGI - Cloud Security Scan Runner
Unified Cloud-Native Application Protection Platform (CNAPP)

Implements 6-layer cloud security scanning combining:
- Wiz-style agentless CSPM + attack path analysis
- Palo Alto-style code-to-cloud correlation
- Aqua-style container & supply chain security
- Sysdig-style runtime threat detection

Phases:
1. Cloud Discovery & Inventory (multi-region, multi-service)
2. CSPM Configuration Scanning (1000+ misconfiguration rules)
3. Code & IaC Analysis (Terraform, CloudFormation, K8s)
4. Container & Supply Chain Scanning (Trivy-based)
5. Runtime Threat Detection (CloudTrail/logs analysis)
6. AI Attack Path Analysis (graph-based risk prioritization)
"""

import asyncio
import logging
import uuid
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, field
import json
from attacks.cloud.schemas import CloudFinding, CloudResource
from core.cloud_scanner_registry import load_default_cloud_scanners

logger = logging.getLogger(__name__)




@dataclass
class CloudScanContext:
    """Maintains state across all cloud scan phases"""
    scan_id: str
    providers: List[str]  # aws, azure, gcp
    credentials: Dict[str, Any]  # Provider-specific credentials
    config: Dict[str, Any]
    
    # Discovery results
    resources: List[CloudResource] = field(default_factory=list)
    resource_graph: Dict[str, List[str]] = field(default_factory=dict)  # Adjacency list
    
    # Scan results
    findings: List[CloudFinding] = field(default_factory=list)
    
    # Progress tracking
    phase: str = "initializing"
    progress_percent: int = 0
    current_task: str = ""
    
    # Statistics
    total_resources_scanned: int = 0
    total_checks_performed: int = 0
    
    def add_finding(self, finding: CloudFinding):
        """Add finding and update severity counters"""
        self.findings.append(finding)
    
    def add_resource(self, resource: CloudResource):
        """Add discovered resource"""
        self.resources.append(resource)
        self.total_resources_scanned += 1
    
    def add_relationship(self, source_id: str, target_id: str):
        """Add edge to resource graph"""
        if source_id not in self.resource_graph:
            self.resource_graph[source_id] = []
        self.resource_graph[source_id].append(target_id)


class CloudScanRunner:
    """
    Main orchestrator for cloud security scanning
    
    Flow:
    ┌─────────────────────────────────────────────────────────────┐
    │  Phase 1: Cloud Discovery & Inventory                       │
    │  - Connect to cloud providers (AWS/Azure/GCP)               │
    │  - Enumerate all regions                                    │
    │  - Discover resources (compute, storage, network, IAM)      │
    │  - Build resource relationship graph                        │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Phase 2: CSPM Configuration Scanning                       │
    │  - Run 1000+ misconfiguration checks (Wiz-style)            │
    │  - CIS Benchmark validation                                 │
    │  - Public access detection                                  │
    │  - Encryption validation                                    │
    │  - IAM/RBAC overprivileged checks                           │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Phase 3: Code & IaC Analysis (Palo Alto-style)             │
    │  - Scan Terraform/CloudFormation/ARM/K8s manifests          │
    │  - Detect secrets in IaC                                    │
    │  - SAST on cloud function code (Lambda, Functions)          │
    │  - Map running resources to source code                     │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Phase 4: Container & Supply Chain (Aqua-style)             │
    │  - Scan container images (ECR, ACR, GCR)                    │
    │  - Trivy-based CVE detection                                │
    │  - SBOM generation                                          │
    │  - Secrets detection in images                              │
    │  - Malware scanning                                         │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Phase 5: Runtime Threat Detection (Sysdig-style)           │
    │  - Analyze CloudTrail/Activity Logs/Admin Logs              │
    │  - Detect privilege escalation attempts                     │
    │  - Identify data exfiltration patterns                      │
    │  - Lateral movement detection                               │
    │  - Anomalous API call analysis                              │
    └─────────────────────────────────────────────────────────────┘
                              ↓
    ┌─────────────────────────────────────────────────────────────┐
    │  Phase 6: AI Attack Path Analysis                           │
    │  - Build attack graphs from resource relationships          │
    │  - Identify exploitable chains                              │
    │  - Calculate blast radius for each finding                  │
    │  - AI-powered risk prioritization                           │
    │  - Generate remediation guidance                            │
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.scan_id = str(uuid.uuid4())[:8]
        self.start_time = None
        self.end_time = None
        
        # Initialize context
        self.context = CloudScanContext(
            scan_id=self.scan_id,
            providers=config.get('providers', ['aws']),
            credentials=config.get('credentials', {}),
            config=config
        )
        
        # Scanner components (lazy-loaded)
        self._aws_scanner = None
        self._azure_scanner = None
        self._gcp_scanner = None
        self._iac_scanner = None
        self._container_scanner = None
        self._runtime_scanner = None
        self._cloud_graph = None
        self._ai_planner = None
        
        # Progress callbacks
        self._progress_callback = config.get('progress_callback')
        self._update_db_callback = config.get('update_db_callback')
        
        logger.info(f"CloudScanRunner initialized. Scan ID: {self.scan_id}")
        logger.info(f"Providers: {self.context.providers}")
    
    def set_progress_callback(self, callback):
        """Set the progress callback function for real-time updates"""
        self._progress_callback = callback
    
    def set_db_callback(self, callback):
        """Set the database update callback function"""
        self._update_db_callback = callback
    
    async def run(self) -> Dict[str, Any]:
        """Execute complete cloud security scan"""
        self.start_time = datetime.utcnow()
        
        try:
            logger.info("=" * 80)
            logger.info(f"CLOUD SECURITY SCAN STARTED - ID: {self.scan_id}")
            logger.info("=" * 80)
            
            # Phase 1: Discovery & Inventory
            await self._phase1_discovery()
            
            # Phase 2: CSPM Configuration Scanning
            await self._phase2_cspm_scanning()
            
            # Phase 3: Code & IaC Analysis
            await self._phase3_iac_analysis()
            
            # Phase 4: Container & Supply Chain Scanning
            await self._phase4_container_scanning()
            
            # Phase 5: Runtime Threat Detection
            await self._phase5_runtime_detection()
            
            # Phase 6: AI Attack Path Analysis
            await self._phase6_ai_analysis()
            
            self.end_time = datetime.utcnow()
            duration = (self.end_time - self.start_time).total_seconds()
            
            logger.info("=" * 80)
            logger.info(f"CLOUD SECURITY SCAN COMPLETED - Duration: {duration:.2f}s")
            logger.info(f"Total Resources: {len(self.context.resources)}")
            logger.info(f"Total Findings: {len(self.context.findings)}")
            logger.info("=" * 80)
            
            return self._build_results()
            
        except Exception as e:
            logger.error(f"Cloud scan failed: {e}", exc_info=True)
            self.context.phase = "error"
            raise
    
    async def _phase1_discovery(self):
        """Phase 1: Cloud Discovery & Inventory"""
        self.context.phase = "discovery"
        self.context.progress_percent = 10
        self.context.current_task = "Discovering cloud resources..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 1] Cloud Discovery & Inventory")
        logger.info("-" * 60)
        
        # Import scanners dynamically
        from attacks.cloud.aws_scanner import AWSSecurityScanner
        from attacks.cloud.azure_scanner import AzureSecurityScanner
        from attacks.cloud.gcp_scanner import GCPSecurityScanner
        
        # Discover resources per provider
        for provider in self.context.providers:
            logger.info(f"Discovering {provider.upper()} resources...")
            
            if provider == 'aws':
                await self._discover_aws()
            elif provider == 'azure':
                await self._discover_azure()
            elif provider == 'gcp':
                await self._discover_gcp()
        
        # Build resource relationship graph
        await self._build_resource_graph()
        
        logger.info(f"Discovery complete. Found {len(self.context.resources)} resources")
        self.context.progress_percent = 20
        await self._notify_progress()
    
    async def _discover_aws(self):
        """Discover AWS resources across all regions"""
        from attacks.cloud.aws_scanner import AWSSecurityScanner
        
        creds = self.context.credentials.get('aws', {})
        scanner = AWSSecurityScanner(
            access_key=creds.get('access_key'),
            secret_key=creds.get('secret_key'),
            session_token=creds.get('session_token'),
            profile=creds.get('profile')
        )
        
        # Enumerate regions
        regions = creds.get('regions', ['us-east-1'])  # Default to primary region
        
        for region in regions:
            logger.info(f"  Scanning AWS region: {region}")
            
            # Discover resources (EC2, S3, Lambda, RDS, etc.)
            # This will be implemented in AWS scanner enhancement
            resources = await scanner.discover_resources(region)
            
            for resource in resources:
                self.context.add_resource(CloudResource(
                    resource_id=resource['id'],
                    resource_type=resource['type'],
                    provider='aws',
                    region=region,
                    name=resource['name'],
                    arn_or_id=resource['arn'],
                    tags=resource.get('tags', {}),
                    metadata=resource.get('metadata', {})
                ))
    
    async def _discover_azure(self):
        """Discover Azure resources across subscriptions"""
        from attacks.cloud.azure_scanner import AzureSecurityScanner
        
        creds = self.context.credentials.get('azure', {})
        scanner = AzureSecurityScanner(
            subscription_id=creds.get('subscription_id'),
            tenant_id=creds.get('tenant_id'),
            client_id=creds.get('client_id'),
            client_secret=creds.get('client_secret')
        )
        
        logger.info(f"  Scanning Azure subscription...")
        resources = await scanner.discover_resources()
        
        for resource in resources:
            self.context.add_resource(CloudResource(
                resource_id=resource['id'],
                resource_type=resource['type'],
                provider='azure',
                region=resource.get('location', 'global'),
                name=resource['name'],
                arn_or_id=resource['id'],
                tags=resource.get('tags', {}),
                metadata=resource.get('metadata', {})
            ))
    
    async def _discover_gcp(self):
        """Discover GCP resources across projects"""
        from attacks.cloud.gcp_scanner import GCPSecurityScanner
        
        creds = self.context.credentials.get('gcp', {})
        scanner = GCPSecurityScanner(
            project_id=creds.get('project_id'),
            service_account_json=creds.get('service_account_json')
        )
        
        logger.info(f"  Scanning GCP project...")
        resources = await scanner.discover_resources()
        
        for resource in resources:
            self.context.add_resource(CloudResource(
                resource_id=resource['id'],
                resource_type=resource['type'],
                provider='gcp',
                region=resource.get('zone', 'global'),
                name=resource['name'],
                arn_or_id=resource['id'],
                tags=resource.get('labels', {}),
                metadata=resource.get('metadata', {})
            ))
    
    async def _build_resource_graph(self):
        """Build relationship graph between cloud resources (Wiz-style Security Graph)"""
        from core.cloud_graph import CloudSecurityGraph
        
        self._cloud_graph = CloudSecurityGraph(self.context.resources)
        await self._cloud_graph.build_graph()
        
        # Store graph in context
        self.context.resource_graph = self._cloud_graph.adjacency_list
        
        logger.info(f"Resource graph built: {len(self.context.resource_graph)} nodes")
    
    async def _phase2_cspm_scanning(self):
        """Phase 2: CSPM Configuration Scanning (1000+ checks)"""
        self.context.phase = "cspm_scanning"
        self.context.progress_percent = 30
        self.context.current_task = "Scanning cloud configurations..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 2] CSPM Configuration Scanning")
        logger.info("-" * 60)
        
        # Run CSPM checks via registry-loaded scanners
        registry = load_default_cloud_scanners()
        for provider in self.context.providers:
            logger.info(f"Running CSPM checks for {provider.upper()} via registry...")
            try:
                scanners = registry.get_scanners(provider)
            except Exception:
                scanners = []
            for scanner_cls in scanners:
                try:
                    cfg = {**self.context.credentials.get(provider, {}), **self.config.get('cloud', {})}
                    scanner = scanner_cls(cfg)
                    findings = await scanner.scan(self.context)
                    for f in findings:
                        self.context.add_finding(self._adapter_to_runner_finding(f))
                except Exception as e:
                    logger.error(f"Scanner {scanner_cls.__name__} failed for {provider}: {e}")
        
        logger.info(f"CSPM scanning complete. {len(self.context.findings)} findings")
        self.context.progress_percent = 45
        await self._notify_progress()

    def _adapter_to_runner_finding(self, f) -> CloudFinding:
        """Convert adapter CloudFinding to runner CloudFinding format."""
        evidence = {}
        try:
            if isinstance(getattr(f, 'evidence', ''), str):
                evidence = json.loads(f.evidence) if f.evidence else {}
            else:
                evidence = getattr(f, 'evidence', {})
        except Exception:
            evidence = {'raw': getattr(f, 'evidence', '')}
        resource_arn = ''
        ctx = getattr(f, 'context', {}) or {}
        resource_arn = ctx.get('resource_arn') or ctx.get('resource_name') or ctx.get('project_id') or ''
        return CloudFinding(
            id=f.id,
            category=getattr(f, 'category', 'A05:2021-Security Misconfiguration'),
            severity=str(getattr(f, 'severity', 'info')),
            title=getattr(f, 'title', ''),
            description=getattr(f, 'description', ''),
            provider=str(getattr(f, 'provider', '')).lower(),
            service=getattr(f, 'service', ''),
            resource_id=getattr(f, 'resource_id', ''),
            resource_arn=resource_arn or getattr(f, 'resource_id', ''),
            region=getattr(f, 'region', 'global'),
            evidence=evidence,
            remediation=getattr(f, 'remediation', ''),
            remediation_cli='',
            cis_benchmark=str(getattr(f, 'compliance', {}).get('cis', '')),
            detection_layer='cspm'
        )
    
    async def _cspm_aws(self):
        """Run AWS CSPM checks"""
        from attacks.cloud.aws_scanner import AWSSecurityScanner
        
        creds = self.context.credentials.get('aws', {})
        scanner = AWSSecurityScanner(
            access_key=creds.get('access_key'),
            secret_key=creds.get('secret_key'),
            session_token=creds.get('session_token'),
            profile=creds.get('profile')
        )
        
        # Run all checks
        findings = await scanner.scan_all()
        
        # Convert to CloudFinding format
        for finding in findings:
            cloud_finding = CloudFinding(
                id=finding.id,
                category=self._map_to_category(finding.cis_benchmark),
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                provider='aws',
                service=finding.service,
                resource_id=finding.resource_id,
                resource_arn=finding.resource_arn,
                region=finding.region,
                evidence=finding.evidence,
                remediation=finding.recommendation,
                remediation_cli=finding.remediation_cli,
                cis_benchmark=finding.cis_benchmark,
                detection_layer='cspm'
            )
            self.context.add_finding(cloud_finding)
    
    async def _cspm_azure(self):
        """Run Azure CSPM checks"""
        from attacks.cloud.azure_scanner import AzureSecurityScanner
        
        creds = self.context.credentials.get('azure', {})
        scanner = AzureSecurityScanner(
            subscription_id=creds.get('subscription_id'),
            tenant_id=creds.get('tenant_id'),
            client_id=creds.get('client_id'),
            client_secret=creds.get('client_secret')
        )
        
        findings = await scanner.scan_all()
        
        for finding in findings:
            cloud_finding = CloudFinding(
                id=finding.id,
                category=self._map_to_category(finding.cis_benchmark),
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                provider='azure',
                service=finding.service,
                resource_id=finding.resource_id,
                resource_arn=finding.resource_id,  # Azure uses resource IDs
                region=finding.region,
                evidence=finding.evidence,
                remediation=finding.recommendation,
                remediation_cli=finding.remediation_cli,
                cis_benchmark=finding.cis_benchmark,
                detection_layer='cspm'
            )
            self.context.add_finding(cloud_finding)
    
    async def _cspm_gcp(self):
        """Run GCP CSPM checks"""
        from attacks.cloud.gcp_scanner import GCPSecurityScanner
        
        creds = self.context.credentials.get('gcp', {})
        scanner = GCPSecurityScanner(
            project_id=creds.get('project_id'),
            service_account_json=creds.get('service_account_json')
        )
        
        findings = await scanner.scan_all()
        
        for finding in findings:
            cloud_finding = CloudFinding(
                id=finding.id,
                category=self._map_to_category(finding.cis_benchmark),
                severity=finding.severity,
                title=finding.title,
                description=finding.description,
                provider='gcp',
                service=finding.service,
                resource_id=finding.resource_id,
                resource_arn=finding.resource_id,  # GCP uses resource names
                region=finding.region,
                evidence=finding.evidence,
                remediation=finding.recommendation,
                remediation_cli=finding.remediation_cli,
                cis_benchmark=finding.cis_benchmark,
                detection_layer='cspm'
            )
            self.context.add_finding(cloud_finding)
    
    async def _phase3_iac_analysis(self):
        """Phase 3: Infrastructure as Code Analysis"""
        self.context.phase = "iac_analysis"
        self.context.progress_percent = 55
        self.context.current_task = "Analyzing IaC templates..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 3] Code & IaC Analysis")
        logger.info("-" * 60)
        
        if not self.config.get('iac_scan_enabled', False):
            logger.info("IaC scanning disabled, skipping...")
            return
        
        from attacks.cloud.iac_scanner import IaCScanner
        
        scanner = IaCScanner(
            iac_paths=self.config.get('iac_paths', []),
            providers=self.context.providers
        )
        
        findings = await scanner.scan()
        
        for finding in findings:
            self.context.add_finding(finding)
        
        logger.info(f"IaC analysis complete. {len(findings)} findings")
        self.context.progress_percent = 65
        await self._notify_progress()
    
    async def _phase4_container_scanning(self):
        """Phase 4: Container & Supply Chain Scanning (Trivy-based)"""
        self.context.phase = "container_scanning"
        self.context.progress_percent = 70
        self.context.current_task = "Scanning container images..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 4] Container & Supply Chain Scanning")
        logger.info("-" * 60)
        
        if not self.config.get('container_scan_enabled', False):
            logger.info("Container scanning disabled, skipping...")
            return
        
        from attacks.cloud.container_scanner import ContainerScanner
        
        scanner = ContainerScanner(
            context=self.context,
            config=self.config
        )
        
        findings = await scanner.scan()
        
        for finding in findings:
            self.context.add_finding(finding)
        
        logger.info(f"Container scanning complete. {len(findings)} findings")
        self.context.progress_percent = 80
        await self._notify_progress()
    
    async def _phase5_runtime_detection(self):
        """Phase 5: Runtime Threat Detection (Sysdig-style)"""
        self.context.phase = "runtime_detection"
        self.context.progress_percent = 85
        self.context.current_task = "Analyzing runtime behavior..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 5] Runtime Threat Detection")
        logger.info("-" * 60)
        
        if not self.config.get('runtime_scan_enabled', False):
            logger.info("Runtime scanning disabled, skipping...")
            return
        
        from attacks.cloud.runtime_scanner import RuntimeScanner
        
        scanner = RuntimeScanner(
            context=self.context,
            config=self.config
        )
        
        findings = await scanner.scan()
        
        for finding in findings:
            self.context.add_finding(finding)
        
        logger.info(f"Runtime detection complete. {len(findings)} findings")
        self.context.progress_percent = 90
        await self._notify_progress()
    
    async def _phase6_ai_analysis(self):
        """Phase 6: AI Attack Path Analysis & Risk Prioritization"""
        self.context.phase = "ai_analysis"
        self.context.progress_percent = 95
        self.context.current_task = "Analyzing attack paths with AI..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 6] AI Attack Path Analysis")
        logger.info("-" * 60)
        
        from core.cloud_graph import CloudSecurityGraph
        from core.ai_planner import AIPlanner
        
        # Build attack graphs
        graph = CloudSecurityGraph(self.context.resources)
        attack_paths = await graph.find_attack_paths(self.context.findings)
        
        # Calculate blast radius for each finding
        for finding in self.context.findings:
            finding.blast_radius_score = await graph.calculate_blast_radius(
                finding.resource_id
            )
            finding.attack_path = attack_paths.get(finding.id, [])
        
        # AI-powered risk prioritization
        ai_planner = AIPlanner(self.config)
        prioritized_findings = await ai_planner.prioritize_cloud_findings(
            self.context.findings,
            self.context.resource_graph
        )
        
        # Update findings with AI scores
        for i, finding in enumerate(self.context.findings):
            if i < len(prioritized_findings):
                finding.exploitability_score = prioritized_findings[i].get('exploitability', 0)
        
        logger.info(f"AI analysis complete. {len(attack_paths)} attack paths identified")
        self.context.progress_percent = 100
        await self._notify_progress()
    
    async def run_extended_scan(self) -> Dict[str, Any]:
        """
        Extended cloud security scan with additional phases:
        - CIEM (Identity & Entitlement Management)
        - Kubernetes Security
        - Drift Detection
        - Sensitive Data Discovery
        - Multi-framework Compliance
        """
        self.start_time = datetime.utcnow()
        
        try:
            logger.info("=" * 80)
            logger.info(f"EXTENDED CLOUD SECURITY SCAN - ID: {self.scan_id}")
            logger.info("=" * 80)
            
            # Standard phases (1-6)
            await self._phase1_discovery()
            await self._phase2_cspm_scanning()
            await self._phase3_iac_analysis()
            await self._phase4_container_scanning()
            await self._phase5_runtime_detection()
            
            # Extended phases (7-11)
            await self._phase7_ciem_scanning()
            await self._phase8_kubernetes_scanning()
            await self._phase9_drift_detection()
            await self._phase10_data_security()
            await self._phase11_compliance_mapping()
            
            # Final AI analysis
            await self._phase6_ai_analysis()
            
            self.end_time = datetime.utcnow()
            return self._build_results()
            
        except Exception as e:
            logger.error(f"Extended cloud scan failed: {e}", exc_info=True)
            raise
    
    async def _phase7_ciem_scanning(self):
        """Phase 7: CIEM - Cloud Identity & Entitlement Management (Wiz-style)"""
        self.context.phase = "ciem_scanning"
        self.context.current_task = "Analyzing cloud identities and permissions..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 7] CIEM - Identity & Entitlement Analysis")
        logger.info("-" * 60)
        
        if not self.config.get('ciem_scan_enabled', True):
            logger.info("CIEM scanning disabled, skipping...")
            return
        
        try:
            from attacks.cloud.ciem_scanner import CIEMScanner
            
            scanner = CIEMScanner(
                config={
                    'providers': self.context.providers,
                    'credentials': self.context.credentials
                },
                context=self.context
            )
            
            findings = await scanner.scan()
            
            for finding in findings:
                cloud_finding = CloudFinding(
                    id=finding.id,
                    category="A01:2021-Broken Access Control",
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    provider=finding.provider,
                    service='iam',
                    resource_id=finding.identity_id,
                    resource_arn=finding.identity_id,
                    region='global',
                    evidence=finding.evidence,
                    remediation=finding.recommendation,
                    cis_benchmark=finding.cis_control,
                    blast_radius_score=finding.blast_radius,
                    detection_layer='ciem'
                )
                self.context.add_finding(cloud_finding)
            
            logger.info(f"CIEM analysis complete. {len(findings)} identity findings")
        except ImportError:
            logger.warning("CIEM scanner not available")
        except Exception as e:
            logger.error(f"CIEM scan error: {e}")
    
    async def _phase8_kubernetes_scanning(self):
        """Phase 8: Kubernetes Security Scanning"""
        self.context.phase = "kubernetes_scanning"
        self.context.current_task = "Scanning Kubernetes clusters..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 8] Kubernetes Security Scanning")
        logger.info("-" * 60)
        
        if not self.config.get('kubernetes_scan_enabled', False):
            logger.info("Kubernetes scanning disabled, skipping...")
            return
        
        try:
            from attacks.cloud.kubernetes_scanner import KubernetesSecurityScanner
            
            scanner = KubernetesSecurityScanner(
                config={
                    'kubeconfig': self.config.get('kubeconfig'),
                    'namespaces': self.config.get('k8s_namespaces', [])
                },
                context=self.context
            )
            
            findings = await scanner.scan()
            
            for finding in findings:
                cloud_finding = CloudFinding(
                    id=finding.id,
                    category="A05:2021-Security Misconfiguration",
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    provider='kubernetes',
                    service=finding.resource_type.lower(),
                    resource_id=f"{finding.namespace}/{finding.resource_name}",
                    resource_arn=f"{finding.namespace}/{finding.resource_name}",
                    region=finding.namespace,
                    evidence=finding.evidence,
                    remediation=finding.recommendation,
                    cis_benchmark=finding.cis_control,
                    detection_layer='kubernetes'
                )
                self.context.add_finding(cloud_finding)
            
            logger.info(f"Kubernetes scan complete. {len(findings)} findings")
        except ImportError:
            logger.warning("Kubernetes scanner not available")
        except Exception as e:
            logger.error(f"Kubernetes scan error: {e}")
    
    async def _phase9_drift_detection(self):
        """Phase 9: Configuration Drift Detection"""
        self.context.phase = "drift_detection"
        self.context.current_task = "Detecting configuration drift..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 9] Configuration Drift Detection")
        logger.info("-" * 60)
        
        if not self.config.get('drift_scan_enabled', False):
            logger.info("Drift detection disabled, skipping...")
            return
        
        try:
            from attacks.cloud.drift_scanner import DriftDetectionScanner
            
            scanner = DriftDetectionScanner(
                config={
                    'iac_type': self.config.get('iac_type', 'terraform'),
                    'iac_path': self.config.get('iac_path'),
                    'credentials': self.context.credentials
                },
                context=self.context
            )
            
            findings = await scanner.scan()
            
            for finding in findings:
                cloud_finding = CloudFinding(
                    id=finding.id,
                    category="A05:2021-Security Misconfiguration",
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    provider=finding.provider,
                    service=finding.resource_type,
                    resource_id=finding.resource_id,
                    resource_arn=finding.resource_id,
                    region='global',
                    evidence={
                        'expected': finding.expected_config,
                        'actual': finding.actual_config,
                        'drift_type': finding.drift_type
                    },
                    remediation=finding.recommendation,
                    detection_layer='drift'
                )
                self.context.add_finding(cloud_finding)
            
            logger.info(f"Drift detection complete. {len(findings)} drift findings")
        except ImportError:
            logger.warning("Drift scanner not available")
        except Exception as e:
            logger.error(f"Drift detection error: {e}")
    
    async def _phase10_data_security(self):
        """Phase 10: Sensitive Data Discovery (Wiz-style)"""
        self.context.phase = "data_security"
        self.context.current_task = "Scanning for sensitive data..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 10] Sensitive Data Discovery")
        logger.info("-" * 60)
        
        if not self.config.get('data_scan_enabled', False):
            logger.info("Data security scanning disabled, skipping...")
            return
        
        try:
            from attacks.cloud.data_security_scanner import SensitiveDataScanner
            
            scanner = SensitiveDataScanner(
                config={
                    'providers': self.context.providers,
                    'credentials': self.context.credentials,
                    'buckets': self.config.get('scan_buckets', []),
                    'max_objects_per_bucket': self.config.get('max_objects', 500)
                },
                context=self.context
            )
            
            findings = await scanner.scan()
            
            for finding in findings:
                cloud_finding = CloudFinding(
                    id=finding.id,
                    category="A02:2021-Cryptographic Failures",
                    severity=finding.severity,
                    title=finding.title,
                    description=finding.description,
                    provider=finding.provider,
                    service=finding.storage_type,
                    resource_id=f"{finding.bucket_name}/{finding.object_key}",
                    resource_arn=f"{finding.bucket_name}/{finding.object_key}",
                    region='global',
                    evidence={
                        'data_type': finding.data_type,
                        'pattern': finding.pattern_name,
                        'match_count': finding.match_count,
                        'sample': finding.sample_match
                    },
                    remediation=finding.recommendation,
                    compliance_frameworks=finding.compliance_frameworks,
                    detection_layer='data_security'
                )
                self.context.add_finding(cloud_finding)
            
            logger.info(f"Data security scan complete. {len(findings)} sensitive data findings")
        except ImportError:
            logger.warning("Data security scanner not available")
        except Exception as e:
            logger.error(f"Data security scan error: {e}")
    
    async def _phase11_compliance_mapping(self):
        """Phase 11: Multi-Framework Compliance Mapping"""
        self.context.phase = "compliance_mapping"
        self.context.current_task = "Mapping findings to compliance frameworks..."
        await self._notify_progress()
        
        logger.info("\n[PHASE 11] Compliance Framework Mapping")
        logger.info("-" * 60)
        
        try:
            from attacks.cloud.compliance_mapper import ComplianceMapper
            
            mapper = ComplianceMapper(config={
                'frameworks': self.config.get('compliance_frameworks', 
                    ['CIS', 'PCI-DSS', 'HIPAA', 'SOC2'])
            })
            
            # Map all findings to compliance controls
            for finding in self.context.findings:
                mappings = mapper.map_finding_to_controls(finding)
                for framework, controls in mappings.items():
                    control_ids = [c.control_id for c in controls]
                    if framework not in finding.compliance_frameworks:
                        finding.compliance_frameworks.extend(
                            [f"{framework}:{cid}" for cid in control_ids]
                        )
            
            # Generate compliance report
            compliance_report = mapper.generate_compliance_report(self.context.findings)
            
            # Store in context for results
            self.context.config['compliance_report'] = {
                framework: {
                    'score': result.score,
                    'total_controls': result.total_controls,
                    'passing': result.passing_controls,
                    'failing': result.failing_controls
                }
                for framework, result in compliance_report.items()
            }
            
            logger.info(f"Compliance mapping complete:")
            for framework, result in compliance_report.items():
                logger.info(f"  {framework}: {result.score:.1f}% ({result.passing_controls}/{result.total_controls} controls)")
                
        except ImportError:
            logger.warning("Compliance mapper not available")
        except Exception as e:
            logger.error(f"Compliance mapping error: {e}")
    
    def _map_to_category(self, cis_benchmark: str) -> str:
        """Map CIS benchmark to OWASP/category"""
        if not cis_benchmark:
            return "A05:2021-Security Misconfiguration"
        
        # Map CIS sections to OWASP
        cis_map = {
            "1.": "A07:2021-Identification and Authentication Failures",
            "2.": "A09:2021-Security Logging and Monitoring Failures",
            "3.": "A05:2021-Security Misconfiguration",
            "4.": "A05:2021-Security Misconfiguration",
        }
        
        for prefix, category in cis_map.items():
            if cis_benchmark.startswith(prefix):
                return category
        
        return "A05:2021-Security Misconfiguration"
    
    async def _notify_progress(self):
        """Notify progress callback and update database"""
        if self._progress_callback:
            await self._progress_callback({
                'scan_id': self.scan_id,
                'phase': self.context.phase,
                'progress': self.context.progress_percent,
                'current_task': self.context.current_task,
                'resources_scanned': self.context.total_resources_scanned,
                'findings_count': len(self.context.findings)
            })
        
        if self._update_db_callback:
            await self._update_db_callback({
                'scan_id': self.scan_id,
                'status': 'running',
                'progress': self.context.progress_percent,
                'current_phase': self.context.phase,
                'critical_count': len([f for f in self.context.findings if f.severity == 'critical']),
                'high_count': len([f for f in self.context.findings if f.severity == 'high']),
                'medium_count': len([f for f in self.context.findings if f.severity == 'medium']),
                'low_count': len([f for f in self.context.findings if f.severity == 'low']),
            })
    
    def _build_results(self) -> Dict[str, Any]:
        """Build final results dictionary"""
        # Calculate severity counts
        severity_counts = {
            'critical': len([f for f in self.context.findings if f.severity == 'critical']),
            'high': len([f for f in self.context.findings if f.severity == 'high']),
            'medium': len([f for f in self.context.findings if f.severity == 'medium']),
            'low': len([f for f in self.context.findings if f.severity == 'low']),
            'info': len([f for f in self.context.findings if f.severity == 'info']),
        }
        
        # Calculate layer breakdown
        layer_counts = {}
        for finding in self.context.findings:
            layer = finding.detection_layer
            layer_counts[layer] = layer_counts.get(layer, 0) + 1
        
        # Calculate provider breakdown
        provider_counts = {}
        for finding in self.context.findings:
            provider = finding.provider
            provider_counts[provider] = provider_counts.get(provider, 0) + 1
        
        # Get compliance report if available
        compliance_report = self.context.config.get('compliance_report', {})
        
        return {
            'scan_id': self.scan_id,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration_seconds': (self.end_time - self.start_time).total_seconds(),
            'providers': self.context.providers,
            'resources_scanned': len(self.context.resources),
            'total_findings': len(self.context.findings),
            'severity_counts': severity_counts,
            'layer_counts': layer_counts,
            'provider_counts': provider_counts,
            'compliance_scores': compliance_report,
            'findings': [self._finding_to_dict(f) for f in self.context.findings],
            'resources': [self._resource_to_dict(r) for r in self.context.resources],
            'attack_graph': self.context.resource_graph
        }
    
    def _finding_to_dict(self, finding: CloudFinding) -> Dict[str, Any]:
        """Convert CloudFinding to dictionary"""
        return {
            'id': finding.id,
            'category': finding.category,
            'severity': finding.severity,
            'title': finding.title,
            'description': finding.description,
            'provider': finding.provider,
            'service': finding.service,
            'resource_id': finding.resource_id,
            'resource_arn': finding.resource_arn,
            'region': finding.region,
            'evidence': finding.evidence,
            'remediation': finding.remediation,
            'remediation_cli': finding.remediation_cli,
            'cis_benchmark': finding.cis_benchmark,
            'compliance_frameworks': finding.compliance_frameworks,
            'cvss_score': finding.cvss_score,
            'blast_radius_score': finding.blast_radius_score,
            'exploitability_score': finding.exploitability_score,
            'attack_path': finding.attack_path,
            'detection_layer': finding.detection_layer,
            'detected_at': finding.detected_at.isoformat()
        }
    
    def _resource_to_dict(self, resource: CloudResource) -> Dict[str, Any]:
        """Convert CloudResource to dictionary"""
        return {
            'resource_id': resource.resource_id,
            'resource_type': resource.resource_type,
            'provider': resource.provider,
            'region': resource.region,
            'name': resource.name,
            'arn_or_id': resource.arn_or_id,
            'tags': resource.tags,
            'metadata': resource.metadata,
            'relationships': resource.relationships
        }
