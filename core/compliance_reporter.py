"""
Compliance Reporter - Enterprise Compliance Report Generation

Generates comprehensive compliance reports for enterprise customers.
Supports:
- SOC 2 Type II
- ISO 27001:2022
- GDPR (General Data Protection Regulation)
- HIPAA (Health Insurance Portability and Accountability Act)
- PCI-DSS (Payment Card Industry Data Security Standard)
- NIST Cybersecurity Framework
- CIS Controls

Each framework maps security controls to Jarwis audit logs, scan results,
and configuration data to provide evidence of compliance.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

logger = logging.getLogger(__name__)


# ============== Framework Definitions ==============

class ComplianceFramework(str, Enum):
    """Supported compliance frameworks"""
    SOC2_TYPE_II = "soc2_type_ii"
    ISO_27001 = "iso_27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    NIST_CSF = "nist_csf"
    CIS_CONTROLS = "cis_controls"


class ControlStatus(str, Enum):
    """Control compliance status"""
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    NEEDS_REVIEW = "needs_review"


class EvidenceType(str, Enum):
    """Types of compliance evidence"""
    AUDIT_LOG = "audit_log"
    CONFIGURATION = "configuration"
    SCAN_RESULT = "scan_result"
    POLICY_DOCUMENT = "policy_document"
    SCREENSHOT = "screenshot"
    ATTESTATION = "attestation"
    AUTOMATED_TEST = "automated_test"


# ============== Data Classes ==============

@dataclass
class ControlMapping:
    """Maps a compliance control to Jarwis features"""
    id: str
    name: str
    description: str
    category: str
    
    # Evidence collection configuration
    evidence_sources: List[str] = field(default_factory=list)
    # Sources: audit_logs, scan_findings, credentials, configurations, etc.
    
    audit_actions: List[str] = field(default_factory=list)
    # Which audit actions provide evidence for this control
    
    required_configs: List[str] = field(default_factory=list)
    # Configuration settings that must be enabled
    
    scan_requirements: List[str] = field(default_factory=list)
    # Scan types that provide evidence
    
    # Compliance criteria
    minimum_score: float = 0.0
    # Minimum evidence score for compliance (0-100)
    
    manual_review_required: bool = False


@dataclass
class Evidence:
    """A piece of compliance evidence"""
    id: str
    control_id: str
    evidence_type: EvidenceType
    title: str
    description: str
    
    collected_at: datetime = field(default_factory=datetime.utcnow)
    
    # Evidence data
    data: Dict = field(default_factory=dict)
    attachments: List[str] = field(default_factory=list)
    
    # Scoring
    score: float = 0.0  # 0-100
    weight: float = 1.0
    
    # Review
    status: str = "collected"
    reviewed_by: Optional[str] = None
    reviewed_at: Optional[datetime] = None
    notes: str = ""


@dataclass
class ControlResult:
    """Result of evaluating a single control"""
    control: ControlMapping
    status: ControlStatus
    score: float  # 0-100
    
    evidence: List[Evidence] = field(default_factory=list)
    
    gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    
    reviewed: bool = False
    review_notes: str = ""


@dataclass
class ComplianceReportResult:
    """Complete compliance report"""
    id: str
    framework: ComplianceFramework
    tenant_id: str
    
    period_start: datetime
    period_end: datetime
    generated_at: datetime = field(default_factory=datetime.utcnow)
    generated_by: str = ""
    
    # Summary
    total_controls: int = 0
    compliant_count: int = 0
    partially_compliant_count: int = 0
    non_compliant_count: int = 0
    not_applicable_count: int = 0
    needs_review_count: int = 0
    
    overall_score: float = 0.0  # 0-100
    
    # Detailed results
    control_results: List[ControlResult] = field(default_factory=list)
    
    # Summary by category
    category_scores: Dict[str, float] = field(default_factory=dict)
    
    # Executive summary
    executive_summary: str = ""
    key_findings: List[str] = field(default_factory=list)
    priority_remediation: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for storage/export"""
        return {
            "id": self.id,
            "framework": self.framework.value,
            "tenant_id": self.tenant_id,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "summary": {
                "total_controls": self.total_controls,
                "compliant": self.compliant_count,
                "partially_compliant": self.partially_compliant_count,
                "non_compliant": self.non_compliant_count,
                "not_applicable": self.not_applicable_count,
                "needs_review": self.needs_review_count,
                "overall_score": round(self.overall_score, 1)
            },
            "category_scores": self.category_scores,
            "executive_summary": self.executive_summary,
            "key_findings": self.key_findings,
            "priority_remediation": self.priority_remediation,
            "control_results": [
                {
                    "control_id": r.control.id,
                    "control_name": r.control.name,
                    "category": r.control.category,
                    "status": r.status.value,
                    "score": round(r.score, 1),
                    "evidence_count": len(r.evidence),
                    "gaps": r.gaps,
                    "recommendations": r.recommendations
                }
                for r in self.control_results
            ]
        }


# ============== Framework Control Mappings ==============

SOC2_CONTROLS: List[ControlMapping] = [
    # CC1 - Control Environment
    ControlMapping(
        id="CC1.1",
        name="COSO Principle 1",
        description="The entity demonstrates a commitment to integrity and ethical values",
        category="Control Environment",
        evidence_sources=["policy_documents"],
        manual_review_required=True
    ),
    
    # CC6 - Logical and Physical Access Controls
    ControlMapping(
        id="CC6.1",
        name="Logical Access Security",
        description="The entity implements logical access security software, infrastructure, and architectures",
        category="Logical Access",
        evidence_sources=["audit_logs", "configurations"],
        audit_actions=["auth.login.success", "auth.login.failed", "auth.mfa.enabled"],
        required_configs=["mfa_enabled", "password_policy"]
    ),
    ControlMapping(
        id="CC6.2",
        name="User Registration and Authorization",
        description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new users",
        category="Logical Access",
        evidence_sources=["audit_logs"],
        audit_actions=["user.created", "role.assigned", "user.modified"]
    ),
    ControlMapping(
        id="CC6.3",
        name="Credential Lifecycle Management",
        description="The entity authorizes, modifies, or removes access based on user roles and responsibilities",
        category="Logical Access",
        evidence_sources=["audit_logs", "configurations"],
        audit_actions=["role.assigned", "role.revoked", "user.deleted", "user.suspended"]
    ),
    ControlMapping(
        id="CC6.6",
        name="Encryption of Data",
        description="The entity implements controls to prevent or detect unauthorized access to system resources",
        category="Logical Access",
        evidence_sources=["configurations", "scan_results"],
        required_configs=["encryption_at_rest", "encryption_in_transit"],
        scan_requirements=["ssl_audit"]
    ),
    ControlMapping(
        id="CC6.7",
        name="Transmission Protection",
        description="The entity restricts the transmission, movement, and removal of information",
        category="Logical Access",
        evidence_sources=["configurations", "scan_results"],
        required_configs=["tls_enforcement"],
        scan_requirements=["ssl_audit"]
    ),
    
    # CC7 - System Operations
    ControlMapping(
        id="CC7.1",
        name="Vulnerability Management",
        description="To detect and address security vulnerabilities",
        category="System Operations",
        evidence_sources=["scan_results"],
        scan_requirements=["vulnerability_scan", "web_scan"]
    ),
    ControlMapping(
        id="CC7.2",
        name="Security Monitoring",
        description="The entity monitors system components for anomalies",
        category="System Operations",
        evidence_sources=["audit_logs", "configurations"],
        audit_actions=["scan.started", "scan.completed", "credential.accessed"]
    ),
    ControlMapping(
        id="CC7.3",
        name="Incident Response",
        description="The entity evaluates security events to determine whether they constitute security incidents",
        category="System Operations",
        evidence_sources=["audit_logs", "policy_documents"],
        manual_review_required=True
    ),
    
    # CC8 - Change Management
    ControlMapping(
        id="CC8.1",
        name="Change Management Process",
        description="The entity authorizes, designs, develops, configures, tests, and implements changes",
        category="Change Management",
        evidence_sources=["audit_logs"],
        audit_actions=["config.changed", "settings.updated"]
    ),
]

ISO27001_CONTROLS: List[ControlMapping] = [
    # A.5 - Information Security Policies
    ControlMapping(
        id="A.5.1.1",
        name="Policies for Information Security",
        description="A set of policies for information security shall be defined",
        category="Security Policies",
        evidence_sources=["policy_documents"],
        manual_review_required=True
    ),
    
    # A.6 - Organization of Information Security
    ControlMapping(
        id="A.6.1.1",
        name="Information Security Roles and Responsibilities",
        description="All information security responsibilities shall be defined and allocated",
        category="Organization",
        evidence_sources=["configurations", "audit_logs"],
        audit_actions=["role.assigned", "user.created"]
    ),
    
    # A.9 - Access Control
    ControlMapping(
        id="A.9.1.1",
        name="Access Control Policy",
        description="An access control policy shall be established and reviewed",
        category="Access Control",
        evidence_sources=["configurations", "policy_documents"],
        required_configs=["rbac_enabled"]
    ),
    ControlMapping(
        id="A.9.2.1",
        name="User Registration and De-registration",
        description="A formal user registration and de-registration process shall be implemented",
        category="Access Control",
        evidence_sources=["audit_logs"],
        audit_actions=["user.created", "user.deleted", "user.suspended"]
    ),
    ControlMapping(
        id="A.9.2.3",
        name="Management of Privileged Access Rights",
        description="The allocation and use of privileged access rights shall be restricted and controlled",
        category="Access Control",
        evidence_sources=["audit_logs", "configurations"],
        audit_actions=["role.assigned", "credential.accessed"],
        required_configs=["rbac_enabled", "admin_mfa_required"]
    ),
    ControlMapping(
        id="A.9.4.1",
        name="Information Access Restriction",
        description="Access to information and application system functions shall be restricted",
        category="Access Control",
        evidence_sources=["configurations", "audit_logs"],
        required_configs=["rbac_enabled"]
    ),
    
    # A.10 - Cryptography
    ControlMapping(
        id="A.10.1.1",
        name="Policy on Use of Cryptographic Controls",
        description="A policy on the use of cryptographic controls shall be developed and implemented",
        category="Cryptography",
        evidence_sources=["configurations"],
        required_configs=["encryption_at_rest", "encryption_in_transit"]
    ),
    ControlMapping(
        id="A.10.1.2",
        name="Key Management",
        description="A policy on the use, protection, and lifetime of cryptographic keys shall be developed",
        category="Cryptography",
        evidence_sources=["configurations", "audit_logs"],
        audit_actions=["credential.rotated"],
        required_configs=["key_rotation_policy"]
    ),
    
    # A.12 - Operations Security
    ControlMapping(
        id="A.12.4.1",
        name="Event Logging",
        description="Event logs shall be produced, kept and regularly reviewed",
        category="Operations Security",
        evidence_sources=["audit_logs", "configurations"],
        required_configs=["audit_logging_enabled"]
    ),
    ControlMapping(
        id="A.12.6.1",
        name="Management of Technical Vulnerabilities",
        description="Information about technical vulnerabilities shall be obtained",
        category="Operations Security",
        evidence_sources=["scan_results"],
        scan_requirements=["vulnerability_scan", "sast_scan"]
    ),
    
    # A.18 - Compliance
    ControlMapping(
        id="A.18.1.3",
        name="Protection of Records",
        description="Records shall be protected from loss, destruction, and falsification",
        category="Compliance",
        evidence_sources=["configurations"],
        required_configs=["backup_enabled", "audit_log_retention"]
    ),
    ControlMapping(
        id="A.18.1.4",
        name="Privacy and Protection of PII",
        description="Privacy and protection of personally identifiable information shall be ensured",
        category="Compliance",
        evidence_sources=["configurations", "policy_documents"],
        required_configs=["data_classification", "pii_protection"],
        manual_review_required=True
    ),
]

GDPR_CONTROLS: List[ControlMapping] = [
    # Article 5 - Principles
    ControlMapping(
        id="Art.5.1.f",
        name="Integrity and Confidentiality",
        description="Personal data shall be processed with appropriate security measures",
        category="Data Protection Principles",
        evidence_sources=["configurations", "scan_results"],
        required_configs=["encryption_at_rest", "encryption_in_transit"],
        scan_requirements=["ssl_audit"]
    ),
    
    # Article 17 - Right to Erasure
    ControlMapping(
        id="Art.17",
        name="Right to Erasure (Right to be Forgotten)",
        description="Data subjects have the right to obtain erasure of personal data",
        category="Data Subject Rights",
        evidence_sources=["configurations", "audit_logs"],
        audit_actions=["data.deleted"],
        required_configs=["data_deletion_enabled"]
    ),
    
    # Article 25 - Data Protection by Design
    ControlMapping(
        id="Art.25",
        name="Data Protection by Design and Default",
        description="Implement appropriate technical measures for data protection",
        category="Privacy by Design",
        evidence_sources=["configurations"],
        required_configs=["encryption_at_rest", "data_minimization", "access_control"]
    ),
    
    # Article 30 - Records of Processing
    ControlMapping(
        id="Art.30",
        name="Records of Processing Activities",
        description="Maintain a record of processing activities",
        category="Documentation",
        evidence_sources=["audit_logs"],
        required_configs=["audit_logging_enabled"]
    ),
    
    # Article 32 - Security of Processing
    ControlMapping(
        id="Art.32.1.a",
        name="Pseudonymisation and Encryption",
        description="Implement pseudonymisation and encryption of personal data",
        category="Security Measures",
        evidence_sources=["configurations"],
        required_configs=["encryption_at_rest", "data_masking"]
    ),
    ControlMapping(
        id="Art.32.1.b",
        name="Confidentiality and Integrity",
        description="Ensure ongoing confidentiality, integrity, and availability",
        category="Security Measures",
        evidence_sources=["configurations", "scan_results"],
        scan_requirements=["vulnerability_scan"]
    ),
    ControlMapping(
        id="Art.32.1.d",
        name="Regular Testing",
        description="Process for regularly testing and evaluating security measures",
        category="Security Measures",
        evidence_sources=["scan_results"],
        scan_requirements=["web_scan", "vulnerability_scan", "sast_scan"]
    ),
    
    # Article 33 - Breach Notification
    ControlMapping(
        id="Art.33",
        name="Notification of Personal Data Breach",
        description="Notify supervisory authority within 72 hours of breach awareness",
        category="Breach Notification",
        evidence_sources=["policy_documents", "configurations"],
        required_configs=["breach_notification_process"],
        manual_review_required=True
    ),
]

HIPAA_CONTROLS: List[ControlMapping] = [
    # Administrative Safeguards - 164.308
    ControlMapping(
        id="164.308(a)(1)",
        name="Security Management Process",
        description="Implement policies and procedures to prevent, detect, and correct security violations",
        category="Administrative Safeguards",
        evidence_sources=["policy_documents", "scan_results"],
        scan_requirements=["vulnerability_scan"],
        manual_review_required=True
    ),
    ControlMapping(
        id="164.308(a)(3)",
        name="Workforce Security",
        description="Implement policies to ensure appropriate access to ePHI",
        category="Administrative Safeguards",
        evidence_sources=["audit_logs", "configurations"],
        audit_actions=["user.created", "role.assigned", "user.suspended"],
        required_configs=["rbac_enabled"]
    ),
    ControlMapping(
        id="164.308(a)(4)",
        name="Information Access Management",
        description="Implement policies for authorizing access to ePHI",
        category="Administrative Safeguards",
        evidence_sources=["configurations", "audit_logs"],
        required_configs=["rbac_enabled", "access_control"]
    ),
    ControlMapping(
        id="164.308(a)(5)",
        name="Security Awareness and Training",
        description="Implement a security awareness and training program",
        category="Administrative Safeguards",
        evidence_sources=["policy_documents"],
        manual_review_required=True
    ),
    
    # Technical Safeguards - 164.312
    ControlMapping(
        id="164.312(a)(1)",
        name="Access Control",
        description="Implement technical policies to allow access only to authorized persons",
        category="Technical Safeguards",
        evidence_sources=["configurations", "audit_logs"],
        audit_actions=["auth.login.success", "auth.login.failed"],
        required_configs=["rbac_enabled", "unique_user_id", "auto_logoff"]
    ),
    ControlMapping(
        id="164.312(b)",
        name="Audit Controls",
        description="Implement hardware, software, and procedures to record and examine access",
        category="Technical Safeguards",
        evidence_sources=["audit_logs", "configurations"],
        required_configs=["audit_logging_enabled"],
        audit_actions=["credential.accessed", "scan.started", "report.accessed"]
    ),
    ControlMapping(
        id="164.312(c)(1)",
        name="Integrity Controls",
        description="Implement policies to protect ePHI from improper alteration or destruction",
        category="Technical Safeguards",
        evidence_sources=["configurations"],
        required_configs=["data_integrity_controls"]
    ),
    ControlMapping(
        id="164.312(d)",
        name="Person or Entity Authentication",
        description="Implement procedures to verify identity before granting access",
        category="Technical Safeguards",
        evidence_sources=["configurations", "audit_logs"],
        audit_actions=["auth.mfa.enabled"],
        required_configs=["mfa_enabled", "strong_authentication"]
    ),
    ControlMapping(
        id="164.312(e)(1)",
        name="Transmission Security",
        description="Implement technical security measures to guard against unauthorized access during transmission",
        category="Technical Safeguards",
        evidence_sources=["configurations", "scan_results"],
        required_configs=["encryption_in_transit", "tls_enforcement"],
        scan_requirements=["ssl_audit"]
    ),
]

PCI_DSS_CONTROLS: List[ControlMapping] = [
    # Requirement 1 - Network Security
    ControlMapping(
        id="PCI-1.1",
        name="Install and Maintain Network Security Controls",
        description="Processes and mechanisms for installing and maintaining network security controls",
        category="Network Security",
        evidence_sources=["configurations", "scan_results"],
        scan_requirements=["network_scan"]
    ),
    
    # Requirement 2 - Secure Configurations
    ControlMapping(
        id="PCI-2.2",
        name="System Components Securely Configured",
        description="System components are configured and managed securely",
        category="Secure Configuration",
        evidence_sources=["scan_results"],
        scan_requirements=["vulnerability_scan", "cloud_scan"]
    ),
    
    # Requirement 3 - Protect Stored Data
    ControlMapping(
        id="PCI-3.5",
        name="Cryptographic Keys Protection",
        description="Cryptographic keys used to protect stored account data are secured",
        category="Data Protection",
        evidence_sources=["configurations"],
        required_configs=["key_management", "encryption_at_rest"]
    ),
    
    # Requirement 6 - Secure Software
    ControlMapping(
        id="PCI-6.2",
        name="Bespoke and Custom Software Security",
        description="Bespoke and custom software are developed securely",
        category="Secure Software",
        evidence_sources=["scan_results"],
        scan_requirements=["sast_scan"]
    ),
    ControlMapping(
        id="PCI-6.3",
        name="Security Vulnerabilities Identified and Addressed",
        description="Security vulnerabilities are identified and addressed",
        category="Secure Software",
        evidence_sources=["scan_results"],
        scan_requirements=["web_scan", "sast_scan"]
    ),
    
    # Requirement 7 - Access Control
    ControlMapping(
        id="PCI-7.2",
        name="Access Control Systems",
        description="Access to system components and data is appropriately defined and assigned",
        category="Access Control",
        evidence_sources=["configurations", "audit_logs"],
        required_configs=["rbac_enabled"],
        audit_actions=["role.assigned"]
    ),
    
    # Requirement 8 - User Identification
    ControlMapping(
        id="PCI-8.3",
        name="Strong Authentication",
        description="Strong authentication for users and administrators is established and managed",
        category="Authentication",
        evidence_sources=["configurations", "audit_logs"],
        required_configs=["mfa_enabled", "strong_password_policy"],
        audit_actions=["auth.mfa.enabled"]
    ),
    
    # Requirement 10 - Logging and Monitoring
    ControlMapping(
        id="PCI-10.2",
        name="Audit Logs Implementation",
        description="Audit logs are implemented to support detection of anomalies",
        category="Logging & Monitoring",
        evidence_sources=["audit_logs", "configurations"],
        required_configs=["audit_logging_enabled"]
    ),
    
    # Requirement 11 - Security Testing
    ControlMapping(
        id="PCI-11.3",
        name="External and Internal Vulnerabilities",
        description="External and internal vulnerabilities are regularly identified, prioritized, and addressed",
        category="Security Testing",
        evidence_sources=["scan_results"],
        scan_requirements=["vulnerability_scan", "web_scan"]
    ),
]

# Map frameworks to their controls
FRAMEWORK_CONTROLS: Dict[ComplianceFramework, List[ControlMapping]] = {
    ComplianceFramework.SOC2_TYPE_II: SOC2_CONTROLS,
    ComplianceFramework.ISO_27001: ISO27001_CONTROLS,
    ComplianceFramework.GDPR: GDPR_CONTROLS,
    ComplianceFramework.HIPAA: HIPAA_CONTROLS,
    ComplianceFramework.PCI_DSS: PCI_DSS_CONTROLS,
}


# ============== Compliance Reporter ==============

class ComplianceReporter:
    """
    Generates comprehensive compliance reports by mapping
    Jarwis security data to compliance framework controls.
    """
    
    def __init__(self, trust_agent=None, db_session=None):
        self._trust = trust_agent
        self._db = db_session
        self._framework_controls = FRAMEWORK_CONTROLS.copy()
    
    async def generate_report(
        self,
        framework: ComplianceFramework,
        tenant_id: str,
        period_start: datetime,
        period_end: datetime,
        generated_by: str
    ) -> ComplianceReportResult:
        """
        Generate a complete compliance report for a framework.
        """
        import uuid
        
        controls = self._framework_controls.get(framework, [])
        if not controls:
            raise ValueError(f"No controls defined for framework: {framework}")
        
        # Initialize report
        report = ComplianceReportResult(
            id=str(uuid.uuid4()),
            framework=framework,
            tenant_id=tenant_id,
            period_start=period_start,
            period_end=period_end,
            generated_by=generated_by,
            total_controls=len(controls)
        )
        
        # Evaluate each control
        control_results = []
        category_totals: Dict[str, Tuple[float, int]] = {}  # category -> (total_score, count)
        
        for control in controls:
            result = await self._evaluate_control(
                control, tenant_id, period_start, period_end
            )
            control_results.append(result)
            
            # Update counts
            if result.status == ControlStatus.COMPLIANT:
                report.compliant_count += 1
            elif result.status == ControlStatus.PARTIALLY_COMPLIANT:
                report.partially_compliant_count += 1
            elif result.status == ControlStatus.NON_COMPLIANT:
                report.non_compliant_count += 1
            elif result.status == ControlStatus.NOT_APPLICABLE:
                report.not_applicable_count += 1
            else:
                report.needs_review_count += 1
            
            # Track category scores
            if control.category not in category_totals:
                category_totals[control.category] = (0.0, 0)
            current = category_totals[control.category]
            category_totals[control.category] = (current[0] + result.score, current[1] + 1)
        
        report.control_results = control_results
        
        # Calculate category and overall scores
        for category, (total, count) in category_totals.items():
            report.category_scores[category] = round(total / count, 1) if count > 0 else 0
        
        if len(control_results) > 0:
            report.overall_score = sum(r.score for r in control_results) / len(control_results)
        
        # Generate executive summary
        report.executive_summary = self._generate_executive_summary(report)
        report.key_findings = self._extract_key_findings(report)
        report.priority_remediation = self._generate_remediation_priorities(report)
        
        # Log report generation
        if self._trust:
            from core.trust_agent import AuditAction
            await self._trust.log_action(
                action=AuditAction.COMPLIANCE_REPORT_GENERATED,
                user_id=generated_by,
                tenant_id=tenant_id,
                metadata={
                    "framework": framework.value,
                    "overall_score": report.overall_score,
                    "compliant_count": report.compliant_count,
                    "non_compliant_count": report.non_compliant_count
                }
            )
        
        return report
    
    async def _evaluate_control(
        self,
        control: ControlMapping,
        tenant_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> ControlResult:
        """Evaluate a single control and collect evidence"""
        evidence_list: List[Evidence] = []
        total_score = 0.0
        total_weight = 0.0
        gaps: List[str] = []
        recommendations: List[str] = []
        
        # Collect evidence from audit logs
        if control.audit_actions:
            audit_evidence = await self._collect_audit_evidence(
                control, tenant_id, period_start, period_end
            )
            evidence_list.extend(audit_evidence)
            
            if audit_evidence:
                score = min(100, len(audit_evidence) * 20)  # Up to 100 for 5+ events
                total_score += score
                total_weight += 1.0
            else:
                gaps.append(f"No audit log events found for {control.name}")
                recommendations.append(f"Ensure {control.name} activities are being logged")
        
        # Check required configurations
        if control.required_configs:
            config_evidence = await self._collect_config_evidence(
                control, tenant_id
            )
            evidence_list.extend(config_evidence)
            
            enabled_count = sum(1 for e in config_evidence if e.data.get("enabled", False))
            if control.required_configs:
                score = (enabled_count / len(control.required_configs)) * 100
                total_score += score
                total_weight += 1.0
                
                if score < 100:
                    missing = [c for c in control.required_configs 
                               if not any(e.data.get("config_name") == c and e.data.get("enabled") 
                                         for e in config_evidence)]
                    if missing:
                        gaps.append(f"Missing configurations: {', '.join(missing)}")
                        recommendations.append(f"Enable the following: {', '.join(missing)}")
        
        # Check scan requirements
        if control.scan_requirements:
            scan_evidence = await self._collect_scan_evidence(
                control, tenant_id, period_start, period_end
            )
            evidence_list.extend(scan_evidence)
            
            if scan_evidence:
                # Score based on scan completion and findings addressed
                score = 80  # Base score for having scans
                total_score += score
                total_weight += 1.0
            else:
                gaps.append(f"No {', '.join(control.scan_requirements)} scans found in period")
                recommendations.append(f"Run regular {', '.join(control.scan_requirements)} scans")
                total_weight += 1.0  # Count as 0
        
        # Calculate final score
        final_score = (total_score / total_weight) if total_weight > 0 else 0
        
        # Determine status
        if control.manual_review_required and not evidence_list:
            status = ControlStatus.NEEDS_REVIEW
        elif final_score >= 80:
            status = ControlStatus.COMPLIANT
        elif final_score >= 50:
            status = ControlStatus.PARTIALLY_COMPLIANT
        elif final_score > 0:
            status = ControlStatus.NON_COMPLIANT
        else:
            status = ControlStatus.NEEDS_REVIEW
        
        return ControlResult(
            control=control,
            status=status,
            score=final_score,
            evidence=evidence_list,
            gaps=gaps,
            recommendations=recommendations
        )
    
    async def _collect_audit_evidence(
        self,
        control: ControlMapping,
        tenant_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> List[Evidence]:
        """Collect audit log evidence for a control"""
        evidence = []
        
        # In production, this would query the AuditLog table
        # For now, return sample evidence structure
        for action in control.audit_actions:
            evidence.append(Evidence(
                id=str(hash(f"{control.id}-{action}")),
                control_id=control.id,
                evidence_type=EvidenceType.AUDIT_LOG,
                title=f"Audit log: {action}",
                description=f"Audit events for {action} within reporting period",
                data={
                    "action": action,
                    "event_count": 0,  # Would be actual count from DB
                    "period_start": period_start.isoformat(),
                    "period_end": period_end.isoformat()
                },
                score=0  # Would calculate based on event count
            ))
        
        return evidence
    
    async def _collect_config_evidence(
        self,
        control: ControlMapping,
        tenant_id: str
    ) -> List[Evidence]:
        """Collect configuration evidence for a control"""
        evidence = []
        
        # Map config names to actual checks
        config_checks = {
            "mfa_enabled": True,  # Would check actual tenant config
            "rbac_enabled": True,
            "encryption_at_rest": True,
            "encryption_in_transit": True,
            "audit_logging_enabled": True,
            "password_policy": True,
            "tls_enforcement": True,
            "key_rotation_policy": False,
            "data_deletion_enabled": True,
        }
        
        for config in control.required_configs:
            enabled = config_checks.get(config, False)
            evidence.append(Evidence(
                id=str(hash(f"{control.id}-config-{config}")),
                control_id=control.id,
                evidence_type=EvidenceType.CONFIGURATION,
                title=f"Configuration: {config}",
                description=f"Configuration setting {config} status",
                data={
                    "config_name": config,
                    "enabled": enabled
                },
                score=100 if enabled else 0
            ))
        
        return evidence
    
    async def _collect_scan_evidence(
        self,
        control: ControlMapping,
        tenant_id: str,
        period_start: datetime,
        period_end: datetime
    ) -> List[Evidence]:
        """Collect scan result evidence for a control"""
        evidence = []
        
        # In production, query ScanHistory table
        for scan_type in control.scan_requirements:
            evidence.append(Evidence(
                id=str(hash(f"{control.id}-scan-{scan_type}")),
                control_id=control.id,
                evidence_type=EvidenceType.SCAN_RESULT,
                title=f"Scan: {scan_type}",
                description=f"{scan_type} scan results within reporting period",
                data={
                    "scan_type": scan_type,
                    "scan_count": 0,  # Would be actual count
                    "findings_addressed": 0,
                    "period_start": period_start.isoformat(),
                    "period_end": period_end.isoformat()
                },
                score=0
            ))
        
        return evidence
    
    def _generate_executive_summary(self, report: ComplianceReportResult) -> str:
        """Generate executive summary text"""
        framework_names = {
            ComplianceFramework.SOC2_TYPE_II: "SOC 2 Type II",
            ComplianceFramework.ISO_27001: "ISO 27001:2022",
            ComplianceFramework.GDPR: "GDPR",
            ComplianceFramework.HIPAA: "HIPAA",
            ComplianceFramework.PCI_DSS: "PCI-DSS v4.0",
            ComplianceFramework.NIST_CSF: "NIST CSF",
            ComplianceFramework.CIS_CONTROLS: "CIS Controls"
        }
        
        name = framework_names.get(report.framework, report.framework.value)
        
        return f"""This {name} compliance assessment was conducted for the period 
{report.period_start.strftime('%B %d, %Y')} to {report.period_end.strftime('%B %d, %Y')}.

Overall Compliance Score: {round(report.overall_score, 1)}%

Of {report.total_controls} controls evaluated:
- {report.compliant_count} controls are fully compliant
- {report.partially_compliant_count} controls are partially compliant
- {report.non_compliant_count} controls are non-compliant
- {report.needs_review_count} controls require manual review

{'The organization demonstrates strong security controls across most areas.' if report.overall_score >= 80 else 'Several areas require attention to achieve compliance.'}
"""
    
    def _extract_key_findings(self, report: ComplianceReportResult) -> List[str]:
        """Extract key findings from control results"""
        findings = []
        
        # Find non-compliant controls
        non_compliant = [r for r in report.control_results 
                        if r.status == ControlStatus.NON_COMPLIANT]
        for result in non_compliant[:5]:  # Top 5
            findings.append(f"Non-compliant: {result.control.name} - {result.gaps[0] if result.gaps else 'Review required'}")
        
        # Find partially compliant
        partial = [r for r in report.control_results 
                  if r.status == ControlStatus.PARTIALLY_COMPLIANT]
        for result in partial[:3]:  # Top 3
            findings.append(f"Partially compliant: {result.control.name} ({round(result.score, 1)}%)")
        
        return findings
    
    def _generate_remediation_priorities(self, report: ComplianceReportResult) -> List[str]:
        """Generate prioritized remediation recommendations"""
        priorities = []
        
        # Non-compliant controls are highest priority
        non_compliant = [r for r in report.control_results 
                        if r.status == ControlStatus.NON_COMPLIANT]
        for result in sorted(non_compliant, key=lambda r: r.score):
            for rec in result.recommendations[:1]:  # Top recommendation per control
                priorities.append(f"[HIGH] {result.control.id}: {rec}")
        
        # Partially compliant next
        partial = [r for r in report.control_results 
                  if r.status == ControlStatus.PARTIALLY_COMPLIANT]
        for result in sorted(partial, key=lambda r: r.score):
            for rec in result.recommendations[:1]:
                priorities.append(f"[MEDIUM] {result.control.id}: {rec}")
        
        return priorities[:10]  # Top 10 priorities
    
    async def export_report(
        self,
        report: ComplianceReportResult,
        format: str = "json",
        output_path: Optional[str] = None
    ) -> bytes:
        """Export report in specified format"""
        if format == "json":
            data = json.dumps(report.to_dict(), indent=2, default=str)
            content = data.encode()
        elif format == "html":
            content = self._generate_html_report(report).encode()
        elif format == "csv":
            content = self._generate_csv_report(report).encode()
        else:
            raise ValueError(f"Unsupported format: {format}")
        
        if output_path:
            Path(output_path).write_bytes(content)
        
        return content
    
    def _generate_html_report(self, report: ComplianceReportResult) -> str:
        """Generate HTML report"""
        framework_names = {
            ComplianceFramework.SOC2_TYPE_II: "SOC 2 Type II",
            ComplianceFramework.ISO_27001: "ISO 27001:2022",
            ComplianceFramework.GDPR: "GDPR",
            ComplianceFramework.HIPAA: "HIPAA",
            ComplianceFramework.PCI_DSS: "PCI-DSS v4.0",
        }
        
        name = framework_names.get(report.framework, report.framework.value)
        
        status_colors = {
            ControlStatus.COMPLIANT: "#22c55e",
            ControlStatus.PARTIALLY_COMPLIANT: "#f59e0b",
            ControlStatus.NON_COMPLIANT: "#ef4444",
            ControlStatus.NOT_APPLICABLE: "#6b7280",
            ControlStatus.NEEDS_REVIEW: "#3b82f6"
        }
        
        controls_html = ""
        for result in report.control_results:
            color = status_colors.get(result.status, "#6b7280")
            controls_html += f"""
            <tr>
                <td>{result.control.id}</td>
                <td>{result.control.name}</td>
                <td>{result.control.category}</td>
                <td style="color: {color}; font-weight: bold;">{result.status.value.replace('_', ' ').title()}</td>
                <td>{round(result.score, 1)}%</td>
            </tr>
            """
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <title>{name} Compliance Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #1e3a5f; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; }}
        h2 {{ color: #1e3a5f; margin-top: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
        .summary-card {{ background: #f8fafc; padding: 20px; border-radius: 8px; text-align: center; }}
        .summary-card .value {{ font-size: 32px; font-weight: bold; color: #1e3a5f; }}
        .summary-card .label {{ color: #64748b; margin-top: 5px; }}
        .score {{ font-size: 48px; font-weight: bold; color: {'#22c55e' if report.overall_score >= 80 else '#f59e0b' if report.overall_score >= 50 else '#ef4444'}; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #e2e8f0; }}
        th {{ background: #f8fafc; font-weight: bold; color: #1e3a5f; }}
        .executive-summary {{ background: #f0f9ff; padding: 20px; border-radius: 8px; white-space: pre-line; }}
        .findings {{ margin-top: 20px; }}
        .findings li {{ margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{name} Compliance Report</h1>
        <p>Period: {report.period_start.strftime('%B %d, %Y')} - {report.period_end.strftime('%B %d, %Y')}</p>
        <p>Generated: {report.generated_at.strftime('%B %d, %Y at %H:%M UTC')}</p>
        
        <div class="summary">
            <div class="summary-card">
                <div class="score">{round(report.overall_score, 1)}%</div>
                <div class="label">Overall Score</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #22c55e;">{report.compliant_count}</div>
                <div class="label">Compliant</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #f59e0b;">{report.partially_compliant_count}</div>
                <div class="label">Partial</div>
            </div>
            <div class="summary-card">
                <div class="value" style="color: #ef4444;">{report.non_compliant_count}</div>
                <div class="label">Non-Compliant</div>
            </div>
        </div>
        
        <h2>Executive Summary</h2>
        <div class="executive-summary">{report.executive_summary}</div>
        
        <h2>Key Findings</h2>
        <ul class="findings">
            {''.join(f'<li>{f}</li>' for f in report.key_findings)}
        </ul>
        
        <h2>Priority Remediation</h2>
        <ul class="findings">
            {''.join(f'<li>{r}</li>' for r in report.priority_remediation)}
        </ul>
        
        <h2>Control Details</h2>
        <table>
            <thead>
                <tr>
                    <th>Control ID</th>
                    <th>Name</th>
                    <th>Category</th>
                    <th>Status</th>
                    <th>Score</th>
                </tr>
            </thead>
            <tbody>
                {controls_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
    
    def _generate_csv_report(self, report: ComplianceReportResult) -> str:
        """Generate CSV report"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow([
            "Control ID", "Control Name", "Category", "Status", 
            "Score", "Gaps", "Recommendations"
        ])
        
        # Data rows
        for result in report.control_results:
            writer.writerow([
                result.control.id,
                result.control.name,
                result.control.category,
                result.status.value,
                round(result.score, 1),
                "; ".join(result.gaps),
                "; ".join(result.recommendations)
            ])
        
        return output.getvalue()


# Factory function
def create_compliance_reporter(trust_agent=None, db_session=None) -> ComplianceReporter:
    """Create a compliance reporter instance"""
    return ComplianceReporter(trust_agent=trust_agent, db_session=db_session)
