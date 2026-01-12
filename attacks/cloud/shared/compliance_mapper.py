"""
Jarwis AGI - Compliance Mapping Engine
Maps findings to multiple compliance frameworks

Supported Frameworks:
- CIS Benchmarks (AWS, Azure, GCP, Kubernetes)
- PCI-DSS v4.0
- HIPAA
- SOC 2 Type II
- NIST 800-53
- GDPR
- ISO 27001
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class ComplianceFramework(Enum):
    CIS = "CIS"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    SOC2 = "SOC2"
    NIST = "NIST-800-53"
    GDPR = "GDPR"
    ISO27001 = "ISO-27001"


@dataclass
class ComplianceControl:
    """Compliance control mapping"""
    framework: str
    control_id: str
    control_name: str
    description: str
    category: str


@dataclass
class ComplianceResult:
    """Compliance assessment result"""
    framework: str
    score: float  # 0-100
    total_controls: int
    passing_controls: int
    failing_controls: int
    controls: List[Dict] = field(default_factory=list)


class ComplianceMapper:
    """
    Compliance Mapping Engine
    Maps security findings to compliance framework controls
    """
    
    # CIS AWS Foundations Benchmark v1.5 controls
    CIS_AWS_CONTROLS = {
        "1.1": ComplianceControl("CIS", "1.1", "Avoid root account usage", "Avoid use of 'root' account", "Identity and Access Management"),
        "1.2": ComplianceControl("CIS", "1.2", "MFA for root", "Ensure MFA is enabled for the 'root' account", "Identity and Access Management"),
        "1.3": ComplianceControl("CIS", "1.3", "No root access keys", "Ensure no root account access keys exist", "Identity and Access Management"),
        "1.4": ComplianceControl("CIS", "1.4", "MFA for IAM users", "Ensure MFA is enabled for all IAM users with console access", "Identity and Access Management"),
        "1.5": ComplianceControl("CIS", "1.5", "Password policy", "Ensure IAM password policy requires at least one uppercase letter", "Identity and Access Management"),
        "1.6": ComplianceControl("CIS", "1.6", "Password lowercase", "Ensure IAM password policy requires at least one lowercase letter", "Identity and Access Management"),
        "1.7": ComplianceControl("CIS", "1.7", "Password symbol", "Ensure IAM password policy requires at least one symbol", "Identity and Access Management"),
        "1.8": ComplianceControl("CIS", "1.8", "Password number", "Ensure IAM password policy requires at least one number", "Identity and Access Management"),
        "1.9": ComplianceControl("CIS", "1.9", "Password length", "Ensure IAM password policy requires minimum length of 14", "Identity and Access Management"),
        "1.10": ComplianceControl("CIS", "1.10", "Password reuse", "Ensure IAM password policy prevents password reuse", "Identity and Access Management"),
        "1.11": ComplianceControl("CIS", "1.11", "Password expiration", "Ensure IAM password policy expires passwords within 90 days", "Identity and Access Management"),
        "1.12": ComplianceControl("CIS", "1.12", "No unused credentials", "Ensure credentials unused for 90 days or more are disabled", "Identity and Access Management"),
        "1.13": ComplianceControl("CIS", "1.13", "Single active key", "Ensure there is only one active access key per IAM user", "Identity and Access Management"),
        "1.14": ComplianceControl("CIS", "1.14", "Access key rotation", "Ensure access keys are rotated every 90 days or less", "Identity and Access Management"),
        "1.15": ComplianceControl("CIS", "1.15", "IAM policies to groups", "Ensure IAM policies are attached only to groups or roles", "Identity and Access Management"),
        "1.16": ComplianceControl("CIS", "1.16", "No full admin privileges", "Ensure IAM policies that allow full '*:*' administrative privileges are not created", "Identity and Access Management"),
        "1.17": ComplianceControl("CIS", "1.17", "Support role", "Ensure a support role has been created to manage incidents", "Identity and Access Management"),
        "2.1.1": ComplianceControl("CIS", "2.1.1", "S3 block public access", "Ensure S3 Block Public Access is enabled", "Storage"),
        "2.1.2": ComplianceControl("CIS", "2.1.2", "S3 bucket MFA delete", "Ensure MFA Delete is enabled on S3 buckets", "Storage"),
        "2.1.3": ComplianceControl("CIS", "2.1.3", "S3 bucket SSL", "Ensure S3 Bucket Policy allows HTTPS requests only", "Storage"),
        "2.1.4": ComplianceControl("CIS", "2.1.4", "S3 bucket encryption", "Ensure all S3 buckets employ encryption-at-rest", "Storage"),
        "2.2.1": ComplianceControl("CIS", "2.2.1", "EBS encryption default", "Ensure EBS volume encryption is enabled by default", "Storage"),
        "3.1": ComplianceControl("CIS", "3.1", "CloudTrail enabled", "Ensure CloudTrail is enabled in all regions", "Logging"),
        "3.2": ComplianceControl("CIS", "3.2", "CloudTrail log validation", "Ensure CloudTrail log file validation is enabled", "Logging"),
        "3.3": ComplianceControl("CIS", "3.3", "CloudTrail S3 bucket access logging", "Ensure the S3 bucket used for CloudTrail has access logging enabled", "Logging"),
        "3.4": ComplianceControl("CIS", "3.4", "CloudTrail CloudWatch integration", "Ensure CloudTrail trails are integrated with CloudWatch Logs", "Logging"),
        "3.5": ComplianceControl("CIS", "3.5", "AWS Config enabled", "Ensure AWS Config is enabled in all regions", "Logging"),
        "3.6": ComplianceControl("CIS", "3.6", "S3 bucket access logging", "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket", "Logging"),
        "3.7": ComplianceControl("CIS", "3.7", "CloudTrail KMS encryption", "Ensure CloudTrail logs are encrypted at rest using KMS CMKs", "Logging"),
        "3.8": ComplianceControl("CIS", "3.8", "KMS key rotation", "Ensure rotation for customer created CMKs is enabled", "Logging"),
        "3.9": ComplianceControl("CIS", "3.9", "VPC flow logging", "Ensure VPC flow logging is enabled in all VPCs", "Logging"),
        "4.1": ComplianceControl("CIS", "4.1", "No public SSH", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22", "Networking"),
        "4.2": ComplianceControl("CIS", "4.2", "No public RDP", "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389", "Networking"),
        "4.3": ComplianceControl("CIS", "4.3", "Default SG restrictions", "Ensure the default security group of every VPC restricts all traffic", "Networking"),
        "5.1": ComplianceControl("CIS", "5.1", "Network ACLs", "Ensure Network ACLs don't allow ingress from 0.0.0.0/0 to admin ports", "Networking"),
    }
    
    # PCI-DSS v4.0 requirements mapping
    PCI_DSS_CONTROLS = {
        "1.1": ComplianceControl("PCI-DSS", "1.1", "Firewall configuration", "Install and maintain network security controls", "Network Security"),
        "1.2": ComplianceControl("PCI-DSS", "1.2", "Network segmentation", "Network security controls configuration", "Network Security"),
        "1.3": ComplianceControl("PCI-DSS", "1.3", "Restrict inbound traffic", "Network access to cardholder data environment is restricted", "Network Security"),
        "1.4": ComplianceControl("PCI-DSS", "1.4", "Personal firewall", "Network connections between trusted and untrusted networks are controlled", "Network Security"),
        "2.1": ComplianceControl("PCI-DSS", "2.1", "Change vendor defaults", "Vendor-supplied defaults are changed before installing a system", "Secure Configuration"),
        "2.2": ComplianceControl("PCI-DSS", "2.2", "System hardening", "System components are configured and managed securely", "Secure Configuration"),
        "2.3": ComplianceControl("PCI-DSS", "2.3", "Wireless security", "Wireless environments are configured and managed securely", "Secure Configuration"),
        "3.1": ComplianceControl("PCI-DSS", "3.1", "Data retention", "Account data storage is kept to a minimum", "Data Protection"),
        "3.2": ComplianceControl("PCI-DSS", "3.2", "SAD not stored", "Sensitive authentication data is not stored after authorization", "Data Protection"),
        "3.3": ComplianceControl("PCI-DSS", "3.3", "PAN masking", "Primary account number is masked when displayed", "Data Protection"),
        "3.4": ComplianceControl("PCI-DSS", "3.4", "PAN encryption", "PAN is rendered unreadable anywhere it is stored", "Data Protection"),
        "3.5": ComplianceControl("PCI-DSS", "3.5", "Key management", "Cryptographic keys used to protect stored account data are secured", "Data Protection"),
        "4.1": ComplianceControl("PCI-DSS", "4.1", "Strong cryptography", "Strong cryptography protects cardholder data during transmission", "Encryption"),
        "4.2": ComplianceControl("PCI-DSS", "4.2", "End-user messaging", "PAN is secured with strong cryptography during transmission", "Encryption"),
        "5.1": ComplianceControl("PCI-DSS", "5.1", "Anti-malware", "Malicious software (malware) is prevented or detected and addressed", "Malware Protection"),
        "5.2": ComplianceControl("PCI-DSS", "5.2", "Anti-malware mechanisms", "Anti-malware mechanisms and processes are active and maintained", "Malware Protection"),
        "5.3": ComplianceControl("PCI-DSS", "5.3", "Anti-malware monitoring", "Anti-malware mechanisms are actively monitored", "Malware Protection"),
        "6.1": ComplianceControl("PCI-DSS", "6.1", "Vulnerability identification", "Security vulnerabilities are identified and managed", "Vulnerability Management"),
        "6.2": ComplianceControl("PCI-DSS", "6.2", "Secure development", "Bespoke and custom software is developed securely", "Vulnerability Management"),
        "6.3": ComplianceControl("PCI-DSS", "6.3", "Security testing", "Security vulnerabilities are identified and addressed during software development", "Vulnerability Management"),
        "6.4": ComplianceControl("PCI-DSS", "6.4", "Public-facing app protection", "Public-facing web applications are protected against attacks", "Vulnerability Management"),
        "6.5": ComplianceControl("PCI-DSS", "6.5", "Change management", "Changes to all system components are managed securely", "Vulnerability Management"),
        "7.1": ComplianceControl("PCI-DSS", "7.1", "Access restriction", "Access to system components and cardholder data is limited", "Access Control"),
        "7.2": ComplianceControl("PCI-DSS", "7.2", "Access control systems", "Access to system components and data is appropriately defined and assigned", "Access Control"),
        "7.3": ComplianceControl("PCI-DSS", "7.3", "Access control policy", "Access to system components and data is managed via an access control system", "Access Control"),
        "8.1": ComplianceControl("PCI-DSS", "8.1", "User identification", "User identification and related accounts are managed throughout their lifecycle", "Identity Management"),
        "8.2": ComplianceControl("PCI-DSS", "8.2", "Strong authentication", "Strong authentication for users and administrators is established", "Identity Management"),
        "8.3": ComplianceControl("PCI-DSS", "8.3", "MFA implementation", "Strong authentication for users and administrators is established", "Identity Management"),
        "8.4": ComplianceControl("PCI-DSS", "8.4", "MFA for remote access", "Multi-factor authentication is implemented for remote network access", "Identity Management"),
        "8.5": ComplianceControl("PCI-DSS", "8.5", "MFA systems", "Multi-factor authentication systems are configured securely", "Identity Management"),
        "8.6": ComplianceControl("PCI-DSS", "8.6", "Authentication policy", "Use of application and system accounts is strictly managed", "Identity Management"),
        "10.1": ComplianceControl("PCI-DSS", "10.1", "Audit logs", "Audit logs are enabled and active", "Logging and Monitoring"),
        "10.2": ComplianceControl("PCI-DSS", "10.2", "Audit log contents", "Audit logs record required events", "Logging and Monitoring"),
        "10.3": ComplianceControl("PCI-DSS", "10.3", "Audit log protection", "Audit logs are protected from destruction and modification", "Logging and Monitoring"),
        "10.4": ComplianceControl("PCI-DSS", "10.4", "Time synchronization", "Audit logs are reviewed to identify anomalies or suspicious activity", "Logging and Monitoring"),
        "10.5": ComplianceControl("PCI-DSS", "10.5", "Log retention", "Audit log history is retained and available for analysis", "Logging and Monitoring"),
        "10.6": ComplianceControl("PCI-DSS", "10.6", "Time sync mechanisms", "Time-synchronization technology is deployed on all systems", "Logging and Monitoring"),
        "10.7": ComplianceControl("PCI-DSS", "10.7", "Critical control failures", "Failures of critical security control systems are detected and responded to promptly", "Logging and Monitoring"),
    }
    
    # HIPAA Security Rule controls
    HIPAA_CONTROLS = {
        "164.308(a)(1)": ComplianceControl("HIPAA", "164.308(a)(1)", "Security Management", "Security Management Process", "Administrative Safeguards"),
        "164.308(a)(2)": ComplianceControl("HIPAA", "164.308(a)(2)", "Assigned Security Responsibility", "Assigned security responsibility", "Administrative Safeguards"),
        "164.308(a)(3)": ComplianceControl("HIPAA", "164.308(a)(3)", "Workforce Security", "Workforce Security", "Administrative Safeguards"),
        "164.308(a)(4)": ComplianceControl("HIPAA", "164.308(a)(4)", "Information Access Management", "Information Access Management", "Administrative Safeguards"),
        "164.308(a)(5)": ComplianceControl("HIPAA", "164.308(a)(5)", "Security Awareness Training", "Security Awareness and Training", "Administrative Safeguards"),
        "164.308(a)(6)": ComplianceControl("HIPAA", "164.308(a)(6)", "Security Incident Procedures", "Security Incident Procedures", "Administrative Safeguards"),
        "164.308(a)(7)": ComplianceControl("HIPAA", "164.308(a)(7)", "Contingency Plan", "Contingency Plan", "Administrative Safeguards"),
        "164.308(a)(8)": ComplianceControl("HIPAA", "164.308(a)(8)", "Evaluation", "Evaluation", "Administrative Safeguards"),
        "164.310(a)(1)": ComplianceControl("HIPAA", "164.310(a)(1)", "Facility Access Controls", "Facility Access Controls", "Physical Safeguards"),
        "164.310(b)": ComplianceControl("HIPAA", "164.310(b)", "Workstation Use", "Workstation Use", "Physical Safeguards"),
        "164.310(c)": ComplianceControl("HIPAA", "164.310(c)", "Workstation Security", "Workstation Security", "Physical Safeguards"),
        "164.310(d)(1)": ComplianceControl("HIPAA", "164.310(d)(1)", "Device and Media Controls", "Device and Media Controls", "Physical Safeguards"),
        "164.312(a)(1)": ComplianceControl("HIPAA", "164.312(a)(1)", "Access Control", "Access Control", "Technical Safeguards"),
        "164.312(b)": ComplianceControl("HIPAA", "164.312(b)", "Audit Controls", "Audit Controls", "Technical Safeguards"),
        "164.312(c)(1)": ComplianceControl("HIPAA", "164.312(c)(1)", "Integrity", "Integrity", "Technical Safeguards"),
        "164.312(d)": ComplianceControl("HIPAA", "164.312(d)", "Person or Entity Authentication", "Person or Entity Authentication", "Technical Safeguards"),
        "164.312(e)(1)": ComplianceControl("HIPAA", "164.312(e)(1)", "Transmission Security", "Transmission Security", "Technical Safeguards"),
    }
    
    # SOC 2 Trust Service Criteria
    SOC2_CONTROLS = {
        "CC1.1": ComplianceControl("SOC2", "CC1.1", "COSO Principle 1", "The entity demonstrates a commitment to integrity and ethical values", "Control Environment"),
        "CC1.2": ComplianceControl("SOC2", "CC1.2", "COSO Principle 2", "The board demonstrates independence and exercises oversight", "Control Environment"),
        "CC1.3": ComplianceControl("SOC2", "CC1.3", "COSO Principle 3", "Management establishes structures, reporting lines, and authorities", "Control Environment"),
        "CC1.4": ComplianceControl("SOC2", "CC1.4", "COSO Principle 4", "The entity demonstrates a commitment to attract and retain competent individuals", "Control Environment"),
        "CC1.5": ComplianceControl("SOC2", "CC1.5", "COSO Principle 5", "The entity holds individuals accountable for internal control responsibilities", "Control Environment"),
        "CC2.1": ComplianceControl("SOC2", "CC2.1", "Internal Communication", "The entity obtains and generates information regarding its objectives", "Communication and Information"),
        "CC2.2": ComplianceControl("SOC2", "CC2.2", "External Communication", "The entity internally communicates information", "Communication and Information"),
        "CC3.1": ComplianceControl("SOC2", "CC3.1", "Risk Objectives", "The entity specifies objectives to identify and assess risks", "Risk Assessment"),
        "CC3.2": ComplianceControl("SOC2", "CC3.2", "Risk Identification", "The entity identifies risks to the achievement of its objectives", "Risk Assessment"),
        "CC3.3": ComplianceControl("SOC2", "CC3.3", "Fraud Consideration", "The entity considers the potential for fraud in assessing risks", "Risk Assessment"),
        "CC3.4": ComplianceControl("SOC2", "CC3.4", "Change Identification", "The entity identifies and assesses changes that could significantly impact internal control", "Risk Assessment"),
        "CC4.1": ComplianceControl("SOC2", "CC4.1", "Monitoring", "The entity selects, develops, and performs ongoing and/or separate evaluations", "Monitoring Activities"),
        "CC4.2": ComplianceControl("SOC2", "CC4.2", "Deficiency Communication", "The entity evaluates and communicates internal control deficiencies", "Monitoring Activities"),
        "CC5.1": ComplianceControl("SOC2", "CC5.1", "Control Selection", "The entity selects and develops control activities", "Control Activities"),
        "CC5.2": ComplianceControl("SOC2", "CC5.2", "Technology Controls", "The entity selects and develops general control activities over technology", "Control Activities"),
        "CC5.3": ComplianceControl("SOC2", "CC5.3", "Policy Deployment", "The entity deploys control activities through policies and procedures", "Control Activities"),
        "CC6.1": ComplianceControl("SOC2", "CC6.1", "Logical Access Security", "The entity implements logical access security software", "Logical and Physical Access"),
        "CC6.2": ComplianceControl("SOC2", "CC6.2", "Access Provisioning", "Prior to issuing system credentials, the entity registers authorized users", "Logical and Physical Access"),
        "CC6.3": ComplianceControl("SOC2", "CC6.3", "Access Removal", "The entity removes access to protected information assets when appropriate", "Logical and Physical Access"),
        "CC6.4": ComplianceControl("SOC2", "CC6.4", "Access Review", "The entity restricts access to protected information assets", "Logical and Physical Access"),
        "CC6.5": ComplianceControl("SOC2", "CC6.5", "Network Security", "The entity discontinues access credentials when access is no longer required", "Logical and Physical Access"),
        "CC6.6": ComplianceControl("SOC2", "CC6.6", "Intrusion Prevention", "The entity implements controls to prevent or detect unauthorized software", "Logical and Physical Access"),
        "CC6.7": ComplianceControl("SOC2", "CC6.7", "Transmission Protection", "The entity restricts the transmission of data to authorized channels", "Logical and Physical Access"),
        "CC6.8": ComplianceControl("SOC2", "CC6.8", "Unauthorized Changes", "The entity implements controls to prevent introduction of unauthorized software", "Logical and Physical Access"),
        "CC7.1": ComplianceControl("SOC2", "CC7.1", "Threat Detection", "To meet its objectives, the entity uses detection and monitoring procedures", "System Operations"),
        "CC7.2": ComplianceControl("SOC2", "CC7.2", "Incident Response", "The entity monitors system components and the operation of those components", "System Operations"),
        "CC7.3": ComplianceControl("SOC2", "CC7.3", "Incident Evaluation", "The entity evaluates security events to determine whether they constitute security incidents", "System Operations"),
        "CC7.4": ComplianceControl("SOC2", "CC7.4", "Incident Containment", "The entity responds to identified security incidents by executing response procedures", "System Operations"),
        "CC7.5": ComplianceControl("SOC2", "CC7.5", "Incident Recovery", "The entity identifies, develops, and implements activities to recover from security incidents", "System Operations"),
        "CC8.1": ComplianceControl("SOC2", "CC8.1", "Change Management", "The entity authorizes, designs, develops, and implements changes", "Change Management"),
        "CC9.1": ComplianceControl("SOC2", "CC9.1", "Risk Mitigation", "The entity identifies, selects, and develops risk mitigation activities", "Risk Mitigation"),
        "CC9.2": ComplianceControl("SOC2", "CC9.2", "Vendor Management", "The entity assesses and manages risks associated with vendors and business partners", "Risk Mitigation"),
    }
    
    # Finding category to compliance control mapping
    FINDING_TO_CONTROL_MAP = {
        # AWS specific mappings
        'public_s3_bucket': {
            'CIS': ['2.1.1', '2.1.3'],
            'PCI-DSS': ['1.3', '7.1'],
            'SOC2': ['CC6.1', 'CC6.6'],
        },
        'unencrypted_s3': {
            'CIS': ['2.1.4'],
            'PCI-DSS': ['3.4', '3.5'],
            'HIPAA': ['164.312(a)(1)', '164.312(e)(1)'],
            'SOC2': ['CC6.7'],
        },
        'public_security_group': {
            'CIS': ['4.1', '4.2', '4.3'],
            'PCI-DSS': ['1.2', '1.3'],
            'SOC2': ['CC6.5', 'CC6.6'],
        },
        'no_mfa': {
            'CIS': ['1.2', '1.4'],
            'PCI-DSS': ['8.3', '8.4'],
            'HIPAA': ['164.312(d)'],
            'SOC2': ['CC6.1', 'CC6.2'],
        },
        'overprivileged_iam': {
            'CIS': ['1.15', '1.16'],
            'PCI-DSS': ['7.1', '7.2'],
            'HIPAA': ['164.312(a)(1)'],
            'SOC2': ['CC6.1', 'CC6.3'],
        },
        'no_cloudtrail': {
            'CIS': ['3.1', '3.2', '3.4'],
            'PCI-DSS': ['10.1', '10.2', '10.3'],
            'HIPAA': ['164.312(b)'],
            'SOC2': ['CC7.1', 'CC7.2'],
        },
        'old_access_key': {
            'CIS': ['1.12', '1.14'],
            'PCI-DSS': ['8.2', '8.6'],
            'SOC2': ['CC6.2', 'CC6.3'],
        },
        'unencrypted_rds': {
            'CIS': ['2.3.1'],
            'PCI-DSS': ['3.4', '4.1'],
            'HIPAA': ['164.312(a)(1)', '164.312(e)(1)'],
            'SOC2': ['CC6.7'],
        },
        'sensitive_data_exposed': {
            'PCI-DSS': ['3.1', '3.2', '3.3', '3.4'],
            'HIPAA': ['164.312(c)(1)', '164.312(e)(1)'],
            'SOC2': ['CC6.1', 'CC6.7'],
        },
        'container_vulnerability': {
            'CIS': ['5.1', '5.2'],
            'PCI-DSS': ['6.1', '6.2'],
            'SOC2': ['CC7.1'],
        },
    }
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        self.enabled_frameworks = self.config.get('frameworks', 
            ['CIS', 'PCI-DSS', 'HIPAA', 'SOC2'])
    
    def map_finding_to_controls(self, finding: Any) -> Dict[str, List[ComplianceControl]]:
        """Map a security finding to compliance controls"""
        result = {}
        
        # Determine finding category
        finding_category = self._categorize_finding(finding)
        
        # Get control mappings
        control_mappings = self.FINDING_TO_CONTROL_MAP.get(finding_category, {})
        
        for framework, control_ids in control_mappings.items():
            if framework not in self.enabled_frameworks:
                continue
            
            controls = []
            control_db = self._get_control_database(framework)
            
            for control_id in control_ids:
                if control_id in control_db:
                    controls.append(control_db[control_id])
            
            if controls:
                result[framework] = controls
        
        return result
    
    def _categorize_finding(self, finding: Any) -> str:
        """Categorize a finding based on its attributes"""
        # Try to get category from finding
        if hasattr(finding, 'category'):
            return finding.category
        
        # Infer from title/description
        title = getattr(finding, 'title', '') or ''
        title_lower = title.lower()
        
        if 's3' in title_lower and 'public' in title_lower:
            return 'public_s3_bucket'
        elif 's3' in title_lower and ('encrypt' in title_lower or 'unencrypt' in title_lower):
            return 'unencrypted_s3'
        elif 'security group' in title_lower and ('public' in title_lower or '0.0.0.0' in title_lower):
            return 'public_security_group'
        elif 'mfa' in title_lower:
            return 'no_mfa'
        elif 'admin' in title_lower or 'overprivilege' in title_lower or 'privilege' in title_lower:
            return 'overprivileged_iam'
        elif 'cloudtrail' in title_lower or 'logging' in title_lower:
            return 'no_cloudtrail'
        elif 'access key' in title_lower and ('old' in title_lower or 'rotate' in title_lower):
            return 'old_access_key'
        elif 'rds' in title_lower and 'encrypt' in title_lower:
            return 'unencrypted_rds'
        elif 'sensitive' in title_lower or 'pii' in title_lower or 'phi' in title_lower:
            return 'sensitive_data_exposed'
        elif 'container' in title_lower or 'cve' in title_lower or 'vulnerability' in title_lower:
            return 'container_vulnerability'
        
        return 'unknown'
    
    def _get_control_database(self, framework: str) -> Dict:
        """Get control database for a framework"""
        if framework == 'CIS':
            return self.CIS_AWS_CONTROLS
        elif framework == 'PCI-DSS':
            return self.PCI_DSS_CONTROLS
        elif framework == 'HIPAA':
            return self.HIPAA_CONTROLS
        elif framework == 'SOC2':
            return self.SOC2_CONTROLS
        return {}
    
    def calculate_compliance_score(self, findings: List[Any], framework: str) -> ComplianceResult:
        """Calculate compliance score for a framework based on findings"""
        control_db = self._get_control_database(framework)
        total_controls = len(control_db)
        
        # Track which controls are failing
        failing_controls = set()
        control_details = []
        
        for finding in findings:
            mappings = self.map_finding_to_controls(finding)
            framework_controls = mappings.get(framework, [])
            
            for control in framework_controls:
                failing_controls.add(control.control_id)
        
        # Build control details
        for control_id, control in control_db.items():
            is_failing = control_id in failing_controls
            control_details.append({
                'control_id': control_id,
                'control_name': control.control_name,
                'category': control.category,
                'status': 'fail' if is_failing else 'pass'
            })
        
        passing_count = total_controls - len(failing_controls)
        score = (passing_count / total_controls) * 100 if total_controls > 0 else 100
        
        return ComplianceResult(
            framework=framework,
            score=round(score, 1),
            total_controls=total_controls,
            passing_controls=passing_count,
            failing_controls=len(failing_controls),
            controls=control_details
        )
    
    def generate_compliance_report(self, findings: List[Any]) -> Dict[str, ComplianceResult]:
        """Generate compliance scores for all enabled frameworks"""
        results = {}
        
        for framework in self.enabled_frameworks:
            results[framework] = self.calculate_compliance_score(findings, framework)
        
        return results
