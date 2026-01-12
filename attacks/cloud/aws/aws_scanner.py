"""
Jarwis AGI - AWS Security Scanner
Comprehensive AWS security assessment

Checks:
- S3 Bucket Security (public access, encryption, logging)
- IAM Security (policies, MFA, access keys)
- EC2 Security (security groups, encryption, metadata)
- RDS Security (encryption, public access, backups)
- Lambda Security (permissions, environment variables)
- CloudTrail & Config (logging, monitoring)
"""

import json
import asyncio
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Callable, Any

from attacks.cloud.shared.base import CloudScanner
from attacks.cloud.shared.schemas import (
    CloudFinding,
    CloudScanContext,
    Provider,
    ScannerMetadata,
    Severity,
)
from attacks.cloud.shared.exceptions import (
    APIThrottlingError,
    ProviderAuthError,
    RateLimitError,
    ServicePermissionError,
)

logger = logging.getLogger(__name__)


@dataclass
class AWSFinding:
    """AWS-specific security finding"""
    id: str
    service: str
    resource_id: str
    resource_arn: str
    region: str
    severity: str
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)
    recommendation: str = ""
    cis_benchmark: str = ""
    remediation_cli: str = ""


class AWSSecurityScanner:
    """
    AWS Security Scanner
    Performs comprehensive security assessment of AWS resources
    """
    
    # CIS AWS Foundations Benchmark checks
    CIS_CHECKS = {
        "1.1": "Avoid use of root account",
        "1.2": "MFA enabled for root account",
        "1.3": "No access keys for root account",
        "1.4": "MFA enabled for IAM users",
        "1.5": "Password policy requirements",
        "2.1": "CloudTrail enabled in all regions",
        "2.2": "CloudTrail log file validation",
        "2.3": "CloudTrail logs encrypted",
        "2.4": "CloudTrail integrated with CloudWatch",
        "3.1": "VPC flow logging enabled",
        "4.1": "No security groups with 0.0.0.0/0 SSH",
        "4.2": "No security groups with 0.0.0.0/0 RDP",
    }
    
    # Available services for scanning
    AVAILABLE_SERVICES = {
        's3': {'name': 'S3 Buckets', 'description': 'Encryption, public access, logging', 'global': True},
        'iam': {'name': 'IAM', 'description': 'Users, roles, MFA, policies', 'global': True},
        'ec2': {'name': 'EC2', 'description': 'Security groups, instances, metadata', 'global': False},
        'rds': {'name': 'RDS', 'description': 'Database encryption, public access', 'global': False},
        'lambda': {'name': 'Lambda', 'description': 'Runtimes, environment variables', 'global': False},
        'cloudtrail': {'name': 'CloudTrail', 'description': 'Logging configuration', 'global': True},
    }
    
    def __init__(
        self,
        access_key: str = None,
        secret_key: str = None,
        session_token: str = None,
        profile: str = None,
        # Enterprise cross-account role parameters
        role_arn: str = None,
        external_id: str = None,
    ):
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.profile = profile
        # Cross-account role support
        self.role_arn = role_arn
        self.external_id = external_id
        self.session = None
        self.findings: List[AWSFinding] = []
        self._verbose_callback: Optional[Callable] = None
        self._boto3_available = False
        self._auth_mode = None  # 'direct', 'assume_role', or 'profile'
        self._init_session()
    
    def _init_session(self):
        """Initialize boto3 session with support for cross-account role assumption"""
        try:
            import boto3
            import os
            self._boto3_available = True
            
            # Priority 1: Cross-account role assumption (Enterprise mode)
            if self.role_arn:
                self._auth_mode = 'assume_role'
                logger.info(f"Using cross-account role assumption: {self.role_arn}")
                
                # Get Jarwis's own credentials for assuming the role
                # These come from environment variables or instance profile
                jarwis_access_key = os.getenv('JARWIS_AWS_ACCESS_KEY')
                jarwis_secret_key = os.getenv('JARWIS_AWS_SECRET_KEY')
                
                if jarwis_access_key and jarwis_secret_key:
                    # Use Jarwis's credentials to assume customer role
                    jarwis_session = boto3.Session(
                        aws_access_key_id=jarwis_access_key,
                        aws_secret_access_key=jarwis_secret_key
                    )
                else:
                    # Use default credentials (instance profile, etc.)
                    jarwis_session = boto3.Session()
                
                sts = jarwis_session.client('sts')
                
                # Build assume role parameters
                assume_params = {
                    'RoleArn': self.role_arn,
                    'RoleSessionName': 'JarwisCloudSecurityScan',
                    'DurationSeconds': 3600  # 1 hour
                }
                
                # Add external ID if provided (prevents confused deputy attack)
                if self.external_id:
                    assume_params['ExternalId'] = self.external_id
                
                # Assume the customer's role
                assumed = sts.assume_role(**assume_params)
                
                # Create session with temporary credentials
                self.session = boto3.Session(
                    aws_access_key_id=assumed['Credentials']['AccessKeyId'],
                    aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
                    aws_session_token=assumed['Credentials']['SessionToken']
                )
                logger.info("Successfully assumed cross-account role")
                
            # Priority 2: Direct credentials (legacy mode)
            elif self.access_key and self.secret_key:
                self._auth_mode = 'direct'
                self.session = boto3.Session(
                    aws_access_key_id=self.access_key,
                    aws_secret_access_key=self.secret_key,
                    aws_session_token=self.session_token
                )
                logger.info("Using direct AWS credentials")
                
            # Priority 3: AWS profile
            elif self.profile:
                self._auth_mode = 'profile'
                self.session = boto3.Session(profile_name=self.profile)
                logger.info(f"Using AWS profile: {self.profile}")
                
            # Priority 4: Default credentials chain
            else:
                self._auth_mode = 'default'
                self.session = boto3.Session()
                logger.info("Using default AWS credentials chain")
                
            logger.info(f"AWS session initialized (mode: {self._auth_mode})")
        except ImportError:
            logger.warning("boto3 not installed. AWS scanning unavailable.")
            self._boto3_available = False
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {e}")
            raise
    
    @classmethod
    def get_available_services(cls) -> Dict[str, Dict]:
        """Return available services for UI service selection"""
        return cls.AVAILABLE_SERVICES

    async def discover_resources(self, region: str = "us-east-1") -> List[Dict[str, Any]]:
        """Lightweight resource discovery to avoid phase-1 failures."""
        resources: List[Dict[str, Any]] = []
        if not self._boto3_available or not self.session:
            return resources

        try:
            s3 = self.session.client("s3")

            def _list_buckets():
                return s3.list_buckets().get("Buckets", [])

            buckets = await asyncio.to_thread(_list_buckets)
            for bucket in buckets:
                resources.append({
                    "id": bucket.get("Name"),
                    "name": bucket.get("Name"),
                    "type": "s3_bucket",
                    "arn": f"arn:aws:s3:::{bucket.get('Name')}",
                    "tags": {},
                    "metadata": {},
                })
        except Exception as e:
            logger.error(f"AWS discovery (S3) failed: {e}")

        try:
            ec2 = self.session.client("ec2", region_name=region)

            def _list_instances():
                reservations = ec2.describe_instances().get("Reservations", [])
                instances = []
                for res in reservations:
                    instances.extend(res.get("Instances", []))
                return instances

            instances = await asyncio.to_thread(_list_instances)
            for inst in instances:
                inst_id = inst.get("InstanceId")
                resources.append({
                    "id": inst_id,
                    "name": inst_id,
                    "type": "ec2_instance",
                    "arn": f"arn:aws:ec2:{region}::instance/{inst_id}",
                    "tags": {t.get("Key"): t.get("Value") for t in inst.get("Tags", [])} if inst.get("Tags") else {},
                    "metadata": {
                        "state": inst.get("State", {}).get("Name"),
                        "type": inst.get("InstanceType"),
                    },
                })
        except Exception as e:
            logger.error(f"AWS discovery (EC2) failed: {e}")

        return resources
    
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
    
    def _add_finding(self, **kwargs):
        """Add a finding to the list"""
        finding = AWSFinding(**kwargs)
        self.findings.append(finding)
        return finding
    
    async def scan(
        self,
        regions: List[str] = None,
        services: List[str] = None
    ):
        """
        Perform AWS security scan
        
        Args:
            regions: List of regions to scan (default: all available)
            services: List of services to scan (default: all supported)
        """
        from attacks.cloud.shared.cloud_scanner import CloudScanResult
        
        if not self._boto3_available:
            self._log("error", "boto3 not installed. Run: pip install boto3")
            return CloudScanResult(
                scan_id="AWS-FAILED",
                provider="aws",
                status="failed"
            )
        
        scan_id = f"AWS-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.findings = []
        
        self._log("start", "Starting AWS security scan")
        
        # Get account ID
        try:
            sts = self.session.client('sts')
            account_id = sts.get_caller_identity()['Account']
        except Exception as e:
            self._log("error", f"Failed to get AWS account info: {e}")
            account_id = "unknown"
        
        # Get regions
        if not regions:
            try:
                ec2 = self.session.client('ec2', region_name='us-east-1')
                regions = [r['RegionName'] for r in ec2.describe_regions()['Regions']]
            except:
                regions = ['us-east-1', 'us-west-2', 'eu-west-1']
        
        # Default services
        if not services:
            services = ['s3', 'iam', 'ec2', 'rds', 'lambda', 'cloudtrail']
        
        resources_scanned = 0
        
        # Global services (IAM, S3)
        if 'iam' in services:
            self._log("phase", "Scanning IAM", "Checking users, roles, policies...")
            resources_scanned += await self._scan_iam()
        
        if 's3' in services:
            self._log("phase", "Scanning S3", "Checking bucket security...")
            resources_scanned += await self._scan_s3()
        
        if 'cloudtrail' in services:
            self._log("phase", "Scanning CloudTrail", "Checking logging configuration...")
            resources_scanned += await self._scan_cloudtrail()
        
        # Regional services
        for region in regions:
            self._log("region", f"Scanning region: {region}")
            
            if 'ec2' in services:
                resources_scanned += await self._scan_ec2(region)
            
            if 'rds' in services:
                resources_scanned += await self._scan_rds(region)
            
            if 'lambda' in services:
                resources_scanned += await self._scan_lambda(region)
        
        # Build result
        result = CloudScanResult(
            scan_id=scan_id,
            provider="aws",
            account_id=account_id,
            scan_start=datetime.now().isoformat(),
            scan_end=datetime.now().isoformat(),
            status="completed",
            resources_scanned=resources_scanned,
            regions_scanned=regions,
            services_scanned=services,
            findings=[asdict(f) for f in self.findings],
            total_findings=len(self.findings)
        )
        
        # Count by severity
        for finding in self.findings:
            if finding.severity == "critical":
                result.critical_count += 1
            elif finding.severity == "high":
                result.high_count += 1
            elif finding.severity == "medium":
                result.medium_count += 1
            elif finding.severity == "low":
                result.low_count += 1
        
        self._log("complete", f"AWS scan complete: {len(self.findings)} findings")
        
        return result
    
    async def _scan_iam(self) -> int:
        """Scan IAM for security issues"""
        resources = 0
        
        try:
            iam = self.session.client('iam')
            
            # Check root account MFA
            try:
                summary = iam.get_account_summary()['SummaryMap']
                if summary.get('AccountMFAEnabled', 0) == 0:
                    self._add_finding(
                        id="AWS-IAM-001",
                        service="iam",
                        resource_id="root",
                        resource_arn="arn:aws:iam::*:root",
                        region="global",
                        severity="critical",
                        title="Root Account MFA Not Enabled",
                        description="The root account does not have MFA enabled.",
                        recommendation="Enable MFA for the root account immediately.",
                        cis_benchmark="1.2"
                    )
            except:
                pass
            
            # Check IAM users
            users = iam.list_users()['Users']
            resources += len(users)
            
            for user in users:
                username = user['UserName']
                user_arn = user['Arn']
                
                # Check for access keys older than 90 days
                try:
                    access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                    for key in access_keys:
                        if key['Status'] == 'Active':
                            age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                            if age > 90:
                                self._add_finding(
                                    id=f"AWS-IAM-KEY-{username}",
                                    service="iam",
                                    resource_id=username,
                                    resource_arn=user_arn,
                                    region="global",
                                    severity="medium",
                                    title=f"Access Key Older Than 90 Days",
                                    description=f"User {username} has an access key that is {age} days old.",
                                    evidence={"key_id": key['AccessKeyId'], "age_days": age},
                                    recommendation="Rotate access keys regularly.",
                                    cis_benchmark="1.4"
                                )
                except:
                    pass
                
                # Check for MFA
                try:
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        # Check if user has console access
                        try:
                            iam.get_login_profile(UserName=username)
                            self._add_finding(
                                id=f"AWS-IAM-MFA-{username}",
                                service="iam",
                                resource_id=username,
                                resource_arn=user_arn,
                                region="global",
                                severity="high",
                                title="IAM User Without MFA",
                                description=f"User {username} has console access but no MFA device.",
                                recommendation="Enable MFA for all IAM users with console access.",
                                cis_benchmark="1.4"
                            )
                        except:
                            pass
                except:
                    pass
            
            # Check for overly permissive policies
            policies = iam.list_policies(Scope='Local')['Policies']
            for policy in policies:
                try:
                    version = iam.get_policy_version(
                        PolicyArn=policy['Arn'],
                        VersionId=policy['DefaultVersionId']
                    )['PolicyVersion']
                    
                    doc = version['Document']
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    
                    for statement in doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow':
                            action = statement.get('Action', [])
                            resource = statement.get('Resource', [])
                            
                            if action == '*' or action == ['*']:
                                if resource == '*' or resource == ['*']:
                                    self._add_finding(
                                        id=f"AWS-IAM-POLICY-{policy['PolicyName']}",
                                        service="iam",
                                        resource_id=policy['PolicyName'],
                                        resource_arn=policy['Arn'],
                                        region="global",
                                        severity="critical",
                                        title="Overly Permissive IAM Policy",
                                        description=f"Policy {policy['PolicyName']} allows all actions on all resources.",
                                        evidence={"statement": statement},
                                        recommendation="Follow least privilege principle."
                                    )
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error scanning IAM: {e}")
        
        return resources
    
    async def _scan_s3(self) -> int:
        """Scan S3 buckets for security issues"""
        resources = 0
        
        try:
            s3 = self.session.client('s3')
            buckets = s3.list_buckets()['Buckets']
            resources = len(buckets)
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                bucket_arn = f"arn:aws:s3:::{bucket_name}"
                
                # Check public access block
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)['PublicAccessBlockConfiguration']
                    if not all([
                        pab.get('BlockPublicAcls', False),
                        pab.get('IgnorePublicAcls', False),
                        pab.get('BlockPublicPolicy', False),
                        pab.get('RestrictPublicBuckets', False)
                    ]):
                        self._add_finding(
                            id=f"AWS-S3-PAB-{bucket_name}",
                            service="s3",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region="global",
                            severity="high",
                            title="S3 Public Access Block Not Fully Enabled",
                            description=f"Bucket {bucket_name} does not have all public access blocks enabled.",
                            evidence={"public_access_block": pab},
                            recommendation="Enable all public access block settings.",
                            remediation_cli=f"aws s3api put-public-access-block --bucket {bucket_name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                        )
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    self._add_finding(
                        id=f"AWS-S3-PAB-{bucket_name}",
                        service="s3",
                        resource_id=bucket_name,
                        resource_arn=bucket_arn,
                        region="global",
                        severity="high",
                        title="S3 Public Access Block Not Configured",
                        description=f"Bucket {bucket_name} has no public access block configuration.",
                        recommendation="Configure public access block."
                    )
                except:
                    pass
                
                # Check encryption
                try:
                    enc = s3.get_bucket_encryption(Bucket=bucket_name)
                except:
                    self._add_finding(
                        id=f"AWS-S3-ENC-{bucket_name}",
                        service="s3",
                        resource_id=bucket_name,
                        resource_arn=bucket_arn,
                        region="global",
                        severity="medium",
                        title="S3 Bucket Not Encrypted",
                        description=f"Bucket {bucket_name} does not have default encryption enabled.",
                        recommendation="Enable default encryption with SSE-S3 or SSE-KMS."
                    )
                
                # Check versioning
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        self._add_finding(
                            id=f"AWS-S3-VER-{bucket_name}",
                            service="s3",
                            resource_id=bucket_name,
                            resource_arn=bucket_arn,
                            region="global",
                            severity="low",
                            title="S3 Bucket Versioning Not Enabled",
                            description=f"Bucket {bucket_name} does not have versioning enabled.",
                            recommendation="Enable versioning for data protection."
                        )
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Error scanning S3: {e}")
        
        return resources
    
    async def _scan_ec2(self, region: str) -> int:
        """Scan EC2 for security issues"""
        resources = 0
        
        try:
            ec2 = self.session.client('ec2', region_name=region)
            
            # Check security groups
            sgs = ec2.describe_security_groups()['SecurityGroups']
            resources += len(sgs)
            
            for sg in sgs:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']
                
                for rule in sg.get('IpPermissions', []):
                    for ip_range in rule.get('IpRanges', []):
                        cidr = ip_range.get('CidrIp', '')
                        
                        if cidr == '0.0.0.0/0':
                            from_port = rule.get('FromPort', 0)
                            to_port = rule.get('ToPort', 65535)
                            
                            # Check for SSH (22) open to world
                            if from_port <= 22 <= to_port:
                                self._add_finding(
                                    id=f"AWS-EC2-SG-SSH-{sg_id}",
                                    service="ec2",
                                    resource_id=sg_id,
                                    resource_arn=f"arn:aws:ec2:{region}:*:security-group/{sg_id}",
                                    region=region,
                                    severity="critical",
                                    title="Security Group Allows SSH from Internet",
                                    description=f"Security group {sg_name} ({sg_id}) allows SSH (port 22) from 0.0.0.0/0.",
                                    evidence={"rule": rule},
                                    recommendation="Restrict SSH access to specific IPs.",
                                    cis_benchmark="4.1"
                                )
                            
                            # Check for RDP (3389) open to world
                            if from_port <= 3389 <= to_port:
                                self._add_finding(
                                    id=f"AWS-EC2-SG-RDP-{sg_id}",
                                    service="ec2",
                                    resource_id=sg_id,
                                    resource_arn=f"arn:aws:ec2:{region}:*:security-group/{sg_id}",
                                    region=region,
                                    severity="critical",
                                    title="Security Group Allows RDP from Internet",
                                    description=f"Security group {sg_name} ({sg_id}) allows RDP (port 3389) from 0.0.0.0/0.",
                                    recommendation="Restrict RDP access to specific IPs.",
                                    cis_benchmark="4.2"
                                )
            
            # Check instances
            instances = ec2.describe_instances()['Reservations']
            for reservation in instances:
                for instance in reservation['Instances']:
                    resources += 1
                    instance_id = instance['InstanceId']
                    
                    # Check for public IP
                    if instance.get('PublicIpAddress'):
                        # Check IMDSv2
                        metadata_options = instance.get('MetadataOptions', {})
                        if metadata_options.get('HttpTokens') != 'required':
                            self._add_finding(
                                id=f"AWS-EC2-IMDS-{instance_id}",
                                service="ec2",
                                resource_id=instance_id,
                                resource_arn=f"arn:aws:ec2:{region}:*:instance/{instance_id}",
                                region=region,
                                severity="medium",
                                title="EC2 Instance Not Using IMDSv2",
                                description=f"Instance {instance_id} is not enforcing IMDSv2.",
                                recommendation="Enable IMDSv2 to prevent SSRF attacks."
                            )
                            
        except Exception as e:
            logger.error(f"Error scanning EC2 in {region}: {e}")
        
        return resources
    
    async def _scan_rds(self, region: str) -> int:
        """Scan RDS for security issues"""
        resources = 0
        
        try:
            rds = self.session.client('rds', region_name=region)
            
            instances = rds.describe_db_instances()['DBInstances']
            resources = len(instances)
            
            for db in instances:
                db_id = db['DBInstanceIdentifier']
                db_arn = db['DBInstanceArn']
                
                # Check public accessibility
                if db.get('PubliclyAccessible', False):
                    self._add_finding(
                        id=f"AWS-RDS-PUBLIC-{db_id}",
                        service="rds",
                        resource_id=db_id,
                        resource_arn=db_arn,
                        region=region,
                        severity="high",
                        title="RDS Instance Publicly Accessible",
                        description=f"RDS instance {db_id} is publicly accessible.",
                        recommendation="Disable public accessibility unless required."
                    )
                
                # Check encryption
                if not db.get('StorageEncrypted', False):
                    self._add_finding(
                        id=f"AWS-RDS-ENC-{db_id}",
                        service="rds",
                        resource_id=db_id,
                        resource_arn=db_arn,
                        region=region,
                        severity="high",
                        title="RDS Instance Not Encrypted",
                        description=f"RDS instance {db_id} storage is not encrypted.",
                        recommendation="Enable encryption at rest."
                    )
                
                # Check automated backups
                if db.get('BackupRetentionPeriod', 0) == 0:
                    self._add_finding(
                        id=f"AWS-RDS-BACKUP-{db_id}",
                        service="rds",
                        resource_id=db_id,
                        resource_arn=db_arn,
                        region=region,
                        severity="medium",
                        title="RDS Automated Backups Disabled",
                        description=f"RDS instance {db_id} has no automated backups.",
                        recommendation="Enable automated backups with appropriate retention."
                    )
                    
        except Exception as e:
            logger.error(f"Error scanning RDS in {region}: {e}")
        
        return resources
    
    async def _scan_lambda(self, region: str) -> int:
        """Scan Lambda for security issues"""
        resources = 0
        
        try:
            lambda_client = self.session.client('lambda', region_name=region)
            
            functions = lambda_client.list_functions()['Functions']
            resources = len(functions)
            
            for func in functions:
                func_name = func['FunctionName']
                func_arn = func['FunctionArn']
                
                # Check for deprecated runtimes
                runtime = func.get('Runtime', '')
                deprecated = ['python2.7', 'python3.6', 'nodejs10.x', 'nodejs8.10', 'dotnetcore2.1']
                if runtime in deprecated:
                    self._add_finding(
                        id=f"AWS-LAMBDA-RUNTIME-{func_name}",
                        service="lambda",
                        resource_id=func_name,
                        resource_arn=func_arn,
                        region=region,
                        severity="medium",
                        title="Lambda Using Deprecated Runtime",
                        description=f"Function {func_name} uses deprecated runtime {runtime}.",
                        recommendation="Upgrade to a supported runtime version."
                    )
                
                # Check environment variables for secrets
                env_vars = func.get('Environment', {}).get('Variables', {})
                secret_patterns = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL']
                for key, value in env_vars.items():
                    if any(p in key.upper() for p in secret_patterns):
                        self._add_finding(
                            id=f"AWS-LAMBDA-SECRET-{func_name}-{key}",
                            service="lambda",
                            resource_id=func_name,
                            resource_arn=func_arn,
                            region=region,
                            severity="high",
                            title="Potential Secret in Lambda Environment",
                            description=f"Function {func_name} has potential secret in environment variable: {key}",
                            recommendation="Use AWS Secrets Manager or Parameter Store."
                        )
                        
        except Exception as e:
            logger.error(f"Error scanning Lambda in {region}: {e}")
        
        return resources


class AWSScanner(CloudScanner):
    """CloudScanner-based AWS scanner adapter using existing methods."""

    metadata = ScannerMetadata(
        name="aws_core",
        provider=Provider.aws,
        services=["iam", "s3", "ec2", "rds", "lambda", "cloudtrail"],
        enabled_by_default=True,
        description="Core AWS security checks (IAM, S3, EC2, RDS, Lambda, CloudTrail)",
    )

    def __init__(self, config: Dict[str, Any]) -> None:
        super().__init__(config)
        self._scanner = AWSSecurityScanner(
            access_key=self.config.get("access_key"),
            secret_key=self.config.get("secret_key"),
            session_token=self.config.get("session_token"),
            profile=self.config.get("profile"),
        )

    async def scan(self, context: CloudScanContext) -> List[CloudFinding]:
        # Discover regions
        try:
            ec2 = self._scanner.session.client("ec2", region_name="us-east-1")
            regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
        except Exception:
            regions = ["us-east-1", "us-west-2", "eu-west-1"]

        services = self.config.get(
            "services", ["s3", "iam", "ec2", "rds", "lambda", "cloudtrail"]
        )

        # Global services
        if "iam" in services:
            await self._safe_call(self._scanner._scan_iam, service="iam")
        if "s3" in services:
            await self._safe_call(self._scanner._scan_s3, service="s3")
        if "cloudtrail" in services:
            await self._safe_call(self._scanner._scan_cloudtrail, service="cloudtrail")

        # Regional services
        for region in regions:
            if "ec2" in services:
                await self._safe_call(self._scanner._scan_ec2, region, service="ec2")
            if "rds" in services:
                await self._safe_call(self._scanner._scan_rds, region, service="rds")
            if "lambda" in services:
                await self._safe_call(self._scanner._scan_lambda, region, service="lambda")
            await self._sleep_rate()

        # Convert AWSFinding -> CloudFinding
        cloud_findings: List[CloudFinding] = []
        for f in self._scanner.findings:
            sev = None
            try:
                sev = Severity(f.severity)
            except Exception:
                sev = Severity.info
            cloud_findings.append(
                CloudFinding(
                    id=f.id,
                    provider=Provider.aws,
                    service=f.service,
                    category=f.cis_benchmark or "general",
                    severity=sev,
                    title=f.title,
                    description=f.description,
                    resource_id=f.resource_id,
                    region=f.region,
                    evidence=json.dumps(f.evidence) if isinstance(f.evidence, dict) else str(f.evidence),
                    remediation=f.recommendation,
                    references=[],
                    cwe=None,
                    cve=[],
                    compliance={"cis": f.cis_benchmark} if f.cis_benchmark else {},
                    context={"resource_arn": getattr(f, "resource_arn", "")},
                )
            )

        return cloud_findings

    async def _safe_call(self, func, *args, service: str = "", **kwargs):
        try:
            return await self.run_limited(self.with_retry(func, *args, **kwargs))
        except Exception as e:
            mapped = self._map_error(e, service)
            raise mapped from e

    def _map_error(self, err: Exception, service: str):
        msg = str(err)
        if "Throttling" in msg or "Rate exceeded" in msg:
            return APIThrottlingError(msg, provider="aws", service=service)
        if "AccessDenied" in msg or "Unauthorized" in msg:
            return ServicePermissionError(msg, provider="aws", service=service)
        if "RequestLimitExceeded" in msg:
            return RateLimitError(msg, provider="aws", service=service)
        if "InvalidClientTokenId" in msg or "AuthFailure" in msg:
            return ProviderAuthError(msg, provider="aws", service=service)
        return err
    
    async def _scan_cloudtrail(self) -> int:
        """Scan CloudTrail configuration"""
        resources = 0
        
        try:
            ct = self.session.client('cloudtrail', region_name='us-east-1')
            
            trails = ct.describe_trails()['trailList']
            resources = len(trails)
            
            if not trails:
                self._add_finding(
                    id="AWS-CT-NONE",
                    service="cloudtrail",
                    resource_id="cloudtrail",
                    resource_arn="arn:aws:cloudtrail:*:*:trail/*",
                    region="global",
                    severity="critical",
                    title="No CloudTrail Trails Configured",
                    description="No CloudTrail trails are configured for this account.",
                    recommendation="Enable CloudTrail for all regions.",
                    cis_benchmark="2.1"
                )
            else:
                for trail in trails:
                    trail_name = trail['Name']
                    trail_arn = trail['TrailARN']
                    
                    # Check if multi-region
                    if not trail.get('IsMultiRegionTrail', False):
                        self._add_finding(
                            id=f"AWS-CT-REGION-{trail_name}",
                            service="cloudtrail",
                            resource_id=trail_name,
                            resource_arn=trail_arn,
                            region="global",
                            severity="medium",
                            title="CloudTrail Not Multi-Region",
                            description=f"Trail {trail_name} is not configured for all regions.",
                            recommendation="Enable multi-region trail.",
                            cis_benchmark="2.1"
                        )
                    
                    # Check log file validation
                    if not trail.get('LogFileValidationEnabled', False):
                        self._add_finding(
                            id=f"AWS-CT-VALID-{trail_name}",
                            service="cloudtrail",
                            resource_id=trail_name,
                            resource_arn=trail_arn,
                            region="global",
                            severity="medium",
                            title="CloudTrail Log Validation Disabled",
                            description=f"Trail {trail_name} does not have log file validation enabled.",
                            recommendation="Enable log file validation.",
                            cis_benchmark="2.2"
                        )
                        
        except Exception as e:
            logger.error(f"Error scanning CloudTrail: {e}")
        
        return resources
