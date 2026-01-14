"""
Jarwis AGI - Cloud Security Service Layer
Orchestrates cloud security scanning across AWS/Azure/GCP
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from database.models import ScanHistory as Scan, User
from database.connection import get_db
from database.subscription import check_subscription_limit
from core.cloud_scan_runner import CloudScanRunner, CloudScanContext
from shared.constants import PLAN_LIMITS

logger = logging.getLogger(__name__)

class CloudSecurityService:
    """Service layer for cloud security operations"""
    
    @staticmethod
    async def validate_credentials(provider: str, credentials: Dict[str, str]) -> Dict[str, Any]:
        """
        Validate cloud provider credentials
        
        Args:
            provider: 'aws', 'azure', or 'gcp'
            credentials: Provider-specific credential dict
        
        Returns:
            {
                'valid': bool,
                'message': str,
                'account_id': str (if valid),
                'regions': List[str] (if valid)
            }
        """
        try:
            if provider == 'aws':
                return await CloudSecurityService._validate_aws_credentials(credentials)
            elif provider == 'azure':
                return await CloudSecurityService._validate_azure_credentials(credentials)
            elif provider == 'gcp':
                return await CloudSecurityService._validate_gcp_credentials(credentials)
            else:
                return {
                    'valid': False,
                    'message': f"Unsupported provider: {provider}"
                }
        except Exception as e:
            logger.error(f"Credential validation failed for {provider}: {e}")
            return {
                'valid': False,
                'message': f"Validation error: {str(e)}"
            }
    
    @staticmethod
    async def _validate_aws_credentials(creds: Dict) -> Dict[str, Any]:
        """Validate AWS credentials - supports both access keys and cross-account role"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            auth_mode = creds.get('auth_mode', 'access_keys')
            
            if auth_mode == 'role':
                # Cross-account role assumption
                role_arn = creds.get('role_arn')
                external_id = creds.get('external_id')
                
                if not role_arn:
                    return {
                        'valid': False,
                        'message': "Role ARN is required for cross-account role authentication"
                    }
                
                # Use default credentials (or environment) to assume the role
                sts = boto3.client('sts')
                
                assume_params = {
                    'RoleArn': role_arn,
                    'RoleSessionName': 'JarwisSecurityScan',
                    'DurationSeconds': 3600
                }
                if external_id:
                    assume_params['ExternalId'] = external_id
                
                try:
                    assumed = await asyncio.to_thread(sts.assume_role, **assume_params)
                    temp_creds = assumed['Credentials']
                    
                    # Verify the assumed role
                    sts_assumed = boto3.client(
                        'sts',
                        aws_access_key_id=temp_creds['AccessKeyId'],
                        aws_secret_access_key=temp_creds['SecretAccessKey'],
                        aws_session_token=temp_creds['SessionToken']
                    )
                    identity = await asyncio.to_thread(sts_assumed.get_caller_identity)
                    account_id = identity['Account']
                    
                    # Get available regions
                    ec2 = boto3.client(
                        'ec2',
                        aws_access_key_id=temp_creds['AccessKeyId'],
                        aws_secret_access_key=temp_creds['SecretAccessKey'],
                        aws_session_token=temp_creds['SessionToken'],
                        region_name='us-east-1'
                    )
                    regions_response = await asyncio.to_thread(ec2.describe_regions)
                    regions = [r['RegionName'] for r in regions_response['Regions']]
                    
                    return {
                        'valid': True,
                        'message': f"Successfully assumed role in AWS account {account_id}",
                        'account_id': account_id,
                        'regions': regions,
                        'assumed_role': role_arn
                    }
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', 'Unknown')
                    if error_code == 'AccessDenied':
                        return {
                            'valid': False,
                            'message': "Access denied. Please ensure the trust policy is correctly configured with the external ID."
                        }
                    raise
            else:
                # Direct access key authentication
                sts = boto3.client(
                    'sts',
                    aws_access_key_id=creds.get('access_key'),
                    aws_secret_access_key=creds.get('secret_key'),
                    aws_session_token=creds.get('session_token')
                )
                
                # Get caller identity
                identity = await asyncio.to_thread(sts.get_caller_identity)
                account_id = identity['Account']
                
                # Get available regions
                ec2 = boto3.client(
                    'ec2',
                    aws_access_key_id=creds.get('access_key'),
                    aws_secret_access_key=creds.get('secret_key'),
                    aws_session_token=creds.get('session_token'),
                    region_name='us-east-1'
                )
                regions_response = await asyncio.to_thread(ec2.describe_regions)
                regions = [r['RegionName'] for r in regions_response['Regions']]
                
                return {
                    'valid': True,
                    'message': f"AWS credentials valid for account {account_id}",
                    'account_id': account_id,
                    'regions': regions
                }
        
        except (ClientError, NoCredentialsError) as e:
            return {
                'valid': False,
                'message': f"AWS credential validation failed: {str(e)}"
            }
        except ImportError:
            return {
                'valid': False,
                'message': "boto3 not installed. Run: pip install boto3"
            }
    
    @staticmethod
    async def _validate_azure_credentials(creds: Dict) -> Dict[str, Any]:
        """Validate Azure credentials"""
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.subscription import SubscriptionClient
            
            credential = ClientSecretCredential(
                tenant_id=creds.get('tenant_id'),
                client_id=creds.get('client_id'),
                client_secret=creds.get('client_secret')
            )
            
            # List subscriptions to verify
            subscription_client = SubscriptionClient(credential)
            subscriptions = list(subscription_client.subscriptions.list())
            
            if not subscriptions:
                return {
                    'valid': False,
                    'message': "No accessible Azure subscriptions found"
                }
            
            sub = subscriptions[0]
            
            # Get available locations
            locations = list(subscription_client.subscriptions.list_locations(sub.subscription_id))
            regions = [loc.name for loc in locations]
            
            return {
                'valid': True,
                'message': f"Azure credentials valid for subscription {sub.display_name}",
                'account_id': sub.subscription_id,
                'regions': regions
            }
        
        except Exception as e:
            return {
                'valid': False,
                'message': f"Azure credential validation failed: {str(e)}"
            }
    
    @staticmethod
    async def _validate_gcp_credentials(creds: Dict) -> Dict[str, Any]:
        """Validate GCP credentials"""
        try:
            import json
            from google.oauth2 import service_account
            from google.cloud import resourcemanager_v3
            
            # Parse service account JSON
            if isinstance(creds.get('service_account_json'), str):
                sa_info = json.loads(creds['service_account_json'])
            else:
                sa_info = creds.get('service_account_json', {})
            
            credentials = service_account.Credentials.from_service_account_info(sa_info)
            
            # Get project info
            project_id = sa_info.get('project_id')
            
            # List available regions (using Compute API)
            from google.cloud import compute_v1
            regions_client = compute_v1.RegionsClient(credentials=credentials)
            regions = list(regions_client.list(project=project_id))
            region_names = [r.name for r in regions]
            
            return {
                'valid': True,
                'message': f"GCP credentials valid for project {project_id}",
                'account_id': project_id,
                'regions': region_names
            }
        
        except Exception as e:
            return {
                'valid': False,
                'message': f"GCP credential validation failed: {str(e)}"
            }
    
    @staticmethod
    async def start_cloud_scan(
        user_id: int,
        website_id: int,
        providers: List[str],
        credentials: Dict[str, Dict],
        regions: List[str] = None,
        iac_paths: List[str] = None,
        container_registries: List[str] = None,
        config: Dict = None,
        db = None
    ) -> Dict[str, Any]:
        """
        Start a new cloud security scan
        
        Args:
            user_id: Database user ID
            website_id: Database website ID (stores scan metadata)
            providers: List of providers to scan ['aws', 'azure', 'gcp']
            credentials: Provider credentials dict
            regions: List of regions to scan (or None for all)
            iac_paths: Paths to IaC files/directories
            container_registries: Container image URLs to scan
            config: Additional scan configuration
            db: Database session
        
        Returns:
            {
                'success': bool,
                'scan_id': int,
                'message': str
            }
        """
        try:
            # Check subscription limits
            user = db.query(User).filter(User.id == user_id).first()
            if not user:
                return {
                    'success': False,
                    'message': "User not found"
                }
            
            # Verify scan limit (basic check)
            # In production, this would be async and use check_subscription_limit
            if user.subscription_plan == 'free':
                # Free tier has 3 scans/month
                scans_this_month = db.query(Scan).filter(
                    Scan.user_id == user_id,
                    Scan.scan_type == 'cloud',
                    Scan.created_at >= datetime.utcnow().replace(day=1)
                ).count()
                if scans_this_month >= 3:
                    return {
                        'success': False,
                        'message': f"Monthly scan limit reached (3 scans). Upgrade your plan."
                    }
            
            # Create scan record
            scan = Scan(
                website_id=website_id,
                scan_type='cloud',
                status='running',
                created_at=datetime.utcnow(),
                config=config or {}
            )
            db.add(scan)
            db.commit()
            db.refresh(scan)
            
            # Build scan configuration
            scan_config = {
                'providers': providers,
                'credentials': credentials,
                'regions': regions or [],
                'iac_paths': iac_paths or [],
                'container_registries': container_registries or [],
                'scan_id': scan.id,
                'user_id': user_id,
                **(config or {})
            }
            
            # Start scan in background
            asyncio.create_task(
                CloudSecurityService._execute_cloud_scan(
                    scan_id=scan.id,
                    config=scan_config,
                    db_session=db
                )
            )
            
            logger.info(f"Cloud scan {scan.id} started for user {user_id}")
            
            return {
                'success': True,
                'scan_id': scan.id,
                'message': f"Cloud scan started successfully. Scanning {len(providers)} provider(s)."
            }
        
        except Exception as e:
            logger.error(f"Failed to start cloud scan: {e}")
            if db:
                db.rollback()
            return {
                'success': False,
                'message': f"Failed to start scan: {str(e)}"
            }
    
    @staticmethod
    async def _execute_cloud_scan(scan_id: int, config: Dict, db_session):
        """Execute cloud scan in background"""
        try:
            # Update scan status
            scan = db_session.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return
            
            scan.status = 'running'
            scan.started_at = datetime.utcnow()
            db_session.commit()
            
            # Run cloud scan
            runner = CloudScanRunner(config)
            
            # Progress callback
            def progress_callback(phase: str, current: int, total: int):
                logger.info(f"Scan {scan_id} - Phase {phase}: {current}/{total}")
            
            results = await runner.run(progress_callback=progress_callback)
            
            # Save findings to database
            findings_count = len(results.get('findings', []))
            
            scan.status = 'completed'
            scan.completed_at = datetime.utcnow()
            scan.findings_count = findings_count
            scan.results = results
            db_session.commit()
            
            logger.info(f"Cloud scan {scan_id} completed with {findings_count} findings")
        
        except Exception as e:
            logger.error(f"Cloud scan {scan_id} failed: {e}")
            scan.status = 'failed'
            scan.error_message = str(e)
            scan.completed_at = datetime.utcnow()
            db_session.commit()
    
    @staticmethod
    async def get_scan_status(scan_id: int, db) -> Optional[Dict]:
        """Get cloud scan status"""
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.scan_type == 'cloud').first()
        if not scan:
            return None
        
        return {
            'id': scan.id,
            'status': scan.status,
            'findings_count': scan.findings_count or 0,
            'created_at': scan.created_at.isoformat() if scan.created_at else None,
            'started_at': scan.started_at.isoformat() if scan.started_at else None,
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
            'error_message': scan.error_message
        }
    
    @staticmethod
    async def get_scan_results(scan_id: int, db) -> Optional[Dict]:
        """Get cloud scan results"""
        scan = db.query(Scan).filter(Scan.id == scan_id, Scan.scan_type == 'cloud').first()
        if not scan:
            return None
        
        return {
            'id': scan.id,
            'status': scan.status,
            'findings': scan.results.get('findings', []) if scan.results else [],
            'summary': scan.results.get('summary', {}) if scan.results else {},
            'attack_paths': scan.results.get('attack_paths', []) if scan.results else [],
            'compliance_scores': scan.results.get('compliance_scores', {}) if scan.results else {}
        }
    
    @staticmethod
    async def calculate_compliance_scores(findings: List[Dict]) -> Dict[str, float]:
        """
        Calculate compliance scores from findings
        
        Returns:
            {
                'CIS': 85.5,  # Percentage
                'PCI-DSS': 78.2,
                'HIPAA': 92.1,
                'SOC2': 88.3
            }
        """
        # Group findings by framework
        framework_findings = {
            'CIS': [],
            'PCI-DSS': [],
            'HIPAA': [],
            'SOC2': []
        }
        
        for finding in findings:
            # Determine framework from finding metadata
            cis_benchmark = finding.get('cis_benchmark', '')
            if cis_benchmark:
                framework_findings['CIS'].append(finding)
            
            # Add to other frameworks based on category
            category = finding.get('category', '')
            if 'encryption' in category.lower() or 'data' in category.lower():
                framework_findings['PCI-DSS'].append(finding)
                framework_findings['HIPAA'].append(finding)
            
            framework_findings['SOC2'].append(finding)
        
        # Calculate scores (inverse of severity-weighted findings)
        scores = {}
        severity_weights = {'critical': 10, 'high': 5, 'medium': 2, 'low': 1, 'info': 0}
        
        for framework, fw_findings in framework_findings.items():
            if not fw_findings:
                scores[framework] = 100.0
                continue
            
            total_weight = sum(severity_weights.get(f.get('severity', 'info'), 0) for f in fw_findings)
            max_possible = len(fw_findings) * 10  # If all were critical
            
            if max_possible > 0:
                scores[framework] = max(0, 100 - (total_weight / max_possible * 100))
            else:
                scores[framework] = 100.0
        
        return scores
    
    @staticmethod
    async def export_findings(
        scan_id: int,
        format: str,
        db
    ) -> Optional[Dict[str, Any]]:
        """
        Export cloud scan findings
        
        Args:
            scan_id: Scan ID
            format: 'json', 'sarif', 'html', 'pdf'
            db: Database session
        
        Returns:
            {
                'file_path': str,
                'content': str (for json/sarif),
                'mime_type': str
            }
        """
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan or not scan.results:
            return None
        
        findings = scan.results.get('findings', [])
        
        if format == 'json':
            import json
            content = json.dumps(findings, indent=2)
            return {
                'content': content,
                'mime_type': 'application/json'
            }
        
        elif format == 'sarif':
            # Convert to SARIF format
            from core.reporters import ReportGenerator
            reporter = ReportGenerator(scan.results, {})
            sarif = reporter.generate_sarif()
            return {
                'content': sarif,
                'mime_type': 'application/sarif+json'
            }
        
        elif format == 'html':
            # Generate HTML report
            from core.reporters import ReportGenerator
            reporter = ReportGenerator(scan.results, {})
            output_dir = Path('reports')
            output_dir.mkdir(exist_ok=True)
            html_path = output_dir / f"cloud_scan_{scan_id}.html"
            reporter.generate_html(str(html_path))
            
            return {
                'file_path': str(html_path),
                'mime_type': 'text/html'
            }
        
        elif format == 'pdf':
            # Generate PDF via HTML
            from core.reporters import ReportGenerator
            reporter = ReportGenerator(scan.results, {})
            output_dir = Path('reports')
            output_dir.mkdir(exist_ok=True)
            html_path = output_dir / f"cloud_scan_{scan_id}.html"
            pdf_path = output_dir / f"cloud_scan_{scan_id}.pdf"
            
            reporter.generate_html(str(html_path))
            await reporter.generate_pdf_async(str(html_path), str(pdf_path))
            
            return {
                'file_path': str(pdf_path),
                'mime_type': 'application/pdf'
            }
        
        return None

    @staticmethod
    async def execute_background_scan(scan_id: str, user_id: int, provider: str, 
                                       credentials: dict, config: dict,
                                       progress_callback=None):
        """
        Execute a cloud scan in background - called by API routes
        
        This method wraps CloudScanRunner for the service layer.
        API routes should call this instead of importing core directly.
        """
        try:
            runner = CloudScanRunner({
                'providers': [provider],
                'credentials': {provider: credentials},
                'scan_id': scan_id,
                'user_id': user_id,
                **config
            })
            
            if progress_callback:
                runner.set_progress_callback(progress_callback)
            
            # Run extended scan with all phases
            results = await runner.run_extended_scan()
            return results
            
        except Exception as e:
            logger.error(f"Cloud scan execution failed: {e}")
            raise

    @staticmethod
    async def generate_report(findings: List[Dict], scan_config: Dict, 
                              format: str, output_dir: str = "reports") -> Dict[str, Any]:
        """
        Generate cloud scan report - called by API routes
        
        This method wraps ReportGenerator for the service layer.
        API routes should call this instead of importing core directly.
        """
        from core.reporters import ReportGenerator
        
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        
        scan_results = {
            "findings": findings,
            "summary": {
                "total": len(findings),
                "critical": len([f for f in findings if f.get('severity') == 'critical']),
                "high": len([f for f in findings if f.get('severity') == 'high']),
                "medium": len([f for f in findings if f.get('severity') == 'medium']),
                "low": len([f for f in findings if f.get('severity') == 'low']),
            },
            **scan_config
        }
        
        reporter = ReportGenerator(scan_results, {})
        scan_id = scan_config.get('scan_id', 'cloud_scan')
        
        if format == 'html':
            html_path = output_path / f"cloud_scan_{scan_id}.html"
            reporter.generate_html(str(html_path))
            return {'file_path': str(html_path), 'mime_type': 'text/html'}
            
        elif format == 'pdf':
            html_path = output_path / f"cloud_scan_{scan_id}.html"
            pdf_path = output_path / f"cloud_scan_{scan_id}.pdf"
            reporter.generate_html(str(html_path))
            await reporter.generate_pdf_async(str(html_path), str(pdf_path))
            return {'file_path': str(pdf_path), 'mime_type': 'application/pdf'}
            
        elif format == 'sarif':
            sarif_content = reporter.generate_sarif()
            return {'content': sarif_content, 'mime_type': 'application/sarif+json'}
            
        elif format == 'json':
            import json
            return {'content': json.dumps(findings, indent=2), 'mime_type': 'application/json'}
        
        return None


# Backwards compatibility alias
CloudService = CloudSecurityService
