"""
Jarwis AGI - Runtime Threat Detection Scanner
Analyzes CloudTrail, Azure Activity Logs, GCP Admin Logs
"""

import json
import asyncio
import logging
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Dict, Any
import uuid

logger = logging.getLogger(__name__)

@dataclass
class RuntimeFinding:
    """Runtime threat finding"""
    id: str
    event_time: datetime
    event_type: str
    user: str
    resource: str
    severity: str
    title: str
    description: str
    evidence: Dict = field(default_factory=dict)

class RuntimeScanner:
    """Runtime Threat Detection Scanner"""
    
    # Suspicious event patterns
    THREAT_PATTERNS = {
        # Privilege escalation
        'privilege_escalation': [
            'AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy', 'PutRolePolicy',
            'CreateAccessKey', 'UpdateAccessKey', 'AssumeRole'
        ],
        # Data exfiltration
        'data_exfiltration': [
            'GetObject', 'CopyObject', 'SelectObjectContent', 'DownloadBlob',
            'CreateSnapshot', 'CreateImage'
        ],
        # Lateral movement
        'lateral_movement': [
            'AssumeRole', 'GetSessionToken', 'CreateVpcPeeringConnection',
            'AcceptVpcPeeringConnection'
        ],
        # Resource manipulation
        'resource_manipulation': [
            'DeleteBucket', 'PutBucketPolicy', 'ModifyInstanceAttribute',
            'AuthorizeSecurityGroupIngress', 'CreateNetworkAclEntry'
        ],
        # Account takeover
        'account_takeover': [
            'ConsoleLogin', 'PasswordRecoveryRequested', 'MfaDeviceDeactivated',
            'UpdateLoginProfile', 'DeleteMfaDevice'
        ]
    }
    
    def __init__(self, context, config):
        self.context = context
        self.config = config
        self.findings: List[RuntimeFinding] = []
        self.lookback_days = config.get('runtime_lookback_days', 7)
    
    async def scan(self) -> List[Any]:
        """Analyze runtime logs for threats"""
        logger.info("Starting runtime threat detection...")
        self.findings = []
        
        # Scan each provider's logs
        for provider in self.context.providers:
            if provider == 'aws':
                await self._scan_cloudtrail()
            elif provider == 'azure':
                await self._scan_azure_activity_logs()
            elif provider == 'gcp':
                await self._scan_gcp_admin_logs()
        
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
                category="A09:2021-Security Logging and Monitoring Failures",
                severity=sev,
                title=finding.title,
                description=finding.description,
                provider=Provider.runtime,
                service="Runtime Logs",
                resource_id=finding.resource,
                resource_arn=finding.resource,
                region="global",
                evidence=finding.evidence,
                remediation="Investigate activity and revoke suspicious access",
                remediation_cli="# Review logs and implement preventive controls",
                detection_layer="runtime",
                detected_at=finding.event_time
            ))
        
        return cloud_findings
    
    async def _scan_cloudtrail(self):
        """Scan AWS CloudTrail logs"""
        logger.info("Analyzing CloudTrail events...")
        
        try:
            import boto3
            creds = self.context.credentials.get('aws', {})
            
            client = boto3.client(
                'cloudtrail',
                aws_access_key_id=creds.get('access_key'),
                aws_secret_access_key=creds.get('secret_key'),
                aws_session_token=creds.get('session_token')
            )
            
            # Query last N days
            start_time = datetime.utcnow() - timedelta(days=self.lookback_days)
            
            paginator = client.get_paginator('lookup_events')
            page_iterator = paginator.paginate(
                StartTime=start_time,
                MaxResults=1000
            )
            
            event_count = 0
            for page in page_iterator:
                for event in page.get('Events', []):
                    event_count += 1
                    await self._analyze_cloudtrail_event(event)
                    
                    if event_count >= 10000:  # Limit analysis
                        break
            
            logger.info(f"Analyzed {event_count} CloudTrail events")
        
        except ImportError:
            logger.warning("boto3 not available for CloudTrail analysis")
        except Exception as e:
            logger.error(f"CloudTrail analysis failed: {e}")
    
    async def _analyze_cloudtrail_event(self, event):
        """Analyze single CloudTrail event"""
        event_name = event.get('EventName', '')
        event_time = event.get('EventTime')
        username = event.get('Username', 'Unknown')
        resources = event.get('Resources', [])
        resource_name = resources[0].get('ResourceName') if resources else 'Unknown'
        
        # Check for privilege escalation
        if event_name in self.THREAT_PATTERNS['privilege_escalation']:
            self._add_finding(
                event_time=event_time,
                event_type='privilege_escalation',
                user=username,
                resource=resource_name,
                severity='high',
                title=f"Potential privilege escalation: {event_name}",
                description=f"User {username} performed {event_name} which may indicate privilege escalation attempt",
                evidence={
                    'event_name': event_name,
                    'source_ip': event.get('SourceIPAddress', ''),
                    'user_agent': event.get('UserAgent', '')
                }
            )
        
        # Check for unusual login patterns
        if event_name == 'ConsoleLogin':
            error_code = event.get('ErrorCode')
            if error_code == 'Failed authentication':
                # Could be brute force
                self._add_finding(
                    event_time=event_time,
                    event_type='account_takeover',
                    user=username,
                    resource='AWS Console',
                    severity='medium',
                    title="Failed console login attempt",
                    description=f"Failed login for user {username}",
                    evidence={'source_ip': event.get('SourceIPAddress', '')}
                )
        
        # Check for data exfiltration
        if event_name in self.THREAT_PATTERNS['data_exfiltration']:
            # Check for large number of GetObject calls
            self._add_finding(
                event_time=event_time,
                event_type='data_exfiltration',
                user=username,
                resource=resource_name,
                severity='medium',
                title=f"Potential data exfiltration: {event_name}",
                description=f"User {username} performed {event_name} which may indicate data access",
                evidence={'event_name': event_name}
            )
    
    async def _scan_azure_activity_logs(self):
        """Scan Azure Activity Logs"""
        logger.info("Analyzing Azure Activity Logs...")
        
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.monitor import MonitorManagementClient
            
            creds = self.context.credentials.get('azure', {})
            
            credential = ClientSecretCredential(
                tenant_id=creds.get('tenant_id'),
                client_id=creds.get('client_id'),
                client_secret=creds.get('client_secret')
            )
            
            monitor_client = MonitorManagementClient(
                credential,
                creds.get('subscription_id')
            )
            
            # Query activity logs
            start_time = datetime.utcnow() - timedelta(days=self.lookback_days)
            filter_str = f"eventTimestamp ge '{start_time.isoformat()}'"
            
            activity_logs = monitor_client.activity_logs.list(filter=filter_str)
            
            event_count = 0
            for log in activity_logs:
                event_count += 1
                await self._analyze_azure_event(log)
                
                if event_count >= 10000:
                    break
            
            logger.info(f"Analyzed {event_count} Azure activity log events")
        
        except ImportError:
            logger.warning("Azure SDK not available for activity log analysis")
        except Exception as e:
            logger.error(f"Azure activity log analysis failed: {e}")
    
    async def _analyze_azure_event(self, event):
        """Analyze single Azure activity log event"""
        operation = event.operation_name.value if hasattr(event.operation_name, 'value') else str(event.operation_name)
        event_time = event.event_timestamp
        caller = event.caller or 'Unknown'
        
        # Check for suspicious operations
        if 'Delete' in operation or 'Remove' in operation:
            self._add_finding(
                event_time=event_time,
                event_type='resource_manipulation',
                user=caller,
                resource=event.resource_id,
                severity='medium',
                title=f"Resource deletion: {operation}",
                description=f"User {caller} performed {operation}",
                evidence={'operation': operation, 'status': event.status.value if hasattr(event.status, 'value') else ''}
            )
    
    async def _scan_gcp_admin_logs(self):
        """Scan GCP Admin Activity Logs"""
        logger.info("Analyzing GCP Admin Logs...")
        
        try:
            from google.cloud import logging_v2
            
            creds_data = self.context.credentials.get('gcp', {})
            project_id = creds_data.get('project_id')
            
            client = logging_v2.LoggingServiceV2Client()
            
            # Query logs
            resource_names = [f"projects/{project_id}"]
            start_time = datetime.utcnow() - timedelta(days=self.lookback_days)
            
            filter_str = f'timestamp>="{start_time.isoformat()}Z" AND logName:"cloudaudit.googleapis.com"'
            
            entries = client.list_log_entries(
                resource_names=resource_names,
                filter_=filter_str
            )
            
            event_count = 0
            for entry in entries:
                event_count += 1
                await self._analyze_gcp_event(entry)
                
                if event_count >= 10000:
                    break
            
            logger.info(f"Analyzed {event_count} GCP admin log events")
        
        except ImportError:
            logger.warning("GCP SDK not available for admin log analysis")
        except Exception as e:
            logger.error(f"GCP admin log analysis failed: {e}")
    
    async def _analyze_gcp_event(self, entry):
        """Analyze single GCP log entry"""
        # Placeholder - full implementation would parse protoPayload
        pass
    
    def _add_finding(self, event_time, event_type, user, resource, severity, title, description, evidence):
        self.findings.append(RuntimeFinding(
            id=f"runtime_{event_type}_{uuid.uuid4().hex[:8]}",
            event_time=event_time,
            event_type=event_type,
            user=user,
            resource=resource,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence
        ))