"""
Jarwis AGI - Sensitive Data Discovery Scanner
Detects exposed sensitive data in cloud storage

Features:
- PII detection (SSN, credit cards, emails, phone numbers)
- API keys and secrets in storage
- PHI/Healthcare data detection
- Financial data patterns
- Custom regex patterns
- Multi-cloud support (S3, Azure Blob, GCS)
"""

import asyncio
import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Callable
import io

logger = logging.getLogger(__name__)


@dataclass
class SensitiveDataFinding:
    """Sensitive data finding"""
    id: str
    provider: str
    storage_type: str
    bucket_name: str
    object_key: str
    data_type: str  # pii, phi, financial, credentials, custom
    pattern_name: str
    severity: str
    title: str
    description: str
    sample_match: str = ""  # Redacted sample
    match_count: int = 0
    compliance_frameworks: List[str] = field(default_factory=list)
    recommendation: str = ""


class SensitiveDataScanner:
    """
    Sensitive Data Discovery Scanner
    Scans cloud storage for exposed sensitive information
    """
    
    # PII patterns
    PII_PATTERNS = {
        'ssn': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'description': 'Social Security Number',
            'compliance': ['PCI-DSS', 'HIPAA', 'GDPR', 'CCPA'],
            'severity': 'critical'
        },
        'credit_card': {
            'pattern': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9][0-9])[0-9]{12})\b',
            'description': 'Credit Card Number',
            'compliance': ['PCI-DSS'],
            'severity': 'critical'
        },
        'email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'description': 'Email Address',
            'compliance': ['GDPR', 'CCPA'],
            'severity': 'medium'
        },
        'phone_us': {
            'pattern': r'\b(?:\+1[-.\s]?)?(?:\([0-9]{3}\)|[0-9]{3})[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
            'description': 'US Phone Number',
            'compliance': ['GDPR', 'CCPA'],
            'severity': 'low'
        },
        'passport': {
            'pattern': r'\b[A-Z]{1,2}[0-9]{6,9}\b',
            'description': 'Passport Number Pattern',
            'compliance': ['GDPR', 'CCPA'],
            'severity': 'high'
        },
        'drivers_license': {
            'pattern': r'\b[A-Z]{1,2}\d{5,8}\b',
            'description': 'Drivers License Pattern',
            'compliance': ['GDPR', 'CCPA'],
            'severity': 'high'
        },
    }
    
    # Healthcare/PHI patterns
    PHI_PATTERNS = {
        'mrn': {
            'pattern': r'\bMRN[:\s#]*\d{6,12}\b',
            'description': 'Medical Record Number',
            'compliance': ['HIPAA'],
            'severity': 'critical'
        },
        'npi': {
            'pattern': r'\b\d{10}\b',  # NPI is 10 digits
            'description': 'National Provider Identifier Pattern',
            'compliance': ['HIPAA'],
            'severity': 'high'
        },
        'diagnosis_code': {
            'pattern': r'\b[A-Z]\d{2}\.?\d{0,2}\b',
            'description': 'ICD-10 Diagnosis Code Pattern',
            'compliance': ['HIPAA'],
            'severity': 'medium'
        },
    }
    
    # Credential patterns
    CREDENTIAL_PATTERNS = {
        'aws_access_key': {
            'pattern': r'\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b',
            'description': 'AWS Access Key ID',
            'compliance': ['SOC2', 'CIS'],
            'severity': 'critical'
        },
        'aws_secret_key': {
            'pattern': r'(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])',
            'description': 'Potential AWS Secret Key',
            'compliance': ['SOC2', 'CIS'],
            'severity': 'critical'
        },
        'gcp_service_account': {
            'pattern': r'"type"\s*:\s*"service_account"',
            'description': 'GCP Service Account Key File',
            'compliance': ['SOC2', 'CIS'],
            'severity': 'critical'
        },
        'azure_connection_string': {
            'pattern': r'DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;]+',
            'description': 'Azure Storage Connection String',
            'compliance': ['SOC2', 'CIS'],
            'severity': 'critical'
        },
        'private_key': {
            'pattern': r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
            'description': 'Private Key',
            'compliance': ['SOC2', 'CIS'],
            'severity': 'critical'
        },
        'jwt_token': {
            'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            'description': 'JWT Token',
            'compliance': ['SOC2'],
            'severity': 'high'
        },
        'api_key_generic': {
            'pattern': r'(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]+["\']?([A-Za-z0-9_-]{20,})["\']?',
            'description': 'Generic API Key',
            'compliance': ['SOC2'],
            'severity': 'high'
        },
        'password_in_url': {
            'pattern': r'(?:https?://)[^:]+:([^@]+)@',
            'description': 'Password in URL',
            'compliance': ['SOC2', 'CIS'],
            'severity': 'critical'
        },
    }
    
    # Financial patterns
    FINANCIAL_PATTERNS = {
        'iban': {
            'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
            'description': 'IBAN Account Number',
            'compliance': ['PCI-DSS', 'GDPR'],
            'severity': 'high'
        },
        'routing_number': {
            'pattern': r'\b\d{9}\b',
            'description': 'Bank Routing Number Pattern',
            'compliance': ['PCI-DSS'],
            'severity': 'medium'
        },
    }
    
    # File extensions to scan (text-based)
    SCANNABLE_EXTENSIONS = [
        '.txt', '.csv', '.json', '.xml', '.yaml', '.yml', '.log', '.sql',
        '.html', '.htm', '.md', '.conf', '.config', '.ini', '.env',
        '.py', '.js', '.java', '.php', '.rb', '.go', '.sh', '.bat'
    ]
    
    # Maximum file size to scan (5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024
    
    def __init__(self, config: Dict, context: Any = None):
        self.config = config
        self.context = context
        self.findings: List[SensitiveDataFinding] = []
        self._finding_id = 0
        self._progress_callback: Optional[Callable] = None
        
        # Combine all patterns
        self.all_patterns = {}
        self.all_patterns.update({f"pii_{k}": v for k, v in self.PII_PATTERNS.items()})
        self.all_patterns.update({f"phi_{k}": v for k, v in self.PHI_PATTERNS.items()})
        self.all_patterns.update({f"cred_{k}": v for k, v in self.CREDENTIAL_PATTERNS.items()})
        self.all_patterns.update({f"fin_{k}": v for k, v in self.FINANCIAL_PATTERNS.items()})
        
        # Add custom patterns from config
        custom_patterns = config.get('custom_patterns', {})
        for name, pattern_config in custom_patterns.items():
            self.all_patterns[f"custom_{name}"] = pattern_config
        
        # Compile patterns
        self.compiled_patterns = {}
        for name, config_data in self.all_patterns.items():
            try:
                self.compiled_patterns[name] = re.compile(config_data['pattern'], re.IGNORECASE)
            except re.error as e:
                logger.warning(f"Invalid regex pattern '{name}': {e}")
    
    def _generate_id(self) -> str:
        self._finding_id += 1
        return f"DATA-{self._finding_id:04d}"
    
    def set_progress_callback(self, callback: Callable):
        """Set callback for progress updates"""
        self._progress_callback = callback
    
    async def scan(self) -> List[SensitiveDataFinding]:
        """Run sensitive data scan across configured storage"""
        self.findings = []
        
        providers = self.config.get('providers', ['aws'])
        credentials = self.config.get('credentials', {})
        
        for provider in providers:
            creds = credentials.get(provider, {})
            
            if provider == 'aws':
                await self._scan_s3(creds)
            elif provider == 'azure':
                await self._scan_azure_blob(creds)
            elif provider == 'gcp':
                await self._scan_gcs(creds)
        
        return self.findings
    
    async def _scan_s3(self, credentials: Dict):
        """Scan AWS S3 buckets for sensitive data"""
        try:
            import boto3
        except ImportError:
            logger.warning("boto3 not installed, skipping S3 scan")
            return
        
        try:
            session = boto3.Session(
                aws_access_key_id=credentials.get('access_key_id'),
                aws_secret_access_key=credentials.get('secret_access_key'),
                aws_session_token=credentials.get('session_token'),
                region_name=credentials.get('region', 'us-east-1')
            )
            
            s3 = session.client('s3')
            
            # Get buckets to scan
            buckets_to_scan = self.config.get('buckets', [])
            
            if not buckets_to_scan:
                # List all buckets
                response = s3.list_buckets()
                buckets_to_scan = [b['Name'] for b in response.get('Buckets', [])]
            
            total_buckets = len(buckets_to_scan)
            
            for idx, bucket_name in enumerate(buckets_to_scan):
                if self._progress_callback:
                    self._progress_callback(f"Scanning S3 bucket: {bucket_name}", 
                                           (idx / total_buckets) * 100)
                
                await self._scan_s3_bucket(s3, bucket_name)
                await asyncio.sleep(0.5)  # Rate limiting
                
        except Exception as e:
            logger.error(f"S3 scan error: {e}")
    
    async def _scan_s3_bucket(self, s3, bucket_name: str):
        """Scan a specific S3 bucket"""
        try:
            # List objects with pagination
            paginator = s3.get_paginator('list_objects_v2')
            
            objects_scanned = 0
            max_objects = self.config.get('max_objects_per_bucket', 1000)
            
            for page in paginator.paginate(Bucket=bucket_name):
                for obj in page.get('Contents', []):
                    if objects_scanned >= max_objects:
                        break
                    
                    key = obj['Key']
                    size = obj['Size']
                    
                    # Skip large files
                    if size > self.MAX_FILE_SIZE:
                        continue
                    
                    # Check extension
                    ext = '.' + key.split('.')[-1].lower() if '.' in key else ''
                    if ext not in self.SCANNABLE_EXTENSIONS:
                        continue
                    
                    # Get object content
                    try:
                        response = s3.get_object(Bucket=bucket_name, Key=key)
                        content = response['Body'].read().decode('utf-8', errors='ignore')
                        
                        await self._scan_content(content, 'aws', 's3', bucket_name, key)
                        objects_scanned += 1
                        
                    except Exception as e:
                        logger.debug(f"Error reading S3 object {bucket_name}/{key}: {e}")
                    
                    await asyncio.sleep(0.1)  # Rate limiting
                    
        except Exception as e:
            logger.error(f"Error scanning S3 bucket {bucket_name}: {e}")
    
    async def _scan_azure_blob(self, credentials: Dict):
        """Scan Azure Blob Storage for sensitive data"""
        try:
            from azure.storage.blob import BlobServiceClient
            from azure.identity import ClientSecretCredential
        except ImportError:
            logger.warning("azure-storage-blob not installed, skipping Azure Blob scan")
            return
        
        try:
            connection_string = credentials.get('connection_string')
            
            if connection_string:
                blob_service = BlobServiceClient.from_connection_string(connection_string)
            else:
                credential = ClientSecretCredential(
                    tenant_id=credentials.get('tenant_id'),
                    client_id=credentials.get('client_id'),
                    client_secret=credentials.get('client_secret')
                )
                account_url = f"https://{credentials.get('storage_account')}.blob.core.windows.net"
                blob_service = BlobServiceClient(account_url, credential=credential)
            
            # List containers
            containers = list(blob_service.list_containers())
            
            for container in containers:
                container_name = container['name']
                
                if self._progress_callback:
                    self._progress_callback(f"Scanning Azure container: {container_name}", 0)
                
                container_client = blob_service.get_container_client(container_name)
                
                objects_scanned = 0
                max_objects = self.config.get('max_objects_per_bucket', 1000)
                
                for blob in container_client.list_blobs():
                    if objects_scanned >= max_objects:
                        break
                    
                    blob_name = blob['name']
                    size = blob['size']
                    
                    if size > self.MAX_FILE_SIZE:
                        continue
                    
                    ext = '.' + blob_name.split('.')[-1].lower() if '.' in blob_name else ''
                    if ext not in self.SCANNABLE_EXTENSIONS:
                        continue
                    
                    try:
                        blob_client = container_client.get_blob_client(blob_name)
                        content = blob_client.download_blob().readall().decode('utf-8', errors='ignore')
                        
                        await self._scan_content(content, 'azure', 'blob', container_name, blob_name)
                        objects_scanned += 1
                        
                    except Exception as e:
                        logger.debug(f"Error reading Azure blob {container_name}/{blob_name}: {e}")
                    
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"Azure Blob scan error: {e}")
    
    async def _scan_gcs(self, credentials: Dict):
        """Scan Google Cloud Storage for sensitive data"""
        try:
            from google.cloud import storage
            from google.oauth2 import service_account
            import json
        except ImportError:
            logger.warning("google-cloud-storage not installed, skipping GCS scan")
            return
        
        try:
            sa_key = credentials.get('service_account_key', '{}')
            if isinstance(sa_key, str):
                sa_info = json.loads(sa_key)
            else:
                sa_info = sa_key
            
            creds = service_account.Credentials.from_service_account_info(sa_info)
            client = storage.Client(credentials=creds, project=credentials.get('project_id'))
            
            # List buckets
            buckets = list(client.list_buckets())
            
            for bucket in buckets:
                bucket_name = bucket.name
                
                if self._progress_callback:
                    self._progress_callback(f"Scanning GCS bucket: {bucket_name}", 0)
                
                objects_scanned = 0
                max_objects = self.config.get('max_objects_per_bucket', 1000)
                
                for blob in bucket.list_blobs():
                    if objects_scanned >= max_objects:
                        break
                    
                    blob_name = blob.name
                    size = blob.size or 0
                    
                    if size > self.MAX_FILE_SIZE:
                        continue
                    
                    ext = '.' + blob_name.split('.')[-1].lower() if '.' in blob_name else ''
                    if ext not in self.SCANNABLE_EXTENSIONS:
                        continue
                    
                    try:
                        content = blob.download_as_text()
                        
                        await self._scan_content(content, 'gcp', 'gcs', bucket_name, blob_name)
                        objects_scanned += 1
                        
                    except Exception as e:
                        logger.debug(f"Error reading GCS object {bucket_name}/{blob_name}: {e}")
                    
                    await asyncio.sleep(0.1)
                    
        except Exception as e:
            logger.error(f"GCS scan error: {e}")
    
    async def _scan_content(self, content: str, provider: str, storage_type: str, 
                            bucket_name: str, object_key: str):
        """Scan content for sensitive data patterns"""
        for pattern_name, compiled_pattern in self.compiled_patterns.items():
            try:
                matches = compiled_pattern.findall(content)
                
                if matches:
                    pattern_config = self.all_patterns[pattern_name]
                    
                    # Determine data type from pattern name
                    if pattern_name.startswith('pii_'):
                        data_type = 'pii'
                    elif pattern_name.startswith('phi_'):
                        data_type = 'phi'
                    elif pattern_name.startswith('cred_'):
                        data_type = 'credentials'
                    elif pattern_name.startswith('fin_'):
                        data_type = 'financial'
                    else:
                        data_type = 'custom'
                    
                    # Redact sample match
                    sample = str(matches[0]) if matches else ''
                    if len(sample) > 4:
                        redacted = sample[:2] + '*' * (len(sample) - 4) + sample[-2:]
                    else:
                        redacted = '*' * len(sample)
                    
                    self.findings.append(SensitiveDataFinding(
                        id=self._generate_id(),
                        provider=provider,
                        storage_type=storage_type,
                        bucket_name=bucket_name,
                        object_key=object_key,
                        data_type=data_type,
                        pattern_name=pattern_name,
                        severity=pattern_config.get('severity', 'high'),
                        title=f"{pattern_config['description']} found in {storage_type}",
                        description=f"Detected {len(matches)} occurrence(s) of {pattern_config['description']} in {bucket_name}/{object_key}",
                        sample_match=redacted,
                        match_count=len(matches),
                        compliance_frameworks=pattern_config.get('compliance', []),
                        recommendation=f"Review and remove or encrypt {pattern_config['description']} data. Consider data classification and access controls."
                    ))
                    
            except Exception as e:
                logger.debug(f"Error scanning with pattern {pattern_name}: {e}")
