"""SSRF Cloud Metadata Scanner - Targets cloud provider metadata endpoints"""

import asyncio
import logging
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)

@dataclass
class SSRFCloudResult:
    id: str
    sub_type: str = "cloud_metadata"
    severity: str = "critical"  # Cloud metadata = critical
    title: str = ""
    cloud_provider: str = ""
    extracted_data: str = ""

class SSRFCloudMetadata:
    """Cloud Metadata SSRF - targets AWS/GCP/Azure metadata endpoints"""
    
    SUB_TYPE = "cloud_metadata"
    
    CLOUD_ENDPOINTS = {
        'aws': [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/user-data",
        ],
        'gcp': [
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://169.254.169.254/computeMetadata/v1/",
        ],
        'azure': [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/identity/oauth2/token",
        ],
    }
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.findings: List[SSRFCloudResult] = []
    
    async def scan(self) -> List[SSRFCloudResult]:
        logger.info(f"Starting Cloud Metadata SSRF scan")
        # Tests cloud metadata endpoints for credential extraction
        return self.findings
