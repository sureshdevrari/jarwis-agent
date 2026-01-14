"""SSRF Basic Scanner - Direct SSRF with visible response"""

import asyncio
import logging
import aiohttp
from dataclasses import dataclass
from typing import List, Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

@dataclass
class SSRFResult:
    id: str
    sub_type: str
    severity: str = "high"
    title: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    confidence: float = 0.0

class SSRFBasic:
    """Basic SSRF - response content is returned to attacker"""
    
    SUB_TYPE = "basic"
    
    PAYLOADS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://[::1]",
        "http://127.0.0.1:80",
        "http://127.0.0.1:22",
        "http://127.0.0.1:3306",
        "http://0.0.0.0",
        "http://2130706433",  # Decimal IP
    ]
    
    LOCALHOST_INDICATORS = [
        "apache", "nginx", "iis", "root:", "localhost",
        "ssh-", "mysql", "127.0.0.1", "internal"
    ]
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.findings: List[SSRFResult] = []
    
    async def scan(self) -> List[SSRFResult]:
        logger.info(f"Starting Basic SSRF scan")
        # Implementation would test URL parameters with localhost payloads
        return self.findings
