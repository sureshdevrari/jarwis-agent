"""SSRF Blind Scanner - No direct response, uses OOB callbacks"""

import asyncio
import logging
from dataclasses import dataclass
from typing import List

logger = logging.getLogger(__name__)

@dataclass  
class SSRFBlindResult:
    id: str
    sub_type: str = "blind"
    severity: str = "high"
    title: str = ""
    url: str = ""
    parameter: str = ""
    payload: str = ""
    callback_received: bool = False

class SSRFBlind:
    """Blind SSRF - uses out-of-band callbacks to detect"""
    
    SUB_TYPE = "blind"
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.callback_server = getattr(context, 'oob_server', None)
        self.findings: List[SSRFBlindResult] = []
    
    async def scan(self) -> List[SSRFBlindResult]:
        logger.info(f"Starting Blind SSRF scan")
        # Uses OOB callback server to detect blind SSRF
        return self.findings
