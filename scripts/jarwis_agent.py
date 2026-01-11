"""
Jarwis Agent - Private Network Scanner Agent

This lightweight agent is deployed inside private networks to enable
scanning of internal IP ranges that cannot be reached from the cloud.

Features:
- Secure communication with Jarwis Cloud via HTTPS
- Local network scanning using embedded scanner modules
- Automatic job polling and result submission
- Configurable via environment variables or config file

Deployment:
1. Register agent at Jarwis dashboard to get agent_id and agent_key
2. Install: pip install jarwis-agent
3. Configure: Set JARWIS_AGENT_ID and JARWIS_AGENT_KEY environment variables
4. Run: python -m jarwis_agent

Or run directly:
    python jarwis_agent.py --agent-id <id> --agent-key <key>
"""

import asyncio
import argparse
import json
import logging
import os
import sys
import platform
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import aiohttp

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from attacks.network import NetworkSecurityScanner
from attacks.network.network_scanner import NetworkScanContext, NetworkScanResult

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('jarwis-agent')


class JarwisAgent:
    """
    Jarwis Agent for private network scanning
    
    Communicates with Jarwis Cloud to:
    1. Send heartbeats
    2. Receive scan jobs
    3. Execute scans locally
    4. Submit results
    """
    
    VERSION = "1.0.0"
    
    def __init__(
        self,
        agent_id: str,
        agent_key: str,
        api_url: str = "https://api.jarwis.io",
        heartbeat_interval: int = 30
    ):
        self.agent_id = agent_id
        self.agent_key = agent_key
        self.api_url = api_url
        self.heartbeat_interval = heartbeat_interval
        self.running = False
        self._session: Optional[aiohttp.ClientSession] = None
    
    async def start(self):
        """Start the agent"""
        logger.info(f"Starting Jarwis Agent v{self.VERSION}")
        logger.info(f"Agent ID: {self.agent_id}")
        logger.info(f"API URL: {self.api_url}")
        logger.info(f"Platform: {platform.system()} {platform.release()}")
        
        self.running = True
        self._session = aiohttp.ClientSession(
            headers={
                'X-Agent-Key': self.agent_key,
                'User-Agent': f'JarwisAgent/{self.VERSION}',
            }
        )
        
        try:
            # Initial registration/check-in
            await self._register()
            
            # Main loop
            while self.running:
                try:
                    # Send heartbeat and check for jobs
                    jobs = await self._heartbeat()
                    
                    if jobs:
                        # Process each pending job
                        for job in jobs:
                            await self._process_job(job)
                    
                    # Wait before next heartbeat
                    await asyncio.sleep(self.heartbeat_interval)
                    
                except aiohttp.ClientError as e:
                    logger.error(f"API communication error: {e}")
                    await asyncio.sleep(60)  # Wait longer on error
                except Exception as e:
                    logger.exception(f"Unexpected error: {e}")
                    await asyncio.sleep(30)
        
        finally:
            if self._session:
                await self._session.close()
    
    async def stop(self):
        """Stop the agent"""
        logger.info("Stopping Jarwis Agent...")
        self.running = False
    
    async def _register(self):
        """Register with Jarwis Cloud"""
        try:
            payload = {
                'version': self.VERSION,
                'platform': platform.system(),
                'hostname': platform.node(),
            }
            
            async with self._session.post(
                f"{self.api_url}/api/network/agents/{self.agent_id}/heartbeat",
                json=payload
            ) as resp:
                if resp.status == 200:
                    logger.info("Successfully registered with Jarwis Cloud")
                elif resp.status == 401:
                    logger.error("Invalid agent credentials. Check agent_id and agent_key.")
                    self.running = False
                elif resp.status == 404:
                    logger.error("Agent not found. Please register the agent first.")
                    self.running = False
                else:
                    text = await resp.text()
                    logger.warning(f"Unexpected response: {resp.status} - {text}")
        
        except aiohttp.ClientConnectorError:
            logger.warning("Cannot reach Jarwis Cloud. Will retry...")
    
    async def _heartbeat(self) -> List[Dict]:
        """
        Send heartbeat and receive pending jobs.
        Returns list of jobs to process.
        """
        try:
            async with self._session.post(
                f"{self.api_url}/api/network/agents/{self.agent_id}/heartbeat",
                json={
                    'version': self.VERSION,
                    'platform': platform.system(),
                    'timestamp': datetime.utcnow().isoformat(),
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    pending_count = data.get('pending_jobs', 0)
                    
                    if pending_count > 0:
                        logger.info(f"Received {pending_count} pending job(s)")
                        return data.get('jobs', [])
                    
                return []
        
        except Exception as e:
            logger.error(f"Heartbeat failed: {e}")
            return []
    
    async def _process_job(self, job: Dict):
        """Process a scan job"""
        scan_id = job.get('scan_id')
        logger.info(f"Processing scan job: {scan_id}")
        
        try:
            # Fetch full job config
            config = await self._fetch_job_config(scan_id)
            if not config:
                return
            
            # Create scanner context
            context = NetworkScanContext(
                targets=config.get('targets', '').split(','),
                credentials=config.get('credentials') if config.get('credentials', {}).get('enabled') else None
            )
            
            # Create scanner
            scanner = NetworkSecurityScanner(
                config={'network_config': config},
                context=context
            )
            
            # Report starting
            await self._update_status(scan_id, 'running', 0)
            
            # Run scan
            findings = await scanner.scan()
            
            # Submit results
            await self._submit_results(scan_id, findings, 'completed', 100)
            
            logger.info(f"Scan {scan_id} completed with {len(findings)} findings")
        
        except Exception as e:
            logger.exception(f"Scan job {scan_id} failed: {e}")
            await self._update_status(scan_id, 'error', 0, str(e))
    
    async def _fetch_job_config(self, scan_id: str) -> Optional[Dict]:
        """Fetch full job configuration from API"""
        try:
            async with self._session.get(
                f"{self.api_url}/api/network/scan/{scan_id}"
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data.get('config', {})
                else:
                    logger.error(f"Failed to fetch job config: {resp.status}")
                    return None
        except Exception as e:
            logger.error(f"Error fetching job config: {e}")
            return None
    
    async def _update_status(
        self,
        scan_id: str,
        status: str,
        progress: int,
        error: str = ""
    ):
        """Update scan status in cloud"""
        try:
            await self._session.post(
                f"{self.api_url}/api/network/agents/{self.agent_id}/results",
                json={
                    'scan_id': scan_id,
                    'status': status,
                    'progress': progress,
                    'error': error,
                    'findings': [],
                }
            )
        except Exception as e:
            logger.error(f"Failed to update status: {e}")
    
    async def _submit_results(
        self,
        scan_id: str,
        findings: List[NetworkScanResult],
        status: str,
        progress: int
    ):
        """Submit scan results to cloud"""
        try:
            # Convert findings to JSON-serializable format
            findings_data = [
                {
                    'id': f.id,
                    'category': f.category,
                    'severity': f.severity,
                    'title': f.title,
                    'description': f.description,
                    'ip_address': f.ip_address,
                    'port': f.port,
                    'protocol': f.protocol,
                    'service': f.service,
                    'version': f.version,
                    'cve_id': f.cve_id,
                    'cvss_score': f.cvss_score,
                    'evidence': f.evidence,
                    'remediation': f.remediation,
                    'timestamp': f.timestamp,
                }
                for f in findings
            ]
            
            # Submit in batches to avoid large payloads
            batch_size = 100
            for i in range(0, len(findings_data), batch_size):
                batch = findings_data[i:i + batch_size]
                
                async with self._session.post(
                    f"{self.api_url}/api/network/agents/{self.agent_id}/results",
                    json={
                        'scan_id': scan_id,
                        'status': status if i + batch_size >= len(findings_data) else 'running',
                        'progress': progress if i + batch_size >= len(findings_data) else int((i + batch_size) / len(findings_data) * 100),
                        'findings': batch,
                    }
                ) as resp:
                    if resp.status != 200:
                        logger.warning(f"Results submission returned {resp.status}")
            
        except Exception as e:
            logger.error(f"Failed to submit results: {e}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Jarwis Agent - Private Network Scanner'
    )
    parser.add_argument(
        '--agent-id',
        default=os.environ.get('JARWIS_AGENT_ID'),
        help='Agent ID (or set JARWIS_AGENT_ID env var)'
    )
    parser.add_argument(
        '--agent-key',
        default=os.environ.get('JARWIS_AGENT_KEY'),
        help='Agent Key (or set JARWIS_AGENT_KEY env var)'
    )
    parser.add_argument(
        '--api-url',
        default=os.environ.get('JARWIS_API_URL', 'http://localhost:8000'),
        help='Jarwis API URL'
    )
    parser.add_argument(
        '--heartbeat-interval',
        type=int,
        default=30,
        help='Heartbeat interval in seconds (default: 30)'
    )
    
    args = parser.parse_args()
    
    if not args.agent_id or not args.agent_key:
        print("Error: Agent ID and Key are required")
        print("Set via arguments or environment variables:")
        print("  --agent-id / JARWIS_AGENT_ID")
        print("  --agent-key / JARWIS_AGENT_KEY")
        sys.exit(1)
    
    print("""
    +=======================================================+
    |              JARWIS AGENT - Network Scanner           |
    ╠=======================================================╣
    |  Deploy this agent inside your private network to     |
    |  enable scanning of internal IP ranges.               |
    +=======================================================+
    """)
    
    agent = JarwisAgent(
        agent_id=args.agent_id,
        agent_key=args.agent_key,
        api_url=args.api_url,
        heartbeat_interval=args.heartbeat_interval
    )
    
    try:
        asyncio.run(agent.start())
    except KeyboardInterrupt:
        print("\nShutting down...")


if __name__ == '__main__':
    main()
