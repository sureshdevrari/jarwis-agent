"""
Jarwis Mobile - Remote Execution Mode

Enables mobile scanning when the emulator runs on a remote agent (client machine)
while the server handles analysis and attack execution.

This module provides the server-side interface for hybrid mobile scanning.
"""

import asyncio
import logging
import uuid
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class RemoteMobileScanConfig:
    """Configuration for remote mobile scan"""
    scan_id: str
    agent_id: str
    
    # App info
    app_path: str = ""              # Path on agent machine, or URL to download
    app_package: str = ""
    platform: str = "android"
    
    # Scan options
    ssl_bypass: bool = True
    crawl_enabled: bool = True
    crawl_duration: int = 120
    attacks_enabled: bool = True
    
    # Target scope
    target_hosts: List[str] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=list)
    
    # Auth (optional)
    auth_enabled: bool = False
    auth_config: Optional[Dict] = None


class RemoteMobileExecutor:
    """
    Server-side executor for remote mobile scans.
    
    Works with MobileAgentManager to:
    1. Start scans on remote agents
    2. Receive traffic from agents
    3. Execute attacks on server
    4. Send attack requests back to agent
    5. Aggregate results
    
    Flow:
        Server                          Agent (Client)
        ------                          --------------
        1. Start scan command --------> Starts emulator/Frida/MITM
        2.                      <------- Traffic captured
        3. Store in RequestStore
        4. Run scanner on request
        5. Create attack request ------> Execute via local proxy
        6.                      <------- Attack response
        7. Analyze for vulnerability
        8. Repeat for all traffic
    """
    
    def __init__(self, scan_id: str, agent_id: str):
        self.scan_id = scan_id
        self.agent_id = agent_id
        
        # Import here to avoid circular imports
        from core.mobile_agent_server import mobile_agent_manager
        self.agent_manager = mobile_agent_manager
        
        # Request store for captured traffic
        self._request_store = None
        
        # Pending attack responses
        self._pending_attacks: Dict[str, asyncio.Future] = {}
        
        # State
        self._running = False
        self._phase = "init"
        
        # Callbacks
        self._on_traffic: Optional[Callable] = None
        self._on_finding: Optional[Callable] = None
        self._on_progress: Optional[Callable] = None
    
    async def initialize(self):
        """Initialize executor and request store"""
        from core.mobile_request_store import MobileRequestStoreDB
        
        self._request_store = MobileRequestStoreDB(
            scan_id=self.scan_id,
            app_package=""
        )
        await self._request_store.initialize()
        
        # Register traffic callback with agent manager
        self.agent_manager.set_traffic_callback(self._handle_traffic)
        
        logger.info(f"RemoteMobileExecutor initialized for scan {self.scan_id}")
    
    async def start_scan(self, config: RemoteMobileScanConfig) -> bool:
        """Start scan on remote agent"""
        logger.info(f"Starting remote scan {self.scan_id} on agent {self.agent_id}")
        
        self._running = True
        self._phase = "starting"
        
        # Build scan command
        scan_config = {
            "scan_id": config.scan_id,
            "command": "start",
            "app_path": config.app_path,
            "app_package": config.app_package,
            "platform": config.platform,
            "ssl_bypass": config.ssl_bypass,
            "crawl_enabled": config.crawl_enabled,
            "crawl_duration": config.crawl_duration,
            "target_hosts": config.target_hosts,
            "exclude_paths": config.exclude_paths,
            "auth_enabled": config.auth_enabled,
            "auth_config": config.auth_config
        }
        
        # Send to agent
        success = await self.agent_manager.start_scan_on_agent(
            agent_id=self.agent_id,
            scan_id=self.scan_id,
            scan_config=scan_config
        )
        
        if success:
            self._phase = "scanning"
        
        return success
    
    async def stop_scan(self):
        """Stop the scan"""
        logger.info(f"Stopping remote scan {self.scan_id}")
        self._running = False
        
        await self.agent_manager.stop_scan_on_agent(self.scan_id)
        self._phase = "stopped"
    
    async def _handle_traffic(self, scan_id: str, traffic_data: dict):
        """Handle traffic captured by agent"""
        if scan_id != self.scan_id:
            return
        
        logger.debug(f"Received traffic: {traffic_data.get('method')} {traffic_data.get('url')}")
        
        # Store in request store
        try:
            request_id = await self._request_store.add_request(
                url=traffic_data.get("url", ""),
                method=traffic_data.get("method", "GET"),
                headers=traffic_data.get("headers", {}),
                body=traffic_data.get("body", ""),
                source="remote_agent",
                frida_hook=traffic_data.get("frida_hook", ""),
                app_package=traffic_data.get("app_package", ""),
                response_status=traffic_data.get("response_status"),
                response_headers=traffic_data.get("response_headers"),
                response_body=traffic_data.get("response_body")
            )
            
            if self._on_traffic:
                await self._on_traffic(request_id, traffic_data)
                
        except Exception as e:
            logger.error(f"Failed to store traffic: {e}")
    
    async def execute_attack(
        self,
        request_id: str,
        scanner_name: str,
        modified_request: dict,
        payload: str = "",
        injection_point: str = "",
        parameter_name: str = ""
    ) -> Optional[dict]:
        """
        Execute attack on remote agent.
        
        Sends modified request to agent, waits for response.
        
        Args:
            request_id: Original request ID
            scanner_name: Scanner name (sqli, xss, etc.)
            modified_request: Modified request data (url, method, headers, body)
            payload: Attack payload
            injection_point: Where payload was injected
            parameter_name: Parameter name if applicable
            
        Returns:
            Response dict or None if failed
        """
        attack_id = f"atk_{uuid.uuid4().hex[:8]}"
        
        # Create attack request
        attack_data = {
            "attack_id": attack_id,
            "request_id": request_id,
            "scanner_name": scanner_name,
            "url": modified_request.get("url"),
            "method": modified_request.get("method", "GET"),
            "headers": modified_request.get("headers", {}),
            "body": modified_request.get("body", ""),
            "payload": payload,
            "injection_point": injection_point,
            "parameter_name": parameter_name,
            "timeout": 30
        }
        
        # Create future for response
        response_future = asyncio.get_event_loop().create_future()
        self._pending_attacks[attack_id] = response_future
        
        try:
            # Send to agent
            success = await self.agent_manager.send_attack_to_agent(
                scan_id=self.scan_id,
                attack_request=attack_data
            )
            
            if not success:
                logger.error(f"Failed to send attack to agent")
                return None
            
            # Wait for response (with timeout)
            response = await asyncio.wait_for(response_future, timeout=60)
            return response
            
        except asyncio.TimeoutError:
            logger.warning(f"Attack timeout: {attack_id}")
            return None
        finally:
            self._pending_attacks.pop(attack_id, None)
    
    async def execute_attack_batch(
        self,
        attacks: List[dict]
    ) -> List[Optional[dict]]:
        """Execute multiple attacks in parallel"""
        tasks = []
        for attack in attacks:
            task = self.execute_attack(
                request_id=attack["request_id"],
                scanner_name=attack["scanner_name"],
                modified_request=attack["modified_request"],
                payload=attack.get("payload", ""),
                injection_point=attack.get("injection_point", ""),
                parameter_name=attack.get("parameter_name", "")
            )
            tasks.append(task)
        
        return await asyncio.gather(*tasks, return_exceptions=True)
    
    def handle_attack_response(self, response_data: dict):
        """Handle attack response from agent"""
        attack_id = response_data.get("attack_id")
        future = self._pending_attacks.get(attack_id)
        
        if future and not future.done():
            future.set_result(response_data)
    
    async def run_scanner(
        self,
        scanner_class,
        request_filter: Optional[Callable] = None
    ) -> List[dict]:
        """
        Run a scanner on captured traffic.
        
        Args:
            scanner_class: Scanner class to instantiate
            request_filter: Optional filter function for requests
            
        Returns:
            List of findings
        """
        findings = []
        
        # Create scanner instance with remote executor
        scanner = scanner_class(
            scan_id=self.scan_id,
            request_store=self._request_store,
            remote_executor=self
        )
        
        # Run scanner
        async for finding in scanner.scan():
            findings.append(finding)
            
            if self._on_finding:
                await self._on_finding(finding)
        
        return findings
    
    async def get_captured_requests(self, limit: int = 100) -> List[dict]:
        """Get captured requests from store"""
        if not self._request_store:
            return []
        
        requests = []
        async for req in self._request_store.iter_all(limit=limit):
            requests.append(req.to_dict())
        
        return requests
    
    async def get_stats(self) -> dict:
        """Get scan statistics"""
        stats = {
            "scan_id": self.scan_id,
            "agent_id": self.agent_id,
            "phase": self._phase,
            "running": self._running,
            "pending_attacks": len(self._pending_attacks)
        }
        
        if self._request_store:
            stats["total_requests"] = await self._request_store.count_all()
            stats["processed_requests"] = await self._request_store.count_processed()
        
        return stats
    
    async def cleanup(self):
        """Cleanup resources"""
        logger.info(f"Cleaning up remote executor for scan {self.scan_id}")
        
        # Cancel pending attacks
        for future in self._pending_attacks.values():
            if not future.done():
                future.cancel()
        
        # Close request store
        if self._request_store:
            await self._request_store.close()
        
        self._running = False
    
    # === Callbacks ===
    
    def set_traffic_callback(self, callback: Callable):
        self._on_traffic = callback
    
    def set_finding_callback(self, callback: Callable):
        self._on_finding = callback
    
    def set_progress_callback(self, callback: Callable):
        self._on_progress = callback


class HybridMobileScanOrchestrator:
    """
    Orchestrator that supports both local and remote mobile scanning.
    
    Modes:
    - LOCAL: Traditional mode - emulator runs locally on server
    - REMOTE: Agent mode - emulator runs on client, traffic relayed to server
    - STATIC_ONLY: No emulator - only static analysis
    
    Automatically selects mode based on:
    1. User preference
    2. Available agents
    3. Server capabilities
    """
    
    def __init__(self, config: dict):
        self.config = config
        self.mode = config.get("mode", "auto")  # local, remote, static_only, auto
        self.scan_id = config.get("scan_id", f"mob_{uuid.uuid4().hex[:8]}")
        
        # Components
        self._local_orchestrator = None
        self._remote_executor = None
        
        # Results
        self.findings = []
        self.endpoints = []
    
    async def run(self) -> dict:
        """Run mobile scan in appropriate mode"""
        
        # Auto-detect mode
        if self.mode == "auto":
            self.mode = await self._detect_best_mode()
        
        logger.info(f"Running mobile scan in {self.mode} mode")
        
        if self.mode == "remote":
            return await self._run_remote_scan()
        elif self.mode == "local":
            return await self._run_local_scan()
        else:
            return await self._run_static_only()
    
    async def _detect_best_mode(self) -> str:
        """Detect best execution mode"""
        user_id = self.config.get("user_id")
        
        # Check for connected agents
        from core.mobile_agent_server import mobile_agent_manager
        
        if user_id:
            agents = mobile_agent_manager.get_user_agents(user_id)
            idle_agents = [a for a in agents if a.state.value == "idle"]
            
            if idle_agents:
                logger.info(f"Found {len(idle_agents)} idle agents, using remote mode")
                self.config["agent_id"] = idle_agents[0].agent_id
                return "remote"
        
        # Check if local emulator is available
        # (server-side emulator - expensive but possible)
        if self._can_run_local_emulator():
            return "local"
        
        # Fall back to static-only
        return "static_only"
    
    def _can_run_local_emulator(self) -> bool:
        """Check if server can run local emulator"""
        # This would check server resources, virtualization support, etc.
        # For now, return False to prefer remote mode
        return False
    
    async def _run_remote_scan(self) -> dict:
        """Run scan via remote agent"""
        agent_id = self.config.get("agent_id")
        
        if not agent_id:
            raise ValueError("No agent_id specified for remote scan")
        
        # Create remote executor
        self._remote_executor = RemoteMobileExecutor(
            scan_id=self.scan_id,
            agent_id=agent_id
        )
        
        await self._remote_executor.initialize()
        
        # Build config
        remote_config = RemoteMobileScanConfig(
            scan_id=self.scan_id,
            agent_id=agent_id,
            app_path=self.config.get("app_path", ""),
            app_package=self.config.get("app_package", ""),
            platform=self.config.get("platform", "android"),
            ssl_bypass=self.config.get("ssl_bypass", True),
            crawl_enabled=self.config.get("crawl_enabled", True),
            target_hosts=self.config.get("target_hosts", [])
        )
        
        try:
            # Start scan on agent
            success = await self._remote_executor.start_scan(remote_config)
            
            if not success:
                raise RuntimeError("Failed to start scan on agent")
            
            # Wait for traffic and run scanners
            # (This would be event-driven in production)
            await asyncio.sleep(remote_config.crawl_duration or 120)
            
            # Run attack scanners on captured traffic
            findings = await self._run_remote_scanners()
            
            return {
                "scan_id": self.scan_id,
                "mode": "remote",
                "status": "completed",
                "findings": findings,
                "stats": await self._remote_executor.get_stats()
            }
            
        finally:
            await self._remote_executor.cleanup()
    
    async def _run_local_scan(self) -> dict:
        """Run scan with local emulator"""
        from attacks.mobile.orchestration.mobile_orchestrator import (
            MobilePenTestOrchestrator,
            MobileScanConfig
        )
        
        # Build config
        local_config = MobileScanConfig(
            app_path=self.config.get("app_path", ""),
            platform=self.config.get("platform", "auto"),
            ssl_pinned=True,
            frida_bypass_enabled=self.config.get("ssl_bypass", True),
            use_emulator=True,
            crawl_enabled=self.config.get("crawl_enabled", True),
            attacks_enabled=True
        )
        
        self._local_orchestrator = MobilePenTestOrchestrator(local_config)
        return await self._local_orchestrator.run()
    
    async def _run_static_only(self) -> dict:
        """Run static analysis only (no emulator)"""
        from attacks.mobile.static.static_analyzer import StaticAnalyzer
        
        logger.info("Running static-only analysis (no emulator available)")
        
        analyzer = StaticAnalyzer()
        findings = await analyzer.analyze(self.config.get("app_path", ""))
        
        return {
            "scan_id": self.scan_id,
            "mode": "static_only",
            "status": "completed",
            "findings": findings,
            "note": "Dynamic analysis skipped - no emulator/agent available"
        }
    
    async def _run_remote_scanners(self) -> List[dict]:
        """Run attack scanners on remotely captured traffic"""
        # Import scanners
        from attacks.mobile.base_mobile_scanner import get_all_mobile_scanners
        
        all_findings = []
        scanners = get_all_mobile_scanners()
        
        for scanner_class in scanners:
            try:
                findings = await self._remote_executor.run_scanner(scanner_class)
                all_findings.extend(findings)
            except Exception as e:
                logger.error(f"Scanner {scanner_class.__name__} failed: {e}")
        
        return all_findings
