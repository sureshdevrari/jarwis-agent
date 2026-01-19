#!/usr/bin/env python3
"""
Jarwis Universal Security Agent - Standalone

Connects to Jarwis server and executes security testing commands.
"""

import argparse
import asyncio
import json
import logging
import os
import platform
import socket
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import aiohttp
import websockets
import yaml


class JarwisAgent:
    """Standalone Jarwis Security Agent"""
    
    def __init__(self, server_url: str, data_dir: Optional[str] = None):
        self.server_url = server_url
        self.data_dir = Path(data_dir) if data_dir else self._default_data_dir()
        self.agent_id = self._get_or_create_agent_id()
        self.ws = None
        self.running = False
        self.logger = logging.getLogger('JarwisAgent')
        
    def _default_data_dir(self) -> Path:
        if platform.system() == 'Windows':
            return Path(os.environ.get('APPDATA', '')) / 'jarwis-agent'
        elif platform.system() == 'Darwin':
            return Path.home() / 'Library' / 'Application Support' / 'jarwis-agent'
        else:
            return Path.home() / '.jarwis-agent'
    
    def _get_or_create_agent_id(self) -> str:
        id_file = self.data_dir / 'agent_id'
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        if id_file.exists():
            return id_file.read_text().strip()
        
        agent_id = str(uuid.uuid4())
        id_file.write_text(agent_id)
        return agent_id
    
    def get_system_info(self) -> Dict[str, Any]:
        """Gather system information"""
        try:
            import psutil
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            cpu_count = psutil.cpu_count()
        except ImportError:
            memory = type('obj', (object,), {'total': 0, 'available': 0})()
            disk = type('obj', (object,), {'total': 0, 'free': 0})()
            cpu_count = os.cpu_count() or 1
        
        return {
            'agent_id': self.agent_id,
            'agent_version': '1.0.0',
            'hostname': socket.gethostname(),
            'platform': platform.system(),
            'platform_version': platform.version(),
            'architecture': platform.machine(),
            'python_version': platform.python_version(),
            'cpu_count': cpu_count,
            'memory_total_gb': round(memory.total / (1024**3), 2),
            'memory_available_gb': round(memory.available / (1024**3), 2),
            'disk_total_gb': round(disk.total / (1024**3), 2),
            'disk_free_gb': round(disk.free / (1024**3), 2),
            'capabilities': self.get_capabilities(),
        }
    
    def get_capabilities(self) -> Dict[str, bool]:
        """Check available capabilities"""
        caps = {
            'web_scanning': True,
            'network_scanning': True,
            'mobile_static': False,
            'mobile_dynamic': False,
            'traffic_intercept': False,
        }
        
        # Check for optional tools
        try:
            import frida
            caps['mobile_dynamic'] = True
        except ImportError:
            pass
        
        try:
            from mitmproxy import options
            caps['traffic_intercept'] = True
        except ImportError:
            pass
        
        # Check for common tools
        tools = ['nmap', 'nikto', 'sqlmap', 'nuclei', 'adb']
        for tool in tools:
            try:
                result = subprocess.run(
                    [tool, '--version'] if tool != 'adb' else [tool, 'version'],
                    capture_output=True, timeout=5
                )
                caps[f'tool_{tool}'] = result.returncode == 0
            except:
                caps[f'tool_{tool}'] = False
        
        return caps
    
    async def connect(self):
        """Connect to Jarwis server"""
        self.logger.info(f"Connecting to {self.server_url}")
        
        try:
            self.ws = await websockets.connect(
                self.server_url,
                ping_interval=30,
                ping_timeout=10,
            )
            self.running = True
            
            # Send registration
            await self.send({
                'type': 'register',
                'data': self.get_system_info(),
            })
            
            self.logger.info("Connected and registered successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            return False
    
    async def send(self, message: Dict[str, Any]):
        """Send message to server"""
        if self.ws:
            await self.ws.send(json.dumps(message))
    
    async def handle_message(self, message: str):
        """Handle incoming message from server"""
        try:
            data = json.loads(message)
            msg_type = data.get('type', '')
            
            if msg_type == 'ping':
                await self.send({'type': 'pong'})
                
            elif msg_type == 'command':
                result = await self.execute_command(data.get('command', {}))
                await self.send({
                    'type': 'result',
                    'command_id': data.get('command_id'),
                    'result': result,
                })
                
            elif msg_type == 'status':
                await self.send({
                    'type': 'status_response',
                    'data': self.get_system_info(),
                })
                
            else:
                self.logger.debug(f"Unknown message type: {msg_type}")
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Invalid JSON: {e}")
    
    async def execute_command(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a command from the server"""
        cmd_type = command.get('type', '')
        self.logger.info(f"Executing command: {cmd_type}")
        
        try:
            if cmd_type == 'shell':
                return await self._run_shell(command.get('cmd', ''))
            elif cmd_type == 'http_request':
                return await self._http_request(command)
            elif cmd_type == 'scan_ports':
                return await self._scan_ports(command)
            elif cmd_type == 'file_read':
                return self._read_file(command.get('path', ''))
            elif cmd_type == 'check_capabilities':
                return {'capabilities': self.get_capabilities()}
            else:
                return {'error': f'Unknown command type: {cmd_type}'}
                
        except Exception as e:
            return {'error': str(e)}
    
    async def _run_shell(self, cmd: str) -> Dict[str, Any]:
        """Run a shell command"""
        # Security: Only allow specific commands
        allowed_prefixes = ['nmap', 'nikto', 'sqlmap', 'nuclei', 'curl', 'wget', 'ping', 'traceroute']
        cmd_lower = cmd.lower().strip()
        
        if not any(cmd_lower.startswith(p) for p in allowed_prefixes):
            return {'error': 'Command not allowed', 'allowed': allowed_prefixes}
        
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            
            return {
                'stdout': stdout.decode('utf-8', errors='replace'),
                'stderr': stderr.decode('utf-8', errors='replace'),
                'returncode': proc.returncode,
            }
        except asyncio.TimeoutError:
            return {'error': 'Command timed out'}
    
    async def _http_request(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Make an HTTP request"""
        async with aiohttp.ClientSession() as session:
            method = command.get('method', 'GET').upper()
            url = command.get('url', '')
            headers = command.get('headers', {})
            data = command.get('data')
            
            async with session.request(method, url, headers=headers, data=data, ssl=False) as resp:
                return {
                    'status': resp.status,
                    'headers': dict(resp.headers),
                    'body': await resp.text(),
                }
    
    async def _scan_ports(self, command: Dict[str, Any]) -> Dict[str, Any]:
        """Basic port scanning"""
        target = command.get('target', '')
        ports = command.get('ports', [80, 443, 22, 21, 25, 3306, 5432])
        
        results = []
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))
                results.append({
                    'port': port,
                    'open': result == 0,
                })
                sock.close()
            except:
                results.append({'port': port, 'open': False, 'error': True})
        
        return {'target': target, 'ports': results}
    
    def _read_file(self, path: str) -> Dict[str, Any]:
        """Read a file (limited to agent data directory)"""
        file_path = Path(path)
        
        # Security: Only allow reading from agent data directory
        try:
            file_path.resolve().relative_to(self.data_dir.resolve())
        except ValueError:
            return {'error': 'Access denied - path outside data directory'}
        
        if not file_path.exists():
            return {'error': 'File not found'}
        
        return {'content': file_path.read_text()}
    
    async def run(self):
        """Main run loop"""
        retry_delay = 5
        max_retry_delay = 60
        
        while True:
            if await self.connect():
                retry_delay = 5  # Reset on successful connection
                
                try:
                    async for message in self.ws:
                        await self.handle_message(message)
                except websockets.ConnectionClosed:
                    self.logger.warning("Connection closed")
                except Exception as e:
                    self.logger.error(f"Error: {e}")
            
            self.logger.info(f"Reconnecting in {retry_delay}s...")
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, max_retry_delay)
    
    def stop(self):
        """Stop the agent"""
        self.running = False
        if self.ws:
            asyncio.create_task(self.ws.close())


def setup_logging(verbose: bool = False):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    logging.getLogger('websockets').setLevel(logging.WARNING)


def check_capabilities():
    """Print available capabilities"""
    agent = JarwisAgent('ws://localhost', None)
    info = agent.get_system_info()
    
    print("\n=== Jarwis Agent System Info ===")
    print(f"Agent ID: {info['agent_id']}")
    print(f"Hostname: {info['hostname']}")
    print(f"Platform: {info['platform']} {info['platform_version']}")
    print(f"Architecture: {info['architecture']}")
    print(f"Python: {info['python_version']}")
    print(f"CPU Cores: {info['cpu_count']}")
    print(f"Memory: {info['memory_available_gb']:.1f} / {info['memory_total_gb']:.1f} GB")
    print(f"Disk: {info['disk_free_gb']:.1f} / {info['disk_total_gb']:.1f} GB")
    
    print("\n=== Capabilities ===")
    for cap, available in info['capabilities'].items():
        status = "" if available else ""
        print(f"  {status} {cap}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description='Jarwis Universal Security Agent',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  jarwis-agent --server wss://jarwis.io/agent/ws/TOKEN
  jarwis-agent --check
  jarwis-agent --server wss://localhost:8000/agent/ws/TOKEN -v
'''
    )
    parser.add_argument('--server', '-s', help='Jarwis server WebSocket URL')
    parser.add_argument('--data-dir', '-d', help='Data directory for agent state')
    parser.add_argument('--check', '-c', action='store_true', help='Check system capabilities')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--version', action='version', version='Jarwis Agent 1.0.0')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    if args.check:
        check_capabilities()
        return
    
    if not args.server:
        parser.print_help()
        print("\nError: --server is required unless using --check")
        sys.exit(1)
    
    agent = JarwisAgent(args.server, args.data_dir)
    
    print(f"""

              JARWIS UNIVERSAL SECURITY AGENT              
                       Version 1.0.0                       

    
Agent ID: {agent.agent_id}
Server:   {args.server}
Data Dir: {agent.data_dir}
    
Connecting...
""")
    
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        print("\nShutting down...")
        agent.stop()


if __name__ == '__main__':
    main()
