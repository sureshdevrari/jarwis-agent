"""
Jarwis AGI Pen Test - Network Scan API Routes
Start network scans, manage agents, get results
"""

import uuid as uuid_lib
import logging
import ipaddress
from datetime import datetime
from typing import Optional, List
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.models import User
from database.dependencies import get_current_active_user
from database.subscription import (
    enforce_subscription_limit,
    SubscriptionAction,
    increment_usage_counter,
)
from database import crud

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/network", tags=["Network Security Scans"])


# ========== Available Tools Endpoint ==========

@router.get("/tools")
async def get_available_tools():
    """
    Get list of available network security tools on the server.
    Tools are checked by phase and availability.
    """
    import shutil
    
    # Define all tools by phase
    tools_by_phase = {
        'discovery': [
            {'name': 'netdiscover', 'description': 'ARP-based network discovery'},
            {'name': 'arp-scan', 'description': 'Fast ARP host discovery'},
        ],
        'port_scan': [
            {'name': 'nmap', 'description': 'Network exploration and security auditing'},
            {'name': 'masscan', 'description': 'Ultra-fast TCP port scanner'},
            {'name': 'rustscan', 'description': 'Fast Rust-based port scanner'},
        ],
        'service_enum': [
            {'name': 'nmap', 'description': 'Service/version detection (-sV)'},
            {'name': 'snmpwalk', 'description': 'SNMP enumeration'},
            {'name': 'dnsrecon', 'description': 'DNS reconnaissance'},
        ],
        'vuln_scan': [
            {'name': 'nuclei', 'description': 'Template-based vulnerability scanner'},
            {'name': 'openvas', 'description': 'Greenbone vulnerability scanner'},
            {'name': 'nmap', 'description': 'Vulners NSE script for CVE detection'},
        ],
        'ssl_audit': [
            {'name': 'sslscan', 'description': 'SSL/TLS configuration scanner'},
            {'name': 'testssl.sh', 'description': 'Comprehensive TLS testing'},
            {'name': 'sslyze', 'description': 'Python-native SSL analyzer'},
        ],
        'exploitation': [
            {'name': 'crackmapexec', 'description': 'AD/SMB/WinRM exploitation'},
            {'name': 'netexec', 'description': 'CrackMapExec successor'},
            {'name': 'impacket-secretsdump', 'description': 'Windows credential extraction'},
            {'name': 'msfconsole', 'description': 'Metasploit framework'},
        ],
        'traffic_analysis': [
            {'name': 'zeek', 'description': 'Network traffic analysis'},
            {'name': 'suricata', 'description': 'Network IDS/IPS'},
            {'name': 'tshark', 'description': 'Wireshark CLI'},
        ],
    }
    
    # Check availability
    result = {}
    total_available = 0
    total_tools = 0
    
    for phase, tools in tools_by_phase.items():
        phase_tools = []
        for tool in tools:
            available = shutil.which(tool['name']) is not None
            phase_tools.append({
                **tool,
                'available': available
            })
            total_tools += 1
            if available:
                total_available += 1
        result[phase] = phase_tools
    
    # Check Python libraries
    python_libs = []
    try:
        import sslyze
        python_libs.append({'name': 'sslyze', 'available': True})
    except ImportError:
        python_libs.append({'name': 'sslyze', 'available': False})
    
    try:
        from gvm.connections import TLSConnection
        python_libs.append({'name': 'gvm-tools', 'available': True})
    except ImportError:
        python_libs.append({'name': 'gvm-tools', 'available': False})
    
    try:
        import impacket
        python_libs.append({'name': 'impacket', 'available': True})
    except ImportError:
        python_libs.append({'name': 'impacket', 'available': False})
    
    return {
        'phases': result,
        'python_libraries': python_libs,
        'summary': {
            'total_tools': total_tools,
            'available': total_available,
            'missing': total_tools - total_available,
        },
        'install_command': 'python attacks/network/install_tools.py --check'
    }


# ========== Request/Response Models ==========

class SSHCredential(BaseModel):
    """SSH credential for authenticated scanning"""
    username: str
    auth_method: str = Field(default="password", pattern="^(password|key|key_passphrase)$")
    password: Optional[str] = None
    private_key: Optional[str] = None
    private_key_passphrase: Optional[str] = None
    port: int = 22
    known_hosts_checking: bool = False
    privilege_escalation: Optional[str] = Field(default=None, pattern="^(sudo|su|pbrun|cisco_enable)$")
    escalation_account: Optional[str] = None
    escalation_password: Optional[str] = None


class WindowsCredential(BaseModel):
    """Windows/SMB credential"""
    username: str
    password: str
    domain: Optional[str] = None
    auth_method: str = Field(default="password", pattern="^(password|ntlm|kerberos)$")


class SNMPCredential(BaseModel):
    """SNMP credential"""
    version: str = Field(default="v2c", pattern="^(v1|v2c|v3)$")
    community_string: Optional[str] = None
    security_level: Optional[str] = None
    username: Optional[str] = None
    auth_protocol: Optional[str] = None
    auth_password: Optional[str] = None
    privacy_protocol: Optional[str] = None
    privacy_password: Optional[str] = None


class DatabaseCredential(BaseModel):
    """Database credential"""
    db_type: str = Field(..., pattern="^(mysql|postgresql|mssql|oracle|mongodb)$")
    username: str
    password: str
    port: Optional[int] = None
    database: Optional[str] = None
    sid: Optional[str] = None
    auth_type: str = Field(default="password", pattern="^(password|windows)$")


class NetworkCredentials(BaseModel):
    """All network scan credentials"""
    enabled: bool = False
    ssh: Optional[SSHCredential] = None
    windows: Optional[WindowsCredential] = None
    snmp: Optional[SNMPCredential] = None
    database: Optional[DatabaseCredential] = None


class NetworkScanRequest(BaseModel):
    """Network scan request"""
    # Target specification
    targets: str = Field(..., description="IP address, subnet (CIDR), or comma-separated list")
    exclude_targets: Optional[str] = Field(None, description="IPs to exclude from scan")
    
    # Scan profile (NEW - uses orchestrator phases)
    profile: str = Field(
        default="standard", 
        pattern="^(quick|standard|comprehensive|stealth|web|internal)$",
        description="Scan profile: quick, standard, comprehensive, stealth, web, or internal"
    )
    
    # Discovery settings
    host_discovery: bool = True
    ping_methods: List[str] = Field(default=["tcp_syn"])
    
    # Port scanning
    port_scan_enabled: bool = True
    port_range: str = Field(default="common", description="'common', '1-1024', 'all', or custom range")
    scan_type: str = Field(default="connect", pattern="^(syn|connect|udp|comprehensive)$")
    
    # Detection
    service_detection: bool = True
    os_detection: bool = True
    version_detection: bool = True
    
    # Vulnerability scanning
    vuln_scan_enabled: bool = True
    cve_check: bool = True
    compliance_check: bool = False
    
    # Credentials (Nessus-style)
    credentials: Optional[NetworkCredentials] = None
    
    # Performance
    max_concurrent_hosts: int = Field(default=10, ge=1, le=100)
    timeout_per_host: int = Field(default=300, ge=30, le=3600)
    rate_limit: int = Field(default=100, ge=1, le=1000)
    
    # Safe mode
    safe_checks: bool = True
    
    # Private network scanning via agent
    use_agent: bool = False
    agent_id: Optional[str] = None


class NetworkScanResponse(BaseModel):
    """Network scan response"""
    scan_id: str
    status: str
    message: str
    targets_count: int
    use_agent: bool


class NetworkFinding(BaseModel):
    """Network scan finding"""
    id: str
    category: str
    severity: str
    title: str
    description: str
    ip_address: str
    port: Optional[int] = None
    protocol: str = "tcp"
    service: str = ""
    version: str = ""
    cve_id: str = ""
    cvss_score: float = 0.0
    evidence: str = ""
    remediation: str = ""


class AgentRegistration(BaseModel):
    """Agent registration request"""
    agent_name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = None
    network_ranges: List[str] = Field(..., description="Private network ranges this agent can scan")


class AgentResponse(BaseModel):
    """Agent registration response"""
    agent_id: str
    agent_key: str  # API key for agent authentication
    name: str
    network_ranges: List[str]
    created_at: datetime


# ========== Private IP Validation ==========

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_private_target(target: str) -> bool:
    """Check if target contains private IP addresses"""
    try:
        if '/' in target:
            network = ipaddress.ip_network(target, strict=False)
            return any(network.overlaps(priv) for priv in PRIVATE_NETWORKS)
        else:
            ip = ipaddress.ip_address(target)
            return any(ip in priv for priv in PRIVATE_NETWORKS)
    except ValueError:
        return False


def validate_network_targets(targets: str) -> tuple[bool, str, int]:
    """
    Validate network targets and count hosts.
    Returns (is_valid, error_message, host_count)
    """
    total_hosts = 0
    
    for target in targets.split(','):
        target = target.strip()
        if not target:
            continue
        
        try:
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                total_hosts += network.num_addresses
            elif '-' in target and target.count('.') == 3:
                # Range like 192.168.1.1-10
                base, end_part = target.rsplit('.', 1)
                if '-' in end_part:
                    start, end = end_part.split('-')
                    total_hosts += int(end) - int(start) + 1
            else:
                # Single IP or hostname
                total_hosts += 1
        except ValueError as e:
            return False, f"Invalid target '{target}': {str(e)}", 0
    
    if total_hosts > 65536:
        return False, "Too many targets (max 65536 hosts per scan)", 0
    
    return True, "", total_hosts


# ========== In-memory stores (would be Redis in production) ==========
network_scan_jobs: dict = {}
agent_registry: dict = {}


# ========== Endpoints ==========

@router.post("/scan", response_model=NetworkScanResponse, status_code=status.HTTP_201_CREATED)
async def start_network_scan(
    scan_request: NetworkScanRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Start a new network security scan.
    
    For private IP ranges (10.x, 172.16-31.x, 192.168.x), you must use a Jarwis Agent
    deployed inside your network.
    
    **Credential-based scanning** enables deeper security checks:
    - SSH: Linux/Unix system audits
    - Windows: Windows policy and patch checks
    - SNMP: Network device configuration
    - Database: Database security assessment
    """
    # ========== SUBSCRIPTION CHECK ==========
    await enforce_subscription_limit(db, current_user, SubscriptionAction.START_SCAN)
    
    # Check network scan access (may be premium feature)
    # await enforce_subscription_limit(db, current_user, SubscriptionAction.ACCESS_NETWORK_SCAN)
    
    # ========== VALIDATE TARGETS ==========
    is_valid, error_msg, host_count = validate_network_targets(scan_request.targets)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )
    
    # ========== CHECK FOR PRIVATE IPs ==========
    has_private = False
    for target in scan_request.targets.split(','):
        target = target.strip()
        if is_private_target(target):
            has_private = True
            break
    
    if has_private and not scan_request.use_agent:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Private IP ranges require a Jarwis Agent. Deploy an agent in your network and set use_agent=true with agent_id."
        )
    
    # Validate agent if specified
    if scan_request.use_agent:
        if not scan_request.agent_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="agent_id is required when use_agent is true"
            )
        
        # Check agent exists and belongs to user
        agent = agent_registry.get(scan_request.agent_id)
        if not agent or agent.get('user_id') != str(current_user.id):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Agent not found or does not belong to you"
            )
    
    # ========== CREATE SCAN JOB ==========
    scan_id = str(uuid_lib.uuid4())[:8]
    
    network_scan_jobs[scan_id] = {
        'status': 'queued',
        'progress': 0,
        'user_id': str(current_user.id),
        'created_at': datetime.utcnow().isoformat(),
        'config': scan_request.model_dump(),
        'findings': [],
        'hosts_scanned': 0,
        'hosts_total': host_count,
    }
    
    # Increment usage
    await increment_usage_counter(db, current_user.id, "scans")
    
    # Start scan in background
    background_tasks.add_task(
        run_network_scan,
        scan_id=scan_id,
        config=scan_request.model_dump(),
        user_id=str(current_user.id)
    )
    
    return NetworkScanResponse(
        scan_id=scan_id,
        status="queued",
        message=f"Network scan started for {host_count} target(s)",
        targets_count=host_count,
        use_agent=scan_request.use_agent
    )


@router.get("/scan/{scan_id}")
async def get_network_scan_status(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Get status and findings of a network scan"""
    job = network_scan_jobs.get(scan_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if job['user_id'] != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    # Build comprehensive response
    response = {
        'scan_id': scan_id,
        'status': job['status'],
        'progress': job.get('progress', 0),
        'current_phase': job.get('current_phase', ''),
        'phase_message': job.get('phase_message', ''),
        'hosts_scanned': job.get('hosts_scanned', 0),
        'hosts_total': job.get('hosts_total', 0),
        'findings_count': len(job.get('findings', [])),
        'findings': job.get('findings', [])[:100],  # Limit response size
        'created_at': job.get('created_at'),
        'last_update': job.get('last_update'),
    }
    
    # Add completed phases if available
    if 'phases_completed' in job:
        response['phases_completed'] = job['phases_completed']
    
    # Add tool execution info
    if 'tools_executed' in job:
        response['tools_executed'] = job['tools_executed']
    
    # Add severity summary if completed
    if 'severity_summary' in job:
        response['severity_summary'] = job['severity_summary']
    
    # Add open ports and services if available
    if 'open_ports' in job:
        response['open_ports'] = job['open_ports']
    
    if 'services' in job:
        response['services'] = job['services']
    
    # Add errors if any
    if 'errors' in job and job['errors']:
        response['errors'] = job['errors']
    
    return response


@router.get("/scan/{scan_id}/findings")
async def get_network_scan_findings(
    scan_id: str,
    severity: Optional[str] = None,
    tool: Optional[str] = None,
    page: int = 1,
    per_page: int = 50,
    current_user: User = Depends(get_current_active_user)
):
    """Get paginated findings from a network scan with filters"""
    job = network_scan_jobs.get(scan_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if job['user_id'] != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    findings = job.get('findings', [])
    
    # Apply filters
    if severity:
        findings = [f for f in findings if f.get('severity') == severity]
    
    if tool:
        findings = [f for f in findings if f.get('tool') == tool]
    
    # Paginate
    total = len(findings)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = findings[start:end]
    
    return {
        'scan_id': scan_id,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page,
        'findings': paginated
    }


@router.delete("/scan/{scan_id}")
async def stop_network_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Stop a running network scan"""
    job = network_scan_jobs.get(scan_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    if job['user_id'] != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    if job['status'] in ['completed', 'error', 'stopped']:
        raise HTTPException(status_code=400, detail="Scan is not running")
    
    job['status'] = 'stopped'
    
    return {'message': 'Scan stopped', 'scan_id': scan_id}


# ========== AGENT MANAGEMENT ==========

@router.post("/agents", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def register_agent(
    agent_data: AgentRegistration,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new Jarwis Agent for private network scanning.
    
    The agent must be deployed inside your private network to scan internal IPs.
    
    Steps:
    1. Register agent here to get agent_id and agent_key
    2. Download Jarwis Agent from dashboard
    3. Install agent in your network
    4. Configure agent with agent_id and agent_key
    5. Start scans with use_agent=true
    """
    # Validate network ranges
    for range_str in agent_data.network_ranges:
        try:
            ipaddress.ip_network(range_str, strict=False)
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid network range: {range_str}"
            )
    
    agent_id = f"agent-{uuid_lib.uuid4().hex[:12]}"
    agent_key = f"jarwis_agent_{uuid_lib.uuid4().hex}"
    
    agent_registry[agent_id] = {
        'id': agent_id,
        'name': agent_data.agent_name,
        'description': agent_data.description,
        'network_ranges': agent_data.network_ranges,
        'user_id': str(current_user.id),
        'created_at': datetime.utcnow().isoformat(),
        'last_seen': None,
        'status': 'offline',
        'version': None,
    }
    
    logger.info(f"Agent registered: {agent_id} for user {current_user.email}")
    
    return AgentResponse(
        agent_id=agent_id,
        agent_key=agent_key,
        name=agent_data.agent_name,
        network_ranges=agent_data.network_ranges,
        created_at=datetime.utcnow()
    )


@router.get("/agents")
async def list_agents(
    current_user: User = Depends(get_current_active_user)
):
    """List all agents registered by the current user"""
    user_agents = [
        {
            'id': agent['id'],
            'name': agent['name'],
            'network_ranges': agent['network_ranges'],
            'status': agent['status'],
            'last_seen': agent['last_seen'],
            'version': agent['version'],
        }
        for agent in agent_registry.values()
        if agent['user_id'] == str(current_user.id)
    ]
    
    return {'agents': user_agents, 'total': len(user_agents)}


@router.delete("/agents/{agent_id}")
async def delete_agent(
    agent_id: str,
    current_user: User = Depends(get_current_active_user)
):
    """Delete a registered agent"""
    agent = agent_registry.get(agent_id)
    
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent['user_id'] != str(current_user.id):
        raise HTTPException(status_code=403, detail="Access denied")
    
    del agent_registry[agent_id]
    
    return {'message': 'Agent deleted', 'agent_id': agent_id}


# ========== AGENT COMMUNICATION (for agent to call) ==========

@router.post("/agents/{agent_id}/heartbeat")
async def agent_heartbeat(
    agent_id: str,
    request: Request
):
    """
    Agent heartbeat endpoint - called by agent to report status.
    Authenticated via agent_key in header.
    """
    agent_key = request.headers.get('X-Agent-Key')
    if not agent_key:
        raise HTTPException(status_code=401, detail="Agent key required")
    
    agent = agent_registry.get(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # In production, verify agent_key against stored hash
    
    agent['last_seen'] = datetime.utcnow().isoformat()
    agent['status'] = 'online'
    
    # Return any pending scan jobs for this agent
    pending_jobs = [
        job for job in network_scan_jobs.values()
        if job['config'].get('agent_id') == agent_id and job['status'] == 'queued'
    ]
    
    return {
        'status': 'ok',
        'pending_jobs': len(pending_jobs),
        'jobs': [{'scan_id': j['scan_id']} for j in pending_jobs[:5]]
    }


@router.post("/agents/{agent_id}/results")
async def agent_submit_results(
    agent_id: str,
    request: Request
):
    """Agent submits scan results"""
    agent_key = request.headers.get('X-Agent-Key')
    if not agent_key:
        raise HTTPException(status_code=401, detail="Agent key required")
    
    body = await request.json()
    scan_id = body.get('scan_id')
    findings = body.get('findings', [])
    status = body.get('status', 'running')
    progress = body.get('progress', 0)
    
    job = network_scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Update job with results
    job['findings'].extend(findings)
    job['status'] = status
    job['progress'] = progress
    
    return {'status': 'ok', 'findings_received': len(findings)}


# ========== BACKGROUND SCAN TASK ==========

async def run_network_scan(scan_id: str, config: dict, user_id: str):
    """Background task to run network scan using the phase orchestrator"""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    job = network_scan_jobs[scan_id]
    job['status'] = 'running'
    job['scan_id'] = scan_id
    
    try:
        # Use the new orchestrator
        from attacks.network import NetworkOrchestrator, ScanProfile
        
        # Map config to scan profile
        profile_map = {
            'quick': ScanProfile.QUICK,
            'standard': ScanProfile.STANDARD,
            'comprehensive': ScanProfile.COMPREHENSIVE,
            'stealth': ScanProfile.STEALTH,
            'web': ScanProfile.WEB,
            'internal': ScanProfile.INTERNAL,
        }
        
        scan_profile = profile_map.get(config.get('profile', 'standard'), ScanProfile.STANDARD)
        
        # If using agent, job will be picked up by agent heartbeat
        if config.get('use_agent'):
            job['status'] = 'waiting_for_agent'
            logger.info(f"Network scan {scan_id} waiting for agent {config.get('agent_id')}")
            return
        
        # Prepare credentials
        credentials = None
        if config.get('credentials') and config['credentials'].get('enabled'):
            credentials = {
                'ssh': config['credentials'].get('ssh'),
                'windows': config['credentials'].get('windows'),
                'snmp': config['credentials'].get('snmp'),
                'database': config['credentials'].get('database'),
            }
        
        # Progress callback - updates job in real-time
        def on_progress(phase: str, progress: float, message: str):
            job['current_phase'] = phase
            job['progress'] = int(progress * 100)
            job['phase_message'] = message
            job['last_update'] = datetime.utcnow().isoformat()
            logger.debug(f"Scan {scan_id}: Phase {phase} - {int(progress*100)}% - {message}")
        
        # Create orchestrator with sequential execution config
        orchestrator = NetworkOrchestrator({
            'timeout': config.get('timeout_per_host', 300),
            'rate_limit': config.get('rate_limit', 100),
            'mode': 'safe',  # Safe mode by default
        })
        
        job['status'] = 'running'
        job['tools_executed'] = []
        
        state = await orchestrator.run(
            target=config['targets'],
            profile=scan_profile,
            credentials=credentials,
            callback=on_progress
        )
        
        # Convert findings to response format with all details
        job['findings'] = [
            {
                'id': f.id,
                'tool': f.tool,
                'category': f.category,
                'severity': f.severity,
                'title': f.title,
                'description': f.description,
                'ip_address': f.target,
                'port': f.port,
                'protocol': f.protocol,
                'service': f.service,
                'version': f.version,
                'cve_id': f.cve_id,
                'cvss_score': f.cvss_score,
                'evidence': f.evidence,
                'remediation': f.remediation,
                'references': f.references,
                'confidence': f.confidence,
                'metadata': f.metadata if hasattr(f, 'metadata') else {},
            }
            for f in state.findings
        ]
        
        # Collect tools that were executed
        tools_used = set()
        for tool_results in state.results.values():
            for result in tool_results:
                tools_used.add(result.tool)
        
        job['status'] = 'completed'
        job['progress'] = 100
        job['hosts_scanned'] = len(state.live_hosts) or 1
        job['phases_completed'] = [p.value for p in state.completed_phases]
        job['open_ports'] = {h: list(ports) for h, ports in state.open_ports.items()}
        job['services'] = state.services
        job['errors'] = state.errors
        job['tools_executed'] = list(tools_used)
        job['completed_at'] = datetime.utcnow().isoformat()
        
        # Summary statistics
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in job['findings']:
            sev = finding.get('severity', 'info')
            if sev in severity_counts:
                severity_counts[sev] += 1
        job['severity_summary'] = severity_counts
        
        logger.info(f"Network scan {scan_id} completed with {len(state.findings)} findings")
        
    except ImportError as e:
        # Fall back to legacy scanner
        logger.warning(f"Orchestrator import failed, using legacy scanner: {e}")
        await run_network_scan_legacy(scan_id, config, user_id)
        
    except Exception as e:
        logger.error(f"Network scan {scan_id} failed: {e}")
        job['status'] = 'error'
        job['error'] = str(e)


async def run_network_scan_legacy(scan_id: str, config: dict, user_id: str):
    """Legacy scanner fallback"""
    job = network_scan_jobs[scan_id]
    
    try:
        from attacks.network import NetworkSecurityScanner
        from attacks.network.network_scanner import NetworkScanContext
        
        context = NetworkScanContext(
            targets=config['targets'].split(','),
            use_agent=config.get('use_agent', False),
            agent_id=config.get('agent_id'),
            credentials=config.get('credentials') if config.get('credentials', {}).get('enabled') else None
        )
        
        scanner = NetworkSecurityScanner(
            config={'network_config': config},
            context=context
        )
        
        findings = await scanner.scan()
        
        job['findings'] = [
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
            }
            for f in findings
        ]
        
        job['status'] = 'completed'
        job['progress'] = 100
        job['hosts_scanned'] = len(context.discovered_hosts)
        
    except Exception as e:
        logger.error(f"Legacy network scan {scan_id} failed: {e}")
        job['status'] = 'error'
        job['error'] = str(e)
