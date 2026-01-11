"""
Jarwis Correlation Engine - Attack Chain Detection
====================================================

Analyzes relationships between vulnerabilities to detect:
- Attack chains (multiple vulns that combine for greater impact)
- Related vulnerabilities (same root cause)
- Exploitation paths (how attacker could chain vulns)

Uses graph analysis (networkx) for path finding.

Author: Jarwis AI Team
Created: January 2026
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime
from enum import Enum
import logging
import hashlib

try:
    import networkx as nx
    HAS_NETWORKX = True
except ImportError:
    HAS_NETWORKX = False
    nx = None

logger = logging.getLogger(__name__)


class ChainType(Enum):
    """Types of attack chains"""
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ACCOUNT_TAKEOVER = "account_takeover"
    REMOTE_CODE_EXECUTION = "remote_code_execution"
    LATERAL_MOVEMENT = "lateral_movement"
    DENIAL_OF_SERVICE = "denial_of_service"
    INFORMATION_GATHERING = "information_gathering"
    AUTHENTICATION_BYPASS = "authentication_bypass"


class VulnerabilityRelation(Enum):
    """Types of relationships between vulnerabilities"""
    ENABLES = "enables"           # Vuln A enables exploitation of Vuln B
    AMPLIFIES = "amplifies"       # Vuln A makes Vuln B worse
    SAME_ROOT_CAUSE = "same_root_cause"  # Both have same underlying issue
    SAME_ENDPOINT = "same_endpoint"      # Both affect same endpoint
    PREREQUISITE = "prerequisite"        # Vuln A must be exploited before Vuln B


@dataclass
class VulnerabilityNode:
    """A vulnerability as a node in the graph"""
    finding_id: str
    title: str
    category: str  # OWASP category
    severity: str
    url: str
    vuln_type: str  # xss, sqli, csrf, etc.
    
    # Scoring
    exploitability: float = 0.5
    impact: float = 0.5
    
    # Metadata
    parameter: Optional[str] = None
    evidence: Optional[str] = None


@dataclass
class VulnerabilityEdge:
    """A relationship between two vulnerabilities"""
    source_id: str
    target_id: str
    relation: VulnerabilityRelation
    weight: float  # Strength of relationship (0-1)
    description: str


@dataclass
class AttackChain:
    """A detected attack chain"""
    chain_id: str
    chain_type: ChainType
    findings: List[str]  # List of finding IDs in order
    
    # Impact assessment
    severity: str  # Worst-case severity
    combined_impact: float
    exploitation_difficulty: float
    
    # Description
    title: str
    description: str
    exploitation_path: List[str]  # Step by step exploitation
    
    # Confidence
    confidence: float
    
    @property
    def finding_count(self) -> int:
        return len(self.findings)


@dataclass
class CorrelationResult:
    """Complete correlation analysis result"""
    attack_chains: List[AttackChain]
    related_groups: List[List[str]]  # Groups of related finding IDs
    total_findings_analyzed: int
    
    # Statistics
    highest_impact_chain: Optional[AttackChain] = None
    unique_chain_types: List[str] = field(default_factory=list)
    
    # Graph metrics
    graph_density: float = 0.0
    most_connected_finding: Optional[str] = None


class CorrelationEngine:
    """
    Attack Chain and Vulnerability Correlation Engine
    
    Detects relationships between vulnerabilities and identifies
    attack chains that could be exploited by attackers.
    """
    
    # Correlation rules: (vuln_type_1, vuln_type_2, relation, weight, chain_type)
    CORRELATION_RULES: List[Tuple[str, str, VulnerabilityRelation, float, Optional[ChainType]]] = [
        # XSS enables account takeover
        ("xss", "session", VulnerabilityRelation.ENABLES, 0.9, ChainType.ACCOUNT_TAKEOVER),
        ("xss", "csrf", VulnerabilityRelation.AMPLIFIES, 0.85, ChainType.ACCOUNT_TAKEOVER),
        ("xss", "auth", VulnerabilityRelation.ENABLES, 0.8, ChainType.AUTHENTICATION_BYPASS),
        
        # SQLi enables data exfiltration
        ("sqli", "idor", VulnerabilityRelation.AMPLIFIES, 0.9, ChainType.DATA_EXFILTRATION),
        ("sqli", "auth", VulnerabilityRelation.ENABLES, 0.95, ChainType.AUTHENTICATION_BYPASS),
        ("sqli", "sensitive", VulnerabilityRelation.ENABLES, 0.9, ChainType.DATA_EXFILTRATION),
        
        # Command injection leads to RCE
        ("cmdi", "path_traversal", VulnerabilityRelation.AMPLIFIES, 0.85, ChainType.REMOTE_CODE_EXECUTION),
        ("cmdi", "upload", VulnerabilityRelation.AMPLIFIES, 0.9, ChainType.REMOTE_CODE_EXECUTION),
        
        # SSRF enables lateral movement
        ("ssrf", "internal", VulnerabilityRelation.ENABLES, 0.9, ChainType.LATERAL_MOVEMENT),
        ("ssrf", "cloud", VulnerabilityRelation.ENABLES, 0.95, ChainType.DATA_EXFILTRATION),
        
        # Auth bypass chains
        ("auth_bypass", "admin", VulnerabilityRelation.ENABLES, 0.95, ChainType.PRIVILEGE_ESCALATION),
        ("auth_bypass", "idor", VulnerabilityRelation.AMPLIFIES, 0.85, ChainType.DATA_EXFILTRATION),
        
        # IDOR chains
        ("idor", "sensitive", VulnerabilityRelation.ENABLES, 0.9, ChainType.DATA_EXFILTRATION),
        ("idor", "privesc", VulnerabilityRelation.ENABLES, 0.85, ChainType.PRIVILEGE_ESCALATION),
        
        # CSRF chains
        ("csrf", "password", VulnerabilityRelation.ENABLES, 0.85, ChainType.ACCOUNT_TAKEOVER),
        ("csrf", "admin", VulnerabilityRelation.ENABLES, 0.8, ChainType.PRIVILEGE_ESCALATION),
        
        # Path traversal chains
        ("path_traversal", "config", VulnerabilityRelation.ENABLES, 0.9, ChainType.DATA_EXFILTRATION),
        ("path_traversal", "source", VulnerabilityRelation.ENABLES, 0.85, ChainType.INFORMATION_GATHERING),
        
        # Info disclosure chains
        ("info_disclosure", "debug", VulnerabilityRelation.AMPLIFIES, 0.7, ChainType.INFORMATION_GATHERING),
        ("info_disclosure", "version", VulnerabilityRelation.AMPLIFIES, 0.6, ChainType.INFORMATION_GATHERING),
        
        # Upload chains
        ("upload", "webshell", VulnerabilityRelation.ENABLES, 0.95, ChainType.REMOTE_CODE_EXECUTION),
        ("upload", "xss", VulnerabilityRelation.ENABLES, 0.75, ChainType.ACCOUNT_TAKEOVER),
        
        # XXE chains
        ("xxe", "ssrf", VulnerabilityRelation.ENABLES, 0.85, ChainType.LATERAL_MOVEMENT),
        ("xxe", "file_read", VulnerabilityRelation.ENABLES, 0.9, ChainType.DATA_EXFILTRATION),
        
        # SSTI chains
        ("ssti", "rce", VulnerabilityRelation.ENABLES, 0.95, ChainType.REMOTE_CODE_EXECUTION),
    ]
    
    # Vulnerability type aliases (for matching finding titles)
    VULN_TYPE_PATTERNS: Dict[str, List[str]] = {
        "xss": ["xss", "cross-site scripting", "script injection", "reflected", "stored xss", "dom xss"],
        "sqli": ["sql injection", "sqli", "sql", "database injection", "mysql", "postgres", "oracle"],
        "cmdi": ["command injection", "os command", "shell injection", "rce", "code execution"],
        "ssrf": ["ssrf", "server-side request", "url fetch", "internal request"],
        "csrf": ["csrf", "cross-site request forgery", "request forgery"],
        "idor": ["idor", "insecure direct object", "object reference", "access control"],
        "auth_bypass": ["authentication bypass", "auth bypass", "login bypass", "broken auth"],
        "auth": ["authentication", "login", "session", "token", "jwt", "cookie"],
        "path_traversal": ["path traversal", "directory traversal", "lfi", "local file", "file inclusion"],
        "upload": ["file upload", "upload vulnerability", "unrestricted upload"],
        "xxe": ["xxe", "xml external entity", "xml injection"],
        "ssti": ["ssti", "template injection", "server-side template"],
        "info_disclosure": ["information disclosure", "info leak", "data exposure", "sensitive data"],
        "debug": ["debug", "stack trace", "error message", "verbose error"],
        "version": ["version disclosure", "server version", "software version"],
        "sensitive": ["sensitive data", "credential", "password", "api key", "secret"],
        "session": ["session", "cookie", "token hijack"],
        "admin": ["admin", "administrator", "privileged", "backend"],
        "privesc": ["privilege escalation", "privesc", "vertical escalation"],
        "config": ["configuration", "config file", ".env", "settings"],
        "source": ["source code", "code exposure", "backup file"],
        "internal": ["internal", "intranet", "private network"],
        "cloud": ["cloud", "aws", "azure", "gcp", "metadata"],
        "webshell": ["webshell", "backdoor", "remote shell"],
        "rce": ["remote code execution", "rce", "code execution"],
        "file_read": ["file read", "arbitrary read", "file access"],
        "password": ["password change", "password reset", "credential update"],
    }
    
    # Severity upgrade rules for chains
    SEVERITY_UPGRADE: Dict[Tuple[str, str], str] = {
        ("high", "high"): "critical",
        ("high", "medium"): "high",
        ("medium", "medium"): "high",
        ("medium", "low"): "medium",
        ("low", "low"): "medium",
    }
    
    def __init__(self, db_session=None):
        """
        Initialize the correlation engine
        
        Args:
            db_session: Optional database session for historical data
        """
        self.db_session = db_session
        self.graph: Optional[Any] = None  # networkx graph
        
        if HAS_NETWORKX:
            self.graph = nx.DiGraph()
        else:
            logger.warning("networkx not available, graph-based analysis disabled")
    
    def analyze_findings(
        self,
        findings: List[Dict[str, Any]]
    ) -> CorrelationResult:
        """
        Analyze a list of findings for correlations and attack chains
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            CorrelationResult with chains and related groups
        """
        if not findings:
            return CorrelationResult(
                attack_chains=[],
                related_groups=[],
                total_findings_analyzed=0
            )
        
        # Convert findings to nodes
        nodes = self._create_nodes(findings)
        
        # Find relationships
        edges = self._find_relationships(nodes)
        
        # Build graph
        if HAS_NETWORKX and self.graph is not None:
            self._build_graph(nodes, edges)
        
        # Detect attack chains
        attack_chains = self._detect_attack_chains(nodes, edges)
        
        # Find related groups (same endpoint or root cause)
        related_groups = self._find_related_groups(nodes)
        
        # Build result
        highest_impact = None
        if attack_chains:
            highest_impact = max(attack_chains, key=lambda c: c.combined_impact)
        
        unique_chain_types = list(set([c.chain_type.value for c in attack_chains]))
        
        # Graph metrics
        graph_density = 0.0
        most_connected = None
        if HAS_NETWORKX and self.graph and len(self.graph.nodes) > 0:
            graph_density = nx.density(self.graph)
            degree_dict = dict(self.graph.degree())
            if degree_dict:
                most_connected = max(degree_dict, key=degree_dict.get)
        
        return CorrelationResult(
            attack_chains=attack_chains,
            related_groups=related_groups,
            total_findings_analyzed=len(findings),
            highest_impact_chain=highest_impact,
            unique_chain_types=unique_chain_types,
            graph_density=round(graph_density, 3),
            most_connected_finding=most_connected
        )
    
    def _create_nodes(
        self, findings: List[Dict[str, Any]]
    ) -> List[VulnerabilityNode]:
        """Convert findings to vulnerability nodes"""
        nodes = []
        
        for finding in findings:
            vuln_type = self._detect_vuln_type(finding)
            
            node = VulnerabilityNode(
                finding_id=finding.get("id", str(hash(str(finding)))),
                title=finding.get("title", "Unknown"),
                category=finding.get("category", "A00"),
                severity=finding.get("severity", "medium"),
                url=finding.get("url", ""),
                vuln_type=vuln_type,
                parameter=finding.get("parameter"),
                evidence=finding.get("evidence"),
                exploitability=self._estimate_exploitability(finding),
                impact=self._estimate_impact(finding)
            )
            nodes.append(node)
        
        return nodes
    
    def _detect_vuln_type(self, finding: Dict[str, Any]) -> str:
        """Detect vulnerability type from finding title and category"""
        title = finding.get("title", "").lower()
        description = finding.get("description", "").lower()
        category = finding.get("category", "")
        
        text = f"{title} {description}"
        
        for vuln_type, patterns in self.VULN_TYPE_PATTERNS.items():
            for pattern in patterns:
                if pattern in text:
                    return vuln_type
        
        # Fall back to OWASP category mapping
        owasp_mapping = {
            "A01": "idor",
            "A02": "sensitive",
            "A03": "sqli",
            "A05": "info_disclosure",
            "A07": "auth",
            "A10": "ssrf",
        }
        
        return owasp_mapping.get(category, "unknown")
    
    def _estimate_exploitability(self, finding: Dict[str, Any]) -> float:
        """Estimate how easy the vulnerability is to exploit"""
        score = 0.5
        
        # Has PoC = easier to exploit
        if finding.get("poc"):
            score += 0.2
        
        # Has parameter identified = easier
        if finding.get("parameter"):
            score += 0.1
        
        # Severity affects exploitability
        severity_boost = {
            "critical": 0.15,
            "high": 0.1,
            "medium": 0.0,
            "low": -0.1,
            "info": -0.2
        }
        score += severity_boost.get(finding.get("severity", "medium"), 0)
        
        return max(0.1, min(1.0, score))
    
    def _estimate_impact(self, finding: Dict[str, Any]) -> float:
        """Estimate the impact of the vulnerability"""
        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.25,
            "info": 0.1
        }
        return severity_scores.get(finding.get("severity", "medium"), 0.5)
    
    def _find_relationships(
        self, nodes: List[VulnerabilityNode]
    ) -> List[VulnerabilityEdge]:
        """Find relationships between vulnerability nodes"""
        edges = []
        
        for i, source in enumerate(nodes):
            for j, target in enumerate(nodes):
                if i == j:
                    continue
                
                # Check correlation rules
                for rule in self.CORRELATION_RULES:
                    source_type, target_type, relation, weight, _ = rule
                    
                    if source.vuln_type == source_type and target.vuln_type == target_type:
                        edges.append(VulnerabilityEdge(
                            source_id=source.finding_id,
                            target_id=target.finding_id,
                            relation=relation,
                            weight=weight,
                            description=f"{source.vuln_type} {relation.value} {target.vuln_type}"
                        ))
                
                # Check for same endpoint relationship
                if source.url and target.url and source.url == target.url:
                    edges.append(VulnerabilityEdge(
                        source_id=source.finding_id,
                        target_id=target.finding_id,
                        relation=VulnerabilityRelation.SAME_ENDPOINT,
                        weight=0.5,
                        description=f"Both affect {source.url}"
                    ))
                
                # Check for same parameter relationship
                if source.parameter and target.parameter and source.parameter == target.parameter:
                    edges.append(VulnerabilityEdge(
                        source_id=source.finding_id,
                        target_id=target.finding_id,
                        relation=VulnerabilityRelation.SAME_ROOT_CAUSE,
                        weight=0.6,
                        description=f"Both affect parameter: {source.parameter}"
                    ))
        
        return edges
    
    def _build_graph(
        self, nodes: List[VulnerabilityNode], edges: List[VulnerabilityEdge]
    ):
        """Build networkx graph from nodes and edges"""
        if not HAS_NETWORKX or self.graph is None:
            return
        
        self.graph.clear()
        
        # Add nodes
        for node in nodes:
            self.graph.add_node(
                node.finding_id,
                title=node.title,
                category=node.category,
                severity=node.severity,
                vuln_type=node.vuln_type,
                exploitability=node.exploitability,
                impact=node.impact
            )
        
        # Add edges
        for edge in edges:
            self.graph.add_edge(
                edge.source_id,
                edge.target_id,
                relation=edge.relation.value,
                weight=edge.weight,
                description=edge.description
            )
    
    def _detect_attack_chains(
        self,
        nodes: List[VulnerabilityNode],
        edges: List[VulnerabilityEdge]
    ) -> List[AttackChain]:
        """Detect attack chains from the vulnerability graph"""
        chains = []
        node_map = {n.finding_id: n for n in nodes}
        
        # Group edges by chain type
        chain_candidates: Dict[ChainType, List[VulnerabilityEdge]] = {}
        
        for edge in edges:
            # Find chain type from correlation rules
            source_node = node_map.get(edge.source_id)
            target_node = node_map.get(edge.target_id)
            
            if not source_node or not target_node:
                continue
            
            for rule in self.CORRELATION_RULES:
                source_type, target_type, _, _, chain_type = rule
                
                if (source_node.vuln_type == source_type and 
                    target_node.vuln_type == target_type and
                    chain_type):
                    if chain_type not in chain_candidates:
                        chain_candidates[chain_type] = []
                    chain_candidates[chain_type].append(edge)
        
        # Build chains from candidates
        for chain_type, chain_edges in chain_candidates.items():
            if not chain_edges:
                continue
            
            # Get unique findings in this chain
            finding_ids = set()
            for edge in chain_edges:
                finding_ids.add(edge.source_id)
                finding_ids.add(edge.target_id)
            
            finding_list = list(finding_ids)
            
            # Calculate combined metrics
            findings_in_chain = [node_map[fid] for fid in finding_list if fid in node_map]
            
            if not findings_in_chain:
                continue
            
            # Combined impact (multiplicative boost)
            base_impact = max(f.impact for f in findings_in_chain)
            combined_impact = min(1.0, base_impact * (1 + 0.1 * len(findings_in_chain)))
            
            # Exploitation difficulty (average)
            avg_exploitability = sum(f.exploitability for f in findings_in_chain) / len(findings_in_chain)
            
            # Determine severity
            severities = [f.severity for f in findings_in_chain]
            chain_severity = self._calculate_chain_severity(severities)
            
            # Build exploitation path
            exploitation_path = self._build_exploitation_path(
                findings_in_chain, chain_edges, chain_type
            )
            
            # Calculate confidence
            avg_weight = sum(e.weight for e in chain_edges) / len(chain_edges)
            confidence = min(0.95, avg_weight * (1 + 0.05 * len(chain_edges)))
            
            # Generate chain ID
            chain_id = hashlib.md5(
                f"{chain_type.value}:{','.join(sorted(finding_list))}".encode()
            ).hexdigest()[:12]
            
            chains.append(AttackChain(
                chain_id=chain_id,
                chain_type=chain_type,
                findings=finding_list,
                severity=chain_severity,
                combined_impact=round(combined_impact, 3),
                exploitation_difficulty=round(1 - avg_exploitability, 3),
                title=self._generate_chain_title(chain_type, findings_in_chain),
                description=self._generate_chain_description(chain_type, findings_in_chain),
                exploitation_path=exploitation_path,
                confidence=round(confidence, 3)
            ))
        
        # Sort by impact
        chains.sort(key=lambda c: c.combined_impact, reverse=True)
        
        return chains
    
    def _calculate_chain_severity(self, severities: List[str]) -> str:
        """Calculate combined severity for a chain"""
        severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        
        # Get two highest severities
        sorted_sevs = sorted(severities, key=lambda s: severity_order.get(s, 0), reverse=True)
        
        if len(sorted_sevs) >= 2:
            key = (sorted_sevs[0], sorted_sevs[1])
            if key in self.SEVERITY_UPGRADE:
                return self.SEVERITY_UPGRADE[key]
        
        return sorted_sevs[0] if sorted_sevs else "medium"
    
    def _build_exploitation_path(
        self,
        findings: List[VulnerabilityNode],
        edges: List[VulnerabilityEdge],
        chain_type: ChainType
    ) -> List[str]:
        """Build step-by-step exploitation path"""
        path = []
        
        # Sort by exploitability (easiest first)
        sorted_findings = sorted(findings, key=lambda f: f.exploitability, reverse=True)
        
        path.append(f"1. Initial access via {sorted_findings[0].title}")
        
        step = 2
        for finding in sorted_findings[1:]:
            relation = "exploit"
            for edge in edges:
                if edge.target_id == finding.finding_id:
                    relation = edge.relation.value
                    break
            
            path.append(f"{step}. {relation.replace('_', ' ').title()} {finding.title}")
            step += 1
        
        # Add final impact
        impact_messages = {
            ChainType.DATA_EXFILTRATION: "Extract sensitive data from the application",
            ChainType.PRIVILEGE_ESCALATION: "Gain administrative or elevated privileges",
            ChainType.ACCOUNT_TAKEOVER: "Take over user accounts",
            ChainType.REMOTE_CODE_EXECUTION: "Execute arbitrary code on the server",
            ChainType.LATERAL_MOVEMENT: "Move laterally within the network",
            ChainType.AUTHENTICATION_BYPASS: "Bypass authentication controls",
        }
        
        final_msg = impact_messages.get(chain_type, "Achieve attack objective")
        path.append(f"{step}. Final impact: {final_msg}")
        
        return path
    
    def _generate_chain_title(
        self,
        chain_type: ChainType,
        findings: List[VulnerabilityNode]
    ) -> str:
        """Generate a title for the attack chain"""
        titles = {
            ChainType.DATA_EXFILTRATION: "Data Exfiltration Chain",
            ChainType.PRIVILEGE_ESCALATION: "Privilege Escalation Chain",
            ChainType.ACCOUNT_TAKEOVER: "Account Takeover Chain",
            ChainType.REMOTE_CODE_EXECUTION: "Remote Code Execution Chain",
            ChainType.LATERAL_MOVEMENT: "Lateral Movement Chain",
            ChainType.DENIAL_OF_SERVICE: "Denial of Service Chain",
            ChainType.INFORMATION_GATHERING: "Information Gathering Chain",
            ChainType.AUTHENTICATION_BYPASS: "Authentication Bypass Chain",
        }
        
        base_title = titles.get(chain_type, "Attack Chain")
        vuln_types = list(set([f.vuln_type for f in findings]))[:3]
        
        return f"{base_title} via {', '.join(vuln_types).upper()}"
    
    def _generate_chain_description(
        self,
        chain_type: ChainType,
        findings: List[VulnerabilityNode]
    ) -> str:
        """Generate a description for the attack chain"""
        descriptions = {
            ChainType.DATA_EXFILTRATION: "An attacker could chain these vulnerabilities to extract sensitive data from the application.",
            ChainType.PRIVILEGE_ESCALATION: "These vulnerabilities can be combined to escalate privileges from a regular user to administrator.",
            ChainType.ACCOUNT_TAKEOVER: "An attacker could use this chain to take over user accounts without knowing their credentials.",
            ChainType.REMOTE_CODE_EXECUTION: "This chain of vulnerabilities could allow an attacker to execute arbitrary code on the server.",
            ChainType.LATERAL_MOVEMENT: "These vulnerabilities enable an attacker to move from the web application to internal network resources.",
            ChainType.AUTHENTICATION_BYPASS: "An attacker could bypass authentication controls by exploiting these vulnerabilities together.",
        }
        
        base_desc = descriptions.get(chain_type, "These vulnerabilities can be chained together for greater impact.")
        
        finding_summary = ", ".join([f.title for f in findings[:3]])
        if len(findings) > 3:
            finding_summary += f", and {len(findings) - 3} more"
        
        return f"{base_desc} Affected findings: {finding_summary}"
    
    def _find_related_groups(
        self, nodes: List[VulnerabilityNode]
    ) -> List[List[str]]:
        """Find groups of related vulnerabilities"""
        groups: List[Set[str]] = []
        
        # Group by URL
        url_groups: Dict[str, Set[str]] = {}
        for node in nodes:
            if node.url:
                # Normalize URL (remove query string)
                base_url = node.url.split("?")[0]
                if base_url not in url_groups:
                    url_groups[base_url] = set()
                url_groups[base_url].add(node.finding_id)
        
        for url, finding_ids in url_groups.items():
            if len(finding_ids) >= 2:
                groups.append(finding_ids)
        
        # Group by parameter
        param_groups: Dict[str, Set[str]] = {}
        for node in nodes:
            if node.parameter:
                if node.parameter not in param_groups:
                    param_groups[node.parameter] = set()
                param_groups[node.parameter].add(node.finding_id)
        
        for param, finding_ids in param_groups.items():
            if len(finding_ids) >= 2:
                groups.append(finding_ids)
        
        # Group by vuln type
        type_groups: Dict[str, Set[str]] = {}
        for node in nodes:
            if node.vuln_type not in type_groups:
                type_groups[node.vuln_type] = set()
            type_groups[node.vuln_type].add(node.finding_id)
        
        for vuln_type, finding_ids in type_groups.items():
            if len(finding_ids) >= 2:
                groups.append(finding_ids)
        
        # Merge overlapping groups
        merged = self._merge_overlapping_groups(groups)
        
        # Convert to list of lists
        return [list(g) for g in merged if len(g) >= 2]
    
    def _merge_overlapping_groups(self, groups: List[Set[str]]) -> List[Set[str]]:
        """Merge groups that share common findings"""
        if not groups:
            return []
        
        merged = []
        used = set()
        
        for i, group1 in enumerate(groups):
            if i in used:
                continue
            
            current = set(group1)
            
            for j, group2 in enumerate(groups[i+1:], i+1):
                if j in used:
                    continue
                
                if current & group2:  # If overlap
                    current |= group2
                    used.add(j)
            
            merged.append(current)
            used.add(i)
        
        return merged
    
    def get_chain_visualization_data(
        self, result: CorrelationResult
    ) -> Dict[str, Any]:
        """
        Get data for visualizing attack chains in the frontend
        
        Args:
            result: CorrelationResult from analyze_findings
            
        Returns:
            Dict with nodes and edges for visualization
        """
        if not HAS_NETWORKX or self.graph is None:
            return {"nodes": [], "edges": [], "chains": []}
        
        nodes_data = []
        for node_id in self.graph.nodes:
            node_attrs = self.graph.nodes[node_id]
            nodes_data.append({
                "id": node_id,
                "label": node_attrs.get("title", node_id)[:30],
                "category": node_attrs.get("category"),
                "severity": node_attrs.get("severity"),
                "vuln_type": node_attrs.get("vuln_type"),
                "size": int(node_attrs.get("impact", 0.5) * 30 + 10)
            })
        
        edges_data = []
        for source, target, edge_attrs in self.graph.edges(data=True):
            edges_data.append({
                "source": source,
                "target": target,
                "relation": edge_attrs.get("relation"),
                "weight": edge_attrs.get("weight", 0.5)
            })
        
        chains_data = []
        for chain in result.attack_chains:
            chains_data.append({
                "id": chain.chain_id,
                "type": chain.chain_type.value,
                "title": chain.title,
                "findings": chain.findings,
                "severity": chain.severity,
                "impact": chain.combined_impact,
                "path": chain.exploitation_path
            })
        
        return {
            "nodes": nodes_data,
            "edges": edges_data,
            "chains": chains_data
        }


# Convenience function for quick analysis
def detect_attack_chains(findings: List[Dict[str, Any]]) -> CorrelationResult:
    """Quick attack chain detection without instantiation"""
    engine = CorrelationEngine()
    return engine.analyze_findings(findings)
