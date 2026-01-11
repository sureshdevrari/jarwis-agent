"""
Jarwis AGI - Cloud Security Graph (Wiz-style)
Builds relationship graphs between cloud resources and identifies attack paths

Key capabilities:
- Resource relationship mapping (EC2→S3, IAM→Lambda, etc.)
- Attack path identification (lateral movement chains)
- Blast radius calculation (impact scoring)
- Toxic combination detection (risk correlation)
"""

import asyncio
import logging
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict, deque
import networkx as nx

logger = logging.getLogger(__name__)


@dataclass
class AttackPath:
    """Represents an attack chain through cloud resources"""
    path_id: str
    start_resource: str
    end_resource: str
    steps: List[str]  # Resource IDs in order
    risk_score: int  # 0-100
    description: str
    exploitation_steps: List[str]  # Human-readable steps
    

class CloudSecurityGraph:
    """
    Cloud Security Graph - Wiz-style resource relationship mapping
    
    Builds a directed graph of cloud resources and their relationships:
    - IAM roles → Resources they can access
    - EC2 instances → S3 buckets they can read/write
    - Lambda functions → Databases they connect to
    - Public endpoints → Internal services
    - Network flows → Security group relationships
    """
    
    def __init__(self, resources: List[Any]):
        self.resources = resources
        self.graph = nx.DiGraph()  # NetworkX directed graph
        self.adjacency_list: Dict[str, List[str]] = defaultdict(list)
        self.resource_map: Dict[str, Any] = {}  # resource_id → resource object
        
        # Build resource lookup map
        for resource in resources:
            self.resource_map[resource.resource_id] = resource
    
    async def build_graph(self):
        """Build resource relationship graph"""
        logger.info("Building cloud security graph...")
        
        # Add all resources as nodes
        for resource in self.resources:
            self.graph.add_node(
                resource.resource_id,
                resource_type=resource.resource_type,
                provider=resource.provider,
                region=resource.region,
                name=resource.name,
                sensitive=self._is_sensitive_resource(resource)
            )
        
        # Add edges based on relationships
        await self._add_iam_relationships()
        await self._add_network_relationships()
        await self._add_data_access_relationships()
        await self._add_compute_relationships()
        
        # Convert NetworkX graph to adjacency list for export
        for node in self.graph.nodes():
            self.adjacency_list[node] = list(self.graph.successors(node))
        
        logger.info(f"Graph built: {self.graph.number_of_nodes()} nodes, {self.graph.number_of_edges()} edges")
    
    async def _add_iam_relationships(self):
        """Add IAM role → resource access edges"""
        for resource in self.resources:
            # AWS IAM role attachments
            if resource.resource_type == 'iam_role':
                attached_policies = resource.metadata.get('attached_policies', [])
                for policy in attached_policies:
                    # Parse policy to find accessible resources
                    accessible_resources = self._parse_policy_resources(policy)
                    for target_id in accessible_resources:
                        if target_id in self.resource_map:
                            self.graph.add_edge(
                                resource.resource_id,
                                target_id,
                                relationship='iam_access',
                                permissions=policy.get('permissions', [])
                            )
            
            # Azure RBAC assignments
            elif resource.resource_type == 'azure_role_assignment':
                principal_id = resource.metadata.get('principal_id')
                scope = resource.metadata.get('scope')
                
                # Find resources in scope
                for target in self.resources:
                    if target.resource_id.startswith(scope):
                        self.graph.add_edge(
                            principal_id,
                            target.resource_id,
                            relationship='rbac_access',
                            role=resource.metadata.get('role_name')
                        )
            
            # GCP IAM bindings
            elif resource.resource_type == 'gcp_iam_binding':
                members = resource.metadata.get('members', [])
                bound_resource = resource.metadata.get('resource')
                
                for member in members:
                    if bound_resource in self.resource_map:
                        self.graph.add_edge(
                            member,
                            bound_resource,
                            relationship='gcp_iam_access',
                            role=resource.metadata.get('role')
                        )
    
    async def _add_network_relationships(self):
        """Add network connectivity edges"""
        for resource in self.resources:
            # AWS Security Groups
            if resource.resource_type == 'security_group':
                ingress_rules = resource.metadata.get('ingress_rules', [])
                
                for rule in ingress_rules:
                    source = rule.get('source')
                    if source == '0.0.0.0/0':
                        # Public internet access
                        self.graph.add_edge(
                            'internet',
                            resource.resource_id,
                            relationship='public_access',
                            protocol=rule.get('protocol'),
                            port=rule.get('port')
                        )
            
            # Azure Network Security Groups
            elif resource.resource_type == 'azure_nsg':
                security_rules = resource.metadata.get('security_rules', [])
                
                for rule in security_rules:
                    if rule.get('source_address_prefix') == '*':
                        self.graph.add_edge(
                            'internet',
                            resource.resource_id,
                            relationship='public_access',
                            protocol=rule.get('protocol'),
                            port=rule.get('destination_port_range')
                        )
            
            # VPC peering connections
            elif resource.resource_type == 'vpc_peering':
                requester_vpc = resource.metadata.get('requester_vpc')
                accepter_vpc = resource.metadata.get('accepter_vpc')
                
                if requester_vpc and accepter_vpc:
                    self.graph.add_edge(
                        requester_vpc,
                        accepter_vpc,
                        relationship='vpc_peering',
                        bidirectional=True
                    )
    
    async def _add_data_access_relationships(self):
        """Add data storage access edges"""
        for resource in self.resources:
            # S3 bucket policies
            if resource.resource_type == 's3_bucket':
                bucket_policy = resource.metadata.get('bucket_policy', {})
                
                # Check for public access
                if self._is_public_policy(bucket_policy):
                    self.graph.add_edge(
                        'internet',
                        resource.resource_id,
                        relationship='public_data_access',
                        access_type='read/write'
                    )
                
                # Check for cross-account access
                principals = self._extract_policy_principals(bucket_policy)
                for principal in principals:
                    if principal != resource.metadata.get('owner_account'):
                        self.graph.add_edge(
                            principal,
                            resource.resource_id,
                            relationship='cross_account_access'
                        )
            
            # RDS instances
            elif resource.resource_type == 'rds_instance':
                publicly_accessible = resource.metadata.get('publicly_accessible', False)
                
                if publicly_accessible:
                    self.graph.add_edge(
                        'internet',
                        resource.resource_id,
                        relationship='public_database_access',
                        engine=resource.metadata.get('engine')
                    )
            
            # Azure Storage Accounts
            elif resource.resource_type == 'azure_storage_account':
                allow_blob_public_access = resource.metadata.get('allow_blob_public_access', False)
                
                if allow_blob_public_access:
                    self.graph.add_edge(
                        'internet',
                        resource.resource_id,
                        relationship='public_data_access',
                        access_type='blob_public'
                    )
    
    async def _add_compute_relationships(self):
        """Add compute resource relationships"""
        for resource in self.resources:
            # EC2 instances
            if resource.resource_type == 'ec2_instance':
                iam_role = resource.metadata.get('iam_instance_profile')
                
                if iam_role and iam_role in self.resource_map:
                    self.graph.add_edge(
                        resource.resource_id,
                        iam_role,
                        relationship='assumes_role'
                    )
            
            # Lambda functions
            elif resource.resource_type == 'lambda_function':
                execution_role = resource.metadata.get('execution_role')
                environment_vars = resource.metadata.get('environment_variables', {})
                
                if execution_role and execution_role in self.resource_map:
                    self.graph.add_edge(
                        resource.resource_id,
                        execution_role,
                        relationship='uses_role'
                    )
                
                # Check environment variables for DB connection strings
                for key, value in environment_vars.items():
                    if 'DB_' in key or 'DATABASE_' in key:
                        # Try to find RDS instance
                        db_resources = [r for r in self.resources if r.resource_type == 'rds_instance']
                        for db in db_resources:
                            if db.metadata.get('endpoint') in value:
                                self.graph.add_edge(
                                    resource.resource_id,
                                    db.resource_id,
                                    relationship='database_connection'
                                )
    
    async def find_attack_paths(self, findings: List[Any]) -> Dict[str, List[str]]:
        """
        Identify attack paths from internet to sensitive resources
        Returns: finding_id → list of resource IDs in attack path
        """
        logger.info("Identifying attack paths...")
        
        attack_paths = {}
        
        # Add internet node if not exists
        if not self.graph.has_node('internet'):
            self.graph.add_node('internet', resource_type='external', sensitive=False)
        
        # Find all sensitive resources
        sensitive_resources = [
            node for node, attrs in self.graph.nodes(data=True)
            if attrs.get('sensitive', False)
        ]
        
        logger.info(f"Found {len(sensitive_resources)} sensitive resources")
        
        # For each finding, find path from internet to affected resource
        for finding in findings:
            resource_id = finding.resource_id
            
            if resource_id not in self.graph:
                continue
            
            # Find shortest path from internet to this resource
            try:
                if nx.has_path(self.graph, 'internet', resource_id):
                    path = nx.shortest_path(self.graph, 'internet', resource_id)
                    attack_paths[finding.id] = path
                    logger.debug(f"Attack path for {resource_id}: {' → '.join(path)}")
            except nx.NetworkXNoPath:
                # No direct path from internet
                pass
        
        # Find multi-hop attack paths (lateral movement)
        for sensitive_resource in sensitive_resources:
            try:
                if nx.has_path(self.graph, 'internet', sensitive_resource):
                    path = nx.shortest_path(self.graph, 'internet', sensitive_resource)
                    
                    if len(path) > 2:  # Multi-hop (internet → resource → sensitive)
                        path_id = f"lateral_movement_{sensitive_resource}"
                        attack_paths[path_id] = path
                        logger.info(f"Lateral movement path: {' → '.join(path)}")
            except nx.NetworkXNoPath:
                pass
        
        logger.info(f"Identified {len(attack_paths)} attack paths")
        return attack_paths
    
    async def calculate_blast_radius(self, resource_id: str) -> int:
        """
        Calculate blast radius: how many resources are reachable from this resource
        Returns: Score 0-100
        """
        if resource_id not in self.graph:
            return 0
        
        # BFS to find all reachable resources
        reachable = set()
        queue = deque([resource_id])
        visited = set([resource_id])
        
        while queue:
            current = queue.popleft()
            
            for successor in self.graph.successors(current):
                if successor not in visited:
                    visited.add(successor)
                    reachable.add(successor)
                    queue.append(successor)
        
        # Count sensitive resources in blast radius
        sensitive_count = sum(
            1 for node in reachable
            if self.graph.nodes[node].get('sensitive', False)
        )
        
        # Score: (reachable_resources / total_resources) * 100
        total_resources = len(self.resource_map)
        if total_resources == 0:
            return 0
        
        base_score = (len(reachable) / total_resources) * 100
        
        # Boost score if sensitive resources are reachable
        if sensitive_count > 0:
            base_score = min(100, base_score + (sensitive_count * 10))
        
        return int(base_score)
    
    def _is_sensitive_resource(self, resource: Any) -> bool:
        """Determine if resource contains sensitive data"""
        sensitive_types = [
            'rds_instance', 's3_bucket', 'azure_storage_account', 
            'gcs_bucket', 'secret', 'key_vault', 'parameter_store'
        ]
        
        if resource.resource_type in sensitive_types:
            return True
        
        # Check tags for sensitivity markers
        tags = resource.tags
        sensitive_tags = ['pii', 'sensitive', 'confidential', 'production', 'prod']
        
        for tag_key, tag_value in tags.items():
            if any(marker in tag_key.lower() or marker in tag_value.lower() 
                   for marker in sensitive_tags):
                return True
        
        return False
    
    def _parse_policy_resources(self, policy: Dict) -> List[str]:
        """Extract resource ARNs from IAM policy"""
        resources = []
        
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            resource_list = statement.get('Resource', [])
            if isinstance(resource_list, str):
                resource_list = [resource_list]
            
            for resource_arn in resource_list:
                # Try to match ARN to our resource map
                for resource_id, resource_obj in self.resource_map.items():
                    if resource_obj.arn_or_id == resource_arn:
                        resources.append(resource_id)
        
        return resources
    
    def _is_public_policy(self, policy: Dict) -> bool:
        """Check if policy allows public access"""
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            effect = statement.get('Effect')
            principal = statement.get('Principal', {})
            
            if effect == 'Allow':
                if principal == '*' or principal.get('AWS') == '*':
                    return True
        
        return False
    
    def _extract_policy_principals(self, policy: Dict) -> List[str]:
        """Extract principals from policy"""
        principals = []
        
        statements = policy.get('Statement', [])
        if isinstance(statements, dict):
            statements = [statements]
        
        for statement in statements:
            principal = statement.get('Principal', {})
            
            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                principals.extend(aws_principals)
        
        return principals
    
    def get_toxic_combinations(self) -> List[Dict[str, Any]]:
        """
        Identify toxic combinations of security issues
        e.g., Public S3 + No Encryption + Contains PII
        """
        toxic_combos = []
        
        for resource in self.resources:
            resource_id = resource.resource_id
            
            # Check for common toxic patterns
            if resource.resource_type == 's3_bucket':
                is_public = self.graph.has_edge('internet', resource_id)
                is_encrypted = resource.metadata.get('encryption_enabled', False)
                has_logging = resource.metadata.get('logging_enabled', False)
                is_sensitive = self._is_sensitive_resource(resource)
                
                if is_public and not is_encrypted and is_sensitive:
                    toxic_combos.append({
                        'resource_id': resource_id,
                        'resource_type': resource.resource_type,
                        'pattern': 'Public + Unencrypted + Sensitive Data',
                        'risk_score': 100,
                        'description': f'S3 bucket {resource.name} is publicly accessible, unencrypted, and may contain sensitive data'
                    })
            
            elif resource.resource_type == 'ec2_instance':
                has_public_ip = resource.metadata.get('public_ip') is not None
                has_admin_access = self._has_admin_iam_role(resource)
                in_public_subnet = resource.metadata.get('subnet_public', False)
                
                if has_public_ip and has_admin_access and in_public_subnet:
                    toxic_combos.append({
                        'resource_id': resource_id,
                        'resource_type': resource.resource_type,
                        'pattern': 'Public EC2 + Admin IAM Role',
                        'risk_score': 90,
                        'description': f'EC2 instance {resource.name} is publicly accessible with administrative IAM permissions'
                    })
        
        return toxic_combos
    
    def _has_admin_iam_role(self, resource: Any) -> bool:
        """Check if resource has administrative IAM permissions"""
        iam_role = resource.metadata.get('iam_instance_profile')
        
        if not iam_role:
            return False
        
        # Check if role has admin policies
        if iam_role in self.resource_map:
            role_obj = self.resource_map[iam_role]
            policies = role_obj.metadata.get('attached_policies', [])
            
            for policy in policies:
                policy_name = policy.get('PolicyName', '')
                if 'Administrator' in policy_name or 'FullAccess' in policy_name:
                    return True
        
        return False
    
    def visualize_graph(self, output_path: str = "cloud_graph.png"):
        """Generate graph visualization using matplotlib"""
        try:
            import matplotlib.pyplot as plt
            
            plt.figure(figsize=(20, 15))
            pos = nx.spring_layout(self.graph, k=2, iterations=50)
            
            # Color nodes by sensitivity
            node_colors = [
                'red' if self.graph.nodes[node].get('sensitive', False) else 'lightblue'
                for node in self.graph.nodes()
            ]
            
            nx.draw(
                self.graph,
                pos,
                node_color=node_colors,
                node_size=500,
                font_size=8,
                font_weight='bold',
                with_labels=True,
                arrows=True,
                arrowsize=10
            )
            
            plt.title("Cloud Security Graph - Resource Relationships")
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            logger.info(f"Graph visualization saved to {output_path}")
            
        except ImportError:
            logger.warning("matplotlib not available, skipping visualization")
