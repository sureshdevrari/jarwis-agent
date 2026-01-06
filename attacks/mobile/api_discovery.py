"""
Jarwis AGI - Mobile API Discovery Engine
Automatically discovers and maps API endpoints from mobile apps

Features:
- Static API extraction from code
- Dynamic API monitoring
- Endpoint classification
- Auth requirement detection
"""

import re
import json
import asyncio
import logging
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from urllib.parse import urlparse, urljoin

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """Discovered API endpoint"""
    id: str
    url: str
    method: str = "GET"
    base_url: str = ""
    path: str = ""
    parameters: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)
    requires_auth: bool = False
    auth_type: str = ""  # bearer, basic, api_key, cookie
    request_body_type: str = ""  # json, form, multipart
    response_type: str = ""  # json, xml, html
    source: str = ""  # static, runtime, traffic
    confidence: float = 1.0


@dataclass
class APIMap:
    """Complete API map for an application"""
    app_name: str
    base_urls: List[str] = field(default_factory=list)
    endpoints: List[APIEndpoint] = field(default_factory=list)
    auth_endpoints: List[APIEndpoint] = field(default_factory=list)
    graphql_endpoints: List[str] = field(default_factory=list)
    websocket_endpoints: List[str] = field(default_factory=list)
    total_endpoints: int = 0


class APIDiscoveryEngine:
    """
    API Discovery Engine for Mobile Applications
    Discovers and maps all API endpoints used by mobile apps
    """
    
    # Common API patterns
    API_PATH_PATTERNS = [
        r'/api/v\d+/[a-zA-Z0-9/_-]+',
        r'/v\d+/[a-zA-Z0-9/_-]+',
        r'/rest/[a-zA-Z0-9/_-]+',
        r'/graphql/?',
        r'/query/?',
        r'/mutation/?',
        r'/ws/?',
        r'/socket\.io/?',
    ]
    
    # Auth-related path patterns
    AUTH_PATTERNS = [
        r'/auth/',
        r'/login',
        r'/logout',
        r'/register',
        r'/signup',
        r'/token',
        r'/oauth',
        r'/refresh',
        r'/verify',
        r'/forgot',
        r'/reset',
        r'/password',
        r'/session',
    ]
    
    # Sensitive endpoint patterns
    SENSITIVE_PATTERNS = [
        r'/admin',
        r'/user',
        r'/profile',
        r'/account',
        r'/payment',
        r'/card',
        r'/wallet',
        r'/transaction',
        r'/order',
        r'/settings',
        r'/config',
        r'/private',
        r'/internal',
    ]
    
    def __init__(self, config: dict = None):
        self.config = config or {}
        self.discovered_endpoints: Dict[str, APIEndpoint] = {}
        self.base_urls: Set[str] = set()
    
    async def discover_from_static(self, extracted_dir: Path, platform: str = "android") -> APIMap:
        """
        Discover APIs from statically extracted app files
        
        Args:
            extracted_dir: Directory containing extracted app files
            platform: 'android' or 'ios'
            
        Returns:
            APIMap with discovered endpoints
        """
        api_map = APIMap(app_name=extracted_dir.name)
        
        # File extensions to scan
        extensions = {'.java', '.kt', '.swift', '.m', '.h', '.json', '.xml', '.js', '.ts', '.smali'}
        
        for root, dirs, files in extracted_dir.rglob("*"):
            # Skip unwanted directories
            if any(skip in str(root) for skip in ['node_modules', '.git', '__MACOSX']):
                continue
            
            for file_path in files:
                if file_path.suffix.lower() in extensions:
                    await self._scan_file_for_apis(file_path)
        
        # Build API map
        api_map.endpoints = list(self.discovered_endpoints.values())
        api_map.base_urls = list(self.base_urls)
        api_map.total_endpoints = len(api_map.endpoints)
        
        # Classify endpoints
        for endpoint in api_map.endpoints:
            if any(re.search(p, endpoint.path, re.I) for p in self.AUTH_PATTERNS):
                api_map.auth_endpoints.append(endpoint)
            if '/graphql' in endpoint.path.lower():
                api_map.graphql_endpoints.append(endpoint.url)
            if any(ws in endpoint.url for ws in ['ws://', 'wss://']):
                api_map.websocket_endpoints.append(endpoint.url)
        
        return api_map
    
    async def _scan_file_for_apis(self, file_path: Path):
        """Scan a single file for API endpoints"""
        try:
            content = file_path.read_text(errors='ignore')
            
            # Find URLs
            url_pattern = r'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'
            urls = re.findall(url_pattern, content)
            
            for url in urls:
                # Skip common non-API URLs
                if any(skip in url for skip in [
                    'google.com/analytics',
                    'facebook.com',
                    'twitter.com',
                    'crashlytics',
                    'firebase.google.com',
                    'schemas.android.com',
                    'www.w3.org',
                    'xmlns',
                    '.png', '.jpg', '.gif', '.css', '.ico'
                ]):
                    continue
                
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                # Only add if it looks like an API
                if any(re.search(p, parsed.path) for p in self.API_PATH_PATTERNS):
                    self._add_endpoint(url, base_url, parsed.path, "static", file_path)
                elif any(re.search(p, parsed.path, re.I) for p in self.SENSITIVE_PATTERNS):
                    self._add_endpoint(url, base_url, parsed.path, "static", file_path)
                
                self.base_urls.add(base_url)
            
            # Find API paths without full URLs
            for pattern in self.API_PATH_PATTERNS:
                paths = re.findall(pattern, content)
                for path in paths:
                    # These will need base URL resolution later
                    endpoint_id = f"PATH-{hash(path) % 10000:04d}"
                    if endpoint_id not in self.discovered_endpoints:
                        self.discovered_endpoints[endpoint_id] = APIEndpoint(
                            id=endpoint_id,
                            url=path,
                            path=path,
                            source="static",
                            confidence=0.7
                        )
                        
        except Exception as e:
            logger.debug(f"Error scanning {file_path}: {e}")
    
    def _add_endpoint(self, url: str, base_url: str, path: str, source: str, file_path: Path = None):
        """Add an endpoint to discovered list"""
        endpoint_id = f"API-{hash(url) % 100000:05d}"
        
        if endpoint_id not in self.discovered_endpoints:
            endpoint = APIEndpoint(
                id=endpoint_id,
                url=url,
                base_url=base_url,
                path=path,
                source=source,
                confidence=0.9
            )
            
            # Detect auth requirements
            if any(re.search(p, path, re.I) for p in self.AUTH_PATTERNS):
                endpoint.requires_auth = True
            
            # Detect method from context (basic heuristic)
            if any(word in path.lower() for word in ['create', 'add', 'new', 'register', 'upload']):
                endpoint.method = "POST"
            elif any(word in path.lower() for word in ['update', 'edit', 'modify']):
                endpoint.method = "PUT"
            elif any(word in path.lower() for word in ['delete', 'remove']):
                endpoint.method = "DELETE"
            
            self.discovered_endpoints[endpoint_id] = endpoint
    
    async def discover_from_traffic(self, traffic_log: List[Dict]) -> APIMap:
        """
        Discover APIs from intercepted traffic
        
        Args:
            traffic_log: List of intercepted requests
            
        Returns:
            APIMap with discovered endpoints
        """
        api_map = APIMap(app_name="traffic_analysis")
        
        for entry in traffic_log:
            if entry.get('type') == 'request':
                url = entry.get('url', '')
                method = entry.get('method', 'GET')
                headers = entry.get('headers', {})
                
                parsed = urlparse(url)
                base_url = f"{parsed.scheme}://{parsed.netloc}"
                
                endpoint_id = f"TRAFFIC-{hash(url + method) % 100000:05d}"
                
                endpoint = APIEndpoint(
                    id=endpoint_id,
                    url=url,
                    method=method,
                    base_url=base_url,
                    path=parsed.path,
                    headers=headers,
                    source="traffic",
                    confidence=1.0
                )
                
                # Detect auth from headers
                if 'Authorization' in headers or 'authorization' in headers:
                    endpoint.requires_auth = True
                    auth_header = headers.get('Authorization', headers.get('authorization', ''))
                    if auth_header.startswith('Bearer'):
                        endpoint.auth_type = "bearer"
                    elif auth_header.startswith('Basic'):
                        endpoint.auth_type = "basic"
                
                if 'Cookie' in headers or 'cookie' in headers:
                    endpoint.requires_auth = True
                    endpoint.auth_type = "cookie"
                
                self.discovered_endpoints[endpoint_id] = endpoint
                self.base_urls.add(base_url)
        
        api_map.endpoints = list(self.discovered_endpoints.values())
        api_map.base_urls = list(self.base_urls)
        api_map.total_endpoints = len(api_map.endpoints)
        
        return api_map
    
    def merge_api_maps(self, *maps: APIMap) -> APIMap:
        """Merge multiple API maps into one"""
        merged = APIMap(app_name="merged")
        seen_urls = set()
        
        for api_map in maps:
            merged.base_urls.extend(api_map.base_urls)
            
            for endpoint in api_map.endpoints:
                url_key = f"{endpoint.method}:{endpoint.url}"
                if url_key not in seen_urls:
                    seen_urls.add(url_key)
                    merged.endpoints.append(endpoint)
                    
                    if endpoint in api_map.auth_endpoints:
                        merged.auth_endpoints.append(endpoint)
            
            merged.graphql_endpoints.extend(api_map.graphql_endpoints)
            merged.websocket_endpoints.extend(api_map.websocket_endpoints)
        
        # Deduplicate
        merged.base_urls = list(set(merged.base_urls))
        merged.graphql_endpoints = list(set(merged.graphql_endpoints))
        merged.websocket_endpoints = list(set(merged.websocket_endpoints))
        merged.total_endpoints = len(merged.endpoints)
        
        return merged
    
    def get_attack_surface(self, api_map: APIMap) -> Dict:
        """
        Analyze API map and return attack surface summary
        """
        attack_surface = {
            "total_endpoints": api_map.total_endpoints,
            "auth_endpoints": len(api_map.auth_endpoints),
            "graphql_endpoints": len(api_map.graphql_endpoints),
            "websocket_endpoints": len(api_map.websocket_endpoints),
            "base_urls": api_map.base_urls,
            "sensitive_endpoints": [],
            "high_value_targets": [],
            "recommendations": []
        }
        
        for endpoint in api_map.endpoints:
            # Identify sensitive endpoints
            if any(re.search(p, endpoint.path, re.I) for p in self.SENSITIVE_PATTERNS):
                attack_surface["sensitive_endpoints"].append({
                    "url": endpoint.url,
                    "method": endpoint.method,
                    "requires_auth": endpoint.requires_auth
                })
            
            # Identify high-value targets
            if any(word in endpoint.path.lower() for word in ['admin', 'payment', 'user', 'password']):
                attack_surface["high_value_targets"].append(endpoint.url)
        
        # Generate recommendations
        if api_map.graphql_endpoints:
            attack_surface["recommendations"].append("Test GraphQL for introspection and injection")
        
        unauthenticated = [e for e in api_map.endpoints if not e.requires_auth and 
                          any(re.search(p, e.path, re.I) for p in self.SENSITIVE_PATTERNS)]
        if unauthenticated:
            attack_surface["recommendations"].append(
                f"Found {len(unauthenticated)} potentially sensitive endpoints without auth"
            )
        
        return attack_surface
    
    def export_to_openapi(self, api_map: APIMap) -> Dict:
        """Export API map to OpenAPI 3.0 format"""
        openapi = {
            "openapi": "3.0.0",
            "info": {
                "title": f"{api_map.app_name} API",
                "version": "1.0.0",
                "description": "Auto-discovered API endpoints by Jarwis AGI"
            },
            "servers": [{"url": url} for url in api_map.base_urls],
            "paths": {}
        }
        
        for endpoint in api_map.endpoints:
            if endpoint.path not in openapi["paths"]:
                openapi["paths"][endpoint.path] = {}
            
            method = endpoint.method.lower()
            openapi["paths"][endpoint.path][method] = {
                "summary": f"Discovered endpoint",
                "operationId": endpoint.id,
                "responses": {
                    "200": {"description": "Success"}
                }
            }
            
            if endpoint.requires_auth:
                openapi["paths"][endpoint.path][method]["security"] = [
                    {"bearerAuth": []} if endpoint.auth_type == "bearer" else {"apiKey": []}
                ]
        
        return openapi
