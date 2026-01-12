"""
Jarwis AGI Pen Test - Mobile Request Store (SQLite-backed)

Scalable request/response storage for mobile app security scanning.
Handles intercepted traffic from Frida hooks and MITM proxy.

Features:
- Stores requests captured via Frida (OkHttp, Retrofit, Alamofire, etc.)
- Stores requests captured via MITM proxy
- Tracks source (frida/mitm) for correlation
- App package/bundle ID tracking
- Request-level checkpoint for scanner resume
- Batch iteration (generator-based)
- Attack request/response storage

Usage:
    store = MobileRequestStoreDB(scan_id="mobile_scan_123", app_package="com.example.app")
    await store.initialize()
    
    # Add request from Frida hook
    req_id = await store.add_request(
        url="https://api.example.com/users",
        method="POST",
        headers={"Authorization": "Bearer xxx"},
        body='{"username": "test"}',
        source="frida",
        frida_hook="okhttp3"
    )
    
    # Iterate requests for scanning
    async for request in store.iter_unprocessed(scanner_name="sqli"):
        # Attack the request
        pass
    
    await store.close()
"""

import aiosqlite
import asyncio
import json
import hashlib
import logging
import re
from typing import Dict, List, Optional, Any, AsyncGenerator, Tuple, Set
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from enum import Enum
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class MobileRequestSource(Enum):
    """Source of the captured request"""
    FRIDA = "frida"           # Captured via Frida instrumentation
    MITM = "mitm"             # Captured via MITM proxy
    MANUAL = "manual"         # Manually added for testing
    REPLAY = "replay"         # Replayed from previous scan


class MobileRequestStatus(Enum):
    """Processing status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class MobileRequestPriority(Enum):
    """Attack priority based on endpoint characteristics"""
    CRITICAL = 1   # Auth endpoints, payment, sensitive data
    HIGH = 2       # API endpoints with parameters
    MEDIUM = 3     # Other API endpoints
    LOW = 4        # Static resources, analytics


@dataclass
class StoredMobileRequest:
    """Request captured from mobile app traffic"""
    id: str
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: str = ""
    content_type: str = ""
    
    # Mobile-specific context
    source: str = "frida"              # frida, mitm, manual
    frida_hook: str = ""               # okhttp3, retrofit, alamofire, urlsession, etc.
    app_package: str = ""              # com.example.app (Android) or bundle ID (iOS)
    app_version: str = ""
    platform: str = "android"          # android or ios
    
    # Authentication context
    has_auth_token: bool = False
    auth_token_type: str = ""          # bearer, basic, api_key, cookie, custom
    auth_token_value: str = ""
    auth_header_name: str = ""         # Authorization, X-API-Key, etc.
    
    # Request analysis
    endpoint_type: str = ""            # login, register, api, graphql, websocket
    parameters: Dict[str, str] = field(default_factory=dict)
    is_sensitive: bool = False         # Contains PII, payment, etc.
    
    # Processing status
    status: str = "pending"
    priority: int = 2
    processed_by: List[str] = field(default_factory=list)
    error_message: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return asdict(self)
    
    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> 'StoredMobileRequest':
        """Create from database row"""
        return cls(
            id=row['id'],
            url=row['url'],
            method=row['method'],
            headers=json.loads(row['headers']) if row['headers'] else {},
            body=row['body'] or "",
            cookies=json.loads(row['cookies']) if row['cookies'] else {},
            timestamp=row['timestamp'] or "",
            content_type=row['content_type'] or "",
            source=row['source'] or "frida",
            frida_hook=row['frida_hook'] or "",
            app_package=row['app_package'] or "",
            app_version=row['app_version'] or "",
            platform=row['platform'] or "android",
            has_auth_token=bool(row['has_auth_token']),
            auth_token_type=row['auth_token_type'] or "",
            auth_token_value=row['auth_token_value'] or "",
            auth_header_name=row['auth_header_name'] or "",
            endpoint_type=row['endpoint_type'] or "",
            parameters=json.loads(row['parameters']) if row['parameters'] else {},
            is_sensitive=bool(row['is_sensitive']),
            status=row['status'] or "pending",
            priority=row['priority'] or 2,
            processed_by=json.loads(row['processed_by']) if row['processed_by'] else [],
            error_message=row['error_message'] or ""
        )
    
    def get_base_url(self) -> str:
        """Get base URL without query parameters"""
        parsed = urlparse(self.url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    
    def has_injectable_params(self) -> bool:
        """Check if request has parameters that can be fuzzed"""
        # Query params
        parsed = urlparse(self.url)
        if parsed.query:
            return True
        # Body params (JSON or form)
        if self.body and self.method.upper() in ['POST', 'PUT', 'PATCH']:
            return True
        return False


@dataclass
class StoredMobileResponse:
    """Response captured from mobile app traffic"""
    request_id: str
    status_code: int
    headers: Dict[str, str]
    body: str = ""
    content_type: str = ""
    content_length: int = 0
    timestamp: str = ""
    response_time_ms: float = 0
    
    # Response analysis
    has_sensitive_data: bool = False
    sensitive_data_types: List[str] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)
    is_json: bool = False
    is_binary: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> 'StoredMobileResponse':
        return cls(
            request_id=row['request_id'],
            status_code=row['status_code'],
            headers=json.loads(row['headers']) if row['headers'] else {},
            body=row['body'] or "",
            content_type=row['content_type'] or "",
            content_length=row['content_length'] or 0,
            timestamp=row['timestamp'] or "",
            response_time_ms=row['response_time_ms'] or 0,
            has_sensitive_data=bool(row['has_sensitive_data']),
            sensitive_data_types=json.loads(row['sensitive_data_types']) if row['sensitive_data_types'] else [],
            error_messages=json.loads(row['error_messages']) if row['error_messages'] else [],
            is_json=bool(row['is_json']),
            is_binary=bool(row['is_binary'])
        )


class MobileRequestStoreDB:
    """
    SQLite-backed request store for mobile app security scanning.
    
    Tables:
    - mobile_requests: All captured mobile app requests
    - mobile_responses: All captured responses
    - mobile_attack_requests: Requests sent by mobile scanners
    - mobile_attack_responses: Responses from attack requests
    - mobile_auth_tokens: Authentication tokens (Bearer, API keys, etc.)
    - mobile_scanner_progress: Scanner checkpoint tracking
    - mobile_endpoints: Discovered API endpoints summary
    """
    
    # Patterns for sensitive endpoint detection
    SENSITIVE_PATTERNS = [
        r'/auth', r'/login', r'/signin', r'/register', r'/signup',
        r'/password', r'/reset', r'/token', r'/oauth', r'/sso',
        r'/payment', r'/checkout', r'/billing', r'/card',
        r'/user', r'/profile', r'/account', r'/me',
        r'/admin', r'/dashboard', r'/settings',
        r'/upload', r'/file', r'/document',
        r'/api/v\d+', r'/graphql', r'/gql'
    ]
    
    # Auth header patterns
    AUTH_HEADERS = [
        'authorization', 'x-api-key', 'x-auth-token', 'x-access-token',
        'api-key', 'apikey', 'token', 'x-csrf-token', 'x-xsrf-token'
    ]
    
    def __init__(
        self,
        scan_id: str,
        app_package: str = "",
        platform: str = "android",
        storage_dir: str = "temp/mobile_scans"
    ):
        self.scan_id = scan_id
        self.app_package = app_package
        self.platform = platform
        self.storage_dir = Path(storage_dir) / scan_id
        self.db_path = self.storage_dir / "mobile_requests.db"
        
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()
        self._url_hashes: Set[str] = set()  # Deduplication cache
        
        # Stats
        self.stats = {
            'frida_requests': 0,
            'mitm_requests': 0,
            'auth_requests': 0,
            'attack_requests': 0,
            'unique_endpoints': 0
        }
        
        logger.info(f"MobileRequestStoreDB initialized: {self.db_path} for {app_package}")
    
    async def initialize(self):
        """Initialize database and create tables"""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self._db = await aiosqlite.connect(str(self.db_path))
        self._db.row_factory = aiosqlite.Row
        
        # Enable WAL mode for concurrent access
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA cache_size=10000")
        
        await self._create_tables()
        await self._db.commit()
        
        # Load existing URL hashes for deduplication
        await self._load_url_hashes()
        
        logger.info(f"MobileRequestStoreDB initialized at {self.db_path}")
    
    async def _create_tables(self):
        """Create all required tables for mobile request storage"""
        
        # Mobile requests table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS mobile_requests (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                method TEXT NOT NULL,
                headers TEXT NOT NULL,
                body TEXT,
                cookies TEXT,
                timestamp TEXT,
                content_type TEXT,
                
                -- Mobile-specific fields
                source TEXT DEFAULT 'frida',
                frida_hook TEXT,
                app_package TEXT,
                app_version TEXT,
                platform TEXT DEFAULT 'android',
                
                -- Auth context
                has_auth_token INTEGER DEFAULT 0,
                auth_token_type TEXT,
                auth_token_value TEXT,
                auth_header_name TEXT,
                
                -- Analysis
                endpoint_type TEXT,
                parameters TEXT,
                is_sensitive INTEGER DEFAULT 0,
                
                -- Processing
                status TEXT DEFAULT 'pending',
                priority INTEGER DEFAULT 2,
                processed_by TEXT,
                error_message TEXT,
                
                -- Metadata
                url_hash TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Mobile responses table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS mobile_responses (
                request_id TEXT PRIMARY KEY,
                status_code INTEGER NOT NULL,
                headers TEXT NOT NULL,
                body TEXT,
                content_type TEXT,
                content_length INTEGER,
                timestamp TEXT,
                response_time_ms REAL,
                has_sensitive_data INTEGER DEFAULT 0,
                sensitive_data_types TEXT,
                error_messages TEXT,
                is_json INTEGER DEFAULT 0,
                is_binary INTEGER DEFAULT 0,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES mobile_requests(id)
            )
        """)
        
        # Attack requests table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS mobile_attack_requests (
                id TEXT PRIMARY KEY,
                original_request_id TEXT,
                scanner_name TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                url TEXT NOT NULL,
                method TEXT NOT NULL,
                headers TEXT NOT NULL,
                body TEXT,
                payload TEXT,
                payload_location TEXT,
                parameter_name TEXT,
                timestamp TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (original_request_id) REFERENCES mobile_requests(id)
            )
        """)
        
        # Attack responses table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS mobile_attack_responses (
                attack_request_id TEXT PRIMARY KEY,
                status_code INTEGER NOT NULL,
                headers TEXT NOT NULL,
                body TEXT,
                response_time_ms REAL,
                body_length INTEGER,
                content_type TEXT,
                timestamp TEXT,
                is_vulnerable INTEGER DEFAULT 0,
                vulnerability_type TEXT,
                evidence TEXT,
                confidence TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (attack_request_id) REFERENCES mobile_attack_requests(id)
            )
        """)
        
        # Auth tokens table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS mobile_auth_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                token_type TEXT NOT NULL,
                token_value TEXT NOT NULL,
                header_name TEXT,
                header_prefix TEXT,
                cookie_name TEXT,
                expires_at TEXT,
                refresh_token TEXT,
                source TEXT,
                captured_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scanner progress table (checkpoint/resume)
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS mobile_scanner_progress (
                scanner_name TEXT,
                request_id TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                findings_count INTEGER DEFAULT 0,
                error_message TEXT,
                PRIMARY KEY (scanner_name, request_id),
                FOREIGN KEY (request_id) REFERENCES mobile_requests(id)
            )
        """)
        
        # Discovered endpoints summary
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS mobile_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                base_url TEXT NOT NULL,
                method TEXT NOT NULL,
                endpoint_type TEXT,
                has_params INTEGER DEFAULT 0,
                param_names TEXT,
                requires_auth INTEGER DEFAULT 0,
                request_count INTEGER DEFAULT 1,
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(base_url, method)
            )
        """)
        
        # Create indexes
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_req_source ON mobile_requests(source)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_req_status ON mobile_requests(status)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_req_priority ON mobile_requests(priority)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_req_package ON mobile_requests(app_package)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_req_auth ON mobile_requests(has_auth_token)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_req_hash ON mobile_requests(url_hash)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_attack_scanner ON mobile_attack_requests(scanner_name)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_mobile_progress_status ON mobile_scanner_progress(status)")
    
    async def _load_url_hashes(self):
        """Load existing URL hashes for deduplication"""
        async with self._lock:
            cursor = await self._db.execute("SELECT url_hash FROM mobile_requests WHERE url_hash IS NOT NULL")
            rows = await cursor.fetchall()
            self._url_hashes = {row['url_hash'] for row in rows}
            logger.debug(f"Loaded {len(self._url_hashes)} URL hashes for deduplication")
    
    def _generate_url_hash(self, url: str, method: str, body: str = "") -> str:
        """Generate hash for deduplication"""
        parsed = urlparse(url)
        # Normalize: ignore query param order
        base = f"{method}:{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if body:
            base += f":{hashlib.md5(body.encode()).hexdigest()[:8]}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]
    
    def _detect_auth_token(self, headers: Dict[str, str]) -> Tuple[bool, str, str, str]:
        """Detect auth token in headers"""
        headers_lower = {k.lower(): (k, v) for k, v in headers.items()}
        
        for auth_header in self.AUTH_HEADERS:
            if auth_header in headers_lower:
                orig_key, value = headers_lower[auth_header]
                
                # Determine token type
                if value.lower().startswith('bearer '):
                    return True, 'bearer', value[7:], orig_key
                elif value.lower().startswith('basic '):
                    return True, 'basic', value[6:], orig_key
                else:
                    return True, 'api_key', value, orig_key
        
        return False, '', '', ''
    
    def _detect_endpoint_type(self, url: str, method: str) -> str:
        """Detect endpoint type based on URL patterns"""
        url_lower = url.lower()
        
        if '/auth' in url_lower or '/login' in url_lower or '/signin' in url_lower:
            return 'auth'
        elif '/register' in url_lower or '/signup' in url_lower:
            return 'registration'
        elif '/graphql' in url_lower or '/gql' in url_lower:
            return 'graphql'
        elif '/ws' in url_lower or 'websocket' in url_lower:
            return 'websocket'
        elif '/upload' in url_lower or '/file' in url_lower:
            return 'file_upload'
        elif '/payment' in url_lower or '/checkout' in url_lower:
            return 'payment'
        elif any(p in url_lower for p in ['/user', '/profile', '/account', '/me']):
            return 'user_data'
        elif '/api/' in url_lower:
            return 'api'
        else:
            return 'other'
    
    def _calculate_priority(
        self,
        url: str,
        method: str,
        has_auth: bool,
        has_params: bool,
        endpoint_type: str
    ) -> int:
        """Calculate attack priority (lower = higher priority)"""
        priority = MobileRequestPriority.MEDIUM.value
        
        # Critical endpoints
        if endpoint_type in ['auth', 'payment', 'user_data']:
            priority = MobileRequestPriority.CRITICAL.value
        # High priority: mutable methods with params
        elif method.upper() in ['POST', 'PUT', 'PATCH', 'DELETE'] and has_params:
            priority = MobileRequestPriority.HIGH.value
        # Low priority: GET without params
        elif method.upper() == 'GET' and not has_params:
            priority = MobileRequestPriority.LOW.value
        
        # Boost authenticated requests
        if has_auth and priority > MobileRequestPriority.HIGH.value:
            priority = MobileRequestPriority.HIGH.value
        
        return priority
    
    def _is_sensitive_endpoint(self, url: str) -> bool:
        """Check if endpoint handles sensitive data"""
        url_lower = url.lower()
        return any(re.search(pattern, url_lower) for pattern in self.SENSITIVE_PATTERNS)
    
    def _extract_parameters(self, url: str, body: str, content_type: str) -> Dict[str, str]:
        """Extract parameters from URL and body"""
        params = {}
        
        # Query parameters
        parsed = urlparse(url)
        if parsed.query:
            params.update(parse_qs(parsed.query, keep_blank_values=True))
            # Flatten single-value lists
            params = {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        
        # Body parameters
        if body:
            if 'json' in content_type.lower():
                try:
                    body_params = json.loads(body)
                    if isinstance(body_params, dict):
                        params.update({k: str(v)[:100] for k, v in body_params.items()})
                except:
                    pass
            elif 'form' in content_type.lower():
                try:
                    for pair in body.split('&'):
                        if '=' in pair:
                            k, v = pair.split('=', 1)
                            params[k] = v[:100]
                except:
                    pass
        
        return params
    
    async def add_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str = "",
        cookies: Dict[str, str] = None,
        source: str = "frida",
        frida_hook: str = "",
        app_package: str = None,
        app_version: str = "",
        platform: str = None,
        deduplicate: bool = True
    ) -> Optional[str]:
        """
        Add a captured request to the store.
        
        Returns:
            Request ID if added, None if deduplicated
        """
        cookies = cookies or {}
        app_package = app_package or self.app_package
        platform = platform or self.platform
        content_type = headers.get('Content-Type', headers.get('content-type', ''))
        
        # Generate hash for deduplication
        url_hash = self._generate_url_hash(url, method, body)
        
        # Check for duplicate
        if deduplicate and url_hash in self._url_hashes:
            logger.debug(f"Skipping duplicate request: {method} {url[:60]}")
            return None
        
        # Generate unique ID
        request_id = hashlib.md5(
            f"{url}:{method}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        # Detect auth token
        has_auth, auth_type, auth_value, auth_header = self._detect_auth_token(headers)
        
        # Analyze endpoint
        endpoint_type = self._detect_endpoint_type(url, method)
        parameters = self._extract_parameters(url, body, content_type)
        is_sensitive = self._is_sensitive_endpoint(url)
        has_params = bool(parameters)
        
        # Calculate priority
        priority = self._calculate_priority(url, method, has_auth, has_params, endpoint_type)
        
        async with self._lock:
            await self._db.execute("""
                INSERT INTO mobile_requests (
                    id, url, method, headers, body, cookies, timestamp, content_type,
                    source, frida_hook, app_package, app_version, platform,
                    has_auth_token, auth_token_type, auth_token_value, auth_header_name,
                    endpoint_type, parameters, is_sensitive, status, priority,
                    processed_by, url_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id, url, method, json.dumps(headers), body, json.dumps(cookies),
                datetime.now().isoformat(), content_type,
                source, frida_hook, app_package, app_version, platform,
                int(has_auth), auth_type, auth_value, auth_header,
                endpoint_type, json.dumps(parameters), int(is_sensitive),
                'pending', priority, '[]', url_hash
            ))
            
            await self._db.commit()
            self._url_hashes.add(url_hash)
        
        # Update stats
        if source == 'frida':
            self.stats['frida_requests'] += 1
        elif source == 'mitm':
            self.stats['mitm_requests'] += 1
        if has_auth:
            self.stats['auth_requests'] += 1
        
        logger.debug(f"Added mobile request: {method} {url[:60]} (source={source}, auth={has_auth})")
        return request_id
    
    async def add_response(
        self,
        request_id: str,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        response_time_ms: float = 0
    ) -> bool:
        """Add response for a captured request"""
        content_type = headers.get('Content-Type', headers.get('content-type', ''))
        is_json = 'json' in content_type.lower()
        is_binary = any(t in content_type.lower() for t in ['image', 'video', 'audio', 'octet'])
        
        async with self._lock:
            await self._db.execute("""
                INSERT OR REPLACE INTO mobile_responses (
                    request_id, status_code, headers, body, content_type,
                    content_length, timestamp, response_time_ms,
                    is_json, is_binary
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id, status_code, json.dumps(headers),
                body[:50000] if body else "",  # Limit body size
                content_type, len(body) if body else 0,
                datetime.now().isoformat(), response_time_ms,
                int(is_json), int(is_binary)
            ))
            await self._db.commit()
        
        return True
    
    async def get_request(self, request_id: str) -> Optional[StoredMobileRequest]:
        """Get a specific request by ID"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM mobile_requests WHERE id = ?", (request_id,)
            )
            row = await cursor.fetchone()
            return StoredMobileRequest.from_row(row) if row else None
    
    async def get_response(self, request_id: str) -> Optional[StoredMobileResponse]:
        """Get response for a request"""
        async with self._lock:
            cursor = await self._db.execute(
                "SELECT * FROM mobile_responses WHERE request_id = ?", (request_id,)
            )
            row = await cursor.fetchone()
            return StoredMobileResponse.from_row(row) if row else None
    
    async def iter_requests(
        self,
        source: str = None,
        has_auth: bool = None,
        has_params: bool = None,
        status: str = None,
        priority_max: int = None,
        batch_size: int = 100
    ) -> AsyncGenerator[StoredMobileRequest, None]:
        """
        Iterate through requests with optional filters.
        Generator-based for memory efficiency.
        """
        conditions = []
        params = []
        
        if source:
            conditions.append("source = ?")
            params.append(source)
        if has_auth is not None:
            conditions.append("has_auth_token = ?")
            params.append(int(has_auth))
        if status:
            conditions.append("status = ?")
            params.append(status)
        if priority_max:
            conditions.append("priority <= ?")
            params.append(priority_max)
        
        where_clause = " AND ".join(conditions) if conditions else "1=1"
        
        offset = 0
        while True:
            async with self._lock:
                cursor = await self._db.execute(f"""
                    SELECT * FROM mobile_requests
                    WHERE {where_clause}
                    ORDER BY priority ASC, created_at ASC
                    LIMIT ? OFFSET ?
                """, (*params, batch_size, offset))
                
                rows = await cursor.fetchall()
            
            if not rows:
                break
            
            for row in rows:
                # Additional has_params filter (requires parsing)
                req = StoredMobileRequest.from_row(row)
                if has_params is not None:
                    if has_params != req.has_injectable_params():
                        continue
                yield req
            
            offset += batch_size
    
    async def iter_unprocessed(
        self,
        scanner_name: str,
        batch_size: int = 50
    ) -> AsyncGenerator[StoredMobileRequest, None]:
        """
        Iterate through requests not yet processed by a specific scanner.
        This enables checkpoint/resume functionality.
        """
        offset = 0
        while True:
            async with self._lock:
                cursor = await self._db.execute("""
                    SELECT r.* FROM mobile_requests r
                    LEFT JOIN mobile_scanner_progress p 
                        ON r.id = p.request_id AND p.scanner_name = ?
                    WHERE p.status IS NULL OR p.status = 'pending'
                    ORDER BY r.priority ASC, r.created_at ASC
                    LIMIT ? OFFSET ?
                """, (scanner_name, batch_size, offset))
                
                rows = await cursor.fetchall()
            
            if not rows:
                break
            
            for row in rows:
                yield StoredMobileRequest.from_row(row)
            
            offset += batch_size
    
    async def mark_processing(self, request_id: str, scanner_name: str):
        """Mark a request as being processed by a scanner"""
        async with self._lock:
            await self._db.execute("""
                INSERT OR REPLACE INTO mobile_scanner_progress 
                (scanner_name, request_id, status, started_at)
                VALUES (?, ?, 'in_progress', ?)
            """, (scanner_name, request_id, datetime.now().isoformat()))
            await self._db.commit()
    
    async def mark_completed(
        self,
        request_id: str,
        scanner_name: str,
        findings_count: int = 0
    ):
        """Mark a request as completed by a scanner"""
        async with self._lock:
            await self._db.execute("""
                UPDATE mobile_scanner_progress
                SET status = 'completed', completed_at = ?, findings_count = ?
                WHERE scanner_name = ? AND request_id = ?
            """, (datetime.now().isoformat(), findings_count, scanner_name, request_id))
            await self._db.commit()
    
    async def mark_failed(
        self,
        request_id: str,
        scanner_name: str,
        error_message: str = ""
    ):
        """Mark a request as failed for a scanner"""
        async with self._lock:
            await self._db.execute("""
                UPDATE mobile_scanner_progress
                SET status = 'failed', completed_at = ?, error_message = ?
                WHERE scanner_name = ? AND request_id = ?
            """, (datetime.now().isoformat(), error_message, scanner_name, request_id))
            await self._db.commit()
    
    async def add_attack_request(
        self,
        original_request_id: str,
        scanner_name: str,
        attack_type: str,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str = "",
        payload: str = "",
        payload_location: str = "",
        parameter_name: str = ""
    ) -> str:
        """Store an attack request for documentation"""
        attack_id = hashlib.md5(
            f"{original_request_id}:{scanner_name}:{payload}:{datetime.now().isoformat()}".encode()
        ).hexdigest()[:16]
        
        async with self._lock:
            await self._db.execute("""
                INSERT INTO mobile_attack_requests (
                    id, original_request_id, scanner_name, attack_type,
                    url, method, headers, body, payload, payload_location,
                    parameter_name, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attack_id, original_request_id, scanner_name, attack_type,
                url, method, json.dumps(headers), body, payload, payload_location,
                parameter_name, datetime.now().isoformat()
            ))
            await self._db.commit()
        
        self.stats['attack_requests'] += 1
        return attack_id
    
    async def add_attack_response(
        self,
        attack_request_id: str,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        response_time_ms: float = 0,
        is_vulnerable: bool = False,
        vulnerability_type: str = "",
        evidence: str = "",
        confidence: str = "medium"
    ):
        """Store attack response"""
        async with self._lock:
            await self._db.execute("""
                INSERT OR REPLACE INTO mobile_attack_responses (
                    attack_request_id, status_code, headers, body,
                    response_time_ms, body_length, content_type, timestamp,
                    is_vulnerable, vulnerability_type, evidence, confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attack_request_id, status_code, json.dumps(headers),
                body[:50000] if body else "",
                response_time_ms, len(body) if body else 0,
                headers.get('Content-Type', ''),
                datetime.now().isoformat(),
                int(is_vulnerable), vulnerability_type, evidence, confidence
            ))
            await self._db.commit()
    
    async def store_auth_token(
        self,
        token_type: str,
        token_value: str,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer",
        source: str = "frida"
    ):
        """Store captured auth token"""
        async with self._lock:
            await self._db.execute("""
                INSERT INTO mobile_auth_tokens 
                (token_type, token_value, header_name, header_prefix, source)
                VALUES (?, ?, ?, ?, ?)
            """, (token_type, token_value, header_name, header_prefix, source))
            await self._db.commit()
        
        logger.info(f"Stored auth token: {token_type} (source={source})")
    
    async def get_latest_auth_token(self, token_type: str = "bearer") -> Optional[Dict]:
        """Get the latest auth token of a specific type"""
        async with self._lock:
            cursor = await self._db.execute("""
                SELECT * FROM mobile_auth_tokens
                WHERE token_type = ?
                ORDER BY captured_at DESC
                LIMIT 1
            """, (token_type,))
            row = await cursor.fetchone()
            
            if row:
                return {
                    'token_type': row['token_type'],
                    'token_value': row['token_value'],
                    'header_name': row['header_name'],
                    'header_prefix': row['header_prefix']
                }
            return None
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get store statistics"""
        async with self._lock:
            # Total requests
            cursor = await self._db.execute("SELECT COUNT(*) as count FROM mobile_requests")
            row = await cursor.fetchone()
            total = row['count']
            
            # By source
            cursor = await self._db.execute("""
                SELECT source, COUNT(*) as count 
                FROM mobile_requests GROUP BY source
            """)
            by_source = {row['source']: row['count'] for row in await cursor.fetchall()}
            
            # By auth status
            cursor = await self._db.execute("""
                SELECT has_auth_token, COUNT(*) as count 
                FROM mobile_requests GROUP BY has_auth_token
            """)
            auth_rows = await cursor.fetchall()
            auth_count = sum(row['count'] for row in auth_rows if row['has_auth_token'])
            
            # Unique endpoints
            cursor = await self._db.execute("""
                SELECT COUNT(DISTINCT url_hash) as count FROM mobile_requests
            """)
            unique = (await cursor.fetchone())['count']
            
            # Scanner progress
            cursor = await self._db.execute("""
                SELECT scanner_name, status, COUNT(*) as count
                FROM mobile_scanner_progress
                GROUP BY scanner_name, status
            """)
            progress_rows = await cursor.fetchall()
            scanner_progress = {}
            for row in progress_rows:
                if row['scanner_name'] not in scanner_progress:
                    scanner_progress[row['scanner_name']] = {}
                scanner_progress[row['scanner_name']][row['status']] = row['count']
        
        return {
            'total_requests': total,
            'by_source': by_source,
            'authenticated_requests': auth_count,
            'unique_endpoints': unique,
            'attack_requests': self.stats['attack_requests'],
            'scanner_progress': scanner_progress
        }
    
    async def close(self):
        """Close database connection"""
        if self._db:
            await self._db.close()
            self._db = None
            logger.info("MobileRequestStoreDB closed")
    
    async def __aenter__(self):
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
