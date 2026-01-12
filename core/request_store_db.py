"""
Jarwis AGI Pen Test - SQLite-backed Request Store

Scalable request/response storage using SQLite instead of in-memory dicts.
Handles 100K+ requests without memory exhaustion.

Features:
- Separate tables for pre-login and post-login requests
- Attack request/response storage
- Request-level status tracking for checkpoint/resume
- Batch iteration (generator-based) to avoid loading all into memory
- Full-text search on request content
- Request prioritization (interesting requests first)

Usage:
    store = RequestStoreDB(scan_id="scan_123")
    await store.initialize()
    
    # Add requests
    req_id = await store.add_request(url, method, headers, body, is_post_login=False)
    
    # Iterate requests in batches
    async for request in store.iter_requests(post_login=False, batch_size=100):
        # Process request
        pass
    
    await store.close()
"""

import aiosqlite
import asyncio
import json
import hashlib
import logging
import os
from typing import Dict, List, Optional, Any, AsyncGenerator, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from pathlib import Path
from enum import Enum
from contextlib import asynccontextmanager

logger = logging.getLogger(__name__)


class RequestStatus(Enum):
    """Status of a request in the processing pipeline"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class RequestPriority(Enum):
    """Priority for attack targeting"""
    HIGH = 1    # Forms, APIs with params, auth endpoints
    MEDIUM = 2  # Dynamic pages with query strings
    LOW = 3     # Static resources, no params


@dataclass
class StoredRequest:
    """Request stored in SQLite database"""
    id: str
    url: str
    method: str
    headers: Dict[str, str]
    body: str = ""
    cookies: Dict[str, str] = field(default_factory=dict)
    timestamp: str = ""
    content_type: str = ""
    
    # Authentication context
    has_auth_token: bool = False
    auth_token_type: str = ""
    auth_token_value: str = ""
    
    # Request metadata
    is_post_login: bool = False
    endpoint_type: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    
    # Processing status
    status: str = "pending"
    priority: int = 2
    processed_by: List[str] = field(default_factory=list)  # Scanner names that processed this
    error_message: str = ""
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'url': self.url,
            'method': self.method,
            'headers': self.headers,
            'body': self.body,
            'cookies': self.cookies,
            'timestamp': self.timestamp,
            'content_type': self.content_type,
            'has_auth_token': self.has_auth_token,
            'auth_token_type': self.auth_token_type,
            'auth_token_value': self.auth_token_value,
            'is_post_login': self.is_post_login,
            'endpoint_type': self.endpoint_type,
            'parameters': self.parameters,
            'status': self.status,
            'priority': self.priority,
            'processed_by': self.processed_by,
            'error_message': self.error_message
        }
    
    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> 'StoredRequest':
        """Create from database row"""
        return cls(
            id=row['id'],
            url=row['url'],
            method=row['method'],
            headers=json.loads(row['headers']),
            body=row['body'] or "",
            cookies=json.loads(row['cookies']) if row['cookies'] else {},
            timestamp=row['timestamp'],
            content_type=row['content_type'] or "",
            has_auth_token=bool(row['has_auth_token']),
            auth_token_type=row['auth_token_type'] or "",
            auth_token_value=row['auth_token_value'] or "",
            is_post_login=bool(row['is_post_login']),
            endpoint_type=row['endpoint_type'] or "",
            parameters=json.loads(row['parameters']) if row['parameters'] else {},
            status=row['status'],
            priority=row['priority'],
            processed_by=json.loads(row['processed_by']) if row['processed_by'] else [],
            error_message=row['error_message'] or ""
        )


@dataclass
class StoredResponse:
    """Response stored in SQLite database"""
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
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    @classmethod
    def from_row(cls, row: aiosqlite.Row) -> 'StoredResponse':
        return cls(
            request_id=row['request_id'],
            status_code=row['status_code'],
            headers=json.loads(row['headers']),
            body=row['body'] or "",
            content_type=row['content_type'] or "",
            content_length=row['content_length'] or 0,
            timestamp=row['timestamp'],
            response_time_ms=row['response_time_ms'] or 0,
            has_sensitive_data=bool(row['has_sensitive_data']),
            sensitive_data_types=json.loads(row['sensitive_data_types']) if row['sensitive_data_types'] else [],
            error_messages=json.loads(row['error_messages']) if row['error_messages'] else []
        )


class RequestStoreDB:
    """
    SQLite-backed request store for scalable web scanning.
    
    Tables:
    - requests: All captured requests (pre and post login)
    - responses: All captured responses
    - attack_requests: Requests sent by scanners
    - attack_responses: Responses from scanner attacks
    - auth_tokens: Stored authentication tokens
    - scan_progress: Request-level progress tracking
    """
    
    def __init__(self, scan_id: str, storage_dir: str = "temp/scans"):
        self.scan_id = scan_id
        self.storage_dir = Path(storage_dir) / scan_id
        self.db_path = self.storage_dir / "requests.db"
        
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()
        
        # Stats
        self.stats = {
            'pre_login_count': 0,
            'post_login_count': 0,
            'attack_request_count': 0
        }
        
        logger.info(f"RequestStoreDB initialized: {self.db_path}")
    
    async def initialize(self):
        """Initialize database and create tables"""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        self._db = await aiosqlite.connect(str(self.db_path))
        self._db.row_factory = aiosqlite.Row
        
        # Enable WAL mode for better concurrent performance
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA cache_size=10000")
        
        await self._create_tables()
        await self._db.commit()
        
        logger.info(f"RequestStoreDB initialized with SQLite at {self.db_path}")
    
    async def _create_tables(self):
        """Create all required tables"""
        
        # Requests table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id TEXT PRIMARY KEY,
                url TEXT NOT NULL,
                method TEXT NOT NULL,
                headers TEXT NOT NULL,
                body TEXT,
                cookies TEXT,
                timestamp TEXT,
                content_type TEXT,
                has_auth_token INTEGER DEFAULT 0,
                auth_token_type TEXT,
                auth_token_value TEXT,
                is_post_login INTEGER DEFAULT 0,
                endpoint_type TEXT,
                parameters TEXT,
                status TEXT DEFAULT 'pending',
                priority INTEGER DEFAULT 2,
                processed_by TEXT,
                error_message TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Responses table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS responses (
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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (request_id) REFERENCES requests(id)
            )
        """)
        
        # Attack requests table (requests modified and sent by scanners)
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS attack_requests (
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
                FOREIGN KEY (original_request_id) REFERENCES requests(id)
            )
        """)
        
        # Attack responses table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS attack_responses (
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
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (attack_request_id) REFERENCES attack_requests(id)
            )
        """)
        
        # Auth tokens table
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token_type TEXT PRIMARY KEY,
                token_value TEXT NOT NULL,
                expires_at TEXT,
                refresh_token TEXT,
                header_name TEXT,
                header_prefix TEXT,
                cookie_name TEXT,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Scanner progress table (which scanner processed which request)
        await self._db.execute("""
            CREATE TABLE IF NOT EXISTS scanner_progress (
                scanner_name TEXT,
                request_id TEXT,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                error_message TEXT,
                PRIMARY KEY (scanner_name, request_id),
                FOREIGN KEY (request_id) REFERENCES requests(id)
            )
        """)
        
        # Create indexes for common queries
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_requests_post_login ON requests(is_post_login)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_requests_priority ON requests(priority)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_requests_method ON requests(method)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_attack_requests_scanner ON attack_requests(scanner_name)")
        await self._db.execute("CREATE INDEX IF NOT EXISTS idx_scanner_progress_status ON scanner_progress(status)")
    
    async def close(self):
        """Close database connection"""
        if self._db:
            await self._db.close()
            self._db = None
            logger.info("RequestStoreDB closed")
    
    def _generate_request_id(self, url: str, method: str, body: str = "") -> str:
        """Generate unique ID for a request"""
        content = f"{method}:{url}:{body[:100]}"
        return hashlib.md5(content.encode()).hexdigest()[:12]
    
    def _detect_priority(self, url: str, method: str, parameters: Dict, endpoint_type: str) -> int:
        """Detect request priority for attack targeting"""
        # High priority: POST/PUT with params, auth endpoints, APIs
        if method in ['POST', 'PUT', 'PATCH', 'DELETE'] and parameters:
            return RequestPriority.HIGH.value
        if any(kw in url.lower() for kw in ['login', 'auth', 'admin', 'api', 'user', 'password']):
            return RequestPriority.HIGH.value
        if endpoint_type in ['api', 'form']:
            return RequestPriority.HIGH.value
        
        # Medium: GET with params
        if parameters:
            return RequestPriority.MEDIUM.value
        
        # Low: Static, no params
        return RequestPriority.LOW.value
    
    def _detect_endpoint_type(self, url: str, headers: Dict[str, str]) -> str:
        """Detect type of endpoint"""
        url_lower = url.lower()
        content_type = headers.get('Content-Type', '').lower()
        accept = headers.get('Accept', '').lower()
        
        if '/api/' in url_lower or 'application/json' in content_type or 'application/json' in accept:
            return 'api'
        if 'x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type:
            return 'form'
        if 'xmlhttprequest' in headers.get('X-Requested-With', '').lower():
            return 'ajax'
        if any(ext in url_lower for ext in ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff']):
            return 'static'
        
        return 'page'
    
    def _parse_parameters(self, url: str, body: str, content_type: str) -> Dict[str, str]:
        """Parse parameters from URL and body"""
        from urllib.parse import urlparse, parse_qs
        
        params = {}
        
        # Parse URL query parameters
        parsed = urlparse(url)
        if parsed.query:
            for key, values in parse_qs(parsed.query).items():
                params[key] = values[0] if values else ''
        
        # Parse body parameters
        if body:
            if 'application/x-www-form-urlencoded' in content_type:
                for key, values in parse_qs(body).items():
                    params[key] = values[0] if values else ''
            elif 'application/json' in content_type:
                try:
                    json_body = json.loads(body)
                    if isinstance(json_body, dict):
                        for key, value in json_body.items():
                            params[key] = str(value) if not isinstance(value, (dict, list)) else json.dumps(value)
                except:
                    pass
        
        return params
    
    def _detect_auth_token(self, headers: Dict[str, str], cookies: Dict[str, str]) -> Tuple[bool, str, str]:
        """Detect authentication token type and value"""
        # Check Authorization header
        auth_header = headers.get('Authorization', headers.get('authorization', ''))
        
        if auth_header:
            if auth_header.startswith('Bearer '):
                token = auth_header[7:]
                if token.count('.') == 2:
                    return True, 'jwt', token
                return True, 'bearer', token
            elif auth_header.startswith('Basic '):
                return True, 'basic', auth_header[6:]
        
        # Check cookies
        session_names = ['session', 'sessionid', 'JSESSIONID', 'PHPSESSID', 'token', 'auth_token']
        for name in session_names:
            if name in cookies:
                return True, 'session_cookie', cookies[name]
        
        return False, '', ''
    
    async def add_request(
        self,
        url: str,
        method: str,
        headers: Dict[str, str],
        body: str = "",
        is_post_login: bool = False
    ) -> str:
        """Add a captured request to the store"""
        async with self._lock:
            request_id = self._generate_request_id(url, method, body)
            
            # Parse cookies
            cookies = {}
            cookie_header = headers.get('Cookie', headers.get('cookie', ''))
            if cookie_header:
                for part in cookie_header.split(';'):
                    if '=' in part:
                        key, value = part.strip().split('=', 1)
                        cookies[key] = value
            
            # Detect auth
            has_auth, token_type, token_value = self._detect_auth_token(headers, cookies)
            
            # Parse params
            content_type = headers.get('Content-Type', '')
            parameters = self._parse_parameters(url, body, content_type)
            
            # Detect endpoint type
            endpoint_type = self._detect_endpoint_type(url, headers)
            
            # Detect priority
            priority = self._detect_priority(url, method, parameters, endpoint_type)
            
            # Insert or replace
            await self._db.execute("""
                INSERT OR REPLACE INTO requests (
                    id, url, method, headers, body, cookies, timestamp,
                    content_type, has_auth_token, auth_token_type, auth_token_value,
                    is_post_login, endpoint_type, parameters, status, priority
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id, url, method.upper(), json.dumps(headers), body,
                json.dumps(cookies), datetime.now().isoformat(), content_type,
                1 if has_auth else 0, token_type, token_value,
                1 if is_post_login else 0, endpoint_type, json.dumps(parameters),
                'pending', priority
            ))
            
            await self._db.commit()
            
            # Update stats
            if is_post_login:
                self.stats['post_login_count'] += 1
            else:
                self.stats['pre_login_count'] += 1
            
            logger.debug(f"Added {'post' if is_post_login else 'pre'}-login request: {method} {url}")
            return request_id
    
    async def add_response(
        self,
        request_id: str,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        response_time_ms: float = 0
    ):
        """Add a captured response to the store"""
        async with self._lock:
            content_type = headers.get('Content-Type', '')
            
            await self._db.execute("""
                INSERT OR REPLACE INTO responses (
                    request_id, status_code, headers, body, content_type,
                    content_length, timestamp, response_time_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                request_id, status_code, json.dumps(headers), body,
                content_type, len(body), datetime.now().isoformat(),
                response_time_ms
            ))
            
            await self._db.commit()
    
    async def get_request(self, request_id: str) -> Optional[StoredRequest]:
        """Get a specific request by ID"""
        async with self._db.execute(
            "SELECT * FROM requests WHERE id = ?", (request_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return StoredRequest.from_row(row)
        return None
    
    async def get_response(self, request_id: str) -> Optional[StoredResponse]:
        """Get response for a request"""
        async with self._db.execute(
            "SELECT * FROM responses WHERE request_id = ?", (request_id,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return StoredResponse.from_row(row)
        return None
    
    async def iter_requests(
        self,
        post_login: bool = False,
        status: Optional[str] = None,
        scanner_name: Optional[str] = None,
        batch_size: int = 100,
        order_by_priority: bool = True
    ) -> AsyncGenerator[StoredRequest, None]:
        """
        Iterate requests in batches (generator-based).
        
        Args:
            post_login: Whether to get post-login requests
            status: Filter by status (pending, completed, etc.)
            scanner_name: Only get requests not yet processed by this scanner
            batch_size: Number of requests per batch
            order_by_priority: Whether to order by priority (high first)
        """
        offset = 0
        
        while True:
            query = "SELECT * FROM requests WHERE is_post_login = ?"
            params: List[Any] = [1 if post_login else 0]
            
            if status:
                query += " AND status = ?"
                params.append(status)
            
            if scanner_name:
                # Exclude requests already processed by this scanner
                query += """ AND id NOT IN (
                    SELECT request_id FROM scanner_progress 
                    WHERE scanner_name = ? AND status = 'completed'
                )"""
                params.append(scanner_name)
            
            if order_by_priority:
                query += " ORDER BY priority ASC, id"
            else:
                query += " ORDER BY id"
            
            query += f" LIMIT {batch_size} OFFSET {offset}"
            
            async with self._db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                
                if not rows:
                    break
                
                for row in rows:
                    yield StoredRequest.from_row(row)
                
                offset += batch_size
    
    async def get_requests_with_params(self, post_login: bool = False) -> List[StoredRequest]:
        """Get requests that have parameters (good attack targets)"""
        query = """
            SELECT * FROM requests 
            WHERE is_post_login = ? AND parameters != '{}' AND parameters IS NOT NULL
            ORDER BY priority ASC
        """
        
        results = []
        async with self._db.execute(query, (1 if post_login else 0,)) as cursor:
            async for row in cursor:
                results.append(StoredRequest.from_row(row))
        
        return results
    
    async def get_request_count(self, post_login: bool = False, status: Optional[str] = None) -> int:
        """Get count of requests"""
        query = "SELECT COUNT(*) FROM requests WHERE is_post_login = ?"
        params = [1 if post_login else 0]
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        async with self._db.execute(query, params) as cursor:
            row = await cursor.fetchone()
            return row[0] if row else 0
    
    async def update_request_status(
        self,
        request_id: str,
        status: str,
        error_message: str = ""
    ):
        """Update request processing status"""
        async with self._lock:
            await self._db.execute(
                "UPDATE requests SET status = ?, error_message = ? WHERE id = ?",
                (status, error_message, request_id)
            )
            await self._db.commit()
    
    async def mark_scanner_progress(
        self,
        scanner_name: str,
        request_id: str,
        status: str,
        error_message: str = ""
    ):
        """Mark scanner progress on a specific request"""
        async with self._lock:
            now = datetime.now().isoformat()
            
            if status == 'in_progress':
                await self._db.execute("""
                    INSERT OR REPLACE INTO scanner_progress 
                    (scanner_name, request_id, status, started_at)
                    VALUES (?, ?, ?, ?)
                """, (scanner_name, request_id, status, now))
            else:
                await self._db.execute("""
                    INSERT OR REPLACE INTO scanner_progress 
                    (scanner_name, request_id, status, completed_at, error_message)
                    VALUES (?, ?, ?, ?, ?)
                """, (scanner_name, request_id, status, now, error_message))
            
            await self._db.commit()
    
    async def get_pending_requests_for_scanner(
        self,
        scanner_name: str,
        post_login: bool = False,
        limit: int = 100
    ) -> List[StoredRequest]:
        """Get requests not yet processed by a specific scanner"""
        query = """
            SELECT r.* FROM requests r
            WHERE r.is_post_login = ?
            AND r.id NOT IN (
                SELECT request_id FROM scanner_progress 
                WHERE scanner_name = ? AND status = 'completed'
            )
            ORDER BY r.priority ASC
            LIMIT ?
        """
        
        results = []
        async with self._db.execute(query, (1 if post_login else 0, scanner_name, limit)) as cursor:
            async for row in cursor:
                results.append(StoredRequest.from_row(row))
        
        return results
    
    async def add_attack_request(
        self,
        attack_id: str,
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
    ):
        """Store an attack request sent by a scanner"""
        async with self._lock:
            await self._db.execute("""
                INSERT OR REPLACE INTO attack_requests (
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
            self.stats['attack_request_count'] += 1
    
    async def add_attack_response(
        self,
        attack_request_id: str,
        status_code: int,
        headers: Dict[str, str],
        body: str = "",
        response_time_ms: float = 0,
        is_vulnerable: bool = False,
        vulnerability_type: str = "",
        evidence: str = ""
    ):
        """Store response from an attack request"""
        async with self._lock:
            await self._db.execute("""
                INSERT OR REPLACE INTO attack_responses (
                    attack_request_id, status_code, headers, body,
                    response_time_ms, body_length, content_type, timestamp,
                    is_vulnerable, vulnerability_type, evidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                attack_request_id, status_code, json.dumps(headers), body,
                response_time_ms, len(body), headers.get('Content-Type', ''),
                datetime.now().isoformat(), 1 if is_vulnerable else 0,
                vulnerability_type, evidence
            ))
            await self._db.commit()
    
    async def store_auth_token(
        self,
        token_type: str,
        token_value: str,
        expires_at: Optional[str] = None,
        refresh_token: Optional[str] = None,
        header_name: str = "Authorization",
        header_prefix: str = "Bearer",
        cookie_name: Optional[str] = None
    ):
        """Store or update an auth token"""
        async with self._lock:
            await self._db.execute("""
                INSERT OR REPLACE INTO auth_tokens (
                    token_type, token_value, expires_at, refresh_token,
                    header_name, header_prefix, cookie_name, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                token_type, token_value, expires_at, refresh_token,
                header_name, header_prefix, cookie_name,
                datetime.now().isoformat()
            ))
            await self._db.commit()
    
    async def get_auth_token(self, token_type: str) -> Optional[Dict[str, Any]]:
        """Get stored auth token"""
        async with self._db.execute(
            "SELECT * FROM auth_tokens WHERE token_type = ?", (token_type,)
        ) as cursor:
            row = await cursor.fetchone()
            if row:
                return {
                    'token_type': row['token_type'],
                    'token_value': row['token_value'],
                    'expires_at': row['expires_at'],
                    'refresh_token': row['refresh_token'],
                    'header_name': row['header_name'],
                    'header_prefix': row['header_prefix'],
                    'cookie_name': row['cookie_name']
                }
        return None
    
    async def get_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        pre_count = await self.get_request_count(post_login=False)
        post_count = await self.get_request_count(post_login=True)
        
        async with self._db.execute("SELECT COUNT(*) FROM attack_requests") as cursor:
            attack_count = (await cursor.fetchone())[0]
        
        async with self._db.execute(
            "SELECT COUNT(*) FROM requests WHERE status = 'pending'"
        ) as cursor:
            pending_count = (await cursor.fetchone())[0]
        
        async with self._db.execute(
            "SELECT COUNT(*) FROM requests WHERE status = 'completed'"
        ) as cursor:
            completed_count = (await cursor.fetchone())[0]
        
        return {
            'pre_login_requests': pre_count,
            'post_login_requests': post_count,
            'total_requests': pre_count + post_count,
            'attack_requests': attack_count,
            'pending_requests': pending_count,
            'completed_requests': completed_count,
            'db_path': str(self.db_path),
            'db_size_mb': os.path.getsize(self.db_path) / (1024 * 1024) if self.db_path.exists() else 0
        }
    
    async def clear_all(self):
        """Clear all data (for testing/reset)"""
        async with self._lock:
            await self._db.execute("DELETE FROM attack_responses")
            await self._db.execute("DELETE FROM attack_requests")
            await self._db.execute("DELETE FROM scanner_progress")
            await self._db.execute("DELETE FROM responses")
            await self._db.execute("DELETE FROM requests")
            await self._db.execute("DELETE FROM auth_tokens")
            await self._db.commit()
            logger.info("RequestStoreDB cleared")
