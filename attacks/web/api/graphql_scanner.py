"""
Jarwis AGI Pen Test - GraphQL Security Scanner
Detects GraphQL vulnerabilities (A01:2021 - Broken Access Control, A03:2021 - Injection)
Based on Web Hacking 101 techniques - adapted for 2025
"""

import asyncio
import logging
import re
import json
from typing import Dict, List, Optional
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin
import aiohttp
import ssl

logger = logging.getLogger(__name__)


@dataclass
class ScanResult:
    id: str
    category: str
    severity: str
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe_id: str = ""
    poc: str = ""
    reasoning: str = ""
    request_data: str = ""
    response_data: str = ""


class GraphQLScanner:
    """
    Scans for GraphQL security vulnerabilities
    OWASP A01:2021 - Broken Access Control
    OWASP A03:2021 - Injection
    
    Attack vectors:
    - Introspection enabled
    - Injection attacks
    - Batching attacks
    - DoS via nested queries
    - Field suggestions (information disclosure)
    - Authorization bypass
    - IDOR via GraphQL
    """
    
    # Common GraphQL endpoints
    GRAPHQL_ENDPOINTS = [
        '/graphql',
        '/graphql/',
        '/api/graphql',
        '/api/graphql/',
        '/v1/graphql',
        '/v2/graphql',
        '/query',
        '/gql',
        '/api/gql',
        '/graphiql',
        '/playground',
        '/console',
        '/__graphql',
        '/api/v1/graphql',
        '/api/v2/graphql',
        '/graph',
        '/graphql/v1',
    ]
    
    # Introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          name
          kind
          fields(includeDeprecated: true) {
            name
            args { name type { name } }
          }
        }
      }
    }
    """
    
    # Mini introspection
    MINI_INTROSPECTION = """
    {
      __schema {
        types {
          name
        }
      }
    }
    """
    
    # Type introspection
    TYPE_INTROSPECTION = """
    {
      __type(name: "User") {
        name
        fields {
          name
          type { name }
        }
      }
    }
    """
    
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
        self.results: List[ScanResult] = []
        self.rate_limit = config.get('rate_limit', 10)
        self.timeout = config.get('timeout', 15)
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        self.graphql_endpoints: List[str] = []
        self.schema: dict = {}
        
    async def scan(self) -> List[ScanResult]:
        """Main scan method"""
        logger.info("Starting GraphQL Security scan...")
        self.results = []
        
        base_url = self.config.get('target', {}).get('url', '')
        if not base_url:
            base_url = self.config.get('target_url', '')
        
        if not base_url:
            return self.results
        
        connector = aiohttp.TCPConnector(ssl=self.ssl_context, limit=10)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.timeout)
        ) as session:
            
            # Discover GraphQL endpoints
            await self._discover_graphql(session, base_url)
            
            if not self.graphql_endpoints:
                logger.info("No GraphQL endpoints discovered")
                return self.results
            
            # Test each endpoint
            for endpoint in self.graphql_endpoints:
                await self._test_introspection(session, endpoint)
                await self._test_injection(session, endpoint)
                await self._test_batching(session, endpoint)
                await self._test_dos_nested_query(session, endpoint)
                await self._test_field_suggestions(session, endpoint)
                await self._test_common_vulnerabilities(session, endpoint)
        
        logger.info(f"GraphQL scan complete. Found {len(self.results)} vulnerabilities")
        return self.results
    
    async def _discover_graphql(self, session: aiohttp.ClientSession, base_url: str):
        """Discover GraphQL endpoints"""
        for endpoint in self.GRAPHQL_ENDPOINTS:
            url = urljoin(base_url, endpoint)
            try:
                await asyncio.sleep(1 / self.rate_limit)
                
                # Test with OPTIONS
                async with session.options(url) as response:
                    if response.status == 200:
                        self.graphql_endpoints.append(url)
                        continue
                
                # Test with simple query
                test_query = {"query": "{ __typename }"}
                headers = {
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0'
                }
                
                async with session.post(url, json=test_query, headers=headers) as response:
                    if response.status == 200:
                        body = await response.text()
                        if 'data' in body or '__typename' in body or 'Query' in body:
                            self.graphql_endpoints.append(url)
                            
            except Exception as e:
                logger.debug(f"Error checking {url}: {e}")
        
        # Also check context endpoints
        if hasattr(self.context, 'endpoints'):
            for endpoint in self.context.endpoints:
                url = endpoint.get('url', '') if isinstance(endpoint, dict) else str(endpoint)
                if 'graphql' in url.lower() or 'gql' in url.lower():
                    if url not in self.graphql_endpoints:
                        self.graphql_endpoints.append(url)
        
        logger.info(f"Discovered {len(self.graphql_endpoints)} GraphQL endpoints")
    
    async def _test_introspection(self, session: aiohttp.ClientSession, url: str):
        """Test if introspection is enabled"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Test full introspection
        query = {"query": self.INTROSPECTION_QUERY}
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            async with session.post(url, json=query, headers=headers) as response:
                body = await response.text()
                
                if response.status == 200 and '__schema' in body:
                    # Parse schema for analysis
                    try:
                        data = json.loads(body)
                        self.schema = data.get('data', {}).get('__schema', {})
                        
                        # Count types and fields
                        types = self.schema.get('types', [])
                        type_count = len(types)
                        
                        result = ScanResult(
                            id=f"GRAPHQL-INTRO-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="medium",
                            title="GraphQL Introspection Enabled",
                            description=f"GraphQL introspection is enabled, exposing {type_count} types. Attackers can discover the entire API schema.",
                            url=url,
                            method="POST",
                            parameter="query",
                            evidence=f"Found {type_count} types in schema",
                            remediation="Disable introspection in production. Use allowlisting for allowed queries.",
                            cwe_id="CWE-200",
                            poc=json.dumps(query),
                            reasoning="Introspection query returned full schema"
                        )
                        self.results.append(result)
                        
                        # Extract sensitive types
                        await self._analyze_schema(url)
                        
                    except json.JSONDecodeError:
                        pass
                        
        except Exception as e:
            logger.debug(f"Introspection test error: {e}")
        
        # Test mini introspection (some servers block full introspection)
        try:
            query = {"query": self.MINI_INTROSPECTION}
            async with session.post(url, json=query, headers=headers) as response:
                body = await response.text()
                
                if response.status == 200 and '__schema' in body and not self.schema:
                    result = ScanResult(
                        id=f"GRAPHQL-INTRO-MINI-{len(self.results)+1}",
                        category="A01:2021 - Broken Access Control",
                        severity="low",
                        title="GraphQL Partial Introspection Enabled",
                        description="Partial GraphQL introspection is enabled, allowing type discovery.",
                        url=url,
                        method="POST",
                        evidence=body[:500],
                        remediation="Disable all introspection queries in production.",
                        cwe_id="CWE-200",
                        reasoning="Mini introspection query successful"
                    )
                    self.results.append(result)
                    
        except Exception:
            pass
    
    async def _analyze_schema(self, url: str):
        """Analyze discovered schema for sensitive types"""
        if not self.schema:
            return
        
        sensitive_types = []
        sensitive_fields = []
        
        for type_info in self.schema.get('types', []):
            type_name = type_info.get('name', '')
            
            # Skip internal types
            if type_name.startswith('__'):
                continue
            
            # Check for sensitive type names
            sensitive_names = ['user', 'admin', 'password', 'secret', 'token', 'key', 'auth', 'credential', 'payment', 'credit']
            if any(s in type_name.lower() for s in sensitive_names):
                sensitive_types.append(type_name)
            
            # Check fields
            for field in type_info.get('fields', []) or []:
                field_name = field.get('name', '')
                if any(s in field_name.lower() for s in sensitive_names):
                    sensitive_fields.append(f"{type_name}.{field_name}")
        
        if sensitive_types or sensitive_fields:
            result = ScanResult(
                id=f"GRAPHQL-SENSITIVE-{len(self.results)+1}",
                category="A01:2021 - Broken Access Control",
                severity="high",
                title="Sensitive Types in GraphQL Schema",
                description=f"Found sensitive types and fields exposed via introspection.",
                url=url,
                method="POST",
                evidence=f"Types: {', '.join(sensitive_types[:10])}; Fields: {', '.join(sensitive_fields[:10])}",
                remediation="Review and restrict access to sensitive types. Implement field-level authorization.",
                cwe_id="CWE-200",
                reasoning="Schema contains potentially sensitive data types"
            )
            self.results.append(result)
    
    async def _test_injection(self, session: aiohttp.ClientSession, url: str):
        """Test for GraphQL injection vulnerabilities"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # SQL injection through GraphQL
        injection_payloads = [
            # SQL Injection
            '{ user(id: "1\' OR \'1\'=\'1") { name } }',
            '{ user(id: "1 UNION SELECT * FROM users--") { name } }',
            '{ users(where: {name: {_eq: "\' OR 1=1--"}}) { id } }',
            
            # NoSQL Injection
            '{ user(query: {"$gt": ""}) { name } }',
            '{ users(filter: {"$where": "1==1"}) { id } }',
            
            # Directive injection
            '{ __typename @skip(if: false) @a])}',
            
            # Alias-based DoS
            '{ a: __typename b: __typename c: __typename }',
        ]
        
        for payload in injection_payloads:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                query = {"query": payload}
                
                async with session.post(url, json=query, headers=headers) as response:
                    body = await response.text()
                    
                    # Check for SQL error messages
                    sql_errors = ['sql', 'syntax', 'mysql', 'postgresql', 'sqlite', 'ora-', 'query']
                    if response.status == 500 or any(e in body.lower() for e in sql_errors):
                        if 'error' in body.lower() or 'exception' in body.lower():
                            result = ScanResult(
                                id=f"GRAPHQL-INJ-{len(self.results)+1}",
                                category="A03:2021 - Injection",
                                severity="high",
                                title="Potential GraphQL Injection",
                                description="GraphQL query with injection payload caused an error, indicating potential injection vulnerability.",
                                url=url,
                                method="POST",
                                parameter="query",
                                evidence=body[:500],
                                remediation="Use parameterized queries. Validate and sanitize all inputs.",
                                cwe_id="CWE-89",
                                poc=payload,
                                reasoning="Injection payload triggered error response"
                            )
                            self.results.append(result)
                            break
                            
            except Exception:
                pass
    
    async def _test_batching(self, session: aiohttp.ClientSession, url: str):
        """Test for query batching attacks"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Test batch query
        batch_query = [
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
            {"query": "{ __typename }"},
        ]
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            async with session.post(url, json=batch_query, headers=headers) as response:
                body = await response.text()
                
                if response.status == 200:
                    try:
                        data = json.loads(body)
                        if isinstance(data, list) and len(data) >= 3:
                            result = ScanResult(
                                id=f"GRAPHQL-BATCH-{len(self.results)+1}",
                                category="A01:2021 - Broken Access Control",
                                severity="medium",
                                title="GraphQL Query Batching Enabled",
                                description="GraphQL accepts batched queries, which can be abused for brute force attacks.",
                                url=url,
                                method="POST",
                                evidence=f"Batch of 3 queries returned {len(data)} responses",
                                remediation="Disable query batching or implement rate limiting per batch.",
                                cwe_id="CWE-307",
                                poc=json.dumps(batch_query),
                                reasoning="Server processed batched queries"
                            )
                            self.results.append(result)
                    except json.JSONDecodeError:
                        pass
                        
        except Exception as e:
            logger.debug(f"Batching test error: {e}")
    
    async def _test_dos_nested_query(self, session: aiohttp.ClientSession, url: str):
        """Test for DoS via deeply nested queries"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Create deeply nested query
        nested_query = "{ __typename "
        for i in range(10):
            nested_query += f"... on Query {{ __typename "
        nested_query += "}" * 11
        
        # Circular reference query (if schema has self-referential types)
        if self.schema:
            for type_info in self.schema.get('types', []):
                type_name = type_info.get('name', '')
                fields = type_info.get('fields', []) or []
                
                for field in fields:
                    field_name = field.get('name', '')
                    field_type = field.get('type', {})
                    
                    # Check for self-referential fields
                    if field_type.get('name') == type_name:
                        # Create recursive query
                        recursive_query = f"{{ {field_name} {{ {field_name} {{ {field_name} {{ {field_name} {{ id }} }} }} }} }}"
                        
                        try:
                            query = {"query": recursive_query}
                            async with session.post(url, json=query, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as response:
                                if response.status == 200:
                                    result = ScanResult(
                                        id=f"GRAPHQL-DOS-{len(self.results)+1}",
                                        category="A01:2021 - Broken Access Control",
                                        severity="medium",
                                        title="GraphQL Recursive Query Allowed",
                                        description="GraphQL allows recursive/circular queries that could cause DoS.",
                                        url=url,
                                        method="POST",
                                        evidence=f"Recursive query on {type_name}.{field_name} accepted",
                                        remediation="Implement query depth limiting and complexity analysis.",
                                        cwe_id="CWE-400",
                                        poc=recursive_query,
                                        reasoning="Recursive query executed successfully"
                                    )
                                    self.results.append(result)
                                    return
                        except Exception:
                            pass
    
    async def _test_field_suggestions(self, session: aiohttp.ClientSession, url: str):
        """Test for field suggestion information disclosure"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Query with typo to trigger suggestions
        test_queries = [
            {"query": "{ usr { name } }"},  # typo of 'user'
            {"query": "{ usrs { id } }"},  # typo of 'users'
            {"query": "{ pasword }"},  # typo of 'password'
        ]
        
        for query in test_queries:
            try:
                await asyncio.sleep(1 / self.rate_limit)
                async with session.post(url, json=query, headers=headers) as response:
                    body = await response.text()
                    
                    suggestion_indicators = ['did you mean', 'suggestion', 'similar', 'perhaps']
                    if any(s in body.lower() for s in suggestion_indicators):
                        result = ScanResult(
                            id=f"GRAPHQL-SUGGEST-{len(self.results)+1}",
                            category="A01:2021 - Broken Access Control",
                            severity="low",
                            title="GraphQL Field Suggestions Enabled",
                            description="GraphQL provides field suggestions on typos, leaking schema information.",
                            url=url,
                            method="POST",
                            evidence=body[:500],
                            remediation="Disable field suggestions in production environments.",
                            cwe_id="CWE-200",
                            poc=json.dumps(query),
                            reasoning="Server provided field suggestions"
                        )
                        self.results.append(result)
                        break
                        
            except Exception:
                pass
    
    async def _test_common_vulnerabilities(self, session: aiohttp.ClientSession, url: str):
        """Test for common GraphQL vulnerabilities"""
        headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0'
        }
        
        # Test for debug mode
        debug_query = {"query": "{ __schema { directives { name } } }", "debug": True}
        
        try:
            await asyncio.sleep(1 / self.rate_limit)
            async with session.post(url, json=debug_query, headers=headers) as response:
                body = await response.text()
                
                if 'debug' in body.lower() or 'stack' in body.lower() or 'trace' in body.lower():
                    result = ScanResult(
                        id=f"GRAPHQL-DEBUG-{len(self.results)+1}",
                        category="A05:2021 - Security Misconfiguration",
                        severity="medium",
                        title="GraphQL Debug Mode Enabled",
                        description="GraphQL appears to have debug mode enabled, exposing sensitive information.",
                        url=url,
                        method="POST",
                        evidence=body[:500],
                        remediation="Disable debug mode in production.",
                        cwe_id="CWE-215",
                        reasoning="Debug information visible in response"
                    )
                    self.results.append(result)
                    
        except Exception:
            pass
        
        # Test for alias-based data harvesting
        if self.schema:
            for type_info in self.schema.get('types', []):
                if type_info.get('name', '').lower() in ['user', 'users', 'account']:
                    # Try to enumerate users via aliases
                    alias_query = ""
                    for i in range(1, 11):
                        alias_query += f'u{i}: user(id: {i}) {{ id name email }} '
                    
                    query = {"query": f"{{ {alias_query} }}"}
                    
                    try:
                        await asyncio.sleep(1 / self.rate_limit)
                        async with session.post(url, json=query, headers=headers) as response:
                            body = await response.text()
                            
                            if response.status == 200 and 'email' in body.lower():
                                result = ScanResult(
                                    id=f"GRAPHQL-ENUM-{len(self.results)+1}",
                                    category="A01:2021 - Broken Access Control",
                                    severity="high",
                                    title="GraphQL User Enumeration via Aliases",
                                    description="GraphQL allows user enumeration through alias queries.",
                                    url=url,
                                    method="POST",
                                    evidence=body[:500],
                                    remediation="Implement authorization checks. Rate limit alias queries.",
                                    cwe_id="CWE-200",
                                    poc=json.dumps(query),
                                    reasoning="Multiple users retrieved via alias queries"
                                )
                                self.results.append(result)
                                break
                                
                    except Exception:
                        pass
