"""
XSS Stored Scanner
===================

Detects Persistent (Stored) Cross-Site Scripting vulnerabilities.

Stored XSS occurs when malicious input is permanently stored on the target
server (e.g., in a database) and later rendered to other users without
proper sanitization.

Detection Flow:
1. Identify storage endpoints (forms, APIs that write data)
2. Inject payloads with unique identifiers
3. Crawl/check retrieval endpoints for payload execution
4. Verify persistence (payload appears on subsequent requests)
5. Optional: Browser verification for JS execution

This is more severe than Reflected XSS because:
- Payload persists and affects all users viewing the content
- No social engineering required (victim just views the page)
- Can lead to worm-like spreading
"""

import asyncio
import logging
import re
import uuid
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
import aiohttp

from .base import XSSBase, XSSResult, XSSContext

logger = logging.getLogger(__name__)


@dataclass
class StoragePoint:
    """Represents a potential XSS storage location"""
    submit_url: str
    submit_method: str
    submit_params: Dict[str, str]
    retrieve_urls: List[str]
    content_type: str = "form"  # form, json, multipart


class XSSStored(XSSBase):
    """
    Scanner for XSS Stored (Persistent) vulnerabilities.
    
    Sub-type: stored
    OWASP: A03:2021 - Injection
    CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation)
    Severity: CRITICAL (higher than reflected due to persistence)
    """
    
    SUB_TYPE = "stored"
    TITLE_FORMAT = "XSS Stored - {location}"
    
    # Payloads with unique identifiers for tracking
    STORED_PAYLOADS = [
        '<script>alert("JARWIS_STORED_{uuid}")</script>',
        '"><script>alert("JARWIS_STORED_{uuid}")</script>',
        '<img src=x onerror=alert("JARWIS_STORED_{uuid}")>',
        '"><img src=x onerror=alert("JARWIS_STORED_{uuid}")>',
        '<svg onload=alert("JARWIS_STORED_{uuid}")>',
        '"><svg/onload=alert("JARWIS_STORED_{uuid}")>',
        '<body onload=alert("JARWIS_STORED_{uuid}")>',
    ]
    
    # Common storage endpoint patterns
    STORAGE_PATTERNS = [
        r'/comment[s]?',
        r'/post[s]?',
        r'/review[s]?',
        r'/feedback',
        r'/message[s]?',
        r'/profile',
        r'/user',
        r'/article[s]?',
        r'/blog',
        r'/forum',
        r'/ticket[s]?',
        r'/submit',
        r'/add',
        r'/create',
        r'/upload',
        r'/update',
        r'/edit',
    ]
    
    # Common text input field names
    TEXT_FIELD_PATTERNS = [
        'comment', 'content', 'body', 'text', 'message', 'description',
        'title', 'name', 'subject', 'bio', 'about', 'note', 'feedback',
        'review', 'post', 'reply', 'question', 'answer',
    ]
    
    def __init__(self, config: dict, context):
        super().__init__(config, context)
        self.injection_tracker: Dict[str, dict] = {}  # uuid -> injection details
        self.wait_time = config.get('stored_xss_wait_time', 2)  # seconds between inject and retrieve
    
    async def scan(self) -> List[XSSResult]:
        """Run XSS Stored scan against target"""
        logger.info(f"Starting XSS Stored scan for {self.context.target_url}")
        
        # Step 1: Identify storage points
        storage_points = await self._identify_storage_points()
        logger.info(f"Found {len(storage_points)} potential storage points")
        
        if not storage_points:
            logger.info("No storage points identified, skipping stored XSS scan")
            return []
        
        async with aiohttp.ClientSession() as session:
            # Step 2: Inject payloads with tracking IDs
            for storage in storage_points:
                await self._inject_payloads(session, storage)
            
            # Step 3: Wait for storage to persist
            await asyncio.sleep(self.wait_time)
            
            # Step 4: Check retrieval endpoints for our payloads
            for storage in storage_points:
                await self._check_retrieval(session, storage)
        
        logger.info(f"XSS Stored scan complete. Found {len(self.findings)} vulnerabilities")
        return self.findings
    
    async def _identify_storage_points(self) -> List[StoragePoint]:
        """Identify endpoints that might store and display user input"""
        storage_points = []
        
        # From crawl results - look for forms
        if hasattr(self.context, 'crawl_results'):
            for page in self.context.crawl_results:
                forms = page.get('forms', [])
                for form in forms:
                    storage = self._analyze_form(form, page.get('url', ''))
                    if storage:
                        storage_points.append(storage)
        
        # From request store - look for POST requests
        if hasattr(self.context, 'request_store'):
            for req in self.context.request_store.get_all():
                if req.get('method', '').upper() == 'POST':
                    storage = self._analyze_request(req)
                    if storage:
                        storage_points.append(storage)
        
        # Pattern-based detection
        if hasattr(self.context, 'discovered_endpoints'):
            for endpoint in self.context.discovered_endpoints:
                if self._matches_storage_pattern(endpoint):
                    storage = StoragePoint(
                        submit_url=endpoint,
                        submit_method='POST',
                        submit_params={},
                        retrieve_urls=[endpoint.replace('/add', '').replace('/create', '')]
                    )
                    storage_points.append(storage)
        
        return storage_points
    
    def _analyze_form(self, form: dict, page_url: str) -> Optional[StoragePoint]:
        """Analyze a form to determine if it's a storage point"""
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        # We're interested in POST forms with text inputs
        if method != 'POST':
            return None
        
        # Look for text/textarea inputs
        text_inputs = []
        for inp in inputs:
            inp_type = inp.get('type', 'text').lower()
            inp_name = inp.get('name', '').lower()
            
            if inp_type in ['text', 'textarea', 'hidden']:
                if any(pattern in inp_name for pattern in self.TEXT_FIELD_PATTERNS):
                    text_inputs.append(inp.get('name'))
        
        if not text_inputs:
            return None
        
        # Resolve action URL
        if not action or action == '#':
            submit_url = page_url
        elif action.startswith('/'):
            parsed = urlparse(page_url)
            submit_url = f"{parsed.scheme}://{parsed.netloc}{action}"
        elif action.startswith('http'):
            submit_url = action
        else:
            parsed = urlparse(page_url)
            base_path = '/'.join(parsed.path.split('/')[:-1])
            submit_url = f"{parsed.scheme}://{parsed.netloc}{base_path}/{action}"
        
        if not self._is_in_scope(submit_url):
            return None
        
        return StoragePoint(
            submit_url=submit_url,
            submit_method='POST',
            submit_params={name: '' for name in text_inputs},
            retrieve_urls=[page_url],  # The page containing the form often shows submissions
            content_type='form'
        )
    
    def _analyze_request(self, req: dict) -> Optional[StoragePoint]:
        """Analyze a captured request to determine if it's a storage point"""
        url = req.get('url', '')
        
        if not self._is_in_scope(url):
            return None
        
        if not self._matches_storage_pattern(url):
            return None
        
        # Look for text parameters in body
        body = req.get('body', {})
        if isinstance(body, str):
            try:
                import json
                body = json.loads(body)
            except:
                body = {}
        
        text_params = {}
        for key, value in body.items():
            if isinstance(value, str) and len(value) > 0:
                if any(pattern in key.lower() for pattern in self.TEXT_FIELD_PATTERNS):
                    text_params[key] = ''
        
        if not text_params:
            return None
        
        # Guess retrieval URL
        retrieve_url = url
        for pattern in ['/add', '/create', '/submit', '/post']:
            if pattern in url.lower():
                retrieve_url = url.lower().replace(pattern, '')
                break
        
        return StoragePoint(
            submit_url=url,
            submit_method='POST',
            submit_params=text_params,
            retrieve_urls=[retrieve_url],
            content_type='json' if req.get('content_type', '').find('json') >= 0 else 'form'
        )
    
    def _matches_storage_pattern(self, url: str) -> bool:
        """Check if URL matches storage endpoint patterns"""
        path = urlparse(url).path.lower()
        return any(re.search(pattern, path) for pattern in self.STORAGE_PATTERNS)
    
    async def _inject_payloads(
        self,
        session: aiohttp.ClientSession,
        storage: StoragePoint
    ) -> None:
        """Inject payloads into storage point"""
        
        for param in storage.submit_params.keys():
            for payload_template in self.STORED_PAYLOADS[:3]:  # Limit to avoid spam
                tracking_id = str(uuid.uuid4())[:8]
                payload = payload_template.format(uuid=tracking_id)
                
                # Build request data
                data = {**storage.submit_params}
                data[param] = payload
                
                try:
                    if storage.content_type == 'json':
                        async with session.post(
                            storage.submit_url,
                            json=data,
                            headers={**self.DEFAULT_HEADERS, 'Content-Type': 'application/json'},
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as response:
                            if response.status < 400:
                                self.injection_tracker[tracking_id] = {
                                    'payload': payload,
                                    'param': param,
                                    'storage': storage,
                                    'status': response.status,
                                }
                    else:
                        async with session.post(
                            storage.submit_url,
                            data=data,
                            headers=self.DEFAULT_HEADERS,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                            ssl=False
                        ) as response:
                            if response.status < 400:
                                self.injection_tracker[tracking_id] = {
                                    'payload': payload,
                                    'param': param,
                                    'storage': storage,
                                    'status': response.status,
                                }
                    
                    await asyncio.sleep(1 / self.rate_limit)
                    
                except Exception as e:
                    logger.debug(f"Injection error: {e}")
    
    async def _check_retrieval(
        self,
        session: aiohttp.ClientSession,
        storage: StoragePoint
    ) -> None:
        """Check retrieval URLs for stored payloads"""
        
        for retrieve_url in storage.retrieve_urls:
            try:
                async with session.get(
                    retrieve_url,
                    headers=self.DEFAULT_HEADERS,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ssl=False
                ) as response:
                    body = await response.text()
                    status = response.status
                    resp_headers = dict(response.headers)
                    
                    # Check for any of our injected payloads
                    for tracking_id, injection in self.injection_tracker.items():
                        marker = f"JARWIS_STORED_{tracking_id}"
                        
                        if marker in body:
                            payload = injection['payload']
                            
                            # Verify executable context
                            if not self._is_executable_context(body, payload):
                                logger.debug(f"Stored payload found but not executable")
                                continue
                            
                            finding = XSSResult(
                                id=self._generate_finding_id("XSS-STORED"),
                                category="A03:2021 - Injection",
                                sub_type=self.SUB_TYPE,
                                severity="critical",  # Stored XSS is critical
                                title=self.TITLE_FORMAT.format(location=injection['param']),
                                description=self._build_description(injection, retrieve_url),
                                url=storage.submit_url,
                                method='POST',
                                parameter=injection['param'],
                                payload=payload,
                                evidence=self._extract_evidence(body, payload),
                                poc=self._build_poc(storage, injection, retrieve_url),
                                reasoning=self._build_reasoning(payload, body, retrieve_url),
                                request_data=self._format_request('GET', retrieve_url, self.DEFAULT_HEADERS),
                                response_data=self._format_response(status, resp_headers, body),
                                confidence=0.90,  # High confidence - we injected and found it
                                verified_execution=False,
                                verification_status="verified",  # Persistence verified
                                cwe_id="CWE-79",
                                remediation=self._build_remediation(),
                            )
                            self.findings.append(finding)
                            
            except Exception as e:
                logger.debug(f"Retrieval check error: {e}")
    
    def _build_description(self, injection: dict, retrieve_url: str) -> str:
        """Build vulnerability description"""
        return f"""A Stored (Persistent) Cross-Site Scripting (XSS) vulnerability was identified in the '{injection['param']}' parameter.

The application stores user-supplied input in the database and later renders it to other users without proper sanitization. This is a **CRITICAL** severity issue.

**Attack Vector:** The attacker submits malicious content once. Every user who views the affected page will have the payload execute in their browser automatically.

**Storage Point:** `{injection['storage'].submit_url}`
**Display Point:** `{retrieve_url}`

**Impact:**
- **Session hijacking** - Steal cookies/tokens from ALL affected users
- **Account takeover** - Capture credentials, perform actions as victims
- **Malware distribution** - Serve malicious content to all visitors
- **Worm propagation** - Self-replicating attacks (e.g., Samy worm)
- **Data exfiltration** - Steal sensitive data visible to users
- **Cryptocurrency mining** - Use visitor's CPU resources

This is more severe than Reflected XSS because:
1. No social engineering required
2. Affects multiple users automatically
3. Payload persists indefinitely
"""
    
    def _extract_evidence(self, body: str, payload: str) -> str:
        """Extract evidence showing stored payload"""
        pos = body.find(payload)
        if pos == -1:
            # Find by marker
            for i in range(20):
                marker = f"JARWIS_STORED_"
                pos = body.find(marker)
                if pos >= 0:
                    break
        
        if pos == -1:
            return "Payload markers detected in stored content"
        
        start = max(0, pos - 150)
        end = min(len(body), pos + len(payload) + 150)
        snippet = body[start:end]
        
        return f"Stored XSS payload found in page content:\n\n```html\n{snippet}\n```"
    
    def _build_poc(self, storage: StoragePoint, injection: dict, retrieve_url: str) -> str:
        """Build Proof of Concept"""
        return f"""### Proof of Concept

**Step 1: Store the Payload**
```http
POST {storage.submit_url} HTTP/1.1
Content-Type: application/x-www-form-urlencoded

{injection['param']}={injection['payload']}
```

**Step 2: View the Payload Execution**
Navigate to: `{retrieve_url}`

The XSS payload will execute automatically for any user viewing this page.

**cURL Injection:**
```bash
curl -X POST "{storage.submit_url}" -d "{injection['param']}=<script>alert('XSS')</script>"
```

**cURL Verification:**
```bash
curl -s "{retrieve_url}" | grep -o "JARWIS_STORED"
```
"""
    
    def _build_reasoning(self, payload: str, body: str, retrieve_url: str) -> str:
        """Build verification reasoning"""
        return f"""✓ Payload was successfully stored on the server
✓ Payload is rendered on retrieval page: {retrieve_url}
✓ Payload is in executable HTML context (not encoded)
✓ Script/event handler tags preserved in output

This confirms persistent XSS - the payload persists across sessions and affects all users."""
    
    def _build_remediation(self) -> str:
        """Build remediation guidance"""
        return """### Remediation (CRITICAL PRIORITY)

**1. Immediate Actions:**
- Remove/sanitize all stored malicious content from database
- Deploy WAF rules to block XSS patterns
- Enable Content-Security-Policy headers

**2. Output Encoding (Primary Defense):**
Always encode data when rendering:
```python
# Python/Jinja2
{{ user_content | e }}

# JavaScript
element.textContent = userContent;  // NOT innerHTML
```

**3. Input Validation:**
- Sanitize HTML input using libraries like DOMPurify, Bleach
- Strip or encode dangerous tags: `<script>`, `<svg>`, `<img>`, etc.
- Whitelist allowed HTML tags if rich text is needed

**4. Content Security Policy:**
```
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
```

**5. Database Cleanup:**
```sql
-- Find potentially malicious content
SELECT * FROM comments WHERE content LIKE '%<script%' OR content LIKE '%onerror=%';
```

**References:**
- OWASP Stored XSS Prevention
- CWE-79: Improper Neutralization of Input During Web Page Generation
"""
