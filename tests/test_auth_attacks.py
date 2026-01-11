"""
Test Authenticated Attack Modules against Jarwis API

This script:
1. Logs in as user2@jarwis.ai to get JWT token
2. Makes authenticated API calls to generate requests
3. Runs attack modules that require session/request on those captured requests
"""

import asyncio
import aiohttp
import logging
import ssl
from datetime import datetime
from typing import List, Dict, Any
from dataclasses import dataclass

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Jarwis API base URL
BASE_URL = "http://localhost:8000"

# Test credentials
TEST_EMAIL = "user2@jarwis.ai"
TEST_PASSWORD = "12341234"


@dataclass
class CapturedRequest:
    """Represents a captured HTTP request"""
    url: str
    method: str
    headers: Dict[str, str]
    body: Any
    has_auth_token: bool = True
    auth_token_type: str = "bearer"
    endpoint_type: str = "api"


async def login() -> Dict[str, Any]:
    """Login and get JWT token"""
    logger.info(f"Logging in as {TEST_EMAIL}...")
    
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": TEST_EMAIL, "password": TEST_PASSWORD}
        ) as response:
            if response.status == 200:
                data = await response.json()
                logger.info(f"Login successful! User: {data.get('user', {}).get('email')}")
                return data
            else:
                error = await response.text()
                logger.error(f"Login failed: {response.status} - {error}")
                return None


async def capture_authenticated_requests(token: str) -> List[CapturedRequest]:
    """Make authenticated API calls to capture requests"""
    
    requests = []
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }
    
    # List of endpoints to test
    endpoints = [
        ("GET", "/api/auth/me", None),
        ("GET", "/api/scans/all", None),
        ("GET", "/api/dashboard/stats", None),
        ("GET", "/api/websites/", None),
        ("POST", "/api/chat/message", {"message": "Hello", "conversation_id": None}),
    ]
    
    async with aiohttp.ClientSession() as session:
        for method, path, body in endpoints:
            url = f"{BASE_URL}{path}"
            try:
                async with session.request(
                    method, 
                    url, 
                    headers=headers,
                    json=body
                ) as response:
                    status = response.status
                    logger.info(f"Captured: {method} {path} -> {status}")
                    
                    requests.append(CapturedRequest(
                        url=url,
                        method=method,
                        headers=headers,
                        body=body,
                        has_auth_token=True,
                        auth_token_type="bearer"
                    ))
            except Exception as e:
                logger.error(f"Failed to capture {path}: {e}")
    
    return requests


async def test_token_removal(session: aiohttp.ClientSession, request: CapturedRequest):
    """Test what happens when auth token is removed"""
    results = []
    
    # Make request WITHOUT the auth token
    headers_without_auth = {k: v for k, v in request.headers.items() 
                            if k.lower() != 'authorization'}
    
    try:
        async with session.request(
            request.method,
            request.url,
            headers=headers_without_auth,
            json=request.body
        ) as response:
            status = response.status
            
            if status == 200:
                # Vulnerability! Endpoint accessible without auth
                results.append({
                    "type": "AUTH_BYPASS",
                    "severity": "critical",
                    "title": f"Authentication Bypass on {request.url}",
                    "description": f"Endpoint {request.url} returns 200 without authentication token",
                    "url": request.url,
                    "method": request.method
                })
                logger.warning(f"[VULN] Auth bypass on {request.url} - returns {status} without token")
            else:
                logger.info(f"[OK] {request.url} correctly requires auth (got {status})")
    except Exception as e:
        logger.error(f"Token removal test failed: {e}")
    
    return results


async def test_invalid_token(session: aiohttp.ClientSession, request: CapturedRequest):
    """Test with invalid/malformed tokens"""
    results = []
    
    invalid_tokens = [
        "invalid_token",
        "Bearer",
        "Bearer ",
        "Bearer null",
        "Bearer undefined",
        "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.",
    ]
    
    for invalid_token in invalid_tokens:
        headers = dict(request.headers)
        headers["Authorization"] = invalid_token
        
        try:
            async with session.request(
                request.method,
                request.url,
                headers=headers,
                json=request.body
            ) as response:
                status = response.status
                
                if status == 200:
                    results.append({
                        "type": "JWT_BYPASS",
                        "severity": "critical",
                        "title": f"JWT Validation Bypass on {request.url}",
                        "description": f"Endpoint accepts invalid token: {invalid_token[:30]}...",
                        "url": request.url,
                        "method": request.method
                    })
                    logger.warning(f"[VULN] JWT bypass on {request.url} with: {invalid_token[:20]}...")
        except Exception as e:
            pass
    
    return results


async def test_idor(session: aiohttp.ClientSession, request: CapturedRequest, auth_token: str):
    """Test IDOR by changing user IDs in the request"""
    results = []
    
    # Check if URL contains UUIDs or IDs
    import re
    uuid_pattern = r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    id_pattern = r'/(\d+)(?:/|$)'
    
    # Replace UUIDs with test UUIDs (other users' IDs)
    test_uuids = [
        "00000000-0000-0000-0000-000000000000",
        "11111111-1111-1111-1111-111111111111",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ]
    
    if re.search(uuid_pattern, request.url):
        for test_uuid in test_uuids:
            modified_url = re.sub(uuid_pattern, test_uuid, request.url)
            
            try:
                async with session.request(
                    request.method,
                    modified_url,
                    headers=request.headers,
                    json=request.body
                ) as response:
                    status = response.status
                    
                    if status == 200:
                        results.append({
                            "type": "IDOR",
                            "severity": "high",
                            "title": f"Potential IDOR on {request.url}",
                            "description": f"Can access resources with modified UUID: {test_uuid}",
                            "url": modified_url,
                            "method": request.method
                        })
                        logger.warning(f"[VULN] IDOR on {modified_url}")
            except Exception as e:
                pass
    
    return results


async def test_privilege_escalation(session: aiohttp.ClientSession, auth_token: str):
    """Test if user2 can access admin endpoints"""
    results = []
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": "application/json"
    }
    
    admin_endpoints = [
        ("GET", "/api/admin/users"),
        ("GET", "/api/admin/settings"),
        ("GET", "/api/admin/stats"),
        ("POST", "/api/admin/users/create", {"email": "test@test.com"}),
        ("DELETE", "/api/admin/users/test-id"),
    ]
    
    for method, path, *body in admin_endpoints:
        url = f"{BASE_URL}{path}"
        body_data = body[0] if body else None
        
        try:
            async with session.request(
                method, 
                url, 
                headers=headers,
                json=body_data
            ) as response:
                status = response.status
                
                if status == 200:
                    results.append({
                        "type": "PRIVILEGE_ESCALATION",
                        "severity": "critical",
                        "title": f"Privilege Escalation: User can access {path}",
                        "description": f"Non-admin user can access admin endpoint: {method} {path}",
                        "url": url,
                        "method": method
                    })
                    logger.warning(f"[VULN] PrivEsc: {method} {path} accessible by regular user")
                elif status == 403 or status == 401:
                    logger.info(f"[OK] {path} correctly blocked (got {status})")
                else:
                    logger.info(f"[INFO] {path} returned {status}")
        except Exception as e:
            logger.error(f"PrivEsc test failed for {path}: {e}")
    
    return results


async def run_all_auth_attacks():
    """Run all authenticated attack modules"""
    
    print("\n" + "=" * 70)
    print("  JARWIS AUTHENTICATED ATTACK TESTING")
    print("  Testing attack modules that require session/JWT token")
    print("=" * 70 + "\n")
    
    # Step 1: Login
    login_result = await login()
    if not login_result:
        print("Failed to login. Is the API server running on port 8000?")
        return
    
    access_token = login_result.get('access_token')
    user = login_result.get('user', {})
    print(f"\n✓ Logged in as: {user.get('email')} (plan: {user.get('plan')})")
    
    # Step 2: Capture authenticated requests
    print("\n[Step 2] Capturing authenticated API requests...")
    requests = await capture_authenticated_requests(access_token)
    print(f"✓ Captured {len(requests)} authenticated requests\n")
    
    # Step 3: Run attack modules
    all_findings = []
    
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    async with aiohttp.ClientSession() as session:
        
        print("[Step 3] Running Token Removal Tests...")
        for req in requests:
            findings = await test_token_removal(session, req)
            all_findings.extend(findings)
        
        print("\n[Step 4] Running Invalid Token Tests...")
        for req in requests:
            findings = await test_invalid_token(session, req)
            all_findings.extend(findings)
        
        print("\n[Step 5] Running IDOR Tests...")
        for req in requests:
            findings = await test_idor(session, req, access_token)
            all_findings.extend(findings)
        
        print("\n[Step 6] Running Privilege Escalation Tests...")
        findings = await test_privilege_escalation(session, access_token)
        all_findings.extend(findings)
    
    # Summary
    print("\n" + "=" * 70)
    print("  AUTHENTICATED ATTACK TEST RESULTS")
    print("=" * 70)
    
    if all_findings:
        print(f"\n⚠️  Found {len(all_findings)} potential vulnerabilities:\n")
        
        by_type = {}
        for finding in all_findings:
            ftype = finding['type']
            if ftype not in by_type:
                by_type[ftype] = []
            by_type[ftype].append(finding)
        
        for ftype, findings in by_type.items():
            print(f"\n  {ftype}: {len(findings)} issues")
            for f in findings[:3]:  # Show first 3
                print(f"    - [{f['severity'].upper()}] {f['title']}")
            if len(findings) > 3:
                print(f"    ... and {len(findings) - 3} more")
    else:
        print("\n✓ No vulnerabilities found in authenticated attacks!")
        print("  All endpoints properly validate authentication and authorization.\n")
    
    return all_findings


if __name__ == "__main__":
    asyncio.run(run_all_auth_attacks())
