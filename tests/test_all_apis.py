"""
Comprehensive API Test Script for Jarwis AGI Pen Test
Tests all major API endpoints for Web, Mobile, and Network scanning
"""
import asyncio
import httpx
from datetime import datetime
import json

BASE_URL = "http://localhost:8000"

# Test credentials
USERS = {
    "superadmin": {"email": "akshaydevrari@gmail.com", "password": "Parilove@1"},
    "admin": {"email": "admin@jarwis.ai", "password": "admin123"},
    "individual": {"email": "user1@jarwis.ai", "password": "12341234"},
    "professional": {"email": "user2@jarwis.ai", "password": "12341234"},
    "enterprise": {"email": "user3@jarwis.ai", "password": "12341234"},
}

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    END = "\033[0m"

def log_success(msg):
    print(f"{Colors.GREEN}✓{Colors.END} {msg}")

def log_error(msg):
    print(f"{Colors.RED}✗{Colors.END} {msg}")

def log_info(msg):
    print(f"{Colors.BLUE}ℹ{Colors.END} {msg}")

def log_warning(msg):
    print(f"{Colors.YELLOW}⚠{Colors.END} {msg}")

async def test_auth(client: httpx.AsyncClient):
    """Test authentication endpoints"""
    print("\n" + "="*60)
    print("🔐 TESTING AUTHENTICATION")
    print("="*60)
    
    tokens = {}
    
    for user_type, creds in USERS.items():
        try:
            resp = await client.post(f"{BASE_URL}/api/auth/login", json=creds)
            if resp.status_code == 200:
                tokens[user_type] = resp.json()["access_token"]
                plan = resp.json()["user"]["plan"]
                log_success(f"Login {user_type}: {creds['email']} (plan={plan})")
            else:
                log_error(f"Login {user_type}: {resp.status_code} - {resp.text[:100]}")
        except Exception as e:
            log_error(f"Login {user_type}: {e}")
    
    return tokens

async def test_web_scan(client: httpx.AsyncClient, token: str):
    """Test web scanning endpoints"""
    print("\n" + "="*60)
    print("🌐 TESTING WEB SCANNING")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # List scans
    try:
        resp = await client.get(f"{BASE_URL}/api/scans/", headers=headers)
        if resp.status_code == 200:
            scans = resp.json().get("scans", [])
            log_success(f"List scans: {len(scans)} scan(s) found")
        else:
            log_error(f"List scans: {resp.status_code}")
    except Exception as e:
        log_error(f"List scans: {e}")
    
    # Create scan
    scan_id = None
    try:
        scan_data = {
            "target_url": "https://httpbin.org",
            "scan_type": "web"
        }
        resp = await client.post(f"{BASE_URL}/api/scans/", json=scan_data, headers=headers)
        if resp.status_code == 201:
            scan_id = resp.json().get("scan_id")
            log_success(f"Create web scan: scan_id={scan_id}")
        else:
            log_error(f"Create web scan: {resp.status_code} - {resp.text[:100]}")
    except Exception as e:
        log_error(f"Create web scan: {e}")
    
    # Get scan status
    if scan_id:
        await asyncio.sleep(2)  # Wait a bit for scan to start
        try:
            resp = await client.get(f"{BASE_URL}/api/scans/{scan_id}", headers=headers)
            if resp.status_code == 200:
                status = resp.json().get("status")
                phase = resp.json().get("phase", "N/A")
                log_success(f"Get scan status: status={status}, phase={phase}")
            else:
                log_error(f"Get scan status: {resp.status_code}")
        except Exception as e:
            log_error(f"Get scan status: {e}")
        
        # Stop scan
        try:
            resp = await client.post(f"{BASE_URL}/api/scans/{scan_id}/stop", headers=headers)
            if resp.status_code == 200:
                log_success(f"Stop scan: {resp.json().get('message', 'OK')}")
            else:
                log_warning(f"Stop scan: {resp.status_code} (may already be stopped)")
        except Exception as e:
            log_error(f"Stop scan: {e}")

async def test_network_scan(client: httpx.AsyncClient, token: str):
    """Test network scanning endpoints"""
    print("\n" + "="*60)
    print("🔌 TESTING NETWORK SCANNING")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get available tools
    try:
        resp = await client.get(f"{BASE_URL}/api/network/tools", headers=headers)
        if resp.status_code == 200:
            summary = resp.json().get("summary", {})
            log_success(f"Network tools: {summary.get('available', 0)}/{summary.get('total_tools', 0)} available")
        else:
            log_error(f"Network tools: {resp.status_code}")
    except Exception as e:
        log_error(f"Network tools: {e}")
    
    # Test agent list
    try:
        resp = await client.get(f"{BASE_URL}/api/network/agents", headers=headers)
        if resp.status_code == 200:
            agents = resp.json().get("agents", [])
            log_success(f"List agents: {len(agents)} agent(s)")
        else:
            log_error(f"List agents: {resp.status_code}")
    except Exception as e:
        log_error(f"List agents: {e}")
    
    # Test scan on public IP (should work without agent)
    try:
        scan_data = {"targets": "8.8.8.8"}  # Google DNS - public IP
        resp = await client.post(f"{BASE_URL}/api/network/scan", json=scan_data, headers=headers)
        if resp.status_code == 201:
            scan_id = resp.json().get("scan_id")
            log_success(f"Create network scan: scan_id={scan_id}")
        elif resp.status_code == 400:
            log_warning(f"Network scan: {resp.json().get('detail', 'Blocked')[:50]}")
        else:
            log_error(f"Network scan: {resp.status_code} - {resp.text[:100]}")
    except Exception as e:
        log_error(f"Network scan: {e}")

async def test_mobile_scan(client: httpx.AsyncClient, token: str):
    """Test mobile scanning endpoints"""
    print("\n" + "="*60)
    print("📱 TESTING MOBILE SCANNING")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Mobile scan requires file upload, so we just check the endpoint exists
    log_info("Mobile scan requires APK/IPA file upload - testing endpoint availability")
    
    try:
        # Create a minimal test file
        import tempfile
        import os
        
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as f:
            f.write(b"PK\x03\x04" + b"\x00" * 100)  # Minimal APK-like structure
            temp_path = f.name
        
        with open(temp_path, "rb") as f:
            files = {"app_file": ("test.apk", f, "application/vnd.android.package-archive")}
            data = {"platform": "android", "app_name": "TestApp"}
            resp = await client.post(f"{BASE_URL}/api/scan/mobile/start", files=files, data=data, headers=headers)
        
        os.unlink(temp_path)
        
        if resp.status_code == 201:
            scan_id = resp.json().get("scan_id")
            log_success(f"Create mobile scan: scan_id={scan_id}")
        elif resp.status_code == 403:
            log_warning(f"Mobile scan: Feature requires higher plan")
        else:
            log_error(f"Mobile scan: {resp.status_code} - {resp.text[:100]}")
    except Exception as e:
        log_error(f"Mobile scan: {e}")

async def test_user_endpoints(client: httpx.AsyncClient, token: str):
    """Test user-related endpoints"""
    print("\n" + "="*60)
    print("👤 TESTING USER ENDPOINTS")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get user profile
    try:
        resp = await client.get(f"{BASE_URL}/api/users/me", headers=headers)
        if resp.status_code == 200:
            user = resp.json()
            log_success(f"User profile: {user.get('email')} (plan={user.get('plan')})")
        else:
            log_error(f"User profile: {resp.status_code}")
    except Exception as e:
        log_error(f"User profile: {e}")
    
    # Get usage stats
    try:
        resp = await client.get(f"{BASE_URL}/api/users/me/stats", headers=headers)
        if resp.status_code == 200:
            stats = resp.json()
            log_success(f"User stats: scans={stats.get('scans_this_month', 0)}")
        else:
            log_warning(f"User stats: {resp.status_code}")
    except Exception as e:
        log_error(f"User stats: {e}")

async def main():
    print("\n" + "="*60)
    print("  JARWIS AGI PEN TEST - COMPREHENSIVE API TEST")
    print(f"  Timestamp: {datetime.now().isoformat()}")
    print("="*60)
    
    async with httpx.AsyncClient(timeout=30.0) as client:
        # Test authentication
        tokens = await test_auth(client)
        
        if not tokens:
            log_error("No tokens obtained, cannot proceed with tests")
            return
        
        # Use professional user for most tests
        pro_token = tokens.get("professional") or tokens.get("enterprise") or list(tokens.values())[0]
        
        # Test all scan types
        await test_user_endpoints(client, pro_token)
        await test_web_scan(client, pro_token)
        await test_network_scan(client, pro_token)
        await test_mobile_scan(client, pro_token)
        
        print("\n" + "="*60)
        print("✅ API TEST COMPLETED")
        print("="*60 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
