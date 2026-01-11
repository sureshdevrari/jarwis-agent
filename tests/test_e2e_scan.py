"""
End-to-End Web Scan Test via API

This test simulates the FULL workflow:
1. Login via API (like frontend does)
2. Start web scan via API
3. Poll for status updates (real-time)
4. Check findings and report generation
5. Verify AttackEngine runs properly

Tests the ACTUAL backend flow that frontend uses.
"""

import asyncio
import aiohttp
import logging
import time
from typing import Dict, Any
from datetime import datetime

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# API Configuration
BASE_URL = "http://localhost:8000"
TEST_EMAIL = "user2@jarwis.ai"
TEST_PASSWORD = "12341234"

# Target to scan (use a safe external target)
SCAN_TARGET = "https://httpbin.org"


class APIClient:
    """API client that mimics frontend behavior"""
    
    def __init__(self):
        self.token = None
        self.session = None
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, *args):
        if self.session:
            await self.session.close()
    
    def _headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers
    
    async def login(self, email: str, password: str) -> Dict[str, Any]:
        """Login and get JWT token"""
        async with self.session.post(
            f"{BASE_URL}/api/auth/login",
            json={"email": email, "password": password}
        ) as response:
            data = await response.json()
            if response.status == 200:
                self.token = data.get("access_token")
                return {"success": True, "data": data}
            return {"success": False, "error": data}
    
    async def start_scan(self, target_url: str, auth_config: Dict = None) -> Dict[str, Any]:
        """Start a new web scan (mimics frontend scanAPI.startScan)"""
        # Build request like frontend does
        scan_request = {
            "target_url": target_url,
            "scan_type": "web",
            "login_url": "",
            "username": "",
            "password": "",
            "config": {
                "attacks": None,  # All attacks enabled
                "scope": None
            }
        }
        
        if auth_config:
            scan_request.update(auth_config)
        
        async with self.session.post(
            f"{BASE_URL}/api/scans/",
            headers=self._headers(),
            json=scan_request
        ) as response:
            data = await response.json()
            if response.status in [200, 201]:
                return {"success": True, "data": data}
            return {"success": False, "error": data, "status": response.status}
    
    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        """Get scan status (mimics frontend polling)"""
        async with self.session.get(
            f"{BASE_URL}/api/scans/{scan_id}",
            headers=self._headers()
        ) as response:
            if response.status == 200:
                return await response.json()
            return {"error": f"Status {response.status}"}
    
    async def get_scan_logs(self, scan_id: str) -> Dict[str, Any]:
        """Get scan logs for live output"""
        try:
            async with self.session.get(
                f"{BASE_URL}/api/scans/{scan_id}/logs",
                headers=self._headers()
            ) as response:
                if response.status == 200:
                    return await response.json()
                return {"logs": []}
        except:
            return {"logs": []}
    
    async def get_scan_findings(self, scan_id: str) -> Dict[str, Any]:
        """Get vulnerabilities found"""
        try:
            async with self.session.get(
                f"{BASE_URL}/api/scans/{scan_id}/findings",
                headers=self._headers()
            ) as response:
                if response.status == 200:
                    return await response.json()
                return {"findings": []}
        except:
            return {"findings": []}


async def test_full_scan_workflow():
    """Test the complete scan workflow via API"""
    
    print("\n" + "=" * 70)
    print("  JARWIS END-TO-END WEB SCAN TEST")
    print("  Testing full workflow: Login → Start Scan → Poll → Results")
    print("=" * 70 + "\n")
    
    async with APIClient() as api:
        # Step 1: Login
        print("[Step 1] Logging in...")
        login_result = await api.login(TEST_EMAIL, TEST_PASSWORD)
        
        if not login_result["success"]:
            print(f"✗ Login failed: {login_result['error']}")
            return
        
        user = login_result["data"].get("user", {})
        print(f"✓ Logged in as: {user.get('email')} (plan: {user.get('plan')})")
        
        # Step 2: Start Scan
        print(f"\n[Step 2] Starting web scan for: {SCAN_TARGET}")
        scan_result = await api.start_scan(SCAN_TARGET)
        
        if not scan_result["success"]:
            print(f"✗ Scan start failed: {scan_result.get('error')}")
            print(f"  Status code: {scan_result.get('status')}")
            return
        
        scan_data = scan_result["data"]
        scan_id = scan_data.get("scan_id") or scan_data.get("id")
        print(f"✓ Scan started: {scan_id}")
        print(f"  Target: {scan_data.get('target_url')}")
        print(f"  Status: {scan_data.get('status')}")
        
        # Step 3: Poll for updates (like frontend does every 2 seconds)
        print(f"\n[Step 3] Polling for status updates...")
        
        max_polls = 180  # Max 6 minutes
        poll_interval = 2
        last_phase = ""
        last_progress = 0
        
        for poll_num in range(max_polls):
            status = await api.get_scan_status(scan_id)
            
            if "error" in status:
                print(f"  Poll {poll_num}: Error - {status['error']}")
                await asyncio.sleep(poll_interval)
                continue
            
            current_status = status.get("status", "unknown")
            current_phase = status.get("phase", "")
            current_progress = status.get("progress", 0)
            findings_count = status.get("findings_count", 0)
            
            # Only print if something changed
            if current_phase != last_phase or abs(current_progress - last_progress) >= 10:
                print(f"  [{current_progress:3d}%] {current_phase} - {current_status} ({findings_count} findings)")
                last_phase = current_phase
                last_progress = current_progress
            
            # Check if scan completed
            if current_status in ["completed", "error", "failed", "stopped"]:
                print(f"\n✓ Scan finished with status: {current_status}")
                break
            
            await asyncio.sleep(poll_interval)
        else:
            print(f"\n⚠ Scan still running after {max_polls * poll_interval}s")
        
        # Step 4: Get final results
        print(f"\n[Step 4] Fetching final results...")
        final_status = await api.get_scan_status(scan_id)
        
        print(f"\n{'='*50}")
        print("SCAN RESULTS SUMMARY")
        print(f"{'='*50}")
        print(f"  Target:     {final_status.get('target_url')}")
        print(f"  Status:     {final_status.get('status')}")
        print(f"  Duration:   {final_status.get('duration', 'N/A')}")
        print(f"  Findings:   {final_status.get('findings_count', 0)} total")
        print(f"    Critical: {final_status.get('critical_count', 0)}")
        print(f"    High:     {final_status.get('high_count', 0)}")
        print(f"    Medium:   {final_status.get('medium_count', 0)}")
        print(f"    Low:      {final_status.get('low_count', 0)}")
        
        # Step 5: Get detailed findings
        findings = await api.get_scan_findings(scan_id)
        if findings.get("findings"):
            print(f"\n[Step 5] Top Findings:")
            for i, finding in enumerate(findings["findings"][:5], 1):
                print(f"  {i}. [{finding.get('severity', 'N/A').upper()}] {finding.get('title', 'No title')}")
                print(f"     URL: {finding.get('url', 'N/A')[:60]}...")
        
        # Step 6: Check logs
        logs = await api.get_scan_logs(scan_id)
        if logs.get("logs"):
            print(f"\n[Step 6] Recent Logs ({len(logs['logs'])} total):")
            for log in logs["logs"][-5:]:
                print(f"  [{log.get('level', 'info')}] {log.get('message', '')[:70]}")
        
        print("\n" + "=" * 70)
        print("  TEST COMPLETED")
        print("=" * 70 + "\n")
        
        return final_status


async def test_frontend_dashboard_apis():
    """Test dashboard-related APIs that frontend uses"""
    
    print("\n" + "=" * 70)
    print("  FRONTEND DASHBOARD API TEST")
    print("=" * 70 + "\n")
    
    async with APIClient() as api:
        # Login
        login_result = await api.login(TEST_EMAIL, TEST_PASSWORD)
        if not login_result["success"]:
            print(f"✗ Login failed")
            return
        
        print(f"✓ Logged in as {TEST_EMAIL}")
        
        # Test dashboard APIs
        tests = [
            ("GET", "/api/scans/all", "Scan History"),
            ("GET", "/api/auth/me", "User Profile"),
            ("GET", "/api/auth/subscription", "Subscription Status"),
            ("GET", "/api/scans/preflight", "Preflight Validation"),
            ("GET", "/api/vulnerabilities", "All Vulnerabilities"),
        ]
        
        for method, endpoint, name in tests:
            try:
                async with api.session.request(
                    method,
                    f"{BASE_URL}{endpoint}",
                    headers=api._headers()
                ) as response:
                    status = response.status
                    if status == 200:
                        data = await response.json()
                        # Check data type
                        if isinstance(data, dict):
                            keys = list(data.keys())[:3]
                            print(f"✓ {name}: OK (keys: {keys})")
                        elif isinstance(data, list):
                            print(f"✓ {name}: OK ({len(data)} items)")
                        else:
                            print(f"✓ {name}: OK")
                    else:
                        print(f"✗ {name}: {status}")
            except Exception as e:
                print(f"✗ {name}: Error - {e}")
    
    print("\n" + "=" * 70 + "\n")


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "--dashboard":
        # Quick dashboard API test
        asyncio.run(test_frontend_dashboard_apis())
    else:
        # Full scan test
        asyncio.run(test_full_scan_workflow())
