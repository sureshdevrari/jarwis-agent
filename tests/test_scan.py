"""Test web and mobile scanning"""
import asyncio
import httpx
import json

API_URL = "http://localhost:8000"

async def main():
    async with httpx.AsyncClient(timeout=60.0) as client:
        # Use existing Pro user (user2@jarwis.ai is already professional)
        print("Logging in with Pro user...")
        login_data = {"email": "user2@jarwis.ai", "password": "password123"}
        resp = await client.post(f"{API_URL}/api/auth/login", json=login_data)
        
        if resp.status_code != 200:
            # Try alternate password
            login_data = {"email": "user2@jarwis.ai", "password": "Test1234!"}
            resp = await client.post(f"{API_URL}/api/auth/login", json=login_data)
        
        if resp.status_code != 200:
            print(f"Login failed: {resp.text}")
            print("\nTrying to use devraris@gmail.com (professional)...")
            login_data = {"email": "devraris@gmail.com", "password": "password123"}
            resp = await client.post(f"{API_URL}/api/auth/login", json=login_data)
            
        if resp.status_code != 200:
            print(f"Login failed: {resp.text}")
            return
        
        token = resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}
        user_info = resp.json().get("user", {})
        print(f"Logged in as: {user_info.get('email')} (Plan: {user_info.get('plan', 'unknown')})")
        
        # Test Web Scan
        print("\n" + "="*50)
        print("TESTING WEB SCAN")
        print("="*50)
        
        web_scan_data = {
            "target_url": "https://httpbin.org",
            "scan_type": "web"
        }
        
        resp = await client.post(f"{API_URL}/api/scans/", json=web_scan_data, headers=headers)
        print(f"Web Scan Start: {resp.status_code}")
        if resp.status_code in [200, 201]:
            scan = resp.json()
            scan_id = scan.get("scan_id")
            print(f"Scan ID: {scan_id}")
            print(f"Initial Status: {scan.get('status')}")
            
            # Poll for progress
            print("\nPolling for progress...")
            for i in range(20):
                await asyncio.sleep(3)
                resp = await client.get(f"{API_URL}/api/scans/{scan_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    print(f"  [{i+1}] Progress: {data.get('progress')}% - Phase: {data.get('phase')} - Status: {data.get('status')}")
                    if data.get('status') in ['completed', 'error', 'stopped']:
                        print(f"\nFinal status: {data.get('status')}")
                        print(f"Findings: {data.get('findings_count', 0)}")
                        break
        else:
            print(f"Error: {resp.text}")
        
        # Test Mobile Scan  
        print("\n" + "="*50)
        print("TESTING MOBILE SCAN")
        print("="*50)
        
        mobile_scan_data = {
            "target_url": "com.example.testapp",
            "scan_type": "mobile"
        }
        
        resp = await client.post(f"{API_URL}/api/scans/", json=mobile_scan_data, headers=headers)
        print(f"Mobile Scan Start: {resp.status_code}")
        if resp.status_code == 200:
            scan = resp.json()
            scan_id = scan.get("scan_id")
            print(f"Scan ID: {scan_id}")
            
            # Poll for progress
            for i in range(5):
                await asyncio.sleep(2)
                resp = await client.get(f"{API_URL}/api/scans/{scan_id}", headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    print(f"  Progress: {data.get('progress')}% - Phase: {data.get('phase')} - Status: {data.get('status')}")
                    if data.get('status') in ['completed', 'error', 'stopped']:
                        break
        else:
            print(f"Error: {resp.text}")
        
        print("\n" + "="*50)
        print("TESTS COMPLETE")
        print("="*50)

if __name__ == "__main__":
    asyncio.run(main())
