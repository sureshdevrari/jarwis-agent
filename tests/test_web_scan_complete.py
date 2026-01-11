#!/usr/bin/env python
"""
Complete test of web scan flow with detailed error reporting.
"""
import requests
import json
import time

BASE_URL = "http://localhost:8000"

def login():
    """Login and get token"""
    response = requests.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": "user1@jarwis.ai", "password": "12341234"}
    )
    assert response.status_code == 200, f"Login failed: {response.text}"
    data = response.json()
    return data['access_token']

def create_web_scan(token):
    """Create a new web scan"""
    headers = {"Authorization": f"Bearer {token}"}
    scan_data = {
        "target_url": "https://httpbin.org",
        "scan_type": "web",
        "login_url": None,
        "username": None,
        "password": None,
        "two_factor": None,
        "config": {}
    }
    
    response = requests.post(
        f"{BASE_URL}/api/scans/",
        headers=headers,
        json=scan_data
    )
    print(f"Create scan response: {response.status_code}")
    print(f"Response body: {response.text}")
    
    assert response.status_code == 201, f"Failed to create scan: {response.text}"
    data = response.json()
    return data['scan_id']

def get_scan_status(token, scan_id):
    """Get scan status"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(
        f"{BASE_URL}/api/scans/{scan_id}",
        headers=headers
    )
    if response.status_code == 200:
        return response.json()
    return None

def get_scan_logs(token, scan_id):
    """Get scan logs"""
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(
        f"{BASE_URL}/api/scans/{scan_id}/logs",
        headers=headers
    )
    if response.status_code == 200:
        data = response.json()
        return data.get('logs', [])  # Extract logs from response
    return []

def main():
    print("=" * 60)
    print("WEB SCAN END-TO-END TEST")
    print("=" * 60)
    
    # Step 1: Login
    print("\n[1] Logging in...")
    token = login()
    print("✅ Login successful")
    
    # Step 2: Create scan
    print("\n[2] Creating web scan...")
    scan_id = create_web_scan(token)
    print(f"✅ Scan created: {scan_id}")
    
    # Step 3: Monitor progress
    print("\n[3] Monitoring scan progress...")
    for i in range(30):  # Monitor for up to 30 seconds
        time.sleep(1)
        status = get_scan_status(token, scan_id)
        if status:
            print(f"  [{i+1}s] Status: {status['status']}, Progress: {status['progress']}%, Phase: {status['phase']}")
            
            if status['status'] in ['completed', 'error']:
                print(f"\n✅ Scan finished with status: {status['status']}")
                
                # Get logs
                logs = get_scan_logs(token, scan_id)
                if logs and isinstance(logs, list):
                    print("\n[4] Scan logs:")
                    for log in logs:
                        if isinstance(log, dict):
                            print(f"  [{log.get('level', 'INFO').upper()}] {log.get('message', '')}")
                        else:
                            print(f"  {log}")
                else:
                    print(f"\n⚠️  No logs available (got: {type(logs)})")
                
                if status['status'] == 'error':
                    print(f"\n❌ ERROR: {status['phase']}")
                    print("\nPlease check the backend logs for full traceback")
                else:
                    print(f"\n✅ SUCCESS! Found {status['findings_count']} vulnerabilities")
                    print(f"   Critical: {status['critical_count']}")
                    print(f"   High: {status['high_count']}")
                    print(f"   Medium: {status['medium_count']}")
                    print(f"   Low: {status['low_count']}")
                
                break
    else:
        print("\n⏱️  Timeout: Scan still running after 30 seconds")
        print("  This is normal for comprehensive scans")

if __name__ == "__main__":
    main()
