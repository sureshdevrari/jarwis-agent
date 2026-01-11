#!/usr/bin/env python
"""Check user2 scans"""
import requests

BASE_URL = "http://localhost:8000"

# Login as user2
response = requests.post(f"{BASE_URL}/api/auth/login", json={"email": "user2@jarwis.ai", "password": "12341234"})
print("Login response:", response.status_code)

if response.status_code == 200:
    token = response.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    
    # Get scans
    response = requests.get(f"{BASE_URL}/api/scans/", headers=headers, params={"per_page": 10})
    data = response.json()
    
    print(f"Total scans: {data.get('total', 0)}\n")
    for scan in data.get("scans", []):
        print(f"ID: {scan['scan_id'][:8]}")
        print(f"  Status: {scan['status']}")
        print(f"  Target: {scan['target_url']}")
        print(f"  Phase: {scan['phase']}")
        print()
else:
    print("Login failed:", response.text)
