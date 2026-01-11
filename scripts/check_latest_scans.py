#!/usr/bin/env python
"""Check latest scan details"""
import requests

BASE_URL = "http://localhost:8000"

response = requests.post(f"{BASE_URL}/api/auth/login", json={"email": "user1@jarwis.ai", "password": "12341234"})
token = response.json()['access_token']
headers = {"Authorization": f"Bearer {token}"}

# Get all scans
response = requests.get(f"{BASE_URL}/api/scans/", headers=headers, params={"per_page": 10})
data = response.json()

print(f"Total scans: {data['total']}\n")
print("Latest 5 scans:")
for scan in data['scans'][:5]:
    print(f"  {scan['scan_id']}: status={scan['status']}, phase={scan['phase']}")
    print(f"    Target: {scan['target_url']}")
    print(f"    Findings: {scan['findings_count']} (Critical: {scan['critical_count']}, High: {scan['high_count']}, Medium: {scan['medium_count']}, Low: {scan['low_count']})")
    print(f"    Started: {scan['started_at']}")
    print()
