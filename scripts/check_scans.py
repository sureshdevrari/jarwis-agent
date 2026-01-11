import requests

# Login
r = requests.post('http://localhost:8000/api/auth/login', json={'email': 'user3@jarwis.ai', 'password': '12341234'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# Get scans
scans_resp = requests.get('http://localhost:8000/api/scans/', headers=headers)
scans_data = scans_resp.json()

print(f"Total scans: {scans_data.get('total', 0)}")
print("\nRecent scans:")
for scan in scans_data.get('scans', [])[:5]:
    print(f"  {scan['scan_id']}: status={scan['status']}, phase={scan.get('phase', 'N/A')}, target={scan.get('target_url', 'N/A')}")
    if scan['status'] == 'error':
        # Get detailed error
        detail_resp = requests.get(f"http://localhost:8000/api/scans/{scan['scan_id']}", headers=headers)
        detail = detail_resp.json()
        print(f"    Error details: {detail.get('phase', 'No error details')}")
