import requests

# Login
r = requests.post('http://localhost:8000/api/auth/login', json={'email': 'user3@jarwis.ai', 'password': '12341234'})
token = r.json()['access_token']
headers = {'Authorization': f'Bearer {token}'}

# Get scan logs
scan_id = '7e355646'
logs_resp = requests.get(f'http://localhost:8000/api/scans/{scan_id}/logs', headers=headers)
logs_data = logs_resp.json()

print(f"Logs for scan {scan_id}:")
for log in logs_data.get('logs', []):
    print(f"  [{log.get('level', 'INFO')}] {log.get('timestamp', '')}: {log.get('message', '')}")
