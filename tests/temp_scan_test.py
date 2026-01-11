import requests

base = "http://localhost:8000"
s = requests.Session()
resp = s.post(f"{base}/api/auth/login", json={"email": "user2@jarwis.ai", "password": "12341234"})
print("login", resp.status_code, resp.text)
resp.raise_for_status()
data = resp.json()
token = data.get("access_token") or data.get("token")
print("token", token)
headers = {"Authorization": f"Bearer {token}"}
payload = {
    "target_url": "https://httpbin.org",
    "scan_type": "web",
    "config": {"attacks": {}}
}
resp = s.post(f"{base}/api/scans", json=payload, headers=headers)
print("create scan", resp.status_code, resp.text)
