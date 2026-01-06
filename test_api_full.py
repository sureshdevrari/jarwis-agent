# Comprehensive API test for Jarwis
import requests
import json
import time
from datetime import datetime

BASE_URL = "http://localhost:8000"

class APITester:
    def __init__(self):
        self.token = None
        self.refresh_token = None
        self.results = []
    
    def test(self, name, method, endpoint, data=None, auth=False, expected_status=None):
        url = f"{BASE_URL}{endpoint}"
        headers = {"Content-Type": "application/json"}
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        
        try:
            if method == "GET":
                r = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                r = requests.post(url, json=data, headers=headers, timeout=10)
            elif method == "PUT":
                r = requests.put(url, json=data, headers=headers, timeout=10)
            elif method == "DELETE":
                r = requests.delete(url, headers=headers, timeout=10)
            
            success = r.status_code < 400 if expected_status is None else r.status_code == expected_status
            status_text = "OK" if success else "FAIL"
            
            print(f"[{status_text}] {name}: {r.status_code}")
            
            self.results.append({
                "name": name,
                "status": r.status_code,
                "success": success
            })
            
            try:
                return r.json() if r.text else {}
            except:
                return {"text": r.text[:200]}
                
        except requests.exceptions.ConnectionError:
            print(f"[FAIL] {name}: Connection refused")
            self.results.append({"name": name, "status": 0, "success": False})
            return None
        except Exception as e:
            print(f"[FAIL] {name}: {e}")
            self.results.append({"name": name, "status": 0, "success": False})
            return None
    
    def summary(self):
        passed = sum(1 for r in self.results if r["success"])
        total = len(self.results)
        print(f"\n{'='*50}")
        print(f"SUMMARY: {passed}/{total} tests passed")
        if passed < total:
            print("\nFailed tests:")
            for r in self.results:
                if not r["success"]:
                    print(f"  - {r['name']}: {r['status']}")


tester = APITester()
print("=" * 60)
print("JARWIS API COMPREHENSIVE TEST")
print(f"Started: {datetime.now()}")
print("=" * 60)

# 1. Health & Basic Endpoints
print("\n[1] HEALTH & BASIC ENDPOINTS")
print("-" * 40)
tester.test("Health Check", "GET", "/api/health")
tester.test("OpenAPI Schema", "GET", "/openapi.json")

# 2. Auth Endpoints (unauthenticated)
print("\n[2] AUTH ENDPOINTS (Public)")
print("-" * 40)
tester.test("Login - Invalid Creds", "POST", "/api/auth/login", 
            {"email": "fake@test.com", "password": "wrong123"}, expected_status=401)

# Register test user
test_email = f"test_{int(time.time())}@example.com"
test_user = {
    "email": test_email,
    "username": f"testuser_{int(time.time())}",
    "password": "SecurePass123!",
    "full_name": "Test User"
}
result = tester.test("Register User", "POST", "/api/auth/register", test_user)

# Try login with new user (should work or require verification)
result = tester.test("Login - New User", "POST", "/api/auth/login",
                     {"email": test_email, "password": "SecurePass123!"})
if result and "access_token" in result:
    tester.token = result["access_token"]
    tester.refresh_token = result.get("refresh_token")
    print(f"    Got access token!")

# 3. Protected Endpoints (requires auth)
print("\n[3] PROTECTED ENDPOINTS")
print("-" * 40)
tester.test("Get Me (no auth)", "GET", "/api/auth/me", expected_status=401)
tester.test("Get Me (with auth)", "GET", "/api/auth/me", auth=True)

# 4. Scan Endpoints
print("\n[4] SCAN ENDPOINTS")
print("-" * 40)
tester.test("List Scans (no auth)", "GET", "/api/scans/", expected_status=401)
tester.test("List Scans (auth)", "GET", "/api/scans/", auth=True)
tester.test("All Scans (auth)", "GET", "/api/scans/all", auth=True)

# 5. Network Scan Endpoints
print("\n[5] NETWORK SCAN ENDPOINTS")
print("-" * 40)
tester.test("Network Tools", "GET", "/api/network/tools", auth=True)
tester.test("Network Agents", "GET", "/api/network/agents", auth=True)

# 6. 2FA Endpoints
print("\n[6] TWO-FACTOR AUTH ENDPOINTS")
print("-" * 40)
tester.test("2FA Status", "GET", "/api/2fa/status", auth=True)

# 7. User Management
print("\n[7] USER ENDPOINTS")
print("-" * 40)
tester.test("Get Users (admin only)", "GET", "/api/users/", auth=True)
tester.test("Get Current User", "GET", "/api/users/me", auth=True)
tester.test("User Subscription", "GET", "/api/users/me/subscription", auth=True)
tester.test("User Features", "GET", "/api/users/me/features", auth=True)
tester.test("User Stats", "GET", "/api/users/me/stats", auth=True)

# 8. API Keys
print("\n[8] API KEY ENDPOINTS")
print("-" * 40)
tester.test("List API Keys", "GET", "/api/keys/", auth=True)

# 9. Payments/Subscription
print("\n[9] PAYMENT ENDPOINTS")
print("-" * 40)
tester.test("Get Plans", "GET", "/api/payments/plans")
tester.test("Payment Config", "GET", "/api/payments/config")

# Summary
tester.summary()
