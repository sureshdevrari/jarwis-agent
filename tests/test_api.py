# Test API endpoints
import requests
import time

BASE_URL = "http://localhost:8000"

def test_endpoint(name, method, url, data=None, headers=None):
    try:
        if method == "GET":
            r = requests.get(url, headers=headers, timeout=5)
        elif method == "POST":
            r = requests.post(url, json=data, headers=headers, timeout=5)
        
        print(f"[{'OK' if r.status_code < 400 else 'FAIL'}] {name}: {r.status_code}")
        if r.status_code < 400:
            return r.json() if r.text else {}
        else:
            print(f"    Response: {r.text[:200]}")
            return None
    except requests.exceptions.ConnectionError:
        print(f"[FAIL] {name}: Connection refused - is server running?")
        return None
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        return None

print("Testing Jarwis API Endpoints\n" + "=" * 40)

# Health check
test_endpoint("Health Check", "GET", f"{BASE_URL}/api/health")

# Auth endpoints
test_endpoint("Login (no data)", "POST", f"{BASE_URL}/api/auth/login", {"email": "test@test.com", "password": "test123"})

# List routes
test_endpoint("API Routes", "GET", f"{BASE_URL}/openapi.json")

print("\nDone!")
