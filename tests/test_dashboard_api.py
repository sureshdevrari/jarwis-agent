#!/usr/bin/env python
"""
Comprehensive Dashboard API Test - All User Types
Tests all dashboard endpoints for Free, Professional, and Enterprise users
"""

import requests
import json
import sys
from datetime import datetime

# Configuration
API_BASE_URL = "http://localhost:8000"
HEADERS = {"Content-Type": "application/json"}

# Test users
TEST_USERS = {
    "free": {
        "email": "user1@jarwis.ai",
        "password": "12341234",
        "plan": "free",
        "expected_features": ["web_only", "no_dashboard_v2"]
    },
    "professional": {
        "email": "user2@jarwis.ai",
        "password": "12341234",
        "plan": "professional",
        "expected_features": ["all_platforms", "dashboard_v2"]
    },
    "enterprise": {
        "email": "user3@jarwis.ai",
        "password": "12341234",
        "plan": "enterprise",
        "expected_features": ["all_features", "dashboard_v2", "unlimited"]
    }
}

class DashboardTester:
    def __init__(self):
        self.session = requests.Session()
        self.tokens = {}
        self.results = {
            "passed": 0,
            "failed": 0,
            "errors": []
        }

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] {level:8} | {message}")

    def test_step(self, message):
        print(f"\n{'='*70}")
        print(f"  TEST: {message}")
        print(f"{'='*70}")

    def login_user(self, user_type):
        """Login and get access token"""
        self.test_step(f"LOGIN - {user_type.upper()} User")
        
        user = TEST_USERS[user_type]
        payload = {
            "email": user["email"],
            "password": user["password"]
        }
        
        try:
            response = self.session.post(
                f"{API_BASE_URL}/api/auth/login",
                json=payload,
                headers=HEADERS,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                self.tokens[user_type] = data.get("access_token")
                self.log(f"✓ Login successful for {user_type}")
                self.log(f"  User: {data.get('email')}")
                self.log(f"  Plan: {data.get('plan', 'N/A')}")
                self.results["passed"] += 1
                return True
            else:
                self.log(f"✗ Login failed: {response.status_code}", "ERROR")
                self.log(f"  Response: {response.text}", "ERROR")
                self.results["failed"] += 1
                self.results["errors"].append(f"Login failed for {user_type}")
                return False
        except Exception as e:
            self.log(f"✗ Login exception: {str(e)}", "ERROR")
            self.results["failed"] += 1
            self.results["errors"].append(f"Login exception: {str(e)}")
            return False

    def test_dashboard_endpoint(self, user_type, endpoint, params=None):
        """Test a specific dashboard endpoint"""
        if user_type not in self.tokens:
            self.log(f"⊘ Skipping {endpoint} - no token for {user_type}", "SKIP")
            return False

        token = self.tokens[user_type]
        headers = {**HEADERS, "Authorization": f"Bearer {token}"}
        
        url = f"{API_BASE_URL}/api/dashboard{endpoint}"
        if params:
            url += f"?{'&'.join(f'{k}={v}' for k, v in params.items())}"

        try:
            response = self.session.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get("success"):
                    self.log(f"✓ {endpoint} ({user_type})")
                    if "data" in data:
                        self.log(f"  Response keys: {', '.join(data['data'].keys())}")
                    self.results["passed"] += 1
                    return True
                else:
                    self.log(f"✗ {endpoint} returned success=false ({user_type})", "WARN")
                    self.log(f"  Message: {data.get('message')}", "WARN")
                    self.results["failed"] += 1
                    return False
            else:
                self.log(f"✗ {endpoint} - Status {response.status_code} ({user_type})", "ERROR")
                self.log(f"  Response: {response.text[:200]}", "ERROR")
                self.results["failed"] += 1
                self.results["errors"].append(f"{endpoint} returned {response.status_code}")
                return False
        except Exception as e:
            self.log(f"✗ {endpoint} exception: {str(e)}", "ERROR")
            self.results["failed"] += 1
            self.results["errors"].append(f"{endpoint} exception: {str(e)}")
            return False

    def test_user_type(self, user_type):
        """Test all endpoints for a user type"""
        print(f"\n\n{'#'*70}")
        print(f"#  TESTING {user_type.upper()} USER")
        print(f"{'#'*70}\n")

        # Step 1: Login
        if not self.login_user(user_type):
            self.log(f"Cannot continue testing {user_type} - login failed", "ERROR")
            return

        # Step 2: Test all dashboard endpoints
        self.test_step("Dashboard Endpoints")
        
        endpoints = [
            "/security-score",
            "/risk-heatmap",
            "/platform-breakdown",
            "/scan-stats",
            "/overview"
        ]
        
        for endpoint in endpoints:
            self.test_dashboard_endpoint(user_type, endpoint, {"days": 30})

    def run_all_tests(self):
        """Run complete test suite"""
        print("\n")
        print("┌" + "─"*68 + "┐")
        print("│" + " "*15 + "DASHBOARD API - COMPREHENSIVE TEST" + " "*20 + "│")
        print("│" + " "*12 + "Testing All User Types and Endpoints" + " "*19 + "│")
        print("└" + "─"*68 + "┘")

        # Test each user type
        for user_type in ["free", "professional", "enterprise"]:
            self.test_user_type(user_type)

        # Print summary
        self.print_summary()

    def print_summary(self):
        """Print test summary"""
        print("\n\n")
        print("┌" + "─"*68 + "┐")
        print("│" + " "*20 + "TEST SUMMARY" + " "*35 + "│")
        print("├" + "─"*68 + "┤")
        
        total = self.results["passed"] + self.results["failed"]
        passed = self.results["passed"]
        failed = self.results["failed"]
        
        pass_rate = (passed / total * 100) if total > 0 else 0
        
        print(f"│  Total Tests:  {total:<10} | Passed: {passed:<10} | Failed: {failed:<10}  │")
        print(f"│  Pass Rate:    {pass_rate:.1f}% {'✓' if pass_rate == 100 else '⚠':<60}        │")
        print("├" + "─"*68 + "┤")
        
        if self.results["errors"]:
            print("│  ERRORS:                                                             │")
            for i, error in enumerate(self.results["errors"][:5], 1):
                error_text = error[:60]
                print(f"│    {i}. {error_text:<63} │")
            if len(self.results["errors"]) > 5:
                print(f"│    ... and {len(self.results['errors'])-5} more errors                    │")
        
        print("└" + "─"*68 + "┘")
        
        # Exit code
        if failed == 0:
            print("\n✓ ALL TESTS PASSED!")
            return 0
        else:
            print(f"\n✗ {failed} TEST(S) FAILED")
            return 1

if __name__ == "__main__":
    try:
        tester = DashboardTester()
        exit_code = tester.run_all_tests()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n✗ Tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n✗ Unexpected error: {str(e)}")
        sys.exit(1)

# Test users with different plans
TEST_USERS = {
    "super_admin": {
        "email": "akshaydevrari@gmail.com",
        "password": "Parilove@1",
        "plan": "enterprise"
    },
    "admin": {
        "email": "admin@jarwis.ai",
        "password": "admin123",
        "plan": "enterprise"
    },
    "individual": {
        "email": "user1@jarwis.ai",
        "password": "12341234",
        "plan": "individual"
    },
    "professional": {
        "email": "user2@jarwis.ai",
        "password": "12341234",
        "plan": "professional"
    },
    "enterprise": {
        "email": "user3@jarwis.ai",
        "password": "12341234",
        "plan": "enterprise"
    }
}

def login(email: str, password: str) -> Dict[str, Any]:
    """Login and get access token"""
    try:
        response = requests.post(
            f"{API_BASE}/api/auth/login",
            json={"email": email, "password": password},
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            return {
                "success": True,
                "token": data.get("data", {}).get("access_token"),
                "user": data.get("data", {}).get("user")
            }
        else:
            return {
                "success": False,
                "error": f"Login failed: {response.status_code}",
                "response": response.text[:500]
            }
    except requests.exceptions.ConnectionError:
        return {"success": False, "error": "Cannot connect to API server. Is it running on port 8000?"}
    except Exception as e:
        return {"success": False, "error": f"Exception: {str(e)}"}


def test_endpoint(endpoint: str, token: str, params: Dict = None) -> Dict[str, Any]:
    """Test a dashboard endpoint"""
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(f"{API_BASE}{endpoint}", headers=headers, params=params)
        
        result = {
            "status_code": response.status_code,
            "success": response.status_code == 200
        }
        
        if response.status_code == 200:
            data = response.json()
            result["data"] = data
        else:
            result["error"] = response.text[:200]
            
        return result
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


def print_section(title: str):
    """Print a formatted section header"""
    print(f"\n{'=' * 80}")
    print(f"  {title}")
    print(f"{'=' * 80}\n")


def print_result(test_name: str, success: bool, details: str = ""):
    """Print test result"""
    status = "✅ PASS" if success else "❌ FAIL"
    print(f"{status} | {test_name}")
    if details:
        print(f"       {details}")


def main():
    print_section("DASHBOARD API TESTING - ALL USER TYPES")
    
    # Dashboard endpoints to test
    endpoints = {
        "security_score": "/api/dashboard/security-score",
        "risk_heatmap": "/api/dashboard/risk-heatmap",
        "platform_breakdown": "/api/dashboard/platform-breakdown",
        "scan_stats": "/api/dashboard/scan-stats",
        "overview": "/api/dashboard/overview"
    }
    
    # Track overall results
    total_tests = 0
    passed_tests = 0
    
    # Test each user type
    for user_type, credentials in TEST_USERS.items():
        print_section(f"Testing User: {credentials['email']} ({credentials['plan'].upper()})")
        
        # Login
        print("🔐 Logging in...")
        login_result = login(credentials["email"], credentials["password"])
        
        if not login_result["success"]:
            print_result(f"Login for {user_type}", False, login_result.get("error", "Unknown error"))
            print(f"   Response: {login_result.get('response', 'N/A')}\n")
            continue
        
        print_result(f"Login for {user_type}", True, f"Token obtained")
        token = login_result["token"]
        user_info = login_result.get("user", {})
        print(f"   User: {user_info.get('name', 'N/A')} | Plan: {user_info.get('subscription_plan', 'N/A')}")
        
        # Test each dashboard endpoint
        print("\n📊 Testing Dashboard Endpoints:")
        for endpoint_name, endpoint_path in endpoints.items():
            total_tests += 1
            result = test_endpoint(endpoint_path, token, params={"days": 30})
            
            if result["success"]:
                passed_tests += 1
                data = result.get("data", {})
                
                # Extract key metrics
                if endpoint_name == "security_score":
                    score_data = data.get("data", {})
                    details = f"Score: {score_data.get('score', 'N/A')}, Grade: {score_data.get('grade', 'N/A')}, Vulnerabilities: {score_data.get('total_vulnerabilities', 0)}"
                    
                elif endpoint_name == "risk_heatmap":
                    heatmap_data = data.get("data", {})
                    totals = heatmap_data.get("totals", {})
                    details = f"Total: {totals.get('total', 0)} (Critical: {totals.get('critical', 0)}, High: {totals.get('high', 0)})"
                    
                elif endpoint_name == "platform_breakdown":
                    breakdown_data = data.get("data", {})
                    platforms = breakdown_data.get("platforms", [])
                    details = f"Platforms: {len(platforms)}"
                    
                elif endpoint_name == "scan_stats":
                    stats_data = data.get("data", {})
                    details = f"Scans: {stats_data.get('total_scans', 0)}, Running: {stats_data.get('running_scans', 0)}"
                    
                elif endpoint_name == "overview":
                    overview_data = data.get("data", {})
                    security_score = overview_data.get("security_score", {})
                    details = f"Complete dashboard data loaded (Score: {security_score.get('score', 'N/A')})"
                
                print_result(endpoint_name, True, details)
            else:
                print_result(endpoint_name, False, f"Status: {result.get('status_code', 'N/A')}")
                if result.get("error"):
                    print(f"       Error: {result['error']}")
        
        print(f"\n   User Summary: {user_type.upper()} completed")
    
    # Print final summary
    print_section("FINAL RESULTS")
    print(f"Total Tests: {total_tests}")
    print(f"Passed: {passed_tests}")
    print(f"Failed: {total_tests - passed_tests}")
    print(f"Success Rate: {(passed_tests/total_tests*100) if total_tests > 0 else 0:.1f}%")
    
    if passed_tests == total_tests:
        print("\n✅ ALL TESTS PASSED! Dashboard API is working correctly for all user types.")
    else:
        print(f"\n⚠️  {total_tests - passed_tests} test(s) failed. Please review the errors above.")
    
    print("\n" + "=" * 80)


if __name__ == "__main__":
    main()
