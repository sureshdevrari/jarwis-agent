#!/usr/bin/env python
"""
Comprehensive Login Issue Diagnostic Script
Tests all components without modifying data
"""

import asyncio
import sys
import json
from pathlib import Path
from typing import Dict, Any

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PROJECT_ROOT))

async def test_database_connection() -> Dict[str, Any]:
    """Test database connectivity"""
    print("\n" + "="*60)
    print("[TEST 1] Database Connection")
    print("="*60)
    
    try:
        from database.config import settings
        from database.connection import test_connection, AsyncSessionLocal
        from sqlalchemy import text
        
        print(f"  Database Type: {settings.DB_TYPE}")
        print(f"  Database Path: {settings.SQLITE_PATH if settings.DB_TYPE == 'sqlite' else settings.POSTGRES_HOST}")
        
        # Test basic connection
        connected, error = await test_connection()
        print(f"  Connection Test: {'✓ PASS' if connected else '✗ FAIL'}")
        if error:
            print(f"    Error: {error}")
        
        # Check if database file exists
        if settings.DB_TYPE == "sqlite":
            db_path = Path(settings.SQLITE_PATH)
            exists = db_path.exists()
            print(f"  Database File Exists: {'✓ YES' if exists else '✗ NO'}")
            if exists:
                size = db_path.stat().st_size
                print(f"    Size: {size / 1024:.2f} KB")
        
        # Try to execute simple query
        try:
            if AsyncSessionLocal:
                async with AsyncSessionLocal() as session:
                    result = await session.execute(text("SELECT 1"))
                    print(f"  Query Execution: ✓ PASS")
            else:
                print(f"  Query Execution: ✗ FAIL (AsyncSessionLocal not available)")
        except Exception as e:
            print(f"  Query Execution: ✗ FAIL")
            print(f"    Error: {e}")
        
        return {
            "status": "pass" if connected else "fail",
            "connected": connected,
            "error": error
        }
    except Exception as e:
        print(f"  ✗ EXCEPTION: {e}")
        return {"status": "error", "error": str(e)}


async def test_database_tables() -> Dict[str, Any]:
    """Check if required tables exist"""
    print("\n" + "="*60)
    print("[TEST 2] Database Tables")
    print("="*60)
    
    try:
        from database.connection import AsyncSessionLocal
        from sqlalchemy import text, inspect
        
        if not AsyncSessionLocal:
            print("  ✗ AsyncSessionLocal not available")
            return {"status": "fail", "error": "No session factory"}
        
        async with AsyncSessionLocal() as session:
            # Get list of tables
            inspector = inspect(await session.connection())
            tables = inspector.get_table_names()
            
            print(f"  Tables Found: {len(tables)}")
            
            required_tables = ["user", "refresh_token", "brute_force_attempt"]
            for table in required_tables:
                exists = table in tables
                print(f"    {table}: {'✓ EXISTS' if exists else '✗ MISSING'}")
            
            # Check user count
            try:
                result = await session.execute(text("SELECT COUNT(*) FROM user"))
                count = result.scalar()
                print(f"  Users in Database: {count}")
            except:
                print(f"  Users in Database: ✗ Cannot query")
        
        return {"status": "pass" if tables else "fail", "tables_count": len(tables), "tables": tables}
    except Exception as e:
        print(f"  ✗ EXCEPTION: {e}")
        return {"status": "error", "error": str(e)}


async def test_api_health() -> Dict[str, Any]:
    """Test API health endpoints"""
    print("\n" + "="*60)
    print("[TEST 3] API Health Endpoints")
    print("="*60)
    
    try:
        import aiohttp
        
        base_url = "http://localhost:8000"
        endpoints = [
            ("/api/health", "General Health"),
            ("/api/health/db", "Database Health")
        ]
        
        async with aiohttp.ClientSession() as session:
            for endpoint, label in endpoints:
                try:
                    async with session.get(f"{base_url}{endpoint}", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                        status = "✓ PASS" if resp.status == 200 else f"✗ FAIL ({resp.status})"
                        print(f"  {label}: {status}")
                        
                        if resp.status == 200:
                            data = await resp.json()
                            if "database" in str(data).lower():
                                db_status = data.get("database", "unknown")
                                print(f"    Database Status: {db_status}")
                        else:
                            text = await resp.text()
                            print(f"    Response: {text[:100]}")
                except asyncio.TimeoutError:
                    print(f"  {label}: ✗ TIMEOUT (backend not responding)")
                except Exception as e:
                    print(f"  {label}: ✗ ERROR - {str(e)[:80]}")
        
        return {"status": "pass"}
    except Exception as e:
        print(f"  ✗ EXCEPTION: {e}")
        return {"status": "error", "error": str(e)}


async def test_cors_config() -> Dict[str, Any]:
    """Test CORS configuration"""
    print("\n" + "="*60)
    print("[TEST 4] CORS Configuration")
    print("="*60)
    
    try:
        import aiohttp
        
        base_url = "http://localhost:8000"
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type"
            }
            
            try:
                async with session.options(f"{base_url}/api/auth/login", headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    cors_origin = resp.headers.get("Access-Control-Allow-Origin", "NOT SET")
                    cors_methods = resp.headers.get("Access-Control-Allow-Methods", "NOT SET")
                    
                    print(f"  CORS Origin: {cors_origin}")
                    print(f"  CORS Methods: {cors_methods}")
                    print(f"  Status: {'✓ PASS' if cors_origin != 'NOT SET' else '⚠ WARNING'}")
            except asyncio.TimeoutError:
                print(f"  ✗ TIMEOUT (backend not responding)")
            except Exception as e:
                print(f"  ✗ ERROR: {str(e)[:80]}")
        
        return {"status": "pass"}
    except Exception as e:
        print(f"  ✗ EXCEPTION: {e}")
        return {"status": "error"}


async def test_login_endpoint() -> Dict[str, Any]:
    """Test login endpoint directly"""
    print("\n" + "="*60)
    print("[TEST 5] Login Endpoint")
    print("="*60)
    
    try:
        import aiohttp
        
        base_url = "http://localhost:8000"
        test_creds = {
            "email": "user1@jarwis.ai",
            "password": "12341234"
        }
        
        async with aiohttp.ClientSession() as session:
            try:
                async with session.post(
                    f"{base_url}/api/auth/login",
                    json=test_creds,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as resp:
                    status_text = "✓ PASS" if resp.status == 200 else f"✗ FAIL ({resp.status})"
                    print(f"  Status Code: {resp.status} {status_text}")
                    
                    response_data = await resp.json()
                    
                    if resp.status == 200:
                        print(f"  ✓ Login successful")
                        print(f"    User: {response_data.get('user', {}).get('email', 'unknown')}")
                        print(f"    Token: {response_data.get('access_token', 'not provided')[:20]}...")
                    else:
                        print(f"  ✗ Login failed")
                        print(f"    Error: {response_data.get('detail', response_data)}")
                    
                    return {
                        "status": "pass" if resp.status == 200 else "fail",
                        "status_code": resp.status,
                        "response": response_data
                    }
            except asyncio.TimeoutError:
                print(f"  ✗ TIMEOUT (backend not responding after 10 seconds)")
                return {"status": "fail", "error": "timeout"}
            except Exception as e:
                print(f"  ✗ ERROR: {str(e)}")
                return {"status": "fail", "error": str(e)}
    except Exception as e:
        print(f"  ✗ EXCEPTION: {e}")
        return {"status": "error", "error": str(e)}


async def test_frontend_config() -> Dict[str, Any]:
    """Test frontend configuration"""
    print("\n" + "="*60)
    print("[TEST 6] Frontend Configuration")
    print("="*60)
    
    try:
        # Check if frontend files exist
        frontend_path = PROJECT_ROOT / "jarwisfrontend" / "src"
        print(f"  Frontend Path: {frontend_path}")
        print(f"  Exists: {'✓ YES' if frontend_path.exists() else '✗ NO'}")
        
        # Check API service file
        api_service = frontend_path / "services" / "api.js"
        print(f"  API Service: {'✓ EXISTS' if api_service.exists() else '✗ MISSING'}")
        
        # Check login page
        login_page = frontend_path / "pages" / "auth" / "Login.jsx"
        print(f"  Login Page: {'✓ EXISTS' if login_page.exists() else '✗ MISSING'}")
        
        # Check for .env or configuration
        env_file = PROJECT_ROOT / "jarwisfrontend" / ".env"
        env_local = PROJECT_ROOT / "jarwisfrontend" / ".env.local"
        
        has_env = env_file.exists() or env_local.exists()
        print(f"  .env File: {'✓ EXISTS' if has_env else '⚠ MISSING (using defaults)'}")
        
        return {"status": "pass"}
    except Exception as e:
        print(f"  ✗ EXCEPTION: {e}")
        return {"status": "error", "error": str(e)}


async def test_dependencies() -> Dict[str, Any]:
    """Test if required dependencies are installed"""
    print("\n" + "="*60)
    print("[TEST 7] Python Dependencies")
    print("="*60)
    
    required_packages = [
        ("fastapi", "FastAPI"),
        ("sqlalchemy", "SQLAlchemy"),
        ("aiosqlite", "AsyncSQLite"),
        ("asyncpg", "AsyncPG"),
        ("pydantic", "Pydantic"),
        ("aiohttp", "aiohttp"),
        ("jose", "python-jose"),
    ]
    
    missing = []
    for package, label in required_packages:
        try:
            __import__(package)
            print(f"  {label}: ✓ INSTALLED")
        except ImportError:
            print(f"  {label}: ✗ MISSING")
            missing.append(package)
    
    return {
        "status": "pass" if not missing else "fail",
        "missing": missing
    }


async def main():
    """Run all diagnostics"""
    print("""
╔════════════════════════════════════════════════════════════╗
║     Jarwis Login Issue - Comprehensive Diagnostic          ║
╚════════════════════════════════════════════════════════════╝
""")
    
    results = {}
    
    # Run all tests
    results["dependencies"] = await test_dependencies()
    results["database_connection"] = await test_database_connection()
    results["database_tables"] = await test_database_tables()
    results["api_health"] = await test_api_health()
    results["cors"] = await test_cors_config()
    results["login"] = await test_login_endpoint()
    results["frontend"] = await test_frontend_config()
    
    # Summary
    print("\n" + "="*60)
    print("DIAGNOSTIC SUMMARY")
    print("="*60)
    
    failed_tests = [k for k, v in results.items() if v.get("status") != "pass"]
    
    if not failed_tests:
        print("\n✓ ALL TESTS PASSED!")
        print("\nIf you're still getting login errors, check:")
        print("  1. Browser console (F12 → Console tab) for JavaScript errors")
        print("  2. Network tab (F12 → Network) for failed requests")
        print("  3. Backend PowerShell window for Python errors")
    else:
        print(f"\n✗ FAILED TESTS ({len(failed_tests)}):")
        for test in failed_tests:
            print(f"  - {test}: {results[test].get('error', 'Unknown error')}")
    
    print("\n" + "="*60)
    print("Full Results (JSON):")
    print("="*60)
    print(json.dumps(results, indent=2, default=str))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\nDiagnostic cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n\n✗ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
