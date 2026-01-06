"""Test login API endpoint"""
import asyncio
import httpx

API_URL = "http://localhost:8001"

async def test_login():
    async with httpx.AsyncClient() as client:
        # Test login with valid credentials
        print("Testing login with user1@jarwis.ai / 12341234")
        
        try:
            response = await client.post(
                f"{API_URL}/api/auth/login",
                json={
                    "email": "user1@jarwis.ai",
                    "password": "12341234"
                },
                timeout=10.0
            )
            
            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")
            
            if response.status_code == 200:
                print("\n[OK] Login successful!")
            else:
                print(f"\n[X] Login failed with status {response.status_code}")
                
        except httpx.ConnectError:
            print("[X] Could not connect to API server at", API_URL)
            print("Make sure the server is running: python -m uvicorn api.server:app --host 0.0.0.0 --port 8000")
        except Exception as e:
            print(f"[X] Error: {e}")

if __name__ == "__main__":
    asyncio.run(test_login())
