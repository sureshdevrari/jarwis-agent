
import sys
import asyncio
from api.server import app, lifespan

print("Import successful")

# Simulate startup
async def test_startup():
    print("Testing startup...")
    async with lifespan(app):
        print("Startup complete")
        # Do nothing, just exit context
    print("Shutdown complete")

if __name__ == "__main__":
    asyncio.run(test_startup())
