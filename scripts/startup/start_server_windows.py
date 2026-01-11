"""
Windows-compatible startup wrapper for Jarwis backend server.
Sets the correct event loop policy before starting uvicorn.
"""
import sys
import asyncio

# MUST set event loop policy BEFORE any async imports
if sys.platform == 'win32':
    # Use WindowsSelectorEventLoopPolicy for subprocess support
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.server:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
