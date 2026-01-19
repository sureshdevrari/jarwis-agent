"""
Jarwis AGI Pen Test - Main API Application
"""
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import routes
from api.routes import api_router

# Import database
from database.connection import init_db, close_db


async def handle_agent_disconnection(agent_id: str, active_scans: set, reason: str):
    """
    Callback for when an agent disconnects with active scans.
    Updates scan status to 'agent_disconnected'.
    """
    from database.connection import SessionLocal
    from database import crud
    
    if not active_scans:
        return
    
    try:
        async with SessionLocal() as db:
            for scan_id in active_scans:
                try:
                    await crud.update_scan_status(
                        db, 
                        scan_id, 
                        "agent_disconnected",
                        error_message=f"Agent disconnected: {reason}"
                    )
                    print(f"[AGENT] Marked scan {scan_id} as agent_disconnected")
                except Exception as e:
                    print(f"[AGENT] Failed to update scan {scan_id}: {e}")
    except Exception as e:
        print(f"[AGENT] Error in disconnection callback: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown"""
    # Startup
    print("\n[LAUNCH] Starting Jarwis API Server...")
    try:
        await init_db()
        print("[OK] Database initialized")
    except Exception as e:
        print(f"[!] Database init warning: {e}")
    
    # Register agent disconnection callback
    try:
        from core.universal_agent_server import universal_agent_manager
        universal_agent_manager.set_disconnection_callback(handle_agent_disconnection)
        await universal_agent_manager.start()
        print("[OK] Universal Agent Manager started")
    except Exception as e:
        print(f"[!] Agent manager warning: {e}")
    
    yield
    
    # Shutdown
    print("\n[SHUTDOWN] Shutting down Jarwis API Server...")
    try:
        from core.universal_agent_server import universal_agent_manager
        await universal_agent_manager.stop()
        print("[OK] Universal Agent Manager stopped")
    except Exception as e:
        print(f"[!] Agent manager shutdown warning: {e}")
    try:
        await close_db()
        print("[OK] Database connections closed")
    except Exception as e:
        print(f"[!] Database shutdown warning: {e}")


app = FastAPI(
    title="Jarwis AGI Pen Test API", 
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register all routes via the combined api_router
app.include_router(api_router)


@app.get('/api/health')
async def health():
    """Health check endpoint"""
    return {"status": "ok", "version": "1.0.0", "service": "jarwis-api"}


@app.get('/api/reports')
async def reports():
    """Reports endpoint for frontend"""
    return []


if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=8000)
