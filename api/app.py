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
    
    yield
    
    # Shutdown
    print("\n[SHUTDOWN] Shutting down Jarwis API Server...")
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
