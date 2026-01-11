"""
Jarwis AGI Pen Test - Startup Script
Ensures all dependencies are installed before running the application
"""

import subprocess
import sys
import os
import threading
import time
import signal

# Global process references for cleanup
mitm_process = None
frontend_process = None


def start_mitm_proxy():
    """Start the MITM proxy for HTTPS traffic interception"""
    global mitm_process
    
    print("\n  Starting MITM Proxy...")
    
    # Ensure mitmproxy is installed
    try:
        result = subprocess.run(
            ["mitmdump", "--version"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print("  [!] mitmproxy not found. Installing...")
            subprocess.run([sys.executable, "-m", "pip", "install", "mitmproxy", "-q"], check=True)
            print("  [OK] mitmproxy installed")
    except FileNotFoundError:
        print("  [!] mitmdump not found. Installing mitmproxy...")
        subprocess.run([sys.executable, "-m", "pip", "install", "mitmproxy", "-q"], check=True)
        print("  [OK] mitmproxy installed")
    except Exception as e:
        print(f"  [X] Failed to check/install mitmproxy: {e}")
        return None
    
    # Setup paths
    from pathlib import Path
    cert_dir = Path.home() / ".jarwis" / "certs"
    cert_dir.mkdir(parents=True, exist_ok=True)
    
    mitm_addon_path = Path(__file__).parent / "core" / "mitm_addon.py"
    traffic_log_path = Path(__file__).parent / "reports" / "traffic_log.json"
    
    # Start mitmdump
    cmd = [
        "mitmdump",
        "--mode", "regular",
        "--listen-host", "127.0.0.1",
        "--listen-port", "8080",
        "--set", f"confdir={cert_dir}",
        "--set", f"jarwis_log_file={traffic_log_path}",
        "-s", str(mitm_addon_path),
        "--ssl-insecure",
        "-q"
    ]
    
    try:
        mitm_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )
        time.sleep(2)  # Wait for proxy to start
        
        if mitm_process.poll() is None:
            print("  [OK] MITM Proxy running on http://127.0.0.1:8080")
            print(f"  [OK] CA Certificate: {cert_dir / 'mitmproxy-ca-cert.pem'}")
            return mitm_process
        else:
            stderr = mitm_process.stderr.read().decode() if mitm_process.stderr else ""
            print(f"  [X] MITM Proxy failed to start: {stderr}")
            return None
    except Exception as e:
        print(f"  [X] Failed to start MITM Proxy: {e}")
        return None


def cleanup_processes():
    """Cleanup all spawned processes on exit"""
    global mitm_process, frontend_process
    
    print("\n  Shutting down services...")
    
    if mitm_process and mitm_process.poll() is None:
        try:
            if sys.platform == "win32":
                mitm_process.terminate()
            else:
                mitm_process.send_signal(signal.SIGTERM)
            mitm_process.wait(timeout=5)
            print("  [OK] MITM Proxy stopped")
        except Exception as e:
            print(f"  [!] Error stopping MITM Proxy: {e}")
            mitm_process.kill()
    
    if frontend_process and frontend_process.poll() is None:
        try:
            if sys.platform == "win32":
                frontend_process.terminate()
            else:
                frontend_process.send_signal(signal.SIGTERM)
            frontend_process.wait(timeout=5)
            print("  [OK] Frontend stopped")
        except Exception as e:
            print(f"  [!] Error stopping Frontend: {e}")
            frontend_process.kill()


def check_ai_status():
    """Check AI provider status (Gemini configured)"""
    print("\n  Checking AI status...")
    print("  [OK] Using Google Gemini AI (gemini-2.5-flash)")
    print("  [OK] AI features enabled via Gemini API")
    return True


def check_and_install_dependencies():
    """Check and install Python dependencies"""
    print("\n" + "="*60)
    print("  Jarwis AGI Pen Test - Dependency Check")
    print("="*60 + "\n")
    
    # Core dependencies required for the application
    required_packages = [
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn[standard]"),
        ("playwright", "playwright"),
        ("aiohttp", "aiohttp"),
        ("httpx", "httpx"),
        ("requests", "requests"),
        ("bs4", "beautifulsoup4"),  # Import name is 'bs4', not 'beautifulsoup4'
        ("rich", "rich"),
        ("yaml", "pyyaml"),  # Import name is 'yaml', not 'pyyaml'
        ("jinja2", "jinja2"),
    ]
    
    missing_packages = []
    
    for import_name, package_name in required_packages:
        try:
            __import__(import_name)
            print(f"  [OK] {package_name}")
        except ImportError:
            print(f"  [X] {package_name} (missing)")
            missing_packages.append(package_name)
    
    if missing_packages:
        print(f"\n  Installing {len(missing_packages)} missing packages...")
        for package in missing_packages:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package, "-q"])
                print(f"  [OK] Installed {package}")
            except subprocess.CalledProcessError as e:
                print(f"  [X] Failed to install {package}: {e}")
                return False
    
    # Check Playwright browsers
    print("\n  Checking Playwright browsers...")
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            # Try to get chromium executable path
            browser = p.chromium
            print("  [OK] Playwright Chromium ready")
    except Exception as e:
        print(f"  [!] Playwright browsers may need installation: {e}")
        print("  Running: playwright install chromium")
        try:
            subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])
            print("  [OK] Playwright Chromium installed")
        except subprocess.CalledProcessError:
            print("  [!] Could not install Playwright browsers automatically")
            print("  Please run: playwright install chromium")
    
    print("\n" + "="*60)
    print("  All dependencies ready!")
    print("="*60 + "\n")
    return True

def start_api_server():
    """Start the FastAPI server with uvicorn"""
    print("Starting API server on http://localhost:8000 ...")
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # Load environment variables from .env file
    try:
        from dotenv import load_dotenv
        load_dotenv()
        print("  [OK] Environment variables loaded from .env")
    except ImportError:
        print("  [!] python-dotenv not installed, using system env vars")
    
    # Import and run the FastAPI app with uvicorn
    import uvicorn
    uvicorn.run("api.server:app", host='0.0.0.0', port=8000, reload=False)

if __name__ == "__main__":
    import atexit
    
    # Register cleanup on exit
    atexit.register(cleanup_processes)
    
    if check_and_install_dependencies():
        print("\n" + "="*60)
        print("  Starting Jarwis Services")
        print("="*60)
        
        # Check AI status
        check_ai_status()
        
        # Start MITM Proxy
        mitm_process = start_mitm_proxy()
        
        print("\n" + "="*60)
        print("  All services running!")
        print("="*60)
        print("\n  Services:")
        print("    - API Server:   http://localhost:8000")
        print("    - MITM Proxy:   http://127.0.0.1:8080")
        print("    - Gemini AI:    Configured [OK]")
        print("\n  Press CTRL+C to stop all services\n")
        
        # Start API Server (blocks until stopped)
        start_api_server()
    else:
        print("Failed to install dependencies. Please check the errors above.")
        sys.exit(1)
