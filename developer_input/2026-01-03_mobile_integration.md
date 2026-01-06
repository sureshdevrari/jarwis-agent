# Developer Session - January 3, 2026

## Session Focus: Mobile App API Discovery & Emulator Setup

### Problem Statement
> "The mobile app API endpoint did not discovered means emulator didn't worked and crawl the mobile app for all pages please fix"

The original static-only scan wasn't finding API endpoints because it only analyzed source files. User needed **dynamic crawling** with Frida to capture live API traffic.

---

## Work Completed ✅

### 1. Created `attacks/mobile/dynamic_crawler.py`
- **Purpose**: Dynamic API discovery by running app with Frida instrumentation
- **Classes**: `DynamicAppCrawler`, `DiscoveredAPI`, `DynamicCrawlResult`
- **Features**:
  - Frida scripts for SSL bypass (TrustManager, OkHttp, Retrofit, Volley, HttpURLConnection, WebView hooks)
  - UI automation via ADB input simulation (taps, scrolls, back button)
  - Captures all HTTP/HTTPS traffic from running app

### 2. Added Dynamic Crawl API Endpoints to `api/app.py`
```
POST   /api/mobile/crawl/dynamic          - Start dynamic crawl
GET    /api/mobile/crawl/<id>/status      - Check crawl status  
GET    /api/mobile/crawl/<id>/apis        - Get discovered APIs
```

### 3. Updated Mobile Scan Flow
- Modified `api/app.py` (lines ~1330) to try dynamic crawling first when:
  - `runtime_analysis` is enabled
  - ADB devices are connected
- Merges dynamic and static results

### 4. Added Frontend Dynamic Crawl UI
- Updated `EmulatorManager.js` with:
  - File upload for APK
  - Duration control
  - Crawl results display
  - API list with method badges
- Updated `EmulatorManager.css` with matching styles

### 5. Android SDK Setup Progress
- ✅ Java 17 installed: `C:\Program Files\Microsoft\jdk-17.0.17.10-hotspot`
- ✅ Android SDK Root: `C:\Users\anshi\.jarwis\android-sdk`
- ✅ cmdline-tools installed
- ✅ platform-tools (ADB) installed
- ✅ emulator component installed
- ✅ platforms/android-33 installed
- 🔄 System image download (android-33;google_apis;x86_64) - was at 11%

---

## Integration Test Results ✅

| Component | Status |
|-----------|--------|
| DynamicAppCrawler imports | ✅ OK |
| EmulatorManager imports | ✅ OK |
| Dynamic crawl endpoints (3) | ✅ OK |
| Emulator endpoints (8) | ✅ OK |
| EmulatorManager.js | ✅ Exists |
| EmulatorManager.css | ✅ Exists |

---

## Next Steps (To Continue Tomorrow)

### 1. Complete System Image Download
```powershell
$env:JAVA_HOME = "C:\Program Files\Microsoft\jdk-17.0.17.10-hotspot"
$env:ANDROID_SDK_ROOT = "C:\Users\anshi\.jarwis\android-sdk"
& "$env:ANDROID_SDK_ROOT\cmdline-tools\latest\bin\sdkmanager.bat" "system-images;android-33;google_apis;x86_64"
```

### 2. Create AVD
```powershell
& "$env:ANDROID_SDK_ROOT\cmdline-tools\latest\bin\avdmanager.bat" create avd -n jarwis_test_device -k "system-images;android-33;google_apis;x86_64" --device "pixel_4"
```

### 3. Start Emulator
```powershell
& "$env:ANDROID_SDK_ROOT\emulator\emulator.exe" -avd jarwis_test_device -no-audio
```

### 4. Install Frida Server on Emulator
```powershell
# Download frida-server for x86_64
# Push to /data/local/tmp/
# chmod +x and run as root
```

### 5. Test Dynamic Crawling
- Upload APK via frontend
- Run dynamic crawl
- Verify API endpoints are discovered

---

## Key Files Modified/Created

| File | Action | Purpose |
|------|--------|---------|
| `attacks/mobile/dynamic_crawler.py` | Created | Frida-based dynamic API discovery |
| `attacks/mobile/__init__.py` | Modified | Export new classes |
| `api/app.py` | Modified | Add 3 new endpoints, update mobile scan |
| `frontend/src/components/EmulatorManager.js` | Modified | Dynamic crawl UI |
| `frontend/src/components/EmulatorManager.css` | Modified | Styles for crawl UI |

---

## Environment Details

- **Python venv**: `D:/jarwis-ai-pentest/venv`
- **Flask Backend**: Port 5000
- **React Frontend**: Port 3001
- **Ollama LLM**: Port 11434 (jarwis:latest, llama3:latest)
- **Target Emulator**: jarwis_test_device, 4GB RAM, x86_64, Android 13 (API 33)

---

## Commands to Start Services

```powershell
# Start backend
cd d:\jarwis-ai-pentest
.\venv\Scripts\python.exe start_server.py

# Start frontend (separate terminal)
cd d:\jarwis-ai-pentest\frontend
npm start

# Check status
Invoke-RestMethod http://localhost:5000/api/health
```
