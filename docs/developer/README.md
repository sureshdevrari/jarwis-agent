# Developer Input Archive

This folder contains session notes organized by date to maintain continuity across development sessions.

## Structure

```
developer_input/
├── README.md                           # This file
├── 2026-01-03_mobile_integration.md    # Mobile app dynamic crawling setup
└── [future dates]_[topic].md           # Future sessions
```

## Naming Convention

Files follow the pattern: `YYYY-MM-DD_topic.md`

## Quick Resume Commands

### Start All Services
```powershell
cd d:\jarwis-ai-pentest
.\venv\Scripts\python.exe start_server.py

# In separate terminal
cd d:\jarwis-ai-pentest\frontend
npm start
```

### Check Service Status
```powershell
Write-Host "Backend: " -NoNewline; try { Invoke-RestMethod http://localhost:5000/api/health -TimeoutSec 2 | Out-Null; Write-Host "UP" -ForegroundColor Green } catch { Write-Host "DOWN" -ForegroundColor Red }
Write-Host "Frontend: " -NoNewline; try { Invoke-WebRequest http://localhost:3001 -TimeoutSec 2 | Out-Null; Write-Host "UP" -ForegroundColor Green } catch { Write-Host "DOWN" -ForegroundColor Red }
Write-Host "Ollama: " -NoNewline; try { Invoke-RestMethod http://localhost:11434/api/tags -TimeoutSec 2 | Out-Null; Write-Host "UP" -ForegroundColor Green } catch { Write-Host "DOWN" -ForegroundColor Red }
```

### Android Emulator Setup (In Progress)
```powershell
$env:JAVA_HOME = "C:\Program Files\Microsoft\jdk-17.0.17.10-hotspot"
$env:ANDROID_SDK_ROOT = "C:\Users\anshi\.jarwis\android-sdk"

# Resume system image download if needed
& "$env:ANDROID_SDK_ROOT\cmdline-tools\latest\bin\sdkmanager.bat" "system-images;android-33;google_apis;x86_64"
```

## Current Project State

- ✅ Web pentest scanner (OWASP Top 10)
- ✅ Mobile static analysis
- ✅ AI Planner with Ollama
- ✅ React frontend
- 🔄 Mobile dynamic crawling (emulator setup pending)
