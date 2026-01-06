# OAuth Setup Reminder - January 4, 2026

## 🚀 Quick Start - Starting Development Servers

**IMPORTANT**: Always start servers in separate windows to avoid VS Code terminal issues.

### Option 1: Use Batch Files (Recommended)
1. Double-click `start_backend.bat` - Opens backend in new window
2. Double-click `start_frontend.bat` - Opens frontend in new window

### Option 2: PowerShell Commands
```powershell
# Start Backend (run from D:\jarwis-ai-pentest)
Start-Process cmd -ArgumentList "/k", "cd /d D:\jarwis-ai-pentest && venv\Scripts\activate.bat && python -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload"

# Start Frontend (run after backend is healthy)
Start-Process cmd -ArgumentList "/k", "cd /d D:\jarwis-ai-pentest\jarwisfrontend && set PORT=3000 && npm start"
```

### Health Check
```powershell
Invoke-RestMethod -Uri "http://localhost:8000/api/health"
```

---

## TODO: Configure OAuth Providers for Social Login

### Google OAuth
1. Go to: https://console.cloud.google.com/apis/credentials
2. Create/Select OAuth 2.0 Client ID
3. Add Authorized redirect URIs:
   - `http://localhost:8000/api/oauth/google/callback`
   - `http://localhost:3000/oauth/callback`
4. Add your email to **Test users** under OAuth consent screen
5. Copy Client ID and Secret to `.env` file

### GitHub OAuth
1. Go to: https://github.com/settings/developers
2. Create/Select OAuth App
3. Set:
   - Homepage URL: `http://localhost:3000`
   - Authorization callback URL: `http://localhost:8000/api/oauth/github/callback`
4. Copy Client ID and Secret to `.env` file

### Microsoft OAuth (Azure AD)
1. Go to: https://portal.azure.com/#blade/Microsoft_AAD_RegisteredApps/ApplicationsListBlade
2. Create/Select App Registration
3. Under **Authentication**, add Redirect URIs:
   - `http://localhost:8000/api/oauth/microsoft/callback`
   - `http://localhost:3000/oauth/callback`
4. Enable "Allow public client flows" = Yes
5. Copy Client ID, Secret, and Tenant ID to `.env` file

### Update .env File
```dotenv
# Google OAuth
GOOGLE_CLIENT_ID=your-actual-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=your-actual-secret

# GitHub OAuth  
GITHUB_CLIENT_ID=your-actual-github-client-id
GITHUB_CLIENT_SECRET=your-actual-github-secret

# Microsoft OAuth
MICROSOFT_CLIENT_ID=your-actual-microsoft-client-id
MICROSOFT_CLIENT_SECRET=your-actual-microsoft-secret
MICROSOFT_TENANT_ID=common
```

### Notes
- Warnings during localhost testing are normal (unverified apps)
- Click "Advanced" → "Go to app (unsafe)" to bypass during development
- Warnings disappear after apps are verified for production
