# Quick Start Guide - Enterprise Dashboard

## 🚀 Start Servers

```powershell
# Terminal 1 - Backend
cd D:\jarwis-ai-pentest
.\.venv\Scripts\python.exe -m uvicorn api.server:app --host 0.0.0.0 --port 8000 --reload

# Terminal 2 - Frontend
cd D:\jarwis-ai-pentest\jarwisfrontend
npm start
```

## 🔗 Access URLs

- **Old Dashboard**: http://localhost:3000/dashboard
- **New Dashboard**: http://localhost:3000/dashboard-v2
- **Backend API**: http://localhost:8000/docs

## 🧪 Test Endpoints (Postman/curl)

### Security Score
```bash
curl -X GET "http://localhost:8000/api/dashboard/security-score?days=30" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Risk Heatmap
```bash
curl -X GET "http://localhost:8000/api/dashboard/risk-heatmap?days=30" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Complete Overview (Optimized)
```bash
curl -X GET "http://localhost:8000/api/dashboard/overview?days=30" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

## 👤 Test Users

| Email | Password | Plan | Use Case |
|-------|----------|------|----------|
| akshaydevrari@gmail.com | Parilove@1 | enterprise | Full features |
| user2@jarwis.ai | 12341234 | professional | Test restrictions |
| user1@jarwis.ai | 12341234 | individual | Limited access |

## ✅ Testing Checklist

### **Dashboard Loading**
- [ ] `/dashboard-v2` loads without errors
- [ ] Security score displays (0-100)
- [ ] Grade badge shows (A-F)
- [ ] Risk heatmap renders
- [ ] Platform risk bars display
- [ ] All stats cards populate

### **Interactivity**
- [ ] Click heatmap cell → filters vulnerabilities
- [ ] Click platform bar → switches to tab
- [ ] Time period selector (7/30/90 days) works
- [ ] Manual refresh button works
- [ ] Auto-refresh triggers after 60s

### **Tab Navigation**
- [ ] Overview tab displays master dashboard
- [ ] Web Security tab shows OWASP chart
- [ ] Mobile Security tab displays with badges
- [ ] Cloud Security tab shows compliance
- [ ] Network Security tab renders

### **Data Accuracy**
- [ ] Scan counts match database
- [ ] Vulnerability counts correct
- [ ] Severity distribution accurate
- [ ] Confidence scores display (Web)
- [ ] Verification badges appear (Mobile)

### **Performance**
- [ ] Page loads < 2 seconds
- [ ] No console errors
- [ ] No 404s in Network tab
- [ ] Auto-refresh doesn't lag
- [ ] Tab switching is smooth

## 🐛 Common Issues

### "Cannot GET /api/dashboard/overview"
**Fix**: Restart backend server
```powershell
.\.venv\Scripts\python.exe -m uvicorn api.server:app --reload
```

### "Module not found: MasterOverview"
**Fix**: Check import paths in JarwisDashboardNew.jsx

### Blank Security Score
**Fix**: Ensure user has completed scans
```python
python create_users.py  # Reset test data
```

### CORS Errors
**Fix**: Check CORS settings in api/server.py
```python
CORS_ORIGINS = ["http://localhost:3000"]
```

## 📊 Sample API Response

### `/api/dashboard/overview`
```json
{
  "success": true,
  "data": {
    "security_score": {
      "score": 85.3,
      "grade": "B",
      "delta": -5.2,
      "breakdown": {
        "web": 90.1,
        "mobile": 85.0,
        "cloud": 80.5,
        "network": 75.3
      },
      "total_vulnerabilities": 42,
      "critical_count": 2,
      "trend": "declining"
    },
    "risk_heatmap": {
      "matrix": [
        {
          "platform": "web",
          "critical": 2,
          "high": 5,
          "medium": 10,
          "low": 8,
          "total": 25
        }
      ],
      "totals": {
        "critical": 6,
        "high": 14,
        "medium": 28,
        "low": 20,
        "total": 68
      }
    }
  }
}
```

## 🔄 Rollback Plan

If issues arise, revert to old dashboard:

### Option 1: Change Default Route
```jsx
// In router.jsx
{
  path: "/dashboard",
  element: <JarwisDashboard />  // Old dashboard
}
```

### Option 2: Feature Flag
```jsx
const USE_NEW_DASHBOARD = false;

{
  path: "/dashboard",
  element: USE_NEW_DASHBOARD 
    ? <JarwisDashboardNew /> 
    : <JarwisDashboard />
}
```

## 📞 Debugging Commands

### Check Backend Status
```powershell
curl http://localhost:8000/api/health
```

### View Backend Logs
```powershell
# Backend logs show in terminal where uvicorn runs
# Look for:
# - "GET /api/dashboard/overview" requests
# - Any 500 errors
# - SQLAlchemy query logs
```

### Check Database
```python
python
>>> from database.connection import get_db
>>> from database.models import Scan, Vulnerability
>>> db = next(get_db())
>>> scan_count = db.query(Scan).count()
>>> vuln_count = db.query(Vulnerability).count()
>>> print(f"Scans: {scan_count}, Vulnerabilities: {vuln_count}")
```

## 🎯 Success Indicators

✅ **Working Correctly:**
- Security score between 0-100
- Heatmap shows data in cells
- Platform bars have non-zero values
- Tabs load without console errors
- Clicking elements navigates properly

❌ **Needs Investigation:**
- All zeros in dashboard
- "undefined" in UI elements
- Console errors about missing data
- 404 errors in Network tab
- Slow loading (>3 seconds)

## 📚 Key Files

**Backend:**
- `services/dashboard_service.py` - Scoring logic
- `api/routes/dashboard.py` - API endpoints
- `api/routes/__init__.py` - Route registration

**Frontend:**
- `src/pages/dashboard/JarwisDashboardNew.jsx` - Main dashboard
- `src/components/dashboard/MasterOverview.jsx` - Overview tab
- `src/services/api.js` - API methods

## 💡 Pro Tips

1. **Use Browser DevTools**: Network tab shows API calls
2. **Check Response Times**: Overview endpoint should be < 500ms
3. **Test with Real Data**: Import production database dump for accuracy
4. **Monitor Auto-Refresh**: Watch Network tab after 60 seconds
5. **Test Multiple Plans**: Verify subscription restrictions work

---

**Last Updated**: January 7, 2026  
**Version**: 2.0.0  
**Status**: Ready for Testing
