# Session Timeout Increase Reminder

## Created: January 4, 2026

## Current Configuration
- **Access Token Expiry**: 5 minutes
- **Session Inactivity Timeout**: 5 minutes  
- **Token Refresh Interval**: Every 30 seconds check
- **Refresh Token Expiry**: 7 days

## Why 5 Minutes?
Initial strict security measure to:
1. Prevent session hijacking attacks
2. Force attackers to constantly renew tokens
3. Minimize window for captured JWT token abuse
4. Test user experience with strict timeouts

## When to Increase
After confirming:
- [ ] Single-session enforcement works correctly
- [ ] Refresh token rotation is reliable
- [ ] No false session terminations reported
- [ ] Security audit of auth flow completed

## Recommended Future Values
- Access Token: 15-30 minutes
- Session Inactivity: 30-60 minutes
- Token Refresh Buffer: 2-5 minutes before expiry

## Files to Update

### Backend (database/auth.py)
```python
class AuthSettings(BaseModel):
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15  # Increase from 5
    SESSION_INACTIVITY_MINUTES: int = 30   # Increase from 5
```

### Frontend (src/services/api.js)
```javascript
const TOKEN_REFRESH_INTERVAL = 15 * 60 * 1000; // 15 minutes
const SESSION_INACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes
```

### Frontend (src/context/AuthContext.jsx)
```javascript
// Change interval from 30 seconds to 60 seconds
refreshIntervalRef.current = setInterval(async () => {
  // ...
}, 60 * 1000);
```

## Security Considerations
- Keep single-session enforcement enabled
- Maintain refresh token rotation
- Continue validating sessions on each request
- Log session termination events for audit
