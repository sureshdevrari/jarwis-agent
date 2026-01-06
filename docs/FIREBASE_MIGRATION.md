# Firebase to FastAPI + PostgreSQL Migration

## Overview

This document describes the migration from Firebase authentication to FastAPI + PostgreSQL for the JARWIS AGI PEN TEST frontend.

## What Changed

### Backend (FastAPI)

New authentication routes added to `api/routes/`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | Register new user |
| `/api/auth/login` | POST | Login with email/password |
| `/api/auth/refresh` | POST | Refresh access token |
| `/api/auth/logout` | POST | Logout (revoke refresh token) |
| `/api/auth/logout/all` | POST | Logout from all devices |
| `/api/auth/me` | GET | Get current user profile |
| `/api/auth/me` | PUT | Update user profile |
| `/api/auth/change-password` | POST | Change password |

Admin routes added to `api/routes/admin.py`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/admin/dashboard` | GET | Admin dashboard stats |
| `/api/admin/users` | GET | List all users (paginated) |
| `/api/admin/users/{id}` | GET | Get user details |
| `/api/admin/users/{id}` | PUT | Update user |
| `/api/admin/users/{id}/approve` | POST | Approve pending user |
| `/api/admin/users/{id}/reject` | POST | Reject/disable user |
| `/api/admin/users/{id}/reset-status` | POST | Reset to pending |
| `/api/admin/users/{id}` | DELETE | Delete user (super admin only) |
| `/api/admin/users/{id}/make-admin` | POST | Promote to admin |
| `/api/admin/users/{id}/remove-admin` | POST | Demote from admin |

### Frontend

#### New Files

- `src/services/api.js` - Centralized API service with axios, token management, and interceptors
- `src/context/AuthContext.jsx` - New auth context using FastAPI backend
- `src/context/UserManagementContext.jsx` - Admin user management context
- `src/pages/auth/Login.jsx` - New login page
- `src/pages/auth/Signup.jsx` - New signup page

#### Updated Files

All components that previously imported from `FirebaseAuthContext` now import from `AuthContext`:

- `src/App.jsx`
- `src/App.tsx`
- `src/components/Header.jsx`
- `src/components/ProtectedRoute.jsx`
- `src/components/layout/AdminLayout.jsx`
- `src/components/layout/JarwisLayout.jsx`
- `src/context/ContactFormContext.jsx`
- `src/pages/auth/AccessDenied.jsx`
- `src/pages/auth/PendingApproval.jsx`
- `src/pages/admin/AdminAccessRequests.jsx`
- `src/pages/admin/AdminOverview.jsx`
- `src/pages/dashboard/JarwisDashboard.jsx`
- `src/routes/AdminRoute.jsx`
- `src/routes/UserDashboardRoute.jsx`
- `src/routes/router.jsx`

#### Deprecated Files (Can be removed)

- `src/firebase/config.js` - No longer needed
- `src/firebase/firestore.rules` - No longer needed
- `src/context/FirebaseAuthContext.jsx` - Replaced by AuthContext
- `src/context/UserApprovalContext.jsx` - Replaced by UserManagementContext
- `src/pages/auth/FirebaseLogin.jsx` - Replaced by Login.jsx
- `src/pages/auth/FirebaseSignup.jsx` - Replaced by Signup.jsx

## Setup Instructions

### 1. Backend Setup

1. Ensure PostgreSQL is running and configured in `database/config.py`

2. Run database migrations:
   ```bash
   cd database
   alembic upgrade head
   ```

3. Start the FastAPI server:
   ```bash
   uvicorn api.server:app --host 0.0.0.0 --port 5000 --reload
   ```

### 2. Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd jarwisfrontend
   ```

2. Copy the environment file:
   ```bash
   cp .env.example .env.local
   ```

3. Edit `.env.local` and set:
   ```
   REACT_APP_API_URL=http://localhost:5000
   ```

4. Install dependencies:
   ```bash
   npm install
   ```

5. Start the development server:
   ```bash
   npm start
   ```

### 3. Create Admin User

After starting the backend, create an admin user using the API:

```bash
# Register a user
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@example.com",
    "username": "admin",
    "password": "YourSecurePassword123",
    "full_name": "Admin User"
  }'

# Then manually update the user in PostgreSQL to be superuser
psql -d jarwis_db -c "UPDATE users SET is_superuser = true, is_verified = true WHERE email = 'admin@example.com';"
```

## Authentication Flow

1. **Login**: User submits email/password â†’ Backend validates â†’ Returns JWT access + refresh tokens
2. **API Requests**: Frontend includes `Authorization: Bearer <access_token>` header
3. **Token Refresh**: When access token expires (401), interceptor automatically uses refresh token to get new tokens
4. **Logout**: Frontend calls `/api/auth/logout` and clears local storage

## Token Storage

Tokens are stored in localStorage:
- `jarwis_access_token` - Short-lived access token (30 min)
- `jarwis_refresh_token` - Long-lived refresh token (7 days)
- `jarwis_user` - Cached user profile data

## User Status Flow

1. **New User**: `is_verified = false`, `is_active = true` â†’ "pending" status
2. **Approved User**: Admin sets `is_verified = true` â†’ "approved" status
3. **Rejected User**: Admin sets `is_active = false` â†’ "rejected" status
4. **Admin User**: `is_superuser = true` â†’ "admin" status

## Breaking Changes

1. **No Social Login**: Google, GitHub, Microsoft OAuth are not yet implemented. Users must use email/password.

2. **User Model Changes**:
   - `approvalStatus` â†’ `is_verified` (boolean)
   - `isApproved` â†’ `is_verified` (boolean)
   - `role` is now computed from `is_superuser`

3. **Context API Changes**:
   - `useUserApprovals()` â†’ `useUserManagement()`
   - Some function names changed (e.g., `approveRequest` â†’ `approveUser`)

## Security Notes

1. Change the JWT secret key in production (`database/auth.py` â†’ `auth_settings.SECRET_KEY`)
2. Use HTTPS in production
3. Configure proper CORS origins instead of `"*"`
4. Set secure cookie flags in production
