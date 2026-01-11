# 04 - Frontend Integration

## Single API Client

**ALWAYS use `services/api.js`** - never create new API files.

```javascript
// ✅ CORRECT
import api from '../services/api';

// ❌ WRONG - never create new API files
import { customFetch } from './myApi';
```

## Generated Config Files

These files are auto-generated - **DO NOT EDIT MANUALLY**:

- `config/endpoints.generated.js` - API endpoint URLs
- `config/constants.generated.js` - Plan limits, settings
- `config/planLimits.generated.js` - Subscription limits

### Regenerate After Changes

```bash
python shared/generate_frontend_types.py
```

## Component Organization

```
jarwisfrontend/src/
├── components/
│   ├── common/        # Shared components
│   ├── dashboard/     # Dashboard widgets
│   ├── settings/      # Settings panels
│   ├── auth/          # Auth components
│   ├── cloud/         # Cloud components
│   ├── scan/          # Scan components
│   ├── landing/       # Landing page
│   ├── layout/        # Layout components
│   └── ui/            # UI primitives
├── pages/
│   ├── dashboard/     # Main dashboard pages
│   ├── admin/         # Admin pages
│   ├── auth/          # Login, register
│   └── cloud/         # Cloud pages
├── context/           # React contexts
├── services/          # API and services
└── config/            # Configuration
```

## Key Patterns

### Use Contexts
```jsx
import { useAuth } from '../context/AuthContext';
import { useSubscription } from '../context/SubscriptionContext';
```

### Protected Routes
```jsx
import ProtectedRoute from '../components/ProtectedRoute';

<ProtectedRoute>
  <DashboardPage />
</ProtectedRoute>
```
