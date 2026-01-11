# 05 - Extension Playbook

## Adding a New Scanner

### Step 1: Create Scanner File

```python
# attacks/web/pre_login/my_new_scanner.py
from dataclasses import dataclass
from typing import List

@dataclass
class ScanResult:
    id: str
    category: str      # OWASP: A01, A02, A03, etc.
    severity: str      # critical, high, medium, low, info
    title: str
    description: str
    url: str
    method: str
    parameter: str = ""
    evidence: str = ""
    poc: str = ""
    reasoning: str = ""

class MyNewScanner:
    def __init__(self, config: dict, context):
        self.config = config
        self.context = context
    
    async def scan(self) -> List[ScanResult]:
        results = []
        for endpoint in self.context.endpoints:
            # Your scanning logic here
            pass
        return results
```

### Step 2: Register Scanner

Edit `attacks/web/pre_login/__init__.py`:

```python
from .my_new_scanner import MyNewScanner

class PreLoginAttacks:
    def __init__(self, config, context):
        self.scanners = [
            # ... existing scanners
            MyNewScanner(config, context),
        ]
```

## Adding a New API Endpoint

### Step 1: Add to Shared Contracts

```python
# shared/api_endpoints.py
class APIEndpoints:
    # ... existing endpoints
    MY_NEW_ENDPOINT = "/api/my-feature"
```

### Step 2: Create Route

```python
# api/routes/my_feature.py
from fastapi import APIRouter

router = APIRouter(prefix="/api/my-feature", tags=["my-feature"])

@router.get("")
async def get_my_feature():
    from services.my_feature_service import get_feature
    return await get_feature()
```

### Step 3: Create Service

```python
# services/my_feature_service.py
async def get_feature():
    # Business logic here
    pass
```

### Step 4: Register Route

```python
# api/routes/__init__.py
from .my_feature import router as my_feature_router

# Add to routers list
```

### Step 5: Regenerate Frontend Types

```bash
python shared/generate_frontend_types.py
```

## Adding a New Frontend Page

### Step 1: Create Page Component

```jsx
// jarwisfrontend/src/pages/dashboard/MyNewPage.jsx
import React from 'react';
import api from '../../services/api';

export default function MyNewPage() {
    return <div>My New Page</div>;
}
```

### Step 2: Add Route

```jsx
// jarwisfrontend/src/App.jsx
import MyNewPage from './pages/dashboard/MyNewPage';

// In routes:
<Route path="/dashboard/my-new-page" element={<MyNewPage />} />
```
