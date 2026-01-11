# Session 2026-01-04 - UI/UX Improvements

## Developer Input Log

### Request 1: Header & Theme Fixes
**Issue:** 
- "Jarwis AGI Security Platform" text showing in upper right header should be removed
- Jarwis logo should be on the left on all pages
- Font colors not visible properly in dark/light mode themes

**Resolution:**
- Removed duplicate branding from sidebar in JarwisLayout.jsx and AdminLayout.jsx
- Added logo to header (left side) on all pages
- Fixed color visibility with proper contrast for both themes:
  - Navigation buttons: `text-gray-300` (dark) / `text-gray-700` (light)
  - Search inputs: `text-white` (dark) / `text-gray-900` (light)
  - Footers: `text-gray-400` (dark) / `text-gray-600` (light)
- Updated ScanQuotaDisplay and SubscriptionBadge components for theme awareness

---

### Request 2: Highlighted Function Cards
**Issue:**
- Main dev containers that contain functions should be highlighted with bold borders to look more beautiful

**Resolution:**
- Added new CSS classes in `index.css`:
  - `.function-card-dark` - Cyan-blue border glow for dark mode
  - `.function-card-light` - Blue border with shadow for light mode
- Applied to:
  - JarwisDashboard.jsx: Quick Actions, System Status, Recent Scans
  - NewScan.jsx: Web/Mobile/Cloud scan forms, Security & Privacy section
  - JarwisChatbot.jsx: Main chat container

---

### Request 3: Jarwis AGI Chatbot Access Control
**Issue:**
- Individual user doesn't have access to Jarwis AGI chatbot
- Need to show upgrade prompt

**Resolution:**
- Added `UpgradeRequired` component in JarwisChatbot.jsx
- Checks `hasFeatureAccess("chatbotAccess")` from subscription context
- Individual/Free users see:
  - Lock icon with professional styling
  - Feature list (vulnerability analysis, code remediation, etc.)
  - "Upgrade Now" button Ã¢â€ â€™ links to /pricing
  - Available on Professional & Enterprise plans only

---

### Request 4: Subscription Limits Clarification
**Issue:**
- User concerned about "5 scans remaining" for individual user
- Question about offering only 1 website to test

**Resolution:**
- Verified planLimits.js configuration is correct:
  - **Individual Plan**: `maxWebsitesPerMonth: 1`, `maxScansPerMonth: 5`
  - Meaning: 1 website can be scanned up to 5 times per month
- Sidebar already displays both limits separately:
  - "Scans" remaining (5 for individual)
  - "Websites" remaining (1 for individual)

---

## Files Modified
- `jarwisfrontend/src/components/layout/JarwisLayout.jsx`
- `jarwisfrontend/src/components/layout/AdminLayout.jsx`
- `jarwisfrontend/src/pages/dashboard/JarwisDashboard.jsx`
- `jarwisfrontend/src/pages/dashboard/JarwisChatbot.jsx`
- `jarwisfrontend/src/pages/dashboard/NewScan.jsx`
- `jarwisfrontend/src/index.css`

## Config Verified (No Changes Needed)
- `jarwisfrontend/src/config/planLimits.js` - Limits already correctly set
