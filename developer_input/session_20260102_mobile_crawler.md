# Developer Input - Session January 2, 2026

## Request: Mobile App Crawling Like Web Application

### User Request:
> "crawl the complete apk and ipa file after login into the application just like web application visit all pages in the app to prepare attack surface, that should include get and post method and all apis, show all endpoints in report where is vulnerability"

### Requirements Extracted:
1. **Crawl APK/IPA after login** - Similar to web app page discovery
2. **Visit all pages/screens** - Comprehensive app exploration
3. **Prepare attack surface** - Map all potential attack vectors
4. **Capture GET and POST methods** - Track all HTTP methods
5. **Discover all APIs** - Find every API endpoint the app uses
6. **Show endpoints in report** - Display which endpoints have vulnerabilities

### Implementation Completed:
- Created `attacks/mobile/app_crawler.py` - MobileAppCrawler class
- Added Phase 4.5: App Crawling & API Discovery in scan flow
- Updated HTML report to include API Endpoints section
- Updated frontend ScanStatus to show endpoint discovery results
- Correlates vulnerabilities with specific endpoints

### Key Features Implemented:
- Static endpoint extraction from source code
- Retrofit/Alamofire annotation parsing
- Traffic log analysis from MITM proxy
- Auth detection per endpoint
- Vulnerability-to-endpoint mapping
- Risk scoring for each endpoint

---

## Previous Requests This Session:

### 1. Results Summary Not Showing / No HTML Report
- Added `generate_mobile_html_report()` function
- Saves reports to `reports/mobile/` folder
- Includes severity breakdown cards

### 2. Login Failure - Show Reason and Stop Scan
- Added Phase 0.5: Authentication Attempt
- Shows specific error message on login failure
- Stops scan if authentication fails
- Displays hints in frontend for troubleshooting

---

*Saved: January 2, 2026*
