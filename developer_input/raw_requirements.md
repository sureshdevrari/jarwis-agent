# Mobile App Authentication Requirements
## Raw Developer Input - Session January 2, 2026

---

### Input #1 - Mobile Testing Features

**Exact Input:**
```
also ask user to provide email username or password in order to login into the app, because 99% apps required login at first stage before interacting with applicaton, if there is otp requesed we can push a notification to user for entering the otp or diable otp authentication wjile testing the app, we will use same mitm proxy type testing with out owasp top strategy using llm and everything we use in web app testing, also add attacks specifically realted to andoid and ios app that is trending in the market, un packing the application should be there to find any exposed key and implement everything i explained
```

**Parsed Requirements:**

1. **User Authentication Input**
   - Ask for email
   - Ask for username  
   - Ask for password
   - Reason: 99% of apps require login first

2. **OTP Handling**
   - Push notification to user to enter OTP
   - OR disable OTP during testing

3. **Testing Approach**
   - Same MITM proxy as web testing
   - OWASP Top 10 strategy
   - LLM integration
   - Everything from web app testing

4. **Platform-Specific Attacks**
   - Android trending attacks
   - iOS trending attacks

5. **App Analysis**
   - Unpacking application
   - Find exposed keys/secrets

---

### Input #2 - OTP Authentication System

**Exact Input:**
```
now what i want is, most of the mobile app android and ios, has authentication method as mobile number with otp authentications, i want to ask user what is the authentication type, wether directly username and password, or sign in with google and insta or any other, or if the application has option to give number and otp to authenticate, now we have to use certain identifier to look into the app what kind of input is provided by the user and according we will authenticate, for mobile number authenticate i have written the ways to implement it, please check "otp_logic" folder in this prpject and implement everything i told you here
```

**Parsed Requirements:**

1. **Authentication Type Detection**
   - Most apps use mobile number + OTP
   - Need to ask user OR auto-detect auth type

2. **Supported Auth Types**
   - Username + Password
   - Sign in with Google
   - Sign in with Instagram
   - Other social providers
   - Mobile number + OTP

3. **Auto-Detection**
   - Use identifiers to look into the app
   - Detect what kind of input is provided
   - Authenticate accordingly

4. **OTP Logic Reference**
   - Check `otp_logic` folder
   - Implement according to that document

---

### Input #3 - Save Inputs

**Exact Input:**
```
whatever the input i have given just save all my input in this session in a folder name as devloper_input so we can recheck everything even later
```

---

## Referenced Documents

### otp_logic/Jarwis_OTP_Authentication_Guide.docx

**Key Points:**

1. **Purpose**: Define secure OTP handling for mobile app testing

2. **Security Rules (NEVER do)**:
   - Read user SMS automatically
   - Store OTPs
   - Reuse OTPs
   - Intercept private communication

3. **User Flow**:
   1. User clicks "Start Testing"
   2. Jarwis detects OTP-based auth
   3. System displays OTP input screen
   4. User manually enters OTP
   5. Jarwis sends to customer backend
   6. Backend returns access token
   7. Security testing begins

4. **Frontend UI Requirements**:
   - Title: "Secure Authentication Required"
   - Message explaining OTP is never stored
   - Security notice with lock icon
   - "Verify & Start Testing" button

5. **Technical Flow**:
   - Frontend → Customer Backend (OTP)
   - Customer Backend → Returns Token
   - Jarwis uses token for testing only

6. **Security Rules**:
   - OTP expires within 60 seconds
   - OTP is single-use
   - Tokens are short-lived
   - Never log OTP
   - Never store OTP
   - Never reuse OTP

7. **What Jarwis Does NOT Do**:
   - Read SMS
   - Access personal data
   - Store credentials
   - Impersonate identity

8. **Disclaimer Text**:
   "Jarwis does not store, log, or reuse your OTP. The OTP is used only once to authenticate and begin security testing. Your privacy and data security are our top priority."

9. **Best Practices**:
   - Use test accounts for production
   - Token-based auth preferred
   - Auth bypass endpoints (IP whitelisted)
   - Manual OTP only when required
