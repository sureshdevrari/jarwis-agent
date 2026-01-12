"""
Jarwis Mobile App Authentication Detector

Analyzes mobile apps to detect authentication methods:
- Username/Password login
- Phone number + OTP authentication
- Social login (Google, Facebook, Apple, Instagram, etc.)
- Biometric authentication
- Token-based authentication
"""

import re
import os
import zipfile
import plistlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum


class AuthType(Enum):
    """Authentication types supported by Jarwis"""
    USERNAME_PASSWORD = "username_password"
    EMAIL_PASSWORD = "email_password"
    PHONE_OTP = "phone_otp"
    GOOGLE_SIGNIN = "google_signin"
    FACEBOOK_LOGIN = "facebook_login"
    APPLE_SIGNIN = "apple_signin"
    INSTAGRAM_LOGIN = "instagram_login"
    TWITTER_LOGIN = "twitter_login"
    GITHUB_LOGIN = "github_login"
    BIOMETRIC = "biometric"
    TOKEN_BASED = "token_based"
    MAGIC_LINK = "magic_link"
    UNKNOWN = "unknown"


@dataclass
class AuthMethod:
    """Detected authentication method"""
    auth_type: AuthType
    confidence: float  # 0.0 to 1.0
    evidence: List[str] = field(default_factory=list)
    ui_elements: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)
    sdk_detected: Optional[str] = None


@dataclass
class AuthDetectionResult:
    """Result of authentication detection"""
    primary_auth: Optional[AuthMethod] = None
    secondary_auth: List[AuthMethod] = field(default_factory=list)
    all_methods: List[AuthMethod] = field(default_factory=list)
    requires_otp: bool = False
    requires_social: bool = False
    app_package: str = ""
    platform: str = ""  # android or ios


class MobileAuthDetector:
    """
    Detects authentication methods used in mobile applications
    by analyzing app resources, code, and configurations.
    """
    
    # Android patterns for auth detection
    ANDROID_AUTH_PATTERNS = {
        AuthType.PHONE_OTP: [
            r'com\.google\.android\.gms\.auth\.api\.phone',
            r'SmsRetriever',
            r'OTPAutoFill',
            r'sendOtp|verifyOtp|requestOtp',
            r'PhoneAuthProvider',
            r'sms[_-]?verification',
            r'mobile[_-]?otp',
            r'otp[_-]?verification',
            r'"phone".*"otp"',
            r'android:inputType="phone"',
            r'<EditText[^>]*phone',
            r'otpView|pinView|OtpEditText',
        ],
        AuthType.GOOGLE_SIGNIN: [
            r'com\.google\.android\.gms\.auth\.api\.signin',
            r'GoogleSignIn',
            r'GoogleApiClient',
            r'com\.google\.android\.gms\.auth',
            r'googleapis\.com/oauth',
            r'accounts\.google\.com',
        ],
        AuthType.FACEBOOK_LOGIN: [
            r'com\.facebook\.login',
            r'com\.facebook\.FacebookSdk',
            r'LoginManager',
            r'facebook-android-sdk',
            r'graph\.facebook\.com',
            r'fb_login_protocol_scheme',
        ],
        AuthType.APPLE_SIGNIN: [
            r'com\.apple\.signin',
            r'SignInWithApple',
            r'appleid\.apple\.com',
        ],
        AuthType.INSTAGRAM_LOGIN: [
            r'com\.instagram',
            r'instagram\.com/oauth',
            r'api\.instagram\.com',
        ],
        AuthType.TWITTER_LOGIN: [
            r'com\.twitter\.sdk',
            r'twitter4j',
            r'api\.twitter\.com',
        ],
        AuthType.GITHUB_LOGIN: [
            r'github\.com/login/oauth',
            r'api\.github\.com',
        ],
        AuthType.USERNAME_PASSWORD: [
            r'android:inputType="textPassword"',
            r'android:inputType="textVisiblePassword"',
            r'PasswordField|passwordInput',
            r'login[_-]?password',
            r'"username".*"password"',
        ],
        AuthType.EMAIL_PASSWORD: [
            r'android:inputType="textEmailAddress"',
            r'emailField|emailInput',
            r'"email".*"password"',
        ],
        AuthType.BIOMETRIC: [
            r'BiometricPrompt',
            r'FingerprintManager',
            r'android\.hardware\.fingerprint',
            r'androidx\.biometric',
        ],
        AuthType.MAGIC_LINK: [
            r'magic[_-]?link',
            r'passwordless',
            r'email[_-]?link[_-]?signin',
        ],
    }
    
    # iOS patterns for auth detection
    IOS_AUTH_PATTERNS = {
        AuthType.PHONE_OTP: [
            r'ASAuthorizationSecurityKeyPublicKeyCredentialProvider',
            r'UITextContentType.*oneTimeCode',
            r'sendOtp|verifyOtp|requestOtp',
            r'SMSVerification',
            r'PhoneAuth',
            r'otp[_-]?verification',
            r'mobile[_-]?otp',
        ],
        AuthType.GOOGLE_SIGNIN: [
            r'GIDSignIn',
            r'GoogleSignIn\.framework',
            r'com\.google\.GIDSignIn',
            r'accounts\.google\.com',
        ],
        AuthType.FACEBOOK_LOGIN: [
            r'FBSDKLoginKit',
            r'FBSDKCoreKit',
            r'FBLoginButton',
            r'graph\.facebook\.com',
        ],
        AuthType.APPLE_SIGNIN: [
            r'ASAuthorizationAppleIDProvider',
            r'ASAuthorizationController',
            r'SignInWithApple',
            r'com\.apple\.developer\.applesignin',
        ],
        AuthType.INSTAGRAM_LOGIN: [
            r'InstagramKit',
            r'instagram\.com/oauth',
        ],
        AuthType.TWITTER_LOGIN: [
            r'TwitterKit',
            r'api\.twitter\.com',
        ],
        AuthType.BIOMETRIC: [
            r'LAContext',
            r'LocalAuthentication\.framework',
            r'biometricType',
            r'canEvaluatePolicy',
            r'TouchID|FaceID',
        ],
        AuthType.USERNAME_PASSWORD: [
            r'UITextContentType.*password',
            r'isSecureTextEntry',
            r'passwordField|passwordInput',
        ],
        AuthType.EMAIL_PASSWORD: [
            r'UITextContentType.*emailAddress',
            r'keyboardType.*emailAddress',
        ],
    }
    
    # UI element indicators
    UI_INDICATORS = {
        AuthType.PHONE_OTP: [
            'enter_mobile', 'phone_number', 'mobile_input', 'otp_input',
            'verification_code', 'enter_otp', 'resend_otp', 'verify_button',
            'get_otp', 'send_otp', 'otp_timer', 'verify_mobile',
        ],
        AuthType.GOOGLE_SIGNIN: [
            'google_sign_in', 'sign_in_google', 'google_button', 'btn_google',
            'ic_google', 'google_logo',
        ],
        AuthType.FACEBOOK_LOGIN: [
            'facebook_login', 'fb_login', 'sign_in_facebook', 'btn_facebook',
            'ic_facebook', 'fb_logo',
        ],
        AuthType.APPLE_SIGNIN: [
            'apple_signin', 'sign_in_apple', 'btn_apple', 'apple_button',
        ],
        AuthType.USERNAME_PASSWORD: [
            'username_input', 'password_input', 'login_button', 'sign_in',
            'txt_username', 'txt_password', 'et_username', 'et_password',
        ],
    }
    
    # API endpoint patterns
    API_PATTERNS = {
        AuthType.PHONE_OTP: [
            r'/api/v\d*/send[_-]?otp',
            r'/api/v\d*/verify[_-]?otp',
            r'/api/v\d*/phone[_-]?auth',
            r'/auth/phone',
            r'/otp/send',
            r'/otp/verify',
            r'/mobile/verify',
        ],
        AuthType.GOOGLE_SIGNIN: [
            r'/auth/google',
            r'/oauth/google',
            r'/social/google',
        ],
        AuthType.FACEBOOK_LOGIN: [
            r'/auth/facebook',
            r'/oauth/facebook',
            r'/social/facebook',
        ],
        AuthType.USERNAME_PASSWORD: [
            r'/api/v\d*/login',
            r'/auth/login',
            r'/user/login',
            r'/signin',
        ],
    }

    def __init__(self, app_path: str):
        """Initialize with path to APK or IPA file"""
        self.app_path = app_path
        self.platform = self._detect_platform()
        self.extracted_content: Dict[str, str] = {}
        self.detected_methods: List[AuthMethod] = []
        
    def _detect_platform(self) -> str:
        """Detect if app is Android or iOS"""
        if self.app_path.lower().endswith('.apk'):
            return 'android'
        elif self.app_path.lower().endswith('.ipa'):
            return 'ios'
        return 'unknown'
    
    async def detect_auth_methods(self) -> AuthDetectionResult:
        """
        Main method to detect all authentication methods in the app.
        Returns AuthDetectionResult with detected methods.
        """
        result = AuthDetectionResult(
            platform=self.platform,
            app_package=self._get_package_name()
        )
        
        # Extract and analyze app content
        await self._extract_app_content()
        
        # Run detection for each auth type
        if self.platform == 'android':
            await self._detect_android_auth()
        elif self.platform == 'ios':
            await self._detect_ios_auth()
        
        # Analyze UI resources
        await self._analyze_ui_resources()
        
        # Analyze API endpoints in code
        await self._analyze_api_endpoints()
        
        # Sort by confidence and set primary/secondary
        self.detected_methods.sort(key=lambda x: x.confidence, reverse=True)
        
        if self.detected_methods:
            result.primary_auth = self.detected_methods[0]
            result.secondary_auth = self.detected_methods[1:4]  # Top 3 secondary
            result.all_methods = self.detected_methods
            
            # Check if OTP or social login required
            result.requires_otp = any(
                m.auth_type == AuthType.PHONE_OTP 
                for m in self.detected_methods 
                if m.confidence > 0.5
            )
            result.requires_social = any(
                m.auth_type in [
                    AuthType.GOOGLE_SIGNIN, 
                    AuthType.FACEBOOK_LOGIN,
                    AuthType.APPLE_SIGNIN,
                    AuthType.INSTAGRAM_LOGIN
                ]
                for m in self.detected_methods 
                if m.confidence > 0.5
            )
        
        return result
    
    def _get_package_name(self) -> str:
        """Get app package/bundle name"""
        try:
            if self.platform == 'android':
                with zipfile.ZipFile(self.app_path, 'r') as zf:
                    # Try to read from AndroidManifest
                    if 'AndroidManifest.xml' in zf.namelist():
                        return "android.app"  # Would need aapt to decode
            elif self.platform == 'ios':
                with zipfile.ZipFile(self.app_path, 'r') as zf:
                    for name in zf.namelist():
                        if 'Info.plist' in name and name.endswith('Info.plist'):
                            return "ios.app"
        except:
            pass
        return "unknown.app"
    
    async def _extract_app_content(self):
        """Extract relevant content from app for analysis"""
        try:
            with zipfile.ZipFile(self.app_path, 'r') as zf:
                for file_info in zf.filelist:
                    name = file_info.filename.lower()
                    
                    # Extract text-based files for analysis
                    if any(ext in name for ext in ['.xml', '.json', '.plist', '.strings', '.js']):
                        try:
                            content = zf.read(file_info.filename)
                            # Try to decode as text
                            try:
                                self.extracted_content[file_info.filename] = content.decode('utf-8')
                            except:
                                self.extracted_content[file_info.filename] = content.decode('latin-1')
                        except:
                            pass
                    
                    # Also analyze resource file names
                    self.extracted_content[f"_filename_{file_info.filename}"] = file_info.filename
                    
        except Exception as e:
            print(f"Error extracting app: {e}")
    
    async def _detect_android_auth(self):
        """Detect authentication methods in Android app"""
        all_content = '\n'.join(self.extracted_content.values())
        
        for auth_type, patterns in self.ANDROID_AUTH_PATTERNS.items():
            evidence = []
            for pattern in patterns:
                matches = re.findall(pattern, all_content, re.IGNORECASE)
                if matches:
                    evidence.extend(matches[:3])  # Limit evidence
            
            if evidence:
                confidence = min(len(evidence) / 5, 1.0)  # More matches = higher confidence
                self.detected_methods.append(AuthMethod(
                    auth_type=auth_type,
                    confidence=confidence,
                    evidence=list(set(evidence))[:5]
                ))
    
    async def _detect_ios_auth(self):
        """Detect authentication methods in iOS app"""
        all_content = '\n'.join(self.extracted_content.values())
        
        for auth_type, patterns in self.IOS_AUTH_PATTERNS.items():
            evidence = []
            for pattern in patterns:
                matches = re.findall(pattern, all_content, re.IGNORECASE)
                if matches:
                    evidence.extend(matches[:3])
            
            if evidence:
                confidence = min(len(evidence) / 5, 1.0)
                self.detected_methods.append(AuthMethod(
                    auth_type=auth_type,
                    confidence=confidence,
                    evidence=list(set(evidence))[:5]
                ))
    
    async def _analyze_ui_resources(self):
        """Analyze UI resource names for auth indicators"""
        filenames = [
            v for k, v in self.extracted_content.items() 
            if k.startswith('_filename_')
        ]
        all_filenames = ' '.join(filenames).lower()
        
        for auth_type, indicators in self.UI_INDICATORS.items():
            found_indicators = []
            for indicator in indicators:
                if indicator.lower() in all_filenames:
                    found_indicators.append(indicator)
            
            if found_indicators:
                # Update existing or add new
                existing = next(
                    (m for m in self.detected_methods if m.auth_type == auth_type), 
                    None
                )
                if existing:
                    existing.ui_elements.extend(found_indicators)
                    existing.confidence = min(existing.confidence + 0.2, 1.0)
                else:
                    self.detected_methods.append(AuthMethod(
                        auth_type=auth_type,
                        confidence=0.3,
                        ui_elements=found_indicators
                    ))
    
    async def _analyze_api_endpoints(self):
        """Analyze code for API endpoint patterns"""
        all_content = '\n'.join(self.extracted_content.values())
        
        for auth_type, patterns in self.API_PATTERNS.items():
            found_endpoints = []
            for pattern in patterns:
                matches = re.findall(pattern, all_content, re.IGNORECASE)
                if matches:
                    found_endpoints.extend(matches)
            
            if found_endpoints:
                existing = next(
                    (m for m in self.detected_methods if m.auth_type == auth_type),
                    None
                )
                if existing:
                    existing.api_endpoints.extend(found_endpoints)
                    existing.confidence = min(existing.confidence + 0.3, 1.0)
                else:
                    self.detected_methods.append(AuthMethod(
                        auth_type=auth_type,
                        confidence=0.4,
                        api_endpoints=found_endpoints
                    ))
    
    def get_auth_summary(self) -> Dict:
        """Get a summary of detected authentication methods"""
        return {
            'platform': self.platform,
            'primary_auth': self.detected_methods[0].auth_type.value if self.detected_methods else None,
            'all_methods': [
                {
                    'type': m.auth_type.value,
                    'confidence': round(m.confidence, 2),
                    'evidence_count': len(m.evidence) + len(m.ui_elements) + len(m.api_endpoints)
                }
                for m in self.detected_methods
            ],
            'requires_otp': any(m.auth_type == AuthType.PHONE_OTP for m in self.detected_methods),
            'has_social_login': any(
                m.auth_type in [AuthType.GOOGLE_SIGNIN, AuthType.FACEBOOK_LOGIN, AuthType.APPLE_SIGNIN]
                for m in self.detected_methods
            )
        }


def create_auth_detector(app_path: str) -> MobileAuthDetector:
    """Factory function to create auth detector"""
    return MobileAuthDetector(app_path)
