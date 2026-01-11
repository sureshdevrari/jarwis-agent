// src/firebase/config.js
// Firebase configuration for Jarwis - Email OTP, Password Reset, and 2FA

import { initializeApp, getApps } from "firebase/app";
import { 
  getAuth, 
  GoogleAuthProvider, 
  GithubAuthProvider, 
  OAuthProvider,
  sendEmailVerification,
  sendPasswordResetEmail,
  applyActionCode,
  confirmPasswordReset,
  verifyPasswordResetCode,
  multiFactor,
  PhoneAuthProvider,
  PhoneMultiFactorGenerator
} from "firebase/auth";
import { getFirestore } from "firebase/firestore";
import { getAnalytics, isSupported } from "firebase/analytics";

// Firebase configuration from environment variables
const firebaseConfig = {
  apiKey: process.env.REACT_APP_FIREBASE_API_KEY,
  authDomain: process.env.REACT_APP_FIREBASE_AUTH_DOMAIN,
  projectId: process.env.REACT_APP_FIREBASE_PROJECT_ID,
  storageBucket: process.env.REACT_APP_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.REACT_APP_FIREBASE_MESSAGING_SENDER_ID,
  appId: process.env.REACT_APP_FIREBASE_APP_ID,
  measurementId: process.env.REACT_APP_FIREBASE_MEASUREMENT_ID
};

// Check if Firebase is properly configured (not just placeholder/dummy values)
const isDummyValue = (val) => {
  if (!val) return true;
  const lowerVal = val.toLowerCase();
  return lowerVal.includes('dummy') || 
         lowerVal.includes('placeholder') || 
         lowerVal.includes('your_') ||
         lowerVal.includes('xxx') ||
         lowerVal === 'undefined' ||
         lowerVal.startsWith('your-');
};

export const isFirebaseConfigured = Boolean(
  firebaseConfig.apiKey && 
  firebaseConfig.authDomain && 
  firebaseConfig.projectId &&
  !isDummyValue(firebaseConfig.apiKey) &&
  !isDummyValue(firebaseConfig.authDomain) &&
  !isDummyValue(firebaseConfig.projectId)
);

// Initialize Firebase only if configured
let app = null;
let auth = null;
let db = null;
let analytics = null;

if (isFirebaseConfigured) {
  // Initialize Firebase app (singleton pattern)
  app = getApps().length === 0 ? initializeApp(firebaseConfig) : getApps()[0];
  
  // Initialize services
  auth = getAuth(app);
  db = getFirestore(app);
  
  // Initialize analytics only in browser and if supported
  if (typeof window !== 'undefined') {
    isSupported().then((supported) => {
      if (supported) {
        analytics = getAnalytics(app);
      }
    }).catch(() => {
      console.log("Analytics not supported in this environment");
    });
  }
  
  console.log("[OK] Firebase initialized successfully");
} else {
  console.warn("[!] Firebase not configured - check environment variables");
}

// Auth providers
const googleProvider = isFirebaseConfigured ? new GoogleAuthProvider() : null;
const githubProvider = isFirebaseConfigured ? new GithubAuthProvider() : null;
const microsoftProvider = isFirebaseConfigured ? new OAuthProvider('microsoft.com') : null;

// Configure Google provider
if (googleProvider) {
  googleProvider.setCustomParameters({
    prompt: 'select_account'
  });
}

// Configure Microsoft provider
if (microsoftProvider) {
  microsoftProvider.setCustomParameters({
    prompt: 'select_account',
    tenant: 'common'
  });
}

// Export Firebase services
export { 
  app, 
  auth, 
  db, 
  analytics,
  googleProvider, 
  githubProvider, 
  microsoftProvider,
  // Firebase Auth functions for OTP/2FA
  sendEmailVerification,
  sendPasswordResetEmail,
  applyActionCode,
  confirmPasswordReset,
  verifyPasswordResetCode,
  multiFactor,
  PhoneAuthProvider,
  PhoneMultiFactorGenerator
};

export default app;
