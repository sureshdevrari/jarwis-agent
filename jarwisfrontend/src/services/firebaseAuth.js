// src/services/firebaseAuth.js
// Firebase Authentication Service for OTP, Password Reset, and 2FA

import { 
  auth, 
  isFirebaseConfigured,
  sendEmailVerification,
  sendPasswordResetEmail,
  applyActionCode,
  confirmPasswordReset,
  verifyPasswordResetCode
} from "../firebase/config";
import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signOut,
  updateProfile,
  reauthenticateWithCredential,
  EmailAuthProvider,
  RecaptchaVerifier,
  checkActionCode,
  multiFactor,
  PhoneAuthProvider,
  PhoneMultiFactorGenerator,
  getMultiFactorResolver
} from "firebase/auth";

/**
 * Firebase Authentication Service
 * Handles email verification, password reset, and 2FA
 */
class FirebaseAuthService {
  constructor() {
    this.recaptchaVerifier = null;
    this.verificationId = null;
  }

  /**
   * Check if Firebase is available
   */
  isAvailable() {
    return isFirebaseConfigured && auth !== null;
  }

  // ============== Email/Password Authentication ==============

  /**
   * Create a new user with email and password
   * @param {string} email 
   * @param {string} password 
   * @param {string} displayName 
   * @returns {Promise<UserCredential>}
   */
  async createUser(email, password, displayName = "") {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    const userCredential = await createUserWithEmailAndPassword(auth, email, password);
    
    // Update display name if provided
    if (displayName) {
      await updateProfile(userCredential.user, { displayName });
    }

    // Send verification email
    await this.sendVerificationEmail(userCredential.user);

    return userCredential;
  }

  /**
   * Sign in with email and password
   * @param {string} email 
   * @param {string} password 
   * @returns {Promise<UserCredential>}
   */
  async signIn(email, password) {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    try {
      const userCredential = await signInWithEmailAndPassword(auth, email, password);
      return { 
        user: userCredential.user, 
        requiresMfa: false 
      };
    } catch (error) {
      // Check if MFA is required
      if (error.code === 'auth/multi-factor-auth-required') {
        const resolver = getMultiFactorResolver(auth, error);
        return {
          user: null,
          requiresMfa: true,
          resolver,
          hints: resolver.hints
        };
      }
      throw error;
    }
  }

  /**
   * Sign out the current user
   */
  async signOut() {
    if (!this.isAvailable()) return;
    await signOut(auth);
  }

  // ============== Email Verification (OTP) ==============

  /**
   * Send verification email to user
   * @param {User} user - Firebase user object
   * @param {string} redirectUrl - URL to redirect after verification
   */
  async sendVerificationEmail(user = null, redirectUrl = null) {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    const targetUser = user || auth.currentUser;
    if (!targetUser) {
      throw new Error("No user to verify");
    }

    const actionCodeSettings = redirectUrl ? {
      url: redirectUrl,
      handleCodeInApp: true
    } : undefined;

    await sendEmailVerification(targetUser, actionCodeSettings);
    return { success: true, message: "Verification email sent" };
  }

  /**
   * Verify email with action code from email link
   * @param {string} actionCode - Code from email verification link
   */
  async verifyEmail(actionCode) {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    // First check the action code to get the email
    let email = null;
    try {
      const actionCodeInfo = await checkActionCode(auth, actionCode);
      email = actionCodeInfo.data?.email || null;
    } catch (checkError) {
      console.warn("Could not check action code:", checkError);
    }

    // Apply the action code to verify the email
    await applyActionCode(auth, actionCode);
    
    // Fallback to current user email if action code check didn't work
    if (!email && auth.currentUser) {
      email = auth.currentUser.email;
    }
    
    return { success: true, message: "Email verified successfully", email };
  }

  /**
   * Get current user's email
   */
  getCurrentUserEmail() {
    if (!this.isAvailable() || !auth.currentUser) {
      return null;
    }
    return auth.currentUser.email;
  }

  /**
   * Check if current user's email is verified
   */
  async isEmailVerified() {
    if (!this.isAvailable() || !auth.currentUser) {
      return false;
    }

    // Reload user to get latest verification status
    await auth.currentUser.reload();
    return auth.currentUser.emailVerified;
  }

  // ============== Password Reset ==============

  /**
   * Send password reset email
   * @param {string} email 
   * @param {string} redirectUrl - URL to redirect after reset
   */
  async sendPasswordResetEmail(email, redirectUrl = null) {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    const actionCodeSettings = redirectUrl ? {
      url: redirectUrl,
      handleCodeInApp: true
    } : undefined;

    await sendPasswordResetEmail(auth, email, actionCodeSettings);
    return { success: true, message: "Password reset email sent" };
  }

  /**
   * Verify password reset code
   * @param {string} actionCode - Code from reset email
   * @returns {Promise<string>} - Email address associated with the code
   */
  async verifyPasswordResetCode(actionCode) {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    const email = await verifyPasswordResetCode(auth, actionCode);
    return email;
  }

  /**
   * Confirm password reset with new password
   * @param {string} actionCode - Code from reset email
   * @param {string} newPassword - New password
   */
  async confirmPasswordReset(actionCode, newPassword) {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    await confirmPasswordReset(auth, actionCode, newPassword);
    return { success: true, message: "Password reset successfully" };
  }

  // ============== Two-Factor Authentication (2FA) ==============

  /**
   * Initialize reCAPTCHA verifier for phone auth
   * @param {string} containerId - HTML element ID for reCAPTCHA
   */
  initRecaptcha(containerId = 'recaptcha-container') {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    // Clear existing verifier
    if (this.recaptchaVerifier) {
      this.recaptchaVerifier.clear();
    }

    this.recaptchaVerifier = new RecaptchaVerifier(auth, containerId, {
      size: 'invisible',
      callback: () => {
        console.log("reCAPTCHA verified");
      },
      'expired-callback': () => {
        console.log("reCAPTCHA expired");
      }
    });

    return this.recaptchaVerifier;
  }

  /**
   * Enroll phone number for 2FA
   * @param {string} phoneNumber - Phone number with country code (+1234567890)
   * @returns {Promise<string>} - Verification ID
   */
  async enrollPhone2FA(phoneNumber) {
    if (!this.isAvailable() || !auth.currentUser) {
      throw new Error("User not authenticated");
    }

    // Ensure reCAPTCHA is initialized
    if (!this.recaptchaVerifier) {
      this.initRecaptcha();
    }

    // Get multi-factor session
    const multiFactorSession = await multiFactor(auth.currentUser).getSession();

    // Send verification code
    const phoneInfoOptions = {
      phoneNumber,
      session: multiFactorSession
    };

    const phoneAuthProvider = new PhoneAuthProvider(auth);
    this.verificationId = await phoneAuthProvider.verifyPhoneNumber(
      phoneInfoOptions, 
      this.recaptchaVerifier
    );

    return this.verificationId;
  }

  /**
   * Complete phone 2FA enrollment with verification code
   * @param {string} verificationCode - 6-digit code from SMS
   * @param {string} displayName - Friendly name for this 2FA method
   */
  async completePhone2FAEnrollment(verificationCode, displayName = "Phone") {
    if (!this.isAvailable() || !auth.currentUser || !this.verificationId) {
      throw new Error("2FA enrollment not started");
    }

    const phoneAuthCredential = PhoneAuthProvider.credential(
      this.verificationId,
      verificationCode
    );

    const multiFactorAssertion = PhoneMultiFactorGenerator.assertion(phoneAuthCredential);

    await multiFactor(auth.currentUser).enroll(multiFactorAssertion, displayName);
    
    this.verificationId = null;
    return { success: true, message: "2FA enrolled successfully" };
  }

  /**
   * Verify 2FA during sign-in
   * @param {MultiFactorResolver} resolver - MFA resolver from sign-in error
   * @param {number} hintIndex - Index of the hint to use (default: 0)
   * @returns {Promise<string>} - Verification ID
   */
  async start2FAVerification(resolver, hintIndex = 0) {
    if (!this.isAvailable()) {
      throw new Error("Firebase not configured");
    }

    // Ensure reCAPTCHA is initialized
    if (!this.recaptchaVerifier) {
      this.initRecaptcha();
    }

    const hint = resolver.hints[hintIndex];
    
    if (hint.factorId === PhoneMultiFactorGenerator.FACTOR_ID) {
      const phoneInfoOptions = {
        multiFactorHint: hint,
        session: resolver.session
      };

      const phoneAuthProvider = new PhoneAuthProvider(auth);
      this.verificationId = await phoneAuthProvider.verifyPhoneNumber(
        phoneInfoOptions,
        this.recaptchaVerifier
      );

      return this.verificationId;
    }

    throw new Error("Unsupported 2FA method");
  }

  /**
   * Complete 2FA verification during sign-in
   * @param {MultiFactorResolver} resolver - MFA resolver
   * @param {string} verificationCode - 6-digit code
   */
  async complete2FAVerification(resolver, verificationCode) {
    if (!this.verificationId) {
      throw new Error("2FA verification not started");
    }

    const phoneAuthCredential = PhoneAuthProvider.credential(
      this.verificationId,
      verificationCode
    );

    const multiFactorAssertion = PhoneMultiFactorGenerator.assertion(phoneAuthCredential);
    const userCredential = await resolver.resolveSignIn(multiFactorAssertion);

    this.verificationId = null;
    return userCredential;
  }

  /**
   * Get enrolled 2FA methods for current user
   */
  getEnrolled2FAMethods() {
    if (!this.isAvailable() || !auth.currentUser) {
      return [];
    }

    return multiFactor(auth.currentUser).enrolledFactors;
  }

  /**
   * Unenroll a 2FA method
   * @param {MultiFactorInfo} factorInfo - Factor to remove
   */
  async unenroll2FA(factorInfo) {
    if (!this.isAvailable() || !auth.currentUser) {
      throw new Error("User not authenticated");
    }

    await multiFactor(auth.currentUser).unenroll(factorInfo);
    return { success: true, message: "2FA method removed" };
  }

  /**
   * Check if user has 2FA enabled
   */
  has2FAEnabled() {
    return this.getEnrolled2FAMethods().length > 0;
  }

  // ============== Utility Methods ==============

  /**
   * Get current Firebase user
   */
  getCurrentUser() {
    return this.isAvailable() ? auth.currentUser : null;
  }

  /**
   * Reauthenticate user (required before sensitive operations)
   * @param {string} password - Current password
   */
  async reauthenticate(password) {
    if (!this.isAvailable() || !auth.currentUser) {
      throw new Error("User not authenticated");
    }

    const credential = EmailAuthProvider.credential(
      auth.currentUser.email,
      password
    );

    await reauthenticateWithCredential(auth.currentUser, credential);
    return { success: true };
  }

  /**
   * Format Firebase error to user-friendly message
   * @param {Error} error 
   */
  formatError(error) {
    const errorMessages = {
      'auth/email-already-in-use': 'An account with this email already exists',
      'auth/invalid-email': 'Please enter a valid email address',
      'auth/operation-not-allowed': 'This sign-in method is not enabled',
      'auth/weak-password': 'Password should be at least 6 characters',
      'auth/user-disabled': 'This account has been disabled',
      'auth/user-not-found': 'No account found with this email',
      'auth/wrong-password': 'Incorrect password',
      'auth/invalid-credential': 'Invalid email or password',
      'auth/too-many-requests': 'Too many attempts. Please try again later',
      'auth/invalid-action-code': 'This link has expired or already been used',
      'auth/expired-action-code': 'This link has expired. Please request a new one',
      'auth/invalid-verification-code': 'Invalid verification code',
      'auth/missing-verification-code': 'Please enter the verification code',
      'auth/quota-exceeded': 'SMS quota exceeded. Please try again later',
      'auth/multi-factor-auth-required': 'Please complete 2FA verification'
    };

    const code = error.code || '';
    return errorMessages[code] || error.message || 'An unexpected error occurred';
  }
}

// Export singleton instance
export const firebaseAuthService = new FirebaseAuthService();
export default firebaseAuthService;
