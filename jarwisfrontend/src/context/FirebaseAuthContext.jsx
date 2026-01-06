// src/context/FirebaseAuthContext.jsx
import { createContext, useContext, useEffect, useState } from "react";
import {
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signInWithPopup,
  GoogleAuthProvider,
  GithubAuthProvider,
  OAuthProvider, // Add this import for Microsoft
  signOut,
  onAuthStateChanged,
} from "firebase/auth";
import {
  doc,
  getDoc,
  setDoc,
  updateDoc,
  serverTimestamp,
} from "firebase/firestore";
import { auth, db, isFirebaseConfigured } from "../firebase/config";

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

// Helper function to format Firebase errors
const formatFirebaseError = (error) => {
  // If user closes popup, don't show error
  if (error.code === "auth/popup-closed-by-user") {
    return null;
  }

  // Extract error code from error object or message
  let errorCode = error.code || "";

  // If we have the error code directly, use it
  if (errorCode.startsWith("auth/")) {
    errorCode = errorCode.replace("auth/", "");
  } else {
    // Extract from message if needed
    let message = error.message || error.code || "An unknown error occurred";

    // Clean up various Firebase error message formats
    message = message.replace(/^Firebase: Error \(auth\//, "");
    message = message.replace(/^Firebase: Error \(/, "");
    message = message.replace(/^auth\//, "");
    message = message.replace(/\)\.?$/, ""); // Remove closing bracket and optional period
    message = message.replace(/\.$/, ""); // Remove trailing period

    errorCode = message;
  }

  // Format common error codes to user-friendly messages
  const errorMessages = {
    "invalid-credential": "Invalid email or password",
    "user-not-found": "No account found with this email",
    "wrong-password": "Incorrect password",
    "email-already-in-use": "An account with this email already exists",
    "weak-password": "Password should be at least 6 characters",
    "invalid-email": "Please enter a valid email address",
    "user-disabled": "This account has been disabled",
    "too-many-requests": "Too many failed attempts. Please try again later",
    "network-request-failed": "Network error. Please check your connection",
    "popup-blocked": "Popup was blocked. Please allow popups and try again",
    "cancelled-popup-request": "Login was cancelled",
    "popup-closed-by-user": null, // Don't show this error
    "account-exists-with-different-credential":
      "An account already exists with this email using a different sign-in method",
  };

  // Return user-friendly message if available, otherwise return cleaned message
  return errorMessages[errorCode] || errorCode.replace(/-/g, " ").toLowerCase();
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [userDoc, setUserDoc] = useState(null);
  const [loading, setLoading] = useState(true);

  // Helper function to create/update user document
  const createOrUpdateUserDoc = async (firebaseUser, additionalData = {}) => {
    try {
      const userDocRef = doc(db, "users", firebaseUser.uid);
      const userDocSnap = await getDoc(userDocRef);

      if (userDocSnap.exists()) {
        // User document exists, update last login
        const existingData = userDocSnap.data();
        await updateDoc(userDocRef, {
          lastLoginAt: serverTimestamp(),
          ...additionalData,
        });
        return { ...existingData, ...additionalData };
      } else {
        // Create new user document
        const newUserDoc = {
          uid: firebaseUser.uid,
          email: firebaseUser.email,
          displayName:
            firebaseUser.displayName || additionalData.displayName || "",
          photoURL: firebaseUser.photoURL || "",
          role: additionalData.role || "user", // Default role
          isApproved: false, // Default to not approved
          approvalStatus: "pending", // Default status
          createdAt: serverTimestamp(),
          lastLoginAt: serverTimestamp(),
          ...additionalData,
        };

        await setDoc(userDocRef, newUserDoc);
        return newUserDoc;
      }
    } catch (error) {
      console.error("Error creating/updating user document:", error);
      throw error;
    }
  };

  // Email/Password Login
  const loginWithEmail = async (email, password) => {
    if (!isFirebaseConfigured) {
      throw new Error(
        "Firebase is not configured for this environment. Add valid REACT_APP_FIREBASE_* values to your .env."
      );
    }

    try {
      const result = await signInWithEmailAndPassword(auth, email, password);

      // Update user document with last login
      const userDocData = await createOrUpdateUserDoc(result.user, {
        lastLoginAt: serverTimestamp(),
      });

      return {
        user: result.user,
        userDoc: userDocData,
        message: "Login successful!",
      };
    } catch (error) {
      console.error("Email login error:", error);
      const formattedError = formatFirebaseError(error);
      if (formattedError) {
        const customError = new Error(formattedError);
        customError.code = error.code;
        throw customError;
      }
      // If formattedError is null (popup closed), don't throw
      throw new Error("Login was cancelled");
    }
  };

  // Social Provider Login
  const loginWithProvider = async (providerName) => {
    if (!isFirebaseConfigured) {
      throw new Error(
        "Firebase is not configured for this environment. Add valid REACT_APP_FIREBASE_* values to your .env."
      );
    }

    let provider;

    switch (providerName.toLowerCase()) {
      case "google":
        provider = new GoogleAuthProvider();
        provider.addScope("email");
        provider.addScope("profile");
        break;
      case "github":
        provider = new GithubAuthProvider();
        provider.addScope("user:email");
        break;
      case "microsoft":
        // Microsoft OAuth provider setup
        provider = new OAuthProvider("microsoft.com");
        provider.addScope("openid");
        provider.addScope("email");
        provider.addScope("profile");
        // Optional: Set tenant ID if you're using Azure AD B2C
        // provider.setCustomParameters({
        //   tenant: 'your-tenant-id'
        // });
        break;
      default:
        throw new Error(`Unsupported provider: ${providerName}`);
    }

    try {
      const result = await signInWithPopup(auth, provider);

      // Create or update user document
      const userDocData = await createOrUpdateUserDoc(result.user, {
        provider: providerName.toLowerCase(),
        authProvider: providerName.toLowerCase(),
        lastLoginAt: serverTimestamp(),
      });

      return {
        user: result.user,
        userDoc: userDocData,
        message: `Successfully signed in with ${providerName}!`,
      };
    } catch (error) {
      console.error(`${providerName} login error:`, error);

      // Handle popup closed by user - don't show error
      if (error.code === "auth/popup-closed-by-user") {
        return { cancelled: true };
      }

      const formattedError = formatFirebaseError(error);
      if (formattedError) {
        const customError = new Error(formattedError);
        customError.code = error.code;
        throw customError;
      }
      // Fallback for unknown errors
      throw new Error("Login failed. Please try again.");
    }
  };

  // Email/Password Signup
  const registerWithEmail = async (email, password, name, company) => {
    if (!isFirebaseConfigured) {
      throw new Error(
        "Firebase is not configured for this environment. Add valid REACT_APP_FIREBASE_* values to your .env."
      );
    }

    try {
      const result = await createUserWithEmailAndPassword(
        auth,
        email,
        password
      );

      // Create user document with additional data
      const userDocData = await createOrUpdateUserDoc(result.user, {
        displayName: name,
        company: company,
        signupMethod: "email",
        authProvider: "email",
      });

      return {
        user: result.user,
        userDoc: userDocData,
        message: "Account created successfully! Waiting for admin approval.",
      };
    } catch (error) {
      console.error("Email signup error:", error);
      const formattedError = formatFirebaseError(error);
      if (formattedError) {
        const customError = new Error(formattedError);
        customError.code = error.code;
        throw customError;
      }
      throw new Error("Signup failed. Please try again.");
    }
  };

  // Alternative signup method
  const signupWithEmail = async (email, password, additionalData = {}) => {
    if (!isFirebaseConfigured) {
      throw new Error(
        "Firebase is not configured for this environment. Add valid REACT_APP_FIREBASE_* values to your .env."
      );
    }

    try {
      const result = await createUserWithEmailAndPassword(
        auth,
        email,
        password
      );

      // Create user document
      const userDocData = await createOrUpdateUserDoc(result.user, {
        ...additionalData,
        signupMethod: "email",
        authProvider: "email",
      });

      return {
        user: result.user,
        userDoc: userDocData,
        message: "Account created successfully! Waiting for admin approval.",
      };
    } catch (error) {
      console.error("Email signup error:", error);
      const formattedError = formatFirebaseError(error);
      if (formattedError) {
        const customError = new Error(formattedError);
        customError.code = error.code;
        throw customError;
      }
      throw new Error("Signup failed. Please try again.");
    }
  };

  // Logout
  const logout = async () => {
    if (!isFirebaseConfigured) {
      throw new Error(
        "Firebase is not configured for this environment. Add valid REACT_APP_FIREBASE_* values to your .env."
      );
    }

    try {
      await signOut(auth);
      setUser(null);
      setUserDoc(null);
      return { message: "Logged out successfully!" };
    } catch (error) {
      console.error("Logout error:", error);
      throw error;
    }
  };

  // Helper functions for role management
  const getUserRole = () => {
    return userDoc?.role || "user";
  };

  const isAdmin = () => {
    return userDoc?.role === "admin";
  };

  // Check if user is approved
  const isApproved = () => {
    if (!userDoc) return false;
    return userDoc.isApproved === true || userDoc.approvalStatus === "approved";
  };

  // Check if user is rejected
  const isRejected = () => {
    if (!userDoc) return false;
    return userDoc.approvalStatus === "rejected";
  };

  // Check if user is pending approval
  const isPending = () => {
    if (!userDoc) return false;
    return (
      userDoc.approvalStatus === "pending" ||
      (!userDoc.isApproved && !userDoc.approvalStatus)
    );
  };

  // Get user approval status
  const getApprovalStatus = () => {
    if (!userDoc) return "unknown";
    if (isAdmin()) return "admin";
    if (isApproved()) return "approved";
    if (isRejected()) return "rejected";
    return "pending";
  };

  // Get redirect path based on user status
  const getRedirectPath = () => {
    if (!userDoc) return "/login";

    if (isAdmin()) return "/admin";

    // For non-admin users, check approval status
    const status = getApprovalStatus();
    switch (status) {
      case "approved":
        return "/dashboard";
      case "pending":
        return "/pending-approval";
      case "rejected":
        return "/access-denied";
      default:
        return "/pending-approval";
    }
  };

  // Access control function - now checks approval status
  const canAccessApp = () => {
    // Must be authenticated and have a userDoc
    if (!user || !userDoc) {
      return false;
    }

    // Admins can always access
    if (isAdmin()) {
      return true;
    }

    // Check if user account is disabled/suspended
    if (userDoc.status === "disabled" || userDoc.status === "suspended") {
      return false;
    }

    // Regular users must be approved to access the app
    return isApproved();
  };

  // Check if user can access admin routes
  const canAccessAdmin = () => {
    return canAccessApp() && isAdmin();
  };

  // Check if user can access dashboard (approved users only)
  const canAccessDashboard = () => {
    if (!user || !userDoc) return false;
    return isAdmin() || isApproved();
  };

  // Auth state listener
  useEffect(() => {
    if (!isFirebaseConfigured) {
      // If Firebase is not configured, skip auth listeners and leave app in unauthenticated state
      setUser(null);
      setUserDoc(null);
      setLoading(false);
      return () => {};
    }

    const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
      setLoading(true);

      if (firebaseUser) {
        setUser(firebaseUser);

        try {
          // Get or create user document
          const userDocData = await createOrUpdateUserDoc(firebaseUser);
          setUserDoc(userDocData);
        } catch (error) {
          console.error("Error fetching user document:", error);
          // Set default user doc if there's an error
          setUserDoc({
            uid: firebaseUser.uid,
            email: firebaseUser.email,
            displayName: firebaseUser.displayName || "",
            role: "user",
            isApproved: false,
            approvalStatus: "pending",
            createdAt: new Date().toISOString(),
          });
        }
      } else {
        setUser(null);
        setUserDoc(null);
      }

      setLoading(false);
    });

    return unsubscribe;
  }, []);

  const value = {
    // User state
    user,
    userDoc,
    loading,

    // Authentication methods
    loginWithEmail,
    loginWithProvider,
    registerWithEmail,
    signupWithEmail,
    logout,

    // Helper functions
    getUserRole,
    isAdmin,
    isApproved,
    isRejected,
    isPending,
    getApprovalStatus,
    getRedirectPath,

    // Access control functions
    canAccessApp,
    canAccessAdmin,
    canAccessDashboard,

    // Legacy compatibility
    login: loginWithEmail,
    signup: signupWithEmail,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
