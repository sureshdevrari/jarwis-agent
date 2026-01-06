// src/context/AuthContext.jsx
// Authentication context using FastAPI + PostgreSQL backend
// Replaces FirebaseAuthContext.jsx

import { createContext, useContext, useEffect, useState, useCallback, useRef } from "react";
import { 
  authAPI, 
  getAccessToken, 
  getStoredUser, 
  clearAuth,
  setStoredUser,
  autoRefreshToken,
  shouldRefreshToken,
  isSessionInactive,
  updateLastActivity
} from "../services/api";
import SessionTimeoutModal from "../components/auth/SessionTimeoutModal";

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
};

// Helper function to format API errors
const formatAPIError = (error) => {
  if (error.response?.data?.detail) {
    return error.response.data.detail;
  }
  if (error.response?.data?.message) {
    return error.response.data.message;
  }
  if (error.message) {
    return error.message;
  }
  return "An unexpected error occurred";
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [userDoc, setUserDoc] = useState(null); // Compatibility with FirebaseAuthContext
  const [loading, setLoading] = useState(true);
  const [sessionExpired, setSessionExpired] = useState(false);
  const [showTimeoutModal, setShowTimeoutModal] = useState(false);
  const [timeoutReason, setTimeoutReason] = useState("inactive");
  const refreshIntervalRef = useRef(null);

  // Handle session timeout - show modal with blur effect
  const handleSessionTimeout = useCallback((reason = "inactive") => {
    console.log(`Session timeout: ${reason}`);
    clearAuth();
    setUser(null);
    setUserDoc(null);
    setSessionExpired(true);
    setTimeoutReason(reason);
    setShowTimeoutModal(true);
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
      refreshIntervalRef.current = null;
    }
  }, []);

  // Auto-refresh token every 3 minutes (before 5-minute expiry)
  // Check for inactivity every 30 seconds for quick session termination
  const startTokenRefreshInterval = useCallback(() => {
    if (refreshIntervalRef.current) {
      clearInterval(refreshIntervalRef.current);
    }
    
    refreshIntervalRef.current = setInterval(async () => {
      // Check for inactivity (timeout based on config)
      if (isSessionInactive()) {
        handleSessionTimeout("inactive");
        return;
      }
      
      // Refresh token if needed (before expiry)
      if (shouldRefreshToken()) {
        try {
          await autoRefreshToken();
          console.log("Token refreshed successfully");
        } catch (error) {
          console.error("Token refresh failed:", error);
          handleSessionTimeout("session_expired");
        }
      }
    }, 30 * 1000); // Check every 30 seconds for quick session termination
  }, [handleSessionTimeout]);

  // Track user activity - only meaningful interactions, NOT mouse movement
  // Mouse movement is too aggressive and prevents proper inactivity detection
  useEffect(() => {
    const handleActivity = () => {
      if (user) {
        updateLastActivity();
      }
    };
    
    // Only track meaningful user activities (not mouse movement)
    window.addEventListener('click', handleActivity);
    window.addEventListener('keydown', handleActivity);
    window.addEventListener('scroll', handleActivity);
    // Removed: mousemove - too aggressive, keeps resetting timer constantly
    
    return () => {
      window.removeEventListener('click', handleActivity);
      window.removeEventListener('keydown', handleActivity);
      window.removeEventListener('scroll', handleActivity);
    };
  }, [user]);

  // Load user from storage on mount
  useEffect(() => {
    const initAuth = async () => {
      try {
        const token = getAccessToken();
        const storedUser = getStoredUser();

        if (token && storedUser) {
          // Check for session inactivity
          if (isSessionInactive()) {
            console.warn("Session inactive on load, clearing auth");
            clearAuth();
            setUser(null);
            setUserDoc(null);
            setLoading(false);
            return;
          }
          
          // Verify token is still valid by fetching profile
          try {
            const profile = await authAPI.getProfile();
            setUser(profile);
            setUserDoc(profile);
            startTokenRefreshInterval();
          } catch (error) {
            // Token expired or invalid
            console.warn("Token validation failed:", error);
            clearAuth();
            setUser(null);
            setUserDoc(null);
          }
        } else {
          setUser(null);
          setUserDoc(null);
        }
      } catch (error) {
        console.error("Auth initialization error:", error);
        clearAuth();
        setUser(null);
        setUserDoc(null);
      } finally {
        setLoading(false);
      }
    };

    initAuth();
    
    // Cleanup interval on unmount
    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [startTokenRefreshInterval]);

  // Email/Password Login
  const loginWithEmail = useCallback(async (email, password) => {
    try {
      const result = await authAPI.login(email, password);
      
      // Get full profile after login
      const profile = await authAPI.getProfile();
      setUser(profile);
      setUserDoc(profile);
      setSessionExpired(false);
      
      // Start token refresh interval
      startTokenRefreshInterval();

      return {
        user: profile,
        userDoc: profile,
        message: "Login successful!",
      };
    } catch (error) {
      console.error("Email login error:", error);
      const errorMessage = formatAPIError(error);
      throw new Error(errorMessage);
    }
  }, [startTokenRefreshInterval]);

  // Social Provider Login (placeholder - can be implemented with OAuth later)
  const loginWithProvider = useCallback(async (providerName) => {
    // For now, social login is not supported with PostgreSQL backend
    // This can be implemented later with OAuth2 flows
    throw new Error(
      `${providerName} login is not yet available. Please use email/password login.`
    );
  }, []);

  // Email/Password Signup
  const registerWithEmail = useCallback(async (email, password, name, company) => {
    try {
      const result = await authAPI.register({
        email,
        password,
        name,
        username: email.split('@')[0], // Generate username from email
        company,
      });

      return {
        message: result.message || "Account created successfully! Waiting for admin approval.",
      };
    } catch (error) {
      console.error("Email signup error:", error);
      const errorMessage = formatAPIError(error);
      throw new Error(errorMessage);
    }
  }, []);

  // Alternative signup method (for compatibility)
  const signupWithEmail = useCallback(async (email, password, additionalData = {}) => {
    return registerWithEmail(
      email,
      password,
      additionalData.displayName || additionalData.name,
      additionalData.company
    );
  }, [registerWithEmail]);

  // Logout
  const logout = useCallback(async () => {
    try {
      await authAPI.logout();
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      // Clear refresh interval
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
        refreshIntervalRef.current = null;
      }
      setUser(null);
      setUserDoc(null);
      setSessionExpired(false);
      clearAuth();
    }
    return { message: "Logged out successfully!" };
  }, []);

  // Refresh user profile
  const refreshProfile = useCallback(async () => {
    try {
      const profile = await authAPI.getProfile();
      setUser(profile);
      setUserDoc(profile);
      setStoredUser(profile);
      return profile;
    } catch (error) {
      console.error("Profile refresh error:", error);
      throw error;
    }
  }, []);

  // Helper functions for role management
  const getUserRole = useCallback(() => {
    return userDoc?.role || "user";
  }, [userDoc]);

  const isAdmin = useCallback(() => {
    return userDoc?.role === "super_admin" || userDoc?.is_superuser === true;
  }, [userDoc]);

  const isSuperAdmin = useCallback(() => {
    return userDoc?.role === "super_admin" || userDoc?.is_superuser === true;
  }, [userDoc]);

  // Check if user is approved (verified)
  const isApproved = useCallback(() => {
    if (!userDoc) return false;
    return userDoc.is_verified === true || userDoc.approval_status === "approved";
  }, [userDoc]);

  // Check if user is rejected (disabled)
  const isRejected = useCallback(() => {
    if (!userDoc) return false;
    return userDoc.is_active === false || userDoc.approval_status === "disabled";
  }, [userDoc]);

  // Check if user is pending approval
  const isPending = useCallback(() => {
    if (!userDoc) return false;
    return (
      userDoc.approval_status === "pending" ||
      (userDoc.is_active === true && userDoc.is_verified === false)
    );
  }, [userDoc]);

  // Get user approval status
  const getApprovalStatus = useCallback(() => {
    if (!userDoc) return "unknown";
    if (isAdmin()) return "admin";
    if (isApproved()) return "approved";
    if (isRejected()) return "rejected";
    return "pending";
  }, [userDoc, isAdmin, isApproved, isRejected]);

  // Get redirect path based on user status
  const getRedirectPath = useCallback(() => {
    if (!userDoc) return "/login";

    if (isAdmin()) return "/admin";

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
  }, [userDoc, isAdmin, getApprovalStatus]);

  // Access control function
  const canAccessApp = useCallback(() => {
    if (!user || !userDoc) {
      return false;
    }

    // Admins can always access
    if (isAdmin()) {
      return true;
    }

    // Check if user account is disabled
    if (!userDoc.is_active) {
      return false;
    }

    // Regular users must be approved to access the app
    return isApproved();
  }, [user, userDoc, isAdmin, isApproved]);

  // Check if user can access admin routes
  const canAccessAdmin = useCallback(() => {
    return canAccessApp() && isAdmin();
  }, [canAccessApp, isAdmin]);

  // Check if user can access dashboard
  const canAccessDashboard = useCallback(() => {
    if (!user || !userDoc) return false;
    return isAdmin() || isApproved();
  }, [user, userDoc, isAdmin, isApproved]);

  // Get user's subscription plan
  const getUserPlan = useCallback(() => {
    if (!userDoc) return "trial";
    return userDoc.plan || "trial";
  }, [userDoc]);

  // Check if user has pro features
  const isPro = useCallback(() => {
    const plan = getUserPlan();
    return ["professional", "enterprise"].includes(plan);
  }, [getUserPlan]);

  // Check if user has enterprise features
  const isEnterprise = useCallback(() => {
    return getUserPlan() === "enterprise";
  }, [getUserPlan]);

  // Get plan display info
  const getPlanInfo = useCallback(() => {
    const plan = getUserPlan();
    const planInfo = {
      free: {
        name: "Free",
        badge: "🆓",
        color: "gray",
        features: ["1 website/month", "7 days dashboard", "Basic scans"]
      },
      individual: {
        name: "Individual",
        badge: "[STAR]",
        color: "blue",
        features: ["5 websites/month", "30 days dashboard", "API testing"]
      },
      professional: {
        name: "Professional",
        badge: "",
        color: "purple",
        features: ["15 websites/month", "60 days dashboard", "Mobile pentest", "Chatbot access"]
      },
      enterprise: {
        name: "Enterprise",
        badge: "",
        color: "gold",
        features: ["Unlimited websites", "365 days dashboard", "All features", "Dedicated support"]
      }
    };
    return planInfo[plan] || planInfo.free;
  }, [getUserPlan]);

  const value = {
    // User state
    user,
    userDoc,
    loading,
    sessionExpired,

    // Authentication methods
    loginWithEmail,
    loginWithProvider,
    registerWithEmail,
    signupWithEmail,
    logout,
    refreshProfile,

    // Helper functions
    getUserRole,
    isAdmin,
    isSuperAdmin,
    isApproved,
    isRejected,
    isPending,
    getApprovalStatus,
    getRedirectPath,

    // Plan/subscription helpers
    getUserPlan,
    isPro,
    isEnterprise,
    getPlanInfo,

    // Access control functions
    canAccessApp,
    canAccessAdmin,
    canAccessDashboard,

    // Legacy compatibility
    login: loginWithEmail,
    signup: signupWithEmail,
    
    // Token management
    token: getAccessToken(),
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
      {/* Session Timeout Modal - blurs screen when session expires */}
      <SessionTimeoutModal 
        isOpen={showTimeoutModal} 
        reason={timeoutReason}
        onClose={() => setShowTimeoutModal(false)}
      />
    </AuthContext.Provider>
  );
};

export default AuthContext;
