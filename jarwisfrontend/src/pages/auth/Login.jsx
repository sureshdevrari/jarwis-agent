// src/pages/auth/Login.jsx
// Login page using FastAPI + PostgreSQL backend with Firebase email verification

import { useState, useEffect } from "react";
import { useNavigate, Link, useSearchParams, useLocation } from "react-router-dom";
import { Eye, EyeOff, Sparkles } from "lucide-react";
import { motion } from "framer-motion";
import { useAuth } from "../../context/AuthContext";
import EscapingButton from "../../components/EscapingButton";
import { firebaseAuthService } from "../../services/firebaseAuth";

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:8000';

const Login = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const {
    loginWithEmail,
    user,
    userDoc,
    loading: authLoading,
  } = useAuth();

  const [loginForm, setLoginForm] = useState({ emailOrUsername: "", password: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [showResendVerification, setShowResendVerification] = useState(false);
  const [resendingVerification, setResendingVerification] = useState(false);
  const [oauthProviders, setOauthProviders] = useState({
    google: false,
    github: false,
    microsoft: false,
  });
  const [status, setStatus] = useState({
    error: "",
    success: "",
    loading: false,
  });

  // Check for state message (e.g., from signup redirect)
  useEffect(() => {
    if (location.state?.message) {
      setStatus(prev => ({
        ...prev,
        success: location.state.message
      }));
      // Clear the state
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state, navigate, location.pathname]);

  // Check OAuth provider status on mount
  useEffect(() => {
    const checkOAuthProviders = async () => {
      try {
        const response = await fetch(`${API_URL}/api/oauth/providers`);
        if (response.ok) {
          const data = await response.json();
          const providers = {};
          data.providers.forEach(p => {
            providers[p.name] = p.configured;
          });
          setOauthProviders(providers);
        }
      } catch (error) {
        console.log("Could not check OAuth providers:", error);
      }
    };
    checkOAuthProviders();

    // Check for OAuth error in URL
    const errorParam = searchParams.get("error");
    if (errorParam) {
      setStatus({
        error: `OAuth login failed: ${errorParam.replace(/_/g, ' ')}`,
        success: "",
        loading: false,
      });
    }
  }, [searchParams]);

  // Redirect path logic
  const getRedirectPathFromUserDoc = (userData) => {
    if (!userData) return "/login";
    if (userData.role === "admin" || userData.role === "super_admin" || userData.is_superuser)
      return "/admin";
    if (userData.is_verified === true || userData.approval_status === "approved") {
      return "/dashboard";
    } else if (userData.approval_status === "rejected" || userData.is_active === false) {
      return "/access-denied";
    } else {
      return "/pending-approval";
    }
  };

  // Redirect automatically when userDoc is ready (already logged in)
  useEffect(() => {
    if (!authLoading && user && userDoc) {
      const redirectPath = getRedirectPathFromUserDoc(userDoc);
      navigate(redirectPath, { replace: true });
    }
  }, [user, userDoc, authLoading, navigate]);

  // Show loading spinner while checking auth state
  if (authLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin"></div>
          <p className="text-gray-400 text-sm">Checking authentication...</p>
        </div>
      </div>
    );
  }

  // If already authenticated, show redirect message
  if (user && userDoc) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="flex flex-col items-center gap-4">
          <div className="w-12 h-12 border-4 border-green-500/30 border-t-green-500 rounded-full animate-spin"></div>
          <p className="text-gray-400 text-sm">Redirecting to dashboard...</p>
        </div>
      </div>
    );
  }

  const handleEmailLogin = async (e) => {
    e.preventDefault();
    setStatus({ error: "", success: "", loading: true });
    setShowResendVerification(false);

    try {
      // Step 1: Check email verification with Firebase (only for users who signed up with Firebase)
      let skipFirebaseCheck = false;
      try {
        const firebaseResult = await firebaseAuthService.signIn(
          loginForm.emailOrUsername,
          loginForm.password
        );
        
        if (firebaseResult.user) {
          // Check if email is verified
          const isVerified = await firebaseAuthService.isEmailVerified();
          
          if (!isVerified) {
            // Sign out from Firebase
            await firebaseAuthService.signOut();
            
            setStatus({
              error: "Please verify your email before logging in. Check your inbox for the verification link.",
              success: "",
              loading: false,
            });
            setShowResendVerification(true);
            return;
          }
          
          // Sign out from Firebase after verification check
          await firebaseAuthService.signOut();
        }
      } catch (firebaseError) {
        // If Firebase user doesn't exist or credentials don't match, 
        // continue with backend login (existing users before Firebase was added)
        const ignoredCodes = [
          'auth/user-not-found',
          'auth/invalid-credential', 
          'auth/wrong-password',
          'auth/invalid-email'
        ];
        if (!ignoredCodes.includes(firebaseError.code)) {
          console.warn("Firebase check warning:", firebaseError.code, firebaseError.message);
        }
        skipFirebaseCheck = true;
      }

      // Step 2: Login with backend
      const result = await loginWithEmail(loginForm.emailOrUsername, loginForm.password);
      setStatus({ error: "", success: result.message, loading: false });

      if (result.userDoc) {
        navigate(getRedirectPathFromUserDoc(result.userDoc));
      }
    } catch (err) {
      console.error("Login error:", err);
      setStatus({
        error: err.message || "Login failed. Please try again.",
        success: "",
        loading: false,
      });
    }
  };

  // Resend verification email
  const handleResendVerification = async () => {
    setResendingVerification(true);
    try {
      // Sign in to Firebase temporarily to get user object
      await firebaseAuthService.signIn(loginForm.emailOrUsername, loginForm.password);
      await firebaseAuthService.sendVerificationEmail();
      await firebaseAuthService.signOut();
      
      setStatus({
        error: "",
        success: "Verification email sent! Please check your inbox.",
        loading: false,
      });
      setShowResendVerification(false);
    } catch (err) {
      setStatus({
        error: "Failed to send verification email. Please try again.",
        success: "",
        loading: false,
      });
    } finally {
      setResendingVerification(false);
    }
  };

  return (
    <div className="min-h-screen flex items-start sm:items-center justify-center px-4 py-8 sm:py-12 safe-area-inset-y" style={{ overflow: "visible" }}>
      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-[440px] bg-gray-900/80 backdrop-blur-2xl rounded-2xl sm:rounded-3xl p-5 sm:p-8 border border-gray-700/50 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-500"
        style={{ overflow: "visible" }}
      >
        {/* Header */}
        <div className="text-center mb-6 sm:mb-8">
          <motion.div
            initial={{ scale: 0 }}
            animate={{ scale: 1 }}
            transition={{ delay: 0.2, type: "spring", stiffness: 200 }}
            className="inline-flex items-center justify-center mb-3 sm:mb-4"
          >
            <img src="/logo/jarwis-logo-transparent.svg" alt="Jarwis Logo" className="w-16 h-16 sm:w-20 sm:h-20 object-contain" />
          </motion.div>
          <motion.h2 
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="text-2xl sm:text-3xl font-black bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent mb-1 sm:mb-2"
          >
            Welcome Back
          </motion.h2>
          <motion.p 
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.4 }}
            className="text-gray-400 text-xs sm:text-sm"
          >
            Access your Jarwis AGI security dashboard
          </motion.p>
        </div>

        {/* Success/Error Messages */}
        {status.success && (
          <div className="mb-6 p-4 bg-green-500/20 border border-green-500/50 rounded-2xl">
            <p className="text-green-400 text-sm text-center">
              {status.success}
            </p>
          </div>
        )}
        {status.error && (
          <div className="mb-6 p-4 bg-red-500/20 border border-red-500/50 rounded-2xl">
            <p className="text-red-400 text-sm text-center">{status.error}</p>
            {showResendVerification && (
              <div className="mt-3 text-center">
                <button
                  type="button"
                  onClick={handleResendVerification}
                  disabled={resendingVerification}
                  className="text-cyan-400 hover:text-cyan-300 text-sm font-medium underline disabled:opacity-50"
                >
                  {resendingVerification ? "Sending..." : "Resend Verification Email"}
                </button>
              </div>
            )}
          </div>
        )}

        {/* Loading State */}
        {status.loading && (
          <div className="mb-6 p-4 bg-blue-500/20 border border-blue-500/50 rounded-2xl">
            <div className="flex items-center justify-center space-x-2">
              <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-400"></div>
              <p className="text-blue-400 text-sm">Signing in...</p>
            </div>
          </div>
        )}

        {/* Email Login Form */}
        <form onSubmit={handleEmailLogin} className="space-y-4">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.5 }}
          >
            <label className="block text-xs sm:text-sm font-bold text-white mb-1.5 sm:mb-2">
              Email / Username
            </label>
            <input
              type="text"
              required
              value={loginForm.emailOrUsername}
              onChange={(e) =>
                setLoginForm({ ...loginForm, emailOrUsername: e.target.value })
              }
              className="w-full px-3 sm:px-4 py-3 sm:py-3.5 bg-gray-800/50 border border-gray-600 rounded-xl sm:rounded-2xl text-white text-base focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 placeholder-gray-400 transition-all duration-300 min-h-[48px]"
              placeholder="your@email.com or username"
              disabled={status.loading}
              autoComplete="username"
            />
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.6 }}
          >
            <label className="block text-xs sm:text-sm font-bold text-white mb-1.5 sm:mb-2">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                required
                value={loginForm.password}
                onChange={(e) =>
                  setLoginForm({ ...loginForm, password: e.target.value })
                }
                className="w-full px-3 sm:px-4 py-3 sm:py-3.5 bg-gray-800/50 border border-gray-600 rounded-xl sm:rounded-2xl text-white text-base focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 placeholder-gray-400 pr-12 transition-all duration-300 min-h-[48px]"
                placeholder="Enter your password"
                disabled={status.loading}
                autoComplete="current-password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 sm:right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white transition-colors p-1 touch-target"
              >
                {showPassword ? (
                  <EyeOff className="w-5 h-5" />
                ) : (
                  <Eye className="w-5 h-5" />
                )}
              </button>
            </div>
          </motion.div>

          {/* Escaping Login Button */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.7 }}
            className="pt-4"
          >
            <EscapingButton
              isFormValid={loginForm.emailOrUsername.trim() !== "" && loginForm.password.trim() !== ""}
              onClick={handleEmailLogin}
              loading={status.loading}
              loadingText="Signing In..."
              className="w-full"
            >
              Sign In
            </EscapingButton>
          </motion.div>
        </form>

        {/* Divider */}
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.8 }}
          className="flex items-center my-6"
        >
          <div className="flex-1 border-t border-gray-600"></div>
          <span className="px-4 text-gray-500 text-sm">or continue with</span>
          <div className="flex-1 border-t border-gray-600"></div>
        </motion.div>

        {/* Social Login Buttons */}
        <motion.div 
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.9 }}
          className="space-y-3"
        >
          {/* Google */}
          <button
            onClick={() => {
              if (!oauthProviders.google) {
                setStatus({ error: "Google OAuth is not configured. Please contact the administrator.", success: "", loading: false });
                return;
              }
              window.location.href = `${API_URL}/api/oauth/google/login`;
            }}
            disabled={status.loading}
            className={`w-full flex items-center justify-center gap-3 py-3 px-6 rounded-2xl transition-all font-medium disabled:opacity-50 ${
              oauthProviders.google 
                ? "bg-white text-gray-800 hover:bg-gray-100" 
                : "bg-gray-700 text-gray-400 cursor-not-allowed"
            }`}
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path fill={oauthProviders.google ? "#4285F4" : "#666"} d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
              <path fill={oauthProviders.google ? "#34A853" : "#666"} d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
              <path fill={oauthProviders.google ? "#FBBC05" : "#666"} d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
              <path fill={oauthProviders.google ? "#EA4335" : "#666"} d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
            </svg>
            Continue with Google {!oauthProviders.google && "(Not configured)"}
          </button>

          {/* GitHub */}
          <button
            onClick={() => {
              if (!oauthProviders.github) {
                setStatus({ error: "GitHub OAuth is not configured. Please contact the administrator.", success: "", loading: false });
                return;
              }
              window.location.href = `${API_URL}/api/oauth/github/login`;
            }}
            disabled={status.loading}
            className={`w-full flex items-center justify-center gap-3 py-3 px-6 rounded-2xl transition-all font-medium border border-gray-600 disabled:opacity-50 ${
              oauthProviders.github 
                ? "bg-gray-800 text-white hover:bg-gray-700" 
                : "bg-gray-800/50 text-gray-500 cursor-not-allowed"
            }`}
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path d="M12 0c-6.626 0-12 5.373-12 12 0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23.957-.266 1.983-.399 3.003-.404 1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576 4.765-1.589 8.199-6.086 8.199-11.386 0-6.627-5.373-12-12-12z"/>
            </svg>
            Continue with GitHub {!oauthProviders.github && "(Not configured)"}
          </button>

          {/* Microsoft */}
          <button
            onClick={() => {
              if (!oauthProviders.microsoft) {
                setStatus({ error: "Microsoft OAuth is not configured. Please contact the administrator.", success: "", loading: false });
                return;
              }
              window.location.href = `${API_URL}/api/oauth/microsoft/login`;
            }}
            disabled={status.loading}
            className={`w-full flex items-center justify-center gap-3 py-3 px-6 rounded-2xl transition-all font-medium border border-gray-600 disabled:opacity-50 ${
              oauthProviders.microsoft 
                ? "bg-[#2F2F2F] text-white hover:bg-[#404040]" 
                : "bg-gray-800/50 text-gray-500 cursor-not-allowed"
            }`}
          >
            <svg className="w-5 h-5" viewBox="0 0 23 23">
              <path fill={oauthProviders.microsoft ? "#f35325" : "#666"} d="M1 1h10v10H1z"/>
              <path fill={oauthProviders.microsoft ? "#81bc06" : "#666"} d="M12 1h10v10H12z"/>
              <path fill={oauthProviders.microsoft ? "#05a6f0" : "#666"} d="M1 12h10v10H1z"/>
              <path fill={oauthProviders.microsoft ? "#ffba08" : "#666"} d="M12 12h10v10H12z"/>
            </svg>
            Continue with Microsoft {!oauthProviders.microsoft && "(Not configured)"}
          </button>
        </motion.div>

        {/* Signup Link */}
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
          className="mt-6 text-center"
        >
          <p className="text-gray-400 text-sm">
            Don't have an account?{" "}
            <Link
              to="/signup"
              className="text-cyan-400 hover:text-cyan-300 font-bold transition-colors"
            >
              Sign up
            </Link>
          </p>
        </motion.div>

        {/* Forgot Password */}
        <motion.div 
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1.1 }}
          className="mt-4 text-center"
        >
          <Link
            to="/forgot-password"
            className="text-gray-500 hover:text-gray-400 text-sm transition-colors"
          >
            Forgot your password?
          </Link>
        </motion.div>
      </motion.div>
    </div>
  );
};

export default Login;
