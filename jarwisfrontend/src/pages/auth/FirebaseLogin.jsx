// src/pages/auth/FirebaseLogin.jsx
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff } from "lucide-react";
import { FiGithub } from "react-icons/fi";
import { useAuth } from "../../context/FirebaseAuthContext";

const FirebaseLogin = () => {
  const navigate = useNavigate();
  const {
    loginWithEmail,
    loginWithProvider,
    user,
    userDoc,
    loading: authLoading,
  } = useAuth();

  const [loginForm, setLoginForm] = useState({ email: "", password: "" });
  const [showPassword, setShowPassword] = useState(false);
  const [status, setStatus] = useState({
    error: "",
    success: "",
    loading: false,
  });

  // Redirect path logic
  const getRedirectPathFromUserDoc = (userData) => {
    if (!userData) return "/login";
    if (userData.role === "admin" || userData.role === "super_admin")
      return "/admin";
    if (
      userData.isApproved === true ||
      userData.approvalStatus === "approved"
    ) {
      return "/dashboard";
    } else if (userData.approvalStatus === "rejected") {
      return "/access-denied";
    } else {
      return "/pending-approval";
    }
  };

  // Redirect automatically when userDoc is ready
  useEffect(() => {
    if (!authLoading && user && userDoc) {
      const redirectPath = getRedirectPathFromUserDoc(userDoc);
      navigate(redirectPath);
    }
  }, [user, userDoc, authLoading, navigate]);

  const handleEmailLogin = async (e) => {
    e.preventDefault();
    setStatus({ error: "", success: "", loading: true });

    try {
      const result = await loginWithEmail(loginForm.email, loginForm.password);
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

  const handleSocialLogin = async (provider) => {
    setStatus({ error: "", success: "", loading: true });

    try {
      const result = await loginWithProvider(provider);

      // Handle popup cancellation - don't show error, just reset loading
      if (result?.cancelled) {
        setStatus({ error: "", success: "", loading: false });
        return;
      }

      setStatus({ error: "", success: result.message, loading: false });

      if (result.userDoc) {
        navigate(getRedirectPathFromUserDoc(result.userDoc));
      }
    } catch (err) {
      console.error(`${provider} login error:`, err);
      setStatus({
        error:
          err.message ||
          `Failed to sign in with ${provider}. Please try again.`,
        success: "",
        loading: false,
      });
    }
  };

  return (
    <div className="min-h-screen flex items-start justify-center px-4 py-12">
      <div className="max-w-md w-full bg-gray-900/80 backdrop-blur-2xl rounded-3xl p-8 border border-gray-700/50 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-500">
        {/* Header */}
        <div className="text-center mb-8">
          <h2 className="text-3xl font-black bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent mb-2">
            Welcome Back
          </h2>
          <p className="text-gray-400 text-sm">
            Access your Jarwis AGI security dashboard
          </p>
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

        {/* Social Login */}
        <div className="space-y-3 mb-6">
          <button
            onClick={() => handleSocialLogin("Google")}
            disabled={status.loading}
            className="w-full flex text-sm items-center justify-center gap-3 px-4 py-3 bg-white text-black rounded-2xl font-bold hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path
                fill="#EA4335"
                d="M12 10.2v3.6h5.09c-.22 1.17-.9 2.16-1.91 2.82l3.09 2.4c1.8-1.66 2.83-4.1 2.83-6.97 0-.67-.06-1.31-.18-1.91H12z"
              />
              <path
                fill="#34A853"
                d="M6.54 13.28a4.8 4.8 0 0 1 0-2.56V8.4H3.3a8.8 8.8 0 0 0 0 7.2l3.24-2.32z"
              />
              <path
                fill="#FBBC05"
                d="M12 5.2c1.02 0 1.94.35 2.67 1.03l2-2C15.91 2.74 14.05 2 12 2A8.8 8.8 0 0 0 3.3 8.4l3.24 2.32C7.53 7.89 9.54 5.2 12 5.2z"
              />
              <path
                fill="#4285F4"
                d="M12 22c2.05 0 3.91-.67 5.37-1.81l-2.38-1.84A5.29 5.29 0 0 1 12 18.8a5.3 5.3 0 0 1-4.71-2.72l-3.24 2.32C6.09 20.26 8.82 22 12 22z"
              />
            </svg>
            Continue with Google
          </button>

          <button
            onClick={() => handleSocialLogin("Microsoft")}
            disabled={status.loading}
            className="w-full flex items-center text-sm justify-center gap-3 px-4 py-3 bg-blue-600 text-white rounded-2xl font-bold hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
          >
            <svg className="w-4 h-4" viewBox="0 0 24 24" fill="currentColor">
              <path d="M11.4 24H0V12.6h11.4V24zM24 24H12.6V12.6H24V24zM11.4 11.4H0V0h11.4v11.4zM24 11.4H12.6V0H24v11.4z" />
            </svg>
            Continue with Microsoft
          </button>

          <button
            onClick={() => handleSocialLogin("GitHub")}
            disabled={status.loading}
            className="w-full flex items-center text-sm justify-center gap-3 px-4 py-3 bg-gray-800 text-white rounded-2xl font-bold hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100"
          >
            <FiGithub className="w-5 h-5" />
            Continue with GitHub
          </button>
        </div>

        {/* Divider */}
        <div className="relative mb-6">
          <div className="absolute inset-0 flex items-center">
            <div className="w-full border-t border-gray-600"></div>
          </div>
          <div className="relative flex justify-center text-sm">
            <span className="px-4 bg-gray-900 text-gray-400 font-medium">
              Or continue with email
            </span>
          </div>
        </div>

        {/* Email Login Form */}
        <form onSubmit={handleEmailLogin} className="space-y-4">
          <div>
            <label className="block text-sm font-bold text-white mb-2">
              Email
            </label>
            <input
              type="email"
              required
              value={loginForm.email}
              onChange={(e) =>
                setLoginForm({ ...loginForm, email: e.target.value })
              }
              placeholder="your@email.com"
              className="w-full px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-2xl text-white focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 transition-all placeholder-gray-400"
              disabled={status.loading}
            />
          </div>

          <div>
            <label className="block text-sm font-bold text-white mb-2">
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
                placeholder="Enter your password"
                className="w-full px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-2xl text-white focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 pr-12 placeholder-gray-400"
                disabled={status.loading}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white"
                disabled={status.loading}
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={status.loading}
            className="w-full bg-gradient-to-r from-blue-500 to-cyan-400 text-white py-3 px-6 rounded-2xl hover:from-cyan-400 hover:to-blue-500 transition-all font-bold shadow-lg hover:shadow-xl disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {status.loading ? "Please wait..." : "ACCESS DASHBOARD"}
          </button>
        </form>

        {/* Debug Info (dev only) */}
        {process.env.NODE_ENV === "development" && user && (
          <div className="mt-4 p-3 bg-gray-800 rounded-lg text-xs">
            <div className="text-gray-400">Debug Info:</div>
            <div className="text-white">User: {user?.email}</div>
            <div className="text-white">
              Role: {userDoc?.role || "loading..."}
            </div>
            <div className="text-white">
              Status: {userDoc?.approvalStatus || "loading..."}
            </div>
            <div className="text-white">
              IsApproved: {String(userDoc?.isApproved)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default FirebaseLogin;
