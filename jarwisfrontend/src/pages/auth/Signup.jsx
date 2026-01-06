// src/pages/auth/Signup.jsx
// Signup page using FastAPI + PostgreSQL backend with Firebase email verification

import { useState, useEffect } from "react";
import { useNavigate, Link } from "react-router-dom";
import { Eye, EyeOff } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import { firebaseAuthService } from "../../services/firebaseAuth";

const Signup = () => {
  const navigate = useNavigate();
  const { registerWithEmail, user, userDoc, loading: authLoading } = useAuth();

  const [signupForm, setSignupForm] = useState({
    name: "",
    email: "",
    password: "",
    confirmPassword: "",
    company: "",
  });
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const [loading, setLoading] = useState(false);

  // Redirect if already logged in
  useEffect(() => {
    if (!authLoading && user && userDoc) {
      const redirectPath = userDoc.role === "admin" || userDoc.role === "super_admin" 
        ? "/admin" 
        : "/dashboard";
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
          <p className="text-gray-400 text-sm">You're already logged in. Redirecting...</p>
        </div>
      </div>
    );
  }

  const validatePassword = (password) => {
    const pattern = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return pattern.test(password);
  };

  const handleSignup = async (e) => {
    e.preventDefault();
    setError("");
    setSuccess("");

    // Validate passwords match
    if (signupForm.password !== signupForm.confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    if (!validatePassword(signupForm.password)) {
      setError(
        "Password must have uppercase, lowercase, number, and minimum 8 characters."
      );
      return;
    }

    setLoading(true);
    try {
      // Step 1: Create user in Firebase for email verification
      let firebaseUser = null;
      let firebaseEmailSent = false;
      try {
        const firebaseResult = await firebaseAuthService.createUser(
          signupForm.email,
          signupForm.password,
          signupForm.name
        );
        firebaseUser = firebaseResult.user;
        firebaseEmailSent = true;
        console.log("Firebase user created, verification email sent to:", signupForm.email);
      } catch (firebaseError) {
        console.error("Firebase error:", firebaseError.code, firebaseError.message);
        
        // Handle specific Firebase errors
        if (firebaseError.code === 'auth/email-already-in-use') {
          // User exists in Firebase - try to resend verification
          try {
            await firebaseAuthService.signIn(signupForm.email, signupForm.password);
            await firebaseAuthService.sendVerificationEmail();
            firebaseEmailSent = true;
            console.log("Verification email resent to existing Firebase user");
          } catch (resendError) {
            console.warn("Could not resend verification:", resendError.message);
          }
        } else if (firebaseError.code === 'auth/weak-password') {
          setError("Password is too weak. Please use at least 6 characters.");
          setLoading(false);
          return;
        } else if (firebaseError.code === 'auth/invalid-email') {
          setError("Invalid email address format.");
          setLoading(false);
          return;
        } else if (firebaseError.code === 'auth/operation-not-allowed') {
          // Email/Password auth not enabled in Firebase Console
          console.warn("Firebase Email auth not enabled, continuing without email verification");
        } else {
          console.warn("Firebase signup warning:", firebaseError.message);
        }
      }

      // Step 2: Create user in backend (FastAPI/SQLite)
      const result = await registerWithEmail(
        signupForm.email,
        signupForm.password,
        signupForm.name,
        signupForm.company
      );

      // Step 3: Show success message about email verification
      const emailMessage = firebaseEmailSent 
        ? `Account created! We've sent a verification email to ${signupForm.email}. Please check your inbox (and spam folder) and verify your email before logging in.`
        : "Account created! Your account is pending admin approval.";
      
      setSuccess(emailMessage);

      // Clear form
      setSignupForm({
        name: "",
        email: "",
        password: "",
        confirmPassword: "",
        company: "",
      });

      // Sign out from Firebase (user needs to verify first)
      await firebaseAuthService.signOut();

      // Redirect to login after 5 seconds (longer to read message)
      const loginMessage = firebaseEmailSent 
        ? "Please verify your email before logging in."
        : "Your account is pending admin approval.";
      
      setTimeout(() => {
        navigate("/login", { 
          state: { message: loginMessage }
        });
      }, 5000);
    } catch (err) {
      setError(err.message);
      // Try to clean up Firebase user if backend failed
      try {
        await firebaseAuthService.signOut();
      } catch (e) {}
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-start sm:items-center justify-center px-4 py-6 sm:py-12 safe-area-inset-y">
      <div className="w-full max-w-[440px] bg-gray-900/80 backdrop-blur-2xl rounded-2xl sm:rounded-3xl p-5 sm:p-8 border border-gray-700/50 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-500">
        <div className="text-center mb-6 sm:mb-8">
          <h2 className="text-2xl sm:text-3xl font-black bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent mb-1 sm:mb-2">
            Create Account
          </h2>
          <p className="text-gray-400 text-xs sm:text-sm">
            Sign up to access your Jarwis AGI dashboard
          </p>
        </div>

        {/* Success/Error Messages */}
        {success && (
          <div className="mb-4 sm:mb-6 p-3 sm:p-4 bg-green-500/20 border border-green-500/50 rounded-xl sm:rounded-2xl">
            <p className="text-green-400 text-xs sm:text-sm text-center">{success}</p>
          </div>
        )}

        {error && (
          <div className="mb-4 sm:mb-6 p-3 sm:p-4 bg-red-500/20 border border-red-500/50 rounded-xl sm:rounded-2xl">
            <p className="text-red-400 text-xs sm:text-sm text-center">{error}</p>
          </div>
        )}

        <form onSubmit={handleSignup} className="space-y-3 sm:space-y-4">
          <div>
            <label className="block text-xs sm:text-sm font-bold text-white mb-1.5 sm:mb-2">
              Full Name
            </label>
            <input
              type="text"
              required
              value={signupForm.name}
              onChange={(e) =>
                setSignupForm({ ...signupForm, name: e.target.value })
              }
              className="w-full px-3 sm:px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-xl sm:rounded-2xl text-white text-base focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 placeholder-gray-400 min-h-[48px]"
              placeholder="Your full name"
              disabled={loading}
              autoComplete="name"
            />
          </div>

          <div>
            <label className="block text-xs sm:text-sm font-bold text-white mb-1.5 sm:mb-2">
              Email
            </label>
            <input
              type="email"
              required
              value={signupForm.email}
              onChange={(e) =>
                setSignupForm({ ...signupForm, email: e.target.value })
              }
              className="w-full px-3 sm:px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-xl sm:rounded-2xl text-white text-base focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 placeholder-gray-400 min-h-[48px]"
              placeholder="your@email.com"
              disabled={loading}
              autoComplete="email"
            />
          </div>

          <div>
            <label className="block text-xs sm:text-sm font-bold text-white mb-1.5 sm:mb-2">
              Company (Optional)
            </label>
            <input
              type="text"
              value={signupForm.company}
              onChange={(e) =>
                setSignupForm({ ...signupForm, company: e.target.value })
              }
              className="w-full px-3 sm:px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-xl sm:rounded-2xl text-white text-base focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 placeholder-gray-400 min-h-[48px]"
              placeholder="Your company name"
              disabled={loading}
              autoComplete="organization"
            />
          </div>

          <div>
            <label className="block text-xs sm:text-sm font-bold text-white mb-1.5 sm:mb-2">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                required
                value={signupForm.password}
                onChange={(e) =>
                  setSignupForm({ ...signupForm, password: e.target.value })
                }
                className="w-full px-3 sm:px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-xl sm:rounded-2xl text-white text-base focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 placeholder-gray-400 pr-12 min-h-[48px]"
                placeholder="Create a strong password"
                disabled={loading}
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 sm:right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white touch-target p-2 -mr-2"
              >
                {showPassword ? (
                  <EyeOff className="w-5 h-5" />
                ) : (
                  <Eye className="w-5 h-5" />
                )}
              </button>
            </div>
            <p className="text-gray-500 text-xs mt-1.5">
              Min 8 chars with uppercase, lowercase, and number
            </p>
          </div>

          <div>
            <label className="block text-xs sm:text-sm font-bold text-white mb-1.5 sm:mb-2">
              Confirm Password
            </label>
            <div className="relative">
              <input
                type={showConfirmPassword ? "text" : "password"}
                required
                value={signupForm.confirmPassword}
                onChange={(e) =>
                  setSignupForm({ ...signupForm, confirmPassword: e.target.value })
                }
                className="w-full px-3 sm:px-4 py-3 bg-gray-800/50 border border-gray-600 rounded-xl sm:rounded-2xl text-white text-base focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20 placeholder-gray-400 pr-12 min-h-[48px]"
                placeholder="Confirm your password"
                disabled={loading}
                autoComplete="new-password"
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 sm:right-4 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-white touch-target p-2 -mr-2"
              >
                {showConfirmPassword ? (
                  <EyeOff className="w-5 h-5" />
                ) : (
                  <Eye className="w-5 h-5" />
                )}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-gradient-to-r from-blue-500 to-cyan-400 text-white py-3 sm:py-3.5 px-6 rounded-xl sm:rounded-2xl hover:from-cyan-400 hover:to-blue-500 transition-all font-bold disabled:opacity-50 disabled:cursor-not-allowed min-h-[48px] touch-target text-sm sm:text-base active:scale-[0.98]"
          >
            {loading ? "Creating Account..." : "Create Account"}
          </button>
        </form>

        {/* Terms */}
        <p className="mt-4 sm:mt-5 text-gray-500 text-xs text-center leading-relaxed px-2">
          By signing up, you agree to our{" "}
          <Link to="/terms" className="text-cyan-400 hover:underline">
            Terms of Service
          </Link>{" "}
          and{" "}
          <Link to="/privacy" className="text-cyan-400 hover:underline">
            Privacy Policy
          </Link>
        </p>

        {/* Login Link */}
        <div className="mt-5 sm:mt-6 text-center pb-2">
          <p className="text-gray-400 text-sm">
            Already have an account?{" "}
            <Link
              to="/login"
              className="text-cyan-400 hover:text-cyan-300 font-bold transition-colors"
            >
              Sign in
            </Link>
          </p>
        </div>
      </div>
    </div>
  );
};

export default Signup;
