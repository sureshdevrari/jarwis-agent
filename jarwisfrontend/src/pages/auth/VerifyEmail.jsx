// src/pages/auth/VerifyEmail.jsx
// Email verification page (from email link)

import { useState, useEffect } from "react";
import { Link, useSearchParams, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { firebaseAuthService } from "../../services/firebaseAuth";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const VerifyEmail = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  
  const [verifying, setVerifying] = useState(true);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState("");

  // Get action code from URL
  const actionCode = searchParams.get("oobCode");
  const mode = searchParams.get("mode");

  // Verify the email on mount
  useEffect(() => {
    const verifyEmail = async () => {
      if (!actionCode || mode !== "verifyEmail") {
        setError("Invalid or missing verification link.");
        setVerifying(false);
        return;
      }

      try {
        // Step 1: Verify with Firebase
        const result = await firebaseAuthService.verifyEmail(actionCode);
        
        // Step 2: Get the user's email from Firebase auth state or result
        const userEmail = result?.email || firebaseAuthService.getCurrentUserEmail();
        
        // Step 3: Notify backend to update user status to "pending"
        if (userEmail) {
          try {
            const response = await fetch(`${API_URL}/api/auth/email-verified`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ email: userEmail })
            });
            const data = await response.json();
            console.log("Backend email verification update:", data);
          } catch (backendError) {
            console.warn("Could not update backend status:", backendError);
            // Continue anyway - user can try logging in
          }
        }
        
        setSuccess(true);
        setVerifying(false);
        
        // Redirect to login after 3 seconds
        setTimeout(() => {
          navigate("/login", { 
            state: { message: "Email verified! Your account is now pending admin approval." }
          });
        }, 3000);
      } catch (err) {
        console.error("Email verification error:", err);
        setError(firebaseAuthService.formatError(err));
        setVerifying(false);
      }
    };

    verifyEmail();
  }, [actionCode, mode, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 p-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5 }}
        className="w-full max-w-md"
      >
        {/* Logo */}
        <div className="text-center mb-8">
          <Link to="/" className="inline-block">
            <img
              src="/logo/jarwis-logo-transparent.svg"
              alt="Jarwis"
              className="h-16 mx-auto mb-4"
            />
          </Link>
          <h1 className="text-2xl font-bold text-white">Email Verification</h1>
        </div>

        {/* Card */}
        <div className="bg-slate-800/50 backdrop-blur-xl rounded-2xl border border-slate-700/50 p-8 shadow-2xl">
          {verifying ? (
            <div className="text-center py-8">
              <svg className="w-16 h-16 animate-spin mx-auto text-cyan-400" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              <p className="text-gray-400 mt-4">Verifying your email...</p>
            </div>
          ) : success ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center"
            >
              <div className="w-20 h-20 bg-green-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                <svg className="w-10 h-10 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-white mb-2">Email Verified!</h2>
              <p className="text-gray-400 mb-6">
                Your email has been verified successfully. You can now access all features.
              </p>
              <p className="text-sm text-gray-500 mb-4">
                Redirecting to login...
              </p>
              <Link
                to="/login"
                className="inline-flex items-center justify-center px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all duration-300"
              >
                Go to Login
              </Link>
            </motion.div>
          ) : (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center"
            >
              <div className="w-20 h-20 bg-red-500/20 rounded-full flex items-center justify-center mx-auto mb-6">
                <svg className="w-10 h-10 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h2 className="text-2xl font-bold text-white mb-2">Verification Failed</h2>
              <p className="text-gray-400 mb-6">{error}</p>
              <div className="space-y-3">
                <Link
                  to="/login"
                  className="block w-full px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-medium rounded-xl hover:from-cyan-400 hover:to-blue-500 transition-all duration-300"
                >
                  Go to Login
                </Link>
                <p className="text-sm text-gray-500">
                  Need a new verification link?{" "}
                  <Link to="/resend-verification" className="text-cyan-400 hover:text-cyan-300">
                    Resend Email
                  </Link>
                </p>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>
    </div>
  );
};

export default VerifyEmail;
