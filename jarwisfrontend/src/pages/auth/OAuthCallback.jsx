// src/pages/auth/OAuthCallback.jsx
// Handles OAuth callback from social login providers

import { useEffect, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { setTokens, setStoredUser, authAPI } from "../../services/api";

const OAuthCallback = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [status, setStatus] = useState("Processing login...");
  const [error, setError] = useState(null);

  useEffect(() => {
    const handleCallback = async () => {
      const accessToken = searchParams.get("access_token");
      const refreshToken = searchParams.get("refresh_token");
      const provider = searchParams.get("provider");
      const errorParam = searchParams.get("error");
      const approvalStatus = searchParams.get("approval_status");
      const isNewUser = searchParams.get("is_new_user") === "true";

      if (errorParam) {
        setError(`Login failed: ${errorParam}`);
        setTimeout(() => navigate("/login"), 3000);
        return;
      }

      if (!accessToken || !refreshToken) {
        setError("Invalid OAuth response");
        setTimeout(() => navigate("/login"), 3000);
        return;
      }

      // Check if new user needs approval BEFORE trying to fetch profile
      if (isNewUser && approvalStatus === "pending") {
        setStatus("Account created! Awaiting admin approval...");
        // Store tokens anyway so user can check status later
        setTokens(accessToken, refreshToken);
        setTimeout(() => navigate("/pending-approval"), 2000);
        return;
      }

      try {
        setStatus("Saving credentials...");
        
        // Store tokens
        setTokens(accessToken, refreshToken);

        // Fetch user profile
        setStatus("Loading your profile...");
        const profile = await authAPI.getProfile();
        setStoredUser(profile);

        setStatus("Login successful! Redirecting...");

        // Redirect based on user role and approval status
        setTimeout(() => {
          if (profile.is_superuser || profile.role === "admin" || profile.role === "super_admin") {
            navigate("/admin");
          } else if (profile.approval_status === "rejected") {
            navigate("/access-denied");
          } else if (profile.approval_status === "pending" || !profile.is_verified) {
            navigate("/pending-approval");
          } else {
            navigate("/dashboard");
          }
        }, 1000);
      } catch (err) {
        console.error("OAuth callback error:", err);
        
        // If profile fetch fails but we have approval_status from URL, use that
        if (approvalStatus === "pending") {
          setStatus("Account pending approval...");
          setTimeout(() => navigate("/pending-approval"), 2000);
          return;
        } else if (approvalStatus === "rejected") {
          setTimeout(() => navigate("/access-denied"), 2000);
          return;
        }
        
        setError("Failed to complete login. Please try again.");
        setTimeout(() => navigate("/login"), 3000);
      }
    };

    handleCallback();
  }, [searchParams, navigate]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 px-4">
      <div className="max-w-md w-full bg-gray-800/50 backdrop-blur-xl rounded-3xl p-8 border border-gray-700/50 shadow-2xl text-center">
        {error ? (
          <>
            <div className="mb-6">
              <div className="w-16 h-16 mx-auto bg-red-500/20 rounded-full flex items-center justify-center">
                <svg className="w-8 h-8 text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
            </div>
            <h2 className="text-xl font-bold text-red-400 mb-2">Login Failed</h2>
            <p className="text-gray-400">{error}</p>
            <p className="text-gray-500 text-sm mt-4">Redirecting to login page...</p>
          </>
        ) : (
          <>
            <div className="mb-6">
              <div className="animate-spin rounded-full h-16 w-16 border-b-2 border-cyan-500 mx-auto"></div>
            </div>
            <h2 className="text-xl font-bold text-white mb-2">Completing Login</h2>
            <p className="text-gray-400">{status}</p>
          </>
        )}
      </div>
    </div>
  );
};

export default OAuthCallback;
