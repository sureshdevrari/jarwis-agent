// src/pages/auth/FirebaseAction.jsx
// Unified Firebase Action Handler for email verification, password reset, etc.

import { useEffect } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";

const FirebaseAction = () => {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const mode = searchParams.get("mode");
    const oobCode = searchParams.get("oobCode");
    const continueUrl = searchParams.get("continueUrl");
    const lang = searchParams.get("lang") || "en";

    // Redirect based on the action mode
    switch (mode) {
      case "resetPassword":
        navigate(`/reset-password?${searchParams.toString()}`, { replace: true });
        break;
      case "verifyEmail":
        navigate(`/verify-email?${searchParams.toString()}`, { replace: true });
        break;
      case "recoverEmail":
        // Email change recovery - can be implemented later
        navigate(`/login?action=email-recovered`, { replace: true });
        break;
      default:
        // Unknown mode - redirect to home
        navigate("/", { replace: true });
        break;
    }
  }, [searchParams, navigate]);

  // Show loading while redirecting
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      <div className="text-center">
        <div className="w-12 h-12 border-4 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin mx-auto mb-4" />
        <p className="text-gray-400">Processing...</p>
      </div>
    </div>
  );
};

export default FirebaseAction;
