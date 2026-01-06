// src/pages/PaymentSuccess.jsx
// Payment success confirmation page
import { useEffect, useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const PaymentSuccess = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { refreshUser, user } = useAuth();
  const [countdown, setCountdown] = useState(5);
  
  const planName = location.state?.plan || "subscription";
  
  useEffect(() => {
    // Refresh user data to get updated plan
    refreshUser?.();
    
    // Auto-redirect countdown
    const timer = setInterval(() => {
      setCountdown((prev) => {
        if (prev <= 1) {
          clearInterval(timer);
          navigate("/dashboard");
          return 0;
        }
        return prev - 1;
      });
    }, 1000);
    
    return () => clearInterval(timer);
  }, [navigate, refreshUser]);

  return (
    <div className="min-h-screen bg-gradient-to-b from-gray-900 to-black flex items-center justify-center p-4">
      <div className="max-w-md w-full text-center">
        {/* Success animation */}
        <div className="mb-8">
          <div className="w-24 h-24 mx-auto bg-green-500/20 rounded-full flex items-center justify-center animate-pulse">
            <svg
              className="w-12 h-12 text-green-400"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M5 13l4 4L19 7"
              />
            </svg>
          </div>
        </div>

        {/* Success message */}
        <h1 className="text-3xl font-bold text-white mb-4">
          Payment Successful! 
        </h1>
        
        <p className="text-gray-300 mb-2">
          Thank you for subscribing to Jarwis AGI Security!
        </p>
        
        <p className="text-cyan-400 font-semibold mb-8">
          Your <span className="capitalize">{planName}</span> plan is now active.
        </p>

        {/* What's next */}
        <div className="bg-gray-800/50 border border-gray-700 rounded-xl p-6 mb-8 text-left">
          <h3 className="text-white font-semibold mb-4">What's next?</h3>
          <ul className="space-y-3 text-sm text-gray-300">
            <li className="flex items-start gap-3">
              <span className="text-green-400 mt-0.5">'œ"</span>
              <span>Your account has been upgraded automatically</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="text-green-400 mt-0.5">'œ"</span>
              <span>All {planName} features are now unlocked</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="text-green-400 mt-0.5">'œ"</span>
              <span>Start your first security scan from the dashboard</span>
            </li>
            <li className="flex items-start gap-3">
              <span className="text-green-400 mt-0.5">'œ"</span>
              <span>Check your email for payment confirmation</span>
            </li>
          </ul>
        </div>

        {/* Redirect notice */}
        <p className="text-gray-500 text-sm mb-4">
          Redirecting to dashboard in {countdown} seconds...
        </p>

        {/* Action buttons */}
        <div className="flex gap-4 justify-center">
          <button
            onClick={() => navigate("/dashboard")}
            className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white font-medium rounded-xl transition-all shadow-lg hover:shadow-cyan-500/25"
          >
            Go to Dashboard
          </button>
          <button
            onClick={() => navigate("/dashboard/new-scan")}
            className="px-6 py-3 bg-gray-700 hover:bg-gray-600 text-white font-medium rounded-xl transition-colors"
          >
            Start a Scan
          </button>
        </div>

        {/* Support note */}
        <p className="mt-8 text-xs text-gray-500">
          Need help? Contact us at{" "}
          <a href="mailto:support@jarwis.ai" className="text-cyan-400 hover:underline">
            support@jarwis.ai
          </a>
        </p>
      </div>
    </div>
  );
};

export default PaymentSuccess;
