// src/components/payment/PaymentModal.jsx
// Modal for Razorpay payment processing
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Check } from "lucide-react";
import { useAuth } from "../../context/AuthContext";
import {
  getUserCountry,
  getCurrencyInfo,
  initiatePayment,
} from "../../services/paymentService";

const PaymentModal = ({ isOpen, onClose, selectedPlan, onPaymentSuccess }) => {
  const navigate = useNavigate();
  const { user, token, refreshUser } = useAuth();
  
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [currencyInfo, setCurrencyInfo] = useState(null);
  const [email, setEmail] = useState(user?.email || "");
  const [isLoadingCurrency, setIsLoadingCurrency] = useState(true);

  // Plan display names and features
  const planDetails = {
    individual: {
      name: "Individual",
      color: "blue",
      icon: "⭐",
      features: [
        "1 User Only",
        "1 Website scan per month",
        "Basic OWASP Top 10 detection",
        "7-day dashboard access",
        "HTML report export",
      ],
    },
    professional: {
      name: "Professional",
      color: "purple",
      icon: "",
      features: [
        "Up to 3 team members",
        "10 Websites per month",
        "API Testing included",
        "Credential-based scanning",
        "AI Chatbot access",
        "365-day dashboard access",
      ],
    },
  };

  // Load currency info on mount
  useEffect(() => {
    const loadCurrencyInfo = async () => {
      setIsLoadingCurrency(true);
      try {
        const countryCode = await getUserCountry();
        const info = await getCurrencyInfo(countryCode);
        setCurrencyInfo(info);
      } catch (err) {
        console.error("Failed to load currency:", err);
        // Fallback to INR
        setCurrencyInfo({
          currency: "INR",
          symbol: "Rs.",
          plans: {
            individual: { amount: 100, display: "Rs.1" },
            professional: { amount: 200, display: "Rs.2" },
          },
        });
      } finally {
        setIsLoadingCurrency(false);
      }
    };
    
    if (isOpen) {
      loadCurrencyInfo();
    }
  }, [isOpen]);

  const handlePayment = async () => {
    if (!email) {
      setError("Please enter your email address");
      return;
    }
    
    setLoading(true);
    setError(null);
    
    try {
      await initiatePayment({
        plan: selectedPlan,
        currency: currencyInfo?.currency || "INR",
        token,
        email,
        userName: user?.full_name || user?.username || "",
        onSuccess: async (result) => {
          setLoading(false);
          // Refresh user data to get updated plan
          if (refreshUser) {
            await refreshUser();
          }
          onPaymentSuccess?.(result);
          onClose();
          
          // Navigate to payment success page
          navigate("/payment-success", { 
            state: { 
              plan: selectedPlan,
              success: true,
            } 
          });
        },
        onError: (err) => {
          setLoading(false);
          setError(err.message || "Payment failed. Please try again.");
        },
        onClose: () => {
          setLoading(false);
        },
      });
    } catch (err) {
      setLoading(false);
      setError(err.message || "Failed to initiate payment");
    }
  };

  if (!isOpen) return null;

  const plan = planDetails[selectedPlan];
  const price = currencyInfo?.plans?.[selectedPlan]?.display || "Loading...";

  return (
    <div className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-0 sm:p-4">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/70 backdrop-blur-sm"
        onClick={onClose}
      />
      
      {/* Modal */}
      <div className="relative bg-gray-900 border border-gray-700 rounded-t-2xl sm:rounded-2xl w-full sm:max-w-md p-5 sm:p-6 shadow-2xl animate-in fade-in slide-in-from-bottom-4 sm:zoom-in duration-200 max-h-[90vh] overflow-y-auto safe-area-inset-bottom">
        {/* Close button */}
        <button
          onClick={onClose}
          className="absolute top-3 sm:top-4 right-3 sm:right-4 text-gray-400 hover:text-white transition-colors min-w-[44px] min-h-[44px] flex items-center justify-center active:scale-95"
        >
          <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
          </svg>
        </button>

        {/* Header */}
        <div className="text-center mb-5 sm:mb-6">
          <span className="text-3xl sm:text-4xl mb-2 block">{plan?.icon}</span>
          <h2 className="text-xl sm:text-2xl font-bold text-white mb-1">
            {plan?.name} Plan
          </h2>
          <div className="text-2xl sm:text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-500">
            {isLoadingCurrency ? (
              <span className="animate-pulse">Loading...</span>
            ) : (
              price
            )}
          </div>
          <p className="text-gray-400 text-xs sm:text-sm mt-1">
            {selectedPlan === "individual" ? "per scan" : "per month"}
          </p>
        </div>

        {/* Features */}
        <div className="mb-5 sm:mb-6">
          <h3 className="text-xs sm:text-sm font-semibold text-gray-300 mb-2 sm:mb-3">What's included:</h3>
          <ul className="space-y-1.5 sm:space-y-2">
            {plan?.features.map((feature, i) => (
              <li key={i} className="flex items-center gap-2 text-xs sm:text-sm text-gray-300">
                <span className="text-green-400 flex-shrink-0"><Check className="w-4 h-4" /></span>
                {feature}
              </li>
            ))}
          </ul>
        </div>

        {/* Email input if not logged in */}
        {!user && (
          <div className="mb-4">
            <label className="block text-xs sm:text-sm font-medium text-gray-300 mb-1.5 sm:mb-2">
              Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
              className="w-full px-3 sm:px-4 py-3 bg-gray-800 border border-gray-600 rounded-lg text-white text-base placeholder-gray-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 min-h-[48px]"
              autoComplete="email"
            />
            <p className="text-xs text-gray-500 mt-1.5">
              You'll receive payment confirmation at this email
            </p>
          </div>
        )}

        {/* Error display */}
        {error && (
          <div className="mb-4 p-3 bg-red-500/20 border border-red-500/50 rounded-lg text-red-400 text-xs sm:text-sm">
            {error}
          </div>
        )}

        {/* Payment button */}
        <button
          onClick={handlePayment}
          disabled={loading || isLoadingCurrency}
          className={`w-full py-3.5 sm:py-4 px-6 rounded-xl font-semibold text-white transition-all duration-200 min-h-[48px] touch-target active:scale-[0.98] text-sm sm:text-base ${
            loading || isLoadingCurrency
              ? "bg-gray-600 cursor-not-allowed"
              : "bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 shadow-lg hover:shadow-cyan-500/25"
          }`}
        >
          {loading ? (
            <span className="flex items-center justify-center gap-2">
              <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Processing...
            </span>
          ) : (
            `Pay ${price}`
          )}
        </button>

        {/* Security note */}
        <div className="mt-4 flex items-center justify-center gap-2 text-xs text-gray-500">
          <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          Secured by Razorpay
        </div>

        {/* Currency info */}
        {currencyInfo && (
          <p className="text-center text-xs text-gray-500 mt-2 pb-2">
            Currency: {currencyInfo.currency} ({currencyInfo.symbol})
          </p>
        )}
      </div>
    </div>
  );
};

export default PaymentModal;
