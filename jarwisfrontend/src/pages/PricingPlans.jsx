import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Check, Sparkles, CreditCard, Shield, Lock } from "lucide-react";
import Footer from "../components/Footer";
import PaymentModal from "../components/payment/PaymentModal";
import { getUserCountry, getCurrencyInfo } from "../services/paymentService";
import { useAuth } from "../context/AuthContext";
import { ScrollProgressBar, RevealOnScroll, StaggerContainer, StaggerItem } from "../components/ui";

const PricingPlans = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  
  const [selectedPlan, setSelectedPlan] = useState(null);
  const [showPaymentModal, setShowPaymentModal] = useState(false);
  const [currencyInfo, setCurrencyInfo] = useState(null);
  const [isLoadingPrices, setIsLoadingPrices] = useState(true);

  // Load currency info based on location
  useEffect(() => {
    const loadCurrency = async () => {
      setIsLoadingPrices(true);
      try {
        const countryCode = await getUserCountry();
        const info = await getCurrencyInfo(countryCode);
        setCurrencyInfo(info);
      } catch (err) {
        console.error("Failed to load currency:", err);
        setCurrencyInfo({
          currency: "INR",
          symbol: "",
          plans: {
            individual: { amount: 100, display: "" },
            professional: { amount: 200, display: "" },
          },
        });
      } finally {
        setIsLoadingPrices(false);
      }
    };
    loadCurrency();
  }, []);

  const handlePlanClick = (planId) => {
    if (planId === "enterprise") {
      navigate("/contact");
    } else {
      setSelectedPlan(planId);
      setShowPaymentModal(true);
    }
  };

  const handlePaymentSuccess = (result) => {
    console.log("Payment successful:", result);
    // User will be redirected to dashboard by the modal
  };

  // Get price display for a plan
  const getPriceDisplay = (planId) => {
    if (isLoadingPrices) return "Loading...";
    if (!currencyInfo?.plans?.[planId]) {
      if (planId === "individual") return "";
      if (planId === "professional") return "";
      return "Custom";
    }
    return currencyInfo.plans[planId].display;
  };

  // Pricing data
  const plans = [
    {
      id: "individual",
      name: "Individuals",
      price: getPriceDisplay("individual"),
      priceSubtext: "per scan",
      buttonText: "Get Started",
      isPaid: true,
      keyCapabilities: [
        "Autonomous security analysis & reporting that detects vulnerabilities",
        "OWASP Top 10 & SANS Top 25 vulnerability detection",
        "DAST [Limited to Public Facing Pages]",
      ],
      usage: [
        "1 User Only",
        "1 Website Only",
        "Do not Cover API Testing",
        "No Credentials Based Scanning",
        "Dashboard and Reporting Access up to 7 Days",
        "Do not have Access to Jarwis AGI Chatbot",
      ],
    },
    {
      id: "professional",
      name: "Professional",
      price: getPriceDisplay("professional"),
      priceSubtext: "per month",
      buttonText: "Subscribe Now",
      isPaid: true,
      highlighted: true,
      keyCapabilities: [
        "Everything in Individual Plan",
        "DAST with Credentials based scanning",
        "Includes API Testing",
        "Mobile & Cloud Security Scanning",
        "Jarwis AGI - Suru 1.1 (500K tokens/month)",
      ],
      usage: [
        "Up to 3 Users can access dashboard",
        "10 Scans per month (Web, Mobile, Cloud, API)",
        "Dashboard Access until the plan is active",
      ],
    },
    {
      id: "enterprise",
      name: "Enterprise",
      price: "Custom pricing",
      priceSubtext: "Billed Annually",
      buttonText: "Contact us",
      isPaid: false,
      keyCapabilities: [
        "Everything in Professional Plan",
        "Unlimited Scans Anytime (Web, Mobile, Cloud, API)",
        "Jarwis AGI - Savi 3.1 Thinking (5M tokens/month)",
        "Best AI Model for Cybersecurity",
        "Compliance and Audits",
        "Dedicated Pentester & Auditor",
        "24x7 Call & Chat support",
      ],
      usage: ["Unlimited Everything", "Dashboard Access until the plan is active"],
    },
  ];

  return (
    <div className="min-h-screen p-4 sm:p-6 lg:p-8 relative">
      {/* Scroll Progress Bar */}
      <ScrollProgressBar />

      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <RevealOnScroll animation="fadeUp">
          <div className="mb-8 sm:mb-12 text-center space-y-3 sm:space-y-4">
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-light text-white mb-2">
            Choose a{" "}
            <span className="bg-gradient-to-r from-blue-500 to-cyan-400 bg-clip-text text-transparent">
              plan
            </span>
          </h1>
          <h2 className="text-3xl sm:text-4xl md:text-5xl font-light text-white">
            that's right for you
          </h2>

          <p className="text-base sm:text-lg text-gray-400 max-w-2xl mx-auto mb-6 sm:mb-10 px-4">
            Scale your cybersecurity with AI-powered protection. Start with
            pay-as-you-go, upgrade when you're ready.
          </p>

          {/* Currency indicator */}
          {currencyInfo && (
            <div className="inline-flex items-center gap-2 px-4 py-2 bg-gray-800/50 border border-gray-700 rounded-full text-sm text-gray-300">
              <span></span>
              <span>Prices shown in {currencyInfo.code}</span>
            </div>
          )}
          </div>
        </RevealOnScroll>

        {/* Pricing Cards */}
        <StaggerContainer className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6 lg:gap-8">
          {plans.map((plan, index) => (
            <StaggerItem key={index} direction="up">
              <div
                className={`relative bg-gray-800 rounded-xl sm:rounded-lg border transition-all duration-300 p-5 sm:p-6 lg:p-8 h-full ${
                plan.highlighted
                  ? "border-2 border-cyan-500 shadow-[0_0_40px_-10px_rgba(6,182,212,0.5)] order-first md:order-none"
                  : "border-t-2 border-teal-900 hover:border-teal-500 hover:shadow-lg hover:shadow-cyan-500/10"
              }`}
            >
              {/* Animated glow background for highlighted */}
              {plan.highlighted && (
                <div className="absolute inset-0 rounded-xl sm:rounded-lg bg-gradient-to-r from-cyan-500/10 via-blue-500/5 to-cyan-500/10 animate-pulse pointer-events-none" />
              )}
              
              {/* Popular badge */}
              {plan.highlighted && (
                <div className="relative mb-3 sm:mb-4">
                  <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-gradient-to-r from-cyan-500 to-blue-500 text-white text-xs font-semibold rounded-full shadow-lg shadow-cyan-500/30">
                    <Sparkles className="w-3 h-3" />
                    MOST POPULAR
                  </span>
                </div>
              )}

              <div className="mb-6 sm:mb-8">
                <h3 className="text-xl sm:text-2xl font-semibold text-white mb-2">
                  {plan.name}
                </h3>
                <div className="flex items-baseline gap-2 flex-wrap">
                  <span className={`text-2xl sm:text-3xl font-bold ${
                    plan.highlighted 
                      ? "text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400"
                      : "text-white"
                  }`}>
                    {plan.price}
                  </span>
                  {plan.priceSubtext && (
                    <span className="text-gray-500 text-xs sm:text-sm">
                      {plan.priceSubtext}
                    </span>
                  )}
                </div>
              </div>

              <button
                onClick={() => handlePlanClick(plan.id)}
                className={`w-full py-3 sm:py-3.5 px-4 sm:px-6 rounded-xl sm:rounded-md mb-6 sm:mb-8 transition-all duration-200 font-medium text-sm sm:text-base min-h-[48px] touch-target flex items-center justify-center gap-2 ${
                  plan.highlighted
                    ? "bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white shadow-lg hover:shadow-cyan-500/25"
                    : plan.id === "enterprise"
                    ? "bg-blue-500 hover:bg-blue-600 text-white border-t-2 border-t-teal-400"
                    : "bg-transparent border border-gray-600 text-white hover:bg-gray-700 hover:border-cyan-500"
                }`}
              >
                {plan.isPaid && (
                  <CreditCard className="w-4 h-4" />
                )}
                {plan.buttonText}
              </button>

              {/* Key Capabilities */}
              <div className="space-y-4 sm:space-y-6">
                <div>
                  <h4 className="text-white font-medium mb-2 sm:mb-3 text-sm sm:text-base">
                    Key Capabilities:
                  </h4>
                  <ul className="list-disc list-outside pl-4 sm:pl-5 text-gray-300 text-xs sm:text-sm space-y-1.5 sm:space-y-2">
                    {plan.keyCapabilities.map((cap, i) => (
                      <li key={i}>{cap}</li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h4 className="text-white font-medium mb-2 sm:mb-3 text-sm sm:text-base">
                    Usage & Limitations:
                  </h4>
                  <ul className="list-disc list-outside pl-4 sm:pl-5 text-gray-300 text-xs sm:text-sm space-y-1.5 sm:space-y-2">
                    {plan.usage.map((u, i) => (
                      <li key={i}>{u}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
            </StaggerItem>
          ))}
        </StaggerContainer>

        {/* Trust badges */}
        <div className="mt-10 sm:mt-16 text-center px-4">
          <div className="flex flex-col sm:flex-row flex-wrap items-center justify-center gap-4 sm:gap-8 text-gray-500">
            <div className="flex items-center gap-2">
              <Lock className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-500" />
              <span className="text-xs sm:text-sm">Secure Payments via Razorpay</span>
            </div>
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-500" />
              <span className="text-xs sm:text-sm">256-bit SSL Encryption</span>
            </div>
            <div className="flex items-center gap-2">
              <CreditCard className="w-4 h-4 sm:w-5 sm:h-5 text-cyan-500" />
              <span className="text-xs sm:text-sm">All Major Cards Accepted</span>
            </div>
          </div>
        </div>
      </div>

      {/* Payment Modal */}
      <PaymentModal
        isOpen={showPaymentModal}
        onClose={() => setShowPaymentModal(false)}
        selectedPlan={selectedPlan}
        onPaymentSuccess={handlePaymentSuccess}
      />

      <Footer />
    </div>
  );
};

export default PricingPlans;
