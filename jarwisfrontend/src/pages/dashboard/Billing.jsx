// src/pages/dashboard/Billing.jsx - Comprehensive Billing & Subscription Management
import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Sparkles, BarChart3, Search, Globe, Users, MessageSquare, History, FileText, RefreshCw, AlertCircle } from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useAuth } from "../../context/AuthContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { MiftyCard, MiftyPageHeader, MiftyBadge, MiftyButton } from "../../components/dashboard/MiftyDashboardComponents";

const API_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

const Billing = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { user, userDoc, token } = useAuth();
  const { currentPlan, usage, getAllUsageStats, canPerformAction, refreshSubscription, serverUsage } = useSubscription();
  
  const [billingData, setBillingData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState(null);
  const [paymentHistory, setPaymentHistory] = useState([]);
  const [savedCards, setSavedCards] = useState([]);

  // Fetch billing data from API
  const fetchBillingData = useCallback(async () => {
    if (!token) return;
    
    setLoading(true);
    try {
      // Fetch subscription details
      const response = await fetch(`${API_URL}/api/users/me/subscription`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      if (response.ok) {
        const data = await response.json();
        setBillingData(data);
      }

      // Fetch payment history
      const paymentsRes = await fetch(`${API_URL}/api/payments/history`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      if (paymentsRes.ok) {
        const payments = await paymentsRes.json();
        setPaymentHistory(payments.payments || []);
      }

      // Fetch saved cards
      const cardsRes = await fetch(`${API_URL}/api/payments/cards`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      
      if (cardsRes.ok) {
        const cards = await cardsRes.json();
        setSavedCards(cards.cards || []);
      }
      
      // Clear any previous errors on success
      setError(null);
    } catch (error) {
      console.error("Failed to fetch billing data:", error);
      setError("Failed to load billing information. Please try again.");
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => {
    fetchBillingData();
    // Also refresh subscription context on page load to get latest usage
    if (refreshSubscription) {
      refreshSubscription();
    }
  }, [fetchBillingData, refreshSubscription]);

  // Calculate next billing date
  const getNextBillingDate = () => {
    if (!billingData?.subscription?.current_period_end) {
      // Default to next month
      const next = new Date();
      next.setMonth(next.getMonth() + 1);
      next.setDate(1);
      return next;
    }
    return new Date(billingData.subscription.current_period_end);
  };

  // Get subscription start date
  const getSubscriptionStartDate = () => {
    if (userDoc?.subscription_start_date) {
      return new Date(userDoc.subscription_start_date);
    }
    if (userDoc?.created_at) {
      return new Date(userDoc.created_at);
    }
    return new Date();
  };

  // Format currency
  const formatCurrency = (amount, currency = "INR") => {
    const symbols = { INR: "Rs.", USD: "$", EUR: "EUR", GBP: "GBP" };
    return `${symbols[currency] || "Rs."}${(amount / 100).toFixed(2)}`;
  };

  // Format date
  const formatDate = (date) => {
    return new Date(date).toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  };

  // Get plan display info
  const getPlanInfo = () => {
    const planId = userDoc?.plan || currentPlan?.id || "trial";
    const plans = {
      trial: { name: "Trial Plan", price: 0, color: "cyan", icon: "🎯" },
      free: { name: "Free Plan", price: 0, color: "slate", icon: "🆓" },
      individual: { name: "Individual", price: 499, color: "blue", icon: "" },
      professional: { name: "Professional", price: 999, color: "purple", icon: "" },
      enterprise: { name: "Enterprise", price: null, color: "amber", icon: "" },
    };
    return plans[planId] || plans.trial;
  };

  const planInfo = getPlanInfo();
  const isPaid = userDoc?.plan && userDoc.plan !== "free" && userDoc.plan !== "trial";

  // Theme classes
  const cardBg = isDarkMode ? "bg-slate-800/50 border-slate-700/50" : "bg-white border-gray-200";
  const textPrimary = isDarkMode ? "text-white" : "text-gray-900";
  const textSecondary = isDarkMode ? "text-slate-400" : "text-gray-500";
  const textMuted = isDarkMode ? "text-slate-500" : "text-gray-400";

  if (loading) {
    return (
      <MiftyJarwisLayout>
        <div className="p-6 flex items-center justify-center min-h-[60vh]">
          <div className="flex flex-col items-center gap-4">
            <div className="w-12 h-12 border-4 border-purple-500/30 border-t-purple-500 rounded-full animate-spin" />
            <p className={textSecondary}>Loading billing information...</p>
          </div>
        </div>
      </MiftyJarwisLayout>
    );
  }

  return (
    <MiftyJarwisLayout>
      <div className="p-6 space-y-6">
        {/* Error Banner */}
        {error && (
          <div className={`rounded-xl border p-4 flex items-center gap-3 ${
            isDarkMode 
              ? "bg-red-900/20 border-red-700/50 text-red-400" 
              : "bg-red-50 border-red-200 text-red-700"
          }`}>
            <AlertCircle className="w-5 h-5 flex-shrink-0" />
            <span className="flex-1">{error}</span>
            <button 
              onClick={fetchBillingData}
              className={`px-3 py-1 rounded-lg text-sm font-medium ${
                isDarkMode 
                  ? "bg-red-800/50 hover:bg-red-800 text-red-300" 
                  : "bg-red-100 hover:bg-red-200 text-red-700"
              }`}
            >
              Retry
            </button>
          </div>
        )}

        {/* Page Header */}
        <MiftyPageHeader
          title="Billing & Subscription"
          subtitle="Manage your subscription, payment methods, and billing history"
          actions={
            <MiftyButton variant="secondary" onClick={() => navigate("/pricing")}>
              View All Plans
            </MiftyButton>
          }
        />

        {/* Current Subscription Card */}
        <div className={`rounded-2xl border p-6 ${cardBg}`}>
          <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-6">
            {/* Plan Info */}
            <div className="flex-1">
              <div className="flex items-center gap-3 mb-4">
                <span className="text-4xl">{planInfo.icon}</span>
                <div>
                  <h2 className={`text-2xl font-bold ${textPrimary}`}>{planInfo.name}</h2>
                  <div className="flex items-center gap-2 mt-1">
                    <MiftyBadge 
                      status={isPaid ? "success" : "info"} 
                      label={isPaid ? "Active" : "Free Tier"} 
                    />
                    {isPaid && (
                      <span className={`text-sm ${textSecondary}`}>
                        Renews {formatDate(getNextBillingDate())}
                      </span>
                    )}
                  </div>
                </div>
              </div>

              {/* Subscription Details */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                  <p className={`text-sm ${textSecondary} mb-1`}>Member Since</p>
                  <p className={`font-semibold ${textPrimary}`}>
                    {formatDate(getSubscriptionStartDate())}
                  </p>
                </div>
                
                {isPaid && (
                  <>
                    <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                      <p className={`text-sm ${textSecondary} mb-1`}>Billing Cycle</p>
                      <p className={`font-semibold ${textPrimary}`}>Monthly</p>
                    </div>
                    
                    <div className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                      <p className={`text-sm ${textSecondary} mb-1`}>Next Payment</p>
                      <p className={`font-semibold ${textPrimary}`}>
                        {formatCurrency(planInfo.price * 100)} on {formatDate(getNextBillingDate())}
                      </p>
                    </div>
                  </>
                )}
              </div>
            </div>

            {/* Action Buttons */}
            <div className="flex flex-col gap-3 min-w-[200px]">
              {!isPaid ? (
                <button
                  onClick={() => navigate("/pricing")}
                  className="px-6 py-3 rounded-xl font-bold text-white bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 shadow-lg shadow-purple-500/30 transition-all duration-300 hover:scale-105"
                >
                  <Sparkles className="w-4 h-4 inline mr-1" /> Upgrade Plan
                </button>
              ) : (
                <>
                  <button
                    onClick={() => navigate("/pricing")}
                    className={`px-6 py-3 rounded-xl font-medium border ${isDarkMode ? "border-slate-600 text-white hover:bg-slate-700" : "border-gray-300 text-gray-700 hover:bg-gray-50"} transition-all`}
                  >
                    Change Plan
                  </button>
                  <button
                    className={`px-6 py-3 rounded-xl font-medium text-red-500 border border-red-500/30 hover:bg-red-500/10 transition-all`}
                  >
                    Cancel Subscription
                  </button>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Usage Overview */}
        <div className={`rounded-2xl border p-6 ${cardBg}`}>
          <div className="flex items-center justify-between mb-4">
            <h3 className={`text-lg font-bold ${textPrimary} flex items-center gap-2`}>
              <BarChart3 className="w-5 h-5" /> Current Usage
            </h3>
            <button
              onClick={async () => {
                setRefreshing(true);
                try {
                  // Refresh subscription data from context (makes API call)
                  if (refreshSubscription) {
                    await refreshSubscription();
                  }
                  // Also refresh billing data
                  await fetchBillingData();
                } finally {
                  setRefreshing(false);
                }
              }}
              disabled={refreshing}
              className={`text-sm px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition-all ${
                refreshing ? "opacity-50 cursor-not-allowed" : ""
              } ${
                isDarkMode 
                  ? "bg-slate-700 hover:bg-slate-600 text-slate-300" 
                  : "bg-gray-100 hover:bg-gray-200 text-gray-600"
              }`}
            >
              <RefreshCw className={`w-4 h-4 ${refreshing ? "animate-spin" : ""}`} />
              {refreshing ? "Refreshing..." : "Refresh"}
            </button>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { 
                label: "Scans This Month", 
                used: serverUsage?.usage?.scans?.used ?? usage?.scansThisMonth ?? 0, 
                limit: serverUsage?.usage?.scans?.limit ?? currentPlan?.maxScansPerMonth ?? 3,
                unlimited: serverUsage?.usage?.scans?.unlimited ?? false,
                icon: <Search className="w-5 h-5" /> 
              },
              { 
                label: "Websites", 
                used: serverUsage?.usage?.websites?.used ?? usage?.websitesThisMonth ?? 0, 
                limit: serverUsage?.usage?.websites?.limit ?? currentPlan?.maxWebsitesPerMonth ?? 1,
                unlimited: serverUsage?.usage?.websites?.unlimited ?? false,
                icon: <Globe className="w-5 h-5" /> 
              },
              { 
                label: "Team Members", 
                used: serverUsage?.usage?.team_members?.used ?? usage?.teamMembers ?? 1, 
                limit: serverUsage?.usage?.team_members?.limit ?? currentPlan?.maxTeamMembers ?? 1,
                unlimited: serverUsage?.usage?.team_members?.unlimited ?? false,
                icon: <Users className="w-5 h-5" /> 
              },
              { 
                label: "AI Questions Today", 
                used: usage?.chatbotQuestionsToday ?? 0, 
                limit: currentPlan?.maxChatbotQuestionsPerDay ?? 0,
                unlimited: false,
                icon: <MessageSquare className="w-5 h-5" /> 
              },
            ].map((item, i) => {
              const percentage = item.limit === 0 ? 0 : Math.min(100, (item.used / item.limit) * 100);
              const isUnlimited = item.unlimited || item.limit === -1 || item.limit === Infinity;
              
              return (
                <div key={i} className={`p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xl">{item.icon}</span>
                    <span className={`text-sm font-medium ${textSecondary}`}>
                      {isUnlimited ? "Unlimited" : `${item.used}/${item.limit}`}
                    </span>
                  </div>
                  <p className={`text-sm font-medium ${textPrimary} mb-2`}>{item.label}</p>
                  {!isUnlimited && (
                    <div className={`h-2 rounded-full ${isDarkMode ? "bg-slate-600" : "bg-gray-200"}`}>
                      <div
                        className={`h-full rounded-full transition-all ${
                          percentage > 90 ? "bg-red-500" : percentage > 70 ? "bg-amber-500" : "bg-purple-500"
                        }`}
                        style={{ width: `${percentage}%` }}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Payment Methods */}
        <div className={`rounded-2xl border p-6 ${cardBg}`}>
          <div className="flex items-center justify-between mb-4">
            <h3 className={`text-lg font-bold ${textPrimary} flex items-center gap-2`}>
              <span></span> Payment Methods
            </h3>
            <button className={`text-sm font-medium ${isDarkMode ? "text-purple-400 hover:text-purple-300" : "text-purple-600 hover:text-purple-700"}`}>
              + Add Card
            </button>
          </div>

          {savedCards.length > 0 ? (
            <div className="space-y-3">
              {savedCards.map((card, i) => (
                <div key={i} className={`flex items-center justify-between p-4 rounded-xl ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-8 rounded flex items-center justify-center ${
                      card.brand === "visa" ? "bg-blue-600" : 
                      card.brand === "mastercard" ? "bg-red-600" : 
                      "bg-slate-600"
                    }`}>
                      <span className="text-white text-xs font-bold uppercase">{card.brand || "Card"}</span>
                    </div>
                    <div>
                      <p className={textPrimary}>**** **** **** {card.last4 || "****"}</p>
                      <p className={`text-sm ${textSecondary}`}>
                        Expires {card.exp_month || "**"}/{card.exp_year || "****"}
                      </p>
                    </div>
                    {card.is_default && (
                      <MiftyBadge status="info" label="Default" />
                    )}
                  </div>
                  <div className="flex items-center gap-2">
                    <button className={`text-sm ${isDarkMode ? "text-slate-400 hover:text-white" : "text-gray-500 hover:text-gray-700"}`}>
                      Edit
                    </button>
                    <button className="text-sm text-red-500 hover:text-red-400">
                      Remove
                    </button>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div className={`text-center py-8 rounded-xl ${isDarkMode ? "bg-slate-700/30" : "bg-gray-50"}`}>
              <span className="text-4xl mb-3 block"></span>
              <p className={textSecondary}>No payment methods saved</p>
              {isPaid && (
                <p className={`text-sm ${textMuted} mt-1`}>
                  Payment was processed through Razorpay checkout
                </p>
              )}
            </div>
          )}
        </div>

        {/* Billing History */}
        <div className={`rounded-2xl border p-6 ${cardBg}`}>
          <div className="flex items-center justify-between mb-4">
            <h3 className={`text-lg font-bold ${textPrimary} flex items-center gap-2`}>
              <History className="w-5 h-5" /> Billing History
            </h3>
            {paymentHistory.length > 0 && (
              <button className={`text-sm font-medium ${isDarkMode ? "text-purple-400 hover:text-purple-300" : "text-purple-600 hover:text-purple-700"}`}>
                Download All
              </button>
            )}
          </div>

          {paymentHistory.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className={`border-b ${isDarkMode ? "border-slate-700" : "border-gray-200"}`}>
                    <th className={`text-left py-3 px-4 text-sm font-semibold ${textSecondary}`}>Date</th>
                    <th className={`text-left py-3 px-4 text-sm font-semibold ${textSecondary}`}>Description</th>
                    <th className={`text-left py-3 px-4 text-sm font-semibold ${textSecondary}`}>Amount</th>
                    <th className={`text-left py-3 px-4 text-sm font-semibold ${textSecondary}`}>Status</th>
                    <th className={`text-right py-3 px-4 text-sm font-semibold ${textSecondary}`}>Invoice</th>
                  </tr>
                </thead>
                <tbody>
                  {paymentHistory.map((payment, i) => (
                    <tr key={i} className={`border-b last:border-0 ${isDarkMode ? "border-slate-700/50" : "border-gray-100"}`}>
                      <td className={`py-4 px-4 ${textPrimary}`}>
                        {formatDate(payment.created_at || payment.date)}
                      </td>
                      <td className={`py-4 px-4 ${textPrimary}`}>
                        {payment.description || `${planInfo.name} Subscription`}
                      </td>
                      <td className={`py-4 px-4 font-medium ${textPrimary}`}>
                        {formatCurrency(payment.amount, payment.currency)}
                      </td>
                      <td className="py-4 px-4">
                        <MiftyBadge 
                          status={payment.status === "paid" || payment.status === "succeeded" ? "success" : "warning"} 
                          label={payment.status || "Paid"} 
                        />
                      </td>
                      <td className="py-4 px-4 text-right">
                        <button className={`text-sm ${isDarkMode ? "text-purple-400 hover:text-purple-300" : "text-purple-600 hover:text-purple-700"}`}>
                          ⬇ Download
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className={`text-center py-8 rounded-xl ${isDarkMode ? "bg-slate-700/30" : "bg-gray-50"}`}>
              <span className="text-4xl mb-3 block"><FileText className="w-10 h-10 mx-auto text-gray-400" /></span>
              <p className={textSecondary}>No billing history</p>
              <p className={`text-sm ${textMuted} mt-1`}>
                {isPaid ? "Your first invoice will appear here after the billing cycle" : "Upgrade to a paid plan to see billing history"}
              </p>
            </div>
          )}
        </div>

        {/* Billing Information */}
        <div className={`rounded-2xl border p-6 ${cardBg}`}>
          <h3 className={`text-lg font-bold ${textPrimary} mb-4 flex items-center gap-2`}>
            <span></span> Billing Information
          </h3>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className={`block text-sm font-medium ${textSecondary} mb-2`}>Billing Email</label>
              <div className={`p-3 rounded-lg ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                <p className={textPrimary}>{userDoc?.email || user?.email || "Not set"}</p>
              </div>
            </div>
            
            <div>
              <label className={`block text-sm font-medium ${textSecondary} mb-2`}>Company Name</label>
              <div className={`p-3 rounded-lg ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                <p className={textPrimary}>{userDoc?.company || "Not set"}</p>
              </div>
            </div>

            <div className="md:col-span-2">
              <label className={`block text-sm font-medium ${textSecondary} mb-2`}>Billing Address</label>
              <div className={`p-3 rounded-lg ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                <p className={textPrimary}>{userDoc?.billing_address || "Not set"}</p>
              </div>
            </div>
          </div>

          <button className={`mt-4 px-4 py-2 rounded-lg text-sm font-medium ${isDarkMode ? "bg-slate-700 text-white hover:bg-slate-600" : "bg-gray-100 text-gray-700 hover:bg-gray-200"} transition-all`}>
            Edit Billing Information
          </button>
        </div>

        {/* Need Help */}
        <div className={`rounded-2xl border p-6 ${isDarkMode ? "bg-gradient-to-r from-purple-900/20 to-cyan-900/20 border-purple-500/20" : "bg-gradient-to-r from-purple-50 to-cyan-50 border-purple-200"}`}>
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div>
              <h3 className={`text-lg font-bold ${textPrimary} mb-1`}>Need Help with Billing?</h3>
              <p className={textSecondary}>
                Contact our support team for any billing questions or issues
              </p>
            </div>
            <button
              onClick={() => navigate("/contact")}
              className={`px-6 py-3 rounded-xl font-medium ${isDarkMode ? "bg-white/10 text-white hover:bg-white/20" : "bg-white text-purple-600 hover:bg-purple-50"} transition-all`}
            >
              Contact Support
            </button>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default Billing;
