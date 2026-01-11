// src/components/subscription/PlanUsageCard.jsx
// Displays current plan usage and limits
import { useNavigate } from "react-router-dom";
import { AlertTriangle, Clock } from "lucide-react";
import { useSubscription } from "../../context/SubscriptionContext";

const PlanUsageCard = ({ isDarkMode, showUpgrade = true, compact = false }) => {
  const navigate = useNavigate();
  const { currentPlan, getAllUsageStats, subscriptionStatus } = useSubscription();
  const usageStats = getAllUsageStats();

  const themeClasses = {
    card: isDarkMode
      ? "p-5 bg-gray-800/50 border border-gray-700 rounded-xl"
      : "p-5 bg-white border border-gray-200 rounded-xl shadow-sm",
    title: isDarkMode ? "text-white" : "text-gray-900",
    text: isDarkMode ? "text-gray-300" : "text-gray-700",
    textMuted: isDarkMode ? "text-gray-500" : "text-gray-400",
    progressBg: isDarkMode ? "bg-gray-700" : "bg-gray-200",
    badge: (color) => {
      const colors = {
        gray: isDarkMode ? "bg-gray-600/30 text-gray-300 border-gray-500/30" : "bg-gray-100 text-gray-700 border-gray-300",
        blue: isDarkMode ? "bg-blue-500/20 text-blue-300 border-blue-500/30" : "bg-blue-100 text-blue-700 border-blue-300",
        purple: isDarkMode ? "bg-purple-500/20 text-purple-300 border-purple-500/30" : "bg-purple-100 text-purple-700 border-purple-300",
        amber: isDarkMode ? "bg-amber-500/20 text-amber-300 border-amber-500/30" : "bg-amber-100 text-amber-700 border-amber-300",
      };
      return colors[color] || colors.gray;
    },
  };

  const getProgressColor = (percentage) => {
    if (percentage >= 90) return "bg-red-500";
    if (percentage >= 70) return "bg-yellow-500";
    return "bg-blue-500";
  };

  const renderUsageBar = (stat) => {
    if (stat.unlimited) {
      return (
        <div className="flex items-center gap-2">
          <span className={`text-sm font-medium ${themeClasses.text}`}>
            {stat.current || 0} used
          </span>
          <span className={`text-xs px-2 py-0.5 rounded-full ${isDarkMode ? "bg-green-500/20 text-green-400" : "bg-green-100 text-green-700"}`}>
            Unlimited
          </span>
        </div>
      );
    }

    return (
      <div className="space-y-1">
        <div className="flex justify-between text-sm">
          <span className={themeClasses.text}>
            {stat.current || 0} / {stat.max}
          </span>
          <span className={`font-medium ${stat.percentage >= 90 ? "text-red-500" : stat.percentage >= 70 ? "text-yellow-500" : themeClasses.textMuted}`}>
            {stat.remaining === 0 ? "Limit reached" : `${stat.remaining} remaining`}
          </span>
        </div>
        <div className={`h-2 rounded-full ${themeClasses.progressBg} overflow-hidden`}>
          <div 
            className={`h-full rounded-full transition-all duration-300 ${getProgressColor(stat.percentage)}`}
            style={{ width: `${stat.percentage}%` }}
          />
        </div>
      </div>
    );
  };

  if (compact) {
    return (
      <div className={themeClasses.card}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <span className="text-xl">{currentPlan.badge}</span>
            <span className={`font-semibold ${themeClasses.title}`}>{currentPlan.name}</span>
          </div>
          {showUpgrade && currentPlan.id !== "enterprise" && (
            <button 
              onClick={() => navigate("/pricing")}
              className={`text-sm font-medium ${isDarkMode ? "text-blue-400 hover:text-blue-300" : "text-blue-600 hover:text-blue-700"}`}
            >
              Upgrade &rarr;
            </button>
          )}
        </div>
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className={themeClasses.textMuted}>Scans</span>
            <span className={themeClasses.text}>
              {usageStats.scans.unlimited ? "Unlimited" : `${usageStats.scans.current}/${usageStats.scans.max}`}
            </span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className={themeClasses.textMuted}>Team</span>
            <span className={themeClasses.text}>
              {usageStats.teamMembers.unlimited ? "Unlimited" : `${usageStats.teamMembers.current}/${usageStats.teamMembers.max}`}
            </span>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={themeClasses.card}>
      {/* Plan Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <span className="text-3xl">{currentPlan.badge}</span>
            <div>
              <h3 className={`text-xl font-bold ${themeClasses.title}`}>{currentPlan.name} Plan</h3>
              <p className={themeClasses.textMuted}>{currentPlan.price}</p>
            </div>
          </div>
        </div>
        <div className={`px-3 py-1.5 rounded-full border ${themeClasses.badge(currentPlan.color)}`}>
          {subscriptionStatus.isActive ? "Active" : "Expired"}
        </div>
      </div>

      {/* Subscription Status */}
      {subscriptionStatus.expiresAt && (
        <div className={`mb-6 p-3 rounded-lg ${
          subscriptionStatus.isExpiringSoon 
            ? (isDarkMode ? "bg-yellow-500/10 border border-yellow-500/30" : "bg-yellow-50 border border-yellow-200")
            : (isDarkMode ? "bg-gray-700/50" : "bg-gray-50")
        }`}>
          <div className="flex items-center gap-2">
            <span>{subscriptionStatus.isExpiringSoon ? <AlertTriangle className="w-4 h-4 text-yellow-500" /> : <Clock className="w-4 h-4" />}</span>
            <span className={themeClasses.text}>
              {subscriptionStatus.isExpiringSoon 
                ? `Expires in ${subscriptionStatus.daysRemaining} days` 
                : `Renews on ${subscriptionStatus.expiresAt.toLocaleDateString()}`}
            </span>
          </div>
        </div>
      )}

      {/* Usage Stats */}
      <div className="space-y-5">
        <h4 className={`font-semibold ${themeClasses.title}`}>Usage This Month</h4>
        
        {/* Scans */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span>🔍</span>
            <span className={`font-medium ${themeClasses.text}`}>Scans</span>
          </div>
          {renderUsageBar(usageStats.scans)}
        </div>

        {/* Team Members */}
        <div>
          <div className="flex items-center gap-2 mb-2">
            <span></span>
            <span className={`font-medium ${themeClasses.text}`}>Team Members</span>
          </div>
          {renderUsageBar(usageStats.teamMembers)}
        </div>
      </div>

      {/* Plan Limits */}
      <div className={`mt-6 pt-6 border-t ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
        <h4 className={`font-semibold mb-4 ${themeClasses.title}`}>Plan Limits</h4>
        <div className="grid grid-cols-2 gap-4">
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-gray-50"}`}>
            <p className={`text-sm ${themeClasses.textMuted}`}>Pages per scan</p>
            <p className={`font-semibold ${themeClasses.title}`}>
              {usageStats.pagesPerScan.unlimited ? "Unlimited" : usageStats.pagesPerScan.max}
            </p>
          </div>
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-gray-50"}`}>
            <p className={`text-sm ${themeClasses.textMuted}`}>Dashboard access</p>
            <p className={`font-semibold ${themeClasses.title}`}>
              {usageStats.dashboardAccess.unlimited ? "Unlimited" : `${usageStats.dashboardAccess.max} days`}
            </p>
          </div>
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-gray-50"}`}>
            <p className={`text-sm ${themeClasses.textMuted}`}>Report retention</p>
            <p className={`font-semibold ${themeClasses.title}`}>
              {usageStats.reportRetention.unlimited ? "Forever" : `${usageStats.reportRetention.max} days`}
            </p>
          </div>
          <div className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-gray-50"}`}>
            <p className={`text-sm ${themeClasses.textMuted}`}>Support level</p>
            <p className={`font-semibold ${themeClasses.title} capitalize`}>
              {currentPlan.supportLevel}
            </p>
          </div>
        </div>
      </div>

      {/* Upgrade Button */}
      {showUpgrade && currentPlan.id !== "enterprise" && (
        <div className="mt-6">
          <button 
            onClick={() => navigate("/pricing")}
            className={`w-full py-3 px-4 rounded-xl font-medium transition-all ${
              isDarkMode 
                ? "bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white"
                : "bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-lg"
            }`}
          >
            ⬆ Upgrade Plan
          </button>
        </div>
      )}
    </div>
  );
};

export default PlanUsageCard;
