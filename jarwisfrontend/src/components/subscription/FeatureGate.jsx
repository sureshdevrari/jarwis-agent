// src/components/subscription/FeatureGate.jsx
// Component to gate features based on subscription plan
import { useNavigate } from "react-router-dom";
import { Lock } from "lucide-react";
import { useSubscription } from "../../context/SubscriptionContext";

// Feature Gate - wraps content that requires specific features
export const FeatureGate = ({ 
  feature, 
  children, 
  fallback = null,
  showUpgradePrompt = true,
  isDarkMode = true 
}) => {
  const navigate = useNavigate();
  const { checkFeature, getUpgradeMessage } = useSubscription();

  const hasAccess = checkFeature(feature);

  if (hasAccess) {
    return children;
  }

  if (fallback) {
    return fallback;
  }

  if (!showUpgradePrompt) {
    return null;
  }

  const upgradeInfo = getUpgradeMessage(feature);

  return (
    <div className={`p-6 rounded-xl text-center ${
      isDarkMode 
        ? "bg-gray-800/50 border border-gray-700" 
        : "bg-gray-50 border border-gray-200"
    }`}>
      <div className="text-4xl mb-3"><Lock className="w-10 h-10 mx-auto text-gray-400" /></div>
      <h3 className={`text-lg font-semibold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
        Feature Locked
      </h3>
      <p className={`mb-4 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
        {upgradeInfo.message}
      </p>
      <button
        onClick={() => navigate("/pricing")}
        className="px-6 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-lg font-medium hover:from-blue-500 hover:to-cyan-500 transition-all"
      >
        View Plans
      </button>
    </div>
  );
};

// Usage Gate - wraps content that requires usage quota
export const UsageGate = ({ 
  action, 
  children, 
  onLimitReached,
  showUpgradePrompt = true,
  isDarkMode = true 
}) => {
  const navigate = useNavigate();
  const { canPerformAction, getActionLimit } = useSubscription();

  const hasQuota = canPerformAction(action);

  if (hasQuota) {
    return children;
  }

  if (onLimitReached) {
    onLimitReached();
  }

  if (!showUpgradePrompt) {
    return null;
  }

  const limit = getActionLimit(action.replace("start", "").replace("add", "").replace("use", "").toLowerCase() + "s");

  return (
    <div className={`p-6 rounded-xl text-center ${
      isDarkMode 
        ? "bg-gray-800/50 border border-gray-700" 
        : "bg-gray-50 border border-gray-200"
    }`}>
      <div className="text-4xl mb-3"><Lock className="w-10 h-10 mx-auto text-gray-400" /></div>
      <h3 className={`text-lg font-semibold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
        Limit Reached
      </h3>
      <p className={`mb-4 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
        You've used all {limit?.max || "available"} {limit?.label?.toLowerCase() || "items"} for this month.
        Upgrade your plan for more capacity.
      </p>
      <button
        onClick={() => navigate("/pricing")}
        className="px-6 py-2 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-lg font-medium hover:from-blue-500 hover:to-cyan-500 transition-all"
      >
        Upgrade Now
      </button>
    </div>
  );
};

// Pro Badge - shows a "PRO" badge for pro features
export const ProBadge = ({ className = "" }) => {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-gradient-to-r from-purple-500/20 to-pink-500/20 text-purple-400 border border-purple-500/30 ${className}`}>
      PRO
    </span>
  );
};

// Enterprise Badge
export const EnterpriseBadge = ({ className = "" }) => {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-gradient-to-r from-amber-500/20 to-yellow-500/20 text-amber-400 border border-amber-500/30 ${className}`}>
      ENTERPRISE
    </span>
  );
};

// Feature Chip - shows feature with lock icon if not available
export const FeatureChip = ({ feature, label, icon, isDarkMode = true }) => {
  const { checkFeature } = useSubscription();
  const hasAccess = checkFeature(feature);

  return (
    <div className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-lg ${
      hasAccess
        ? (isDarkMode ? "bg-green-500/10 text-green-400 border border-green-500/30" : "bg-green-50 text-green-700 border border-green-200")
        : (isDarkMode ? "bg-gray-700/50 text-gray-500 border border-gray-600" : "bg-gray-100 text-gray-400 border border-gray-200")
    }`}>
      <span>{hasAccess ? icon : <Lock className="w-4 h-4" />}</span>
      <span className="text-sm font-medium">{label}</span>
      {!hasAccess && <ProBadge />}
    </div>
  );
};

// Hook for checking feature access imperatively
export const useFeatureAccess = (feature) => {
  const { checkFeature, getUpgradeMessage } = useSubscription();
  const hasAccess = checkFeature(feature);
  const upgradeInfo = getUpgradeMessage(feature);
  
  return { hasAccess, upgradeInfo };
};

// Hook for checking usage limits imperatively
export const useUsageLimit = (action) => {
  const { canPerformAction, getActionLimit } = useSubscription();
  const hasQuota = canPerformAction(action);
  const limitInfo = getActionLimit(action);
  
  return { hasQuota, limitInfo };
};

export default FeatureGate;
