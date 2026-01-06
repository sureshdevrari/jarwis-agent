// src/components/subscription/QuickUsageIndicator.jsx
// A compact usage indicator for sidebar or header
import { useSubscription } from "../../context/SubscriptionContext";

const QuickUsageIndicator = ({ isDarkMode, showLabel = true }) => {
  const { currentPlan, getAllUsageStats, subscriptionStatus } = useSubscription();
  const usage = getAllUsageStats();
  
  const scans = usage?.scans;
  if (!scans) return null;
  
  // Don't show for unlimited plans
  if (scans.unlimited) {
    return (
      <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm ${
        isDarkMode ? "bg-green-500/10 text-green-400" : "bg-green-50 text-green-700"
      }`}>
        <span>∞</span>
        {showLabel && <span>Unlimited Scans</span>}
      </div>
    );
  }
  
  const percentage = scans.percentage || 0;
  const isLow = percentage >= 90;
  const isMedium = percentage >= 70 && percentage < 90;
  
  const getColor = () => {
    if (isLow) return isDarkMode ? "text-red-400 bg-red-500/10" : "text-red-600 bg-red-50";
    if (isMedium) return isDarkMode ? "text-amber-400 bg-amber-500/10" : "text-amber-600 bg-amber-50";
    return isDarkMode ? "text-blue-400 bg-blue-500/10" : "text-blue-600 bg-blue-50";
  };
  
  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm ${getColor()}`}>
      <div className="flex items-center gap-1">
        <span>{scans.current}</span>
        <span className="opacity-60">/</span>
        <span>{scans.max}</span>
      </div>
      {showLabel && (
        <span className="opacity-80">
          {isLow ? "scans left!" : "scans"}
        </span>
      )}
      
      {/* Mini progress bar */}
      <div className={`w-12 h-1.5 rounded-full overflow-hidden ${isDarkMode ? "bg-gray-700" : "bg-gray-200"}`}>
        <div 
          className={`h-full rounded-full transition-all ${
            isLow ? "bg-red-500" : isMedium ? "bg-amber-500" : "bg-blue-500"
          }`}
          style={{ width: `${Math.min(percentage, 100)}%` }}
        />
      </div>
    </div>
  );
};

export default QuickUsageIndicator;
