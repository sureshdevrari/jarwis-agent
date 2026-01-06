// src/pages/dashboard/JarwisDashboard.jsx - Modern Premium Dashboard with Animations
import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
// Use the new Mifty-styled layout for modern dashboard experience
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { scanAPI } from "../../services/api";
import {
  MiftyStatCard,
  MiftyPageHeader,
  MiftyCard,
  MiftySectionTitle,
  MiftyBadge,
  MiftyQuickAction,
  MiftyProgressBar,
} from "../../components/dashboard/MiftyDashboardComponents";

// =============================================
// ANIMATED COMPONENTS
// =============================================

// Animated counter that smoothly counts up
const AnimatedCounter = ({ value, duration = 1500 }) => {
  const [count, setCount] = useState(0);
  
  useEffect(() => {
    const target = parseInt(value) || 0;
    if (target === 0) {
      setCount(0);
      return;
    }
    
    const startTime = performance.now();
    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      
      // Easing function for smooth animation
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      setCount(Math.floor(easeOutQuart * target));
      
      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };
    
    requestAnimationFrame(animate);
  }, [value, duration]);
  
  return <span>{count.toLocaleString()}</span>;
};

// Glassmorphism Card Component with hover effects
const GlassCard = ({ 
  children, 
  className = "", 
  hover = true, 
  onClick, 
  isDarkMode,
  gradient = false,
  glow = false,
  highlighted = false 
}) => {
  // Use highlighted function-card styling for main content areas
  if (highlighted) {
    return (
      <div 
        className={`
          ${isDarkMode ? "function-card-dark" : "function-card-light"}
          ${onClick ? 'cursor-pointer' : 'cursor-default'}
          ${className}
        `}
        onClick={onClick}
      >
        {children}
      </div>
    );
  }

  const baseClasses = isDarkMode
    ? "backdrop-blur-xl bg-gradient-to-br from-white/[0.08] to-white/[0.02] border border-white/[0.08] rounded-2xl"
    : "backdrop-blur-xl bg-gradient-to-br from-white/80 to-white/60 border border-gray-200/60 rounded-2xl shadow-lg";
  
  const hoverClasses = hover
    ? isDarkMode
      ? `hover:from-white/[0.12] hover:to-white/[0.05] hover:border-white/[0.15] 
         hover:shadow-2xl hover:shadow-cyan-500/10 
         hover:-translate-y-1 hover:scale-[1.01]
         active:scale-[0.99] active:translate-y-0`
      : `hover:from-white hover:to-white/90 hover:border-gray-300/80 
         hover:shadow-2xl hover:shadow-black/10 
         hover:-translate-y-1 hover:scale-[1.01]
         active:scale-[0.99] active:translate-y-0`
    : "";
  
  const glowClasses = glow && isDarkMode
    ? "ring-1 ring-cyan-500/20 shadow-lg shadow-cyan-500/5"
    : glow && !isDarkMode
    ? "ring-1 ring-blue-500/20 shadow-lg shadow-blue-500/10"
    : "";
  
  return (
    <div 
      className={`
        transition-all duration-500 ease-out cursor-${onClick ? 'pointer' : 'default'}
        ${baseClasses} ${hoverClasses} ${glowClasses} ${className}
      `}
      onClick={onClick}
    >
      {children}
    </div>
  );
};

// Gradient animated button
const GradientButton = ({ 
  children, 
  onClick, 
  variant = "primary", 
  size = "md", 
  className = "", 
  icon,
  loading = false,
  disabled = false 
}) => {
  const variants = {
    primary: `bg-gradient-to-r from-cyan-500 via-blue-500 to-purple-500 
              hover:from-cyan-400 hover:via-blue-400 hover:to-purple-400 
              text-white shadow-lg shadow-cyan-500/30 hover:shadow-cyan-500/50
              before:absolute before:inset-0 before:bg-gradient-to-r before:from-transparent before:via-white/20 before:to-transparent
              before:-translate-x-full hover:before:translate-x-full before:transition-transform before:duration-700`,
    secondary: `bg-gradient-to-r from-gray-700 to-gray-600 
                hover:from-gray-600 hover:to-gray-500 
                text-white shadow-lg shadow-gray-900/30`,
    success: `bg-gradient-to-r from-emerald-500 to-teal-500 
              hover:from-emerald-400 hover:to-teal-400 
              text-white shadow-lg shadow-emerald-500/30 hover:shadow-emerald-500/50`,
    danger: `bg-gradient-to-r from-red-500 to-rose-500 
             hover:from-red-400 hover:to-rose-400 
             text-white shadow-lg shadow-red-500/30`,
    ghost: `bg-transparent border-2 border-white/20 
            hover:border-white/40 hover:bg-white/5 text-white`,
  };
  
  const sizes = {
    sm: "px-4 py-2 text-sm",
    md: "px-6 py-3 text-base",
    lg: "px-8 py-4 text-lg",
  };
  
  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className={`
        relative overflow-hidden
        ${variants[variant]} ${sizes[size]}
        rounded-xl font-semibold
        transform transition-all duration-300 ease-out
        hover:scale-105 active:scale-95
        flex items-center justify-center gap-2
        disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100
        ${className}
      `}
    >
      {loading ? (
        <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      ) : (
        <>
          {icon && <span className="text-lg">{icon}</span>}
          {children}
        </>
      )}
    </button>
  );
};

// Animated Stat Card
const StatCard = ({ 
  label, 
  value, 
  icon, 
  trend, 
  trendUp, 
  color = "blue", 
  isDarkMode, 
  delay = 0,
  subtitle 
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [isHovered, setIsHovered] = useState(false);
  
  useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), delay);
    return () => clearTimeout(timer);
  }, [delay]);
  
  const colorSchemes = {
    blue: {
      gradient: "from-blue-500 to-cyan-400",
      iconBg: isDarkMode ? "bg-blue-500/15 border-blue-500/20" : "bg-blue-50 border-blue-200",
      iconText: isDarkMode ? "text-blue-400" : "text-blue-600",
      glow: "shadow-blue-500/20",
    },
    red: {
      gradient: "from-red-500 to-rose-400",
      iconBg: isDarkMode ? "bg-red-500/15 border-red-500/20" : "bg-red-50 border-red-200",
      iconText: isDarkMode ? "text-red-400" : "text-red-600",
      glow: "shadow-red-500/20",
    },
    amber: {
      gradient: "from-amber-500 to-orange-400",
      iconBg: isDarkMode ? "bg-amber-500/15 border-amber-500/20" : "bg-amber-50 border-amber-200",
      iconText: isDarkMode ? "text-amber-400" : "text-amber-600",
      glow: "shadow-amber-500/20",
    },
    green: {
      gradient: "from-emerald-500 to-teal-400",
      iconBg: isDarkMode ? "bg-emerald-500/15 border-emerald-500/20" : "bg-emerald-50 border-emerald-200",
      iconText: isDarkMode ? "text-emerald-400" : "text-emerald-600",
      glow: "shadow-emerald-500/20",
    },
    purple: {
      gradient: "from-purple-500 to-pink-400",
      iconBg: isDarkMode ? "bg-purple-500/15 border-purple-500/20" : "bg-purple-50 border-purple-200",
      iconText: isDarkMode ? "text-purple-400" : "text-purple-600",
      glow: "shadow-purple-500/20",
    },
    cyan: {
      gradient: "from-cyan-500 to-blue-400",
      iconBg: isDarkMode ? "bg-cyan-500/15 border-cyan-500/20" : "bg-cyan-50 border-cyan-200",
      iconText: isDarkMode ? "text-cyan-400" : "text-cyan-600",
      glow: "shadow-cyan-500/20",
    },
  };
  
  const colors = colorSchemes[color] || colorSchemes.blue;
  
  return (
    <div 
      className={`
        transform transition-all duration-700 ease-out
        ${isVisible ? 'opacity-100 translate-y-0' : 'opacity-0 translate-y-8'}
      `}
      onMouseEnter={() => setIsHovered(true)}
      onMouseLeave={() => setIsHovered(false)}
    >
      <GlassCard isDarkMode={isDarkMode} className={`p-6 group ${isHovered ? `shadow-xl ${colors.glow}` : ''}`}>
        {/* Background gradient on hover */}
        <div className={`
          absolute inset-0 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-500
          bg-gradient-to-br ${colors.gradient} blur-3xl -z-10
        `} style={{ opacity: isHovered ? 0.05 : 0 }} />
        
        <div className="flex items-start justify-between mb-4">
          <div className={`
            p-3.5 rounded-xl border ${colors.iconBg}
            transition-all duration-500 ease-out
            group-hover:scale-110 group-hover:rotate-6
            ${isHovered ? `shadow-lg ${colors.glow}` : ''}
          `}>
            <span className={`text-2xl ${colors.iconText} transition-transform duration-300`}>
              {icon}
            </span>
          </div>
          
          {trend && (
            <div className={`
              flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold
              transition-all duration-300 group-hover:scale-105
              ${trendUp 
                ? isDarkMode 
                  ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" 
                  : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                : isDarkMode 
                  ? "bg-red-500/15 text-red-400 border border-red-500/20" 
                  : "bg-red-50 text-red-700 border border-red-200"
              }
            `}>
              <span className="transition-transform duration-300 group-hover:scale-125">
                {trendUp ? "" : ""}
              </span>
              <span>{trend}</span>
            </div>
          )}
        </div>
        
        <p className={`text-sm font-medium mb-2 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
          {label}
        </p>
        
        <p className={`text-4xl font-bold mb-1 bg-gradient-to-r ${colors.gradient} bg-clip-text text-transparent`}>
          <AnimatedCounter value={value} />
        </p>
        
        {subtitle && (
          <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
            {subtitle}
          </p>
        )}
      </GlassCard>
    </div>
  );
};

// Quick Action Button with shimmer effect
const QuickActionButton = ({ 
  icon, 
  label, 
  sublabel, 
  onClick, 
  color = "blue", 
  isDarkMode,
  badge,
  locked = false,
  lockedMessage = "Upgrade to Pro"
}) => {
  const colorClasses = {
    blue: {
      bg: isDarkMode 
        ? "from-blue-600/10 via-cyan-600/5 to-blue-600/10 hover:from-blue-600/20 hover:via-cyan-600/10 hover:to-blue-600/20" 
        : "from-blue-50 via-cyan-50 to-blue-50 hover:from-blue-100 hover:via-cyan-100 hover:to-blue-100",
      border: isDarkMode 
        ? "border-blue-500/20 hover:border-cyan-400/40" 
        : "border-blue-200 hover:border-blue-400",
      text: isDarkMode ? "text-blue-300" : "text-blue-700",
    },
    purple: {
      bg: isDarkMode 
        ? "from-purple-600/10 via-pink-600/5 to-purple-600/10 hover:from-purple-600/20 hover:via-pink-600/10 hover:to-purple-600/20" 
        : "from-purple-50 via-pink-50 to-purple-50 hover:from-purple-100 hover:via-pink-100 hover:to-purple-100",
      border: isDarkMode 
        ? "border-purple-500/20 hover:border-pink-400/40" 
        : "border-purple-200 hover:border-purple-400",
      text: isDarkMode ? "text-purple-300" : "text-purple-700",
    },
    amber: {
      bg: isDarkMode 
        ? "from-amber-600/10 via-orange-600/5 to-amber-600/10 hover:from-amber-600/20 hover:via-orange-600/10 hover:to-amber-600/20" 
        : "from-amber-50 via-orange-50 to-amber-50 hover:from-amber-100 hover:via-orange-100 hover:to-amber-100",
      border: isDarkMode 
        ? "border-amber-500/20 hover:border-orange-400/40" 
        : "border-amber-200 hover:border-amber-400",
      text: isDarkMode ? "text-amber-300" : "text-amber-700",
    },
    green: {
      bg: isDarkMode 
        ? "from-emerald-600/10 via-teal-600/5 to-emerald-600/10 hover:from-emerald-600/20 hover:via-teal-600/10 hover:to-emerald-600/20" 
        : "from-emerald-50 via-teal-50 to-emerald-50 hover:from-emerald-100 hover:via-teal-100 hover:to-emerald-100",
      border: isDarkMode 
        ? "border-emerald-500/20 hover:border-teal-400/40" 
        : "border-emerald-200 hover:border-emerald-400",
      text: isDarkMode ? "text-emerald-300" : "text-emerald-700",
    },
    gray: {
      bg: isDarkMode 
        ? "from-gray-600/10 to-gray-700/10 hover:from-gray-600/20 hover:to-gray-700/20" 
        : "from-gray-50 to-gray-100 hover:from-gray-100 hover:to-gray-200",
      border: isDarkMode 
        ? "border-gray-600/30 hover:border-gray-500/50" 
        : "border-gray-200 hover:border-gray-400",
      text: isDarkMode ? "text-gray-300" : "text-gray-700",
    },
  };
  
  const c = colorClasses[color] || colorClasses.blue;
  
  return (
    <button
      onClick={onClick}
      className={`
        group relative overflow-hidden
        w-full p-5 rounded-xl
        bg-gradient-to-br ${locked ? (isDarkMode ? "from-gray-700/30 to-gray-800/30" : "from-gray-100 to-gray-200") : c.bg}
        border ${locked ? (isDarkMode ? "border-gray-600/40" : "border-gray-300") : c.border}
        transition-all duration-500 ease-out
        ${locked ? "cursor-pointer opacity-75" : "hover:shadow-xl hover:-translate-y-1.5 hover:scale-[1.02]"}
        active:scale-[0.98] active:translate-y-0
        text-left
      `}
    >
      {/* Shimmer effect - only show when not locked */}
      {!locked && (
        <div className={`
          absolute inset-0 -translate-x-full group-hover:translate-x-full 
          transition-transform duration-1000 ease-out
          bg-gradient-to-r from-transparent via-white/10 to-transparent
          pointer-events-none
        `} />
      )}
      
      {/* Locked overlay */}
      {locked && (
        <div className={`
          absolute inset-0 rounded-xl flex items-center justify-center
          bg-gradient-to-br ${isDarkMode ? "from-gray-900/60 to-gray-800/60" : "from-gray-100/80 to-gray-200/80"}
          backdrop-blur-[1px] z-10
        `}>
          <div className="text-center px-3">
            <span className="text-xl mb-1 block">🔒</span>
            <span className={`text-xs font-semibold block ${isDarkMode ? "text-purple-400" : "text-purple-600"}`}>
              Pro Feature
            </span>
            <span className={`text-[10px] block mt-1 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
              Click to see plans
            </span>
          </div>
        </div>
      )}
      
      {/* Badge - show PRO badge for locked features */}
      {(badge || locked) && (
        <span className={`
          absolute top-3 right-3 px-2 py-0.5 rounded-full text-xs font-bold z-20
          ${locked 
            ? "bg-gradient-to-r from-purple-500 to-pink-500 text-white" 
            : "bg-gradient-to-r from-cyan-500 to-blue-500 text-white animate-pulse"
          }
        `}>
          {locked ? "PRO" : badge}
        </span>
      )}
      
      <div className={`flex items-center gap-4 ${locked ? "opacity-40" : ""}`}>
        <span className={`
          text-3xl transition-all duration-500 ease-out
          ${!locked && "group-hover:scale-125 group-hover:rotate-12"}
        `}>
          {icon}
        </span>
        <div>
          <p className={`font-bold text-base ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            {label}
          </p>
          {sublabel && (
            <p className={`text-sm mt-0.5 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
              {sublabel}
            </p>
          )}
        </div>
      </div>
    </button>
  );
};

// Animated Status Indicator
const StatusIndicator = ({ label, status = "online", isDarkMode }) => {
  const statusConfig = {
    online: { color: "bg-emerald-400", text: "Online", shadow: "shadow-emerald-400/50" },
    warning: { color: "bg-amber-400", text: "Warning", shadow: "shadow-amber-400/50" },
    offline: { color: "bg-red-400", text: "Offline", shadow: "shadow-red-400/50" },
    loading: { color: "bg-blue-400", text: "Loading", shadow: "shadow-blue-400/50" },
  };
  
  const config = statusConfig[status] || statusConfig.online;
  
  return (
    <div className={`
      flex items-center justify-between py-3 px-2 rounded-lg
      transition-all duration-300
      hover:${isDarkMode ? 'bg-white/5' : 'bg-gray-50'}
    `}>
      <div className="flex items-center gap-3">
        <div className="relative">
          <div className={`w-2.5 h-2.5 ${config.color} rounded-full shadow-lg ${config.shadow}`} />
          <div className={`absolute inset-0 w-2.5 h-2.5 ${config.color} rounded-full animate-ping opacity-60`} />
        </div>
        <span className={isDarkMode ? "text-gray-200" : "text-gray-700"}>{label}</span>
      </div>
      <span className={`text-xs font-medium ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
        {config.text}
      </span>
    </div>
  );
};

// Progress Ring Component
const ProgressRing = ({ progress, size = 80, strokeWidth = 6, color = "cyan", isDarkMode }) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (progress / 100) * circumference;
  
  const colors = {
    cyan: "stroke-cyan-500",
    blue: "stroke-blue-500",
    green: "stroke-emerald-500",
    purple: "stroke-purple-500",
    red: "stroke-red-500",
  };
  
  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg className="rotate-[-90deg]" width={size} height={size}>
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          className={isDarkMode ? "stroke-white/10" : "stroke-gray-200"}
          strokeWidth={strokeWidth}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={radius}
          className={`${colors[color]} transition-all duration-1000 ease-out`}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          fill="none"
          style={{
            strokeDasharray: circumference,
            strokeDashoffset: offset,
          }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className={`text-lg font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          {progress}%
        </span>
      </div>
    </div>
  );
};

// =============================================
// MAIN DASHBOARD COMPONENT
// =============================================

const JarwisDashboard = () => {
  const navigate = useNavigate();
  const { user, userDoc, getPlanInfo, isPro, isEnterprise } = useAuth();
  const { isDarkMode } = useTheme();
  const { canPerformAction, checkFeature, currentPlan, getActionLimit } = useSubscription();
  
  // Check if user has access to pro features
  const hasMobileAccess = checkFeature('mobileAppTesting');
  const hasCloudAccess = checkFeature('cloudScanning');
  const hasApiAccess = checkFeature('apiTesting');
  const hasChatbotAccess = checkFeature('chatbotAccess');
  
  // Handler for locked features - navigate to billing
  const handleLockedFeature = (featureName) => {
    // Open settings panel with billing tab
    navigate("/dashboard", { state: { openSettings: true, settingsTab: "billing" } });
  };

  // State for API data
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({ total: 0, web: 0, mobile: 0, cloud: 0, running: 0 });
  const [vulnerabilities, setVulnerabilities] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });
  const [loading, setLoading] = useState(true);
  const [currentTime, setCurrentTime] = useState(new Date());
  
  // System health state - fetched from backend
  const [systemHealth, setSystemHealth] = useState({ score: 0, services: {} });
  const [healthLoading, setHealthLoading] = useState(true);

  // Get scan usage limits
  const scansLimit = getActionLimit('scans');

  // Update time every minute
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 60000);
    return () => clearInterval(timer);
  }, []);

  // Fetch system health from backend
  const fetchSystemHealth = useCallback(async () => {
    try {
      const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
      
      // Check main API health
      const healthRes = await fetch(`${apiUrl}/api/health`);
      const apiHealthy = healthRes.ok;
      
      // Check database health
      let dbHealthy = false;
      try {
        const dbRes = await fetch(`${apiUrl}/api/health/db`);
        const dbData = await dbRes.json();
        dbHealthy = dbData.status === 'ok';
      } catch {
        dbHealthy = false;
      }
      
      // Calculate health score based on services
      const services = {
        api: apiHealthy,
        database: dbHealthy,
        scanning: apiHealthy, // Scanning depends on API
        reporting: apiHealthy, // Reporting depends on API
      };
      
      const healthyCount = Object.values(services).filter(Boolean).length;
      const score = Math.round((healthyCount / Object.keys(services).length) * 100);
      
      setSystemHealth({ score, services });
    } catch (error) {
      console.error('Failed to fetch system health:', error);
      setSystemHealth({ score: 0, services: { api: false, database: false, scanning: false, reporting: false } });
    } finally {
      setHealthLoading(false);
    }
  }, []);

  // Fetch dashboard data
  const fetchDashboardData = useCallback(async () => {
    try {
      const scansData = await scanAPI.listScans({});
      setScans(scansData.scans || []);
      setStats(scansData.stats || { total: 0, web: 0, mobile: 0, cloud: 0, running: 0 });

      const vulnResponse = await fetch(`${process.env.REACT_APP_API_URL || 'http://localhost:8000'}/api/vulnerabilities`);
      if (vulnResponse.ok) {
        const vulnData = await vulnResponse.json();
        setVulnerabilities(vulnData.summary || { total: 0, critical: 0, high: 0, medium: 0, low: 0 });
      }
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
    fetchSystemHealth();
    // Refresh data every 60 seconds instead of 10 to prevent excessive polling
    const interval = setInterval(() => {
      fetchDashboardData();
      fetchSystemHealth();
    }, 60000);
    return () => clearInterval(interval);
  }, [fetchDashboardData, fetchSystemHealth]);

  // Get greeting based on time
  const getGreeting = () => {
    const hour = currentTime.getHours();
    if (hour < 12) return "Good morning";
    if (hour < 17) return "Good afternoon";
    return "Good evening";
  };

  // Format scans for display
  const recentScans = scans.slice(0, 5).map(scan => ({
    id: scan.scan_id || scan.id,
    domain: scan.target || scan.target_url || 'Unknown',
    type: scan.scan_type || scan.type || 'Web',
    findings: scan.findings_count || 0,
    criticalCount: scan.results?.critical || 0,
    highCount: scan.results?.high || 0,
    started: scan.started_at ? new Date(scan.started_at).toLocaleDateString() : 'Unknown',
    status: scan.status || 'unknown',
  }));

  // Get plan info
  const planInfo = getPlanInfo();

  return (
    <MiftyJarwisLayout>
      <div className="space-y-8 p-6">
        {/* ========================================= */}
        {/* HERO SECTION */}
        {/* ========================================= */}
        <div 
          className="relative overflow-hidden mifty-animate-slide-up"
          style={{ animationDelay: '0ms' }}
        >
          <GlassCard isDarkMode={isDarkMode} hover={false} className="p-8 relative overflow-hidden">
            {/* Animated background elements */}
            <div className="absolute inset-0 pointer-events-none overflow-hidden">
              <div className={`
                absolute -top-24 -right-24 w-64 h-64 
                ${isDarkMode ? "bg-cyan-500/20" : "bg-cyan-200/60"} 
                rounded-full blur-[80px] animate-pulse
              `} style={{ animationDuration: '4s' }} />
              <div className={`
                absolute -bottom-24 -left-24 w-64 h-64 
                ${isDarkMode ? "bg-purple-500/20" : "bg-purple-200/60"} 
                rounded-full blur-[80px] animate-pulse
              `} style={{ animationDuration: '5s', animationDelay: '1s' }} />
              <div className={`
                absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 
                ${isDarkMode ? "bg-blue-500/10" : "bg-blue-200/40"} 
                rounded-full blur-[100px] animate-pulse
              `} style={{ animationDuration: '6s', animationDelay: '2s' }} />
            </div>
            
            <div className="relative z-10 flex flex-col xl:flex-row xl:items-center xl:justify-between gap-8">
              {/* Left side - Greeting */}
              <div className="space-y-4">
                <p className={`
                  text-sm font-medium tracking-wide
                  ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}
                `}>
                  Welcome to Jarwis AGI
                </p>
                <h1 className="text-3xl sm:text-4xl lg:text-5xl font-bold leading-tight">
                  <span className={isDarkMode ? "text-white" : "text-gray-900"}>
                    {getGreeting()},{" "}
                  </span>
                  <span className="bg-gradient-to-r from-cyan-400 via-blue-500 to-purple-500 bg-clip-text text-transparent animate-gradient">
                    {(user?.full_name || user?.username || userDoc?.full_name || userDoc?.username || "Security Pro").split(" ")[0]}
                  </span>
                  <span className="ml-2 inline-block animate-wave"></span>
                </h1>
                <p className={`
                  text-base sm:text-lg max-w-xl
                  ${isDarkMode ? "text-gray-300" : "text-gray-600"}
                `}>
                  Your AI security assistant is ready to protect your applications. 
                  Start scanning or review your security posture.
                </p>
                
                {/* CTA Buttons */}
                <div className="flex flex-wrap gap-4 pt-2">
                  <GradientButton 
                    onClick={() => navigate("/dashboard/new-scan")} 
                    icon=""
                    size="lg"
                  >
                    Start New Scan
                  </GradientButton>
                  <button
                    onClick={() => navigate("/dashboard/vulnerabilities")}
                    className={`
                      px-6 py-3.5 rounded-xl font-semibold
                      border-2 transition-all duration-300
                      hover:scale-105 active:scale-95
                      ${isDarkMode 
                        ? "border-white/20 text-white hover:border-white/40 hover:bg-white/5" 
                        : "border-gray-300 text-gray-700 hover:border-gray-400 hover:bg-gray-50"
                      }
                    `}
                  >
                    View Vulnerabilities
                  </button>
                </div>
              </div>
              
              {/* Right side - Plan Badge & Quick Stats */}
              <div className="flex flex-col items-start xl:items-end gap-4">
                {/* Plan Badge */}
                <div className={`
                  px-6 py-4 rounded-2xl font-semibold
                  flex items-center gap-4
                  backdrop-blur-md transition-all duration-300
                  hover:scale-105 cursor-pointer
                  ${isEnterprise()
                    ? "bg-gradient-to-r from-amber-500/20 to-yellow-500/20 border border-amber-500/30"
                    : isPro()
                    ? "bg-gradient-to-r from-purple-500/20 to-pink-500/20 border border-purple-500/30"
                    : isDarkMode
                    ? "bg-white/5 border border-white/10"
                    : "bg-gray-100/80 border border-gray-200"
                  }
                `}
                onClick={() => navigate("/pricing")}
                >
                  <span className="text-3xl">{planInfo?.badge || ""}</span>
                  <div>
                    <p className={`font-bold text-lg ${
                      isEnterprise()
                        ? "text-amber-300"
                        : isPro()
                        ? "text-purple-300"
                        : isDarkMode ? "text-white" : "text-gray-900"
                    }`}>
                      {planInfo?.name || "Free"} Plan
                    </p>
                    <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                      {planInfo?.description || "Current plan features"}
                    </p>
                  </div>
                  <button
                    onClick={() => navigate("/pricing")}
                    className={`
                      group flex items-center gap-2 
                      text-sm font-medium transition-all duration-300
                      ${isDarkMode ? "text-cyan-400 hover:text-cyan-300" : "text-cyan-600 hover:text-cyan-500"}
                    `}
                  >
                    <span className="animate-pulse">*</span>
                    <span className="group-hover:underline underline-offset-4">
                      Upgrade for unlimited scans
                    </span>
                    <span className="transition-transform duration-300 group-hover:translate-x-1">&rarr;</span>
                  </button>
                </div>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6">
          <StatCard
            label="Total Scans"
            value={stats.total}
            icon=""
            trend={stats.running > 0 ? `${stats.running} running` : null}
            trendUp={true}
            color="blue"
            isDarkMode={isDarkMode}
            delay={100}
            subtitle="All time"
          />
          <StatCard
            label="Vulnerabilities"
            value={vulnerabilities.total}
            icon=""
            trend={vulnerabilities.high > 0 ? `${vulnerabilities.high} high` : null}
            trendUp={false}
            color="amber"
            isDarkMode={isDarkMode}
            delay={200}
            subtitle="Found issues"
          />
          <StatCard
            label="Critical Issues"
            value={vulnerabilities.critical}
            icon=""
            color="red"
            isDarkMode={isDarkMode}
            delay={300}
            subtitle="Immediate action"
          />
          <StatCard
            label="Resolved"
            value={0}
            icon="✓"
            trend="This month"
            trendUp={true}
            color="green"
            isDarkMode={isDarkMode}
            delay={400}
            subtitle="Fixed issues"
          />
        </div>
          </GlassCard>
        </div>

        {/* ========================================= */}
        {/* MAIN CONTENT GRID */}
        {/* ========================================= */}
        <div className="grid grid-cols-1 xl:grid-cols-3 gap-8">
          {/* Quick Actions - 2 columns */}
          <div 
            className="xl:col-span-2 animate-fadeIn"
            style={{ animationDelay: '200ms' }}
          >
            <GlassCard isDarkMode={isDarkMode} hover={false} highlighted={true} className="p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h2 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    Quick Scan
                  </h2>
                  <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                    Launch security assessments with one click
                  </p>
                </div>
                <button
                  onClick={() => navigate("/dashboard/new-scan")}
                  className={`
                    hidden sm:flex items-center gap-2 px-5 py-2.5
                    bg-gradient-to-r from-cyan-500 to-blue-500 text-white 
                    rounded-xl font-semibold
                    shadow-lg shadow-cyan-500/25
                    transition-all duration-300
                    hover:shadow-cyan-500/40 hover:scale-105
                    active:scale-95
                  `}
                >
                  <span className="text-lg">+</span>
                  <span>New Scan</span>
                </button>
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                <QuickActionButton
                  icon="🌐"
                  label="Web Application"
                  sublabel="OWASP Top 10 Scanner"
                  onClick={() => navigate("/dashboard/new-scan")}
                  color="blue"
                  isDarkMode={isDarkMode}
                />
                <QuickActionButton
                  icon="📱"
                  label="Mobile App"
                  sublabel="APK & IPA Analysis"
                  onClick={hasMobileAccess 
                    ? () => navigate("/dashboard/new-scan", { state: { scanType: "mobile" } })
                    : () => handleLockedFeature("Mobile App Testing")
                  }
                  color="purple"
                  isDarkMode={isDarkMode}
                  locked={!hasMobileAccess}
                  lockedMessage="Pro Feature"
                />
                <QuickActionButton
                  icon="☁️"
                  label="Cloud Security"
                  sublabel="AWS, Azure, GCP"
                  onClick={hasCloudAccess 
                    ? () => navigate("/dashboard/new-scan", { state: { scanType: "cloud" } })
                    : () => handleLockedFeature("Cloud Security")
                  }
                  color="amber"
                  isDarkMode={isDarkMode}
                  locked={!hasCloudAccess}
                  lockedMessage="Pro Feature"
                />
                <QuickActionButton
                  icon="🔌"
                  label="API Security"
                  sublabel="REST & GraphQL Testing"
                  onClick={hasApiAccess 
                    ? () => navigate("/dashboard/new-scan", { state: { scanType: "api" } })
                    : () => handleLockedFeature("API Security Testing")
                  }
                  color="green"
                  isDarkMode={isDarkMode}
                  locked={!hasApiAccess}
                  lockedMessage="Pro Feature"
                />
                <QuickActionButton
                  icon="📋"
                  label="Scan History"
                  sublabel="View all scans"
                  onClick={() => navigate("/dashboard/scan-history")}
                  color="gray"
                  isDarkMode={isDarkMode}
                />
                <QuickActionButton
                  icon="🤖"
                  label="Ask Jarwis AGI"
                  sublabel="Security assistant"
                  onClick={hasChatbotAccess 
                    ? () => navigate("/dashboard/jarwis-chatbot")
                    : () => handleLockedFeature("Jarwis AGI Chatbot")
                  }
                  color="green"
                  isDarkMode={isDarkMode}
                  locked={!hasChatbotAccess}
                  lockedMessage="Pro Feature"
                />
              </div>
            </GlassCard>
          </div>

          {/* System Status - 1 column */}
          <div 
            className="xl:col-span-1 animate-fadeIn"
            style={{ animationDelay: '300ms' }}
          >
            <GlassCard isDarkMode={isDarkMode} hover={false} highlighted={true} className="p-6 h-full">
              <div className="flex items-center justify-between mb-6">
                <h2 className={isDarkMode ? "text-xl font-bold text-white" : "text-xl font-bold text-gray-900"}>System Status
                </h2>
                <span className={`
                  px-3 py-1.5 rounded-full text-xs font-bold
                  ${systemHealth.score >= 75 ? "animate-pulse" : ""}
                  ${systemHealth.score >= 75
                    ? isDarkMode 
                      ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30" 
                      : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                    : systemHealth.score >= 50
                      ? isDarkMode
                        ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                        : "bg-amber-100 text-amber-700 border border-amber-200"
                      : isDarkMode
                        ? "bg-red-500/20 text-red-400 border border-red-500/30"
                        : "bg-red-100 text-red-700 border border-red-200"
                  }`}>
                  {systemHealth.score >= 75 ? "Online" : systemHealth.score >= 50 ? "Degraded" : "Offline"}
                </span>
              </div>
              
              {/* Health Ring */}
              <div className="flex items-center justify-center mb-6">
                {healthLoading ? (
                  <div className="w-[100px] h-[100px] flex items-center justify-center">
                    <div className="w-8 h-8 border-4 border-cyan-500/30 border-t-cyan-500 rounded-full animate-spin" />
                  </div>
                ) : (
                  <ProgressRing 
                    progress={systemHealth.score} 
                    size={100} 
                    strokeWidth={8} 
                    color={systemHealth.score >= 75 ? "cyan" : systemHealth.score >= 50 ? "purple" : "red"} 
                    isDarkMode={isDarkMode} 
                  />
                )}
              </div>
              
              <p className={`text-center text-sm mb-6 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                System Health Score
              </p>
              
              {/* Status List */}
              <div className={`
                space-y-1 rounded-xl p-3
                ${isDarkMode ? "bg-white/5" : "bg-gray-50"}
              `}>
                <StatusIndicator 
                  label="API Server" 
                  status={systemHealth.services?.api ? "online" : "offline"} 
                  isDarkMode={isDarkMode} 
                />
                <StatusIndicator 
                  label="Database" 
                  status={systemHealth.services?.database ? "online" : "offline"} 
                  isDarkMode={isDarkMode} 
                />
                <StatusIndicator 
                  label="Scanning Engine" 
                  status={systemHealth.services?.scanning ? "online" : "offline"} 
                  isDarkMode={isDarkMode} 
                />
                <StatusIndicator 
                  label="Report Generator" 
                  status={systemHealth.services?.reporting ? "online" : "offline"} 
                  isDarkMode={isDarkMode} 
                />
              </div>
              
              {/* Scan Usage */}
              <div className={`
                mt-4 pt-4 
                border-t ${isDarkMode ? "border-white/10" : "border-gray-200"}
              `}>
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-sm font-medium ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                    Scan Usage
                  </span>
                  <span className={`text-sm font-bold ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`}>
                    {scansLimit.current || 0}/{scansLimit.unlimited ? "∞" : scansLimit.max}
                  </span>
                </div>
                <div className={`h-2 rounded-full overflow-hidden ${isDarkMode ? "bg-white/10" : "bg-gray-200"}`}>
                  <div 
                    className="h-full bg-gradient-to-r from-cyan-500 to-purple-500 transition-all duration-500"
                    style={{ 
                      width: scansLimit.unlimited 
                        ? "100%" 
                        : `${Math.min(((scansLimit.current || 0) / scansLimit.max) * 100, 100)}%` 
                    }}
                  />
                </div>
                <p className={`text-xs mt-2 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                  {scansLimit.unlimited 
                    ? "Unlimited scans available" 
                    : `${scansLimit.remaining || scansLimit.max} scans remaining this month`}
                </p>
              </div>
              
              <div className={`
                mt-4 pt-4 text-center
                border-t ${isDarkMode ? "border-white/10" : "border-gray-200"}
              `}>
                <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                  Last updated: {new Date().toLocaleTimeString()}
                </p>
              </div>
            </GlassCard>
          </div>

          {/* Recent Scans */}
          <div 
            className="animate-fadeIn"
            style={{ animationDelay: '400ms' }}
          >
          <GlassCard isDarkMode={isDarkMode} hover={false} highlighted={true} className="p-6">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  Recent Scans
                </h2>
                <p className={`${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                  Your latest security assessments and findings
                </p>
              </div>
              <button
                onClick={() => navigate("/dashboard/scan-history")}
                className={`
                  px-5 py-2.5 rounded-xl font-semibold
                  transition-all duration-300
                  hover:scale-105 active:scale-95
                  ${isDarkMode 
                    ? "bg-white/5 border border-white/10 text-gray-300 hover:bg-white/10 hover:text-white hover:border-white/20"
                    : "bg-gray-100 border border-gray-200 text-gray-700 hover:bg-gray-200 hover:border-gray-300"}`}
                >
                  View All Scans
                </button>
              </div>

            {loading ? (
              <div className="flex flex-col items-center justify-center py-16">
                <div className="relative">
                  <div className="w-12 h-12 rounded-full border-4 border-cyan-500/30 border-t-cyan-500 animate-spin" />
                  <div className="absolute inset-0 w-12 h-12 rounded-full border-4 border-transparent border-b-purple-500/50 animate-spin" style={{ animationDirection: 'reverse', animationDuration: '1.5s' }} />
                </div>
                <p className={`mt-4 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                  Loading scan data...
                </p>
              </div>
            ) : recentScans.length === 0 ? (
              <div className="text-center py-16">
                <div className="relative inline-block">
                  <div className="text-7xl mb-4 animate-bounce">*</div>
                  <div className={`absolute bottom-0 right-0 w-4 h-4 rounded-full ${isDarkMode ? "bg-white/20" : "bg-gray-300"}
                    animate-pulse
                  `} />
                </div>
                <h3 className={`text-2xl font-bold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  No scans yet
                </h3>
                <p className={`mb-8 max-w-md mx-auto ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                  Start your first security scan to discover vulnerabilities and 
                  get AI-powered recommendations
                </p>
                <GradientButton 
                  onClick={() => navigate("/dashboard/new-scan")} 
                  icon=""
                  size="lg"
                >
                  Start Your First Scan
                </GradientButton>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className={`
                      border-b
                      ${isDarkMode ? "border-white/10" : "border-gray-200"}
                    `}>
                      {["Target", "Type", "Findings", "Date", "Status", ""].map((header, i) => (
                        <th 
                          key={header || i} 
                          className={`
                            text-left py-4 px-4 text-sm font-semibold uppercase tracking-wider
                            ${isDarkMode ? "text-gray-400" : "text-gray-500"}
                          `}
                        >
                          {header}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {recentScans.map((scan, index) => (
                      <tr 
                        key={scan.id}
                        className={`
                          group transition-all duration-300 cursor-pointer
                          border-b
                          ${isDarkMode 
                            ? "hover:bg-white/[0.03] border-white/5" 
                            : "hover:bg-gray-50 border-gray-100"
                          }
                        `}
                        onClick={() => navigate("/dashboard/vulnerabilities", { state: { scanId: scan.id } })}
                        style={{ 
                          animation: `fadeInUp 0.5s ease-out forwards`,
                          animationDelay: `${index * 100}ms`,
                          opacity: 0,
                        }}
                      >
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-3">
                            <div className={`
                              w-8 h-8 rounded-lg flex items-center justify-center text-sm
                              ${isDarkMode ? "bg-white/10" : "bg-gray-100"}
                            `}>
                              🌐
                            </div>
                            <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                              {scan.domain.length > 30 ? scan.domain.substring(0, 30) + '...' : scan.domain}
                            </span>
                          </div>
                        </td>
                        <td className="py-4 px-4">
                          <span className={`
                            px-3 py-1.5 rounded-lg text-xs font-bold
                            ${scan.type === 'Web' 
                              ? isDarkMode ? "bg-blue-500/15 text-blue-300 border border-blue-500/20" : "bg-blue-100 text-blue-700"
                              : scan.type === 'Mobile'
                              ? isDarkMode ? "bg-purple-500/15 text-purple-300 border border-purple-500/20" : "bg-purple-100 text-purple-700"
                              : isDarkMode ? "bg-amber-500/15 text-amber-300 border border-amber-500/20" : "bg-amber-100 text-amber-700"
                            }
                          `}>
                            {scan.type}
                          </span>
                        </td>
                        <td className="py-4 px-4">
                          <div className="flex items-center gap-2">
                            <span className={`font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                              {scan.findings}
                            </span>
                            {scan.criticalCount > 0 && (
                              <span className={`
                                px-2 py-0.5 rounded-full text-xs font-bold animate-pulse
                                ${isDarkMode ? "bg-red-500/20 text-red-300" : "bg-red-100 text-red-700"}
                              `}>
                                {scan.criticalCount} critical
                              </span>
                            )}
                          </div>
                        </td>
                        <td className={`py-4 px-4 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                          {scan.started}
                        </td>
                        <td className="py-4 px-4">
                          <span className={`
                            px-3 py-1.5 rounded-full text-xs font-bold
                            ${scan.status === 'completed'
                              ? isDarkMode ? "bg-emerald-500/15 text-emerald-300 border border-emerald-500/20" : "bg-emerald-100 text-emerald-700"
                              : scan.status === 'running'
                              ? isDarkMode ? "bg-blue-500/15 text-blue-300 border border-blue-500/20" : "bg-blue-100 text-blue-700"
                              : isDarkMode ? "bg-gray-500/15 text-gray-300 border border-gray-500/20" : "bg-gray-100 text-gray-700"
                            }
                          `}>
                            {scan.status === 'running' && (
                              <span className="inline-block w-2 h-2 bg-current rounded-full mr-1.5 animate-pulse" />
                            )}
                            {scan.status.charAt(0).toUpperCase() + scan.status.slice(1)}
                          </span>
                        </td>
                        <td className="py-4 px-4">
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              navigate("/dashboard/vulnerabilities", { state: { scanId: scan.id } });
                            }}
                            className={`
                              px-4 py-2 rounded-lg text-sm font-semibold
                              transition-all duration-300
                              opacity-0 group-hover:opacity-100 translate-x-2 group-hover:translate-x-0
                              ${isDarkMode 
                                ? "bg-cyan-500/20 text-cyan-300 hover:bg-cyan-500/30 border border-cyan-500/30" 
                                : "bg-cyan-50 text-cyan-700 hover:bg-cyan-100 border border-cyan-200"
                              }
                            `}
                          >
                            Details 
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </GlassCard>
        </div>
      </div>
      </div>

      {/* ========================================= */}
      {/* CUSTOM ANIMATIONS CSS */}
      {/* ========================================= */}
      <style>{`
        @keyframes fadeIn {
          from { 
            opacity: 0; 
            transform: translateY(20px); 
          }
          to { 
            opacity: 1; 
            transform: translateY(0); 
          }
        }
        
        @keyframes fadeInUp {
          from { 
            opacity: 0; 
            transform: translateY(10px); 
          }
          to { 
            opacity: 1; 
            transform: translateY(0); 
          }
        }
        
        @keyframes wave {
          0%, 100% { transform: rotate(0deg); }
          25% { transform: rotate(20deg); }
          75% { transform: rotate(-10deg); }
        }
        
        @keyframes gradient {
          0% { background-position: 0% 50%; }
          50% { background-position: 100% 50%; }
          100% { background-position: 0% 50%; }
        }
        
        .animate-fadeIn {
          animation: fadeIn 0.7s ease-out forwards;
        }
        
        .animate-wave {
          display: inline-block;
          animation: wave 2s ease-in-out infinite;
          transform-origin: 70% 70%;
        }
        
        .animate-gradient {
          background-size: 200% 200%;
          animation: gradient 3s ease infinite;
        }
      `}</style>
    </MiftyJarwisLayout>
  );
};

export default JarwisDashboard;
