// MiftyJarwisLayout.jsx - Modern Mifty-inspired Dashboard Layout
// Premium e-commerce style with smooth animations

import { useState, useRef, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import ScrollToTop from "../ScrollToTop";
import SettingsPanel from "../settings/SettingsPanel";

// Professional Dashboard Icons
const DashboardIcons = {
  dashboard: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
    </svg>
  ),
  scan: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v17.25m0 0c-1.472 0-2.882.265-4.185.75M12 20.25c1.472 0 2.882.265 4.185.75M18.75 4.97A48.416 48.416 0 0012 4.5c-2.291 0-4.545.16-6.75.47m13.5 0c1.01.143 2.01.317 3 .52m-3-.52l2.62 10.726c.122.499-.106 1.028-.589 1.202a5.988 5.988 0 01-2.031.352 5.988 5.988 0 01-2.031-.352c-.483-.174-.711-.703-.59-1.202L18.75 4.971zm-16.5.52c.99-.203 1.99-.377 3-.52m0 0l2.62 10.726c.122.499-.106 1.028-.589 1.202a5.989 5.989 0 01-2.031.352 5.989 5.989 0 01-2.031-.352c-.483-.174-.711-.703-.589-1.202L5.25 4.971z" />
    </svg>
  ),
  history: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  active: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z" />
    </svg>
  ),
  vulnerabilities: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.25-8.25-3.286zm0 13.036h.008v.008H12v-.008z" />
    </svg>
  ),
  ai: (
    <svg className="w-5 h-5" viewBox="0 0 500 500" fill="none" xmlns="http://www.w3.org/2000/svg">
      <defs>
        <linearGradient id="jarwisSidebarGradient" x1="250" y1="111" x2="250" y2="384" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#00C19F"/>
          <stop offset="1" stopColor="#256AD1"/>
        </linearGradient>
      </defs>
      <path fill="url(#jarwisSidebarGradient)" d="M343.73,166.48l-12.75-7.4L250,112.35l-25.51,14.73l-12.75,7.33l-80.97,46.8V318.8l25.5,14.72l12.75,7.4l12.75,7.33l12.75,7.39L250,387.65l25.51-14.73l12.75-7.4l12.75-7.33l12.75-7.33l55.47-32.07V181.21L343.73,166.48z M250,127.08l80.97,46.73v14.73l0,0v14.73l0,0v65.29l-12.75,7.14v-94.49l-12.75-7.4l-55.47-32l-12.75-7.33L250,127.08z M250,314.01L194.53,282V218L250,185.99L305.47,218v64.84L250,314.01z M143.53,188.54l80.97-46.73l12.75,7.33h0.07l12.69,7.39l55.47,32.01v14.72l-55.47-32l-12.75-7.4l-12.75-7.33l-12.75,7.4h-0.07l-55.41,32l-12.75,7.4V188.54z M143.53,311.47V218l12.75-7.33l12.75-7.4l55.41-32l12.81,7.4l-55.47,32L169.03,218l-12.75,7.39v93.41L143.53,311.47z M250,372.92l-55.47-32l-12.75-7.4l-12.75-7.33v-93.47l12.75-7.39v93.47v0.06l12.75,7.33L250,358.2l12.75,7.33L250,372.92z M275.51,358.2l-12.75-7.4L250,343.47l-55.47-32v-14.73l55.47,32l12.75,7.4l12.75,7.33l12.75,7.4L275.51,358.2z M356.47,311.47l-55.47,32l-12.75-7.33l55.47-32v-0.07l12.75-7.33V311.47z M356.47,282l-12.75,7.33l-12.75,7.4l-55.47,32l-12.63-7.27l68.09-38.32l12.75-7.14l12.75-7.2V282z M356.47,254.21l-12.75,7.13v-65.41v-14.72l12.75,7.33V254.21z"/>
      <polygon fill="#00C598" points="250,229.09 220.91,245.88 220.91,279.44 250,296.23 279.09,279.88 279.09,245.88"/>
      <path fill="#256AD1" d="M250,208.65c-13.03,0-23.62,10.6-23.62,23.63v5.37l7-4.04v-1.33c0-9.17,7.46-16.63,16.63-16.63c9.16,0,16.63,7.46,16.63,16.63v1.33l7,4.04v-5.37C273.62,219.25,263.02,208.65,250,208.65z"/>
    </svg>
  ),
  settings: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.431l-1.003.827c-.293.24-.438.613-.431.992a6.759 6.759 0 010 .255c-.007.378.138.75.43.99l1.005.828c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.57 6.57 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.28c-.09.543-.56.941-1.11.941h-2.594c-.55 0-1.02-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.431l1.004-.827c.292-.24.437-.613.43-.992a6.932 6.932 0 010-.255c.007-.378-.138-.75-.43-.99l-1.004-.828a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.087.22-.128.332-.183.582-.495.644-.869l.214-1.281z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
  home: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 12l8.954-8.955c.44-.439 1.152-.439 1.591 0L21.75 12M4.5 9.75v10.125c0 .621.504 1.125 1.125 1.125H9.75v-4.875c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125V21h4.125c.621 0 1.125-.504 1.125-1.125V9.75M8.25 21h8.25" />
    </svg>
  ),
  logout: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 9V5.25A2.25 2.25 0 0013.5 3h-6a2.25 2.25 0 00-2.25 2.25v13.5A2.25 2.25 0 007.5 21h6a2.25 2.25 0 002.25-2.25V15M12 9l-3 3m0 0l3 3m-3-3h12.75" />
    </svg>
  ),
  search: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
    </svg>
  ),
  sun: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
    </svg>
  ),
  moon: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
    </svg>
  ),
  bell: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
    </svg>
  ),
  chevronDown: (
    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  ),
  menu: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
    </svg>
  ),
  close: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
    </svg>
  ),
};

// Subscription Badge Component
const SubscriptionBadge = ({ plan, isDarkMode }) => {
  const badgeConfig = {
    free: { label: "FREE", color: "slate" },
    individual: { label: "INDIVIDUAL", color: "cyan" },
    professional: { label: "PRO", color: "violet" },
    enterprise: { label: "ENTERPRISE", color: "amber" }
  };

  const config = badgeConfig[plan] || badgeConfig.free;
  
  const colorClasses = {
    slate: isDarkMode ? "bg-slate-500/20 border-slate-400/30 text-slate-300" : "bg-gray-100 border-gray-300 text-gray-700",
    cyan: isDarkMode ? "bg-cyan-500/20 border-cyan-400/30 text-cyan-300" : "bg-cyan-50 border-cyan-300 text-cyan-700",
    violet: isDarkMode ? "bg-violet-500/20 border-violet-400/30 text-violet-300" : "bg-violet-50 border-violet-300 text-violet-700",
    amber: isDarkMode ? "bg-amber-500/20 border-amber-400/30 text-amber-300" : "bg-amber-50 border-amber-300 text-amber-700",
  };

  return (
    <div className={`
      inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-bold tracking-wider
      ${colorClasses[config.color]}
      transition-all duration-300 hover:scale-105
    `}>
      <div className={`w-2 h-2 rounded-full ${isDarkMode ? "bg-current" : "bg-current"} animate-pulse`}></div>
      <span>{config.label}</span>
    </div>
  );
};

// Progress Bar Component
const UsageProgressBar = ({ current, max, unlimited, color, isDarkMode }) => {
  if (unlimited) {
    return (
      <div className="flex items-center gap-2">
        <div className={`flex-1 h-1.5 rounded-full overflow-hidden ${isDarkMode ? "bg-slate-700/50" : "bg-gray-200"}`}>
          <div className={`h-full w-full ${color} animate-pulse`}></div>
        </div>
        <span className={`text-xs ${isDarkMode ? "text-slate-400" : "text-gray-600"}`}>Unlimited</span>
      </div>
    );
  }
  
  const percentage = max > 0 ? Math.min((current / max) * 100, 100) : 0;
  const remaining = max - current;
  
  return (
    <div className="space-y-1">
      <div className={`flex-1 h-1.5 rounded-full overflow-hidden ${isDarkMode ? "bg-slate-700/50" : "bg-gray-200"}`}>
        <div 
          className={`h-full ${color} transition-all duration-500 ease-out`}
          style={{ width: `${percentage}%` }}
        ></div>
      </div>
      <div className="flex justify-between text-xs">
        <span className={isDarkMode ? "text-slate-400" : "text-gray-600"}>{current} used</span>
        <span className={remaining <= 1 ? "text-red-500" : isDarkMode ? "text-purple-400" : "text-purple-600"}>
          {remaining} left
        </span>
      </div>
    </div>
  );
};

const MiftyJarwisLayout = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, userDoc, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const { currentPlan, planId, usage, getActionLimit } = useSubscription();
  const [searchQuery, setSearchQuery] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsInitialTab, setSettingsInitialTab] = useState("account");
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const [usageExpanded, setUsageExpanded] = useState(false);
  const userDropdownRef = useRef(null);

  // Handle opening settings from route state
  useEffect(() => {
    if (location.state?.openSettings) {
      setSettingsOpen(true);
      if (location.state?.settingsTab) {
        setSettingsInitialTab(location.state.settingsTab);
      }
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state, navigate, location.pathname]);

  // Redirect admins
  useEffect(() => {
    if (userDoc.role === "admin" || userDoc.role === "super_admin") {
      navigate("/admin");
    }
  }, [userDoc.role, navigate]);

  // Close dropdown on outside click
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (userDropdownRef.current && !userDropdownRef.current.contains(event.target)) {
        setUserDropdownOpen(false);
      }
    };
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  const handleSearch = (e) => {
    e.preventDefault();
    if (searchQuery.trim()) {
      console.log("Searching for:", searchQuery);
    }
  };

  const navigationItems = [
    { href: "/dashboard", icon: DashboardIcons.dashboard, label: "Dashboard" },
    { href: "/dashboard/new-scan", icon: DashboardIcons.scan, label: "New Scan" },
    { href: "/dashboard/scan-history", icon: DashboardIcons.history, label: "Scan History" },
    { href: "/dashboard/scanning", icon: DashboardIcons.active, label: "Active Scan" },
    { href: "/dashboard/vulnerabilities", icon: DashboardIcons.vulnerabilities, label: "Vulnerabilities" },
    { href: "/dashboard/reports", icon: <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}><path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" /></svg>, label: "Reports" },
    { href: "/dashboard/jarwis-chatbot", icon: DashboardIcons.ai, label: "Jarwis AGI", badge: "New" },
  ];

  const bottomNavigationItems = [
    { href: "settings", icon: DashboardIcons.settings, label: "Settings", isSettings: true },
    { href: "/", icon: DashboardIcons.home, label: "Back to Home" },
  ];

  const isActive = (path) => location.pathname === path;

  const displayName = user?.displayName || userDoc?.displayName || userDoc?.email?.split("@")[0] || "User";
  const userEmail = user?.email || userDoc?.email || "";
  const userInitial = displayName.charAt(0).toUpperCase();

  const scansLimit = getActionLimit("scans");
  const websitesLimit = getActionLimit("websites");

  return (
    <div className={`
      min-h-screen font-sans
      ${isDarkMode ? "bg-[#0f172a]" : "bg-slate-50"}
    `}>
      <ScrollToTop />

      {/* Mobile Sidebar Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside className={`
        mifty-sidebar mifty-scrollbar
        ${isDarkMode ? "mifty-sidebar-dark mifty-scrollbar-dark" : "mifty-sidebar-light mifty-scrollbar-light"}
        ${sidebarCollapsed ? "mifty-sidebar-collapsed" : ""}
        ${sidebarOpen ? "open" : ""}
      `}>
        {/* Brand / Logo - Clickable to navigate to dashboard */}
        <button 
          onClick={() => navigate("/dashboard")}
          className={`
            mifty-sidebar-brand flex-shrink-0 w-full cursor-pointer
            transition-all duration-200 hover:opacity-80
            ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}
          `}
        >
          <img 
            src="/logo/jarwis-logo-transparent.svg" 
            alt="Jarwis" 
            className="w-10 h-10 object-contain"
          />
          {!sidebarCollapsed && (
            <span className="mifty-sidebar-brand-text">Jarwis</span>
          )}
        </button>

        {/* User Profile Section */}
        <div className={`p-4 border-b flex-shrink-0 ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}`}>
          <div className={`
            p-3 rounded-xl
            ${isDarkMode ? "bg-slate-800/50 border border-slate-700/50" : "bg-gray-50 border border-gray-200"}
          `}>
            <div className="flex items-center gap-3 mb-3">
              <div className={`
                w-10 h-10 rounded-xl flex items-center justify-center text-lg font-bold
                bg-gradient-to-br from-purple-500 to-cyan-500 text-white
                shadow-lg shadow-purple-500/30
              `}>
                {userInitial}
              </div>
              {!sidebarCollapsed && (
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-semibold truncate ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {displayName}
                  </p>
                  <p className={`text-xs truncate ${isDarkMode ? "text-slate-400" : "text-gray-500"}`}>
                    {userEmail}
                  </p>
                </div>
              )}
            </div>
            {!sidebarCollapsed && (
              <SubscriptionBadge plan={planId || userDoc?.plan || "free"} isDarkMode={isDarkMode} />
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-3 overflow-y-auto min-h-0">
          <div className="mifty-nav-section">
            {!sidebarCollapsed && (
              <div className="mifty-nav-section-title">NAVIGATION</div>
            )}
            {navigationItems.map((item) => {
              const isItemActive = isActive(item.href);
              return (
                <button
                  key={item.href}
                  onClick={() => {
                    navigate(item.href);
                    setSidebarOpen(false);
                  }}
                  className={`mifty-nav-item ${isItemActive ? "active" : ""}`}
                  title={sidebarCollapsed ? item.label : undefined}
                >
                  <span className="mifty-nav-item-icon">{item.icon}</span>
                  {!sidebarCollapsed && <span>{item.label}</span>}
                  {!sidebarCollapsed && item.badge && (
                    <span className="mifty-nav-item-badge">{item.badge}</span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="mifty-nav-section mt-4">
            {!sidebarCollapsed && (
              <div className="mifty-nav-section-title">ACCOUNT</div>
            )}
            {bottomNavigationItems.map((item) => {
              const isItemActive = item.isSettings ? settingsOpen : isActive(item.href);
              return (
                <button
                  key={item.href}
                  onClick={() => {
                    if (item.isSettings) {
                      setSettingsOpen(true);
                      setSidebarOpen(false);
                    } else {
                      navigate(item.href);
                      setSidebarOpen(false);
                    }
                  }}
                  className={`mifty-nav-item ${isItemActive ? "active" : ""}`}
                  title={sidebarCollapsed ? item.label : undefined}
                >
                  <span className="mifty-nav-item-icon">{item.icon}</span>
                  {!sidebarCollapsed && <span>{item.label}</span>}
                </button>
              );
            })}
          </div>
        </nav>

        {/* Usage Stats - Compact Dropdown */}
        <div className={`relative flex-shrink-0 ${isDarkMode ? "border-t border-slate-700/50" : "border-t border-gray-200"}`}>
          <button
            onClick={() => setUsageExpanded(!usageExpanded)}
            className={`
              w-full flex items-center ${sidebarCollapsed ? "justify-center px-2" : "justify-between px-4"} py-2
              text-xs transition-all duration-200
              ${isDarkMode 
                ? "text-slate-400 hover:text-slate-300 hover:bg-slate-800/50" 
                : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"
              }
            `}
            title={sidebarCollapsed ? "Usage" : undefined}
          >
            <div className="flex items-center gap-2">
              <svg className={`w-3.5 h-3.5 ${isDarkMode ? "text-slate-500" : "text-gray-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
              </svg>
              {!sidebarCollapsed && <span>Usage: {scansLimit.current || 0}/{scansLimit.unlimited ? "Unlimited" : scansLimit.max} scans</span>}
            </div>
            {!sidebarCollapsed && (
              <svg 
                className={`w-3.5 h-3.5 transition-transform duration-200 ${usageExpanded ? "rotate-180" : ""}`} 
                fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
              </svg>
            )}
          </button>
          
          {/* Dropdown panel */}
          {usageExpanded && (
            <div className={`
              absolute bottom-full left-0 right-0 mb-1 ${sidebarCollapsed ? "left-2 right-auto w-48" : "mx-2"} p-3 rounded-lg shadow-lg z-50
              ${isDarkMode 
                ? "bg-slate-800 border border-slate-700" 
                : "bg-white border border-gray-200"
              }
            `}>
              <div className={`text-xs font-semibold mb-3 ${isDarkMode ? "text-slate-300" : "text-gray-700"}`}>
                Billing Cycle Usage
              </div>
              
              <div className="space-y-3">
                {/* Scans */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className={isDarkMode ? "text-slate-400" : "text-gray-600"}>Scans</span>
                    <span className={isDarkMode ? "text-purple-400" : "text-purple-600"}>{scansLimit.current || 0}/{scansLimit.unlimited ? "Unlimited" : scansLimit.max}</span>
                  </div>
                  <div className={`h-1.5 rounded-full overflow-hidden ${isDarkMode ? "bg-slate-700" : "bg-gray-200"}`}>
                    <div 
                      className="h-full bg-gradient-to-r from-purple-500 to-violet-500 transition-all duration-300"
                      style={{ width: scansLimit.unlimited ? "100%" : `${Math.min(((scansLimit.current || 0) / scansLimit.max) * 100, 100)}%` }}
                    />
                  </div>
                </div>
                
                {/* Websites */}
                <div className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className={isDarkMode ? "text-slate-400" : "text-gray-600"}>Websites</span>
                    <span className={isDarkMode ? "text-cyan-400" : "text-cyan-600"}>{websitesLimit.current || 0}/{websitesLimit.unlimited ? "Unlimited" : websitesLimit.max}</span>
                  </div>
                  <div className={`h-1.5 rounded-full overflow-hidden ${isDarkMode ? "bg-slate-700" : "bg-gray-200"}`}>
                    <div 
                      className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                      style={{ width: websitesLimit.unlimited ? "100%" : `${Math.min(((websitesLimit.current || 0) / websitesLimit.max) * 100, 100)}%` }}
                    />
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Upgrade Banner */}
        {!sidebarCollapsed && planId !== "enterprise" && planId !== "professional" && (
          <div className="mifty-upgrade-banner m-3 flex-shrink-0">
            <h4 className="mifty-upgrade-banner-title">Jarwis Security</h4>
            <p className="mifty-upgrade-banner-text">
              Unlock advanced security features
            </p>
            <button onClick={() => navigate("/pricing")} className="mifty-upgrade-banner-btn">
              Upgrade your plan
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
              </svg>
            </button>
          </div>
        )}
      </aside>

      {/* Main Content Area */}
      <div className={`
        mifty-main-content
        ${isDarkMode ? "mifty-main-content-dark" : "mifty-main-content-light"}
        ${sidebarCollapsed ? "mifty-main-content-collapsed" : ""}
      `}>
        {/* Header */}
        <header className={`
          mifty-header
          ${isDarkMode ? "mifty-header-dark" : "mifty-header-light"}
        `}>
          {/* Left: Mobile menu & Search */}
          <div className="flex items-center gap-4 flex-1">
            {/* Mobile Menu Button */}
            <button
              className={`
                lg:hidden p-2 rounded-xl transition-all duration-300
                ${isDarkMode 
                  ? "hover:bg-white/5 text-slate-400 hover:text-white" 
                  : "hover:bg-gray-100 text-gray-600 hover:text-gray-900"
                }
              `}
              onClick={() => setSidebarOpen(!sidebarOpen)}
            >
              {sidebarOpen ? DashboardIcons.close : DashboardIcons.menu}
            </button>

            {/* Sidebar Collapse Toggle (Desktop) */}
            <button
              className={`
                hidden lg:flex p-2 rounded-xl transition-all duration-300
                ${isDarkMode 
                  ? "hover:bg-white/5 text-slate-400 hover:text-white" 
                  : "hover:bg-gray-100 text-gray-600 hover:text-gray-900"
                }
              `}
              onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
            >
              <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6.75h16.5M3.75 12h16.5m-16.5 5.25H12" />
              </svg>
            </button>

            {/* Search Bar */}
            <div className={`
              mifty-header-search hidden sm:block
              ${isDarkMode ? "mifty-header-search-dark" : "mifty-header-search-light"}
            `}>
              <span className="mifty-header-search-icon">
                {DashboardIcons.search}
              </span>
              <input
                type="text"
                placeholder="Search scans, vulnerabilities..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>

          {/* Right: Actions */}
          <div className="mifty-header-actions">
            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className={`
                mifty-header-action-btn
                ${isDarkMode ? "mifty-header-action-btn-dark" : "mifty-header-action-btn-light"}
              `}
              title={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
            >
              <div className={`transition-transform duration-500 ${isDarkMode ? "rotate-0" : "rotate-180"}`}>
                {isDarkMode ? DashboardIcons.moon : DashboardIcons.sun}
              </div>
            </button>

            {/* Notifications */}
            <button
              className={`
                mifty-header-action-btn
                ${isDarkMode ? "mifty-header-action-btn-dark" : "mifty-header-action-btn-light"}
              `}
            >
              {DashboardIcons.bell}
              <div className="mifty-header-notification-badge"></div>
            </button>

            {/* User Dropdown */}
            <div className="relative" ref={userDropdownRef}>
              <button
                onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                className={`
                  mifty-user-dropdown
                  ${isDarkMode ? "mifty-user-dropdown-dark" : "mifty-user-dropdown-light"}
                `}
              >
                <div className="mifty-user-avatar">
                  {userInitial}
                </div>
                <div className="hidden md:block text-left">
                  <p className={`text-sm font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {displayName}
                  </p>
                  <p className={`text-xs ${isDarkMode ? "text-slate-400" : "text-gray-500"}`}>
                    {planId || "Free"}
                  </p>
                </div>
                <span className={`hidden md:block ${isDarkMode ? "text-slate-400" : "text-gray-500"}`}>
                  {DashboardIcons.chevronDown}
                </span>
              </button>

              {/* Dropdown Menu */}
              {userDropdownOpen && (
                <div className={`
                  absolute right-0 mt-2 w-56 rounded-xl shadow-xl z-50 py-2
                  mifty-animate-scale-in origin-top-right
                  ${isDarkMode 
                    ? "bg-slate-800 border border-slate-700" 
                    : "bg-white border border-gray-200"
                  }
                `}>
                  <div className={`px-4 py-3 border-b ${isDarkMode ? "border-slate-700" : "border-gray-100"}`}>
                    <p className={`text-sm font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                      {displayName}
                    </p>
                    <p className={`text-xs truncate ${isDarkMode ? "text-slate-400" : "text-gray-500"}`}>
                      {userEmail}
                    </p>
                  </div>
                  <div className="py-1">
                    <button
                      onClick={() => { setSettingsOpen(true); setUserDropdownOpen(false); }}
                      className={`
                        w-full flex items-center gap-3 px-4 py-2.5 text-sm text-left
                        ${isDarkMode 
                          ? "text-slate-300 hover:bg-white/5 hover:text-white" 
                          : "text-gray-700 hover:bg-gray-50 hover:text-gray-900"
                        }
                      `}
                    >
                      {DashboardIcons.settings}
                      <span>Settings</span>
                    </button>
                    <button
                      onClick={() => { navigate("/dashboard/billing"); setUserDropdownOpen(false); }}
                      className={`
                        w-full flex items-center gap-3 px-4 py-2.5 text-sm text-left
                        ${isDarkMode 
                          ? "text-slate-300 hover:bg-white/5 hover:text-white" 
                          : "text-gray-700 hover:bg-gray-50 hover:text-gray-900"
                        }
                      `}
                    >
                      <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M2.25 8.25h19.5M2.25 9h19.5m-16.5 5.25h6m-6 2.25h3m-3.75 3h15a2.25 2.25 0 002.25-2.25V6.75A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25v10.5A2.25 2.25 0 004.5 19.5z" />
                      </svg>
                      <span>Billing</span>
                    </button>
                  </div>
                  <div className={`border-t py-1 ${isDarkMode ? "border-slate-700" : "border-gray-100"}`}>
                    <button
                      onClick={() => { handleLogout(); setUserDropdownOpen(false); }}
                      className={`
                        w-full flex items-center gap-3 px-4 py-2.5 text-sm text-left
                        ${isDarkMode 
                          ? "text-red-400 hover:bg-red-500/10" 
                          : "text-red-600 hover:bg-red-50"
                        }
                      `}
                    >
                      {DashboardIcons.logout}
                      <span>Logout</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main className="min-h-[calc(100vh-70px)]">
          {children}
        </main>

        {/* Footer */}
        <footer className={`
          px-6 py-4 text-center text-sm border-t
          ${isDarkMode 
            ? "text-slate-500 border-slate-800" 
            : "text-gray-500 border-gray-200"
          }
        `}>
          <p>(C) 2026 Jarwis AGI - Autonomous Cybersecurity Platform</p>
        </footer>
      </div>

      {/* Settings Panel */}
      <SettingsPanel 
        isOpen={settingsOpen} 
        onClose={() => {
          setSettingsOpen(false);
          setSettingsInitialTab("account");
        }} 
        isDarkMode={isDarkMode}
        initialTab={settingsInitialTab}
      />
    </div>
  );
};

export default MiftyJarwisLayout;
