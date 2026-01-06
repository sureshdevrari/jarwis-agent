// MiftyAdminLayout.jsx - Modern Mifty-inspired Admin Dashboard Layout
// Premium e-commerce style with smooth animations for administrators

import { useState, useRef, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import ScrollToTop from "../ScrollToTop";
import SettingsPanel from "../settings/SettingsPanel";

// Admin Dashboard Icons
const AdminIcons = {
  overview: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3.75 6A2.25 2.25 0 016 3.75h2.25A2.25 2.25 0 0110.5 6v2.25a2.25 2.25 0 01-2.25 2.25H6a2.25 2.25 0 01-2.25-2.25V6zM3.75 15.75A2.25 2.25 0 016 13.5h2.25a2.25 2.25 0 012.25 2.25V18a2.25 2.25 0 01-2.25 2.25H6A2.25 2.25 0 013.75 18v-2.25zM13.5 6a2.25 2.25 0 012.25-2.25H18A2.25 2.25 0 0120.25 6v2.25A2.25 2.25 0 0118 10.5h-2.25a2.25 2.25 0 01-2.25-2.25V6zM13.5 15.75a2.25 2.25 0 012.25-2.25H18a2.25 2.25 0 012.25 2.25V18A2.25 2.25 0 0118 20.25h-2.25A2.25 2.25 0 0113.5 18v-2.25z" />
    </svg>
  ),
  requests: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  submissions: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21.75 6.75v10.5a2.25 2.25 0 01-2.25 2.25h-15a2.25 2.25 0 01-2.25-2.25V6.75m19.5 0A2.25 2.25 0 0019.5 4.5h-15a2.25 2.25 0 00-2.25 2.25m19.5 0v.243a2.25 2.25 0 01-1.07 1.916l-7.5 4.615a2.25 2.25 0 01-2.36 0L3.32 8.91a2.25 2.25 0 01-1.07-1.916V6.75" />
    </svg>
  ),
  users: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 19.128a9.38 9.38 0 002.625.372 9.337 9.337 0 004.121-.952 4.125 4.125 0 00-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 018.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0111.964-3.07M12 6.375a3.375 3.375 0 11-6.75 0 3.375 3.375 0 016.75 0zm8.25 2.25a2.625 2.625 0 11-5.25 0 2.625 2.625 0 015.25 0z" />
    </svg>
  ),
  vulnerability: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.25-8.25-3.286zm0 13.036h.008v.008H12v-.008z" />
    </svg>
  ),
  audit: (
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
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
  shield: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.25-8.25-3.286z" />
    </svg>
  ),
};

// Admin Stats Display
const AdminStatsDisplay = ({ isDarkMode }) => {
  const stats = {
    pendingRequests: 12,
    activeUsers: 156,
    todayScans: 43,
  };

  return (
    <div className={`px-4 py-4 border-t ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}`}>
      <div className={`text-xs font-semibold uppercase tracking-wider mb-3 ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>
        System Overview
      </div>
      
      <div className="space-y-3">
        <div className={`flex items-center justify-between p-2.5 rounded-lg ${isDarkMode ? "bg-rose-500/10 border border-rose-500/20" : "bg-red-50 border border-red-200"}`}>
          <span className={`text-xs ${isDarkMode ? "text-slate-300" : "text-gray-700"}`}>Pending Requests</span>
          <span className={`text-sm font-bold ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>{stats.pendingRequests}</span>
        </div>
        <div className={`flex items-center justify-between p-2.5 rounded-lg ${isDarkMode ? "bg-emerald-500/10 border border-emerald-500/20" : "bg-green-50 border border-green-200"}`}>
          <span className={`text-xs ${isDarkMode ? "text-slate-300" : "text-gray-700"}`}>Active Users</span>
          <span className={`text-sm font-bold ${isDarkMode ? "text-emerald-400" : "text-green-600"}`}>{stats.activeUsers}</span>
        </div>
        <div className={`flex items-center justify-between p-2.5 rounded-lg ${isDarkMode ? "bg-amber-500/10 border border-amber-500/20" : "bg-amber-50 border border-amber-200"}`}>
          <span className={`text-xs ${isDarkMode ? "text-slate-300" : "text-gray-700"}`}>Today's Scans</span>
          <span className={`text-sm font-bold ${isDarkMode ? "text-amber-400" : "text-amber-600"}`}>{stats.todayScans}</span>
        </div>
      </div>
    </div>
  );
};

const MiftyAdminLayout = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, userDoc, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const [searchQuery, setSearchQuery] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [userDropdownOpen, setUserDropdownOpen] = useState(false);
  const userDropdownRef = useRef(null);

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

  const adminNavigationItems = [
    { href: "/admin", icon: AdminIcons.overview, label: "Overview" },
    { href: "/admin/requests", icon: AdminIcons.requests, label: "Access Requests", badge: "12" },
    { href: "/admin/submissions", icon: AdminIcons.submissions, label: "Submissions" },
    { href: "/admin/users", icon: AdminIcons.users, label: "Users & Tenants" },
    { href: "/admin/push-vulnerability", icon: AdminIcons.vulnerability, label: "Push Vulnerability" },
    { href: "/admin/audit-log", icon: AdminIcons.audit, label: "Audit Log" },
  ];

  const bottomNavigationItems = [
    { href: "settings", icon: AdminIcons.settings, label: "Settings", isSettings: true },
    { href: "/", icon: AdminIcons.home, label: "Back to Home" },
  ];

  const isActive = (path) => location.pathname === path;

  const displayName = user?.displayName || userDoc?.displayName || userDoc?.email?.split("@")[0] || "Admin";
  const userEmail = user?.email || userDoc?.email || "";
  const userInitial = displayName.charAt(0).toUpperCase();

  // Override sidebar colors for admin (rose/red theme)
  const adminSidebarStyle = {
    '--mifty-primary': '#e11d48',
    '--mifty-primary-light': '#fb7185',
    '--mifty-primary-dark': '#be123c',
    '--mifty-primary-rgb': '225, 29, 72',
  };

  return (
    <div 
      className={`min-h-screen font-sans ${isDarkMode ? "bg-[#0f172a]" : "bg-slate-50"}`}
      style={adminSidebarStyle}
    >
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
        fixed left-0 top-0 h-screen z-50 overflow-hidden
        transition-all duration-300 ease-out
        ${sidebarCollapsed ? "w-20" : "w-64"}
        ${sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
        ${isDarkMode 
          ? "bg-gradient-to-b from-slate-900 via-slate-900 to-rose-950/30 border-r border-slate-700/50" 
          : "bg-white border-r border-gray-200 shadow-xl"
        }
      `}>
        {/* Brand / Logo */}
        <div className={`
          p-5 flex items-center gap-3 border-b
          ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}
        `}>
          <div className={`
            w-10 h-10 rounded-xl flex items-center justify-center
            bg-gradient-to-br from-rose-500 to-red-600
            shadow-lg shadow-rose-500/30
          `}>
            {AdminIcons.shield}
          </div>
          {!sidebarCollapsed && (
            <div>
              <span className="text-xl font-bold bg-gradient-to-r from-rose-400 to-red-400 bg-clip-text text-transparent">
                Jarwis
              </span>
              <span className={`block text-xs ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>
                Admin Panel
              </span>
            </div>
          )}
        </div>

        {/* Admin Profile Section */}
        <div className={`p-4 border-b ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}`}>
          <div className={`
            p-3 rounded-xl
            ${isDarkMode ? "bg-slate-800/50 border border-slate-700/50" : "bg-gray-50 border border-gray-200"}
          `}>
            <div className="flex items-center gap-3">
              <div className={`
                w-10 h-10 rounded-xl flex items-center justify-center text-lg font-bold
                bg-gradient-to-br from-rose-500 to-red-600 text-white
                shadow-lg shadow-rose-500/30
              `}>
                {userInitial}
              </div>
              {!sidebarCollapsed && (
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-semibold truncate ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {displayName}
                  </p>
                  <p className={`text-xs ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>
                    Administrator
                  </p>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className={`flex-1 p-3 overflow-y-auto mifty-scrollbar ${isDarkMode ? "mifty-scrollbar-dark" : "mifty-scrollbar-light"}`}>
          <div className="space-y-1">
            {!sidebarCollapsed && (
              <div className={`px-3 py-2 text-[10px] font-semibold uppercase tracking-wider ${isDarkMode ? "text-slate-500" : "text-gray-500"}`}>
                MANAGEMENT
              </div>
            )}
            {adminNavigationItems.map((item) => {
              const isItemActive = isActive(item.href);
              return (
                <button
                  key={item.href}
                  onClick={() => {
                    navigate(item.href);
                    setSidebarOpen(false);
                  }}
                  className={`
                    w-full flex items-center gap-3 px-3 py-2.5 rounded-xl
                    text-left transition-all duration-200
                    relative overflow-hidden group
                    ${isItemActive
                      ? isDarkMode
                        ? "bg-gradient-to-r from-rose-500/20 to-rose-600/10 text-rose-300 border border-rose-500/30"
                        : "bg-gradient-to-r from-red-100 to-rose-50 text-red-700 border border-red-300"
                      : isDarkMode
                        ? "text-slate-400 hover:text-white hover:bg-slate-800/60 border border-transparent"
                        : "text-gray-700 hover:text-gray-900 hover:bg-gray-50 border border-transparent"
                    }
                  `}
                  title={sidebarCollapsed ? item.label : undefined}
                >
                  {/* Active indicator */}
                  {isItemActive && (
                    <div className={`
                      absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 rounded-r-full
                      bg-gradient-to-b from-rose-400 to-red-500
                    `}></div>
                  )}
                  
                  <span className={`
                    transition-all duration-200 ml-1
                    ${isItemActive 
                      ? isDarkMode ? "text-rose-400" : "text-red-600"
                      : isDarkMode ? "text-slate-400 group-hover:text-rose-400" : "text-gray-600 group-hover:text-red-600"
                    }
                  `}>
                    {item.icon}
                  </span>
                  
                  {!sidebarCollapsed && (
                    <>
                      <span className="font-medium text-sm">{item.label}</span>
                      {item.badge && (
                        <span className={`
                          ml-auto px-2 py-0.5 rounded-full text-[10px] font-bold
                          ${isDarkMode 
                            ? "bg-rose-500/20 text-rose-400 border border-rose-500/30" 
                            : "bg-red-100 text-red-700 border border-red-200"
                          }
                          animate-pulse
                        `}>
                          {item.badge}
                        </span>
                      )}
                    </>
                  )}
                </button>
              );
            })}
          </div>

          <div className="space-y-1 mt-6">
            {!sidebarCollapsed && (
              <div className={`px-3 py-2 text-[10px] font-semibold uppercase tracking-wider ${isDarkMode ? "text-slate-500" : "text-gray-500"}`}>
                ACCOUNT
              </div>
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
                  className={`
                    w-full flex items-center gap-3 px-3 py-2.5 rounded-xl
                    text-left transition-all duration-200
                    ${isItemActive
                      ? isDarkMode
                        ? "bg-gradient-to-r from-rose-500/20 to-rose-600/10 text-rose-300 border border-rose-500/30"
                        : "bg-gradient-to-r from-red-100 to-rose-50 text-red-700 border border-red-300"
                      : isDarkMode
                        ? "text-slate-400 hover:text-white hover:bg-slate-800/60 border border-transparent"
                        : "text-gray-700 hover:text-gray-900 hover:bg-gray-50 border border-transparent"
                    }
                  `}
                  title={sidebarCollapsed ? item.label : undefined}
                >
                  <span className={`ml-1 ${isDarkMode ? "text-slate-400" : "text-gray-600"}`}>
                    {item.icon}
                  </span>
                  {!sidebarCollapsed && <span className="font-medium text-sm">{item.label}</span>}
                </button>
              );
            })}
          </div>
        </nav>

        {/* Admin Stats */}
        {!sidebarCollapsed && <AdminStatsDisplay isDarkMode={isDarkMode} />}
      </aside>

      {/* Main Content Area */}
      <div className={`
        transition-all duration-300
        ${sidebarCollapsed ? "lg:ml-20" : "lg:ml-64"}
        ${isDarkMode ? "bg-[#0f172a]" : "bg-slate-50"}
        min-h-screen
      `}>
        {/* Header */}
        <header className={`
          sticky top-0 z-30 h-[70px] flex items-center justify-between px-6
          backdrop-blur-xl
          ${isDarkMode 
            ? "bg-slate-900/80 border-b border-slate-700/50" 
            : "bg-white/80 border-b border-gray-200"
          }
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
              {sidebarOpen ? AdminIcons.close : AdminIcons.menu}
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

            {/* Admin Badge */}
            <div className={`
              hidden sm:flex items-center gap-2 px-3 py-1.5 rounded-full
              ${isDarkMode 
                ? "bg-rose-500/10 border border-rose-500/30" 
                : "bg-red-50 border border-red-200"
              }
            `}>
              <div className="w-2 h-2 rounded-full bg-rose-500 animate-pulse"></div>
              <span className={`text-xs font-bold ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>
                ADMIN MODE
              </span>
            </div>

            {/* Search Bar */}
            <div className={`
              hidden md:flex flex-1 max-w-md items-center gap-3 px-4 py-2.5 rounded-xl
              ${isDarkMode 
                ? "bg-slate-800/50 border border-slate-700/50 focus-within:border-rose-500/50" 
                : "bg-gray-50 border border-gray-200 focus-within:border-red-400"
              }
              transition-all duration-200
            `}>
              <span className={isDarkMode ? "text-slate-400" : "text-gray-500"}>
                {AdminIcons.search}
              </span>
              <input
                type="text"
                placeholder="Search users, logs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`
                  flex-1 bg-transparent outline-none text-sm
                  ${isDarkMode 
                    ? "text-white placeholder-slate-400" 
                    : "text-gray-900 placeholder-gray-500"
                  }
                `}
              />
            </div>
          </div>

          {/* Right: Actions */}
          <div className="flex items-center gap-2">
            {/* Theme Toggle */}
            <button
              onClick={toggleTheme}
              className={`
                p-2.5 rounded-xl transition-all duration-300
                ${isDarkMode 
                  ? "hover:bg-white/5 text-slate-400 hover:text-rose-400" 
                  : "hover:bg-gray-100 text-gray-600 hover:text-amber-500"
                }
              `}
              title={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
            >
              {isDarkMode ? AdminIcons.moon : AdminIcons.sun}
            </button>

            {/* Notifications */}
            <button
              className={`
                p-2.5 rounded-xl relative transition-all duration-300
                ${isDarkMode 
                  ? "hover:bg-white/5 text-slate-400 hover:text-white" 
                  : "hover:bg-gray-100 text-gray-600 hover:text-gray-900"
                }
              `}
            >
              {AdminIcons.bell}
              <span className="absolute top-1 right-1 w-2.5 h-2.5 bg-rose-500 rounded-full border-2 border-slate-900 animate-pulse"></span>
            </button>

            {/* User Dropdown */}
            <div className="relative" ref={userDropdownRef}>
              <button
                onClick={() => setUserDropdownOpen(!userDropdownOpen)}
                className={`
                  flex items-center gap-3 px-3 py-2 rounded-xl
                  transition-all duration-200
                  ${isDarkMode 
                    ? "hover:bg-white/5" 
                    : "hover:bg-gray-50"
                  }
                `}
              >
                <div className={`
                  w-9 h-9 rounded-xl flex items-center justify-center text-sm font-bold
                  bg-gradient-to-br from-rose-500 to-red-600 text-white
                  shadow-lg shadow-rose-500/30
                `}>
                  {userInitial}
                </div>
                <div className="hidden md:block text-left">
                  <p className={`text-sm font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {displayName}
                  </p>
                  <p className={`text-xs ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>
                    Admin
                  </p>
                </div>
                <span className={`hidden md:block ${isDarkMode ? "text-slate-400" : "text-gray-500"}`}>
                  {AdminIcons.chevronDown}
                </span>
              </button>

              {/* Dropdown Menu */}
              {userDropdownOpen && (
                <div className={`
                  absolute right-0 mt-2 w-56 rounded-xl shadow-xl z-50 py-2
                  animate-in fade-in slide-in-from-top-2 duration-200
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
                      {AdminIcons.settings}
                      <span>Settings</span>
                    </button>
                  </div>
                  <div className={`border-t py-1 ${isDarkMode ? "border-slate-700" : "border-gray-100"}`}>
                    <button
                      onClick={() => { handleLogout(); setUserDropdownOpen(false); }}
                      className={`
                        w-full flex items-center gap-3 px-4 py-2.5 text-sm text-left
                        ${isDarkMode 
                          ? "text-rose-400 hover:bg-rose-500/10" 
                          : "text-red-600 hover:bg-red-50"
                        }
                      `}
                    >
                      {AdminIcons.logout}
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
          <p>(C) 2026 Jarwis AGI - Admin Console</p>
        </footer>
      </div>

      {/* Settings Panel */}
      <SettingsPanel 
        isOpen={settingsOpen} 
        onClose={() => setSettingsOpen(false)} 
        isDarkMode={isDarkMode}
      />
    </div>
  );
};

export default MiftyAdminLayout;
