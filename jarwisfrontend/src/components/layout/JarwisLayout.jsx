import { useState, useRef, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import ScrollToTop from "../ScrollToTop";
import SettingsPanel from "../settings/SettingsPanel";

// Professional Cyber Security Icons (SVG)
const Icons = {
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
    <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.456 2.456L21.75 6l-1.035.259a3.375 3.375 0 00-2.456 2.456zM16.894 20.567L16.5 21.75l-.394-1.183a2.25 2.25 0 00-1.423-1.423L13.5 18.75l1.183-.394a2.25 2.25 0 001.423-1.423l.394-1.183.394 1.183a2.25 2.25 0 001.423 1.423l1.183.394-1.183.394a2.25 2.25 0 00-1.423 1.423z" />
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
};

// Subscription Badge Component - Theme Aware
const SubscriptionBadge = ({ plan, isDarkMode }) => {
  const badgeConfig = {
    free: {
      label: "FREE",
      darkBgClass: "bg-slate-500/20 border-slate-400/30",
      lightBgClass: "bg-gray-100 border-gray-300",
      darkTextClass: "text-slate-300",
      lightTextClass: "text-gray-700",
      glowClass: "shadow-slate-500/20",
      iconBg: "bg-gray-500",
    },
    individual: {
      label: "INDIVIDUAL",
      darkBgClass: "bg-cyan-500/20 border-cyan-400/30",
      lightBgClass: "bg-cyan-50 border-cyan-300",
      darkTextClass: "text-cyan-300",
      lightTextClass: "text-cyan-700",
      glowClass: "shadow-cyan-500/30",
      iconBg: "bg-cyan-500",
    },
    professional: {
      label: "PRO",
      darkBgClass: "bg-violet-500/20 border-violet-400/30",
      lightBgClass: "bg-violet-50 border-violet-300",
      darkTextClass: "text-violet-300",
      lightTextClass: "text-violet-700",
      glowClass: "shadow-violet-500/30",
      iconBg: "bg-violet-500",
    },
    enterprise: {
      label: "ENTERPRISE",
      darkBgClass: "bg-amber-500/20 border-amber-400/30",
      lightBgClass: "bg-amber-50 border-amber-300",
      darkTextClass: "text-amber-300",
      lightTextClass: "text-amber-700",
      glowClass: "shadow-amber-500/30",
      iconBg: "bg-amber-500",
    }
  };

  const config = badgeConfig[plan] || badgeConfig.free;

  return (
    <div className={`
      inline-flex items-center gap-2 px-3 py-1.5 rounded-lg border 
      ${isDarkMode ? config.darkBgClass : config.lightBgClass} 
      ${isDarkMode ? config.darkTextClass : config.lightTextClass}
      ${isDarkMode ? `shadow-lg ${config.glowClass}` : "shadow-sm"}
      backdrop-blur-sm
      transition-all duration-300 hover:scale-105
    `}>
      <div className={`w-2 h-2 rounded-full ${config.iconBg} animate-pulse`}></div>
      <span className="text-xs font-bold tracking-wider">{config.label}</span>
    </div>
  );
};

// Scan Quota Progress Component - Collapsible
const ScanQuotaDisplay = ({ isDarkMode, currentPlan, usage, getActionLimit }) => {
  const [isExpanded, setIsExpanded] = useState(false);
  const scansLimit = getActionLimit("scans");
  const websitesLimit = getActionLimit("websites");
  
  // Calculate remaining for summary
  const scansUsed = scansLimit.current || 0;
  const scansMax = scansLimit.unlimited ? "Unlimited" : scansLimit.max;
  const websitesUsed = websitesLimit.current || 0;
  const websitesMax = websitesLimit.unlimited ? "Unlimited" : websitesLimit.max;

  return (
    <div className="relative">
      {/* Minimal dropdown trigger */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className={`
          w-full flex items-center justify-between px-4 py-2
          text-xs transition-all duration-200
          ${isDarkMode 
            ? "text-gray-400 hover:text-gray-300 hover:bg-slate-800/50" 
            : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"
          }
        `}
      >
        <div className="flex items-center gap-2">
          <svg className={`w-3.5 h-3.5 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
          </svg>
          <span>Usage: {scansUsed}/{scansMax} scans</span>
        </div>
        <svg 
          className={`w-3.5 h-3.5 transition-transform duration-200 ${isExpanded ? "rotate-180" : ""}`} 
          fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>
      
      {/* Dropdown panel - appears above the button */}
      {isExpanded && (
        <div className={`
          absolute bottom-full left-0 right-0 mb-1 mx-2 p-3 rounded-lg shadow-lg z-50
          ${isDarkMode 
            ? "bg-slate-800 border border-slate-700" 
            : "bg-white border border-gray-200"
          }
        `}>
          <div className={`text-xs font-semibold mb-3 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
            Billing Cycle Usage
          </div>
          
          <div className="space-y-3">
            {/* Scans */}
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className={isDarkMode ? "text-gray-400" : "text-gray-600"}>Scans</span>
                <span className={isDarkMode ? "text-cyan-400" : "text-blue-600"}>{scansUsed}/{scansMax}</span>
              </div>
              <div className={`h-1.5 rounded-full overflow-hidden ${isDarkMode ? "bg-slate-700" : "bg-gray-200"}`}>
                <div 
                  className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 transition-all duration-300"
                  style={{ width: scansLimit.unlimited ? "100%" : `${Math.min((scansUsed / scansLimit.max) * 100, 100)}%` }}
                />
              </div>
            </div>
            
            {/* Websites */}
            <div className="space-y-1">
              <div className="flex items-center justify-between text-xs">
                <span className={isDarkMode ? "text-gray-400" : "text-gray-600"}>Websites</span>
                <span className={isDarkMode ? "text-violet-400" : "text-purple-600"}>{websitesUsed}/{websitesMax}</span>
              </div>
              <div className={`h-1.5 rounded-full overflow-hidden ${isDarkMode ? "bg-slate-700" : "bg-gray-200"}`}>
                <div 
                  className="h-full bg-gradient-to-r from-violet-500 to-purple-500 transition-all duration-300"
                  style={{ width: websitesLimit.unlimited ? "100%" : `${Math.min((websitesUsed / websitesLimit.max) * 100, 100)}%` }}
                />
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const JarwisLayout = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, userDoc, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const { currentPlan, planId, usage, getActionLimit } = useSubscription();
  const [searchQuery, setSearchQuery] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [settingsInitialTab, setSettingsInitialTab] = useState("account");
  const [hoveredNav, setHoveredNav] = useState(null);

  // Handle opening settings from route state (e.g., from Quick Actions upgrade prompt)
  useEffect(() => {
    if (location.state?.openSettings) {
      setSettingsOpen(true);
      if (location.state?.settingsTab) {
        setSettingsInitialTab(location.state.settingsTab);
      }
      // Clear the state to prevent reopening on refresh
      navigate(location.pathname, { replace: true, state: {} });
    }
  }, [location.state, navigate, location.pathname]);

  useEffect(() => {
    if (userDoc.role === "admin" || userDoc.role === "super_admin") {
      navigate("/admin");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [userDoc.role]);

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

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  const navigationItems = [
    { href: "/dashboard", icon: Icons.dashboard, label: "Dashboard" },
    { href: "/dashboard/new-scan", icon: Icons.scan, label: "New Scan" },
    { href: "/dashboard/scan-history", icon: Icons.history, label: "Scan History" },
    { href: "/dashboard/scanning", icon: Icons.active, label: "Active Scan" },
    { href: "/dashboard/vulnerabilities", icon: Icons.vulnerabilities, label: "Vulnerabilities" },
    { href: "/dashboard/jarwis-chatbot", icon: Icons.ai, label: "Jarwis AGI" },
    { href: "settings", icon: Icons.settings, label: "Settings", isSettings: true },
    { href: "/", icon: Icons.home, label: "Back to Home" },
  ];

  const isActive = (path) => location.pathname === path;

  const canvasRef = useRef(null);

  // Cyber Grid Animation
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");

    let width = (canvas.width = window.innerWidth);
    let height = (canvas.height = window.innerHeight);
    let animationId;
    let particles = [];
    
    // Create cyber particles
    const createParticles = () => {
      particles = [];
      for (let i = 0; i < 50; i++) {
        particles.push({
          x: Math.random() * width,
          y: Math.random() * height,
          size: Math.random() * 2 + 0.5,
          speedX: (Math.random() - 0.5) * 0.5,
          speedY: (Math.random() - 0.5) * 0.5,
          opacity: Math.random() * 0.5 + 0.2,
        });
      }
    };
    
    createParticles();

    const animate = () => {
      ctx.clearRect(0, 0, width, height);
      
      // Draw grid
      ctx.strokeStyle = isDarkMode ? "rgba(6, 182, 212, 0.03)" : "rgba(59, 130, 246, 0.05)";
      ctx.lineWidth = 1;
      const gridSize = 40;
      
      for (let x = 0; x < width; x += gridSize) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, height);
        ctx.stroke();
      }
      for (let y = 0; y < height; y += gridSize) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(width, y);
        ctx.stroke();
      }
      
      // Draw and update particles
      particles.forEach((p, i) => {
        p.x += p.speedX;
        p.y += p.speedY;
        
        if (p.x < 0 || p.x > width) p.speedX *= -1;
        if (p.y < 0 || p.y > height) p.speedY *= -1;
        
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx.fillStyle = isDarkMode 
          ? `rgba(6, 182, 212, ${p.opacity})`
          : `rgba(59, 130, 246, ${p.opacity})`;
        ctx.fill();
        
        // Draw connections
        particles.slice(i + 1).forEach(p2 => {
          const dx = p.x - p2.x;
          const dy = p.y - p2.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          
          if (dist < 120) {
            ctx.beginPath();
            ctx.moveTo(p.x, p.y);
            ctx.lineTo(p2.x, p2.y);
            ctx.strokeStyle = isDarkMode
              ? `rgba(6, 182, 212, ${0.1 * (1 - dist / 120)})`
              : `rgba(59, 130, 246, ${0.1 * (1 - dist / 120)})`;
            ctx.stroke();
          }
        });
      });

      animationId = requestAnimationFrame(animate);
    };

    animate();

    const resize = () => {
      width = canvas.width = window.innerWidth;
      height = canvas.height = window.innerHeight;
      createParticles();
    };

    window.addEventListener("resize", resize);

    return () => {
      cancelAnimationFrame(animationId);
      window.removeEventListener("resize", resize);
    };
  }, [isDarkMode]);

  // Get user's display name
  const displayName = user?.displayName || userDoc?.displayName || userDoc?.email?.split("@")[0] || "User";
  const userEmail = user?.email || userDoc?.email || "";

  return (
    <div className={`
      min-h-screen font-sans relative overflow-hidden
      ${isDarkMode 
        ? "bg-[#0a0e17] text-gray-100" 
        : "bg-gradient-to-br from-slate-50 via-white to-blue-50 text-gray-900"
      }
    `}>
      <ScrollToTop />
      
      {/* Animated Canvas Background */}
      <canvas ref={canvasRef} className="absolute inset-0 z-0" />

      {/* Gradient Overlays */}
      <div className="absolute inset-0 pointer-events-none z-0">
        <div className={`
          absolute top-0 left-0 w-96 h-96 rounded-full blur-[128px] opacity-30
          ${isDarkMode ? "bg-cyan-600" : "bg-blue-400"}
        `}></div>
        <div className={`
          absolute bottom-0 right-0 w-80 h-80 rounded-full blur-[128px] opacity-20
          ${isDarkMode ? "bg-violet-600" : "bg-purple-400"}
        `}></div>
        <div className={`
          absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 
          w-[600px] h-[600px] rounded-full blur-[200px] opacity-10
          ${isDarkMode ? "bg-blue-500" : "bg-cyan-300"}
        `}></div>
      </div>

      {/* Grid Container */}
      <div className="relative z-10 min-h-screen grid grid-cols-1 lg:grid-cols-[280px_1fr]">
        
        {/* Mobile Sidebar Overlay */}
        {sidebarOpen && (
          <div
            className="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 lg:hidden"
            onClick={() => setSidebarOpen(false)}
          />
        )}

        {/* Sidebar */}
        <aside className={`
          fixed lg:sticky top-0 left-0 h-screen w-80 lg:w-[280px] z-50 lg:z-10
          ${isDarkMode 
            ? "bg-[#0d1321]/90 border-r border-cyan-500/10" 
            : "bg-white/80 border-r border-blue-200/50 shadow-xl"
          }
          backdrop-blur-xl
          transform transition-transform duration-300 ease-out
          ${sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
          flex flex-col
        `}>
          
          {/* User Profile Section */}
          <div className={`
            p-5 border-b
            ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}
          `}>
            
            {/* User Profile Card */}
            <div className={`
              p-3 rounded-xl
              ${isDarkMode 
                ? "bg-slate-800/50 border border-slate-700/50" 
                : "bg-gray-50 border border-gray-200"
              }
            `}>
              <div className="flex items-center gap-3 mb-3">
                <div className={`
                  w-10 h-10 rounded-lg flex items-center justify-center text-lg font-bold
                  ${isDarkMode 
                    ? "bg-gradient-to-br from-cyan-500/30 to-blue-600/30 text-cyan-300 border border-cyan-500/20" 
                    : "bg-gradient-to-br from-blue-100 to-cyan-100 text-blue-700 border border-blue-200"
                  }
                `}>
                  {displayName.charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-semibold truncate ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {displayName}
                  </p>
                  <p className={`text-xs truncate ${isDarkMode ? "text-slate-400" : "text-gray-500"}`}>
                    {userEmail}
                  </p>
                </div>
              </div>
              <SubscriptionBadge plan={planId || userDoc?.plan || "free"} isDarkMode={isDarkMode} />
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-1.5 overflow-y-auto">
            {navigationItems.map((item, index) => {
              const isItemActive = item.isSettings ? settingsOpen : isActive(item.href);
              const isHovered = hoveredNav === index;
              
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
                  onMouseEnter={() => setHoveredNav(index)}
                  onMouseLeave={() => setHoveredNav(null)}
                  className={`
                    w-full flex items-center gap-3 px-4 py-3 rounded-xl
                    text-left transition-all duration-300 ease-out
                    relative overflow-hidden group
                    ${isItemActive
                      ? isDarkMode
                        ? "bg-gradient-to-r from-cyan-500/20 to-blue-600/10 text-cyan-300 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                        : "bg-gradient-to-r from-blue-100 to-cyan-50 text-blue-700 border border-blue-300 shadow-md"
                      : isDarkMode
                        ? "text-gray-300 hover:text-white hover:bg-slate-800/60 border border-transparent hover:border-slate-700/50"
                        : "text-gray-700 hover:text-gray-900 hover:bg-white hover:shadow-md border border-transparent hover:border-gray-200"
                    }
                    ${isHovered && !isItemActive ? "transform scale-[1.02]" : ""}
                  `}
                >
                  {/* Glow effect on hover */}
                  {isHovered && !isItemActive && (
                    <div className={`
                      absolute inset-0 rounded-xl opacity-50
                      ${isDarkMode 
                        ? "bg-gradient-to-r from-cyan-500/5 to-transparent" 
                        : "bg-gradient-to-r from-blue-500/5 to-transparent"
                      }
                    `}></div>
                  )}
                  
                  <span className={`
                    relative z-10 transition-all duration-300
                    ${isHovered || isItemActive ? "scale-110" : ""}
                    ${isItemActive 
                      ? isDarkMode ? "text-cyan-400" : "text-blue-600"
                      : isDarkMode ? "text-gray-400 group-hover:text-cyan-400" : "text-gray-600 group-hover:text-blue-600"
                    }
                  `}>
                    {item.icon}
                  </span>
                  <span className={`relative z-10 font-medium text-sm ${!isItemActive && (isDarkMode ? "text-gray-300" : "text-gray-700")}`}>{item.label}</span>
                  
                  {/* Active indicator */}
                  {isItemActive && (
                    <div className={`
                      absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 rounded-r-full
                      ${isDarkMode ? "bg-cyan-400" : "bg-blue-600"}
                    `}></div>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Scan Quota Display */}
          <ScanQuotaDisplay 
            isDarkMode={isDarkMode}
            currentPlan={currentPlan}
            usage={usage}
            getActionLimit={getActionLimit}
          />

          {/* Upgrade CTA (for non-enterprise users) */}
          {planId !== "enterprise" && planId !== "professional" && (
            <div className={`
              mx-4 mb-4 p-4 rounded-xl
              ${isDarkMode 
                ? "bg-gradient-to-br from-violet-600/20 to-cyan-600/20 border border-violet-500/30" 
                : "bg-gradient-to-br from-blue-100 to-purple-100 border border-blue-200"
              }
            `}>
              <p className={`text-xs font-semibold mb-2 ${isDarkMode ? "text-violet-300" : "text-violet-700"}`}>
                 Upgrade for more power
              </p>
              <button
                onClick={() => navigate("/pricing")}
                className={`
                  w-full py-2 px-3 rounded-lg text-xs font-bold
                  transition-all duration-300 hover:scale-105
                  ${isDarkMode 
                    ? "bg-gradient-to-r from-violet-600 to-cyan-600 text-white shadow-lg shadow-violet-500/30" 
                    : "bg-gradient-to-r from-blue-600 to-purple-600 text-white shadow-lg shadow-blue-500/30"
                  }
                `}
              >
                View Plans
              </button>
            </div>
          )}
        </aside>

        {/* Main Content */}
        <main className="relative z-10 flex flex-col min-h-screen overflow-x-hidden">
          
          {/* Top Header Bar */}
          <header className={`
            sticky top-0 z-30 px-3 sm:px-4 lg:px-6 py-3 sm:py-4
            ${isDarkMode 
              ? "bg-[#0a0e17]/80 border-b border-slate-700/50" 
              : "bg-white/80 border-b border-gray-200"
            }
            backdrop-blur-xl safe-area-inset-top
          `}>
            <div className="flex items-center gap-2 sm:gap-4">
              
              {/* Mobile Menu Button */}
              <button
                className={`
                  lg:hidden p-2 sm:p-2.5 rounded-xl transition-all duration-300 min-w-[44px] min-h-[44px] flex items-center justify-center
                  ${isDarkMode 
                    ? "bg-slate-800/60 border border-slate-700/50 hover:bg-slate-700/60 text-gray-200" 
                    : "bg-white border border-gray-200 hover:bg-gray-50 shadow-sm text-gray-700"
                  }
                  active:scale-95
                `}
                onClick={toggleSidebar}
                aria-label="Toggle menu"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={sidebarOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16M4 18h16"} />
                </svg>
              </button>

              {/* Logo in Header */}
              <div className="flex items-center gap-2 sm:gap-3">
                <img 
                  src="/logo/jarwis-logo-transparent.svg" 
                  alt="Jarwis" 
                  className="w-8 h-8 sm:w-10 sm:h-10 object-contain"
                  onError={(e) => {
                    e.target.onerror = null;
                    e.target.src = '';
                    e.target.style.display = 'none';
                  }}
                />
              </div>

              {/* Search Bar - Hide on very small screens */}
              <form 
                onSubmit={handleSearch} 
                className={`
                  hidden xs:flex flex-1 max-w-2xl items-center gap-2 sm:gap-3 px-3 sm:px-4 py-2 sm:py-2.5 rounded-xl
                  transition-all duration-300
                  ${isDarkMode 
                    ? "bg-slate-800/60 border border-slate-700/50 focus-within:border-cyan-500/50 focus-within:shadow-lg focus-within:shadow-cyan-500/10" 
                    : "bg-white border border-gray-200 focus-within:border-blue-400 focus-within:shadow-lg focus-within:shadow-blue-500/10"
                  }
                  hover:border-opacity-100
                `}
              >
                <span className={isDarkMode ? "text-gray-400" : "text-gray-500"}>
                  {Icons.search}
                </span>
                <input
                  type="text"
                  placeholder="Search scans, domains..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={`
                    flex-1 bg-transparent outline-none text-sm min-w-0
                    ${isDarkMode 
                      ? "text-white placeholder-gray-400" 
                      : "text-gray-900 placeholder-gray-500"
                    }
                  `}
                />
                <kbd className={`
                  hidden md:inline-flex items-center px-2 py-1 text-xs font-mono rounded
                  ${isDarkMode 
                    ? "bg-slate-700/80 text-gray-300 border border-slate-600" 
                    : "bg-gray-100 text-gray-600 border border-gray-300"
                  }
                `}>
                  'Œ˜K
                </kbd>
              </form>

              {/* Right Side Actions */}
              <div className="flex items-center gap-1.5 sm:gap-3 ml-auto">
                
                {/* Theme Toggle */}
                <button
                  onClick={toggleTheme}
                  className={`
                    relative p-2 sm:p-2.5 rounded-xl transition-all duration-300 min-w-[40px] min-h-[40px] sm:min-w-[44px] sm:min-h-[44px] flex items-center justify-center
                    ${isDarkMode 
                      ? "bg-slate-800/60 border border-slate-700/50 hover:border-cyan-500/30 text-cyan-400" 
                      : "bg-white border border-gray-200 hover:border-amber-300 text-amber-500 shadow-sm"
                    }
                    active:scale-95
                  `}
                  title={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
                >
                  <div className={`transition-transform duration-500 ${isDarkMode ? "rotate-0" : "rotate-180"}`}>
                    {isDarkMode ? Icons.moon : Icons.sun}
                  </div>
                </button>

                {/* Notifications */}
                <button
                  className={`
                    relative p-2 sm:p-2.5 rounded-xl transition-all duration-300 min-w-[40px] min-h-[40px] sm:min-w-[44px] sm:min-h-[44px] flex items-center justify-center
                    ${isDarkMode 
                      ? "bg-slate-800/60 border border-slate-700/50 hover:border-cyan-500/30 text-slate-400 hover:text-cyan-400" 
                      : "bg-white border border-gray-200 hover:border-blue-300 text-gray-500 hover:text-blue-600 shadow-sm"
                    }
                    active:scale-95
                  `}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                  </svg>
                  <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-red-500 rounded-full border-2 border-current"></div>
                </button>

                {/* User Menu */}
                <div className={`
                  hidden lg:flex items-center gap-2 px-2 sm:px-3 py-1.5 sm:py-2 rounded-xl
                  ${isDarkMode 
                    ? "bg-slate-800/80 border border-slate-600" 
                    : "bg-white border border-gray-200 shadow-sm"
                  }
                `}>
                  <div className={`w-2 h-2 rounded-full bg-emerald-500 animate-pulse`}></div>
                  <span className={`text-xs sm:text-sm font-medium truncate max-w-[100px] sm:max-w-none ${isDarkMode ? "text-white" : "text-gray-800"}`}>
                    {displayName}
                  </span>
                </div>

                {/* Logout Button */}
                <button
                  onClick={handleLogout}
                  className={`
                    flex items-center gap-1 sm:gap-2 px-2.5 sm:px-4 py-2 sm:py-2.5 rounded-xl min-w-[40px] min-h-[40px] sm:min-w-[44px] sm:min-h-[44px]
                    transition-all duration-300 active:scale-95
                    ${isDarkMode 
                      ? "bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20" 
                      : "bg-red-50 border border-red-200 text-red-600 hover:bg-red-100"
                    }
                  `}
                >
                  {Icons.logout}
                  <span className="hidden sm:inline text-xs sm:text-sm font-medium">Logout</span>
                </button>
              </div>
            </div>
          </header>

          {/* Page Content */}
          <div className="flex-1 p-3 sm:p-4 lg:p-6 xl:p-8 overflow-x-hidden safe-area-inset-bottom">
            <div className="relative z-10 max-w-full">{children}</div>
          </div>

          {/* Footer */}
          <footer className={`
            px-4 sm:px-6 py-3 sm:py-4 text-center text-xs sm:text-sm
            ${isDarkMode ? "text-gray-400" : "text-gray-600"}
            border-t ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}
            safe-area-inset-bottom
          `}>
            <p>(C) 2026 Jarwis AGI - Autonomous Cybersecurity Platform</p>
          </footer>
        </main>
      </div>

      {/* Settings Panel */}
      <SettingsPanel 
        isOpen={settingsOpen} 
        onClose={() => {
          setSettingsOpen(false);
          setSettingsInitialTab("account"); // Reset tab on close
        }} 
        isDarkMode={isDarkMode}
        initialTab={settingsInitialTab}
      />
    </div>
  );
};

export default JarwisLayout;
