import { useState, useRef, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import ScrollToTop from "../ScrollToTop";
import SettingsPanel from "../settings/SettingsPanel";

// Professional Admin Icons (SVG)
const Icons = {
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
  shield: (
    <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.25-8.25-3.286z" />
    </svg>
  ),
};

// Admin Stats Display Component
const AdminStatsDisplay = ({ isDarkMode }) => {
  // Mock stats - would be fetched from API
  const stats = {
    pendingRequests: 12,
    activeUsers: 156,
    todayScans: 43,
  };

  return (
    <div className={`px-4 py-4 border-t ${isDarkMode ? "border-rose-700/30" : "border-red-200"}`}>
      <div className={`text-xs font-semibold uppercase tracking-wider mb-3 ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>
        System Overview
      </div>
      
      <div className="space-y-3">
        <div className={`flex items-center justify-between p-2.5 rounded-lg ${isDarkMode ? "bg-rose-500/10 border border-rose-500/20" : "bg-red-50 border border-red-200"}`}>
          <span className={`text-xs ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>Pending Requests</span>
          <span className={`text-sm font-bold ${isDarkMode ? "text-rose-400" : "text-red-600"}`}>{stats.pendingRequests}</span>
        </div>
        <div className={`flex items-center justify-between p-2.5 rounded-lg ${isDarkMode ? "bg-emerald-500/10 border border-emerald-500/20" : "bg-green-50 border border-green-200"}`}>
          <span className={`text-xs ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>Active Users</span>
          <span className={`text-sm font-bold ${isDarkMode ? "text-emerald-400" : "text-green-600"}`}>{stats.activeUsers}</span>
        </div>
        <div className={`flex items-center justify-between p-2.5 rounded-lg ${isDarkMode ? "bg-amber-500/10 border border-amber-500/20" : "bg-amber-50 border border-amber-200"}`}>
          <span className={`text-xs ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>Today's Scans</span>
          <span className={`text-sm font-bold ${isDarkMode ? "text-amber-400" : "text-amber-600"}`}>{stats.todayScans}</span>
        </div>
      </div>
    </div>
  );
};

const AdminLayout = ({ children }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, userDoc, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const [searchQuery, setSearchQuery] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [hoveredNav, setHoveredNav] = useState(null);

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

  const adminNavigationItems = [
    { href: "/admin", icon: Icons.overview, label: "Overview" },
    { href: "/admin/requests", icon: Icons.requests, label: "Access Requests" },
    { href: "/admin/submissions", icon: Icons.submissions, label: "Submissions" },
    { href: "/admin/users", icon: Icons.users, label: "Users & Tenants" },
    { href: "/admin/push-vulnerability", icon: Icons.vulnerability, label: "Push Vulnerability" },
    { href: "/admin/audit-log", icon: Icons.audit, label: "Audit Log" },
    { href: "settings", icon: Icons.settings, label: "Settings", isSettings: true },
    { href: "/", icon: Icons.home, label: "Back to Home" },
  ];

  const isActive = (path) => location.pathname === path;

  const canvasRef = useRef(null);

  // Cyber Grid Animation - Admin Theme (Red/Orange)
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
      ctx.strokeStyle = isDarkMode ? "rgba(244, 63, 94, 0.03)" : "rgba(239, 68, 68, 0.05)";
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
          ? `rgba(244, 63, 94, ${p.opacity})`
          : `rgba(239, 68, 68, ${p.opacity})`;
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
              ? `rgba(244, 63, 94, ${0.1 * (1 - dist / 120)})`
              : `rgba(239, 68, 68, ${0.1 * (1 - dist / 120)})`;
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

  // Get admin display name
  const displayName = user?.displayName || userDoc?.displayName || "Admin";

  return (
    <div className={`
      min-h-screen font-sans relative overflow-hidden
      ${isDarkMode 
        ? "bg-[#0a0c12] text-gray-100" 
        : "bg-gradient-to-br from-slate-50 via-white to-rose-50 text-gray-900"
      }
    `}>
      <ScrollToTop />
      
      {/* Animated Canvas Background */}
      <canvas ref={canvasRef} className="absolute inset-0 z-0" />

      {/* Gradient Overlays */}
      <div className="absolute inset-0 pointer-events-none z-0">
        <div className={`
          absolute top-0 left-0 w-96 h-96 rounded-full blur-[128px] opacity-30
          ${isDarkMode ? "bg-rose-600" : "bg-red-400"}
        `}></div>
        <div className={`
          absolute bottom-0 right-0 w-80 h-80 rounded-full blur-[128px] opacity-20
          ${isDarkMode ? "bg-amber-600" : "bg-orange-400"}
        `}></div>
        <div className={`
          absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 
          w-[600px] h-[600px] rounded-full blur-[200px] opacity-10
          ${isDarkMode ? "bg-red-500" : "bg-rose-300"}
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
            ? "bg-[#0d0f14]/90 border-r border-rose-500/10" 
            : "bg-white/80 border-r border-red-200/50 shadow-xl"
          }
          backdrop-blur-xl
          transform transition-transform duration-300 ease-out
          ${sidebarOpen ? "translate-x-0" : "-translate-x-full lg:translate-x-0"}
          flex flex-col
        `}>
          
          {/* Admin Profile Section */}
          <div className={`
            p-5 border-b
            ${isDarkMode ? "border-rose-700/30" : "border-red-200"}
          `}>
            {/* Admin Profile Card */}
            <div className={`
              p-3 rounded-xl
              ${isDarkMode 
                ? "bg-rose-900/20 border border-rose-700/30" 
                : "bg-red-50 border border-red-200"
              }
            `}>
              <div className="flex items-center gap-3">
                <div className={`
                  w-10 h-10 rounded-lg flex items-center justify-center
                  ${isDarkMode 
                    ? "bg-gradient-to-br from-rose-500/30 to-amber-600/30 border border-rose-500/20" 
                    : "bg-gradient-to-br from-red-100 to-orange-100 border border-red-200"
                  }
                `}>
                  <svg className={`w-5 h-5 ${isDarkMode ? "text-rose-400" : "text-red-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.57-.598-3.75h-.152c-3.196 0-6.1-1.25-8.25-3.286z" />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-semibold truncate ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {displayName}
                  </p>
                  <div className={`
                    inline-flex items-center gap-1.5 px-2 py-0.5 rounded-md text-xs font-bold mt-1
                    ${isDarkMode 
                      ? "bg-rose-500/20 text-rose-300 border border-rose-500/30" 
                      : "bg-red-100 text-red-700 border border-red-200"
                    }
                  `}>
                    <div className="w-1.5 h-1.5 rounded-full bg-current animate-pulse"></div>
                    SUPER ADMIN
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Navigation */}
          <nav className="flex-1 p-4 space-y-1.5 overflow-y-auto">
            {adminNavigationItems.map((item, index) => {
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
                        ? "bg-gradient-to-r from-rose-500/20 to-amber-600/10 text-rose-300 border border-rose-500/30 shadow-lg shadow-rose-500/10"
                        : "bg-gradient-to-r from-red-100 to-orange-50 text-red-700 border border-red-300 shadow-md"
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
                        ? "bg-gradient-to-r from-rose-500/5 to-transparent" 
                        : "bg-gradient-to-r from-red-500/5 to-transparent"
                      }
                    `}></div>
                  )}
                  
                  <span className={`
                    relative z-10 transition-all duration-300
                    ${isHovered || isItemActive ? "scale-110" : ""}
                    ${isItemActive 
                      ? isDarkMode ? "text-rose-400" : "text-red-600"
                      : isDarkMode ? "text-gray-400 group-hover:text-rose-400" : "text-gray-600 group-hover:text-red-600"
                    }
                  `}>
                    {item.icon}
                  </span>
                  <span className={`relative z-10 font-medium text-sm ${!isItemActive && (isDarkMode ? "text-gray-300" : "text-gray-700")}`}>{item.label}</span>
                  
                  {/* Active indicator */}
                  {isItemActive && (
                    <div className={`
                      absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 rounded-r-full
                      ${isDarkMode ? "bg-rose-400" : "bg-red-600"}
                    `}></div>
                  )}
                </button>
              );
            })}
          </nav>

          {/* Admin Stats Display */}
          <AdminStatsDisplay isDarkMode={isDarkMode} />
        </aside>

        {/* Main Content */}
        <main className="relative z-10 flex flex-col min-h-screen">
          
          {/* Top Header Bar */}
          <header className={`
            sticky top-0 z-30 px-6 py-4
            ${isDarkMode 
              ? "bg-[#0a0c12]/80 border-b border-slate-700/50" 
              : "bg-white/80 border-b border-gray-200"
            }
            backdrop-blur-xl
          `}>
            <div className="flex items-center gap-4">
              
              {/* Mobile Menu Button */}
              <button
                className={`
                  lg:hidden p-2.5 rounded-xl transition-all duration-300
                  ${isDarkMode 
                    ? "bg-slate-800/60 border border-slate-700/50 hover:bg-slate-700/60 text-gray-200" 
                    : "bg-white border border-gray-200 hover:bg-gray-50 shadow-sm text-gray-700"
                  }
                  hover:scale-105
                `}
                onClick={toggleSidebar}
                aria-label="Toggle menu"
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d={sidebarOpen ? "M6 18L18 6M6 6l12 12" : "M4 6h16M4 12h16M4 18h16"} />
                </svg>
              </button>

              {/* Logo in Header */}
              <div className="flex items-center gap-3">
                <img 
                  src="/logo/jarwis-logo-transparent.svg" 
                  alt="Jarwis" 
                  className="w-10 h-10 object-contain"
                  onError={(e) => {
                    e.target.onerror = null;
                    e.target.src = '';
                    e.target.style.display = 'none';
                  }}
                />
              </div>

              {/* Search Bar */}
              <form 
                onSubmit={handleSearch} 
                className={`
                  flex-1 max-w-2xl flex items-center gap-3 px-4 py-2.5 rounded-xl
                  transition-all duration-300
                  ${isDarkMode 
                    ? "bg-slate-800/60 border border-slate-700/50 focus-within:border-rose-500/50 focus-within:shadow-lg focus-within:shadow-rose-500/10" 
                    : "bg-white border border-gray-200 focus-within:border-red-400 focus-within:shadow-lg focus-within:shadow-red-500/10"
                  }
                  hover:border-opacity-100
                `}
              >
                <span className={isDarkMode ? "text-gray-400" : "text-gray-500"}>
                  {Icons.search}
                </span>
                <input
                  type="text"
                  placeholder="Search users, domains, scans..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className={`
                    flex-1 bg-transparent outline-none text-sm
                    ${isDarkMode 
                      ? "text-white placeholder-gray-400" 
                      : "text-gray-900 placeholder-gray-500"
                    }
                  `}
                />
                <kbd className={`
                  hidden sm:inline-flex items-center px-2 py-1 text-xs font-mono rounded
                  ${isDarkMode 
                    ? "bg-slate-700/80 text-gray-300 border border-slate-600" 
                    : "bg-gray-100 text-gray-600 border border-gray-300"
                  }
                `}>
                  ⌘K
                </kbd>
              </form>

              {/* Right Side Actions */}
              <div className="flex items-center gap-3">
                
                {/* Theme Toggle */}
                <button
                  onClick={toggleTheme}
                  className={`
                    relative p-2.5 rounded-xl transition-all duration-300 hover:scale-110
                    ${isDarkMode 
                      ? "bg-slate-800/60 border border-slate-700/50 hover:border-rose-500/30 text-rose-400" 
                      : "bg-white border border-gray-200 hover:border-amber-300 text-amber-500 shadow-sm"
                    }
                  `}
                  title={isDarkMode ? "Switch to light mode" : "Switch to dark mode"}
                >
                  <div className={`transition-transform duration-500 ${isDarkMode ? "rotate-0" : "rotate-180"}`}>
                    {isDarkMode ? Icons.moon : Icons.sun}
                  </div>
                </button>

                {/* Alerts */}
                <button
                  className={`
                    relative p-2.5 rounded-xl transition-all duration-300 hover:scale-110
                    ${isDarkMode 
                      ? "bg-slate-800/60 border border-slate-700/50 hover:border-rose-500/30 text-slate-400 hover:text-rose-400" 
                      : "bg-white border border-gray-200 hover:border-red-300 text-gray-500 hover:text-red-600 shadow-sm"
                    }
                  `}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M14.857 17.082a23.848 23.848 0 005.454-1.31A8.967 8.967 0 0118 9.75v-.7V9A6 6 0 006 9v.75a8.967 8.967 0 01-2.312 6.022c1.733.64 3.56 1.085 5.455 1.31m5.714 0a24.255 24.255 0 01-5.714 0m5.714 0a3 3 0 11-5.714 0" />
                  </svg>
                  <div className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-rose-500 rounded-full border-2 border-current animate-pulse"></div>
                </button>

                {/* Admin Badge */}
                <div className={`
                  hidden md:flex items-center gap-2 px-3 py-2 rounded-xl
                  ${isDarkMode 
                    ? "bg-rose-900/20 border border-rose-700/30" 
                    : "bg-red-50 border border-red-200 shadow-sm"
                  }
                `}>
                  <div className={`w-2 h-2 rounded-full bg-rose-500 animate-pulse`}></div>
                  <span className={`text-sm font-semibold ${isDarkMode ? "text-rose-300" : "text-red-700"}`}>
                    Admin
                  </span>
                </div>

                {/* Logout Button */}
                <button
                  onClick={handleLogout}
                  className={`
                    flex items-center gap-2 px-4 py-2.5 rounded-xl
                    transition-all duration-300 hover:scale-105
                    ${isDarkMode 
                      ? "bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20" 
                      : "bg-red-50 border border-red-200 text-red-600 hover:bg-red-100"
                    }
                  `}
                >
                  {Icons.logout}
                  <span className="hidden sm:inline text-sm font-medium">Logout</span>
                </button>
              </div>
            </div>
          </header>

          {/* Page Content */}
          <div className="flex-1 p-6 lg:p-8">
            <div className="relative z-10">{children}</div>
          </div>

          {/* Footer */}
          <footer className={`
            px-6 py-4 text-center text-sm
            ${isDarkMode ? "text-gray-400" : "text-gray-600"}
            border-t ${isDarkMode ? "border-slate-700/50" : "border-gray-200"}
          `}>
            <p>(C) 2026 Jarwis Admin * Secure, Observable, Auditable</p>
          </footer>
        </main>
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

export default AdminLayout;
