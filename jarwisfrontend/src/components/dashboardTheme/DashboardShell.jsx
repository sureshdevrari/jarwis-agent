import { useMemo } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { useTheme } from "../../context/ThemeContext";
import ScrollToTop from "../ScrollToTop";
import SyndashLayout from "../syndashTheme/SyndashLayout";
import { featureFlags } from "../../config/features";
import {
  Activity,
  BarChart3,
  Bot,
  Cloud,
  FileText,
  History,
  Home,
  LogOut,
  Menu,
  ScanLine,
  ShieldCheck,
} from "lucide-react";

const navItems = [
  { href: "/dashboard", label: "Overview", icon: Home },
  { href: "/dashboard/new-scan", label: "New Scan", icon: ScanLine },
  { href: "/dashboard/scanning", label: "Active Scan", icon: Activity },
  { href: "/dashboard/scan-history", label: "Scan History", icon: History },
  { href: "/dashboard/vulnerabilities", label: "Vulnerabilities", icon: ShieldCheck },
  { href: "/dashboard/reports", label: "Reports", icon: FileText },
  { href: "/dashboard/billing", label: "Billing", icon: BarChart3 },
  { href: "/dashboard/cloud-scan", label: "Cloud Scans", icon: Cloud },
  { href: "/dashboard/jarwis-chatbot", label: "Jarwis AGI", icon: Bot },
];

const classNames = (...parts) => parts.filter(Boolean).join(" ");

const PlanBadge = ({ planId }) => {
  const label = (planId || "trial").toUpperCase();
  return (
    <div className="inline-flex items-center gap-2 rounded-full bg-blue-50 px-3 py-1 text-xs font-semibold text-blue-700">
      <span className="h-2 w-2 rounded-full bg-blue-500" />
      <span>{label}</span>
    </div>
  );
};

const UsagePill = ({ scans }) => {
  if (!scans) return null;
  const pct = scans.unlimited ? 0 : Math.min(Math.round((scans.current / (scans.max || 1)) * 100), 100);
  return (
    <div className="mt-3 rounded-xl border border-slate-200 bg-white p-3">
      <div className="flex items-center justify-between text-xs font-semibold text-slate-600">
        <span>Scans this month</span>
        <span>{scans.unlimited ? "Unlimited" : `${scans.current}/${scans.max}`}</span>
      </div>
      {!scans.unlimited && (
        <div className="mt-2 h-2 w-full rounded-full bg-slate-100">
          <div className="h-full rounded-full bg-blue-500" style={{ width: `${pct}%` }} />
        </div>
      )}
    </div>
  );
};

const Sidebar = ({ activePath, onNavigate }) => {
  return (
    <aside className="hidden w-64 flex-shrink-0 flex-col border-r border-slate-200 bg-white lg:flex">
      <div className="flex items-center gap-3 px-6 py-5">
        <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-blue-600 text-white font-bold">J</div>
        <div>
          <div className="text-sm font-semibold text-slate-900">Jarwis</div>
          <div className="text-xs text-slate-500">Security Platform</div>
        </div>
      </div>
      <nav className="flex-1 space-y-1 px-3">
        {navItems.map(({ href, label, icon: Icon }) => {
          const isActive = activePath === href || activePath.startsWith(`${href}/`);
          return (
            <button
              key={href}
              onClick={() => onNavigate(href)}
              className={classNames(
                "flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-sm font-semibold transition",
                isActive ? "bg-blue-50 text-blue-700" : "text-slate-600 hover:bg-slate-100"
              )}
            >
              <Icon className="h-4 w-4" />
              <span>{label}</span>
            </button>
          );
        })}
      </nav>
    </aside>
  );
};

const Topbar = ({ displayName, email, onToggleTheme, isDarkMode, onLogout }) => {
  return (
    <header className="sticky top-0 z-20 border-b border-slate-200 bg-white/90 backdrop-blur">
      <div className="flex items-center justify-between px-4 py-3 lg:px-6">
        <div className="flex items-center gap-3 lg:hidden">
          <Menu className="h-5 w-5 text-slate-600" />
          <span className="text-sm font-semibold text-slate-700">Jarwis</span>
        </div>
        <div className="hidden items-center gap-3 text-sm font-semibold text-slate-600 lg:flex">
          <ShieldCheck className="h-4 w-4 text-blue-600" />
          <span>Secure by design</span>
        </div>
        <div className="flex items-center gap-4">
          <button
            onClick={onToggleTheme}
            className="rounded-full border border-slate-200 bg-white px-3 py-1 text-xs font-semibold text-slate-600 shadow-sm hover:border-blue-200 hover:text-blue-700"
          >
            {isDarkMode ? "Light" : "Dark"}
          </button>
          <div className="flex items-center gap-3 rounded-full border border-slate-200 bg-white px-3 py-1.5 shadow-sm">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-gradient-to-br from-blue-600 to-indigo-600 text-sm font-bold text-white">
              {displayName?.charAt(0)?.toUpperCase() || "U"}
            </div>
            <div className="hidden text-left text-xs leading-tight text-slate-600 sm:block">
              <div className="font-semibold text-slate-800">{displayName || "User"}</div>
              <div className="text-slate-500">{email || ""}</div>
            </div>
            <button
              onClick={onLogout}
              className="rounded-full p-1 text-slate-500 hover:bg-slate-100 hover:text-red-600"
              aria-label="Logout"
            >
              <LogOut className="h-4 w-4" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};

const DashboardShell = ({ children }) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, userDoc, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const { planId, getActionLimit } = useSubscription();

  const scansLimit = useMemo(() => getActionLimit("scans"), [getActionLimit]);
  const displayName = user?.displayName || userDoc?.displayName || userDoc?.email?.split("@")[0] || "User";
  const userEmail = user?.email || userDoc?.email || "";

  const handleNavigate = (href) => {
    navigate(href);
  };

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
    } catch (err) {
      console.error("Logout error", err);
    }
  };

  // Use new Syndash theme when feature flag is enabled
  if (featureFlags.useNewDashboard) {
    return <SyndashLayout>{children}</SyndashLayout>;
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <ScrollToTop />
      <div className="flex">
        <Sidebar activePath={location.pathname} onNavigate={handleNavigate} />
        <div className="flex min-h-screen flex-1 flex-col">
          <Topbar
            displayName={displayName}
            email={userEmail}
            onToggleTheme={toggleTheme}
            isDarkMode={isDarkMode}
            onLogout={handleLogout}
          />
          <main className="flex-1 px-4 py-6 lg:px-8">
            <div className="mb-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
              <PlanBadge planId={planId} />
              <div className="max-w-md w-full lg:w-80">
                <UsagePill scans={scansLimit} />
              </div>
            </div>
            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm lg:p-6">
              {children}
            </div>
          </main>
        </div>
      </div>
    </div>
  );
};

export default DashboardShell;
