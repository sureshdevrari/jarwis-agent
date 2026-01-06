// Mifty Dashboard Components - Reusable Modern UI Components
// Inspired by Mannatthemes Mifty E-commerce Dashboard

import { useState, useEffect } from "react";

// =============================================
// STAT CARD - Performance metrics card
// =============================================
export const MiftyStatCard = ({
  icon,
  label,
  value,
  trend,
  trendUp = true,
  trendLabel = "vs last month",
  color = "primary",
  isDarkMode = true,
  delay = 0,
}) => {
  const [isVisible, setIsVisible] = useState(false);
  const [animatedValue, setAnimatedValue] = useState(0);

  useEffect(() => {
    const timer = setTimeout(() => setIsVisible(true), delay);
    return () => clearTimeout(timer);
  }, [delay]);

  // Animate value counting up
  useEffect(() => {
    if (!isVisible) return;
    const numValue = parseInt(value?.toString().replace(/\D/g, "")) || 0;
    const duration = 1500;
    const startTime = performance.now();

    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const easeOutQuart = 1 - Math.pow(1 - progress, 4);
      setAnimatedValue(Math.floor(easeOutQuart * numValue));

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }, [isVisible, value]);

  const colorMap = {
    primary: {
      iconBg: isDarkMode
        ? "bg-purple-500/15 border-purple-500/20"
        : "bg-purple-50 border-purple-200",
      iconText: isDarkMode ? "text-purple-400" : "text-purple-600",
      gradient: "from-purple-500 to-violet-400",
    },
    success: {
      iconBg: isDarkMode
        ? "bg-emerald-500/15 border-emerald-500/20"
        : "bg-emerald-50 border-emerald-200",
      iconText: isDarkMode ? "text-emerald-400" : "text-emerald-600",
      gradient: "from-emerald-500 to-teal-400",
    },
    warning: {
      iconBg: isDarkMode
        ? "bg-amber-500/15 border-amber-500/20"
        : "bg-amber-50 border-amber-200",
      iconText: isDarkMode ? "text-amber-400" : "text-amber-600",
      gradient: "from-amber-500 to-orange-400",
    },
    danger: {
      iconBg: isDarkMode
        ? "bg-red-500/15 border-red-500/20"
        : "bg-red-50 border-red-200",
      iconText: isDarkMode ? "text-red-400" : "text-red-600",
      gradient: "from-red-500 to-rose-400",
    },
    info: {
      iconBg: isDarkMode
        ? "bg-cyan-500/15 border-cyan-500/20"
        : "bg-cyan-50 border-cyan-200",
      iconText: isDarkMode ? "text-cyan-400" : "text-cyan-600",
      gradient: "from-cyan-500 to-blue-400",
    },
  };

  const colors = colorMap[color] || colorMap.primary;

  // Format the display value
  const displayValue =
    typeof value === "string" && value.includes("$")
      ? `$${animatedValue.toLocaleString()}${value.includes("k") ? "k" : ""}`
      : animatedValue.toLocaleString();

  return (
    <div
      className={`
        transition-all duration-700 ease-out
        ${isVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"}
      `}
    >
      <div
        className={`
        mifty-card p-6 group relative overflow-hidden
        ${isDarkMode ? "mifty-card-dark" : "mifty-card-light"}
      `}
      >
        {/* Background gradient orb */}
        <div
          className={`
          absolute -top-10 -right-10 w-32 h-32 rounded-full blur-3xl opacity-0 
          group-hover:opacity-20 transition-opacity duration-500
          bg-gradient-to-br ${colors.gradient}
        `}
        />

        <div className="relative z-10">
          <div className="flex items-start justify-between mb-4">
            <div
              className={`
              w-12 h-12 rounded-xl border flex items-center justify-center
              transition-all duration-500 ease-out
              group-hover:scale-110 group-hover:rotate-6
              ${colors.iconBg}
            `}
            >
              <span className={`text-2xl ${colors.iconText}`}>{icon}</span>
            </div>

            {trend && (
              <div
                className={`
                flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold
                transition-all duration-300 group-hover:scale-105
                ${
                  trendUp
                    ? isDarkMode
                      ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20"
                      : "bg-emerald-50 text-emerald-700 border border-emerald-200"
                    : isDarkMode
                    ? "bg-red-500/15 text-red-400 border border-red-500/20"
                    : "bg-red-50 text-red-700 border border-red-200"
                }
              `}
              >
                <span className="transition-transform duration-300 group-hover:scale-125">
                  {trendUp ? "↑" : "↓"}
                </span>
                <span>{trend}</span>
              </div>
            )}
          </div>

          <p
            className={`text-sm font-medium mb-2 ${
              isDarkMode ? "text-slate-400" : "text-gray-500"
            }`}
          >
            {label}
          </p>

          <p
            className={`text-3xl font-bold mb-1 bg-gradient-to-r ${colors.gradient} bg-clip-text text-transparent`}
          >
            {displayValue}
          </p>

          {trendLabel && (
            <p
              className={`text-xs ${
                isDarkMode ? "text-slate-500" : "text-gray-400"
              }`}
            >
              {trendLabel}
            </p>
          )}
        </div>
      </div>
    </div>
  );
};

// =============================================
// PROFILE CARD - User profile display
// =============================================
export const MiftyProfileCard = ({
  name,
  email,
  role,
  avatar,
  languages = [],
  stats = [],
  isDarkMode = true,
}) => {
  return (
    <div
      className={`
      mifty-card overflow-hidden
      ${isDarkMode ? "mifty-card-dark" : "mifty-card-light"}
    `}
    >
      {/* Cover gradient */}
      <div className="h-24 bg-gradient-to-r from-purple-600 via-violet-500 to-cyan-500 relative">
        <div className="absolute inset-0 bg-gradient-to-t from-black/30 to-transparent" />
        <div className="absolute inset-0 opacity-30">
          <svg className="w-full h-full">
            <defs>
              <pattern
                id="grid"
                width="20"
                height="20"
                patternUnits="userSpaceOnUse"
              >
                <path
                  d="M 20 0 L 0 0 0 20"
                  fill="none"
                  stroke="white"
                  strokeWidth="0.5"
                  opacity="0.3"
                />
              </pattern>
            </defs>
            <rect width="100%" height="100%" fill="url(#grid)" />
          </svg>
        </div>
      </div>

      <div className="px-6 pb-6 -mt-12 relative">
        {/* Avatar */}
        <div className="flex justify-center mb-4">
          <div className="w-24 h-24 rounded-2xl p-1 bg-gradient-to-br from-purple-500 to-cyan-500 shadow-lg shadow-purple-500/30">
            {avatar ? (
              <img
                src={avatar}
                alt={name}
                className={`w-full h-full object-cover rounded-xl ${
                  isDarkMode ? "bg-slate-800" : "bg-white"
                }`}
              />
            ) : (
              <div
                className={`
                w-full h-full rounded-xl flex items-center justify-center
                text-3xl font-bold
                ${
                  isDarkMode
                    ? "bg-slate-800 text-purple-400"
                    : "bg-white text-purple-600"
                }
              `}
              >
                {name?.charAt(0)?.toUpperCase()}
              </div>
            )}
          </div>
        </div>

        {/* Name & Role */}
        <div className="text-center mb-4">
          <h3
            className={`text-xl font-bold mb-1 ${
              isDarkMode ? "text-white" : "text-gray-900"
            }`}
          >
            {name}
          </h3>
          <span className="text-purple-500 text-sm font-medium">{role}</span>
        </div>

        {/* Info items */}
        <div
          className={`
          p-4 rounded-xl space-y-3
          ${
            isDarkMode
              ? "bg-slate-800/50 border border-slate-700/50"
              : "bg-gray-50 border border-gray-200"
          }
        `}
        >
          {languages.length > 0 && (
            <div className="flex items-center gap-3 text-sm">
              <svg
                className="w-4 h-4 text-purple-500"
                fill="none"
                viewBox="0 0 24 24"
                stroke="currentColor"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M3 5h12M9 3v2m1.048 9.5A18.022 18.022 0 016.412 9m6.088 9h7M11 21l5-10 5 10M12.751 5C11.783 10.77 8.07 15.61 3 18.129"
                />
              </svg>
              <span className={isDarkMode ? "text-slate-300" : "text-gray-700"}>
                {languages.join(" / ")}
              </span>
            </div>
          )}

          <div className="flex items-center gap-3 text-sm">
            <svg
              className="w-4 h-4 text-purple-500"
              fill="none"
              viewBox="0 0 24 24"
              stroke="currentColor"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
              />
            </svg>
            <span className={isDarkMode ? "text-slate-300" : "text-gray-700"}>
              {email}
            </span>
          </div>
        </div>

        {/* Quick Stats */}
        {stats.length > 0 && (
          <div className="grid grid-cols-2 gap-3 mt-4">
            {stats.map((stat, idx) => (
              <div
                key={idx}
                className={`
                  p-3 rounded-xl text-center
                  ${
                    isDarkMode
                      ? "bg-slate-800/30 border border-slate-700/30"
                      : "bg-gray-50 border border-gray-100"
                  }
                `}
              >
                <p
                  className={`text-lg font-bold ${
                    isDarkMode ? "text-white" : "text-gray-900"
                  }`}
                >
                  {stat.value}
                </p>
                <p
                  className={`text-xs ${
                    isDarkMode ? "text-slate-500" : "text-gray-500"
                  }`}
                >
                  {stat.label}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// =============================================
// DATA TABLE - Modern data table
// =============================================
export const MiftyDataTable = ({
  columns = [],
  data = [],
  onRowClick,
  isDarkMode = true,
  emptyMessage = "No data available",
}) => {
  return (
    <div
      className={`
      mifty-card overflow-hidden
      ${isDarkMode ? "mifty-card-dark" : "mifty-card-light"}
    `}
    >
      <div className="mifty-table-container">
        <table
          className={`mifty-table ${
            isDarkMode ? "mifty-table-dark" : "mifty-table-light"
          }`}
        >
          <thead>
            <tr>
              {columns.map((col, idx) => (
                <th key={idx} style={{ width: col.width }}>
                  {col.header}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {data.length === 0 ? (
              <tr>
                <td
                  colSpan={columns.length}
                  className="text-center py-8 opacity-50"
                >
                  {emptyMessage}
                </td>
              </tr>
            ) : (
              data.map((row, rowIdx) => (
                <tr
                  key={rowIdx}
                  onClick={() => onRowClick?.(row)}
                  className={onRowClick ? "cursor-pointer" : ""}
                >
                  {columns.map((col, colIdx) => (
                    <td key={colIdx}>
                      {col.render ? col.render(row[col.key], row) : row[col.key]}
                    </td>
                  ))}
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// =============================================
// STATUS BADGE - Colored status indicator
// =============================================
export const MiftyBadge = ({
  status,
  children,
  size = "md",
}) => {
  const statusColors = {
    success: "mifty-badge-success",
    completed: "mifty-badge-success",
    active: "mifty-badge-success",
    warning: "mifty-badge-warning",
    pending: "mifty-badge-warning",
    danger: "mifty-badge-danger",
    critical: "mifty-badge-danger",
    cancelled: "mifty-badge-danger",
    info: "mifty-badge-info",
    primary: "mifty-badge-primary",
  };

  const sizeClasses = {
    sm: "text-[10px] px-2 py-0.5",
    md: "text-xs px-3 py-1",
    lg: "text-sm px-4 py-1.5",
  };

  return (
    <span
      className={`
      mifty-badge
      ${statusColors[status] || statusColors.info}
      ${sizeClasses[size]}
    `}
    >
      {children}
    </span>
  );
};

// =============================================
// PROGRESS BAR - Animated progress indicator
// =============================================
export const MiftyProgressBar = ({
  value = 0,
  max = 100,
  color = "primary",
  showLabel = false,
  size = "md",
  isDarkMode = true,
}) => {
  const percentage = Math.min((value / max) * 100, 100);

  const colorClasses = {
    primary: "mifty-progress-bar-primary",
    success: "mifty-progress-bar-success",
    warning: "mifty-progress-bar-warning",
    danger: "mifty-progress-bar-danger",
  };

  const sizeClasses = {
    sm: "h-1",
    md: "h-1.5",
    lg: "h-2",
  };

  return (
    <div className="w-full">
      <div
        className={`
        mifty-progress ${sizeClasses[size]}
        ${isDarkMode ? "mifty-progress-dark" : "mifty-progress-light"}
      `}
      >
        <div
          className={`mifty-progress-bar ${colorClasses[color]}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
      {showLabel && (
        <div className="flex justify-between mt-1 text-xs">
          <span className={isDarkMode ? "text-slate-400" : "text-gray-600"}>
            {value} / {max}
          </span>
          <span className={isDarkMode ? "text-slate-400" : "text-gray-600"}>
            {Math.round(percentage)}%
          </span>
        </div>
      )}
    </div>
  );
};

// =============================================
// ACTION BUTTON - Styled button component
// =============================================
export const MiftyButton = ({
  children,
  variant = "primary",
  size = "md",
  icon,
  loading = false,
  disabled = false,
  onClick,
  className = "",
}) => {
  const variantClasses = {
    primary: "mifty-btn-primary",
    secondary: "mifty-btn-secondary",
    success: "mifty-btn-success",
    danger: "mifty-btn-danger",
  };

  const sizeClasses = {
    sm: "px-3 py-1.5 text-xs",
    md: "px-5 py-2.5 text-sm",
    lg: "px-6 py-3 text-base",
  };

  return (
    <button
      onClick={onClick}
      disabled={disabled || loading}
      className={`
        mifty-btn
        ${variantClasses[variant]}
        ${sizeClasses[size]}
        ${disabled ? "opacity-50 cursor-not-allowed" : ""}
        ${className}
      `}
    >
      {loading ? (
        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
      ) : (
        <>
          {icon && <span>{icon}</span>}
          {children}
        </>
      )}
    </button>
  );
};

// =============================================
// QUICK ACTION CARD - Clickable action cards
// =============================================
export const MiftyQuickAction = ({
  icon,
  title,
  description,
  color = "primary",
  onClick,
  isDarkMode = true,
  badge,
  locked = false,
}) => {
  const colorMap = {
    primary: {
      bg: isDarkMode
        ? "from-purple-600/10 via-violet-600/5 to-purple-600/10 hover:from-purple-600/20 hover:via-violet-600/10 hover:to-purple-600/20"
        : "from-purple-50 via-violet-50 to-purple-50 hover:from-purple-100",
      border: isDarkMode
        ? "border-purple-500/20 hover:border-purple-400/40"
        : "border-purple-200 hover:border-purple-400",
      iconBg: isDarkMode ? "bg-purple-500/15" : "bg-purple-100",
      iconText: isDarkMode ? "text-purple-400" : "text-purple-600",
    },
    cyan: {
      bg: isDarkMode
        ? "from-cyan-600/10 via-blue-600/5 to-cyan-600/10 hover:from-cyan-600/20"
        : "from-cyan-50 via-blue-50 to-cyan-50 hover:from-cyan-100",
      border: isDarkMode
        ? "border-cyan-500/20 hover:border-cyan-400/40"
        : "border-cyan-200 hover:border-cyan-400",
      iconBg: isDarkMode ? "bg-cyan-500/15" : "bg-cyan-100",
      iconText: isDarkMode ? "text-cyan-400" : "text-cyan-600",
    },
    amber: {
      bg: isDarkMode
        ? "from-amber-600/10 via-orange-600/5 to-amber-600/10 hover:from-amber-600/20"
        : "from-amber-50 via-orange-50 to-amber-50 hover:from-amber-100",
      border: isDarkMode
        ? "border-amber-500/20 hover:border-amber-400/40"
        : "border-amber-200 hover:border-amber-400",
      iconBg: isDarkMode ? "bg-amber-500/15" : "bg-amber-100",
      iconText: isDarkMode ? "text-amber-400" : "text-amber-600",
    },
    emerald: {
      bg: isDarkMode
        ? "from-emerald-600/10 via-teal-600/5 to-emerald-600/10 hover:from-emerald-600/20"
        : "from-emerald-50 via-teal-50 to-emerald-50 hover:from-emerald-100",
      border: isDarkMode
        ? "border-emerald-500/20 hover:border-emerald-400/40"
        : "border-emerald-200 hover:border-emerald-400",
      iconBg: isDarkMode ? "bg-emerald-500/15" : "bg-emerald-100",
      iconText: isDarkMode ? "text-emerald-400" : "text-emerald-600",
    },
  };

  const colors = colorMap[color] || colorMap.primary;

  return (
    <button
      onClick={onClick}
      disabled={locked}
      className={`
        group relative overflow-hidden w-full p-5 rounded-xl text-left
        bg-gradient-to-br ${colors.bg}
        border ${colors.border}
        transition-all duration-500 ease-out
        ${locked ? "opacity-60 cursor-not-allowed" : "hover:shadow-xl hover:-translate-y-1.5 hover:scale-[1.02]"}
        active:scale-[0.98] active:translate-y-0
      `}
    >
      {/* Shimmer effect */}
      <div
        className={`
        absolute inset-0 -translate-x-full group-hover:translate-x-full 
        transition-transform duration-1000 ease-out
        bg-gradient-to-r from-transparent via-white/10 to-transparent
        pointer-events-none
      `}
      />

      {/* Badge */}
      {badge && (
        <div className="absolute top-3 right-3">
          <span
            className={`
            px-2 py-0.5 rounded-full text-[10px] font-bold uppercase
            ${
              isDarkMode
                ? "bg-purple-500/20 text-purple-400 border border-purple-500/30"
                : "bg-purple-100 text-purple-700 border border-purple-200"
            }
          `}
          >
            {badge}
          </span>
        </div>
      )}

      {/* Lock overlay */}
      {locked && (
        <div
          className={`
          absolute inset-0 rounded-xl flex items-center justify-center
          ${isDarkMode ? "bg-slate-900/60" : "bg-gray-100/80"}
          backdrop-blur-[1px] z-10
        `}
        >
          <div className="text-center">
            <span className="text-2xl mb-1 block">[LOCK]</span>
            <span
              className={`text-xs font-semibold ${
                isDarkMode ? "text-purple-400" : "text-purple-600"
              }`}
            >
              Upgrade to Pro
            </span>
          </div>
        </div>
      )}

      <div className="relative z-0">
        <div
          className={`
          w-12 h-12 rounded-xl flex items-center justify-center mb-3
          ${colors.iconBg}
          transition-all duration-300 group-hover:scale-110 group-hover:rotate-6
        `}
        >
          <span className={`text-2xl ${colors.iconText}`}>{icon}</span>
        </div>

        <h4
          className={`font-semibold mb-1 ${
            isDarkMode ? "text-white" : "text-gray-900"
          }`}
        >
          {title}
        </h4>
        <p
          className={`text-sm ${
            isDarkMode ? "text-slate-400" : "text-gray-500"
          }`}
        >
          {description}
        </p>
      </div>
    </button>
  );
};

// =============================================
// PAGE HEADER - Section title with breadcrumb
// =============================================
export const MiftyPageHeader = ({
  title,
  breadcrumbs = [],
  actions,
  isDarkMode = true,
}) => {
  return (
    <div className="mifty-page-header">
      <div>
        {breadcrumbs.length > 0 && (
          <div className="mifty-breadcrumb mb-2">
            {breadcrumbs.map((item, idx) => (
              <span key={idx}>
                <span
                  className={`mifty-breadcrumb-item ${
                    idx === breadcrumbs.length - 1 ? "active" : ""
                  }`}
                >
                  {item}
                </span>
                {idx < breadcrumbs.length - 1 && (
                  <span className="mifty-breadcrumb-separator mx-2">/</span>
                )}
              </span>
            ))}
          </div>
        )}
        <h1
          className={`mifty-page-title ${
            isDarkMode ? "mifty-page-title-dark" : "mifty-page-title-light"
          }`}
        >
          {title}
        </h1>
      </div>
      {actions && <div className="flex items-center gap-3">{actions}</div>}
    </div>
  );
};

// =============================================
// CARD WRAPPER - Simple card container
// =============================================
export const MiftyCard = ({ children, className = "", isDarkMode = true, onClick, hover = true }) => {
  return (
    <div
      onClick={onClick}
      className={`
        mifty-card p-6
        ${isDarkMode ? "mifty-card-dark" : "mifty-card-light"}
        ${onClick ? "cursor-pointer" : ""}
        ${!hover ? "hover:transform-none hover:shadow-none" : ""}
        ${className}
      `}
    >
      {children}
    </div>
  );
};

// =============================================
// SECTION TITLE - Card section header
// =============================================
export const MiftySectionTitle = ({
  title,
  action,
  icon,
  isDarkMode = true,
}) => {
  return (
    <div className="flex items-center justify-between mb-4">
      <div className="flex items-center gap-2">
        {icon && (
          <span className={isDarkMode ? "text-purple-400" : "text-purple-600"}>
            {icon}
          </span>
        )}
        <h3
          className={`font-semibold ${
            isDarkMode ? "text-white" : "text-gray-900"
          }`}
        >
          {title}
        </h3>
      </div>
      {action && action}
    </div>
  );
};

// =============================================
// UPGRADE BANNER - CTA for upgrades
// =============================================
export const MiftyUpgradeBanner = ({ onClick }) => {
  return (
    <div className="mifty-upgrade-banner">
      <h4 className="mifty-upgrade-banner-title">Mannat Themes</h4>
      <p className="mifty-upgrade-banner-text">
        Jarwis is a high quality security platform.
      </p>
      <button onClick={onClick} className="mifty-upgrade-banner-btn">
        Upgrade your plan
        <svg
          className="w-4 h-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M9 5l7 7-7 7"
          />
        </svg>
      </button>
    </div>
  );
};

export default {
  MiftyStatCard,
  MiftyProfileCard,
  MiftyDataTable,
  MiftyBadge,
  MiftyProgressBar,
  MiftyButton,
  MiftyQuickAction,
  MiftyPageHeader,
  MiftyCard,
  MiftySectionTitle,
  MiftyUpgradeBanner,
};
