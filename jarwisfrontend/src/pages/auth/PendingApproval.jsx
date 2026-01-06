// src/pages/auth/PendingApproval.jsx
import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { Clock, Shield, Mail, CheckCircle } from "lucide-react";

const PendingApproval = () => {
  const { user, userDoc, logout, isApproved, isRejected, getApprovalStatus } =
    useAuth();
  const { isDarkMode } = useTheme();
  const navigate = useNavigate();

  // Redirect if user status changes
  useEffect(() => {
    if (!user) {
      navigate("/login");
      return;
    }

    if (isApproved()) {
      navigate("/dashboard");
      return;
    }

    if (isRejected()) {
      navigate("/access-denied");
      return;
    }
  }, [user, userDoc, isApproved, isRejected, navigate]);

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
    } catch (error) {
      console.error("Logout error:", error);
    }
  };

  const formatDate = (timestamp) => {
    if (!timestamp) return "Recently";

    let date;
    if (typeof timestamp === "string") {
      date = new Date(timestamp);
    } else if (timestamp.toDate) {
      date = timestamp.toDate();
    } else {
      date = new Date(timestamp);
    }

    return date.toLocaleDateString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  const themeClasses = {
    container: isDarkMode
      ? "min-h-screen bg-gradient-to-br from-gray-900 via-blue-900/20 to-gray-900 flex items-center justify-center p-4"
      : "min-h-screen bg-gradient-to-br from-blue-50 via-white to-cyan-50 flex items-center justify-center p-4",

    card: isDarkMode
      ? "max-w-md w-full bg-gray-800/90 backdrop-blur-xl border border-gray-700/50 rounded-3xl p-8 shadow-2xl"
      : "max-w-md w-full bg-white/90 backdrop-blur-xl border border-gray-200 rounded-3xl p-8 shadow-xl",

    iconContainer: isDarkMode
      ? "w-20 h-20 bg-yellow-500/20 rounded-full flex items-center justify-center mb-6 mx-auto"
      : "w-20 h-20 bg-yellow-100 rounded-full flex items-center justify-center mb-6 mx-auto",

    title: isDarkMode
      ? "text-2xl font-bold text-gray-100 text-center mb-4"
      : "text-2xl font-bold text-gray-900 text-center mb-4",

    subtitle: isDarkMode
      ? "text-gray-400 text-center mb-8 leading-relaxed"
      : "text-gray-600 text-center mb-8 leading-relaxed",

    infoCard: isDarkMode
      ? "bg-gray-700/50 border border-gray-600/50 rounded-xl p-4 mb-6"
      : "bg-gray-50 border border-gray-200 rounded-xl p-4 mb-6",

    infoLabel: isDarkMode
      ? "text-gray-400 text-sm font-medium"
      : "text-gray-600 text-sm font-medium",

    infoValue: isDarkMode
      ? "text-gray-200 font-semibold"
      : "text-gray-900 font-semibold",

    statusBadge: isDarkMode
      ? "inline-flex items-center px-3 py-1 bg-yellow-500/20 text-yellow-400 border border-yellow-500/30 rounded-full text-sm font-medium"
      : "inline-flex items-center px-3 py-1 bg-yellow-100 text-yellow-800 border border-yellow-300 rounded-full text-sm font-medium",

    logoutButton: isDarkMode
      ? "w-full px-6 py-3 bg-gray-600 hover:bg-gray-500 text-white rounded-xl font-medium transition-all duration-200"
      : "w-full px-6 py-3 bg-gray-200 hover:bg-gray-300 text-gray-800 rounded-xl font-medium transition-all duration-200",
  };

  return (
    <div className={themeClasses.container}>
      <div className={themeClasses.card}>
        {/* Status Icon */}
        <div className={themeClasses.iconContainer}>
          <Clock className="w-10 h-10 text-yellow-500" />
        </div>

        {/* Title */}
        <h1 className={themeClasses.title}>Account Pending Approval</h1>

        {/* Subtitle */}
        <p className={themeClasses.subtitle}>
          Your account has been created successfully! An administrator will
          review your request and approve access to the platform.
        </p>

        {/* User Info */}
        <div className={themeClasses.infoCard}>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className={themeClasses.infoLabel}>Email</span>
              <span className={themeClasses.infoValue}>{user?.email}</span>
            </div>

            <div className="flex items-center justify-between">
              <span className={themeClasses.infoLabel}>Name</span>
              <span className={themeClasses.infoValue}>
                {userDoc?.displayName || "Not provided"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className={themeClasses.infoLabel}>Company</span>
              <span className={themeClasses.infoValue}>
                {userDoc?.company || "Not provided"}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className={themeClasses.infoLabel}>Requested</span>
              <span className={themeClasses.infoValue}>
                {formatDate(userDoc?.createdAt)}
              </span>
            </div>

            <div className="flex items-center justify-between">
              <span className={themeClasses.infoLabel}>Status</span>
              <div className={themeClasses.statusBadge}>
                <Clock className="w-4 h-4 mr-1" />
                Pending Review
              </div>
            </div>
          </div>
        </div>

        {/* What happens next */}
        <div className={`${themeClasses.infoCard} mb-8`}>
          <h3
            className={`font-semibold mb-3 ${
              isDarkMode ? "text-gray-200" : "text-gray-800"
            }`}
          >
            What happens next?
          </h3>
          <div className="space-y-2">
            <div className="flex items-start space-x-3">
              <Shield
                className={`w-4 h-4 mt-0.5 ${
                  isDarkMode ? "text-blue-400" : "text-blue-600"
                }`}
              />
              <span
                className={`text-sm ${
                  isDarkMode ? "text-gray-300" : "text-gray-700"
                }`}
              >
                An administrator will review your request
              </span>
            </div>
            <div className="flex items-start space-x-3">
              <Mail
                className={`w-4 h-4 mt-0.5 ${
                  isDarkMode ? "text-green-400" : "text-green-600"
                }`}
              />
              <span
                className={`text-sm ${
                  isDarkMode ? "text-gray-300" : "text-gray-700"
                }`}
              >
                You'll receive an email notification when approved
              </span>
            </div>
            <div className="flex items-start space-x-3">
              <CheckCircle
                className={`w-4 h-4 mt-0.5 ${
                  isDarkMode ? "text-purple-400" : "text-purple-600"
                }`}
              />
              <span
                className={`text-sm ${
                  isDarkMode ? "text-gray-300" : "text-gray-700"
                }`}
              >
                You can then access your dashboard
              </span>
            </div>
          </div>
        </div>

        {/* Actions */}
        <div className="space-y-4">
          <button onClick={handleLogout} className={themeClasses.logoutButton}>
            Sign Out
          </button>

          <p
            className={`text-center text-sm ${
              isDarkMode ? "text-gray-500" : "text-gray-600"
            }`}
          >
            Questions? Contact support at support@jarwis.ai
          </p>
        </div>
      </div>
    </div>
  );
};

export default PendingApproval;
