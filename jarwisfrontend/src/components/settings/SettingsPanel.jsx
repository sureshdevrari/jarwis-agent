// src/components/settings/SettingsPanel.jsx
// Comprehensive Settings Panel for User Dashboard
import { useState, useRef, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useSubscription } from "../../context/SubscriptionContext";
import PlanUsageCard from "../subscription/PlanUsageCard";
import { FeatureChip, ProBadge, EnterpriseBadge } from "../subscription/FeatureGate";
import { initiatePayment, getUserCountry, getCurrencyInfo } from "../../services/paymentService";
import TwoFactorSettings from "./TwoFactorSettings";
import { getAccessToken } from "../../services/api";

const SettingsPanel = ({ isOpen, onClose, isDarkMode, initialTab = "account" }) => {
  const navigate = useNavigate();
  const { user, userDoc, isPro, isEnterprise, getPlanInfo, logout } = useAuth();
  const { currentPlan, getAllFeatures, canPerformAction, getActionLimit } = useSubscription();
  const panelRef = useRef(null);
  
  // Local state for settings
  const [activeSection, setActiveSection] = useState(initialTab);
  const [profileImage, setProfileImage] = useState(userDoc?.profile_image || null);
  
  // Update active section when initialTab changes
  useEffect(() => {
    if (isOpen && initialTab) {
      setActiveSection(initialTab);
    }
  }, [isOpen, initialTab]);
  const [isUploading, setIsUploading] = useState(false);
  const [showTeamModal, setShowTeamModal] = useState(false);
  const [teamMembers, setTeamMembers] = useState([]);
  const [newTeamEmail, setNewTeamEmail] = useState("");
  const [notifications, setNotifications] = useState({
    email: true,
    push: true,
    scanComplete: true,
    criticalVuln: true,
    weeklyReport: false,
    marketing: false,
  });
  const [preferences, setPreferences] = useState({
    autoScan: false,
    detailedLogs: true,
    saveHistory: true,
    twoFactorAuth: false,
  });
  
  // Payment states
  const [paymentLoading, setPaymentLoading] = useState(false);
  const [paymentError, setPaymentError] = useState(null);
  const [paymentSuccess, setPaymentSuccess] = useState(false);
  const [currencyInfo, setCurrencyInfo] = useState(null);
  
  // Fetch currency info on mount
  useEffect(() => {
    const fetchCurrencyInfo = async () => {
      try {
        const country = await getUserCountry();
        const info = await getCurrencyInfo(country);
        setCurrencyInfo(info);
      } catch (err) {
        console.error("Failed to get currency info:", err);
      }
    };
    fetchCurrencyInfo();
  }, []);
  
  // Handle upgrade to Pro payment
  const handleUpgradeToPro = useCallback(async () => {
    setPaymentLoading(true);
    setPaymentError(null);
    setPaymentSuccess(false);
    
    try {
      const token = getAccessToken();
      const currency = currencyInfo?.currency || "INR";
      
      await initiatePayment({
        plan: "professional",
        currency,
        token,
        email: user?.email || userDoc?.email,
        userName: userDoc?.full_name || userDoc?.name || user?.email?.split('@')[0],
        onSuccess: (result) => {
          setPaymentSuccess(true);
          setPaymentLoading(false);
          // Refresh the page to update subscription status
          setTimeout(() => {
            window.location.reload();
          }, 2000);
        },
        onError: (error) => {
          setPaymentError(error.message || "Payment failed. Please try again.");
          setPaymentLoading(false);
        },
        onClose: () => {
          setPaymentLoading(false);
        },
      });
    } catch (error) {
      setPaymentError(error.message || "Failed to initiate payment");
      setPaymentLoading(false);
    }
  }, [user, userDoc, currencyInfo]);

  // Close on outside click
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (panelRef.current && !panelRef.current.contains(event.target)) {
        onClose();
      }
    };
    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen, onClose]);

  // Close on escape key
  useEffect(() => {
    const handleEscape = (e) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      document.addEventListener("keydown", handleEscape);
    }
    return () => document.removeEventListener("keydown", handleEscape);
  }, [isOpen, onClose]);

  const handleImageUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    // Validate file type
    if (!file.type.startsWith("image/")) {
      alert("Please upload an image file");
      return;
    }

    // Validate file size (max 5MB)
    if (file.size > 5 * 1024 * 1024) {
      alert("Image must be less than 5MB");
      return;
    }

    setIsUploading(true);
    try {
      // Create preview
      const reader = new FileReader();
      reader.onloadend = () => {
        setProfileImage(reader.result);
      };
      reader.readAsDataURL(file);

      // TODO: Upload to server
      // await authAPI.uploadProfileImage(file);
      
      setTimeout(() => {
        setIsUploading(false);
      }, 1000);
    } catch (error) {
      console.error("Upload failed:", error);
      setIsUploading(false);
    }
  };

  const handleInviteTeamMember = async () => {
    if (!newTeamEmail.trim()) return;
    
    // TODO: API call to invite team member
    setTeamMembers([...teamMembers, { 
      email: newTeamEmail, 
      role: "viewer", 
      status: "pending",
      invitedAt: new Date().toISOString()
    }]);
    setNewTeamEmail("");
  };

  const handleRemoveTeamMember = (email) => {
    setTeamMembers(teamMembers.filter(m => m.email !== email));
  };

  const planInfo = getPlanInfo();
  const canAccessTeam = isPro() || isEnterprise();

  // Settings sections configuration
  const settingsSections = [
    { id: "account", icon: "User", label: "Account", available: true },
    { id: "profile", icon: "Profile", label: "Profile", available: true },
    { id: "security", icon: "Lock", label: "Security", available: true },
    { id: "notifications", icon: "Bell", label: "Notifications", available: true },
    { id: "team", icon: "Team", label: "Team Access", available: canAccessTeam, proOnly: true },
    { id: "integrations", icon: "Link", label: "Integrations", available: true },
    { id: "billing", icon: "Card", label: "Billing", available: true },
    { id: "preferences", icon: "Gear", label: "Preferences", available: true },
    { id: "data", icon: "Data", label: "Data & Privacy", available: true },
    { id: "help", icon: "Help", label: "Help & Support", available: true },
  ];

  // Theme classes
  const themeClasses = {
    overlay: isDarkMode
      ? "fixed inset-0 bg-black/60 backdrop-blur-sm z-50"
      : "fixed inset-0 bg-gray-500/40 backdrop-blur-sm z-50",
    panel: isDarkMode
      ? "fixed right-0 top-0 h-full w-full sm:w-[90vw] sm:max-w-2xl bg-gray-900 border-l border-gray-700 shadow-2xl z-50 overflow-hidden safe-area-inset-x"
      : "fixed right-0 top-0 h-full w-full sm:w-[90vw] sm:max-w-2xl bg-white border-l border-gray-200 shadow-2xl z-50 overflow-hidden safe-area-inset-x",
    header: isDarkMode
      ? "flex items-center justify-between p-4 sm:p-6 border-b border-gray-700"
      : "flex items-center justify-between p-4 sm:p-6 border-b border-gray-200",
    title: isDarkMode
      ? "text-xl sm:text-2xl font-bold text-white"
      : "text-xl sm:text-2xl font-bold text-gray-900",
    closeBtn: isDarkMode
      ? "p-2 min-w-[44px] min-h-[44px] flex items-center justify-center rounded-lg hover:bg-gray-700 text-gray-400 hover:text-white transition-colors active:scale-95"
      : "p-2 min-w-[44px] min-h-[44px] flex items-center justify-center rounded-lg hover:bg-gray-100 text-gray-500 hover:text-gray-900 transition-colors active:scale-95",
    sidebar: isDarkMode
      ? "hidden md:block w-56 border-r border-gray-700 p-4 space-y-1 overflow-y-auto"
      : "hidden md:block w-56 border-r border-gray-200 p-4 space-y-1 overflow-y-auto",
    sidebarBtn: (active, available) => isDarkMode
      ? `w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all min-h-[44px] ${
          !available ? "opacity-50 cursor-not-allowed" :
          active ? "bg-blue-600/20 text-blue-400 border border-blue-500/30" : "text-gray-300 hover:bg-gray-800 hover:text-white"
        }`
      : `w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-all min-h-[44px] ${
          !available ? "opacity-50 cursor-not-allowed" :
          active ? "bg-blue-100 text-blue-700 border border-blue-300" : "text-gray-700 hover:bg-gray-100 hover:text-gray-900"
        }`,
    content: isDarkMode
      ? "flex-1 p-4 sm:p-6 overflow-y-auto"
      : "flex-1 p-4 sm:p-6 overflow-y-auto",
    card: isDarkMode
      ? "p-4 sm:p-5 bg-gray-800/50 border border-gray-700 rounded-xl mb-4"
      : "p-4 sm:p-5 bg-gray-50 border border-gray-200 rounded-xl mb-4 shadow-sm",
    cardTitle: isDarkMode
      ? "text-base sm:text-lg font-semibold text-white mb-3 sm:mb-4"
      : "text-base sm:text-lg font-semibold text-gray-900 mb-3 sm:mb-4",
    label: isDarkMode
      ? "block text-xs sm:text-sm font-medium text-gray-400 mb-1.5 sm:mb-2"
      : "block text-xs sm:text-sm font-medium text-gray-600 mb-1.5 sm:mb-2",
    input: isDarkMode
      ? "w-full px-3 sm:px-4 py-2.5 bg-gray-700 border border-gray-600 rounded-lg text-white text-base placeholder-gray-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-colors min-h-[48px]"
      : "w-full px-3 sm:px-4 py-2.5 bg-white border border-gray-300 rounded-lg text-gray-900 text-base placeholder-gray-400 focus:border-blue-500 focus:ring-1 focus:ring-blue-500 outline-none transition-colors min-h-[48px]",
    btnPrimary: isDarkMode
      ? "px-4 py-2.5 sm:py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors min-h-[44px] active:scale-95"
      : "px-4 py-2.5 sm:py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors shadow-sm min-h-[44px] active:scale-95",
    btnSecondary: isDarkMode
      ? "px-4 py-2.5 sm:py-2 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg font-medium transition-colors border border-gray-600 min-h-[44px] active:scale-95"
      : "px-4 py-2.5 sm:py-2 bg-white hover:bg-gray-50 text-gray-700 rounded-lg font-medium transition-colors border border-gray-300 shadow-sm min-h-[44px] active:scale-95",
    btnDanger: isDarkMode
      ? "px-4 py-2.5 sm:py-2 bg-red-600/20 hover:bg-red-600/30 text-red-400 rounded-lg font-medium transition-colors border border-red-500/30 min-h-[44px] active:scale-95"
      : "px-4 py-2.5 sm:py-2 bg-red-50 hover:bg-red-100 text-red-700 rounded-lg font-medium transition-colors border border-red-200 min-h-[44px] active:scale-95",
    toggle: (enabled) => `relative inline-flex h-7 sm:h-6 w-12 sm:w-11 items-center rounded-full transition-colors ${
      enabled 
        ? (isDarkMode ? "bg-blue-600" : "bg-blue-600") 
        : (isDarkMode ? "bg-gray-600" : "bg-gray-300")
    }`,
    toggleKnob: (enabled) => `inline-block h-5 sm:h-4 w-5 sm:w-4 transform rounded-full bg-white transition-transform ${
      enabled ? "translate-x-6" : "translate-x-1"
    }`,
    badge: isDarkMode
      ? "px-2 py-0.5 text-xs font-medium bg-gradient-to-r from-purple-500/20 to-pink-500/20 text-purple-300 border border-purple-500/30 rounded-full"
      : "px-2 py-0.5 text-xs font-medium bg-gradient-to-r from-purple-100 to-pink-100 text-purple-700 border border-purple-300 rounded-full",
    text: isDarkMode ? "text-gray-300" : "text-gray-700",
    textMuted: isDarkMode ? "text-gray-500" : "text-gray-400",
  };

  if (!isOpen) return null;

  const renderContent = () => {
    switch (activeSection) {
      case "account":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Account Information</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Full Name</label>
                  <input
                    type="text"
                    defaultValue={userDoc?.full_name || userDoc?.displayName || ""}
                    className={themeClasses.input}
                    placeholder="Enter your full name"
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>Email Address</label>
                  <input
                    type="email"
                    defaultValue={userDoc?.email || user?.email || ""}
                    className={themeClasses.input}
                    disabled
                  />
                  <p className={`text-xs mt-1 ${themeClasses.textMuted}`}>
                    Email cannot be changed. Contact support if needed.
                  </p>
                </div>
                <div>
                  <label className={themeClasses.label}>Company / Organization</label>
                  <input
                    type="text"
                    defaultValue={userDoc?.company || ""}
                    className={themeClasses.input}
                    placeholder="Your company name"
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>Job Title</label>
                  <input
                    type="text"
                    defaultValue={userDoc?.job_title || ""}
                    className={themeClasses.input}
                    placeholder="e.g., Security Engineer"
                  />
                </div>
              </div>
              <div className="mt-6 flex justify-end">
                <button className={themeClasses.btnPrimary}>Save Changes</button>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Current Plan</h3>
              <div className="flex items-center justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-2xl">{planInfo?.badge}</span>
                    <span className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                      {planInfo?.name} Plan
                    </span>
                  </div>
                  <p className={themeClasses.textMuted}>
                    {userDoc?.scans_this_month || 0} / {isEnterprise() ? "Unlimited" : (planInfo?.maxScansPerMonth || 10)} scans used this month
                  </p>
                </div>
                <button 
                  onClick={() => navigate("/pricing")}
                  className={themeClasses.btnSecondary}
                >
                  {isPro() || isEnterprise() ? "Manage Plan" : "Upgrade"}
                </button>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={`${themeClasses.cardTitle} text-red-500`}>Danger Zone</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Once you delete your account, there is no going back. Please be certain.
              </p>
              <button className={themeClasses.btnDanger}>Delete Account</button>
            </div>
          </div>
        );

      case "profile":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Profile Picture</h3>
              <div className="flex items-center gap-6">
                <div className="relative">
                  <div className={`w-24 h-24 rounded-full overflow-hidden border-4 ${isDarkMode ? "border-gray-600" : "border-gray-300"}`}>
                    {profileImage ? (
                      <img src={profileImage} alt="Profile" className="w-full h-full object-cover" />
                    ) : (
                      <div className={`w-full h-full flex items-center justify-center text-3xl ${isDarkMode ? "bg-gray-700" : "bg-gray-200"}`}>
                        {(userDoc?.full_name || userDoc?.displayName || "U")[0].toUpperCase()}
                      </div>
                    )}
                  </div>
                  {isUploading && (
                    <div className="absolute inset-0 flex items-center justify-center bg-black/50 rounded-full">
                      <div className="animate-spin w-6 h-6 border-2 border-white border-t-transparent rounded-full"></div>
                    </div>
                  )}
                </div>
                <div>
                  <input
                    type="file"
                    id="profile-upload"
                    accept="image/*"
                    onChange={handleImageUpload}
                    className="hidden"
                  />
                  <label htmlFor="profile-upload" className={`${themeClasses.btnSecondary} cursor-pointer inline-block`}>
                    Upload New Photo
                  </label>
                  <p className={`text-xs mt-2 ${themeClasses.textMuted}`}>
                    JPG, PNG or GIF. Max 5MB.
                  </p>
                </div>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Bio</h3>
              <textarea
                rows={4}
                defaultValue={userDoc?.bio || ""}
                className={themeClasses.input}
                placeholder="Tell us a bit about yourself..."
              />
              <div className="mt-4 flex justify-end">
                <button className={themeClasses.btnPrimary}>Save Bio</button>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Social Links</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>LinkedIn</label>
                  <input type="url" className={themeClasses.input} placeholder="https://linkedin.com/in/..." />
                </div>
                <div>
                  <label className={themeClasses.label}>Twitter / X</label>
                  <input type="url" className={themeClasses.input} placeholder="https://twitter.com/..." />
                </div>
                <div>
                  <label className={themeClasses.label}>GitHub</label>
                  <input type="url" className={themeClasses.input} placeholder="https://github.com/..." />
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button className={themeClasses.btnPrimary}>Save Links</button>
              </div>
            </div>
          </div>
        );

      case "security":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Password</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Current Password</label>
                  <input type="password" className={themeClasses.input} placeholder="********" />
                </div>
                <div>
                  <label className={themeClasses.label}>New Password</label>
                  <input type="password" className={themeClasses.input} placeholder="********" />
                </div>
                <div>
                  <label className={themeClasses.label}>Confirm New Password</label>
                  <input type="password" className={themeClasses.input} placeholder="********" />
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button className={themeClasses.btnPrimary}>Update Password</button>
              </div>
            </div>

            {/* Two-Factor Authentication Component */}
            <TwoFactorSettings isDarkMode={isDarkMode} user={user} />

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Active Sessions</h3>
              <div className="space-y-3">
                <div className={`flex items-center justify-between p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"}`}>
                  <div className="flex items-center gap-3">
                    <span></span>
                    <div>
                      <p className={isDarkMode ? "text-white font-medium" : "text-gray-900 font-medium"}>
                        Current Session
                      </p>
                      <p className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                        This device
                      </p>
                    </div>
                  </div>
                  <span className="px-2 py-1 text-xs font-medium bg-green-500/20 text-green-500 rounded-full">Active</span>
                </div>
              </div>
              <button className={`${themeClasses.btnDanger} mt-4`}>Sign Out All Devices</button>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Login History</h3>
              <div className="space-y-2">
                {[
                  { date: "Today, 10:30 AM", location: "Mumbai, India", device: "Chrome on Windows" },
                  { date: "Yesterday, 2:15 PM", location: "Mumbai, India", device: "Safari on iPhone" },
                  { date: "Jan 1, 2026", location: "Delhi, India", device: "Firefox on Mac" },
                ].map((login, i) => (
                  <div key={i} className={`flex items-center justify-between py-2 ${i > 0 ? `border-t ${isDarkMode ? "border-gray-700" : "border-gray-200"}` : ""}`}>
                    <div>
                      <p className={themeClasses.text}>{login.device}</p>
                      <p className={`text-sm ${themeClasses.textMuted}`}>{login.location}</p>
                    </div>
                    <span className={`text-sm ${themeClasses.textMuted}`}>{login.date}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      case "notifications":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Email Notifications</h3>
              <div className="space-y-4">
                {[
                  { key: "scanComplete", label: "Scan Completed", desc: "Get notified when a scan finishes" },
                  { key: "criticalVuln", label: "Critical Vulnerabilities", desc: "Immediate alerts for critical findings" },
                  { key: "weeklyReport", label: "Weekly Summary", desc: "Receive a weekly security report" },
                  { key: "marketing", label: "Product Updates", desc: "News about features and improvements" },
                ].map((item) => (
                  <div key={item.key} className="flex items-center justify-between">
                    <div>
                      <p className={themeClasses.text}>{item.label}</p>
                      <p className={`text-sm ${themeClasses.textMuted}`}>{item.desc}</p>
                    </div>
                    <button
                      onClick={() => setNotifications({...notifications, [item.key]: !notifications[item.key]})}
                      className={themeClasses.toggle(notifications[item.key])}
                    >
                      <span className={themeClasses.toggleKnob(notifications[item.key])} />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Push Notifications</h3>
              <div className="flex items-center justify-between">
                <div>
                  <p className={themeClasses.text}>Browser Notifications</p>
                  <p className={`text-sm ${themeClasses.textMuted}`}>Receive real-time alerts in your browser</p>
                </div>
                <button
                  onClick={() => setNotifications({...notifications, push: !notifications.push})}
                  className={themeClasses.toggle(notifications.push)}
                >
                  <span className={themeClasses.toggleKnob(notifications.push)} />
                </button>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Slack Integration</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Connect Slack to receive scan alerts in your workspace
              </p>
              <button className={themeClasses.btnSecondary}>
                <span></span> Connect Slack
              </button>
            </div>
          </div>
        );

      case "team":
        if (!canAccessTeam) {
          return (
            <div className={themeClasses.card}>
              <div className="text-center py-8">
                <span></span>
                <h3 className={`text-xl font-bold mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  Team Access is a Pro Feature
                </h3>
                <p className={`${themeClasses.textMuted} mb-6`}>
                  Upgrade to Pro or Enterprise to invite team members and collaborate on security scans.
                </p>
                <button onClick={() => navigate("/pricing")} className={themeClasses.btnPrimary}>
                  Upgrade Now
                </button>
              </div>
            </div>
          );
        }
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Invite Team Members</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                {isEnterprise() 
                  ? "Invite unlimited team members to collaborate" 
                  : "Invite up to 5 team members (Pro plan)"}
              </p>
              <div className="flex gap-3">
                <input
                  type="email"
                  value={newTeamEmail}
                  onChange={(e) => setNewTeamEmail(e.target.value)}
                  className={`flex-1 ${themeClasses.input}`}
                  placeholder="colleague@company.com"
                />
                <button onClick={handleInviteTeamMember} className={themeClasses.btnPrimary}>
                  Send Invite
                </button>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Team Members</h3>
              {teamMembers.length === 0 ? (
                <p className={themeClasses.textMuted}>No team members yet. Invite someone above!</p>
              ) : (
                <div className="space-y-3">
                  {teamMembers.map((member, i) => (
                    <div key={i} className={`flex items-center justify-between p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"}`}>
                      <div className="flex items-center gap-3">
                        <div className={`w-10 h-10 rounded-full flex items-center justify-center ${isDarkMode ? "bg-gray-600" : "bg-gray-200"}`}>
                          {member.email[0].toUpperCase()}
                        </div>
                        <div>
                          <p className={isDarkMode ? "text-white" : "text-gray-900"}>{member.email}</p>
                          <p className={`text-sm ${themeClasses.textMuted}`}>
                            {member.status === "pending" ? "Invitation pending" : member.role}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <select className={`${themeClasses.input} w-auto`}>
                          <option value="viewer">Viewer</option>
                          <option value="editor">Editor</option>
                          <option value="admin">Admin</option>
                        </select>
                        <button 
                          onClick={() => handleRemoveTeamMember(member.email)}
                          className="p-2 text-red-500 hover:bg-red-500/10 rounded-lg transition-colors">
                          Remove
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Team Permissions</h3>
              <div className="space-y-3">
                {[
                  { role: "Admin", perms: "Full access to all features and settings" },
                  { role: "Editor", perms: "Can create scans, view results, and manage reports" },
                  { role: "Viewer", perms: "Can only view scan results and reports" },
                ].map((item, i) => (
                  <div key={i} className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700/30" : "bg-gray-100"}`}>
                    <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>{item.role}</p>
                    <p className={`text-sm ${themeClasses.textMuted}`}>{item.perms}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        );

      case "integrations":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Connected Services</h3>
              <div className="space-y-4">
                {[
                  { name: "GitHub", icon: "Icon", status: false, desc: "Import repositories for scanning" },
                  { name: "GitLab", icon: "Icon", status: false, desc: "Connect GitLab projects" },
                  { name: "Jira", icon: "Icon", status: false, desc: "Create tickets from vulnerabilities" },
                  { name: "Slack", icon: "Icon", status: false, desc: "Receive notifications in Slack" },
                  { name: "Microsoft Teams", icon: "Icon", status: false, desc: "Team notifications" },
                  { name: "AWS", icon: "Icon", status: false, desc: "Scan AWS infrastructure" },
                ].map((service) => (
                  <div key={service.name} className={`flex items-center justify-between p-4 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"}`}>
                    <div className="flex items-center gap-4">
                      <span className="text-3xl">{service.icon}</span>
                      <div>
                        <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>{service.name}</p>
                        <p className={`text-sm ${themeClasses.textMuted}`}>{service.desc}</p>
                      </div>
                    </div>
                    <button className={service.status ? themeClasses.btnDanger : themeClasses.btnSecondary}>
                      {service.status ? "Disconnect" : "Connect"}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Webhooks</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Send scan results to your own endpoints
              </p>
              <div className="space-y-3">
                <input type="url" className={themeClasses.input} placeholder="https://your-webhook-endpoint.com/jarwis" />
                <div className="flex gap-3">
                  <button className={themeClasses.btnPrimary}>Add Webhook</button>
                  <button className={themeClasses.btnSecondary}>Test</button>
                </div>
              </div>
            </div>
          </div>
        );

      case "billing":
        const allFeatures = getAllFeatures();
        return (
          <div className="space-y-6">
            {/* Payment Success/Error Messages */}
            {paymentSuccess && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-green-500/20 border-green-500/30 text-green-400" : "bg-green-50 border-green-200 text-green-700"}`}>
                <div className="flex items-center gap-3">
                  <span></span>
                  <div>
                    <p className="font-semibold">Payment Successful!</p>
                    <p className="text-sm opacity-80">Your subscription has been upgraded. Refreshing...</p>
                  </div>
                </div>
              </div>
            )}
            
            {paymentError && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-red-500/20 border-red-500/30 text-red-400" : "bg-red-50 border-red-200 text-red-700"}`}>
                <div className="flex items-center gap-3">
                  <span></span>
                  <div>
                    <p className="font-semibold">Payment Failed</p>
                    <p className="text-sm opacity-80">{paymentError}</p>
                  </div>
                </div>
              </div>
            )}
            
            {/* Plan Usage Card */}
            <PlanUsageCard isDarkMode={isDarkMode} compact={false} />
            
            {/* Upgrade to Pro Card - Show for free/individual users */}
            {(currentPlan.id === 'free' || currentPlan.id === 'individual') && (
              <div className={`p-6 rounded-xl border-2 ${isDarkMode ? "bg-gradient-to-br from-purple-900/30 to-pink-900/20 border-purple-500/40" : "bg-gradient-to-br from-purple-50 to-pink-50 border-purple-300"}`}>
                <div className="flex items-start justify-between flex-wrap gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <span></span>
                      <h3 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        Upgrade to Professional
                      </h3>
                    </div>
                    <p className={`text-sm mb-4 ${themeClasses.textMuted}`}>
                      Unlock all features including Mobile App Testing, Cloud Security, API Testing, and Jarwis AGI Chatbot
                    </p>
                    
                    {/* Pro Features List */}
                    <div className="grid grid-cols-2 gap-2 mb-4">
                      {[
                        "* Unlimited Scans",
                        "* Advanced DAST",
                        "* API Security", 
                        "* Jarwis AGI Chatbot",
                        "* Priority Support",
                        "* Custom Reports"
                      ].map((feature, i) => (
                        <div key={i} className={`text-sm ${isDarkMode ? "text-gray-300" : "text-gray-600"}`}>
                          {feature}
                        </div>
                      ))}
                    </div>
                    
                    {/* Pricing */}
                    <div className="flex items-baseline gap-2 mb-4">
                      <span className={`text-3xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        {currencyInfo?.symbol || ""}{currencyInfo?.plans?.professional?.amount ? (currencyInfo.plans.professional.amount / 100).toFixed(0) : "999"}
                      </span>
                      <span className={themeClasses.textMuted}>/month</span>
                    </div>
                  </div>
                  
                  <div className="flex flex-col gap-3">
                    <button 
                      onClick={handleUpgradeToPro}
                      disabled={paymentLoading}
                      className={`
                        px-6 py-3 rounded-xl font-bold text-white
                        bg-gradient-to-r from-purple-600 to-pink-600
                        hover:from-purple-500 hover:to-pink-500
                        shadow-lg shadow-purple-500/30
                        transition-all duration-300
                        hover:scale-105 hover:shadow-purple-500/50
                        disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:scale-100
                        flex items-center gap-2
                      `}
                    >
                      {paymentLoading ? (
                        <>
                          <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                          Processing...
                        </>
                      ) : (
                        <>
                          <span></span>
                          Upgrade Now
                        </>
                      )}
                    </button>
                    <p className={`text-xs text-center ${themeClasses.textMuted}`}>
                      Secure payment via Razorpay
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Plan Features */}
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Your Plan Features</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-4">
                {allFeatures.map((feature, i) => (
                  <div 
                    key={i} 
                    className={`flex items-center gap-3 p-3 rounded-lg ${
                      feature.available 
                        ? isDarkMode ? "bg-green-500/10 border border-green-500/20" : "bg-green-50 border border-green-200"
                        : isDarkMode ? "bg-gray-700/30 border border-gray-600/30" : "bg-gray-50 border border-gray-200"
                    }`}
                  >
                    <span className={`text-lg ${feature.available ? "opacity-100" : "opacity-40"}`}>
                      {feature.available ? "*" : "x"}
                    </span>
                    <div className="flex-1 min-w-0">
                      <p className={`text-sm font-medium ${feature.available ? (isDarkMode ? "text-white" : "text-gray-900") : themeClasses.textMuted}`}>
                        {feature.name}
                      </p>
                      {!feature.available && feature.requiredPlan && (
                        <p className="text-xs text-amber-500">
                          {feature.requiredPlan === 'professional' ? <ProBadge /> : <EnterpriseBadge />}
                        </p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
              
              {/* Enterprise CTA for pro users */}
              {currentPlan.id === 'professional' && (
                <div className={`mt-6 p-4 rounded-lg ${isDarkMode ? "bg-gradient-to-r from-amber-500/10 to-orange-500/10 border border-amber-500/20" : "bg-gradient-to-r from-amber-50 to-orange-50 border border-amber-200"}`}>
                  <div className="flex items-center justify-between flex-wrap gap-4">
                    <div>
                      <p className={`font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        Need More Power?
                      </p>
                      <p className={`text-sm ${themeClasses.textMuted}`}>
                        Enterprise plans include unlimited scans, dedicated support, and custom integrations
                      </p>
                    </div>
                    <button onClick={() => navigate("/contact")} className={themeClasses.btnPrimary}>
                      Contact Sales
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Usage Limits */}
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Usage Limits</h3>
              <div className="space-y-4 mt-4">
                {[
                  { label: "Scans per Month", stat: getActionLimit('scans') },
                  { label: "Pages per Scan", stat: getActionLimit('pagesPerScan') },
                  { label: "Team Members", stat: getActionLimit('teamMembers') },
                  { label: "Dashboard Access", stat: getActionLimit('dashboardAccess') },
                ].map((item, i) => {
                  const stat = item.stat || {};
                  const isUnlimited = stat.unlimited;
                  const percentage = stat.percentage || 0;
                  const current = stat.current;
                  const max = stat.max;
                  
                  return (
                    <div key={i} className={`p-3 rounded-lg ${isDarkMode ? "bg-gray-700/30" : "bg-gray-50"}`}>
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-sm font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                          {item.label}
                        </span>
                        <span className={`text-sm ${themeClasses.textMuted}`}>
                          {isUnlimited 
                            ? "Unlimited" 
                            : current !== undefined 
                              ? `${current} / ${max}` 
                              : `${max} ${stat.unit || ""}`}
                        </span>
                      </div>
                      {current !== undefined && !isUnlimited && (
                        <div className={`h-2 rounded-full overflow-hidden ${isDarkMode ? "bg-gray-600" : "bg-gray-200"}`}>
                          <div 
                            className={`h-full rounded-full transition-all duration-300 ${
                              percentage > 90 ? "bg-red-500" : percentage > 70 ? "bg-amber-500" : "bg-blue-500"
                            }`}
                            style={{ width: `${percentage}%` }}
                          />
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Payment Method */}
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Payment Method</h3>
              <p className={themeClasses.textMuted}>
                Payment methods are managed through Razorpay. Your subscription is billed automatically.
              </p>
              {(isPro() || isEnterprise()) && (
                <button 
                  onClick={() => navigate("/pricing")}
                  className={`mt-3 ${themeClasses.btnSecondary}`}
                >
                  Manage Subscription
                </button>
              )}
            </div>

            {/* Billing History */}
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Billing History</h3>
              {(isPro() || isEnterprise()) ? (
                <div className={`p-4 rounded-lg ${isDarkMode ? "bg-gray-700/30" : "bg-gray-50"}`}>
                  <p className={themeClasses.text}>Subscription Active</p>
                  <p className={`text-sm ${themeClasses.textMuted} mt-1`}>
                    {planInfo?.name} Plan - Billing managed through Razorpay
                  </p>
                </div>
              ) : (
                <p className={themeClasses.textMuted}>No billing history - Upgrade to a paid plan to get started</p>
              )}
            </div>
          </div>
        );

      case "preferences":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Scan Preferences</h3>
              <div className="space-y-4">
                {[
                  { key: "autoScan", label: "Auto-start Scans", desc: "Automatically start scans after domain verification" },
                  { key: "detailedLogs", label: "Detailed Logging", desc: "Show verbose output during scans" },
                  { key: "saveHistory", label: "Save Scan History", desc: "Keep a history of all your scans" },
                ].map((item) => (
                  <div key={item.key} className="flex items-center justify-between">
                    <div>
                      <p className={themeClasses.text}>{item.label}</p>
                      <p className={`text-sm ${themeClasses.textMuted}`}>{item.desc}</p>
                    </div>
                    <button
                      onClick={() => setPreferences({...preferences, [item.key]: !preferences[item.key]})}
                      className={themeClasses.toggle(preferences[item.key])}
                    >
                      <span className={themeClasses.toggleKnob(preferences[item.key])} />
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Default Scan Settings</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Default Scan Type</label>
                  <select className={themeClasses.input}>
                    <option>Full OWASP Top 10 Scan</option>
                    <option>Quick Scan</option>
                    <option>API Security Scan</option>
                    <option>Authenticated Scan</option>
                  </select>
                </div>
                <div>
                  <label className={themeClasses.label}>Report Format</label>
                  <select className={themeClasses.input}>
                    <option>HTML + JSON</option>
                    <option>PDF</option>
                    <option>SARIF</option>
                    <option>All Formats</option>
                  </select>
                </div>
                <div>
                  <label className={themeClasses.label}>Timezone</label>
                  <select className={themeClasses.input}>
                    <option>Asia/Kolkata (IST)</option>
                    <option>UTC</option>
                    <option>America/New_York (EST)</option>
                    <option>Europe/London (GMT)</option>
                  </select>
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button className={themeClasses.btnPrimary}>Save Preferences</button>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Language & Region</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Language</label>
                  <select className={themeClasses.input}>
                    <option>English</option>
                    <option>Hindi</option>
                    <option>Spanish</option>
                    <option>French</option>
                    <option>German</option>
                  </select>
                </div>
                <div>
                  <label className={themeClasses.label}>Date Format</label>
                  <select className={themeClasses.input}>
                    <option>DD/MM/YYYY</option>
                    <option>MM/DD/YYYY</option>
                    <option>YYYY-MM-DD</option>
                  </select>
                </div>
              </div>
            </div>
          </div>
        );

      case "data":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Data Export</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Download all your data including scans, reports, and settings
              </p>
              <div className="flex gap-3">
                <button className={themeClasses.btnPrimary}>Export All Data</button>
                <button className={themeClasses.btnSecondary}>Export Scans Only</button>
              </div>
            </div>

            {/* Data Retention */}
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Data Retention</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Keep scan history for</label>
                  <select className={themeClasses.input}>
                    <option>30 days</option>
                    <option>90 days</option>
                    <option>1 year</option>
                    <option>Forever</option>
                  </select>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className={themeClasses.text}>Auto-delete old scans</p>
                    <p className={`text-sm ${themeClasses.textMuted}`}>Automatically remove scans older than retention period</p>
                  </div>
                  <button className={themeClasses.toggle(false)}>
                    <span className={themeClasses.toggleKnob(false)} />
                  </button>
                </div>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Privacy</h3>
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className={themeClasses.text}>Analytics & Usage Data</p>
                    <p className={`text-sm ${themeClasses.textMuted}`}>Help improve Jarwis by sharing anonymous usage data</p>
                  </div>
                  <button className={themeClasses.toggle(true)}>
                    <span className={themeClasses.toggleKnob(true)} />
                  </button>
                </div>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={`${themeClasses.cardTitle} text-red-500`}>Delete All Data</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Permanently delete all your scans, reports, and history. This action cannot be undone.
              </p>
              <button className={themeClasses.btnDanger}>Delete All My Data</button>
            </div>
          </div>
        );

      case "help":
        return (
          <div className="space-y-6">
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Help & Resources</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {[
                  { icon: "Icon", title: "Documentation", desc: "Read our comprehensive guides" },
                  { icon: "Icon", title: "Tutorials", desc: "Step-by-step video tutorials" },
                  { icon: "Icon", title: "Community", desc: "Join our Discord server" },
                  { icon: "Icon", title: "Report Bug", desc: "Found an issue? Let us know" },
                ].map((item, i) => (
                  <button 
                    key={i}
                    className={`p-4 rounded-lg text-left transition-all ${isDarkMode ? "bg-gray-700/50 hover:bg-gray-700" : "bg-white border border-gray-200 hover:border-gray-300 hover:shadow-sm"}`}
                  >
                    <span className="text-2xl mb-2 block">{item.icon}</span>
                    <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>{item.title}</p>
                    <p className={`text-sm ${themeClasses.textMuted}`}>{item.desc}</p>
                  </button>
                ))}
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Contact Support</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                {isEnterprise() 
                  ? "As an Enterprise customer, you have priority 24/7 support" 
                  : isPro()
                  ? "Pro customers get priority email support"
                  : "Free support via email (48hr response time)"}
              </p>
              <div className="flex gap-3">
                <button className={themeClasses.btnPrimary}>
                  Email Support
                </button>
                {(isPro() || isEnterprise()) && (
                  <button className={themeClasses.btnSecondary}>
                    Live Chat
                  </button>
                )}
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>About Jarwis</h3>
              <div className="space-y-2">
                <div className="flex justify-between">
                  <span className={themeClasses.textMuted}>Version</span>
                  <span className={themeClasses.text}>2.0.0</span>
                </div>
                <div className="flex justify-between">
                  <span className={themeClasses.textMuted}>Last Updated</span>
                  <span className={themeClasses.text}>January 3, 2026</span>
                </div>
              </div>
              <div className="mt-4 flex gap-3">
                <button onClick={() => navigate("/terms")} className={`text-sm ${isDarkMode ? "text-blue-400" : "text-blue-600"}`}>
                  Terms of Service
                </button>
                <button onClick={() => navigate("/privacy")} className={`text-sm ${isDarkMode ? "text-blue-400" : "text-blue-600"}`}>
                  Privacy Policy
                </button>
              </div>
            </div>
          </div>
        );

      default:
        return null;
    }
  };

  return (
    <>
      {/* Overlay */}
      <div className={themeClasses.overlay} onClick={onClose} />
      
      {/* Panel */}
      <div 
        ref={panelRef}
        className={`${themeClasses.panel} transform transition-transform duration-300 ease-out`}
        style={{ transform: isOpen ? "translateX(0)" : "translateX(100%)" }}
      >
        {/* Header */}
        <div className={`flex items-center justify-between p-4 border-b ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
          <h2 className={`text-xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Settings</h2>
          <button 
            onClick={onClose}
            className={`p-2 rounded-lg ${isDarkMode ? 'hover:bg-gray-700 text-gray-400' : 'hover:bg-gray-100 text-gray-600'}`}
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Mobile Section Selector - visible only on mobile */}
        <div className={`md:hidden flex overflow-x-auto gap-2 p-3 border-b ${isDarkMode ? 'border-gray-700 bg-gray-800/50' : 'border-gray-200 bg-gray-50'}`}>
          {settingsSections.filter(s => s.available).map((section) => (
            <button
              key={section.id}
              onClick={() => setActiveSection(section.id)}
              className={`flex-shrink-0 flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all min-h-[40px] ${
                activeSection === section.id
                  ? isDarkMode 
                    ? 'bg-blue-600/20 text-blue-400 border border-blue-500/30' 
                    : 'bg-blue-100 text-blue-700 border border-blue-300'
                  : isDarkMode 
                    ? 'bg-gray-700 text-gray-300' 
                    : 'bg-white text-gray-700 border border-gray-200'
              }`}
            >
              <span>{section.icon}</span>
              <span className="whitespace-nowrap">{section.label}</span>
            </button>
          ))}
        </div>

        {/* Body */}
        <div className="flex h-[calc(100%-80px)] md:h-[calc(100%-80px)]" style={{ height: 'calc(100% - 80px - 56px)', '@media (min-width: 768px)': { height: 'calc(100% - 80px)' } }}>
          {/* Sidebar Navigation - hidden on mobile */}
          <div className={themeClasses.sidebar}>
            {settingsSections.map((section) => (
              <button
                key={section.id}
                onClick={() => section.available && setActiveSection(section.id)}
                className={themeClasses.sidebarBtn(activeSection === section.id, section.available)}
                disabled={!section.available}
              >
                <span className="text-lg">{section.icon}</span>
                <span className="text-sm font-medium flex-1">{section.label}</span>
                {section.proOnly && !section.available && (
                  <span className={themeClasses.badge}>PRO</span>
                )}
              </button>
            ))}
          </div>

          {/* Content Area */}
          <div className={themeClasses.content}>
            {renderContent()}
          </div>
        </div>
      </div>
    </>
  );
};

export default SettingsPanel;
