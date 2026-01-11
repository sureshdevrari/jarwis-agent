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
import AgentManagement from "./AgentManagement";
import VerifiedDomainsSettings from "./VerifiedDomainsSettings";
import { getAccessToken, authAPI, userSettingsAPI } from "../../services/api";

const SettingsPanel = ({ isOpen, onClose, isDarkMode, initialTab = "account", isInlinePage = false }) => {
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
  
  // Account form state (controlled inputs)
  const [accountForm, setAccountForm] = useState({
    full_name: userDoc?.full_name || userDoc?.displayName || "",
    email: userDoc?.email || user?.email || "",
    company: userDoc?.company || "",
    job_title: userDoc?.job_title || "",
  });
  
  // Profile form state
  const [profileForm, setProfileForm] = useState({
    bio: userDoc?.bio || "",
    linkedin_url: userDoc?.linkedin_url || "",
    twitter_url: userDoc?.twitter_url || "",
    github_url: userDoc?.github_url || "",
  });
  
  // Preferences form state
  const [preferencesForm, setPreferencesForm] = useState({
    default_scan_type: userDoc?.scan_preferences?.default_scan_type || "full",
    report_format: userDoc?.scan_preferences?.report_format || "html_json",
    timezone: userDoc?.timezone || "Asia/Kolkata",
    language: userDoc?.language || "en",
    date_format: userDoc?.scan_preferences?.date_format || "DD/MM/YYYY",
    data_retention_days: userDoc?.scan_preferences?.data_retention_days || 90,
    auto_delete_old_scans: userDoc?.scan_preferences?.auto_delete_old_scans || false,
    share_analytics: userDoc?.scan_preferences?.share_analytics !== false,
  });
  
  // Password change form state
  const [passwordForm, setPasswordForm] = useState({
    current_password: "",
    new_password: "",
    confirm_password: "",
  });
  
  // UI feedback states
  const [savingAccount, setSavingAccount] = useState(false);
  const [savingProfile, setSavingProfile] = useState(false);
  const [savingNotifications, setSavingNotifications] = useState(false);
  const [savingPreferences, setSavingPreferences] = useState(false);
  const [savingPassword, setSavingPassword] = useState(false);
  const [exportingData, setExportingData] = useState(false);
  const [deletingData, setDeletingData] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState(null);
  const [saveError, setSaveError] = useState(null);
  
  // Delete account modal state
  const [showDeleteAccountModal, setShowDeleteAccountModal] = useState(false);
  const [showDeleteDataModal, setShowDeleteDataModal] = useState(false);
  const [deleteConfirmPassword, setDeleteConfirmPassword] = useState("");
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  
  // Track dirty state for unsaved changes warning
  const [dirtyForms, setDirtyForms] = useState({
    account: false,
    profile: false,
    notifications: false,
    preferences: false,
    password: false,
  });
  
  // Check if any form has unsaved changes
  const hasUnsavedChanges = Object.values(dirtyForms).some(Boolean);
  
  // Warn user about unsaved changes when leaving
  useEffect(() => {
    const handleBeforeUnload = (e) => {
      if (hasUnsavedChanges) {
        e.preventDefault();
        e.returnValue = "You have unsaved changes. Are you sure you want to leave?";
        return e.returnValue;
      }
    };
    
    window.addEventListener("beforeunload", handleBeforeUnload);
    return () => window.removeEventListener("beforeunload", handleBeforeUnload);
  }, [hasUnsavedChanges]);
  
  // Mark form as dirty when values change
  const markDirty = useCallback((formName) => {
    setDirtyForms(prev => ({ ...prev, [formName]: true }));
  }, []);
  
  // Clear dirty state after successful save
  const clearDirty = useCallback((formName) => {
    setDirtyForms(prev => ({ ...prev, [formName]: false }));
  }, []);
  
  // Update form states when userDoc changes
  useEffect(() => {
    if (userDoc) {
      setAccountForm({
        full_name: userDoc.full_name || userDoc.displayName || "",
        email: userDoc.email || user?.email || "",
        company: userDoc.company || "",
        job_title: userDoc.job_title || "",
      });
      setProfileForm({
        bio: userDoc.bio || "",
        linkedin_url: userDoc.linkedin_url || "",
        twitter_url: userDoc.twitter_url || "",
        github_url: userDoc.github_url || "",
      });
      if (userDoc.notification_settings) {
        setNotifications(prev => ({ ...prev, ...userDoc.notification_settings }));
      }
      if (userDoc.scan_preferences) {
        setPreferences(prev => ({ ...prev, ...userDoc.scan_preferences }));
      }
    }
  }, [userDoc, user]);
  
  // Clear feedback after 5 seconds
  useEffect(() => {
    if (saveSuccess || saveError) {
      const timer = setTimeout(() => {
        setSaveSuccess(null);
        setSaveError(null);
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [saveSuccess, saveError]);
  
  // Login history and sessions state
  const [loginHistory, setLoginHistory] = useState([]);
  const [activeSessions, setActiveSessions] = useState([]);
  const [loadingHistory, setLoadingHistory] = useState(false);
  
  // Payment states
  const [paymentLoading, setPaymentLoading] = useState(false);
  const [paymentError, setPaymentError] = useState(null);
  const [paymentSuccess, setPaymentSuccess] = useState(false);
  const [currencyInfo, setCurrencyInfo] = useState(null);
  
  // Fetch login history and sessions when security tab is active
  useEffect(() => {
    const fetchSecurityData = async () => {
      if (activeSection === 'security' && isOpen) {
        setLoadingHistory(true);
        try {
          const [historyRes, sessionsRes] = await Promise.all([
            authAPI.getLoginHistory(10),
            authAPI.getActiveSessions()
          ]);
          
          if (historyRes.success && historyRes.data) {
            setLoginHistory(historyRes.data.history || []);
          }
          if (sessionsRes.success && sessionsRes.data) {
            setActiveSessions(sessionsRes.data.sessions || []);
          }
        } catch (err) {
          console.error("Failed to fetch security data:", err);
        } finally {
          setLoadingHistory(false);
        }
      }
    };
    fetchSecurityData();
  }, [activeSection, isOpen]);
  
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

  // Close on outside click (only for modal mode)
  useEffect(() => {
    if (isInlinePage) return; // Skip for inline page mode
    const handleClickOutside = (event) => {
      if (panelRef.current && !panelRef.current.contains(event.target)) {
        onClose();
      }
    };
    if (isOpen) {
      document.addEventListener("mousedown", handleClickOutside);
    }
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, [isOpen, onClose, isInlinePage]);

  // Close on escape key (only for modal mode)
  useEffect(() => {
    if (isInlinePage) return; // Skip for inline page mode
    const handleEscape = (e) => {
      if (e.key === "Escape") onClose();
    };
    if (isOpen) {
      document.addEventListener("keydown", handleEscape);
    }
    return () => document.removeEventListener("keydown", handleEscape);
  }, [isOpen, onClose, isInlinePage]);

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

      // Upload to server
      const result = await userSettingsAPI.uploadAvatar(file);
      if (result.success) {
        setSaveSuccess("Profile picture updated successfully!");
      } else {
        setSaveError(result.error || "Failed to upload image");
      }
      
      setIsUploading(false);
    } catch (error) {
      console.error("Upload failed:", error);
      setSaveError("Failed to upload image");
      setIsUploading(false);
    }
  };

  // Save account settings
  const handleSaveAccount = async () => {
    setSavingAccount(true);
    setSaveError(null);
    try {
      const result = await userSettingsAPI.updateProfile({
        full_name: accountForm.full_name,
        company: accountForm.company,
        job_title: accountForm.job_title,
      });
      if (result.success) {
        setSaveSuccess("Account settings saved successfully!");
        clearDirty('account');
      } else {
        setSaveError(result.error || "Failed to save account settings");
      }
    } catch (error) {
      console.error("Save account failed:", error);
      setSaveError("Failed to save account settings");
    } finally {
      setSavingAccount(false);
    }
  };

  // Save profile/bio settings
  const handleSaveProfile = async () => {
    setSavingProfile(true);
    setSaveError(null);
    try {
      const result = await userSettingsAPI.updateProfile({
        bio: profileForm.bio,
        linkedin_url: profileForm.linkedin_url,
        twitter_url: profileForm.twitter_url,
        github_url: profileForm.github_url,
      });
      if (result.success) {
        setSaveSuccess("Profile saved successfully!");
        clearDirty('profile');
      } else {
        setSaveError(result.error || "Failed to save profile");
      }
    } catch (error) {
      console.error("Save profile failed:", error);
      setSaveError("Failed to save profile");
    } finally {
      setSavingProfile(false);
    }
  };

  // Save notification settings
  const handleSaveNotifications = async () => {
    setSavingNotifications(true);
    setSaveError(null);
    try {
      const result = await userSettingsAPI.updateNotifications(notifications);
      if (result.success) {
        setSaveSuccess("Notification settings saved!");
        clearDirty('notifications');
      } else {
        setSaveError(result.error || "Failed to save notifications");
      }
    } catch (error) {
      console.error("Save notifications failed:", error);
      setSaveError("Failed to save notification settings");
    } finally {
      setSavingNotifications(false);
    }
  };

  // Save scan preferences
  const handleSavePreferences = async () => {
    setSavingPreferences(true);
    setSaveError(null);
    try {
      const result = await userSettingsAPI.updatePreferences({
        ...preferences,
        default_scan_type: preferencesForm.default_scan_type,
        report_format: preferencesForm.report_format,
        timezone: preferencesForm.timezone,
        language: preferencesForm.language,
        date_format: preferencesForm.date_format,
        data_retention_days: preferencesForm.data_retention_days,
        auto_delete_old_scans: preferencesForm.auto_delete_old_scans,
        share_analytics: preferencesForm.share_analytics,
      });
      if (result.success) {
        setSaveSuccess("Preferences saved successfully!");
        clearDirty('preferences');
      } else {
        setSaveError(result.error || "Failed to save preferences");
      }
    } catch (error) {
      console.error("Save preferences failed:", error);
      setSaveError("Failed to save preferences");
    } finally {
      setSavingPreferences(false);
    }
  };

  // Change password
  const handleChangePassword = async () => {
    if (passwordForm.new_password !== passwordForm.confirm_password) {
      setSaveError("New passwords do not match");
      return;
    }
    if (passwordForm.new_password.length < 8) {
      setSaveError("Password must be at least 8 characters");
      return;
    }
    
    setSavingPassword(true);
    setSaveError(null);
    try {
      const result = await authAPI.changePassword(
        passwordForm.current_password,
        passwordForm.new_password
      );
      if (result.success) {
        setSaveSuccess("Password updated successfully!");
        setPasswordForm({ current_password: "", new_password: "", confirm_password: "" });
        clearDirty('password');
      } else {
        setSaveError(result.error || "Failed to change password");
      }
    } catch (error) {
      console.error("Change password failed:", error);
      setSaveError("Failed to change password");
    } finally {
      setSavingPassword(false);
    }
  };

  // Export all user data (GDPR)
  const handleExportData = async () => {
    setExportingData(true);
    try {
      // Backend returns a ZIP blob directly
      const blob = await userSettingsAPI.exportData();
      if (blob && blob.size > 0) {
        // Download the ZIP file
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `jarwis_data_export_${new Date().toISOString().split('T')[0]}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
        setSaveSuccess("Data exported successfully!");
      } else {
        setSaveError("Failed to export data - empty response");
      }
    } catch (error) {
      console.error("Export data failed:", error);
      setSaveError("Failed to export data");
    } finally {
      setExportingData(false);
    }
  };

  // Delete all user data (keeps account)
  const handleDeleteAllData = async () => {
    if (deleteConfirmText !== "DELETE ALL DATA") {
      setSaveError("Please type 'DELETE ALL DATA' to confirm");
      return;
    }
    
    setDeletingData(true);
    try {
      const result = await userSettingsAPI.deleteAllData(deleteConfirmPassword);
      if (result.success) {
        setSaveSuccess("All scan data deleted successfully");
        setShowDeleteDataModal(false);
        setDeleteConfirmPassword("");
        setDeleteConfirmText("");
      } else {
        setSaveError(result.error || "Failed to delete data");
      }
    } catch (error) {
      console.error("Delete data failed:", error);
      setSaveError("Failed to delete data");
    } finally {
      setDeletingData(false);
    }
  };

  // Delete account entirely
  const handleDeleteAccount = async () => {
    if (deleteConfirmText !== "DELETE MY ACCOUNT") {
      setSaveError("Please type 'DELETE MY ACCOUNT' to confirm");
      return;
    }
    
    setDeletingData(true);
    try {
      const result = await userSettingsAPI.deleteAccount(deleteConfirmPassword);
      if (result.success) {
        // Log out and redirect to home
        logout();
        navigate("/");
      } else {
        setSaveError(result.error || "Failed to delete account");
      }
    } catch (error) {
      console.error("Delete account failed:", error);
      setSaveError("Failed to delete account");
    } finally {
      setDeletingData(false);
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
  
  // Map section IDs to their dirty form state keys
  const sectionDirtyMap = {
    account: ['account'],
    profile: ['profile'],
    security: ['password'],
    notifications: ['notifications'],
    preferences: ['preferences'],
  };
  
  // Check if a section has unsaved changes
  const isSectionDirty = (sectionId) => {
    const formKeys = sectionDirtyMap[sectionId];
    if (!formKeys) return false;
    return formKeys.some(key => dirtyForms[key]);
  };

  // Settings sections configuration with proper icons
  const settingsSections = [
    { id: "account", icon: "👤", label: "Account", available: true },
    { id: "profile", icon: "🎨", label: "Profile", available: true },
    { id: "security", icon: "🔒", label: "Security", available: true },
    { id: "domains", icon: "🌐", label: "Verified Domains", available: true },
    { id: "notifications", icon: "🔔", label: "Notifications", available: true },
    { id: "data", icon: "📊", label: "Data Controls", available: true },
    { id: "team", icon: "👥", label: "Team Access", available: canAccessTeam, proOnly: true },
    { id: "agents", icon: "🖥️", label: "Network Agents", available: true },
    { id: "integrations", icon: "🔗", label: "Integrations", available: true },
    { id: "billing", icon: "💳", label: "Billing", available: true },
    { id: "preferences", icon: "⚙️", label: "Preferences", available: true },
    { id: "help", icon: "❓", label: "Help & Support", available: true },
  ];

  // Theme classes - ChatGPT-style centered modal
  const themeClasses = {
    overlay: isDarkMode
      ? "fixed inset-0 bg-black/70 backdrop-blur-md z-50 flex items-center justify-center p-2 sm:p-4"
      : "fixed inset-0 bg-black/50 backdrop-blur-md z-50 flex items-center justify-center p-2 sm:p-4",
    modal: isDarkMode
      ? "relative w-full max-w-3xl h-[90vh] sm:h-[85vh] max-h-[700px] bg-gray-900 rounded-xl sm:rounded-2xl shadow-2xl overflow-hidden flex flex-col sm:flex-row animate-in fade-in zoom-in-95 duration-200"
      : "relative w-full max-w-3xl h-[90vh] sm:h-[85vh] max-h-[700px] bg-white rounded-xl sm:rounded-2xl shadow-2xl overflow-hidden flex flex-col sm:flex-row animate-in fade-in zoom-in-95 duration-200",
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
      ? "hidden sm:block w-52 border-r border-gray-700 py-3 flex-shrink-0 overflow-y-auto"
      : "hidden sm:block w-52 border-r border-gray-200 py-3 flex-shrink-0 overflow-y-auto",
    mobileTabs: isDarkMode
      ? "sm:hidden flex items-center gap-2 p-3 border-b border-gray-700 overflow-x-auto scrollbar-hide"
      : "sm:hidden flex items-center gap-2 p-3 border-b border-gray-200 overflow-x-auto scrollbar-hide",
    mobileTab: (active) => isDarkMode
      ? `flex-shrink-0 px-3 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
          active ? "bg-gray-700 text-white" : "text-gray-400 hover:bg-gray-800"
        }`
      : `flex-shrink-0 px-3 py-2 rounded-lg text-sm font-medium transition-all whitespace-nowrap ${
          active ? "bg-gray-200 text-gray-900" : "text-gray-600 hover:bg-gray-100"
        }`,
    sidebarBtn: (active, available) => isDarkMode
      ? `w-full flex items-center gap-3 px-4 py-2.5 text-left transition-all text-sm ${
          !available ? "opacity-50 cursor-not-allowed" :
          active ? "bg-gray-700 text-white" : "text-gray-400 hover:bg-gray-800 hover:text-gray-200"
        }`
      : `w-full flex items-center gap-3 px-4 py-2.5 text-left transition-all text-sm ${
          !available ? "opacity-50 cursor-not-allowed" :
          active ? "bg-gray-100 text-gray-900" : "text-gray-600 hover:bg-gray-50 hover:text-gray-900"
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
            {/* Success/Error feedback */}
            {saveSuccess && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-green-500/20 border-green-500/30 text-green-400" : "bg-green-50 border-green-200 text-green-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✓</span>
                  <p>{saveSuccess}</p>
                </div>
              </div>
            )}
            {saveError && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-red-500/20 border-red-500/30 text-red-400" : "bg-red-50 border-red-200 text-red-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✕</span>
                  <p>{saveError}</p>
                </div>
              </div>
            )}
            
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Account Information</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Full Name</label>
                  <input
                    type="text"
                    value={accountForm.full_name}
                    onChange={(e) => { setAccountForm({...accountForm, full_name: e.target.value}); markDirty('account'); }}
                    className={themeClasses.input}
                    placeholder="Enter your full name"
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>Email Address</label>
                  <input
                    type="email"
                    value={accountForm.email}
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
                    value={accountForm.company}
                    onChange={(e) => { setAccountForm({...accountForm, company: e.target.value}); markDirty('account'); }}
                    className={themeClasses.input}
                    placeholder="Your company name"
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>Job Title</label>
                  <input
                    type="text"
                    value={accountForm.job_title}
                    onChange={(e) => { setAccountForm({...accountForm, job_title: e.target.value}); markDirty('account'); }}
                    className={themeClasses.input}
                    placeholder="e.g., Security Engineer"
                  />
                </div>
              </div>
              <div className="mt-6 flex justify-end">
                <button 
                  onClick={handleSaveAccount}
                  disabled={savingAccount}
                  className={themeClasses.btnPrimary}
                  aria-label="Save account changes"
                >
                  {savingAccount ? "Saving..." : "Save Changes"}
                </button>
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
              <button 
                onClick={() => setShowDeleteAccountModal(true)}
                className={themeClasses.btnDanger}
                aria-label="Delete account permanently"
              >
                Delete Account
              </button>
            </div>
            
            {/* Delete Account Confirmation Modal */}
            {showDeleteAccountModal && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
                <div className={`w-full max-w-md mx-4 p-6 rounded-xl ${isDarkMode ? "bg-gray-800 border border-gray-700" : "bg-white border border-gray-200"} shadow-2xl`}>
                  <h3 className={`text-xl font-bold mb-4 text-red-500`}>Delete Your Account?</h3>
                  <p className={`${themeClasses.textMuted} mb-4`}>
                    This action is <strong>permanent and irreversible</strong>. All your data, scans, and reports will be deleted.
                  </p>
                  <div className="space-y-4">
                    <div>
                      <label className={themeClasses.label}>Type "DELETE MY ACCOUNT" to confirm</label>
                      <input
                        type="text"
                        value={deleteConfirmText}
                        onChange={(e) => setDeleteConfirmText(e.target.value)}
                        className={themeClasses.input}
                        placeholder="DELETE MY ACCOUNT"
                      />
                    </div>
                    <div>
                      <label className={themeClasses.label}>Enter your password</label>
                      <input
                        type="password"
                        value={deleteConfirmPassword}
                        onChange={(e) => setDeleteConfirmPassword(e.target.value)}
                        className={themeClasses.input}
                        placeholder="Your password"
                      />
                    </div>
                  </div>
                  <div className="mt-6 flex gap-3 justify-end">
                    <button
                      onClick={() => {
                        setShowDeleteAccountModal(false);
                        setDeleteConfirmPassword("");
                        setDeleteConfirmText("");
                      }}
                      className={themeClasses.btnSecondary}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleDeleteAccount}
                      disabled={deletingData || deleteConfirmText !== "DELETE MY ACCOUNT"}
                      className={`${themeClasses.btnDanger} disabled:opacity-50 disabled:cursor-not-allowed`}
                    >
                      {deletingData ? "Deleting..." : "Delete Forever"}
                    </button>
                  </div>
                </div>
              </div>
            )}
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
                value={profileForm.bio}
                onChange={(e) => { setProfileForm({...profileForm, bio: e.target.value}); markDirty('profile'); }}
                className={themeClasses.input}
                placeholder="Tell us a bit about yourself..."
              />
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Social Links</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>LinkedIn</label>
                  <input 
                    type="url" 
                    value={profileForm.linkedin_url}
                    onChange={(e) => { setProfileForm({...profileForm, linkedin_url: e.target.value}); markDirty('profile'); }}
                    className={themeClasses.input} 
                    placeholder="https://linkedin.com/in/..." 
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>Twitter / X</label>
                  <input 
                    type="url" 
                    value={profileForm.twitter_url}
                    onChange={(e) => { setProfileForm({...profileForm, twitter_url: e.target.value}); markDirty('profile'); }}
                    className={themeClasses.input} 
                    placeholder="https://twitter.com/..." 
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>GitHub</label>
                  <input 
                    type="url" 
                    value={profileForm.github_url}
                    onChange={(e) => { setProfileForm({...profileForm, github_url: e.target.value}); markDirty('profile'); }}
                    className={themeClasses.input} 
                    placeholder="https://github.com/..." 
                  />
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button 
                  onClick={handleSaveProfile}
                  disabled={savingProfile}
                  className={themeClasses.btnPrimary}
                  aria-label="Save profile changes"
                >
                  {savingProfile ? "Saving..." : "Save Profile"}
                </button>
              </div>
            </div>
          </div>
        );

      case "security":
        return (
          <div className="space-y-6">
            {saveSuccess && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-green-500/20 border-green-500/30 text-green-400" : "bg-green-50 border-green-200 text-green-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✓</span>
                  <p>{saveSuccess}</p>
                </div>
              </div>
            )}
            {saveError && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-red-500/20 border-red-500/30 text-red-400" : "bg-red-50 border-red-200 text-red-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✕</span>
                  <p>{saveError}</p>
                </div>
              </div>
            )}
            
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Password</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Current Password</label>
                  <input 
                    type="password" 
                    value={passwordForm.current_password}
                    onChange={(e) => { setPasswordForm({...passwordForm, current_password: e.target.value}); markDirty('password'); }}
                    className={themeClasses.input} 
                    placeholder="********" 
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>New Password</label>
                  <input 
                    type="password" 
                    value={passwordForm.new_password}
                    onChange={(e) => { setPasswordForm({...passwordForm, new_password: e.target.value}); markDirty('password'); }}
                    className={themeClasses.input} 
                    placeholder="********" 
                  />
                </div>
                <div>
                  <label className={themeClasses.label}>Confirm New Password</label>
                  <input 
                    type="password" 
                    value={passwordForm.confirm_password}
                    onChange={(e) => { setPasswordForm({...passwordForm, confirm_password: e.target.value}); markDirty('password'); }}
                    className={themeClasses.input} 
                    placeholder="********" 
                  />
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button 
                  onClick={handleChangePassword}
                  disabled={savingPassword || !passwordForm.current_password || !passwordForm.new_password}
                  className={`${themeClasses.btnPrimary} disabled:opacity-50 disabled:cursor-not-allowed`}
                  aria-label="Update password"
                >
                  {savingPassword ? "Updating..." : "Update Password"}
                </button>
              </div>
            </div>

            {/* Two-Factor Authentication Component */}
            <TwoFactorSettings isDarkMode={isDarkMode} user={user} />

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Active Sessions</h3>
              <div className="space-y-3">
                {activeSessions.length > 0 ? activeSessions.map((session, idx) => (
                  <div key={idx} className={`flex items-center justify-between p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"}`}>
                    <div className="flex items-center gap-3">
                      <span>💻</span>
                      <div>
                        <p className={isDarkMode ? "text-white font-medium" : "text-gray-900 font-medium"}>
                          {session.is_current ? 'Current Session' : session.user_agent?.substring(0, 30) || 'Unknown Device'}
                        </p>
                        <p className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                          {session.ip_address || 'Unknown IP'}
                        </p>
                      </div>
                    </div>
                    <span className={`px-2 py-1 text-xs font-medium ${session.is_current ? 'bg-green-500/20 text-green-500' : 'bg-blue-500/20 text-blue-500'} rounded-full`}>
                      {session.is_current ? 'Active' : 'Other'}
                    </span>
                  </div>
                )) : (
                  <div className={`flex items-center justify-between p-3 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"}`}>
                    <div className="flex items-center gap-3">
                      <span>💻</span>
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
                )}
              </div>
              <button className={`${themeClasses.btnDanger} mt-4`} onClick={() => authAPI.logoutAll && authAPI.logoutAll()}>Sign Out All Devices</button>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Login History</h3>
              {loadingHistory ? (
                <div className="flex items-center justify-center py-4">
                  <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-500"></div>
                </div>
              ) : (
              <div className="space-y-2">
                {loginHistory.length > 0 ? loginHistory.map((login, i) => (
                  <div key={i} className={`flex items-center justify-between py-2 ${i > 0 ? `border-t ${isDarkMode ? "border-gray-700" : "border-gray-200"}` : ""}`}>
                    <div>
                      <p className={themeClasses.text}>{login.device || 'Unknown Device'}</p>
                      <p className={`text-sm ${themeClasses.textMuted}`}>{login.ip_address || login.location || 'Unknown'}</p>
                    </div>
                    <div className="text-right">
                      <span className={`text-sm ${themeClasses.textMuted}`}>
                        {login.timestamp ? new Date(login.timestamp).toLocaleString() : login.date}
                      </span>
                      {login.success === false && (
                        <p className="text-xs text-red-500">Failed</p>
                      )}
                    </div>
                  </div>
                )) : (
                  <p className={`text-sm ${themeClasses.textMuted}`}>No login history available yet.</p>
                )}
              </div>
              )}
            </div>
          </div>
        );

      case "domains":
        return <VerifiedDomainsSettings isDarkMode={isDarkMode} />;

      case "notifications":
        return (
          <div className="space-y-6">
            {saveSuccess && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-green-500/20 border-green-500/30 text-green-400" : "bg-green-50 border-green-200 text-green-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✓</span>
                  <p>{saveSuccess}</p>
                </div>
              </div>
            )}
            
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
                      onClick={() => { setNotifications({...notifications, [item.key]: !notifications[item.key]}); markDirty('notifications'); }}
                      className={themeClasses.toggle(notifications[item.key])}
                      aria-label={`Toggle ${item.label}`}
                      aria-pressed={notifications[item.key]}
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
                  onClick={() => { setNotifications({...notifications, push: !notifications.push}); markDirty('notifications'); }}
                  className={themeClasses.toggle(notifications.push)}
                  aria-label="Toggle browser notifications"
                  aria-pressed={notifications.push}
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
            
            {/* Save Notifications Button */}
            <div className="flex justify-end">
              <button
                onClick={handleSaveNotifications}
                disabled={savingNotifications}
                className={themeClasses.btnPrimary}
                aria-label="Save notification settings"
              >
                {savingNotifications ? "Saving..." : "Save Notification Settings"}
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

      case "agents":
        return (
          <div className="space-y-6">
            <AgentManagement />
          </div>
        );

      case "integrations":
        return (
          <div className="space-y-6">
            {/* Coming Soon Notice */}
            <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-blue-500/10 border-blue-500/30 text-blue-400" : "bg-blue-50 border-blue-200 text-blue-700"}`}>
              <div className="flex items-center gap-3">
                <span>🚧</span>
                <div>
                  <p className="font-medium">Integrations Coming Soon</p>
                  <p className={`text-sm ${isDarkMode ? "text-blue-400/80" : "text-blue-600"}`}>
                    We're working on bringing these integrations to Jarwis. Stay tuned!
                  </p>
                </div>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Connected Services</h3>
              <div className="space-y-4">
                {[
                  { name: "GitHub", icon: "🐙", status: false, desc: "Import repositories for scanning", comingSoon: true },
                  { name: "GitLab", icon: "🦊", status: false, desc: "Connect GitLab projects", comingSoon: true },
                  { name: "Jira", icon: "📋", status: false, desc: "Create tickets from vulnerabilities", comingSoon: true },
                  { name: "Slack", icon: "💬", status: false, desc: "Receive notifications in Slack", comingSoon: true },
                  { name: "Microsoft Teams", icon: "👥", status: false, desc: "Team notifications", comingSoon: true },
                  { name: "AWS", icon: "☁️", status: false, desc: "Scan AWS infrastructure", comingSoon: true },
                ].map((service) => (
                  <div key={service.name} className={`flex items-center justify-between p-4 rounded-lg ${isDarkMode ? "bg-gray-700/50" : "bg-white border border-gray-200"} ${service.comingSoon ? "opacity-75" : ""}`}>
                    <div className="flex items-center gap-4">
                      <span className="text-3xl">{service.icon}</span>
                      <div>
                        <div className="flex items-center gap-2">
                          <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>{service.name}</p>
                          {service.comingSoon && (
                            <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${isDarkMode ? "bg-amber-500/20 text-amber-400" : "bg-amber-100 text-amber-700"}`}>
                              Coming Soon
                            </span>
                          )}
                        </div>
                        <p className={`text-sm ${themeClasses.textMuted}`}>{service.desc}</p>
                      </div>
                    </div>
                    <button 
                      className={`${service.status ? themeClasses.btnDanger : themeClasses.btnSecondary} ${service.comingSoon ? "cursor-not-allowed opacity-50" : ""}`}
                      disabled={service.comingSoon}
                      title={service.comingSoon ? "This integration is coming soon" : ""}
                    >
                      {service.status ? "Disconnect" : "Connect"}
                    </button>
                  </div>
                ))}
              </div>
            </div>

            <div className={themeClasses.card}>
              <div className="flex items-center gap-2 mb-2">
                <h3 className={themeClasses.cardTitle}>Webhooks</h3>
                <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${isDarkMode ? "bg-amber-500/20 text-amber-400" : "bg-amber-100 text-amber-700"}`}>
                  Coming Soon
                </span>
              </div>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Send scan results to your own endpoints
              </p>
              <div className="space-y-3 opacity-50">
                <input 
                  type="url" 
                  className={themeClasses.input} 
                  placeholder="https://your-webhook-endpoint.com/jarwis" 
                  disabled
                />
                <div className="flex gap-3">
                  <button className={themeClasses.btnPrimary} disabled>Add Webhook</button>
                  <button className={themeClasses.btnSecondary} disabled>Test</button>
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
            {saveSuccess && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-green-500/20 border-green-500/30 text-green-400" : "bg-green-50 border-green-200 text-green-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✓</span>
                  <p>{saveSuccess}</p>
                </div>
              </div>
            )}
            
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
                      onClick={() => { setPreferences({...preferences, [item.key]: !preferences[item.key]}); markDirty('preferences'); }}
                      className={themeClasses.toggle(preferences[item.key])}
                      aria-label={`Toggle ${item.label}`}
                      aria-pressed={preferences[item.key]}
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
                  <select 
                    value={preferencesForm.default_scan_type}
                    onChange={(e) => { setPreferencesForm({...preferencesForm, default_scan_type: e.target.value}); markDirty('preferences'); }}
                    className={themeClasses.input}
                    aria-label="Default scan type"
                  >
                    <option value="full">Full OWASP Top 10 Scan</option>
                    <option value="quick">Quick Scan</option>
                    <option value="api">API Security Scan</option>
                    <option value="authenticated">Authenticated Scan</option>
                  </select>
                </div>
                <div>
                  <label className={themeClasses.label}>Report Format</label>
                  <select 
                    value={preferencesForm.report_format}
                    onChange={(e) => { setPreferencesForm({...preferencesForm, report_format: e.target.value}); markDirty('preferences'); }}
                    className={themeClasses.input}
                    aria-label="Report format"
                  >
                    <option value="html_json">HTML + JSON</option>
                    <option value="pdf">PDF</option>
                    <option value="sarif">SARIF</option>
                    <option value="all">All Formats</option>
                  </select>
                </div>
                <div>
                  <label className={themeClasses.label}>Timezone</label>
                  <select 
                    value={preferencesForm.timezone}
                    onChange={(e) => { setPreferencesForm({...preferencesForm, timezone: e.target.value}); markDirty('preferences'); }}
                    className={themeClasses.input}
                    aria-label="Timezone"
                  >
                    <option value="Asia/Kolkata">Asia/Kolkata (IST)</option>
                    <option value="UTC">UTC</option>
                    <option value="America/New_York">America/New_York (EST)</option>
                    <option value="Europe/London">Europe/London (GMT)</option>
                    <option value="America/Los_Angeles">America/Los_Angeles (PST)</option>
                    <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
                    <option value="Australia/Sydney">Australia/Sydney (AEST)</option>
                  </select>
                </div>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Language & Region</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Language</label>
                  <select 
                    value={preferencesForm.language}
                    onChange={(e) => { setPreferencesForm({...preferencesForm, language: e.target.value}); markDirty('preferences'); }}
                    className={themeClasses.input}
                    aria-label="Language"
                  >
                    <option value="en">English</option>
                    <option value="hi">Hindi</option>
                    <option value="es">Spanish</option>
                    <option value="fr">French</option>
                    <option value="de">German</option>
                    <option value="ja">Japanese</option>
                    <option value="zh">Chinese</option>
                  </select>
                </div>
                <div>
                  <label className={themeClasses.label}>Date Format</label>
                  <select 
                    value={preferencesForm.date_format}
                    onChange={(e) => { setPreferencesForm({...preferencesForm, date_format: e.target.value}); markDirty('preferences'); }}
                    className={themeClasses.input}
                    aria-label="Date format"
                  >
                    <option value="DD/MM/YYYY">DD/MM/YYYY</option>
                    <option value="MM/DD/YYYY">MM/DD/YYYY</option>
                    <option value="YYYY-MM-DD">YYYY-MM-DD</option>
                  </select>
                </div>
              </div>
            </div>
            
            {/* Save Preferences Button */}
            <div className="flex justify-end">
              <button
                onClick={handleSavePreferences}
                disabled={savingPreferences}
                className={themeClasses.btnPrimary}
                aria-label="Save all preferences"
              >
                {savingPreferences ? "Saving..." : "Save All Preferences"}
              </button>
            </div>
          </div>
        );

      case "data":
        return (
          <div className="space-y-6">
            {saveSuccess && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-green-500/20 border-green-500/30 text-green-400" : "bg-green-50 border-green-200 text-green-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✓</span>
                  <p>{saveSuccess}</p>
                </div>
              </div>
            )}
            {saveError && (
              <div className={`p-4 rounded-lg border ${isDarkMode ? "bg-red-500/20 border-red-500/30 text-red-400" : "bg-red-50 border-red-200 text-red-700"}`}>
                <div className="flex items-center gap-3">
                  <span>✕</span>
                  <p>{saveError}</p>
                </div>
              </div>
            )}
            
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Data Export (GDPR)</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Download all your data including scans, reports, and settings. This may take a few moments.
              </p>
              <div className="flex gap-3">
                <button 
                  onClick={handleExportData}
                  disabled={exportingData}
                  className={themeClasses.btnPrimary}
                >
                  {exportingData ? "Exporting..." : "Export All Data"}
                </button>
              </div>
            </div>

            {/* Data Retention */}
            <div className={themeClasses.card}>
              <h3 className={themeClasses.cardTitle}>Data Retention</h3>
              <div className="space-y-4">
                <div>
                  <label className={themeClasses.label}>Keep scan history for</label>
                  <select 
                    value={preferencesForm.data_retention_days}
                    onChange={(e) => { setPreferencesForm({...preferencesForm, data_retention_days: parseInt(e.target.value)}); markDirty('preferences'); }}
                    className={themeClasses.input}
                    aria-label="Data retention period"
                  >
                    <option value={30}>30 days</option>
                    <option value={90}>90 days</option>
                    <option value={365}>1 year</option>
                    <option value={-1}>Forever</option>
                  </select>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <p className={themeClasses.text}>Auto-delete old scans</p>
                    <p className={`text-sm ${themeClasses.textMuted}`}>Automatically remove scans older than retention period</p>
                  </div>
                  <button
                    onClick={() => { setPreferencesForm({...preferencesForm, auto_delete_old_scans: !preferencesForm.auto_delete_old_scans}); markDirty('preferences'); }}
                    className={themeClasses.toggle(preferencesForm.auto_delete_old_scans)}
                    aria-label="Toggle auto-delete old scans"
                    aria-pressed={preferencesForm.auto_delete_old_scans}
                  >
                    <span className={themeClasses.toggleKnob(preferencesForm.auto_delete_old_scans)} />
                  </button>
                </div>
              </div>
              <div className="mt-4 flex justify-end">
                <button
                  onClick={handleSavePreferences}
                  disabled={savingPreferences}
                  className={themeClasses.btnPrimary}
                >
                  {savingPreferences ? "Saving..." : "Save Retention Settings"}
                </button>
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
                  <button
                    onClick={() => { setPreferencesForm({...preferencesForm, share_analytics: !preferencesForm.share_analytics}); markDirty('preferences'); }}
                    className={themeClasses.toggle(preferencesForm.share_analytics)}
                    aria-label="Toggle analytics sharing"
                    aria-pressed={preferencesForm.share_analytics}
                  >
                    <span className={themeClasses.toggleKnob(preferencesForm.share_analytics)} />
                  </button>
                </div>
              </div>
            </div>

            <div className={themeClasses.card}>
              <h3 className={`${themeClasses.cardTitle} text-red-500`}>Delete All Scan Data</h3>
              <p className={`${themeClasses.textMuted} mb-4`}>
                Permanently delete all your scans, reports, and history. Your account will remain active.
              </p>
              <button 
                onClick={() => setShowDeleteDataModal(true)}
                className={themeClasses.btnDanger}
              >
                Delete All My Data
              </button>
            </div>
            
            {/* Delete Data Confirmation Modal */}
            {showDeleteDataModal && (
              <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
                <div className={`w-full max-w-md mx-4 p-6 rounded-xl ${isDarkMode ? "bg-gray-800 border border-gray-700" : "bg-white border border-gray-200"} shadow-2xl`}>
                  <h3 className={`text-xl font-bold mb-4 text-red-500`}>Delete All Scan Data?</h3>
                  <p className={`${themeClasses.textMuted} mb-4`}>
                    This will permanently delete all your scans, reports, and vulnerability findings. Your account will remain active.
                  </p>
                  <div className="space-y-4">
                    <div>
                      <label className={themeClasses.label}>Type "DELETE ALL DATA" to confirm</label>
                      <input
                        type="text"
                        value={deleteConfirmText}
                        onChange={(e) => setDeleteConfirmText(e.target.value)}
                        className={themeClasses.input}
                        placeholder="DELETE ALL DATA"
                      />
                    </div>
                    <div>
                      <label className={themeClasses.label}>Enter your password</label>
                      <input
                        type="password"
                        value={deleteConfirmPassword}
                        onChange={(e) => setDeleteConfirmPassword(e.target.value)}
                        className={themeClasses.input}
                        placeholder="Your password"
                      />
                    </div>
                  </div>
                  <div className="mt-6 flex gap-3 justify-end">
                    <button
                      onClick={() => {
                        setShowDeleteDataModal(false);
                        setDeleteConfirmPassword("");
                        setDeleteConfirmText("");
                      }}
                      className={themeClasses.btnSecondary}
                    >
                      Cancel
                    </button>
                    <button
                      onClick={handleDeleteAllData}
                      disabled={deletingData || deleteConfirmText !== "DELETE ALL DATA"}
                      className={`${themeClasses.btnDanger} disabled:opacity-50 disabled:cursor-not-allowed`}
                    >
                      {deletingData ? "Deleting..." : "Delete All Data"}
                    </button>
                  </div>
                </div>
              </div>
            )}
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

  // Inline page mode - renders directly without modal overlay
  if (isInlinePage) {
    return (
      <div className={`w-full ${isDarkMode ? 'bg-gray-900' : 'bg-gray-50'} rounded-xl overflow-hidden`}>
        {/* Page Header */}
        <div className={`px-6 py-4 border-b ${isDarkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'}`}>
          <h1 className={`text-2xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
            Account Settings
          </h1>
          <p className={`text-sm mt-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
            Manage your account settings and preferences
          </p>
        </div>

        <div className="flex flex-col sm:flex-row min-h-[600px]">
          {/* Left Sidebar */}
          <div className={`w-full sm:w-56 border-b sm:border-b-0 sm:border-r ${isDarkMode ? 'border-gray-700 bg-gray-800' : 'border-gray-200 bg-white'} py-3 flex-shrink-0`}>
            {/* Mobile Tabs - horizontal scroll */}
            <div className={`sm:hidden flex items-center gap-2 px-3 overflow-x-auto scrollbar-hide`}>
              {settingsSections.filter(s => s.available).map((section) => (
                <button
                  key={section.id}
                  onClick={() => setActiveSection(section.id)}
                  className={`${themeClasses.mobileTab(activeSection === section.id)} relative`}
                >
                  <span className="mr-1.5">{section.icon}</span>
                  {section.label}
                  {isSectionDirty(section.id) && (
                    <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-amber-500" title="Unsaved changes" />
                  )}
                </button>
              ))}
            </div>

            {/* Desktop Navigation Items */}
            <div className="hidden sm:block space-y-0.5">
              {settingsSections.map((section) => (
                <button
                  key={section.id}
                  onClick={() => section.available && setActiveSection(section.id)}
                  className={themeClasses.sidebarBtn(activeSection === section.id, section.available)}
                  disabled={!section.available}
                >
                  <span className="text-base opacity-70">{section.icon}</span>
                  <span className="flex-1">{section.label}</span>
                  {isSectionDirty(section.id) && (
                    <span className="w-2 h-2 rounded-full bg-amber-500" title="Unsaved changes" />
                  )}
                  {section.proOnly && !section.available && (
                    <span className={themeClasses.badge}>PRO</span>
                  )}
                </button>
              ))}
            </div>
          </div>

          {/* Right Content Area */}
          <div className="flex-1 flex flex-col overflow-hidden min-w-0">
            {/* Content Header with section title - desktop only */}
            <div className={`hidden sm:block px-6 py-4 border-b flex-shrink-0 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
              <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                {settingsSections.find(s => s.id === activeSection)?.label || 'Settings'}
              </h3>
            </div>
            
            {/* Scrollable Content */}
            <div className={`flex-1 overflow-y-auto p-4 sm:p-6 ${isDarkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
              {renderContent()}
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className={themeClasses.overlay} onClick={onClose}>
      {/* Modal - ChatGPT style centered */}
      <div 
        ref={panelRef}
        className={themeClasses.modal}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Mobile Header with close button and title */}
        <div className={`sm:hidden flex items-center gap-2 px-4 py-3 border-b flex-shrink-0 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
          <button 
            onClick={onClose}
            className={`p-1.5 rounded-lg ${isDarkMode ? 'hover:bg-gray-700 text-gray-400 hover:text-white' : 'hover:bg-gray-100 text-gray-500 hover:text-gray-900'} transition-colors`}
          >
            <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
          <h2 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Settings</h2>
        </div>

        {/* Mobile Tabs - horizontal scroll */}
        <div className={themeClasses.mobileTabs}>
          {settingsSections.filter(s => s.available).map((section) => (
            <button
              key={section.id}
              onClick={() => setActiveSection(section.id)}
              className={`${themeClasses.mobileTab(activeSection === section.id)} relative`}
            >
              <span className="mr-1.5">{section.icon}</span>
              {section.label}
              {isSectionDirty(section.id) && (
                <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-amber-500" title="Unsaved changes" />
              )}
            </button>
          ))}
        </div>

        {/* Desktop Left Sidebar */}
        <div className={themeClasses.sidebar}>
          {/* Close button and title */}
          <div className={`flex items-center gap-2 px-4 pb-3 mb-2 border-b ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
            <button 
              onClick={onClose}
              className={`p-1.5 rounded-lg ${isDarkMode ? 'hover:bg-gray-700 text-gray-400 hover:text-white' : 'hover:bg-gray-100 text-gray-500 hover:text-gray-900'} transition-colors`}
            >
              <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
            <h2 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>Settings</h2>
          </div>

          {/* Navigation Items */}
          <div className="space-y-0.5">
            {settingsSections.map((section) => (
              <button
                key={section.id}
                onClick={() => section.available && setActiveSection(section.id)}
                className={themeClasses.sidebarBtn(activeSection === section.id, section.available)}
                disabled={!section.available}
              >
                <span className="text-base opacity-70">{section.icon}</span>
                <span className="flex-1">{section.label}</span>
                {isSectionDirty(section.id) && (
                  <span className="w-2 h-2 rounded-full bg-amber-500" title="Unsaved changes" />
                )}
                {section.proOnly && !section.available && (
                  <span className={themeClasses.badge}>PRO</span>
                )}
              </button>
            ))}
          </div>
        </div>

        {/* Right Content Area */}
        <div className="flex-1 flex flex-col overflow-hidden min-w-0">
          {/* Content Header with section title - desktop only */}
          <div className={`hidden sm:block px-6 py-4 border-b flex-shrink-0 ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
            <h3 className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
              {settingsSections.find(s => s.id === activeSection)?.label || 'Settings'}
            </h3>
          </div>
          
          {/* Scrollable Content */}
          <div className={`flex-1 overflow-y-auto p-4 sm:p-6 ${isDarkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
            {renderContent()}
          </div>
        </div>
      </div>
    </div>
  );
};

export default SettingsPanel;
