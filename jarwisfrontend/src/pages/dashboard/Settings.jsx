// src/pages/dashboard/Settings.jsx - Account Settings Page
import { useState, useEffect } from "react";
import { useLocation } from "react-router-dom";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import SettingsPanel from "../../components/settings/SettingsPanel";

const Settings = () => {
  const location = useLocation();
  const { isDarkMode } = useTheme();
  const [activeTab, setActiveTab] = useState("account");
  const [showVerificationBanner, setShowVerificationBanner] = useState(false);

  // Check if there's a specific tab requested via state, URL params, or sessionStorage
  useEffect(() => {
    // Check URL params for verification_required reason
    const params = new URLSearchParams(location.search);
    const reason = params.get("reason");
    if (reason === "verification_required") {
      setShowVerificationBanner(true);
    }
    
    // Priority: location state > sessionStorage > URL params for tab
    if (location.state?.settingsTab) {
      setActiveTab(location.state.settingsTab);
    } else if (location.state?.requireVerification) {
      // Redirected from ScanPageRoute
      setActiveTab("domains");
      setShowVerificationBanner(true);
    } else {
      // Check sessionStorage (set by NetworkScanConfig "Setup Agent" button)
      const storedTab = sessionStorage.getItem("settingsTab");
      if (storedTab) {
        setActiveTab(storedTab);
        sessionStorage.removeItem("settingsTab"); // Clear after reading
      } else {
        // Check URL params as fallback
        const tabParam = params.get("tab");
        if (tabParam) {
          setActiveTab(tabParam);
        }
      }
    }
  }, [location.state, location.search]);

  return (
    <MiftyJarwisLayout>
      <div className="p-6">
        {/* Verification Required Banner */}
        {showVerificationBanner && (
          <div className={`mb-6 p-4 rounded-xl border ${
            isDarkMode 
              ? "bg-amber-900/30 border-amber-700/50 text-amber-300" 
              : "bg-amber-50 border-amber-200 text-amber-800"
          }`}>
            <div className="flex gap-3">
              <span className="text-2xl">🔐</span>
              <div>
                <h3 className={`font-semibold text-base ${isDarkMode ? "text-amber-200" : "text-amber-900"}`}>
                  Domain Verification Required
                </h3>
                <p className="text-sm mt-1">
                  Your account uses a personal email address. To start security scans, you must first verify ownership of at least one domain by adding a DNS TXT record.
                </p>
                <button
                  onClick={() => setShowVerificationBanner(false)}
                  className={`mt-2 text-xs font-medium underline ${isDarkMode ? "text-amber-400" : "text-amber-600"}`}
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        )}
        
        {/* Render SettingsPanel inline (always open) */}
        <SettingsPanel 
          isOpen={true} 
          onClose={() => {}} 
          isDarkMode={isDarkMode}
          initialTab={activeTab}
          isInlinePage={true}
        />
      </div>
    </MiftyJarwisLayout>
  );
};

export default Settings;
