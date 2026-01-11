// MobileScanForm - Dedicated mobile scan configuration form
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Smartphone } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { mobileScanAPI } from "../../services/api";
import { getInputClass, getLabelClass, getCancelButtonClass } from "./scanFormStyles";

const MobileScanForm = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { canPerformAction, checkActionAllowed, refreshSubscription } = useSubscription();

  const [mobileForm, setMobileForm] = useState({
    appFile: null,
    appName: "",
    platform: "android",
    sslPinningBypass: true,
    fridaScripts: true,
    interceptTraffic: true,
    notes: "",
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const inputClass = getInputClass(isDarkMode);
  const labelClass = getLabelClass(isDarkMode);
  const cancelButtonClass = getCancelButtonClass(isDarkMode);

  const handleInputChange = (e) => {
    const { name, value, type, checked, files } = e.target;
    if (type === "file") {
      setMobileForm((prev) => ({ ...prev, [name]: files[0] }));
    } else if (type === "checkbox") {
      setMobileForm((prev) => ({ ...prev, [name]: checked }));
    } else {
      setMobileForm((prev) => ({ ...prev, [name]: value }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      // Check subscription for mobile pentesting feature
      const canUseMobile = canPerformAction("useMobileAppTesting");
      if (!canUseMobile) {
        const serverCheck = await checkActionAllowed("mobile_pentest");
        if (!serverCheck.allowed) {
          throw new Error(serverCheck.message || "Mobile app testing requires a Professional or Enterprise plan.");
        }
      }
      
      if (!mobileForm.appFile) {
        throw new Error("Please select an APK or IPA file");
      }

      const config = {
        app_name: mobileForm.appName || mobileForm.appFile.name,
        platform: mobileForm.platform,
        ssl_pinning_bypass: mobileForm.sslPinningBypass,
        frida_scripts: mobileForm.fridaScripts,
        intercept_traffic: mobileForm.interceptTraffic,
      };

      const response = await mobileScanAPI.startScan(mobileForm.appFile, config);

      if (response.scan_id) {
        refreshSubscription();
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "mobile" },
        });
      } else {
        throw new Error(response.error || "Failed to start mobile scan");
      }
    } catch (err) {
      console.error("Start mobile scan error:", err);
      setError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-4xl space-y-6">
      {error && (
        <div className="p-4 mb-4 bg-red-500/20 border border-red-500/50 rounded-xl text-red-400">
          {error}
        </div>
      )}

      <div className="space-y-2">
        <label className={labelClass}>App File (APK/IPA) *</label>
        <input
          type="file"
          name="appFile"
          accept=".apk,.ipa"
          onChange={handleInputChange}
          required
          className={inputClass}
        />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="space-y-2">
          <label className={labelClass}>App Name</label>
          <input
            name="appName"
            type="text"
            placeholder="My Mobile App"
            value={mobileForm.appName}
            onChange={handleInputChange}
            className={inputClass}
          />
        </div>
        <div className="space-y-2">
          <label className={labelClass}>Platform</label>
          <select
            name="platform"
            value={mobileForm.platform}
            onChange={handleInputChange}
            className={inputClass}
          >
            <option value="android">Android (APK)</option>
            <option value="ios">iOS (IPA)</option>
          </select>
        </div>
      </div>

      <div className="space-y-4">
        <label className={labelClass}>Testing Options</label>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[
            { name: "sslPinningBypass", label: "SSL Pinning Bypass", desc: "Use Frida to bypass" },
            { name: "fridaScripts", label: "Frida Scripts", desc: "Runtime analysis" },
            { name: "interceptTraffic", label: "Traffic Interception", desc: "MITM proxy capture" },
          ].map((opt) => (
            <label
              key={opt.name}
              className={`flex items-start gap-3 p-4 rounded-xl cursor-pointer ${
                isDarkMode
                  ? "bg-slate-700/50 border border-slate-600/50 hover:border-purple-500/50"
                  : "bg-gray-50 border border-gray-200 hover:border-purple-300"
              }`}
            >
              <input
                type="checkbox"
                name={opt.name}
                checked={mobileForm[opt.name]}
                onChange={handleInputChange}
                className="mt-1"
              />
              <div>
                <div className={isDarkMode ? "text-white font-medium" : "text-gray-900 font-medium"}>
                  {opt.label}
                </div>
                <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                  {opt.desc}
                </div>
              </div>
            </label>
          ))}
        </div>
      </div>

      <div className="flex gap-4 pt-4">
        <button
          type="submit"
          disabled={isSubmitting || !mobileForm.appFile}
          className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-purple-500 text-white rounded-xl hover:from-purple-500 hover:to-purple-400 disabled:opacity-50 transition-all duration-300 font-semibold"
        >
          {isSubmitting ? "Starting..." : <><Smartphone className="w-4 h-4" /> Start Mobile Scan</>}
        </button>
        <button
          type="button"
          onClick={() => navigate("/dashboard")}
          className={cancelButtonClass}
        >
          Cancel
        </button>
      </div>
    </form>
  );
};

export default MobileScanForm;
