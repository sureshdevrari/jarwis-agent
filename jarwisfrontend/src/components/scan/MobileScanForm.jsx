// MobileScanForm - Dedicated mobile scan configuration form
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Smartphone, Lock, Eye, EyeOff, User, Phone, ChevronDown, ChevronUp, Shield, Key, Mail, AlertTriangle, Upload, CheckCircle, XCircle, Loader2 } from "lucide-react";
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
    // Authentication fields for dynamic testing
    authEnabled: false,
    authType: "email_password", // email_password, phone_otp, social, manual
    username: "",
    password: "",
    phone: "",
    // 2FA fields
    twoFactorEnabled: false,
    twoFactorType: "sms", // sms, email, authenticator
  });

  // Upload state for two-step flow
  const [uploadState, setUploadState] = useState({
    status: 'idle', // idle, uploading, success, error
    progress: 0,
    fileId: null,
    appInfo: null,
    deviceStatus: null,
    installationStatus: null,
    message: null,
    error: null,
  });

  const [showPassword, setShowPassword] = useState(false);
  const [showAuthSection, setShowAuthSection] = useState(false);
  const [show2FAWarning, setShow2FAWarning] = useState(false);

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const inputClass = getInputClass(isDarkMode);
  const labelClass = getLabelClass(isDarkMode);
  const cancelButtonClass = getCancelButtonClass(isDarkMode);

  const handleInputChange = (e) => {
    const { name, value, type, checked, files } = e.target;
    if (type === "file") {
      setMobileForm((prev) => ({ ...prev, [name]: files[0] }));
      // Reset upload state when new file is selected
      setUploadState({ status: 'idle', progress: 0, fileId: null, appInfo: null, error: null });
    } else if (type === "checkbox") {
      setMobileForm((prev) => ({ ...prev, [name]: checked }));
    } else {
      setMobileForm((prev) => ({ ...prev, [name]: value }));
    }
  };

  // Handle file upload (step 1 of two-step flow)
  const handleUpload = async () => {
    if (!mobileForm.appFile) return;
    
    setUploadState({ status: 'uploading', progress: 0, fileId: null, appInfo: null, deviceStatus: null, installationStatus: null, error: null });
    
    try {
      const result = await mobileScanAPI.uploadApp(
        mobileForm.appFile,
        mobileForm.platform,
        (percent, loaded, total) => {
          setUploadState(prev => ({ ...prev, progress: percent }));
        }
      );
      
      setUploadState({
        status: 'success',
        progress: 100,
        fileId: result.file_id,
        appInfo: result.app_info,
        deviceStatus: result.device_status,
        installationStatus: result.installation_status,
        message: result.message,
        error: null,
      });
      
      // Auto-fill app name if detected
      if (result.app_info?.package_name && !mobileForm.appName) {
        setMobileForm(prev => ({ ...prev, appName: result.app_info.package_name }));
      }
    } catch (err) {
      console.error("Upload error:", err);
      setUploadState({
        status: 'error',
        progress: 0,
        fileId: null,
        appInfo: null,
        deviceStatus: null,
        installationStatus: null,
        error: err.response?.data?.detail || err.message || 'Upload failed',
      });
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
      
      // Must have either uploaded file or file selected
      if (!uploadState.fileId && !mobileForm.appFile) {
        throw new Error("Please select and upload an APK or IPA file");
      }

      const config = {
        app_name: mobileForm.appName || mobileForm.appFile?.name,
        platform: mobileForm.platform,
        ssl_pinning_bypass: mobileForm.sslPinningBypass,
        frida_scripts: mobileForm.fridaScripts,
        intercept_traffic: mobileForm.interceptTraffic,
        // Authentication config for dynamic testing
        auth_enabled: mobileForm.authEnabled,
        auth_type: mobileForm.authType,
        username: mobileForm.username,
        password: mobileForm.password,
        phone: mobileForm.phone,
        // 2FA config
        two_factor_enabled: mobileForm.twoFactorEnabled,
        two_factor_type: mobileForm.twoFactorType,
      };

      let response;
      if (uploadState.fileId) {
        // Use the two-step flow with file_id
        response = await mobileScanAPI.startScanWithFileId(uploadState.fileId, config);
      } else {
        // Fallback to direct upload (shouldn't happen with new UI)
        response = await mobileScanAPI.startScan(mobileForm.appFile, config);
      }

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

  // Format file size for display
  const formatFileSize = (bytes) => {
    if (!bytes) return '';
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-4xl space-y-6">
      {error && (
        <div className="p-4 mb-4 bg-red-500/20 border border-red-500/50 rounded-xl text-red-400">
          {error}
        </div>
      )}

      {/* File Selection and Upload Section */}
      <div className="space-y-4">
        <label className={labelClass}>App File (APK/XAPK/IPA) *</label>
        
        <div className="flex gap-4 items-start">
          <div className="flex-1">
            <input
              type="file"
              name="appFile"
              accept=".apk,.xapk,.ipa"
              onChange={handleInputChange}
              className={inputClass}
              disabled={uploadState.status === 'uploading'}
            />
            {mobileForm.appFile && (
              <p className={`mt-1 text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
                {mobileForm.appFile.name} ({formatFileSize(mobileForm.appFile.size)})
              </p>
            )}
          </div>
          
          {/* Upload Button */}
          {mobileForm.appFile && uploadState.status !== 'success' && (
            <button
              type="button"
              onClick={handleUpload}
              disabled={uploadState.status === 'uploading'}
              className={`flex items-center gap-2 px-5 py-2.5 rounded-xl font-semibold transition-all duration-300 ${
                uploadState.status === 'uploading'
                  ? 'bg-gray-500 cursor-wait'
                  : 'bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400'
              } text-white`}
            >
              {uploadState.status === 'uploading' ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Uploading... {uploadState.progress}%
                </>
              ) : (
                <>
                  <Upload className="w-4 h-4" />
                  Upload App
                </>
              )}
            </button>
          )}
        </div>

        {/* Upload Progress Bar */}
        {uploadState.status === 'uploading' && (
          <div className="mt-3">
            <div className={`h-2 rounded-full overflow-hidden ${isDarkMode ? 'bg-slate-700' : 'bg-gray-200'}`}>
              <div 
                className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all duration-300"
                style={{ width: `${uploadState.progress}%` }}
              />
            </div>
            <p className={`mt-1 text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Uploading... {uploadState.progress}%
            </p>
          </div>
        )}

        {/* Upload Success - App Info Display */}
        {uploadState.status === 'success' && (
          <div className={`mt-3 p-4 rounded-xl border ${
            isDarkMode 
              ? 'bg-green-900/20 border-green-500/50' 
              : 'bg-green-50 border-green-300'
          }`}>
            <div className="flex items-center gap-2 mb-3">
              <CheckCircle className={`w-5 h-5 ${isDarkMode ? 'text-green-400' : 'text-green-600'}`} />
              <span className={`font-semibold ${isDarkMode ? 'text-green-400' : 'text-green-700'}`}>
                {uploadState.message || 'App Uploaded Successfully!'}
              </span>
            </div>
            
            {/* App Info */}
            {uploadState.appInfo && (
              <div className={`grid grid-cols-2 md:grid-cols-3 gap-3 text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                {uploadState.appInfo.package_name && (
                  <div>
                    <span className={isDarkMode ? 'text-gray-500' : 'text-gray-500'}>Package: </span>
                    <span className="font-mono">{uploadState.appInfo.package_name}</span>
                  </div>
                )}
                {uploadState.appInfo.version_name && (
                  <div>
                    <span className={isDarkMode ? 'text-gray-500' : 'text-gray-500'}>Version: </span>
                    <span>{uploadState.appInfo.version_name}</span>
                  </div>
                )}
                {uploadState.appInfo.target_sdk && (
                  <div>
                    <span className={isDarkMode ? 'text-gray-500' : 'text-gray-500'}>Target SDK: </span>
                    <span>{uploadState.appInfo.target_sdk}</span>
                  </div>
                )}
                {uploadState.appInfo.min_sdk && (
                  <div>
                    <span className={isDarkMode ? 'text-gray-500' : 'text-gray-500'}>Min SDK: </span>
                    <span>{uploadState.appInfo.min_sdk}</span>
                  </div>
                )}
                {uploadState.appInfo.permissions_count && (
                  <div>
                    <span className={isDarkMode ? 'text-gray-500' : 'text-gray-500'}>Permissions: </span>
                    <span>{uploadState.appInfo.permissions_count}</span>
                  </div>
                )}
              </div>
            )}
            
            {/* Device & Installation Status */}
            {uploadState.deviceStatus && (
              <div className={`mt-3 pt-3 border-t ${isDarkMode ? 'border-green-800/50' : 'border-green-200'}`}>
                <div className={`flex items-center gap-4 text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                  <div className="flex items-center gap-2">
                    <Smartphone className={`w-4 h-4 ${uploadState.deviceStatus.connected ? (isDarkMode ? 'text-green-400' : 'text-green-600') : (isDarkMode ? 'text-gray-500' : 'text-gray-400')}`} />
                    <span>
                      {uploadState.deviceStatus.connected 
                        ? `Device: ${uploadState.deviceStatus.device_id}` 
                        : 'No device connected'}
                    </span>
                  </div>
                  
                  {uploadState.installationStatus && (
                    <div className="flex items-center gap-2">
                      {uploadState.installationStatus.installed ? (
                        <>
                          <CheckCircle className={`w-4 h-4 ${isDarkMode ? 'text-green-400' : 'text-green-600'}`} />
                          <span className={isDarkMode ? 'text-green-400' : 'text-green-600'}>Installed</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className={`w-4 h-4 ${isDarkMode ? 'text-amber-400' : 'text-amber-600'}`} />
                          <span className={isDarkMode ? 'text-amber-400' : 'text-amber-600'}>
                            {uploadState.installationStatus.error || 'Will install on scan start'}
                          </span>
                        </>
                      )}
                    </div>
                  )}
                </div>
                
                {!uploadState.deviceStatus.connected && (
                  <p className={`mt-2 text-xs ${isDarkMode ? 'text-amber-400/80' : 'text-amber-600'}`}>
                    ⚠️ Start an emulator or connect a device for full dynamic testing. Static analysis will still work.
                  </p>
                )}
              </div>
            )}
            
            <button
              type="button"
              onClick={() => {
                setUploadState({ status: 'idle', progress: 0, fileId: null, appInfo: null, deviceStatus: null, installationStatus: null, message: null, error: null });
                setMobileForm(prev => ({ ...prev, appFile: null }));
              }}
              className={`mt-3 text-sm underline ${isDarkMode ? 'text-gray-400 hover:text-gray-300' : 'text-gray-600 hover:text-gray-800'}`}
            >
              Choose a different file
            </button>
          </div>
        )}

        {/* Upload Error */}
        {uploadState.status === 'error' && (
          <div className={`mt-3 p-4 rounded-xl border ${
            isDarkMode 
              ? 'bg-red-900/20 border-red-500/50' 
              : 'bg-red-50 border-red-300'
          }`}>
            <div className="flex items-center gap-2">
              <XCircle className={`w-5 h-5 ${isDarkMode ? 'text-red-400' : 'text-red-600'}`} />
              <span className={`font-semibold ${isDarkMode ? 'text-red-400' : 'text-red-700'}`}>
                Upload Failed
              </span>
            </div>
            <p className={`mt-1 text-sm ${isDarkMode ? 'text-red-300' : 'text-red-600'}`}>
              {uploadState.error}
            </p>
            <button
              type="button"
              onClick={handleUpload}
              className={`mt-2 text-sm underline ${isDarkMode ? 'text-blue-400 hover:text-blue-300' : 'text-blue-600 hover:text-blue-800'}`}
            >
              Try again
            </button>
          </div>
        )}
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

      {/* Authentication Section */}
      <div className="space-y-4">
        <button
          type="button"
          onClick={() => setShowAuthSection(!showAuthSection)}
          className={`flex items-center justify-between w-full p-4 rounded-xl transition-all ${
            isDarkMode
              ? "bg-slate-700/50 border border-slate-600/50 hover:border-purple-500/50"
              : "bg-gray-50 border border-gray-200 hover:border-purple-300"
          }`}
        >
          <div className="flex items-center gap-3">
            <Lock className={`w-5 h-5 ${isDarkMode ? "text-purple-400" : "text-purple-600"}`} />
            <div className="text-left">
              <div className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Authentication for Dynamic Testing
              </div>
              <div className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Configure credentials if the app requires login
              </div>
            </div>
          </div>
          {showAuthSection ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>

        {showAuthSection && (
          <div className={`p-4 rounded-xl space-y-4 ${
            isDarkMode ? "bg-slate-800/50 border border-slate-700" : "bg-gray-50 border border-gray-200"
          }`}>
            {/* Enable Auth Toggle */}
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                name="authEnabled"
                checked={mobileForm.authEnabled}
                onChange={handleInputChange}
                className="w-5 h-5 rounded"
              />
              <span className={isDarkMode ? "text-white" : "text-gray-900"}>
                Enable authenticated testing
              </span>
            </label>

            {mobileForm.authEnabled && (
              <>
                {/* Auth Type Selector */}
                <div className="space-y-2">
                  <label className={labelClass}>Authentication Type</label>
                  <select
                    name="authType"
                    value={mobileForm.authType}
                    onChange={handleInputChange}
                    className={inputClass}
                  >
                    <option value="email_password">Email / Password</option>
                    <option value="phone_otp">Phone + OTP</option>
                    <option value="social">Social Login (Google/Facebook/Apple)</option>
                    <option value="manual">Manual Login (I'll login myself)</option>
                  </select>
                </div>

                {/* Email/Password Fields */}
                {mobileForm.authType === "email_password" && (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <label className={labelClass}>
                        <User className="w-4 h-4 inline mr-2" />
                        Username / Email
                      </label>
                      <input
                        name="username"
                        type="text"
                        placeholder="user@example.com"
                        value={mobileForm.username}
                        onChange={handleInputChange}
                        className={inputClass}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className={labelClass}>
                        <Lock className="w-4 h-4 inline mr-2" />
                        Password
                      </label>
                      <div className="relative">
                        <input
                          name="password"
                          type={showPassword ? "text" : "password"}
                          placeholder="••••••••"
                          value={mobileForm.password}
                          onChange={handleInputChange}
                          className={inputClass}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(!showPassword)}
                          className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-300"
                        >
                          {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                  </div>
                )}

                {/* 2FA Toggle - Show when email/password auth is selected */}
                {mobileForm.authType === "email_password" && (mobileForm.username || mobileForm.password) && (
                  <div className={`mt-4 p-4 rounded-xl border ${isDarkMode ? "bg-slate-800/50 border-slate-700" : "bg-gray-50 border-gray-200"}`}>
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Shield className={`w-5 h-5 ${isDarkMode ? "text-blue-400" : "text-blue-600"}`} />
                        <div>
                          <label className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                            App requires 2FA / OTP
                          </label>
                          <p className={`text-xs mt-0.5 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                            Enable if login requires OTP verification
                          </p>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => {
                          const newValue = !mobileForm.twoFactorEnabled;
                          setMobileForm(prev => ({ ...prev, twoFactorEnabled: newValue }));
                          if (newValue) setShow2FAWarning(true);
                        }}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          mobileForm.twoFactorEnabled
                            ? "bg-blue-600"
                            : isDarkMode ? "bg-slate-600" : "bg-gray-300"
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-white transition-transform ${
                            mobileForm.twoFactorEnabled ? "translate-x-6" : "translate-x-1"
                          }`}
                        />
                      </button>
                    </div>

                    {/* 2FA Warning Popup */}
                    {show2FAWarning && mobileForm.twoFactorEnabled && (
                      <div className={`mt-4 p-4 rounded-lg border-2 animate-pulse ${
                        isDarkMode 
                          ? "bg-amber-900/40 border-amber-500" 
                          : "bg-amber-50 border-amber-400"
                      }`}>
                        <div className="flex items-start gap-3">
                          <AlertTriangle className={`w-6 h-6 flex-shrink-0 ${isDarkMode ? "text-amber-400" : "text-amber-600"}`} />
                          <div>
                            <p className={`font-semibold ${isDarkMode ? "text-amber-300" : "text-amber-700"}`}>
                              ⚠️ Be Ready to Enter OTP!
                            </p>
                            <p className={`text-sm mt-1 ${isDarkMode ? "text-amber-200/80" : "text-amber-600"}`}>
                              During the scan, you will be prompted to enter the OTP code from your dashboard. 
                              Please keep your phone or authenticator app ready. You'll have <strong>3 minutes</strong> to enter the code.
                            </p>
                            <button
                              type="button"
                              onClick={() => setShow2FAWarning(false)}
                              className={`mt-3 px-4 py-1.5 text-sm rounded-lg font-medium transition-colors ${
                                isDarkMode 
                                  ? "bg-amber-600 hover:bg-amber-500 text-white" 
                                  : "bg-amber-500 hover:bg-amber-400 text-white"
                              }`}
                            >
                              Got it, I'm ready!
                            </button>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* 2FA Type Selection */}
                    {mobileForm.twoFactorEnabled && !show2FAWarning && (
                      <div className={`mt-4 pt-4 border-t border-dashed ${isDarkMode ? "border-slate-600" : "border-gray-300"}`}>
                        <label className={`text-sm font-medium mb-2 block ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                          How will you receive the OTP?
                        </label>
                        <div className="grid grid-cols-3 gap-3">
                          {[
                            { id: 'sms', label: 'SMS', icon: Smartphone, desc: 'Text message' },
                            { id: 'email', label: 'Email', icon: Mail, desc: 'Email code' },
                            { id: 'authenticator', label: 'App', icon: Key, desc: 'Authenticator' },
                          ].map(option => {
                            const IconComponent = option.icon;
                            return (
                              <button
                                key={option.id}
                                type="button"
                                onClick={() => setMobileForm(prev => ({ ...prev, twoFactorType: option.id }))}
                                className={`p-3 rounded-lg border text-center transition-all ${
                                  mobileForm.twoFactorType === option.id
                                    ? isDarkMode
                                      ? "bg-blue-600/20 border-blue-500 text-blue-400"
                                      : "bg-blue-50 border-blue-500 text-blue-700"
                                    : isDarkMode
                                      ? "bg-slate-700/50 border-slate-600 text-gray-400 hover:border-slate-500"
                                      : "bg-white border-gray-200 text-gray-600 hover:border-gray-300"
                                }`}
                              >
                                <IconComponent className="w-5 h-5 mx-auto mb-1" />
                                <div className="text-sm font-medium">{option.label}</div>
                                <div className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>{option.desc}</div>
                              </button>
                            );
                          })}
                        </div>
                        <p className={`text-xs mt-3 ${isDarkMode ? "text-amber-400/80" : "text-amber-600"}`}>
                          ⏱️ You'll have 3 minutes to enter the OTP code when prompted during the scan
                        </p>
                      </div>
                    )}
                  </div>
                )}

                {/* Phone OTP Fields */}
                {mobileForm.authType === "phone_otp" && (
                  <div className="space-y-2">
                    <label className={labelClass}>
                      <Phone className="w-4 h-4 inline mr-2" />
                      Phone Number
                    </label>
                    <input
                      name="phone"
                      type="tel"
                      placeholder="+1234567890"
                      value={mobileForm.phone}
                      onChange={handleInputChange}
                      className={inputClass}
                    />
                    <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                      You'll be prompted to enter OTP during the scan
                    </p>
                  </div>
                )}

                {/* Social Login Info */}
                {mobileForm.authType === "social" && (
                  <div className={`p-3 rounded-lg ${isDarkMode ? "bg-blue-900/30 border border-blue-700" : "bg-blue-50 border border-blue-200"}`}>
                    <p className={`text-sm ${isDarkMode ? "text-blue-300" : "text-blue-700"}`}>
                      During the scan, you'll be prompted to complete social login on the device/emulator.
                      The scan will pause and wait for you to authenticate.
                    </p>
                  </div>
                )}

                {/* Manual Login Info */}
                {mobileForm.authType === "manual" && (
                  <div className={`p-3 rounded-lg ${isDarkMode ? "bg-yellow-900/30 border border-yellow-700" : "bg-yellow-50 border border-yellow-200"}`}>
                    <p className={`text-sm ${isDarkMode ? "text-yellow-300" : "text-yellow-700"}`}>
                      The scan will pause after launching the app. You'll manually login on the device,
                      then click "Continue" in the dashboard to resume testing authenticated endpoints.
                    </p>
                  </div>
                )}
              </>
            )}
          </div>
        )}
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
          disabled={isSubmitting || uploadState.status !== 'success'}
          className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-purple-600 to-purple-500 text-white rounded-xl hover:from-purple-500 hover:to-purple-400 disabled:opacity-50 transition-all duration-300 font-semibold"
        >
          {isSubmitting ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Starting...
            </>
          ) : (
            <>
              <Smartphone className="w-4 h-4" />
              Start Mobile Scan
            </>
          )}
        </button>
        <button
          type="button"
          onClick={() => navigate("/dashboard")}
          className={cancelButtonClass}
        >
          Cancel
        </button>
      </div>
      
      {/* Help text if file not uploaded yet */}
      {mobileForm.appFile && uploadState.status === 'idle' && (
        <p className={`text-sm ${isDarkMode ? 'text-amber-400' : 'text-amber-600'}`}>
          👆 Click "Upload App" to upload the file before starting the scan
        </p>
      )}
    </form>
  );
};

export default MobileScanForm;
