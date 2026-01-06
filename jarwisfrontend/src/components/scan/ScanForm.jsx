// src/components/scan/ScanForm.jsx
// Comprehensive scan form supporting Web, Mobile, and Cloud scans
import { useState, useEffect } from "react";
import { useTheme } from "../../context/ThemeContext";
import { cloudScanAPI } from "../../services/api";

const ScanForm = ({ onStartScan, isLoading }) => {
  const { isDarkMode } = useTheme();

  const [formData, setFormData] = useState({
    // Web scan fields
    target_url: "",
    scan_type: "web",
    login_url: "",
    username: "",
    password: "",
    username_selector: "#email",
    password_selector: "#password",
    submit_selector: 'button[type="submit"]',
    success_indicator: "",
    headless: false,
    // Mobile scan fields
    app_path: "",
    runtime_analysis: false,
    device_id: "",
    ssl_pinned: "unknown",
    bypass_ssl_pinning: false,
    // Mobile authentication fields
    mobile_auth_enabled: false,
    mobile_username: "",
    mobile_password: "",
    mobile_email: "",
    mobile_auth_type: "email_password",
    // OTP handling
    otp_enabled: false,
    otp_handling: "prompt",
    otp_phone: "",
    // MITM Proxy
    mitm_enabled: true,
    mitm_port: 8080,
    // Advanced mobile options
    enable_unpacking: true,
    ai_analysis: true,
    // Cloud scan fields
    provider: "aws",
    aws_profile: "",
    aws_region: "us-east-1",
    azure_subscription: "",
    azure_tenant: "",
    gcp_project: "",
    gcp_credentials: "",
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [mobileAuthEnabled, setMobileAuthEnabled] = useState(false);
  const [cloudProviders, setCloudProviders] = useState({});
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileError, setFileError] = useState("");
  const [showSslInfo, setShowSslInfo] = useState(false);
  const [showOtpInfo, setShowOtpInfo] = useState(false);
  const [showMitmInfo, setShowMitmInfo] = useState(false);

  // Fetch available cloud providers on mount
  useEffect(() => {
    cloudScanAPI.getProviders()
      .then((data) => setCloudProviders(data))
      .catch((err) => console.log("Cloud providers check failed:", err));
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const ALLOWED_EXTENSIONS = [".apk", ".ipa"];
  const MAX_FILE_SIZE = 500 * 1024 * 1024;

  const validateMobileAppFile = (file) => {
    if (!file) return "Please select a file";
    const fileName = file.name.toLowerCase();
    const extension = fileName.substring(fileName.lastIndexOf("."));
    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return `Invalid file type. Only APK and IPA files are allowed. Got: ${extension}`;
    }
    if (file.size > MAX_FILE_SIZE) {
      return `File too large. Maximum size is 500MB. Got: ${(file.size / (1024 * 1024)).toFixed(2)}MB`;
    }
    return null;
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    setFileError("");
    setSelectedFile(null);
    if (!file) return;
    const error = validateMobileAppFile(file);
    if (error) {
      setFileError(error);
      e.target.value = "";
      return;
    }
    setSelectedFile(file);
    setFormData((prev) => ({ ...prev, app_path: file.name }));
  };

  const handleFileDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    const file = e.dataTransfer.files[0];
    setFileError("");
    setSelectedFile(null);
    if (!file) return;
    const error = validateMobileAppFile(file);
    if (error) {
      setFileError(error);
      return;
    }
    setSelectedFile(file);
    setFormData((prev) => ({ ...prev, app_path: file.name }));
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (formData.scan_type === "web") {
      if (!formData.target_url) {
        alert("Please enter a target URL");
        return;
      }
    } else if (formData.scan_type === "mobile") {
      if (!selectedFile) {
        alert("Please upload an APK or IPA file");
        return;
      }
      const error = validateMobileAppFile(selectedFile);
      if (error) {
        alert(error);
        return;
      }
    } else if (formData.scan_type === "cloud") {
      if (formData.provider === "azure" && !formData.azure_subscription) {
        alert("Please enter Azure Subscription ID");
        return;
      }
      if (formData.provider === "gcp" && !formData.gcp_project) {
        alert("Please enter GCP Project ID");
        return;
      }
    }
    onStartScan(formData, selectedFile);
  };

  const scanTypes = [
    { id: "web", name: "Web Application", icon: "[WEB]", description: "OWASP Top 10 Testing" },
    { id: "mobile", name: "Mobile App", icon: "[MOBILE]", description: "Android & iOS Security" },
    { id: "cloud", name: "Cloud Infrastructure", icon: "", description: "AWS, Azure, GCP" },
  ];

  const awsRegions = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "eu-west-1", "eu-west-2", "eu-central-1",
    "ap-south-1", "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
  ];

  // Theme classes
  const cardClass = isDarkMode
    ? "bg-slate-800/50 border border-slate-700/50 rounded-xl p-6"
    : "bg-white border border-gray-200 rounded-xl p-6 shadow-sm";

  const inputClass = isDarkMode
    ? "w-full px-4 py-3 bg-slate-800/50 border border-slate-700/50 rounded-lg text-white placeholder-gray-400 focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 outline-none transition-all"
    : "w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 outline-none transition-all shadow-sm";

  const labelClass = isDarkMode
    ? "block text-sm font-medium text-gray-300 mb-2"
    : "block text-sm font-medium text-gray-700 mb-2";

  const sectionTitle = isDarkMode
    ? "text-lg font-semibold text-white mb-4 flex items-center gap-2"
    : "text-lg font-semibold text-gray-900 mb-4 flex items-center gap-2";

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      {/* Scan Type Selection */}
      <div className={cardClass}>
        <h3 className={sectionTitle}>[TARGET] Select Scan Type</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {scanTypes.map((type) => (
            <div
              key={type.id}
              className={`cursor-pointer p-4 rounded-xl border-2 transition-all duration-300 ${
                formData.scan_type === type.id
                  ? isDarkMode
                    ? "border-blue-500 bg-blue-500/10"
                    : "border-blue-500 bg-blue-50"
                  : isDarkMode
                  ? "border-slate-700 hover:border-slate-600"
                  : "border-gray-200 hover:border-gray-300"
              }`}
              onClick={() => setFormData((prev) => ({ ...prev, scan_type: type.id }))}
            >
              <div className="text-3xl mb-2">{type.icon}</div>
              <div className={isDarkMode ? "text-white font-medium" : "text-gray-900 font-medium"}>
                {type.name}
              </div>
              <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                {type.description}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Web Application Scan Form */}
      {formData.scan_type === "web" && (
        <>
          <div className={cardClass}>
            <h3 className={sectionTitle}>[WEB] Web Application Target</h3>
            <div className="space-y-4">
              <div>
                <label className={labelClass}>Target Website URL *</label>
                <input
                  type="url"
                  name="target_url"
                  value={formData.target_url}
                  onChange={handleChange}
                  placeholder="https://example.com"
                  className={inputClass}
                  required
                />
                <p className={isDarkMode ? "text-gray-500 text-sm mt-1" : "text-gray-500 text-sm mt-1"}>
                  The main URL of the website to test
                </p>
              </div>
            </div>
          </div>

          <div className={cardClass}>
            <div className="flex justify-between items-center mb-4">
              <h3 className={sectionTitle}>[SECURE] Authentication</h3>
              <label className="relative inline-flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  className="sr-only peer"
                  checked={authEnabled}
                  onChange={(e) => setAuthEnabled(e.target.checked)}
                />
                <div className="w-11 h-6 bg-gray-600 peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
              </label>
            </div>

            {authEnabled && (
              <div className="space-y-4">
                <div>
                  <label className={labelClass}>Login Page URL</label>
                  <input
                    type="text"
                    name="login_url"
                    value={formData.login_url}
                    onChange={handleChange}
                    placeholder="/login or https://example.com/login"
                    className={inputClass}
                  />
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className={labelClass}>Username / Email</label>
                    <input
                      type="text"
                      name="username"
                      value={formData.username}
                      onChange={handleChange}
                      placeholder="testuser@example.com"
                      className={inputClass}
                    />
                  </div>
                  <div>
                    <label className={labelClass}>Password</label>
                    <input
                      type="password"
                      name="password"
                      value={formData.password}
                      onChange={handleChange}
                      placeholder="********"
                      className={inputClass}
                    />
                  </div>
                </div>

                <button
                  type="button"
                  className={isDarkMode ? "text-blue-400 hover:text-blue-300 text-sm" : "text-blue-600 hover:text-blue-500 text-sm"}
                  onClick={() => setShowAdvanced(!showAdvanced)}
                >
                  {showAdvanced ? "▼ Hide" : "▶ Show"} Advanced Selectors
                </button>

                {showAdvanced && (
                  <div className="space-y-4 mt-4 p-4 rounded-lg bg-slate-900/30 border border-slate-700/50">
                    <div>
                      <label className={labelClass}>Username Field Selector</label>
                      <input
                        type="text"
                        name="username_selector"
                        value={formData.username_selector}
                        onChange={handleChange}
                        className={`${inputClass} font-mono text-sm`}
                      />
                    </div>
                    <div>
                      <label className={labelClass}>Password Field Selector</label>
                      <input
                        type="text"
                        name="password_selector"
                        value={formData.password_selector}
                        onChange={handleChange}
                        className={`${inputClass} font-mono text-sm`}
                      />
                    </div>
                    <div>
                      <label className={labelClass}>Submit Button Selector</label>
                      <input
                        type="text"
                        name="submit_selector"
                        value={formData.submit_selector}
                        onChange={handleChange}
                        className={`${inputClass} font-mono text-sm`}
                      />
                    </div>
                    <div>
                      <label className={labelClass}>Success Indicator</label>
                      <input
                        type="text"
                        name="success_indicator"
                        value={formData.success_indicator}
                        onChange={handleChange}
                        placeholder="/dashboard or .welcome-message"
                        className={inputClass}
                      />
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className={cardClass}>
            <h3 className={sectionTitle}>[GEAR] Options</h3>
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                name="headless"
                checked={formData.headless}
                onChange={handleChange}
                className="w-5 h-5 rounded border-gray-600 text-blue-600 focus:ring-blue-500"
              />
              <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                Run browser in headless mode (hidden)
              </span>
            </label>
          </div>
        </>
      )}

      {/* Mobile App Scan Form */}
      {formData.scan_type === "mobile" && (
        <>
          <div className={cardClass}>
            <h3 className={sectionTitle}>[MOBILE] Mobile Application Target</h3>
            
            <div className="mb-4">
              <label className={labelClass}>Upload Application File (APK/IPA) *</label>
              <div
                className={`relative border-2 border-dashed rounded-xl p-8 text-center transition-all ${
                  selectedFile
                    ? isDarkMode
                      ? "border-green-500 bg-green-500/10"
                      : "border-green-500 bg-green-50"
                    : fileError
                    ? "border-red-500 bg-red-500/10"
                    : isDarkMode
                    ? "border-slate-600 hover:border-slate-500"
                    : "border-gray-300 hover:border-gray-400"
                }`}
                onDrop={handleFileDrop}
                onDragOver={handleDragOver}
              >
                <input
                  type="file"
                  id="app_file"
                  accept=".apk,.ipa"
                  onChange={handleFileSelect}
                  className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                />
                {selectedFile ? (
                  <div className="space-y-2">
                    <span className="text-4xl">{selectedFile.name.endsWith(".apk") ? "[BOT]" : ""}</span>
                    <p className={isDarkMode ? "text-white font-medium" : "text-gray-900 font-medium"}>
                      {selectedFile.name}
                    </p>
                    <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
                      ({(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)
                    </p>
                    <button
                      type="button"
                      className="text-red-400 hover:text-red-300 text-sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedFile(null);
                        setFormData((prev) => ({ ...prev, app_path: "" }));
                      }}
                    >
                      x Remove
                    </button>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <span className="text-4xl">[SEND]</span>
                    <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                      Drag & drop your APK or IPA file here
                    </p>
                    <p className={isDarkMode ? "text-gray-500" : "text-gray-500"}>or click to browse</p>
                  </div>
                )}
              </div>
              {fileError && <p className="text-red-400 text-sm mt-2">[X] {fileError}</p>}
              <p className={isDarkMode ? "text-gray-500 text-sm mt-2" : "text-gray-500 text-sm mt-2"}>
                Accepted formats: .apk (Android), .ipa (iOS) * Max size: 500MB
              </p>
            </div>

            <div className={`p-4 rounded-lg ${isDarkMode ? "bg-blue-900/20 border border-blue-700/30" : "bg-blue-50 border border-blue-200"}`}>
              <strong className={isDarkMode ? "text-blue-300" : "text-blue-700"}>
                [LIST] OWASP Mobile Top 10 Coverage:
              </strong>
              <ul className={`mt-2 grid grid-cols-1 md:grid-cols-2 gap-1 text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                <li>M1: Improper Platform Usage</li>
                <li>M2: Insecure Data Storage</li>
                <li>M3: Insecure Communication</li>
                <li>M4: Insecure Authentication</li>
                <li>M5: Insufficient Cryptography</li>
                <li>M6: Insecure Authorization</li>
                <li>M7: Client Code Quality</li>
                <li>M8: Code Tampering</li>
                <li>M9: Reverse Engineering</li>
                <li>M10: Extraneous Functionality</li>
              </ul>
            </div>
          </div>

          {/* SSL Pinning Configuration */}
          {selectedFile && (
            <div className={cardClass}>
              <div className="flex justify-between items-center mb-4">
                <h3 className={sectionTitle}>[SECURE] SSL Pinning Configuration</h3>
                <button
                  type="button"
                  className={isDarkMode ? "text-blue-400 hover:text-blue-300 text-sm" : "text-blue-600 hover:text-blue-500 text-sm"}
                  onClick={() => setShowSslInfo(!showSslInfo)}
                >
                  {showSslInfo ? "▼ Hide Info" : " What is SSL Pinning?"}
                </button>
              </div>

              {showSslInfo && (
                <div className={`mb-4 p-4 rounded-lg ${isDarkMode ? "bg-slate-900/50 border border-slate-700/50" : "bg-gray-50 border border-gray-200"}`}>
                  <p className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                    <strong>SSL/Certificate Pinning</strong> is a security technique used by mobile apps
                    to prevent man-in-the-middle (MITM) attacks. When an app uses SSL pinning, it only
                    trusts specific certificates.
                  </p>
                </div>
              )}

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {[
                  { value: "pinned", icon: "[LOCK]", title: "Yes, SSL Pinned", desc: "App rejects proxy certificates" },
                  { value: "unpinned", icon: "[UNLOCK]", title: "No, Not Pinned", desc: "App accepts any valid cert" },
                  { value: "unknown", icon: "", title: "I Don't Know", desc: "Auto-detect during scan" },
                ].map((option) => (
                  <div
                    key={option.value}
                    className={`cursor-pointer p-4 rounded-xl border-2 transition-all text-center ${
                      formData.ssl_pinned === option.value
                        ? isDarkMode
                          ? "border-blue-500 bg-blue-500/10"
                          : "border-blue-500 bg-blue-50"
                        : isDarkMode
                        ? "border-slate-700 hover:border-slate-600"
                        : "border-gray-200 hover:border-gray-300"
                    }`}
                    onClick={() =>
                      setFormData((prev) => ({
                        ...prev,
                        ssl_pinned: option.value,
                        bypass_ssl_pinning: option.value === "pinned",
                      }))
                    }
                  >
                    <div className="text-2xl mb-2">{option.icon}</div>
                    <div className={isDarkMode ? "text-white font-medium" : "text-gray-900 font-medium"}>
                      {option.title}
                    </div>
                    <div className={isDarkMode ? "text-gray-400 text-sm" : "text-gray-600 text-sm"}>
                      {option.desc}
                    </div>
                  </div>
                ))}
              </div>

              {formData.ssl_pinned === "pinned" && (
                <div className={`mt-4 p-4 rounded-lg ${isDarkMode ? "bg-purple-900/20 border border-purple-700/30" : "bg-purple-50 border border-purple-200"}`}>
                  <div className="flex items-center gap-2 mb-2">
                    <span className="text-2xl"></span>
                    <strong className={isDarkMode ? "text-purple-300" : "text-purple-700"}>
                      Frida SSL Bypass Enabled
                    </strong>
                  </div>
                  <p className={isDarkMode ? "text-gray-300 text-sm" : "text-gray-700 text-sm"}>
                    We'll use Frida to bypass SSL pinning. Requires a rooted device with Frida server.
                  </p>
                  <div className="mt-3">
                    <label className={labelClass}>Device ID (optional)</label>
                    <input
                      type="text"
                      name="device_id"
                      value={formData.device_id}
                      onChange={handleChange}
                      placeholder="Leave empty for auto-detect"
                      className={inputClass}
                    />
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Mobile Auth & Analysis Options */}
          {selectedFile && (
            <>
              <div className={cardClass}>
                <div className="flex justify-between items-center mb-4">
                  <h3 className={sectionTitle}>[KEY] App Authentication</h3>
                  <label className="relative inline-flex items-center cursor-pointer">
                    <input
                      type="checkbox"
                      className="sr-only peer"
                      checked={mobileAuthEnabled}
                      onChange={(e) => setMobileAuthEnabled(e.target.checked)}
                    />
                    <div className="w-11 h-6 bg-gray-600 peer-focus:ring-4 peer-focus:ring-blue-800 rounded-full peer peer-checked:after:translate-x-full after:content-[''] after:absolute after:top-[2px] after:left-[2px] after:bg-white after:rounded-full after:h-5 after:w-5 after:transition-all peer-checked:bg-blue-600"></div>
                  </label>
                </div>

                {mobileAuthEnabled && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                      {[
                        { value: "email_password", icon: "[EMAIL]", label: "Email & Password" },
                        { value: "phone_otp", icon: "[MOBILE]", label: "Phone + OTP" },
                        { value: "username_password", icon: "", label: "Username & Password" },
                        { value: "social", icon: "[LINK]", label: "Social Login" },
                      ].map((authType) => (
                        <div
                          key={authType.value}
                          className={`cursor-pointer p-3 rounded-lg border text-center transition-all ${
                            formData.mobile_auth_type === authType.value
                              ? isDarkMode
                                ? "border-blue-500 bg-blue-500/10"
                                : "border-blue-500 bg-blue-50"
                              : isDarkMode
                              ? "border-slate-700 hover:border-slate-600"
                              : "border-gray-200 hover:border-gray-300"
                          }`}
                          onClick={() => setFormData((prev) => ({ ...prev, mobile_auth_type: authType.value }))}
                        >
                          <span className="text-xl">{authType.icon}</span>
                          <div className={`text-sm mt-1 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                            {authType.label}
                          </div>
                        </div>
                      ))}
                    </div>

                    {(formData.mobile_auth_type === "email_password" || formData.mobile_auth_type === "username_password") && (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <label className={labelClass}>
                            {formData.mobile_auth_type === "email_password" ? "Email Address" : "Username"} *
                          </label>
                          <input
                            type={formData.mobile_auth_type === "email_password" ? "email" : "text"}
                            name={formData.mobile_auth_type === "email_password" ? "mobile_email" : "mobile_username"}
                            value={formData.mobile_auth_type === "email_password" ? formData.mobile_email : formData.mobile_username}
                            onChange={handleChange}
                            placeholder={formData.mobile_auth_type === "email_password" ? "test@example.com" : "testuser"}
                            className={inputClass}
                          />
                        </div>
                        <div>
                          <label className={labelClass}>Password *</label>
                          <input
                            type="password"
                            name="mobile_password"
                            value={formData.mobile_password}
                            onChange={handleChange}
                            placeholder="********"
                            className={inputClass}
                          />
                        </div>
                      </div>
                    )}

                    {formData.mobile_auth_type === "phone_otp" && (
                      <div>
                        <label className={labelClass}>Phone Number *</label>
                        <input
                          type="tel"
                          name="otp_phone"
                          value={formData.otp_phone}
                          onChange={handleChange}
                          placeholder="+1 234 567 8900"
                          className={inputClass}
                        />
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div className={cardClass}>
                <h3 className={sectionTitle}>[TOOL] Extraction & Analysis</h3>
                <div className="space-y-3">
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      name="enable_unpacking"
                      checked={formData.enable_unpacking}
                      onChange={handleChange}
                      className="w-5 h-5 rounded border-gray-600 text-blue-600 focus:ring-blue-500"
                    />
                    <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                      Unpack & Decompile Application
                    </span>
                    <span className="px-2 py-1 text-xs bg-green-500/20 text-green-400 rounded">Recommended</span>
                  </label>
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      name="ai_analysis"
                      checked={formData.ai_analysis}
                      onChange={handleChange}
                      className="w-5 h-5 rounded border-gray-600 text-blue-600 focus:ring-blue-500"
                    />
                    <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                      Enable AI-Powered Analysis (Jarwis LLM)
                    </span>
                    <span className="px-2 py-1 text-xs bg-green-500/20 text-green-400 rounded">Recommended</span>
                  </label>
                  <label className="flex items-center gap-3 cursor-pointer">
                    <input
                      type="checkbox"
                      name="runtime_analysis"
                      checked={formData.runtime_analysis}
                      onChange={handleChange}
                      className="w-5 h-5 rounded border-gray-600 text-blue-600 focus:ring-blue-500"
                    />
                    <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                      Enable Full Runtime Analysis (Frida hooks)
                    </span>
                  </label>
                </div>
              </div>
            </>
          )}
        </>
      )}

      {/* Cloud Infrastructure Scan Form */}
      {formData.scan_type === "cloud" && (
        <>
          <div className={cardClass}>
            <h3 className={sectionTitle}> Cloud Provider</h3>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { id: "aws", icon: "", name: "Amazon AWS" },
                { id: "azure", icon: "[BLUE]", name: "Microsoft Azure" },
                { id: "gcp", icon: "[RED]", name: "Google Cloud" },
                { id: "all", icon: "[WEB]", name: "All Providers" },
              ].map((provider) => (
                <div
                  key={provider.id}
                  className={`cursor-pointer p-4 rounded-xl border-2 text-center transition-all ${
                    formData.provider === provider.id
                      ? isDarkMode
                        ? "border-blue-500 bg-blue-500/10"
                        : "border-blue-500 bg-blue-50"
                      : isDarkMode
                      ? "border-slate-700 hover:border-slate-600"
                      : "border-gray-200 hover:border-gray-300"
                  }`}
                  onClick={() => setFormData((prev) => ({ ...prev, provider: provider.id }))}
                >
                  <div className="text-2xl mb-2">{provider.icon}</div>
                  <div className={isDarkMode ? "text-white font-medium text-sm" : "text-gray-900 font-medium text-sm"}>
                    {provider.name}
                  </div>
                  {cloudProviders[provider.id]?.available && (
                    <span className="text-xs text-green-400 mt-1 block">SDK Ready</span>
                  )}
                </div>
              ))}
            </div>
          </div>

          {(formData.provider === "aws" || formData.provider === "all") && (
            <div className={cardClass}>
              <h3 className={sectionTitle}> AWS Configuration</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className={labelClass}>AWS Profile</label>
                  <input
                    type="text"
                    name="aws_profile"
                    value={formData.aws_profile}
                    onChange={handleChange}
                    placeholder="default"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className={labelClass}>AWS Region</label>
                  <select
                    name="aws_region"
                    value={formData.aws_region}
                    onChange={handleChange}
                    className={inputClass}
                  >
                    {awsRegions.map((region) => (
                      <option key={region} value={region}>
                        {region}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </div>
          )}

          {(formData.provider === "azure" || formData.provider === "all") && (
            <div className={cardClass}>
              <h3 className={sectionTitle}>[BLUE] Azure Configuration</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className={labelClass}>Subscription ID *</label>
                  <input
                    type="text"
                    name="azure_subscription"
                    value={formData.azure_subscription}
                    onChange={handleChange}
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className={labelClass}>Tenant ID (optional)</label>
                  <input
                    type="text"
                    name="azure_tenant"
                    value={formData.azure_tenant}
                    onChange={handleChange}
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    className={inputClass}
                  />
                </div>
              </div>
            </div>
          )}

          {(formData.provider === "gcp" || formData.provider === "all") && (
            <div className={cardClass}>
              <h3 className={sectionTitle}>[RED] GCP Configuration</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className={labelClass}>Project ID *</label>
                  <input
                    type="text"
                    name="gcp_project"
                    value={formData.gcp_project}
                    onChange={handleChange}
                    placeholder="my-project-123456"
                    className={inputClass}
                  />
                </div>
                <div>
                  <label className={labelClass}>Service Account JSON Path</label>
                  <input
                    type="text"
                    name="gcp_credentials"
                    value={formData.gcp_credentials}
                    onChange={handleChange}
                    placeholder="path/to/service-account.json"
                    className={inputClass}
                  />
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {/* Submit Button */}
      <div className="flex gap-4">
        <button
          type="submit"
          disabled={isLoading}
          className="flex-1 flex items-center justify-center gap-2 px-6 py-4 bg-gradient-to-r from-blue-600 to-blue-500 text-white rounded-xl hover:from-blue-500 hover:to-blue-400 disabled:opacity-50 disabled:cursor-not-allowed transition-all font-semibold text-lg"
        >
          {isLoading ? (
            <>
              <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
              </svg>
              Starting Scan...
            </>
          ) : (
            <>
              [LAUNCH] Start{" "}
              {formData.scan_type === "web"
                ? "Penetration Test"
                : formData.scan_type === "mobile"
                ? "Mobile Security Scan"
                : "Cloud Security Scan"}
            </>
          )}
        </button>
      </div>

      {/* Disclaimer */}
      <div className={`p-4 rounded-lg ${isDarkMode ? "bg-yellow-900/20 border border-yellow-700/30" : "bg-yellow-50 border border-yellow-200"}`}>
        <p className={isDarkMode ? "text-yellow-300 text-sm" : "text-yellow-700 text-sm"}>
          [!] <strong>Warning:</strong> Only scan systems you own or have explicit written permission to test.
          Unauthorized access is illegal.
        </p>
      </div>
    </form>
  );
};

export default ScanForm;
