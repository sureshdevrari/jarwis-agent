import React, { useState, useEffect } from 'react';
import './ScanForm.css';

const ScanForm = ({ onStartScan, isLoading }) => {
  const [formData, setFormData] = useState({
    // Web scan fields
    target_url: '',
    scan_type: 'web',
    login_url: '',
    username: '',
    password: '',
    username_selector: '#email',
    password_selector: '#password',
    submit_selector: 'button[type="submit"]',
    success_indicator: '',
    headless: false,
    // Mobile scan fields
    app_path: '',
    runtime_analysis: false,
    device_id: '',
    ssl_pinned: 'unknown',  // 'pinned', 'unpinned', 'unknown'
    bypass_ssl_pinning: false,
    // Mobile authentication fields
    mobile_auth_enabled: false,
    mobile_username: '',
    mobile_password: '',
    mobile_email: '',
    mobile_auth_type: 'email_password',  // 'email_password', 'phone_otp', 'social'
    // OTP handling
    otp_enabled: false,
    otp_handling: 'prompt',  // 'prompt', 'disable', 'auto_read'
    otp_phone: '',
    // MITM Proxy
    mitm_enabled: true,
    mitm_port: 8080,
    // Advanced mobile options
    enable_unpacking: true,
    ai_analysis: true,
    // Cloud scan fields
    provider: 'aws',
    aws_profile: '',
    aws_region: 'us-east-1',
    azure_subscription: '',
    azure_tenant: '',
    gcp_project: '',
    gcp_credentials: '',
  });

  const [showAdvanced, setShowAdvanced] = useState(false);
  const [authEnabled, setAuthEnabled] = useState(false);
  const [mobileAuthEnabled, setMobileAuthEnabled] = useState(false);
  const [cloudProviders, setCloudProviders] = useState({});
  const [selectedFile, setSelectedFile] = useState(null);
  const [fileError, setFileError] = useState('');
  const [uploadProgress, setUploadProgress] = useState(0);
  const [showSslInfo, setShowSslInfo] = useState(false);
  const [showOtpInfo, setShowOtpInfo] = useState(false);
  const [showMitmInfo, setShowMitmInfo] = useState(false);

  // Fetch available cloud providers on mount
  useEffect(() => {
    fetch('http://localhost:5000/api/scan/cloud/providers')
      .then(res => res.json())
      .then(data => setCloudProviders(data))
      .catch(err => console.log('Cloud providers check failed:', err));
  }, []);

  const handleChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }));
  };

  // Allowed file extensions for mobile app scanning
  const ALLOWED_EXTENSIONS = ['.apk', '.ipa'];
  const MAX_FILE_SIZE = 500 * 1024 * 1024; // 500MB max

  const validateMobileAppFile = (file) => {
    if (!file) return 'Please select a file';
    
    const fileName = file.name.toLowerCase();
    const extension = fileName.substring(fileName.lastIndexOf('.'));
    
    if (!ALLOWED_EXTENSIONS.includes(extension)) {
      return `Invalid file type. Only APK and IPA files are allowed. Got: ${extension}`;
    }
    
    if (file.size > MAX_FILE_SIZE) {
      return `File too large. Maximum size is 500MB. Got: ${(file.size / (1024 * 1024)).toFixed(2)}MB`;
    }
    
    return null; // No error
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    setFileError('');
    setSelectedFile(null);
    
    if (!file) return;
    
    const error = validateMobileAppFile(file);
    if (error) {
      setFileError(error);
      e.target.value = ''; // Clear the input
      return;
    }
    
    setSelectedFile(file);
    setFormData(prev => ({ ...prev, app_path: file.name }));
  };

  const handleFileDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    
    const file = e.dataTransfer.files[0];
    setFileError('');
    setSelectedFile(null);
    
    if (!file) return;
    
    const error = validateMobileAppFile(file);
    if (error) {
      setFileError(error);
      return;
    }
    
    setSelectedFile(file);
    setFormData(prev => ({ ...prev, app_path: file.name }));
  };

  const handleDragOver = (e) => {
    e.preventDefault();
    e.stopPropagation();
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    
    if (formData.scan_type === 'web') {
      if (!formData.target_url) {
        alert('Please enter a target URL');
        return;
      }
    } else if (formData.scan_type === 'mobile') {
      if (!selectedFile) {
        alert('Please upload an APK or IPA file');
        return;
      }
      // Double-check file validation before submit
      const error = validateMobileAppFile(selectedFile);
      if (error) {
        alert(error);
        return;
      }
    } else if (formData.scan_type === 'cloud') {
      if (formData.provider === 'azure' && !formData.azure_subscription) {
        alert('Please enter Azure Subscription ID');
        return;
      }
      if (formData.provider === 'gcp' && !formData.gcp_project) {
        alert('Please enter GCP Project ID');
        return;
      }
    }
    
    // Pass both formData and selectedFile for mobile scans
    onStartScan(formData, selectedFile);
  };

  const scanTypes = [
    { id: 'web', name: 'Web Application', icon: 'Ã°Å¸Å’Â', description: 'OWASP Top 10 Testing' },
    { id: 'mobile', name: 'Mobile App', icon: 'Ã°Å¸â€œÂ±', description: 'Android & iOS Security' },
    { id: 'cloud', name: 'Cloud Infrastructure', icon: 'Ã¢ËœÂÃ¯Â¸Â', description: 'AWS, Azure, GCP' },
  ];

  const awsRegions = [
    'us-east-1', 'us-east-2', 'us-west-1', 'us-west-2',
    'eu-west-1', 'eu-west-2', 'eu-central-1',
    'ap-south-1', 'ap-southeast-1', 'ap-southeast-2', 'ap-northeast-1'
  ];

  return (
    <form className="scan-form" onSubmit={handleSubmit}>
      {/* Scan Type Selection */}
      <div className="form-section">
        <h3>Ã°Å¸Å½Â¯ Select Scan Type</h3>
        <div className="scan-type-grid">
          {scanTypes.map(type => (
            <div
              key={type.id}
              className={`scan-type-card ${formData.scan_type === type.id ? 'selected' : ''}`}
              onClick={() => setFormData(prev => ({ ...prev, scan_type: type.id }))}
            >
              <span className="icon">{type.icon}</span>
              <span className="name">{type.name}</span>
              <span className="description">{type.description}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Web Application Scan Form */}
      {formData.scan_type === 'web' && (
        <>
          <div className="form-section">
            <h3>Ã°Å¸Å’Â Web Application Target</h3>
            
            <div className="form-group">
              <label htmlFor="target_url">Target Website URL *</label>
              <input
                type="url"
                id="target_url"
                name="target_url"
                value={formData.target_url}
                onChange={handleChange}
                placeholder="https://example.com"
                required
              />
              <span className="hint">The main URL of the website to test</span>
            </div>
          </div>

          <div className="form-section">
            <div className="section-header">
              <h3>Ã°Å¸â€Â Authentication</h3>
              <label className="toggle">
                <input
                  type="checkbox"
                  checked={authEnabled}
                  onChange={(e) => setAuthEnabled(e.target.checked)}
                />
                <span className="slider"></span>
              </label>
            </div>

            {authEnabled && (
              <div className="auth-fields">
                <div className="form-group">
                  <label htmlFor="login_url">Login Page URL</label>
                  <input
                    type="text"
                    id="login_url"
                    name="login_url"
                    value={formData.login_url}
                    onChange={handleChange}
                    placeholder="/login or https://example.com/login"
                  />
                </div>

                <div className="form-row">
                  <div className="form-group">
                    <label htmlFor="username">Username / Email</label>
                    <input
                      type="text"
                      id="username"
                      name="username"
                      value={formData.username}
                      onChange={handleChange}
                      placeholder="testuser@example.com"
                    />
                  </div>

                  <div className="form-group">
                    <label htmlFor="password">Password</label>
                    <input
                      type="password"
                      id="password"
                      name="password"
                      value={formData.password}
                      onChange={handleChange}
                      placeholder="Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢"
                    />
                  </div>
                </div>

                <button
                  type="button"
                  className="btn-text"
                  onClick={() => setShowAdvanced(!showAdvanced)}
                >
                  {showAdvanced ? 'Ã¢â€“Â¼ Hide' : 'Ã¢â€“Â¶ Show'} Advanced Selectors
                </button>

                {showAdvanced && (
                  <div className="advanced-fields">
                    <div className="form-group">
                      <label htmlFor="username_selector">Username Field Selector</label>
                      <input
                        type="text"
                        id="username_selector"
                        name="username_selector"
                        value={formData.username_selector}
                        onChange={handleChange}
                        className="mono"
                      />
                    </div>

                    <div className="form-group">
                      <label htmlFor="password_selector">Password Field Selector</label>
                      <input
                        type="text"
                        id="password_selector"
                        name="password_selector"
                        value={formData.password_selector}
                        onChange={handleChange}
                        className="mono"
                      />
                    </div>

                    <div className="form-group">
                      <label htmlFor="submit_selector">Submit Button Selector</label>
                      <input
                        type="text"
                        id="submit_selector"
                        name="submit_selector"
                        value={formData.submit_selector}
                        onChange={handleChange}
                        className="mono"
                      />
                    </div>

                    <div className="form-group">
                      <label htmlFor="success_indicator">Success Indicator (URL or element)</label>
                      <input
                        type="text"
                        id="success_indicator"
                        name="success_indicator"
                        value={formData.success_indicator}
                        onChange={handleChange}
                        placeholder="/dashboard or .welcome-message"
                      />
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          <div className="form-section">
            <h3>Ã¢Å¡â„¢Ã¯Â¸Â Options</h3>
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="headless"
                checked={formData.headless}
                onChange={handleChange}
              />
              <span>Run browser in headless mode (hidden)</span>
            </label>
          </div>
        </>
      )}

      {/* Mobile App Scan Form */}
      {formData.scan_type === 'mobile' && (
        <>
          <div className="form-section">
            <h3>Ã°Å¸â€œÂ± Mobile Application Target</h3>
            
            <div className="form-group">
              <label>Upload Application File (APK/IPA) *</label>
              <div 
                className={`file-upload-zone ${selectedFile ? 'has-file' : ''} ${fileError ? 'has-error' : ''}`}
                onDrop={handleFileDrop}
                onDragOver={handleDragOver}
              >
                <input
                  type="file"
                  id="app_file"
                  accept=".apk,.ipa"
                  onChange={handleFileSelect}
                  className="file-input"
                />
                <div className="file-upload-content">
                  {selectedFile ? (
                    <>
                      <span className="file-icon">{selectedFile.name.endsWith('.apk') ? 'Ã°Å¸Â¤â€“' : 'Ã°Å¸ÂÅ½'}</span>
                      <span className="file-name">{selectedFile.name}</span>
                      <span className="file-size">({(selectedFile.size / (1024 * 1024)).toFixed(2)} MB)</span>
                      <button 
                        type="button" 
                        className="file-remove-btn"
                        onClick={() => { setSelectedFile(null); setFormData(prev => ({ ...prev, app_path: '' })); }}
                      >
                        Ã¢Å“â€¢ Remove
                      </button>
                    </>
                  ) : (
                    <>
                      <span className="upload-icon">Ã°Å¸â€œÂ¤</span>
                      <span className="upload-text">Drag & drop your APK or IPA file here</span>
                      <span className="upload-or">or</span>
                      <label htmlFor="app_file" className="upload-btn">Browse Files</label>
                    </>
                  )}
                </div>
              </div>
              {fileError && <span className="file-error">Ã¢ÂÅ’ {fileError}</span>}
              <span className="hint">Accepted formats: .apk (Android), .ipa (iOS) Ã¢â‚¬Â¢ Max size: 500MB</span>
            </div>

            <div className="info-box">
              <strong>Ã°Å¸â€œâ€¹ OWASP Mobile Top 10 Coverage:</strong>
              <ul>
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

          {/* SSL Pinning Configuration - Only show after file is selected */}
          {selectedFile && (
            <div className="form-section">
              <div className="section-header">
                <h3>Ã°Å¸â€Â SSL Pinning Configuration</h3>
                <button 
                  type="button" 
                  className="info-toggle-btn"
                  onClick={() => setShowSslInfo(!showSslInfo)}
                >
                  {showSslInfo ? 'Ã¢â€“Â¼ Hide Info' : 'Ã¢Ââ€œ What is SSL Pinning?'}
                </button>
              </div>

              {showSslInfo && (
                <div className="info-box ssl-info">
                  <strong>Ã°Å¸â€œÅ¡ What is SSL Pinning?</strong>
                  <p>
                    <strong>SSL/Certificate Pinning</strong> is a security technique used by mobile apps 
                    to prevent man-in-the-middle (MITM) attacks. When an app uses SSL pinning, it only 
                    trusts specific certificates, making it harder to intercept network traffic.
                  </p>
                  <div className="ssl-comparison">
                    <div className="ssl-type">
                      <span className="ssl-icon">Ã°Å¸â€â€™</span>
                      <strong>SSL Pinned App</strong>
                      <ul>
                        <li>Rejects proxy certificates</li>
                        <li>Harder to analyze traffic</li>
                        <li>Requires Frida to bypass</li>
                        <li>Examples: Banking apps, secure messaging</li>
                      </ul>
                    </div>
                    <div className="ssl-type">
                      <span className="ssl-icon">Ã°Å¸â€â€œ</span>
                      <strong>Unpinned App</strong>
                      <ul>
                        <li>Accepts any valid certificate</li>
                        <li>Easy traffic interception</li>
                        <li>No bypass needed</li>
                        <li>Examples: Basic apps, news readers</li>
                      </ul>
                    </div>
                  </div>
                  <p className="ssl-tip">
                    Ã°Å¸â€™Â¡ <strong>Tip:</strong> If you're unsure, select "I don't know" and we'll attempt 
                    to detect it automatically during the scan.
                  </p>
                </div>
              )}

              <div className="form-group">
                <label>Does this app use SSL Pinning?</label>
                <div className="ssl-option-grid">
                  <div
                    className={`ssl-option-card ${formData.ssl_pinned === 'pinned' ? 'selected' : ''}`}
                    onClick={() => setFormData(prev => ({ ...prev, ssl_pinned: 'pinned', bypass_ssl_pinning: true }))}
                  >
                    <span className="ssl-card-icon">Ã°Å¸â€â€™</span>
                    <span className="ssl-card-title">Yes, SSL Pinned</span>
                    <span className="ssl-card-desc">App rejects proxy certificates</span>
                  </div>
                  <div
                    className={`ssl-option-card ${formData.ssl_pinned === 'unpinned' ? 'selected' : ''}`}
                    onClick={() => setFormData(prev => ({ ...prev, ssl_pinned: 'unpinned', bypass_ssl_pinning: false }))}
                  >
                    <span className="ssl-card-icon">Ã°Å¸â€â€œ</span>
                    <span className="ssl-card-title">No, Not Pinned</span>
                    <span className="ssl-card-desc">App accepts any valid cert</span>
                  </div>
                  <div
                    className={`ssl-option-card ${formData.ssl_pinned === 'unknown' ? 'selected' : ''}`}
                    onClick={() => setFormData(prev => ({ ...prev, ssl_pinned: 'unknown', bypass_ssl_pinning: false }))}
                  >
                    <span className="ssl-card-icon">Ã¢Ââ€œ</span>
                    <span className="ssl-card-title">I Don't Know</span>
                    <span className="ssl-card-desc">Auto-detect during scan</span>
                  </div>
                </div>
              </div>

              {formData.ssl_pinned === 'pinned' && (
                <div className="frida-notice">
                  <div className="frida-header">
                    <span className="frida-icon">Ã°Å¸Ââ„¢</span>
                    <strong>Frida SSL Bypass Enabled</strong>
                  </div>
                  <p>
                    We'll use <strong>Frida</strong> to bypass SSL pinning and intercept HTTPS traffic. 
                    This requires:
                  </p>
                  <ul>
                    <li>Ã¢Å“â€¦ A rooted Android device or jailbroken iOS device</li>
                    <li>Ã¢Å“â€¦ Frida server running on the device</li>
                    <li>Ã¢Å“â€¦ USB debugging enabled (Android) or trusted computer (iOS)</li>
                  </ul>
                  
                  <div className="form-group" style={{ marginTop: '16px' }}>
                    <label htmlFor="device_id">Device ID (optional)</label>
                    <input
                      type="text"
                      id="device_id"
                      name="device_id"
                      value={formData.device_id}
                      onChange={handleChange}
                      placeholder="Leave empty for auto-detect"
                    />
                    <span className="hint">Run 'adb devices' (Android) or 'idevice_id -l' (iOS) to find your device ID</span>
                  </div>
                </div>
              )}

              {formData.ssl_pinned === 'unknown' && (
                <div className="auto-detect-notice">
                  <span className="notice-icon">Ã°Å¸â€Â</span>
                  <p>
                    We'll analyze the app's code to detect SSL pinning implementations. 
                    If pinning is detected, we'll prompt you to connect a device for Frida bypass.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Mobile App Authentication - Show after file is selected */}
          {selectedFile && (
            <div className="form-section">
              <div className="section-header">
                <h3>Ã°Å¸â€â€˜ App Authentication</h3>
                <label className="toggle">
                  <input
                    type="checkbox"
                    checked={mobileAuthEnabled}
                    onChange={(e) => setMobileAuthEnabled(e.target.checked)}
                  />
                  <span className="slider"></span>
                </label>
              </div>
              <p className="section-description">
                Most apps require login before accessing features. Provide credentials to test authenticated surfaces.
              </p>

              {mobileAuthEnabled && (
                <div className="auth-fields mobile-auth">
                  <div className="form-group">
                    <label>Authentication Type</label>
                    <div className="auth-type-grid">
                      <div
                        className={`auth-type-card ${formData.mobile_auth_type === 'email_password' ? 'selected' : ''}`}
                        onClick={() => setFormData(prev => ({ ...prev, mobile_auth_type: 'email_password' }))}
                      >
                        <span className="auth-icon">Ã°Å¸â€œÂ§</span>
                        <span className="auth-name">Email & Password</span>
                      </div>
                      <div
                        className={`auth-type-card ${formData.mobile_auth_type === 'phone_otp' ? 'selected' : ''}`}
                        onClick={() => setFormData(prev => ({ ...prev, mobile_auth_type: 'phone_otp', otp_enabled: true }))}
                      >
                        <span className="auth-icon">Ã°Å¸â€œÂ±</span>
                        <span className="auth-name">Phone + OTP</span>
                      </div>
                      <div
                        className={`auth-type-card ${formData.mobile_auth_type === 'username_password' ? 'selected' : ''}`}
                        onClick={() => setFormData(prev => ({ ...prev, mobile_auth_type: 'username_password' }))}
                      >
                        <span className="auth-icon">Ã°Å¸â€˜Â¤</span>
                        <span className="auth-name">Username & Password</span>
                      </div>
                      <div
                        className={`auth-type-card ${formData.mobile_auth_type === 'social' ? 'selected' : ''}`}
                        onClick={() => setFormData(prev => ({ ...prev, mobile_auth_type: 'social' }))}
                      >
                        <span className="auth-icon">Ã°Å¸â€â€”</span>
                        <span className="auth-name">Social Login</span>
                      </div>
                    </div>
                  </div>

                  {formData.mobile_auth_type === 'email_password' && (
                    <div className="form-row">
                      <div className="form-group">
                        <label htmlFor="mobile_email">Email Address *</label>
                        <input
                          type="email"
                          id="mobile_email"
                          name="mobile_email"
                          value={formData.mobile_email}
                          onChange={handleChange}
                          placeholder="test@example.com"
                        />
                      </div>
                      <div className="form-group">
                        <label htmlFor="mobile_password">Password *</label>
                        <input
                          type="password"
                          id="mobile_password"
                          name="mobile_password"
                          value={formData.mobile_password}
                          onChange={handleChange}
                          placeholder="Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢"
                        />
                      </div>
                    </div>
                  )}

                  {formData.mobile_auth_type === 'username_password' && (
                    <div className="form-row">
                      <div className="form-group">
                        <label htmlFor="mobile_username">Username *</label>
                        <input
                          type="text"
                          id="mobile_username"
                          name="mobile_username"
                          value={formData.mobile_username}
                          onChange={handleChange}
                          placeholder="testuser"
                        />
                      </div>
                      <div className="form-group">
                        <label htmlFor="mobile_password">Password *</label>
                        <input
                          type="password"
                          id="mobile_password"
                          name="mobile_password"
                          value={formData.mobile_password}
                          onChange={handleChange}
                          placeholder="Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢Ã¢â‚¬Â¢"
                        />
                      </div>
                    </div>
                  )}

                  {formData.mobile_auth_type === 'phone_otp' && (
                    <div className="form-group">
                      <label htmlFor="otp_phone">Phone Number *</label>
                      <input
                        type="tel"
                        id="otp_phone"
                        name="otp_phone"
                        value={formData.otp_phone}
                        onChange={handleChange}
                        placeholder="+1 234 567 8900"
                      />
                      <span className="hint">Include country code</span>
                    </div>
                  )}

                  {formData.mobile_auth_type === 'social' && (
                    <div className="social-login-notice">
                      <span className="notice-icon">Ã¢â€žÂ¹Ã¯Â¸Â</span>
                      <p>
                        For social login (Google, Facebook, Apple, etc.), we'll need you to manually 
                        complete the login on the device. We'll monitor the OAuth flow and capture 
                        the authentication tokens for testing.
                      </p>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* OTP Handling - Show if auth enabled and relevant */}
          {selectedFile && mobileAuthEnabled && (formData.mobile_auth_type === 'phone_otp' || formData.mobile_auth_type === 'email_password') && (
            <div className="form-section">
              <div className="section-header">
                <h3>Ã°Å¸â€œÂ² OTP / 2FA Handling</h3>
                <button 
                  type="button" 
                  className="info-toggle-btn"
                  onClick={() => setShowOtpInfo(!showOtpInfo)}
                >
                  {showOtpInfo ? 'Ã¢â€“Â¼ Hide Info' : 'Ã¢Ââ€œ How does OTP work?'}
                </button>
              </div>

              {showOtpInfo && (
                <div className="info-box otp-info">
                  <strong>Ã°Å¸â€œÅ¡ OTP / Two-Factor Authentication</strong>
                  <p>
                    Many apps use OTP (One-Time Password) for additional security. When the app 
                    sends an OTP during login, Jarwis can handle it in several ways:
                  </p>
                  <div className="otp-options-info">
                    <div className="otp-option-info">
                      <strong>Ã°Å¸â€â€ Prompt for OTP</strong>
                      <p>We'll pause and show you a notification to enter the OTP you receive.</p>
                    </div>
                    <div className="otp-option-info">
                      <strong>Ã°Å¸Å¡Â« Disable OTP (Testing)</strong>
                      <p>If you control the test environment, disable OTP temporarily in the backend.</p>
                    </div>
                    <div className="otp-option-info">
                      <strong>Ã°Å¸Â¤â€“ Auto-Read SMS</strong>
                      <p>On rooted devices, we can automatically read incoming SMS to get the OTP.</p>
                    </div>
                  </div>
                </div>
              )}

              <div className="form-group">
                <label>How should we handle OTP / 2FA?</label>
                <div className="otp-option-grid">
                  <div
                    className={`otp-option-card ${formData.otp_handling === 'prompt' ? 'selected' : ''}`}
                    onClick={() => setFormData(prev => ({ ...prev, otp_handling: 'prompt' }))}
                  >
                    <span className="otp-card-icon">Ã°Å¸â€â€</span>
                    <span className="otp-card-title">Prompt Me</span>
                    <span className="otp-card-desc">I'll enter OTP when prompted</span>
                  </div>
                  <div
                    className={`otp-option-card ${formData.otp_handling === 'disable' ? 'selected' : ''}`}
                    onClick={() => setFormData(prev => ({ ...prev, otp_handling: 'disable' }))}
                  >
                    <span className="otp-card-icon">Ã°Å¸Å¡Â«</span>
                    <span className="otp-card-title">Disabled in Backend</span>
                    <span className="otp-card-desc">OTP is turned off for testing</span>
                  </div>
                  <div
                    className={`otp-option-card ${formData.otp_handling === 'auto_read' ? 'selected' : ''}`}
                    onClick={() => setFormData(prev => ({ ...prev, otp_handling: 'auto_read' }))}
                  >
                    <span className="otp-card-icon">Ã°Å¸Â¤â€“</span>
                    <span className="otp-card-title">Auto-Read SMS</span>
                    <span className="otp-card-desc">Requires rooted device</span>
                  </div>
                </div>
              </div>

              {formData.otp_handling === 'prompt' && (
                <div className="otp-prompt-notice">
                  <span className="notice-icon">Ã°Å¸â€â€</span>
                  <p>
                    When the app requests OTP, you'll see a notification in Jarwis to enter the code. 
                    Keep your phone nearby to receive the OTP.
                  </p>
                </div>
              )}

              {formData.otp_handling === 'auto_read' && (
                <div className="otp-auto-notice warning">
                  <span className="notice-icon">Ã¢Å¡Â Ã¯Â¸Â</span>
                  <p>
                    <strong>Requires:</strong> Rooted Android device with Frida server. 
                    We'll hook the SMS receiver to automatically capture and input the OTP.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* MITM Proxy Configuration */}
          {selectedFile && (
            <div className="form-section">
              <div className="section-header">
                <h3>Ã°Å¸â€â‚¬ Traffic Interception (MITM Proxy)</h3>
                <button 
                  type="button" 
                  className="info-toggle-btn"
                  onClick={() => setShowMitmInfo(!showMitmInfo)}
                >
                  {showMitmInfo ? 'Ã¢â€“Â¼ Hide Info' : 'Ã¢Ââ€œ What is MITM?'}
                </button>
              </div>

              {showMitmInfo && (
                <div className="info-box mitm-info">
                  <strong>Ã°Å¸â€œÅ¡ Man-in-the-Middle (MITM) Proxy</strong>
                  <p>
                    MITM proxy intercepts all network traffic between the app and its servers. 
                    This allows Jarwis to:
                  </p>
                  <ul>
                    <li>Ã°Å¸â€Â Discover all API endpoints the app communicates with</li>
                    <li>Ã°Å¸â€Â Analyze authentication tokens and session handling</li>
                    <li>Ã°Å¸â€œÂ Log all requests/responses for vulnerability analysis</li>
                    <li>Ã°Å¸Å½Â¯ Test for injection flaws, IDOR, and broken access controls</li>
                    <li>Ã°Å¸Â¤â€“ Feed traffic data to AI for intelligent attack recommendations</li>
                  </ul>
                  <p className="mitm-tip">
                    Ã°Å¸â€™Â¡ This is the same approach used in web app testing - we use mitmproxy to 
                    capture and analyze all HTTP/HTTPS traffic.
                  </p>
                </div>
              )}

              <label className="checkbox-label mitm-toggle">
                <input
                  type="checkbox"
                  name="mitm_enabled"
                  checked={formData.mitm_enabled}
                  onChange={handleChange}
                />
                <span>Enable Traffic Interception</span>
                <span className="recommended-badge">Recommended</span>
              </label>

              {formData.mitm_enabled && (
                <div className="mitm-config">
                  <div className="form-row">
                    <div className="form-group">
                      <label htmlFor="mitm_port">Proxy Port</label>
                      <input
                        type="number"
                        id="mitm_port"
                        name="mitm_port"
                        value={formData.mitm_port}
                        onChange={handleChange}
                        min="1024"
                        max="65535"
                      />
                      <span className="hint">Default: 8080</span>
                    </div>
                  </div>

                  <div className="mitm-device-setup">
                    <strong>Ã°Å¸â€œÂ± Device Configuration Required:</strong>
                    <ol>
                      <li>Connect device to same WiFi as this computer</li>
                      <li>Set proxy: <code>YOUR_IP:{formData.mitm_port}</code></li>
                      <li>Install mitmproxy CA certificate on device</li>
                    </ol>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* App Unpacking & AI Analysis */}
          {selectedFile && (
            <div className="form-section">
              <h3>Ã°Å¸â€Â§ Extraction & Analysis</h3>
              
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  name="enable_unpacking"
                  checked={formData.enable_unpacking}
                  onChange={handleChange}
                />
                <span>Unpack & Decompile Application</span>
                <span className="recommended-badge">Recommended</span>
              </label>
              <span className="hint" style={{ marginLeft: '28px', display: 'block' }}>
                Extracts APK/IPA contents to find hardcoded secrets, API keys, credentials, 
                and sensitive data in code/resources
              </span>

              <label className="checkbox-label" style={{ marginTop: '12px' }}>
                <input
                  type="checkbox"
                  name="ai_analysis"
                  checked={formData.ai_analysis}
                  onChange={handleChange}
                />
                <span>Enable AI-Powered Analysis (Jarwis LLM)</span>
                <span className="recommended-badge">Recommended</span>
              </label>
              <span className="hint" style={{ marginLeft: '28px', display: 'block' }}>
                Uses Jarwis AGI to analyze code patterns, suggest attack vectors, and 
                prioritize findings based on exploitability
              </span>
            </div>
          )}

          <div className="form-section">
            <h3>Ã°Å¸â€Â¬ Advanced Analysis Options</h3>
            
            <label className="checkbox-label">
              <input
                type="checkbox"
                name="runtime_analysis"
                checked={formData.runtime_analysis}
                onChange={handleChange}
              />
              <span>Enable Full Runtime Analysis (hooks all security-sensitive APIs)</span>
            </label>
            <span className="hint" style={{ marginLeft: '28px', display: 'block' }}>
              Monitors crypto operations, file access, keychain, and more via Frida
            </span>
          </div>
        </>
      )}

      {/* Cloud Infrastructure Scan Form */}
      {formData.scan_type === 'cloud' && (
        <>
          <div className="form-section">
            <h3>Ã¢ËœÂÃ¯Â¸Â Cloud Provider</h3>
            
            <div className="cloud-provider-grid">
              <div
                className={`cloud-provider-card ${formData.provider === 'aws' ? 'selected' : ''}`}
                onClick={() => setFormData(prev => ({ ...prev, provider: 'aws' }))}
              >
                <span className="provider-icon">Ã°Å¸Å¸Â </span>
                <span className="provider-name">Amazon AWS</span>
                {cloudProviders.aws?.available && <span className="status-badge available">SDK Ready</span>}
              </div>
              <div
                className={`cloud-provider-card ${formData.provider === 'azure' ? 'selected' : ''}`}
                onClick={() => setFormData(prev => ({ ...prev, provider: 'azure' }))}
              >
                <span className="provider-icon">Ã°Å¸â€Âµ</span>
                <span className="provider-name">Microsoft Azure</span>
                {cloudProviders.azure?.available && <span className="status-badge available">SDK Ready</span>}
              </div>
              <div
                className={`cloud-provider-card ${formData.provider === 'gcp' ? 'selected' : ''}`}
                onClick={() => setFormData(prev => ({ ...prev, provider: 'gcp' }))}
              >
                <span className="provider-icon">Ã°Å¸â€Â´</span>
                <span className="provider-name">Google Cloud</span>
                {cloudProviders.gcp?.available && <span className="status-badge available">SDK Ready</span>}
              </div>
              <div
                className={`cloud-provider-card ${formData.provider === 'all' ? 'selected' : ''}`}
                onClick={() => setFormData(prev => ({ ...prev, provider: 'all' }))}
              >
                <span className="provider-icon">Ã°Å¸Å’Â</span>
                <span className="provider-name">All Providers</span>
              </div>
            </div>
          </div>

          {/* AWS Configuration */}
          {(formData.provider === 'aws' || formData.provider === 'all') && (
            <div className="form-section">
              <h3>Ã°Å¸Å¸Â  AWS Configuration</h3>
              
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="aws_profile">AWS Profile</label>
                  <input
                    type="text"
                    id="aws_profile"
                    name="aws_profile"
                    value={formData.aws_profile}
                    onChange={handleChange}
                    placeholder="default"
                  />
                  <span className="hint">AWS CLI profile name (leave empty for default)</span>
                </div>

                <div className="form-group">
                  <label htmlFor="aws_region">AWS Region</label>
                  <select
                    id="aws_region"
                    name="aws_region"
                    value={formData.aws_region}
                    onChange={handleChange}
                    className="form-select"
                  >
                    {awsRegions.map(region => (
                      <option key={region} value={region}>{region}</option>
                    ))}
                  </select>
                </div>
              </div>

              <div className="info-box">
                <strong>Ã°Å¸â€Â AWS Security Checks:</strong>
                <ul>
                  <li>IAM: Root MFA, access keys, policies</li>
                  <li>S3: Public access, encryption, versioning</li>
                  <li>EC2: Security groups, IMDSv2</li>
                  <li>RDS: Public access, encryption, backups</li>
                  <li>Lambda: Deprecated runtimes, secrets in env</li>
                  <li>CloudTrail: Multi-region, log validation</li>
                </ul>
              </div>
            </div>
          )}

          {/* Azure Configuration */}
          {(formData.provider === 'azure' || formData.provider === 'all') && (
            <div className="form-section">
              <h3>Ã°Å¸â€Âµ Azure Configuration</h3>
              
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="azure_subscription">Subscription ID *</label>
                  <input
                    type="text"
                    id="azure_subscription"
                    name="azure_subscription"
                    value={formData.azure_subscription}
                    onChange={handleChange}
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="azure_tenant">Tenant ID (optional)</label>
                  <input
                    type="text"
                    id="azure_tenant"
                    name="azure_tenant"
                    value={formData.azure_tenant}
                    onChange={handleChange}
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  />
                </div>
              </div>

              <div className="info-box">
                <strong>Ã°Å¸â€Â Azure Security Checks:</strong>
                <ul>
                  <li>Storage: HTTPS, public access, encryption</li>
                  <li>VMs: Disk encryption, managed identity</li>
                  <li>NSGs: SSH/RDP from internet</li>
                  <li>SQL: TDE, firewall rules</li>
                  <li>Key Vault: Soft delete, purge protection</li>
                </ul>
              </div>
            </div>
          )}

          {/* GCP Configuration */}
          {(formData.provider === 'gcp' || formData.provider === 'all') && (
            <div className="form-section">
              <h3>Ã°Å¸â€Â´ GCP Configuration</h3>
              
              <div className="form-row">
                <div className="form-group">
                  <label htmlFor="gcp_project">Project ID *</label>
                  <input
                    type="text"
                    id="gcp_project"
                    name="gcp_project"
                    value={formData.gcp_project}
                    onChange={handleChange}
                    placeholder="my-project-123456"
                  />
                </div>

                <div className="form-group">
                  <label htmlFor="gcp_credentials">Service Account JSON Path</label>
                  <input
                    type="text"
                    id="gcp_credentials"
                    name="gcp_credentials"
                    value={formData.gcp_credentials}
                    onChange={handleChange}
                    placeholder="C:\path\to\service-account.json"
                  />
                  <span className="hint">Leave empty to use default credentials</span>
                </div>
              </div>

              <div className="info-box">
                <strong>Ã°Å¸â€Â GCP Security Checks:</strong>
                <ul>
                  <li>Storage: Public access, uniform access, versioning</li>
                  <li>Compute: Default SA, public IPs</li>
                  <li>Cloud SQL: SSL, authorized networks, backups</li>
                  <li>IAM: Overly permissive roles, public bindings</li>
                  <li>Firewall: SSH/RDP from 0.0.0.0/0</li>
                </ul>
              </div>
            </div>
          )}
        </>
      )}

      <div className="form-actions">
        <button type="submit" className="btn-primary" disabled={isLoading}>
          {isLoading ? (
            <>
              <span className="spinner"></span>
              Starting Scan...
            </>
          ) : (
            <>
              Ã°Å¸Å¡â‚¬ Start {formData.scan_type === 'web' ? 'Penetration Test' : 
                       formData.scan_type === 'mobile' ? 'Mobile Security Scan' : 
                       'Cloud Security Scan'}
            </>
          )}
        </button>
      </div>

      <div className="disclaimer">
        Ã¢Å¡Â Ã¯Â¸Â <strong>Warning:</strong> Only scan systems you own or have explicit written permission to test.
        Unauthorized access is illegal.
      </div>
    </form>
  );
};

export default ScanForm;
