import React, { useState, useEffect, useCallback, useRef } from 'react';
import ScanForm from './components/ScanForm';
import ScanStatus from './components/ScanStatus';
import ChatbotTab from './components/ChatbotTab';
import OTPModal from './components/OTPModal';
import EmulatorManager from './components/EmulatorManager';
import ScanHistory from './components/ScanHistory';
import { startScan, healthCheck, listReports, getReportUrl, getRunningScans, getLastScan, listScans } from './services/api';
import './App.css';
import jarwisLogo from './assets/jarwis-logo.png';

function App() {
  const [view, setView] = useState('form'); // 'form', 'scanning', 'reports', 'history', 'chat', 'emulator'
  const [previousView, setPreviousView] = useState(null); // Track previous view for back navigation
  const [currentScanId, setCurrentScanId] = useState(null);
  const [activeMobileScanId, setActiveMobileScanId] = useState(null); // Preserve mobile scan state
  const [isLoading, setIsLoading] = useState(false);
  const [apiStatus, setApiStatus] = useState('checking');
  const [lastHealthCheck, setLastHealthCheck] = useState(null);
  const [reports, setReports] = useState([]);
  const [error, setError] = useState(null);
  const [hasRunningScan, setHasRunningScan] = useState(false);
  const [lastScan, setLastScan] = useState(null);
  const [scanHistory, setScanHistory] = useState([]);
  const [serverLogs, setServerLogs] = useState([]);
  
  // Preserve component state when switching tabs
  const emulatorStateRef = useRef(null);
  
  // OTP Modal state
  const [showOTPModal, setShowOTPModal] = useState(false);
  const [otpConfig, setOtpConfig] = useState({
    phoneNumber: '',
    scanId: '',
    timeoutSeconds: 60
  });

  const checkApiHealth = useCallback(async () => {
    try {
      await healthCheck();
      setApiStatus('connected');
      setLastHealthCheck(new Date());
    } catch (err) {
      setApiStatus('disconnected');
    }
  }, []);

  useEffect(() => {
    checkApiHealth();
    loadReports();
    checkForRunningScan();
    loadScanHistory();
  }, [checkApiHealth]);

  // Auto-refresh API health check every 10 seconds
  useEffect(() => {
    const healthInterval = setInterval(() => {
      checkApiHealth();
    }, 10000);
    return () => clearInterval(healthInterval);
  }, [checkApiHealth]);

  // Periodically check for running scans
  useEffect(() => {
    const interval = setInterval(() => {
      if (view !== 'scanning') {
        checkForRunningScan();
      }
    }, 5000);
    return () => clearInterval(interval);
  }, [view]);

  const checkForRunningScan = async () => {
    try {
      const running = await getRunningScans();
      if (running && running.length > 0) {
        setHasRunningScan(true);
        // If we don't have a current scan, use the first running one
        if (!currentScanId && view !== 'scanning') {
          setCurrentScanId(running[0].id);
        }
      } else {
        setHasRunningScan(false);
      }
    } catch (err) {
      console.error('Failed to check running scans:', err);
    }
  };

  const loadScanHistory = async () => {
    try {
      const scans = await listScans();
      setScanHistory(scans);
      // Also get the last scan for quick access
      if (scans && scans.length > 0) {
        const sorted = [...scans].sort((a, b) => 
          new Date(b.started_at) - new Date(a.started_at)
        );
        setLastScan(sorted[0]);
      }
    } catch (err) {
      console.error('Failed to load scan history:', err);
    }
  };

  const loadReports = async () => {
    try {
      const data = await listReports();
      setReports(data);
    } catch (err) {
      console.error('Failed to load reports:', err);
    }
  };

  const handleStartScan = async (formData, selectedFile = null) => {
    setIsLoading(true);
    setError(null);
    
    try {
      let result;
      
      // Handle mobile scan with file upload
      if (formData.scan_type === 'mobile' && selectedFile) {
        const uploadFormData = new FormData();
        uploadFormData.append('app_file', selectedFile);
        uploadFormData.append('runtime_analysis', formData.runtime_analysis);
        uploadFormData.append('device_id', formData.device_id || '');
        
        // SSL Pinning configuration
        uploadFormData.append('ssl_pinned', formData.ssl_pinned || 'unknown');
        uploadFormData.append('bypass_ssl_pinning', formData.bypass_ssl_pinning || false);
        
        // Authentication configuration
        uploadFormData.append('mobile_auth_enabled', formData.mobile_auth_enabled || false);
        uploadFormData.append('mobile_auth_type', formData.mobile_auth_type || 'email_password');
        uploadFormData.append('mobile_email', formData.mobile_email || '');
        uploadFormData.append('mobile_username', formData.mobile_username || '');
        uploadFormData.append('mobile_password', formData.mobile_password || '');
        
        // OTP configuration
        uploadFormData.append('otp_enabled', formData.otp_enabled || false);
        uploadFormData.append('otp_handling', formData.otp_handling || 'prompt');
        uploadFormData.append('otp_phone', formData.otp_phone || '');
        
        // MITM and analysis configuration
        uploadFormData.append('mitm_enabled', formData.mitm_enabled !== false);  // Default true
        uploadFormData.append('mitm_port', formData.mitm_port || 8080);
        uploadFormData.append('enable_unpacking', formData.enable_unpacking !== false);  // Default true
        uploadFormData.append('ai_analysis', formData.ai_analysis !== false);  // Default true
        
        const response = await fetch('http://localhost:5000/api/scan/mobile/upload', {
          method: 'POST',
          body: uploadFormData
        });
        
        result = await response.json();
        
        if (!response.ok) {
          throw new Error(result.error || 'Failed to upload file');
        }
      } else {
        result = await startScan(formData);
      }
      
      setCurrentScanId(result.scan_id);
      setHasRunningScan(true);
      
      // Track mobile scans separately
      if (formData.scan_type === 'mobile') {
        setActiveMobileScanId(result.scan_id);
      }
      
      navigateToView('scanning');
    } catch (err) {
      setError(err.message || err.response?.data?.error || 'Failed to start scan. Make sure the API server is running.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleScanComplete = () => {
    setHasRunningScan(false);
    loadReports();
    loadScanHistory();
    // Auto-switch to reports view after a short delay
    setTimeout(() => {
      loadReports();
    }, 1000);
  };

  const handleNewScan = () => {
    setCurrentScanId(null);
    navigateToView('form');
    loadReports();
    loadScanHistory();
  };

  const handleViewLastScan = () => {
    if (lastScan) {
      setCurrentScanId(lastScan.id);
      navigateToView('scanning');
    }
  };

  const handleViewRunningScan = () => {
    if (currentScanId) {
      navigateToView('scanning');
    }
  };

  // OTP Modal handlers
  const handleOTPSubmit = async (otpValue) => {
    try {
      const response = await fetch('http://localhost:5000/api/mobile/auth/otp/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: otpConfig.scanId,
          otp: otpValue,
          phone_number: otpConfig.phoneNumber
        })
      });
      
      const result = await response.json();
      
      if (result.authenticated) {
        setShowOTPModal(false);
        // Continue with scan
      } else {
        throw new Error(result.message || 'OTP verification failed');
      }
    } catch (err) {
      throw err;
    }
  };

  const handleOTPResend = async () => {
    try {
      await fetch('http://localhost:5000/api/mobile/auth/otp/resend', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scan_id: otpConfig.scanId,
          phone_number: otpConfig.phoneNumber
        })
      });
    } catch (err) {
      console.error('Failed to resend OTP:', err);
    }
  };

  const handleOTPCancel = () => {
    setShowOTPModal(false);
  };

  // Enhanced navigation that preserves state
  const navigateToView = useCallback((newView) => {
    if (newView !== view) {
      setPreviousView(view);
      setView(newView);
    }
  }, [view]);

  // Handle viewing a specific scan from history
  const handleViewScan = useCallback((scan) => {
    if (scan) {
      setCurrentScanId(scan.id);
      if (scan.type === 'mobile') {
        setActiveMobileScanId(scan.id);
      }
      navigateToView('scanning');
    }
  }, [navigateToView]);

  // Resume a running scan
  const handleResumeScan = useCallback((scan) => {
    if (scan && scan.status === 'running') {
      setCurrentScanId(scan.id);
      if (scan.type === 'mobile') {
        setActiveMobileScanId(scan.id);
      }
      navigateToView('scanning');
    }
  }, [navigateToView]);

  return (
    <div className="app">
      {/* OTP Modal */}
      <OTPModal
        isOpen={showOTPModal}
        onSubmit={handleOTPSubmit}
        onResend={handleOTPResend}
        onCancel={handleOTPCancel}
        phoneNumber={otpConfig.phoneNumber}
        timeoutSeconds={otpConfig.timeoutSeconds}
      />
      
      <header className="header">
        <div className="header-content">
          <div className="logo">
            <img src="/jarwis-logo.png" alt="Jarwis" className="logo-image" />
            <div className="logo-text">
              <h1>JARWIS</h1>
              <span className="tagline">Security Testing by BKD Labs</span>
            </div>
          </div>
          
          <nav className="nav">
            <button 
              className={`nav-btn ${view === 'form' ? 'active' : ''}`}
              onClick={() => navigateToView('form')}
            >
              ðŸŽ¯ New Scan
            </button>
            {hasRunningScan && currentScanId && (
              <button 
                className={`nav-btn running-scan ${view === 'scanning' ? 'active' : ''}`}
                onClick={() => navigateToView('scanning')}
              >
                ðŸ”„ Live Scan
                <span className="pulse-dot"></span>
              </button>
            )}
            {lastScan && !hasRunningScan && (
              <button 
                className={`nav-btn last-scan ${view === 'scanning' ? 'active' : ''}`}
                onClick={handleViewLastScan}
              >
                ðŸ• Last Scan
              </button>
            )}
            <button 
              className={`nav-btn ${view === 'reports' ? 'active' : ''}`}
              onClick={() => { navigateToView('reports'); loadReports(); }}
            >
              ðŸ“Š Reports {reports.length > 0 && <span className="badge">{reports.length}</span>}
            </button>
            <button 
              className={`nav-btn ${view === 'history' ? 'active' : ''}`}
              onClick={() => navigateToView('history')}
            >
              ðŸ“œ History {scanHistory.length > 0 && <span className="badge">{scanHistory.length}</span>}
            </button>
            <button 
              className={`nav-btn ai-assistant ${view === 'chat' ? 'active' : ''}`}
              onClick={() => navigateToView('chat')}
            >
              <img src={jarwisLogo} alt="" className="nav-icon" /> AI Assistant
            </button>
            <button 
              className={`nav-btn ${view === 'emulator' ? 'active' : ''}`}
              onClick={() => navigateToView('emulator')}
              title="Android Emulator for mobile security testing"
            >
              ðŸ¤– Emulator
              {activeMobileScanId && <span className="badge mobile-active">â—</span>}
            </button>
          </nav>

          <div className={`api-status ${apiStatus}`}>
            <span className="status-dot"></span>
            <span>API {apiStatus === 'connected' ? 'Connected' : apiStatus === 'checking' ? 'Checking...' : 'Disconnected'}</span>
          </div>
        </div>
      </header>

      <main className="main">
        {apiStatus === 'disconnected' && (
          <div className="alert alert-error">
            <strong>âš ï¸ API Server Not Connected</strong>
            <p>Please start the backend server: <code>python api/app.py</code></p>
            <button onClick={checkApiHealth}>Retry Connection</button>
          </div>
        )}

        {error && (
          <div className="alert alert-error">
            <strong>Error:</strong> {error}
            <button onClick={() => setError(null)}>Ã—</button>
          </div>
        )}

        {view === 'form' && (
          <div className="content-wrapper">
            <div className="page-header">
              <h2>Start a New Penetration Test</h2>
              <p>Configure your target and authentication settings, then launch the OWASP Top 10 scan.</p>
            </div>
            <ScanForm onStartScan={handleStartScan} isLoading={isLoading} />
          </div>
        )}

        {view === 'scanning' && currentScanId && (
          <div className="content-wrapper">
            <ScanStatus 
              scanId={currentScanId} 
              onScanComplete={handleScanComplete}
              onNewScan={handleNewScan}
            />
          </div>
        )}

        {view === 'reports' && (
          <div className="content-wrapper">
            <div className="page-header">
              <h2>Scan Reports</h2>
              <p>View and download previous penetration test reports.</p>
              <button className="btn-secondary refresh-btn" onClick={loadReports}>
                ðŸ”„ Refresh
              </button>
            </div>
            
            {reports.length === 0 ? (
              <div className="empty-state">
                <span className="empty-icon">ðŸ“­</span>
                <h3>No Reports Yet</h3>
                <p>Complete a scan to generate your first report.</p>
                <button className="btn-primary" onClick={() => setView('form')}>
                  Start a Scan
                </button>
              </div>
            ) : (
              <div className="reports-grid">
                {reports.map((report, index) => (
                  <div key={index} className="report-card">
                    <div className="report-icon">ðŸ“„</div>
                    <div className="report-info">
                      <h4>{report.name}</h4>
                      <span className="report-date">
                        {new Date(report.created * 1000).toLocaleString()}
                      </span>
                      {report.dir && (
                        <span className="report-dir">{report.dir}</span>
                      )}
                    </div>
                    <a 
                      href={getReportUrl(report)} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className="btn-view"
                    >
                      View
                    </a>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {view === 'history' && (
          <div className="content-wrapper full-width">
            <ScanHistory 
              onViewScan={handleViewScan}
              onResumeScan={handleResumeScan}
              onNewScan={handleNewScan}
              currentScanId={currentScanId}
            />
          </div>
        )}

        {view === 'chat' && (
          <div className="content-wrapper chat-view">
            <ChatbotTab 
              scanId={currentScanId}
              scanHistory={scanHistory}
              currentScan={lastScan}
              serverLogs={serverLogs}
            />
          </div>
        )}

        {view === 'emulator' && (
          <div className="content-wrapper emulator-view">
            <EmulatorManager 
              preserveState={true}
              stateRef={emulatorStateRef}
              activeMobileScanId={activeMobileScanId}
              onMobileScanStart={(scanId) => {
                setActiveMobileScanId(scanId);
                setCurrentScanId(scanId);
              }}
            />
          </div>
        )}
      </main>

      <footer className="footer">
        <p>JARWIS AGI PEN TEST â€¢ OWASP Top 10 Security Scanner â€¢ Use responsibly on authorized targets only</p>
      </footer>
    </div>
  );
}

export default App;
