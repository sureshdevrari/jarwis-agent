import React, { useState, useEffect, useCallback, useImperativeHandle, forwardRef } from 'react';
import './EmulatorManager.css';

const EmulatorManager = forwardRef(({ 
  preserveState = false, 
  stateRef = null, 
  activeMobileScanId = null,
  onMobileScanStart = null 
}, ref) => {
  const [status, setStatus] = useState(() => {
    // Restore state from ref if preserveState is enabled
    if (preserveState && stateRef?.current?.status) {
      return stateRef.current.status;
    }
    return {
      sdk_installed: false,
      emulator_installed: false,
      platform_tools_installed: false,
      running: false,
      device_id: '',
      frida_installed: false,
      proxy_configured: false,
      ca_installed: false,
      setup_in_progress: false,
      setup_step: '',
      setup_progress: 0,
      setup_error: null
    };
  });
  const [packages, setPackages] = useState(() => {
    if (preserveState && stateRef?.current?.packages) {
      return stateRef.current.packages;
    }
    return [];
  });
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState(() => {
    if (preserveState && stateRef?.current?.message) {
      return stateRef.current.message;
    }
    return '';
  });
  const [headless, setHeadless] = useState(false);
  
  // Dynamic Crawl State
  const [crawlFile, setCrawlFile] = useState(null);
  const [crawlDuration, setCrawlDuration] = useState(60);
  const [crawling, setCrawling] = useState(() => {
    if (preserveState && stateRef?.current?.crawling) {
      return stateRef.current.crawling;
    }
    return false;
  });
  const [crawlResult, setCrawlResult] = useState(() => {
    if (preserveState && stateRef?.current?.crawlResult) {
      return stateRef.current.crawlResult;
    }
    return null;
  });
  const [crawlId, setCrawlId] = useState(() => {
    if (preserveState && stateRef?.current?.crawlId) {
      return stateRef.current.crawlId;
    }
    return null;
  });

  // Real-time logs and Frida status
  const [logs, setLogs] = useState([]);
  const [fridaStatus, setFridaStatus] = useState({ installed: false, running: false, hooked_processes: [] });
  const [showLogs, setShowLogs] = useState(true);
  const [logFilter, setLogFilter] = useState('all'); // all, emulator, frida, adb, ssl, proxy
  const [autoScroll, setAutoScroll] = useState(true);
  const logsEndRef = React.useRef(null);

  // Save state to ref whenever it changes
  useEffect(() => {
    if (preserveState && stateRef) {
      stateRef.current = {
        status,
        packages,
        message,
        crawling,
        crawlResult,
        crawlId
      };
    }
  }, [preserveState, stateRef, status, packages, message, crawling, crawlResult, crawlId]);

  // Expose methods to parent via ref
  useImperativeHandle(ref, () => ({
    getStatus: () => status,
    getCrawlId: () => crawlId,
    refresh: fetchStatus
  }));

  const fetchStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/emulator/status');
      const data = await res.json();
      setStatus(data);
      
      if (data.running) {
        fetchPackages();
      }
    } catch (err) {
      console.error('Failed to fetch status:', err);
    }
  }, []);

  const fetchPackages = async () => {
    try {
      const res = await fetch('/api/emulator/packages');
      const data = await res.json();
      if (data.success) {
        setPackages(data.packages);
      }
    } catch (err) {
      console.error('Failed to fetch packages:', err);
    }
  };

  // Fetch real-time logs
  const fetchLogs = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: '100' });
      if (logFilter !== 'all') params.append('source', logFilter);
      
      const res = await fetch(`/api/emulator/logs?${params}`);
      const data = await res.json();
      if (data.logs) {
        setLogs(data.logs);
      }
    } catch (err) {
      console.error('Failed to fetch logs:', err);
    }
  }, [logFilter]);

  // Fetch Frida status
  const fetchFridaStatus = useCallback(async () => {
    try {
      const res = await fetch('/api/emulator/frida/status');
      const data = await res.json();
      setFridaStatus(data);
    } catch (err) {
      console.error('Failed to fetch Frida status:', err);
    }
  }, []);

  // Auto-scroll logs
  useEffect(() => {
    if (autoScroll && logsEndRef.current) {
      logsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [logs, autoScroll]);

  useEffect(() => {
    fetchStatus();
    fetchLogs();
    const interval = setInterval(fetchStatus, 5000);
    const logsInterval = setInterval(fetchLogs, 2000);
    const fridaInterval = setInterval(fetchFridaStatus, 10000);
    return () => {
      clearInterval(interval);
      clearInterval(logsInterval);
      clearInterval(fridaInterval);
    };
  }, [fetchStatus, fetchLogs, fetchFridaStatus]);

  const handleSetup = async () => {
    setLoading(true);
    setMessage('Starting emulator setup...');
    
    try {
      const res = await fetch('/api/emulator/setup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headless, api_level: 'android-33', ram_mb: 4096 })
      });
      const data = await res.json();
      setMessage(data.message);
    } catch (err) {
      setMessage('Failed to start setup: ' + err.message);
    }
    
    setLoading(false);
  };

  const handleStart = async () => {
    setLoading(true);
    setMessage('Starting emulator...');
    
    try {
      const res = await fetch('/api/emulator/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ headless })
      });
      const data = await res.json();
      setMessage(data.success ? 'Emulator started!' : data.error);
      fetchStatus();
    } catch (err) {
      setMessage('Failed to start: ' + err.message);
    }
    
    setLoading(false);
  };

  const handleStop = async () => {
    setLoading(true);
    setMessage('Stopping emulator...');
    
    try {
      const res = await fetch('/api/emulator/stop', { method: 'POST' });
      const data = await res.json();
      setMessage(data.success ? 'Emulator stopped' : data.error);
      fetchStatus();
    } catch (err) {
      setMessage('Failed to stop: ' + err.message);
    }
    
    setLoading(false);
  };

  const handleStartFrida = async () => {
    setLoading(true);
    setMessage('Starting Frida server...');
    
    try {
      const res = await fetch('/api/emulator/frida/start', { method: 'POST' });
      const data = await res.json();
      setMessage(data.success ? 'Frida server running!' : data.error);
      fetchStatus();
    } catch (err) {
      setMessage('Failed: ' + err.message);
    }
    
    setLoading(false);
  };

  // Dynamic Crawl Functions
  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      const ext = file.name.toLowerCase().slice(-4);
      if (ext === '.apk' || ext === '.ipa') {
        setCrawlFile(file);
        setMessage(`Selected: ${file.name}`);
      } else {
        setMessage('Please select an APK or IPA file');
      }
    }
  };

  const handleStartCrawl = async () => {
    if (!crawlFile) {
      setMessage('Please select an APK file first');
      return;
    }

    setCrawling(true);
    setCrawlResult(null);
    setMessage('Uploading and starting dynamic crawl...');

    try {
      // First upload the file
      const formData = new FormData();
      formData.append('app_file', crawlFile);

      const uploadRes = await fetch('/api/scan/mobile/upload', {
        method: 'POST',
        body: formData
      });
      const uploadData = await uploadRes.json();

      if (!uploadData.app_path) {
        throw new Error(uploadData.error || 'Upload failed');
      }

      // Start dynamic crawl
      const crawlRes = await fetch('/api/mobile/crawl/dynamic', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          app_path: uploadData.app_path,
          duration: crawlDuration
        })
      });
      const crawlData = await crawlRes.json();
      
      if (crawlData.crawl_id) {
        setCrawlId(crawlData.crawl_id);
        setMessage('Dynamic crawl started! Monitoring APIs...');
        pollCrawlStatus(crawlData.crawl_id);
      } else {
        throw new Error(crawlData.error || 'Failed to start crawl');
      }

    } catch (err) {
      setMessage('Error: ' + err.message);
      setCrawling(false);
    }
  };

  const pollCrawlStatus = async (id) => {
    try {
      const res = await fetch(`/api/mobile/crawl/${id}/status`);
      const data = await res.json();

      if (data.status === 'completed') {
        setCrawling(false);
        setCrawlResult(data);
        setMessage(`✅ Crawl complete! Found ${data.stats?.total_apis || 0} APIs`);
      } else if (data.status === 'error') {
        setCrawling(false);
        setMessage('Crawl failed: ' + (data.error || 'Unknown error'));
      } else {
        // Still running, poll again
        setTimeout(() => pollCrawlStatus(id), 3000);
      }
    } catch (err) {
      setCrawling(false);
      setMessage('Error checking status: ' + err.message);
    }
  };

  return (
    <div className="emulator-manager">
      <div className="emulator-header">
        <h2>🤖 Android Emulator</h2>
        <p className="subtitle">
          Virtual device for mobile security testing with Frida SSL bypass
        </p>
      </div>

      {/* Status Grid */}
      <div className="status-grid">
        <div className={`status-item ${status.sdk_installed ? 'active' : ''}`}>
          <span className="status-icon">{status.sdk_installed ? '✅' : '❌'}</span>
          <span className="status-label">SDK</span>
        </div>
        <div className={`status-item ${status.emulator_installed ? 'active' : ''}`}>
          <span className="status-icon">{status.emulator_installed ? '✅' : '❌'}</span>
          <span className="status-label">Emulator</span>
        </div>
        <div className={`status-item ${status.running ? 'active running' : ''}`}>
          <span className="status-icon">{status.running ? '🟢' : '⚫'}</span>
          <span className="status-label">Running</span>
        </div>
        <div className={`status-item ${status.frida_installed ? 'active' : ''}`}>
          <span className="status-icon">{status.frida_installed ? '✅' : '❌'}</span>
          <span className="status-label">Frida</span>
        </div>
        <div className={`status-item ${status.proxy_configured ? 'active' : ''}`}>
          <span className="status-icon">{status.proxy_configured ? '✅' : '❌'}</span>
          <span className="status-label">Proxy</span>
        </div>
        <div className={`status-item ${status.ca_installed ? 'active' : ''}`}>
          <span className="status-icon">{status.ca_installed ? '✅' : '❌'}</span>
          <span className="status-label">CA Cert</span>
        </div>
      </div>

      {/* Setup Progress */}
      {status.setup_in_progress && (
        <div className="setup-progress">
          <div className="progress-header">
            <span>🔧 {status.setup_step}</span>
            <span>{status.setup_progress}%</span>
          </div>
          <div className="progress-bar">
            <div 
              className="progress-fill" 
              style={{ width: `${status.setup_progress}%` }}
            />
          </div>
          <p className="progress-note">
            This may take 10-30 minutes. Do not close the browser.
          </p>
        </div>
      )}

      {/* Setup Error */}
      {status.setup_error && (
        <div className="error-message">
          ❌ Setup Error: {status.setup_error}
        </div>
      )}

      {/* Device Info */}
      {status.running && status.device_id && (
        <div className="device-info">
          <h3>📱 Connected Device</h3>
          <div className="device-details">
            <span className="device-id">{status.device_id}</span>
            <span className="device-status">Online</span>
          </div>
        </div>
      )}

      {/* Options */}
      <div className="options-section">
        <label className="checkbox-option">
          <input
            type="checkbox"
            checked={headless}
            onChange={(e) => setHeadless(e.target.checked)}
          />
          <span>Headless Mode (No GUI - faster)</span>
        </label>
      </div>

      {/* Action Buttons */}
      <div className="action-buttons">
        {!status.sdk_installed || !status.emulator_installed ? (
          <button 
            onClick={handleSetup} 
            disabled={loading || status.setup_in_progress}
            className="btn-primary"
          >
            {status.setup_in_progress ? '⏳ Setup in Progress...' : '🚀 Full Setup'}
          </button>
        ) : !status.running ? (
          <button onClick={handleStart} disabled={loading} className="btn-success">
            ▶️ Start Emulator
          </button>
        ) : (
          <>
            <button onClick={handleStop} disabled={loading} className="btn-danger">
              ⏹️ Stop
            </button>
            {!status.frida_installed && (
              <button onClick={handleStartFrida} disabled={loading} className="btn-warning">
                🔧 Install Frida
              </button>
            )}
          </>
        )}
      </div>

      {/* Message */}
      {message && (
        <div className="message-box">
          {message}
        </div>
      )}

      {/* Installed Packages */}
      {status.running && packages.length > 0 && (
        <div className="packages-section">
          <h3>📦 Installed Apps ({packages.length})</h3>
          <div className="packages-list">
            {packages.slice(0, 10).map((pkg, idx) => (
              <div key={idx} className="package-item">
                {pkg}
              </div>
            ))}
            {packages.length > 10 && (
              <div className="package-more">
                +{packages.length - 10} more
              </div>
            )}
          </div>
        </div>
      )}

      {/* Dynamic Crawl Section */}
      {status.running && (
        <div className="dynamic-crawl-section">
          <h3>🕷️ Dynamic API Discovery</h3>
          <p className="section-desc">
            Upload an APK to automatically discover all API endpoints by running the app with Frida SSL bypass
          </p>
          
          <div className="crawl-controls">
            <div className="file-input-wrapper">
              <input
                type="file"
                accept=".apk,.ipa"
                onChange={handleFileChange}
                id="crawl-file-input"
                disabled={crawling}
              />
              <label htmlFor="crawl-file-input" className="file-label">
                {crawlFile ? crawlFile.name : '📁 Select APK/IPA'}
              </label>
            </div>
            
            <div className="duration-control">
              <label>Duration (seconds):</label>
              <input
                type="number"
                value={crawlDuration}
                onChange={(e) => setCrawlDuration(parseInt(e.target.value) || 60)}
                min="30"
                max="300"
                disabled={crawling}
              />
            </div>
            
            <button 
              onClick={handleStartCrawl} 
              disabled={!crawlFile || crawling}
              className={`btn-crawl ${crawling ? 'crawling' : ''}`}
            >
              {crawling ? '🔄 Crawling...' : '🚀 Start Dynamic Crawl'}
            </button>
          </div>

          {/* Crawl Results */}
          {crawlResult && crawlResult.apis && (
            <div className="crawl-results">
              <h4>📡 Discovered APIs ({crawlResult.apis.length})</h4>
              <div className="crawl-stats">
                <span>GET: {crawlResult.stats?.get_count || 0}</span>
                <span>POST: {crawlResult.stats?.post_count || 0}</span>
                <span>Auth Required: {crawlResult.stats?.auth_apis || 0}</span>
                <span>SSL Bypassed: {crawlResult.stats?.ssl_bypassed ? '✅' : '❌'}</span>
              </div>
              
              <div className="api-list">
                {crawlResult.apis.slice(0, 20).map((api, idx) => (
                  <div key={idx} className={`api-item ${api.method.toLowerCase()}`}>
                    <span className={`method-badge ${api.method.toLowerCase()}`}>
                      {api.method}
                    </span>
                    <span className="api-path">{api.path}</span>
                    <span className="api-base">{api.base_url}</span>
                    {api.requires_auth && <span className="auth-badge">🔒</span>}
                  </div>
                ))}
                {crawlResult.apis.length > 20 && (
                  <div className="api-more">
                    +{crawlResult.apis.length - 20} more APIs discovered
                  </div>
                )}
              </div>
              
              {crawlResult.base_urls && crawlResult.base_urls.length > 0 && (
                <div className="base-urls">
                  <h5>🌐 Base URLs Found:</h5>
                  {crawlResult.base_urls.map((url, idx) => (
                    <div key={idx} className="base-url">{url}</div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Frida Status Panel */}
      {status.running && (
        <div className="frida-status-panel">
          <h3>🔧 Frida Status</h3>
          <div className="frida-grid">
            <div className={`frida-item ${fridaStatus.installed ? 'active' : ''}`}>
              <span className="frida-icon">{fridaStatus.installed ? '✅' : '❌'}</span>
              <span>Installed</span>
            </div>
            <div className={`frida-item ${fridaStatus.running ? 'active running' : ''}`}>
              <span className="frida-icon">{fridaStatus.running ? '🟢' : '⚫'}</span>
              <span>Server Running</span>
            </div>
            <div className="frida-item">
              <span className="frida-icon">📦</span>
              <span>v{fridaStatus.version || 'N/A'}</span>
            </div>
            <div className="frida-item">
              <span className="frida-icon">🔍</span>
              <span>{fridaStatus.hooked_processes?.length || 0} Processes</span>
            </div>
          </div>
          
          {fridaStatus.hooked_processes && fridaStatus.hooked_processes.length > 0 && (
            <div className="hooked-processes">
              <h4>👁️ Visible Processes</h4>
              <div className="process-list">
                {fridaStatus.hooked_processes.slice(0, 10).map((p, idx) => (
                  <div key={idx} className="process-item">
                    <span className="process-pid">{p.pid}</span>
                    <span className="process-name">{p.name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Real-time Logs Panel */}
      <div className="logs-panel">
        <div className="logs-header">
          <h3>📋 Real-time Logs</h3>
          <div className="logs-controls">
            <select 
              value={logFilter} 
              onChange={(e) => setLogFilter(e.target.value)}
              className="log-filter"
            >
              <option value="all">All Sources</option>
              <option value="emulator">🤖 Emulator</option>
              <option value="frida">🔧 Frida</option>
              <option value="adb">📱 ADB</option>
              <option value="ssl">🔒 SSL</option>
              <option value="proxy">🌐 Proxy</option>
            </select>
            <label className="auto-scroll-toggle">
              <input
                type="checkbox"
                checked={autoScroll}
                onChange={(e) => setAutoScroll(e.target.checked)}
              />
              Auto-scroll
            </label>
            <button 
              className="btn-toggle-logs"
              onClick={() => setShowLogs(!showLogs)}
            >
              {showLogs ? '▼ Hide' : '▶ Show'}
            </button>
            <button 
              className="btn-clear-logs"
              onClick={async () => {
                await fetch('/api/emulator/logs/clear', { method: 'POST' });
                setLogs([]);
              }}
            >
              🗑️ Clear
            </button>
          </div>
        </div>
        
        {showLogs && (
          <div className="logs-container">
            {logs.length === 0 ? (
              <div className="no-logs">
                <span>📭</span>
                <p>No logs yet. Start the emulator to see activity.</p>
              </div>
            ) : (
              <div className="logs-list">
                {logs.map((log, idx) => (
                  <div key={idx} className={`log-entry ${log.level}`}>
                    <span className="log-time">
                      {new Date(log.timestamp).toLocaleTimeString()}
                    </span>
                    <span className={`log-source ${log.source}`}>
                      {log.source === 'emulator' && '🤖'}
                      {log.source === 'frida' && '🔧'}
                      {log.source === 'adb' && '📱'}
                      {log.source === 'ssl' && '🔒'}
                      {log.source === 'proxy' && '🌐'}
                      {log.source === 'system' && '⚙️'}
                      {log.source}
                    </span>
                    <span className="log-message">{log.message}</span>
                    {log.details && (
                      <span className="log-details" title={JSON.stringify(log.details)}>
                        📎
                      </span>
                    )}
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            )}
          </div>
        )}
      </div>

      {/* Help Section */}
      <div className="help-section">
        <h4>How it works:</h4>
        <ol>
          <li><strong>Full Setup</strong> - Downloads Android SDK, creates virtual device</li>
          <li><strong>Start Emulator</strong> - Boots the Android emulator</li>
          <li><strong>Frida Server</strong> - Enables SSL pinning bypass</li>
          <li><strong>Run Mobile Scan</strong> - Now captures live app traffic!</li>
        </ol>
      </div>
    </div>
  );
});

EmulatorManager.displayName = 'EmulatorManager';

export default EmulatorManager;
