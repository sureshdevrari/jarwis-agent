import React, { useState, useEffect, useCallback, useRef } from 'react';
import { getScanStatus, getScanLogs, stopScan, getReportUrl, getMobileScanStatus, getMobileScanLogs, stopMobileScan } from '../services/api';
import './ScanStatus.css';

// Helper to detect scan type from scan ID
const getScanType = (scanId) => {
  if (!scanId) return 'web';
  if (scanId.startsWith('MOBILE-')) return 'mobile';
  if (scanId.startsWith('CLOUD-')) return 'cloud';
  return 'web';
};

const ScanStatus = ({ scanId, onScanComplete, onNewScan }) => {
  const [status, setStatus] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [connectionStatus, setConnectionStatus] = useState('connected');
  const [retryCount, setRetryCount] = useState(0);
  const [lastLogTimestamp, setLastLogTimestamp] = useState(null);
  const logsEndRef = useRef(null);
  const pollIntervalRef = useRef(null);
  const retryTimeoutRef = useRef(null);

  // Auto-scroll logs to bottom
  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const scanType = getScanType(scanId);

  const fetchStatus = useCallback(async () => {
    try {
      // Use correct API based on scan type
      const data = scanType === 'mobile' 
        ? await getMobileScanStatus(scanId)
        : await getScanStatus(scanId);
      setStatus(data);
      setError(null);
      setConnectionStatus('connected');
      setRetryCount(0);
      
      if (data.status === 'completed' || data.status === 'error' || data.status === 'stopped') {
        if (onScanComplete) {
          onScanComplete(data);
        }
        // Clear polling interval when scan is done
        if (pollIntervalRef.current) {
          clearInterval(pollIntervalRef.current);
          pollIntervalRef.current = null;
        }
      }
    } catch (err) {
      console.error('Status fetch error:', err);
      setConnectionStatus('disconnected');
      setRetryCount(prev => prev + 1);
      
      // Only show error after multiple retries
      if (retryCount >= 3) {
        setError('Connection lost. Attempting to reconnect...');
      }
    }
  }, [scanId, onScanComplete, retryCount]);

  const fetchLogs = useCallback(async () => {
    try {
      // Use correct API based on scan type
      const data = scanType === 'mobile'
        ? await getMobileScanLogs(scanId, lastLogTimestamp)
        : await getScanLogs(scanId, lastLogTimestamp);
      if (data.logs && data.logs.length > 0) {
        setLogs(prevLogs => {
          // Merge new logs, avoiding duplicates
          const existingTimestamps = new Set(prevLogs.map(l => l.timestamp));
          const newLogs = data.logs.filter(l => !existingTimestamps.has(l.timestamp));
          return [...prevLogs, ...newLogs];
        });
        // Update last timestamp for incremental fetching
        const lastLog = data.logs[data.logs.length - 1];
        setLastLogTimestamp(lastLog.timestamp);
      }
    } catch (err) {
      console.error('Logs fetch error:', err);
    }
  }, [scanId, lastLogTimestamp]);

  // Main polling effect
  useEffect(() => {
    // Initial fetch
    fetchStatus();
    fetchLogs();
    
    // Set up polling interval - faster when connected, slower when disconnected
    const pollInterval = connectionStatus === 'connected' ? 1500 : 3000;
    
    pollIntervalRef.current = setInterval(() => {
      const isDone = status?.status === 'completed' || status?.status === 'error' || status?.status === 'stopped';
      if (!isDone) {
        fetchStatus();
        fetchLogs();
      }
    }, pollInterval);

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current);
      }
    };
  }, [scanId, connectionStatus]);

  // Auto-reconnect effect
  useEffect(() => {
    if (connectionStatus === 'disconnected' && retryCount > 0) {
      // Exponential backoff for reconnection attempts
      const delay = Math.min(retryCount * 2000, 10000);
      retryTimeoutRef.current = setTimeout(() => {
        console.log(`Reconnection attempt ${retryCount}...`);
        fetchStatus();
      }, delay);
    }
    
    return () => {
      if (retryTimeoutRef.current) {
        clearTimeout(retryTimeoutRef.current);
      }
    };
  }, [connectionStatus, retryCount, fetchStatus]);

  const handleStop = async () => {
    try {
      // Use correct stop API based on scan type
      scanType === 'mobile' 
        ? await stopMobileScan(scanId)
        : await stopScan(scanId);
      fetchStatus();
    } catch (err) {
      setError('Failed to stop scan');
    }
  };

  const getLogIcon = (type) => {
    switch (type) {
      case 'info': return 'ℹ️';
      case 'success': return '✅';
      case 'warning': return '⚠️';
      case 'error': return '❌';
      case 'ai': return '🛡️';
      case 'finding': return '🔴';
      case 'phase': return '📊';
      default: return '•';
    }
  };

  const getLogClass = (type) => {
    return `log-entry log-${type}`;
  };

  if (error && retryCount >= 5) {
    return (
      <div className="scan-status error">
        <div className="status-icon">❌</div>
        <h3>Connection Error</h3>
        <p>{error}</p>
        <p className="retry-info">Retry attempts: {retryCount}</p>
        <button className="btn-primary" onClick={() => { setRetryCount(0); fetchStatus(); }}>
          🔄 Retry Connection
        </button>
        <button className="btn-secondary" onClick={onNewScan}>Start New Scan</button>
      </div>
    );
  }

  if (!status) {
    return (
      <div className="scan-status loading">
        <div className="loader"></div>
        <p>Loading scan status...</p>
        {connectionStatus === 'disconnected' && (
          <p className="reconnecting">Reconnecting... (attempt {retryCount})</p>
        )}
      </div>
    );
  }

  const getStatusIcon = () => {
    switch (status.status) {
      case 'running': return '🔄';
      case 'completed': return '✅';
      case 'error': return '❌';
      case 'stopped': return '⏹️';
      case 'queued': return '⏳';
      default: return '📊';
    }
  };

  const getStatusColor = () => {
    switch (status.status) {
      case 'running': return 'blue';
      case 'completed': return 'green';
      case 'error': return 'red';
      case 'stopped': return 'orange';
      default: return 'gray';
    }
  };

  return (
    <div className="scan-status-container">
      {connectionStatus === 'disconnected' && (
        <div className="connection-warning">
          <span className="warning-icon">⚠️</span>
          <span>Connection interrupted. Reconnecting... (attempt {retryCount})</span>
        </div>
      )}
      <div className={`scan-status ${getStatusColor()}`}>
        <div className="status-header">
          <span className="status-icon">{getStatusIcon()}</span>
          <div>
            <h3>Scan {status.status.charAt(0).toUpperCase() + status.status.slice(1)}</h3>
            <p className="scan-id mono">ID: {scanId}</p>
          </div>
          <div className={`connection-dot ${connectionStatus}`}></div>
        </div>

        <div className="status-details">
          <div className="detail-row">
            <span className="label">Target:</span>
            <span className="value mono">{status.config?.target_url}</span>
          </div>
          <div className="detail-row">
            <span className="label">Phase:</span>
            <span className="value">{status.phase} {status.message && <span className="phase-message">- {status.message}</span>}</span>
          </div>
          <div className="detail-row">
            <span className="label">Started:</span>
            <span className="value">{new Date(status.started_at).toLocaleString()}</span>
          </div>
          {status.config?.auth_enabled && (
            <div className="detail-row">
              <span className="label">Authentication:</span>
              <span className="value badge-enabled">Enabled</span>
            </div>
          )}
          {status.findings_count > 0 && (
            <div className="detail-row">
              <span className="label">Findings So Far:</span>
              <span className="value findings-count">{status.findings_count}</span>
            </div>
          )}
        </div>

        {status.status === 'running' && (
          <div className="progress-section">
            <div className="progress-bar">
              <div 
                className="progress-fill" 
                style={{ width: `${status.progress}%` }}
              ></div>
            </div>
            <span className="progress-text">{status.progress}%</span>
          </div>
        )}

        {/* Live Logs Panel */}
        {(status.status === 'running' || logs.length > 0) && (
          <div className="logs-section">
            <h4>🖥️ Live Scan Output</h4>
            <div className="logs-container">
              {logs.length === 0 ? (
                <div className="log-entry log-info">Waiting for scan output...</div>
              ) : (
                logs.map((log, index) => (
                  <div key={index} className={getLogClass(log.type)}>
                    <span className="log-icon">{getLogIcon(log.type)}</span>
                    <span className="log-time">{new Date(log.timestamp).toLocaleTimeString()}</span>
                    <span className="log-message">{log.message}</span>
                    {log.details && <span className="log-details">{log.details}</span>}
                  </div>
                ))
              )}
              <div ref={logsEndRef} />
            </div>
          </div>
        )}

        {status.status === 'completed' && status.results && (
          <div className="results-summary">
            <h4>📋 Results Summary</h4>
            <div className="summary-grid">
              <div className="summary-card">
                <span className="number">{status.results.findings_count || status.results.total_findings || 0}</span>
                <span className="label">Total Findings</span>
              </div>
              {status.results.critical !== undefined && (
                <div className="summary-card critical">
                  <span className="number">{status.results.critical}</span>
                  <span className="label">Critical</span>
                </div>
              )}
              {status.results.high !== undefined && (
                <div className="summary-card high">
                  <span className="number">{status.results.high}</span>
                  <span className="label">High</span>
                </div>
              )}
              {status.results.medium !== undefined && (
                <div className="summary-card medium">
                  <span className="number">{status.results.medium}</span>
                  <span className="label">Medium</span>
                </div>
              )}
              {status.results.low !== undefined && (
                <div className="summary-card low">
                  <span className="number">{status.results.low}</span>
                  <span className="label">Low</span>
                </div>
              )}
            </div>
            
            {/* API Endpoints Discovery Section */}
            {status.results.endpoints && status.results.endpoints.total > 0 && (
              <div className="endpoints-summary">
                <h5>🗺️ API Endpoints Discovered</h5>
                <div className="endpoints-grid">
                  <div className="endpoint-stat">
                    <span className="endpoint-number">{status.results.endpoints.total}</span>
                    <span className="endpoint-label">Total Endpoints</span>
                  </div>
                  <div className="endpoint-stat get">
                    <span className="endpoint-number">{status.results.endpoints.get}</span>
                    <span className="endpoint-label">GET</span>
                  </div>
                  <div className="endpoint-stat post">
                    <span className="endpoint-number">{status.results.endpoints.post}</span>
                    <span className="endpoint-label">POST/PUT</span>
                  </div>
                  <div className="endpoint-stat auth">
                    <span className="endpoint-number">{status.results.endpoints.auth_endpoints}</span>
                    <span className="endpoint-label">Auth APIs</span>
                  </div>
                  <div className="endpoint-stat vulnerable">
                    <span className="endpoint-number">{status.results.endpoints.vulnerable}</span>
                    <span className="endpoint-label">Vulnerable</span>
                  </div>
                </div>
                {status.results.endpoints.base_urls && status.results.endpoints.base_urls.length > 0 && (
                  <div className="base-urls">
                    <span className="base-urls-label">Base URLs:</span>
                    {status.results.endpoints.base_urls.slice(0, 3).map((url, idx) => (
                      <span key={idx} className="base-url-badge">{url}</span>
                    ))}
                    {status.results.endpoints.base_urls.length > 3 && (
                      <span className="base-url-more">+{status.results.endpoints.base_urls.length - 3} more</span>
                    )}
                  </div>
                )}
              </div>
            )}
            
            {status.results.report_path && (
              <a 
                href={`http://localhost:5000/api/${status.results.report_path}`}
                target="_blank"
                rel="noopener noreferrer"
                className="btn-report"
              >
                📄 View Full Report
              </a>
            )}
          </div>
        )}

        {status.status === 'error' && (
          <div className="error-message">
            <strong>Error:</strong> {status.error}
            {status.auth_failed && (
              <div className="auth-error-hint">
                <p>💡 Authentication failed. Please check:</p>
                <ul>
                  <li>Username/Email is correct</li>
                  <li>Password is correct</li>
                  <li>Account is not locked or disabled</li>
                </ul>
              </div>
            )}
          </div>
        )}

        <div className="status-actions">
          {status.status === 'running' && (
            <button className="btn-danger" onClick={handleStop}>
              ⏹️ Stop Scan
            </button>
          )}
          {(status.status === 'completed' || status.status === 'error' || status.status === 'stopped') && (
            <button className="btn-primary" onClick={onNewScan}>
              🔄 Start New Scan
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ScanStatus;
