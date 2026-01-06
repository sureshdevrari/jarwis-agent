import React, { useState, useEffect, useCallback } from 'react';
import './ScanHistory.css';

const ScanHistory = ({ 
  onViewScan, 
  onResumeScan,
  onNewScan,
  currentScanId 
}) => {
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState({ total: 0, web: 0, mobile: 0, cloud: 0, running: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  
  // Filters
  const [typeFilter, setTypeFilter] = useState('all'); // all, web, mobile, cloud
  const [statusFilter, setStatusFilter] = useState('all'); // all, running, completed, error, stopped
  const [searchQuery, setSearchQuery] = useState('');
  const [sortBy, setSortBy] = useState('date_desc'); // date_desc, date_asc, status, severity
  
  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 10;

  const fetchScans = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Use the new combined endpoint with filters
      const params = new URLSearchParams();
      if (typeFilter !== 'all') params.append('type', typeFilter);
      if (statusFilter !== 'all') params.append('status', statusFilter);
      if (searchQuery) params.append('search', searchQuery);
      
      const res = await fetch(`/api/scans/all?${params.toString()}`);
      const data = await res.json();
      
      if (data.scans) {
        setScans(data.scans);
        setStats(data.stats || { total: 0, web: 0, mobile: 0, cloud: 0, running: 0 });
      } else if (Array.isArray(data)) {
        // Fallback for old API format
        setScans(data);
      }
      
    } catch (err) {
      console.error('Failed to load scans:', err);
      setError('Failed to load scan history');
    } finally {
      setLoading(false);
    }
  }, [typeFilter, statusFilter, searchQuery]);

  useEffect(() => {
    fetchScans();
    
    // Auto-refresh every 5 seconds for running scans
    const interval = setInterval(fetchScans, 5000);
    return () => clearInterval(interval);
  }, [fetchScans]);

  // Sort and paginate scans (server already filters)
  const getAllScans = () => {
    let allScans = [...scans];
    
    // Apply sorting
    allScans.sort((a, b) => {
      const dateA = new Date(a.started_at || a.start_time || 0);
      const dateB = new Date(b.started_at || b.start_time || 0);
      
      switch (sortBy) {
        case 'date_asc':
          return dateA - dateB;
        case 'status':
          return (a.status || '').localeCompare(b.status || '');
        case 'severity':
          const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
          const aMax = a.findings?.reduce((max, f) => 
            Math.min(max, sevOrder[f.severity] ?? 5), 5) ?? 5;
          const bMax = b.findings?.reduce((max, f) => 
            Math.min(max, sevOrder[f.severity] ?? 5), 5) ?? 5;
          return aMax - bMax;
        case 'date_desc':
        default:
          return dateB - dateA;
      }
    });
    
    return allScans;
  };

  const filteredScans = getAllScans();
  const totalPages = Math.ceil(filteredScans.length / itemsPerPage);
  const paginatedScans = filteredScans.slice(
    (currentPage - 1) * itemsPerPage,
    currentPage * itemsPerPage
  );

  // Use stats from API response
  const displayStats = {
    total: stats.total || scans.length,
    web: stats.web || 0,
    mobile: stats.mobile || 0,
    cloud: stats.cloud || 0,
    running: stats.running || 0,
    completed: stats.completed || 0,
    failed: stats.error || 0,
  };

  const getScanIcon = (scan) => {
    switch (scan.type || scan.scan_type) {
      case 'mobile': return '📱';
      case 'cloud': return '☁️';
      case 'web':
      default: return '🌐';
    }
  };

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed': return '✅';
      case 'running': return '🔄';
      case 'error': return '❌';
      case 'stopped': return '⏹️';
      case 'queued': return '⏳';
      default: return '❓';
    }
  };

  const getSeverityBadges = (scan) => {
    const results = scan.results || {};
    const badges = [];
    
    if (results.critical > 0) badges.push({ label: 'CRITICAL', count: results.critical, class: 'critical' });
    if (results.high > 0) badges.push({ label: 'HIGH', count: results.high, class: 'high' });
    if (results.medium > 0) badges.push({ label: 'MEDIUM', count: results.medium, class: 'medium' });
    if (results.low > 0) badges.push({ label: 'LOW', count: results.low, class: 'low' });
    
    return badges;
  };

  const formatDuration = (startedAt, completedAt) => {
    if (!startedAt) return '-';
    const start = new Date(startedAt);
    const end = completedAt ? new Date(completedAt) : new Date();
    const diff = Math.floor((end - start) / 1000);
    
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ${diff % 60}s`;
    return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
  };

  return (
    <div className="scan-history">
      {/* Header */}
      <div className="history-header">
        <div className="header-title">
          <h2>📜 Scan History</h2>
          <p className="subtitle">View and manage all your security scans</p>
        </div>
        <div className="header-actions">
          <button className="btn-refresh" onClick={fetchScans} disabled={loading}>
            🔄 Refresh
          </button>
          <button className="btn-primary" onClick={onNewScan}>
            ➕ New Scan
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="stats-grid">
        <div className="stat-card total" onClick={() => setTypeFilter('all')}>
          <span className="stat-icon">📊</span>
          <div className="stat-content">
            <span className="stat-value">{displayStats.total}</span>
            <span className="stat-label">Total Scans</span>
          </div>
        </div>
        <div className={`stat-card web ${typeFilter === 'web' ? 'active' : ''}`} onClick={() => setTypeFilter('web')}>
          <span className="stat-icon">🌐</span>
          <div className="stat-content">
            <span className="stat-value">{displayStats.web}</span>
            <span className="stat-label">Web Scans</span>
          </div>
        </div>
        <div className={`stat-card mobile ${typeFilter === 'mobile' ? 'active' : ''}`} onClick={() => setTypeFilter('mobile')}>
          <span className="stat-icon">📱</span>
          <div className="stat-content">
            <span className="stat-value">{displayStats.mobile}</span>
            <span className="stat-label">Mobile Scans</span>
          </div>
        </div>
        <div className={`stat-card cloud ${typeFilter === 'cloud' ? 'active' : ''}`} onClick={() => setTypeFilter('cloud')}>
          <span className="stat-icon">☁️</span>
          <div className="stat-content">
            <span className="stat-value">{displayStats.cloud}</span>
            <span className="stat-label">Cloud Scans</span>
          </div>
        </div>
        {displayStats.running > 0 && (
          <div className="stat-card running pulse" onClick={() => setStatusFilter('running')}>
            <span className="stat-icon">🔄</span>
            <div className="stat-content">
              <span className="stat-value">{displayStats.running}</span>
              <span className="stat-label">Running</span>
            </div>
          </div>
        )}
      </div>

      {/* Filters Bar */}
      <div className="filters-bar">
        <div className="search-box">
          <span className="search-icon">🔍</span>
          <input
            type="text"
            placeholder="Search by target, scan ID..."
            value={searchQuery}
            onChange={(e) => { setSearchQuery(e.target.value); setCurrentPage(1); }}
          />
          {searchQuery && (
            <button className="clear-search" onClick={() => setSearchQuery('')}>×</button>
          )}
        </div>
        
        <div className="filter-group">
          <label>Type:</label>
          <select value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setCurrentPage(1); }}>
            <option value="all">All Types</option>
            <option value="web">🌐 Web</option>
            <option value="mobile">📱 Mobile</option>
            <option value="cloud">☁️ Cloud</option>
          </select>
        </div>
        
        <div className="filter-group">
          <label>Status:</label>
          <select value={statusFilter} onChange={(e) => { setStatusFilter(e.target.value); setCurrentPage(1); }}>
            <option value="all">All Status</option>
            <option value="running">🔄 Running</option>
            <option value="completed">✅ Completed</option>
            <option value="error">❌ Failed</option>
            <option value="stopped">⏹️ Stopped</option>
          </select>
        </div>
        
        <div className="filter-group">
          <label>Sort:</label>
          <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
            <option value="date_desc">Newest First</option>
            <option value="date_asc">Oldest First</option>
            <option value="status">By Status</option>
            <option value="severity">By Severity</option>
          </select>
        </div>
      </div>

      {/* Results Count */}
      <div className="results-info">
        Showing {paginatedScans.length} of {filteredScans.length} scans
        {(typeFilter !== 'all' || statusFilter !== 'all' || searchQuery) && (
          <button className="clear-filters" onClick={() => {
            setTypeFilter('all');
            setStatusFilter('all');
            setSearchQuery('');
          }}>
            Clear Filters
          </button>
        )}
      </div>

      {/* Error State */}
      {error && (
        <div className="error-message">
          <span>⚠️ {error}</span>
          <button onClick={fetchScans}>Retry</button>
        </div>
      )}

      {/* Loading State */}
      {loading && scans.length === 0 && (
        <div className="loading-state">
          <div className="spinner"></div>
          <p>Loading scan history...</p>
        </div>
      )}

      {/* Empty State */}
      {!loading && filteredScans.length === 0 && (
        <div className="empty-state">
          <span className="empty-icon">📋</span>
          <h3>No Scans Found</h3>
          <p>
            {searchQuery || typeFilter !== 'all' || statusFilter !== 'all'
              ? 'Try adjusting your filters'
              : 'Start your first security scan to see history here'}
          </p>
          {!searchQuery && typeFilter === 'all' && statusFilter === 'all' && (
            <button className="btn-primary" onClick={onNewScan}>
              Start a Scan
            </button>
          )}
        </div>
      )}

      {/* Scan List */}
      {paginatedScans.length > 0 && (
        <div className="scan-list">
          {paginatedScans.map((scan) => (
            <div 
              key={scan.id} 
              className={`scan-card ${scan.status} ${scan.id === currentScanId ? 'current' : ''}`}
            >
              {/* Type & Status Icons */}
              <div className="scan-icons">
                <span className="type-icon" title={scan.type || scan.scan_type}>{getScanIcon(scan)}</span>
                <span className={`status-icon ${scan.status}`} title={scan.status}>
                  {getStatusIcon(scan.status)}
                  {scan.status === 'running' && <span className="pulse-ring"></span>}
                </span>
              </div>
              
              {/* Main Info */}
              <div className="scan-info">
                <div className="scan-header">
                  <h4 className="scan-target" title={scan.target}>
                    {scan.target?.length > 50 ? scan.target.substring(0, 50) + '...' : scan.target}
                  </h4>
                  {scan.id === currentScanId && (
                    <span className="current-badge">Current</span>
                  )}
                </div>
                
                <div className="scan-meta">
                  <span className="scan-id">ID: {scan.id}</span>
                  <span className="scan-date">
                    📅 {new Date(scan.started_at || scan.start_time).toLocaleString()}
                  </span>
                  <span className="scan-duration">
                    ⏱️ {formatDuration(scan.started_at || scan.start_time, scan.completed_at || scan.end_time)}
                  </span>
                  <span className={`scan-type-badge ${scan.type || scan.scan_type}`}>
                    {(scan.type || scan.scan_type || 'web')?.toUpperCase()}
                  </span>
                </div>
                
                {/* Progress for running scans */}
                {scan.status === 'running' && scan.progress !== undefined && (
                  <div className="scan-progress">
                    <div className="progress-bar">
                      <div className="progress-fill" style={{ width: `${scan.progress}%` }}></div>
                    </div>
                    <span className="progress-text">{scan.progress}% - {scan.phase}</span>
                  </div>
                )}
                
                {/* Severity Badges for completed scans */}
                {scan.status === 'completed' && (
                  <div className="severity-badges">
                    {getSeverityBadges(scan).length > 0 ? (
                      getSeverityBadges(scan).map((badge, i) => (
                        <span key={i} className={`severity-badge ${badge.class}`}>
                          {badge.count} {badge.label}
                        </span>
                      ))
                    ) : (
                      <span className="no-findings">✅ No vulnerabilities found</span>
                    )}
                  </div>
                )}
                
                {/* Error message */}
                {scan.status === 'error' && scan.error && (
                  <div className="error-info">
                    <span className="error-text">❌ {scan.error}</span>
                  </div>
                )}
              </div>
              
              {/* Actions */}
              <div className="scan-actions">
                <button 
                  className="btn-view"
                  onClick={() => onViewScan(scan)}
                >
                  {scan.status === 'running' ? '👁️ Monitor' : '📋 Details'}
                </button>
                
                {scan.status === 'completed' && scan.results?.report_path && (
                  <a 
                    href={`/api/reports/${scan.results.report_path.replace('reports/', '')}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="btn-report"
                  >
                    📄 Report
                  </a>
                )}
                
                {scan.status === 'error' && (
                  <button 
                    className="btn-retry"
                    onClick={() => onResumeScan && onResumeScan(scan)}
                  >
                    🔁 Retry
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="pagination">
          <button 
            className="page-btn"
            disabled={currentPage === 1}
            onClick={() => setCurrentPage(1)}
          >
            ⟪
          </button>
          <button 
            className="page-btn"
            disabled={currentPage === 1}
            onClick={() => setCurrentPage(p => p - 1)}
          >
            ←
          </button>
          
          <span className="page-info">
            Page {currentPage} of {totalPages}
          </span>
          
          <button 
            className="page-btn"
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage(p => p + 1)}
          >
            →
          </button>
          <button 
            className="page-btn"
            disabled={currentPage === totalPages}
            onClick={() => setCurrentPage(totalPages)}
          >
            ⟫
          </button>
        </div>
      )}
    </div>
  );
};

export default ScanHistory;
