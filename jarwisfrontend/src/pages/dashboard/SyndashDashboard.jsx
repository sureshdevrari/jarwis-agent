/**
 * Syndash Dashboard - Main Security Dashboard
 * Connected to real API endpoints
 */
import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useSubscription } from "../../context/SubscriptionContext";
import api from "../../services/api";

export default function SyndashDashboard() {
  const navigate = useNavigate();
  const { user, userDoc } = useAuth();
  const { planId, getActionLimit } = useSubscription();
  
  // Data states
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [dashboardData, setDashboardData] = useState(null);
  
  // UI states
  const [activeStat, setActiveStat] = useState(null);
  const [chartsVisible, setChartsVisible] = useState(false);
  const [activeVuln, setActiveVuln] = useState(null);
  
  const scoreRef = useRef(null);
  const vulnRef = useRef(null);

  // Fetch dashboard data on mount
  useEffect(() => {
    fetchDashboardData();
  }, []);

  const fetchDashboardData = async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response = await api.get("/api/dashboard/overview?days=30");
      
      if (response.data?.success) {
        setDashboardData(response.data.data);
      } else {
        setError(response.data?.message || "Failed to load dashboard");
      }
    } catch (err) {
      console.error("Dashboard fetch error:", err);
      setError("Failed to load dashboard data");
    } finally {
      setLoading(false);
    }
  };

  // Calculate stats from dashboard data
  const stats = useMemo(() => {
    if (!dashboardData?.scan_stats || !dashboardData?.security_score) {
      return [
        { label: "Total Scans", value: 0, trend: "+0%", trendUp: true, icon: "📊", color: "primary" },
        { label: "Critical Issues", value: 0, trend: "+0%", trendUp: false, icon: "🚨", color: "danger" },
        { label: "High Risks", value: 0, trend: "+0%", trendUp: true, icon: "⚠️", color: "warning" },
        { label: "Clean Scans", value: 0, trend: "+0%", trendUp: true, icon: "✅", color: "success" },
      ];
    }
    
    const { scan_stats, security_score } = dashboardData;
    const delta = security_score.delta || 0;
    
    return [
      { 
        label: "Total Scans", 
        value: scan_stats.total_scans || 0, 
        trend: `${delta >= 0 ? '+' : ''}${delta}%`, 
        trendUp: delta >= 0, 
        icon: "📊", 
        color: "primary" 
      },
      { 
        label: "Critical Issues", 
        value: security_score.critical_count || 0, 
        trend: security_score.trend === "improving" ? "↘" : "↗", 
        trendUp: security_score.trend === "improving", 
        icon: "🚨", 
        color: "danger" 
      },
      { 
        label: "High Risks", 
        value: security_score.high_count || 0, 
        trend: `${security_score.high_count || 0} found`, 
        trendUp: false, 
        icon: "⚠️", 
        color: "warning" 
      },
      { 
        label: "Security Score", 
        value: Math.round(security_score.score || 0), 
        trend: `Grade ${security_score.grade || 'N/A'}`, 
        trendUp: security_score.trend !== "declining", 
        icon: "✅", 
        color: "success" 
      },
    ];
  }, [dashboardData]);

  // Get recent scans from API data
  const recentScans = useMemo(() => {
    return dashboardData?.recent_scans || [];
  }, [dashboardData]);

  // Get vulnerabilities from API data
  const vulnerabilities = useMemo(() => {
    return dashboardData?.top_vulnerabilities || [];
  }, [dashboardData]);

  // Platform breakdown from API
  const platformBreakdown = useMemo(() => {
    if (!dashboardData?.scan_stats?.scans_by_type) {
      return [];
    }
    
    const types = dashboardData.scan_stats.scans_by_type;
    const total = Object.values(types).reduce((a, b) => a + b, 0) || 1;
    
    return [
      { platform: "Web Applications", scans: types.web || 0, percentage: Math.round(((types.web || 0) / total) * 100) },
      { platform: "Mobile Apps", scans: types.mobile || 0, percentage: Math.round(((types.mobile || 0) / total) * 100) },
      { platform: "Network", scans: types.network || 0, percentage: Math.round(((types.network || 0) / total) * 100) },
      { platform: "Cloud", scans: types.cloud || 0, percentage: Math.round(((types.cloud || 0) / total) * 100) },
    ];
  }, [dashboardData]);

  // Stat details popup content
  const statDetails = useMemo(() => ({
    "Total Scans": {
      title: "Scan Volume",
      summary: "Recent scanning activity across all surfaces",
      items: platformBreakdown.map(p => ({ label: p.platform.split(" ")[0], value: p.scans }))
    },
    "Critical Issues": {
      title: "Critical Findings",
      summary: "Highest-risk issues requiring immediate attention",
      items: vulnerabilities
        .filter(v => v.severity === "critical")
        .slice(0, 4)
        .map(v => ({ label: v.title, value: 1 }))
    },
    "High Risks": {
      title: "High Severity",
      summary: "High-level vulnerabilities requiring attention",
      items: vulnerabilities
        .filter(v => v.severity === "high")
        .slice(0, 4)
        .map(v => ({ label: v.title, value: 1 }))
    },
    "Security Score": {
      title: "Security Score Details",
      summary: `Your overall security posture: ${dashboardData?.security_score?.grade || 'N/A'}`,
      items: [
        { label: "Score", value: dashboardData?.security_score?.score || 0 },
        { label: "Trend", value: dashboardData?.security_score?.trend || "unknown" },
        { label: "Critical", value: dashboardData?.security_score?.critical_count || 0 },
        { label: "High", value: dashboardData?.security_score?.high_count || 0 },
      ]
    }
  }), [dashboardData, platformBreakdown, vulnerabilities]);

  const gradientsMap = {
    primary: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
    danger: 'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)',
    warning: 'linear-gradient(135deg, #ffc107 0%, #ff8b38 100%)',
    success: 'linear-gradient(135deg, #0ba360 0%, #3cba92 100%)'
  };

  // Vulnerability severity breakdown
  const vulnStats = useMemo(() => {
    if (!dashboardData?.security_score) {
      return [];
    }
    const ss = dashboardData.security_score;
    return [
      { label: 'Critical', value: ss.critical_count || 0, color: gradientsMap.danger },
      { label: 'High', value: ss.high_count || 0, color: gradientsMap.warning },
      { label: 'Medium', value: ss.medium_count || 0, color: gradientsMap.primary },
      { label: 'Low', value: ss.low_count || 0, color: gradientsMap.success },
    ];
  }, [dashboardData]);

  // Security score trend data
  const securityScore = useMemo(() => {
    // Use placeholder trend data - in production, this would come from API
    const score = dashboardData?.security_score?.score || 0;
    const base = Math.max(50, score - 15);
    return [base, base + 4, base + 1, base + 7, base + 11, Math.round(score)];
  }, [dashboardData]);

  // Vulnerability distribution for pie chart
  const vulnerabilityDistribution = useMemo(() => {
    if (!dashboardData?.security_score) {
      return [];
    }
    const ss = dashboardData.security_score;
    return [
      { label: 'Critical', value: ss.critical_count || 0, color: 'rgba(244, 63, 94, 0.9)' },
      { label: 'High', value: ss.high_count || 0, color: 'rgba(249, 115, 22, 0.9)' },
      { label: 'Medium', value: ss.medium_count || 0, color: 'rgba(99, 102, 241, 0.9)' },
      { label: 'Low', value: ss.low_count || 0, color: 'rgba(16, 185, 129, 0.9)' },
      { label: 'Info', value: ss.info_count || 0, color: 'rgba(59, 130, 246, 0.9)' },
    ].filter(item => item.value > 0);
  }, [dashboardData]);

  // Intersection observer for chart animations
  useEffect(() => {
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) setChartsVisible(true);
        });
      },
      { threshold: 0.3 }
    );

    if (scoreRef.current) observer.observe(scoreRef.current);
    if (vulnRef.current) observer.observe(vulnRef.current);

    return () => observer.disconnect();
  }, []);

  // Get user display name
  const displayName = user?.displayName || userDoc?.displayName || userDoc?.email?.split("@")[0] || "User";

  if (loading) {
    return (
      <div style={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center', 
        height: '50vh',
        flexDirection: 'column',
        gap: 16
      }}>
        <div style={{
          width: 50,
          height: 50,
          border: '4px solid rgba(102, 126, 234, 0.2)',
          borderTopColor: '#667eea',
          borderRadius: '50%',
          animation: 'spin 1s linear infinite'
        }} />
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        <p style={{ opacity: 0.7 }}>Loading dashboard...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div style={{ textAlign: 'center', padding: 40 }}>
        <h2 style={{ color: '#f43f5e', marginBottom: 16 }}>⚠️ Error</h2>
        <p style={{ opacity: 0.7, marginBottom: 20 }}>{error}</p>
        <button 
          className="btn btn-primary"
          onClick={fetchDashboardData}
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div>
      {/* Page Header */}
      <div className="d-flex justify-between align-center mb-4">
        <div>
          <h1 style={{ fontSize: 28, fontWeight: 700, marginBottom: 8 }}>
            Security Dashboard
          </h1>
          <p style={{ opacity: 0.7 }}>Welcome back, {displayName}! Here's your security overview.</p>
        </div>
        <button 
          className="btn btn-primary"
          onClick={() => navigate('/dashboard/new-scan')}
        >
          🚀 New Scan
        </button>
      </div>

      {/* Stats Cards */}
      <div className="row mb-4">
        {stats.map((stat, idx) => (
          <div key={idx} className="col-md-3">
            <div 
              className="card" 
              style={{
                background: gradientsMap[stat.color],
                color: 'white',
                position: 'relative',
                overflow: 'hidden',
                cursor: 'pointer',
                transition: 'transform 0.2s ease, box-shadow 0.2s ease'
              }}
              onClick={() => setActiveStat(stat.label)}
              onMouseEnter={e => e.currentTarget.style.transform = 'translateY(-4px)'}
              onMouseLeave={e => e.currentTarget.style.transform = 'translateY(0)'}
            >
              <div style={{
                position: 'absolute',
                top: -20,
                right: -20,
                fontSize: 120,
                opacity: 0.15,
                transform: 'rotate(-15deg)'
              }}>
                {stat.icon}
              </div>
              <div style={{ position: 'relative', zIndex: 1 }}>
                <div style={{ fontSize: 14, opacity: 0.9, marginBottom: 8, fontWeight: 500 }}>
                  {stat.label}
                </div>
                <div style={{ fontSize: 36, fontWeight: 700, marginBottom: 8 }}>
                  {stat.value}
                </div>
                <div style={{ 
                  fontSize: 13, 
                  display: 'flex', 
                  alignItems: 'center', 
                  gap: 6,
                  padding: '6px 12px',
                  background: 'rgba(255, 255, 255, 0.2)',
                  borderRadius: 20,
                  width: 'fit-content'
                }}>
                  <span style={{ fontSize: 16 }}>{stat.trendUp ? '↗' : '↘'}</span>
                  <span style={{ fontWeight: 600 }}>{stat.trend}</span>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Stat Detail Modal */}
      {activeStat && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.55)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 2000,
          padding: 20,
        }}
          onClick={() => setActiveStat(null)}
        >
          <div style={{
            width: '100%',
            maxWidth: 520,
            background: '#ffffff',
            color: '#1f2937',
            borderRadius: 16,
            padding: 24,
            boxShadow: '0 18px 50px rgba(0,0,0,0.35)',
            border: '1px solid rgba(102,126,234,0.15)',
            position: 'relative',
          }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="d-flex justify-between align-center" style={{ marginBottom: 12 }}>
              <div>
                <p style={{ margin: 0, fontSize: 12, letterSpacing: 0.5, opacity: 0.7, textTransform: 'uppercase' }}>Metric</p>
                <h3 style={{ margin: '4px 0', fontSize: 22, fontWeight: 700 }}>{activeStat}</h3>
                <p style={{ margin: 0, opacity: 0.75, fontSize: 13 }}>
                  {statDetails[activeStat]?.summary || 'No summary available'}
                </p>
              </div>
              <button className="btn btn-outline" style={{ padding: '8px 12px' }} onClick={() => setActiveStat(null)}>Close</button>
            </div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
              gap: 10,
            }}>
              {statDetails[activeStat]?.items?.map((item, idx) => (
                <div key={idx} style={{
                  padding: 12,
                  borderRadius: 12,
                  background: 'rgba(102,126,234,0.08)',
                  border: '1px solid rgba(102,126,234,0.15)',
                }}>
                  <p style={{ margin: 0, fontSize: 12, opacity: 0.75 }}>{item.label}</p>
                  <p style={{ margin: '4px 0 0', fontSize: 18, fontWeight: 700 }}>{item.value}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      <div className="row">
        {/* Recent Scans */}
        <div className="col-md-8">
          <div className="card">
            <div className="d-flex justify-between align-center mb-3">
              <h2 style={{ fontSize: 18, fontWeight: 600 }}>Recent Scans</h2>
              <button 
                className="btn btn-outline"
                onClick={() => navigate('/dashboard/scan-history')}
              >
                View All
              </button>
            </div>
            <div className="table-responsive">
              <table>
                <thead>
                  <tr>
                    <th>Date</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {recentScans.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: 40, opacity: 0.6 }}>
                        No scans yet. Start your first security scan!
                      </td>
                    </tr>
                  ) : (
                    recentScans.map((scan) => (
                      <tr key={scan.id}>
                        <td>{scan.date}</td>
                        <td>
                          <span className="badge info">{scan.type}</span>
                        </td>
                        <td style={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {scan.target}
                        </td>
                        <td>
                          <span className={`badge ${
                            scan.status === 'Completed' ? 'success' : 
                            scan.status === 'Running' ? 'warning' : 'danger'
                          }`}>
                            {scan.status}
                          </span>
                        </td>
                        <td>
                          <span className={`badge ${
                            scan.severity === 'critical' ? 'danger' :
                            scan.severity === 'high' ? 'warning' :
                            scan.severity === 'medium' ? 'info' : 'success'
                          }`}>
                            {scan.findings} issues
                          </span>
                        </td>
                        <td>
                          <button 
                            className="btn btn-outline" 
                            style={{ padding: '6px 12px', fontSize: 12 }}
                            onClick={() => navigate('/dashboard/vulnerabilities', { 
                              state: { 
                                scanId: scan.id,
                                scanType: scan.type?.toLowerCase() || 'web'
                              }
                            })}
                          >
                            View
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Platform Breakdown */}
        <div className="col-md-4">
          <div className="card" style={{
            background: 'linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%)',
            border: '1px solid rgba(102, 126, 234, 0.1)'
          }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>Platform Breakdown</h2>
            {platformBreakdown.map((item, idx) => {
              const gradients = [
                'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
                'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)',
                'linear-gradient(135deg, #ffc107 0%, #ff8b38 100%)',
                'linear-gradient(135deg, #f093fb 0%, #f5576c 100%)'
              ];
              
              return (
                <div key={idx} style={{ marginBottom: 20 }}>
                  <div className="d-flex justify-between align-center mb-2">
                    <span style={{ fontSize: 14, fontWeight: 500 }}>{item.platform}</span>
                    <span style={{ 
                      fontSize: 14, 
                      fontWeight: 700,
                      background: gradients[idx],
                      WebkitBackgroundClip: 'text',
                      WebkitTextFillColor: 'transparent',
                      backgroundClip: 'text'
                    }}>
                      {item.scans} scans
                    </span>
                  </div>
                  <div style={{
                    height: 10,
                    borderRadius: 10,
                    background: 'rgba(0,0,0,0.05)',
                    overflow: 'hidden',
                    position: 'relative'
                  }}>
                    <div 
                      style={{ 
                        height: '100%',
                        width: `${item.percentage || 0}%`,
                        background: gradients[idx],
                        borderRadius: 10,
                        transition: 'width 0.5s ease',
                        boxShadow: `0 0 10px ${idx === 0 ? 'rgba(102, 126, 234, 0.4)' : 'rgba(79, 172, 254, 0.4)'}`
                      }}
                    />
                  </div>
                  <div style={{ 
                    fontSize: 12, 
                    opacity: 0.7, 
                    marginTop: 6,
                    fontWeight: 500
                  }}>
                    {item.percentage || 0}% of total scans
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Vulnerabilities */}
      <div className="row mt-3">
        <div className="col-md-8">
          <div className="card">
            <div className="d-flex justify-between align-center mb-3">
              <h2 style={{ fontSize: 18, fontWeight: 600 }}>Top Vulnerabilities</h2>
              <button 
                className="btn btn-outline"
                onClick={() => navigate('/dashboard/vulnerabilities')}
              >
                View All
              </button>
            </div>
            <div className="table-responsive">
              <table>
                <thead>
                  <tr>
                    <th>Vulnerability</th>
                    <th>Severity</th>
                    <th>Component</th>
                    <th>Status</th>
                    <th>Date</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {vulnerabilities.length === 0 ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: 40, opacity: 0.6 }}>
                        No vulnerabilities found. Great job! 🎉
                      </td>
                    </tr>
                  ) : (
                    vulnerabilities.map((vuln) => (
                      <tr key={vuln.id}>
                        <td>{vuln.title}</td>
                        <td>
                          <span className={`badge ${vuln.severity === 'critical' ? 'danger' : vuln.severity === 'high' ? 'warning' : vuln.severity === 'medium' ? 'info' : 'success'}`}>
                            {vuln.severity}
                          </span>
                        </td>
                        <td>{vuln.affected}</td>
                        <td>
                          <span className={`badge ${vuln.status === 'Resolved' ? 'success' : 'warning'}`}>
                            {vuln.status}
                          </span>
                        </td>
                        <td>{vuln.date}</td>
                        <td>
                          <button 
                            className="btn btn-outline" 
                            style={{ padding: '6px 12px', fontSize: 12 }} 
                            onClick={() => setActiveVuln(vuln)}
                          >
                            View Details
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
        <div className="col-md-4">
          <div className="card" style={{
            background: 'linear-gradient(135deg, #ffffff 0%, #f8f9fa 100%)',
            border: '1px solid rgba(102, 126, 234, 0.2)'
          }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 16 }}>Severity Breakdown</h2>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10 }}>
              {vulnStats.map((item, idx) => (
                <div key={idx} style={{
                  padding: 12,
                  borderRadius: 12,
                  background: 'rgba(0,0,0,0.03)',
                  border: '1px solid rgba(0,0,0,0.05)',
                  boxShadow: '0 10px 24px rgba(0,0,0,0.06)'
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                    <span style={{ fontSize: 13, fontWeight: 700 }}>{item.label}</span>
                    <span style={{
                      width: 12,
                      height: 12,
                      borderRadius: 4,
                      background: item.color,
                      boxShadow: '0 0 0 4px rgba(0,0,0,0.05)'
                    }} />
                  </div>
                  <div style={{ fontSize: 26, fontWeight: 800 }}>{item.value}</div>
                  <div style={{ height: 8, background: 'rgba(0,0,0,0.08)', borderRadius: 6, overflow: 'hidden', marginTop: 8 }}>
                    <div style={{
                      height: '100%',
                      width: `${Math.min(item.value * 25, 100)}%`,
                      background: item.color,
                      transition: 'width 0.5s ease'
                    }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Vulnerability Detail Modal */}
      {activeVuln && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.55)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 2100,
          padding: 20,
        }}
          onClick={() => setActiveVuln(null)}
        >
          <div style={{
            width: '100%',
            maxWidth: 540,
            background: '#ffffff',
            color: '#1f2937',
            borderRadius: 16,
            padding: 24,
            boxShadow: '0 18px 50px rgba(0,0,0,0.35)',
            border: '1px solid rgba(102,126,234,0.15)',
            position: 'relative',
          }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="d-flex justify-between align-center" style={{ marginBottom: 12 }}>
              <div>
                <p style={{ margin: 0, fontSize: 12, letterSpacing: 0.5, opacity: 0.7, textTransform: 'uppercase' }}>Vulnerability</p>
                <h3 style={{ margin: '4px 0', fontSize: 22, fontWeight: 700 }}>{activeVuln.title}</h3>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 6, flexWrap: 'wrap' }}>
                  <span className={`badge ${activeVuln.severity === 'critical' ? 'danger' : activeVuln.severity === 'high' ? 'warning' : activeVuln.severity === 'medium' ? 'info' : 'success'}`}>
                    {activeVuln.severity}
                  </span>
                  <span className={`badge ${activeVuln.status === 'Resolved' ? 'success' : 'warning'}`}>
                    {activeVuln.status}
                  </span>
                  <span className="badge secondary">{activeVuln.date}</span>
                </div>
              </div>
              <button className="btn btn-outline" style={{ padding: '8px 12px' }} onClick={() => setActiveVuln(null)}>Close</button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12, marginBottom: 12 }}>
              <div style={{
                padding: 12,
                borderRadius: 12,
                background: 'rgba(0,0,0,0.03)',
                border: '1px solid rgba(0,0,0,0.05)',
              }}>
                <p style={{ margin: 0, fontSize: 12, opacity: 0.7 }}>Affected Component</p>
                <p style={{ margin: '4px 0 0', fontSize: 16, fontWeight: 700 }}>{activeVuln.affected}</p>
              </div>
              <div style={{
                padding: 12,
                borderRadius: 12,
                background: 'rgba(0,0,0,0.03)',
                border: '1px solid rgba(0,0,0,0.05)',
              }}>
                <p style={{ margin: 0, fontSize: 12, opacity: 0.7 }}>Discovered</p>
                <p style={{ margin: '4px 0 0', fontSize: 16, fontWeight: 700 }}>{activeVuln.date}</p>
              </div>
            </div>

            <div style={{ fontSize: 13, lineHeight: 1.6, opacity: 0.9 }}>
              This vulnerability affects {activeVuln.affected?.toLowerCase()} and may lead to potential security risks. 
              View the full vulnerability report for detailed remediation steps.
            </div>
            
            <div style={{ marginTop: 16, display: 'flex', gap: 12 }}>
              <button 
                className="btn btn-primary"
                onClick={() => {
                  setActiveVuln(null);
                  navigate('/dashboard/vulnerability/' + activeVuln.id);
                }}
              >
                View Full Details
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Charts Row */}
      <div className="row">
        <div className="col-md-6">
          <div className="card" style={{
            background: 'linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%)',
            border: '2px solid rgba(102, 126, 234, 0.2)'
          }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>Security Score Trend</h2>
            <div className="chart-container" ref={scoreRef} style={{ alignItems: 'flex-end', padding: 20 }}>
              <div style={{ display: 'flex', gap: 12, width: '100%', height: 220, alignItems: 'flex-end' }}>
                {securityScore.map((score, idx) => {
                  const height = chartsVisible ? `${(score / 100) * 100}%` : '8%';
                  return (
                    <div key={idx} style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'flex-end', gap: 8 }}>
                      <div style={{
                        height,
                        minHeight: 12,
                        borderRadius: 10,
                        background: 'linear-gradient(180deg, rgba(102,126,234,0.9) 0%, rgba(118,75,162,0.8) 100%)',
                        boxShadow: '0 10px 24px rgba(102,126,234,0.25)',
                        transition: 'height 0.9s ease',
                        transitionDelay: `${idx * 80}ms`,
                      }} />
                      <div style={{ textAlign: 'center', fontSize: 12, opacity: 0.8 }}>W{idx + 1}</div>
                    </div>
                  );
                })}
              </div>
              <div style={{ marginTop: 12, display: 'flex', justifyContent: 'space-between', fontSize: 12, opacity: 0.7, width: '100%' }}>
                <span>Last 6 weeks</span>
                <span>Current: {Math.max(...securityScore)} / 100</span>
              </div>
            </div>
          </div>
        </div>
        <div className="col-md-6">
          <div className="card" style={{
            background: 'linear-gradient(135deg, #f8f9fa 0%, #ffffff 100%)',
            border: '2px solid rgba(79, 172, 254, 0.2)'
          }}>
            <h2 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>Vulnerability Distribution</h2>
            <div className="chart-container" ref={vulnRef} style={{ padding: 20 }}>
              <div style={{ display: 'flex', gap: 20, alignItems: 'center', width: '100%', flexWrap: 'wrap' }}>
                {vulnerabilityDistribution.length > 0 ? (
                  <>
                    <div style={{
                      width: 180,
                      height: 180,
                      borderRadius: '50%',
                      background: (() => {
                        const total = vulnerabilityDistribution.reduce((sum, item) => sum + item.value, 0);
                        if (total === 0) return 'rgba(102,126,234,0.1)';
                        let current = 0;
                        return `conic-gradient(${vulnerabilityDistribution.map((item) => {
                          const start = (current / total) * 360;
                          current += item.value;
                          const end = (current / total) * 360;
                          const alpha = chartsVisible ? 1 : 0;
                          return `${item.color.replace('0.9', alpha.toString())} ${start}deg ${end}deg`;
                        }).join(', ')})`;
                      })(),
                      boxShadow: '0 20px 40px rgba(0,0,0,0.15)',
                      position: 'relative',
                      transition: 'opacity 0.6s ease',
                      opacity: chartsVisible ? 1 : 0,
                    }}>
                      <div style={{
                        position: 'absolute',
                        inset: 18,
                        borderRadius: '50%',
                        background: '#ffffff',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        flexDirection: 'column',
                        textAlign: 'center',
                        boxShadow: 'inset 0 0 0 1px rgba(102,126,234,0.2)'
                      }}>
                        <div style={{ fontSize: 26, fontWeight: 800, color: '#111827' }}>
                          {vulnerabilityDistribution.reduce((sum, item) => sum + item.value, 0)}
                        </div>
                        <div style={{ fontSize: 12, opacity: 0.7 }}>Total</div>
                      </div>
                    </div>
                    <div style={{ flex: 1, minWidth: 220, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10 }}>
                      {vulnerabilityDistribution.map((item, idx) => (
                        <div key={idx} style={{
                          padding: 12,
                          borderRadius: 12,
                          background: 'rgba(0,0,0,0.03)',
                          border: '1px solid rgba(0,0,0,0.04)',
                          display: 'flex',
                          alignItems: 'center',
                          gap: 10,
                          opacity: chartsVisible ? 1 : 0,
                          transform: chartsVisible ? 'translateY(0)' : 'translateY(8px)',
                          transition: 'all 0.4s ease',
                          transitionDelay: `${idx * 60}ms`,
                        }}>
                          <span style={{
                            width: 12,
                            height: 12,
                            borderRadius: 4,
                            background: item.color,
                            boxShadow: '0 0 0 4px rgba(0,0,0,0.05)'
                          }} />
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: 13, fontWeight: 700 }}>{item.label}</div>
                            <div style={{ fontSize: 12, opacity: 0.75 }}>
                              {item.value} issues
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </>
                ) : (
                  <div style={{ textAlign: 'center', width: '100%', padding: 40, opacity: 0.6 }}>
                    <p>No vulnerabilities to display</p>
                    <p style={{ fontSize: 12 }}>Run a security scan to see distribution</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Subscription Info */}
      <div className="row mt-3">
        <div className="col-md-12">
          <div className="card" style={{ 
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            color: 'white'
          }}>
            <div className="d-flex justify-between align-center">
              <div>
                <h3 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>
                  Current Plan: {(planId || 'free').charAt(0).toUpperCase() + (planId || 'free').slice(1)}
                </h3>
                <p style={{ opacity: 0.9, fontSize: 14 }}>
                  {getActionLimit && getActionLimit('scans')?.unlimited 
                    ? 'Unlimited scans available'
                    : `${getActionLimit?.('scans')?.current || 0} / ${getActionLimit?.('scans')?.max || 0} scans used this month`
                  }
                </p>
              </div>
              <button 
                className="btn" 
                style={{ 
                  background: 'rgba(255,255,255,0.2)', 
                  color: 'white',
                  border: '1px solid rgba(255,255,255,0.3)'
                }}
                onClick={() => navigate('/dashboard/billing')}
              >
                Manage Plan
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
