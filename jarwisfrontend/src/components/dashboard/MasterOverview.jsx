// Master Overview Dashboard - Unified Security Console
import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { dashboardAPI } from '../../services/api';
import EnterpriseCard from '../ui/EnterpriseCard';
import SecurityScoreBar from '../ui/SecurityScoreBar';
import RiskHeatmap from '../ui/RiskHeatmap';
import PlatformRiskBars from '../ui/PlatformRiskBars';
import StatCard from '../ui/StatCard';

const MasterOverview = ({ onNavigateToPlatform, onNavigateToVulnerabilities }) => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [refreshing, setRefreshing] = useState(false);
  const [data, setData] = useState(null);
  const [timePeriod, setTimePeriod] = useState(30); // days

  // Fetch dashboard data
  const fetchDashboardData = useCallback(async (showRefreshIndicator = false) => {
    try {
      if (showRefreshIndicator) {
        setRefreshing(true);
      } else {
        setLoading(true);
      }
      setError(null);

      const response = await dashboardAPI.getOverview(timePeriod);
      
      if (response.success) {
        setData(response.data);
      } else {
        setError(response.message || 'Failed to fetch dashboard data');
      }
    } catch (err) {
      console.error('Dashboard fetch error:', err);
      setError(err.message || 'Failed to fetch dashboard data');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [timePeriod]);

  // Initial load
  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  // Auto-refresh every 60 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      fetchDashboardData(true);
    }, 60000);

    return () => clearInterval(interval);
  }, [fetchDashboardData]);

  // Handle heatmap cell click - filter vulnerabilities
  const handleHeatmapCellClick = ({ platform, severity }) => {
    if (onNavigateToVulnerabilities) {
      onNavigateToVulnerabilities({ platform, severity });
    } else {
      navigate(`/dashboard/vulnerabilities?platform=${platform}&severity=${severity}`);
    }
  };

  // Handle platform card click
  const handlePlatformClick = (platform) => {
    if (onNavigateToPlatform) {
      onNavigateToPlatform(platform);
    }
  };

  // Handle manual refresh
  const handleRefresh = () => {
    fetchDashboardData(true);
  };

  // Handle time period change
  const handleTimePeriodChange = (days) => {
    setTimePeriod(days);
  };

  if (loading && !data) {
    return (
      <div className="space-y-6">
        <div className="flex items-center justify-center py-20">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
        </div>
      </div>
    );
  }

  if (error && !data) {
    return (
      <EnterpriseCard variant="critical">
        <div className="text-center py-8">
          <p className="text-red-400 mb-4">{error}</p>
          <button
            onClick={handleRefresh}
            className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg transition-colors"
          >
            Retry
          </button>
        </div>
      </EnterpriseCard>
    );
  }

  const securityScore = data?.security_score || {};
  const riskHeatmap = data?.risk_heatmap || {};
  const platformBreakdown = data?.platform_breakdown || {};
  const scanStats = data?.scan_stats || {};

  return (
    <div className="space-y-6">
      {/* Header with controls */}
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold text-gray-100">Security Overview</h2>
          <p className="text-sm text-gray-400 mt-1">
            Last updated: {new Date(securityScore.last_updated || Date.now()).toLocaleString()}
          </p>
        </div>
        
        <div className="flex items-center gap-4">
          {/* Time period selector */}
          <select
            value={timePeriod}
            onChange={(e) => handleTimePeriodChange(Number(e.target.value))}
            className="px-3 py-2 bg-gray-800 border border-gray-700 rounded-lg text-gray-200 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
          >
            <option value={7}>Last 7 days</option>
            <option value={30}>Last 30 days</option>
            <option value={90}>Last 90 days</option>
          </select>

          {/* Refresh button */}
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="px-4 py-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 rounded-lg text-gray-200 text-sm transition-colors disabled:opacity-50 flex items-center gap-2"
          >
            <span className={refreshing ? 'animate-spin' : ''}>↻</span>
            {refreshing ? 'Refreshing...' : 'Refresh'}
          </button>
        </div>
      </div>

      {/* Global Security Posture Section */}
      <EnterpriseCard variant="elevated">
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Global Security Posture</h3>
        
        <div className="mb-6">
          <div className="flex items-end justify-between mb-2">
            <div>
              <span className="text-sm text-gray-400">Overall Security Score</span>
              <div className="flex items-baseline gap-2">
                <span className={`text-5xl font-bold ${
                  securityScore.score >= 90 ? 'text-green-400' :
                  securityScore.score >= 80 ? 'text-lime-400' :
                  securityScore.score >= 70 ? 'text-yellow-400' :
                  securityScore.score >= 60 ? 'text-orange-400' :
                  'text-red-400'
                }`}>
                  {securityScore.score || 0}
                </span>
                <span className="text-2xl text-gray-400">/100</span>
                <span className={`text-lg px-3 py-1 rounded-lg ${
                  securityScore.grade === 'A' ? 'bg-green-900 text-green-300' :
                  securityScore.grade === 'B' ? 'bg-lime-900 text-lime-300' :
                  securityScore.grade === 'C' ? 'bg-yellow-900 text-yellow-300' :
                  securityScore.grade === 'D' ? 'bg-orange-900 text-orange-300' :
                  'bg-red-900 text-red-300'
                }`}>
                  Grade {securityScore.grade || 'F'}
                </span>
              </div>
            </div>

            {/* Trend indicator */}
            <div className="text-right">
              <div className="text-sm text-gray-400 mb-1">Trend</div>
              <div className={`flex items-center gap-2 text-lg ${
                securityScore.trend === 'improving' ? 'text-green-400' :
                securityScore.trend === 'declining' ? 'text-red-400' :
                'text-gray-400'
              }`}>
                {securityScore.trend === 'improving' && '📈 Improving'}
                {securityScore.trend === 'declining' && '📉 Declining'}
                {securityScore.trend === 'stable' && '→ Stable'}
                {securityScore.delta !== 0 && (
                  <span className="text-sm">({securityScore.delta > 0 ? '+' : ''}{securityScore.delta})</span>
                )}
              </div>
            </div>
          </div>

          <SecurityScoreBar
            score={securityScore.score || 0}
            showLabel={false}
            showScore={false}
            height="h-6"
          />
        </div>

        {/* Key Stats Grid */}
        <div className="grid grid-cols-4 gap-4 pt-4 border-t border-gray-700">
          <div className="text-center">
            <div className="text-2xl font-bold text-gray-100">{securityScore.total_vulnerabilities || 0}</div>
            <div className="text-sm text-gray-400">Total Issues</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">{securityScore.critical_count || 0}</div>
            <div className="text-sm text-gray-400">Critical</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-orange-400">{securityScore.high_count || 0}</div>
            <div className="text-sm text-gray-400">High</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400">{securityScore.medium_count || 0}</div>
            <div className="text-sm text-gray-400">Medium</div>
          </div>
        </div>
      </EnterpriseCard>

      {/* Platform Risk Breakdown */}
      <PlatformRiskBars
        data={platformBreakdown}
        onPlatformClick={handlePlatformClick}
      />

      {/* Risk Heatmap */}
      <div>
        <h3 className="text-lg font-semibold text-gray-200 mb-3">Risk Heatmap - Click to Filter</h3>
        <RiskHeatmap
          data={riskHeatmap}
          onCellClick={handleHeatmapCellClick}
        />
      </div>

      {/* Scan Statistics Grid */}
      <div>
        <h3 className="text-lg font-semibold text-gray-200 mb-3">Scan Activity</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCard
            title="Total Scans"
            value={scanStats.total_scans || 0}
            icon="🔍"
            subtitle={`${scanStats.completed_scans || 0} completed`}
          />
          <StatCard
            title="Running Scans"
            value={scanStats.running_scans || 0}
            icon="⏳"
            variant={scanStats.running_scans > 0 ? 'info' : 'default'}
          />
          <StatCard
            title="Web Scans"
            value={scanStats.scans_by_type?.web || 0}
            icon="🌐"
            onClick={() => handlePlatformClick('web')}
          />
          <StatCard
            title="Mobile Scans"
            value={scanStats.scans_by_type?.mobile || 0}
            icon="📱"
            onClick={() => handlePlatformClick('mobile')}
          />
          <StatCard
            title="Cloud Scans"
            value={scanStats.scans_by_type?.cloud || 0}
            icon="☁️"
            onClick={() => handlePlatformClick('cloud')}
          />
          <StatCard
            title="Network Scans"
            value={scanStats.scans_by_type?.network || 0}
            icon="🔌"
            onClick={() => handlePlatformClick('network')}
          />
          <StatCard
            title="Avg Duration"
            value={`${Math.round(scanStats.avg_scan_duration_seconds || 0)}s`}
            icon="⏱️"
            subtitle="Per scan"
          />
          <StatCard
            title="Failed Scans"
            value={scanStats.failed_scans || 0}
            icon="❌"
            variant={scanStats.failed_scans > 0 ? 'warning' : 'default'}
          />
        </div>
      </div>

      {/* Quick Actions */}
      <EnterpriseCard>
        <h3 className="text-lg font-semibold text-gray-200 mb-4">Quick Actions</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <button
            onClick={() => navigate('/dashboard/new-scan')}
            className="px-4 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors font-medium text-sm"
          >
            ➕ New Scan
          </button>
          <button
            onClick={() => navigate('/dashboard/vulnerabilities')}
            className="px-4 py-3 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 rounded-lg transition-colors font-medium text-sm"
          >
            📋 All Vulnerabilities
          </button>
          <button
            onClick={() => navigate('/dashboard/reports')}
            className="px-4 py-3 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 rounded-lg transition-colors font-medium text-sm"
          >
            📊 Reports
          </button>
          <button
            onClick={() => navigate('/dashboard/scan-history')}
            className="px-4 py-3 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-gray-200 rounded-lg transition-colors font-medium text-sm"
          >
            📜 History
          </button>
        </div>
      </EnterpriseCard>
    </div>
  );
};

export default MasterOverview;
