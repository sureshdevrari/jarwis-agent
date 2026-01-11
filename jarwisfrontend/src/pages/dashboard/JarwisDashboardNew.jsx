// Unified Enterprise Dashboard with Tab Navigation
import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import MiftyJarwisLayout from '../../components/layout/MiftyJarwisLayout';
import DashboardShell from '../../components/dashboardTheme/DashboardShell';
import { featureFlags } from '../../config/features';
import { useAuth } from '../../context/AuthContext';
import { useTheme } from '../../context/ThemeContext';
import MasterOverview from '../../components/dashboard/MasterOverview';
import WebSecurityTab from '../../components/dashboard/WebSecurityTab';
import MobileSecurityTab from '../../components/dashboard/MobileSecurityTab';
import CloudSecurityTab from '../../components/dashboard/CloudSecurityTab';
import NetworkSecurityTab from '../../components/dashboard/NetworkSecurityTab';

const JarwisDashboard = () => {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { isDarkMode } = useTheme();
  const [activeTab, setActiveTab] = useState('overview');
  const Layout = featureFlags.useNewDashboard ? DashboardShell : MiftyJarwisLayout;

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📊' },
    { id: 'web', label: 'Web Security', icon: '🌐' },
    { id: 'mobile', label: 'Mobile Security', icon: '📱' },
    { id: 'cloud', label: 'Cloud Security', icon: '☁️' },
    { id: 'network', label: 'Network Security', icon: '🔌' }
  ];

  // Handle navigation from master overview to platform tabs
  const handleNavigateToPlatform = (platform) => {
    setActiveTab(platform);
  };

  // Handle navigation to vulnerabilities with filters
  const handleNavigateToVulnerabilities = (filters = {}) => {
    const queryParams = new URLSearchParams(filters).toString();
    navigate(`/dashboard/vulnerabilities${queryParams ? `?${queryParams}` : ''}`);
  };

  return (
    <Layout>
      <div className="min-h-screen">
        {/* Header */}
        <div className="mb-6">
          <h1 className={`text-3xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
            Security Dashboard
          </h1>
          <p className={`mt-2 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            Welcome back, <span className="font-semibold">{user?.name || user?.email}</span>
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="mb-6">
          <div className={`border-b ${isDarkMode ? 'border-gray-700' : 'border-gray-200'}`}>
            <nav className="-mb-px flex space-x-4 overflow-x-auto">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`
                    whitespace-nowrap py-4 px-6 border-b-2 font-medium text-sm
                    flex items-center gap-2 transition-all duration-200
                    ${
                      activeTab === tab.id
                        ? isDarkMode
                          ? 'border-blue-500 text-blue-400'
                          : 'border-blue-600 text-blue-600'
                        : isDarkMode
                        ? 'border-transparent text-gray-400 hover:text-gray-300 hover:border-gray-600'
                        : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                    }
                  `}
                >
                  <span className="text-lg">{tab.icon}</span>
                  <span>{tab.label}</span>
                </button>
              ))}
            </nav>
          </div>
        </div>

        {/* Tab Content */}
        <div className="transition-all duration-300">
          {activeTab === 'overview' && (
            <MasterOverview
              onNavigateToPlatform={handleNavigateToPlatform}
              onNavigateToVulnerabilities={handleNavigateToVulnerabilities}
            />
          )}
          {activeTab === 'web' && <WebSecurityTab />}
          {activeTab === 'mobile' && <MobileSecurityTab />}
          {activeTab === 'cloud' && <CloudSecurityTab />}
          {activeTab === 'network' && <NetworkSecurityTab />}
        </div>
      </div>
    </Layout>
  );
};

export default JarwisDashboard;
