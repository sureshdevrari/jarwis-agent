// src/components/agent/AgentDownloadPage.jsx
// Enterprise-style agent download page for all security testing modules

import React, { useState, useEffect } from 'react';
import {
  Download,
  Monitor,
  Apple,
  Terminal,
  Copy,
  CheckCircle,
  ExternalLink,
  Shield,
  Cpu,
  Network,
  Smartphone,
  Globe,
  Server,
  Key,
  RefreshCw,
  AlertCircle,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Zap,
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { universalAgentAPI, mobileAgentAPI, serverConfigAPI } from '../../services/api';

// Platform detection
const detectPlatform = () => {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('win')) return 'windows';
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('linux')) return 'linux';
  return 'windows';
};

// Agent version and download info
const AGENT_VERSION = '2.1.0';
const RELEASE_DATE = '2026-01-20';
const GITHUB_RELEASE_BASE = `https://github.com/sureshdevrari/jarwis-agent/releases/download/v${AGENT_VERSION}`;

const DOWNLOAD_OPTIONS = {
  windows: {
    name: 'Windows',
    icon: Monitor,
    description: 'Windows 10/11 (64-bit)',
    downloads: [
      {
        id: 'gui',
        name: 'GUI Installer',
        filename: 'JarwisAgentSetup-GUI.exe',
        size: '45 MB',
        recommended: true,
        description: '⭐ Professional installer wizard with branding and EULA',
        silentCmd: null,
        directUrl: `${GITHUB_RELEASE_BASE}/JarwisAgentSetup-GUI.exe`,
      },
      {
        id: 'exe',
        name: 'CLI Executable',
        filename: 'jarwis-agent.exe',
        size: '15 MB',
        recommended: false,
        description: 'Standalone executable for advanced users',
        silentCmd: 'jarwis-agent.exe --activate YOUR_KEY --service',
        directUrl: `${GITHUB_RELEASE_BASE}/jarwis-agent.exe`,
      },
    ],
    requirements: [
      'Windows 10 version 1903 or later',
      'Windows 11 (all versions)',
      '4 GB RAM minimum',
      '500 MB free disk space',
      'Administrator privileges for installation',
    ],
  },
  macos: {
    name: 'macOS',
    icon: Apple,
    description: 'macOS 11+ (Intel & Apple Silicon)',
    downloads: [
      {
        id: 'dmg',
        name: 'DMG Installer',
        filename: `JarwisAgentSetup-${AGENT_VERSION}.dmg`,
        size: '45 MB',
        recommended: true,
        description: '⭐ DMG with professional GUI installer wizard',
        silentCmd: null,
        directUrl: `${GITHUB_RELEASE_BASE}/JarwisAgentSetup-${AGENT_VERSION}.dmg`,
      },
      {
        id: 'binary',
        name: 'CLI Binary',
        filename: 'jarwis-agent-macos',
        size: '14 MB',
        recommended: false,
        description: 'Standalone binary for advanced users',
        silentCmd: 'chmod +x jarwis-agent-macos && sudo mv jarwis-agent-macos /usr/local/bin/jarwis-agent',
        directUrl: `${GITHUB_RELEASE_BASE}/jarwis-agent-macos`,
      },
    ],
    requirements: [
      'macOS 11 Big Sur or later',
      'Intel or Apple Silicon (M1/M2/M3)',
      '4 GB RAM minimum',
      '500 MB free disk space',
      'Administrator password for installation',
    ],
  },
  linux: {
    name: 'Linux',
    icon: Terminal,
    description: 'Ubuntu, Debian, RHEL, CentOS',
    downloads: [
      {
        id: 'installer',
        name: 'GUI Installer',
        filename: `jarwis-agent-${AGENT_VERSION}-linux-installer.tar.gz`,
        size: '50 MB',
        recommended: true,
        description: '⭐ Extract & run install.sh - launches GUI wizard if X11 available',
        silentCmd: 'tar -xzf jarwis-agent-*-linux-installer.tar.gz && sudo ./install.sh',
        directUrl: `${GITHUB_RELEASE_BASE}/jarwis-agent-${AGENT_VERSION}-linux-installer.tar.gz`,
      },
      {
        id: 'deb',
        name: 'DEB Package',
        filename: `jarwis-agent_${AGENT_VERSION}_amd64.deb`,
        size: '28 MB',
        recommended: false,
        description: 'For Ubuntu, Debian, Linux Mint',
        silentCmd: `sudo dpkg -i jarwis-agent_${AGENT_VERSION}_amd64.deb`,
        directUrl: `${GITHUB_RELEASE_BASE}/jarwis-agent_${AGENT_VERSION}_amd64.deb`,
      },
      {
        id: 'rpm',
        name: 'RPM Package',
        filename: `jarwis-agent-${AGENT_VERSION}-1.x86_64.rpm`,
        size: '28 MB',
        recommended: false,
        description: 'For RHEL, CentOS, Fedora, Rocky',
        silentCmd: `sudo rpm -i jarwis-agent-${AGENT_VERSION}-1.x86_64.rpm`,
        directUrl: `${GITHUB_RELEASE_BASE}/jarwis-agent-${AGENT_VERSION}-1.x86_64.rpm`,
      },
      {
        id: 'binary',
        name: 'CLI Binary',
        filename: 'jarwis-agent-linux',
        size: '28 MB',
        recommended: false,
        description: 'Portable binary for any Linux distro',
        silentCmd: 'chmod +x jarwis-agent-linux && sudo mv jarwis-agent-linux /usr/local/bin/jarwis-agent',
        directUrl: `${GITHUB_RELEASE_BASE}/jarwis-agent-linux`,
      },
    ],
    requirements: [
      'Ubuntu 18.04+, Debian 10+',
      'RHEL/CentOS 7+, Fedora 30+',
      'x86_64 or ARM64 architecture',
      '4 GB RAM minimum',
      '500 MB free disk space',
      'Root/sudo privileges',
    ],
  },
};

// Scan types that benefit from the agent
const AGENT_USE_CASES = [
  {
    id: 'web',
    name: 'Web Security Scanning',
    icon: Globe,
    description: 'OWASP Top 10, XSS, SQL Injection, SSRF testing',
    required: true,
  },
  {
    id: 'mobile-dynamic',
    name: 'Mobile Dynamic Analysis',
    icon: Smartphone,
    description: 'Runtime analysis with Frida, SSL bypass, API interception',
    required: true,
  },
  {
    id: 'network-internal',
    name: 'Internal Network Scanning',
    icon: Network,
    description: 'Port scanning, service detection, vulnerability assessment on internal IPs',
    required: true,
  },
  {
    id: 'cloud',
    name: 'Cloud Security Assessment',
    icon: Server,
    description: 'AWS, Azure, GCP, Kubernetes security scanning',
    required: true,
  },
  {
    id: 'sast',
    name: 'Source Code Analysis',
    icon: Cpu,
    description: 'Static code analysis for secrets, vulnerabilities, dependencies',
    required: true,
  },
];

// Network requirements for agent connectivity
const NETWORK_REQUIREMENTS = {
  outbound: [
    { port: 443, protocol: 'TCP/WSS', destination: 'api.jarwis.io', purpose: 'WebSocket connection to Jarwis server' },
    { port: 443, protocol: 'HTTPS', destination: '*.jarwis.io', purpose: 'API calls and updates' },
  ],
  note: 'All connections are outbound only. No inbound ports need to be opened.',
};

// Installation steps per OS
const INSTALLATION_STEPS = {
  windows: [
    { step: 1, title: 'Download GUI Installer', description: 'Download JarwisAgentSetup-GUI.exe (recommended)' },
    { step: 2, title: 'Run Installer', description: 'Double-click to launch the professional setup wizard' },
    { step: 3, title: 'Configure Server', description: 'Server URL is pre-filled with the URL shown above. Change only if using a different Jarwis server' },
    { step: 4, title: 'Enter Activation Key', description: 'Copy your activation key from below (optional - can activate later)' },
    { step: 5, title: 'Complete Setup', description: 'Agent connects automatically. Tray icon shows connection status' },
  ],
  macos: [
    { step: 1, title: 'Download DMG', description: 'Download JarwisAgentSetup DMG with GUI installer' },
    { step: 2, title: 'Run Installer', description: 'Mount DMG and run the installer wizard' },
    { step: 3, title: 'Configure Server', description: 'Enter the Server URL shown above (or your self-hosted server URL)' },
    { step: 4, title: 'Enter Activation Key', description: 'Paste your activation key or skip to activate later' },
    { step: 5, title: 'Grant Permissions', description: 'Allow the agent in System Preferences → Security & Privacy if prompted' },
  ],
  linux: [
    { step: 1, title: 'Download Installer', description: 'Download the GUI installer tarball or DEB/RPM package' },
    { step: 2, title: 'Run Installer', description: 'Extract tarball and run ./install.sh (launches GUI if X11 available)' },
    { step: 3, title: 'Configure Server', description: 'Enter the Server URL shown above (or your self-hosted server URL)' },
    { step: 4, title: 'Enter Activation Key', description: 'Paste your activation key or skip to activate later' },
    { step: 5, title: 'Start Service', description: 'Installer enables systemd service automatically' },
  ],
};

// Server configuration info - will be overridden by dynamic config
const DEFAULT_SERVER_CONFIG = {
  defaultUrl: window.location.origin,
  description: 'The Jarwis Server URL is where your agent connects to receive scan commands and send results.',
  selfHostedNote: 'If your organization uses a self-hosted Jarwis server, enter that URL instead.',
};

// Troubleshooting FAQ
const TROUBLESHOOTING = [
  {
    question: 'Agent shows "Connection Failed"',
    answer: 'Check your firewall allows outbound connections on port 443 to api.jarwis.io. If behind a corporate proxy, configure the agent with: jarwis-agent --proxy http://proxy:port',
  },
  {
    question: 'Installation fails on Windows',
    answer: 'Right-click the installer and select "Run as Administrator". If SmartScreen blocks it, click "More info" → "Run anyway".',
  },
  {
    question: 'Permission denied on Linux/macOS',
    answer: 'Use sudo for installation: sudo dpkg -i jarwis-agent.deb or sudo installer -pkg jarwis-agent.pkg -target /',
  },
  {
    question: 'Agent not starting automatically',
    answer: 'Windows: Check Services (services.msc) for "Jarwis Agent". Linux: Run sudo systemctl status jarwis-agent. macOS: Check /Library/LaunchDaemons/com.jarwis.agent.plist',
  },
  {
    question: 'How do I update the agent?',
    answer: 'Download the latest version and install over the existing one. Your activation key will be preserved.',
  },
];

// Cache key for server config
const SERVER_CONFIG_CACHE_KEY = 'jarwis_server_config';
const SERVER_CONFIG_CACHE_TTL = 5 * 60 * 1000; // 5 minutes

// Get cached config or return null
const getCachedServerConfig = () => {
  try {
    const cached = sessionStorage.getItem(SERVER_CONFIG_CACHE_KEY);
    if (cached) {
      const { data, timestamp } = JSON.parse(cached);
      if (Date.now() - timestamp < SERVER_CONFIG_CACHE_TTL) {
        return data;
      }
    }
  } catch (e) {
    console.warn('Failed to read server config cache:', e);
  }
  return null;
};

// Save config to cache
const setCachedServerConfig = (config) => {
  try {
    sessionStorage.setItem(SERVER_CONFIG_CACHE_KEY, JSON.stringify({
      data: config,
      timestamp: Date.now()
    }));
  } catch (e) {
    console.warn('Failed to cache server config:', e);
  }
};

const AgentDownloadPage = () => {
  const { isDarkMode } = useTheme();
  const [selectedPlatform, setSelectedPlatform] = useState(detectPlatform());
  const [activationKey, setActivationKey] = useState(null);
  const [keyLoading, setKeyLoading] = useState(false);
  const [keyError, setKeyError] = useState(null);
  const [connectedAgents, setConnectedAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [copied, setCopied] = useState(null);
  const [expandedDownload, setExpandedDownload] = useState(null);
  const [showAllPlatforms, setShowAllPlatforms] = useState(false);
  // Initialize with immediate fallback to window.location.origin
  const [serverUrl, setServerUrl] = useState(() => {
    // Priority: 1. Cached config 2. Environment variable 3. window.location.origin
    const cached = getCachedServerConfig();
    if (cached?.server_url) return cached.server_url;
    if (import.meta.env.VITE_JARWIS_SERVER_URL) return import.meta.env.VITE_JARWIS_SERVER_URL;
    return window.location.origin;
  });
  const [serverConfigLoading, setServerConfigLoading] = useState(false); // Start false since we have immediate fallback

  // Load server config, connected agents, and activation key on mount
  useEffect(() => {
    fetchServerConfig();
    fetchConnectedAgents();
    generateActivationKey();
  }, []);

  const fetchServerConfig = async () => {
    // Check cache first
    const cached = getCachedServerConfig();
    if (cached?.server_url) {
      setServerUrl(cached.server_url);
      return; // Use cached value, skip API call
    }

    setServerConfigLoading(true);
    try {
      const config = await serverConfigAPI.getAgentSetupConfig();
      const url = config.server_url || window.location.origin;
      setServerUrl(url);
      // Cache the successful response
      setCachedServerConfig({ server_url: url, ...config });
    } catch (err) {
      console.error('Failed to fetch server config:', err);
      // Fallback already set via useState initializer - window.location.origin handles 99% of cases
    } finally {
      setServerConfigLoading(false);
    }
  };

  const fetchConnectedAgents = async () => {
    setAgentsLoading(true);
    try {
      // Try universal agent API first, fall back to mobile agent API
      try {
        const response = await universalAgentAPI.listAgents();
        setConnectedAgents(response?.agents || []);
      } catch {
        const response = await mobileAgentAPI.listAgents();
        setConnectedAgents(response?.agents || []);
      }
    } catch (err) {
      console.error('Failed to fetch agents:', err);
    } finally {
      setAgentsLoading(false);
    }
  };

  const generateActivationKey = async () => {
    setKeyLoading(true);
    setKeyError(null);
    try {
      // Try universal agent API first, fall back to mobile agent API
      try {
        const data = await universalAgentAPI.getToken();
        setActivationKey(data.token);
      } catch {
        const data = await mobileAgentAPI.getAgentToken();
        setActivationKey(data.token);
      }
    } catch (err) {
      console.error('Failed to generate key:', err);
      setKeyError(err.message || 'Failed to generate activation key');
    } finally {
      setKeyLoading(false);
    }
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  // State for download errors
  const [downloadError, setDownloadError] = useState(null);
  const [downloading, setDownloading] = useState(null);

  const handleDownload = async (platform, downloadId, directUrl = null) => {
    setDownloading(downloadId);
    setDownloadError(null);
    
    try {
      // If we have a direct URL (GitHub release), use it directly
      if (directUrl) {
        window.open(directUrl, '_blank');
        setDownloading(null);
        return;
      }
      
      // Fallback to backend API endpoint for downloads
      const response = await universalAgentAPI.downloadAgent(platform, downloadId);
      
      // If we get a redirect URL, open it
      if (response?.download_url) {
        window.open(response.download_url, '_blank');
      }
    } catch (error) {
      console.error('Download error:', error);
      const errorDetail = error.response?.data?.detail;
      
      if (errorDetail?.error === 'build_not_found') {
        setDownloadError({
          type: 'not_built',
          message: errorDetail.message,
          buildCommand: errorDetail.build_command,
          platform: errorDetail.platform,
        });
      } else {
        setDownloadError({
          type: 'error',
          message: error.response?.data?.detail || error.message || 'Download failed',
        });
      }
    } finally {
      setDownloading(null);
    }
  };

  // Styles
  const cardBg = isDarkMode ? 'bg-gray-800' : 'bg-white';
  const cardBorder = isDarkMode ? 'border-gray-700' : 'border-gray-200';
  const textPrimary = isDarkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = isDarkMode ? 'text-gray-400' : 'text-gray-600';
  const hoverBg = isDarkMode ? 'hover:bg-gray-700' : 'hover:bg-gray-50';

  const platformInfo = DOWNLOAD_OPTIONS[selectedPlatform];
  const PlatformIcon = platformInfo.icon;

  return (
    <div className={`min-h-screen ${isDarkMode ? 'bg-gray-900' : 'bg-gray-50'}`}>
      <div className="max-w-6xl mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-gradient-to-br from-purple-500 to-indigo-600 mb-4">
            <Shield className="w-8 h-8 text-white" />
          </div>
          <h1 className={`text-3xl font-bold ${textPrimary} mb-2`}>
            Download Jarwis Agent
          </h1>
          <p className={`${textSecondary} max-w-2xl mx-auto`}>
            Install the lightweight Jarwis Agent on your systems to enable internal security testing.
            The agent runs in the background and securely connects to your Jarwis cloud console.
          </p>
        </div>

        {/* Server URL & Activation Key Section */}
        <div className={`${cardBg} border ${cardBorder} rounded-xl p-6 mb-8`}>
          {/* Server URL Info */}
          <div className="flex items-start gap-4 mb-6 pb-6 border-b border-gray-200 dark:border-gray-700">
            <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-blue-500/10 flex items-center justify-center">
              <Server className="w-5 h-5 text-blue-500" />
            </div>
            <div className="flex-1">
              <h2 className={`text-lg font-semibold ${textPrimary} mb-1`}>
                Jarwis Server URL
              </h2>
              <p className={`${textSecondary} text-sm mb-3`}>
                The installer will ask for the server URL. Use the default unless you have a self-hosted Jarwis server.
              </p>
              <div className="flex items-center gap-3">
                <code className={`flex-1 px-4 py-3 rounded-lg font-mono text-sm ${
                  isDarkMode ? 'bg-gray-900 text-blue-400' : 'bg-gray-100 text-blue-600'
                }`}>
                  {serverConfigLoading ? 'Loading...' : serverUrl}
                </code>
                <button
                  onClick={() => copyToClipboard(serverUrl, 'server-url')}
                  className={`p-3 rounded-lg ${hoverBg} border ${cardBorder} transition-colors`}
                  title="Copy to clipboard"
                  disabled={serverConfigLoading}
                >
                  {copied === 'server-url' ? (
                    <Check className="w-5 h-5 text-green-500" />
                  ) : (
                    <Copy className="w-5 h-5" />
                  )}
                </button>
              </div>
              <p className={`${textSecondary} text-xs mt-2`}>
                💡 This is pre-filled in the installer. Only change if using a self-hosted Jarwis deployment.
              </p>
            </div>
          </div>

          {/* Activation Key */}
          <div className="flex items-start gap-4">
            <div className="flex-shrink-0 w-10 h-10 rounded-lg bg-amber-500/10 flex items-center justify-center">
              <Key className="w-5 h-5 text-amber-500" />
            </div>
            <div className="flex-1">
              <h2 className={`text-lg font-semibold ${textPrimary} mb-1`}>
                Your Activation Key <span className={`text-sm font-normal ${textSecondary}`}>(Optional)</span>
              </h2>
              <p className={`${textSecondary} text-sm mb-4`}>
                This key links the agent to your account. You can enter it during installation or activate later from the dashboard.
              </p>
              
              {keyLoading ? (
                <div className="flex items-center gap-2 text-sm">
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span className={textSecondary}>Generating key...</span>
                </div>
              ) : keyError ? (
                <div className="flex items-center gap-2 text-red-500 text-sm">
                  <AlertCircle className="w-4 h-4" />
                  <span>{keyError}</span>
                  <button
                    onClick={generateActivationKey}
                    className="text-purple-500 hover:text-purple-400 underline"
                  >
                    Retry
                  </button>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <code className={`flex-1 px-4 py-3 rounded-lg font-mono text-sm ${
                    isDarkMode ? 'bg-gray-900 text-green-400' : 'bg-gray-100 text-green-600'
                  } break-all`}>
                    {activationKey || 'XXXX-XXXX-XXXX-XXXX'}
                  </code>
                  <button
                    onClick={() => copyToClipboard(activationKey, 'activation-key')}
                    className={`p-3 rounded-lg ${hoverBg} border ${cardBorder} transition-colors`}
                    title="Copy to clipboard"
                  >
                    {copied === 'activation-key' ? (
                      <Check className="w-5 h-5 text-green-500" />
                    ) : (
                      <Copy className="w-5 h-5" />
                    )}
                  </button>
                  <button
                    onClick={generateActivationKey}
                    className={`p-3 rounded-lg ${hoverBg} border ${cardBorder} transition-colors`}
                    title="Generate new key"
                  >
                    <RefreshCw className="w-5 h-5" />
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {/* Platform Selection */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-8">
          {Object.entries(DOWNLOAD_OPTIONS).map(([key, platform]) => {
            const Icon = platform.icon;
            const isSelected = selectedPlatform === key;
            return (
              <button
                key={key}
                onClick={() => setSelectedPlatform(key)}
                className={`p-4 rounded-xl border-2 text-left transition-all ${
                  isSelected
                    ? 'border-purple-500 bg-purple-500/10'
                    : `${cardBorder} ${cardBg} ${hoverBg}`
                }`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                    isSelected ? 'bg-purple-500/20' : isDarkMode ? 'bg-gray-700' : 'bg-gray-100'
                  }`}>
                    <Icon className={`w-5 h-5 ${isSelected ? 'text-purple-500' : textSecondary}`} />
                  </div>
                  <div>
                    <div className={`font-semibold ${textPrimary}`}>{platform.name}</div>
                    <div className={`text-sm ${textSecondary}`}>{platform.description}</div>
                  </div>
                  {key === detectPlatform() && (
                    <span className="ml-auto px-2 py-1 text-xs rounded-full bg-green-500/10 text-green-500">
                      Detected
                    </span>
                  )}
                </div>
              </button>
            );
          })}
        </div>

        {/* Download Options */}
        <div className={`${cardBg} border ${cardBorder} rounded-xl overflow-hidden mb-8`}>
          <div className="p-6 border-b border-gray-700/50">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <PlatformIcon className="w-6 h-6 text-purple-500" />
                <div>
                  <h2 className={`text-xl font-semibold ${textPrimary}`}>
                    {platformInfo.name} Downloads
                  </h2>
                  <p className={`text-sm ${textSecondary}`}>
                    Version {AGENT_VERSION} • Released {RELEASE_DATE}
                  </p>
                </div>
              </div>
            </div>
          </div>

          <div className="divide-y divide-gray-700/50">
            {platformInfo.downloads.map((download) => (
              <div key={download.id} className="p-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                      isDarkMode ? 'bg-gray-700' : 'bg-gray-100'
                    }`}>
                      <Download className="w-6 h-6 text-purple-500" />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`font-semibold ${textPrimary}`}>{download.name}</span>
                        {download.recommended && (
                          <span className="px-2 py-0.5 text-xs rounded-full bg-green-500/10 text-green-500 font-medium">
                            Recommended
                          </span>
                        )}
                      </div>
                      <div className={`text-sm ${textSecondary}`}>
                        {download.filename} • {download.size}
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setExpandedDownload(
                        expandedDownload === download.id ? null : download.id
                      )}
                      className={`p-2 rounded-lg ${hoverBg} transition-colors`}
                    >
                      {expandedDownload === download.id ? (
                        <ChevronDown className="w-5 h-5" />
                      ) : (
                        <ChevronRight className="w-5 h-5" />
                      )}
                    </button>
                    <button
                      onClick={() => handleDownload(selectedPlatform, download.id, download.directUrl)}
                      disabled={downloading === download.id}
                      className={`px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg font-medium transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed`}
                    >
                      {downloading === download.id ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          Downloading...
                        </>
                      ) : (
                        <>
                          <Download className="w-4 h-4" />
                          Download
                        </>
                      )}
                    </button>
                  </div>
                </div>

                {/* Download Error */}
                {downloadError && downloadError.platform === selectedPlatform && (
                  <div className={`mt-4 p-4 rounded-lg ${isDarkMode ? 'bg-red-900/20 border border-red-800' : 'bg-red-50 border border-red-200'}`}>
                    <div className="flex items-start gap-3">
                      <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                      <div className="flex-1">
                        <p className={`font-medium ${isDarkMode ? 'text-red-300' : 'text-red-800'}`}>
                          {downloadError.type === 'not_built' ? 'Agent Not Built' : 'Download Failed'}
                        </p>
                        <p className={`text-sm mt-1 ${isDarkMode ? 'text-red-400' : 'text-red-600'}`}>
                          {downloadError.message}
                        </p>
                        {downloadError.buildCommand && (
                          <div className="mt-3">
                            <p className={`text-sm font-medium ${textPrimary} mb-1`}>Build Command:</p>
                            <code className={`block px-3 py-2 rounded text-sm font-mono ${
                              isDarkMode ? 'bg-gray-800' : 'bg-gray-100'
                            }`}>
                              {downloadError.buildCommand}
                            </code>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* Expanded details */}
                {expandedDownload === download.id && (
                  <div className={`mt-4 pt-4 border-t ${cardBorder}`}>
                    <p className={`${textSecondary} text-sm mb-4`}>{download.description}</p>
                    
                    {download.silentCmd && (
                      <div>
                        <div className={`text-sm font-medium ${textPrimary} mb-2`}>
                          Silent Install Command:
                        </div>
                        <div className="flex items-center gap-2">
                          <code className={`flex-1 px-3 py-2 rounded-lg font-mono text-sm ${
                            isDarkMode ? 'bg-gray-900' : 'bg-gray-100'
                          } overflow-x-auto`}>
                            {download.silentCmd.replace('YOUR_KEY', activationKey || 'YOUR_KEY')}
                          </code>
                          <button
                            onClick={() => copyToClipboard(
                              download.silentCmd.replace('YOUR_KEY', activationKey || 'YOUR_KEY'),
                              `cmd-${download.id}`
                            )}
                            className={`p-2 rounded-lg ${hoverBg} border ${cardBorder}`}
                          >
                            {copied === `cmd-${download.id}` ? (
                              <Check className="w-4 h-4 text-green-500" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* System Requirements */}
          <div className={`p-4 ${isDarkMode ? 'bg-gray-800/50' : 'bg-gray-50'}`}>
            <div className={`text-sm font-medium ${textPrimary} mb-2`}>System Requirements:</div>
            <ul className={`text-sm ${textSecondary} grid grid-cols-1 md:grid-cols-2 gap-1`}>
              {platformInfo.requirements.map((req, i) => (
                <li key={i} className="flex items-center gap-2">
                  <Check className="w-4 h-4 text-green-500 flex-shrink-0" />
                  {req}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* When You Need the Agent */}
        <div className={`${cardBg} border ${cardBorder} rounded-xl p-6 mb-8`}>
          <h2 className={`text-xl font-semibold ${textPrimary} mb-4`}>
            When You Need the Agent
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {AGENT_USE_CASES.map((useCase) => {
              const Icon = useCase.icon;
              return (
                <div
                  key={useCase.id}
                  className={`p-4 rounded-lg ${isDarkMode ? 'bg-gray-700/50' : 'bg-gray-50'}`}
                >
                  <div className="flex items-start gap-3">
                    <div className={`w-10 h-10 rounded-lg flex items-center justify-center ${
                      useCase.required ? 'bg-purple-500/20' : 'bg-gray-500/20'
                    }`}>
                      <Icon className={`w-5 h-5 ${useCase.required ? 'text-purple-500' : textSecondary}`} />
                    </div>
                    <div>
                      <div className="flex items-center gap-2">
                        <span className={`font-medium ${textPrimary}`}>{useCase.name}</span>
                        {useCase.required && (
                          <span className="px-2 py-0.5 text-xs rounded-full bg-purple-500/10 text-purple-500">
                            Required
                          </span>
                        )}
                      </div>
                      <p className={`text-sm ${textSecondary} mt-1`}>{useCase.description}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
          <div className={`mt-4 p-4 rounded-lg ${isDarkMode ? 'bg-blue-500/10' : 'bg-blue-50'} border ${isDarkMode ? 'border-blue-500/20' : 'border-blue-200'}`}>
            <div className="flex items-start gap-3">
              <Zap className="w-5 h-5 text-blue-500 mt-0.5" />
              <div>
                <div className={`font-medium ${textPrimary}`}>All Scan Types Require Agent:</div>
                <p className={`text-sm ${textSecondary} mt-1`}>
                  For enhanced security, all scan types now require a connected Jarwis Agent. 
                  Your credentials and scan data stay local on your machine.
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* Installation Steps */}
        <div className={`${cardBg} border ${cardBorder} rounded-xl p-6 mb-8`}>
          <h2 className={`text-xl font-semibold ${textPrimary} mb-4`}>
            Installation Steps for {platformInfo.name}
          </h2>
          <div className="space-y-4">
            {INSTALLATION_STEPS[selectedPlatform].map((item) => (
              <div key={item.step} className="flex items-start gap-4">
                <div className="w-8 h-8 rounded-full bg-purple-600 flex items-center justify-center text-white font-bold text-sm flex-shrink-0">
                  {item.step}
                </div>
                <div>
                  <div className={`font-medium ${textPrimary}`}>{item.title}</div>
                  <p className={`text-sm ${textSecondary} mt-1`}>{item.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Network Requirements */}
        <div className={`${cardBg} border ${cardBorder} rounded-xl p-6 mb-8`}>
          <h2 className={`text-xl font-semibold ${textPrimary} mb-4`}>
            Network Requirements
          </h2>
          <p className={`text-sm ${textSecondary} mb-4`}>{NETWORK_REQUIREMENTS.note}</p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className={`${isDarkMode ? 'bg-gray-700/50' : 'bg-gray-50'}`}>
                  <th className={`px-4 py-2 text-left font-medium ${textPrimary}`}>Port</th>
                  <th className={`px-4 py-2 text-left font-medium ${textPrimary}`}>Protocol</th>
                  <th className={`px-4 py-2 text-left font-medium ${textPrimary}`}>Destination</th>
                  <th className={`px-4 py-2 text-left font-medium ${textPrimary}`}>Purpose</th>
                </tr>
              </thead>
              <tbody>
                {NETWORK_REQUIREMENTS.outbound.map((req, i) => (
                  <tr key={i} className={`border-t ${cardBorder}`}>
                    <td className={`px-4 py-2 ${textPrimary}`}>{req.port}</td>
                    <td className={`px-4 py-2 ${textSecondary}`}>{req.protocol}</td>
                    <td className={`px-4 py-2 font-mono text-xs ${textSecondary}`}>{req.destination}</td>
                    <td className={`px-4 py-2 ${textSecondary}`}>{req.purpose}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Troubleshooting */}
        <div className={`${cardBg} border ${cardBorder} rounded-xl p-6 mb-8`}>
          <h2 className={`text-xl font-semibold ${textPrimary} mb-4 flex items-center gap-2`}>
            <AlertCircle className="w-5 h-5" />
            Troubleshooting
          </h2>
          <div className="space-y-4">
            {TROUBLESHOOTING.map((item, i) => (
              <details key={i} className={`group rounded-lg border ${cardBorder}`}>
                <summary className={`px-4 py-3 cursor-pointer font-medium ${textPrimary} hover:${isDarkMode ? 'bg-gray-700/50' : 'bg-gray-50'} rounded-lg flex items-center justify-between`}>
                  {item.question}
                  <ChevronRight className="w-4 h-4 group-open:rotate-90 transition-transform" />
                </summary>
                <div className={`px-4 py-3 text-sm ${textSecondary} border-t ${cardBorder}`}>
                  {item.answer}
                </div>
              </details>
            ))}
          </div>
        </div>

        {/* Connected Agents */}
        <div className={`${cardBg} border ${cardBorder} rounded-xl p-6`}>
          <div className="flex items-center justify-between mb-4">
            <h2 className={`text-xl font-semibold ${textPrimary}`}>
              Connected Agents
            </h2>
            <button
              onClick={fetchConnectedAgents}
              className={`p-2 rounded-lg ${hoverBg} transition-colors`}
              title="Refresh"
            >
              <RefreshCw className={`w-5 h-5 ${agentsLoading ? 'animate-spin' : ''}`} />
            </button>
          </div>

          {agentsLoading ? (
            <div className="flex items-center justify-center py-8">
              <RefreshCw className="w-6 h-6 animate-spin text-purple-500" />
            </div>
          ) : connectedAgents.length === 0 ? (
            <div className="text-center py-8">
              <div className={`w-16 h-16 rounded-full ${isDarkMode ? 'bg-gray-700' : 'bg-gray-100'} mx-auto mb-4 flex items-center justify-center`}>
                <Cpu className="w-8 h-8 text-gray-400" />
              </div>
              <p className={`${textSecondary} mb-2`}>No agents connected yet</p>
              <p className={`text-sm ${textSecondary}`}>
                Download and install the agent using the options above
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {connectedAgents.map((agent) => (
                <div
                  key={agent.agent_id}
                  className={`p-4 rounded-lg ${isDarkMode ? 'bg-gray-700/50' : 'bg-gray-50'} flex items-center justify-between`}
                >
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-lg bg-green-500/20 flex items-center justify-center">
                      <CheckCircle className="w-5 h-5 text-green-500" />
                    </div>
                    <div>
                      <div className={`font-medium ${textPrimary}`}>
                        {agent.hostname || agent.agent_id}
                      </div>
                      <div className={`text-sm ${textSecondary} flex items-center gap-3`}>
                        <span>{agent.os || 'Unknown OS'}</span>
                        <span>•</span>
                        <span>v{agent.version || '1.0.0'}</span>
                        <span>•</span>
                        <span className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : 'Just now'}
                        </span>
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-3 py-1 text-xs rounded-full bg-green-500/10 text-green-500 font-medium">
                      Online
                    </span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Documentation Link */}
        <div className="mt-8 text-center">
          <a
            href="https://docs.jarwis.io/agent"
            target="_blank"
            rel="noopener noreferrer"
            className={`inline-flex items-center gap-2 ${textSecondary} hover:text-purple-500 transition-colors`}
          >
            <ExternalLink className="w-4 h-4" />
            View full documentation
          </a>
        </div>
      </div>
    </div>
  );
};

export default AgentDownloadPage;
