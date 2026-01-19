// src/components/mobile/AgentSetupWizard.jsx
// Step-by-step wizard for setting up Jarwis Mobile Agent on client machines

import React, { useState, useEffect } from 'react';
import {
  Monitor,
  Terminal,
  CheckCircle,
  XCircle,
  Copy,
  ExternalLink,
  Loader2,
  RefreshCw,
  Smartphone,
  Wifi,
  Shield,
  Download,
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  Info,
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { mobileAgentAPI } from '../../services/api';

// Platform detection
const detectPlatform = () => {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('win')) return 'windows';
  if (ua.includes('mac')) return 'macos';
  if (ua.includes('linux')) return 'linux';
  return 'windows';
};

// Prerequisites for each platform
const PREREQUISITES = {
  windows: [
    { id: 'python', name: 'Python 3.9+', command: 'python --version', installUrl: 'https://www.python.org/downloads/' },
    { id: 'adb', name: 'Android Debug Bridge (ADB)', command: 'adb --version', installUrl: 'https://developer.android.com/studio' },
    { id: 'frida', name: 'Frida Tools', command: 'frida --version', installUrl: null, pipInstall: 'pip install frida-tools' },
    { id: 'mitmproxy', name: 'mitmproxy', command: 'mitmdump --version', installUrl: null, pipInstall: 'pip install mitmproxy' },
  ],
  macos: [
    { id: 'python', name: 'Python 3.9+', command: 'python3 --version', installUrl: 'https://www.python.org/downloads/' },
    { id: 'adb', name: 'Android Debug Bridge (ADB)', command: 'adb --version', installUrl: 'https://developer.android.com/studio' },
    { id: 'frida', name: 'Frida Tools', command: 'frida --version', installUrl: null, pipInstall: 'pip3 install frida-tools' },
    { id: 'mitmproxy', name: 'mitmproxy', command: 'mitmdump --version', installUrl: null, pipInstall: 'pip3 install mitmproxy' },
  ],
  linux: [
    { id: 'python', name: 'Python 3.9+', command: 'python3 --version', installUrl: 'https://www.python.org/downloads/' },
    { id: 'adb', name: 'Android Debug Bridge (ADB)', command: 'adb --version', installUrl: null, aptInstall: 'sudo apt install android-tools-adb' },
    { id: 'frida', name: 'Frida Tools', command: 'frida --version', installUrl: null, pipInstall: 'pip3 install frida-tools' },
    { id: 'mitmproxy', name: 'mitmproxy', command: 'mitmdump --version', installUrl: null, pipInstall: 'pip3 install mitmproxy' },
  ],
};

const STEPS = [
  { id: 'platform', label: 'Select Platform', icon: Monitor },
  { id: 'prerequisites', label: 'Install Prerequisites', icon: Download },
  { id: 'agent', label: 'Download Agent', icon: Terminal },
  { id: 'connect', label: 'Connect to Jarwis', icon: Wifi },
];

const AgentSetupWizard = ({ onComplete, onCancel }) => {
  const { isDarkMode } = useTheme();
  const [currentStep, setCurrentStep] = useState(0);
  const [platform, setPlatform] = useState(detectPlatform());
  const [agentToken, setAgentToken] = useState(null);
  const [tokenLoading, setTokenLoading] = useState(false);
  const [tokenError, setTokenError] = useState(null);
  const [instructions, setInstructions] = useState(null);
  const [instructionsLoading, setInstructionsLoading] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected'); // disconnected, connecting, connected
  const [connectedAgent, setConnectedAgent] = useState(null);
  const [expandedPrereq, setExpandedPrereq] = useState(null);
  const [downloading, setDownloading] = useState(false);
  const [downloadError, setDownloadError] = useState(null);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  const [copied, setCopied] = useState(null);

  // Fetch setup instructions when platform changes
  useEffect(() => {
    if (currentStep >= 1) {
      fetchInstructions();
    }
  }, [platform, currentStep]);

  // Poll for agent connection when on connect step
  useEffect(() => {
    let interval;
    if (currentStep === 3 && connectionStatus !== 'connected') {
      setConnectionStatus('connecting');
      interval = setInterval(checkForConnection, 3000);
    }
    return () => clearInterval(interval);
  }, [currentStep, connectionStatus]);

  const fetchInstructions = async () => {
    setInstructionsLoading(true);
    try {
      const data = await mobileAgentAPI.getSetupInstructions(platform);
      setInstructions(data);
    } catch (err) {
      console.error('Failed to fetch instructions:', err);
    } finally {
      setInstructionsLoading(false);
    }
  };

  const generateToken = async () => {
    setTokenLoading(true);
    setTokenError(null);
    try {
      const data = await mobileAgentAPI.getAgentToken();
      setAgentToken(data.token);
    } catch (err) {
      console.error('Failed to generate token:', err);
      setTokenError(err.message || 'Failed to generate token');
    } finally {
      setTokenLoading(false);
    }
  };

  const checkForConnection = async () => {
    try {
      const response = await mobileAgentAPI.listAgents();
      // API returns { agents: [...], count: N } - extract the agents array
      const agents = response?.agents || [];
      if (agents.length > 0) {
        // Find the most recently connected agent
        const latestAgent = agents[0];
        setConnectedAgent(latestAgent);
        setConnectionStatus('connected');
      }
    } catch (err) {
      console.error('Connection check error:', err);
    }
  };

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const nextStep = () => {
    if (currentStep < STEPS.length - 1) {
      setCurrentStep(currentStep + 1);
      if (currentStep === 2) {
        // Generate token when moving to connect step
        generateToken();
      }
    }
  };

  const prevStep = () => {
    if (currentStep > 0) {
      setCurrentStep(currentStep - 1);
    }
  };

  const handleComplete = () => {
    if (connectedAgent && onComplete) {
      onComplete(connectedAgent);
    }
  };

  // Styling helpers
  const cardClass = isDarkMode
    ? 'bg-slate-800/50 border border-slate-700 rounded-xl'
    : 'bg-white border border-gray-200 rounded-xl shadow-sm';

  const stepIndicatorClass = (index) => {
    if (index < currentStep) {
      return isDarkMode
        ? 'bg-green-500 text-white'
        : 'bg-green-500 text-white';
    }
    if (index === currentStep) {
      return isDarkMode
        ? 'bg-purple-500 text-white'
        : 'bg-purple-600 text-white';
    }
    return isDarkMode
      ? 'bg-slate-700 text-slate-400'
      : 'bg-gray-200 text-gray-500';
  };

  const renderPlatformSelector = () => (
    <div className="space-y-4">
      <p className={isDarkMode ? 'text-gray-300' : 'text-gray-600'}>
        Select the operating system where you'll run the mobile testing agent:
      </p>
      <div className="grid grid-cols-3 gap-4">
        {['windows', 'macos', 'linux'].map((p) => (
          <button
            key={p}
            onClick={() => setPlatform(p)}
            className={`p-4 rounded-xl border-2 transition-all ${
              platform === p
                ? isDarkMode
                  ? 'border-purple-500 bg-purple-500/20'
                  : 'border-purple-600 bg-purple-50'
                : isDarkMode
                  ? 'border-slate-600 hover:border-slate-500'
                  : 'border-gray-200 hover:border-gray-300'
            }`}
          >
            <Monitor className={`w-8 h-8 mx-auto mb-2 ${
              platform === p
                ? isDarkMode ? 'text-purple-400' : 'text-purple-600'
                : isDarkMode ? 'text-gray-400' : 'text-gray-500'
            }`} />
            <span className={`capitalize font-medium ${
              platform === p
                ? isDarkMode ? 'text-purple-300' : 'text-purple-700'
                : isDarkMode ? 'text-gray-300' : 'text-gray-700'
            }`}>
              {p === 'macos' ? 'macOS' : p.charAt(0).toUpperCase() + p.slice(1)}
            </span>
          </button>
        ))}
      </div>
    </div>
  );

  const renderPrerequisites = () => {
    const prereqs = PREREQUISITES[platform] || PREREQUISITES.windows;
    return (
      <div className="space-y-4">
        <p className={isDarkMode ? 'text-gray-300' : 'text-gray-600'}>
          Install these prerequisites on your machine before setting up the agent:
        </p>
        <div className="space-y-3">
          {prereqs.map((prereq) => (
            <div
              key={prereq.id}
              className={`rounded-lg border ${isDarkMode ? 'border-slate-600' : 'border-gray-200'}`}
            >
              <button
                onClick={() => setExpandedPrereq(expandedPrereq === prereq.id ? null : prereq.id)}
                className={`w-full flex items-center justify-between p-4 ${isDarkMode ? 'hover:bg-slate-700/50' : 'hover:bg-gray-50'} rounded-lg transition-colors`}
              >
                <div className="flex items-center gap-3">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${isDarkMode ? 'bg-slate-700' : 'bg-gray-100'}`}>
                    <Download className={`w-4 h-4 ${isDarkMode ? 'text-purple-400' : 'text-purple-600'}`} />
                  </div>
                  <span className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                    {prereq.name}
                  </span>
                </div>
                {expandedPrereq === prereq.id ? (
                  <ChevronDown className={`w-5 h-5 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                ) : (
                  <ChevronRight className={`w-5 h-5 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                )}
              </button>
              {expandedPrereq === prereq.id && (
                <div className={`px-4 pb-4 space-y-3 ${isDarkMode ? 'text-gray-300' : 'text-gray-600'}`}>
                  <p className="text-sm">Check if installed:</p>
                  <div className={`flex items-center gap-2 p-2 rounded font-mono text-sm ${isDarkMode ? 'bg-slate-900' : 'bg-gray-100'}`}>
                    <code>{prereq.command}</code>
                    <button
                      onClick={() => copyToClipboard(prereq.command, prereq.id + '-cmd')}
                      className={`ml-auto p-1 rounded ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-200'}`}
                    >
                      {copied === prereq.id + '-cmd' ? (
                        <CheckCircle className="w-4 h-4 text-green-500" />
                      ) : (
                        <Copy className="w-4 h-4" />
                      )}
                    </button>
                  </div>
                  {prereq.installUrl && (
                    <a
                      href={prereq.installUrl}
                      target="_blank"
                      rel="noopener noreferrer"
                      className={`inline-flex items-center gap-2 text-sm ${isDarkMode ? 'text-purple-400 hover:text-purple-300' : 'text-purple-600 hover:text-purple-700'}`}
                    >
                      <ExternalLink className="w-4 h-4" />
                      Download from official website
                    </a>
                  )}
                  {prereq.pipInstall && (
                    <div>
                      <p className="text-sm mb-1">Install via pip:</p>
                      <div className={`flex items-center gap-2 p-2 rounded font-mono text-sm ${isDarkMode ? 'bg-slate-900' : 'bg-gray-100'}`}>
                        <code>{prereq.pipInstall}</code>
                        <button
                          onClick={() => copyToClipboard(prereq.pipInstall, prereq.id + '-pip')}
                          className={`ml-auto p-1 rounded ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-200'}`}
                        >
                          {copied === prereq.id + '-pip' ? (
                            <CheckCircle className="w-4 h-4 text-green-500" />
                          ) : (
                            <Copy className="w-4 h-4" />
                          )}
                        </button>
                      </div>
                    </div>
                  )}
                  {prereq.aptInstall && (
                    <div>
                      <p className="text-sm mb-1">Install via apt:</p>
                      <div className={`flex items-center gap-2 p-2 rounded font-mono text-sm ${isDarkMode ? 'bg-slate-900' : 'bg-gray-100'}`}>
                        <code>{prereq.aptInstall}</code>
                        <button
                          onClick={() => copyToClipboard(prereq.aptInstall, prereq.id + '-apt')}
                          className={`ml-auto p-1 rounded ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-200'}`}
                        >
                          {copied === prereq.id + '-apt' ? (
                            <CheckCircle className="w-4 h-4 text-green-500" />
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
      </div>
    );
  };

  const handleAgentDownload = async () => {
    setDownloading(true);
    setDownloadError(null);
    setDownloadSuccess(false);
    try {
      await mobileAgentAPI.downloadAgent(platform);
      setDownloadSuccess(true);
    } catch (err) {
      console.error('Download failed:', err);
      setDownloadError(err.message || 'Failed to download agent package');
    } finally {
      setDownloading(false);
    }
  };

  const renderAgentDownload = () => {
    const pythonCmd = platform === 'windows' ? 'python' : 'python3';
    const pipCmd = platform === 'windows' ? 'pip' : 'pip3';
    
    // Commands for manual setup (no scripts needed - avoids OS security blocks)
    const installDepsCmd = `${pipCmd} install -r requirements.txt`;
    const createVenvCmd = platform === 'windows' 
      ? 'python -m venv venv && venv\\Scripts\\activate'
      : 'python3 -m venv venv && source venv/bin/activate';
    
    // Python check command
    const pythonCheckCmd = platform === 'windows' ? 'python --version' : 'python3 --version';

    return (
      <div className="space-y-6">
        <p className={isDarkMode ? 'text-gray-300' : 'text-gray-600'}>
          Download and set up the Jarwis Mobile Agent on your <span className="font-medium capitalize">{platform === 'macos' ? 'macOS' : platform}</span> machine:
        </p>

        {/* Step 0: Install Python First */}
        <div className={`p-4 rounded-lg border-2 ${isDarkMode ? 'border-yellow-500/50 bg-yellow-500/10' : 'border-yellow-400 bg-yellow-50'}`}>
          <h4 className={`font-medium mb-3 flex items-center gap-2 ${isDarkMode ? 'text-yellow-300' : 'text-yellow-700'}`}>
            <AlertTriangle className="w-5 h-5" />
            First: Install Python (if not already installed)
          </h4>
          <p className={`text-sm mb-4 ${isDarkMode ? 'text-yellow-200/70' : 'text-yellow-700'}`}>
            Python is required to run the agent. Most Windows and macOS systems don't have it pre-installed.
          </p>
          
          {/* Check if Python is installed */}
          <div className="mb-4">
            <p className={`text-xs mb-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
              Check if Python is installed (open terminal and run):
            </p>
            <div className={`flex items-center gap-2 p-3 rounded font-mono text-sm ${isDarkMode ? 'bg-slate-900' : 'bg-white border'}`}>
              <code className="flex-1">{pythonCheckCmd}</code>
              <button
                onClick={() => copyToClipboard(pythonCheckCmd, 'python-check')}
                className={`p-1 rounded shrink-0 ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-100'}`}
              >
                {copied === 'python-check' ? (
                  <CheckCircle className="w-4 h-4 text-green-500" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>

          {/* Download Python link */}
          <a
            href="https://www.python.org/downloads/"
            target="_blank"
            rel="noopener noreferrer"
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              isDarkMode
                ? 'bg-yellow-500/20 text-yellow-300 hover:bg-yellow-500/30 border border-yellow-500/50'
                : 'bg-yellow-100 text-yellow-800 hover:bg-yellow-200 border border-yellow-300'
            }`}
          >
            <ExternalLink className="w-4 h-4" />
            Download Python from python.org
          </a>
          
          {platform === 'windows' && (
            <p className={`text-xs mt-3 ${isDarkMode ? 'text-yellow-200/60' : 'text-yellow-600'}`}>
              <strong>Important:</strong> During installation, check ✓ "Add Python to PATH" at the bottom of the installer.
            </p>
          )}
          {platform === 'macos' && (
            <p className={`text-xs mt-3 ${isDarkMode ? 'text-yellow-200/60' : 'text-yellow-600'}`}>
              <strong>Tip:</strong> You can also install via Homebrew: <code className={`px-1 rounded ${isDarkMode ? 'bg-slate-800' : 'bg-yellow-200'}`}>brew install python</code>
            </p>
          )}
          {platform === 'linux' && (
            <p className={`text-xs mt-3 ${isDarkMode ? 'text-yellow-200/60' : 'text-yellow-600'}`}>
              <strong>Tip:</strong> Install via package manager: <code className={`px-1 rounded ${isDarkMode ? 'bg-slate-800' : 'bg-yellow-200'}`}>sudo apt install python3 python3-pip python3-venv</code>
            </p>
          )}
        </div>

        {/* Step 1: Download */}
        <div className={`p-4 rounded-lg ${isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50'}`}>
          <h4 className={`font-medium mb-3 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
            Step 1: Download Agent Package
          </h4>
          <p className={`text-sm mb-4 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            Download and extract the ZIP file to a folder (e.g., <code className={`px-1 rounded ${isDarkMode ? 'bg-slate-900' : 'bg-gray-200'}`}>{platform === 'windows' ? 'C:\\jarwis-agent' : '~/jarwis-agent'}</code>).
          </p>
          
          {downloadError && (
            <div className={`mb-4 p-3 rounded-lg flex items-center gap-2 ${isDarkMode ? 'bg-red-500/20 text-red-300' : 'bg-red-50 text-red-700'}`}>
              <XCircle className="w-5 h-5 flex-shrink-0" />
              <span className="text-sm">{downloadError}</span>
            </div>
          )}

          {downloadSuccess && (
            <div className={`mb-4 p-3 rounded-lg flex items-center gap-2 ${isDarkMode ? 'bg-green-500/20 text-green-300' : 'bg-green-50 text-green-700'}`}>
              <CheckCircle className="w-5 h-5 flex-shrink-0" />
              <span className="text-sm">Download started! Extract the ZIP and follow the steps below.</span>
            </div>
          )}

          <button
            onClick={handleAgentDownload}
            disabled={downloading}
            className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg font-medium transition-colors ${
              downloading
                ? isDarkMode 
                  ? 'bg-purple-500/30 text-purple-300 cursor-not-allowed' 
                  : 'bg-purple-200 text-purple-500 cursor-not-allowed'
                : isDarkMode
                  ? 'bg-purple-500 text-white hover:bg-purple-600'
                  : 'bg-purple-600 text-white hover:bg-purple-700'
            }`}
          >
            {downloading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                Downloading...
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                Download for {platform === 'macos' ? 'macOS' : platform.charAt(0).toUpperCase() + platform.slice(1)}
              </>
            )}
          </button>
        </div>

        {/* Step 2: Setup Commands */}
        <div className={`p-4 rounded-lg ${isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50'}`}>
          <h4 className={`font-medium mb-3 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
            Step 2: Install Dependencies
          </h4>
          <p className={`text-sm mb-4 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            Open a terminal in the extracted folder and run these commands:
          </p>

          {/* Command 1: Create virtual environment (optional) */}
          <div className="mb-3">
            <p className={`text-xs mb-1 ${isDarkMode ? 'text-gray-500' : 'text-gray-500'}`}>
              Create virtual environment (recommended):
            </p>
            <div className={`flex items-center gap-2 p-3 rounded font-mono text-sm ${isDarkMode ? 'bg-slate-900' : 'bg-white border'}`}>
              <code className="flex-1 break-all">{createVenvCmd}</code>
              <button
                onClick={() => copyToClipboard(createVenvCmd, 'venv-cmd')}
                className={`p-1 rounded shrink-0 ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-100'}`}
              >
                {copied === 'venv-cmd' ? (
                  <CheckCircle className="w-4 h-4 text-green-500" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>

          {/* Command 2: Install dependencies */}
          <div>
            <p className={`text-xs mb-1 ${isDarkMode ? 'text-gray-500' : 'text-gray-500'}`}>
              Install required packages:
            </p>
            <div className={`flex items-center gap-2 p-3 rounded font-mono text-sm ${isDarkMode ? 'bg-slate-900' : 'bg-white border'}`}>
              <code className="flex-1">{installDepsCmd}</code>
              <button
                onClick={() => copyToClipboard(installDepsCmd, 'install-cmd')}
                className={`p-1 rounded shrink-0 ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-100'}`}
              >
                {copied === 'install-cmd' ? (
                  <CheckCircle className="w-4 h-4 text-green-500" />
                ) : (
                  <Copy className="w-4 h-4" />
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Info Box */}
        <div className={`p-4 rounded-lg border ${isDarkMode ? 'border-blue-500/30 bg-blue-500/10' : 'border-blue-200 bg-blue-50'}`}>
          <h4 className={`font-medium mb-2 flex items-center gap-2 ${isDarkMode ? 'text-blue-300' : 'text-blue-700'}`}>
            <Info className="w-4 h-4" />
            Why copy-paste commands?
          </h4>
          <p className={`text-sm ${isDarkMode ? 'text-blue-200/70' : 'text-blue-600'}`}>
            Running Python/pip commands directly is trusted by your OS. Script files (.bat/.sh) from downloads 
            are often blocked by Windows SmartScreen or macOS Gatekeeper for security reasons.
          </p>
        </div>

        {/* Package Contents */}
        <div className={`p-4 rounded-lg border ${isDarkMode ? 'border-slate-600 bg-slate-800/30' : 'border-gray-200 bg-gray-50'}`}>
          <h4 className={`font-medium mb-3 flex items-center gap-2 ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
            <Info className="w-4 h-4" />
            Package Contents
          </h4>
          <ul className={`text-sm space-y-1 ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            <li>• <code className="text-xs px-1 rounded bg-slate-700/30">jarwis_agent.py</code> - Main agent script</li>
            <li>• <code className="text-xs px-1 rounded bg-slate-700/30">core/mobile_agent/</code> - Agent modules</li>
            <li>• <code className="text-xs px-1 rounded bg-slate-700/30">requirements.txt</code> - Python dependencies</li>
            <li>• <code className="text-xs px-1 rounded bg-slate-700/30">README.md</code> - Detailed instructions</li>
          </ul>
        </div>
      </div>
    );
  };

  const renderConnectStep = () => {
    const serverUrl = window.location.origin.replace('http://', 'ws://').replace('https://', 'wss://');
    const pythonCmd = platform === 'windows' ? 'python' : 'python3';
    const connectCommand = agentToken
      ? `${pythonCmd} jarwis_agent.py --server ${serverUrl}/api/mobile-agent/ws/${agentToken}`
      : 'Generating token...';

    return (
      <div className="space-y-6">
        {/* Token Section */}
        <div className={`p-4 rounded-lg ${isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50'}`}>
          <div className="flex items-center justify-between mb-3">
            <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
              Your Agent Token
            </h4>
            <button
              onClick={generateToken}
              disabled={tokenLoading}
              className={`flex items-center gap-1 text-sm ${isDarkMode ? 'text-purple-400 hover:text-purple-300' : 'text-purple-600 hover:text-purple-700'}`}
            >
              <RefreshCw className={`w-4 h-4 ${tokenLoading ? 'animate-spin' : ''}`} />
              Regenerate
            </button>
          </div>

          {tokenError && (
            <div className={`mb-3 p-3 rounded-lg ${isDarkMode ? 'bg-red-500/20 text-red-300' : 'bg-red-50 text-red-700'}`}>
              <AlertTriangle className="w-4 h-4 inline mr-2" />
              {tokenError}
            </div>
          )}

          {tokenLoading ? (
            <div className={`flex items-center justify-center p-4 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
              <Loader2 className="w-5 h-5 animate-spin mr-2" />
              Generating secure token...
            </div>
          ) : agentToken ? (
            <div className={`p-3 rounded font-mono text-sm break-all ${isDarkMode ? 'bg-slate-900' : 'bg-white border'}`}>
              <div className="flex items-start gap-2">
                <code className="flex-1">{agentToken}</code>
                <button
                  onClick={() => copyToClipboard(agentToken, 'token')}
                  className={`p-1 rounded shrink-0 ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-100'}`}
                >
                  {copied === 'token' ? (
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              </div>
            </div>
          ) : null}

          <p className={`mt-2 text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
            <Info className="w-4 h-4 inline mr-1" />
            Token expires in 30 minutes. Keep it secure.
          </p>
        </div>

        {/* Connect Command */}
        <div className={`p-4 rounded-lg border ${isDarkMode ? 'border-purple-500/30 bg-purple-500/10' : 'border-purple-200 bg-purple-50'}`}>
          <h4 className={`font-medium mb-3 ${isDarkMode ? 'text-purple-300' : 'text-purple-700'}`}>
            Run this command in your agent folder:
          </h4>
          <div className={`p-3 rounded font-mono text-sm ${isDarkMode ? 'bg-slate-900' : 'bg-white border'}`}>
            <div className="flex items-start gap-2">
              <code className="flex-1 break-all">{connectCommand}</code>
              {agentToken && (
                <button
                  onClick={() => copyToClipboard(connectCommand, 'connect-cmd')}
                  className={`p-1 rounded shrink-0 ${isDarkMode ? 'hover:bg-slate-700' : 'hover:bg-gray-100'}`}
                >
                  {copied === 'connect-cmd' ? (
                    <CheckCircle className="w-4 h-4 text-green-500" />
                  ) : (
                    <Copy className="w-4 h-4" />
                  )}
                </button>
              )}
            </div>
          </div>
          <p className={`mt-2 text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`}>
            Make sure you're in the extracted agent folder with virtual environment activated.
          </p>
        </div>

        {/* Connection Status */}
        <div className={`p-4 rounded-lg ${
          connectionStatus === 'connected'
            ? isDarkMode ? 'bg-green-500/20 border border-green-500/30' : 'bg-green-50 border border-green-200'
            : isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50'
        }`}>
          <div className="flex items-center gap-3">
            {connectionStatus === 'connected' ? (
              <>
                <CheckCircle className={`w-6 h-6 ${isDarkMode ? 'text-green-400' : 'text-green-600'}`} />
                <div>
                  <p className={`font-medium ${isDarkMode ? 'text-green-300' : 'text-green-700'}`}>
                    Agent Connected!
                  </p>
                  {connectedAgent && (
                    <p className={`text-sm ${isDarkMode ? 'text-green-400/70' : 'text-green-600'}`}>
                      {connectedAgent.device_name || connectedAgent.agent_id} • {connectedAgent.platform}
                    </p>
                  )}
                </div>
              </>
            ) : connectionStatus === 'connecting' ? (
              <>
                <Loader2 className={`w-6 h-6 animate-spin ${isDarkMode ? 'text-purple-400' : 'text-purple-600'}`} />
                <div>
                  <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                    Waiting for agent connection...
                  </p>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    Run the connect command on your machine
                  </p>
                </div>
              </>
            ) : (
              <>
                <Wifi className={`w-6 h-6 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                <div>
                  <p className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                    Not connected
                  </p>
                  <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                    Generate a token and connect your agent
                  </p>
                </div>
              </>
            )}
          </div>
        </div>
      </div>
    );
  };

  const renderStepContent = () => {
    switch (currentStep) {
      case 0:
        return renderPlatformSelector();
      case 1:
        return renderPrerequisites();
      case 2:
        return renderAgentDownload();
      case 3:
        return renderConnectStep();
      default:
        return null;
    }
  };

  return (
    <div className={`${cardClass} p-6`}>
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className={`p-3 rounded-xl ${isDarkMode ? 'bg-purple-500/20' : 'bg-purple-100'}`}>
          <Smartphone className={`w-6 h-6 ${isDarkMode ? 'text-purple-400' : 'text-purple-600'}`} />
        </div>
        <div>
          <h2 className={`text-xl font-bold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
            Setup Mobile Agent
          </h2>
          <p className={`text-sm ${isDarkMode ? 'text-gray-400' : 'text-gray-600'}`}>
            Run mobile security tests from your local machine
          </p>
        </div>
      </div>

      {/* Step Indicators */}
      <div className="flex items-center justify-between mb-8">
        {STEPS.map((step, index) => (
          <React.Fragment key={step.id}>
            <div className="flex flex-col items-center">
              <div className={`w-10 h-10 rounded-full flex items-center justify-center mb-2 transition-colors ${stepIndicatorClass(index)}`}>
                {index < currentStep ? (
                  <CheckCircle className="w-5 h-5" />
                ) : (
                  <step.icon className="w-5 h-5" />
                )}
              </div>
              <span className={`text-xs font-medium text-center max-w-[80px] ${
                index <= currentStep
                  ? isDarkMode ? 'text-white' : 'text-gray-900'
                  : isDarkMode ? 'text-gray-500' : 'text-gray-400'
              }`}>
                {step.label}
              </span>
            </div>
            {index < STEPS.length - 1 && (
              <div className={`flex-1 h-0.5 mx-2 ${
                index < currentStep
                  ? 'bg-green-500'
                  : isDarkMode ? 'bg-slate-700' : 'bg-gray-200'
              }`} />
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Step Content */}
      <div className="min-h-[300px] mb-6">
        {renderStepContent()}
      </div>

      {/* Navigation Buttons */}
      <div className="flex justify-between pt-4 border-t ${isDarkMode ? 'border-slate-700' : 'border-gray-200'}">
        <button
          onClick={onCancel || prevStep}
          className={`px-4 py-2 rounded-lg font-medium transition-colors ${
            isDarkMode
              ? 'text-gray-400 hover:text-white hover:bg-slate-700'
              : 'text-gray-600 hover:text-gray-900 hover:bg-gray-100'
          }`}
        >
          {currentStep === 0 ? 'Cancel' : 'Back'}
        </button>

        {currentStep < STEPS.length - 1 ? (
          <button
            onClick={nextStep}
            className="px-6 py-2 rounded-lg font-medium bg-gradient-to-r from-purple-600 to-pink-600 text-white hover:from-purple-500 hover:to-pink-500 transition-all"
          >
            Continue
          </button>
        ) : connectionStatus === 'connected' ? (
          <button
            onClick={handleComplete}
            className="px-6 py-2 rounded-lg font-medium bg-gradient-to-r from-green-600 to-emerald-600 text-white hover:from-green-500 hover:to-emerald-500 transition-all"
          >
            Start Testing
          </button>
        ) : (
          <button
            disabled
            className="px-6 py-2 rounded-lg font-medium bg-gray-500 text-gray-300 cursor-not-allowed"
          >
            Waiting for connection...
          </button>
        )}
      </div>
    </div>
  );
};

export default AgentSetupWizard;
