// src/components/scan/NetworkScanConfig.jsx
// Comprehensive network scan configuration with private/public network support
import { useState, useEffect } from "react";
import { 
  Wifi, Server, Lock, Shield, AlertTriangle, Info, 
  ChevronDown, ChevronUp, Key, Eye, EyeOff, Plus, 
  Trash2, RefreshCw, CheckCircle2, XCircle, Globe,
  Router, Database, Cloud, Terminal, Settings
} from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { networkScanAPI } from "../../services/api";

// Network type definitions
const NETWORK_TYPES = [
  { 
    id: "public", 
    name: "Public Network", 
    description: "External/internet-facing assets (IPs, domains)", 
    icon: Globe,
    color: "blue",
    requiresAgent: false 
  },
  { 
    id: "private", 
    name: "Private Network", 
    description: "Internal network (10.x.x.x, 172.16.x.x, 192.168.x.x)", 
    icon: Lock,
    color: "purple",
    requiresAgent: true 
  },
  { 
    id: "cloud_vpc", 
    name: "Cloud VPC", 
    description: "AWS VPC, Azure VNet, GCP Subnet", 
    icon: Cloud,
    color: "cyan",
    requiresAgent: true 
  },
];

// Scan profiles with phase configurations
const SCAN_PROFILES = [
  { 
    id: "quick", 
    name: "Quick Scan", 
    description: "Fast host discovery + top 1000 ports",
    duration: "5-15 min",
    phases: ["discovery", "port_scan"],
    icon: "⚡"
  },
  { 
    id: "standard", 
    name: "Standard Scan", 
    description: "Full port scan + service detection + SSL audit",
    duration: "30-60 min",
    phases: ["discovery", "port_scan", "service_enum", "vuln_scan", "ssl_audit"],
    icon: "📊"
  },
  { 
    id: "comprehensive", 
    name: "Comprehensive", 
    description: "All phases including credential testing",
    duration: "1-3 hours",
    phases: ["discovery", "port_scan", "service_enum", "vuln_scan", "ssl_audit", "credential", "exploitation"],
    icon: "🔬"
  },
  { 
    id: "stealth", 
    name: "Stealth Mode", 
    description: "Low and slow to avoid detection",
    duration: "2-4 hours",
    phases: ["port_scan", "vuln_scan"],
    icon: "🥷"
  },
];

// Individual scan phases
const SCAN_PHASES = [
  { id: "discovery", name: "Host Discovery", description: "Find live hosts on network", icon: Router },
  { id: "port_scan", name: "Port Scanning", description: "Discover open ports", icon: Server },
  { id: "service_enum", name: "Service Detection", description: "Identify services and versions", icon: Database },
  { id: "vuln_scan", name: "Vulnerability Scan", description: "Check for CVEs and misconfigs", icon: Shield },
  { id: "ssl_audit", name: "SSL/TLS Audit", description: "Certificate and cipher analysis", icon: Lock },
  { id: "credential", name: "Credential Testing", description: "Default password checks", icon: Key },
  { id: "exploitation", name: "Exploitation", description: "Safe exploit verification", icon: Terminal },
];

// Port range presets
const PORT_PRESETS = [
  { id: "top100", name: "Top 100", value: "top100", description: "Most common ports" },
  { id: "top1000", name: "Top 1000", value: "top1000", description: "Standard scan" },
  { id: "common", name: "Common Services", value: "common", description: "Web, SSH, DB, etc." },
  { id: "all", name: "All Ports", value: "1-65535", description: "Full port range (slow)" },
  { id: "custom", name: "Custom", value: "custom", description: "Specify your own" },
];

const NetworkScanConfig = ({ 
  onConfigChange, 
  initialConfig = {},
  showAgentSetup = true 
}) => {
  const { isDarkMode } = useTheme();
  
  // Main config state
  const [config, setConfig] = useState({
    networkType: "public",
    targets: "",
    profile: "standard",
    customPhases: [],
    portRange: "top1000",
    customPorts: "",
    useAgent: false,
    agentId: "",
    serviceDetection: true,
    vulnScan: true,
    sslAudit: true,
    safeChecks: true,
    maxConcurrentHosts: 10,
    timeoutPerHost: 300,
    rateLimit: 100,
    credentials: {
      enabled: false,
      ssh: { enabled: false, username: "", password: "", privateKey: "" },
      windows: { enabled: false, username: "", password: "", domain: "" },
      snmp: { enabled: false, community: "public", version: "2c" },
    },
    ...initialConfig
  });

  // UI state
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showCredentials, setShowCredentials] = useState(false);
  const [showPhases, setShowPhases] = useState(false);
  const [agents, setAgents] = useState([]);
  const [agentsLoading, setAgentsLoading] = useState(false);
  const [showPassword, setShowPassword] = useState({});

  // Fetch agents on mount
  useEffect(() => {
    if (showAgentSetup) {
      fetchAgents();
    }
  }, [showAgentSetup]);

  // Notify parent of config changes
  useEffect(() => {
    onConfigChange?.(config);
  }, [config, onConfigChange]);

  const fetchAgents = async () => {
    setAgentsLoading(true);
    try {
      const response = await networkScanAPI.getAgents?.();
      // Handle both {agents: [...]} and direct array format
      if (response?.agents) {
        setAgents(response.agents);
      } else if (Array.isArray(response)) {
        setAgents(response);
      } else {
        setAgents([]);
      }
    } catch (err) {
      console.warn("Failed to fetch agents:", err);
      setAgents([]);
    } finally {
      setAgentsLoading(false);
    }
  };

  const updateConfig = (updates) => {
    setConfig(prev => ({ ...prev, ...updates }));
  };

  const updateCredentials = (type, field, value) => {
    setConfig(prev => ({
      ...prev,
      credentials: {
        ...prev.credentials,
        [type]: {
          ...prev.credentials[type],
          [field]: value
        }
      }
    }));
  };

  const togglePhase = (phaseId) => {
    setConfig(prev => {
      const phases = prev.customPhases.includes(phaseId)
        ? prev.customPhases.filter(p => p !== phaseId)
        : [...prev.customPhases, phaseId];
      return { ...prev, customPhases: phases };
    });
  };

  // Check if private network is selected
  const isPrivateNetwork = config.networkType === "private" || config.networkType === "cloud_vpc";
  const selectedProfile = SCAN_PROFILES.find(p => p.id === config.profile);

  // Style classes
  const cardClass = isDarkMode 
    ? "bg-slate-800/50 border border-slate-700/50 rounded-xl backdrop-blur-xl"
    : "bg-white border border-gray-200 rounded-xl shadow-sm";
  
  const inputClass = isDarkMode
    ? "w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-gray-400 focus:border-blue-500/50 focus:ring-2 focus:ring-blue-500/20 transition-all outline-none"
    : "w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-500 focus:border-blue-500 focus:ring-2 focus:ring-blue-200 transition-all outline-none";

  const labelClass = isDarkMode
    ? "block text-sm font-medium text-gray-300 mb-2"
    : "block text-sm font-medium text-gray-700 mb-2";

  return (
    <div className="space-y-6">
      {/* Network Type Selection */}
      <div className={`${cardClass} p-6`}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          <Wifi className="w-5 h-5 inline-block mr-2" />
          Network Type
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {NETWORK_TYPES.map((type) => {
            const Icon = type.icon;
            const isSelected = config.networkType === type.id;
            return (
              <button
                key={type.id}
                type="button"
                onClick={() => updateConfig({ 
                  networkType: type.id, 
                  useAgent: type.requiresAgent 
                })}
                className={`p-4 rounded-xl border-2 transition-all text-left ${
                  isSelected
                    ? isDarkMode 
                      ? "border-cyan-500 bg-cyan-500/10" 
                      : "border-cyan-500 bg-cyan-50"
                    : isDarkMode
                    ? "border-slate-600 hover:border-slate-500"
                    : "border-gray-200 hover:border-gray-300"
                }`}
              >
                <div className="flex items-center gap-3 mb-2">
                  <Icon className={`w-6 h-6 ${
                    isSelected 
                      ? "text-cyan-500" 
                      : isDarkMode ? "text-gray-400" : "text-gray-500"
                  }`} />
                  <span className={`font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {type.name}
                  </span>
                  {isSelected && (
                    <CheckCircle2 className="w-5 h-5 ml-auto text-cyan-500" />
                  )}
                </div>
                <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  {type.description}
                </p>
                {type.requiresAgent && (
                  <div className={`mt-2 text-xs px-2 py-1 rounded-full inline-flex items-center gap-1 ${
                    isDarkMode ? "bg-amber-500/20 text-amber-400" : "bg-amber-100 text-amber-700"
                  }`}>
                    <Lock className="w-3 h-3" /> Requires Agent
                  </div>
                )}
              </button>
            );
          })}
        </div>

        {/* Agent Required Warning */}
        {isPrivateNetwork && (
          <div className={`mt-4 p-4 rounded-lg flex items-start gap-3 ${
            isDarkMode ? "bg-amber-500/10 border border-amber-500/30" : "bg-amber-50 border border-amber-200"
          }`}>
            <AlertTriangle className={`w-5 h-5 mt-0.5 ${isDarkMode ? "text-amber-400" : "text-amber-600"}`} />
            <div>
              <p className={`font-medium ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
                Jarwis Agent Required
              </p>
              <p className={`text-sm mt-1 ${isDarkMode ? "text-gray-300" : "text-gray-600"}`}>
                Private networks require a Jarwis Agent deployed inside your network. 
                The agent polls our servers for scan jobs and executes them locally.
              </p>
            </div>
          </div>
        )}
      </div>

      {/* Target Input */}
      <div className={`${cardClass} p-6`}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          <Server className="w-5 h-5 inline-block mr-2" />
          Scan Targets
        </h3>
        
        <div className="space-y-4">
          <div>
            <label className={labelClass}>
              Target Hosts, IPs, or CIDR Ranges *
            </label>
            <textarea
              value={config.targets}
              onChange={(e) => updateConfig({ targets: e.target.value })}
              placeholder={
                config.networkType === "public"
                  ? "example.com\n203.0.113.50\n198.51.100.0/24"
                  : "10.0.1.0/24\n192.168.1.1-254\n172.16.0.50"
              }
              className={`${inputClass} h-32 resize-none font-mono`}
              required
            />
            <p className={`text-sm mt-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Enter one target per line. Supports IP addresses, hostnames, CIDR notation, and ranges.
            </p>
          </div>
        </div>
      </div>

      {/* Scan Profile Selection */}
      <div className={`${cardClass} p-6`}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          <Settings className="w-5 h-5 inline-block mr-2" />
          Scan Profile
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {SCAN_PROFILES.map((profile) => {
            const isSelected = config.profile === profile.id;
            return (
              <button
                key={profile.id}
                type="button"
                onClick={() => updateConfig({ profile: profile.id })}
                className={`p-4 rounded-xl border-2 transition-all text-left ${
                  isSelected
                    ? isDarkMode 
                      ? "border-cyan-500 bg-cyan-500/10" 
                      : "border-cyan-500 bg-cyan-50"
                    : isDarkMode
                    ? "border-slate-600 hover:border-slate-500"
                    : "border-gray-200 hover:border-gray-300"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="text-2xl">{profile.icon}</span>
                  {isSelected && (
                    <CheckCircle2 className="w-5 h-5 text-cyan-500" />
                  )}
                </div>
                <p className={`font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  {profile.name}
                </p>
                <p className={`text-xs mt-1 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                  {profile.description}
                </p>
                <p className={`text-xs mt-2 ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`}>
                  ⏱️ {profile.duration}
                </p>
              </button>
            );
          })}
        </div>

        {/* Custom Phase Selection */}
        <div className="mt-4">
          <button
            type="button"
            onClick={() => setShowPhases(!showPhases)}
            className={`flex items-center gap-2 text-sm ${
              isDarkMode ? "text-cyan-400 hover:text-cyan-300" : "text-cyan-600 hover:text-cyan-700"
            }`}
          >
            {showPhases ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
            Customize scan phases
          </button>
          
          {showPhases && (
            <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-3">
              {SCAN_PHASES.map((phase) => {
                const Icon = phase.icon;
                const isIncluded = selectedProfile?.phases.includes(phase.id) || 
                                   config.customPhases.includes(phase.id);
                return (
                  <label
                    key={phase.id}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isIncluded
                        ? isDarkMode 
                          ? "border-green-500/50 bg-green-500/10" 
                          : "border-green-500 bg-green-50"
                        : isDarkMode
                        ? "border-slate-600 hover:border-slate-500"
                        : "border-gray-200 hover:border-gray-300"
                    }`}
                  >
                    <div className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={isIncluded}
                        onChange={() => togglePhase(phase.id)}
                        className="w-4 h-4 rounded"
                      />
                      <Icon className={`w-4 h-4 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`} />
                      <span className={`text-sm font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        {phase.name}
                      </span>
                    </div>
                    <p className={`text-xs mt-1 ml-6 ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
                      {phase.description}
                    </p>
                  </label>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Port Range */}
      <div className={`${cardClass} p-6`}>
        <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
          Port Range
        </h3>
        
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {PORT_PRESETS.map((preset) => {
            const isSelected = config.portRange === preset.id;
            return (
              <button
                key={preset.id}
                type="button"
                onClick={() => updateConfig({ portRange: preset.id })}
                className={`p-3 rounded-lg border text-left transition-all ${
                  isSelected
                    ? isDarkMode 
                      ? "border-cyan-500 bg-cyan-500/10" 
                      : "border-cyan-500 bg-cyan-50"
                    : isDarkMode
                    ? "border-slate-600 hover:border-slate-500"
                    : "border-gray-200 hover:border-gray-300"
                }`}
              >
                <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  {preset.name}
                </p>
                <p className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                  {preset.description}
                </p>
              </button>
            );
          })}
        </div>

        {config.portRange === "custom" && (
          <div className="mt-4">
            <input
              type="text"
              value={config.customPorts}
              onChange={(e) => updateConfig({ customPorts: e.target.value })}
              placeholder="22,80,443,3306 or 1-1000"
              className={inputClass}
            />
          </div>
        )}
      </div>

      {/* Agent Selection (for private networks) */}
      {isPrivateNetwork && showAgentSetup && (
        <div className={`${cardClass} p-6`}>
          <div className="flex items-center justify-between mb-4">
            <h3 className={`text-lg font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              <Shield className="w-5 h-5 inline-block mr-2" />
              Jarwis Agent
            </h3>
            <button
              type="button"
              onClick={fetchAgents}
              className={`flex items-center gap-2 text-sm ${
                isDarkMode ? "text-gray-400 hover:text-white" : "text-gray-600 hover:text-gray-900"
              }`}
            >
              <RefreshCw className={`w-4 h-4 ${agentsLoading ? "animate-spin" : ""}`} />
              Refresh
            </button>
          </div>

          {agents.length === 0 ? (
            <div className={`p-6 rounded-lg text-center ${
              isDarkMode ? "bg-slate-700/50" : "bg-gray-50"
            }`}>
              <Shield className={`w-12 h-12 mx-auto mb-4 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`} />
              <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                No Agents Registered
              </p>
              <p className={`text-sm mt-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Deploy a Jarwis Agent in your private network to start scanning internal assets.
              </p>
              <button
                type="button"
                onClick={() => {
                  // Navigate to settings page with agents tab
                  window.location.href = "/dashboard/settings";
                  // Store the desired tab in sessionStorage for the Settings page to read
                  sessionStorage.setItem("settingsTab", "agents");
                }}
                className={`mt-4 px-4 py-2 rounded-lg flex items-center gap-2 mx-auto ${
                  isDarkMode 
                    ? "bg-cyan-600 text-white hover:bg-cyan-500" 
                    : "bg-cyan-500 text-white hover:bg-cyan-600"
                }`}
              >
                <Plus className="w-4 h-4" />
                Setup Agent
              </button>
            </div>
          ) : (
            <div className="space-y-3">
              {agents.map((agent) => (
                <label
                  key={agent.id || agent.agent_id}
                  className={`p-4 rounded-lg border cursor-pointer flex items-center gap-4 transition-all ${
                    config.agentId === (agent.id || agent.agent_id)
                      ? isDarkMode 
                        ? "border-cyan-500 bg-cyan-500/10" 
                        : "border-cyan-500 bg-cyan-50"
                      : isDarkMode
                      ? "border-slate-600 hover:border-slate-500"
                      : "border-gray-200 hover:border-gray-300"
                  }`}
                >
                  <input
                    type="radio"
                    name="agent"
                    value={agent.id || agent.agent_id}
                    checked={config.agentId === (agent.id || agent.agent_id)}
                    onChange={() => updateConfig({ agentId: agent.id || agent.agent_id, useAgent: true })}
                    className="w-5 h-5"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        {agent.name}
                      </span>
                      <span className={`px-2 py-0.5 text-xs rounded-full ${
                        agent.status === "online"
                          ? "bg-green-500/20 text-green-400"
                          : "bg-red-500/20 text-red-400"
                      }`}>
                        {agent.status || "unknown"}
                      </span>
                    </div>
                    <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                      Networks: {agent.network_ranges?.join(", ") || "Not specified"}
                    </p>
                    <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>
                      Last seen: {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "Never"}
                    </p>
                  </div>
                </label>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Credential Configuration */}
      <div className={`${cardClass} p-6`}>
        <button
          type="button"
          onClick={() => setShowCredentials(!showCredentials)}
          className={`w-full flex items-center justify-between ${
            isDarkMode ? "text-white" : "text-gray-900"
          }`}
        >
          <div className="flex items-center gap-2">
            <Key className="w-5 h-5" />
            <span className="text-lg font-semibold">Credential Testing</span>
            {config.credentials.enabled && (
              <span className={`px-2 py-0.5 text-xs rounded-full ${
                isDarkMode ? "bg-green-500/20 text-green-400" : "bg-green-100 text-green-700"
              }`}>
                Enabled
              </span>
            )}
          </div>
          {showCredentials ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>

        {showCredentials && (
          <div className="mt-4 space-y-6">
            <label className="flex items-center gap-3 cursor-pointer">
              <input
                type="checkbox"
                checked={config.credentials.enabled}
                onChange={(e) => updateConfig({ 
                  credentials: { ...config.credentials, enabled: e.target.checked }
                })}
                className="w-5 h-5 rounded"
              />
              <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                Enable credential-based testing (finds more vulnerabilities)
              </span>
            </label>

            {config.credentials.enabled && (
              <div className="space-y-4 pl-8">
                {/* SSH Credentials */}
                <div className={`p-4 rounded-lg ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                  <label className="flex items-center gap-3 cursor-pointer mb-3">
                    <input
                      type="checkbox"
                      checked={config.credentials.ssh.enabled}
                      onChange={(e) => updateCredentials("ssh", "enabled", e.target.checked)}
                      className="w-4 h-4 rounded"
                    />
                    <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                      SSH Credentials
                    </span>
                  </label>
                  
                  {config.credentials.ssh.enabled && (
                    <div className="grid grid-cols-2 gap-3">
                      <input
                        type="text"
                        placeholder="Username"
                        value={config.credentials.ssh.username}
                        onChange={(e) => updateCredentials("ssh", "username", e.target.value)}
                        className={inputClass}
                      />
                      <div className="relative">
                        <input
                          type={showPassword.ssh ? "text" : "password"}
                          placeholder="Password"
                          value={config.credentials.ssh.password}
                          onChange={(e) => updateCredentials("ssh", "password", e.target.value)}
                          className={inputClass}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(p => ({ ...p, ssh: !p.ssh }))}
                          className="absolute right-3 top-1/2 -translate-y-1/2"
                        >
                          {showPassword.ssh ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* Windows Credentials */}
                <div className={`p-4 rounded-lg ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                  <label className="flex items-center gap-3 cursor-pointer mb-3">
                    <input
                      type="checkbox"
                      checked={config.credentials.windows.enabled}
                      onChange={(e) => updateCredentials("windows", "enabled", e.target.checked)}
                      className="w-4 h-4 rounded"
                    />
                    <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                      Windows/SMB Credentials
                    </span>
                  </label>
                  
                  {config.credentials.windows.enabled && (
                    <div className="grid grid-cols-3 gap-3">
                      <input
                        type="text"
                        placeholder="Domain"
                        value={config.credentials.windows.domain}
                        onChange={(e) => updateCredentials("windows", "domain", e.target.value)}
                        className={inputClass}
                      />
                      <input
                        type="text"
                        placeholder="Username"
                        value={config.credentials.windows.username}
                        onChange={(e) => updateCredentials("windows", "username", e.target.value)}
                        className={inputClass}
                      />
                      <div className="relative">
                        <input
                          type={showPassword.windows ? "text" : "password"}
                          placeholder="Password"
                          value={config.credentials.windows.password}
                          onChange={(e) => updateCredentials("windows", "password", e.target.value)}
                          className={inputClass}
                        />
                        <button
                          type="button"
                          onClick={() => setShowPassword(p => ({ ...p, windows: !p.windows }))}
                          className="absolute right-3 top-1/2 -translate-y-1/2"
                        >
                          {showPassword.windows ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                        </button>
                      </div>
                    </div>
                  )}
                </div>

                {/* SNMP Credentials */}
                <div className={`p-4 rounded-lg ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
                  <label className="flex items-center gap-3 cursor-pointer mb-3">
                    <input
                      type="checkbox"
                      checked={config.credentials.snmp.enabled}
                      onChange={(e) => updateCredentials("snmp", "enabled", e.target.checked)}
                      className="w-4 h-4 rounded"
                    />
                    <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                      SNMP Community String
                    </span>
                  </label>
                  
                  {config.credentials.snmp.enabled && (
                    <div className="grid grid-cols-2 gap-3">
                      <input
                        type="text"
                        placeholder="Community string (e.g., public)"
                        value={config.credentials.snmp.community}
                        onChange={(e) => updateCredentials("snmp", "community", e.target.value)}
                        className={inputClass}
                      />
                      <select
                        value={config.credentials.snmp.version}
                        onChange={(e) => updateCredentials("snmp", "version", e.target.value)}
                        className={inputClass}
                      >
                        <option value="1">SNMP v1</option>
                        <option value="2c">SNMP v2c</option>
                        <option value="3">SNMP v3</option>
                      </select>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Advanced Options */}
      <div className={`${cardClass} p-6`}>
        <button
          type="button"
          onClick={() => setShowAdvanced(!showAdvanced)}
          className={`w-full flex items-center justify-between ${
            isDarkMode ? "text-white" : "text-gray-900"
          }`}
        >
          <div className="flex items-center gap-2">
            <Settings className="w-5 h-5" />
            <span className="text-lg font-semibold">Advanced Options</span>
          </div>
          {showAdvanced ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>

        {showAdvanced && (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className={labelClass}>Max Concurrent Hosts</label>
              <input
                type="number"
                min="1"
                max="100"
                value={config.maxConcurrentHosts}
                onChange={(e) => updateConfig({ maxConcurrentHosts: parseInt(e.target.value) || 10 })}
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Timeout per Host (seconds)</label>
              <input
                type="number"
                min="30"
                max="3600"
                value={config.timeoutPerHost}
                onChange={(e) => updateConfig({ timeoutPerHost: parseInt(e.target.value) || 300 })}
                className={inputClass}
              />
            </div>
            <div>
              <label className={labelClass}>Rate Limit (packets/sec)</label>
              <input
                type="number"
                min="1"
                max="1000"
                value={config.rateLimit}
                onChange={(e) => updateConfig({ rateLimit: parseInt(e.target.value) || 100 })}
                className={inputClass}
              />
            </div>

            <div className="md:col-span-3 space-y-3">
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.serviceDetection}
                  onChange={(e) => updateConfig({ serviceDetection: e.target.checked })}
                  className="w-5 h-5 rounded"
                />
                <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                  Service Detection (identify software versions)
                </span>
              </label>
              
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.vulnScan}
                  onChange={(e) => updateConfig({ vulnScan: e.target.checked })}
                  className="w-5 h-5 rounded"
                />
                <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                  Vulnerability Scanning (check CVE database)
                </span>
              </label>
              
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.sslAudit}
                  onChange={(e) => updateConfig({ sslAudit: e.target.checked })}
                  className="w-5 h-5 rounded"
                />
                <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                  SSL/TLS Audit (certificate and cipher analysis)
                </span>
              </label>
              
              <label className="flex items-center gap-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={config.safeChecks}
                  onChange={(e) => updateConfig({ safeChecks: e.target.checked })}
                  className="w-5 h-5 rounded"
                />
                <span className={isDarkMode ? "text-gray-300" : "text-gray-700"}>
                  Safe Checks Only (no DoS or destructive tests)
                </span>
              </label>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default NetworkScanConfig;
