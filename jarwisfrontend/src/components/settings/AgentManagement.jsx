// src/components/settings/AgentManagement.jsx
// Agent management panel for network scanning
import { useState, useEffect } from "react";
import { 
  Shield, Plus, Trash2, RefreshCw, CheckCircle2, XCircle, 
  Copy, Eye, EyeOff, Terminal, AlertTriangle,
  Server, Wifi, Clock, ChevronDown, ChevronUp
} from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { networkScanAPI } from "../../services/api";

const AgentManagement = () => {
  const { isDarkMode } = useTheme();
  
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [showRegisterForm, setShowRegisterForm] = useState(false);
  const [newAgent, setNewAgent] = useState({
    name: "",
    description: "",
    networkRanges: "",
  });
  const [registering, setRegistering] = useState(false);
  const [registeredAgent, setRegisteredAgent] = useState(null);
  const [showAgentKey, setShowAgentKey] = useState({});
  const [copiedField, setCopiedField] = useState(null);
  const [showSetupInstructions, setShowSetupInstructions] = useState(false);

  useEffect(() => {
    fetchAgents();
  }, []);

  const fetchAgents = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await networkScanAPI.getAgents();
      // Handle both {agents: [...]} and direct array format
      if (response?.agents) {
        setAgents(response.agents);
      } else if (Array.isArray(response)) {
        setAgents(response);
      } else {
        setAgents([]);
      }
    } catch (err) {
      console.error("Failed to fetch agents:", err);
      setError("Failed to load agents. Please try again.");
      setAgents([]);
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterAgent = async (e) => {
    e.preventDefault();
    setRegistering(true);
    setError(null);

    try {
      const networkRanges = newAgent.networkRanges
        .split(/[\n,]/)
        .map(r => r.trim())
        .filter(r => r.length > 0);

      if (networkRanges.length === 0) {
        throw new Error("Please specify at least one network range");
      }

      const response = await networkScanAPI.registerAgent({
        agent_name: newAgent.name,
        description: newAgent.description,
        network_ranges: networkRanges,
      });

      setRegisteredAgent(response);
      setNewAgent({ name: "", description: "", networkRanges: "" });
      fetchAgents();
    } catch (err) {
      console.error("Failed to register agent:", err);
      const errorMessage = err.response?.data?.detail || err.message || "Failed to register agent";
      setError(errorMessage);
    } finally {
      setRegistering(false);
    }
  };

  const handleDeleteAgent = async (agentId) => {
    if (!window.confirm("Are you sure you want to delete this agent? This cannot be undone.")) {
      return;
    }

    try {
      await networkScanAPI.deleteAgent(agentId);
      fetchAgents();
    } catch (err) {
      console.error("Failed to delete agent:", err);
      setError("Failed to delete agent. Please try again.");
    }
  };

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const cardClass = isDarkMode 
    ? "bg-slate-800/50 border border-slate-700/50 rounded-xl backdrop-blur-xl"
    : "bg-white border border-gray-200 rounded-xl shadow-sm";
  
  const inputClass = isDarkMode
    ? "w-full px-4 py-3 bg-slate-700/50 border border-slate-600/50 rounded-lg text-white placeholder-gray-400 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20 transition-all outline-none"
    : "w-full px-4 py-3 bg-white border border-gray-300 rounded-lg text-gray-900 placeholder-gray-500 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-200 transition-all outline-none";

  const labelClass = isDarkMode
    ? "block text-sm font-medium text-gray-300 mb-2"
    : "block text-sm font-medium text-gray-700 mb-2";

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h2 className={`text-xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            <Shield className="w-6 h-6 inline-block mr-2" />
            Network Agents
          </h2>
          <p className={`mt-1 text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            Manage agents for scanning private networks
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={fetchAgents}
            disabled={loading}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
              isDarkMode 
                ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                : "bg-gray-100 text-gray-700 hover:bg-gray-200"
            }`}
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
          <button
            onClick={() => setShowRegisterForm(!showRegisterForm)}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-all ${
              isDarkMode 
                ? "bg-cyan-600 text-white hover:bg-cyan-500" 
                : "bg-cyan-500 text-white hover:bg-cyan-600"
            }`}
          >
            <Plus className="w-4 h-4" />
            Register Agent
          </button>
        </div>
      </div>

      {/* Error Display */}
      {error && (
        <div className={`p-4 rounded-lg flex items-start gap-3 ${
          isDarkMode ? "bg-red-500/10 border border-red-500/30" : "bg-red-50 border border-red-200"
        }`}>
          <AlertTriangle className={`w-5 h-5 ${isDarkMode ? "text-red-400" : "text-red-600"}`} />
          <p className={isDarkMode ? "text-red-400" : "text-red-700"}>{error}</p>
          <button 
            onClick={() => setError(null)}
            className={`ml-auto ${isDarkMode ? "text-red-400 hover:text-red-300" : "text-red-600 hover:text-red-700"}`}
          >
            <XCircle className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Registration Form */}
      {showRegisterForm && (
        <div className={`${cardClass} p-6`}>
          <h3 className={`text-lg font-semibold mb-4 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            Register New Agent
          </h3>
          
          <form onSubmit={handleRegisterAgent} className="space-y-4">
            <div>
              <label className={labelClass}>Agent Name *</label>
              <input
                type="text"
                value={newAgent.name}
                onChange={(e) => setNewAgent(prev => ({ ...prev, name: e.target.value }))}
                placeholder="e.g., HQ-DataCenter-Agent"
                className={inputClass}
                required
              />
            </div>

            <div>
              <label className={labelClass}>Description</label>
              <input
                type="text"
                value={newAgent.description}
                onChange={(e) => setNewAgent(prev => ({ ...prev, description: e.target.value }))}
                placeholder="e.g., Scans internal data center network"
                className={inputClass}
              />
            </div>

            <div>
              <label className={labelClass}>Network Ranges *</label>
              <textarea
                value={newAgent.networkRanges}
                onChange={(e) => setNewAgent(prev => ({ ...prev, networkRanges: e.target.value }))}
                placeholder={"10.0.0.0/8\n192.168.1.0/24\n172.16.0.0/12"}
                className={`${inputClass} h-24 resize-none font-mono`}
                required
              />
              <p className={`text-sm mt-1 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                Enter private network CIDR ranges this agent can scan (one per line)
              </p>
            </div>

            <div className="flex gap-3">
              <button
                type="submit"
                disabled={registering || !newAgent.name || !newAgent.networkRanges}
                className={`flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-all ${
                  registering || !newAgent.name || !newAgent.networkRanges
                    ? "bg-gray-400 text-white cursor-not-allowed"
                    : isDarkMode 
                    ? "bg-cyan-600 text-white hover:bg-cyan-500" 
                    : "bg-cyan-500 text-white hover:bg-cyan-600"
                }`}
              >
                {registering ? (
                  <><RefreshCw className="w-4 h-4 animate-spin" /> Registering...</>
                ) : (
                  <><Plus className="w-4 h-4" /> Register Agent</>
                )}
              </button>
              <button
                type="button"
                onClick={() => setShowRegisterForm(false)}
                className={`px-6 py-3 rounded-lg transition-all ${
                  isDarkMode 
                    ? "bg-slate-700 text-gray-300 hover:bg-slate-600" 
                    : "bg-gray-100 text-gray-700 hover:bg-gray-200"
                }`}
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Newly Registered Agent Credentials */}
      {registeredAgent && (
        <div className={`${cardClass} p-6 border-2 ${isDarkMode ? "border-green-500/50" : "border-green-500"}`}>
          <div className="flex items-center gap-3 mb-4">
            <CheckCircle2 className="w-6 h-6 text-green-500" />
            <h3 className={`text-lg font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Agent Registered Successfully!
            </h3>
          </div>
          
          <div className={`p-4 rounded-lg ${isDarkMode ? "bg-amber-500/10 border border-amber-500/30" : "bg-amber-50 border border-amber-200"} mb-4`}>
            <p className={`text-sm ${isDarkMode ? "text-amber-400" : "text-amber-700"}`}>
              <strong>⚠️ Important:</strong> Save these credentials now. The agent key will not be shown again!
            </p>
          </div>

          <div className="space-y-4">
            <div>
              <label className={labelClass}>Agent ID</label>
              <div className="flex gap-2">
                <code className={`flex-1 px-4 py-2 rounded-lg font-mono text-sm ${
                  isDarkMode ? "bg-slate-700 text-cyan-400" : "bg-gray-100 text-cyan-700"
                }`}>
                  {registeredAgent.agent_id}
                </code>
                <button
                  onClick={() => copyToClipboard(registeredAgent.agent_id, 'agent_id')}
                  className={`px-3 py-2 rounded-lg ${isDarkMode ? "bg-slate-700 hover:bg-slate-600" : "bg-gray-100 hover:bg-gray-200"}`}
                >
                  {copiedField === 'agent_id' ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className={labelClass}>Agent Key (Secret)</label>
              <div className="flex gap-2">
                <code className={`flex-1 px-4 py-2 rounded-lg font-mono text-sm overflow-x-auto ${
                  isDarkMode ? "bg-slate-700 text-cyan-400" : "bg-gray-100 text-cyan-700"
                }`}>
                  {showAgentKey.new ? registeredAgent.agent_key : '••••••••••••••••••••••••••••••••'}
                </code>
                <button
                  onClick={() => setShowAgentKey(prev => ({ ...prev, new: !prev.new }))}
                  className={`px-3 py-2 rounded-lg ${isDarkMode ? "bg-slate-700 hover:bg-slate-600" : "bg-gray-100 hover:bg-gray-200"}`}
                >
                  {showAgentKey.new ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
                <button
                  onClick={() => copyToClipboard(registeredAgent.agent_key, 'agent_key')}
                  className={`px-3 py-2 rounded-lg ${isDarkMode ? "bg-slate-700 hover:bg-slate-600" : "bg-gray-100 hover:bg-gray-200"}`}
                >
                  {copiedField === 'agent_key' ? <CheckCircle2 className="w-4 h-4 text-green-500" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          </div>

          <button
            onClick={() => setRegisteredAgent(null)}
            className={`mt-4 w-full py-2 rounded-lg ${
              isDarkMode ? "bg-slate-700 hover:bg-slate-600 text-gray-300" : "bg-gray-100 hover:bg-gray-200 text-gray-700"
            }`}
          >
            I've saved these credentials
          </button>
        </div>
      )}

      {/* Setup Instructions */}
      <div className={cardClass}>
        <button
          onClick={() => setShowSetupInstructions(!showSetupInstructions)}
          className={`w-full p-4 flex items-center justify-between ${isDarkMode ? "text-white" : "text-gray-900"}`}
        >
          <div className="flex items-center gap-2">
            <Terminal className="w-5 h-5" />
            <span className="font-semibold">Agent Deployment Instructions</span>
          </div>
          {showSetupInstructions ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
        </button>

        {showSetupInstructions && (
          <div className="p-6 pt-0 space-y-4">
            <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Deploy the Jarwis Agent inside your private network to enable internal scanning.
            </p>

            <div>
              <h4 className={`font-medium mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Option 1: Docker (Recommended)
              </h4>
              <pre className={`p-4 rounded-lg overflow-x-auto text-sm ${
                isDarkMode ? "bg-slate-900 text-gray-300" : "bg-gray-900 text-gray-100"
              }`}>
{`docker run -d \\
  --name jarwis-agent \\
  --restart unless-stopped \\
  -e JARWIS_AGENT_ID="your-agent-id" \\
  -e JARWIS_AGENT_KEY="your-agent-key" \\
  -e JARWIS_API_URL="https://api.jarwis.io" \\
  --network host \\
  jarwis/network-agent:latest`}
              </pre>
            </div>

            <div>
              <h4 className={`font-medium mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Option 2: Python Script
              </h4>
              <pre className={`p-4 rounded-lg overflow-x-auto text-sm ${
                isDarkMode ? "bg-slate-900 text-gray-300" : "bg-gray-900 text-gray-100"
              }`}>
{`# Clone and setup
git clone https://github.com/jarwis-ai/jarwis-agent.git
cd jarwis-agent
pip install -r requirements.txt

# Configure environment
export JARWIS_AGENT_ID="your-agent-id"
export JARWIS_AGENT_KEY="your-agent-key"
export JARWIS_API_URL="https://api.jarwis.io"

# Run agent
python jarwis_agent.py`}
              </pre>
            </div>

            <div className={`p-4 rounded-lg ${isDarkMode ? "bg-slate-700/50" : "bg-gray-50"}`}>
              <h4 className={`font-medium mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Firewall Requirements
              </h4>
              <ul className={`text-sm space-y-1 ${isDarkMode ? "text-gray-300" : "text-gray-600"}`}>
                <li>✅ <strong>Outbound TCP 443</strong> to api.jarwis.io (required)</li>
                <li>✅ <strong>Internal TCP/UDP</strong> to scan targets (required)</li>
                <li>❌ <strong>No inbound</strong> connections required</li>
              </ul>
            </div>
          </div>
        )}
      </div>

      {/* Agent List */}
      <div className={`${cardClass} overflow-hidden`}>
        <div className={`p-4 border-b ${isDarkMode ? "border-slate-700" : "border-gray-200"}`}>
          <h3 className={`font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            Registered Agents ({agents.length})
          </h3>
        </div>

        {loading ? (
          <div className="p-8 text-center">
            <RefreshCw className={`w-8 h-8 mx-auto animate-spin ${isDarkMode ? "text-gray-500" : "text-gray-400"}`} />
            <p className={`mt-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>Loading agents...</p>
          </div>
        ) : agents.length === 0 ? (
          <div className="p-8 text-center">
            <Shield className={`w-12 h-12 mx-auto ${isDarkMode ? "text-gray-600" : "text-gray-400"}`} />
            <p className={`mt-4 font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              No Agents Registered
            </p>
            <p className={`mt-2 text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
              Register an agent to start scanning private networks.
            </p>
          </div>
        ) : (
          <div className={`divide-y ${isDarkMode ? "divide-slate-700" : "divide-gray-200"}`}>
            {agents.map((agent) => (
              <div 
                key={agent.agent_id || agent.id} 
                className={`p-4 ${isDarkMode ? "hover:bg-slate-700/50" : "hover:bg-gray-50"} transition-colors`}
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3">
                      <Server className={`w-5 h-5 ${isDarkMode ? "text-gray-400" : "text-gray-500"}`} />
                      <span className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                        {agent.name}
                      </span>
                      <span className={`px-2 py-0.5 text-xs rounded-full ${
                        agent.status === "online"
                          ? "bg-green-500/20 text-green-400"
                          : agent.status === "offline"
                          ? "bg-red-500/20 text-red-400"
                          : "bg-gray-500/20 text-gray-400"
                      }`}>
                        {agent.status || "unknown"}
                      </span>
                    </div>
                    
                    <div className={`mt-2 text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                      <p className="flex items-center gap-2">
                        <Wifi className="w-4 h-4" />
                        Networks: {agent.network_ranges?.join(", ") || "Not specified"}
                      </p>
                      <p className="flex items-center gap-2 mt-1">
                        <Clock className="w-4 h-4" />
                        Last seen: {agent.last_seen ? new Date(agent.last_seen).toLocaleString() : "Never"}
                      </p>
                    </div>

                    <div className={`mt-2 text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                      ID: {agent.agent_id || agent.id}
                    </div>
                  </div>

                  <button
                    onClick={() => handleDeleteAgent(agent.agent_id || agent.id)}
                    className={`p-2 rounded-lg transition-colors ${
                      isDarkMode 
                        ? "text-red-400 hover:bg-red-500/20" 
                        : "text-red-600 hover:bg-red-50"
                    }`}
                  >
                    <Trash2 className="w-5 h-5" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default AgentManagement;
