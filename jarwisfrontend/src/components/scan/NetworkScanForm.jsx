// NetworkScanForm - Dedicated network scan configuration form
import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Wifi } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { networkScanAPI } from "../../services/api";
import NetworkScanConfig from "./NetworkScanConfig";

const NetworkScanForm = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { refreshSubscription } = useSubscription();

  const [networkConfig, setNetworkConfig] = useState({
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
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const handleNetworkConfigChange = useCallback((newConfig) => {
    setNetworkConfig(newConfig);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      if (!networkConfig.targets.trim()) {
        setError("Please specify at least one target (IP, hostname, or CIDR)");
        setIsSubmitting(false);
        return;
      }

      // Check if private network requires agent
      if ((networkConfig.networkType === "private" || networkConfig.networkType === "cloud_vpc") && !networkConfig.agentId) {
        setError("Private network scans require a Jarwis Agent. Please register and select an agent.");
        setIsSubmitting(false);
        return;
      }

      // Build port range value
      let portRangeValue = networkConfig.portRange;
      if (networkConfig.portRange === "custom") {
        portRangeValue = networkConfig.customPorts || "1-65535";
      } else if (networkConfig.portRange === "top100") {
        portRangeValue = "top100";
      } else if (networkConfig.portRange === "top1000") {
        portRangeValue = "top1000";
      } else if (networkConfig.portRange === "common") {
        portRangeValue = "common";
      } else if (networkConfig.portRange === "all") {
        portRangeValue = "1-65535";
      }

      // Build credentials object
      const credentials = networkConfig.credentials.enabled ? {
        enabled: true,
        ssh: networkConfig.credentials.ssh.enabled ? {
          username: networkConfig.credentials.ssh.username,
          password: networkConfig.credentials.ssh.password,
          private_key: networkConfig.credentials.ssh.privateKey,
        } : null,
        windows: networkConfig.credentials.windows.enabled ? {
          username: networkConfig.credentials.windows.username,
          password: networkConfig.credentials.windows.password,
          domain: networkConfig.credentials.windows.domain,
        } : null,
        snmp: networkConfig.credentials.snmp.enabled ? {
          community: networkConfig.credentials.snmp.community,
          version: networkConfig.credentials.snmp.version,
        } : null,
      } : { enabled: false };

      const response = await networkScanAPI.startScan({
        targets: networkConfig.targets,
        profile: networkConfig.profile,
        port_range: portRangeValue,
        service_detection: networkConfig.serviceDetection,
        vuln_scan_enabled: networkConfig.vulnScan,
        ssl_audit_enabled: networkConfig.sslAudit,
        safe_checks: networkConfig.safeChecks,
        use_agent: networkConfig.useAgent,
        agent_id: networkConfig.agentId || null,
        credentials: credentials,
        max_concurrent_hosts: networkConfig.maxConcurrentHosts,
        timeout_per_host: networkConfig.timeoutPerHost,
        rate_limit: networkConfig.rateLimit,
      });

      if (response.scan_id) {
        refreshSubscription();
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "network" },
        });
      } else {
        throw new Error(response.error || response.detail || "Failed to start network scan");
      }
    } catch (err) {
      console.error("Start network scan error:", err);
      let errorMessage = "Failed to start network scan";
      if (err.response?.data?.detail) {
        const detail = err.response.data.detail;
        if (typeof detail === "string") errorMessage = detail;
        else if (detail.message) errorMessage = detail.message;
      } else if (err.message) {
        errorMessage = err.message;
      }
      setError(errorMessage);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      {error && (
        <div className="p-4 mb-4 bg-red-500/20 border border-red-500/50 rounded-xl text-red-400">
          {error}
        </div>
      )}

      <NetworkScanConfig
        onConfigChange={handleNetworkConfigChange}
        initialConfig={networkConfig}
        showAgentSetup={true}
      />
      
      {/* Submit Buttons */}
      <div className="mt-8 flex gap-4 justify-end">
        <button
          type="button"
          onClick={() => navigate("/dashboard")}
          className={
            isDarkMode
              ? "px-6 py-3 bg-slate-700/50 border border-slate-600/50 text-gray-300 rounded-xl hover:bg-slate-600/50 transition-all font-medium"
              : "px-6 py-3 bg-gray-100 border border-gray-300 text-gray-700 rounded-xl hover:bg-gray-200 transition-all font-medium"
          }
        >
          Cancel
        </button>
        <button
          type="submit"
          disabled={isSubmitting || !networkConfig.targets.trim()}
          className={`flex items-center gap-2 px-6 py-3 rounded-xl font-semibold transition-all ${
            isSubmitting || !networkConfig.targets.trim()
              ? "bg-gray-400 text-white cursor-not-allowed"
              : isDarkMode
              ? "bg-gradient-to-r from-cyan-600 to-blue-600 text-white hover:from-cyan-700 hover:to-blue-700"
              : "bg-gradient-to-r from-cyan-500 to-blue-500 text-white hover:from-cyan-600 hover:to-blue-600"
          }`}
        >
          <Wifi className="w-5 h-5" />
          {isSubmitting ? "Starting Scan..." : "Start Network Scan"}
        </button>
      </div>
    </form>
  );
};

export default NetworkScanForm;
