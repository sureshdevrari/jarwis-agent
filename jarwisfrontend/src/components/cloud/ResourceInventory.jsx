// src/components/cloud/ResourceInventory.jsx - Cloud Resource Inventory Table
import { useState, useMemo } from "react";
import { useTheme } from "../../context/ThemeContext";
import {
  Server,
  Database,
  HardDrive,
  Globe,
  Key,
  Users,
  Shield,
  Cloud,
  Container,
  Network,
  Lock,
  Unlock,
  AlertTriangle,
  CheckCircle,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  ExternalLink,
} from "lucide-react";

// Resource type icons
const RESOURCE_ICONS = {
  EC2: Server,
  RDS: Database,
  S3: HardDrive,
  Lambda: Cloud,
  IAM: Users,
  VPC: Network,
  EKS: Container,
  SecurityGroup: Shield,
  KMS: Key,
  CloudFront: Globe,
  VM: Server,
  Storage: HardDrive,
  SQL: Database,
  AKS: Container,
  GCE: Server,
  GCS: HardDrive,
  GKE: Container,
  default: Cloud,
};

// Risk score badge
const RiskBadge = ({ score }) => {
  const getColor = () => {
    if (score >= 80) return "bg-red-500";
    if (score >= 60) return "bg-orange-500";
    if (score >= 40) return "bg-yellow-500";
    return "bg-green-500";
  };

  const getLabel = () => {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 40) return "Medium";
    return "Low";
  };

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium text-white ${getColor()}`}>
      {getLabel()} ({score})
    </span>
  );
};

// Provider badge
const ProviderBadge = ({ provider }) => {
  const colors = {
    aws: "bg-orange-100 text-orange-700",
    azure: "bg-blue-100 text-blue-700",
    gcp: "bg-green-100 text-green-700",
    kubernetes: "bg-indigo-100 text-indigo-700",
  };

  return (
    <span className={`px-2 py-0.5 rounded text-xs font-medium ${colors[provider] || "bg-gray-100 text-gray-700"}`}>
      {provider?.toUpperCase() || "Unknown"}
    </span>
  );
};

// Resource row component
const ResourceRow = ({ resource, isExpanded, onToggle, isDarkMode }) => {
  const Icon = RESOURCE_ICONS[resource.type] || RESOURCE_ICONS.default;
  
  return (
    <>
      {/* Main row */}
      <tr
        className={`cursor-pointer transition-colors ${
          isDarkMode
            ? "hover:bg-gray-700"
            : "hover:bg-gray-50"
        }`}
        onClick={() => onToggle(resource.id)}
      >
        <td className="px-4 py-3">
          <button className={isDarkMode ? "text-gray-400" : "text-gray-500"}>
            {isExpanded ? (
              <ChevronDown className="w-4 h-4" />
            ) : (
              <ChevronRight className="w-4 h-4" />
            )}
          </button>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${isDarkMode ? "bg-gray-700" : "bg-gray-100"}`}>
              <Icon className={`w-4 h-4 ${isDarkMode ? "text-gray-300" : "text-gray-600"}`} />
            </div>
            <div>
              <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                {resource.name || resource.id}
              </p>
              <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                {resource.id}
              </p>
            </div>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className={`text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
            {resource.type}
          </span>
        </td>
        <td className="px-4 py-3">
          <ProviderBadge provider={resource.provider} />
        </td>
        <td className="px-4 py-3">
          <span className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            {resource.region || "N/A"}
          </span>
        </td>
        <td className="px-4 py-3">
          <RiskBadge score={resource.risk_score || 0} />
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {resource.public_exposed && (
              <span title="Publicly Exposed">
                <Globe className="w-4 h-4 text-red-500" />
              </span>
            )}
            {resource.encrypted ? (
              <span title="Encrypted">
                <Lock className="w-4 h-4 text-green-500" />
              </span>
            ) : (
              <span title="Not Encrypted">
                <Unlock className="w-4 h-4 text-yellow-500" />
              </span>
            )}
            {resource.findings_count > 0 && (
              <span title={`${resource.findings_count} findings`}>
                <AlertTriangle className="w-4 h-4 text-orange-500" />
              </span>
            )}
          </div>
        </td>
      </tr>
      
      {/* Expanded details */}
      {isExpanded && (
        <tr className={isDarkMode ? "bg-gray-750" : "bg-gray-50"}>
          <td colSpan={7} className="px-4 py-4">
            <div className="pl-8 space-y-4">
              {/* Resource details grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {resource.account_id && (
                  <div>
                    <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                      Account ID
                    </p>
                    <p className={`text-sm font-mono ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      {resource.account_id}
                    </p>
                  </div>
                )}
                {resource.created_at && (
                  <div>
                    <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                      Created
                    </p>
                    <p className={`text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      {new Date(resource.created_at).toLocaleDateString()}
                    </p>
                  </div>
                )}
                {resource.vpc_id && (
                  <div>
                    <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                      VPC ID
                    </p>
                    <p className={`text-sm font-mono ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      {resource.vpc_id}
                    </p>
                  </div>
                )}
                {resource.subnet_id && (
                  <div>
                    <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                      Subnet
                    </p>
                    <p className={`text-sm font-mono ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                      {resource.subnet_id}
                    </p>
                  </div>
                )}
              </div>

              {/* Tags */}
              {resource.tags && Object.keys(resource.tags).length > 0 && (
                <div>
                  <p className={`text-xs mb-2 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    Tags
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(resource.tags).map(([key, value]) => (
                      <span
                        key={key}
                        className={`px-2 py-0.5 rounded text-xs ${
                          isDarkMode ? "bg-gray-700 text-gray-300" : "bg-gray-200 text-gray-700"
                        }`}
                      >
                        {key}: {value}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Findings preview */}
              {resource.findings_count > 0 && (
                <div>
                  <p className={`text-xs mb-2 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    Related Findings ({resource.findings_count})
                  </p>
                  <button
                    className={`text-sm flex items-center gap-1 ${
                      isDarkMode ? "text-blue-400 hover:text-blue-300" : "text-blue-600 hover:text-blue-700"
                    }`}
                  >
                    View findings
                    <ExternalLink className="w-3 h-3" />
                  </button>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
};

// Main Resource Inventory component
const ResourceInventory = ({ resources = [], findings = [] }) => {
  const { isDarkMode } = useTheme();
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedRows, setExpandedRows] = useState(new Set());
  const [filterType, setFilterType] = useState("all");
  const [filterProvider, setFilterProvider] = useState("all");
  const [sortBy, setSortBy] = useState("risk_score");
  const [sortOrder, setSortOrder] = useState("desc");

  // Compute findings count per resource
  const resourcesWithFindings = useMemo(() => {
    return resources.map((resource) => {
      const resourceFindings = findings.filter(
        (f) => f.resource_id === resource.id || f.url?.includes(resource.id)
      );
      return {
        ...resource,
        findings_count: resourceFindings.length,
      };
    });
  }, [resources, findings]);

  // Filter and sort resources
  const filteredResources = useMemo(() => {
    let result = resourcesWithFindings;

    // Search filter
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        (r) =>
          r.name?.toLowerCase().includes(query) ||
          r.id?.toLowerCase().includes(query) ||
          r.type?.toLowerCase().includes(query)
      );
    }

    // Type filter
    if (filterType !== "all") {
      result = result.filter((r) => r.type === filterType);
    }

    // Provider filter
    if (filterProvider !== "all") {
      result = result.filter((r) => r.provider === filterProvider);
    }

    // Sort
    result = [...result].sort((a, b) => {
      let aVal = a[sortBy] || 0;
      let bVal = b[sortBy] || 0;
      if (typeof aVal === "string") aVal = aVal.toLowerCase();
      if (typeof bVal === "string") bVal = bVal.toLowerCase();
      
      if (sortOrder === "asc") {
        return aVal > bVal ? 1 : -1;
      }
      return aVal < bVal ? 1 : -1;
    });

    return result;
  }, [resourcesWithFindings, searchQuery, filterType, filterProvider, sortBy, sortOrder]);

  // Get unique types and providers for filters
  const resourceTypes = [...new Set(resources.map((r) => r.type))].filter(Boolean);
  const providers = [...new Set(resources.map((r) => r.provider))].filter(Boolean);

  // Toggle row expansion
  const toggleRow = (id) => {
    const newExpanded = new Set(expandedRows);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedRows(newExpanded);
  };

  // Stats
  const stats = useMemo(() => {
    return {
      total: resources.length,
      publicExposed: resources.filter((r) => r.public_exposed).length,
      unencrypted: resources.filter((r) => !r.encrypted).length,
      highRisk: resources.filter((r) => (r.risk_score || 0) >= 60).length,
    };
  }, [resources]);

  if (!resources || resources.length === 0) {
    return (
      <div className={`p-8 rounded-xl text-center ${
        isDarkMode ? "bg-gray-800" : "bg-white"
      } border ${isDarkMode ? "border-gray-700" : "border-gray-200"}`}>
        <Cloud className={`w-12 h-12 mx-auto mb-3 ${isDarkMode ? "text-gray-600" : "text-gray-300"}`} />
        <p className={isDarkMode ? "text-gray-500" : "text-gray-400"}>
          No cloud resources discovered
        </p>
        <p className={`text-sm mt-1 ${isDarkMode ? "text-gray-600" : "text-gray-500"}`}>
          Run a cloud scan to discover resources
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stats bar */}
      <div className="grid grid-cols-4 gap-4">
        <div className={`p-4 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${
          isDarkMode ? "border-gray-700" : "border-gray-200"
        }`}>
          <p className={`text-2xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            {stats.total}
          </p>
          <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            Total Resources
          </p>
        </div>
        <div className={`p-4 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${
          isDarkMode ? "border-gray-700" : "border-gray-200"
        }`}>
          <p className="text-2xl font-bold text-red-500">{stats.publicExposed}</p>
          <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            Publicly Exposed
          </p>
        </div>
        <div className={`p-4 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${
          isDarkMode ? "border-gray-700" : "border-gray-200"
        }`}>
          <p className="text-2xl font-bold text-yellow-500">{stats.unencrypted}</p>
          <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            Not Encrypted
          </p>
        </div>
        <div className={`p-4 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${
          isDarkMode ? "border-gray-700" : "border-gray-200"
        }`}>
          <p className="text-2xl font-bold text-orange-500">{stats.highRisk}</p>
          <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            High Risk
          </p>
        </div>
      </div>

      {/* Filters */}
      <div className={`p-4 rounded-lg ${isDarkMode ? "bg-gray-800" : "bg-white"} border ${
        isDarkMode ? "border-gray-700" : "border-gray-200"
      }`}>
        <div className="flex flex-wrap gap-4">
          {/* Search */}
          <div className="flex-1 min-w-[200px]">
            <div className="relative">
              <Search className={`absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 ${
                isDarkMode ? "text-gray-500" : "text-gray-400"
              }`} />
              <input
                type="text"
                placeholder="Search resources..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className={`w-full pl-10 pr-4 py-2 rounded-lg border ${
                  isDarkMode
                    ? "bg-gray-700 border-gray-600 text-white placeholder-gray-400"
                    : "bg-white border-gray-300 text-gray-900 placeholder-gray-500"
                }`}
              />
            </div>
          </div>

          {/* Type filter */}
          <select
            value={filterType}
            onChange={(e) => setFilterType(e.target.value)}
            className={`px-4 py-2 rounded-lg border ${
              isDarkMode
                ? "bg-gray-700 border-gray-600 text-white"
                : "bg-white border-gray-300 text-gray-900"
            }`}
          >
            <option value="all">All Types</option>
            {resourceTypes.map((type) => (
              <option key={type} value={type}>{type}</option>
            ))}
          </select>

          {/* Provider filter */}
          <select
            value={filterProvider}
            onChange={(e) => setFilterProvider(e.target.value)}
            className={`px-4 py-2 rounded-lg border ${
              isDarkMode
                ? "bg-gray-700 border-gray-600 text-white"
                : "bg-white border-gray-300 text-gray-900"
            }`}
          >
            <option value="all">All Providers</option>
            {providers.map((p) => (
              <option key={p} value={p}>{p.toUpperCase()}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Table */}
      <div className={`rounded-xl overflow-hidden border ${
        isDarkMode ? "border-gray-700" : "border-gray-200"
      }`}>
        <table className="w-full">
          <thead className={isDarkMode ? "bg-gray-800" : "bg-gray-50"}>
            <tr>
              <th className="px-4 py-3 text-left w-10"></th>
              <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${
                isDarkMode ? "text-gray-400" : "text-gray-500"
              }`}>
                Resource
              </th>
              <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${
                isDarkMode ? "text-gray-400" : "text-gray-500"
              }`}>
                Type
              </th>
              <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${
                isDarkMode ? "text-gray-400" : "text-gray-500"
              }`}>
                Provider
              </th>
              <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${
                isDarkMode ? "text-gray-400" : "text-gray-500"
              }`}>
                Region
              </th>
              <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${
                isDarkMode ? "text-gray-400" : "text-gray-500"
              }`}>
                Risk Score
              </th>
              <th className={`px-4 py-3 text-left text-xs font-medium uppercase tracking-wider ${
                isDarkMode ? "text-gray-400" : "text-gray-500"
              }`}>
                Status
              </th>
            </tr>
          </thead>
          <tbody className={`divide-y ${isDarkMode ? "divide-gray-700 bg-gray-800" : "divide-gray-200 bg-white"}`}>
            {filteredResources.map((resource) => (
              <ResourceRow
                key={resource.id}
                resource={resource}
                isExpanded={expandedRows.has(resource.id)}
                onToggle={toggleRow}
                isDarkMode={isDarkMode}
              />
            ))}
          </tbody>
        </table>

        {filteredResources.length === 0 && (
          <div className={`p-8 text-center ${isDarkMode ? "bg-gray-800" : "bg-white"}`}>
            <p className={isDarkMode ? "text-gray-500" : "text-gray-400"}>
              No resources match your filters
            </p>
          </div>
        )}
      </div>

      {/* Footer */}
      <div className={`text-sm ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
        Showing {filteredResources.length} of {resources.length} resources
      </div>
    </div>
  );
};

export default ResourceInventory;
