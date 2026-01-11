// src/pages/cloud/CloudScanStart.jsx - Cloud Security Scan Configuration
import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useTheme } from "../../context/ThemeContext";
import { cloudScanAPI } from "../../services/api";
import {
  Cloud,
  Server,
  Shield,
  AlertTriangle,
  CheckCircle,
  ChevronRight,
  Info,
  Key,
  Eye,
  EyeOff,
  RefreshCw,
  Play,
  FileCode,
  Container,
  Activity,
  Download,
  Lock,
  Unlock,
} from "lucide-react";

// Provider configurations with both legacy and enterprise auth modes
const PROVIDERS = {
  aws: {
    name: "Amazon Web Services",
    icon: "🔶",
    color: "orange",
    authModes: {
      enterprise: {
        name: "Cross-Account Role (Recommended)",
        description: "More secure - uses IAM role with temporary credentials",
        credentials: [
          { key: "role_arn", label: "Role ARN", type: "text", required: true, 
            placeholder: "arn:aws:iam::123456789012:role/JarwisSecurityScannerRole" },
          { key: "external_id", label: "External ID", type: "text", required: true, 
            placeholder: "Will be generated for you" },
          { key: "region", label: "Default Region", type: "select", required: true, 
            options: ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"] 
          },
        ],
      },
      legacy: {
        name: "Direct Credentials (Legacy)",
        description: "Uses access keys directly - less secure",
        credentials: [
          { key: "access_key_id", label: "Access Key ID", type: "text", required: true },
          { key: "secret_access_key", label: "Secret Access Key", type: "password", required: true },
          { key: "region", label: "Default Region", type: "select", required: true, 
            options: ["us-east-1", "us-east-2", "us-west-1", "us-west-2", "eu-west-1", "eu-central-1", "ap-southeast-1", "ap-northeast-1"] 
          },
          { key: "session_token", label: "Session Token (Optional)", type: "password", required: false },
        ],
      },
    },
    services: [
      { id: "s3", name: "S3 Buckets", description: "Encryption, public access, logging", default: true },
      { id: "iam", name: "IAM", description: "Users, roles, MFA, policies", default: true },
      { id: "ec2", name: "EC2", description: "Security groups, instances, metadata", default: true },
      { id: "rds", name: "RDS", description: "Database encryption, public access", default: true },
      { id: "lambda", name: "Lambda", description: "Runtimes, environment variables", default: true },
      { id: "cloudtrail", name: "CloudTrail", description: "Logging configuration", default: true },
    ],
  },
  azure: {
    name: "Microsoft Azure",
    icon: "🔵",
    color: "blue",
    authModes: {
      enterprise: {
        name: "Service Principal",
        description: "Standard Azure authentication with service principal",
        credentials: [
          { key: "tenant_id", label: "Tenant ID", type: "text", required: true },
          { key: "client_id", label: "Client ID", type: "text", required: true },
          { key: "client_secret", label: "Client Secret", type: "password", required: true },
          { key: "subscription_ids", label: "Subscription IDs (comma-separated)", type: "text", required: true,
            placeholder: "sub-id-1, sub-id-2" },
        ],
      },
    },
    services: [
      { id: "storage", name: "Storage Accounts", description: "Encryption, public access, HTTPS", default: true },
      { id: "vms", name: "Virtual Machines", description: "Managed disks, encryption", default: true },
      { id: "sql", name: "SQL Servers", description: "Auditing, encryption, firewall", default: true },
      { id: "network", name: "Network Security", description: "NSGs, RDP/SSH access", default: true },
      { id: "keyvaults", name: "Key Vaults", description: "Soft delete, purge protection", default: true },
      { id: "aks", name: "AKS Clusters", description: "RBAC, network policies", default: true },
      { id: "appservices", name: "App Services", description: "HTTPS, TLS, authentication", default: true },
      { id: "monitor", name: "Logging & Monitoring", description: "Activity logs, retention", default: true },
    ],
  },
  gcp: {
    name: "Google Cloud Platform",
    icon: "🔴",
    color: "red",
    authModes: {
      enterprise: {
        name: "Service Account",
        description: "Uses service account JSON key or workload identity",
        credentials: [
          { key: "project_ids", label: "Project IDs (comma-separated)", type: "text", required: true,
            placeholder: "my-project-1, my-project-2" },
          { key: "service_account_key", label: "Service Account JSON Key", type: "textarea", required: true },
        ],
      },
    },
    services: [
      { id: "compute", name: "Compute Engine", description: "Instances, service accounts", default: true },
      { id: "storage", name: "Cloud Storage", description: "Bucket permissions, public access", default: true },
      { id: "iam", name: "IAM", description: "Service accounts, policies", default: true },
      { id: "sql", name: "Cloud SQL", description: "SSL, authorized networks", default: true },
      { id: "gke", name: "GKE", description: "RBAC, network policies", default: true },
    ],
  },
};

// Scan modules
const SCAN_MODULES = [
  {
    id: "cspm",
    name: "CSPM (Cloud Security Posture)",
    description: "CIS Benchmarks, security misconfigurations",
    icon: Shield,
    default: true,
  },
  {
    id: "iac",
    name: "IaC Security Scanner",
    description: "Terraform, CloudFormation, Kubernetes manifests",
    icon: FileCode,
    default: true,
  },
  {
    id: "container",
    name: "Container Security",
    description: "Image vulnerabilities, registry scanning",
    icon: Container,
    default: true,
  },
  {
    id: "runtime",
    name: "Runtime Threat Detection",
    description: "CloudTrail, Activity Logs, anomaly detection",
    icon: Activity,
    default: false,
  },
];

// Compliance frameworks
const COMPLIANCE_FRAMEWORKS = [
  { id: "CIS", name: "CIS Benchmarks", description: "Industry-standard security configs" },
  { id: "PCI-DSS", name: "PCI-DSS", description: "Payment card security" },
  { id: "HIPAA", name: "HIPAA", description: "Healthcare data protection" },
  { id: "SOC2", name: "SOC 2", description: "Trust service criteria" },
];

const CloudScanStart = () => {
  const { isDarkMode } = useTheme();
  const navigate = useNavigate();

  // State
  const [step, setStep] = useState(1);
  const [selectedProvider, setSelectedProvider] = useState(null);
  const [authMode, setAuthMode] = useState("enterprise"); // 'enterprise' or 'legacy'
  const [credentials, setCredentials] = useState({});
  const [showPasswords, setShowPasswords] = useState({});
  const [selectedModules, setSelectedModules] = useState(
    SCAN_MODULES.filter((m) => m.default).map((m) => m.id)
  );
  const [selectedServices, setSelectedServices] = useState([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState(["CIS"]);
  const [iacPath, setIacPath] = useState("");
  const [containerImage, setContainerImage] = useState("");
  const [isValidating, setIsValidating] = useState(false);
  const [validationResult, setValidationResult] = useState(null);
  const [isStarting, setIsStarting] = useState(false);
  const [error, setError] = useState(null);
  const [onboardingTemplate, setOnboardingTemplate] = useState(null);
  const [externalId, setExternalId] = useState(null);

  // Initialize selected services when provider changes
  useEffect(() => {
    if (selectedProvider) {
      const provider = PROVIDERS[selectedProvider];
      const defaultServices = provider.services
        .filter((s) => s.default)
        .map((s) => s.id);
      setSelectedServices(defaultServices);
      
      // Reset auth mode and credentials
      setAuthMode("enterprise");
      setCredentials({});
      setValidationResult(null);
      
      // Generate external ID for AWS
      if (selectedProvider === "aws") {
        fetchExternalId();
      }
    }
  }, [selectedProvider]);

  // Fetch external ID for AWS
  const fetchExternalId = async () => {
    try {
      const response = await cloudScanAPI.generateExternalId();
      setExternalId(response.external_id);
      setCredentials(prev => ({ ...prev, external_id: response.external_id }));
    } catch (err) {
      console.error("Failed to generate external ID:", err);
    }
  };

  // Fetch onboarding template
  const fetchOnboardingTemplate = async () => {
    if (!selectedProvider) return;
    try {
      const template = await cloudScanAPI.getOnboardingTemplate(selectedProvider);
      setOnboardingTemplate(template);
    } catch (err) {
      console.error("Failed to fetch onboarding template:", err);
    }
  };

  // Download template
  const downloadTemplate = () => {
    if (!onboardingTemplate) return;
    const blob = new Blob([onboardingTemplate.template_content], { type: "text/plain" });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    const ext = onboardingTemplate.template_type === "cloudformation" ? "yaml" : 
                onboardingTemplate.template_type === "powershell" ? "ps1" : "sh";
    a.download = `jarwis-${selectedProvider}-setup.${ext}`;
    a.click();
    window.URL.revokeObjectURL(url);
  };

  // Handle credential change
  const handleCredentialChange = (key, value) => {
    setCredentials((prev) => ({ ...prev, [key]: value }));
    setValidationResult(null);
  };

  // Toggle password visibility
  const togglePassword = (key) => {
    setShowPasswords((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  // Toggle module selection
  const toggleModule = (moduleId) => {
    setSelectedModules((prev) =>
      prev.includes(moduleId)
        ? prev.filter((id) => id !== moduleId)
        : [...prev, moduleId]
    );
  };

  // Toggle framework selection
  const toggleFramework = (frameworkId) => {
    setSelectedFrameworks((prev) =>
      prev.includes(frameworkId)
        ? prev.filter((id) => id !== frameworkId)
        : [...prev, frameworkId]
    );
  };

  // Validate credentials
  const validateCredentials = async () => {
    if (!selectedProvider) return;

    setIsValidating(true);
    setError(null);
    setValidationResult(null);

    try {
      const response = await cloudScanAPI.validateCredentials(selectedProvider, credentials);
      setValidationResult({
        success: response.valid,
        message: response.message || (response.valid ? "Credentials validated successfully" : "Invalid credentials"),
      });
    } catch (err) {
      setValidationResult({
        success: false,
        message: err.response?.data?.detail || "Failed to validate credentials",
      });
    } finally {
      setIsValidating(false);
    }
  };

  // Start scan
  const startScan = async () => {
    if (!selectedProvider || !validationResult?.success) return;

    setIsStarting(true);
    setError(null);

    try {
      const config = {
        providers: [selectedProvider],
        credentials: {
          [selectedProvider]: {
            ...credentials,
            auth_mode: authMode,
          },
        },
        services: selectedServices,
        modules: selectedModules,
        compliance_frameworks: selectedFrameworks,
        options: {
          iac_path: iacPath || undefined,
          container_image: containerImage || undefined,
        },
      };

      const response = await cloudScanAPI.startScan(config);
      
      // Navigate to results page
      navigate(`/dashboard/cloud/${response.scan_id}`);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to start scan");
    } finally {
      setIsStarting(false);
    }
  };

  // Check if current step is complete
  const isStepComplete = () => {
    switch (step) {
      case 1:
        return selectedProvider !== null;
      case 2:
        if (!selectedProvider) return false;
        const provider = PROVIDERS[selectedProvider];
        const currentAuthMode = provider.authModes[authMode];
        if (!currentAuthMode) return false;
        return currentAuthMode.credentials
          .filter((c) => c.required)
          .every((c) => credentials[c.key]?.trim());
      case 3:
        // At least one service and one module and one framework
        return selectedServices.length > 0 && selectedModules.length > 0 && selectedFrameworks.length > 0;
      default:
        return false;
    }
  };

  return (
    <div className={`min-h-screen py-8 ${isDarkMode ? "bg-gray-900" : "bg-gray-50"}`}>
      <div className="max-w-4xl mx-auto px-4">
        {/* Header */}
        <div className="mb-8">
          <h1 className={`text-3xl font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            Cloud Security Scan
          </h1>
          <p className={`mt-2 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
            Comprehensive cloud infrastructure security assessment
          </p>
        </div>

        {/* Progress Steps */}
        <div className="flex items-center mb-8">
          {[1, 2, 3].map((s) => (
            <div key={s} className="flex items-center">
              <div
                className={`w-10 h-10 rounded-full flex items-center justify-center font-bold ${
                  step >= s
                    ? "bg-blue-600 text-white"
                    : isDarkMode
                    ? "bg-gray-700 text-gray-400"
                    : "bg-gray-200 text-gray-500"
                }`}
              >
                {s}
              </div>
              {s < 3 && (
                <div
                  className={`w-24 h-1 mx-2 ${
                    step > s
                      ? "bg-blue-600"
                      : isDarkMode
                      ? "bg-gray-700"
                      : "bg-gray-200"
                  }`}
                />
              )}
            </div>
          ))}
        </div>

        {/* Step 1: Select Provider */}
        {step === 1 && (
          <div className="space-y-4">
            <h2 className={`text-xl font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Select Cloud Provider
            </h2>
            <div className="grid grid-cols-3 gap-4">
              {Object.entries(PROVIDERS).map(([key, provider]) => (
                <button
                  key={key}
                  onClick={() => setSelectedProvider(key)}
                  className={`p-6 rounded-xl border-2 transition-all text-left ${
                    selectedProvider === key
                      ? "border-blue-500 bg-blue-500/10"
                      : isDarkMode
                      ? "border-gray-700 bg-gray-800 hover:border-gray-600"
                      : "border-gray-200 bg-white hover:border-gray-300"
                  }`}
                >
                  <span className="text-4xl">{provider.icon}</span>
                  <h3 className={`mt-3 font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {provider.name}
                  </h3>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Step 2: Enter Credentials */}
        {step === 2 && selectedProvider && (
          <div className="space-y-6">
            <h2 className={`text-xl font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Configure {PROVIDERS[selectedProvider].name} Access
            </h2>

            {/* Auth Mode Toggle - Only show if provider has multiple auth modes */}
            {Object.keys(PROVIDERS[selectedProvider].authModes).length > 1 && (
              <div>
                <h3 className={`text-sm font-medium mb-3 ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                  Authentication Method
                </h3>
                <div className="flex gap-4">
                  {Object.entries(PROVIDERS[selectedProvider].authModes).map(([mode, config]) => (
                    <button
                      key={mode}
                      onClick={() => {
                        setAuthMode(mode);
                        setCredentials({});
                        setValidationResult(null);
                      }}
                      className={`flex items-center gap-3 px-4 py-3 rounded-lg border-2 transition-all ${
                        authMode === mode
                          ? "border-blue-500 bg-blue-500/10"
                          : isDarkMode
                          ? "border-gray-700 hover:border-gray-600"
                          : "border-gray-200 hover:border-gray-300"
                      }`}
                    >
                      {mode === "enterprise" || mode === "role" || mode === "workload_identity" ? (
                        <Lock className={`w-5 h-5 ${authMode === mode ? "text-blue-500" : isDarkMode ? "text-gray-400" : "text-gray-500"}`} />
                      ) : (
                        <Unlock className={`w-5 h-5 ${authMode === mode ? "text-blue-500" : isDarkMode ? "text-gray-400" : "text-gray-500"}`} />
                      )}
                      <div className="text-left">
                        <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                          {config.label}
                        </p>
                        <p className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                          {config.description}
                        </p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Info box */}
            <div className={`p-4 rounded-lg flex items-start gap-3 ${
              isDarkMode ? "bg-blue-500/10" : "bg-blue-50"
            }`}>
              <Info className="w-5 h-5 text-blue-500 mt-0.5" />
              <div>
                <p className={`text-sm ${isDarkMode ? "text-blue-300" : "text-blue-700"}`}>
                  {authMode === "role" || authMode === "workload_identity" 
                    ? "Enterprise authentication uses secure cross-account roles. Your AWS account remains in control."
                    : "Your credentials are encrypted and never stored. They are only used during the scan."}
                </p>
              </div>
            </div>

            {/* Onboarding Template Download - Only for enterprise modes */}
            {(authMode === "role" || authMode === "workload_identity") && (
              <div className={`p-4 rounded-lg border ${
                isDarkMode ? "border-gray-700 bg-gray-800" : "border-gray-200 bg-gray-50"
              }`}>
                <h4 className={`font-medium mb-2 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  Setup Instructions
                </h4>
                <p className={`text-sm mb-3 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                  {onboardingTemplate?.instructions || "Download and run the setup template to create the required IAM role in your cloud account."}
                </p>
                <button
                  onClick={() => {
                    if (!onboardingTemplate) fetchOnboardingTemplate();
                    else downloadTemplate();
                  }}
                  className="flex items-center gap-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition-colors"
                >
                  <Download className="w-4 h-4" />
                  {onboardingTemplate ? "Download Setup Template" : "Load Template..."}
                </button>
              </div>
            )}

            {/* Credential fields - filtered by current auth mode */}
            <div className="space-y-4">
              {PROVIDERS[selectedProvider].authModes[authMode]?.credentials.map((field) => (
                <div key={field.key}>
                  <label className={`block text-sm font-medium mb-2 ${
                    isDarkMode ? "text-gray-300" : "text-gray-700"
                  }`}>
                    {field.label}
                    {field.required && <span className="text-red-500 ml-1">*</span>}
                  </label>

                  {field.type === "textarea" ? (
                    <textarea
                      value={credentials[field.key] || ""}
                      onChange={(e) => handleCredentialChange(field.key, e.target.value)}
                      rows={4}
                      className={`w-full px-4 py-3 rounded-lg border font-mono text-sm ${
                        isDarkMode
                          ? "bg-gray-800 border-gray-600 text-white placeholder-gray-400"
                          : "bg-white border-gray-300 text-gray-900 placeholder-gray-500"
                      }`}
                      placeholder={`Paste your ${field.label} here...`}
                    />
                  ) : field.type === "select" ? (
                    <select
                      value={credentials[field.key] || ""}
                      onChange={(e) => handleCredentialChange(field.key, e.target.value)}
                      className={`w-full px-4 py-3 rounded-lg border ${
                        isDarkMode
                          ? "bg-gray-800 border-gray-600 text-white"
                          : "bg-white border-gray-300 text-gray-900"
                      }`}
                    >
                      <option value="">Select {field.label}</option>
                      {field.options.map((opt) => (
                        <option key={opt} value={opt}>{opt}</option>
                      ))}
                    </select>
                  ) : field.readonly ? (
                    <div className="relative">
                      <input
                        type="text"
                        value={credentials[field.key] || ""}
                        readOnly
                        className={`w-full px-4 py-3 rounded-lg border font-mono text-sm ${
                          isDarkMode
                            ? "bg-gray-900 border-gray-600 text-gray-300"
                            : "bg-gray-100 border-gray-300 text-gray-700"
                        }`}
                      />
                      <span className={`absolute right-3 top-1/2 -translate-y-1/2 text-xs ${
                        isDarkMode ? "text-gray-500" : "text-gray-400"
                      }`}>
                        Auto-generated
                      </span>
                    </div>
                  ) : (
                    <div className="relative">
                      <input
                        type={
                          field.type === "password" && !showPasswords[field.key]
                            ? "password"
                            : "text"
                        }
                        value={credentials[field.key] || ""}
                        onChange={(e) => handleCredentialChange(field.key, e.target.value)}
                        className={`w-full px-4 py-3 rounded-lg border pr-12 ${
                          isDarkMode
                            ? "bg-gray-800 border-gray-600 text-white placeholder-gray-400"
                            : "bg-white border-gray-300 text-gray-900 placeholder-gray-500"
                        }`}
                        placeholder={`Enter ${field.label}`}
                      />
                      {field.type === "password" && (
                        <button
                          type="button"
                          onClick={() => togglePassword(field.key)}
                          className={`absolute right-3 top-1/2 -translate-y-1/2 ${
                            isDarkMode ? "text-gray-400" : "text-gray-500"
                          }`}
                        >
                          {showPasswords[field.key] ? (
                            <EyeOff className="w-5 h-5" />
                          ) : (
                            <Eye className="w-5 h-5" />
                          )}
                        </button>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>

            {/* Validate button */}
            <button
              onClick={validateCredentials}
              disabled={isValidating || !isStepComplete()}
              className={`flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-colors ${
                isValidating || !isStepComplete()
                  ? "bg-gray-500 text-gray-300 cursor-not-allowed"
                  : "bg-blue-600 text-white hover:bg-blue-700"
              }`}
            >
              {isValidating ? (
                <>
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  Validating...
                </>
              ) : (
                <>
                  <Key className="w-5 h-5" />
                  Validate Credentials
                </>
              )}
            </button>

            {/* Validation result */}
            {validationResult && (
              <div className={`p-4 rounded-lg flex items-center gap-3 ${
                validationResult.success
                  ? isDarkMode ? "bg-green-500/10" : "bg-green-50"
                  : isDarkMode ? "bg-red-500/10" : "bg-red-50"
              }`}>
                {validationResult.success ? (
                  <CheckCircle className="w-5 h-5 text-green-500" />
                ) : (
                  <AlertTriangle className="w-5 h-5 text-red-500" />
                )}
                <p className={validationResult.success 
                  ? isDarkMode ? "text-green-300" : "text-green-700"
                  : isDarkMode ? "text-red-300" : "text-red-700"
                }>
                  {validationResult.message}
                </p>
              </div>
            )}
          </div>
        )}

        {/* Step 3: Configure Scan */}
        {step === 3 && (
          <div className="space-y-6">
            <h2 className={`text-xl font-semibold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
              Configure Scan Options
            </h2>

            {/* Cloud Services to Scan */}
            {selectedProvider && PROVIDERS[selectedProvider].services.length > 0 && (
              <div>
                <div className="flex items-center justify-between mb-3">
                  <h3 className={`text-lg font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {PROVIDERS[selectedProvider].name} Services to Scan
                  </h3>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setSelectedServices(PROVIDERS[selectedProvider].services.map(s => s.id))}
                      className={`text-sm px-3 py-1 rounded ${
                        isDarkMode 
                          ? "bg-gray-700 text-gray-300 hover:bg-gray-600" 
                          : "bg-gray-200 text-gray-700 hover:bg-gray-300"
                      }`}
                    >
                      Select All
                    </button>
                    <button
                      onClick={() => setSelectedServices([])}
                      className={`text-sm px-3 py-1 rounded ${
                        isDarkMode 
                          ? "bg-gray-700 text-gray-300 hover:bg-gray-600" 
                          : "bg-gray-200 text-gray-700 hover:bg-gray-300"
                      }`}
                    >
                      Deselect All
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  {PROVIDERS[selectedProvider].services.map((service) => {
                    const isSelected = selectedServices.includes(service.id);
                    return (
                      <button
                        key={service.id}
                        onClick={() => {
                          setSelectedServices(prev => 
                            isSelected 
                              ? prev.filter(s => s !== service.id)
                              : [...prev, service.id]
                          );
                        }}
                        className={`p-3 rounded-lg border text-left transition-all ${
                          isSelected
                            ? "border-blue-500 bg-blue-500/10"
                            : isDarkMode
                            ? "border-gray-700 hover:border-gray-600"
                            : "border-gray-200 hover:border-gray-300"
                        }`}
                      >
                        <div className="flex items-center gap-2">
                          <div className={`w-4 h-4 rounded border flex items-center justify-center ${
                            isSelected 
                              ? "bg-blue-500 border-blue-500" 
                              : isDarkMode ? "border-gray-500" : "border-gray-400"
                          }`}>
                            {isSelected && <CheckCircle className="w-3 h-3 text-white" />}
                          </div>
                          <div>
                            <p className={`font-medium text-sm ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                              {service.label}
                            </p>
                            <p className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                              {service.id.toUpperCase()}
                            </p>
                          </div>
                        </div>
                      </button>
                    );
                  })}
                </div>
                <p className={`mt-2 text-sm ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                  {selectedServices.length} of {PROVIDERS[selectedProvider].services.length} services selected
                </p>
              </div>
            )}

            {/* Scan Modules */}
            <div>
              <h3 className={`text-lg font-medium mb-3 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Scan Modules
              </h3>
              <div className="grid grid-cols-2 gap-4">
                {SCAN_MODULES.map((module) => {
                  const Icon = module.icon;
                  const isSelected = selectedModules.includes(module.id);
                  return (
                    <button
                      key={module.id}
                      onClick={() => toggleModule(module.id)}
                      className={`p-4 rounded-lg border-2 text-left transition-all ${
                        isSelected
                          ? "border-blue-500 bg-blue-500/10"
                          : isDarkMode
                          ? "border-gray-700 hover:border-gray-600"
                          : "border-gray-200 hover:border-gray-300"
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        <Icon className={`w-6 h-6 ${isSelected ? "text-blue-500" : isDarkMode ? "text-gray-400" : "text-gray-500"}`} />
                        <div>
                          <p className={`font-medium ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                            {module.name}
                          </p>
                          <p className={`text-sm ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>
                            {module.description}
                          </p>
                        </div>
                      </div>
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Compliance Frameworks */}
            <div>
              <h3 className={`text-lg font-medium mb-3 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                Compliance Frameworks
              </h3>
              <div className="flex flex-wrap gap-3">
                {COMPLIANCE_FRAMEWORKS.map((framework) => {
                  const isSelected = selectedFrameworks.includes(framework.id);
                  return (
                    <button
                      key={framework.id}
                      onClick={() => toggleFramework(framework.id)}
                      className={`px-4 py-2 rounded-lg border transition-all ${
                        isSelected
                          ? "border-blue-500 bg-blue-500/10 text-blue-500"
                          : isDarkMode
                          ? "border-gray-600 text-gray-300 hover:border-gray-500"
                          : "border-gray-300 text-gray-700 hover:border-gray-400"
                      }`}
                    >
                      {framework.name}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Optional: IaC Path */}
            {selectedModules.includes("iac") && (
              <div>
                <label className={`block text-sm font-medium mb-2 ${
                  isDarkMode ? "text-gray-300" : "text-gray-700"
                }`}>
                  IaC Files Path (Optional)
                </label>
                <input
                  type="text"
                  value={iacPath}
                  onChange={(e) => setIacPath(e.target.value)}
                  placeholder="e.g., ./terraform or s3://bucket/iac"
                  className={`w-full px-4 py-3 rounded-lg border ${
                    isDarkMode
                      ? "bg-gray-800 border-gray-600 text-white placeholder-gray-400"
                      : "bg-white border-gray-300 text-gray-900 placeholder-gray-500"
                  }`}
                />
              </div>
            )}

            {/* Optional: Container Image */}
            {selectedModules.includes("container") && (
              <div>
                <label className={`block text-sm font-medium mb-2 ${
                  isDarkMode ? "text-gray-300" : "text-gray-700"
                }`}>
                  Container Image (Optional)
                </label>
                <input
                  type="text"
                  value={containerImage}
                  onChange={(e) => setContainerImage(e.target.value)}
                  placeholder="e.g., myregistry.com/app:latest"
                  className={`w-full px-4 py-3 rounded-lg border ${
                    isDarkMode
                      ? "bg-gray-800 border-gray-600 text-white placeholder-gray-400"
                      : "bg-white border-gray-300 text-gray-900 placeholder-gray-500"
                  }`}
                />
              </div>
            )}

            {/* Error display */}
            {error && (
              <div className={`p-4 rounded-lg flex items-center gap-3 ${
                isDarkMode ? "bg-red-500/10" : "bg-red-50"
              }`}>
                <AlertTriangle className="w-5 h-5 text-red-500" />
                <p className={isDarkMode ? "text-red-300" : "text-red-700"}>{error}</p>
              </div>
            )}
          </div>
        )}

        {/* Navigation buttons */}
        <div className={`mt-8 pt-6 border-t flex justify-between ${
          isDarkMode ? "border-gray-700" : "border-gray-200"
        }`}>
          {step > 1 ? (
            <button
              onClick={() => setStep(step - 1)}
              className={`px-6 py-3 rounded-lg font-medium ${
                isDarkMode
                  ? "bg-gray-700 text-white hover:bg-gray-600"
                  : "bg-gray-200 text-gray-700 hover:bg-gray-300"
              }`}
            >
              Back
            </button>
          ) : (
            <div />
          )}

          {step < 3 ? (
            <button
              onClick={() => setStep(step + 1)}
              disabled={!isStepComplete() || (step === 2 && !validationResult?.success)}
              className={`flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-colors ${
                isStepComplete() && (step !== 2 || validationResult?.success)
                  ? "bg-blue-600 text-white hover:bg-blue-700"
                  : "bg-gray-500 text-gray-300 cursor-not-allowed"
              }`}
            >
              Next
              <ChevronRight className="w-5 h-5" />
            </button>
          ) : (
            <button
              onClick={startScan}
              disabled={isStarting || !isStepComplete()}
              className={`flex items-center gap-2 px-6 py-3 rounded-lg font-medium transition-colors ${
                !isStarting && isStepComplete()
                  ? "bg-green-600 text-white hover:bg-green-700"
                  : "bg-gray-500 text-gray-300 cursor-not-allowed"
              }`}
            >
              {isStarting ? (
                <>
                  <RefreshCw className="w-5 h-5 animate-spin" />
                  Starting Scan...
                </>
              ) : (
                <>
                  <Play className="w-5 h-5" />
                  Start Cloud Scan
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default CloudScanStart;
