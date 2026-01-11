// CloudScanForm - Dedicated cloud scan configuration form
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Rocket } from "lucide-react";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { cloudScanAPI } from "../../services/api";
import { getInputClass, getLabelClass, getCancelButtonClass } from "./scanFormStyles";

const CloudScanForm = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();
  const { refreshSubscription } = useSubscription();

  const [cloudForm, setCloudForm] = useState({
    provider: "aws",
    accessKeyId: "",
    secretAccessKey: "",
    region: "us-east-1",
    subscriptionId: "",
    tenantId: "",
    clientId: "",
    clientSecret: "",
    projectId: "",
    serviceAccountKey: null,
    notes: "",
  });

  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState(null);

  const inputClass = getInputClass(isDarkMode);
  const labelClass = getLabelClass(isDarkMode);
  const cancelButtonClass = getCancelButtonClass(isDarkMode);

  const handleInputChange = (e) => {
    const { name, value, files } = e.target;
    if (name === "serviceAccountKey") {
      setCloudForm((prev) => ({ ...prev, [name]: files[0] }));
    } else {
      setCloudForm((prev) => ({ ...prev, [name]: value }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSubmitting(true);
    setError(null);

    try {
      let credentials = {};

      switch (cloudForm.provider) {
        case "aws":
          credentials = {
            access_key_id: cloudForm.accessKeyId,
            secret_access_key: cloudForm.secretAccessKey,
            region: cloudForm.region,
          };
          break;
        case "azure":
          credentials = {
            subscription_id: cloudForm.subscriptionId,
            tenant_id: cloudForm.tenantId,
            client_id: cloudForm.clientId,
            client_secret: cloudForm.clientSecret,
          };
          break;
        case "gcp":
          credentials = {
            project_id: cloudForm.projectId,
            service_account_key: cloudForm.serviceAccountKey,
          };
          break;
      }

      const response = await cloudScanAPI.startScan(cloudForm.provider, credentials);

      if (response.scan_id) {
        refreshSubscription();
        navigate("/dashboard/scanning", {
          state: { scanId: response.scan_id, scanType: "cloud" },
        });
      } else {
        throw new Error(response.error || "Failed to start cloud scan");
      }
    } catch (err) {
      console.error("Start cloud scan error:", err);
      setError(err.message);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="max-w-4xl space-y-6">
      {error && (
        <div className="p-4 mb-4 bg-red-500/20 border border-red-500/50 rounded-xl text-red-400">
          {error}
        </div>
      )}

      <div className="space-y-2">
        <label className={labelClass}>Cloud Provider *</label>
        <div className="grid grid-cols-1 xs:grid-cols-3 gap-3 sm:gap-4">
          {[
            { id: "aws", label: "AWS", icon: "☁️" },
            { id: "azure", label: "Azure", icon: "☁️" },
            { id: "gcp", label: "GCP", icon: "☁️" },
          ].map((provider) => (
            <button
              key={provider.id}
              type="button"
              onClick={() => setCloudForm((prev) => ({ ...prev, provider: provider.id }))}
              className={`p-3 sm:p-4 rounded-xl font-medium transition-all min-h-[60px] sm:min-h-[80px] active:scale-95 ${
                cloudForm.provider === provider.id
                  ? "bg-amber-600 text-white border-2 border-amber-400"
                  : isDarkMode
                  ? "bg-slate-700/50 border border-slate-600/50 text-gray-300 hover:border-amber-500/50"
                  : "bg-gray-50 border border-gray-200 text-gray-700 hover:border-amber-300"
              }`}
            >
              <span className="text-xl sm:text-2xl">{provider.icon}</span>
              <div className="mt-1 sm:mt-2 text-sm sm:text-base">{provider.label}</div>
            </button>
          ))}
        </div>
      </div>

      {/* AWS Credentials */}
      {cloudForm.provider === "aws" && (
        <div className="space-y-4">
          <input
            name="accessKeyId"
            type="text"
            placeholder="AWS Access Key ID"
            value={cloudForm.accessKeyId}
            onChange={handleInputChange}
            required
            className={inputClass}
          />
          <input
            name="secretAccessKey"
            type="password"
            placeholder="AWS Secret Access Key"
            value={cloudForm.secretAccessKey}
            onChange={handleInputChange}
            required
            className={inputClass}
          />
          <input
            name="region"
            type="text"
            placeholder="Region (e.g., us-east-1)"
            value={cloudForm.region}
            onChange={handleInputChange}
            className={inputClass}
          />
        </div>
      )}

      {/* Azure Credentials */}
      {cloudForm.provider === "azure" && (
        <div className="space-y-4">
          <input
            name="subscriptionId"
            type="text"
            placeholder="Subscription ID"
            value={cloudForm.subscriptionId}
            onChange={handleInputChange}
            required
            className={inputClass}
          />
          <input
            name="tenantId"
            type="text"
            placeholder="Tenant ID"
            value={cloudForm.tenantId}
            onChange={handleInputChange}
            required
            className={inputClass}
          />
          <input
            name="clientId"
            type="text"
            placeholder="Client ID"
            value={cloudForm.clientId}
            onChange={handleInputChange}
            required
            className={inputClass}
          />
          <input
            name="clientSecret"
            type="password"
            placeholder="Client Secret"
            value={cloudForm.clientSecret}
            onChange={handleInputChange}
            required
            className={inputClass}
          />
        </div>
      )}

      {/* GCP Credentials */}
      {cloudForm.provider === "gcp" && (
        <div className="space-y-4">
          <input
            name="projectId"
            type="text"
            placeholder="GCP Project ID"
            value={cloudForm.projectId}
            onChange={handleInputChange}
            required
            className={inputClass}
          />
          <div className="space-y-2">
            <label className={labelClass}>Service Account Key (JSON)</label>
            <input
              type="file"
              name="serviceAccountKey"
              accept=".json"
              onChange={handleInputChange}
              required
              className={inputClass}
            />
          </div>
        </div>
      )}

      <div className="flex gap-4 pt-4">
        <button
          type="submit"
          disabled={isSubmitting}
          className="flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-amber-600 to-amber-500 text-white rounded-xl hover:from-amber-500 hover:to-amber-400 disabled:opacity-50 transition-all duration-300 font-semibold"
        >
          {isSubmitting ? "Starting..." : <><Rocket className="w-4 h-4" /> Start Cloud Scan</>}
        </button>
        <button
          type="button"
          onClick={() => navigate("/dashboard")}
          className={cancelButtonClass}
        >
          Cancel
        </button>
      </div>
    </form>
  );
};

export default CloudScanForm;
