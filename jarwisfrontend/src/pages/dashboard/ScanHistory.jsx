// src/pages/dashboard/ScanHistory.jsx - Scan History Page
import { useNavigate } from "react-router-dom";
import DashboardPageLayout from "../../components/dashboardTheme/DashboardPageLayout";
import { useTheme } from "../../context/ThemeContext";
import ScanHistoryComponent from "../../components/scan/ScanHistory";

const ScanHistory = () => {
  const { isDarkMode } = useTheme();
  const navigate = useNavigate();

  // Handler for viewing a scan (navigates to scanning page for running, or vulnerabilities for completed)
  const handleViewScan = (scan) => {
    const scanId = scan.scan_id || scan.id;
    const scanType = scan.type || scan.scan_type || "web";
    
    if (scan.status === "running") {
      // Navigate to live scanning page
      navigate(`/dashboard/scanning?scan_id=${scanId}&type=${scanType}`, {
        state: { scanId, scanType, target_url: scan.target_url || scan.target }
      });
    } else if (scan.status === "completed") {
      // Navigate to vulnerabilities/results page
      navigate(`/dashboard/vulnerabilities`, {
        state: { scanId, scanType }
      });
    }
  };

  // Handler for starting a new scan
  const handleNewScan = () => {
    navigate("/dashboard/new-scan");
  };

  return (
    <DashboardPageLayout>
      <div className="space-y-6 p-6">
        {/* Header */}
        <div>
          <h1
            className={
              isDarkMode
                ? "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400 mb-2"
                : "text-3xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-cyan-600 mb-2"
            }
          >
            Scan History
          </h1>
          <p
            className={
              isDarkMode ? "text-gray-400" : "text-gray-600"
            }
          >
            View and manage all your security scans in one place.
          </p>
        </div>

        {/* Scan History Component */}
        <ScanHistoryComponent 
          onViewScan={handleViewScan}
          onNewScan={handleNewScan}
        />
      </div>
    </DashboardPageLayout>
  );
};

export default ScanHistory;
