// src/pages/dashboard/ScanHistory.jsx - Scan History Page
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import ScanHistoryComponent from "../../components/scan/ScanHistory";

const ScanHistory = () => {
  const { isDarkMode } = useTheme();

  return (
    <MiftyJarwisLayout>
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
        <ScanHistoryComponent />
      </div>
    </MiftyJarwisLayout>
  );
};

export default ScanHistory;
