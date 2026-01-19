// MobileAgentSetupPage - Dedicated page for setting up mobile agents
import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Smartphone, ArrowLeft } from "lucide-react";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { AgentSetupWizard } from "../../components/mobile";

const MobileAgentSetupPage = () => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();

  const handleComplete = (agent) => {
    // Navigate back to mobile scan page with the agent selected
    navigate("/dashboard/scan/mobile", { 
      state: { selectedAgent: agent, scanMode: 'remote' } 
    });
  };

  const handleCancel = () => {
    navigate("/dashboard/scan/mobile");
  };

  return (
    <MiftyJarwisLayout>
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          <button
            onClick={() => navigate("/dashboard/scan/mobile")}
            className={`p-2 rounded-lg transition-colors ${
              isDarkMode
                ? "hover:bg-slate-700 text-gray-400 hover:text-white"
                : "hover:bg-gray-100 text-gray-500 hover:text-gray-700"
            }`}
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className={isDarkMode 
              ? "text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400"
              : "text-2xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-purple-600 to-pink-600"
            }>
              Setup Mobile Agent
            </h1>
            <p className={isDarkMode ? "text-gray-400" : "text-gray-600"}>
              Configure your machine for remote mobile security testing
            </p>
          </div>
        </div>

        {/* Setup Wizard */}
        <AgentSetupWizard 
          onComplete={handleComplete}
          onCancel={handleCancel}
        />

        {/* Info Section */}
        <div className={isDarkMode 
          ? "p-6 bg-gradient-to-r from-purple-500/10 to-pink-500/10 border border-purple-500/20 rounded-2xl"
          : "p-6 bg-gradient-to-r from-purple-50 to-pink-50 border border-purple-200 rounded-2xl"
        }>
          <h3 className={`font-semibold mb-3 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
            Why use a Remote Agent?
          </h3>
          <ul className={`space-y-2 text-sm ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
            <li className="flex items-start gap-2">
              <span className="text-green-500">✓</span>
              <span>Run dynamic testing on your own hardware with full emulator access</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-500">✓</span>
              <span>Better performance with local emulator and Frida instrumentation</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-500">✓</span>
              <span>Traffic interception works seamlessly without VPN tunneling</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-green-500">✓</span>
              <span>Test apps that require physical device features or specific configurations</span>
            </li>
          </ul>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default MobileAgentSetupPage;
