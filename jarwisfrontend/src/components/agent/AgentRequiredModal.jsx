// src/components/agent/AgentRequiredModal.jsx
// Modal shown when user tries to start a scan without a connected agent

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X,
  Shield,
  Download,
  Monitor,
  Apple,
  Terminal,
  AlertTriangle,
  ArrowRight,
  CheckCircle,
  Smartphone,
  Globe,
  Network,
  Cloud,
  Code,
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';

// Scan type display info
const SCAN_TYPE_INFO = {
  web: {
    name: 'Web Security Scan',
    icon: Globe,
    color: 'blue',
    description: 'OWASP Top 10, XSS, SQL Injection, and more',
  },
  mobile_static: {
    name: 'Mobile Static Analysis',
    icon: Smartphone,
    color: 'purple',
    description: 'APK/IPA analysis, hardcoded secrets, insecure storage',
  },
  mobile_dynamic: {
    name: 'Mobile Dynamic Analysis',
    icon: Smartphone,
    color: 'purple',
    description: 'Runtime analysis with Frida, SSL bypass, API interception',
  },
  network: {
    name: 'Network Security Scan',
    icon: Network,
    color: 'green',
    description: 'Port scanning, service detection, vulnerability assessment',
  },
  cloud_aws: {
    name: 'AWS Cloud Security',
    icon: Cloud,
    color: 'orange',
    description: 'IAM, S3, EC2, Lambda security misconfigurations',
  },
  cloud_azure: {
    name: 'Azure Cloud Security',
    icon: Cloud,
    color: 'cyan',
    description: 'Azure AD, Storage, VMs security assessment',
  },
  cloud_gcp: {
    name: 'GCP Cloud Security',
    icon: Cloud,
    color: 'red',
    description: 'GCP IAM, Cloud Storage, Compute Engine security',
  },
  cloud_kubernetes: {
    name: 'Kubernetes Security',
    icon: Cloud,
    color: 'indigo',
    description: 'K8s cluster security, RBAC, network policies',
  },
  sast: {
    name: 'Source Code Analysis',
    icon: Code,
    color: 'amber',
    description: 'Hardcoded secrets, vulnerable dependencies, code flaws',
  },
};

const AgentRequiredModal = ({ 
  isOpen, 
  onClose, 
  scanType = 'web',
  title = 'Jarwis Agent Required',
  message = null,
}) => {
  const navigate = useNavigate();
  const { isDarkMode } = useTheme();

  if (!isOpen) return null;

  const scanInfo = SCAN_TYPE_INFO[scanType] || SCAN_TYPE_INFO.web;
  const ScanIcon = scanInfo.icon;

  const handleSetupAgent = () => {
    onClose();
    navigate('/dashboard/agent-setup');
  };

  // Styles
  const overlayBg = 'bg-black/60 backdrop-blur-sm';
  const modalBg = isDarkMode ? 'bg-gray-800' : 'bg-white';
  const textPrimary = isDarkMode ? 'text-white' : 'text-gray-900';
  const textSecondary = isDarkMode ? 'text-gray-400' : 'text-gray-600';
  const borderColor = isDarkMode ? 'border-gray-700' : 'border-gray-200';

  return (
    <AnimatePresence>
      {isOpen && (
        <div className={`fixed inset-0 z-50 flex items-center justify-center p-4 ${overlayBg}`}>
          <motion.div
            initial={{ opacity: 0, scale: 0.95, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 20 }}
            transition={{ duration: 0.2 }}
            className={`${modalBg} rounded-2xl shadow-2xl max-w-lg w-full overflow-hidden`}
          >
            {/* Header with gradient */}
            <div className="bg-gradient-to-r from-purple-600 to-indigo-600 p-6 relative">
              <button
                onClick={onClose}
                className="absolute top-4 right-4 p-2 rounded-lg bg-white/10 hover:bg-white/20 transition-colors"
              >
                <X className="w-5 h-5 text-white" />
              </button>
              
              <div className="flex items-center gap-4">
                <div className="w-14 h-14 rounded-xl bg-white/20 flex items-center justify-center">
                  <Shield className="w-8 h-8 text-white" />
                </div>
                <div>
                  <h2 className="text-xl font-bold text-white">{title}</h2>
                  <p className="text-purple-200 text-sm mt-1">
                    Secure scanning requires a local agent
                  </p>
                </div>
              </div>
            </div>

            {/* Content */}
            <div className="p-6">
              {/* Scan type info */}
              <div className={`flex items-center gap-3 p-4 rounded-xl ${isDarkMode ? 'bg-gray-700/50' : 'bg-gray-50'} mb-6`}>
                <div className={`p-2 rounded-lg bg-${scanInfo.color}-500/10`}>
                  <ScanIcon className={`w-5 h-5 text-${scanInfo.color}-500`} />
                </div>
                <div>
                  <p className={`font-medium ${textPrimary}`}>{scanInfo.name}</p>
                  <p className={`text-sm ${textSecondary}`}>{scanInfo.description}</p>
                </div>
              </div>

              {/* Message */}
              <div className={`flex items-start gap-3 p-4 rounded-xl border ${borderColor} mb-6`}>
                <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                <div>
                  <p className={`font-medium ${textPrimary} mb-1`}>Agent Not Connected</p>
                  <p className={`text-sm ${textSecondary}`}>
                    {message || `To start a ${scanInfo.name.toLowerCase()}, you need to install and connect the Jarwis Agent on your system. The agent runs locally and executes security tests securely.`}
                  </p>
                </div>
              </div>

              {/* Benefits */}
              <div className="space-y-3 mb-6">
                <p className={`text-sm font-medium ${textPrimary}`}>Why do you need an agent?</p>
                <div className="grid grid-cols-1 gap-2">
                  {[
                    'Execute security tests from your local network',
                    'Keep credentials secure - never sent to cloud',
                    'Access internal systems and private networks',
                    'Full control over what gets tested',
                  ].map((benefit, idx) => (
                    <div key={idx} className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-green-500 flex-shrink-0" />
                      <span className={`text-sm ${textSecondary}`}>{benefit}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Platform icons */}
              <div className={`flex items-center justify-center gap-4 py-4 border-t ${borderColor}`}>
                <span className={`text-sm ${textSecondary}`}>Available for:</span>
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${isDarkMode ? 'bg-gray-700' : 'bg-gray-100'}`} title="Windows">
                    <Monitor className={`w-4 h-4 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                  </div>
                  <div className={`p-2 rounded-lg ${isDarkMode ? 'bg-gray-700' : 'bg-gray-100'}`} title="macOS">
                    <Apple className={`w-4 h-4 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                  </div>
                  <div className={`p-2 rounded-lg ${isDarkMode ? 'bg-gray-700' : 'bg-gray-100'}`} title="Linux">
                    <Terminal className={`w-4 h-4 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`} />
                  </div>
                </div>
              </div>
            </div>

            {/* Actions */}
            <div className={`px-6 pb-6 flex gap-3`}>
              <button
                onClick={onClose}
                className={`flex-1 px-4 py-3 rounded-xl font-medium transition-colors ${
                  isDarkMode 
                    ? 'bg-gray-700 hover:bg-gray-600 text-gray-300' 
                    : 'bg-gray-100 hover:bg-gray-200 text-gray-700'
                }`}
              >
                Cancel
              </button>
              <button
                onClick={handleSetupAgent}
                className="flex-1 px-4 py-3 rounded-xl font-medium bg-gradient-to-r from-purple-600 to-indigo-600 text-white hover:from-purple-500 hover:to-indigo-500 transition-all flex items-center justify-center gap-2"
              >
                <Download className="w-4 h-4" />
                Setup Agent
                <ArrowRight className="w-4 h-4" />
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};

export default AgentRequiredModal;
