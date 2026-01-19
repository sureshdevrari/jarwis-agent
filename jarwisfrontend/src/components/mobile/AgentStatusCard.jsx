// src/components/mobile/AgentStatusCard.jsx
// Shows connected mobile agent status with controls

import React, { useState } from 'react';
import {
  Smartphone,
  Wifi,
  WifiOff,
  Monitor,
  Cpu,
  HardDrive,
  Clock,
  XCircle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  Activity,
  Shield,
} from 'lucide-react';
import { useTheme } from '../../context/ThemeContext';
import { mobileAgentAPI } from '../../services/api';

const AgentStatusCard = ({ 
  agent, 
  onDisconnect, 
  onRefresh,
  isSelected = false,
  onSelect,
  showDetails = false,
}) => {
  const { isDarkMode } = useTheme();
  const [expanded, setExpanded] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);

  const handleDisconnect = async () => {
    if (!agent?.agent_id) return;
    
    setDisconnecting(true);
    try {
      await mobileAgentAPI.disconnectAgent(agent.agent_id);
      if (onDisconnect) {
        onDisconnect(agent.agent_id);
      }
    } catch (err) {
      console.error('Failed to disconnect agent:', err);
    } finally {
      setDisconnecting(false);
    }
  };

  const formatUptime = (connectedAt) => {
    if (!connectedAt) return 'Unknown';
    const start = new Date(connectedAt);
    const now = new Date();
    const diff = Math.floor((now - start) / 1000);
    
    if (diff < 60) return `${diff}s`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m`;
    return `${Math.floor(diff / 86400)}d ${Math.floor((diff % 86400) / 3600)}h`;
  };

  const getStatusColor = (status) => {
    switch (status) {
      case 'connected':
      case 'ready':
        return isDarkMode ? 'text-green-400' : 'text-green-600';
      case 'scanning':
      case 'busy':
        return isDarkMode ? 'text-yellow-400' : 'text-yellow-600';
      case 'disconnected':
      case 'error':
        return isDarkMode ? 'text-red-400' : 'text-red-600';
      default:
        return isDarkMode ? 'text-gray-400' : 'text-gray-600';
    }
  };

  const getStatusBg = (status) => {
    switch (status) {
      case 'connected':
      case 'ready':
        return isDarkMode ? 'bg-green-500/20' : 'bg-green-50';
      case 'scanning':
      case 'busy':
        return isDarkMode ? 'bg-yellow-500/20' : 'bg-yellow-50';
      case 'disconnected':
      case 'error':
        return isDarkMode ? 'bg-red-500/20' : 'bg-red-50';
      default:
        return isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50';
    }
  };

  const status = agent?.status || 'unknown';
  const isOnline = ['connected', 'ready', 'scanning', 'busy'].includes(status);

  return (
    <div
      className={`rounded-xl border transition-all ${
        isSelected
          ? isDarkMode
            ? 'border-purple-500 bg-purple-500/10'
            : 'border-purple-500 bg-purple-50'
          : isDarkMode
            ? 'border-slate-700 bg-slate-800/50 hover:border-slate-600'
            : 'border-gray-200 bg-white hover:border-gray-300'
      } ${onSelect ? 'cursor-pointer' : ''}`}
      onClick={onSelect ? () => onSelect(agent) : undefined}
    >
      {/* Main Card Content */}
      <div className="p-4">
        <div className="flex items-start justify-between">
          {/* Agent Info */}
          <div className="flex items-center gap-3">
            <div className={`p-2 rounded-lg ${getStatusBg(status)}`}>
              {isOnline ? (
                <Wifi className={`w-5 h-5 ${getStatusColor(status)}`} />
              ) : (
                <WifiOff className={`w-5 h-5 ${getStatusColor(status)}`} />
              )}
            </div>
            <div>
              <h4 className={`font-medium ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                {agent?.device_name || agent?.agent_id?.slice(0, 8) || 'Unknown Agent'}
              </h4>
              <div className="flex items-center gap-2 mt-1">
                <span className={`text-xs px-2 py-0.5 rounded-full ${getStatusBg(status)} ${getStatusColor(status)}`}>
                  {status.charAt(0).toUpperCase() + status.slice(1)}
                </span>
                <span className={`text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                  {agent?.platform || 'unknown'}
                </span>
              </div>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2">
            {onRefresh && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onRefresh();
                }}
                className={`p-2 rounded-lg transition-colors ${
                  isDarkMode
                    ? 'hover:bg-slate-700 text-gray-400 hover:text-white'
                    : 'hover:bg-gray-100 text-gray-500 hover:text-gray-700'
                }`}
              >
                <RefreshCw className="w-4 h-4" />
              </button>
            )}
            {showDetails && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  setExpanded(!expanded);
                }}
                className={`p-2 rounded-lg transition-colors ${
                  isDarkMode
                    ? 'hover:bg-slate-700 text-gray-400 hover:text-white'
                    : 'hover:bg-gray-100 text-gray-500 hover:text-gray-700'
                }`}
              >
                {expanded ? (
                  <ChevronUp className="w-4 h-4" />
                ) : (
                  <ChevronDown className="w-4 h-4" />
                )}
              </button>
            )}
            {isOnline && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  handleDisconnect();
                }}
                disabled={disconnecting}
                className={`p-2 rounded-lg transition-colors ${
                  isDarkMode
                    ? 'hover:bg-red-500/20 text-red-400 hover:text-red-300'
                    : 'hover:bg-red-50 text-red-500 hover:text-red-600'
                } ${disconnecting ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                <XCircle className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        {/* Quick Stats Row */}
        {isOnline && (
          <div className={`flex items-center gap-4 mt-3 pt-3 border-t ${isDarkMode ? 'border-slate-700' : 'border-gray-100'}`}>
            {agent?.connected_at && (
              <div className="flex items-center gap-1.5">
                <Clock className={`w-4 h-4 ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  {formatUptime(agent.connected_at)}
                </span>
              </div>
            )}
            {agent?.emulator_running !== undefined && (
              <div className="flex items-center gap-1.5">
                <Smartphone className={`w-4 h-4 ${
                  agent.emulator_running
                    ? isDarkMode ? 'text-green-400' : 'text-green-600'
                    : isDarkMode ? 'text-gray-500' : 'text-gray-400'
                }`} />
                <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  {agent.emulator_running ? 'Emulator Ready' : 'No Emulator'}
                </span>
              </div>
            )}
            {agent?.frida_ready !== undefined && (
              <div className="flex items-center gap-1.5">
                <Shield className={`w-4 h-4 ${
                  agent.frida_ready
                    ? isDarkMode ? 'text-green-400' : 'text-green-600'
                    : isDarkMode ? 'text-gray-500' : 'text-gray-400'
                }`} />
                <span className={`text-xs ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  {agent.frida_ready ? 'Frida Ready' : 'No Frida'}
                </span>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Expanded Details */}
      {expanded && showDetails && (
        <div className={`px-4 pb-4 border-t ${isDarkMode ? 'border-slate-700' : 'border-gray-100'}`}>
          <div className="pt-4 grid grid-cols-2 gap-4">
            {/* System Info */}
            <div className={`p-3 rounded-lg ${isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50'}`}>
              <h5 className={`text-xs font-medium mb-2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                System
              </h5>
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <Monitor className={`w-4 h-4 ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                  <span className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                    {agent?.os || 'Unknown OS'}
                  </span>
                </div>
                {agent?.hostname && (
                  <div className="flex items-center gap-2">
                    <Cpu className={`w-4 h-4 ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`} />
                    <span className={`text-sm ${isDarkMode ? 'text-gray-300' : 'text-gray-700'}`}>
                      {agent.hostname}
                    </span>
                  </div>
                )}
              </div>
            </div>

            {/* Capabilities */}
            <div className={`p-3 rounded-lg ${isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50'}`}>
              <h5 className={`text-xs font-medium mb-2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                Capabilities
              </h5>
              <div className="flex flex-wrap gap-1">
                {(agent?.capabilities || ['traffic_capture', 'frida', 'mitm']).map((cap) => (
                  <span
                    key={cap}
                    className={`text-xs px-2 py-0.5 rounded ${
                      isDarkMode
                        ? 'bg-purple-500/20 text-purple-300'
                        : 'bg-purple-100 text-purple-700'
                    }`}
                  >
                    {cap.replace('_', ' ')}
                  </span>
                ))}
              </div>
            </div>

            {/* Stats */}
            {agent?.stats && (
              <div className={`col-span-2 p-3 rounded-lg ${isDarkMode ? 'bg-slate-700/50' : 'bg-gray-50'}`}>
                <h5 className={`text-xs font-medium mb-2 ${isDarkMode ? 'text-gray-400' : 'text-gray-500'}`}>
                  Session Stats
                </h5>
                <div className="grid grid-cols-3 gap-4">
                  <div>
                    <p className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                      {agent.stats.requests_captured || 0}
                    </p>
                    <p className={`text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                      Requests
                    </p>
                  </div>
                  <div>
                    <p className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                      {agent.stats.scans_completed || 0}
                    </p>
                    <p className={`text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                      Scans
                    </p>
                  </div>
                  <div>
                    <p className={`text-lg font-semibold ${isDarkMode ? 'text-white' : 'text-gray-900'}`}>
                      {agent.stats.vulnerabilities_found || 0}
                    </p>
                    <p className={`text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`}>
                      Findings
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Agent ID */}
          <div className={`mt-3 pt-3 border-t ${isDarkMode ? 'border-slate-700' : 'border-gray-200'}`}>
            <p className={`text-xs ${isDarkMode ? 'text-gray-500' : 'text-gray-400'}`}>
              Agent ID: <code className="font-mono">{agent?.agent_id || 'N/A'}</code>
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

export default AgentStatusCard;
