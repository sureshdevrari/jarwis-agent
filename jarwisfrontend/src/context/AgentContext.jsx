// src/context/AgentContext.jsx
// Global context for agent status management across the application

import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { universalAgentAPI, mobileAgentAPI } from '../services/api';
import { useAuth } from './AuthContext';

const AgentContext = createContext();

export const useAgent = () => {
  const context = useContext(AgentContext);
  if (!context) {
    throw new Error('useAgent must be used within an AgentProvider');
  }
  return context;
};

// Agent status polling interval (30 seconds)
const POLL_INTERVAL = 30000;

// Exponential backoff settings for reconnection
const BACKOFF_BASE = 1000; // 1 second
const BACKOFF_MAX = 60000; // 60 seconds
const BACKOFF_MULTIPLIER = 2;

export const AgentProvider = ({ children }) => {
  const { user } = useAuth();
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [isConnected, setIsConnected] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  
  const pollIntervalRef = useRef(null);
  const backoffRef = useRef(BACKOFF_BASE);
  const reconnectTimeoutRef = useRef(null);

  // Fetch all connected agents
  const fetchAgents = useCallback(async (showLoading = false) => {
    if (!user) {
      setAgents([]);
      setIsConnected(false);
      setLoading(false);
      return;
    }

    if (showLoading) {
      setLoading(true);
    }

    try {
      const response = await universalAgentAPI.getStatus();
      
      if (response?.data) {
        const agentList = response.data.agents || [];
        setAgents(agentList);
        setIsConnected(agentList.length > 0 && agentList.some(a => a.status === 'connected'));
        setLastUpdated(new Date());
        setError(null);
        
        // Reset backoff on successful fetch
        backoffRef.current = BACKOFF_BASE;
        setReconnecting(false);
      }
    } catch (err) {
      console.error('Failed to fetch agent status:', err);
      setError(err.message || 'Failed to fetch agent status');
      setIsConnected(false);
      
      // Start exponential backoff for reconnection
      if (!reconnecting) {
        startReconnection();
      }
    } finally {
      setLoading(false);
    }
  }, [user]);

  // Start exponential backoff reconnection
  const startReconnection = useCallback(() => {
    setReconnecting(true);
    
    const attemptReconnect = async () => {
      try {
        await fetchAgents(false);
        if (!error) {
          // Success - stop reconnection
          setReconnecting(false);
          backoffRef.current = BACKOFF_BASE;
          return;
        }
      } catch (err) {
        // Failed - schedule next attempt with backoff
        console.log(`Reconnection failed, retrying in ${backoffRef.current}ms`);
      }
      
      // Schedule next attempt with exponential backoff
      reconnectTimeoutRef.current = setTimeout(() => {
        backoffRef.current = Math.min(backoffRef.current * BACKOFF_MULTIPLIER, BACKOFF_MAX);
        attemptReconnect();
      }, backoffRef.current);
    };
    
    attemptReconnect();
  }, [fetchAgents, error]);

  // Get agent for specific scan type
  const getAgentForScanType = useCallback((scanType) => {
    if (!agents.length) return null;
    
    // Map scan types to agent capabilities
    const capabilityMap = {
      'web': ['web_security', 'web'],
      'network': ['network', 'network_security'],
      'mobile_static': ['mobile', 'mobile_static'],
      'mobile_dynamic': ['mobile', 'mobile_dynamic'],
      'cloud_aws': ['cloud', 'aws'],
      'cloud_azure': ['cloud', 'azure'],
      'cloud_gcp': ['cloud', 'gcp'],
      'cloud_k8s': ['cloud', 'kubernetes'],
      'sast': ['sast', 'code_analysis'],
    };
    
    const requiredCapabilities = capabilityMap[scanType] || [scanType];
    
    // Find an agent that supports this scan type
    const compatibleAgent = agents.find(agent => 
      agent.status === 'connected' && 
      agent.capabilities?.some(cap => requiredCapabilities.includes(cap))
    );
    
    // Fallback to any connected agent if specific capability not found
    return compatibleAgent || agents.find(a => a.status === 'connected') || null;
  }, [agents]);

  // Check if user has any connected agent
  const hasConnectedAgent = useCallback(() => {
    return agents.some(agent => agent.status === 'connected');
  }, [agents]);

  // Check if agent supports specific scan type
  const canPerformScan = useCallback((scanType) => {
    return !!getAgentForScanType(scanType);
  }, [getAgentForScanType]);

  // Refresh agent status manually
  const refreshStatus = useCallback(async () => {
    await fetchAgents(true);
  }, [fetchAgents]);

  // Register a new agent (after download/install)
  const registerAgent = useCallback(async (registrationData) => {
    try {
      const response = await universalAgentAPI.register(registrationData);
      await fetchAgents(false); // Refresh list
      return response?.data;
    } catch (err) {
      console.error('Failed to register agent:', err);
      throw err;
    }
  }, [fetchAgents]);

  // Disconnect an agent
  const disconnectAgent = useCallback(async (agentId) => {
    try {
      await universalAgentAPI.disconnect(agentId);
      await fetchAgents(false); // Refresh list
    } catch (err) {
      console.error('Failed to disconnect agent:', err);
      throw err;
    }
  }, [fetchAgents]);

  // Setup polling when user is authenticated
  useEffect(() => {
    if (user) {
      // Initial fetch
      fetchAgents(true);
      
      // Setup polling
      pollIntervalRef.current = setInterval(() => {
        fetchAgents(false);
      }, POLL_INTERVAL);
    } else {
      // Clear state when logged out
      setAgents([]);
      setIsConnected(false);
      setLoading(false);
    }

    return () => {
      if (pollIntervalRef.current) {
        clearInterval(pollIntervalRef.current);
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [user, fetchAgents]);

  // Value to provide to consumers
  const value = {
    // State
    agents,
    loading,
    error,
    lastUpdated,
    isConnected,
    reconnecting,
    
    // Methods
    fetchAgents,
    refreshStatus,
    getAgentForScanType,
    hasConnectedAgent,
    canPerformScan,
    registerAgent,
    disconnectAgent,
    
    // Computed
    connectedCount: agents.filter(a => a.status === 'connected').length,
    totalCount: agents.length,
  };

  return (
    <AgentContext.Provider value={value}>
      {children}
    </AgentContext.Provider>
  );
};

export default AgentContext;
