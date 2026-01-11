// src/hooks/useWebSocket.js
// Custom hook for WebSocket connections with auto-reconnect

import { useState, useEffect, useRef, useCallback } from 'react';
import { getAccessToken, getTokenExpiry, autoRefreshToken, getRefreshToken } from '../services/api';

// WebSocket message types (must match backend)
export const MessageType = {
  SCAN_PROGRESS: 'scan_progress',
  SCAN_STATUS: 'scan_status',
  SCAN_LOG: 'scan_log',
  SCAN_COMPLETE: 'scan_complete',
  SCAN_ERROR: 'scan_error',
  FINDING: 'finding',
  DASHBOARD_UPDATE: 'dashboard_update',
  NOTIFICATION: 'notification',
  PING: 'ping',
  PONG: 'pong',
};

// Connection states
export const ConnectionState = {
  CONNECTING: 'connecting',
  CONNECTED: 'connected',
  DISCONNECTED: 'disconnected',
  RECONNECTING: 'reconnecting',
  ERROR: 'error',
};

// Get WebSocket base URL
const getWSBaseURL = () => {
  const apiUrl = process.env.REACT_APP_API_URL || 'http://localhost:8000';
  // Convert http(s) to ws(s)
  return apiUrl.replace(/^http/, 'ws');
};

/**
 * Custom hook for WebSocket connections with auto-reconnect
 * 
 * @param {string} endpoint - WebSocket endpoint path (e.g., '/ws/scans/abc123')
 * @param {Object} options - Configuration options
 * @param {boolean} options.autoConnect - Auto-connect on mount (default: true)
 * @param {number} options.reconnectAttempts - Max reconnect attempts (default: 5)
 * @param {number} options.reconnectInterval - Reconnect delay in ms (default: 3000)
 * @param {boolean} options.includeToken - Include auth token (default: true)
 * @param {Function} options.onMessage - Callback for all messages
 * @param {Function} options.onConnect - Callback on connection
 * @param {Function} options.onDisconnect - Callback on disconnection
 * @param {Function} options.onError - Callback on error
 */
export function useWebSocket(endpoint, options = {}) {
  const {
    autoConnect = true,
    reconnectAttempts = 5,
    reconnectInterval = 3000,
    includeToken = true,
    onMessage,
    onConnect,
    onDisconnect,
    onError,
  } = options;

  const [connectionState, setConnectionState] = useState(ConnectionState.DISCONNECTED);
  const [lastMessage, setLastMessage] = useState(null);
  const [error, setError] = useState(null);
  
  const wsRef = useRef(null);
  const reconnectCountRef = useRef(0);
  const reconnectTimeoutRef = useRef(null);
  const pingIntervalRef = useRef(null);
  const isManualDisconnectRef = useRef(false);

  // Build WebSocket URL with token
  const getWSUrl = useCallback(() => {
    const baseUrl = getWSBaseURL();
    let url = `${baseUrl}${endpoint}`;
    
    if (includeToken) {
      const token = getAccessToken();
      if (token) {
        const separator = url.includes('?') ? '&' : '?';
        url = `${url}${separator}token=${token}`;
      }
    }
    
    return url;
  }, [endpoint, includeToken]);

  // Send a message through WebSocket
  const sendMessage = useCallback((data) => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify(data));
      return true;
    }
    console.warn('WebSocket not connected, cannot send message');
    return false;
  }, []);

  // Send ping to keep connection alive
  const sendPing = useCallback(() => {
    sendMessage({ action: 'ping' });
  }, [sendMessage]);

  // Subscribe to another scan
  const subscribeScan = useCallback((scanId) => {
    sendMessage({ action: 'subscribe', scan_id: scanId });
  }, [sendMessage]);

  // Unsubscribe from a scan
  const unsubscribeScan = useCallback((scanId) => {
    sendMessage({ action: 'unsubscribe', scan_id: scanId });
  }, [sendMessage]);

  // Helper to check if token needs refresh (expires within 2 minutes)
  const shouldRefreshToken = useCallback(() => {
    const expiry = getTokenExpiry();
    if (!expiry) return false;
    const bufferMs = 2 * 60 * 1000; // 2 minutes
    return Date.now() > (expiry - bufferMs);
  }, []);

  // Connect to WebSocket (with token refresh if needed)
  const connect = useCallback(async () => {
    if (wsRef.current?.readyState === WebSocket.OPEN) {
      console.log('WebSocket already connected');
      return;
    }

    isManualDisconnectRef.current = false;
    setConnectionState(ConnectionState.CONNECTING);
    setError(null);

    // Refresh token before connecting if it's about to expire
    if (includeToken && shouldRefreshToken() && getRefreshToken()) {
      try {
        console.log('[WebSocket] Refreshing token before connect...');
        await autoRefreshToken();
      } catch (err) {
        console.warn('[WebSocket] Token refresh failed, connecting with current token:', err);
      }
    }

    try {
      const url = getWSUrl();
      console.log('[WebSocket] Connecting to:', url.replace(/token=[^&]+/, 'token=***'));
      
      const ws = new WebSocket(url);
      wsRef.current = ws;

      ws.onopen = () => {
        console.log('[WebSocket] Connected');
        setConnectionState(ConnectionState.CONNECTED);
        reconnectCountRef.current = 0;
        
        // Start ping interval (every 30 seconds)
        pingIntervalRef.current = setInterval(sendPing, 30000);
        
        onConnect?.();
      };

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          setLastMessage(data);
          
          // Handle pong internally
          if (data.type === MessageType.PONG) {
            return;
          }
          
          onMessage?.(data);
        } catch (e) {
          console.warn('[WebSocket] Failed to parse message:', e);
        }
      };

      ws.onerror = (event) => {
        console.error('[WebSocket] Error:', event);
        setError('Connection error');
        setConnectionState(ConnectionState.ERROR);
        onError?.(event);
      };

      ws.onclose = (event) => {
        console.log('[WebSocket] Disconnected:', event.code, event.reason);
        setConnectionState(ConnectionState.DISCONNECTED);
        
        // Clear ping interval
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }
        
        onDisconnect?.();

        // Auto-reconnect if not manual disconnect and within limits
        if (!isManualDisconnectRef.current && reconnectCountRef.current < reconnectAttempts) {
          setConnectionState(ConnectionState.RECONNECTING);
          reconnectCountRef.current += 1;
          
          console.log(`[WebSocket] Reconnecting (${reconnectCountRef.current}/${reconnectAttempts})...`);
          
          reconnectTimeoutRef.current = setTimeout(() => {
            connect();
          }, reconnectInterval);
        }
      };
    } catch (e) {
      console.error('[WebSocket] Connection error:', e);
      setError(e.message);
      setConnectionState(ConnectionState.ERROR);
    }
  }, [getWSUrl, onConnect, onDisconnect, onError, onMessage, reconnectAttempts, reconnectInterval, sendPing]);

  // Disconnect from WebSocket
  const disconnect = useCallback(() => {
    isManualDisconnectRef.current = true;
    
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }
    
    if (pingIntervalRef.current) {
      clearInterval(pingIntervalRef.current);
      pingIntervalRef.current = null;
    }
    
    if (wsRef.current) {
      wsRef.current.close(1000, 'Manual disconnect');
      wsRef.current = null;
    }
    
    setConnectionState(ConnectionState.DISCONNECTED);
    reconnectCountRef.current = 0;
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    if (autoConnect && endpoint) {
      connect();
    }

    return () => {
      disconnect();
    };
  }, [autoConnect, endpoint, connect, disconnect]);

  return {
    connectionState,
    isConnected: connectionState === ConnectionState.CONNECTED,
    isConnecting: connectionState === ConnectionState.CONNECTING || connectionState === ConnectionState.RECONNECTING,
    lastMessage,
    error,
    connect,
    disconnect,
    sendMessage,
    subscribeScan,
    unsubscribeScan,
  };
}

/**
 * Specialized hook for scan updates
 * 
 * @param {string} scanId - Scan ID to subscribe to
 * @param {Object} callbacks - Event callbacks
 */
export function useScanWebSocket(scanId, callbacks = {}) {
  const {
    enabled = true,
    onProgress,
    onStatus,
    onLog,
    onComplete,
    onError,
    onFinding,
    onConnect,
    onDisconnect,
  } = callbacks;

  const handleMessage = useCallback((message) => {
    switch (message.type) {
      case MessageType.SCAN_PROGRESS:
        onProgress?.(message.data);
        break;
      case MessageType.SCAN_STATUS:
        onStatus?.(message.data);
        break;
      case MessageType.SCAN_LOG:
        onLog?.(message.data);
        break;
      case MessageType.SCAN_COMPLETE:
        onComplete?.(message.data);
        break;
      case MessageType.SCAN_ERROR:
        onError?.(message.data);
        break;
      case MessageType.FINDING:
        onFinding?.(message.data);
        break;
      default:
        console.log('[ScanWS] Unknown message type:', message.type);
    }
  }, [onProgress, onStatus, onLog, onComplete, onError, onFinding]);

  const ws = useWebSocket(
    (scanId && enabled) ? `/ws/scans/${scanId}` : null,
    {
      autoConnect: !!(scanId && enabled),
      onMessage: handleMessage,
      onConnect,
      onDisconnect,
    }
  );

  return ws;
}

/**
 * Specialized hook for dashboard updates
 */
export function useDashboardWebSocket(callbacks = {}) {
  const { onUpdate, onNotification } = callbacks;

  const handleMessage = useCallback((message) => {
    switch (message.type) {
      case MessageType.DASHBOARD_UPDATE:
        onUpdate?.(message.data);
        break;
      case MessageType.NOTIFICATION:
        onNotification?.(message.data);
        break;
      default:
        break;
    }
  }, [onUpdate, onNotification]);

  return useWebSocket('/ws/dashboard', {
    onMessage: handleMessage,
  });
}

export default useWebSocket;
