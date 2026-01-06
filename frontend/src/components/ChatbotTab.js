import React, { useState, useRef, useEffect } from 'react';
import './ChatbotTab.css';
import jarwisLogo from '../assets/jarwis-logo.png';

const ChatbotTab = ({ scanId, scanHistory, currentScan, serverLogs }) => {
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "Ã°Å¸â€˜â€¹ Hi! I'm Jarwis AGI, created by **BKD Labs**. I have full access to your scan results, findings, and server logs. Ask me anything about your security testing!\n\n**Quick questions:**\n- What vulnerabilities were found?\n- Explain the critical findings\n- How do I fix the XSS vulnerability?\n- Summarize my last scan",
      timestamp: new Date().toISOString()
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [isThinking, setIsThinking] = useState(false);
  const [thinkingText, setThinkingText] = useState('');
  const [currentResponse, setCurrentResponse] = useState('');
  const [chatbotStatus, setChatbotStatus] = useState({ available: false, model: 'unknown' });
  const [selectedModel, setSelectedModel] = useState('jarwis'); // 'jarwis' or 'sav'
  const [lastScanData, setLastScanData] = useState(null);
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  // Get user session ID (for future auth)
  const getUserSessionId = () => {
    let sessionId = localStorage.getItem('jarwis_session_id');
    if (!sessionId) {
      sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
      localStorage.setItem('jarwis_session_id', sessionId);
    }
    return sessionId;
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, currentResponse]);

  // Check chatbot status on mount
  useEffect(() => {
    checkChatbotStatus();
    loadChatHistory();
    loadLastScanResults();
  }, []);

  // Update chatbot context when scan changes or scanHistory updates
  useEffect(() => {
    if (scanId) {
      updateScanContext();
    } else if (scanHistory && scanHistory.length > 0) {
      // Auto-load last scan if no current scan
      loadLastScanResults();
    }
  }, [scanId, currentScan, scanHistory]);

  const loadLastScanResults = async () => {
    try {
      // Get the last scan from history
      const response = await fetch('http://localhost:5000/api/scans/last');
      const data = await response.json();
      if (data.scan_id) {
        setLastScanData(data);
        // Update context with last scan
        const sessionId = getUserSessionId();
        await fetch('http://localhost:5000/api/chat/context', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            session_id: sessionId,
            scan_id: data.scan_id,
            include_logs: true
          })
        });
      }
    } catch (error) {
      console.error('Failed to load last scan:', error);
    }
  };

  const checkChatbotStatus = async () => {
    try {
      const response = await fetch('http://localhost:5000/api/chat/status');
      const data = await response.json();
      setChatbotStatus(data);
    } catch (error) {
      console.error('Failed to check chatbot status:', error);
    }
  };

  const loadChatHistory = async () => {
    try {
      const sessionId = getUserSessionId();
      const response = await fetch(`http://localhost:5000/api/chat/history?session_id=${sessionId}`);
      const data = await response.json();
      if (data.history && data.history.length > 0) {
        setMessages([messages[0], ...data.history]);
      }
    } catch (error) {
      console.error('Failed to load chat history:', error);
    }
  };

  const updateScanContext = async () => {
    try {
      const sessionId = getUserSessionId();
      await fetch('http://localhost:5000/api/chat/context', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          session_id: sessionId,
          scan_id: scanId,
          include_logs: true
        })
      });
    } catch (error) {
      console.error('Failed to update scan context:', error);
    }
  };

  const handleSendMessage = async () => {
    if (!inputMessage.trim() || isLoading) return;

    const userMessage = {
      role: 'user',
      content: inputMessage,
      timestamp: new Date().toISOString()
    };

    setMessages(prev => [...prev, userMessage]);
    setInputMessage('');
    setIsLoading(true);
    setCurrentResponse('');

    // Different behavior based on selected model
    let thinkingInterval = null;
    if (selectedModel === 'sav') {
      // Sav 1.1 - Deep thinking mode
      setIsThinking(true);
      const thinkingPhases = [
        'Sav 1.1 is analyzing your query...',
        'Deep diving into context...',
        'Reviewing all scan findings...',
        'Cross-referencing vulnerabilities...',
        'Formulating detailed response...'
      ];
      let phaseIndex = 0;
      setThinkingText(thinkingPhases[0]);
      thinkingInterval = setInterval(() => {
        phaseIndex = (phaseIndex + 1) % thinkingPhases.length;
        setThinkingText(thinkingPhases[phaseIndex]);
      }, 1500);
    } else {
      // Jarwis AGI - Quick response mode
      setIsTyping(true);
    }

    try {
      const sessionId = getUserSessionId();
      const activeScanId = scanId || (lastScanData ? lastScanData.scan_id : '');
      const response = await fetch('http://localhost:5000/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: inputMessage,
          scan_id: activeScanId,
          session_id: sessionId,
          include_logs: true,
          include_findings: true,
          model_mode: selectedModel  // 'jarwis' or 'sav'
        })
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let fullResponse = '';

      // Stop thinking, start typing
      clearInterval(thinkingInterval);
      setIsThinking(false);
      setIsTyping(true);

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === 'chunk') {
                fullResponse += data.content;
                setCurrentResponse(fullResponse);
              } else if (data.type === 'end') {
                setMessages(prev => [...prev, {
                  role: 'assistant',
                  content: fullResponse,
                  timestamp: new Date().toISOString()
                }]);
                setCurrentResponse('');
              }
            } catch (e) {
              // Ignore parse errors for incomplete chunks
            }
          }
        }
      }
    } catch (error) {
      console.error('Chat error:', error);
      clearInterval(thinkingInterval);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: "Sorry, I encountered an error. Please try again.",
        timestamp: new Date().toISOString()
      }]);
    }

    setIsLoading(false);
    setIsTyping(false);
    setIsThinking(false);
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('scan_id', scanId || '');
    formData.append('session_id', getUserSessionId());

    setMessages(prev => [...prev, {
      role: 'user',
      content: `Ã°Å¸â€œÅ½ Uploaded file: ${file.name}`,
      timestamp: new Date().toISOString()
    }]);

    setIsLoading(true);
    setIsTyping(true);
    setCurrentResponse('');

    try {
      const response = await fetch('http://localhost:5000/api/chat/upload', {
        method: 'POST',
        body: formData
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let fullResponse = '';

      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        const chunk = decoder.decode(value);
        const lines = chunk.split('\n');

        for (const line of lines) {
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === 'chunk') {
                fullResponse += data.content;
                setCurrentResponse(fullResponse);
              } else if (data.type === 'end') {
                setMessages(prev => [...prev, {
                  role: 'assistant',
                  content: fullResponse,
                  timestamp: new Date().toISOString()
                }]);
                setCurrentResponse('');
              }
            } catch (e) {
              // Ignore parse errors
            }
          }
        }
      }
    } catch (error) {
      console.error('Upload error:', error);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: "Sorry, I couldn't analyze the file. Please try again.",
        timestamp: new Date().toISOString()
      }]);
    }

    setIsLoading(false);
    setIsTyping(false);
    fileInputRef.current.value = '';
  };

  const handleClearChat = async () => {
    try {
      const sessionId = getUserSessionId();
      await fetch('http://localhost:5000/api/chat/clear', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ session_id: sessionId })
      });
      setMessages([messages[0]]);
    } catch (error) {
      console.error('Failed to clear chat:', error);
    }
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatMessage = (content) => {
    // Enhanced markdown-like formatting
    return content
      .replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>')
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/```([\s\S]*?)```/g, '<pre>$1</pre>')
      .replace(/\n/g, '<br/>');
  };

  const quickQuestions = [
    "What vulnerabilities were found?",
    "Explain the critical findings",
    "How do I fix the most severe issue?",
    "Summarize my scan results",
    "What should I prioritize?"
  ];

  const getActiveScanId = () => scanId || (lastScanData ? lastScanData.scan_id : null);

  return (
    <div className="chatbot-tab">
      {/* Header */}
      <div className="chatbot-tab-header">
        <div className="chatbot-tab-info">
          <img src={jarwisLogo} alt="Jarwis AGI" className="chatbot-tab-avatar" />
          <div className="chatbot-tab-details">
            <h2>{selectedModel === 'sav' ? 'Sav 1.1' : 'Jarwis AGI'} Assistant</h2>
            <span className="chatbot-tab-subtitle">
              by BKD Labs Ã¢â‚¬Â¢ {chatbotStatus.available ? 'Connected' : 'Offline Mode'}
              {selectedModel === 'sav' && ' Ã¢â‚¬Â¢ Deep Analysis Mode'}
            </span>
          </div>
        </div>
        <div className="chatbot-tab-actions">
          {/* Model Switcher */}
          <div className="model-switcher">
            <button 
              className={`model-btn ${selectedModel === 'jarwis' ? 'active' : ''}`}
              onClick={() => setSelectedModel('jarwis')}
              title="Quick responses"
            >
              Ã¢Å¡Â¡ Jarwis AGI
            </button>
            <button 
              className={`model-btn sav ${selectedModel === 'sav' ? 'active' : ''}`}
              onClick={() => setSelectedModel('sav')}
              title="Deep analysis with detailed thinking"
            >
              Ã°Å¸Â§Â  Sav 1.1
            </button>
          </div>
          {getActiveScanId() && (
            <span className="scan-context-badge">
              Ã°Å¸â€œÅ  {scanId ? 'Active' : 'Last'}: {getActiveScanId().slice(0, 12)}...
            </span>
          )}
          <button className="clear-chat-btn" onClick={handleClearChat} title="Clear conversation">
            Ã°Å¸â€”â€˜Ã¯Â¸Â Clear
          </button>
        </div>
      </div>

      {/* Model Info Banner */}
      {selectedModel === 'sav' && (
        <div className="model-info-banner sav">
          <span className="model-badge">Sav 1.1</span>
          <span>Deep Thinking Mode - Provides detailed analysis with step-by-step reasoning</span>
        </div>
      )}

      {/* Quick Questions */}
      <div className="quick-questions">
        <span className="quick-questions-label">Quick questions:</span>
        <div className="quick-questions-list">
          {quickQuestions.map((q, i) => (
            <button 
              key={i} 
              className="quick-question-btn"
              onClick={() => setInputMessage(q)}
              disabled={isLoading}
            >
              {q}
            </button>
          ))}
        </div>
      </div>

      {/* Messages */}
      <div className="chatbot-tab-messages">
        {messages.map((msg, index) => (
          <div key={index} className={`chat-message ${msg.role}`}>
            {msg.role === 'assistant' && (
              <img src={jarwisLogo} alt="Jarwis" className="chat-message-avatar" />
            )}
            <div className="chat-message-content">
              <div 
                className="chat-message-text"
                dangerouslySetInnerHTML={{ __html: formatMessage(msg.content) }}
              />
              <div className="chat-message-time">
                {new Date(msg.timestamp).toLocaleTimeString()}
              </div>
            </div>
          </div>
        ))}

        {/* Sav 1.1 Thinking indicator */}
        {isThinking && (
          <div className="chat-message assistant">
            <img src={jarwisLogo} alt="Jarwis" className="chat-message-avatar" />
            <div className="chat-message-content">
              <div className="sav-thinking">
                <div className="sav-thinking-header">
                  <span className="sav-model-badge">Sav 1.1</span>
                  <span className="sav-thinking-label">Deep Thinking</span>
                </div>
                <div className="sav-thinking-text">{thinkingText}</div>
                <div className="sav-thinking-dots">
                  <span></span>
                  <span></span>
                  <span></span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Typing response */}
        {isTyping && currentResponse && (
          <div className="chat-message assistant">
            <img src={jarwisLogo} alt="Jarwis" className="chat-message-avatar" />
            <div className="chat-message-content">
              <div 
                className="chat-message-text typing"
                dangerouslySetInnerHTML={{ __html: formatMessage(currentResponse) }}
              />
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Area */}
      <div className="chatbot-tab-input-area">
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileUpload}
          style={{ display: 'none' }}
          accept=".txt,.json,.log,.xml,.html,.js,.py,.yaml,.yml,.conf,.cfg,.md"
        />
        <button 
          className="upload-file-btn"
          onClick={() => fileInputRef.current.click()}
          disabled={isLoading}
          title="Upload file for analysis"
        >
          Ã°Å¸â€œÅ½
        </button>
        <textarea
          className="chat-input"
          placeholder="Ask about your findings, vulnerabilities, or security testing..."
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyPress={handleKeyPress}
          disabled={isLoading}
          rows={2}
        />
        <button 
          className="send-message-btn"
          onClick={handleSendMessage}
          disabled={isLoading || !inputMessage.trim()}
        >
          {isLoading ? (
            <span className="sending-spinner">Ã¢Å¸Â³</span>
          ) : (
            'Ã¢Å¾Â¤'
          )}
        </button>
      </div>

      {/* Footer */}
      <div className="chatbot-tab-footer">
        <span>Powered by Jarwis Human Intelligence Ã¢â‚¬Â¢ Your data stays private</span>
      </div>
    </div>
  );
};

export default ChatbotTab;
