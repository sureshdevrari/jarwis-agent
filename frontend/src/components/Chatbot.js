import React, { useState, useRef, useEffect } from 'react';
import './Chatbot.css';

const Chatbot = ({ scanId, findings }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      role: 'assistant',
      content: "ðŸ‘‹ Hi! I'm Jarwis AGI, created by BKD Labs. I'm here to help you understand your security findings. What would you like to know?",
      timestamp: new Date().toISOString()
    }
  ]);
  const [inputMessage, setInputMessage] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [isTyping, setIsTyping] = useState(false);
  const [currentResponse, setCurrentResponse] = useState('');
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, currentResponse]);

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
    setIsTyping(true);
    setCurrentResponse('');

    try {
      const response = await fetch('http://localhost:5000/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: inputMessage,
          scan_id: scanId
        })
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
              // Ignore parse errors for incomplete chunks
            }
          }
        }
      }
    } catch (error) {
      console.error('Chat error:', error);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: "Sorry, I encountered an error. Please try again.",
        timestamp: new Date().toISOString()
      }]);
    }

    setIsLoading(false);
    setIsTyping(false);
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('scan_id', scanId || '');

    setMessages(prev => [...prev, {
      role: 'user',
      content: `ðŸ“Ž Uploaded file: ${file.name}`,
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

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatMessage = (content) => {
    // Simple markdown-like formatting
    return content
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`(.*?)`/g, '<code>$1</code>')
      .replace(/\n/g, '<br/>');
  };

  return (
    <>
      {/* Chat Toggle Button */}
      <button 
        className={`chatbot-toggle ${isOpen ? 'open' : ''}`}
        onClick={() => setIsOpen(!isOpen)}
      >
        {isOpen ? (
          <span>âœ•</span>
        ) : (
          <span>ðŸ’¬</span>
        )}
      </button>

      {/* Chat Window */}
      {isOpen && (
        <div className="chatbot-container">
          {/* Header */}
          <div className="chatbot-header">
            <div className="chatbot-avatar">
              <span>ðŸ¤–</span>
            </div>
            <div className="chatbot-info">
              <h3>Jarwis AGI</h3>
              <span className="chatbot-subtitle">by BKD Labs</span>
            </div>
            <button className="chatbot-close" onClick={() => setIsOpen(false)}>
              âœ•
            </button>
          </div>

          {/* Messages */}
          <div className="chatbot-messages">
            {messages.map((msg, index) => (
              <div key={index} className={`message ${msg.role}`}>
                {msg.role === 'assistant' && (
                  <div className="message-avatar">ðŸ¤–</div>
                )}
                <div className="message-content">
                  <div 
                    className="message-text"
                    dangerouslySetInnerHTML={{ __html: formatMessage(msg.content) }}
                  />
                  <div className="message-time">
                    {new Date(msg.timestamp).toLocaleTimeString()}
                  </div>
                </div>
              </div>
            ))}

            {/* Typing indicator */}
            {isTyping && currentResponse && (
              <div className="message assistant">
                <div className="message-avatar">ðŸ¤–</div>
                <div className="message-content">
                  <div 
                    className="message-text typing"
                    dangerouslySetInnerHTML={{ __html: formatMessage(currentResponse) }}
                  />
                </div>
              </div>
            )}

            {/* Thinking indicator */}
            {isTyping && !currentResponse && (
              <div className="message assistant">
                <div className="message-avatar">ðŸ¤–</div>
                <div className="message-content">
                  <div className="thinking-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                </div>
              </div>
            )}

            <div ref={messagesEndRef} />
          </div>

          {/* Input Area */}
          <div className="chatbot-input-area">
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileUpload}
              style={{ display: 'none' }}
              accept=".txt,.json,.log,.xml,.html,.js,.py,.yaml,.yml,.conf,.cfg"
            />
            <button 
              className="upload-btn"
              onClick={() => fileInputRef.current.click()}
              disabled={isLoading}
              title="Upload file for analysis"
            >
              ðŸ“Ž
            </button>
            <textarea
              className="chatbot-input"
              placeholder="Ask about your findings..."
              value={inputMessage}
              onChange={(e) => setInputMessage(e.target.value)}
              onKeyPress={handleKeyPress}
              disabled={isLoading}
              rows={1}
            />
            <button 
              className="send-btn"
              onClick={handleSendMessage}
              disabled={isLoading || !inputMessage.trim()}
            >
              {isLoading ? '...' : 'âž¤'}
            </button>
          </div>

          {/* Footer */}
          <div className="chatbot-footer">
            <span>Powered by Jarwis Human Intelligence</span>
          </div>
        </div>
      )}
    </>
  );
};

export default Chatbot;
