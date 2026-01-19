/**
 * SyndashLayout - Main layout wrapper for Syndash theme
 * Includes Sidebar, Topbar, and Chatbot
 */
import React, { useState, useEffect, useRef } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../../context/AuthContext";
import { useTheme } from "../../context/ThemeContext";
import { CHAT } from "../../config/endpoints.generated";
import api from "../../services/api";
import "./syndash-theme.css";

// Navigation menu structure
const menu = [
  { 
    section: "MAIN",
    items: [
      { text: "Dashboard", icon: "📊", path: "/dashboard" },
      { text: "Billing & Plans", icon: "💳", path: "/dashboard/billing" },
    ]
  },
  {
    section: "SECURITY SCANNING",
    items: [
      { 
        text: "New Scan", 
        icon: "🚀", 
        hasChildren: true,
        children: [
          { text: "Web Scan", icon: "🌐", path: "/dashboard/scan/web" },
          { text: "Mobile Scan", icon: "📱", path: "/dashboard/scan/mobile" },
          { text: "Network Scan", icon: "🌍", path: "/dashboard/scan/network" },
          { text: "Cloud Scan", icon: "☁️", path: "/dashboard/scan/cloud" },
          { text: "Code Review", icon: "🔍", path: "/dashboard/scan/sast" },
        ]
      },
      { text: "Active Scan", icon: "⚡", path: "/dashboard/scanning" },
      { text: "Scan History", icon: "📜", path: "/dashboard/scan-history" },
    ]
  },
  {
    section: "RESULTS",
    items: [
      { text: "Vulnerabilities", icon: "🚨", path: "/dashboard/vulnerabilities" },
      { text: "Reports", icon: "📄", path: "/dashboard/reports" },
    ]
  },
  {
    section: "AI ASSISTANT",
    items: [
      { text: "Jarwis AGI", icon: "🤖", path: "/dashboard/jarwis-chatbot" },
    ]
  },
  {
    section: "SETTINGS",
    items: [
      { text: "Agent Setup", icon: "📥", path: "/dashboard/agent-setup" },
      { text: "Account Settings", icon: "⚙️", path: "/dashboard/settings" },
    ]
  },
];

// Admin menu items (added conditionally)
const adminMenu = {
  section: "ADMINISTRATION",
  items: [
    {
      text: "Admin Panel",
      icon: "🛡️",
      hasChildren: true,
      children: [
        { text: "Admin Dashboard", icon: "📈", path: "/admin" },
        { text: "User Management", icon: "👥", path: "/admin/users" },
        { text: "Access Requests", icon: "📋", path: "/admin/requests" },
      ]
    }
  ]
};

// Sidebar Component
function Sidebar({ isOpen, isDarkMode, userRole }) {
  const location = useLocation();
  const [expandedItems, setExpandedItems] = useState({});

  const toggleExpand = (itemText) => {
    setExpandedItems(prev => ({
      ...prev,
      [itemText]: !prev[itemText]
    }));
  };

  // Add admin menu if user is admin
  const fullMenu = userRole === 'admin' || userRole === 'superadmin' 
    ? [...menu.slice(0, -1), adminMenu, menu[menu.length - 1]]
    : menu;
  
  return (
    <aside className={`syndash-sidebar ${isOpen ? 'open' : 'closed'} ${isDarkMode ? 'dark' : 'light'}`}>
      <div className="sidebar-header">
        <div className="logo">
          <div className="logo-icon">J</div>
          {isOpen && <span className="logo-text">Jarwis AI</span>}
        </div>
      </div>
      
      <nav className="sidebar-nav">
        {fullMenu.map((section, idx) => (
          <div key={idx} className="nav-section">
            {isOpen && <div className="section-label">{section.section}</div>}
            {section.items.map((item) => (
              <div key={item.text}>
                {item.hasChildren ? (
                  <>
                    <button
                      className="nav-item nav-parent"
                      onClick={() => toggleExpand(item.text)}
                      title={!isOpen ? item.text : ''}
                    >
                      <span className="nav-icon">{item.icon}</span>
                      {isOpen && (
                        <>
                          <span className="nav-text">{item.text}</span>
                          <span className={`nav-arrow ${expandedItems[item.text] ? 'expanded' : ''}`}>
                            ▼
                          </span>
                        </>
                      )}
                    </button>
                    {isOpen && expandedItems[item.text] && (
                      <div className="nav-children">
                        {item.children.map((child) => (
                          <Link
                            key={child.path}
                            to={child.path}
                            state={child.state || {}}
                            className={`nav-item nav-child ${location.pathname === child.path ? 'active' : ''}`}
                          >
                            <span className="nav-icon">{child.icon}</span>
                            <span className="nav-text">{child.text}</span>
                          </Link>
                        ))}
                      </div>
                    )}
                  </>
                ) : (
                  <Link
                    to={item.path}
                    className={`nav-item ${location.pathname === item.path ? 'active' : ''}`}
                    title={!isOpen ? item.text : ''}
                  >
                    <span className="nav-icon">{item.icon}</span>
                    {isOpen && <span className="nav-text">{item.text}</span>}
                  </Link>
                )}
              </div>
            ))}
          </div>
        ))}
      </nav>
    </aside>
  );
}

// Topbar Component
function Topbar({ toggleSidebar, isDarkMode, toggleDarkMode, user, userDoc, onLogout }) {
  const [showUserMenu, setShowUserMenu] = useState(false);
  const menuRef = useRef(null);
  const navigate = useNavigate();

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (menuRef.current && !menuRef.current.contains(event.target)) {
        setShowUserMenu(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleNavigate = (path) => {
    navigate(path);
    setShowUserMenu(false);
  };

  const displayName = user?.displayName || userDoc?.displayName || userDoc?.email?.split("@")[0] || "User";
  const userRole = userDoc?.role || "User";
  const userInitial = displayName.charAt(0).toUpperCase();

  return (
    <header className={`syndash-topbar ${isDarkMode ? 'dark' : 'light'}`}>
      <div className="topbar-left">
        <button className="menu-toggle" onClick={toggleSidebar}>
          ☰
        </button>
        <div className="search-box">
          <span className="search-icon">🔍</span>
          <input type="text" placeholder="Search..." />
        </div>
      </div>
      
      <div className="topbar-right">
        <button className="icon-btn" onClick={toggleDarkMode} title={isDarkMode ? 'Light Mode' : 'Dark Mode'}>
          {isDarkMode ? '☀️' : '🌙'}
        </button>
        <button className="icon-btn" title="Notifications">
          <span className="notification-badge">0</span>
          🔔
        </button>
        <div className="user-menu-wrapper" ref={menuRef}>
          <div 
            className="user-menu" 
            onClick={() => setShowUserMenu(!showUserMenu)}
          >
            <div className="user-avatar">{userInitial}</div>
            <div className="user-info">
              <span className="user-name">{displayName}</span>
              <span className="user-role">{userRole}</span>
            </div>
            <span className="dropdown-arrow">{showUserMenu ? '▲' : '▼'}</span>
          </div>
          
          {showUserMenu && (
            <div className="user-dropdown">
              <button className="dropdown-item" onClick={() => handleNavigate('/dashboard/settings')}>
                <span className="dropdown-icon">👤</span>
                <span>My Profile</span>
              </button>
              <button className="dropdown-item" onClick={() => handleNavigate('/dashboard/settings')}>
                <span className="dropdown-icon">⚙️</span>
                <span>Settings</span>
              </button>
              <button className="dropdown-item" onClick={() => handleNavigate('/dashboard/billing')}>
                <span className="dropdown-icon">💳</span>
                <span>Billing</span>
              </button>
              <div className="dropdown-divider"></div>
              <button className="dropdown-item logout" onClick={onLogout}>
                <span className="dropdown-icon">🚪</span>
                <span>Logout</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}

// Chatbot Component
function Chatbot({ isDarkMode }) {
  const [isOpen, setIsOpen] = useState(false);
  const [messages, setMessages] = useState([
    {
      type: 'bot',
      text: 'Hi! I\'m Jarwis AI, your security testing assistant. How can I help you today?',
      time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isTyping, setIsTyping] = useState(false);
  const messagesEndRef = useRef(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const quickQuestions = [
    "How do I start a web scan?",
    "What's my security score?",
    "Explain recent vulnerabilities",
    "Generate scan report"
  ];

  const handleSend = async () => {
    if (!inputValue.trim()) return;

    const userMessage = {
      type: 'user',
      text: inputValue,
      time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
    };

    setMessages(prev => [...prev, userMessage]);
    const question = inputValue;
    setInputValue('');
    setIsTyping(true);

    try {
      // Call the chat API via generated endpoint constants
      const response = await api.post(CHAT.SEND, { message: question });
      
      if (response.data?.success && response.data?.data?.response) {
        setMessages(prev => [...prev, {
          type: 'bot',
          text: response.data.data.response,
          time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
        }]);
      } else {
        // Fallback to local response
        setMessages(prev => [...prev, {
          type: 'bot',
          text: getBotResponse(question),
          time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
        }]);
      }
    } catch {
      // Fallback to local response on error
      setMessages(prev => [...prev, {
        type: 'bot',
        text: getBotResponse(question),
        time: new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const getBotResponse = (question) => {
    const q = question.toLowerCase();
    
    if (q.includes('scan') && q.includes('web')) {
      return "To start a web scan:\n1. Click 'Start Scan' in the sidebar\n2. Enter your target URL\n3. Configure authentication if needed\n4. Select security checks\n5. Click 'Start Scan'";
    } else if (q.includes('security') && q.includes('score')) {
      return "Your security score is calculated based on:\n• Recent scan results\n• Vulnerability severity levels\n• Remediation progress\n\nCheck the Dashboard for your current score!";
    } else if (q.includes('vulnerabilities') || q.includes('vuln')) {
      return "To view vulnerabilities:\n1. Go to 'Vulnerabilities' in the sidebar\n2. Filter by severity (Critical, High, Medium, Low)\n3. Click any item for detailed remediation steps";
    } else if (q.includes('report')) {
      return "To generate reports:\n1. Go to 'Reports' in the sidebar\n2. Select a completed scan\n3. Choose format: HTML, PDF, or JSON\n4. Click Download";
    } else if (q.includes('hello') || q.includes('hi')) {
      return "Hello! I'm here to help with your security testing. Ask me about scans, vulnerabilities, or reports!";
    } else {
      return "I can help you with:\n• Starting security scans\n• Understanding vulnerabilities\n• Generating reports\n• Explaining security concepts\n\nWhat would you like to know?";
    }
  };

  const handleQuickQuestion = (question) => {
    setInputValue(question);
  };

  return (
    <>
      <button 
        className={`chatbot-toggle ${isOpen ? 'active' : ''}`}
        onClick={() => setIsOpen(!isOpen)}
        title="Chat with Jarwis AI"
      >
        {isOpen ? '✕' : '💬'}
      </button>

      {isOpen && (
        <div className={`chatbot-window ${isDarkMode ? 'dark' : 'light'}`}>
          <div className="chatbot-header">
            <div className="chatbot-avatar">
              <div className="avatar-gradient">J</div>
              <span className="status-indicator"></span>
            </div>
            <div className="chatbot-info">
              <h3>Jarwis AI Assistant</h3>
              <p>Online • Always ready to help</p>
            </div>
            <button className="chatbot-close" onClick={() => setIsOpen(false)}>✕</button>
          </div>

          <div className="chatbot-messages">
            {messages.map((msg, idx) => (
              <div key={idx} className={`message ${msg.type}`}>
                {msg.type === 'bot' && <div className="message-avatar">J</div>}
                <div className="message-bubble">
                  <div className="message-text">{msg.text}</div>
                  <div className="message-time">{msg.time}</div>
                </div>
              </div>
            ))}
            
            {isTyping && (
              <div className="message bot">
                <div className="message-avatar">J</div>
                <div className="message-bubble typing">
                  <div className="typing-indicator">
                    <span></span>
                    <span></span>
                    <span></span>
                  </div>
                </div>
              </div>
            )}
            
            <div ref={messagesEndRef} />
          </div>

          {messages.length <= 1 && (
            <div className="quick-questions">
              <div className="quick-label">Quick questions:</div>
              {quickQuestions.map((q, idx) => (
                <button 
                  key={idx} 
                  className="quick-btn"
                  onClick={() => handleQuickQuestion(q)}
                >
                  {q}
                </button>
              ))}
            </div>
          )}

          <div className="chatbot-input">
            <input 
              type="text"
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyPress={(e) => e.key === 'Enter' && handleSend()}
              placeholder="Type your message..."
            />
            <button 
              className="send-btn" 
              onClick={handleSend}
              disabled={!inputValue.trim()}
            >
              ➤
            </button>
          </div>
        </div>
      )}
    </>
  );
}

// Main Layout Component
export default function SyndashLayout({ children }) {
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const { user, userDoc, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const toggleSidebar = () => setSidebarOpen(!sidebarOpen);

  const handleLogout = async () => {
    try {
      await logout();
      navigate("/login");
    } catch (err) {
      console.error("Logout error", err);
    }
  };

  const userRole = userDoc?.role || "user";

  return (
    <div className={`syndash-app ${isDarkMode ? 'dark-mode' : 'light-mode'}`}>
      <Sidebar 
        isOpen={sidebarOpen} 
        isDarkMode={isDarkMode} 
        userRole={userRole}
      />
      <div className={`syndash-main ${sidebarOpen ? 'sidebar-open' : 'sidebar-closed'}`}>
        <Topbar 
          toggleSidebar={toggleSidebar} 
          isDarkMode={isDarkMode}
          toggleDarkMode={toggleTheme}
          user={user}
          userDoc={userDoc}
          onLogout={handleLogout}
        />
        <div className="syndash-page">
          {children}
        </div>
      </div>
      <Chatbot isDarkMode={isDarkMode} />
    </div>
  );
}
