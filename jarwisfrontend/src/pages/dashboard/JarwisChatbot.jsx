// src/pages/dashboard/JarwisChatbot.jsx - Premium Jarwis AGI Chatbot with History
import { useState, useRef, useEffect, useCallback } from "react";
import { useLocation, useSearchParams, useNavigate } from "react-router-dom";
import MiftyJarwisLayout from "../../components/layout/MiftyJarwisLayout";
import { useTheme } from "../../context/ThemeContext";
import { useSubscription } from "../../context/SubscriptionContext";
import { chatAPI } from "../../services/api";

// Jarwis Logo Component (SVG - Transparent)
const JarwisLogo = ({ className = "w-8 h-8", animated = false }) => (
  <svg 
    className={`${className} ${animated ? "animate-pulse" : ""}`} 
    viewBox="0 0 500 500" 
    fill="none" 
    xmlns="http://www.w3.org/2000/svg"
  >
    <defs>
      <linearGradient id="jarwisGradient" x1="250" y1="111.235" x2="250" y2="383.576" gradientUnits="userSpaceOnUse">
        <stop offset="0" stopColor="#00C19F"/>
        <stop offset="1" stopColor="#256AD1"/>
      </linearGradient>
    </defs>
    <path 
      fill="url(#jarwisGradient)" 
      d="M343.73,166.48l-12.75-7.4L250,112.35l-25.51,14.73l-12.75,7.33l-80.97,46.8V318.8l25.5,14.72l12.75,7.4l12.75,7.33l12.75,7.39L250,387.65l25.51-14.73l12.75-7.4l12.75-7.33l12.75-7.33l55.47-32.07V181.21L343.73,166.48z M250,127.08l80.97,46.73v14.73l0,0v14.73l0,0v65.29l-12.75,7.14v-94.49l-12.75-7.4l-55.47-32l-12.75-7.33L250,127.08z M250,314.01L194.53,282V218L250,185.99L305.47,218v64.84L250,314.01z M143.53,188.54l80.97-46.73l12.75,7.33h0.07l12.69,7.39l55.47,32.01v14.72l-55.47-32l-12.75-7.4l-12.75-7.33l-12.75,7.4h-0.07l-55.41,32l-12.75,7.4V188.54z M143.53,311.47V218l12.75-7.33l12.75-7.4l55.41-32l12.81,7.4l-55.47,32L169.03,218l-12.75,7.39v93.41L143.53,311.47z M250,372.92l-55.47-32l-12.75-7.4l-12.75-7.33v-93.47l12.75-7.39v93.47v0.06l12.75,7.33L250,358.2l12.75,7.33L250,372.92z M275.51,358.2l-12.75-7.4L250,343.47l-55.47-32v-14.73l55.47,32l12.75,7.4l12.75,7.33l12.75,7.4L275.51,358.2z M356.47,311.47l-55.47,32l-12.75-7.33l55.47-32v-0.07l12.75-7.33V311.47z M356.47,282l-12.75,7.33l-12.75,7.4l-55.47,32l-12.63-7.27l68.09-38.32l12.75-7.14l12.75-7.2V282z M356.47,254.21l-12.75,7.13v-65.41v-14.72l12.75,7.33V254.21z"
    />
    <polygon fill="#00C598" points="250,229.09 220.91,245.88 220.91,279.44 250,296.23 279.09,279.88 279.09,245.88"/>
    <path fill="#256AD1" d="M250,208.65c-13.03,0-23.62,10.6-23.62,23.63v5.37l7-4.04v-1.33c0-9.17,7.46-16.63,16.63-16.63c9.16,0,16.63,7.46,16.63,16.63v1.33l7,4.04v-5.37C273.62,219.25,263.02,208.65,250,208.65z"/>
  </svg>
);

// Upgrade Required Component
const UpgradeRequired = ({ isDarkMode, onNavigate }) => (
  <div className={`flex flex-col items-center justify-center h-[calc(100vh-200px)] text-center px-6 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
    <div className={`p-8 rounded-2xl max-w-lg w-full ${isDarkMode ? "bg-gradient-to-br from-slate-800/80 to-slate-900/80 border-2 border-violet-500/30 shadow-xl shadow-violet-500/10" : "bg-gradient-to-br from-white to-gray-50 border-2 border-violet-300 shadow-xl"}`}>
      <div className={`w-20 h-20 mx-auto mb-6 rounded-2xl flex items-center justify-center ${isDarkMode ? "bg-gradient-to-br from-violet-500/20 to-purple-600/20 border border-violet-500/30" : "bg-gradient-to-br from-violet-100 to-purple-100 border border-violet-200"}`}>
        <JarwisLogo className="w-12 h-12" />
      </div>
      <h2 className={`text-2xl font-bold mb-3 ${isDarkMode ? "text-white" : "text-gray-900"}`}>Jarwis AGI Chatbot</h2>
      <p className={`text-lg mb-2 ${isDarkMode ? "text-violet-300" : "text-violet-700"} font-semibold`}>Available on Professional & Enterprise Plans</p>
      <p className={`mb-6 ${isDarkMode ? "text-gray-400" : "text-gray-600"}`}>Get instant AI-powered security guidance, vulnerability explanations, and remediation code samples.</p>
      <button onClick={() => onNavigate("/pricing")} className={`w-full py-3 px-6 rounded-xl font-semibold transition-all ${isDarkMode ? "bg-gradient-to-r from-violet-600 to-purple-600 text-white hover:from-violet-500 hover:to-purple-500" : "bg-gradient-to-r from-violet-500 to-purple-500 text-white hover:from-violet-400 hover:to-purple-400"}`}>
        Upgrade to Professional
      </button>
    </div>
  </div>
);

// Chat History Sidebar
const ChatHistorySidebar = ({ isDarkMode, chatSessions, currentSessionId, onSelectSession, onNewChat, onDeleteSession, searchQuery, onSearchChange, tokenUsage, isEnterprise }) => {
  const filteredSessions = chatSessions.filter(session => 
    session.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    session.preview.toLowerCase().includes(searchQuery.toLowerCase())
  );

  const tokenLimit = isEnterprise ? 5000000 : 500000;
  const tokenPercent = Math.min((tokenUsage / tokenLimit) * 100, 100);

  return (
    <div className={`w-72 flex-shrink-0 flex flex-col h-full ${isDarkMode ? "bg-slate-900/50 border-r border-slate-700/50" : "bg-gray-50 border-r border-gray-200"}`}>
      {/* Header with Gradient */}
      <div className={`p-4 ${isDarkMode ? "bg-gradient-to-r from-cyan-500/10 to-blue-600/10" : "bg-gradient-to-r from-cyan-50 to-blue-50"}`}>
        <div className="flex items-center gap-3 mb-4">
          <JarwisLogo className="w-8 h-8" />
          <div>
            <h2 className={`font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>Chat History</h2>
            <p className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-500"}`}>{chatSessions.length} conversations</p>
          </div>
        </div>
        
        {/* New Chat Button */}
        <button
          onClick={onNewChat}
          className={`w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl font-medium transition-all ${
            isDarkMode 
              ? "bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500 shadow-lg shadow-cyan-500/20" 
              : "bg-gradient-to-r from-cyan-500 to-blue-500 text-white hover:from-cyan-400 hover:to-blue-400 shadow-lg"
          }`}
        >
          <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4" />
          </svg>
          New Chat
        </button>
      </div>

      {/* Search Box */}
      <div className="px-4 py-3">
        <div className="relative">
          <svg className={`absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search chats..."
            className={`w-full pl-10 pr-4 py-2.5 rounded-xl text-sm outline-none transition-all ${
              isDarkMode 
                ? "bg-slate-800/50 border border-slate-700 text-white placeholder-gray-500 focus:border-cyan-500/50 focus:ring-2 focus:ring-cyan-500/20" 
                : "bg-white border border-gray-200 text-gray-900 placeholder-gray-400 focus:border-cyan-500 focus:ring-2 focus:ring-cyan-500/20"
            }`}
          />
        </div>
      </div>

      {/* Chat Sessions List */}
      <div className="flex-1 overflow-y-auto px-2 space-y-1">
        {filteredSessions.length === 0 ? (
          <div className={`text-center py-8 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
            <JarwisLogo className="w-12 h-12 mx-auto mb-3 opacity-30" />
            <p className="text-sm">{searchQuery ? "No matching chats" : "No chat history yet"}</p>
            <p className="text-xs mt-1">Start a new conversation</p>
          </div>
        ) : (
          filteredSessions.map((session) => (
            <div
              key={session.id}
              onClick={() => onSelectSession(session.id)}
              className={`group relative p-3 rounded-xl cursor-pointer transition-all ${
                currentSessionId === session.id
                  ? isDarkMode
                    ? "bg-gradient-to-r from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10"
                    : "bg-gradient-to-r from-cyan-50 to-blue-50 border border-cyan-200 shadow-md"
                  : isDarkMode
                    ? "hover:bg-slate-800/50 border border-transparent"
                    : "hover:bg-gray-100 border border-transparent"
              }`}
            >
              <div className="flex items-start gap-3">
                <div className={`flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center ${
                  currentSessionId === session.id 
                    ? isDarkMode ? "bg-cyan-500/20" : "bg-cyan-100"
                    : isDarkMode ? "bg-slate-700" : "bg-gray-200"
                }`}>
                  <svg className={`w-4 h-4 ${currentSessionId === session.id ? isDarkMode ? "text-cyan-400" : "text-cyan-600" : isDarkMode ? "text-gray-400" : "text-gray-500"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                  </svg>
                </div>
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium truncate ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    {session.title}
                  </p>
                  <p className={`text-xs truncate mt-0.5 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    {session.preview}
                  </p>
                  <p className={`text-xs mt-1 flex items-center gap-1 ${isDarkMode ? "text-gray-600" : "text-gray-400"}`}>
                    <svg className="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    {session.date}
                  </p>
                </div>
              </div>
              {/* Delete Button */}
              <button
                onClick={(e) => { e.stopPropagation(); onDeleteSession(session.id); }}
                className={`absolute right-2 top-2 p-1.5 rounded-lg opacity-0 group-hover:opacity-100 transition-all ${isDarkMode ? "hover:bg-red-500/20 text-red-400" : "hover:bg-red-100 text-red-500"}`}
              >
                <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          ))
        )}
      </div>

      {/* Token Usage Footer */}
      <div className={`p-4 border-t ${isDarkMode ? "border-slate-700/50 bg-slate-900/30" : "border-gray-200 bg-gray-50/50"}`}>
        <div className={`text-xs ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
          <div className="flex justify-between mb-2">
            <span className="font-medium">Monthly Token Usage</span>
            <span className={`font-semibold ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`}>
              {(tokenUsage / 1000).toFixed(0)}K / {isEnterprise ? "5M" : "500K"}
            </span>
          </div>
          <div className={`h-2 rounded-full overflow-hidden ${isDarkMode ? "bg-slate-700" : "bg-gray-200"}`}>
            <div 
              className={`h-full rounded-full transition-all duration-500 ${
                tokenPercent > 80 
                  ? "bg-gradient-to-r from-red-500 to-orange-500" 
                  : "bg-gradient-to-r from-cyan-500 to-blue-500"
              }`}
              style={{ width: `${tokenPercent}%` }}
            />
          </div>
          <p className={`text-center mt-2 ${isDarkMode ? "text-gray-600" : "text-gray-400"}`}>
            {isEnterprise ? "Enterprise Plan" : "Professional Plan"}
          </p>
        </div>
      </div>
    </div>
  );
};

const JarwisChatbot = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();
  const messagesEndRef = useRef(null);
  const fileInputRef = useRef(null);
  const { isDarkMode } = useTheme();
  const { hasFeatureAccess, subscription } = useSubscription();

  const hasChatbotAccess = hasFeatureAccess("chatbotAccess");
  const isEnterprise = subscription?.plan === "enterprise";

  // State
  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const [currentResponse, setCurrentResponse] = useState("");
  const [scanId, setScanId] = useState(null);
  const [selectedModel, setSelectedModel] = useState("suru");
  const [historySearchQuery, setHistorySearchQuery] = useState("");
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [tokenUsage, setTokenUsage] = useState(0);
  
  // Chat sessions (persisted to localStorage)
  const [chatSessions, setChatSessions] = useState([]);
  const [currentSessionId, setCurrentSessionId] = useState(null);

  // Load chat sessions from localStorage
  useEffect(() => {
    const saved = localStorage.getItem("jarwis_chat_sessions");
    if (saved) {
      try {
        const sessions = JSON.parse(saved);
        setChatSessions(sessions);
        if (sessions.length > 0) {
          setCurrentSessionId(sessions[0].id);
          setMessages(sessions[0].messages || []);
        }
      } catch (e) {
        console.error("Failed to load chat sessions:", e);
      }
    }
    
    // Load token usage
    const savedTokens = localStorage.getItem("jarwis_token_usage");
    if (savedTokens) {
      const { tokens, date } = JSON.parse(savedTokens);
      // Reset if new day
      if (date !== new Date().toDateString()) {
        setTokenUsage(0);
      } else {
        setTokenUsage(tokens);
      }
    }
  }, []);

  // Save chat sessions to localStorage
  useEffect(() => {
    if (chatSessions.length > 0) {
      localStorage.setItem("jarwis_chat_sessions", JSON.stringify(chatSessions));
    }
  }, [chatSessions]);

  // Update current session messages
  useEffect(() => {
    if (currentSessionId && messages.length > 0) {
      setChatSessions(prev => prev.map(session => 
        session.id === currentSessionId 
          ? { 
              ...session, 
              messages,
              preview: messages[messages.length - 1]?.content?.slice(0, 50) + "..." || "",
              title: messages.find(m => m.type === "user")?.content?.slice(0, 30) || "New Chat"
            }
          : session
      ));
    }
  }, [messages, currentSessionId]);

  useEffect(() => {
    const urlScanId = searchParams.get("scan_id");
    const stateScanId = location.state?.scanId;
    setScanId(urlScanId || stateScanId || null);
  }, [searchParams, location.state]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, currentResponse]);

  const handleNewChat = () => {
    const newSession = {
      id: Date.now().toString(),
      title: "New Chat",
      preview: "Start a new conversation...",
      date: new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
      messages: []
    };
    setChatSessions(prev => [newSession, ...prev]);
    setCurrentSessionId(newSession.id);
    setMessages([]);
  };

  const handleSelectSession = (sessionId) => {
    const session = chatSessions.find(s => s.id === sessionId);
    if (session) {
      setCurrentSessionId(sessionId);
      setMessages(session.messages || []);
    }
  };

  const handleDeleteSession = (sessionId) => {
    setChatSessions(prev => prev.filter(s => s.id !== sessionId));
    if (currentSessionId === sessionId) {
      const remaining = chatSessions.filter(s => s.id !== sessionId);
      if (remaining.length > 0) {
        setCurrentSessionId(remaining[0].id);
        setMessages(remaining[0].messages || []);
      } else {
        setCurrentSessionId(null);
        setMessages([]);
      }
    }
  };

  const handleSendMessage = useCallback(async (messageText = inputMessage) => {
    if (!messageText.trim() || isTyping) return;

    // Create new session if none exists
    if (!currentSessionId) {
      const newSession = {
        id: Date.now().toString(),
        title: messageText.slice(0, 30),
        preview: messageText.slice(0, 50) + "...",
        date: new Date().toLocaleDateString("en-US", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
        messages: []
      };
      setChatSessions(prev => [newSession, ...prev]);
      setCurrentSessionId(newSession.id);
    }

    const userMessage = {
      id: Date.now(),
      type: "user",
      content: messageText,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setInputMessage("");
    setIsTyping(true);
    setCurrentResponse("");

    try {
      const modelMode = selectedModel === "savi" ? "sav" : "jarwis";
      const response = await chatAPI.sendMessage(messageText, scanId, modelMode);

      if (response.ok) {
        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let fullResponse = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          const chunk = decoder.decode(value);
          const lines = chunk.split("\n");

          for (const line of lines) {
            if (line.startsWith("data: ")) {
              try {
                const data = JSON.parse(line.slice(6));
                if (data.type === "chunk") {
                  fullResponse += data.content;
                  setCurrentResponse(fullResponse);
                } else if (data.type === "end") {
                  // Update token usage
                  const newTokens = tokenUsage + (fullResponse.length * 1.3); // Rough estimate
                  setTokenUsage(newTokens);
                  localStorage.setItem("jarwis_token_usage", JSON.stringify({
                    tokens: newTokens,
                    date: new Date().toDateString()
                  }));
                  
                  setMessages((prev) => [...prev, {
                    id: Date.now(),
                    type: "bot",
                    content: fullResponse,
                    timestamp: new Date(),
                    model: selectedModel
                  }]);
                  setCurrentResponse("");
                }
              } catch (e) { /* ignore parse errors */ }
            }
          }
        }
      } else {
        throw new Error("API request failed");
      }
    } catch (error) {
      console.error("Chat error:", error);
      setMessages((prev) => [...prev, {
        id: Date.now(),
        type: "bot",
        content: "I'm having trouble connecting right now. Please try again in a moment.",
        timestamp: new Date(),
        model: selectedModel,
        isError: true
      }]);
    }

    setIsTyping(false);
    setCurrentResponse("");
  }, [inputMessage, isTyping, currentSessionId, selectedModel, scanId, tokenUsage]);

  const handleKeyPress = (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const formatTimestamp = (timestamp) => {
    if (!timestamp) return "";
    const date = new Date(timestamp);
    return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };

  const formatMessage = (content) => {
    if (!content) return "";
    return content
      .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre class="bg-slate-900 p-4 rounded-xl overflow-x-auto my-3 text-sm border border-slate-700"><code class="text-emerald-400 font-mono">$2</code></pre>')
      .replace(/`([^`]+)`/g, '<code class="bg-slate-800/80 px-2 py-1 rounded-md text-cyan-400 text-sm font-mono">$1</code>')
      .replace(/\*\*(.*?)\*\*/g, '<strong class="text-white font-semibold">$1</strong>')
      .replace(/\n/g, '<br/>');
  };

  const quickActions = [
    { icon: "🔐", text: "SQL Injection fix", color: "from-red-500/20 to-orange-500/20" },
    { icon: "🛡️", text: "Prevent XSS attacks", color: "from-blue-500/20 to-cyan-500/20" },
    { icon: "🔑", text: "Secure authentication", color: "from-green-500/20 to-emerald-500/20" },
    { icon: "🌐", text: "API security tips", color: "from-purple-500/20 to-pink-500/20" },
    { icon: "⚡", text: "CSRF protection", color: "from-yellow-500/20 to-amber-500/20" },
  ];

  if (!hasChatbotAccess) {
    return (
      <MiftyJarwisLayout>
        <UpgradeRequired isDarkMode={isDarkMode} onNavigate={navigate} />
      </MiftyJarwisLayout>
    );
  }

  return (
    <MiftyJarwisLayout>
      <div className="flex h-[calc(100vh-80px)]">
        {/* Chat History Sidebar */}
        {sidebarOpen && (
          <ChatHistorySidebar
            isDarkMode={isDarkMode}
            chatSessions={chatSessions}
            currentSessionId={currentSessionId}
            onSelectSession={handleSelectSession}
            onNewChat={handleNewChat}
            onDeleteSession={handleDeleteSession}
            searchQuery={historySearchQuery}
            onSearchChange={setHistorySearchQuery}
            tokenUsage={tokenUsage}
            isEnterprise={isEnterprise}
          />
        )}

        {/* Main Chat Area */}
        <div className="flex-1 flex flex-col min-w-0">
          {/* Header */}
          <div className={`flex-shrink-0 px-6 py-4 flex items-center justify-between border-b backdrop-blur-sm ${isDarkMode ? "border-slate-700/50 bg-slate-900/80" : "border-gray-200 bg-white/80"}`}>
            <div className="flex items-center gap-4">
              {/* Toggle Sidebar */}
              <button
                onClick={() => setSidebarOpen(!sidebarOpen)}
                className={`p-2.5 rounded-xl transition-all ${isDarkMode ? "hover:bg-slate-700 text-gray-400 hover:text-white" : "hover:bg-gray-100 text-gray-600 hover:text-gray-900"}`}
              >
                <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  {sidebarOpen ? (
                    <path strokeLinecap="round" strokeLinejoin="round" d="M11 19l-7-7 7-7m8 14l-7-7 7-7" />
                  ) : (
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
                  )}
                </svg>
              </button>
              
              <div className="flex items-center gap-3">
                <div className={`w-11 h-11 rounded-xl flex items-center justify-center ${isDarkMode ? "bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10" : "bg-gradient-to-br from-cyan-50 to-blue-50 border border-cyan-200"}`}>
                  <JarwisLogo className="w-7 h-7" />
                </div>
                <div>
                  <h1 className={`text-lg font-bold ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                    Jarwis AGI
                  </h1>
                  <p className={`text-xs flex items-center gap-1.5 ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                    <span className="w-2 h-2 bg-emerald-500 rounded-full animate-pulse"></span>
                    Security Intelligence Assistant
                  </p>
                </div>
              </div>
            </div>

            {/* Model Selector */}
            <div className={`flex items-center gap-1 p-1.5 rounded-2xl ${isDarkMode ? "bg-slate-800/80 border border-slate-700" : "bg-gray-100 border border-gray-200"}`}>
              <button
                onClick={() => setSelectedModel("suru")}
                className={`px-5 py-2.5 rounded-xl text-sm font-medium transition-all flex items-center gap-2 ${
                  selectedModel === "suru"
                    ? "bg-gradient-to-r from-cyan-500 to-blue-600 text-white shadow-lg shadow-cyan-500/30"
                    : isDarkMode ? "text-gray-400 hover:text-white hover:bg-slate-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-200"
                }`}
              >
                <span className="text-lg">⚡</span>
                <span>Suru 1.1</span>
              </button>
              <button
                onClick={() => isEnterprise ? setSelectedModel("savi") : navigate("/pricing")}
                className={`px-5 py-2.5 rounded-xl text-sm font-medium transition-all flex items-center gap-2 ${
                  selectedModel === "savi"
                    ? "bg-gradient-to-r from-purple-500 to-pink-600 text-white shadow-lg shadow-purple-500/30"
                    : isDarkMode ? "text-gray-400 hover:text-white hover:bg-slate-700" : "text-gray-600 hover:text-gray-900 hover:bg-gray-200"
                } ${!isEnterprise ? "opacity-60" : ""}`}
              >
                <span className="text-lg">🧠</span>
                <span>Savi 3.1</span>
                {!isEnterprise && (
                  <span className={`text-xs px-2 py-0.5 rounded-full font-semibold ${isDarkMode ? "bg-amber-500/20 text-amber-400" : "bg-amber-100 text-amber-700"}`}>
                    ENT
                  </span>
                )}
              </button>
            </div>
          </div>

          {/* Messages Area */}
          <div className={`flex-1 overflow-y-auto p-6 ${isDarkMode ? "bg-gradient-to-b from-slate-900/50 to-slate-950/50" : "bg-gradient-to-b from-gray-50 to-white"}`}>
            {messages.length === 0 ? (
              /* Welcome Screen */
              <div className="flex flex-col items-center justify-center h-full text-center max-w-3xl mx-auto">
                {/* Animated Logo */}
                <div className={`relative w-24 h-24 rounded-3xl flex items-center justify-center mb-8 ${isDarkMode ? "bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30" : "bg-gradient-to-br from-cyan-50 to-blue-50 border border-cyan-200"}`}>
                  <JarwisLogo className="w-14 h-14" />
                  <div className="absolute -inset-1 bg-gradient-to-r from-cyan-500 to-blue-600 rounded-3xl blur-xl opacity-20 animate-pulse"></div>
                </div>
                
                <h2 className={`text-3xl font-bold mb-3 ${isDarkMode ? "text-white" : "text-gray-900"}`}>
                  How can I help you today?
                </h2>
                <p className={`text-base mb-10 max-w-lg ${isDarkMode ? "text-gray-400" : "text-gray-500"}`}>
                  I'm Jarwis, your AI security assistant. Ask me about vulnerabilities, security best practices, or get help analyzing your scan results.
                </p>
                
                {/* Quick Action Cards */}
                <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-4 w-full">
                  {quickActions.map((action, index) => (
                    <button
                      key={index}
                      onClick={() => handleSendMessage(action.text)}
                      className={`group p-5 rounded-2xl text-left transition-all hover:scale-105 hover:-translate-y-1 ${
                        isDarkMode 
                          ? `bg-gradient-to-br ${action.color} border border-slate-700/50 hover:border-cyan-500/50` 
                          : "bg-white border border-gray-200 hover:border-cyan-300 hover:shadow-xl"
                      }`}
                    >
                      <span className="text-3xl mb-3 block group-hover:scale-110 transition-transform">{action.icon}</span>
                      <span className={`text-sm font-medium ${isDarkMode ? "text-gray-300" : "text-gray-700"}`}>
                        {action.text}
                      </span>
                    </button>
                  ))}
                </div>
                
                {/* Scan context hint */}
                {scanId && (
                  <div className={`mt-8 px-6 py-4 rounded-2xl flex items-center gap-3 ${isDarkMode ? "bg-emerald-500/10 border border-emerald-500/30" : "bg-emerald-50 border border-emerald-200"}`}>
                    <svg className={`w-5 h-5 ${isDarkMode ? "text-emerald-400" : "text-emerald-600"}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                    </svg>
                    <span className={`text-sm ${isDarkMode ? "text-emerald-300" : "text-emerald-700"}`}>
                      Scan context loaded - I can help analyze your findings
                    </span>
                  </div>
                )}
              </div>
            ) : (
              /* Chat Messages */
              <div className="max-w-4xl mx-auto space-y-6">
                {messages.map((message) => (
                  <div key={message.id} className={`flex ${message.type === "user" ? "justify-end" : "justify-start"}`}>
                    <div className={`flex items-start gap-3 max-w-[85%] ${message.type === "user" ? "flex-row-reverse" : ""}`}>
                      {/* Avatar */}
                      <div className={`flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center ${
                        message.type === "user"
                          ? "bg-gradient-to-br from-blue-500 to-blue-600 shadow-lg shadow-blue-500/30"
                          : isDarkMode 
                            ? "bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30 shadow-lg shadow-cyan-500/10" 
                            : "bg-gradient-to-br from-cyan-50 to-blue-50 border border-cyan-200"
                      }`}>
                        {message.type === "user" ? (
                          <svg className="w-5 h-5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                          </svg>
                        ) : (
                          <JarwisLogo className="w-6 h-6" />
                        )}
                      </div>

                      {/* Message Bubble */}
                      <div className={`rounded-2xl overflow-hidden ${
                        message.type === "user"
                          ? "bg-gradient-to-br from-blue-500 to-blue-600 text-white shadow-lg shadow-blue-500/20"
                          : message.isError
                            ? isDarkMode ? "bg-red-500/10 border border-red-500/30" : "bg-red-50 border border-red-200"
                            : isDarkMode ? "bg-slate-800/80 border border-slate-700/50 shadow-xl" : "bg-white border border-gray-200 shadow-lg"
                      }`}>
                        {/* Bot Message Header */}
                        {message.type === "bot" && !message.isError && (
                          <div className={`flex items-center gap-2 px-4 py-2 border-b ${isDarkMode ? "border-slate-700/50 bg-slate-800/50" : "border-gray-100 bg-gray-50/50"}`}>
                            <JarwisLogo className="w-4 h-4" />
                            <span className={`text-xs font-semibold ${
                              message.model === "savi" 
                                ? isDarkMode ? "text-purple-400" : "text-purple-600"
                                : isDarkMode ? "text-cyan-400" : "text-cyan-600"
                            }`}>
                              {message.model === "savi" ? "Savi 3.1 Thinking" : "Suru 1.1"}
                            </span>
                            <span className={`text-xs ${isDarkMode ? "text-gray-600" : "text-gray-400"}`}>•</span>
                            <span className={`text-xs ${isDarkMode ? "text-gray-500" : "text-gray-400"}`}>
                              {formatTimestamp(message.timestamp)}
                            </span>
                          </div>
                        )}
                        
                        <div className="p-4">
                          <div 
                            className={`prose prose-sm max-w-none ${isDarkMode ? "prose-invert" : ""} ${message.type === "user" ? "text-white" : ""}`}
                            dangerouslySetInnerHTML={{ __html: formatMessage(message.content) }}
                          />
                          {message.type === "user" && (
                            <div className="text-xs mt-2 text-blue-200">
                              {formatTimestamp(message.timestamp)}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}

                {/* Streaming Response */}
                {isTyping && currentResponse && (
                  <div className="flex justify-start">
                    <div className="flex items-start gap-3 max-w-[85%]">
                      <div className={`flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center ${isDarkMode ? "bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30" : "bg-gradient-to-br from-cyan-50 to-blue-50 border border-cyan-200"}`}>
                        <JarwisLogo className="w-6 h-6" animated />
                      </div>
                      <div className={`rounded-2xl overflow-hidden ${isDarkMode ? "bg-slate-800/80 border border-slate-700/50 shadow-xl" : "bg-white border border-gray-200 shadow-lg"}`}>
                        <div className={`flex items-center gap-2 px-4 py-2 border-b ${isDarkMode ? "border-slate-700/50 bg-slate-800/50" : "border-gray-100 bg-gray-50/50"}`}>
                          <JarwisLogo className="w-4 h-4" animated />
                          <span className={`text-xs font-semibold ${isDarkMode ? "text-cyan-400" : "text-cyan-600"}`}>
                            {selectedModel === "savi" ? "Savi 3.1 Thinking" : "Suru 1.1"}
                          </span>
                          <span className="flex gap-1 ml-2">
                            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse"></span>
                            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse" style={{ animationDelay: "150ms" }}></span>
                            <span className="w-1.5 h-1.5 bg-cyan-400 rounded-full animate-pulse" style={{ animationDelay: "300ms" }}></span>
                          </span>
                        </div>
                        <div className="p-4">
                          <div className={`prose prose-sm max-w-none ${isDarkMode ? "prose-invert" : ""}`} dangerouslySetInnerHTML={{ __html: formatMessage(currentResponse) }} />
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Typing Indicator */}
                {isTyping && !currentResponse && (
                  <div className="flex justify-start">
                    <div className="flex items-start gap-3">
                      <div className={`flex-shrink-0 w-10 h-10 rounded-xl flex items-center justify-center ${isDarkMode ? "bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/30" : "bg-gradient-to-br from-cyan-50 to-blue-50 border border-cyan-200"}`}>
                        <JarwisLogo className="w-6 h-6" animated />
                      </div>
                      <div className={`rounded-2xl px-5 py-4 ${isDarkMode ? "bg-slate-800/80 border border-slate-700/50" : "bg-white border border-gray-200"}`}>
                        <div className="flex items-center gap-2">
                          <div className="w-2.5 h-2.5 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: "0ms" }}></div>
                          <div className="w-2.5 h-2.5 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: "150ms" }}></div>
                          <div className="w-2.5 h-2.5 bg-cyan-400 rounded-full animate-bounce" style={{ animationDelay: "300ms" }}></div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <div ref={messagesEndRef} />
              </div>
            )}
          </div>

          {/* Input Area */}
          <div className={`flex-shrink-0 p-4 border-t backdrop-blur-sm ${isDarkMode ? "border-slate-700/50 bg-slate-900/80" : "border-gray-200 bg-white/80"}`}>
            <div className="max-w-4xl mx-auto">
              <div className={`flex items-end gap-3 p-3 rounded-2xl ${isDarkMode ? "bg-slate-800/80 border border-slate-700" : "bg-gray-100 border border-gray-200"}`}>
                {/* File Upload */}
                <input type="file" ref={fileInputRef} className="hidden" accept=".txt,.json,.log,.xml,.html,.js,.py,.yaml,.yml" />
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={isTyping}
                  className={`p-3 rounded-xl transition-all ${isDarkMode ? "hover:bg-slate-700 text-gray-400 hover:text-white" : "hover:bg-gray-200 text-gray-500 hover:text-gray-700"} ${isTyping ? "opacity-50 cursor-not-allowed" : ""}`}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13" />
                  </svg>
                </button>

                {/* Text Input */}
                <textarea
                  value={inputMessage}
                  onChange={(e) => {
                    setInputMessage(e.target.value);
                    e.target.style.height = "auto";
                    e.target.style.height = Math.min(e.target.scrollHeight, 200) + "px";
                  }}
                  onKeyDown={handleKeyPress}
                  placeholder="Ask Jarwis anything about security..."
                  disabled={isTyping}
                  rows={1}
                  className={`flex-1 px-4 py-3 rounded-xl resize-none outline-none bg-transparent ${isDarkMode ? "text-white placeholder-gray-500" : "text-gray-900 placeholder-gray-400"} ${isTyping ? "opacity-50" : ""}`}
                  style={{ minHeight: "48px", maxHeight: "200px" }}
                />

                {/* Send Button */}
                <button
                  onClick={() => handleSendMessage()}
                  disabled={isTyping || !inputMessage.trim()}
                  className={`p-3 rounded-xl transition-all ${
                    isTyping || !inputMessage.trim()
                      ? "bg-gray-600 text-gray-400 cursor-not-allowed"
                      : "bg-gradient-to-r from-cyan-500 to-blue-600 text-white hover:from-cyan-400 hover:to-blue-500 shadow-lg shadow-cyan-500/30 hover:shadow-cyan-500/50"
                  }`}
                >
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
                  </svg>
                </button>
              </div>
              
              <p className={`text-xs text-center mt-3 ${isDarkMode ? "text-gray-600" : "text-gray-400"}`}>
                Jarwis AGI • Powered by BKD Labs • {selectedModel === "savi" ? "Savi 3.1 Thinking" : "Suru 1.1"} Model
              </p>
            </div>
          </div>
        </div>
      </div>
    </MiftyJarwisLayout>
  );
};

export default JarwisChatbot;
