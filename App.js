import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import { motion, AnimatePresence } from 'framer-motion';
import toast, { Toaster } from 'react-hot-toast';import { 
  MessageCircle, 
  Send, 
  Search, 
  Settings, 
  Lock, 
  Unlock,
  Timer,
  Shield,
  User,
  LogOut,
  UserPlus,
  Users
} from 'lucide-react';
import './App.css';

const API_BASE = process.env.REACT_APP_API_BASE || 'http://localhost:5000/api';

const App = () => {
  // Authentication state
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  
  // UI state
  const [activeView, setActiveView] = useState('login');
  const [sidebarTab, setSidebarTab] = useState('conversations'); // 'conversations' or 'contacts'
  const [selectedConversation, setSelectedConversation] = useState(null);
  const [showProfile, setShowProfile] = useState(false);
  const [showDecryptionPanel, setShowDecryptionPanel] = useState(false);
  
  // Data state
  const [conversations, setConversations] = useState([]);
  const [contacts, setContacts] = useState([]);
  const [messages, setMessages] = useState([]);
  const [decryptionRequests, setDecryptionRequests] = useState([]);
  const [searchResults, setSearchResults] = useState([]);
  
  // Form state
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [registerForm, setRegisterForm] = useState({ username: '', password: '', bio: '' });
  const [messageText, setMessageText] = useState('');
  const [senderKey, setSenderKey] = useState('');
  const [keyHint, setKeyHint] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [contactSearchQuery, setContactSearchQuery] = useState('');
  
  // Socket connection
  const [socket, setSocket] = useState(null);
  const messagesEndRef = useRef(null);
  
  // Revolutionary features
  const [typingUsers, setTypingUsers] = useState([]);
  const [isTyping, setIsTyping] = useState(false);
  const [destructingMessages, setDestructingMessages] = useState(new Set());

 // Initialize socket connection
useEffect(() => {
  if (token && !socket) {
    const newSocket = io('http://localhost:5000', {
      auth: { token }
    });
    
    newSocket.on('connect', () => {
      console.log('Revolutionary socket connected');
      setSocket(newSocket);
    });

    newSocket.on('new_message', (message) => {
      if (selectedConversation && message.conversation_id === selectedConversation.id) {
        setMessages(prev => [...prev, message]);
      }
      fetchConversations();
    });

    newSocket.on('decryption_request', (request) => {
      toast(`🔓 Decryption request from ${request.requester_username}`, {
        duration: 5000,
        icon: '🔑'
      });
      fetchDecryptionRequests();
    });

    newSocket.on('message_decrypted', (data) => {
      const { message_id, content, self_destruct_timer } = data;
      
      setMessages(prev => prev.map(msg => 
        msg.id === message_id 
          ? { ...msg, content, is_decrypted: true }
          : msg
      ));

      setTimeout(() => {
        setDestructingMessages(prev => new Set(prev).add(message_id));
        
        setTimeout(() => {
          setMessages(prev => prev.filter(msg => msg.id !== message_id));
          setDestructingMessages(prev => {
            const newSet = new Set(prev);
            newSet.delete(message_id);
            return newSet;
          });
          
          if (newSocket) {
            newSocket.emit('message_self_destructed', { message_id });
          }
        }, 2000);
        
      }, self_destruct_timer * 1000);
    });

    newSocket.on('user_typing', (data) => {
      if (data.is_typing) {
        setTypingUsers(prev => [...prev.filter(u => u.user_id !== data.user_id), data]);
      } else {
        setTypingUsers(prev => prev.filter(u => u.user_id !== data.user_id));
      }
    });

    newSocket.on('error', (error) => {
      toast.error(error.message);
    });

    return () => {
      newSocket.close();
    };
  }
}, [token]);

  // Authentication functions
  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${API_BASE}/auth/login`, loginForm);
      const { token, user } = response.data;
      
      localStorage.setItem('token', token);
      setToken(token);
      setCurrentUser(user);
      setIsAuthenticated(true);
      setActiveView('chat');
      
      toast.success('🚀 Welcome to Vanish!');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Login failed');
    }
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post(`${API_BASE}/auth/register`, registerForm);
      const { token, user } = response.data;
      
      localStorage.setItem('token', token);
      setToken(token);
      setCurrentUser(user);
      setIsAuthenticated(true);
      setActiveView('chat');
      
      toast.success('🎉 Account created successfully!');
    } catch (error) {
      toast.error(error.response?.data?.error || 'Registration failed');
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setCurrentUser(null);
    setIsAuthenticated(false);
    setActiveView('login');
    if (socket) {
      socket.disconnect();
      setSocket(null);
    }
    toast.success('👋 Logged out successfully');
  };

  // Data fetching functions
  const fetchConversations = async () => {
    try {
      const response = await axios.get(`${API_BASE}/conversations`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setConversations(response.data.conversations);
    } catch (error) {
      toast.error('Failed to fetch conversations');
    }
  };

  const fetchContacts = async () => {
    try {
      const response = await axios.get(`${API_BASE}/contacts`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setContacts(response.data.contacts);
    } catch (error) {
      toast.error('Failed to fetch contacts');
    }
  };

  const fetchMessages = async (conversationId) => {
    try {
      const response = await axios.get(`${API_BASE}/conversations/${conversationId}/messages`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setMessages(response.data.messages);
    } catch (error) {
      toast.error('Failed to fetch messages');
    }
  };

  const fetchDecryptionRequests = async () => {
    try {
      const response = await axios.get(`${API_BASE}/decryption-requests`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setDecryptionRequests(response.data.requests);
    } catch (error) {
      console.error('Failed to fetch decryption requests');
    }
  };

  // Contact management functions
  const searchUsers = async (query) => {
    if (!query || query.trim().length < 2) {
      setSearchResults([]);
      return;
    }
    
    try {
      const response = await axios.get(`${API_BASE}/contacts/search?query=${encodeURIComponent(query)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setSearchResults(response.data.users);
    } catch (error) {
      toast.error('Search failed');
    }
  };

const addContact = async (contactId, nickname) => {
  try {
    await axios.post(`${API_BASE}/contacts`, {
      contact_id: contactId,
      nickname: nickname
    }, {
      headers: { Authorization: `Bearer ${token}` }
    });
    
    toast.success('Contact added successfully!');
    fetchContacts();
    setSearchResults([]);
    setContactSearchQuery('');
  } catch (error) {
    toast.error(error.response?.data?.error || 'Failed to add contact');
  }
};

  const startDirectConversation = async (contactId) => {
    try {
      const response = await axios.post(`${API_BASE}/conversations/direct`, {
        contact_id: contactId
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      fetchConversations();
      setSidebarTab('conversations');
      
      // Find and select the new conversation
      setTimeout(() => {
        const newConv = conversations.find(c => 
          c.id === response.data.conversation_id || 
          c.id === response.data.conversation?.id
        );
        if (newConv) {
          setSelectedConversation(newConv);
        }
      }, 500);
      
      toast.success('Conversation started!');
    } catch (error) {
      toast.error('Failed to start conversation');
    }
  };

  // Revolutionary messaging functions
  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!messageText.trim() || !senderKey.trim() || !selectedConversation) return;

    try {
      const messageData = {
        conversation_id: selectedConversation.id,
        content: messageText,
        sender_key: senderKey,
        key_hint: keyHint || 'No hint provided',
        message_type: 'text'
      };

      if (socket) {
        socket.emit('send_message', messageData);
      }
      
      setMessageText('');
      setSenderKey('');
      setKeyHint('');
      
    } catch (error) {
      toast.error('Failed to send message');
    }
  };

  const handleRequestDecryption = (messageId) => {
    if (socket) {
      socket.emit('request_decryption', { message_id: messageId });
      toast.success('🔓 Decryption request sent');
    }
  };

  const handleProvideDecryptionKey = (requestId, key, approve = true) => {
    if (socket) {
      socket.emit('provide_decryption_key', {
        request_id: requestId,
        decryption_key: key,
        approve
      });
      
      setDecryptionRequests(prev => 
        prev.filter(req => req.id !== requestId)
      );
      
      toast.success(approve ? '🔑 Message decrypted' : '❌ Request denied');
    }
  };

  // Typing indicators
  const handleTyping = () => {
    if (selectedConversation && socket) {
      if (!isTyping) {
        setIsTyping(true);
        socket.emit('typing', {
          conversation_id: selectedConversation.id,
          is_typing: true
        });
        
        setTimeout(() => {
          setIsTyping(false);
          socket.emit('typing', {
            conversation_id: selectedConversation.id,
            is_typing: false
          });
        }, 3000);
      }
    }
  };

  // Load initial data
 useEffect(() => {
  const initializeData = async () => {
    if (token) {
      setIsAuthenticated(true);
      setActiveView('chat');
      await fetchConversations();
      await fetchContacts();
      await fetchDecryptionRequests();
    }
  };
  
  initializeData();
}, [token]);

useEffect(() => {
  const handleConversationChange = async () => {
    if (selectedConversation) {
      await fetchMessages(selectedConversation.id);
      if (socket) {
        socket.emit('join_conversation', { conversation_id: selectedConversation.id });
      }
    }
  };
  
  handleConversationChange();
}, [selectedConversation, socket]);

  // Auto scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Contact search effect
  useEffect(() => {
  const handleSearch = async () => {
    if (sidebarTab === 'contacts') {
      await searchUsers(contactSearchQuery);
    }
  };

  const delayedSearch = setTimeout(handleSearch, 300);
  return () => clearTimeout(delayedSearch);
}, [contactSearchQuery, sidebarTab]);

  // Revolutionary login/register interface
  if (!isAuthenticated) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="auth-header"
          >
            <Shield className="auth-logo" size={48} />
            <h1>Vanish</h1>
            <p>Revolutionary Ephemeral Messaging</p>
          </motion.div>

          <div className="auth-tabs">
            <button
              className={activeView === 'login' ? 'active' : ''}
              onClick={() => setActiveView('login')}
            >
              Login
            </button>
            <button
              className={activeView === 'register' ? 'active' : ''}
              onClick={() => setActiveView('register')}
            >
              Register
            </button>
          </div>

          <AnimatePresence mode="wait">
            {activeView === 'login' ? (
              <motion.form
                key="login"
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 20 }}
                onSubmit={handleLogin}
                className="auth-form"
              >
                <div className="form-group">
                  <input
                    type="text"
                    placeholder="Username"
                    value={loginForm.username}
                    onChange={(e) => setLoginForm({...loginForm, username: e.target.value})}
                    required
                  />
                </div>
                <div className="form-group">
                  <input
                    type="password"
                    placeholder="Password"
                    value={loginForm.password}
                    onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                    required
                  />
                </div>
                <button type="submit" className="auth-button">
                  <Lock size={20} />
                  Secure Login
                </button>
              </motion.form>
            ) : (
              <motion.form
                key="register"
                initial={{ opacity: 0, x: 20 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -20 }}
                onSubmit={handleRegister}
                className="auth-form"
              >
                <div className="form-group">
                  <input
                    type="text"
                    placeholder="Username"
                    value={registerForm.username}
                    onChange={(e) => setRegisterForm({...registerForm, username: e.target.value})}
                    required
                  />
                </div>
                <div className="form-group">
                  <input
                    type="password"
                    placeholder="Password"
                    value={registerForm.password}
                    onChange={(e) => setRegisterForm({...registerForm, password: e.target.value})}
                    required
                  />
                </div>
                <div className="form-group">
                  <input
                    type="text"
                    placeholder="Bio (optional)"
                    value={registerForm.bio}
                    onChange={(e) => setRegisterForm({...registerForm, bio: e.target.value})}
                  />
                </div>
                <button type="submit" className="auth-button">
                  <Shield size={20} />
                  Create Account
                </button>
              </motion.form>
            )}
          </AnimatePresence>
        </div>
      </div>
    );
  }

  // Revolutionary WhatsApp-like main interface
  return (
    <div className="chat-container">
      <Toaster position="top-right" />
      
      {/* Sidebar */}
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="user-info">
            <div className="avatar">
              <User size={20} />
            </div>
            <span>{currentUser?.username}</span>
          </div>
          <div className="header-actions">
            <button onClick={() => setShowDecryptionPanel(!showDecryptionPanel)}>
              <Unlock size={20} />
              {decryptionRequests.length > 0 && (
                <span className="notification-badge">{decryptionRequests.length}</span>
              )}
            </button>
            <button onClick={() => setShowProfile(!showProfile)}>
              <Settings size={20} />
            </button>
            <button onClick={handleLogout}>
              <LogOut size={20} />
            </button>
          </div>
        </div>

       {/* Search Bar */}
        <div className="search-bar">
          <Search size={18} />
          <input
            type="text"
            placeholder={sidebarTab === 'conversations' ? 'Search conversations...' : 'Search users...'}
            value={sidebarTab === 'conversations' ? searchQuery : contactSearchQuery}
            onChange={(e) => {
              if (sidebarTab === 'conversations') {
                setSearchQuery(e.target.value);
              } else {
                setContactSearchQuery(e.target.value);
              }
            }}
          />
          <button
            onClick={() => setSidebarTab(sidebarTab === 'conversations' ? 'contacts' : 'conversations')}
            style={{ 
              background: 'rgba(100, 255, 218, 0.2)', 
              border: '1px solid rgba(100, 255, 218, 0.3)',
              borderRadius: '8px',
              padding: '8px',
              color: '#64ffda'
            }}
          >
            {sidebarTab === 'conversations' ? <Users size={18} /> : <MessageCircle size={18} />}
          </button>
        </div>

        {/* Conversations Tab */}
        {sidebarTab === 'conversations' && (
          <div className="conversations-list">
            {conversations
              .filter(conv => 
                !searchQuery || 
                conv.display_name.toLowerCase().includes(searchQuery.toLowerCase())
              )
              .map((conv) => (
                <motion.div
                  key={conv.id}
                  className={`conversation-item ${selectedConversation?.id === conv.id ? 'active' : ''}`}
                  onClick={() => setSelectedConversation(conv)}
                  whileHover={{ backgroundColor: 'rgba(255,255,255,0.05)' }}
                  whileTap={{ scale: 0.98 }}
                >
                  <div className="conversation-avatar">
                    <User size={24} />
                    {conv.contact_online && <div className="online-indicator" />}
                  </div>
                  <div className="conversation-info">
                    <div className="conversation-name">{conv.display_name}</div>
                    <div className="conversation-preview">
                      {conv.message_count} encrypted messages
                    </div>
                  </div>
                  <div className="conversation-meta">
                    <Timer size={14} />
                  </div>
                </motion.div>
              ))}
          </div>
        )}

        {/* Contacts Tab */}
        {sidebarTab === 'contacts' && (
          <div className="conversations-list">
            {/* Search Results */}
            {contactSearchQuery && searchResults.length > 0 && (
              <>
                <div style={{ 
                  padding: '15px 20px 10px', 
                  fontSize: '0.875rem', 
                  fontWeight: '600', 
                  color: '#64ffda', 
                  textTransform: 'uppercase', 
                  letterSpacing: '0.5px' 
                }}>
                  Search Results
                </div>
                {searchResults.map((user) => (
                  <div key={user.id} className="conversation-item">
                    <div className="conversation-avatar">
                      <User size={24} />
                    </div>
                    <div className="conversation-info">
                      <div className="conversation-name">{user.username}</div>
                      <div className="conversation-preview">{user.bio}</div>
                    </div>
                    <div className="conversation-meta">
                      {!user.is_contact && (
                        <button
                          onClick={() => addContact(user.id, user.username)}
                          style={{ 
                            padding: '8px', 
                            background: 'rgba(100, 255, 218, 0.2)', 
                            border: '1px solid rgba(100, 255, 218, 0.3)', 
                            borderRadius: '50%', 
                            color: '#64ffda', 
                            cursor: 'pointer' 
                          }}
                        >
                          <UserPlus size={16} />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </>
            )}

            {/* User's Contacts */}
            <div style={{ 
              padding: '15px 20px 10px', 
              fontSize: '0.875rem', 
              fontWeight: '600', 
              color: '#64ffda', 
              textTransform: 'uppercase', 
              letterSpacing: '0.5px' 
            }}>
              My Contacts
            </div>
            {contacts.map((contact) => (
              <div key={contact.contact_id} className="conversation-item">
                <div className="conversation-avatar">
                  <User size={24} />
                  {contact.is_online && <div className="online-indicator" />}
                </div>
                <div className="conversation-info">
                  <div className="conversation-name">{contact.nickname || contact.username}</div>
                  <div className="conversation-preview">
                    {contact.is_online ? 'Online' : 'Last seen recently'}
                  </div>
                </div>
                <div className="conversation-meta">
                  <button
                    onClick={() => startDirectConversation(contact.user_id)}
                    style={{ 
                      padding: '8px', 
                      background: 'rgba(100, 255, 218, 0.2)', 
                      border: '1px solid rgba(100, 255, 218, 0.3)', 
                      borderRadius: '50%', 
                      color: '#64ffda', 
                      cursor: 'pointer' 
                    }}
                  >
                    <MessageCircle size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Main Chat Area */}
      <div className="chat-area">
        {selectedConversation ? (
          <>
            <div className="chat-header">
              <div className="chat-user-info">
                <div className="avatar">
                  <User size={20} />
                </div>
                <div>
                  <h3>{selectedConversation.display_name}</h3>
                  <span className={selectedConversation.contact_online ? 'online' : 'offline'}>
                    {selectedConversation.contact_online ? 'Online' : 'Offline'}
                  </span>
                </div>
              </div>
              <div className="chat-actions">
                <Shield size={20} />
                <span>End-to-End Encrypted</span>
              </div>
            </div>

            <div className="messages-area">
              <AnimatePresence>
                {messages.map((message) => (
                  <motion.div
                    key={message.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ 
                      opacity: destructingMessages.has(message.id) ? 0 : 1,
                      scale: destructingMessages.has(message.id) ? 0.8 : 1
                    }}
                    exit={{ opacity: 0, scale: 0.8 }}
                    className={`message ${message.sender_id === currentUser?.id ? 'sent' : 'received'}`}
                  >
                    <div className="message-content">
                      {message.content === '[ENCRYPTED - Double-click to request decryption]' ? (
                        <div 
                          className="encrypted-message"
                          onDoubleClick={() => handleRequestDecryption(message.id)}
                        >
                          <Lock size={16} />
                          <span>🔒 Encrypted Message - Double-click to decrypt</span>
                          <small>Hint: {message.sender_key_hint}</small>
                        </div>
                      ) : (
                        <div className="decrypted-message">
                          <Unlock size={16} />
                          <span>{message.content}</span>
                          <div className="destruction-timer">
                            <Timer size={12} />
                            Self-destructs in {message.self_destruct_timer}s
                          </div>
                        </div>
                      )}
                    </div>
                    <div className="message-time">
                      {new Date(message.created_at).toLocaleTimeString()}
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
              
              {typingUsers.length > 0 && (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="typing-indicator"
                >
                  {typingUsers[0].username} is typing...
                </motion.div>
              )}
              
              <div ref={messagesEndRef} />
            </div>

            <form onSubmit={handleSendMessage} className="message-input-area">
              <div className="encryption-controls">
                <input
                  type="password"
                  placeholder="🔑 Your decryption key"
                  value={senderKey}
                  onChange={(e) => setSenderKey(e.target.value)}
                  required
                />
                <input
                  type="text"
                  placeholder="💡 Key hint (optional)"
                  value={keyHint}
                  onChange={(e) => setKeyHint(e.target.value)}
                />
              </div>
              <div className="message-input-container">
                <input
                  type="text"
                  placeholder="Type a revolutionary message..."
                  value={messageText}
                  onChange={(e) => {
                    setMessageText(e.target.value);
                    handleTyping();
                  }}
                  required
                />
                <button type="submit">
                  <Send size={20} />
                </button>
              </div>
            </form>
          </>
        ) : (
          <div className="no-conversation">
            <MessageCircle size={64} />
            <h3>Select a conversation</h3>
            <p>Choose a contact to start a revolutionary encrypted conversation</p>
          </div>
        )}
      </div>

      {/* Decryption Requests Panel */}
      <AnimatePresence>
        {showDecryptionPanel && (
          <motion.div
            initial={{ x: 300, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 300, opacity: 0 }}
            className="decryption-panel"
          >
            <h3>🔓 Decryption Requests</h3>
            {decryptionRequests.map((request) => (
              <div key={request.id} className="decryption-request">
                <div className="request-info">
                  <strong>{request.requester_username}</strong> wants to decrypt your message
                  <small>Hint: {request.sender_key_hint}</small>
                </div>
                <div className="request-actions">
                  <input
                    type="password"
                    placeholder="Enter decryption key"
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        handleProvideDecryptionKey(request.id, e.target.value, true);
                      }
                    }}
                  />
                  <button onClick={() => handleProvideDecryptionKey(request.id, '', false)}>
                    Deny
                  </button>
                </div>
              </div>
            ))}
            {decryptionRequests.length === 0 && (
              <p>No pending decryption requests</p>
            )}
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default App;
