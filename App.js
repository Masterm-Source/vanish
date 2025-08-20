import React, { useState, useEffect, useRef } from 'react';
import axios from 'axios';
import io from 'socket.io-client';
import FileUploadModal from './components/FileUploadModal';
import FileMessage from './components/FileMessage';
import MediaViewer from './components/MediaViewer';
import LivePreview from './components/LivePreview';
import { Paperclip } from 'lucide-react'; // Add Paperclip icon
import { motion, AnimatePresence } from 'framer-motion';
import Picker, { Theme } from 'emoji-picker-react';
import toast, { Toaster } from 'react-hot-toast';import { 
  MessageCircle, 
  Send,
  Smile, 
  Search, 
  Settings, 
  Lock, 
  Unlock,
  Timer,
  Shield,
  User,
  LogOut,
  UserPlus,
  Volume2,
  VolumeX,
  Users
} from 'lucide-react';
import './App.css';
import KeyChangeModal from './components/KeyChangeModal';

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
  const [registerForm, setRegisterForm] = useState({ username: '', password: '', email: '', bio: '' });
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

// Add these new states after your existing state declarations
const [openDropdown, setOpenDropdown] = useState(null);
const [pendingDecryption, setPendingDecryption] = useState({});
const [decryptionInputs, setDecryptionInputs] = useState({});
const [isDecrypting, setIsDecrypting] = useState({});
const [successMessages, setSuccessMessages] = useState(new Set());
// ADD THIS NEW STATE
const [audioInitialized, setAudioInitialized] = useState(false);
const [inlineDecryptionKey, setInlineDecryptionKey] = useState('');
// ADD this state at the top of App.js
const [timerIntervals, setTimerIntervals] = useState({});
const [conversationKeys, setConversationKeys] = useState({}); // To hold the receiver's key for each convo
const [senderApprovals, setSenderApprovals] = useState({}); // Tracks if sender has approved a message
const [showKeyChangeModal, setShowKeyChangeModal] = useState(false);
const [conversationKeyStatus, setConversationKeyStatus] = useState({}); // e.g., { 123: true, 456: false }
const [showEmojiPicker, setShowEmojiPicker] = useState(false);
const [fileToUpload, setFileToUpload] = useState(null);
const [viewOnceMedia, setViewOnceMedia] = useState({ message: null, file: null });
const fileInputRef = useRef(null);
// State for our new audio files
const decryptionSoundRef = useRef(null);
const completionSoundRef = useRef(null);
const [isMuted, setIsMuted] = useState(false);
const typingSoundRef = useRef(null);
const notificationSoundRef = useRef(null);
const [liveDecoys, setLiveDecoys] = useState({});
// Sound effect functions using pre-loaded audio files
// Sound effect functions using on-demand loading and useRef

// ADD THIS ENTIRE NEW FUNCTION
const initializeAudio = () => {
  // Prevent running this more than once
  if (audioInitialized) return;

  console.log('Initializing all audio on user interaction...');
  
  // Decryption Sounds
  const decSound = new Audio('/sounds/decryption.mp3?v=1.0');
  decSound.loop = true;
  decryptionSoundRef.current = decSound;

  const compSound = new Audio('/sounds/complete.mp3?v=1.0');
  completionSoundRef.current = compSound;

  // **NEW**: Typing and Notification Sounds
  const typeSound = new Audio('/sounds/typing.mp3?v=1.0');
  typingSoundRef.current = typeSound;

  const notifSound = new Audio('/sounds/notification.mp3?v=1.0');
  notificationSoundRef.current = notifSound;

  // Pre-load all audio data
  decSound.load();
  compSound.load();
  typeSound.load();
  notifSound.load();

  setAudioInitialized(true);
};
// REPLACE the three old audio functions with these
const playCracklingSound = () => {
  if (decryptionSoundRef.current) {
    decryptionSoundRef.current.currentTime = 0; // Rewind before playing
    decryptionSoundRef.current.play().catch(error => console.error("Decryption sound play error:", error));
  }
};

const stopCracklingSound = () => {
  if (decryptionSoundRef.current) {
    decryptionSoundRef.current.pause();
  }
};

const playCompletionChime = () => {
  if (completionSoundRef.current) {
    completionSoundRef.current.currentTime = 0; // Rewind before playing
    completionSoundRef.current.play().catch(error => console.error("Completion sound play error:", error));
  }
};

const playTypingSound = () => {
    if (!isMuted && typingSoundRef.current) {
        typingSoundRef.current.currentTime = 0;
        typingSoundRef.current.play().catch(e => console.error("Typing sound error:", e));
    }
};

const playNotificationSound = () => {
    if (!isMuted && notificationSoundRef.current) {
        notificationSoundRef.current.currentTime = 0;
        notificationSoundRef.current.play().catch(e => console.error("Notification sound error:", e));
    }
};

// Initialize socket connection
useEffect(() => {
    if (token) {
        const newSocket = io('http://localhost:5000', {
            auth: { token }
        });

newSocket.on('connect', () => {
    console.log('Revolutionary socket connected:', newSocket.id);
    setSocket(newSocket);

    // Define the socket event handlers
    const setupSocketHandlers = () => {
      // Socket event handlers...
    }; // Closing brace for setupSocketHandlers

    setupSocketHandlers(); // Call the function
}); // Add this closing brace
    }

// Download handler function
const handleDownload = async (message) => {
    try {
        const downloadUrl = `${API_BASE}/files/download/${message.id}?token=${message.download_token}`;

        if (message.ephemeral_type === 'view_once') {
            toast.loading("Loading secure media...", { id: 'download-toast' });
            const response = await axios.get(downloadUrl, { responseType: 'blob' });
            const fileBlob = new Blob([response.data], { type: message.file_metadata.mimeType });
            setViewOnceMedia({ message: message, file: fileBlob });
            toast.dismiss('download-toast');

        } else { // 'standard' files
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.setAttribute('download', message.decrypted_metadata.originalName);
            document.body.appendChild(link);
            link.click();
            link.parentNode.removeChild(link);
        }
    } catch (error) {
        toast.error("Download failed. The secure link may have expired or been used already.");
        console.error("File download/view error:", error.response || error);
    }
};

const handleViewOnceComplete = (messageId) => {
    if (socket) {
        socket.emit('view_once_completed', { message_id: messageId });
    }
    setViewOnceMedia({ message: null, file: null }); // Close the viewer
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


  // Authentication functions
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

  // Dropdown management
const toggleMessageDropdown = (messageId) => {
  setOpenDropdown(openDropdown === messageId ? null : messageId);
};

// Format countdown timer
const formatCountdown = (expiresAt) => {
  if (!expiresAt) return '00:00';
  const now = new Date();
  const expiry = new Date(expiresAt);
  const secondsRemaining = Math.max(0, Math.floor((expiry - now) / 1000));
  
  const minutes = Math.floor(secondsRemaining / 60);
  const seconds = secondsRemaining % 60;
  
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
};

const handleInlineDecryptionRequest = (messageId) => {
  if (socket) {
    socket.emit('request_decryption', { message_id: messageId });
    toast.success('🔓 Decryption request sent');
  }
};

// Handle decryption input
const handleDecryptionInput = (messageId, value) => {
  setDecryptionInputs(prev => ({ ...prev, [messageId]: value }));
};

// Provide inline decryption key
// Provide inline decryption key
const handleProvideInlineKey = (messageId) => {
  const key = decryptionInputs[messageId];
  if (!key || !socket) return;

  socket.emit('sender_provide_key', {
    message_id: messageId,
    decryption_key: key,
  });

  // Optimistically remove the input box from the UI
  setPendingDecryption(prev => {
    const newState = { ...prev };
    delete newState[messageId];
    return newState;
  });

  // **THE FIX**: Immediately remove the corresponding notification from the panel.
  setDecryptionRequests(prevRequests => 
    prevRequests.filter(req => req.message_id !== messageId)
  );
};

// This function is called when the RECEIVER clicks "Finalize Decrypt".
const handleReceiverProvideKey = (messageId) => {
    // **THE FIX**: The key is now read from the new, isolated state.
    const key = inlineDecryptionKey; 
    if (!key || !socket) {
        toast.error("Please enter your Personal Decryption Key to finalize.");
        return;
    }

    socket.emit('receiver_provide_key', {
        message_id: messageId,
        decryption_key: key,
    });

    // **CRITICAL SECURITY STEP**: Immediately clear the key from the state after use.
    setInlineDecryptionKey('');
};

// Deny inline decryption
const handleDenyInlineDecryption = (messageId) => {
  setPendingDecryption(prev => {
    const newState = { ...prev };
    delete newState[messageId];
    return newState;
  });
  
  setDecryptionInputs(prev => {
    const newState = { ...prev };
    delete newState[messageId];
    return newState;
  });
  
  if (socket) {
    socket.emit('provide_inline_decryption', {
      message_id: messageId,
      approve: false
    });
  }
  
  toast.error('❌ Decryption denied');
};

// Delete message
const handleDeleteMessage = (messageId) => {
  if (socket) {
    socket.emit('delete_message', { message_id: messageId });
  }
  setOpenDropdown(null);
};

const onEmojiClick = (emojiObject) => {
  setMessageText(prevInput => prevInput + emojiObject.emoji);
  // Optional: Close the picker after selecting an emoji. If you want it to stay open, remove this line.
  setShowEmojiPicker(false); 
};

// Save conversation key to the database
const handleSaveConversationKey = async () => {
  if (!selectedConversation) return;
  const conversationId = selectedConversation.id;
  const key = conversationKeys[conversationId];

  if (!key || key.trim().length === 0) {
    toast.error('Please enter a conversation key.');
    return;
  }

  try {
    await axios.post(`${API_BASE}/security/set-conversation-key`, 
    {
      conversationId: conversationId,
      key: key
    }, 
    {
      headers: { Authorization: `Bearer ${token}` }
    });

    toast.success('Personal Decryption Key saved securely!');
    // **THE FIX**: Update the new state to true for this conversation
    setConversationKeyStatus(prev => ({ ...prev, [conversationId]: true }));
    setConversationKeys(prev => ({ ...prev, [conversationId]: '' }));

  } catch (error) {
    toast.error(error.response?.data?.error || 'Failed to save key');
  }
};

// Calculates the decryption time based on the "complexity" (length) of the message.
const calculateDecryptionDuration = (messageLength) => {
  const minDuration = 5000;  // 5 seconds
  const maxDuration = 30000; // 30 seconds
  const minLength = 1;       // A single character message
  const maxLength = 500;     // A long message to cap the duration

  if (messageLength <= minLength) {
    return minDuration;
  }
  if (messageLength >= maxLength) {
    return maxDuration;
  }

  // Linearly scale the duration between the min and max based on length
  const lengthRatio = (messageLength - minLength) / (maxLength - minLength);
  const duration = minDuration + (lengthRatio * (maxDuration - minDuration));
  
  return duration;
};

// Epic decryption animation function
const startDecryptionAnimation = async (messageId, decoyContent, realContent, selfDestructTimer, newExpiresAt) => {
  setIsDecrypting(prev => ({ ...prev, [messageId]: true }));
  playCracklingSound();

  const messageElement = document.querySelector(`[data-message-id="${messageId}"] .message-text-content`);
  // We also need the wrapper element to change its border color
  const wrapperElement = document.querySelector(`[data-message-id="${messageId}"] .message-wrapper`);
  

  if (!messageElement || !wrapperElement) return;

  const scrambleChars = '█▓▒░ABCDEFGHIJKLMÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwxyz0123456789!?@#$%&';
  
  // Handle sender's approval signal
        socket.on('sender_approved_decryption', (data) => {
            const { message_id } = data;
            toast.success('Sender has approved your request. Please enter your key to decrypt.');
            setSenderApprovals(prev => ({ ...prev, [message_id]: true }));
        });
        
        socket.on('error', (error) => toast.error(error.message || 'A connection error occurred.'));

        // Attach socket event listeners
    socket.on('live_decoy_update', (data) => {
      console.log('📡 [CLIENT-RECEIVE] Got live_decoy_update:', data);
      console.log('📡 [CLIENT-RECEIVE] Current selected conversation:', selectedConversation?.id);
      console.log('📡 [CLIENT-RECEIVE] Data conversation_id:', data.conversation_id);
      console.log('📡 [CLIENT-RECEIVE] Should update?', selectedConversation && selectedConversation.id === data.conversation_id);

      const { conversation_id, sender_username, decoy_content } = data;
      
      if (selectedConversation && selectedConversation.id === conversation_id) {
          setLiveDecoys(prev => {
              const newDecoys = {
                  ...prev,
                  [conversation_id]: { sender_username, decoy_content }
              };
              console.log('📡 [CLIENT-RECEIVE] New liveDecoys state:', newDecoys);
              return newDecoys;
          });
      } else {
          console.log('📡 [CLIENT-RECEIVE] Ignoring - wrong conversation or no selected conversation');
      }
    });

        socket.on('finalize_message', (finalMessageObject) => {
            const { conversation_id } = finalMessageObject;
            setMessages(prevMessages => {
                const messageExists = prevMessages.some(msg => msg.id === finalMessageObject.id);
                if (!messageExists) {
                    return [...prevMessages, finalMessageObject];
                }
                return prevMessages;
            });

            setLiveDecoys(prev => {
                const newDecoys = { ...prev };
                delete newDecoys[conversation_id];
                return newDecoys;
            });
            
            setConversations(prevConvos => 
                prevConvos.map(convo => 
                    convo.id === conversation_id 
                    ? { ...convo, last_message_at: finalMessageObject.created_at } 
                    : convo
                ).sort((a, b) => new Date(b.last_message_at) - new Date(a.last_message_at))
            );
        });

         // **THE FIX (2/2)**: This new handler fixes the real-time message update bug.
        socket.on('new_message', (newMessageFromServer) => {
            if (!newMessageFromServer || !newMessageFromServer.id) {
                console.error("Received an invalid message object from server:", newMessageFromServer);
                return;
            }

            // Add the new file message to the messages array
            setMessages(prevMessages => {
                const messageExists = prevMessages.some(msg => msg.id === newMessageFromServer.id);
                if (!messageExists) {
                    return [...prevMessages, newMessageFromServer];
                }
                return prevMessages;
            });
            
            // Update the conversation list and play a notification sound if needed
            setSelectedConversation(currentSelectedConv => {
                const isActiveChat = currentSelectedConv && currentSelectedConv.id === newMessageFromServer.conversation_id;
                if (!isActiveChat) {
                    playNotificationSound();
                }
                setConversations(prevConvos => {
                  const newConvos = prevConvos.map(convo => {
                    if (convo.id === newMessageFromServer.conversation_id) {
                      const newUnreadCount = isActiveChat ? convo.unread_count : (Number(convo.unread_count) || 0) + 1;
                      return { ...convo, last_message_at: newMessageFromServer.created_at, unread_count: newUnreadCount };
                    }
                    return convo;
                  });
                  return newConvos.sort((a, b) => new Date(b.last_message_at) - new Date(a.last_message_at));
                });
                return currentSelectedConv;
            });
        });

         socket.on('decryption_request', (request) => {
          toast(`🔓 Decryption request from ${request.requester_username}`, {
            duration: 5000,
            icon: '🔑'
          });

          // 1. Add the request to the state for the panel and badge to update
          setDecryptionRequests(prevRequests => {
            const requestExists = prevRequests.some(r => r.id === request.id);
            if (!requestExists) {
              return [request, ...prevRequests];
            }
            return prevRequests;
          });

          // 2. **THE FIX**: Immediately trigger the inline input box for the sender.
          setPendingDecryption(prev => ({ ...prev, [request.message_id]: true }));
        });

        socket.on('message_decrypted', (data) => {
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
              
              if (socket) {
                socket.emit('message_self_destructed', { message_id });
              }
            }, 2000);
            
          }, self_destruct_timer * 1000);
        });

        socket.on('user_typing', (data) => {
          if (data.is_typing) {
            setTypingUsers(prev => [...prev.filter(u => u.user_id !== data.user_id), data]);
          } else {
            setTypingUsers(prev => prev.filter(u => u.user_id !== data.user_id));
          }
        });

        socket.on('error', (error) => {
          toast.error(error.message);
        });

        // Add these new listeners before the return statement in the socket useEffect
        socket.on('message_seen_update', (data) => {
            const { message_id } = data;
            setMessages(prev => prev.map(msg => 
              msg.id === message_id 
                ? { ...msg, is_seen: true }
                : msg
            ));
        });

        socket.on('start_decryption_animation', (data) => {
            const { message_id, decoy_content, real_content, self_destruct_timer, expires_at } = data;
            
            // Start the epic decryption animation
            startDecryptionAnimation(message_id, decoy_content, real_content, self_destruct_timer, expires_at);
            
            // Clear pending decryption state
            setPendingDecryption(prev => {
              const newState = { ...prev };
              delete newState[message_id];
              return newState;
            });
        });

        socket.on('inline_decryption_denied', (data) => {
            toast.error('❌ Decryption request denied');
        });

        socket.on('file_decrypted_successfully', (data) => {
            const { message_id, decrypted_metadata, download_token } = data;

            setMessages(prev => prev.map(msg => {
                if (msg.id === message_id) {
                    return { 
                        ...msg, // **THIS IS THE FIX**: Preserve all existing properties of the message...
                        is_decrypted: true, 
                        decrypted_metadata: decrypted_metadata,
                        download_token: download_token 
                    };
                }
                return msg;
            }));

            setPendingDecryption(prev => {
                const newState = { ...prev };
                delete newState[message_id];
                return newState;
            });
            setDecryptionRequests(prev => prev.filter(req => req.message_id !== message_id));
            
            toast.success("File decrypted. Ready to view or download.");
        });

        socket.on('message_deleted', (data) => {
            const { message_id } = data;
            setMessages(prev => prev.filter(msg => msg.id !== message_id));
            toast.success('🗑️ Message deleted');
        });

        // The cleanup function runs only when the component unmounts.
        return () => {
            console.log('Closing socket connection.');
            if (socket) {
                socket.close();
            }
        };
    }
}, [token]);

// Additional socket event handlers useEffect
useEffect(() => {
    const handleSenderApproved = (data) => {
        const { message_id } = data;
        toast.success('Sender has approved your request.');
        setSenderApprovals(prev => ({ ...prev, [message_id]: true }));
    };

    const handleLiveDecoyUpdate = (data) => {
        const { conversation_id, sender_username, decoy_content } = data;
        if (selectedConversation && selectedConversation.id === conversation_id) {
            setLiveDecoys({ [conversation_id]: { sender_username, decoy_content } });
        }
    };

    const handleFinalizeMessage = (finalMessageObject) => {
        const { conversation_id } = finalMessageObject;
        setMessages(prev => [...prev, finalMessageObject]);
        setLiveDecoys(prev => {
            const newDecoys = { ...prev };
            delete newDecoys[conversation_id];
            return newDecoys;
        });
        setConversations(prev => prev.map(c => c.id === conversation_id ? { ...c, last_message_at: finalMessageObject.created_at } : c).sort((a,b) => new Date(b.last_message_at) - new Date(a.last_message_at)));
    };

    const handleNewFileMessage = (newMessage) => {
        setMessages(prev => [...prev, newMessage]);
        if (!selectedConversation || selectedConversation.id !== newMessage.conversation_id) {
            playNotificationSound();
            setConversations(prev => prev.map(c => c.id === newMessage.conversation_id ? { ...c, unread_count: (c.unread_count || 0) + 1, last_message_at: newMessage.created_at } : c).sort((a,b) => new Date(b.last_message_at) - new Date(a.last_message_at)));
        } else {
             setConversations(prev => prev.map(c => c.id === newMessage.conversation_id ? { ...c, last_message_at: newMessage.created_at } : c).sort((a,b) => new Date(b.last_message_at) - new Date(a.last_message_at)));
        }
    };

    const handleDecryptionRequest = (request) => {
        toast(`🔓 Decryption request from ${request.requester_username}`);
        setDecryptionRequests(prev => [request, ...prev]);
        setPendingDecryption(prev => ({ ...prev, [request.message_id]: true }));
    };

    const handleFileDecrypted = (data) => {
        const { message_id, decrypted_metadata, download_token } = data;
        setMessages(prev => prev.map(msg => msg.id === message_id ? { ...msg, is_decrypted: true, decrypted_metadata, download_token } : msg));
        setPendingDecryption(prev => { const newState = { ...prev }; delete newState[message_id]; return newState; });
        setDecryptionRequests(prev => prev.filter(req => req.message_id !== message_id));
        toast.success("File decrypted. Ready to view or download.");
    };

    const handleMessageDeleted = (data) => {
        setMessages(prev => prev.filter(msg => msg.id !== data.message_id));
    };

    const handleStartAnimation = (data) => {
        startDecryptionAnimation(data.message_id, data.decoy_content, data.real_content, data.self_destruct_timer, data.expires_at);
        setPendingDecryption(prev => { const newState = { ...prev }; delete newState[data.message_id]; return newState; });
    };
    
    const handleUserTyping = (data) => {
      if (data.is_typing) {
        setTypingUsers(prev => [...prev.filter(u => u.user_id !== data.user_id), data]);
      } else {
        setTypingUsers(prev => prev.filter(u => u.user_id !== data.user_id));
      }
    };

    if (socket) {
        // Registering all listeners
        socket.on('sender_approved_decryption', handleSenderApproved);
        socket.on('live_decoy_update', handleLiveDecoyUpdate);
        socket.on('finalize_message', handleFinalizeMessage);
        socket.on('new_message', handleNewFileMessage);
        socket.on('decryption_request', handleDecryptionRequest);
        socket.on('file_decrypted_successfully', handleFileDecrypted);
        socket.on('message_deleted', handleMessageDeleted);
        socket.on('start_decryption_animation', handleStartAnimation);
        socket.on('user_typing', handleUserTyping);

        // Cleanup function to remove listeners, preventing memory leaks and duplicate handlers.
        return () => {
            socket.off('sender_approved_decryption', handleSenderApproved);
            socket.off('live_decoy_update', handleLiveDecoyUpdate);
            socket.off('finalize_message', handleFinalizeMessage);
            socket.off('new_message', handleNewFileMessage);
            socket.off('decryption_request', handleDecryptionRequest);
            socket.off('file_decrypted_successfully', handleFileDecrypted);
            socket.off('message_deleted', handleMessageDeleted);
            socket.off('start_decryption_animation', handleStartAnimation);
            socket.off('user_typing', handleUserTyping);
        };
    }
}, [socket]); // Only re-run when socket changes

  // Authentication functions
const handleLogin = async (e) => {
  e.preventDefault();
  try {
    const response = await axios.post(`${API_BASE}/auth/login`, loginForm);
    const { token } = response.data; // We only need the token.
    localStorage.setItem('token', token);
    setToken(token); // Setting the token will trigger the new auth useEffect.
    toast.success('🚀 Welcome to Vanish!');
  } catch (error) {
    toast.error(error.response?.data?.error || 'Login failed');
  }
};
    const handleRegister = async (e) => {
  e.preventDefault();
  try {
    const response = await axios.post(`${API_BASE}/auth/register`, registerForm);
    const { token } = response.data; // We only need the token.
    localStorage.setItem('token', token);
    setToken(token); // Setting the token will trigger the new auth useEffect.
    toast.success('🎉 Account created successfully!');
  } catch (error) {
    toast.error(error.response?.data?.error || 'Registration failed');
  }
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

const fetchKeyStatus = async (conversationId) => {
  if (!token) return;
  try {
    const response = await axios.get(`${API_BASE}/security/check-conversation-key/${conversationId}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    // Update the status for this specific conversation
    setConversationKeyStatus(prev => ({ ...prev, [conversationId]: response.data.hasKey }));
  } catch (error) {
    console.error('Failed to fetch key status for convo', conversationId);
    // Default to false on error
    setConversationKeyStatus(prev => ({ ...prev, [conversationId]: false }));
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

  // 1. Create a temporary message object for INSTANT UI update.
  // This makes the sender's UI feel instantaneous.
  const tempId = `temp_${Date.now()}`; // A temporary, unique key for React
  const messageData = {
    conversation_id: selectedConversation.id,
    content: messageText, // The real content, which we will handle
    sender_key: senderKey,
    // No hint needed
  };

  // 2. The data that will actually be sent to the server.
  const socketMessageData = {
      conversation_id: selectedConversation.id,
      content: messageText,
      sender_key: senderKey,
      message_type: 'text'
  };

  // 3. Emit the message to the server via Socket.IO.
  if (socket) {
    socket.emit('send_message', socketMessageData);
  }

  // 4. Clear the input fields immediately.
  setMessageText('');
  setSenderKey('');
  
  // NOTE: We DO NOT add the message to the state here.
  // The server is the single source of truth. We will wait for the
  // 'new_message' broadcast to come back to ALL clients, including the sender.
  // This ensures 100% data consistency.
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

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
        setFileToUpload(file);
    }
    // Reset the input value to allow selecting the same file again
    e.target.value = null; 
};

const handleSendFile = async (ephemeralType) => {
    if (!fileToUpload || !senderKey || !selectedConversation) {
        toast.error("File, decryption key, and conversation are required.");
        return;
    }

    try {
        // Step 1: Upload the raw (encrypted) file to the server
        const formData = new FormData();
        formData.append('file', fileToUpload);

        const uploadResponse = await axios.post(`${API_BASE}/files/upload`, formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
                Authorization: `Bearer ${token}`
            }
        });

        // Step 2: Create the file metadata object
        const fileMetadata = {
            path: uploadResponse.data.filePath.replace(/\\/g, '/'), // Normalize path for consistency
            originalName: fileToUpload.name,
            mimeType: fileToUpload.type,
            size: fileToUpload.size
        };

        // Step 3: Emit the socket event to create the file message
        if (socket) {
            socket.emit('send_file_message', {
                conversation_id: selectedConversation.id,
                sender_key: senderKey,
                file_metadata: fileMetadata,
                ephemeral_type: ephemeralType
            });
        }

        setFileToUpload(null); // Close the modal
        setSenderKey(''); // Clear the key input

    } catch (error) {
        toast.error("File upload failed.");
        console.error("Upload error:", error);
    }
};

useEffect(() => {
    console.log('🎨 [STATE] liveDecoys state changed:', liveDecoys);
    console.log('🎨 [STATE] selectedConversation:', selectedConversation?.id);
    console.log('🎨 [STATE] Should render LivePreview:', 
        selectedConversation && liveDecoys[selectedConversation.id]);
}, [liveDecoys, selectedConversation]);

// === REPLACE handleFileDecrypt WITH THIS NEW FUNCTION ===
const handleFileActionClick = async (message) => {
    if (!message?.download_token) {
        toast.error("Security token is missing. Please decrypt the file again.");
        return;
    }

    try {
        // The URL with the one-time token is all that's needed now.
        const downloadUrl = `${API_BASE}/files/download/${message.id}?token=${message.download_token}`;

        if (message.ephemeral_type === 'view_once') {
            toast.loading("Loading secure media...", { id: 'download-toast' });
            // For View Once, we still use axios to fetch the blob into the viewer.
            const response = await axios.get(downloadUrl, { responseType: 'blob' });
            const fileBlob = new Blob([response.data], { type: message.file_metadata.mimeType });
            setViewOnceMedia({ message: message, file: fileBlob });
            toast.dismiss('download-toast');

        } else { // 'standard' files
            // For standard files, we can now use a simple link, which is more reliable for downloads.
            const link = document.createElement('a');
            link.href = downloadUrl;
            link.setAttribute('download', message.decrypted_metadata.originalName);
            document.body.appendChild(link);
            link.click();
            link.parentNode.removeChild(link);
        }

    } catch (error) {
        toast.error("Download failed. The secure link may have expired or been used already.");
        console.error("File download/view error:", error.response || error);
    }
};

const handleViewOnceComplete = (messageId) => {
    if (socket) {
        socket.emit('view_once_completed', { message_id: messageId });
    }
    setViewOnceMedia({ message: null, file: null }); // Close the viewer
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


  // Authentication functions
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

  // Dropdown management
const toggleMessageDropdown = (messageId) => {
  setOpenDropdown(openDropdown === messageId ? null : messageId);
};

// Format countdown timer
const formatCountdown = (expiresAt) => {
  if (!expiresAt) return '00:00';
  const now = new Date();
  const expiry = new Date(expiresAt);
  const secondsRemaining = Math.max(0, Math.floor((expiry - now) / 1000));
  
  const minutes = Math.floor(secondsRemaining / 60);
  const seconds = secondsRemaining % 60;
  
  return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
};

const handleInlineDecryptionRequest = (messageId) => {
  if (socket) {
    socket.emit('request_decryption', { message_id: messageId });
    toast.success('🔓 Decryption request sent');
  }
};

// Handle decryption input
const handleDecryptionInput = (messageId, value) => {
  setDecryptionInputs(prev => ({ ...prev, [messageId]: value }));
};

// Provide inline decryption key
// Provide inline decryption key
const handleProvideInlineKey = (messageId) => {
  const key = decryptionInputs[messageId];
  if (!key || !socket) return;

  socket.emit('sender_provide_key', {
    message_id: messageId,
    decryption_key: key,
  });

  // Optimistically remove the input box from the UI
  setPendingDecryption(prev => {
    const newState = { ...prev };
    delete newState[messageId];
    return newState;
  });

  // **THE FIX**: Immediately remove the corresponding notification from the panel.
  setDecryptionRequests(prevRequests => 
    prevRequests.filter(req => req.message_id !== messageId)
  );
};

// This function is called when the RECEIVER clicks "Finalize Decrypt".
const handleReceiverProvideKey = (messageId) => {
    // **THE FIX**: The key is now read from the new, isolated state.
    const key = inlineDecryptionKey; 
    if (!key || !socket) {
        toast.error("Please enter your Personal Decryption Key to finalize.");
        return;
    }

    socket.emit('receiver_provide_key', {
        message_id: messageId,
        decryption_key: key,
    });

    // **CRITICAL SECURITY STEP**: Immediately clear the key from the state after use.
    setInlineDecryptionKey('');
};

// Deny inline decryption
const handleDenyInlineDecryption = (messageId) => {
  setPendingDecryption(prev => {
    const newState = { ...prev };
    delete newState[messageId];
    return newState;
  });
  
  setDecryptionInputs(prev => {
    const newState = { ...prev };
    delete newState[messageId];
    return newState;
  });
  
  if (socket) {
    socket.emit('provide_inline_decryption', {
      message_id: messageId,
      approve: false
    });
  }
  
  toast.error('❌ Decryption denied');
};

// Delete message
const handleDeleteMessage = (messageId) => {
  if (socket) {
    socket.emit('delete_message', { message_id: messageId });
  }
  setOpenDropdown(null);
};

const onEmojiClick = (emojiObject) => {
  setMessageText(prevInput => prevInput + emojiObject.emoji);
  // Optional: Close the picker after selecting an emoji. If you want it to stay open, remove this line.
  setShowEmojiPicker(false); 
};

// Save conversation key to the database
const handleSaveConversationKey = async () => {
  if (!selectedConversation) return;
  const conversationId = selectedConversation.id;
  const key = conversationKeys[conversationId];

  if (!key || key.trim().length === 0) {
    toast.error('Please enter a conversation key.');
    return;
  }

  try {
    await axios.post(`${API_BASE}/security/set-conversation-key`, 
    {
      conversationId: conversationId,
      key: key
    }, 
    {
      headers: { Authorization: `Bearer ${token}` }
    });

    toast.success('Personal Decryption Key saved securely!');
    // **THE FIX**: Update the new state to true for this conversation
    setConversationKeyStatus(prev => ({ ...prev, [conversationId]: true }));
    setConversationKeys(prev => ({ ...prev, [conversationId]: '' }));

  } catch (error) {
    toast.error(error.response?.data?.error || 'Failed to save key');
  }
};

// Calculates the decryption time based on the "complexity" (length) of the message.
const calculateDecryptionDuration = (messageLength) => {
  const minDuration = 5000;  // 5 seconds
  const maxDuration = 30000; // 30 seconds
  const minLength = 1;       // A single character message
  const maxLength = 500;     // A long message to cap the duration

  if (messageLength <= minLength) {
    return minDuration;
  }
  if (messageLength >= maxLength) {
    return maxDuration;
  }

  // Linearly scale the duration between the min and max based on length
  const lengthRatio = (messageLength - minLength) / (maxLength - minLength);
  const duration = minDuration + (lengthRatio * (maxDuration - minDuration));
  
  return duration;
};

// Epic decryption animation function
const startDecryptionAnimation = async (messageId, decoyContent, realContent, selfDestructTimer, newExpiresAt) => {
  setIsDecrypting(prev => ({ ...prev, [messageId]: true }));
  playCracklingSound();

  const messageElement = document.querySelector(`[data-message-id="${messageId}"] .message-text-content`);
  // We also need the wrapper element to change its border color
  const wrapperElement = document.querySelector(`[data-message-id="${messageId}"] .message-wrapper`);
  

  if (!messageElement || !wrapperElement) return;

  const scrambleChars = '█▓▒░ABCDEFGHIJKLMÑOPQRSTUVWXYZabcdefghijklmnñopqrstuvwxyz0123456789!?@#$';
  const realChars = realContent.split('');
  
  const maxLength = realChars.length;
  const totalDuration = calculateDecryptionDuration(realContent.length);

  // --- NEW RANDOM REVEAL LOGIC ---
  // 1. Create an array of all indices *except* the first and last.
  const middleIndices = Array.from({ length: Math.max(0, maxLength - 2) }, (_, i) => i + 1);

  // 2. Shuffle the middle indices randomly (Fisher-Yates shuffle algorithm).
  for (let i = middleIndices.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [middleIndices[i], middleIndices[j]] = [middleIndices[j], middleIndices[i]];
  }

  // 3. Create the final reveal order: the shuffled middle, then the first and last characters.
  const revealOrder = [...middleIndices];
  if (maxLength > 0) revealOrder.push(0);
  if (maxLength > 1) revealOrder.push(maxLength - 1);
  // --- END NEW RANDOM REVEAL LOGIC ---

  let startTime = null;
  const revealedIndices = new Set();

  const animate = (currentTime) => {
    if (!startTime) startTime = currentTime;
    const elapsedTime = currentTime - startTime;
    const progress = Math.min(elapsedTime / totalDuration, 1.0);

    // --- SYNCHRONIZED GREEN PHASE LOGIC ---
    if (progress < 0.89) {
      messageElement.classList.add('glow-red');
      messageElement.classList.remove('glow-green');
      wrapperElement.classList.remove('phase-green'); // Ensure wrapper is red
    } else {
      messageElement.classList.add('glow-green');
      messageElement.classList.remove('glow-red');
      wrapperElement.classList.add('phase-green'); // Make wrapper green
    }
    // --- END SYNCHRONIZED GREEN PHASE LOGIC ---

    // Determine how many characters to reveal based on our random order
    const revealedCount = Math.floor(progress * maxLength);
    for (let i = 0; i < revealedCount; i++) {
      revealedIndices.add(revealOrder[i]);
    }
    
    const frameText = realChars.map((char, index) => {
      // If the index is in our set of revealed indices, show the real character.
      if (revealedIndices.has(index)) {
        return realChars[index];
      }
      // Otherwise, show a random scramble character.
      return scrambleChars[Math.floor(Math.random() * scrambleChars.length)];
    });
    
    messageElement.textContent = frameText.join('');

    if (progress < 1.0) {
      requestAnimationFrame(animate);
    } else {
      messageElement.textContent = realContent;
      messageElement.classList.add('glow-green');
      messageElement.classList.remove('glow-red');
      completeDecryption(messageId, realContent, selfDestructTimer, newExpiresAt);
    }
  };

  requestAnimationFrame(animate);
};

// Complete decryption with green glow and shimmer
const completeDecryption = (messageId, realContent, selfDestructTimer, newExpiresAt) => {
  stopCracklingSound();
  playCompletionChime();

  // **THE FIX**: Immediately turn off the "decrypting" state.
  // This prevents the CSS class conflict on the next re-render.
  setIsDecrypting(prev => {
    const newState = { ...prev };
    delete newState[messageId];
    return newState;
  });

  // Add the message to the "success" state for the green text glow
  setSuccessMessages(prev => new Set(prev).add(messageId));

  // Update the message content AND the expires_at timestamp
  setMessages(prev => prev.map(msg =>
    msg.id === messageId 
    ? { 
        ...msg, 
        content: realContent, 
        is_encrypted_display: false, 
        is_decrypted: true,
        expires_at: newExpiresAt // Set the new timer data
      } 
    : msg
  ));
  
  // Schedule the final cleanup for the text glow effect
  setTimeout(() => {
    setSuccessMessages(prev => {
      const newSet = new Set(prev);
      newSet.delete(messageId);
      return newSet;
    });
    
    const messageElement = document.querySelector(`[data-message-id="${messageId}"] .message-text-content`);
    if (messageElement) {
        messageElement.classList.remove('glow-green');
    }
  }, 3000);
};
// Message seen tracking
const markMessageAsSeen = (messageId) => {
  if (socket) {
    socket.emit('message_seen', { message_id: messageId });
  }
};

// HOOK 1: THE USER INITIALIZER. Its ONLY job is to set the currentUser state from the token.
useEffect(() => {
  if (token) {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]));
      const userFromToken = { id: payload.id, username: payload.username };
      console.log('[AUTH_EFFECT] Setting current user from token:', userFromToken);
      setCurrentUser(userFromToken);
      setIsAuthenticated(true);
      setActiveView('chat');
    } catch (e) {
      console.error('Invalid token found. Logging out.');
      handleLogout();
    }
  }
}, [token]);

// HOOK 2: THE DATA FETCHER. It runs ONLY AFTER the user is confirmed.
useEffect(() => {
  if (!currentUser || !socket) return;
  
  const fetchAllUserData = async () => {
    console.log('[DATA_EFFECT] Current user is set. Fetching all user data...');
    // We need to get the conversations first to check for a persisted ID
    await fetchConversations(); 
    await fetchContacts();
    await fetchDecryptionRequests();

    // After conversations are fetched, check localStorage
    const lastConvoId = localStorage.getItem('vanish-last-convo-id');
    if (lastConvoId) {
      setConversations(currentConversations => {
        const lastConvo = currentConversations.find(c => c.id === parseInt(lastConvoId));
        if (lastConvo) {
          setSelectedConversation(lastConvo);
        }
        return currentConversations;
      });
    }
  };

  fetchAllUserData();
}, [currentUser, socket]);

useEffect(() => {
  const handleConversationChange = async () => {
    if (selectedConversation) {
      localStorage.setItem('vanish-last-convo-id', selectedConversation.id);
      
      // **THE FIX**: Explicitly tell the server to add this socket to the conversation room.
      if (socket) {
        socket.emit('join_conversation', { conversation_id: selectedConversation.id });
      }

      await fetchKeyStatus(selectedConversation.id); 
      await fetchMessages(selectedConversation.id);

      if (socket) {
        socket.emit('join_conversation', { conversation_id: selectedConversation.id });

  socket.emit('mark_conversation_as_read', { conversation_id: selectedConversation.id });
}

      setConversations(prevConvos =>
        prevConvos.map(c => 
          c.id === selectedConversation.id ? { ...c, unread_count: 0 } : c
        )
      );
    }
  };
  
  handleConversationChange();
}, [selectedConversation, socket]); // Dependencies are correct

  // Auto scroll to bottom
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

// This hook now ONLY handles the countdown timer for successfully decrypted messages.
useEffect(() => {
  const interval = setInterval(() => {
    const now = new Date();
    let changed = false;
    
    // Filter out ONLY decrypted messages that have expired.
    const updatedMessages = messages.filter(msg => {
      if (msg.is_decrypted && msg.expires_at) {
        if (now >= new Date(msg.expires_at)) {
          changed = true;
          return false; // Remove this message
        }
      }
      return true; // Keep all other messages
    });

    if (changed) {
      setMessages(updatedMessages);
    } else {
      // Force a re-render to update countdown timers without filtering
      setTimerIntervals(prev => ({...prev}));
    }
  }, 1000);

  return () => clearInterval(interval);
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
// === DEFINITIVE REPLACEMENT for the entire return block of App.js ===

  // Revolutionary login/register interface
  if (!isAuthenticated) {
    return (
      <div className="auth-container">
        <div className="auth-card">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} className="auth-header">
            <Shield className="auth-logo" size={48} />
            <h1>Vanish</h1>
            <p>Revolutionary Ephemeral Messaging</p>
          </motion.div>
          <div className="auth-tabs">
            <button className={activeView === 'login' ? 'active' : ''} onClick={() => setActiveView('login')}>Login</button>
            <button className={activeView === 'register' ? 'active' : ''} onClick={() => setActiveView('register')}>Register</button>
          </div>
          <AnimatePresence mode="wait">
            {activeView === 'login' ? (
              <motion.form key="login" initial={{ opacity: 0, x: -20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: 20 }} onSubmit={handleLogin} className="auth-form">
                <div className="form-group"><input type="text" placeholder="Username" value={loginForm.username} onChange={(e) => setLoginForm({...loginForm, username: e.target.value})} required /></div>
                <div className="form-group"><input type="password" placeholder="Password" value={loginForm.password} onChange={(e) => setLoginForm({...loginForm, password: e.target.value})} required /></div>
                <button type="submit" className="auth-button"><Lock size={20} /> Secure Login</button>
              </motion.form>
            ) : (
              <motion.form key="register" initial={{ opacity: 0, x: 20 }} animate={{ opacity: 1, x: 0 }} exit={{ opacity: 0, x: -20 }} onSubmit={handleRegister} className="auth-form">
                <div className="form-group"><input type="text" placeholder="Username" value={registerForm.username} onChange={(e) => setRegisterForm({...registerForm, username: e.target.value})} required /></div>
                <div className="form-group"><input type="password" placeholder="Password" value={registerForm.password} onChange={(e) => setRegisterForm({...registerForm, password: e.target.value})} required /></div>
                <div className="form-group"><input type="email" placeholder="Email for Account Security" value={registerForm.email} onChange={(e) => setRegisterForm({...registerForm, email: e.target.value})} required /></div>
                <div className="form-group"><input type="text" placeholder="Bio (optional)" value={registerForm.bio} onChange={(e) => setRegisterForm({...registerForm, bio: e.target.value})} /></div>
                <button type="submit" className="auth-button"><Shield size={20} /> Create Account</button>
              </motion.form>
            )}
          </AnimatePresence>
        </div>
      </div>
    );
  }

  // Revolutionary WhatsApp-like main interface
  return (
    <div className="chat-container" onClick={initializeAudio}>
        {/* The AnimatedBackground will go here later if we add it */}
        <Toaster position="top-right" />
        <input type="file" ref={fileInputRef} style={{ display: 'none' }} onChange={handleFileSelect} />
        <FileUploadModal file={fileToUpload} onSend={handleSendFile} onCancel={() => setFileToUpload(null)} />
        {viewOnceMedia.file && (
            <MediaViewer 
                file={viewOnceMedia.file} 
                onViwed={() => handleViewOnceComplete(viewOnceMedia.message.id)} 
            />
        )}
      
      <div className="sidebar">
        <div className="sidebar-header">
          <div className="user-info">
            <div className="avatar"><User size={20} /></div>
            <span>{currentUser?.username}</span>
          </div>
          <div className="header-actions">
            <button onClick={() => setIsMuted(!isMuted)} title={isMuted ? "Unmute Sounds" : "Mute Sounds"}>
                {isMuted ? <VolumeX size={20} /> : <Volume2 size={20} />}
            </button>
            <button onClick={() => setShowDecryptionPanel(!showDecryptionPanel)}>
              <Unlock size={20} />
              {decryptionRequests.length > 0 && (<span className="notification-badge">{decryptionRequests.length}</span>)}
            </button>
            <button onClick={() => setShowProfile(!showProfile)}><Settings size={20} /></button>
            <button onClick={handleLogout}><LogOut size={20} /></button>
          </div>
        </div>

        <div className="search-bar">
          <Search size={18} />
          <input
            type="text"
            placeholder={sidebarTab === 'conversations' ? 'Search conversations...' : 'Search users...'}
            value={sidebarTab === 'conversations' ? searchQuery : contactSearchQuery}
            onChange={(e) => {
              if (sidebarTab === 'conversations') setSearchQuery(e.target.value);
              else setContactSearchQuery(e.target.value);
            }}
          />
          <button onClick={() => setSidebarTab(sidebarTab === 'conversations' ? 'contacts' : 'conversations')} className="sidebar-tab-toggle">
            {sidebarTab === 'conversations' ? <Users size={18} /> : <MessageCircle size={18} />}
          </button>
        </div>

        {sidebarTab === 'conversations' ? (
          <div className="conversations-list">
            {conversations
              .filter(conv => !searchQuery || conv.display_name.toLowerCase().includes(searchQuery.toLowerCase()))
              .map((conv) => (
                <motion.div key={conv.id} className={`conversation-item ${selectedConversation?.id === conv.id ? 'active' : ''}`} onClick={() => setSelectedConversation(conv)} whileHover={{ backgroundColor: 'rgba(255,255,255,0.05)' }} whileTap={{ scale: 0.98 }}>
                  <div className="conversation-avatar"><User size={24} />{conv.contact_online && <div className="online-indicator" />}</div>
                  <div className="conversation-info">
                    <div className="conversation-name">
                      <span>{conv.display_name}</span>
                      {conv.unread_count > 0 && <span className="unread-badge">{conv.unread_count}</span>}
                    </div>
                    <div className="conversation-preview">{conv.message_count} encrypted messages</div>
                  </div>
                </motion.div>
              ))}
          </div>
        ) : (
          // **THE FIX**: This entire block was missing and has been restored.
          <div className="conversations-list">
            {contactSearchQuery && searchResults.length > 0 && (
              <>
                <div className="list-header">Search Results</div>
                {searchResults.map((user) => (
                  <div key={user.id} className="conversation-item">
                    <div className="conversation-avatar"><User size={24} /></div>
                    <div className="conversation-info">
                      <div className="conversation-name">{user.username}</div>
                      <div className="conversation-preview">{user.bio || 'No bio'}</div>
                    </div>
                    <div className="conversation-meta">
                       {!user.is_contact && (
                        <button onClick={() => addContact(user.id, user.username)} className="gradient-btn icon-only">
                          <UserPlus size={16} />
                        </button>
                      )}
                    </div>
                  </div>
                ))}
              </>
            )}

            <div className="list-header">My Contacts</div>
            {contacts.map((contact) => (
              <div key={contact.contact_id} className="conversation-item">
                <div className="conversation-avatar"><User size={24} />{contact.is_online && <div className="online-indicator" />}</div>
                <div className="conversation-info">
                  <div className="conversation-name">{contact.nickname || contact.username}</div>
                  <div className="conversation-preview">{contact.is_online ? 'Online' : 'Last seen recently'}</div>
                </div>
                <div className="conversation-meta">
                  <button onClick={() => startDirectConversation(contact.user_id)} className="gradient-btn icon-only">
                    <MessageCircle size={16} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div 
  className="chat-area" 
  style={{
    backgroundImage: `
      linear-gradient(rgba(10, 10, 10, 0.85), rgba(10, 10, 10, 0.85)),
      url('/images/chat-bg.png')
    `,
    backgroundSize: 'cover',
    backgroundPosition: 'center center',
    backgroundRepeat: 'no-repeat'
  }}
>
        {selectedConversation ? (
          <>
            <div className="chat-header">
              <div className="chat-user-info">
                <div className="avatar"><User size={20} /></div>
                <div>
                  <h3>{selectedConversation.display_name}</h3>
                  <span className={selectedConversation.contact_online ? 'online' : 'offline'}>{selectedConversation.contact_online ? 'Online' : 'Offline'}</span>
                </div>
              </div>
              <div className="conversation-key-area">
                {conversationKeyStatus[selectedConversation.id] ? (
                  <div className="key-display-saved"><span>********</span><button onClick={() => setShowKeyChangeModal(true)}>Change/Forgot Key</button></div>
                ) : (
                  <div className="key-display-edit">
                    <input type="password" placeholder="Set Personal Decryption Key" value={conversationKeys[selectedConversation.id] || ''} onChange={e => setConversationKeys(prev => ({ ...prev, [selectedConversation.id]: e.target.value }))} />
                    <button onClick={handleSaveConversationKey} className="save-key-btn">Save</button>
                  </div>
                )}
              </div>
            </div>

            <motion.div className="messages-area" layout>
              <AnimatePresence>
                {messages.map((message) => {
                  const isFromCurrentUser = message.sender_id === currentUser?.id;
                  return (
                    <motion.div key={message.id} layout className={`message ${isFromCurrentUser ? 'sent' : 'received'} ${openDropdown === message.id ? 'dropdown-active' : ''}`} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, scale: 0.8 }} data-message-id={message.id}>
                      <div className="message-container">
                        <div className={`message-wrapper ${isDecrypting[message.id] ? 'wrapper-decrypting' : ''}`}>
                          {message.message_type === 'file' ? <FileMessage message={message} onActionClick={handleFileActionClick} /> : <span className="message-text-content">{message.content}</span>}
                          {!message.is_encrypted_display && message.message_type !== 'file' && (<div className="destruction-timer"><Timer size={12} />Self-destructs in {formatCountdown(message.expires_at)}</div>)}
                        </div>
                        <div className="message-dropdown">
                          <button className="dropdown-trigger" onClick={() => toggleMessageDropdown(message.id)}>•••</button>
                          {openDropdown === message.id && (
                            <div className="dropdown-menu">
                              {message.sender_id !== currentUser?.id && message.is_encrypted_display && !message.is_decrypted && (<button onClick={() => handleInlineDecryptionRequest(message.id)} className="dropdown-item request-key">Request Decryption</button>)}
                              <button onClick={() => handleDeleteMessage(message.id)} className="dropdown-item delete-item">Delete Message</button>
                            </div>
                          )}
                        </div>
                      </div>
                      <div className="message-time">
                        {isFromCurrentUser && (<span className={`message-status ${message.is_seen ? 'received' : 'sent'}`}>{message.is_seen ? 'Seen' : 'Sent'}</span>)}
                        <span>{new Date(message.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                      </div>
                      {pendingDecryption[message.id] && (
                        <div className="inline-decryption-request">
                          {isFromCurrentUser ? (
                            <><input type="password" placeholder="Enter YOUR message key..." className="decryption-input" value={decryptionInputs[message.id] || ''} onChange={(e) => handleDecryptionInput(message.id, e.target.value)} /><button onClick={() => handleProvideInlineKey(message.id)} className="approve-btn">Approve</button><button onClick={() => handleDenyInlineDecryption(message.id)} className="deny-btn">Deny</button></>
                          ) : (
                            <><input type="password" placeholder="Enter your Personal Decryption Key..." className="decryption-input" value={inlineDecryptionKey} onChange={e => setInlineDecryptionKey(e.target.value)} /><button onClick={() => handleReceiverProvideKey(message.id)} className="approve-btn" disabled={!senderApprovals[message.id]}>{senderApprovals[message.id] ? 'Finalize' : 'Awaiting...'}</button><button onClick={() => handleDenyInlineDecryption(message.id)} className="deny-btn">Cancel</button></>
                          )}
                        </div>
                      )}
                    </motion.div>
                  );
                })}
              </AnimatePresence>

   {selectedConversation && liveDecoys[selectedConversation.id] && (
  <LivePreview
    decoyData={liveDecoys[selectedConversation.id]}
      />
   )}
              <div ref={messagesEndRef} />
            </motion.div>
            
            {typingUsers.length > 0 && (<motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="typing-indicator" >{typingUsers[0].username} is typing...</motion.div>)}

            <form onSubmit={handleSendMessage} className="message-input-area">
              {showEmojiPicker && (<div className="emoji-picker-container"><Picker onEmojiClick={onEmojiClick} autoFocusSearch={false} theme={Theme.DARK} emojiStyle="google" /></div>)}
              <div className="message-input-container">
                <button type="button" className="icon-btn" onClick={() => setShowEmojiPicker(!showEmojiPicker)}><Smile size={22} /></button>
                <button type="button" className="icon-btn" onClick={() => fileInputRef.current.click()}><Paperclip size={22} /></button>
                <input type="text" placeholder="Type a revolutionary message..." value={messageText} onChange={(e) => {
  const newText = e.target.value;
  console.log('🎯 [CLIENT-EMIT] Text changed:', newText.length, 'chars');
  console.log('🎯 [CLIENT-EMIT] Selected conversation:', selectedConversation?.id);
  console.log('🎯 [CLIENT-EMIT] Socket exists:', !!socket);
  console.log('🎯 [CLIENT-EMIT] Socket connected:', socket?.connected);
  setMessageText(newText);
  handleTyping(); // This handles the "user is typing..." indicator

  // **THE FIX**: Emit the live typing event to the server.
  if (socket && selectedConversation) {
     console.log('🎯 [CLIENT-EMIT] Emitting live_typing_update with:', {
      conversation_id: selectedConversation.id,
      text_length: newText.length
    });

    socket.emit('live_typing_update', {
      conversation_id: selectedConversation.id,
      text_length: newText.length
    });
  } else {
    console.log('❌ [CLIENT-EMIT] Cannot emit - missing socket or conversation');
  }
}} onKeyDown={playTypingSound} required />
                <button type="submit" className="gradient-btn"><Send size={20} /></button>
              </div>
              <div className="encryption-controls">
                <input type="password" placeholder="🔑 Your Message Key" value={senderKey} onChange={(e) => setSenderKey(e.target.value)} required />
              </div>
            </form>
          </>
        ) : (
          <div className="no-conversation"><MessageCircle size={64} /><h3>Select a conversation</h3><p>Choose a contact to start a revolutionary encrypted conversation</p></div>
        )}
      </div>

      <AnimatePresence>
        {showDecryptionPanel && (
          <motion.div initial={{ x: 300, opacity: 0 }} animate={{ x: 0, opacity: 1 }} exit={{ x: 300, opacity: 0 }} className="decryption-panel">
            <h3>🔓 Decryption Requests</h3>
            {decryptionRequests.map((request) => (
              <div key={request.id} className="decryption-request clickable" onClick={() => {
                  const targetConvo = conversations.find(c => c.id === request.conversation_id);
                  if (targetConvo) {
                    setSelectedConversation(targetConvo);
                    setPendingDecryption(prev => ({ ...prev, [request.message_id]: true }));
                    setShowDecryptionPanel(false);
                  }
                }}>
                <div className="request-info">
                  <strong>{request.requester_username}</strong> wants to decrypt a message
                  <small>In chat: {conversations.find(c => c.id === request.conversation_id)?.display_name || 'Unknown'}</small>
                </div>
              </div>
            ))}
            {decryptionRequests.length === 0 && (<p>No pending decryption requests</p>)}
          </motion.div>
        )}
      </AnimatePresence>

      {showKeyChangeModal && selectedConversation && (<KeyChangeModal conversationId={selectedConversation.id} token={token} onClose={() => setShowKeyChangeModal(false)} />)}
    </div>
  );
}

export default App;
