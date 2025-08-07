import React, { useState, useEffect } from 'react'; 
import './App.css'; 
import { io } from 'socket.io-client'; 
const socket = io('http://localhost:5000', { autoConnect: false }); 
function App() { 
  const [message, setMessage] = useState(''); 
  const [messageId, setMessageId] = useState(''); 
  const [response, setResponse] = useState(''); 
  const [notification, setNotification] = useState(''); 
  const [username, setUsername] = useState(''); 
  const [password, setPassword] = useState(''); 
  const [messages, setMessages] = useState([]); 
  const [token, setToken] = useState(localStorage.getItem('token') || null); 
  useEffect(() => { 
    if (token) { 
      socket.auth = { token }; 
      socket.connect(); 
      socket.on('messageCreated', (data) => { 
        setNotification(`New message created: ID ${data.id}, Expires: ${data.expires_at}`); 
      }); 
      socket.on('messageDeleted', (data) => { 
        setNotification(`Message deleted: ID ${data.id}`); 
        setMessages(messages.filter(msg => msg.id !== data.id)); 
      }); 
      socket.on('messageCleaned', (data) => { 
        setNotification(`Messages expired and removed: IDs ${data.ids.join(', ')}`); 
        setMessages(messages.filter(msg => !data.ids.includes(msg.id))); 
      }); 
    } 
    return () => { 
      socket.off('messageCreated'); 
      socket.off('messageDeleted'); 
      socket.off('messageCleaned'); 
    }; 
  }, [token, messages]); 
  const register = async (e) => { 
    e.preventDefault(); 
    try { 
      const res = await fetch('http://localhost:5000/register', { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ username, password }) 
      }); 
      const data = await res.json(); 
      if (!res.ok) throw new Error(data.error || 'Registration failed'); 
      setResponse(data.message); 
      setUsername(''); 
      setPassword(''); 
    } catch (err) { 
      console.error('Register error:', err); 
      setResponse('Error: ' + err.message); 
    } 
  }; 
  const login = async (e) => { 
    e.preventDefault(); 
    try { 
      const res = await fetch('http://localhost:5000/login', { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json' }, 
        body: JSON.stringify({ username, password }) 
      }); 
      const data = await res.json(); 
      if (!res.ok) throw new Error(data.error || 'Login failed'); 
      localStorage.setItem('token', data.token); 
      setToken(data.token); 
      setResponse('Logged in successfully'); 
      setUsername(''); 
      setPassword(''); 
    } catch (err) { 
      console.error('Login error:', err); 
      setResponse('Error: ' + err.message); 
    } 
  }; 
  const logout = () => { 
    localStorage.removeItem('token'); 
    setToken(null); 
    socket.disconnect(); 
    setResponse('Logged out'); 
    setMessages([]); 
  }; 
  const sendMessage = async (e) => { 
    e.preventDefault(); 
    if (!token) return setResponse('Error: Please log in'); 
    try { 
      const res = await fetch('http://localhost:5000/messages', { 
        method: 'POST', 
        headers: { 
          'Content-Type': 'application/json', 
          'Authorization': `Bearer ${token}` 
        }, 
        body: JSON.stringify({ content: message }) 
      }); 
      const data = await res.json(); 
      if (!res.ok) throw new Error(data.error || 'Failed to send message'); 
      setResponse(`Stored: ID ${data.id}, Expires: ${data.expires_at}`); 
      setMessage(''); 
    } catch (err) { 
      console.error('Send error:', err); 
      setResponse('Error: ' + err.message); 
    } 
  }; 
  const getMessage = async (e) => { 
    e.preventDefault(); 
    if (!token) return setResponse('Error: Please log in'); 
    try { 
      const res = await fetch(`http://localhost:5000/messages/${messageId}`, { 
        headers: { 'Authorization': `Bearer ${token}` } 
      }); 
      const data = await res.json(); 
      if (!res.ok) throw new Error(data.error || 'Failed to retrieve message'); 
      setResponse(`Retrieved: ID ${data.id}, Content: ${data.content}, Expires: ${data.expires_at}`); 
      setMessageId(''); 
    } catch (err) { 
      console.error('Retrieve error:', err); 
      setResponse('Error: ' + err.message); 
    } 
  }; 
  const deleteMessage = async (e) => { 
    e.preventDefault(); 
    if (!token) return setResponse('Error: Please log in'); 
    try { 
      const res = await fetch(`http://localhost:5000/messages/${messageId}`, { 
        method: 'DELETE', 
        headers: { 'Authorization': `Bearer ${token}` } 
      }); 
      const data = await res.json(); 
      if (!res.ok) throw new Error(data.error || 'Failed to delete message'); 
      setResponse(data.message); 
      setMessageId(''); 
    } catch (err) { 
      console.error('Delete error:', err); 
      setResponse('Error: ' + err.message); 
    } 
  }; 
  const listMessages = async () => { 
    if (!token) return setResponse('Error: Please log in'); 
    try { 
      const res = await fetch('http://localhost:5000/messages', { 
        headers: { 'Authorization': `Bearer ${token}` } 
      }); 
      const data = await res.json(); 
      if (!res.ok) throw new Error(data.error || 'Failed to list messages'); 
      setMessages(data); 
      setResponse(data.length > 0 ? 'Messages retrieved' : 'No messages found'); 
    } catch (err) { 
      console.error('List error:', err); 
      setResponse('Error: ' + err.message); 
    } 
  }; 
  return ( 
    <div className="App"> 
      <h1>Vanish</h1> 
      <p className="status">Status: {token ? 'Logged in' : 'Not logged in'}</p> 
      <p className="notification">Notification: {notification}</p> 
      {!token && ( 
        <div className="form-container"> 
          <form onSubmit={register}> 
            <input 
              type="text" 
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
              placeholder="Username" 
            /> 
            <input 
              type="password" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              placeholder="Password" 
            /> 
            <button type="submit">Register</button> 
          </form> 
          <form onSubmit={login}> 
            <input 
              type="text" 
              value={username} 
              onChange={(e) => setUsername(e.target.value)} 
              placeholder="Username" 
            /> 
            <input 
              type="password" 
              value={password} 
              onChange={(e) => setPassword(e.target.value)} 
              placeholder="Password" 
            /> 
            <button type="submit">Login</button> 
          </form> 
        </div> 
      )} 
      {token && ( 
        <div className="form-container"> 
          <button onClick={logout}>Logout</button> 
          <button onClick={listMessages}>List Messages</button> 
          <form onSubmit={sendMessage}> 
            <input 
              type="text" 
              value={message} 
              onChange={(e) => setMessage(e.target.value)} 
              placeholder="Enter message to send" 
            /> 
            <button type="submit">Send</button> 
          </form> 
          <form onSubmit={getMessage}> 
            <input 
              type="text" 
              value={messageId} 
              onChange={(e) => setMessageId(e.target.value)} 
              placeholder="Enter message ID to retrieve" 
            /> 
            <button type="submit">Retrieve</button> 
          </form> 
          <form onSubmit={deleteMessage}> 
            <input 
              type="text" 
              value={messageId} 
              onChange={(e) => setMessageId(e.target.value)} 
              placeholder="Enter message ID to delete" 
            /> 
            <button type="submit">Delete</button> 
          </form> 
          {messages.length > 0 && ( 
            <ul className="message-list"> 
              {messages.map(msg => ( 
                <li key={msg.id} className="message-item"> 
                  ID: {msg.id}, Content: {msg.content}, Expires: {msg.expires_at} 
                </li> 
              ))} 
            </ul> 
          )} 
        </div> 
      )} 
      <p className={response.startsWith('Error') ? 'error' : ''}>Response: {response}</p> 
    </div> 
  ); 
} 
export default App; 
