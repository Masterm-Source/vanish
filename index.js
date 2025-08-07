const express = require('express'); 
const { Pool } = require('pg'); 
const cors = require('cors'); 
const crypto = require('crypto'); 
const jwt = require('jsonwebtoken'); 
const bcrypt = require('bcrypt'); 
const { Server } = require('socket.io'); 
const http = require('http'); 
const cron = require('node-cron'); 
const app = express(); 
const server = http.createServer(app); 
const io = new Server(server, { cors: { origin: 'http://localhost:3001' } }); 
const port = 5000; 
const JWT_SECRET = 'vanish-secret-123'; 
app.use(cors({ origin: 'http://localhost:3001' })); 
app.use(express.json()); 
const pool = new Pool({ 
  user: 'vanish_user', 
  host: 'localhost', 
  database: 'vanish_db', 
  password: 'vanish123', 
  port: 5432 
}); 
const key = crypto.scryptSync('secret-key-123', 'salt', 32); 
const encrypt = (text) => { 
  const iv = crypto.randomBytes(16); 
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv); 
  let encrypted = cipher.update(text, 'utf8', 'hex'); 
  encrypted += cipher.final('hex'); 
  return { iv: iv.toString('hex'), content: encrypted }; 
}; 
const decrypt = (encrypted, iv) => { 
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(iv, 'hex')); 
  let decrypted = decipher.update(encrypted, 'hex', 'utf8'); 
  decrypted += decipher.final('utf8'); 
  return decrypted; 
}; 
const authenticateToken = async (req, res, next) => { 
  const authHeader = req.headers['authorization']; 
  const token = authHeader && authHeader.split(' ')[1]; 
  if (!token) return res.status(401).json({ error: 'Access denied' }); 
  try { 
    const decoded = jwt.verify(token, JWT_SECRET); 
    req.user = decoded; 
    next(); 
  } catch (err) { 
    res.status(403).json({ error: 'Invalid token' }); 
  } 
}; 
io.use((socket, next) => { 
  const token = socket.handshake.auth.token; 
  if (!token) return next(new Error('Authentication error')); 
  try { 
    const decoded = jwt.verify(token, JWT_SECRET); 
    socket.user = decoded; 
    next(); 
  } catch (err) { 
    next(new Error('Invalid token')); 
  } 
}); 
io.on('connection', (socket) => { 
  console.log('Client connected:', socket.id, 'User:', socket.user.username); 
  socket.on('disconnect', () => console.log('Client disconnected:', socket.id)); 
}); 
cron.schedule('0 * * * *', async () => { 
  try { 
    const result = await pool.query('DELETE FROM messages WHERE expires_at <= NOW() RETURNING id'); 
    if (result.rows.length > 0) { 
      const deletedIds = result.rows.map(row => row.id); 
      io.emit('messageCleaned', { ids: deletedIds }); 
      console.log('Cleaned expired messages:', deletedIds); 
    } 
  } catch (err) { 
    console.error('Cleanup error:', err.message); 
  } 
}); 
app.post('/register', async (req, res) => { 
  try { 
    const { username, password } = req.body; 
    if (!username || !password) throw new Error('Username and password required'); 
    const hashedPassword = await bcrypt.hash(password, 10); 
    const result = await pool.query( 
      'INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id, username', 
      [username, hashedPassword] 
    ); 
    res.json({ message: 'User registered', user: result.rows[0] }); 
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  } 
}); 
app.post('/login', async (req, res) => { 
  try { 
    const { username, password } = req.body; 
    if (!username || !password) throw new Error('Username and password required'); 
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]); 
    if (result.rows.length === 0) throw new Error('User not found'); 
    const user = result.rows[0]; 
    const validPassword = await bcrypt.compare(password, user.password); 
    if (!validPassword) throw new Error('Invalid password'); 
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' }); 
    res.json({ token }); 
  } catch (err) { 
    res.status(401).json({ error: err.message }); 
  } 
}); 
app.get('/', async (req, res) => { 
  try { 
    const result = await pool.query('SELECT NOW()'); 
    res.send('Vanish Backend: Database connected at ' + result.rows[0].now); 
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  } 
}); 
app.get('/messages', authenticateToken, async (req, res) => { 
  try { 
    const result = await pool.query( 
      'SELECT * FROM messages WHERE expires_at > NOW() AND user_id = $1', 
      [req.user.id] 
    ); 
    const messages = result.rows.map(row => { 
      const [encrypted, iv] = row.content.split(':'); 
      const decrypted = decrypt(encrypted, iv); 
      return { id: row.id, content: decrypted, created_at: row.created_at, expires_at: row.expires_at }; 
    }); 
    res.json(messages); 
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  } 
}); 
app.post('/messages', authenticateToken, async (req, res) => { 
  try { 
    const { content } = req.body; 
    if (!content) throw new Error('Content is required'); 
    const { iv, content: encryptedContent } = encrypt(content); 
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); 
    const result = await pool.query( 
      'INSERT INTO messages (content, expires_at, user_id) VALUES ($1, $2, $3) RETURNING *', 
      [encryptedContent + ':' + iv, expiresAt, req.user.id] 
    ); 
    io.emit('messageCreated', { id: result.rows[0].id, expires_at: result.rows[0].expires_at }); 
    res.json(result.rows[0]); 
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  } 
}); 
app.get('/messages/:id', authenticateToken, async (req, res) => { 
  try { 
    const { id } = req.params; 
    const result = await pool.query( 
      'SELECT * FROM messages WHERE id = $1 AND expires_at > NOW() AND user_id = $2', 
      [id, req.user.id] 
    ); 
    if (result.rows.length === 0) { 
      return res.status(404).json({ error: 'Message not found or expired' }); 
    } 
    const [encrypted, iv] = result.rows[0].content.split(':'); 
    const decrypted = decrypt(encrypted, iv); 
    res.json({ id: result.rows[0].id, content: decrypted, created_at: result.rows[0].created_at, expires_at: result.rows[0].expires_at }); 
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  } 
}); 
app.delete('/messages/:id', authenticateToken, async (req, res) => { 
  try { 
    const { id } = req.params; 
    const result = await pool.query( 
      'DELETE FROM messages WHERE id = $1 AND expires_at > NOW() AND user_id = $2 RETURNING id', 
      [id, req.user.id] 
    ); 
    if (result.rows.length === 0) { 
      return res.status(404).json({ error: 'Message not found or expired' }); 
    } 
    io.emit('messageDeleted', { id: result.rows[0].id }); 
    res.json({ message: `Deleted: ID ${result.rows[0].id}` }); 
  } catch (err) { 
    res.status(500).json({ error: err.message }); 
  } 
}); 
server.listen(port, () => console.log(`Server running on port ${port}`)); 
