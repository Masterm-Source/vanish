const { Pool } = require('pg');
const crypto = require('crypto');

const pool = new Pool({
  user: 'vanish_user',
  host: 'localhost',
  database: 'vanish_db',
  password: 'vanish123',
  port: 5432
});

// Decrypt message with sender's key
const decryptMessage = (encryptedContent, senderKey) => {
  try {
    const [encrypted, ivHex] = encryptedContent.split(':');
    const algorithm = 'aes-256-cbc';
    const key = crypto.scryptSync(senderKey, 'vanish-salt', 32);
    const iv = Buffer.from(ivHex, 'hex');
    
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error('Invalid decryption key');
  }
};

// Initialize Socket.IO with revolutionary features
const initializeSocket = (io, authenticateSocket, handleDisconnect) => {
  
  io.use(authenticateSocket);

  io.on('connection', (socket) => {
    console.log(`🔗 User connected: ${socket.user.username} (ID: ${socket.user.id})`);

    // Join user to their personal room for notifications
    socket.join(`user_${socket.user.id}`);

    // Join user to their conversation rooms
    joinUserConversations(socket);

    // Handle joining conversation rooms
    socket.on('join_conversation', async (data) => {
      try {
        const { conversation_id } = data;
        
        // Verify user is participant
        const participantCheck = await pool.query(
          'SELECT id FROM conversation_participants WHERE conversation_id = $1 AND user_id = $2',
          [conversation_id, socket.user.id]
        );

        if (participantCheck.rows.length > 0) {
          socket.join(`conversation_${conversation_id}`);
          console.log(`📱 ${socket.user.username} joined conversation ${conversation_id}`);
        }
      } catch (error) {
        console.error('Join conversation error:', error);
      }
    });

    // Handle new message sending
    socket.on('send_message', async (data) => {
      try {
        const { conversation_id, content, sender_key, key_hint, message_type = 'text' } = data;
        const senderId = socket.user.id;

        // Verify user is participant
        const participantCheck = await pool.query(
          'SELECT id FROM conversation_participants WHERE conversation_id = $1 AND user_id = $2',
          [conversation_id, senderId]
        );

        if (participantCheck.rows.length === 0) {
          socket.emit('error', { message: 'Not authorized to send messages' });
          return;
        }

        // Encrypt message
        const algorithm = 'aes-256-cbc';
        const key = crypto.scryptSync(sender_key, 'vanish-salt', 32);
        const iv = crypto.randomBytes(16);
        
        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(content, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const encryptedContent = `${encrypted}:${iv.toString('hex')}`;

        // Calculate self-destruction time
        const destructionTimer = content.length <= 50 ? 60 : 
                               content.length <= 200 ? 120 : 
                               content.length <= 500 ? 180 : 240;

        // Store message
        const result = await pool.query(`
          INSERT INTO messages (
            conversation_id, sender_id, content, message_type, 
            sender_key_hint, self_destruct_timer, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
          RETURNING *
        `, [conversation_id, senderId, encryptedContent, message_type, key_hint, destructionTimer]);

        const message = result.rows[0];

        // Update conversation last message time
        await pool.query(
          'UPDATE conversations SET last_message_at = NOW() WHERE id = $1',
          [conversation_id]
        );

        // Broadcast to conversation participants
        const messageData = {
          id: message.id,
          conversation_id: message.conversation_id,
          sender_id: message.sender_id,
          sender_username: socket.user.username,
          sender_photo: socket.user.profile_photo,
          message_type: message.message_type,
          sender_key_hint: message.sender_key_hint,
          is_decrypted: false,
          self_destruct_timer: message.self_destruct_timer,
          created_at: message.created_at,
          content: '[ENCRYPTED - Double-click to request decryption]'
        };

        io.to(`conversation_${conversation_id}`).emit('new_message', messageData);
        console.log(`💬 Message sent in conversation ${conversation_id}`);

      } catch (error) {
        console.error('Send message error:', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    // Handle decryption request (revolutionary feature)
    socket.on('request_decryption', async (data) => {
      try {
        const { message_id } = data;
        const requesterId = socket.user.id;

        // Get message details
        const messageResult = await pool.query(
          'SELECT * FROM messages WHERE id = $1',
          [message_id]
        );

        if (messageResult.rows.length === 0) {
          socket.emit('error', { message: 'Message not found' });
          return;
        }

        const message = messageResult.rows[0];

        // Don't allow sender to request their own message
        if (message.sender_id === requesterId) {
          socket.emit('error', { message: 'Cannot request decryption of your own message' });
          return;
        }

        // Create decryption request
        const requestResult = await pool.query(`
          INSERT INTO decryption_requests (
            message_id, requester_id, sender_id, status
          ) VALUES ($1, $2, $3, 'pending') 
          RETURNING *
        `, [message_id, requesterId, message.sender_id]);

        const request = requestResult.rows[0];

        // Notify sender about decryption request
        io.to(`user_${message.sender_id}`).emit('decryption_request', {
          request_id: request.id,
          message_id: message_id,
          requester_username: socket.user.username,
          requester_photo: socket.user.profile_photo,
          key_hint: message.sender_key_hint,
          requested_at: request.requested_at
        });

        // Confirm to requester
        socket.emit('decryption_requested', {
          message: 'Decryption request sent to sender'
        });

        console.log(`🔓 Decryption requested for message ${message_id}`);

      } catch (error) {
        console.error('Request decryption error:', error);
        socket.emit('error', { message: 'Failed to request decryption' });
      }
    });

    // Handle sender providing decryption key (revolutionary feature)
    socket.on('provide_decryption_key', async (data) => {
      try {
        const { request_id, decryption_key, approve = true } = data;
        const senderId = socket.user.id;

        // Get decryption request
        const requestResult = await pool.query(
          'SELECT * FROM decryption_requests WHERE id = $1 AND sender_id = $2',
          [request_id, senderId]
        );

        if (requestResult.rows.length === 0) {
          socket.emit('error', { message: 'Decryption request not found' });
          return;
        }

        const request = requestResult.rows[0];

        if (!approve) {
          // Deny decryption request
          await pool.query(
            'UPDATE decryption_requests SET status = $1, resolved_at = NOW() WHERE id = $2',
            ['denied', request_id]
          );

          io.to(`user_${request.requester_id}`).emit('decryption_denied', {
            message_id: request.message_id,
            message: 'Sender denied decryption request'
          });

          socket.emit('decryption_response_sent', { message: 'Decryption request denied' });
          return;
        }

        // Get message to decrypt
        const messageResult = await pool.query(
          'SELECT * FROM messages WHERE id = $1',
          [request.message_id]
        );

        const message = messageResult.rows[0];

        // Try to decrypt with provided key
        const decryptedContent = decryptMessage(message.content, decryption_key);

        // Update message as decrypted
        await pool.query(
          'UPDATE messages SET is_decrypted = true, decryption_key = $1 WHERE id = $2',
          [decryption_key, request.message_id]
        );

        // Update request as approved
        await pool.query(
          'UPDATE decryption_requests SET status = $1, resolved_at = NOW() WHERE id = $2',
          ['approved', request_id]
        );

        // Send decrypted message to requester with self-destruction
        io.to(`user_${request.requester_id}`).emit('message_decrypted', {
          message_id: request.message_id,
          content: decryptedContent,
          self_destruct_timer: message.self_destruct_timer,
          decrypted_at: new Date()
        });

        // Confirm to sender
        socket.emit('decryption_response_sent', {
          message: 'Message decrypted for requester'
        });

        console.log(`🔑 Message ${request.message_id} decrypted successfully`);

      } catch (error) {
        console.error('Provide decryption key error:', error);
        socket.emit('error', { 
          message: error.message.includes('Invalid decryption key') ? 
                   'Invalid decryption key' : 'Failed to decrypt message' 
        });
      }
    });

    // Handle typing indicators
    socket.on('typing', (data) => {
      const { conversation_id, is_typing } = data;
      socket.to(`conversation_${conversation_id}`).emit('user_typing', {
        user_id: socket.user.id,
        username: socket.user.username,
        is_typing
      });
    });

    // Handle message self-destruction
    socket.on('message_self_destructed', async (data) => {
      try {
        const { message_id } = data;

        // Mark message as destroyed
        await pool.query(
          'UPDATE messages SET destroyed_at = NOW() WHERE id = $1',
          [message_id]
        );

        console.log(`💥 Message ${message_id} self-destructed`);

      } catch (error) {
        console.error('Self-destruct error:', error);
      }
    });

    // Handle disconnect
    socket.on('disconnect', async () => {
      console.log(`❌ User disconnected: ${socket.user.username}`);
      await handleDisconnect(socket.user.id);
    });

  });

  // Helper function to join user to their conversation rooms
  const joinUserConversations = async (socket) => {
    try {
      const result = await pool.query(`
        SELECT DISTINCT c.id
        FROM conversations c
        JOIN conversation_participants cp ON c.id = cp.conversation_id
        WHERE cp.user_id = $1
      `, [socket.user.id]);

      result.rows.forEach(row => {
        socket.join(`conversation_${row.id}`);
      });

    } catch (error) {
      console.error('Join conversations error:', error);
    }
  };

  console.log('🚀 Revolutionary Socket.IO service initialized');
};

module.exports = {
  initializeSocket
};
