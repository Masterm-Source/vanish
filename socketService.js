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

// Generate fake base64 decoy content
const generateDecoy = (originalMessageLength) => {
  // Create realistic decoy length (1.3x to 1.8x original length)
  const multiplier = 1.3 + (Math.random() * 0.5);
  const targetLength = Math.ceil(originalMessageLength * multiplier);
  
  // Generate random bytes and convert to base64
  const randomBytes = crypto.randomBytes(targetLength);
  let decoy = randomBytes.toString('base64');
  
  // Add some realistic-looking structure occasionally
  if (Math.random() > 0.5) {
    // Insert some dots, equals signs, and slashes to make it look more authentic
    const insertions = ['...', '==', '//', '::'];
    const randomInsertion = insertions[Math.floor(Math.random() * insertions.length)];
    const insertPosition = Math.floor(decoy.length * Math.random());
    decoy = decoy.slice(0, insertPosition) + randomInsertion + decoy.slice(insertPosition);
  }
  
  // Ensure minimum length for very short messages
  if (decoy.length < 50) {
    decoy += crypto.randomBytes(30).toString('base64');
  }
  
  return decoy;
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

    // REPLACE your entire send_message handler (around lines 75-130) with this:

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

        // Generate decoy content
        const decoyContent = generateDecoy(content.length);

        // Calculate self-destruction time
        const destructionTimer = content.length <= 50 ? 60 : 
                               content.length <= 200 ? 120 : 
                               content.length <= 500 ? 180 : 240;

        // Store message with decoy
        const result = await pool.query(`
          INSERT INTO messages (
            conversation_id, sender_id, content, message_type, 
            sender_key_hint, self_destruct_timer, decoy_content, 
            is_encrypted_display, is_seen, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW()) 
          RETURNING *
        `, [conversation_id, senderId, encryptedContent, message_type, key_hint, destructionTimer, decoyContent, true, false]);

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
          is_encrypted_display: true,
          is_decrypted: false,
          is_seen: false,
          self_destruct_timer: message.self_destruct_timer,
          created_at: message.created_at,
          content: decoyContent,  // Show decoy to everyone initially
          decoy_content: decoyContent
        };

        io.to(`conversation_${conversation_id}`).emit('new_message', messageData);
        console.log(`💬 Message sent in conversation ${conversation_id} with decoy`);

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

    // Handle message seen (read receipt)
    socket.on('message_seen', async (data) => {
      try {
        const { message_id } = data;
        const viewerId = socket.user.id;

        // Update message as seen
        const result = await pool.query(
          'UPDATE messages SET is_seen = true WHERE id = $1 AND sender_id != $2 RETURNING sender_id',
          [message_id, viewerId]
        );

        if (result.rows.length > 0) {
          const senderId = result.rows[0].sender_id;
          
          // Notify sender that message was seen
          io.to(`user_${senderId}`).emit('message_seen_update', {
            message_id: message_id,
            seen_by: socket.user.username,
            seen_at: new Date()
          });

          console.log(`👀 Message ${message_id} seen by ${socket.user.username}`);
        }

      } catch (error) {
        console.error('Message seen error:', error);
      }
    });

    // Handle inline decryption request
    socket.on('inline_decryption_request', async (data) => {
      try {
        const { message_id, sender_id } = data;
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

        // Notify sender about inline decryption request
        io.to(`user_${sender_id}`).emit('inline_decryption_request', {
          message_id: message_id,
          requester_username: socket.user.username,
          requester_id: requesterId,
          key_hint: message.sender_key_hint
        });

        console.log(`🔓 Inline decryption requested for message ${message_id}`);

      } catch (error) {
        console.error('Inline decryption request error:', error);
        socket.emit('error', { message: 'Failed to request decryption' });
      }
    });

    // Handle inline decryption key provision
    socket.on('provide_inline_decryption', async (data) => {
      try {
        const { message_id, decryption_key, approve = true } = data;
        const senderId = socket.user.id;

        // Get message
        const messageResult = await pool.query(
          'SELECT * FROM messages WHERE id = $1 AND sender_id = $2',
          [message_id, senderId]
        );

        if (messageResult.rows.length === 0) {
          socket.emit('error', { message: 'Message not found or not authorized' });
          return;
        }

        const message = messageResult.rows[0];

        if (!approve) {
          // Deny decryption request
          io.to(`conversation_${message.conversation_id}`).emit('inline_decryption_denied', {
            message_id: message_id,
            message: 'Sender denied decryption request'
          });

          socket.emit('decryption_response_sent', { message: 'Decryption request denied' });
          return;
        }

        // Try to decrypt with provided key
        const decryptedContent = decryptMessage(message.content, decryption_key);

        // Update message as decrypted
        await pool.query(
          'UPDATE messages SET is_decrypted = true, is_encrypted_display = false WHERE id = $1',
          [message_id]
        );

        // Emit decryption animation to all conversation participants
        io.to(`conversation_${message.conversation_id}`).emit('start_decryption_animation', {
          message_id: message_id,
          decoy_content: message.decoy_content,
          real_content: decryptedContent,
          self_destruct_timer: message.self_destruct_timer
        });

        console.log(`🔑 Message ${message_id} decrypted inline successfully`);

      } catch (error) {
        console.error('Provide inline decryption error:', error);
        socket.emit('error', { 
          message: error.message.includes('Invalid decryption key') ? 
                   'Invalid decryption key' : 'Failed to decrypt message' 
        });
      }
    });

    // Handle delete message
    socket.on('delete_message', async (data) => {
      try {
        const { message_id } = data;
        const userId = socket.user.id;

        // Check if user is authorized to delete (sender or recipient)
        const messageResult = await pool.query(`
          SELECT m.*, cp.user_id as participant_user_id
          FROM messages m
          JOIN conversation_participants cp ON m.conversation_id = cp.conversation_id
          WHERE m.id = $1 AND (m.sender_id = $2 OR cp.user_id = $2)
        `, [message_id, userId]);

        if (messageResult.rows.length === 0) {
          socket.emit('error', { message: 'Not authorized to delete this message' });
          return;
        }

        const message = messageResult.rows[0];

        // Mark message as deleted
        await pool.query(
          'UPDATE messages SET deleted_at = NOW(), deleted_by = $1 WHERE id = $2',
          [userId, message_id]
        );

        // Notify all conversation participants
        io.to(`conversation_${message.conversation_id}`).emit('message_deleted', {
          message_id: message_id,
          deleted_by: socket.user.username,
          deleted_at: new Date()
        });

        console.log(`🗑️ Message ${message_id} deleted by ${socket.user.username}`);

      } catch (error) {
        console.error('Delete message error:', error);
        socket.emit('error', { message: 'Failed to delete message' });
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
