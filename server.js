require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Datastore = require('nedb');
const path = require('path');
const fs = require('fs');

// Create data directory if it doesn't exist
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
    fs.mkdirSync(dataDir);
}

// Initialize Express app
const app = express();
const server = http.createServer(app);

// Configure CORS
const corsOptions = {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
    credentials: true
};

app.use(cors(corsOptions));

// Configure Socket.IO with CORS
const io = socketIO(server, {
    cors: {
        origin: 'http://localhost:3000',
        methods: ['GET', 'POST'],
        credentials: true
    }
});

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Initialize databases
const db = {
    users: new Datastore({ filename: path.join(dataDir, 'users.db'), autoload: true }),
    messages: new Datastore({ filename: path.join(dataDir, 'messages.db'), autoload: true }),
    sessions: new Datastore({ filename: path.join(dataDir, 'sessions.db'), autoload: true })
};

// Create indices
db.users.ensureIndex({ fieldName: 'username', unique: true });
db.messages.ensureIndex({ fieldName: 'timestamp' });

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something went wrong!' });
});

// Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // Check if username exists
        const existingUser = await new Promise((resolve, reject) => {
            db.users.findOne({ username }, (err, user) => {
                if (err) reject(err);
                resolve(user);
            });
        });

        if (existingUser) {
            return res.status(400).json({ message: 'Username already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = {
            username,
            password: hashedPassword,
            createdAt: new Date(),
            status: 'Hey there! I am using WhatsApp Clone',
            profilePicture: null,
            isOnline: true
        };

        db.users.insert(user, (err, newUser) => {
            if (err) {
                return res.status(500).json({ message: 'Error creating user' });
            }

            const token = jwt.sign({ id: newUser._id, username }, JWT_SECRET);
            res.status(201).json({ token, user: { ...newUser, password: undefined } });
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Find user
        db.users.findOne({ username }, async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                return res.status(401).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign({ id: user._id, username }, JWT_SECRET);
            res.json({ token, user: { ...user, password: undefined } });
        });
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

// Get all users
app.get('/api/users', authenticateToken, (req, res) => {
    db.users.find({}, { password: 0 }, (err, users) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching users' });
        }
        res.json(users);
    });
});

// Get user messages
app.get('/api/messages/:userId', authenticateToken, (req, res) => {
    const { userId } = req.params;
    db.messages.find({
        $or: [
            { sender: req.user.id, recipient: userId },
            { sender: userId, recipient: req.user.id }
        ]
    })
    .sort({ timestamp: 1 })
    .exec((err, messages) => {
        if (err) {
            return res.status(500).json({ message: 'Error fetching messages' });
        }
        res.json(messages);
    });
});

// Map to store connected users
const connectedUsers = new Map();

// Function to broadcast updated user list
function broadcastUsers() {
    const users = Array.from(connectedUsers.values()).map((user) => ({
        userId: user.user._id,
        username: user.user.username,
        isOnline: user.isOnline
    }));
    io.emit('users', users);
}

// Socket.IO connection handling
io.on('connection', (socket) => {
    const token = socket.handshake.auth.token;
    if (!token) {
        socket.disconnect();
        return;
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.userId = decoded.userId;

        // Find user in database
        db.users.findOne({ _id: socket.userId }, (err, user) => {
            if (err || !user) {
                socket.disconnect();
                return;
            }

            socket.user = user;
            connectedUsers.set(socket.userId, {
                socket,
                user,
                isOnline: true
            });

            // Broadcast updated user list
            broadcastUsers();
        });

        socket.on('private message', async (data) => {
            const { recipientId, content } = data;
            const recipient = connectedUsers.get(recipientId);
            const sender = connectedUsers.get(socket.userId);

            if (!recipient || !sender) return;

            const message = {
                _id: Date.now().toString(),
                sender: socket.userId,
                senderName: sender.user.username,
                recipient: recipientId,
                content,
                timestamp: new Date().toISOString(),
                status: 'sent'
            };

            // Send to recipient if online
            if (recipient.socket) {
                recipient.socket.emit('private message', message);
                message.status = 'delivered';
                socket.emit('message status', { messageId: message._id, status: 'delivered' });
            }

            // Send back to sender with status
            socket.emit('private message', { ...message, status: 'sent' });
        });

        // Handle typing events
        socket.on('typing', ({ recipientId }) => {
            const recipient = connectedUsers.get(recipientId);
            if (recipient?.socket) {
                recipient.socket.emit('typing', { userId: socket.userId });
            }
        });

        socket.on('stopTyping', ({ recipientId }) => {
            const recipient = connectedUsers.get(recipientId);
            if (recipient?.socket) {
                recipient.socket.emit('stopTyping', { userId: socket.userId });
            }
        });

        socket.on('disconnect', () => {
            if (socket.userId) {
                connectedUsers.delete(socket.userId);
                broadcastUsers();
            }
        });

    } catch (error) {
        socket.disconnect();
    }
});

// Start server
const PORT = process.env.PORT || 3001;
server.listen(PORT, '0.0.0.0', (err) => {
    if (err) {
        console.error('Error starting server:', err);
        return;
    }
    console.log(`Server running on port ${PORT}`);
});
