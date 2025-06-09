// ========================================
// GOSOK ANGKA BACKEND - FIXED VERSION 3.1.0
// Added Forced Winning Number Feature
// ========================================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIO = require('socket.io');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// CHECK CRITICAL ENV VARS
if (!process.env.JWT_SECRET) {
    console.error('❌ FATAL ERROR: JWT_SECRET is not defined in environment variables!');
    process.exit(1);
}
if (!process.env.MONGODB_URI) {
    console.error('❌ FATAL ERROR: MONGODB_URI is not defined in environment variables!');
    process.exit(1);
}
console.log('✅ Environment variables configured');

// ========================================
// DATABASE CONNECTION
// ========================================
async function connectDB() {
    try {
        const mongoURI = process.env.MONGODB_URI;
        
        console.log('🔌 Connecting to MongoDB...');
        
        await mongoose.connect(mongoURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            retryWrites: true,
            w: 'majority'
        });
        
        console.log('✅ MongoDB connected successfully!');
        console.log(`📊 Database: ${mongoose.connection.name}`);
        
    } catch (error) {
        console.error('❌ MongoDB connection error:', error.message);
        process.exit(1);
    }
}

// Connect to database immediately
connectDB();

// ========================================
// CORS CONFIGURATION
// ========================================
const allowedOrigins = [
    // Netlify domains
    'https://gosokangkahoki.netlify.app',     
    'https://www.gosokangkahoki.netlify.app',
    /^https:\/\/.*--gosokangkahoki\.netlify\.app$/,
    /^https:\/\/.*\.gosokangkahoki\.netlify\.app$/,
    
    // Custom domains
    'https://gosokangkahoki.com',             
    'https://www.gosokangkahoki.com',         
    'http://gosokangkahoki.com',              
    'http://www.gosokangkahoki.com',         
    
    // Railway backend
    'https://gosokangka-backend-production.up.railway.app',
    
    // Development
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000',
    'http://localhost:8080',
    'http://127.0.0.1:8080'
];

app.use(cors({
    origin: function(origin, callback) {
        console.log('🔍 CORS Debug - Request origin:', origin);
        
        if (!origin) {
            console.log('✅ CORS: Allowing request with no origin');
            return callback(null, true);
        }
        
        if (allowedOrigins.includes(origin)) {
            console.log('✅ CORS: Origin allowed (exact match):', origin);
            return callback(null, true);
        }
        
        const isAllowed = allowedOrigins.some(allowed => {
            if (allowed instanceof RegExp) {
                return allowed.test(origin);
            }
            return false;
        });
        
        if (isAllowed) {
            console.log('✅ CORS: Origin allowed (regex match):', origin);
            return callback(null, true);
        }
        
        if (origin.includes('.netlify.app')) {
            console.log('⚠️ CORS: Temporarily allowing Netlify domain:', origin);
            return callback(null, true);
        }
        
        console.log('❌ CORS: Origin blocked:', origin);
        const error = new Error(`CORS blocked: ${origin} not allowed`);
        error.status = 403;
        callback(error);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: [
        'Content-Type', 
        'Authorization', 
        'X-Requested-With',
        'Accept',
        'Origin',
        'Access-Control-Request-Method',
        'Access-Control-Request-Headers'
    ],
    optionsSuccessStatus: 200
}));

// Handle preflight requests
app.options('*', (req, res) => {
    console.log('🔍 Preflight request from:', req.headers.origin);
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, Content-Length, X-Requested-With');
    res.header('Access-Control-Allow-Credentials', true);
    res.sendStatus(200);
});

// ========================================
// SOCKET.IO SETUP
// ========================================
const io = socketIO(server, {
    cors: {
        origin: function(origin, callback) {
            if (!origin) return callback(null, true);
            
            if (allowedOrigins.includes(origin) || 
                allowedOrigins.some(allowed => allowed instanceof RegExp && allowed.test(origin)) ||
                origin.includes('.netlify.app')) {
                return callback(null, true);
            }
            
            callback(new Error('Socket.IO CORS blocked'));
        },
        credentials: true,
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling'],
    allowEIO3: true
});

// Global socket manager
const socketManager = {
    broadcastPrizeUpdate: (data) => {
        io.emit('prizes:updated', data);
        console.log('📡 Broadcasting prize update:', data.type);
    },
    broadcastSettingsUpdate: (data) => {
        io.emit('settings:updated', data);
        console.log('📡 Broadcasting settings update');
    },
    broadcastUserUpdate: (data) => {
        io.emit('users:updated', data);
        console.log('📡 Broadcasting user update:', data.type);
    },
    broadcastNewWinner: (data) => {
        io.emit('winner:new', data);
        console.log('📡 Broadcasting new winner');
    },
    broadcastNewScratch: (data) => {
        io.emit('scratch:new', data);
        console.log('📡 Broadcasting new scratch');
    },
    broadcastNewUser: (data) => {
        io.emit('user:new-registration', data);
        console.log('📡 Broadcasting new user registration');
    },
    broadcastTokenPurchase: (data) => {
        io.emit('token:purchased', data);
        console.log('📡 Broadcasting token purchase');
    }
};

// Add middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
    console.log(`🔍 ${req.method} ${req.path} from origin: ${req.headers.origin || 'NO-ORIGIN'}`);
    next();
});

// ========================================
// DATABASE SCHEMAS - UPDATED WITH FORCED WINNING
// ========================================

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true },
    password: { type: String, required: true },
    phoneNumber: { type: String, required: true },
    status: { type: String, default: 'active' },
    scratchCount: { type: Number, default: 0 },
    winCount: { type: Number, default: 0 },
    lastScratchDate: { type: Date },
    customWinRate: { type: Number, default: null },
    freeScratchesRemaining: { type: Number, default: 1 }, 
    paidScratchesRemaining: { type: Number, default: 0 }, 
    totalPurchasedScratches: { type: Number, default: 0 },
    forcedWinningNumber: { type: String, default: null }, // NEW: Admin bisa set angka khusus untuk user
    createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});

const prizeSchema = new mongoose.Schema({
    winningNumber: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    type: { type: String, enum: ['voucher', 'cash', 'physical'], required: true },
    value: { type: Number, required: true },
    stock: { type: Number, required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

const scratchSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    scratchNumber: { type: String, required: true },
    isWin: { type: Boolean, default: false },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize' },
    isPaid: { type: Boolean, default: false },
    scratchDate: { type: Date, default: Date.now }
});

const winnerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize', required: true },
    scratchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scratch', required: true },
    claimStatus: { type: String, enum: ['pending', 'completed', 'expired'], default: 'pending' },
    claimCode: { type: String, required: true },
    scratchDate: { type: Date, default: Date.now },
    claimDate: { type: Date }
});

const gameSettingsSchema = new mongoose.Schema({
    winningNumber: { type: String, required: true },
    winProbability: { type: Number, default: 5 },
    maxFreeScratchesPerDay: { type: Number, default: 1 },
    minFreeScratchesPerDay: { type: Number, default: 1 },
    scratchTokenPrice: { type: Number, default: 10000 },
    isGameActive: { type: Boolean, default: true },
    resetTime: { type: String, default: '00:00' }
});

const tokenPurchaseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    quantity: { type: Number, required: true },
    pricePerToken: { type: Number, required: true },
    totalAmount: { type: Number, required: true },
    paymentStatus: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
    paymentMethod: { type: String },
    notes: { type: String },
    purchaseDate: { type: Date, default: Date.now },
    completedDate: { type: Date }
});

const chatSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    userIP: { type: String },
    userAgent: { type: String },
    messages: [{
        from: { type: String, enum: ['user', 'admin'], required: true },
        message: { type: String, required: true },
        timestamp: { type: Date, default: Date.now },
        isRead: { type: Boolean, default: false }
    }],
    lastActivity: { type: Date, default: Date.now }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Prize = mongoose.model('Prize', prizeSchema);
const Scratch = mongoose.model('Scratch', scratchSchema);
const Winner = mongoose.model('Winner', winnerSchema);
const GameSettings = mongoose.model('GameSettings', gameSettingsSchema);
const Chat = mongoose.model('Chat', chatSchema);
const TokenPurchase = mongoose.model('TokenPurchase', tokenPurchaseSchema);

// ========================================
// MIDDLEWARE
// ========================================

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    
    if (!token) {
        console.error('❌ No token provided for:', req.path);
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        req.userType = decoded.userType;
        console.log('✅ Token verified:', { userId: decoded.userId, userType: decoded.userType });
        next();
    } catch (error) {
        console.error('❌ Token verification failed:', error.message);
        return res.status(403).json({ error: 'Invalid token: ' + error.message });
    }
};

const verifyAdmin = (req, res, next) => {
    if (req.userType !== 'admin') {
        console.error('❌ Admin access required for:', req.userId);
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ========================================
// SOCKET.IO HANDLERS
// ========================================

io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error'));
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.userId = decoded.userId;
        socket.userType = decoded.userType;
        next();
    } catch (err) {
        next(new Error('Authentication error'));
    }
});

io.on('connection', (socket) => {
    console.log('✅ User connected:', socket.userId, 'Type:', socket.userType);
    
    socket.join(`user-${socket.userId}`);
    
    if (socket.userType === 'admin') {
        socket.join('admin-room');
        
        // Handle admin events
        socket.on('admin:settings-changed', async (data) => {
            try {
                socket.broadcast.emit('settings:updated', data);
                console.log('📡 Admin changed settings, broadcasting to all clients');
            } catch (error) {
                console.error('Settings broadcast error:', error);
            }
        });
        
        socket.on('admin:prize-added', async (data) => {
            try {
                socket.broadcast.emit('prizes:updated', {
                    type: 'prize_added',
                    prizeData: data,
                    message: 'New prize added'
                });
                console.log('📡 Admin added prize, broadcasting to all clients');
            } catch (error) {
                console.error('Prize add broadcast error:', error);
            }
        });
        
        socket.on('admin:prize-updated', async (data) => {
            try {
                socket.broadcast.emit('prizes:updated', {
                    type: 'prize_updated',
                    prizeId: data.prizeId,
                    prizeData: data.data,
                    message: 'Prize updated'
                });
                console.log('📡 Admin updated prize, broadcasting to all clients');
            } catch (error) {
                console.error('Prize update broadcast error:', error);
            }
        });
        
        socket.on('admin:prize-deleted', async (data) => {
            try {
                socket.broadcast.emit('prizes:updated', {
                    type: 'prize_deleted',
                    prizeId: data.prizeId,
                    message: 'Prize deleted'
                });
                console.log('📡 Admin deleted prize, broadcasting to all clients');
            } catch (error) {
                console.error('Prize delete broadcast error:', error);
            }
        });
        
        // Emit admin connected event
        io.emit('admin:connected', {
            adminId: socket.userId,
            timestamp: new Date()
        });
        
        socket.on('admin:get-active-chats', async () => {
            try {
                const activeChats = await Chat.find({ 
                    lastActivity: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
                })
                .populate('userId', 'name email phoneNumber status lastScratchDate')
                .sort({ lastActivity: -1 });
                
                const formattedChats = activeChats.map(chat => {
                    const lastMessage = chat.messages[chat.messages.length - 1];
                    const unreadCount = chat.messages.filter(m => m.from === 'user' && !m.isRead).length;
                    
                    return {
                        _id: chat._id,
                        user: {
                            ...chat.userId.toObject(),
                            userIP: chat.userIP,
                            userAgent: chat.userAgent,
                            isOnline: io.sockets.adapter.rooms.has(`user-${chat.userId._id}`)
                        },
                        lastMessage: lastMessage ? {
                            content: lastMessage.message,
                            timestamp: lastMessage.timestamp,
                            from: lastMessage.from
                        } : null,
                        unreadCount,
                        lastActivity: chat.lastActivity
                    };
                });
                
                socket.emit('admin:active-chats', formattedChats);
            } catch (error) {
                socket.emit('error', { message: 'Failed to load chats' });
            }
        });
    }

    // Chat message handlers
    socket.on('chat:send-message', async (data) => {
        try {
            const { message, userIP, userAgent } = data;
            
            let chat = await Chat.findOne({ userId: socket.userId });
            if (!chat) {
                chat = new Chat({ 
                    userId: socket.userId, 
                    messages: [],
                    userIP: userIP || socket.handshake.address,
                    userAgent: userAgent || socket.handshake.headers['user-agent']
                });
            }
            
            if (userIP && chat.userIP !== userIP) {
                chat.userIP = userIP;
            }
            if (userAgent && chat.userAgent !== userAgent) {
                chat.userAgent = userAgent;
            }
            
            const newMessage = {
                from: socket.userType === 'admin' ? 'admin' : 'user',
                message: message.trim(),
                timestamp: new Date(),
                isRead: false
            };
            
            chat.messages.push(newMessage);
            chat.lastActivity = new Date();
            await chat.save();
            
            const user = await User.findById(socket.userId).select('name email phoneNumber');
            
            socket.emit('chat:message-sent', {
                ...newMessage,
                _id: chat.messages[chat.messages.length - 1]._id
            });
            
            if (socket.userType === 'admin') {
                io.to(`user-${data.targetUserId}`).emit('chat:new-message', {
                    ...newMessage,
                    chatId: chat._id
                });
            } else {
                io.to('admin-room').emit('chat:new-message', {
                    ...newMessage,
                    chatId: chat._id,
                    user: user,
                    userIP: chat.userIP,
                    userAgent: chat.userAgent
                });
            }
        } catch (error) {
            console.error('Send message error:', error);
            socket.emit('error', { message: 'Failed to send message' });
        }
    });

    socket.on('admin:send-message', async (data) => {
        try {
            const { userId, message } = data;
            
            let chat = await Chat.findOne({ userId });
            if (!chat) {
                chat = new Chat({ userId, messages: [] });
            }
            
            const newMessage = {
                from: 'admin',
                message: message.trim(),
                timestamp: new Date(),
                isRead: false
            };
            
            chat.messages.push(newMessage);
            chat.lastActivity = new Date();
            await chat.save();
            
            socket.emit('admin:message-sent', {
                ...newMessage,
                _id: chat.messages[chat.messages.length - 1]._id,
                userId
            });
            
            io.to(`user-${userId}`).emit('chat:new-message', {
                ...newMessage,
                chatId: chat._id
            });
        } catch (error) {
            socket.emit('error', { message: 'Failed to send message' });
        }
    });

    socket.on('disconnect', () => {
        console.log('❌ User disconnected:', socket.userId);
        
        if (socket.userType === 'user') {
            io.to('admin-room').emit('user:offline', {
                userId: socket.userId,
                timestamp: new Date()
            });
        }
    });
});

// ========================================
// ROUTES
// ========================================

// Root endpoint
app.get('/', (req, res) => {
    res.json({
        message: '🎯 Gosok Angka Backend API',
        version: '3.1.0',
        status: 'Production Ready',
        domain: 'gosokangkahoki.com',
        features: {
            realtime: 'Socket.io enabled with sync events',
            chat: 'Live chat support', 
            auth: 'Email/Phone login support',
            database: 'MongoDB Atlas connected',
            cors: 'Production domains configured',
            winRate: 'Per-user win rate support',
            tokenPurchase: 'Token purchase system enabled',
            forcedWinning: 'Admin can set winning number for users'
        },
        endpoints: {
            auth: '/api/auth',
            user: '/api/user', 
            game: '/api/game',
            admin: '/api/admin',
            public: '/api/public',
            tokenPurchase: '/api/token-purchase'
        },
        timestamp: new Date().toISOString()
    });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        uptime: process.uptime()
    });
});

// Alternative health check
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        uptime: process.uptime()
    });
});

// Status endpoint
app.get('/api/status', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString()
    });
});

// Test auth endpoint
app.get('/api/admin/test-auth', verifyToken, verifyAdmin, (req, res) => {
    res.json({
        message: 'Auth test successful',
        userId: req.userId,
        userType: req.userType,
        timestamp: new Date().toISOString()
    });
});

// ========================================
// AUTH ROUTES
// ========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phoneNumber } = req.body;
        
        if (!name || !password) {
            return res.status(400).json({ error: 'Nama dan password harus diisi' });
        }
        
        let userEmail = email;
        let userPhone = phoneNumber;
        
        if (email && !phoneNumber) {
            userPhone = '0000000000';
        }
        
        if (phoneNumber && !email) {
            const timestamp = Date.now();
            userEmail = `user${timestamp}@gosokangka.com`;
        }
        
        if (!userEmail || !userPhone) {
            return res.status(400).json({ error: 'Email atau nomor HP harus diisi' });
        }
        
        if (userEmail && userEmail !== 'dummy@gosokangka.com') {
            const existingUserByEmail = await User.findOne({ email: userEmail.toLowerCase() });
            if (existingUserByEmail) {
                return res.status(400).json({ error: 'Email sudah terdaftar' });
            }
        }
        
        if (userPhone && userPhone !== '0000000000') {
            const existingUserByPhone = await User.findOne({ phoneNumber: userPhone });
            if (existingUserByPhone) {
                return res.status(400).json({ error: 'Nomor HP sudah terdaftar' });
            }
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Get default settings for free scratches
        const settings = await GameSettings.findOne();
        const defaultFreeScratches = settings?.maxFreeScratchesPerDay || 1;
        
        const user = new User({
            name,
            email: userEmail.toLowerCase(),
            password: hashedPassword,
            phoneNumber: userPhone,
            freeScratchesRemaining: defaultFreeScratches
        });
        
        await user.save();
        
        // Broadcast new user registration
        socketManager.broadcastNewUser({
            user: {
                _id: user._id,
                name: user.name,
                email: user.email,
                phoneNumber: user.phoneNumber,
                createdAt: user.createdAt
            }
        });
        
        const token = jwt.sign(
            { userId: user._id, userType: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            message: 'Registrasi berhasil',
            token,
            user: {
                _id: user._id,
                id: user._id,
                name: user.name,
                email: user.email,
                phoneNumber: user.phoneNumber,
                scratchCount: user.scratchCount,
                winCount: user.winCount,
                status: user.status,
                freeScratchesRemaining: user.freeScratchesRemaining,
                paidScratchesRemaining: user.paidScratchesRemaining
            }
        });
    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password, email } = req.body;
        
        const loginIdentifier = identifier || email;
        
        if (!loginIdentifier || !password) {
            return res.status(400).json({ error: 'Email/No HP dan password harus diisi' });
        }
        
        let user;
        
        if (loginIdentifier.includes('@')) {
            user = await User.findOne({ email: loginIdentifier.toLowerCase() });
        } else {
            const cleanPhone = loginIdentifier.replace(/\D/g, '');
            user = await User.findOne({ phoneNumber: cleanPhone });
            
            if (!user) {
                user = await User.findOne({ phoneNumber: loginIdentifier });
            }
        }
        
        if (!user) {
            return res.status(400).json({ error: 'Email/No HP atau password salah' });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Email/No HP atau password salah' });
        }
        
        const token = jwt.sign(
            { userId: user._id, userType: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.json({
            message: 'Login berhasil',
            token,
            user: {
                _id: user._id,
                id: user._id,
                name: user.name,
                email: user.email,
                phoneNumber: user.phoneNumber,
                scratchCount: user.scratchCount,
                winCount: user.winCount,
                status: user.status,
                lastScratchDate: user.lastScratchDate,
                freeScratchesRemaining: user.freeScratchesRemaining,
                paidScratchesRemaining: user.paidScratchesRemaining
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// USER ROUTES  
// ========================================

app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json(user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// GAME ROUTES - UPDATED WITH FORCED WINNING
// ========================================

app.post('/api/game/scratch', verifyToken, async (req, res) => {
    try {
        const settings = await GameSettings.findOne();
        if (!settings || !settings.isGameActive) {
            return res.status(400).json({ error: 'Game sedang tidak aktif' });
        }
        
        const user = await User.findById(req.userId);
        
        // Check if user has any scratches remaining
        const totalScratches = (user.freeScratchesRemaining || 0) + (user.paidScratchesRemaining || 0);
        if (totalScratches <= 0) {
            // Check if it's a new day
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            if (!user.lastScratchDate || user.lastScratchDate < today) {
                // Reset free scratches for new day
                user.freeScratchesRemaining = settings.maxFreeScratchesPerDay || 1;
                await user.save();
            } else {
                return res.status(400).json({ 
                    error: 'Tidak ada kesempatan tersisa! Beli token scratch atau tunggu besok.',
                    needTokens: true 
                });
            }
        }
        
        // Generate scratch number - Check for forced winning number first
        let scratchNumber;
        if (user.forcedWinningNumber) {
            scratchNumber = user.forcedWinningNumber;
            // Clear forced winning number after use
            user.forcedWinningNumber = null;
            console.log(`🎯 Using forced winning number for ${user.name}: ${scratchNumber}`);
        } else {
            scratchNumber = Math.floor(1000 + Math.random() * 9000).toString();
        }
        
        let isWin = false;
        let prize = null;
        let winner = null;
        let isPaidScratch = false;
        
        // Use paid scratch first if available
        if (user.paidScratchesRemaining > 0) {
            isPaidScratch = true;
        }
        
        // Check for exact match first (guaranteed win)
        const activePrize = await Prize.findOne({ 
            winningNumber: scratchNumber,
            stock: { $gt: 0 },
            isActive: true
        });
        
        if (activePrize) {
            isWin = true;
            prize = activePrize;
            
            prize.stock -= 1;
            await prize.save();
            
            // Broadcast prize stock update
            socketManager.broadcastPrizeUpdate({
                type: 'stock_updated',
                prizeId: prize._id,
                newStock: prize.stock,
                message: 'Prize stock updated'
            });
        } else {
            // If no exact match, check win probability
            const winRate = user.customWinRate !== null ? user.customWinRate : settings.winProbability;
            console.log(`🎲 Win rate for ${user.name}: ${winRate}% (${user.customWinRate !== null ? 'custom' : 'global'})`);
            
            const randomChance = Math.random() * 100;
            if (randomChance <= winRate) {
                // User wins! Find a random available prize
                const availablePrizes = await Prize.find({
                    stock: { $gt: 0 },
                    isActive: true
                });
                
                if (availablePrizes.length > 0) {
                    // Select random prize
                    prize = availablePrizes[Math.floor(Math.random() * availablePrizes.length)];
                    isWin = true;
                    
                    prize.stock -= 1;
                    await prize.save();
                    
                    // Broadcast prize stock update
                    socketManager.broadcastPrizeUpdate({
                        type: 'stock_updated',
                        prizeId: prize._id,
                        newStock: prize.stock,
                        message: 'Prize stock updated'
                    });
                }
            }
        }
        
        const scratch = new Scratch({
            userId: req.userId,
            scratchNumber,
            isWin,
            prizeId: prize?._id,
            isPaid: isPaidScratch
        });
        
        await scratch.save();
        
        // Broadcast new scratch event
        const scratchData = {
            _id: scratch._id,
            userId: req.userId,
            scratchNumber,
            isWin,
            isPaid: isPaidScratch,
            scratchDate: scratch.scratchDate
        };
        
        if (isWin && prize) {
            scratchData.prize = {
                name: prize.name,
                type: prize.type,
                value: prize.value
            };
        }
        
        socketManager.broadcastNewScratch(scratchData);
        
        if (isWin && prize) {
            const claimCode = Math.random().toString(36).substring(2, 10).toUpperCase();
            
            winner = new Winner({
                userId: req.userId,
                prizeId: prize._id,
                scratchId: scratch._id,
                claimCode
            });
            
            await winner.save();
            
            // Broadcast new winner with populated data
            const winnerData = await Winner.findById(winner._id)
                .populate('userId', 'name email phoneNumber')
                .populate('prizeId', 'name value type');
                
            socketManager.broadcastNewWinner(winnerData);
        }
        
        // Update user scratch counts
        if (isPaidScratch) {
            user.paidScratchesRemaining -= 1;
        } else {
            user.freeScratchesRemaining -= 1;
        }
        
        user.scratchCount += 1;
        if (isWin) user.winCount += 1;
        user.lastScratchDate = new Date();
        
        await user.save();
        
        res.json({
            scratchNumber,
            isWin,
            prize: isWin ? {
                name: prize.name,
                type: prize.type,
                value: prize.value,
                claimCode: winner?.claimCode
            } : null,
            remainingScratches: {
                free: user.freeScratchesRemaining,
                paid: user.paidScratchesRemaining,
                total: user.freeScratchesRemaining + user.paidScratchesRemaining
            },
            isPaidScratch
        });
    } catch (error) {
        console.error('Scratch error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/user/history', verifyToken, async (req, res) => {
    try {
        const scratches = await Scratch.find({ userId: req.userId })
            .populate('prizeId')
            .sort({ scratchDate: -1 })
            .limit(50);
            
        res.json({ scratches });
    } catch (error) {
        console.error('History error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// PUBLIC ROUTES (NO AUTH REQUIRED)
// ========================================

// Get active prizes (for game app) - UPDATED to show all prizes regardless of stock
app.get('/api/public/prizes', async (req, res) => {
    try {
        const prizes = await Prize.find({ isActive: true }).sort({ createdAt: -1 });
        res.json(prizes);
    } catch (error) {
        console.error('Get public prizes error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get game settings with token price (for game app)
app.get('/api/public/game-settings', async (req, res) => {
    try {
        let settings = await GameSettings.findOne();
        
        if (!settings) {
            settings = new GameSettings({
                winningNumber: '1234',
                winProbability: 5,
                maxFreeScratchesPerDay: 1,
                minFreeScratchesPerDay: 1,
                scratchTokenPrice: 10000,
                isGameActive: true,
                resetTime: '00:00'
            });
            await settings.save();
        }
        
        // Only return public-safe fields
        res.json({
            isGameActive: settings.isGameActive,
            maxFreeScratchesPerDay: settings.maxFreeScratchesPerDay,
            minFreeScratchesPerDay: settings.minFreeScratchesPerDay,
            scratchTokenPrice: settings.scratchTokenPrice,
            resetTime: settings.resetTime
        });
    } catch (error) {
        console.error('Get public settings error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// ADMIN ROUTES
// ========================================

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username dan password harus diisi' });
        }
        
        const admin = await Admin.findOne({ username });
        if (!admin) {
            return res.status(400).json({ error: 'Username atau password salah' });
        }
        
        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Username atau password salah' });
        }
        
        const token = jwt.sign(
            { userId: admin._id, userType: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        res.json({
            message: 'Login berhasil',
            token,
            admin: {
                _id: admin._id,
                id: admin._id,
                name: admin.name,
                username: admin.username,
                role: admin.role
            }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// FIXED: Change admin password
app.post('/api/admin/change-password', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        
        console.log('📝 Change password request for admin:', req.userId);
        
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ error: 'Password lama dan baru harus diisi' });
        }
        
        if (newPassword.length < 6) {
            return res.status(400).json({ error: 'Password baru minimal 6 karakter' });
        }
        
        const admin = await Admin.findById(req.userId);
        if (!admin) {
            console.error('❌ Admin not found:', req.userId);
            return res.status(404).json({ error: 'Admin tidak ditemukan' });
        }
        
        const isValidPassword = await bcrypt.compare(oldPassword, admin.password);
        if (!isValidPassword) {
            console.error('❌ Invalid old password for admin:', req.userId);
            return res.status(400).json({ error: 'Password lama salah' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        admin.password = hashedPassword;
        await admin.save();
        
        console.log('✅ Password changed successfully for admin:', req.userId);
        res.json({ message: 'Password berhasil diubah' });
    } catch (error) {
        console.error('❌ Change admin password error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.get('/api/admin/dashboard', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const [totalUsers, todayScratches, todayWinners, totalPrizesResult, pendingPurchases] = await Promise.all([
            User.countDocuments(),
            Scratch.countDocuments({ scratchDate: { $gte: today } }),
            Winner.countDocuments({ scratchDate: { $gte: today } }),
            Winner.aggregate([
                { $match: { claimStatus: 'completed' } },
                { $lookup: {
                    from: 'prizes',
                    localField: 'prizeId',
                    foreignField: '_id',
                    as: 'prize'
                }},
                { $unwind: '$prize' },
                { $group: {
                    _id: null,
                    total: { $sum: '$prize.value' }
                }}
            ]),
            TokenPurchase.countDocuments({ paymentStatus: 'pending' })
        ]);
        
        res.json({
            totalUsers,
            todayScratches,
            todayWinners,
            totalPrizes: totalPrizesResult[0]?.total || 0,
            pendingPurchases
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '' } = req.query;
        
        // Build search query
        let query = {};
        if (search) {
            query = {
                $or: [
                    { name: { $regex: search, $options: 'i' } },
                    { email: { $regex: search, $options: 'i' } },
                    { phoneNumber: { $regex: search, $options: 'i' } }
                ]
            };
        }
        
        const users = await User.find(query)
            .select('-password')
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .sort({ createdAt: -1 });
            
        const total = await User.countDocuments(query);
        
        res.json({
            users,
            total,
            totalPages: Math.ceil(total / limit),
            currentPage: parseInt(page),
            page: parseInt(page),
            limit: parseInt(limit)
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get user detail
app.get('/api/admin/users/:userId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const user = await User.findById(userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        // Get user's scratch history
        const scratches = await Scratch.find({ userId })
            .populate('prizeId')
            .sort({ scratchDate: -1 })
            .limit(10);
        
        // Get user's wins
        const wins = await Winner.find({ userId })
            .populate('prizeId')
            .sort({ scratchDate: -1 });
        
        // Get user's token purchases
        const tokenPurchases = await TokenPurchase.find({ userId })
            .populate('adminId', 'name username')
            .sort({ purchaseDate: -1 })
            .limit(10);
        
        res.json({
            user,
            scratches,
            wins,
            tokenPurchases,
            stats: {
                totalScratches: user.scratchCount || 0,
                totalWins: user.winCount || 0,
                winRate: user.scratchCount > 0 ? ((user.winCount / user.scratchCount) * 100).toFixed(2) : 0,
                customWinRate: user.customWinRate,
                forcedWinningNumber: user.forcedWinningNumber,
                totalPurchasedScratches: user.totalPurchasedScratches || 0
            }
        });
    } catch (error) {
        console.error('Get user detail error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// FIXED: Reset user password by admin
app.post('/api/admin/users/:userId/reset-password', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { newPassword } = req.body;
        
        console.log('📝 Reset password request for user:', userId);
        
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password baru harus minimal 6 karakter' });
        }
        
        // Validasi userId format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            console.error('❌ Invalid userId format:', userId);
            return res.status(400).json({ error: 'Invalid user ID format' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            console.error('❌ User not found:', userId);
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        await user.save();
        
        console.log('✅ Password reset successfully for user:', userId);
        
        // Broadcast user update
        socketManager.broadcastUserUpdate({
            type: 'password_reset',
            userId: user._id,
            adminId: req.userId
        });
        
        res.json({ 
            message: 'Password berhasil direset',
            userId: user._id
        });
    } catch (error) {
        console.error('❌ Reset password error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// NEW: Update user win rate
app.put('/api/admin/users/:userId/win-rate', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { winRate } = req.body;
        
        console.log('📝 Update win rate request for user:', userId, 'to', winRate);
        
        // Validate win rate
        if (winRate !== null && (winRate < 0 || winRate > 100)) {
            return res.status(400).json({ error: 'Win rate harus antara 0-100 atau null' });
        }
        
        // Validate userId format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            console.error('❌ Invalid userId format:', userId);
            return res.status(400).json({ error: 'Invalid user ID format' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            console.error('❌ User not found:', userId);
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        user.customWinRate = winRate;
        await user.save();
        
        console.log('✅ Win rate updated successfully for user:', userId);
        
        // Broadcast user update
        socketManager.broadcastUserUpdate({
            type: 'win_rate_updated',
            userId: user._id,
            winRate: winRate,
            adminId: req.userId
        });
        
        res.json({ 
            message: 'Win rate berhasil diupdate',
            userId: user._id,
            winRate: winRate
        });
    } catch (error) {
        console.error('❌ Update win rate error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// NEW: Set forced winning number for user
app.put('/api/admin/users/:userId/forced-winning', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { winningNumber } = req.body;
        
        console.log('📝 Set forced winning number for user:', userId, 'to', winningNumber);
        
        // Validate winning number
        if (winningNumber !== null && (winningNumber.length !== 4 || isNaN(winningNumber))) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka atau null' });
        }
        
        // Validate userId format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            console.error('❌ Invalid userId format:', userId);
            return res.status(400).json({ error: 'Invalid user ID format' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            console.error('❌ User not found:', userId);
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        user.forcedWinningNumber = winningNumber;
        await user.save();
        
        console.log('✅ Forced winning number set successfully for user:', userId);
        
        // Broadcast user update
        socketManager.broadcastUserUpdate({
            type: 'forced_winning_updated',
            userId: user._id,
            winningNumber: winningNumber,
            adminId: req.userId
        });
        
        res.json({ 
            message: 'Forced winning number berhasil diset',
            userId: user._id,
            winningNumber: winningNumber
        });
    } catch (error) {
        console.error('❌ Set forced winning error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.get('/api/admin/game-settings', verifyToken, verifyAdmin, async (req, res) => {
    try {
        let settings = await GameSettings.findOne();
        
        if (!settings) {
            settings = new GameSettings({
                winningNumber: '1234',
                winProbability: 5,
                maxFreeScratchesPerDay: 1,
                minFreeScratchesPerDay: 1,
                scratchTokenPrice: 10000,
                isGameActive: true,
                resetTime: '00:00'
            });
            await settings.save();
        }
        
        res.json(settings);
    } catch (error) {
        console.error('Get settings error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/admin/game-settings', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { 
            winningNumber, 
            winProbability, 
            maxFreeScratchesPerDay,
            minFreeScratchesPerDay,
            scratchTokenPrice,
            isGameActive, 
            resetTime 
        } = req.body;
        
        if (winningNumber && (winningNumber.length !== 4 || isNaN(winningNumber))) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        if (minFreeScratchesPerDay > maxFreeScratchesPerDay) {
            return res.status(400).json({ error: 'Minimum tidak boleh lebih besar dari maksimum' });
        }
        
        const settings = await GameSettings.findOneAndUpdate(
            {},
            { 
                winningNumber, 
                winProbability, 
                maxFreeScratchesPerDay,
                minFreeScratchesPerDay,
                scratchTokenPrice,
                isGameActive,
                resetTime: resetTime || '00:00'
            },
            { new: true, upsert: true }
        );
        
        // Broadcast settings update
        socketManager.broadcastSettingsUpdate({
            settings: {
                isGameActive: settings.isGameActive,
                maxFreeScratchesPerDay: settings.maxFreeScratchesPerDay,
                minFreeScratchesPerDay: settings.minFreeScratchesPerDay,
                scratchTokenPrice: settings.scratchTokenPrice,
                resetTime: settings.resetTime,
                winProbability: settings.winProbability
            }
        });
        
        res.json(settings);
    } catch (error) {
        console.error('Update settings error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get prizes (admin)
app.get('/api/admin/prizes', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const prizes = await Prize.find().sort({ createdAt: -1 });
        res.json(prizes);
    } catch (error) {
        console.error('Get prizes error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/admin/prizes', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { winningNumber, name, type, value, stock } = req.body;
        
        if (!winningNumber || winningNumber.length !== 4 || isNaN(winningNumber)) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        const existingPrize = await Prize.findOne({ winningNumber });
        if (existingPrize) {
            return res.status(400).json({ error: 'Winning number sudah digunakan' });
        }
        
        const prize = new Prize({
            winningNumber,
            name,
            type,
            value,
            stock,
            isActive: true
        });
        
        await prize.save();
        
        // Broadcast new prize
        socketManager.broadcastPrizeUpdate({
            type: 'prize_added',
            prizeData: prize,
            message: 'New prize added'
        });
        
        res.status(201).json(prize);
    } catch (error) {
        console.error('Add prize error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/admin/prizes/:prizeId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { prizeId } = req.params;
        const { winningNumber, name, type, value, stock, isActive } = req.body;
        
        if (winningNumber && (winningNumber.length !== 4 || isNaN(winningNumber))) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        if (winningNumber) {
            const existingPrize = await Prize.findOne({ 
                winningNumber, 
                _id: { $ne: prizeId } 
            });
            if (existingPrize) {
                return res.status(400).json({ error: 'Winning number sudah digunakan prize lain' });
            }
        }
        
        const prize = await Prize.findByIdAndUpdate(
            prizeId,
            { winningNumber, name, type, value, stock, isActive },
            { new: true }
        );
        
        if (!prize) {
            return res.status(404).json({ error: 'Prize tidak ditemukan' });
        }
        
        // Broadcast prize update
        socketManager.broadcastPrizeUpdate({
            type: 'prize_updated',
            prizeId: prize._id,
            prizeData: prize,
            message: 'Prize updated'
        });
        
        res.json(prize);
    } catch (error) {
        console.error('Update prize error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.delete('/api/admin/prizes/:prizeId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { prizeId } = req.params;
        
        const prize = await Prize.findByIdAndDelete(prizeId);
        if (!prize) {
            return res.status(404).json({ error: 'Prize tidak ditemukan' });
        }
        
        // Broadcast prize deletion
        socketManager.broadcastPrizeUpdate({
            type: 'prize_deleted',
            prizeId: prizeId,
            message: 'Prize deleted'
        });
        
        res.json({ message: 'Prize berhasil dihapus' });
    } catch (error) {
        console.error('Delete prize error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/recent-winners', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { limit = 50 } = req.query;
        
        const winners = await Winner.find()
            .populate('userId', 'name email phoneNumber')
            .populate('prizeId', 'name value type')
            .sort({ scratchDate: -1 })
            .limit(parseInt(limit));
            
        res.json(winners);
    } catch (error) {
        console.error('Get winners error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// NEW: Update winner claim status
app.put('/api/admin/winners/:winnerId/claim-status', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { winnerId } = req.params;
        const { claimStatus } = req.body;
        
        if (!['pending', 'completed', 'expired'].includes(claimStatus)) {
            return res.status(400).json({ error: 'Invalid claim status' });
        }
        
        const winner = await Winner.findByIdAndUpdate(
            winnerId,
            { 
                claimStatus,
                ...(claimStatus === 'completed' && { claimDate: new Date() })
            },
            { new: true }
        )
        .populate('userId', 'name email phoneNumber')
        .populate('prizeId', 'name value type');
        
        if (!winner) {
            return res.status(404).json({ error: 'Winner tidak ditemukan' });
        }
        
        res.json({
            message: 'Status berhasil diupdate',
            winner
        });
    } catch (error) {
        console.error('Update claim status error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get all scratch history
app.get('/api/admin/scratch-history', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        
        const scratches = await Scratch.find()
            .populate('userId', 'name email phoneNumber')
            .populate('prizeId', 'name value type')
            .sort({ scratchDate: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
            
        const total = await Scratch.countDocuments();
        
        res.json({
            scratches: scratches,
            total: total,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Get scratch history error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// TOKEN PURCHASE ROUTES
// ========================================

// Get all token purchases (admin)
app.get('/api/admin/token-purchases', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, status = 'all' } = req.query;
        
        let query = {};
        if (status !== 'all') {
            query.paymentStatus = status;
        }
        
        const purchases = await TokenPurchase.find(query)
            .populate('userId', 'name email phoneNumber')
            .populate('adminId', 'name username')
            .sort({ purchaseDate: -1 })
            .limit(limit * 1)
            .skip((page - 1) * limit);
            
        const total = await TokenPurchase.countDocuments(query);
        
        res.json({
            purchases,
            total,
            page: parseInt(page),
            limit: parseInt(limit),
            totalPages: Math.ceil(total / limit)
        });
    } catch (error) {
        console.error('Get token purchases error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Create token purchase for user (admin)
app.post('/api/admin/token-purchase', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId, quantity, paymentMethod, notes } = req.body;
        
        if (!userId || !quantity || quantity < 1) {
            return res.status(400).json({ error: 'User ID dan quantity harus diisi' });
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        const settings = await GameSettings.findOne();
        const pricePerToken = settings?.scratchTokenPrice || 10000;
        const totalAmount = quantity * pricePerToken;
        
        const purchase = new TokenPurchase({
            userId,
            adminId: req.userId,
            quantity,
            pricePerToken,
            totalAmount,
            paymentMethod: paymentMethod || 'cash',
            notes: notes || ''
        });
        
        await purchase.save();
        
        res.status(201).json({
            message: 'Token purchase created successfully',
            purchase: await purchase.populate(['userId', 'adminId'])
        });
    } catch (error) {
        console.error('Create token purchase error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Complete token purchase (admin)
app.put('/api/admin/token-purchase/:purchaseId/complete', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { purchaseId } = req.params;
        
        const purchase = await TokenPurchase.findById(purchaseId)
            .populate('userId');
            
        if (!purchase) {
            return res.status(404).json({ error: 'Purchase tidak ditemukan' });
        }
        
        if (purchase.paymentStatus === 'completed') {
            return res.status(400).json({ error: 'Purchase sudah completed' });
        }
        
        // Update user's paid scratches
        const user = await User.findById(purchase.userId);
        user.paidScratchesRemaining += purchase.quantity;
        user.totalPurchasedScratches += purchase.quantity;
        await user.save();
        
        // Update purchase status
        purchase.paymentStatus = 'completed';
        purchase.completedDate = new Date();
        await purchase.save();
        
        // Broadcast token purchase
        socketManager.broadcastTokenPurchase({
            userId: user._id,
            quantity: purchase.quantity,
            totalAmount: purchase.totalAmount
        });
        
        res.json({
            message: 'Token purchase completed successfully',
            purchase: await purchase.populate(['userId', 'adminId']),
            userScratches: {
                free: user.freeScratchesRemaining,
                paid: user.paidScratchesRemaining,
                total: user.freeScratchesRemaining + user.paidScratchesRemaining
            }
        });
    } catch (error) {
        console.error('Complete token purchase error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Cancel token purchase (admin)
app.put('/api/admin/token-purchase/:purchaseId/cancel', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { purchaseId } = req.params;
        
        const purchase = await TokenPurchase.findById(purchaseId);
        if (!purchase) {
            return res.status(404).json({ error: 'Purchase tidak ditemukan' });
        }
        
        if (purchase.paymentStatus === 'completed') {
            return res.status(400).json({ error: 'Cannot cancel completed purchase' });
        }
        
        purchase.paymentStatus = 'cancelled';
        await purchase.save();
        
        res.json({
            message: 'Token purchase cancelled successfully',
            purchase: await purchase.populate(['userId', 'adminId'])
        });
    } catch (error) {
        console.error('Cancel token purchase error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Analytics endpoints
app.get('/api/admin/analytics', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { period = '7days' } = req.query;
        
        let dateFilter = {};
        const now = new Date();
        
        switch(period) {
            case 'today':
                dateFilter = {
                    $gte: new Date(now.setHours(0,0,0,0))
                };
                break;
            case '7days':
                dateFilter = {
                    $gte: new Date(now.setDate(now.getDate() - 7))
                };
                break;
            case '30days':
                dateFilter = {
                    $gte: new Date(now.setDate(now.getDate() - 30))
                };
                break;
            case 'all':
            default:
                // No date filter
                break;
        }
        
        const scratchQuery = period === 'all' ? {} : { scratchDate: dateFilter };
        const purchaseQuery = period === 'all' ? {} : { purchaseDate: dateFilter };
        
        const [totalScratches, totalWins, totalPrizeValue, totalTokenSales] = await Promise.all([
            Scratch.countDocuments(scratchQuery),
            Scratch.countDocuments({ ...scratchQuery, isWin: true }),
            Winner.aggregate([
                { $match: period === 'all' ? {} : { scratchDate: dateFilter } },
                { $lookup: {
                    from: 'prizes',
                    localField: 'prizeId',
                    foreignField: '_id',
                    as: 'prize'
                }},
                { $unwind: '$prize' },
                { $group: {
                    _id: null,
                    total: { $sum: '$prize.value' }
                }}
            ]),
            TokenPurchase.aggregate([
                { $match: { ...purchaseQuery, paymentStatus: 'completed' } },
                { $group: {
                    _id: null,
                    totalQuantity: { $sum: '$quantity' },
                    totalRevenue: { $sum: '$totalAmount' }
                }}
            ])
        ]);
        
        const winRate = totalScratches > 0 ? ((totalWins / totalScratches) * 100).toFixed(2) : 0;
        
        res.json({
            period,
            totalScratches,
            totalWins,
            winRate: parseFloat(winRate),
            totalPrizeValue: totalPrizeValue[0]?.total || 0,
            totalTokensSold: totalTokenSales[0]?.totalQuantity || 0,
            totalTokenRevenue: totalTokenSales[0]?.totalRevenue || 0
        });
    } catch (error) {
        console.error('Get analytics error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// User analytics
app.get('/api/admin/analytics/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const now = new Date();
        const thirtyDaysAgo = new Date(now.setDate(now.getDate() - 30));
        
        const [totalUsers, activeUsers, newUsers, paidUsers] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ lastScratchDate: { $gte: thirtyDaysAgo } }),
            User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
            User.countDocuments({ totalPurchasedScratches: { $gt: 0 } })
        ]);
        
        res.json({
            totalUsers,
            activeUsers,
            newUsers,
            paidUsers
        });
    } catch (error) {
        console.error('Get user analytics error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Chat endpoints
app.get('/api/user/chat/history', verifyToken, async (req, res) => {
    try {
        const chat = await Chat.findOne({ userId: req.userId });
        
        if (!chat) {
            return res.json({ messages: [], userIP: req.ip });
        }
        
        if (chat.userIP !== req.ip) {
            chat.userIP = req.ip;
            await chat.save();
        }
        
        res.json({
            messages: chat.messages,
            userIP: chat.userIP,
            chatId: chat._id
        });
    } catch (error) {
        console.error('Get user chat error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/chat/active', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const activeChats = await Chat.find({ 
            lastActivity: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
        })
        .populate('userId', 'name email phoneNumber status lastScratchDate')
        .sort({ lastActivity: -1 });
        
        const formattedChats = activeChats.map(chat => {
            const lastMessage = chat.messages[chat.messages.length - 1];
            const unreadCount = chat.messages.filter(m => m.from === 'user' && !m.isRead).length;
            
            return {
                _id: chat._id,
                user: {
                    ...chat.userId.toObject(),
                    userIP: chat.userIP,
                    userAgent: chat.userAgent
                },
                lastMessage: lastMessage ? {
                    content: lastMessage.message,
                    timestamp: lastMessage.timestamp,
                    from: lastMessage.from
                } : null,
                unreadCount,
                lastActivity: chat.lastActivity
            };
        });
        
        res.json(formattedChats);
    } catch (error) {
        console.error('Get active chats error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/chat/history/:userId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const chat = await Chat.findOne({ userId });
        
        if (!chat) {
            return res.json([]);
        }
        
        chat.messages.forEach(msg => {
            if (msg.from === 'user') {
                msg.isRead = true;
            }
        });
        await chat.save();
        
        res.json(chat.messages);
    } catch (error) {
        console.error('Get chat history error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// INITIALIZATION FUNCTIONS
// ========================================

async function createDefaultAdmin() {
    try {
        const adminExists = await Admin.findOne({ username: 'admin' });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('GosokAngka2024!', 10);
            
            const admin = new Admin({
                username: 'admin',
                password: hashedPassword,
                name: 'Administrator',
                role: 'admin'
            });
            
            await admin.save();
            console.log('✅ Default admin created!');
            console.log('🔑 Username: admin');
            console.log('🔑 Password: GosokAngka2024!');
            console.log('⚠️ IMPORTANT: Change password after first login!');
        }
    } catch (error) {
        console.error('❌ Error creating default admin:', error);
    }
}

async function createDefaultSettings() {
    try {
        const settingsExist = await GameSettings.findOne();
        
        if (!settingsExist) {
            const settings = new GameSettings({
                winningNumber: '1234',
                winProbability: 5,
                maxFreeScratchesPerDay: 1,
                minFreeScratchesPerDay: 1,
                scratchTokenPrice: 10000,
                isGameActive: true,
                resetTime: '00:00'
            });
            
            await settings.save();
            console.log('✅ Default game settings created!');
        }
    } catch (error) {
        console.error('❌ Error creating default settings:', error);
    }
}

async function createSamplePrizes() {
    try {
        const prizeCount = await Prize.countDocuments();
        
        if (prizeCount === 0) {
            const samplePrizes = [
                {
                    winningNumber: '1234',
                    name: 'iPhone 15 Pro',
                    type: 'physical',
                    value: 20000000,
                    stock: 2,
                    isActive: true
                },
                {
                    winningNumber: '5678',
                    name: 'Voucher Shopee Rp500.000',
                    type: 'voucher',
                    value: 500000,
                    stock: 10,
                    isActive: true
                },
                {
                    winningNumber: '9999',
                    name: 'Cash Prize Rp1.000.000',
                    type: 'cash',
                    value: 1000000,
                    stock: 5,
                    isActive: true
                }
            ];
            
            await Prize.insertMany(samplePrizes);
            console.log('✅ Sample prizes created!');
        }
    } catch (error) {
        console.error('❌ Error creating sample prizes:', error);
    }
}

async function initializeDatabase() {
    await createDefaultAdmin();
    await createDefaultSettings();
    await createSamplePrizes();
}

// ========================================
// ERROR HANDLING (MOVED TO END)
// ========================================

// 404 handler (MOVED AFTER ALL ROUTES)
app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        requestedPath: req.path,
        availableEndpoints: [
            'GET /',
            'GET /health',
            'GET /api/health',
            'GET /api/status',
            'GET /api/admin/test-auth',
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET /api/user/profile',
            'POST /api/game/scratch',
            'GET /api/user/history',
            'GET /api/public/prizes',
            'GET /api/public/game-settings',
            'POST /api/admin/login',
            'POST /api/admin/change-password',
            'GET /api/admin/dashboard',
            'GET /api/admin/users',
            'GET /api/admin/users/:userId',
            'POST /api/admin/users/:userId/reset-password',
            'PUT /api/admin/users/:userId/win-rate',
            'PUT /api/admin/users/:userId/forced-winning',
            'GET /api/admin/game-settings',
            'PUT /api/admin/game-settings',
            'GET /api/admin/prizes',
            'POST /api/admin/prizes',
            'PUT /api/admin/prizes/:prizeId',
            'DELETE /api/admin/prizes/:prizeId',
            'GET /api/admin/recent-winners',
            'PUT /api/admin/winners/:winnerId/claim-status',
            'GET /api/admin/scratch-history',
            'GET /api/admin/analytics',
            'GET /api/admin/analytics/users',
            'GET /api/admin/token-purchases',
            'POST /api/admin/token-purchase',
            'PUT /api/admin/token-purchase/:purchaseId/complete',
            'PUT /api/admin/token-purchase/:purchaseId/cancel'
        ]
    });
});

// Global error handler (MOVED TO VERY END)
app.use((err, req, res, next) => {
    if (err.message && err.message.includes('CORS')) {
        console.error('❌ CORS Error:', err.message);
        console.error('❌ Request origin:', req.headers.origin);
        
        return res.status(403).json({ 
            error: 'CORS Error',
            message: 'Origin not allowed',
            origin: req.headers.origin,
            allowedOrigins: allowedOrigins.filter(o => typeof o === 'string')
        });
    }
    
    console.error('❌ Global error:', err);
    res.status(500).json({ 
        error: 'Something went wrong!',
        message: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log('========================================');
    console.log('🎯 GOSOK ANGKA BACKEND - PRODUCTION V3.1');
    console.log('========================================');
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 Domain: gosokangkahoki.com`);
    console.log(`📡 API URL: https://gosokangka-backend-production.up.railway.app`);
    console.log(`🔌 Socket.io enabled with realtime sync`);
    console.log(`📧 Email/Phone login support enabled`);
    console.log(`🎮 Game features: Scratch cards, Prizes, Chat`);
    console.log(`📊 Database: MongoDB Atlas`);
    console.log(`🔐 Security: JWT Authentication, CORS configured`);
    console.log(`🆕 New Features V3.1:`);
    console.log(`   - Token purchase system`);
    console.log(`   - Min/Max free scratches settings`);
    console.log(`   - Winner claim status management`);
    console.log(`   - Enhanced analytics with token sales`);
    console.log(`   - Per-user scratch token management`);
    console.log(`   - Forced winning number for users`);
    console.log('========================================');
    
    // Initialize database with default data
    setTimeout(initializeDatabase, 2000);
});
