// ========================================
// GOSOK ANGKA BACKEND - PRODUCTION READY
// Fixed Version untuk gosokangkahoki.com
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

// ========================================
// DATABASE CONNECTION - FIXED
// ========================================
async function connectDB() {
    try {
        const mongoURI = process.env.MONGODB_URI;
        
        if (!mongoURI) {
            throw new Error('MONGODB_URI tidak ditemukan di environment variables');
        }

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
// CORS CONFIGURATION - UPDATED FOR PRODUCTION
// ========================================
const allowedOrigins = [
    'https://gosokangkahoki.netlify.app',     // Netlify domain
    'https://gosokangkahoki.com',             // Custom domain
    'https://www.gosokangkahoki.com',         // Custom domain dengan www
    'http://gosokangkahoki.com',              // HTTP version (just in case)
    'http://www.gosokangkahoki.com',         // HTTP dengan www
    'https://gosokangka-backend-production.up.railway.app',
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000'
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, Postman, etc.)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            console.log('❌ CORS blocked origin:', origin);
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// ========================================
// SOCKET.IO SETUP - FIXED
// ========================================
const io = socketIO(server, {
    cors: {
        origin: allowedOrigins,
        credentials: true,
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling']
});

// Add middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ========================================
// DATABASE SCHEMAS
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
    maxScratchesPerDay: { type: Number, default: 1 },
    isGameActive: { type: Boolean, default: true }
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

// ========================================
// MIDDLEWARE
// ========================================

const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        req.userType = decoded.userType;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

const verifyAdmin = (req, res, next) => {
    if (req.userType !== 'admin') {
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
        version: '2.0.0',
        status: 'Production Ready',
        domain: 'gosokangkahoki.com',
        features: {
            realtime: 'Socket.io enabled',
            chat: 'Live chat support', 
            auth: 'Email/Phone login support',
            database: 'MongoDB Atlas connected',
            cors: 'Production domains configured'
        },
        endpoints: {
            auth: '/api/auth',
            user: '/api/user', 
            game: '/api/game',
            admin: '/api/admin'
        },
        timestamp: new Date().toISOString()
    });
});

// Health check
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        uptime: process.uptime()
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
        
        const user = new User({
            name,
            email: userEmail.toLowerCase(),
            password: hashedPassword,
            phoneNumber: userPhone
        });
        
        await user.save();
        
        const token = jwt.sign(
            { userId: user._id, userType: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        res.status(201).json({
            message: 'Registrasi berhasil',
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email
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
                id: user._id,
                name: user.name,
                email: user.email
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
// GAME ROUTES
// ========================================

app.post('/api/game/scratch', verifyToken, async (req, res) => {
    try {
        const settings = await GameSettings.findOne();
        if (!settings || !settings.isGameActive) {
            return res.status(400).json({ error: 'Game sedang tidak aktif' });
        }
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const user = await User.findById(req.userId);
        if (user.lastScratchDate && user.lastScratchDate >= today) {
            return res.status(400).json({ 
                error: 'Kamu sudah gosok hari ini, coba lagi besok!' 
            });
        }
        
        const scratchNumber = Math.floor(1000 + Math.random() * 9000).toString();
        
        let isWin = false;
        let prize = null;
        let winner = null;
        
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
        }
        
        const scratch = new Scratch({
            userId: req.userId,
            scratchNumber,
            isWin,
            prizeId: prize?._id
        });
        
        await scratch.save();
        
        if (isWin && prize) {
            const claimCode = Math.random().toString(36).substring(2, 10).toUpperCase();
            
            winner = new Winner({
                userId: req.userId,
                prizeId: prize._id,
                scratchId: scratch._id,
                claimCode
            });
            
            await winner.save();
        }
        
        await User.findByIdAndUpdate(req.userId, {
            $inc: {
                scratchCount: 1,
                winCount: isWin ? 1 : 0
            },
            lastScratchDate: new Date()
        });
        
        res.json({
            scratchNumber,
            isWin,
            prize: isWin ? {
                name: prize.name,
                type: prize.type,
                value: prize.value,
                claimCode: winner?.claimCode
            } : null
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
            
        res.json(scratches);
    } catch (error) {
        console.error('History error:', error);
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
                id: admin._id,
                name: admin.name,
                username: admin.username
            }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/dashboard', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const [totalUsers, todayScratches, todayWinners, totalPrizesResult] = await Promise.all([
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
            ])
        ]);
        
        res.json({
            totalUsers,
            todayScratches,
            todayWinners,
            totalPrizes: totalPrizesResult[0]?.total || 0
        });
    } catch (error) {
        console.error('Dashboard error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10 } = req.query;
        
        const users = await User.find()
            .select('-password')
            .limit(limit * 1)
            .skip((page - 1) * limit)
            .sort({ createdAt: -1 });
            
        const total = await User.countDocuments();
        
        res.json({
            users,
            totalPages: Math.ceil(total / limit),
            currentPage: page
        });
    } catch (error) {
        console.error('Get users error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/game-settings', async (req, res) => {
    try {
        let settings = await GameSettings.findOne();
        
        if (!settings) {
            settings = new GameSettings({
                winningNumber: '1234',
                winProbability: 5,
                maxScratchesPerDay: 1,
                isGameActive: true
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
        const { winningNumber, winProbability, maxScratchesPerDay, isGameActive } = req.body;
        
        if (winningNumber && (winningNumber.length !== 4 || isNaN(winningNumber))) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        const settings = await GameSettings.findOneAndUpdate(
            {},
            { winningNumber, winProbability, maxScratchesPerDay, isGameActive },
            { new: true, upsert: true }
        );
        
        res.json(settings);
    } catch (error) {
        console.error('Update settings error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/prizes', async (req, res) => {
    try {
        const prizes = await Prize.find({ isActive: true }).sort({ createdAt: -1 });
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
            stock
        });
        
        await prize.save();
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
        
        res.json({ message: 'Prize berhasil dihapus' });
    } catch (error) {
        console.error('Delete prize error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/admin/recent-winners', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const winners = await Winner.find()
            .populate('userId', 'name email')
            .populate('prizeId', 'name value')
            .sort({ scratchDate: -1 })
            .limit(20);
            
        res.json(winners);
    } catch (error) {
        console.error('Get winners error:', error);
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
                name: 'Administrator'
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
                maxScratchesPerDay: 1,
                isGameActive: true
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
                    stock: 2
                },
                {
                    winningNumber: '5678',
                    name: 'Voucher Shopee Rp500.000',
                    type: 'voucher',
                    value: 500000,
                    stock: 10
                },
                {
                    winningNumber: '9999',
                    name: 'Cash Prize Rp1.000.000',
                    type: 'cash',
                    value: 1000000,
                    stock: 5
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
// ERROR HANDLING
// ========================================

app.use((req, res) => {
    res.status(404).json({ 
        error: 'Endpoint not found',
        availableEndpoints: [
            'GET /',
            'GET /health',
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET /api/user/profile',
            'POST /api/game/scratch',
            'POST /api/admin/login'
        ]
    });
});

app.use((err, req, res, next) => {
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
    console.log('🎯 GOSOK ANGKA BACKEND - PRODUCTION');
    console.log('========================================');
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 Domain: gosokangkahoki.com`);
    console.log(`📡 API URL: https://gosokangka-backend-production.up.railway.app`);
    console.log(`🔌 Socket.io enabled for real-time chat`);
    console.log(`📧 Email/Phone login support enabled`);
    console.log(`🎮 Game features: Scratch cards, Prizes, Chat`);
    console.log(`📊 Database: MongoDB Atlas`);
    console.log(`🔐 Security: JWT Authentication, CORS configured`);
    console.log('========================================');
    
    // Initialize database with default data
    setTimeout(initializeDatabase, 2000);
});
