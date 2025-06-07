// ========================================
// GOSOK ANGKA BACKEND - PRODUCTION READY WITH SOCKET.IO
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

// Create HTTP server
const server = http.createServer(app);

// Setup Socket.io
const io = socketIO(server, {
    cors: {
        origin: [
            'https://gosokangkahoki.com',
            'https://www.gosokangkahoki.com',
            'http://localhost:3000',
            'http://localhost:5000'
        ],
        credentials: true
    }
});

// CORS Configuration
app.use(cors({
    origin: [
        'https://gosokangkahoki.com',
        'https://www.gosokangkahoki.com',
        'http://localhost:3000'
    ],
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// MongoDB Connection dengan retry logic
const connectDB = async () => {
    try {
        await mongoose.connect(process.env.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        });
        console.log('✅ MongoDB Connected Successfully!');
    } catch (error) {
        console.error('❌ MongoDB Connection Error:', error);
        console.log('⏳ Retrying in 5 seconds...');
        setTimeout(connectDB, 5000);
    }
};

connectDB();

// ========================================
// DATABASE SCHEMAS
// ========================================

// User Schema
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

// Admin Schema
const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    name: { type: String, required: true },
    role: { type: String, default: 'admin' },
    createdAt: { type: Date, default: Date.now }
});

// Prize Schema
const prizeSchema = new mongoose.Schema({
    winningNumber: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    type: { type: String, enum: ['voucher', 'cash', 'physical'], required: true },
    value: { type: Number, required: true },
    stock: { type: Number, required: true },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now }
});

// Scratch Schema
const scratchSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    scratchNumber: { type: String, required: true },
    isWin: { type: Boolean, default: false },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize' },
    scratchDate: { type: Date, default: Date.now }
});

// Winner Schema
const winnerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize', required: true },
    scratchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scratch', required: true },
    claimStatus: { type: String, enum: ['pending', 'completed', 'expired'], default: 'pending' },
    claimCode: { type: String, required: true },
    scratchDate: { type: Date, default: Date.now },
    claimDate: { type: Date }
});

// Game Settings Schema
const gameSettingsSchema = new mongoose.Schema({
    winningNumber: { type: String, required: true },
    winProbability: { type: Number, default: 5 },
    maxScratchesPerDay: { type: Number, default: 1 },
    isGameActive: { type: Boolean, default: true }
});

// Updated Chat Schema with IP and User Agent
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
// SOCKET.IO CONFIGURATION
// ========================================

// Socket.io Authentication Middleware
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

// Socket.io Connection Handler
io.on('connection', (socket) => {
    console.log('User connected:', socket.userId);
    
    // Join user's personal room
    socket.join(`user-${socket.userId}`);
    
    // If admin, join admin room
    if (socket.userType === 'admin') {
        socket.join('admin-room');
        
        // Send all active chats to admin
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
    
    // Handle user sending message
    socket.on('chat:send-message', async (data) => {
        try {
            const { message, userIP, userAgent } = data;
            
            // Find or create chat
            let chat = await Chat.findOne({ userId: socket.userId });
            if (!chat) {
                chat = new Chat({ 
                    userId: socket.userId, 
                    messages: [],
                    userIP: userIP || socket.handshake.address,
                    userAgent: userAgent || socket.handshake.headers['user-agent']
                });
            }
            
            // Update IP and user agent if changed
            if (userIP && chat.userIP !== userIP) {
                chat.userIP = userIP;
            }
            if (userAgent && chat.userAgent !== userAgent) {
                chat.userAgent = userAgent;
            }
            
            // Add message
            const newMessage = {
                from: socket.userType === 'admin' ? 'admin' : 'user',
                message: message.trim(),
                timestamp: new Date(),
                isRead: false
            };
            
            chat.messages.push(newMessage);
            chat.lastActivity = new Date();
            await chat.save();
            
            // Get user details
            const user = await User.findById(socket.userId)
                .select('name email phoneNumber');
            
            // Emit to sender
            socket.emit('chat:message-sent', {
                ...newMessage,
                _id: chat.messages[chat.messages.length - 1]._id
            });
            
            // Emit to recipient
            if (socket.userType === 'admin') {
                // Admin sending to user
                io.to(`user-${data.targetUserId}`).emit('chat:new-message', {
                    ...newMessage,
                    chatId: chat._id
                });
            } else {
                // User sending to admin
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
    
    // Handle admin sending message to specific user
    socket.on('admin:send-message', async (data) => {
        try {
            const { userId, message } = data;
            
            // Find or create chat
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
            
            // Emit to admin
            socket.emit('admin:message-sent', {
                ...newMessage,
                _id: chat.messages[chat.messages.length - 1]._id,
                userId
            });
            
            // Emit to user
            io.to(`user-${userId}`).emit('chat:new-message', {
                ...newMessage,
                chatId: chat._id
            });
        } catch (error) {
            socket.emit('error', { message: 'Failed to send message' });
        }
    });
    
    // Handle mark as read
    socket.on('chat:mark-read', async (data) => {
        try {
            const { chatId } = data;
            
            await Chat.updateOne(
                { _id: chatId },
                { $set: { 'messages.$[elem].isRead': true } },
                { arrayFilters: [{ 'elem.from': { $ne: socket.userType } }] }
            );
            
            socket.emit('chat:marked-read', { chatId });
            
            // Notify admin about read status
            if (socket.userType === 'user') {
                io.to('admin-room').emit('chat:messages-read', {
                    userId: socket.userId,
                    chatId
                });
            }
        } catch (error) {
            socket.emit('error', { message: 'Failed to mark as read' });
        }
    });
    
    // Handle typing indicators
    socket.on('chat:typing', (data) => {
        if (socket.userType === 'admin') {
            io.to(`user-${data.targetUserId}`).emit('chat:user-typing', {
                isTyping: data.isTyping,
                from: 'admin'
            });
        } else {
            io.to('admin-room').emit('chat:user-typing', {
                isTyping: data.isTyping,
                userId: socket.userId,
                from: 'user'
            });
        }
    });
    
    // Handle disconnect
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.userId);
        
        // Notify admins if user disconnected
        if (socket.userType === 'user') {
            io.to('admin-room').emit('user:offline', {
                userId: socket.userId,
                timestamp: new Date()
            });
        }
    });
});

// ========================================
// MIDDLEWARE
// ========================================

// Verify JWT Token
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

// Verify Admin
const verifyAdmin = (req, res, next) => {
    if (req.userType !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// ========================================
// ROUTES - ROOT
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: 'Gosok Angka Backend API',
        version: '1.0.0',
        features: {
            realtime: 'Socket.io enabled',
            chat: 'Live chat support'
        },
        endpoints: {
            auth: '/api/auth',
            user: '/api/user',
            game: '/api/game',
            admin: '/api/admin'
        }
    });
});

// ========================================
// ROUTES - AUTHENTICATION
// ========================================

// User Registration
app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phoneNumber } = req.body;
        
        // Validation
        if (!name || !email || !password || !phoneNumber) {
            return res.status(400).json({ error: 'Semua field harus diisi' });
        }
        
        // Check if user exists
        const existingUser = await User.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(400).json({ error: 'Email sudah terdaftar' });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create user
        const user = new User({
            name,
            email: email.toLowerCase(),
            password: hashedPassword,
            phoneNumber
        });
        
        await user.save();
        
        // Generate token
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

// User Login
app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email dan password harus diisi' });
        }
        
        // Find user
        const user = await User.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(400).json({ error: 'Email atau password salah' });
        }
        
        // Check password
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(400).json({ error: 'Email atau password salah' });
        }
        
        // Generate token
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
// ROUTES - USER
// ========================================

// Get User Profile
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

// Update User Profile
app.put('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const { name, phoneNumber } = req.body;
        
        const user = await User.findByIdAndUpdate(
            req.userId,
            { name, phoneNumber },
            { new: true }
        ).select('-password');
        
        res.json({
            message: 'Profile berhasil diupdate',
            user
        });
    } catch (error) {
        console.error('Update profile error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// ROUTES - GAME
// ========================================

// Scratch Card
app.post('/api/game/scratch', verifyToken, async (req, res) => {
    try {
        // Get game settings
        const settings = await GameSettings.findOne();
        if (!settings || !settings.isGameActive) {
            return res.status(400).json({ error: 'Game sedang tidak aktif' });
        }
        
        // Check if user already scratched today
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const user = await User.findById(req.userId);
        if (user.lastScratchDate && user.lastScratchDate >= today) {
            return res.status(400).json({ 
                error: 'Kamu sudah gosok hari ini, coba lagi besok!' 
            });
        }
        
        // Generate random 4-digit number
        const scratchNumber = Math.floor(1000 + Math.random() * 9000).toString();
        
        // Check if win
        let isWin = false;
        let prize = null;
        let winner = null;
        
        // Check against all active prizes
        const activePrize = await Prize.findOne({ 
            winningNumber: scratchNumber,
            stock: { $gt: 0 },
            isActive: true
        });
        
        if (activePrize) {
            isWin = true;
            prize = activePrize;
            
            // Decrease stock
            prize.stock -= 1;
            await prize.save();
        }
        
        // Create scratch record
        const scratch = new Scratch({
            userId: req.userId,
            scratchNumber,
            isWin,
            prizeId: prize?._id
        });
        
        await scratch.save();
        
        // If win, create winner record
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
        
        // Update user stats
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

// Get User Scratch History
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

// Get User Winners
app.get('/api/user/winners', verifyToken, async (req, res) => {
    try {
        const winners = await Winner.find({ userId: req.userId })
            .populate('prizeId')
            .sort({ scratchDate: -1 });
            
        res.json(winners);
    } catch (error) {
        console.error('Winners error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// ROUTES - ADMIN
// ========================================

// Admin Login
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

// Get Dashboard Stats
app.get('/api/admin/dashboard', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const [
            totalUsers,
            todayScratches,
            todayWinners,
            totalPrizesResult
        ] = await Promise.all([
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

// Get All Users
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

// Reset User Password
app.post('/api/admin/users/:userId/reset-password', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { newPassword } = req.body;
        
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password minimal 6 karakter' });
        }
        
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        
        const user = await User.findByIdAndUpdate(userId, {
            password: hashedPassword
        });
        
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        res.json({ message: 'Password berhasil direset' });
    } catch (error) {
        console.error('Reset password error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Game Settings - PUBLIC ENDPOINT (untuk frontend game)
app.get('/api/admin/game-settings', async (req, res) => {
    try {
        let settings = await GameSettings.findOne();
        
        // Create default settings if not exists
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

// Update Game Settings
app.put('/api/admin/game-settings', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { winningNumber, winProbability, maxScratchesPerDay, isGameActive } = req.body;
        
        // Validation
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

// Generate Random Winning Number
app.post('/api/admin/generate-winning-number', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const winningNumber = Math.floor(1000 + Math.random() * 9000).toString();
        
        const settings = await GameSettings.findOneAndUpdate(
            {},
            { winningNumber },
            { new: true, upsert: true }
        );
        
        res.json({ winningNumber: settings.winningNumber });
    } catch (error) {
        console.error('Generate number error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get All Prizes - PUBLIC ENDPOINT (untuk frontend game)
app.get('/api/admin/prizes', async (req, res) => {
    try {
        const prizes = await Prize.find({ isActive: true }).sort({ createdAt: -1 });
        res.json(prizes);
    } catch (error) {
        console.error('Get prizes error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add Prize
app.post('/api/admin/prizes', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { winningNumber, name, type, value, stock } = req.body;
        
        // Validation
        if (!winningNumber || winningNumber.length !== 4 || isNaN(winningNumber)) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        // Check if winning number already exists
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

// Update Prize
app.put('/api/admin/prizes/:prizeId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { prizeId } = req.params;
        const { winningNumber, name, type, value, stock, isActive } = req.body;
        
        // Validation
        if (winningNumber && (winningNumber.length !== 4 || isNaN(winningNumber))) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
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

// Delete Prize
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

// Get Recent Winners
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

// Get Analytics
app.get('/api/admin/analytics', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { period = '7days' } = req.query;
        
        // Calculate date range
        const endDate = new Date();
        const startDate = new Date();
        
        switch(period) {
            case '7days':
                startDate.setDate(startDate.getDate() - 7);
                break;
            case '30days':
                startDate.setDate(startDate.getDate() - 30);
                break;
            case '3months':
                startDate.setMonth(startDate.getMonth() - 3);
                break;
        }
        
        // Get daily stats
        const dailyStats = await Scratch.aggregate([
            {
                $match: {
                    scratchDate: { $gte: startDate, $lte: endDate }
                }
            },
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$scratchDate" }
                    },
                    scratches: { $sum: 1 },
                    winners: {
                        $sum: { $cond: ["$isWin", 1, 0] }
                    }
                }
            },
            { $sort: { _id: 1 } }
        ]);
        
        // Format data for chart
        const labels = [];
        const scratches = [];
        const winners = [];
        
        dailyStats.forEach(stat => {
            const date = new Date(stat._id);
            labels.push(date.toLocaleDateString('id-ID', { weekday: 'short' }));
            scratches.push(stat.scratches);
            winners.push(stat.winners);
        });
        
        res.json({ labels, scratches, winners });
    } catch (error) {
        console.error('Analytics error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// ROUTES - CHAT (UPDATED WITH SOCKET SUPPORT)
// ========================================

// Get Chat History with Socket Support
app.get('/api/user/chat/history', verifyToken, async (req, res) => {
    try {
        const chat = await Chat.findOne({ userId: req.userId });
        
        if (!chat) {
            return res.json({ messages: [], userIP: req.ip });
        }
        
        // Update user IP if changed
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

// Admin Get All Active Chats
app.get('/api/admin/chat/active', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const activeChats = await Chat.find({ 
            lastActivity: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } // Last 24 hours
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

// Get Chat History (Admin)
app.get('/api/admin/chat/history/:userId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        const chat = await Chat.findOne({ userId });
        
        if (!chat) {
            return res.json([]);
        }
        
        // Mark as read
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
// INITIAL SETUP
// ========================================

// Create Default Admin
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
            console.log('Username: admin');
            console.log('Password: GosokAngka2024!');
            console.log('⚠️  IMPORTANT: Change this password after first login!');
        }
    } catch (error) {
        console.error('Error creating default admin:', error);
    }
}

// Create Default Game Settings
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
        console.error('Error creating default settings:', error);
    }
}

// Create Sample Prizes
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
        console.error('Error creating sample prizes:', error);
    }
}

// Initialize Database
async function initializeDatabase() {
    await createDefaultAdmin();
    await createDefaultSettings();
    await createSamplePrizes();
}

// ========================================
// ERROR HANDLING
// ========================================

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Global Error Handler
app.use((err, req, res, next) => {
    console.error('Global error:', err);
    res.status(500).json({ error: 'Something went wrong!' });
});

// ========================================
// START SERVER WITH SOCKET.IO
// ========================================

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log('========================================');
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`📡 API URL: http://localhost:${PORT}`);
    console.log(`🔌 Socket.io enabled for real-time chat`);
    console.log(`🌐 Ready for production deployment`);
    console.log('========================================');
    
    // Initialize database with default data
    setTimeout(initializeDatabase, 2000);
});
