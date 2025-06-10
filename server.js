// ========================================
// GOSOK ANGKA BACKEND - COMPLETE VERSION 4.1.0
// RAILWAY OPTIMIZED WITH FULL FEATURES
// ========================================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIO = require('socket.io');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ========================================
// SIMPLE LOGGING FOR RAILWAY
// ========================================
const log = (message, data = '') => {
    const timestamp = new Date().toISOString();
    if (data) {
        console.log(`[${timestamp}] ${message}`, JSON.stringify(data, null, 2));
    } else {
        console.log(`[${timestamp}] ${message}`);
    }
};

// Environment validation
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
    log('❌ FATAL ERROR: Missing required environment variables:', missingEnvVars);
    process.exit(1);
}

log('✅ Environment variables validated');

// ========================================
// DATABASE CONNECTION WITH RETRY LOGIC
// ========================================
async function connectDB() {
    const maxRetries = 5;
    let retryCount = 0;
    
    while (retryCount < maxRetries) {
        try {
            log('🔌 Connecting to MongoDB...', { attempt: retryCount + 1 });
            
            await mongoose.connect(process.env.MONGODB_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                retryWrites: true,
                w: 'majority',
                maxPoolSize: 10,
                serverSelectionTimeoutMS: 15000,
                socketTimeoutMS: 45000,
                bufferCommands: false,
                bufferMaxEntries: 0
            });
            
            log('✅ MongoDB connected successfully!', {
                database: mongoose.connection.name,
                host: mongoose.connection.host
            });
            return;
            
        } catch (error) {
            retryCount++;
            log('❌ MongoDB connection error:', {
                error: error.message,
                attempt: retryCount,
                retriesLeft: maxRetries - retryCount
            });
            
            if (retryCount >= maxRetries) {
                log('💀 Max MongoDB connection retries exceeded');
                process.exit(1);
            }
            
            const delay = Math.pow(2, retryCount) * 1000;
            log(`⏳ Retrying connection in ${delay}ms...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
}

// Connect to database immediately
connectDB();

// ========================================
// MIDDLEWARE SETUP
// ========================================

// Enhanced CORS Configuration
const allowedOrigins = [
    'https://gosokangkahoki.netlify.app',
    'https://www.gosokangkahoki.netlify.app',
    'https://gosokangkahoki.com',
    'https://www.gosokangkahoki.com',
    'https://admin.gosokangkahoki.com',
    'https://gosokangka-backend-production.up.railway.app',
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000'
];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.includes(origin)) {
            log('✅ CORS: Origin allowed', { origin });
            return callback(null, true);
        }
        
        if (origin && origin.includes('.netlify.app')) {
            log('⚠️ CORS: Netlify preview URL allowed', { origin });
            return callback(null, true);
        }
        
        log('❌ CORS: Origin blocked', { origin });
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
        'Origin'
    ],
    optionsSuccessStatus: 200
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging middleware
app.use((req, res, next) => {
    const startTime = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        log('HTTP Request', {
            method: req.method,
            url: req.url,
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip
        });
    });
    
    next();
});

// ========================================
// SOCKET.IO SETUP WITH ENHANCED FEATURES
// ========================================
const io = socketIO(server, {
    cors: {
        origin: allowedOrigins,
        credentials: true,
        methods: ["GET", "POST"]
    },
    transports: ['websocket', 'polling'],
    allowEIO3: true,
    pingTimeout: 60000,
    pingInterval: 25000
});

// Enhanced Socket Manager
const socketManager = {
    connections: new Map(),
    adminConnections: new Set(),
    userConnections: new Map(),
    
    addConnection(socketId, userId, userType) {
        this.connections.set(socketId, { userId, userType, connectedAt: new Date() });
        
        if (userType === 'admin') {
            this.adminConnections.add(socketId);
        } else {
            this.userConnections.set(userId, socketId);
        }
        
        log('Socket connected', { socketId, userId, userType, totalConnections: this.connections.size });
    },
    
    removeConnection(socketId) {
        const connection = this.connections.get(socketId);
        if (connection) {
            const { userId, userType } = connection;
            
            if (userType === 'admin') {
                this.adminConnections.delete(socketId);
            } else {
                this.userConnections.delete(userId);
            }
            
            this.connections.delete(socketId);
            log('Socket disconnected', { socketId, userId, userType, totalConnections: this.connections.size });
        }
    },
    
    broadcastToAdmins(event, data) {
        this.adminConnections.forEach(socketId => {
            const socket = io.sockets.sockets.get(socketId);
            if (socket) {
                socket.emit(event, data);
            }
        });
        log('Broadcast to admins', { event, adminCount: this.adminConnections.size });
    },
    
    broadcastToUser(userId, event, data) {
        const socketId = this.userConnections.get(userId);
        if (socketId) {
            const socket = io.sockets.sockets.get(socketId);
            if (socket) {
                socket.emit(event, data);
                log('Broadcast to user', { userId, event });
            }
        }
    },
    
    broadcastToAll(event, data) {
        io.emit(event, data);
        log('Broadcast to all', { event, totalConnections: this.connections.size });
    },
    
    getConnectionStats() {
        return {
            total: this.connections.size,
            admins: this.adminConnections.size,
            users: this.userConnections.size,
            uptime: process.uptime()
        };
    }
};

// ========================================
// DATABASE SCHEMAS
// ========================================

const userSchema = new mongoose.Schema({
    name: { 
        type: String, 
        required: true, 
        trim: true,
        minlength: 2,
        maxlength: 100
    },
    email: { 
        type: String, 
        required: true, 
        unique: true, 
        lowercase: true,
        validate: {
            validator: function(email) {
                return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
            },
            message: 'Invalid email format'
        }
    },
    password: { 
        type: String, 
        required: true,
        minlength: 6
    },
    phoneNumber: { 
        type: String, 
        required: true,
        validate: {
            validator: function(phone) {
                return /^[0-9+\-\s()]+$/.test(phone);
            },
            message: 'Invalid phone number format'
        }
    },
    status: { 
        type: String, 
        enum: ['active', 'inactive', 'banned'], 
        default: 'active' 
    },
    scratchCount: { type: Number, default: 0, min: 0 },
    winCount: { type: Number, default: 0, min: 0 },
    lastScratchDate: { type: Date },
    customWinRate: { 
        type: Number, 
        default: null,
        min: 0,
        max: 100
    },
    freeScratchesRemaining: { type: Number, default: 1, min: 0 }, 
    paidScratchesRemaining: { type: Number, default: 0, min: 0 }, 
    totalPurchasedScratches: { type: Number, default: 0, min: 0 },
    forcedWinningNumber: { 
        type: String, 
        default: null,
        validate: {
            validator: function(num) {
                return num === null || /^\d{4}$/.test(num);
            },
            message: 'Forced winning number must be 4 digits'
        }
    },
    preparedScratchNumber: { 
        type: String, 
        default: null,
        validate: {
            validator: function(num) {
                return num === null || /^\d{4}$/.test(num);
            },
            message: 'Prepared scratch number must be 4 digits'
        }
    },
    preparedScratchDate: { type: Date, default: null },
    preparedScratchMetadata: {
        isForced: { type: Boolean, default: false },
        generationMethod: { type: String, enum: ['random', 'forced'], default: 'random' },
        clientIP: String,
        userAgent: String
    },
    lastActivity: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 50
    },
    password: { 
        type: String, 
        required: true,
        minlength: 6
    },
    name: { 
        type: String, 
        required: true,
        trim: true,
        maxlength: 100
    },
    role: { 
        type: String, 
        enum: ['admin', 'super_admin'], 
        default: 'admin' 
    },
    lastLogin: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

const prizeSchema = new mongoose.Schema({
    winningNumber: { 
        type: String, 
        required: true, 
        unique: true,
        validate: {
            validator: function(num) {
                return /^\d{4}$/.test(num);
            },
            message: 'Winning number must be 4 digits'
        }
    },
    name: { 
        type: String, 
        required: true,
        trim: true,
        maxlength: 200
    },
    type: { 
        type: String, 
        enum: ['voucher', 'cash', 'physical'], 
        required: true 
    },
    value: { 
        type: Number, 
        required: true,
        min: 1000
    },
    stock: { 
        type: Number, 
        required: true,
        min: 0
    },
    originalStock: { type: Number, required: true },
    isActive: { type: Boolean, default: true },
    totalWins: { type: Number, default: 0 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const scratchSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    scratchNumber: { 
        type: String, 
        required: true,
        validate: {
            validator: function(num) {
                return /^\d{4}$/.test(num);
            },
            message: 'Scratch number must be 4 digits'
        }
    },
    isWin: { type: Boolean, default: false },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize' },
    isPaid: { type: Boolean, default: false },
    winMethod: { 
        type: String, 
        enum: ['exact_match', 'probability', null],
        default: null
    },
    scratchMetadata: {
        winMethod: String,
        preparedAt: Date,
        executedAt: Date,
        userAgent: String,
        clientIP: String,
        originalPreparedData: mongoose.Schema.Types.Mixed
    },
    scratchDate: { type: Date, default: Date.now }
});

const winnerSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    prizeId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Prize', 
        required: true 
    },
    scratchId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Scratch', 
        required: true 
    },
    claimStatus: { 
        type: String, 
        enum: ['pending', 'completed', 'expired'], 
        default: 'pending' 
    },
    claimCode: { 
        type: String, 
        required: true,
        unique: true,
        uppercase: true
    },
    winMethod: { 
        type: String, 
        enum: ['exact_match', 'probability'],
        required: true
    },
    scratchDate: { type: Date, default: Date.now },
    claimDate: { type: Date },
    notificationSent: { type: Boolean, default: false }
});

const gameSettingsSchema = new mongoose.Schema({
    winProbability: { 
        type: Number, 
        default: 5,
        min: 0,
        max: 100
    },
    maxFreeScratchesPerDay: { 
        type: Number, 
        default: 1,
        min: 0,
        max: 10
    },
    minFreeScratchesPerDay: { 
        type: Number, 
        default: 1,
        min: 0,
        max: 10
    },
    scratchTokenPrice: { 
        type: Number, 
        default: 10000,
        min: 1000
    },
    isGameActive: { type: Boolean, default: true },
    resetTime: { 
        type: String, 
        default: '00:00',
        validate: {
            validator: function(time) {
                return /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(time);
            },
            message: 'Invalid time format (HH:MM)'
        }
    },
    maintenanceMessage: { type: String, default: '' },
    updatedAt: { type: Date, default: Date.now },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
});

const tokenPurchaseSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true 
    },
    adminId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'Admin', 
        required: true 
    },
    quantity: { 
        type: Number, 
        required: true,
        min: 1
    },
    pricePerToken: { 
        type: Number, 
        required: true,
        min: 1000
    },
    totalAmount: { 
        type: Number, 
        required: true,
        min: 1000
    },
    paymentStatus: { 
        type: String, 
        enum: ['pending', 'completed', 'cancelled'], 
        default: 'pending' 
    },
    paymentMethod: { 
        type: String,
        enum: ['cash', 'transfer', 'qris', 'e-wallet'],
        default: 'cash'
    },
    notes: { type: String, maxlength: 500 },
    purchaseDate: { type: Date, default: Date.now },
    completedDate: { type: Date },
    cancelledDate: { type: Date },
    cancelReason: { type: String }
});

// Create indexes for performance
userSchema.index({ email: 1 }, { unique: true });
userSchema.index({ phoneNumber: 1 }, { unique: true });
userSchema.index({ preparedScratchDate: 1 });
userSchema.index({ lastActivity: 1 });
scratchSchema.index({ userId: 1, scratchDate: -1 });
scratchSchema.index({ scratchDate: -1 });
winnerSchema.index({ userId: 1, scratchDate: -1 });
winnerSchema.index({ claimCode: 1 }, { unique: true });
prizeSchema.index({ winningNumber: 1 }, { unique: true });
tokenPurchaseSchema.index({ userId: 1, purchaseDate: -1 });
tokenPurchaseSchema.index({ paymentStatus: 1 });

// Create Models
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Prize = mongoose.model('Prize', prizeSchema);
const Scratch = mongoose.model('Scratch', scratchSchema);
const Winner = mongoose.model('Winner', winnerSchema);
const GameSettings = mongoose.model('GameSettings', gameSettingsSchema);
const TokenPurchase = mongoose.model('TokenPurchase', tokenPurchaseSchema);

// ========================================
// AUTHENTICATION MIDDLEWARE
// ========================================

const verifyToken = (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    
    if (!token) {
        log('No token provided', { path: req.path, ip: req.ip });
        return res.status(401).json({ 
            error: 'Access denied. No token provided.',
            code: 'NO_TOKEN'
        });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        req.userType = decoded.userType;
        
        if (decoded.userType === 'user') {
            User.findByIdAndUpdate(decoded.userId, { lastActivity: new Date() }).exec();
        }
        
        log('Token verified', { 
            userId: decoded.userId, 
            userType: decoded.userType,
            path: req.path
        });
        next();
    } catch (error) {
        log('Token verification failed', { 
            error: error.message,
            path: req.path,
            ip: req.ip
        });
        return res.status(403).json({ 
            error: 'Invalid token',
            code: 'INVALID_TOKEN'
        });
    }
};

const verifyAdmin = (req, res, next) => {
    if (req.userType !== 'admin') {
        log('Admin access required', { 
            userId: req.userId,
            userType: req.userType,
            path: req.path
        });
        return res.status(403).json({ 
            error: 'Admin access required',
            code: 'ADMIN_REQUIRED'
        });
    }
    next();
};

// ========================================
// SOCKET.IO AUTHENTICATION & HANDLERS
// ========================================

io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error: No token provided'));
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        socket.userId = decoded.userId;
        socket.userType = decoded.userType;
        
        log('Socket authenticated', { 
            socketId: socket.id,
            userId: decoded.userId,
            userType: decoded.userType
        });
        
        next();
    } catch (err) {
        log('Socket authentication failed', { 
            socketId: socket.id,
            error: err.message
        });
        next(new Error('Authentication error: Invalid token'));
    }
});

io.on('connection', (socket) => {
    socketManager.addConnection(socket.id, socket.userId, socket.userType);
    
    socket.join(`user-${socket.userId}`);
    
    if (socket.userType === 'admin') {
        socket.join('admin-room');
        
        socket.emit('connection:stats', socketManager.getConnectionStats());
        
        socket.on('admin:settings-changed', async (data) => {
            try {
                socketManager.broadcastToAll('settings:updated', data);
                log('Admin changed settings', { 
                    adminId: socket.userId,
                    settings: data
                });
            } catch (error) {
                log('Settings broadcast error', { error: error.message });
            }
        });
        
        socket.on('admin:prize-added', async (data) => {
            try {
                socketManager.broadcastToAll('prizes:updated', {
                    type: 'prize_added',
                    prizeData: data,
                    message: 'New prize added'
                });
                log('Admin added prize', { 
                    adminId: socket.userId,
                    prizeId: data._id
                });
            } catch (error) {
                log('Prize add broadcast error', { error: error.message });
            }
        });
        
        socket.on('admin:user-action', async (data) => {
            try {
                const { action, userId, details } = data;
                
                socketManager.broadcastToAdmins('users:updated', {
                    type: action,
                    userId: userId,
                    details: details,
                    adminId: socket.userId
                });
                
                log('Admin user action', { 
                    adminId: socket.userId,
                    action,
                    targetUserId: userId
                });
            } catch (error) {
                log('Admin user action error', { error: error.message });
            }
        });
        
        socketManager.broadcastToAdmins('admin:connected', {
            adminId: socket.userId,
            timestamp: new Date(),
            connectionStats: socketManager.getConnectionStats()
        });
    }

    socket.on('user:activity', async (data) => {
        try {
            await User.findByIdAndUpdate(socket.userId, { lastActivity: new Date() });
            
            socketManager.broadcastToAdmins('user:activity', {
                userId: socket.userId,
                activity: data,
                timestamp: new Date()
            });
        } catch (error) {
            log('User activity error', { error: error.message });
        }
    });

    socket.on('disconnect', (reason) => {
        log('Socket disconnected', { 
            socketId: socket.id,
            userId: socket.userId,
            userType: socket.userType,
            reason
        });
        
        if (socket.userType === 'user') {
            socketManager.broadcastToAdmins('user:offline', {
                userId: socket.userId,
                timestamp: new Date(),
                reason
            });
        }
        
        socketManager.removeConnection(socket.id);
    });
});

// ========================================
// UTILITY FUNCTIONS
// ========================================

const generateClaimCode = () => {
    return crypto.randomBytes(4).toString('hex').toUpperCase();
};

const generateCryptoSecureNumber = () => {
    const randomBytes = crypto.randomBytes(2);
    const randomNum = Math.floor(1000 + (randomBytes.readUInt16BE(0) % 9000));
    return randomNum.toString().padStart(4, '0');
};

const enhancedErrorResponse = (res, statusCode, error, code, details = null) => {
    const response = {
        success: false,
        error,
        code,
        timestamp: new Date().toISOString()
    };
    
    if (details && process.env.NODE_ENV === 'development') {
        response.details = details;
    }
    
    log('API Error Response', {
        statusCode,
        error,
        code,
        details: details?.message || details
    });
    
    return res.status(statusCode).json(response);
};

const enhancedSuccessResponse = (res, message, data = null, meta = null) => {
    const response = {
        success: true,
        message,
        timestamp: new Date().toISOString()
    };
    
    if (data) response.data = data;
    if (meta) response.meta = meta;
    
    return res.json(response);
};

// ========================================
// CLEANUP JOBS
// ========================================

const cleanupExpiredPreparedScratches = async () => {
    try {
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        
        const result = await User.updateMany(
            { 
                preparedScratchDate: { $lt: fiveMinutesAgo },
                preparedScratchNumber: { $ne: null }
            },
            { 
                $unset: { 
                    preparedScratchNumber: "",
                    preparedScratchDate: "",
                    preparedScratchMetadata: ""
                }
            }
        );
        
        if (result.modifiedCount > 0) {
            log('🧹 Cleaned up expired prepared scratches', { 
                count: result.modifiedCount 
            });
        }
    } catch (error) {
        log('❌ Cleanup expired scratches error', { error: error.message });
    }
};

setInterval(cleanupExpiredPreparedScratches, 2 * 60 * 1000);

// ========================================
// ROOT & HEALTH ENDPOINTS
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: '🎯 Gosok Angka Backend API - Complete',
        version: '4.1.0',
        status: 'Production Ready - RAILWAY OPTIMIZED',
        domain: 'gosokangkahoki.com',
        features: {
            realtime: 'Socket.io enabled with enhanced sync events',
            auth: 'JWT with role-based access control',
            database: 'MongoDB with optimized indexing',
            cors: 'Production domains configured',
            synchronization: 'Real-time client-server sync',
            validation: 'Comprehensive input validation',
            errorHandling: 'Structured error responses'
        },
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

app.get('/api/health', (req, res) => {
    const healthcheck = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        memory: process.memoryUsage(),
        socketConnections: socketManager.getConnectionStats(),
        environment: process.env.NODE_ENV || 'development',
        version: '4.1.0'
    };
    
    const status = mongoose.connection.readyState === 1 ? 200 : 503;
    res.status(status).json(healthcheck);
});

app.get('/health', (req, res) => {
    res.redirect('/api/health');
});

// ========================================
// AUTH ROUTES WITH ENHANCED VALIDATION
// ========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phoneNumber } = req.body;
        
        if (!name || name.trim().length < 2) {
            return enhancedErrorResponse(res, 400, 'Nama minimal 2 karakter', 'INVALID_NAME');
        }
        
        if (!password || password.length < 6) {
            return enhancedErrorResponse(res, 400, 'Password minimal 6 karakter', 'INVALID_PASSWORD');
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
            return enhancedErrorResponse(res, 400, 'Email atau nomor HP harus diisi', 'MISSING_CONTACT');
        }
        
        const existingUser = await User.findOne({
            $or: [
                { email: userEmail.toLowerCase() },
                { phoneNumber: userPhone }
            ]
        });
        
        if (existingUser) {
            return enhancedErrorResponse(res, 400, 'Email atau nomor HP sudah terdaftar', 'USER_EXISTS');
        }
        
        const hashedPassword = await bcrypt.hash(password, 12);
        
        const settings = await GameSettings.findOne();
        const defaultFreeScratches = settings?.maxFreeScratchesPerDay || 1;
        
        const user = new User({
            name: name.trim(),
            email: userEmail.toLowerCase(),
            password: hashedPassword,
            phoneNumber: userPhone,
            freeScratchesRemaining: defaultFreeScratches
        });
        
        await user.save();
        
        socketManager.broadcastToAdmins('user:new-registration', {
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
        
        log('User registered', { 
            userId: user._id,
            name: user.name,
            email: user.email
        });
        
        res.status(201).json({
            success: true,
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
        log('Register error', { error: error.message });
        return enhancedErrorResponse(res, 500, 'Server error', 'REGISTER_ERROR', error);
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { identifier, password, email } = req.body;
        
        const loginIdentifier = identifier || email;
        
        if (!loginIdentifier || !password) {
            return enhancedErrorResponse(res, 400, 'Email/No HP dan password harus diisi', 'MISSING_CREDENTIALS');
        }
        
        let user;
        
        if (loginIdentifier.includes('@')) {
            user = await User.findOne({ email: loginIdentifier.toLowerCase() });
        } else {
            const cleanPhone = loginIdentifier.replace(/\D/g, '');
            user = await User.findOne({ 
                $or: [
                    { phoneNumber: cleanPhone },
                    { phoneNumber: loginIdentifier }
                ]
            });
        }
        
        if (!user) {
            return enhancedErrorResponse(res, 400, 'Email/No HP atau password salah', 'INVALID_CREDENTIALS');
        }
        
        if (user.status === 'banned') {
            return enhancedErrorResponse(res, 403, 'Akun Anda telah diblokir', 'ACCOUNT_BANNED');
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return enhancedErrorResponse(res, 400, 'Email/No HP atau password salah', 'INVALID_CREDENTIALS');
        }
        
        user.lastActivity = new Date();
        await user.save();
        
        const token = jwt.sign(
            { userId: user._id, userType: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        log('User logged in', { 
            userId: user._id,
            name: user.name,
            email: user.email
        });
        
        res.json({
            success: true,
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
        log('Login error', { error: error.message });
        return enhancedErrorResponse(res, 500, 'Server error', 'LOGIN_ERROR', error);
    }
});

// ========================================
// USER ROUTES
// ========================================

app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return enhancedErrorResponse(res, 404, 'User not found', 'USER_NOT_FOUND');
        }
        
        log('Profile request', { 
            userId: user._id,
            name: user.name,
            freeScratchesRemaining: user.freeScratchesRemaining,
            paidScratchesRemaining: user.paidScratchesRemaining
        });
        
        res.json(user);
    } catch (error) {
        log('Profile error', { error: error.message });
        return enhancedErrorResponse(res, 500, 'Server error', 'PROFILE_ERROR', error);
    }
});

// ========================================
// ENHANCED GAME ROUTES
// ========================================

app.post('/api/game/prepare-scratch', verifyToken, async (req, res) => {
    try {
        const settings = await GameSettings.findOne();
        if (!settings || !settings.isGameActive) {
            return enhancedErrorResponse(res, 400, 'Game sedang maintenance', 'GAME_INACTIVE');
        }
        
        const user = await User.findById(req.userId);
        
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        if (user.preparedScratchNumber && user.preparedScratchDate < fiveMinutesAgo) {
            log('Clearing expired prepared scratch', { 
                userId: user._id,
                expiredNumber: user.preparedScratchNumber
            });
            user.preparedScratchNumber = null;
            user.preparedScratchDate = null;
            user.preparedScratchMetadata = null;
            await user.save();
        }
        
        if (user.preparedScratchNumber && user.preparedScratchDate > fiveMinutesAgo) {
            log('User already has active prepared scratch', { 
                userId: user._id,
                preparedNumber: user.preparedScratchNumber
            });
            return res.json({
                success: true,
                message: 'Scratch already prepared',
                scratchNumber: user.preparedScratchNumber,
                preparedAt: user.preparedScratchDate,
                expiresAt: new Date(user.preparedScratchDate.getTime() + 5 * 60 * 1000),
                alreadyPrepared: true
            });
        }
        
        const totalScratches = (user.freeScratchesRemaining || 0) + (user.paidScratchesRemaining || 0);
        log('Checking user scratches', { 
            userId: user._id,
            freeScratchesRemaining: user.freeScratchesRemaining,
            paidScratchesRemaining: user.paidScratchesRemaining,
            totalScratches
        });
        
        if (totalScratches <= 0) {
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            if (!user.lastScratchDate || user.lastScratchDate < today) {
                const freeScratches = Math.floor(Math.random() * (settings.maxFreeScratchesPerDay - settings.minFreeScratchesPerDay + 1)) + settings.minFreeScratchesPerDay;
                user.freeScratchesRemaining = freeScratches;
                await user.save();
                log('New day! Reset free scratches', { 
                    userId: user._id,
                    freeScratches
                });
            } else {
                return enhancedErrorResponse(res, 400, 'Tidak ada kesempatan tersisa! Beli token scratch atau tunggu besok.', 'NO_SCRATCHES_REMAINING', {
                    needTokens: true,
                    nextReset: new Date(today.getTime() + 24 * 60 * 60 * 1000)
                });
            }
        }
        
        let scratchNumber;
        let isForced = false;
        
        if (user.forcedWinningNumber) {
            scratchNumber = user.forcedWinningNumber;
            isForced = true;
            log('Using forced winning number', { 
                userId: user._id,
                forcedNumber: scratchNumber
            });
            
            user.forcedWinningNumber = null;
        } else {
            scratchNumber = generateCryptoSecureNumber();
            log('Generated crypto-secure random number', { 
                userId: user._id,
                scratchNumber
            });
        }
        
        user.preparedScratchNumber = scratchNumber;
        user.preparedScratchDate = new Date();
        user.preparedScratchMetadata = {
            isForced,
            generationMethod: isForced ? 'forced' : 'random',
            clientIP: req.ip,
            userAgent: req.headers['user-agent']
        };
        
        await user.save();
        
        log('Prepared scratch number', { 
            userId: user._id,
            scratchNumber,
            method: isForced ? 'FORCED' : 'RANDOM'
        });
        
        res.json({
            success: true,
            message: 'Scratch prepared successfully',
            scratchNumber: scratchNumber,
            preparedAt: user.preparedScratchDate,
            expiresAt: new Date(user.preparedScratchDate.getTime() + 5 * 60 * 1000),
            isForced,
            remainingTime: 300,
            alreadyPrepared: false
        });
    } catch (error) {
        log('Prepare scratch error', { 
            userId: req.userId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error saat menyiapkan scratch', 'PREPARE_ERROR', error);
    }
});

app.post('/api/game/scratch', verifyToken, async (req, res) => {
    try {
        const { scratchNumber } = req.body;
        
        if (!scratchNumber) {
            return enhancedErrorResponse(res, 400, 'Scratch number is required', 'MISSING_SCRATCH_NUMBER');
        }
        
        const settings = await GameSettings.findOne();
        if (!settings || !settings.isGameActive) {
            return enhancedErrorResponse(res, 400, 'Game sedang maintenance', 'GAME_INACTIVE');
        }
        
        const user = await User.findById(req.userId);
        
        if (!user.preparedScratchNumber) {
            log('No prepared scratch', { userId: user._id });
            return enhancedErrorResponse(res, 400, 'Tidak ada scratch yang disiapkan. Silakan prepare scratch terlebih dahulu.', 'NO_PREPARED_SCRATCH', {
                requireNewPreparation: true
            });
        }
        
        if (user.preparedScratchNumber !== scratchNumber) {
            log('Invalid scratch number', { 
                userId: user._id,
                expected: user.preparedScratchNumber,
                received: scratchNumber
            });
            return enhancedErrorResponse(res, 400, 'Nomor scratch tidak valid. Silakan prepare scratch baru.', 'INVALID_SCRATCH_NUMBER', {
                requireNewPreparation: true
            });
        }
        
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        if (user.preparedScratchDate < fiveMinutesAgo) {
            log('Prepared scratch expired', { 
                userId: user._id,
                preparedAt: user.preparedScratchDate
            });
            
            user.preparedScratchNumber = null;
            user.preparedScratchDate = null;
            user.preparedScratchMetadata = null;
            await user.save();
            
            return enhancedErrorResponse(res, 400, 'Scratch number expired. Silakan prepare scratch baru.', 'SCRATCH_EXPIRED', {
                requireNewPreparation: true,
                expiredAt: user.preparedScratchDate
            });
        }
        
        const totalScratches = (user.freeScratchesRemaining || 0) + (user.paidScratchesRemaining || 0);
        if (totalScratches <= 0) {
            return enhancedErrorResponse(res, 400, 'Tidak ada kesempatan tersisa!', 'NO_SCRATCHES_REMAINING', {
                needTokens: true
            });
        }
        
        let isWin = false;
        let prize = null;
        let winner = null;
        let winMethod = null;
        let isPaidScratch = user.paidScratchesRemaining > 0;
        
        log('Executing scratch', { 
            userId: user._id,
            scratchNumber,
            freeScratchesRemaining: user.freeScratchesRemaining,
            paidScratchesRemaining: user.paidScratchesRemaining,
            isPaidScratch
        });
        
        const exactMatchPrize = await Prize.findOne({ 
            winningNumber: scratchNumber,
            stock: { $gt: 0 },
            isActive: true
        });
        
        if (exactMatchPrize) {
            isWin = true;
            prize = exactMatchPrize;
            winMethod = 'exact_match';
            
            log('EXACT MATCH WIN!', { 
                userId: user._id,
                scratchNumber,
                prizeName: prize.name,
                prizeValue: prize.value
            });
            
            await Prize.findByIdAndUpdate(prize._id, { 
                $inc: { stock: -1, totalWins: 1 },
                updatedAt: new Date()
            });
            
            socketManager.broadcastToAll('prizes:updated', {
                type: 'stock_updated',
                prizeId: prize._id,
                newStock: prize.stock - 1,
                winMethod: 'exact_match'
            });
        } else {
            const winRate = user.customWinRate !== null ? user.customWinRate : settings.winProbability;
            log('Checking probability win', { 
                userId: user._id,
                winRate,
                isCustom: user.customWinRate !== null
            });
            
            const randomBytes = crypto.randomBytes(4);
            const randomChance = (randomBytes.readUInt32BE(0) / 0xFFFFFFFF) * 100;
            
            if (randomChance <= winRate) {
                const availablePrizes = await Prize.find({
                    stock: { $gt: 0 },
                    isActive: true
                }).sort({ value: 1 });
                
                if (availablePrizes.length > 0) {
                    const weights = availablePrizes.map(p => 1 / Math.sqrt(p.value));
                    const totalWeight = weights.reduce((sum, w) => sum + w, 0);
                    const randomWeight = Math.random() * totalWeight;
                    
                    let cumulativeWeight = 0;
                    for (let i = 0; i < availablePrizes.length; i++) {
                        cumulativeWeight += weights[i];
                        if (randomWeight <= cumulativeWeight) {
                            prize = availablePrizes[i];
                            break;
                        }
                    }
                    
                    if (prize) {
                        isWin = true;
                        winMethod = 'probability';
                        
                        log('PROBABILITY WIN!', { 
                            userId: user._id,
                            scratchNumber,
                            prizeName: prize.name,
                            prizeValue: prize.value,
                            winRate,
                            randomChance: randomChance.toFixed(2)
                        });
                        
                        await Prize.findByIdAndUpdate(prize._id, { 
                            $inc: { stock: -1, totalWins: 1 },
                            updatedAt: new Date()
                        });
                        
                        socketManager.broadcastToAll('prizes:updated', {
                            type: 'stock_updated',
                            prizeId: prize._id,
                            newStock: prize.stock - 1,
                            winMethod: 'probability'
                        });
                    }
                } else {
                    log('Would have won but no prizes available', { 
                        userId: user._id,
                        winRate,
                        randomChance: randomChance.toFixed(2)
                    });
                }
            } else {
                log('Did not win probability', { 
                    userId: user._id,
                    winRate,
                    randomChance: randomChance.toFixed(2)
                });
            }
        }
        
        const scratch = new Scratch({
            userId: req.userId,
            scratchNumber,
            isWin,
            prizeId: prize?._id,
            isPaid: isPaidScratch,
            winMethod,
            scratchMetadata: {
                winMethod,
                preparedAt: user.preparedScratchDate,
                executedAt: new Date(),
                userAgent: req.headers['user-agent'],
                clientIP: req.ip,
                originalPreparedData: user.preparedScratchMetadata
            }
        });
        
        await scratch.save();
        
        if (isWin && prize) {
            const claimCode = generateClaimCode();
            
            winner = new Winner({
                userId: req.userId,
                prizeId: prize._id,
                scratchId: scratch._id,
                claimCode,
                winMethod
            });
            
            await winner.save();
            
            const populatedWinner = await Winner.findById(winner._id)
                .populate('userId', 'name email phoneNumber')
                .populate('prizeId', 'name value type');
                
            socketManager.broadcastToAll('winner:new', populatedWinner);
            socketManager.broadcastToAdmins('winner:new', {
                winner: populatedWinner,
                timestamp: new Date()
            });
        }
        
        const oldBalances = {
            free: user.freeScratchesRemaining || 0,
            paid: user.paidScratchesRemaining || 0
        };
        
        if (isPaidScratch) {
            user.paidScratchesRemaining -= 1;
        } else {
            user.freeScratchesRemaining -= 1;
        }
        
        user.scratchCount = (user.scratchCount || 0) + 1;
        if (isWin) user.winCount = (user.winCount || 0) + 1;
        user.lastScratchDate = new Date();
        
        user.preparedScratchNumber = null;
        user.preparedScratchDate = null;
        user.preparedScratchMetadata = null;
        
        await user.save();
        
        const scratchEventData = {
            _id: scratch._id,
            userId: req.userId,
            userName: user.name,
            scratchNumber,
            isWin,
            isPaid: isPaidScratch,
            winMethod,
            scratchDate: scratch.scratchDate,
            prize: isWin ? {
                name: prize.name,
                type: prize.type,
                value: prize.value
            } : null
        };
        
        socketManager.broadcastToAll('scratch:new', scratchEventData);
        socketManager.broadcastToAdmins('scratch:new', {
            ...scratchEventData,
            userDetails: {
                email: user.email,
                phoneNumber: user.phoneNumber
            }
        });
        
        log('Scratch completed', { 
            userId: user._id,
            scratchNumber,
            isWin,
            winMethod,
            newBalances: {
                free: user.freeScratchesRemaining,
                paid: user.paidScratchesRemaining
            }
        });
        
        res.json({
            success: true,
            scratchNumber,
            isWin,
            winMethod,
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
            balanceChanges: {
                oldBalances,
                newBalances: {
                    free: user.freeScratchesRemaining,
                    paid: user.paidScratchesRemaining
                }
            },
            isPaidScratch,
            executedAt: new Date()
        });
    } catch (error) {
        log('Scratch error', { 
            userId: req.userId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error saat mengeksekusi scratch', 'SCRATCH_ERROR', error);
    }
});

app.get('/api/user/history', verifyToken, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        
        const scratches = await Scratch.find({ userId: req.userId })
            .populate('prizeId')
            .sort({ scratchDate: -1 })
            .limit(limitNum)
            .skip((pageNum - 1) * limitNum)
            .lean();
            
        const total = await Scratch.countDocuments({ userId: req.userId });
        
        log('User history request', { 
            userId: req.userId,
            page: pageNum,
            limit: limitNum,
            total
        });
            
        res.json({ 
            success: true,
            scratches,
            pagination: {
                page: pageNum,
                limit: limitNum,
                total,
                totalPages: Math.ceil(total / limitNum)
            }
        });
    } catch (error) {
        log('History error', { 
            userId: req.userId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error', 'HISTORY_ERROR', error);
    }
});

// ========================================
// PUBLIC ROUTES (NO AUTH REQUIRED)
// ========================================

app.get('/api/public/prizes', async (req, res) => {
    try {
        const prizes = await Prize.find({ 
            isActive: true,
            stock: { $gt: 0 }
        })
        .select('winningNumber name type value stock')
        .sort({ value: 1 })
        .lean();
        
        log('Public prizes request', { count: prizes.length });
        
        res.json(prizes);
    } catch (error) {
        log('Get public prizes error', { error: error.message });
        return enhancedErrorResponse(res, 500, 'Server error', 'PRIZES_ERROR', error);
    }
});

app.get('/api/public/game-settings', async (req, res) => {
    try {
        let settings = await GameSettings.findOne();
        
        if (!settings) {
            settings = new GameSettings({
                winProbability: 5,
                maxFreeScratchesPerDay: 1,
                minFreeScratchesPerDay: 1,
                scratchTokenPrice: 10000,
                isGameActive: true,
                resetTime: '00:00'
            });
            await settings.save();
            log('Default game settings created');
        }
        
        const publicSettings = {
            isGameActive: settings.isGameActive,
            maxFreeScratchesPerDay: settings.maxFreeScratchesPerDay,
            minFreeScratchesPerDay: settings.minFreeScratchesPerDay,
            scratchTokenPrice: settings.scratchTokenPrice,
            resetTime: settings.resetTime,
            maintenanceMessage: settings.maintenanceMessage || ''
        };
        
        log('Public settings request');
        
        res.json(publicSettings);
    } catch (error) {
        log('Get public settings error', { error: error.message });
        return enhancedErrorResponse(res, 500, 'Server error', 'SETTINGS_ERROR', error);
    }
});

// ========================================
// ADMIN ROUTES
// ========================================

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return enhancedErrorResponse(res, 400, 'Username dan password harus diisi', 'MISSING_CREDENTIALS');
        }
        
        const admin = await Admin.findOne({ username: username.toLowerCase() });
        if (!admin) {
            log('Admin login failed - user not found', { username });
            return enhancedErrorResponse(res, 400, 'Username atau password salah', 'INVALID_CREDENTIALS');
        }
        
        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            log('Admin login failed - invalid password', { username });
            return enhancedErrorResponse(res, 400, 'Username atau password salah', 'INVALID_CREDENTIALS');
        }
        
        admin.lastLogin = new Date();
        await admin.save();
        
        const token = jwt.sign(
            { userId: admin._id, userType: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        log('Admin logged in', { 
            adminId: admin._id,
            username: admin.username,
            name: admin.name
        });
        
        res.json({
            success: true,
            message: 'Login berhasil',
            token,
            admin: {
                _id: admin._id,
                id: admin._id,
                name: admin.name,
                username: admin.username,
                role: admin.role,
                lastLogin: admin.lastLogin
            }
        });
    } catch (error) {
        log('Admin login error', { error: error.message });
        return enhancedErrorResponse(res, 500, 'Server error', 'LOGIN_ERROR', error);
    }
});

app.get('/api/admin/dashboard', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const [
            totalUsers,
            todayScratches,
            todayWinners,
            totalPrizesResult,
            pendingPurchases,
            activePrizes,
            totalTokenSales
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
            ]),
            TokenPurchase.countDocuments({ paymentStatus: 'pending' }),
            Prize.countDocuments({ isActive: true, stock: { $gt: 0 } }),
            TokenPurchase.aggregate([
                { $match: { paymentStatus: 'completed' } },
                { $group: {
                    _id: null,
                    totalQuantity: { $sum: '$quantity' },
                    totalRevenue: { $sum: '$totalAmount' }
                }}
            ])
        ]);
        
        const dashboardData = {
            totalUsers,
            todayScratches,
            todayWinners,
            totalPrizes: totalPrizesResult[0]?.total || 0,
            pendingPurchases,
            activePrizes,
            totalTokensSold: totalTokenSales[0]?.totalQuantity || 0,
            totalTokenRevenue: totalTokenSales[0]?.totalRevenue || 0,
            systemHealth: {
                databaseConnected: mongoose.connection.readyState === 1,
                socketConnections: socketManager.getConnectionStats(),
                uptime: process.uptime()
            }
        };
        
        log('Dashboard stats', { 
            adminId: req.userId,
            stats: dashboardData
        });
        
        res.json(dashboardData);
    } catch (error) {
        log('Dashboard error', { 
            adminId: req.userId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error', 'DASHBOARD_ERROR', error);
    }
});

app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, search = '', status = 'all' } = req.query;
        const pageNum = parseInt(page);
        const limitNum = parseInt(limit);
        
        let query = {};
        if (search) {
            query.$or = [
                { name: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } },
                { phoneNumber: { $regex: search, $options: 'i' } }
            ];
        }
        
        if (status !== 'all') {
            query.status = status;
        }
        
        const users = await User.find(query)
            .select('-password -preparedScratchMetadata')
            .limit(limitNum)
            .skip((pageNum - 1) * limitNum)
            .sort({ createdAt: -1 })
            .lean();
            
        const total = await User.countDocuments(query);
        
        log('Admin users request', { 
            adminId: req.userId,
            page: pageNum,
            limit: limitNum,
            search,
            total
        });
        
        res.json({
            success: true,
            users,
            pagination: {
                page: pageNum,
                limit: limitNum,
                total,
                totalPages: Math.ceil(total / limitNum)
            }
        });
    } catch (error) {
        log('Get users error', { 
            adminId: req.userId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error', 'GET_USERS_ERROR', error);
    }
});

app.get('/api/admin/users/:userId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return enhancedErrorResponse(res, 400, 'Invalid user ID format', 'INVALID_USER_ID');
        }
        
        const user = await User.findById(userId).select('-password').lean();
        if (!user) {
            return enhancedErrorResponse(res, 404, 'User tidak ditemukan', 'USER_NOT_FOUND');
        }
        
        const [scratches, wins, tokenPurchases] = await Promise.all([
            Scratch.find({ userId })
                .populate('prizeId', 'name value type')
                .sort({ scratchDate: -1 })
                .limit(20)
                .lean(),
            Winner.find({ userId })
                .populate('prizeId', 'name value type')
                .sort({ scratchDate: -1 })
                .lean(),
            TokenPurchase.find({ userId })
                .populate('adminId', 'name username')
                .sort({ purchaseDate: -1 })
                .limit(10)
                .lean()
        ]);
        
        const userStats = {
            totalScratches: user.scratchCount || 0,
            totalWins: user.winCount || 0,
            winRate: user.scratchCount > 0 ? ((user.winCount / user.scratchCount) * 100).toFixed(2) : 0,
            customWinRate: user.customWinRate,
            forcedWinningNumber: user.forcedWinningNumber,
            totalPurchasedScratches: user.totalPurchasedScratches || 0,
            hasPreparedScratch: !!user.preparedScratchNumber,
            preparedScratchExpiry: user.preparedScratchDate ? 
                new Date(user.preparedScratchDate.getTime() + 5 * 60 * 1000) : null
        };
        
        log('User detail request', { 
            adminId: req.userId,
            targetUserId: userId,
            userStats
        });
        
        res.json({
            success: true,
            user,
            scratches,
            wins,
            tokenPurchases,
            stats: userStats
        });
    } catch (error) {
        log('Get user detail error', { 
            adminId: req.userId,
            targetUserId: req.params.userId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error', 'USER_DETAIL_ERROR', error);
    }
});

app.post('/api/admin/token-purchase', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId, quantity, paymentMethod, notes } = req.body;
        
        if (!userId || !quantity || quantity < 1) {
            return enhancedErrorResponse(res, 400, 'User ID dan quantity harus diisi', 'INVALID_PURCHASE_DATA');
        }
        
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return enhancedErrorResponse(res, 400, 'Invalid user ID format', 'INVALID_USER_ID');
        }
        
        const user = await User.findById(userId);
        if (!user) {
            return enhancedErrorResponse(res, 404, 'User tidak ditemukan', 'USER_NOT_FOUND');
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
        
        log('Token purchase created', { 
            adminId: req.userId,
            userId,
            quantity,
            totalAmount,
            purchaseId: purchase._id
        });
        
        const populatedPurchase = await TokenPurchase.findById(purchase._id)
            .populate('userId', 'name email phoneNumber')
            .populate('adminId', 'name username');
        
        res.status(201).json({
            success: true,
            message: 'Token purchase created successfully',
            purchase: populatedPurchase
        });
    } catch (error) {
        log('Create token purchase error', { 
            adminId: req.userId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error', 'CREATE_PURCHASE_ERROR', error);
    }
});

app.put('/api/admin/token-purchase/:purchaseId/complete', verifyToken, verifyAdmin, async (req, res) => {
    const session = await mongoose.startSession();
    
    try {
        await session.withTransaction(async () => {
            const { purchaseId } = req.params;
            
            if (!mongoose.Types.ObjectId.isValid(purchaseId)) {
                throw new Error('Invalid purchase ID format');
            }
            
            const purchase = await TokenPurchase.findById(purchaseId)
                .populate('userId', 'name email phoneNumber freeScratchesRemaining paidScratchesRemaining totalPurchasedScratches')
                .session(session);
                
            if (!purchase) {
                throw new Error('Purchase tidak ditemukan');
            }
            
            if (purchase.paymentStatus === 'completed') {
                throw new Error('Purchase sudah completed');
            }
            
            if (purchase.paymentStatus === 'cancelled') {
                throw new Error('Purchase sudah dibatalkan');
            }
            
            const user = await User.findById(purchase.userId._id).session(session);
            if (!user) {
                throw new Error('User tidak ditemukan');
            }
            
            const oldBalance = user.paidScratchesRemaining || 0;
            user.paidScratchesRemaining = oldBalance + purchase.quantity;
            user.totalPurchasedScratches = (user.totalPurchasedScratches || 0) + purchase.quantity;
            
            await user.save({ session });
            
            purchase.paymentStatus = 'completed';
            purchase.completedDate = new Date();
            await purchase.save({ session });
            
            log('Token purchase completed', { 
                adminId: req.userId,
                purchaseId: purchase._id,
                userId: user._id,
                quantity: purchase.quantity,
                oldBalance,
                newBalance: user.paidScratchesRemaining
            });
            
            socketManager.broadcastToUser(user._id.toString(), 'user:token-updated', {
                userId: user._id,
                quantity: purchase.quantity,
                newBalance: {
                    free: user.freeScratchesRemaining || 0,
                    paid: user.paidScratchesRemaining,
                    total: (user.freeScratchesRemaining || 0) + user.paidScratchesRemaining
                },
                message: `${purchase.quantity} token berhasil ditambahkan ke akun Anda!`
            });
            
            socketManager.broadcastToAdmins('token:purchased', {
                userId: user._id,
                quantity: purchase.quantity,
                totalAmount: purchase.totalAmount,
                adminId: req.userId,
                newBalance: {
                    free: user.freeScratchesRemaining || 0,
                    paid: user.paidScratchesRemaining
                }
            });
        });
        
        const updatedPurchase = await TokenPurchase.findById(req.params.purchaseId)
            .populate(['userId', 'adminId']);
        
        res.json({
            success: true,
            message: 'Token purchase completed successfully',
            purchase: updatedPurchase
        });
        
    } catch (error) {
        log('Complete token purchase error', { 
            adminId: req.userId,
            purchaseId: req.params.purchaseId,
            error: error.message 
        });
        return enhancedErrorResponse(res, 500, 'Server error', 'COMPLETE_PURCHASE_ERROR', error);
    } finally {
        await session.endSession();
    }
});

// ========================================
// ERROR HANDLING & 404
// ========================================

app.use((req, res) => {
    log('404 - Endpoint not found', { 
        path: req.path,
        method: req.method,
        ip: req.ip
    });
    
    res.status(404).json({ 
        success: false,
        error: 'Endpoint not found',
        code: 'ENDPOINT_NOT_FOUND',
        requestedPath: req.path,
        method: req.method,
        timestamp: new Date().toISOString()
    });
});

app.use((err, req, res, next) => {
    if (err.message && err.message.includes('CORS')) {
        log('CORS Error', { 
            message: err.message,
            origin: req.headers.origin,
            path: req.path
        });
        
        return res.status(403).json({ 
            success: false,
            error: 'CORS Error',
            code: 'CORS_BLOCKED',
            message: 'Origin not allowed',
            origin: req.headers.origin
        });
    }
    
    log('Global error', { 
        error: err.message,
        path: req.path,
        method: req.method,
        ip: req.ip
    });
    
    res.status(err.status || 500).json({ 
        success: false,
        error: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong!',
        code: 'INTERNAL_ERROR',
        timestamp: new Date().toISOString()
    });
});

// ========================================
// INITIALIZATION FUNCTIONS
// ========================================

async function createDefaultAdmin() {
    try {
        const adminExists = await Admin.findOne({ username: 'admin' });
        
        if (!adminExists) {
            const hashedPassword = await bcrypt.hash('GosokAngka2024!', 12);
            
            const admin = new Admin({
                username: 'admin',
                password: hashedPassword,
                name: 'Super Administrator',
                role: 'super_admin'
            });
            
            await admin.save();
            log('✅ Default admin created!', {
                username: 'admin',
                password: 'GosokAngka2024!'
            });
        }
    } catch (error) {
        log('❌ Error creating default admin', { error: error.message });
    }
}

async function createDefaultSettings() {
    try {
        const settingsExist = await GameSettings.findOne();
        
        if (!settingsExist) {
            const settings = new GameSettings({
                winProbability: 5,
                maxFreeScratchesPerDay: 1,
                minFreeScratchesPerDay: 1,
                scratchTokenPrice: 10000,
                isGameActive: true,
                resetTime: '00:00'
            });
            
            await settings.save();
            log('✅ Default game settings created!');
        }
    } catch (error) {
        log('❌ Error creating default settings', { error: error.message });
    }
}

async function createSamplePrizes() {
    try {
        const prizeCount = await Prize.countDocuments();
        
        if (prizeCount === 0) {
            const samplePrizes = [
                {
                    winningNumber: '1093',
                    name: 'iPhone 15 Pro',
                    type: 'physical',
                    value: 15000000,
                    stock: 2,
                    originalStock: 2,
                    isActive: true
                },
                {
                    winningNumber: '2415',
                    name: 'Cash Prize 50 Juta',
                    type: 'cash',
                    value: 50000000,
                    stock: 1,
                    originalStock: 1,
                    isActive: true
                },
                {
                    winningNumber: '6451',
                    name: 'Voucher Tokopedia Rp250K',
                    type: 'voucher',
                    value: 250000,
                    stock: 10,
                    originalStock: 10,
                    isActive: true
                },
                {
                    winningNumber: '9026',
                    name: 'Voucher Shopee Rp500K',
                    type: 'voucher',
                    value: 500000,
                    stock: 5,
                    originalStock: 5,
                    isActive: true
                }
            ];
            
            await Prize.insertMany(samplePrizes);
            log('✅ Sample prizes created!', { count: samplePrizes.length });
        }
    } catch (error) {
        log('❌ Error creating sample prizes', { error: error.message });
    }
}

async function initializeDatabase() {
    log('🔧 Initializing database...');
    await createDefaultAdmin();
    await createDefaultSettings();
    await createSamplePrizes();
    log('✅ Database initialization completed!');
}

// ========================================
// GRACEFUL SHUTDOWN HANDLING
// ========================================

process.on('SIGTERM', () => {
    log('🛑 SIGTERM received, starting graceful shutdown...');
    
    server.close(() => {
        log('✅ HTTP server closed');
        
        mongoose.connection.close(false, () => {
            log('✅ MongoDB connection closed');
            process.exit(0);
        });
    });
});

process.on('SIGINT', () => {
    log('🛑 SIGINT received, starting graceful shutdown...');
    
    server.close(() => {
        log('✅ HTTP server closed');
        
        mongoose.connection.close(false, () => {
            log('✅ MongoDB connection closed');
            process.exit(0);
        });
    });
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 5000;

server.listen(PORT, '0.0.0.0', () => {
    log('========================================');
    log('🎯 GOSOK ANGKA BACKEND - COMPLETE v4.1.0');
    log('========================================');
    log(`✅ Server running on port ${PORT}`);
    log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    log(`📡 API URL: ${process.env.NODE_ENV === 'production' ? 'https://gosokangka-backend-production.up.railway.app' : `http://localhost:${PORT}`}`);
    log(`🔌 Socket.io enabled with enhanced real-time sync`);
    log(`📊 Database: MongoDB Atlas with optimized indexing`);
    log(`🔐 Security: CORS, JWT authentication, input validation`);
    log('🆕 COMPLETE FEATURES v4.1.0:');
    log('   ✅ COMPLETE: All frontend endpoints supported');
    log('   ✅ COMPLETE: Real-time socket events for admin & user');
    log('   ✅ COMPLETE: Token purchase system with transactions');
    log('   ✅ COMPLETE: Advanced scratch system with prepare/execute');
    log('   ✅ COMPLETE: Admin dashboard with live monitoring');
    log('   ✅ COMPLETE: User management with detailed profiles');
    log('   ✅ COMPLETE: Prize system with exact match & probability');
    log('   ✅ OPTIMIZED: Railway deployment with reduced memory usage');
    log('========================================');
    
    setTimeout(initializeDatabase, 2000);
});

module.exports = server;
