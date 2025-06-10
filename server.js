// ========================================
// GOSOK ANGKA BACKEND - FIXED VERSION 4.2.0
// RAILWAY OPTIMIZED WITH ALL FIXES
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
// ENHANCED LOGGING FOR RAILWAY
// ========================================
const log = (message, data = '') => {
    const timestamp = new Date().toISOString();
    if (data && typeof data === 'object') {
        console.log(`[${timestamp}] ${message}:`, JSON.stringify(data, null, 2));
    } else if (data) {
        console.log(`[${timestamp}] ${message}: ${data}`);
    } else {
        console.log(`[${timestamp}] ${message}`);
    }
};

// Validate required environment variables
const requiredEnvVars = ['JWT_SECRET', 'MONGODB_URI'];
const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);

if (missingEnvVars.length > 0) {
    log('❌ FATAL ERROR: Missing environment variables', missingEnvVars);
    process.exit(1);
}

log('✅ Environment variables validated');
log('🚀 Starting Gosok Angka Backend v4.2.0 (Fixed)');

// ========================================
// ENHANCED DATABASE CONNECTION
// ========================================
async function connectDB() {
    const maxRetries = 5;
    let retryCount = 0;
    
    while (retryCount < maxRetries) {
        try {
            log('🔌 Connecting to MongoDB...', { attempt: retryCount + 1 });
            
            // Enhanced connection options for Railway
            await mongoose.connect(process.env.MONGODB_URI, {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                retryWrites: true,
                w: 'majority',
                maxPoolSize: 5, // Reduced for Railway memory limits
                serverSelectionTimeoutMS: 10000, // 10 second timeout
                socketTimeoutMS: 45000,
                bufferCommands: false,
                bufferMaxEntries: 0,
                connectTimeoutMS: 10000,
                heartbeatFrequencyMS: 10000
            });
            
            log('✅ MongoDB connected successfully!', {
                database: mongoose.connection.name,
                host: mongoose.connection.host,
                readyState: mongoose.connection.readyState
            });
            
            // Handle connection events
            mongoose.connection.on('error', (err) => {
                log('❌ MongoDB connection error:', err.message);
            });
            
            mongoose.connection.on('disconnected', () => {
                log('⚠️ MongoDB disconnected');
            });
            
            mongoose.connection.on('reconnected', () => {
                log('✅ MongoDB reconnected');
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

// Start database connection
connectDB();

// ========================================
// ENHANCED CORS CONFIGURATION
// ========================================
const allowedOrigins = [
    // Netlify domains
    'https://gosokangkahoki.netlify.app',
    'https://www.gosokangkahoki.netlify.app',
    
    // Custom domains
    'https://gosokangkahoki.com',
    'https://www.gosokangkahoki.com',
    'https://admin.gosokangkahoki.com',
    
    // Railway backend domain (FIXED)
    'https://gosokangka-backend-production-e9fa.up.railway.app',
    
    // Development
    'http://localhost:3000',
    'http://localhost:5000',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5000',
    
    // Additional Railway domains
    'https://gosokangka-backend-production.up.railway.app'
];

app.use(cors({
    origin: function(origin, callback) {
        // Allow requests with no origin (mobile apps, etc.)
        if (!origin) return callback(null, true);
        
        // Check if origin is in allowed list
        if (allowedOrigins.includes(origin)) {
            log('✅ CORS: Origin allowed', { origin });
            return callback(null, true);
        }
        
        // Allow Netlify preview URLs
        if (origin && (origin.includes('.netlify.app') || origin.includes('--'))) {
            log('⚠️ CORS: Netlify preview URL allowed', { origin });
            return callback(null, true);
        }
        
        // Allow Railway preview URLs
        if (origin && origin.includes('.railway.app')) {
            log('⚠️ CORS: Railway preview URL allowed', { origin });
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
        'Origin',
        'Cache-Control',
        'Pragma'
    ],
    optionsSuccessStatus: 200
}));

// Enhanced middleware
app.use(express.json({ limit: '5mb' })); // Reduced for Railway
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

// Request logging with reduced verbosity for Railway
app.use((req, res, next) => {
    const startTime = Date.now();
    
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        // Only log important requests to reduce Railway logs
        if (res.statusCode >= 400 || duration > 1000) {
            log('HTTP Request', {
                method: req.method,
                url: req.url,
                status: res.statusCode,
                duration: `${duration}ms`
            });
        }
    });
    
    next();
});

// ========================================
// ENHANCED SOCKET.IO SETUP
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
    pingInterval: 25000,
    maxHttpBufferSize: 1e6, // 1MB limit for Railway
    serveClient: false // Disable serving client files to save memory
});

// Enhanced Socket Manager with memory optimization
const socketManager = {
    connections: new Map(),
    adminConnections: new Set(),
    userConnections: new Map(),
    
    addConnection(socketId, userId, userType) {
        this.connections.set(socketId, { 
            userId, 
            userType, 
            connectedAt: Date.now() // Use timestamp instead of Date object
        });
        
        if (userType === 'admin') {
            this.adminConnections.add(socketId);
        } else {
            this.userConnections.set(userId, socketId);
        }
        
        // Only log if there are few connections to reduce logs
        if (this.connections.size <= 10) {
            log('Socket connected', { socketId: socketId.substring(0, 8), userType, total: this.connections.size });
        }
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
        }
    },
    
    broadcastToAdmins(event, data) {
        let sentCount = 0;
        this.adminConnections.forEach(socketId => {
            const socket = io.sockets.sockets.get(socketId);
            if (socket) {
                socket.emit(event, data);
                sentCount++;
            }
        });
        
        if (sentCount > 0) {
            log('Broadcast to admins', { event, count: sentCount });
        }
    },
    
    broadcastToUser(userId, event, data) {
        const socketId = this.userConnections.get(userId);
        if (socketId) {
            const socket = io.sockets.sockets.get(socketId);
            if (socket) {
                socket.emit(event, data);
                return true;
            }
        }
        return false;
    },
    
    broadcastToAll(event, data) {
        const connectionCount = this.connections.size;
        io.emit(event, data);
        
        if (connectionCount > 0) {
            log('Broadcast to all', { event, connections: connectionCount });
        }
    },
    
    getConnectionStats() {
        return {
            total: this.connections.size,
            admins: this.adminConnections.size,
            users: this.userConnections.size,
            uptime: Math.floor(process.uptime())
        };
    },
    
    // Cleanup old connections every 5 minutes
    cleanup() {
        const fiveMinutesAgo = Date.now() - 5 * 60 * 1000;
        let cleanedCount = 0;
        
        for (const [socketId, connection] of this.connections.entries()) {
            if (connection.connectedAt < fiveMinutesAgo) {
                const socket = io.sockets.sockets.get(socketId);
                if (!socket || !socket.connected) {
                    this.removeConnection(socketId);
                    cleanedCount++;
                }
            }
        }
        
        if (cleanedCount > 0) {
            log('Socket cleanup', { cleaned: cleanedCount, remaining: this.connections.size });
        }
    }
};

// Cleanup timer
setInterval(() => socketManager.cleanup(), 5 * 60 * 1000);

// ========================================
// DATABASE SCHEMAS (Optimized)
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
        index: true, // Added index
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
        index: true, // Added index
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
        default: 'active',
        index: true // Added index
    },
    scratchCount: { type: Number, default: 0, min: 0 },
    winCount: { type: Number, default: 0, min: 0 },
    lastScratchDate: { type: Date, index: true },
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
    preparedScratchDate: { type: Date, default: null, index: true },
    preparedScratchMetadata: {
        isForced: { type: Boolean, default: false },
        generationMethod: { type: String, enum: ['random', 'forced'], default: 'random' },
        clientIP: String,
        userAgent: String
    },
    lastActivity: { type: Date, default: Date.now, index: true },
    createdAt: { type: Date, default: Date.now, index: true }
}, {
    // Optimize for Railway memory
    toJSON: { virtuals: false, versionKey: false },
    toObject: { virtuals: false, versionKey: false }
});

const adminSchema = new mongoose.Schema({
    username: { 
        type: String, 
        required: true, 
        unique: true,
        trim: true,
        minlength: 3,
        maxlength: 50,
        index: true
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
        index: true,
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
        min: 1000,
        index: true
    },
    stock: { 
        type: Number, 
        required: true,
        min: 0,
        index: true
    },
    originalStock: { type: Number, required: true },
    isActive: { type: Boolean, default: true, index: true },
    totalWins: { type: Number, default: 0 },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

const scratchSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true,
        index: true
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
    isWin: { type: Boolean, default: false, index: true },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize' },
    isPaid: { type: Boolean, default: false, index: true },
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
        clientIP: String
    },
    scratchDate: { type: Date, default: Date.now, index: true }
});

const winnerSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        ref: 'User', 
        required: true,
        index: true
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
        default: 'pending',
        index: true
    },
    claimCode: { 
        type: String, 
        required: true,
        unique: true,
        uppercase: true,
        index: true
    },
    winMethod: { 
        type: String, 
        enum: ['exact_match', 'probability'],
        required: true
    },
    scratchDate: { type: Date, default: Date.now, index: true },
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
        required: true,
        index: true
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
        default: 'pending',
        index: true
    },
    paymentMethod: { 
        type: String,
        enum: ['cash', 'transfer', 'qris', 'e-wallet'],
        default: 'cash'
    },
    notes: { type: String, maxlength: 500 },
    purchaseDate: { type: Date, default: Date.now, index: true },
    completedDate: { type: Date },
    cancelledDate: { type: Date },
    cancelReason: { type: String }
});

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
        return res.status(401).json({ 
            error: 'Access denied. No token provided.',
            code: 'NO_TOKEN'
        });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        req.userType = decoded.userType;
        
        // Update last activity for users (async, don't wait)
        if (decoded.userType === 'user') {
            User.findByIdAndUpdate(decoded.userId, { lastActivity: new Date() }).exec().catch(() => {});
        }
        
        next();
    } catch (error) {
        return res.status(403).json({ 
            error: 'Invalid token',
            code: 'INVALID_TOKEN'
        });
    }
};

const verifyAdmin = (req, res, next) => {
    if (req.userType !== 'admin') {
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
        
        next();
    } catch (err) {
        next(new Error('Authentication error: Invalid token'));
    }
});

io.on('connection', (socket) => {
    socketManager.addConnection(socket.id, socket.userId, socket.userType);
    
    socket.join(`user-${socket.userId}`);
    
    if (socket.userType === 'admin') {
        socket.join('admin-room');
        socket.emit('connection:stats', socketManager.getConnectionStats());
        
        // Admin event handlers
        socket.on('admin:settings-changed', async (data) => {
            try {
                socketManager.broadcastToAll('settings:updated', data);
            } catch (error) {
                log('Settings broadcast error', error.message);
            }
        });
        
        socket.on('admin:prize-added', async (data) => {
            try {
                socketManager.broadcastToAll('prizes:updated', {
                    type: 'prize_added',
                    prizeData: data,
                    message: 'New prize added'
                });
            } catch (error) {
                log('Prize add broadcast error', error.message);
            }
        });
        
        socketManager.broadcastToAdmins('admin:connected', {
            adminId: socket.userId,
            timestamp: Date.now(),
            connectionStats: socketManager.getConnectionStats()
        });
    }

    // User activity handler
    socket.on('user:activity', async (data) => {
        try {
            // Update user activity (async, don't wait)
            User.findByIdAndUpdate(socket.userId, { lastActivity: new Date() }).exec().catch(() => {});
            
            socketManager.broadcastToAdmins('user:activity', {
                userId: socket.userId,
                activity: data,
                timestamp: Date.now()
            });
        } catch (error) {
            // Silent fail to prevent socket errors
        }
    });

    socket.on('disconnect', (reason) => {
        if (socket.userType === 'user') {
            socketManager.broadcastToAdmins('user:offline', {
                userId: socket.userId,
                timestamp: Date.now(),
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
// CLEANUP JOBS (Memory Optimized)
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
            log('🧹 Cleaned expired prepared scratches', { count: result.modifiedCount });
        }
    } catch (error) {
        log('❌ Cleanup error', error.message);
    }
};

// Run cleanup every 2 minutes
setInterval(cleanupExpiredPreparedScratches, 2 * 60 * 1000);

// Memory cleanup every 10 minutes
setInterval(() => {
    if (global.gc) {
        global.gc();
        log('🗑️ Memory cleanup executed');
    }
}, 10 * 60 * 1000);

// ========================================
// ROOT & HEALTH ENDPOINTS
// ========================================

app.get('/', (req, res) => {
    res.json({
        message: '🎯 Gosok Angka Backend API - Fixed Version',
        version: '4.2.0',
        status: 'Production Ready - RAILWAY OPTIMIZED & FIXED',
        domain: 'gosokangkahoki.com',
        railway: {
            url: 'https://gosokangka-backend-production-e9fa.up.railway.app',
            status: 'Connected',
            optimizations: 'Memory optimized, Enhanced CORS, Fixed Socket.io'
        },
        features: {
            realtime: 'Socket.io with enhanced sync',
            auth: 'JWT with role-based access',
            database: 'MongoDB Atlas optimized',
            cors: 'Fixed for Railway deployment',
            synchronization: 'Real-time client-server sync',
            validation: 'Comprehensive input validation',
            errorHandling: 'Structured error responses'
        },
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        environment: process.env.NODE_ENV || 'development',
        connections: socketManager.getConnectionStats()
    });
});

app.get('/api/health', (req, res) => {
    const memUsage = process.memoryUsage();
    const healthcheck = {
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: Math.floor(process.uptime()),
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        memory: {
            used: Math.round(memUsage.heapUsed / 1024 / 1024) + ' MB',
            total: Math.round(memUsage.heapTotal / 1024 / 1024) + ' MB',
            external: Math.round(memUsage.external / 1024 / 1024) + ' MB'
        },
        socketConnections: socketManager.getConnectionStats(),
        environment: process.env.NODE_ENV || 'development',
        version: '4.2.0',
        railway: {
            optimized: true,
            corsFixed: true,
            memoryOptimized: true
        }
    };
    
    const status = mongoose.connection.readyState === 1 ? 200 : 503;
    res.status(status).json(healthcheck);
});

// ========================================
// AUTH ROUTES
// ========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phoneNumber } = req.body;
        
        // Enhanced validation
        if (!name || name.trim().length < 2) {
            return enhancedErrorResponse(res, 400, 'Nama minimal 2 karakter', 'INVALID_NAME');
        }
        
        if (!password || password.length < 6) {
            return enhancedErrorResponse(res, 400, 'Password minimal 6 karakter', 'INVALID_PASSWORD');
        }
        
        let userEmail = email;
        let userPhone = phoneNumber;
        
        // Auto-generate email or phone if one is missing
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
        
        // Check existing user
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
        
        // Broadcast to admins
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
            name: user.name
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
        log('Register error', error.message);
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
        
        // Determine if it's email or phone
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
        
        // Update last activity
        user.lastActivity = new Date();
        await user.save();
        
        const token = jwt.sign(
            { userId: user._id, userType: 'user' },
            process.env.JWT_SECRET,
            { expiresIn: '7d' }
        );
        
        log('User logged in', { 
            userId: user._id,
            name: user.name
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
        log('Login error', error.message);
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
        
        res.json(user);
    } catch (error) {
        log('Profile error', error.message);
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
        
        // Clean expired prepared scratch
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        if (user.preparedScratchNumber && user.preparedScratchDate < fiveMinutesAgo) {
            user.preparedScratchNumber = null;
            user.preparedScratchDate = null;
            user.preparedScratchMetadata = null;
            await user.save();
        }
        
        // Check if already has active prepared scratch
        if (user.preparedScratchNumber && user.preparedScratchDate > fiveMinutesAgo) {
            return res.json({
                success: true,
                message: 'Scratch already prepared',
                scratchNumber: user.preparedScratchNumber,
                preparedAt: user.preparedScratchDate,
                expiresAt: new Date(user.preparedScratchDate.getTime() + 5 * 60 * 1000),
                alreadyPrepared: true
            });
        }
        
        // Check available scratches
        const totalScratches = (user.freeScratchesRemaining || 0) + (user.paidScratchesRemaining || 0);
        
        if (totalScratches <= 0) {
            // Check if new day - reset free scratches
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
        
        // Generate scratch number
        let scratchNumber;
        let isForced = false;
        
        if (user.forcedWinningNumber) {
            scratchNumber = user.forcedWinningNumber;
            isForced = true;
            user.forcedWinningNumber = null;
        } else {
            scratchNumber = generateCryptoSecureNumber();
        }
        
        // Save prepared scratch
        user.preparedScratchNumber = scratchNumber;
        user.preparedScratchDate = new Date();
        user.preparedScratchMetadata = {
            isForced,
            generationMethod: isForced ? 'forced' : 'random',
            clientIP: req.ip,
            userAgent: req.headers['user-agent']
        };
        
        await user.save();
        
        log('Prepared scratch', { 
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
        
        // Validate prepared scratch
        if (!user.preparedScratchNumber) {
            return enhancedErrorResponse(res, 400, 'Tidak ada scratch yang disiapkan. Silakan prepare scratch terlebih dahulu.', 'NO_PREPARED_SCRATCH', {
                requireNewPreparation: true
            });
        }
        
        if (user.preparedScratchNumber !== scratchNumber) {
            return enhancedErrorResponse(res, 400, 'Nomor scratch tidak valid. Silakan prepare scratch baru.', 'INVALID_SCRATCH_NUMBER', {
                requireNewPreparation: true
            });
        }
        
        // Check expiry
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        if (user.preparedScratchDate < fiveMinutesAgo) {
            user.preparedScratchNumber = null;
            user.preparedScratchDate = null;
            user.preparedScratchMetadata = null;
            await user.save();
            
            return enhancedErrorResponse(res, 400, 'Scratch number expired. Silakan prepare scratch baru.', 'SCRATCH_EXPIRED', {
                requireNewPreparation: true,
                expiredAt: user.preparedScratchDate
            });
        }
        
        // Check remaining scratches
        const totalScratches = (user.freeScratchesRemaining || 0) + (user.paidScratchesRemaining || 0);
        if (totalScratches <= 0) {
            return enhancedErrorResponse(res, 400, 'Tidak ada kesempatan tersisa!', 'NO_SCRATCHES_REMAINING', {
                needTokens: true
            });
        }
        
        // Determine win logic
        let isWin = false;
        let prize = null;
        let winner = null;
        let winMethod = null;
        let isPaidScratch = user.paidScratchesRemaining > 0;
        
        // 1. Check exact match first
        const exactMatchPrize = await Prize.findOne({ 
            winningNumber: scratchNumber,
            stock: { $gt: 0 },
            isActive: true
        });
        
        if (exactMatchPrize) {
            isWin = true;
            prize = exactMatchPrize;
            winMethod = 'exact_match';
            
            // Update prize stock
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
            // 2. Check probability win
            const winRate = user.customWinRate !== null ? user.customWinRate : settings.winProbability;
            
            const randomBytes = crypto.randomBytes(4);
            const randomChance = (randomBytes.readUInt32BE(0) / 0xFFFFFFFF) * 100;
            
            if (randomChance <= winRate) {
                // User won by probability - select a prize
                const availablePrizes = await Prize.find({
                    stock: { $gt: 0 },
                    isActive: true
                }).sort({ value: 1 });
                
                if (availablePrizes.length > 0) {
                    // Weighted selection (lower value prizes more likely)
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
                        
                        // Update prize stock
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
                }
            }
        }
        
        // Create scratch record
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
                clientIP: req.ip
            }
        });
        
        await scratch.save();
        
        // Create winner record if won
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
            
            // Broadcast winner
            const populatedWinner = await Winner.findById(winner._id)
                .populate('userId', 'name email phoneNumber')
                .populate('prizeId', 'name value type');
                
            socketManager.broadcastToAll('winner:new', populatedWinner);
            socketManager.broadcastToAdmins('winner:new', {
                winner: populatedWinner,
                timestamp: new Date()
            });
        }
        
        // Update user balances
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
        
        // Clear prepared scratch
        user.preparedScratchNumber = null;
        user.preparedScratchDate = null;
        user.preparedScratchMetadata = null;
        
        await user.save();
        
        // Broadcast scratch event
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
            winMethod
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
        const limitNum = Math.min(parseInt(limit), 100); // Max 100 items per page
        
        const scratches = await Scratch.find({ userId: req.userId })
            .populate('prizeId')
            .sort({ scratchDate: -1 })
            .limit(limitNum)
            .skip((pageNum - 1) * limitNum)
            .lean();
            
        const total = await Scratch.countDocuments({ userId: req.userId });
            
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
// PUBLIC ROUTES
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
        
        res.json(prizes);
    } catch (error) {
        log('Get public prizes error', error.message);
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
        }
        
        const publicSettings = {
            isGameActive: settings.isGameActive,
            maxFreeScratchesPerDay: settings.maxFreeScratchesPerDay,
            minFreeScratchesPerDay: settings.minFreeScratchesPerDay,
            scratchTokenPrice: settings.scratchTokenPrice,
            resetTime: settings.resetTime,
            maintenanceMessage: settings.maintenanceMessage || ''
        };
        
        res.json(publicSettings);
    } catch (error) {
        log('Get public settings error', error.message);
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
            return enhancedErrorResponse(res, 400, 'Username atau password salah', 'INVALID_CREDENTIALS');
        }
        
        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
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
            username: admin.username
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
        log('Admin login error', error.message);
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
                uptime: Math.floor(process.uptime())
            }
        };
        
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
        const limitNum = Math.min(parseInt(limit), 100); // Max 100 items per page
        
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
            totalAmount
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
            
            // Broadcast to user
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
            
            // Broadcast to admins
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
        path: req.path
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
            log('✅ Default admin created', {
                username: 'admin',
                password: 'GosokAngka2024!'
            });
        }
    } catch (error) {
        log('❌ Error creating default admin', error.message);
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
            log('✅ Default game settings created');
        }
    } catch (error) {
        log('❌ Error creating default settings', error.message);
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
            log('✅ Sample prizes created', { count: samplePrizes.length });
        }
    } catch (error) {
        log('❌ Error creating sample prizes', error.message);
    }
}

async function initializeDatabase() {
    log('🔧 Initializing database...');
    await createDefaultAdmin();
    await createDefaultSettings();
    await createSamplePrizes();
    log('✅ Database initialization completed');
}

// ========================================
// GRACEFUL SHUTDOWN
// ========================================

const gracefulShutdown = (signal) => {
    log(`🛑 ${signal} received, starting graceful shutdown...`);
    
    server.close(() => {
        log('✅ HTTP server closed');
        
        mongoose.connection.close(false, () => {
            log('✅ MongoDB connection closed');
            process.exit(0);
        });
    });
    
    // Force exit after 30 seconds
    setTimeout(() => {
        log('⚠️ Force exit after 30 seconds');
        process.exit(1);
    }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    log('💀 Uncaught Exception', err.message);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

process.on('unhandledRejection', (reason, promise) => {
    log('💀 Unhandled Rejection', { reason: reason?.message || reason });
    gracefulShutdown('UNHANDLED_REJECTION');
});

// ========================================
// START SERVER
// ========================================

const PORT = process.env.PORT || 5000;

server.listen(PORT, '0.0.0.0', () => {
    log('========================================');
    log('🎯 GOSOK ANGKA BACKEND - FIXED v4.2.0');
    log('========================================');
    log(`✅ Server running on port ${PORT}`);
    log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    log(`📡 Railway URL: https://gosokangka-backend-production-e9fa.up.railway.app`);
    log(`🔌 Socket.io enabled with enhanced real-time sync`);
    log(`📊 Database: MongoDB Atlas with optimized connections`);
    log(`🔐 Security: Enhanced CORS, JWT auth, input validation`);
    log(`💾 Memory: Optimized for Railway deployment`);
    log('🆕 FIXES IN v4.2.0:');
    log('   ✅ FIXED: Railway backend URL in CORS');
    log('   ✅ FIXED: MongoDB connection with retry logic');
    log('   ✅ FIXED: Memory optimization for Railway');
    log('   ✅ FIXED: Enhanced error handling');
    log('   ✅ FIXED: Socket.io connection stability');
    log('   ✅ FIXED: Database query optimization');
    log('   ✅ OPTIMIZED: Reduced logging for Railway');
    log('   ✅ OPTIMIZED: Memory cleanup intervals');
    log('========================================');
    
    // Initialize database after server starts
    setTimeout(initializeDatabase, 2000);
});

module.exports = server;
