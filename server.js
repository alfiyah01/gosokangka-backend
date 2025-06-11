// ========================================
// GOSOK ANGKA BACKEND - SECURITY ENHANCED VERSION 4.2.0
// ADDED: Complete Security Features + All Original Features
// Backend URL: gosokangka-backend-production-e9fa.up.railway.app
// ========================================

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const http = require('http');
const socketIO = require('socket.io');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');
const xss = require('xss');
const mongoSanitize = require('express-mongo-sanitize');
const speakeasy = require('speakeasy');
require('dotenv').config();

const app = express();
const server = http.createServer(app);

// ========================================
// SECURITY ENHANCEMENTS
// ========================================

// Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "unpkg.com"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "wss:", "https:"],
            fontSrc: ["'self'", "cdnjs.cloudflare.com"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        },
    },
    crossOriginEmbedderPolicy: false
}));

// Rate Limiting
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        securityLogger.logSuspiciousActivity(req.ip, 'RATE_LIMIT_EXCEEDED', {
            endpoint: req.path,
            userAgent: req.get('User-Agent')
        });
        res.status(429).json({
            error: 'Too many requests from this IP, please try again later.',
            retryAfter: '15 minutes'
        });
    }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login attempts per windowMs
    message: {
        error: 'Too many login attempts from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        securityLogger.logSuspiciousActivity(req.ip, 'LOGIN_RATE_LIMIT_EXCEEDED', {
            endpoint: req.path,
            userAgent: req.get('User-Agent'),
            body: { username: req.body.username || req.body.identifier }
        });
        res.status(429).json({
            error: 'Too many login attempts from this IP, please try again later.',
            retryAfter: '15 minutes'
        });
    }
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // limit each IP to 50 admin requests per windowMs
    message: {
        error: 'Too many admin requests from this IP, please try again later.',
        retryAfter: '15 minutes'
    },
    handler: (req, res) => {
        securityLogger.logSuspiciousActivity(req.ip, 'ADMIN_RATE_LIMIT_EXCEEDED', {
            endpoint: req.path,
            adminId: req.userId,
            userAgent: req.get('User-Agent')
        });
        res.status(429).json({
            error: 'Too many admin requests from this IP, please try again later.',
            retryAfter: '15 minutes'
        });
    }
});

// Input Sanitization
const sanitizeInput = (input) => {
    if (typeof input !== 'string') return input;
    return xss(validator.escape(input.trim()));
};

const sanitizeObject = (obj) => {
    const sanitized = {};
    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            if (typeof obj[key] === 'string') {
                sanitized[key] = sanitizeInput(obj[key]);
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                sanitized[key] = sanitizeObject(obj[key]);
            } else {
                sanitized[key] = obj[key];
            }
        }
    }
    return sanitized;
};

// Security Logger
const securityLogger = {
    logAction: (userId, userType, action, details = {}) => {
        const logEntry = {
            timestamp: new Date().toISOString(),
            userId,
            userType,
            action,
            details,
            ip: details.ip || 'unknown'
        };
        console.log(`[SECURITY] ${JSON.stringify(logEntry)}`);
        // In production, save to database or external logging service
    },

    logSuspiciousActivity: (ip, type, details = {}) => {
        const logEntry = {
            timestamp: new Date().toISOString(),
            ip,
            type,
            details,
            severity: 'HIGH'
        };
        console.log(`[SUSPICIOUS] ${JSON.stringify(logEntry)}`);
        // In production, trigger alerts
    },

    logAuthAttempt: (identifier, success, ip, userAgent = '') => {
        const logEntry = {
            timestamp: new Date().toISOString(),
            identifier,
            success,
            ip,
            userAgent: userAgent.substring(0, 100) // Limit length
        };
        console.log(`[AUTH] ${JSON.stringify(logEntry)}`);
    }
};

// Apply general rate limiting
app.use('/api/', generalLimiter);

// Apply stricter rate limiting for auth endpoints
app.use('/api/auth/', authLimiter);
app.use('/api/admin/login', authLimiter);

// Apply admin rate limiting
app.use('/api/admin/', adminLimiter);

// Force HTTPS in production
if (process.env.NODE_ENV === 'production') {
    app.use((req, res, next) => {
        if (req.header('x-forwarded-proto') !== 'https') {
            return res.redirect(`https://${req.header('host')}${req.url}`);
        }
        next();
    });
}

// Prevent NoSQL injection
app.use(mongoSanitize());

// CHECK CRITICAL ENV VARS
if (!process.env.JWT_SECRET) {
    console.error('❌ FATAL ERROR: JWT_SECRET is not defined in environment variables!');
    process.exit(1);
}
if (process.env.JWT_SECRET.length < 32) {
    console.error('❌ FATAL ERROR: JWT_SECRET must be at least 32 characters long for security!');
    process.exit(1);
}
if (!process.env.MONGODB_URI) {
    console.error('❌ FATAL ERROR: MONGODB_URI is not defined in environment variables!');
    process.exit(1);
}
console.log('✅ Environment variables configured securely');
console.log('🌐 Backend URL: gosokangka-backend-production-e9fa.up.railway.app');

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
// CORS CONFIGURATION - ENHANCED SECURITY
// ========================================
const allowedOrigins = [
    // Main domains
    'https://gosokangkahoki.netlify.app',     
    'https://www.gosokangkahoki.netlify.app',
    'https://gosokangkahoki.com',             
    'https://www.gosokangkahoki.com',         
    'http://gosokangkahoki.com',              
    'http://www.gosokangkahoki.com',         
    
    // Netlify deployment domains
    /^https:\/\/.*--gosokangkahoki\.netlify\.app$/,
    /^https:\/\/.*\.gosokangkahoki\.netlify\.app$/,
    
    // Railway backend
    'https://gosokangka-backend-production-e9fa.up.railway.app',
    'https://gosokangka-backend-production.up.railway.app',
    
    // Development (only in non-production)
    ...(process.env.NODE_ENV !== 'production' ? [
        'http://localhost:3000',
        'http://localhost:5000',
        'http://127.0.0.1:3000',
        'http://127.0.0.1:5000',
        'http://localhost:8080',
        'http://127.0.0.1:8080'
    ] : [])
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
        
        // More restrictive in production
        if (process.env.NODE_ENV !== 'production' && origin.includes('.netlify.app')) {
            console.log('⚠️ CORS: Temporarily allowing Netlify domain (dev mode):', origin);
            return callback(null, true);
        }
        
        console.log('❌ CORS: Origin blocked:', origin);
        securityLogger.logSuspiciousActivity(origin, 'CORS_VIOLATION', {
            requestedOrigin: origin,
            timestamp: new Date().toISOString()
        });
        
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
// SOCKET.IO SETUP - ENHANCED SECURITY
// ========================================
const io = socketIO(server, {
    cors: {
        origin: function(origin, callback) {
            if (!origin) return callback(null, true);
            
            if (allowedOrigins.includes(origin) || 
                allowedOrigins.some(allowed => allowed instanceof RegExp && allowed.test(origin)) ||
                (process.env.NODE_ENV !== 'production' && origin.includes('.netlify.app'))) {
                return callback(null, true);
            }
            
            securityLogger.logSuspiciousActivity(origin, 'SOCKET_CORS_VIOLATION', {
                requestedOrigin: origin,
                timestamp: new Date().toISOString()
            });
            
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
        securityLogger.logAction('system', 'system', 'PRIZE_UPDATE_BROADCAST', data);
    },
    broadcastSettingsUpdate: (data) => {
        io.emit('settings:updated', data);
        console.log('📡 Broadcasting settings update');
        securityLogger.logAction('system', 'system', 'SETTINGS_UPDATE_BROADCAST', data);
    },
    broadcastUserUpdate: (data) => {
        io.emit('users:updated', data);
        console.log('📡 Broadcasting user update:', data.type);
        securityLogger.logAction('system', 'system', 'USER_UPDATE_BROADCAST', data);
    },
    broadcastNewWinner: (data) => {
        io.emit('winner:new', data);
        console.log('📡 Broadcasting new winner');
        securityLogger.logAction('system', 'system', 'NEW_WINNER_BROADCAST', { winnerId: data._id });
    },
    broadcastNewScratch: (data) => {
        io.emit('scratch:new', data);
        console.log('📡 Broadcasting new scratch');
        securityLogger.logAction(data.userId, 'user', 'NEW_SCRATCH_BROADCAST', { scratchId: data._id });
    },
    broadcastNewUser: (data) => {
        io.emit('user:new-registration', data);
        console.log('📡 Broadcasting new user registration');
        securityLogger.logAction(data.user._id, 'user', 'NEW_USER_REGISTRATION', { userId: data.user._id });
    },
    broadcastTokenPurchase: (data) => {
        // Broadcast ke semua admin
        io.to('admin-room').emit('token:purchased', data);
        // Broadcast ke user yang bersangkutan untuk update balance
        io.to(`user-${data.userId}`).emit('user:token-updated', {
            userId: data.userId,
            newBalance: data.newBalance,
            quantity: data.quantity,
            message: `${data.quantity} token berhasil ditambahkan ke akun Anda!`
        });
        console.log('📡 Broadcasting token purchase to user:', data.userId);
        securityLogger.logAction(data.userId, 'user', 'TOKEN_PURCHASE_BROADCAST', { quantity: data.quantity });
    }
};

// Add middleware
app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf) => {
        // Store raw body for webhook verification if needed
        req.rawBody = buf;
    }
}));
app.use(express.urlencoded({ extended: true }));

// Request logging with security info
app.use((req, res, next) => {
    const userAgent = req.get('User-Agent') || 'Unknown';
    const ip = req.ip || req.connection.remoteAddress;
    
    console.log(`🔍 ${req.method} ${req.path} from IP: ${ip}, Origin: ${req.headers.origin || 'NO-ORIGIN'}`);
    
    // Log suspicious patterns
    if (req.path.includes('..') || req.path.includes('<script>') || req.path.includes('eval(')) {
        securityLogger.logSuspiciousActivity(ip, 'SUSPICIOUS_PATH', {
            path: req.path,
            userAgent: userAgent.substring(0, 100),
            headers: req.headers
        });
    }
    
    req.clientInfo = { ip, userAgent };
    next();
});

// ========================================
// DATABASE SCHEMAS - ENHANCED WITH SECURITY FIELDS
// ========================================

const userSchema = new mongoose.Schema({
    name: { type: String, required: true, maxlength: 100 },
    email: { type: String, required: true, unique: true, lowercase: true, maxlength: 100 },
    password: { type: String, required: true },
    phoneNumber: { type: String, required: true, maxlength: 20 },
    status: { type: String, default: 'active', enum: ['active', 'inactive', 'suspended'] },
    scratchCount: { type: Number, default: 0 },
    winCount: { type: Number, default: 0 },
    lastScratchDate: { type: Date },
    customWinRate: { type: Number, default: null, min: 0, max: 100 },
    freeScratchesRemaining: { type: Number, default: 1, min: 0 }, 
    paidScratchesRemaining: { type: Number, default: 0, min: 0 }, 
    totalPurchasedScratches: { type: Number, default: 0, min: 0 },
    forcedWinningNumber: { type: String, default: null },
    preparedScratchNumber: { type: String, default: null },
    preparedScratchDate: { type: Date, default: null },
    // Security fields
    lastLoginIP: { type: String },
    lastLoginDate: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    accountLockedUntil: { type: Date },
    passwordChangedAt: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now }
});

const adminSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, maxlength: 50 },
    password: { type: String, required: true },
    name: { type: String, required: true, maxlength: 100 },
    role: { type: String, default: 'admin', enum: ['admin', 'super_admin'] },
    // Security fields
    lastLoginIP: { type: String },
    lastLoginDate: { type: Date },
    failedLoginAttempts: { type: Number, default: 0 },
    accountLockedUntil: { type: Date },
    passwordChangedAt: { type: Date, default: Date.now },
    twoFactorSecret: { type: String }, // For 2FA
    twoFactorEnabled: { type: Boolean, default: false },
    // Activity tracking
    lastActivity: { type: Date, default: Date.now },
    sessionCount: { type: Number, default: 0 },
    createdAt: { type: Date, default: Date.now }
});

const prizeSchema = new mongoose.Schema({
    winningNumber: { type: String, required: true, unique: true, match: /^\d{4}$/ },
    name: { type: String, required: true, maxlength: 200 },
    type: { type: String, enum: ['voucher', 'cash', 'physical'], required: true },
    value: { type: Number, required: true, min: 0 },
    stock: { type: Number, required: true, min: 0 },
    isActive: { type: Boolean, default: true },
    createdAt: { type: Date, default: Date.now },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
});

const scratchSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    scratchNumber: { type: String, required: true, match: /^\d{4}$/ },
    isWin: { type: Boolean, default: false },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize' },
    isPaid: { type: Boolean, default: false },
    scratchDate: { type: Date, default: Date.now },
    // Security fields
    ipAddress: { type: String },
    userAgent: { type: String, maxlength: 500 }
});

const winnerSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    prizeId: { type: mongoose.Schema.Types.ObjectId, ref: 'Prize', required: true },
    scratchId: { type: mongoose.Schema.Types.ObjectId, ref: 'Scratch', required: true },
    claimStatus: { type: String, enum: ['pending', 'completed', 'expired'], default: 'pending' },
    claimCode: { type: String, required: true },
    scratchDate: { type: Date, default: Date.now },
    claimDate: { type: Date },
    // Security fields
    ipAddress: { type: String },
    claimedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
});

const gameSettingsSchema = new mongoose.Schema({
    winningNumber: { type: String, required: true, match: /^\d{4}$/ },
    winProbability: { type: Number, default: 5, min: 0, max: 100 },
    maxFreeScratchesPerDay: { type: Number, default: 1, min: 0, max: 10 },
    minFreeScratchesPerDay: { type: Number, default: 1, min: 0, max: 10 },
    scratchTokenPrice: { type: Number, default: 10000, min: 1000 },
    isGameActive: { type: Boolean, default: true },
    resetTime: { type: String, default: '00:00' },
    // Security settings
    maxDailyScratches: { type: Number, default: 100, min: 1 },
    maintenanceMode: { type: Boolean, default: false },
    lastModifiedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' },
    lastModifiedAt: { type: Date, default: Date.now }
});

const tokenPurchaseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    adminId: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin', required: true },
    quantity: { type: Number, required: true, min: 1 },
    pricePerToken: { type: Number, required: true, min: 1000 },
    totalAmount: { type: Number, required: true, min: 1000 },
    paymentStatus: { type: String, enum: ['pending', 'completed', 'cancelled'], default: 'pending' },
    paymentMethod: { type: String, maxlength: 50 },
    notes: { type: String, maxlength: 500 },
    purchaseDate: { type: Date, default: Date.now },
    completedDate: { type: Date },
    // Security fields
    ipAddress: { type: String },
    completedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'Admin' }
});

// Security audit log schema
const auditLogSchema = new mongoose.Schema({
    userId: { type: String, required: true },
    userType: { type: String, enum: ['user', 'admin', 'system'], required: true },
    action: { type: String, required: true },
    resource: { type: String },
    details: { type: mongoose.Schema.Types.Mixed },
    ipAddress: { type: String },
    userAgent: { type: String, maxlength: 500 },
    timestamp: { type: Date, default: Date.now },
    severity: { type: String, enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], default: 'LOW' }
});

// Create Models
const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);
const Prize = mongoose.model('Prize', prizeSchema);
const Scratch = mongoose.model('Scratch', scratchSchema);
const Winner = mongoose.model('Winner', winnerSchema);
const GameSettings = mongoose.model('GameSettings', gameSettingsSchema);
const TokenPurchase = mongoose.model('TokenPurchase', tokenPurchaseSchema);
const AuditLog = mongoose.model('AuditLog', auditLogSchema);

// ========================================
// ENHANCED MIDDLEWARE WITH SECURITY
// ========================================

const verifyToken = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.split(' ')[1];
    
    if (!token) {
        console.error('❌ No token provided for:', req.path);
        securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'NO_TOKEN_PROVIDED', {
            path: req.path,
            userAgent: req.clientInfo.userAgent
        });
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        req.userType = decoded.userType;
        
        // Check if user/admin still exists and is active
        if (decoded.userType === 'admin') {
            const admin = await Admin.findById(decoded.userId);
            if (!admin) {
                throw new Error('Admin not found');
            }
            if (admin.accountLockedUntil && admin.accountLockedUntil > new Date()) {
                throw new Error('Account is locked');
            }
            // Update last activity
            admin.lastActivity = new Date();
            await admin.save();
        } else {
            const user = await User.findById(decoded.userId);
            if (!user) {
                throw new Error('User not found');
            }
            if (user.status !== 'active') {
                throw new Error('Account is not active');
            }
            if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
                throw new Error('Account is locked');
            }
        }
        
        console.log('✅ Token verified:', { userId: decoded.userId, userType: decoded.userType });
        next();
    } catch (error) {
        console.error('❌ Token verification failed:', error.message);
        securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'INVALID_TOKEN', {
            path: req.path,
            userAgent: req.clientInfo.userAgent,
            error: error.message
        });
        return res.status(403).json({ error: 'Invalid token: ' + error.message });
    }
};

const verifyAdmin = (req, res, next) => {
    if (req.userType !== 'admin') {
        console.error('❌ Admin access required for:', req.userId);
        securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'UNAUTHORIZED_ADMIN_ACCESS', {
            userId: req.userId,
            path: req.path,
            userAgent: req.clientInfo.userAgent
        });
        return res.status(403).json({ error: 'Admin access required' });
    }
    next();
};

// Input validation middleware
const validateInput = (req, res, next) => {
    // Sanitize body
    if (req.body) {
        req.body = sanitizeObject(req.body);
    }
    
    // Sanitize query params
    if (req.query) {
        req.query = sanitizeObject(req.query);
    }
    
    // Sanitize params
    if (req.params) {
        req.params = sanitizeObject(req.params);
    }
    
    next();
};

// Apply input validation to all routes
app.use(validateInput);

// ========================================
// SOCKET.IO HANDLERS - ENHANCED SECURITY
// ========================================

io.use(async (socket, next) => {
    try {
        const token = socket.handshake.auth.token;
        if (!token) {
            return next(new Error('Authentication error: No token provided'));
        }
        
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Verify user/admin still exists and is active
        if (decoded.userType === 'admin') {
            const admin = await Admin.findById(decoded.userId);
            if (!admin || (admin.accountLockedUntil && admin.accountLockedUntil > new Date())) {
                return next(new Error('Authentication error: Invalid admin'));
            }
        } else {
            const user = await User.findById(decoded.userId);
            if (!user || user.status !== 'active' || (user.accountLockedUntil && user.accountLockedUntil > new Date())) {
                return next(new Error('Authentication error: Invalid user'));
            }
        }
        
        socket.userId = decoded.userId;
        socket.userType = decoded.userType;
        next();
    } catch (err) {
        securityLogger.logSuspiciousActivity(socket.handshake.address, 'SOCKET_AUTH_FAILED', {
            error: err.message,
            userAgent: socket.handshake.headers['user-agent']
        });
        next(new Error('Authentication error'));
    }
});

io.on('connection', (socket) => {
    console.log('✅ User connected:', socket.userId, 'Type:', socket.userType);
    securityLogger.logAction(socket.userId, socket.userType, 'SOCKET_CONNECTED', {
        ip: socket.handshake.address
    });
    
    socket.join(`user-${socket.userId}`);
    
    if (socket.userType === 'admin') {
        socket.join('admin-room');
        
        // Handle admin events with logging
        socket.on('admin:settings-changed', async (data) => {
            try {
                securityLogger.logAction(socket.userId, 'admin', 'SETTINGS_CHANGED', data);
                socket.broadcast.emit('settings:updated', data);
                console.log('📡 Admin changed settings, broadcasting to all clients');
            } catch (error) {
                console.error('Settings broadcast error:', error);
            }
        });
        
        socket.on('admin:prize-added', async (data) => {
            try {
                securityLogger.logAction(socket.userId, 'admin', 'PRIZE_ADDED', data);
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
                securityLogger.logAction(socket.userId, 'admin', 'PRIZE_UPDATED', data);
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
                securityLogger.logAction(socket.userId, 'admin', 'PRIZE_DELETED', data);
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
    }

    socket.on('disconnect', () => {
        console.log('❌ User disconnected:', socket.userId);
        securityLogger.logAction(socket.userId, socket.userType, 'SOCKET_DISCONNECTED', {
            ip: socket.handshake.address
        });
        
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

// Root endpoint - UPDATED INFO
app.get('/', (req, res) => {
    res.json({
        message: '🎯 Gosok Angka Backend API',
        version: '4.2.0',
        status: 'Production Ready - SECURITY ENHANCED',
        domain: 'gosokangkahoki.com',
        backend: 'gosokangka-backend-production-e9fa.up.railway.app',
        features: {
            realtime: 'Socket.io enabled with sync events',
            auth: 'Email/Phone login support',
            database: 'MongoDB Atlas connected',
            cors: 'Production domains configured',
            winRate: 'Per-user win rate support',
            tokenPurchase: 'Complete token purchase system',
            forcedWinning: 'Admin can set winning number for users',
            synchronizedScratch: 'Perfect client-server scratch sync',
            noNotification: 'No notifications during scratch',
            mobileAdmin: 'Mobile responsive admin panel'
        },
        security: {
            rateLimit: 'Multi-tier rate limiting enabled',
            inputSanitization: 'XSS and injection protection',
            securityHeaders: 'Helmet.js security headers',
            auditLogging: 'Complete activity logging',
            accountLocking: 'Failed login attempt protection',
            corsStrict: 'Production-grade CORS policy',
            httpsEnforced: 'HTTPS redirect in production',
            tokenValidation: 'Enhanced JWT validation'
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
        uptime: process.uptime(),
        backend: 'gosokangka-backend-production-e9fa.up.railway.app',
        security: 'ENHANCED',
        version: '4.2.0'
    });
});

// Alternative health check
app.get('/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        database: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        uptime: process.uptime(),
        version: '4.2.0'
    });
});

// ========================================
// AUTH ROUTES - ENHANCED SECURITY
// ========================================

app.post('/api/auth/register', async (req, res) => {
    try {
        const { name, email, password, phoneNumber } = req.body;
        
        // Enhanced validation
        if (!name || !password) {
            return res.status(400).json({ error: 'Nama dan password harus diisi' });
        }
        
        if (password.length < 6) {
            return res.status(400).json({ error: 'Password minimal 6 karakter' });
        }
        
        // Check for suspicious patterns
        if (name.length > 100 || (email && email.length > 100) || (phoneNumber && phoneNumber.length > 20)) {
            securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'SUSPICIOUS_REGISTRATION_DATA', {
                name: name.substring(0, 20),
                email: email?.substring(0, 20),
                phoneNumber: phoneNumber?.substring(0, 15)
            });
            return res.status(400).json({ error: 'Data tidak valid' });
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
        
        // Validate email format if provided
        if (userEmail && userEmail !== 'dummy@gosokangka.com' && !validator.isEmail(userEmail)) {
            return res.status(400).json({ error: 'Format email tidak valid' });
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
        
        // Enhanced password hashing
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        
        // Get default settings for free scratches
        const settings = await GameSettings.findOne();
        const defaultFreeScratches = settings?.maxFreeScratchesPerDay || 1;
        
        const user = new User({
            name,
            email: userEmail.toLowerCase(),
            password: hashedPassword,
            phoneNumber: userPhone,
            freeScratchesRemaining: defaultFreeScratches,
            lastLoginIP: req.clientInfo.ip,
            lastLoginDate: new Date()
        });
        
        await user.save();
        
        // Log successful registration
        securityLogger.logAction(user._id, 'user', 'USER_REGISTERED', {
            ip: req.clientInfo.ip,
            userAgent: req.clientInfo.userAgent,
            email: userEmail,
            phoneNumber: userPhone
        });
        
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
        securityLogger.logAction('unknown', 'user', 'REGISTRATION_FAILED', {
            ip: req.clientInfo.ip,
            error: error.message
        });
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
        
        // Log failed login attempt
        const logFailedAttempt = () => {
            securityLogger.logAuthAttempt(loginIdentifier, false, req.clientInfo.ip, req.clientInfo.userAgent);
        };
        
        if (!user) {
            logFailedAttempt();
            return res.status(400).json({ error: 'Email/No HP atau password salah' });
        }
        
        // Check if account is locked
        if (user.accountLockedUntil && user.accountLockedUntil > new Date()) {
            logFailedAttempt();
            const lockTimeRemaining = Math.ceil((user.accountLockedUntil - new Date()) / (1000 * 60));
            return res.status(423).json({ 
                error: `Akun terkunci. Coba lagi dalam ${lockTimeRemaining} menit.`,
                lockedUntil: user.accountLockedUntil
            });
        }
        
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            // Increment failed attempts
            user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;
            
            // Lock account after 5 failed attempts for 30 minutes
            if (user.failedLoginAttempts >= 5) {
                user.accountLockedUntil = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
                securityLogger.logAction(user._id, 'user', 'ACCOUNT_LOCKED', {
                    ip: req.clientInfo.ip,
                    failedAttempts: user.failedLoginAttempts
                });
            }
            
            await user.save();
            logFailedAttempt();
            return res.status(400).json({ error: 'Email/No HP atau password salah' });
        }
        
        // Successful login - reset failed attempts
        user.failedLoginAttempts = 0;
        user.accountLockedUntil = undefined;
        user.lastLoginIP = req.clientInfo.ip;
        user.lastLoginDate = new Date();
        await user.save();
        
        // Log successful login
        securityLogger.logAuthAttempt(loginIdentifier, true, req.clientInfo.ip, req.clientInfo.userAgent);
        securityLogger.logAction(user._id, 'user', 'USER_LOGIN', {
            ip: req.clientInfo.ip,
            userAgent: req.clientInfo.userAgent
        });
        
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
        securityLogger.logAction('unknown', 'user', 'LOGIN_ERROR', {
            ip: req.clientInfo.ip,
            error: error.message
        });
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// USER ROUTES - ENHANCED SECURITY
// ========================================

app.get('/api/user/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        console.log(`📊 Profile request for user ${user.name}: Free=${user.freeScratchesRemaining}, Paid=${user.paidScratchesRemaining}`);
        
        securityLogger.logAction(req.userId, 'user', 'PROFILE_ACCESS', {
            ip: req.clientInfo.ip
        });
        
        res.json(user);
    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// GAME ROUTES - ENHANCED SECURITY WITH NO NOTIFICATION & PERFECT SYNC
// ========================================

// Prepare scratch endpoint - Enhanced security
app.post('/api/game/prepare-scratch', verifyToken, async (req, res) => {
    try {
        const settings = await GameSettings.findOne();
        if (!settings || !settings.isGameActive) {
            return res.status(400).json({ error: 'Game sedang tidak aktif' });
        }
        
        if (settings.maintenanceMode) {
            return res.status(503).json({ error: 'Game sedang dalam maintenance' });
        }
        
        const user = await User.findById(req.userId);
        
        // Check daily scratch limit
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        const todayScratches = await Scratch.countDocuments({
            userId: req.userId,
            scratchDate: { $gte: today }
        });
        
        if (todayScratches >= (settings.maxDailyScratches || 100)) {
            securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'DAILY_SCRATCH_LIMIT_EXCEEDED', {
                userId: req.userId,
                todayScratches
            });
            return res.status(429).json({ error: 'Batas scratch harian tercapai' });
        }
        
        // Check if user has any scratches remaining
        const totalScratches = (user.freeScratchesRemaining || 0) + (user.paidScratchesRemaining || 0);
        console.log(`🎮 Prepare scratch for ${user.name}: Free=${user.freeScratchesRemaining}, Paid=${user.paidScratchesRemaining}, Total=${totalScratches}`);
        
        if (totalScratches <= 0) {
            // Check if it's a new day
            const today = new Date();
            today.setHours(0, 0, 0, 0);
            
            if (!user.lastScratchDate || user.lastScratchDate < today) {
                // Reset free scratches for new day
                user.freeScratchesRemaining = settings.maxFreeScratchesPerDay || 1;
                await user.save();
                console.log(`🌅 New day! Reset free scratches for ${user.name} to ${user.freeScratchesRemaining}`);
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
            console.log(`🎯 Using forced winning number for ${user.name}: ${scratchNumber}`);
            
            // Clear forced winning number after use
            user.forcedWinningNumber = null;
        } else {
            scratchNumber = Math.floor(1000 + Math.random() * 9000).toString();
            console.log(`🎲 Generated random number for ${user.name}: ${scratchNumber}`);
        }
        
        // Store prepared scratch number for perfect sync
        user.preparedScratchNumber = scratchNumber;
        user.preparedScratchDate = new Date();
        await user.save();
        
        // Log prepare action
        securityLogger.logAction(req.userId, 'user', 'SCRATCH_PREPARED', {
            scratchNumber,
            ip: req.clientInfo.ip,
            totalScratches
        });
        
        console.log(`✅ Prepared scratch number ${scratchNumber} for user ${user.name} - READY FOR PERFECT SYNC`);
        
        res.json({
            message: 'Scratch prepared successfully',
            scratchNumber: scratchNumber,
            preparedAt: user.preparedScratchDate
        });
    } catch (error) {
        console.error('❌ Prepare scratch error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Enhanced scratch endpoint - PERFECT SYNC & NO NOTIFICATION with security
app.post('/api/game/scratch', verifyToken, async (req, res) => {
    try {
        const { scratchNumber } = req.body;
        
        if (!scratchNumber) {
            return res.status(400).json({ error: 'Scratch number is required' });
        }
        
        if (!/^\d{4}$/.test(scratchNumber)) {
            securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'INVALID_SCRATCH_NUMBER_FORMAT', {
                userId: req.userId,
                scratchNumber
            });
            return res.status(400).json({ error: 'Invalid scratch number format' });
        }
        
        const settings = await GameSettings.findOne();
        if (!settings || !settings.isGameActive) {
            return res.status(400).json({ error: 'Game sedang tidak aktif' });
        }
        
        if (settings.maintenanceMode) {
            return res.status(503).json({ error: 'Game sedang dalam maintenance' });
        }
        
        const user = await User.findById(req.userId);
        
        // PERFECT SYNC - Validate scratch number matches prepared number
        if (!user.preparedScratchNumber || user.preparedScratchNumber !== scratchNumber) {
            console.error(`❌ SYNC ERROR for ${user.name}. Expected: ${user.preparedScratchNumber}, Got: ${scratchNumber}`);
            securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'SCRATCH_SYNC_ERROR', {
                userId: req.userId,
                expected: user.preparedScratchNumber,
                received: scratchNumber
            });
            return res.status(400).json({ 
                error: 'Invalid scratch number. Please prepare a new scratch.',
                requireNewPreparation: true
            });
        }
        
        // Check if prepared scratch is not too old (max 5 minutes)
        const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
        if (user.preparedScratchDate < fiveMinutesAgo) {
            console.error(`❌ Prepared scratch number expired for ${user.name}`);
            // Clear expired prepared scratch
            user.preparedScratchNumber = null;
            user.preparedScratchDate = null;
            await user.save();
            
            return res.status(400).json({ 
                error: 'Prepared scratch number expired. Please prepare a new scratch.',
                requireNewPreparation: true
            });
        }
        
        // Check if user has any scratches remaining
        const totalScratches = (user.freeScratchesRemaining || 0) + (user.paidScratchesRemaining || 0);
        console.log(`🎮 Execute scratch for ${user.name} with number ${scratchNumber}: Free=${user.freeScratchesRemaining}, Paid=${user.paidScratchesRemaining}, Total=${totalScratches}`);
        
        if (totalScratches <= 0) {
            return res.status(400).json({ 
                error: 'Tidak ada kesempatan tersisa! Beli token scratch atau tunggu besok.',
                needTokens: true 
            });
        }
        
        let isWin = false;
        let prize = null;
        let winner = null;
        let isPaidScratch = false;
        
        // Use paid scratch first if available
        if (user.paidScratchesRemaining > 0) {
            isPaidScratch = true;
        }
        
        // PERFECT PRIZE SYNC - Check for exact match first (guaranteed win)
        const activePrize = await Prize.findOne({ 
            winningNumber: scratchNumber,
            stock: { $gt: 0 },
            isActive: true
        });
        
        if (activePrize) {
            isWin = true;
            prize = activePrize;
            
            console.log(`🎉 EXACT MATCH WIN! ${user.name} won ${prize.name} with number ${scratchNumber}`);
            
            // Reduce prize stock
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
            console.log(`🎲 No exact match. Checking win probability for ${user.name}: ${winRate}% (${user.customWinRate !== null ? 'custom' : 'global'})`);
            
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
                    
                    console.log(`🎊 PROBABILITY WIN! ${user.name} won ${prize.name} via probability (${winRate}%)`);
                    
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
                    console.log(`😔 ${user.name} would have won via probability but no prizes available`);
                }
            } else {
                console.log(`😔 ${user.name} didn't win. Random: ${randomChance.toFixed(2)}%, WinRate: ${winRate}%`);
            }
        }
        
        // Create scratch record with security info
        const scratch = new Scratch({
            userId: req.userId,
            scratchNumber,
            isWin,
            prizeId: prize?._id,
            isPaid: isPaidScratch,
            ipAddress: req.clientInfo.ip,
            userAgent: req.clientInfo.userAgent
        });
        
        await scratch.save();
        
        // Log scratch action
        securityLogger.logAction(req.userId, 'user', 'SCRATCH_EXECUTED', {
            scratchNumber,
            isWin,
            isPaid: isPaidScratch,
            prizeId: prize?._id,
            ip: req.clientInfo.ip
        });
        
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
        
        // Create winner record if user won
        if (isWin && prize) {
            const claimCode = Math.random().toString(36).substring(2, 10).toUpperCase();
            
            winner = new Winner({
                userId: req.userId,
                prizeId: prize._id,
                scratchId: scratch._id,
                claimCode,
                ipAddress: req.clientInfo.ip
            });
            
            await winner.save();
            
            // Log winning
            securityLogger.logAction(req.userId, 'user', 'PRIZE_WON', {
                prizeId: prize._id,
                claimCode,
                ip: req.clientInfo.ip
            });
            
            // Broadcast new winner with populated data
            const winnerData = await Winner.findById(winner._id)
                .populate('userId', 'name email phoneNumber')
                .populate('prizeId', 'name value type');
                
            socketManager.broadcastNewWinner(winnerData);
        }
        
        // Update user scratch counts and clear prepared scratch
        if (isPaidScratch) {
            user.paidScratchesRemaining -= 1;
        } else {
            user.freeScratchesRemaining -= 1;
        }
        
        user.scratchCount += 1;
        if (isWin) user.winCount += 1;
        user.lastScratchDate = new Date();
        
        // Clear prepared scratch after use for perfect sync
        user.preparedScratchNumber = null;
        user.preparedScratchDate = null;
        
        await user.save();
        
        console.log(`✅ Scratch completed for ${user.name}: Win=${isWin}, NewBalance=Free:${user.freeScratchesRemaining}/Paid:${user.paidScratchesRemaining}`);
        
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
        console.error('❌ Scratch error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/user/history', verifyToken, async (req, res) => {
    try {
        const scratches = await Scratch.find({ userId: req.userId })
            .populate('prizeId')
            .sort({ scratchDate: -1 })
            .limit(50);
            
        securityLogger.logAction(req.userId, 'user', 'HISTORY_ACCESS', {
            ip: req.clientInfo.ip
        });
            
        res.json({ scratches });
    } catch (error) {
        console.error('History error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// PUBLIC ROUTES (NO AUTH REQUIRED) - ENHANCED SECURITY
// ========================================

// Get active prizes (for game app) with rate limiting
app.get('/api/public/prizes', async (req, res) => {
    try {
        const prizes = await Prize.find({ isActive: true }).sort({ createdAt: -1 });
        console.log(`📊 Public prizes request: ${prizes.length} active prizes found`);
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
            isGameActive: settings.isGameActive && !settings.maintenanceMode,
            maxFreeScratchesPerDay: settings.maxFreeScratchesPerDay,
            minFreeScratchesPerDay: settings.minFreeScratchesPerDay,
            scratchTokenPrice: settings.scratchTokenPrice,
            resetTime: settings.resetTime,
            maintenanceMode: settings.maintenanceMode || false
        });
    } catch (error) {
        console.error('Get public settings error:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ========================================
// ADMIN ROUTES - ENHANCED SECURITY & COMPLETE IMPLEMENTATION
// ========================================

app.post('/api/admin/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'Username dan password harus diisi' });
        }
        
        // Enhanced validation
        if (username.length > 50 || password.length > 100) {
            securityLogger.logSuspiciousActivity(req.clientInfo.ip, 'SUSPICIOUS_ADMIN_LOGIN_DATA', {
                username: username.substring(0, 20),
                userAgent: req.clientInfo.userAgent
            });
            return res.status(400).json({ error: 'Data tidak valid' });
        }
        
        const admin = await Admin.findOne({ username });
        
        // Log failed login attempt
        const logFailedAttempt = () => {
            securityLogger.logAuthAttempt(username, false, req.clientInfo.ip, req.clientInfo.userAgent);
        };
        
        if (!admin) {
            logFailedAttempt();
            return res.status(400).json({ error: 'Username atau password salah' });
        }
        
        // Check if account is locked
        if (admin.accountLockedUntil && admin.accountLockedUntil > new Date()) {
            logFailedAttempt();
            const lockTimeRemaining = Math.ceil((admin.accountLockedUntil - new Date()) / (1000 * 60));
            return res.status(423).json({ 
                error: `Akun admin terkunci. Coba lagi dalam ${lockTimeRemaining} menit.`,
                lockedUntil: admin.accountLockedUntil
            });
        }
        
        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            // Increment failed attempts
            admin.failedLoginAttempts = (admin.failedLoginAttempts || 0) + 1;
            
            // Lock account after 3 failed attempts for 60 minutes (stricter for admin)
            if (admin.failedLoginAttempts >= 3) {
                admin.accountLockedUntil = new Date(Date.now() + 60 * 60 * 1000); // 60 minutes
                securityLogger.logAction(admin._id, 'admin', 'ADMIN_ACCOUNT_LOCKED', {
                    ip: req.clientInfo.ip,
                    failedAttempts: admin.failedLoginAttempts
                });
            }
            
            await admin.save();
            logFailedAttempt();
            return res.status(400).json({ error: 'Username atau password salah' });
        }
        
        // Successful login - reset failed attempts
        admin.failedLoginAttempts = 0;
        admin.accountLockedUntil = undefined;
        admin.lastLoginIP = req.clientInfo.ip;
        admin.lastLoginDate = new Date();
        admin.sessionCount = (admin.sessionCount || 0) + 1;
        await admin.save();
        
        // Log successful admin login
        securityLogger.logAuthAttempt(username, true, req.clientInfo.ip, req.clientInfo.userAgent);
        securityLogger.logAction(admin._id, 'admin', 'ADMIN_LOGIN', {
            ip: req.clientInfo.ip,
            userAgent: req.clientInfo.userAgent,
            sessionCount: admin.sessionCount
        });
        
        // Shorter token expiry for admin (2 hours)
        const token = jwt.sign(
            { userId: admin._id, userType: 'admin' },
            process.env.JWT_SECRET,
            { expiresIn: '2h' }
        );
        
        res.json({
            message: 'Login berhasil',
            token,
            admin: {
                _id: admin._id,
                id: admin._id,
                name: admin.name,
                username: admin.username,
                role: admin.role,
                lastLoginDate: admin.lastLoginDate,
                sessionCount: admin.sessionCount
            }
        });
    } catch (error) {
        console.error('Admin login error:', error);
        securityLogger.logAction('unknown', 'admin', 'ADMIN_LOGIN_ERROR', {
            ip: req.clientInfo.ip,
            error: error.message
        });
        res.status(500).json({ error: 'Server error' });
    }
});

// Change admin password - Enhanced security
app.post('/api/admin/change-password', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        
        console.log('📝 Change password request for admin:', req.userId);
        
        if (!oldPassword || !newPassword) {
            return res.status(400).json({ error: 'Password lama dan baru harus diisi' });
        }
        
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'Password baru minimal 8 karakter' });
        }
        
        // Enhanced password strength validation
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/;
        if (!passwordRegex.test(newPassword)) {
            return res.status(400).json({ 
                error: 'Password harus mengandung minimal: 1 huruf kecil, 1 huruf besar, 1 angka, dan 1 karakter khusus' 
            });
        }
        
        const admin = await Admin.findById(req.userId);
        if (!admin) {
            console.error('❌ Admin not found:', req.userId);
            return res.status(404).json({ error: 'Admin tidak ditemukan' });
        }
        
        const isValidPassword = await bcrypt.compare(oldPassword, admin.password);
        if (!isValidPassword) {
            console.error('❌ Invalid old password for admin:', req.userId);
            securityLogger.logAction(req.userId, 'admin', 'INVALID_PASSWORD_CHANGE_ATTEMPT', {
                ip: req.clientInfo.ip
            });
            return res.status(400).json({ error: 'Password lama salah' });
        }
        
        // Enhanced password hashing
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        admin.password = hashedPassword;
        admin.passwordChangedAt = new Date();
        await admin.save();
        
        console.log('✅ Password changed successfully for admin:', req.userId);
        securityLogger.logAction(req.userId, 'admin', 'PASSWORD_CHANGED', {
            ip: req.clientInfo.ip
        });
        
        res.json({ message: 'Password berhasil diubah' });
    } catch (error) {
        console.error('❌ Change admin password error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Dashboard endpoint - Enhanced with security metrics
app.get('/api/admin/dashboard', verifyToken, verifyAdmin, async (req, res) => {
    try {
        console.log('📊 Dashboard request from admin:', req.userId);
        
        const today = new Date();
        today.setHours(0, 0, 0, 0);
        
        const [totalUsers, todayScratches, todayWinners, totalPrizesResult, pendingPurchases, suspiciousActivities] = await Promise.all([
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
            AuditLog.countDocuments({ 
                timestamp: { $gte: today }, 
                severity: { $in: ['HIGH', 'CRITICAL'] } 
            })
        ]);
        
        const dashboardData = {
            totalUsers,
            todayScratches,
            todayWinners,
            totalPrizes: totalPrizesResult[0]?.total || 0,
            pendingPurchases,
            suspiciousActivities
        };
        
        console.log('✅ Dashboard data:', dashboardData);
        securityLogger.logAction(req.userId, 'admin', 'DASHBOARD_ACCESS', {
            ip: req.clientInfo.ip
        });
        
        res.json(dashboardData);
    } catch (error) {
        console.error('❌ Dashboard error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Users endpoint - Enhanced security
app.get('/api/admin/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 10, search = '' } = req.query;
        
        console.log('👥 Users request:', { page, limit, search });
        
        // Validate pagination inputs
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(50, Math.max(1, parseInt(limit))); // Max 50 per page
        
        // Build search query with security considerations
        let query = {};
        if (search) {
            const sanitizedSearch = search.trim().substring(0, 100); // Limit search length
            query = {
                $or: [
                    { name: { $regex: sanitizedSearch, $options: 'i' } },
                    { email: { $regex: sanitizedSearch, $options: 'i' } },
                    { phoneNumber: { $regex: sanitizedSearch, $options: 'i' } }
                ]
            };
        }
        
        const users = await User.find(query)
            .select('-password -preparedScratchNumber -preparedScratchDate') // Hide sensitive fields
            .limit(limitNum)
            .skip((pageNum - 1) * limitNum)
            .sort({ createdAt: -1 });
            
        const total = await User.countDocuments(query);
        
        console.log(`✅ Found ${users.length} users out of ${total} total`);
        
        securityLogger.logAction(req.userId, 'admin', 'USERS_LIST_ACCESS', {
            ip: req.clientInfo.ip,
            search: search.substring(0, 50),
            page: pageNum,
            limit: limitNum
        });
        
        res.json({
            users,
            total,
            totalPages: Math.ceil(total / limitNum),
            currentPage: pageNum,
            page: pageNum,
            limit: limitNum
        });
    } catch (error) {
        console.error('❌ Get users error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Get user detail - Enhanced security
app.get('/api/admin/users/:userId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        
        console.log('👤 User detail request for:', userId);
        
        // Validate ObjectId format
        if (!mongoose.Types.ObjectId.isValid(userId)) {
            console.error('❌ Invalid userId format:', userId);
            return res.status(400).json({ error: 'Invalid user ID format' });
        }
        
        const user = await User.findById(userId).select('-password -preparedScratchNumber -preparedScratchDate');
        if (!user) {
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        // Get user's scratch history (limited)
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
        
        console.log(`✅ User detail loaded for ${user.name}`);
        
        securityLogger.logAction(req.userId, 'admin', 'USER_DETAIL_ACCESS', {
            ip: req.clientInfo.ip,
            targetUserId: userId
        });
        
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
        console.error('❌ Get user detail error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Reset user password by admin - Enhanced security
app.post('/api/admin/users/:userId/reset-password', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { newPassword } = req.body;
        
        console.log('🔐 Reset password request for user:', userId);
        
        if (!newPassword || newPassword.length < 6) {
            return res.status(400).json({ error: 'Password baru harus minimal 6 karakter' });
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
        
        // Enhanced password hashing
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);
        user.password = hashedPassword;
        user.passwordChangedAt = new Date();
        // Reset failed login attempts
        user.failedLoginAttempts = 0;
        user.accountLockedUntil = undefined;
        await user.save();
        
        console.log('✅ Password reset successfully for user:', userId);
        
        securityLogger.logAction(req.userId, 'admin', 'USER_PASSWORD_RESET', {
            ip: req.clientInfo.ip,
            targetUserId: userId,
            targetUserName: user.name
        });
        
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

// Update user win rate - Enhanced security
app.put('/api/admin/users/:userId/win-rate', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { winRate } = req.body;
        
        console.log('🎯 Update win rate request for user:', userId, 'to', winRate);
        
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
        
        const oldWinRate = user.customWinRate;
        user.customWinRate = winRate;
        await user.save();
        
        console.log('✅ Win rate updated successfully for user:', userId);
        
        securityLogger.logAction(req.userId, 'admin', 'USER_WIN_RATE_UPDATED', {
            ip: req.clientInfo.ip,
            targetUserId: userId,
            targetUserName: user.name,
            oldWinRate,
            newWinRate: winRate
        });
        
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

// Set forced winning number for user - Enhanced security
app.put('/api/admin/users/:userId/forced-winning', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId } = req.params;
        const { winningNumber } = req.body;
        
        console.log('🎯 Set forced winning number for user:', userId, 'to', winningNumber);
        
        // Validate winning number
        if (winningNumber !== null && (!/^\d{4}$/.test(winningNumber))) {
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
        
        // Clear any existing prepared scratch when setting forced number for perfect sync
        if (winningNumber !== null) {
            user.preparedScratchNumber = null;
            user.preparedScratchDate = null;
            console.log('🧹 Cleared existing prepared scratch for forced number - PERFECT SYNC');
        }
        
        const oldWinningNumber = user.forcedWinningNumber;
        user.forcedWinningNumber = winningNumber;
        await user.save();
        
        console.log('✅ Forced winning number set successfully for user:', userId);
        
        securityLogger.logAction(req.userId, 'admin', 'USER_FORCED_WINNING_SET', {
            ip: req.clientInfo.ip,
            targetUserId: userId,
            targetUserName: user.name,
            oldWinningNumber,
            newWinningNumber: winningNumber
        });
        
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

// Game settings routes - Enhanced security
app.get('/api/admin/game-settings', verifyToken, verifyAdmin, async (req, res) => {
    try {
        console.log('⚙️ Game settings request from admin:', req.userId);
        
        let settings = await GameSettings.findOne();
        
        if (!settings) {
            settings = new GameSettings({
                winningNumber: '1234',
                winProbability: 5,
                maxFreeScratchesPerDay: 1,
                minFreeScratchesPerDay: 1,
                scratchTokenPrice: 10000,
                isGameActive: true,
                resetTime: '00:00',
                lastModifiedBy: req.userId
            });
            await settings.save();
            console.log('✅ Default game settings created');
        }
        
        console.log('✅ Game settings loaded');
        securityLogger.logAction(req.userId, 'admin', 'GAME_SETTINGS_ACCESS', {
            ip: req.clientInfo.ip
        });
        
        res.json(settings);
    } catch (error) {
        console.error('❌ Get settings error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
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
            resetTime,
            maintenanceMode,
            maxDailyScratches
        } = req.body;
        
        console.log('⚙️ Update game settings request:', req.body);
        
        // Enhanced validation
        if (winningNumber && !/^\d{4}$/.test(winningNumber)) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        if (winProbability !== undefined && (winProbability < 0 || winProbability > 100)) {
            return res.status(400).json({ error: 'Win probability harus antara 0-100' });
        }
        
        if (maxFreeScratchesPerDay !== undefined && (maxFreeScratchesPerDay < 0 || maxFreeScratchesPerDay > 10)) {
            return res.status(400).json({ error: 'Max free scratches harus antara 0-10' });
        }
        
        if (minFreeScratchesPerDay !== undefined && maxFreeScratchesPerDay !== undefined && 
            minFreeScratchesPerDay > maxFreeScratchesPerDay) {
            return res.status(400).json({ error: 'Minimum tidak boleh lebih besar dari maksimum' });
        }
        
        if (scratchTokenPrice !== undefined && scratchTokenPrice < 1000) {
            return res.status(400).json({ error: 'Harga token minimal Rp 1.000' });
        }
        
        if (maxDailyScratches !== undefined && (maxDailyScratches < 1 || maxDailyScratches > 1000)) {
            return res.status(400).json({ error: 'Max daily scratches harus antara 1-1000' });
        }
        
        const oldSettings = await GameSettings.findOne();
        
        const settings = await GameSettings.findOneAndUpdate(
            {},
            { 
                winningNumber, 
                winProbability, 
                maxFreeScratchesPerDay,
                minFreeScratchesPerDay,
                scratchTokenPrice,
                isGameActive,
                resetTime: resetTime || '00:00',
                maintenanceMode: maintenanceMode || false,
                maxDailyScratches: maxDailyScratches || 100,
                lastModifiedBy: req.userId,
                lastModifiedAt: new Date()
            },
            { new: true, upsert: true }
        );
        
        console.log('✅ Game settings updated');
        
        // Log significant changes
        securityLogger.logAction(req.userId, 'admin', 'GAME_SETTINGS_UPDATED', {
            ip: req.clientInfo.ip,
            oldSettings: {
                isGameActive: oldSettings?.isGameActive,
                winProbability: oldSettings?.winProbability,
                maintenanceMode: oldSettings?.maintenanceMode
            },
            newSettings: {
                isGameActive: settings.isGameActive,
                winProbability: settings.winProbability,
                maintenanceMode: settings.maintenanceMode
            }
        });
        
        // Broadcast settings update
        socketManager.broadcastSettingsUpdate({
            settings: {
                isGameActive: settings.isGameActive,
                maxFreeScratchesPerDay: settings.maxFreeScratchesPerDay,
                minFreeScratchesPerDay: settings.minFreeScratchesPerDay,
                scratchTokenPrice: settings.scratchTokenPrice,
                resetTime: settings.resetTime,
                winProbability: settings.winProbability,
                maintenanceMode: settings.maintenanceMode
            }
        });
        
        res.json(settings);
    } catch (error) {
        console.error('❌ Update settings error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Prize management routes - Enhanced security
app.get('/api/admin/prizes', verifyToken, verifyAdmin, async (req, res) => {
    try {
        console.log('🎁 Prizes request from admin:', req.userId);
        
        const prizes = await Prize.find()
            .populate('createdBy', 'name username')
            .sort({ createdAt: -1 });
        
        console.log(`✅ Found ${prizes.length} prizes`);
        
        securityLogger.logAction(req.userId, 'admin', 'PRIZES_LIST_ACCESS', {
            ip: req.clientInfo.ip
        });
        
        res.json(prizes);
    } catch (error) {
        console.error('❌ Get prizes error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.post('/api/admin/prizes', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { winningNumber, name, type, value, stock } = req.body;
        
        console.log('🎁 Add prize request:', req.body);
        
        // Enhanced validation
        if (!winningNumber || !/^\d{4}$/.test(winningNumber)) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        if (!name || name.length > 200) {
            return res.status(400).json({ error: 'Nama prize harus diisi dan maksimal 200 karakter' });
        }
        
        if (!['voucher', 'cash', 'physical'].includes(type)) {
            return res.status(400).json({ error: 'Tipe prize tidak valid' });
        }
        
        if (!value || value < 0) {
            return res.status(400).json({ error: 'Nilai prize harus lebih dari 0' });
        }
        
        if (!stock || stock < 0) {
            return res.status(400).json({ error: 'Stok harus lebih dari 0' });
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
            isActive: true,
            createdBy: req.userId
        });
        
        await prize.save();
        
        console.log('✅ Prize added:', prize.name);
        
        securityLogger.logAction(req.userId, 'admin', 'PRIZE_ADDED', {
            ip: req.clientInfo.ip,
            prizeId: prize._id,
            prizeName: prize.name,
            winningNumber: prize.winningNumber,
            value: prize.value
        });
        
        // Broadcast new prize
        socketManager.broadcastPrizeUpdate({
            type: 'prize_added',
            prizeData: prize,
            message: 'New prize added'
        });
        
        res.status(201).json(prize);
    } catch (error) {
        console.error('❌ Add prize error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.put('/api/admin/prizes/:prizeId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { prizeId } = req.params;
        const { winningNumber, name, type, value, stock, isActive } = req.body;
        
        console.log('🎁 Update prize request:', prizeId, req.body);
        
        // Validate prizeId format
        if (!mongoose.Types.ObjectId.isValid(prizeId)) {
            return res.status(400).json({ error: 'Invalid prize ID format' });
        }
        
        // Enhanced validation
        if (winningNumber && !/^\d{4}$/.test(winningNumber)) {
            return res.status(400).json({ error: 'Winning number harus 4 digit angka' });
        }
        
        if (name && name.length > 200) {
            return res.status(400).json({ error: 'Nama prize maksimal 200 karakter' });
        }
        
        if (type && !['voucher', 'cash', 'physical'].includes(type)) {
            return res.status(400).json({ error: 'Tipe prize tidak valid' });
        }
        
        if (value !== undefined && value < 0) {
            return res.status(400).json({ error: 'Nilai prize harus lebih dari atau sama dengan 0' });
        }
        
        if (stock !== undefined && stock < 0) {
            return res.status(400).json({ error: 'Stok harus lebih dari atau sama dengan 0' });
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
        
        const oldPrize = await Prize.findById(prizeId);
        if (!oldPrize) {
            return res.status(404).json({ error: 'Prize tidak ditemukan' });
        }
        
        const prize = await Prize.findByIdAndUpdate(
            prizeId,
            { winningNumber, name, type, value, stock, isActive },
            { new: true }
        );
        
        console.log('✅ Prize updated:', prize.name);
        
        securityLogger.logAction(req.userId, 'admin', 'PRIZE_UPDATED', {
            ip: req.clientInfo.ip,
            prizeId: prize._id,
            prizeName: prize.name,
            changes: {
                winningNumber: { old: oldPrize.winningNumber, new: prize.winningNumber },
                value: { old: oldPrize.value, new: prize.value },
                stock: { old: oldPrize.stock, new: prize.stock },
                isActive: { old: oldPrize.isActive, new: prize.isActive }
            }
        });
        
        // Broadcast prize update
        socketManager.broadcastPrizeUpdate({
            type: 'prize_updated',
            prizeId: prize._id,
            prizeData: prize,
            message: 'Prize updated'
        });
        
        res.json(prize);
    } catch (error) {
        console.error('❌ Update prize error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

app.delete('/api/admin/prizes/:prizeId', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { prizeId } = req.params;
        
        console.log('🎁 Delete prize request:', prizeId);
        
        // Validate prizeId format
        if (!mongoose.Types.ObjectId.isValid(prizeId)) {
            return res.status(400).json({ error: 'Invalid prize ID format' });
        }
        
        const prize = await Prize.findById(prizeId);
        if (!prize) {
            return res.status(404).json({ error: 'Prize tidak ditemukan' });
        }
        
        // Check if prize is being used in active scratches/winners
        const activeWinners = await Winner.countDocuments({ 
            prizeId: prizeId, 
            claimStatus: 'pending' 
        });
        
        if (activeWinners > 0) {
            return res.status(400).json({ 
                error: `Cannot delete prize. ${activeWinners} pending claims exist.` 
            });
        }
        
        await Prize.findByIdAndDelete(prizeId);
        
        console.log('✅ Prize deleted:', prize.name);
        
        securityLogger.logAction(req.userId, 'admin', 'PRIZE_DELETED', {
            ip: req.clientInfo.ip,
            prizeId: prizeId,
            prizeName: prize.name,
            winningNumber: prize.winningNumber,
            value: prize.value
        });
        
        // Broadcast prize deletion
        socketManager.broadcastPrizeUpdate({
            type: 'prize_deleted',
            prizeId: prizeId,
            message: 'Prize deleted'
        });
        
        res.json({ message: 'Prize berhasil dihapus' });
    } catch (error) {
        console.error('❌ Delete prize error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Winners routes - Enhanced security
app.get('/api/admin/recent-winners', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { limit = 50 } = req.query;
        
        // Validate limit
        const limitNum = Math.min(100, Math.max(1, parseInt(limit))); // Max 100
        
        console.log('🏆 Recent winners request, limit:', limitNum);
        
        const winners = await Winner.find()
            .populate('userId', 'name email phoneNumber')
            .populate('prizeId', 'name value type')
            .populate('claimedBy', 'name username')
            .sort({ scratchDate: -1 })
            .limit(limitNum);
            
        console.log(`✅ Found ${winners.length} winners`);
        
        securityLogger.logAction(req.userId, 'admin', 'WINNERS_LIST_ACCESS', {
            ip: req.clientInfo.ip,
            limit: limitNum
        });
        
        res.json(winners);
    } catch (error) {
        console.error('❌ Get winners error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Update winner claim status - Enhanced security
app.put('/api/admin/winners/:winnerId/claim-status', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { winnerId } = req.params;
        const { claimStatus } = req.body;
        
        console.log('🏆 Update winner claim status:', winnerId, 'to', claimStatus);
        
        // Validate winnerId format
        if (!mongoose.Types.ObjectId.isValid(winnerId)) {
            return res.status(400).json({ error: 'Invalid winner ID format' });
        }
        
        if (!['pending', 'completed', 'expired'].includes(claimStatus)) {
            return res.status(400).json({ error: 'Invalid claim status' });
        }
        
        const oldWinner = await Winner.findById(winnerId);
        if (!oldWinner) {
            return res.status(404).json({ error: 'Winner tidak ditemukan' });
        }
        
        const winner = await Winner.findByIdAndUpdate(
            winnerId,
            { 
                claimStatus,
                claimedBy: claimStatus === 'completed' ? req.userId : undefined,
                ...(claimStatus === 'completed' && { claimDate: new Date() })
            },
            { new: true }
        )
        .populate('userId', 'name email phoneNumber')
        .populate('prizeId', 'name value type')
        .populate('claimedBy', 'name username');
        
        console.log('✅ Winner claim status updated');
        
        securityLogger.logAction(req.userId, 'admin', 'WINNER_CLAIM_STATUS_UPDATED', {
            ip: req.clientInfo.ip,
            winnerId: winnerId,
            oldStatus: oldWinner.claimStatus,
            newStatus: claimStatus,
            prizeValue: winner.prizeId?.value
        });
        
        res.json({
            message: 'Status berhasil diupdate',
            winner
        });
    } catch (error) {
        console.error('❌ Update claim status error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Get all scratch history - Enhanced security
app.get('/api/admin/scratch-history', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50 } = req.query;
        
        // Validate pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit))); // Max 100
        
        console.log('📜 Scratch history request:', { page: pageNum, limit: limitNum });
        
        const scratches = await Scratch.find()
            .populate('userId', 'name email phoneNumber')
            .populate('prizeId', 'name value type')
            .sort({ scratchDate: -1 })
            .limit(limitNum)
            .skip((pageNum - 1) * limitNum);
            
        const total = await Scratch.countDocuments();
        
        console.log(`✅ Found ${scratches.length} scratches out of ${total} total`);
        
        securityLogger.logAction(req.userId, 'admin', 'SCRATCH_HISTORY_ACCESS', {
            ip: req.clientInfo.ip,
            page: pageNum,
            limit: limitNum
        });
        
        res.json({
            scratches: scratches,
            total: total,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil(total / limitNum)
        });
    } catch (error) {
        console.error('❌ Get scratch history error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ========================================
// TOKEN PURCHASE ROUTES - ENHANCED SECURITY & COMPLETE IMPLEMENTATION
// ========================================

// Get all token purchases (admin) - Enhanced security
app.get('/api/admin/token-purchases', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 20, status = 'all' } = req.query;
        
        // Validate pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(50, Math.max(1, parseInt(limit))); // Max 50
        
        console.log('💰 Token purchases request:', { page: pageNum, limit: limitNum, status });
        
        let query = {};
        if (status !== 'all' && ['pending', 'completed', 'cancelled'].includes(status)) {
            query.paymentStatus = status;
        }
        
        const purchases = await TokenPurchase.find(query)
            .populate('userId', 'name email phoneNumber')
            .populate('adminId', 'name username')
            .populate('completedBy', 'name username')
            .sort({ purchaseDate: -1 })
            .limit(limitNum)
            .skip((pageNum - 1) * limitNum);
            
        const total = await TokenPurchase.countDocuments(query);
        
        console.log(`✅ Found ${purchases.length} token purchases out of ${total} total`);
        
        securityLogger.logAction(req.userId, 'admin', 'TOKEN_PURCHASES_LIST_ACCESS', {
            ip: req.clientInfo.ip,
            page: pageNum,
            limit: limitNum,
            status
        });
        
        res.json({
            purchases,
            total,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil(total / limitNum)
        });
    } catch (error) {
        console.error('❌ Get token purchases error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Create token purchase for user (admin) - Enhanced security
app.post('/api/admin/token-purchase', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { userId, quantity, paymentMethod, notes } = req.body;
        
        console.log('💰 Create token purchase request:', req.body);
        
        // Enhanced validation
        if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ error: 'Valid User ID harus diisi' });
        }
        
        if (!quantity || quantity < 1 || quantity > 1000) {
            return res.status(400).json({ error: 'Quantity harus antara 1-1000' });
        }
        
        if (paymentMethod && paymentMethod.length > 50) {
            return res.status(400).json({ error: 'Payment method terlalu panjang' });
        }
        
        if (notes && notes.length > 500) {
            return res.status(400).json({ error: 'Notes terlalu panjang (max 500 karakter)' });
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
            notes: notes || '',
            ipAddress: req.clientInfo.ip
        });
        
        await purchase.save();
        
        console.log(`💰 Token purchase created: ${quantity} tokens for user ${user.name} by admin ${req.userId}`);
        
        securityLogger.logAction(req.userId, 'admin', 'TOKEN_PURCHASE_CREATED', {
            ip: req.clientInfo.ip,
            targetUserId: userId,
            targetUserName: user.name,
            quantity,
            totalAmount,
            paymentMethod
        });
        
        res.status(201).json({
            message: 'Token purchase created successfully',
            purchase: await purchase.populate(['userId', 'adminId'])
        });
    } catch (error) {
        console.error('❌ Create token purchase error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Complete token purchase (admin) - Enhanced security
app.put('/api/admin/token-purchase/:purchaseId/complete', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { purchaseId } = req.params;
        
        console.log(`💰 Completing token purchase: ${purchaseId}`);
        
        // Validate purchaseId format
        if (!mongoose.Types.ObjectId.isValid(purchaseId)) {
            return res.status(400).json({ error: 'Invalid purchase ID format' });
        }
        
        const purchase = await TokenPurchase.findById(purchaseId)
            .populate('userId', 'name email phoneNumber freeScratchesRemaining paidScratchesRemaining totalPurchasedScratches');
            
        if (!purchase) {
            console.error('❌ Purchase not found:', purchaseId);
            return res.status(404).json({ error: 'Purchase tidak ditemukan' });
        }
        
        if (purchase.paymentStatus === 'completed') {
            console.error('❌ Purchase already completed:', purchaseId);
            return res.status(400).json({ error: 'Purchase sudah completed' });
        }
        
        if (purchase.paymentStatus === 'cancelled') {
            console.error('❌ Purchase is cancelled:', purchaseId);
            return res.status(400).json({ error: 'Purchase sudah dibatalkan' });
        }
        
        if (!purchase.userId || !purchase.userId._id) {
            console.error('❌ Invalid userId in purchase:', purchase);
            return res.status(500).json({ error: 'Invalid purchase data' });
        }
        
        // Get userId dari populated object
        const userId = purchase.userId._id;
        
        // Update user's paid scratches dengan fetch user terbaru
        const user = await User.findById(userId);
        if (!user) {
            console.error('❌ User not found for purchase:', userId);
            return res.status(404).json({ error: 'User tidak ditemukan' });
        }
        
        const oldBalance = user.paidScratchesRemaining || 0;
        user.paidScratchesRemaining = (user.paidScratchesRemaining || 0) + purchase.quantity;
        user.totalPurchasedScratches = (user.totalPurchasedScratches || 0) + purchase.quantity;
        
        await user.save();
        
        console.log(`✅ User ${user.name} token balance updated: ${oldBalance} → ${user.paidScratchesRemaining} (+${purchase.quantity})`);
        
        // Update purchase status
        purchase.paymentStatus = 'completed';
        purchase.completedDate = new Date();
        purchase.completedBy = req.userId;
        await purchase.save();
        
        // Log completion
        securityLogger.logAction(req.userId, 'admin', 'TOKEN_PURCHASE_COMPLETED', {
            ip: req.clientInfo.ip,
            purchaseId,
            targetUserId: userId,
            targetUserName: user.name,
            quantity: purchase.quantity,
            totalAmount: purchase.totalAmount,
            oldBalance,
            newBalance: user.paidScratchesRemaining
        });
        
        // Broadcast token purchase dengan data yang benar
        socketManager.broadcastTokenPurchase({
            userId: user._id,
            quantity: purchase.quantity,
            totalAmount: purchase.totalAmount,
            newBalance: user.paidScratchesRemaining
        });
        
        console.log(`📡 Token purchase completed and broadcasted for user: ${user.name}`);
        
        res.json({
            message: 'Token purchase completed successfully',
            purchase: await purchase.populate(['userId', 'adminId', 'completedBy']),
            userScratches: {
                free: user.freeScratchesRemaining || 0,
                paid: user.paidScratchesRemaining,
                total: (user.freeScratchesRemaining || 0) + user.paidScratchesRemaining
            }
        });
    } catch (error) {
        console.error('❌ Complete token purchase error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Cancel token purchase (admin) - Enhanced security
app.put('/api/admin/token-purchase/:purchaseId/cancel', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { purchaseId } = req.params;
        
        console.log(`❌ Cancelling token purchase: ${purchaseId}`);
        
        // Validate purchaseId format
        if (!mongoose.Types.ObjectId.isValid(purchaseId)) {
            return res.status(400).json({ error: 'Invalid purchase ID format' });
        }
        
        const purchase = await TokenPurchase.findById(purchaseId);
        if (!purchase) {
            return res.status(404).json({ error: 'Purchase tidak ditemukan' });
        }
        
        if (purchase.paymentStatus === 'completed') {
            return res.status(400).json({ error: 'Cannot cancel completed purchase' });
        }
        
        if (purchase.paymentStatus === 'cancelled') {
            return res.status(400).json({ error: 'Purchase sudah dibatalkan' });
        }
        
        purchase.paymentStatus = 'cancelled';
        await purchase.save();
        
        console.log(`❌ Token purchase cancelled: ${purchaseId}`);
        
        securityLogger.logAction(req.userId, 'admin', 'TOKEN_PURCHASE_CANCELLED', {
            ip: req.clientInfo.ip,
            purchaseId,
            quantity: purchase.quantity,
            totalAmount: purchase.totalAmount
        });
        
        res.json({
            message: 'Token purchase cancelled successfully',
            purchase: await purchase.populate(['userId', 'adminId'])
        });
    } catch (error) {
        console.error('❌ Cancel token purchase error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Analytics endpoints - Enhanced security
app.get('/api/admin/analytics', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { period = '7days' } = req.query;
        
        console.log('📊 Analytics request for period:', period);
        
        if (!['today', '7days', '30days', 'all'].includes(period)) {
            return res.status(400).json({ error: 'Invalid period' });
        }
        
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
        
        const analyticsData = {
            period,
            totalScratches,
            totalWins,
            winRate: parseFloat(winRate),
            totalPrizeValue: totalPrizeValue[0]?.total || 0,
            totalTokensSold: totalTokenSales[0]?.totalQuantity || 0,
            totalTokenRevenue: totalTokenSales[0]?.totalRevenue || 0
        };
        
        console.log('✅ Analytics data:', analyticsData);
        
        securityLogger.logAction(req.userId, 'admin', 'ANALYTICS_ACCESS', {
            ip: req.clientInfo.ip,
            period
        });
        
        res.json(analyticsData);
    } catch (error) {
        console.error('❌ Get analytics error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// User analytics - Enhanced security
app.get('/api/admin/analytics/users', verifyToken, verifyAdmin, async (req, res) => {
    try {
        console.log('👥 User analytics request');
        
        const now = new Date();
        const thirtyDaysAgo = new Date(now.setDate(now.getDate() - 30));
        
        const [totalUsers, activeUsers, newUsers, paidUsers, suspendedUsers] = await Promise.all([
            User.countDocuments(),
            User.countDocuments({ lastScratchDate: { $gte: thirtyDaysAgo } }),
            User.countDocuments({ createdAt: { $gte: thirtyDaysAgo } }),
            User.countDocuments({ totalPurchasedScratches: { $gt: 0 } }),
            User.countDocuments({ status: { $in: ['inactive', 'suspended'] } })
        ]);
        
        const userAnalytics = {
            totalUsers,
            activeUsers,
            newUsers,
            paidUsers,
            suspendedUsers
        };
        
        console.log('✅ User analytics:', userAnalytics);
        
        securityLogger.logAction(req.userId, 'admin', 'USER_ANALYTICS_ACCESS', {
            ip: req.clientInfo.ip
        });
        
        res.json(userAnalytics);
    } catch (error) {
        console.error('❌ Get user analytics error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Security audit logs endpoint
app.get('/api/admin/security-logs', verifyToken, verifyAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, severity = 'all' } = req.query;
        
        // Validate pagination
        const pageNum = Math.max(1, parseInt(page));
        const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
        
        let query = {};
        if (severity !== 'all' && ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(severity)) {
            query.severity = severity;
        }
        
        const logs = await AuditLog.find(query)
            .sort({ timestamp: -1 })
            .limit(limitNum)
            .skip((pageNum - 1) * limitNum);
            
        const total = await AuditLog.countDocuments(query);
        
        securityLogger.logAction(req.userId, 'admin', 'SECURITY_LOGS_ACCESS', {
            ip: req.clientInfo.ip,
            page: pageNum,
            limit: limitNum,
            severity
        });
        
        res.json({
            logs,
            total,
            page: pageNum,
            limit: limitNum,
            totalPages: Math.ceil(total / limitNum)
        });
    } catch (error) {
        console.error('❌ Get security logs error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// Test auth endpoint for debugging - Enhanced security
app.get('/api/admin/test-auth', verifyToken, verifyAdmin, async (req, res) => {
    try {
        console.log('🧪 Test auth request from admin:', req.userId);
        
        const admin = await Admin.findById(req.userId).select('-password');
        if (!admin) {
            return res.status(404).json({ error: 'Admin not found' });
        }
        
        securityLogger.logAction(req.userId, 'admin', 'AUTH_TEST', {
            ip: req.clientInfo.ip
        });
        
        res.json({
            message: 'Authentication successful',
            admin: {
                _id: admin._id,
                name: admin.name,
                username: admin.username,
                role: admin.role,
                lastLoginDate: admin.lastLoginDate,
                sessionCount: admin.sessionCount
            },
            timestamp: new Date().toISOString(),
            security: {
                version: '4.2.0',
                features: ['rate-limiting', 'input-sanitization', 'audit-logging', 'account-locking']
            }
        });
    } catch (error) {
        console.error('❌ Test auth error:', error);
        res.status(500).json({ error: 'Server error: ' + error.message });
    }
});

// ========================================
// INITIALIZATION FUNCTIONS - ENHANCED SECURITY
// ========================================

async function createDefaultAdmin() {
    try {
        const adminExists = await Admin.findOne({ username: 'admin' });
        
        if (!adminExists) {
            // Enhanced password hashing
            const saltRounds = 12;
            const hashedPassword = await bcrypt.hash('GosokAngka2024!', saltRounds);
            
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
            console.log('🔒 SECURITY: Enhanced password hashing with bcrypt salt rounds: 12');
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
                resetTime: '00:00',
                maxDailyScratches: 100,
                maintenanceMode: false
            });
            
            await settings.save();
            console.log('✅ Default game settings created with security enhancements!');
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
                    winningNumber: '1093',
                    name: 'iPhone 15',
                    type: 'physical',
                    value: 15000000,
                    stock: 2,
                    isActive: true
                },
                {
                    winningNumber: '2415',
                    name: 'Cash Prize 50 Jt',
                    type: 'cash',
                    value: 50000000,
                    stock: 1,
                    isActive: true
                },
                {
                    winningNumber: '6451',
                    name: 'Voucher Tokopedia Rp250K',
                    type: 'voucher',
                    value: 250000,
                    stock: 10,
                    isActive: true
                },
                {
                    winningNumber: '9026',
                    name: 'Voucher Shopee Rp500K',
                    type: 'voucher',
                    value: 500000,
                    stock: 5,
                    isActive: true
                }
            ];
            
            await Prize.insertMany(samplePrizes);
            console.log('✅ Sample prizes created and synced with security tracking!');
        }
    } catch (error) {
        console.error('❌ Error creating sample prizes:', error);
    }
}

async function initializeDatabase() {
    await createDefaultAdmin();
    await createDefaultSettings();
    await createSamplePrizes();
    
    // Create indexes for performance and security
    try {
        await User.createIndexes([
            { email: 1 },
            { phoneNumber: 1 },
            { lastLoginIP: 1 },
            { createdAt: -1 }
        ]);
        
        await Scratch.createIndexes([
            { userId: 1, scratchDate: -1 },
            { scratchDate: -1 },
            { ipAddress: 1 }
        ]);
        
        await AuditLog.createIndexes([
            { timestamp: -1 },
            { userId: 1, timestamp: -1 },
            { severity: 1, timestamp: -1 }
        ]);
        
        console.log('✅ Database indexes created for performance and security!');
    } catch (error) {
        console.error('❌ Error creating indexes:', error);
    }
}

// ========================================
// ERROR HANDLING - ENHANCED SECURITY
// ========================================

// 404 handler with security logging
app.use((req, res) => {
    console.log('❌ 404 - Endpoint not found:', req.path);
    
    // Log suspicious 404s
    if (req.path.includes('..') || req.path.includes('<script>') || req.path.includes('admin') || req.path.includes('config')) {
        securityLogger.logSuspiciousActivity(req.clientInfo?.ip || req.ip, 'SUSPICIOUS_404', {
            path: req.path,
            userAgent: req.get('User-Agent'),
            referer: req.get('Referer')
        });
    }
    
    res.status(404).json({ 
        error: 'Endpoint not found',
        requestedPath: req.path,
        backend: 'gosokangka-backend-production-e9fa.up.railway.app',
        version: '4.2.0',
        security: 'ENHANCED',
        availableEndpoints: [
            'GET /',
            'GET /health',
            'GET /api/health',
            'POST /api/auth/register',
            'POST /api/auth/login',
            'GET /api/user/profile',
            'POST /api/game/prepare-scratch',
            'POST /api/game/scratch',
            'GET /api/user/history',
            'GET /api/public/prizes',
            'GET /api/public/game-settings',
            'POST /api/admin/login',
            'ALL ADMIN ENDPOINTS (Protected)'
        ]
    });
});

// Global error handler with security enhancements
app.use((err, req, res, next) => {
    // Log security-related errors
    if (err.message && (err.message.includes('CORS') || err.message.includes('rate limit') || err.message.includes('validation'))) {
        securityLogger.logSuspiciousActivity(req.clientInfo?.ip || req.ip, 'SECURITY_ERROR', {
            error: err.message,
            path: req.path,
            userAgent: req.get('User-Agent')
        });
    }
    
    if (err.message && err.message.includes('CORS')) {
        console.error('❌ CORS Error:', err.message);
        console.error('❌ Request origin:', req.headers.origin);
        
        return res.status(403).json({ 
            error: 'CORS Error',
            message: 'Origin not allowed',
            origin: req.headers.origin,
            backend: 'gosokangka-backend-production-e9fa.up.railway.app'
        });
    }
    
    // Don't expose sensitive error details in production
    console.error('❌ Global error:', err);
    
    if (process.env.NODE_ENV === 'production') {
        res.status(500).json({ 
            error: 'Something went wrong!',
            backend: 'gosokangka-backend-production-e9fa.up.railway.app',
            version: '4.2.0',
            security: 'ENHANCED',
            timestamp: new Date().toISOString()
        });
    } else {
        res.status(500).json({ 
            error: 'Something went wrong!',
            backend: 'gosokangka-backend-production-e9fa.up.railway.app',
            message: err.message,
            stack: err.stack
        });
    }
});

// ========================================
// SECURITY MONITORING & CLEANUP
// ========================================

// Cleanup old audit logs (run daily)
setInterval(async () => {
    try {
        const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        const deletedCount = await AuditLog.deleteMany({
            timestamp: { $lt: thirtyDaysAgo },
            severity: { $in: ['LOW', 'MEDIUM'] }
        });
        
        if (deletedCount.deletedCount > 0) {
            console.log(`🧹 Cleaned up ${deletedCount.deletedCount} old audit logs`);
        }
    } catch (error) {
        console.error('❌ Error cleaning up audit logs:', error);
    }
}, 24 * 60 * 60 * 1000); // Run once per day

// Security health check
setInterval(async () => {
    try {
        const now = new Date();
        const oneHourAgo = new Date(now - 60 * 60 * 1000);
        
        // Check for suspicious activities in the last hour
        const suspiciousCount = await AuditLog.countDocuments({
            timestamp: { $gte: oneHourAgo },
            severity: { $in: ['HIGH', 'CRITICAL'] }
        });
        
        if (suspiciousCount > 10) {
            console.log(`🚨 SECURITY ALERT: ${suspiciousCount} suspicious activities in the last hour!`);
            // In production, trigger alerts (email, Slack, etc.)
        }
        
        // Check for locked accounts
        const lockedUsers = await User.countDocuments({
            accountLockedUntil: { $gt: now }
        });
        
        const lockedAdmins = await Admin.countDocuments({
            accountLockedUntil: { $gt: now }
        });
        
        if (lockedUsers > 0 || lockedAdmins > 0) {
            console.log(`🔒 Security Status: ${lockedUsers} users and ${lockedAdmins} admins currently locked`);
        }
        
    } catch (error) {
        console.error('❌ Error in security health check:', error);
    }
}, 60 * 60 * 1000); // Run every hour

// ========================================
// START SERVER - ENHANCED SECURITY
// ========================================

const PORT = process.env.PORT || 5000;

server.listen(PORT, () => {
    console.log('========================================');
    console.log('🎯 GOSOK ANGKA BACKEND - SECURITY ENHANCED V4.2.0');
    console.log('========================================');
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🌐 Domain: gosokangkahoki.com`);
    console.log(`📡 Backend URL: gosokangka-backend-production-e9fa.up.railway.app`);
    console.log(`🔌 Socket.io enabled with realtime sync`);
    console.log(`📧 Email/Phone login support enabled`);
    console.log(`🎮 Game features: Scratch cards, Prizes, Chat`);
    console.log(`📊 Database: MongoDB Atlas`);
    console.log(`🔐 Security: JWT Authentication, CORS configured`);
    console.log('');
    console.log('🛡️ SECURITY FEATURES V4.2.0:');
    console.log('   ✅ Multi-tier Rate Limiting (General/Auth/Admin)');
    console.log('   ✅ Input Sanitization & XSS Protection');
    console.log('   ✅ SQL/NoSQL Injection Prevention');
    console.log('   ✅ Security Headers (Helmet.js)');
    console.log('   ✅ Account Locking (Failed Login Protection)');
    console.log('   ✅ Enhanced Password Hashing (bcrypt 12 rounds)');
    console.log('   ✅ Complete Audit Logging & Activity Tracking');
    console.log('   ✅ Suspicious Activity Detection');
    console.log('   ✅ Enhanced JWT Token Validation');
    console.log('   ✅ HTTPS Enforcement (Production)');
    console.log('   ✅ CORS Strict Policy');
    console.log('   ✅ Real-time Security Monitoring');
    console.log('   ✅ Automated Security Cleanup');
    console.log('');
    console.log('🆕 COMPLETE FIXES + SECURITY:');
    console.log('   ✅ FIXED: NO notification during scratch process');
    console.log('   ✅ FIXED: PERFECT client-server number synchronization');
    console.log('   ✅ FIXED: Prize winning numbers 100% synced with database');
    console.log('   ✅ FIXED: Mobile responsive admin panel with toggle menu');
    console.log('   ✅ ENHANCED: Real-time token balance updates');
    console.log('   ✅ COMPLETE: All admin routes implemented & working');
    console.log('   ✅ SECURED: Enhanced validation & error handling');
    console.log('   ✅ PROTECTED: Multi-layer security implementation');
    console.log('');
    console.log('🔒 SECURITY RECOMMENDATIONS:');
    console.log('   ⚠️  IMMEDIATELY change default admin password!');
    console.log('   ⚠️  Ensure JWT_SECRET is 32+ characters strong');
    console.log('   ⚠️  Enable MongoDB Atlas IP whitelist');
    console.log('   ⚠️  Setup automated backups');
    console.log('   ⚠️  Monitor security logs regularly');
    console.log('========================================');
    
    // Initialize database with default data
    setTimeout(initializeDatabase, 2000);
});

// Graceful shutdown with security cleanup
process.on('SIGTERM', () => {
    console.log('🔄 SIGTERM received. Starting graceful shutdown...');
    
    server.close(() => {
        console.log('✅ HTTP server closed');
        
        mongoose.connection.close(false, () => {
            console.log('✅ MongoDB connection closed');
            console.log('👋 Process terminated gracefully');
            process.exit(0);
        });
    });
});

process.on('SIGINT', () => {
    console.log('🔄 SIGINT received. Starting graceful shutdown...');
    
    server.close(() => {
        console.log('✅ HTTP server closed');
        
        mongoose.connection.close(false, () => {
            console.log('✅ MongoDB connection closed');
            console.log('👋 Process terminated gracefully');
            process.exit(0);
        });
    });
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
    console.error('❌ Uncaught Exception:', err);
    securityLogger.logSuspiciousActivity('system', 'UNCAUGHT_EXCEPTION', {
        error: err.message,
        stack: err.stack
    });
    process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
    console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
    securityLogger.logSuspiciousActivity('system', 'UNHANDLED_REJECTION', {
        reason: reason.toString(),
        promise: promise.toString()
    });
});

module.exports = app;
