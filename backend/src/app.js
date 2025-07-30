const express = require("express");
const session = require("express-session");
const passport = require("passport");
const mongoose = require("mongoose");
const morgan = require("morgan");
const cors = require("cors");
const helmet = require("helmet");
const compression = require("compression");
const rateLimit = require("express-rate-limit");
const MongoStore = require("connect-mongo");
require("dotenv").config();
require("./config/passport");

const logger = require("./lib/logger");
const { FRONTEND_URL } = require("./lib/constant");

// Import routes
const authRoutes = require("./routes/authRoutes");
const githubRoutes = require("./routes/githubRoutes");
const codeRoutes = require("./routes/codeRoutes");
const flowchartRoutes = require("./routes/flowChartRoutes");
const workflowRoutes = require("./routes/workflowRoutes");
const chatbotRoutes = require("./routes/chatbotRoutes");

const app = express();

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

// Compression middleware
app.use(compression());

// CORS configuration
app.use(cors({ 
  origin: FRONTEND_URL, 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use('/api/', limiter);

// Body parsing middleware
app.use(express.json({ 
  limit: '50mb',
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));
app.use(express.urlencoded({ 
  limit: '50mb', 
  extended: true 
}));

// Session configuration with MongoDB store
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'your-secret-key',
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      ttl: 24 * 60 * 60, // 1 day
      autoRemove: 'native'
    }),
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      sameSite: 'lax', // Changed from conditional to always 'lax' for development
      domain: process.env.NODE_ENV === 'production' ? undefined : undefined
    }
  })
);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Logging middleware
app.use(morgan('combined', { stream: logger.stream }));

// Database Connection with retry logic
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      maxPoolSize: 10,
      minPoolSize: 5,
      maxIdleTimeMS: 30000,
      retryWrites: true,
      w: 'majority'
    });
    logger.info("✅ MongoDB Connected Successfully");
  } catch (err) {
    logger.error("❌ MongoDB Connection Error:", err);
    process.exit(1);
  }
};

// Connect to database
connectDB();

// Health check route
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  });
});

// API Routes
app.use("/api/auth", authRoutes);
app.use("/api/github", githubRoutes);
app.use("/api/code", codeRoutes);
app.use('/api/flowchart', flowchartRoutes);
app.use('/api/workflows', workflowRoutes);
app.use('/api/chatbot', chatbotRoutes);

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Route not found',
    message: `Cannot ${req.method} ${req.originalUrl}`,
    timestamp: new Date().toISOString()
  });
});

// Global error handler
app.use((err, req, res, next) => {
  logger.error('💥 Global Error Handler:', {
    error: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  // Don't leak error details in production
  const isDevelopment = process.env.NODE_ENV === 'development';
  
  res.status(err.status || 500).json({
    error: isDevelopment ? err.message : 'Internal Server Error',
    ...(isDevelopment && { stack: err.stack }),
    timestamp: new Date().toISOString(),
    path: req.path,
    method: req.method
  });
});

// Graceful shutdown for database
process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    logger.info('✅ MongoDB connection closed through app termination');
    process.exit(0);
  } catch (err) {
    logger.error('❌ Error closing MongoDB connection:', err);
    process.exit(1);
  }
});

module.exports = app;
