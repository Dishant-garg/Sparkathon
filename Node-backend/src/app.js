const express = require("express");
const session = require("express-session");
const passport = require("passport");
const mongoose = require("mongoose");
const morgan = require("morgan");
const cors = require("cors");
require("dotenv").config();
require("./config/passport");

const authRoutes = require("./routes/authRoutes");
const githubRoutes = require("./routes/githubRoutes");
const codeRoutes = require("./routes/codeRoutes");
const flowchartRoutes = require("./routes/flowChartRoutes");
const workflowRoutes = require("./routes/workflowRoutes");
const { FRONTEND_URL } = require("./lib/constant");

const app = express();

// Database Connection
mongoose
  .connect(process.env.MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    serverSelectionTimeoutMS: 30000, // 30 seconds
    socketTimeoutMS: 45000, // 45 seconds
    maxPoolSize: 10,
    minPoolSize: 5,
  })
  .then(() => console.log("MongoDB Connected Successfully"))
  .catch((err) => {
    console.error("MongoDB Connection Error:", err);
    process.exit(1);
  });

// Middleware
app.use(cors({ origin: `${FRONTEND_URL}`, credentials: true }));
// Increase body size limits for large workflow data
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

// Logging
app.use(morgan("dev"));

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/github", githubRoutes);
app.use("/api/code", codeRoutes);
app.use('/api/flowchart', flowchartRoutes);
app.use('/api/workflows', workflowRoutes);

// Health check route
app.get('/api/health', (req, res) => {
  res.json({
    status: 'OK',
    timestamp: new Date().toISOString(),
    version: '1.0.0'
  });
});

module.exports = app;
