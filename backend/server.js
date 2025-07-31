const app = require("./src/app");
const logger = require("./src/lib/logger");

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || 'development';

const server = app.listen(PORT, () => {
  logger.info(`🚀 Vulnpilot Backend Server running on http://localhost:${PORT}`);
  logger.info(`📊 Environment: ${NODE_ENV}`);
  logger.info(`⏰ Started at: ${new Date().toISOString()}`);
});

// Graceful shutdown handling
const gracefulShutdown = (signal) => {
  logger.info(`📴 Received ${signal}. Starting graceful shutdown...`);
  
  server.close((err) => {
    if (err) {
      logger.error('❌ Error during server shutdown:', err);
      process.exit(1);
    }
    
    logger.info('✅ Server closed successfully');
    process.exit(0);
  });
};

// Handle different shutdown signals
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  logger.error('💥 Uncaught Exception:', err);
  process.exit(1);
});

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  logger.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

module.exports = server;
