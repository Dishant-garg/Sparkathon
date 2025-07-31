# Node.js Backend Dockerfile
FROM node:18-alpine

# Set environment variables
ENV NODE_ENV=production \
    NPM_CONFIG_LOGLEVEL=warn \
    NPM_CONFIG_COLOR=false

# Create app user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Set work directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p logs tmp && \
    chown -R nodejs:nodejs /app

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["node", "server.js"]
