# Makefile for Vulnpilot - Sparkathon Project
# AI-Powered Vulnerability Detection & Security Automation Platform

.PHONY: help setup install build start stop clean test lint docker-build docker-up docker-down logs dev prod

# Default target
help: ## Show this help message
	@echo "Vulnpilot - Sparkathon Project Management"
	@echo "========================================"
	@echo ""
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Setup and Installation
setup: ## Setup complete development environment
	@echo "🚀 Setting up Vulnpilot development environment..."
	@$(MAKE) check-dependencies
	@$(MAKE) install-dependencies
	@$(MAKE) setup-env
	@$(MAKE) docker-build
	@echo "✅ Setup complete! Run 'make dev' to begin development."

check-dependencies: ## Check if required tools are installed
	@echo "🔍 Checking dependencies..."
	@command -v node >/dev/null 2>&1 || { echo "❌ Node.js is required but not installed. Please install Node.js 18+"; exit 1; }
	@command -v npm >/dev/null 2>&1 || { echo "❌ npm is required but not installed."; exit 1; }
	@command -v docker >/dev/null 2>&1 || { echo "❌ Docker is required but not installed."; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo "❌ Docker Compose is required but not installed."; exit 1; }
	@command -v python3 >/dev/null 2>&1 || { echo "❌ Python 3 is required but not installed."; exit 1; }
	@echo "✅ All dependencies are installed!"

install-dependencies: ## Install all project dependencies
	@echo "📦 Installing dependencies for all services..."
	@echo "Installing Node.js backend dependencies..."
	@cd backend && npm install
	@echo "Installing React frontend dependencies..."
	@cd frontend && npm install
	@echo "Installing Python Django backend dependencies..."
	@cd service && pip3 install -r requirements.txt
	@echo "✅ All dependencies installed!"

setup-env: ## Setup environment files
	@echo "⚙️ Setting up environment files..."
	@if [ ! -f backend/.env ]; then \
		echo "Creating Node.js backend .env file..."; \
		cp backend/.env.example backend/.env 2>/dev/null || \
		echo "NODE_ENV=development\nPORT=3000\nMONGODB_URI=mongodb://localhost:27017/vulnpilot\nSESSION_SECRET=your-session-secret\nGITHUB_CLIENT_ID=your-github-client-id\nGITHUB_CLIENT_SECRET=your-github-client-secret\nGROQ_API_KEY=your-groq-api-key\nJWT_SECRET=your-jwt-secret\nEMAIL_USER=your-email@gmail.com\nEMAIL_PASSWORD=your-app-password\nDEFAULT_EMAIL_RECIPIENT=your-email@gmail.com" > backend/.env; \
	fi
	@if [ ! -f service/.env ]; then \
		echo "Creating Django backend .env file..."; \
		echo "DEBUG=True\nSECRET_KEY=your-django-secret-key\nDATABASE_URL=sqlite:///db.sqlite3" > service/.env; \
	fi
	@if [ ! -f frontend/.env ]; then \
		echo "Creating React frontend .env file..."; \
		echo "VITE_API_BASE_URL=http://localhost:3000\nVITE_DJANGO_API_URL=http://localhost:8000\nVITE_APP_NAME=Vulnpilot" > frontend/.env; \
	fi
	@echo "✅ Environment files created! Please update them with your actual credentials."

# Development Commands
dev: ## Start all services in development mode
	@echo "🚀 Starting all services in development mode..."
	@$(MAKE) -j3 dev-django dev-node dev-react

dev-django: ## Start Django backend in development mode
	@echo "🐍 Starting Django backend..."
	@cd service && python3 manage.py migrate && python3 manage.py runserver 8000

dev-node: ## Start Node.js backend in development mode
	@echo "🟢 Starting Node.js backend..."
	@cd backend && npm run dev

dev-react: ## Start React frontend in development mode
	@echo "⚛️ Starting React frontend..."
	@cd frontend && npm run dev

# Production Commands
start: ## Start all services using Docker
	@echo "🚀 Starting all services with Docker..."
	@$(MAKE) docker-up

stop: ## Stop all services
	@echo "🛑 Stopping all services..."
	@$(MAKE) docker-down
	@pkill -f "python3 manage.py runserver" 2>/dev/null || true
	@pkill -f "npm run dev" 2>/dev/null || true
	@pkill -f "vite" 2>/dev/null || true

# Docker Commands
docker-build: ## Build all Docker images
	@echo "🐳 Building Docker images..."
	@cd service && docker build -t vulnpilot-django .
	@cd backend && if [ -f Dockerfile ]; then docker build -t vulnpilot-node .; fi
	@cd frontend && if [ -f Dockerfile ]; then docker build -t vulnpilot-react .; fi
	@echo "✅ Docker images built successfully!"

docker-up: ## Start services with Docker Compose
	@echo "🐳 Starting services with Docker Compose..."
	docker-compose up -d
	@echo "✅ Services started! Django: http://localhost:8000"

docker-down: ## Stop Docker services
	@echo "🐳 Stopping Docker services..."
	docker-compose down
	@echo "✅ Docker services stopped!"

docker-logs: ## Show Docker logs
	@echo "📋 Showing Docker logs..."
	docker-compose logs -f

# Build Commands
build: ## Build all projects for production
	@echo "🏗️ Building all projects for production..."
	@$(MAKE) build-react
	@$(MAKE) build-node
	@echo "✅ All projects built successfully!"

build-react: ## Build React frontend for production
	@echo "⚛️ Building React frontend..."
	@cd frontend && npm run build
	@echo "✅ React frontend built!"

build-node: ## Build Node.js backend (if applicable)
	@echo "🟢 Preparing Node.js backend for production..."
	@cd backend && npm run prod --if-present
	@echo "✅ Node.js backend prepared!"

# Testing
test: ## Run tests for all projects
	@echo "🧪 Running tests..."
	@$(MAKE) test-node
	@$(MAKE) test-react
	@$(MAKE) test-django

test-node: ## Run Node.js backend tests
	@echo "🟢 Running Node.js tests..."
	@cd backend && npm test --if-present

test-react: ## Run React frontend tests
	@echo "⚛️ Running React tests..."
	@cd frontend && npm test --if-present

test-django: ## Run Django backend tests
	@echo "🐍 Running Django tests..."
	@cd service && python3 manage.py test

# Code Quality
lint: ## Run linting for all projects
	@echo "🔍 Running linting..."
	@$(MAKE) lint-node
	@$(MAKE) lint-react

lint-node: ## Run Node.js linting
	@echo "🟢 Linting Node.js code..."
	@cd backend && npm run lint --if-present

lint-react: ## Run React linting
	@echo "⚛️ Linting React code..."
	@cd frontend && npm run lint --if-present

lint-fix: ## Fix linting issues
	@echo "🔧 Fixing linting issues..."
	@cd backend && npm run lint:fix --if-present
	@cd frontend && npm run lint --fix --if-present

# Database Management
migrate: ## Run Django database migrations
	@echo "🗄️ Running database migrations..."
	@cd service && python3 manage.py makemigrations && python3 manage.py migrate

create-superuser: ## Create Django superuser
	@echo "👤 Creating Django superuser..."
	@cd service && python3 manage.py createsuperuser

# Cleanup
clean: ## Clean build artifacts and temporary files
	@echo "🧹 Cleaning up..."
	@cd frontend && rm -rf dist/ node_modules/.cache/
	@cd backend && rm -rf logs/*.log
	@cd service && find . -name "*.pyc" -delete && find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	@docker system prune -f
	@echo "✅ Cleanup complete!"

# Logs
logs: ## Show logs from all services
	@echo "📋 Showing application logs..."
	@echo "=== Node.js Backend Logs ==="
	@tail -n 50 backend/logs/combined.log 2>/dev/null || echo "No Node.js logs found"
	@echo "=== Django Backend Logs ==="
	@tail -n 50 service/nmap_scan.log 2>/dev/null || echo "No Django logs found"

# Health Check
health: ## Check health of all services
	@echo "🏥 Checking service health..."
	@echo "Django Backend (port 8000):"
	@curl -s http://localhost:8000/health 2>/dev/null && echo "✅ Django: Healthy" || echo "❌ Django: Not responding"
	@echo "Node.js Backend (port 3000):"
	@curl -s http://localhost:3000/health 2>/dev/null && echo "✅ Node.js: Healthy" || echo "❌ Node.js: Not responding"
	@echo "React Frontend (port 5173):"
	@curl -s http://localhost:5173 2>/dev/null && echo "✅ React: Healthy" || echo "❌ React: Not responding"

# Quick Start
quick-start: ## Quick start for demonstration
	@echo "⚡ Quick start setup..."
	@$(MAKE) check-dependencies
	@$(MAKE) install-dependencies
	@$(MAKE) setup-env
	@echo "✅ Ready! Now run 'make dev' to start development or 'make start' for production."

# Installation helper
install: setup ## Alias for setup command

# Status
status: ## Show status of all services
	@echo "📊 Service Status:"
	@echo "=================="
	@ps aux | grep -E "(manage.py runserver|npm|vite)" | grep -v grep || echo "No development servers running"
	@echo ""
	@docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep vulnpilot || echo "No Docker containers running"
