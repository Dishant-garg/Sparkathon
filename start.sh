#!/bin/bash

# Vulnpilot - Quick Start Script
# AI-Powered Vulnerability Detection & Security Automation Platform

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Banner
show_banner() {
    echo -e "${BLUE}"
    echo "==========================================="
    echo "    Vulnpilot - Sparkathon Project"
    echo "   AI-Powered Security Automation"
    echo "==========================================="
    echo -e "${NC}"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check system requirements
check_requirements() {
    log_info "Checking system requirements..."
    
    local requirements_met=true
    
    # Check Node.js
    if command_exists node; then
        local node_version=$(node --version | cut -d'v' -f2)
        log_success "Node.js found: v$node_version"
    else
        log_error "Node.js is not installed. Please install Node.js 18+"
        requirements_met=false
    fi
    
    # Check npm
    if command_exists npm; then
        local npm_version=$(npm --version)
        log_success "npm found: v$npm_version"
    else
        log_error "npm is not installed"
        requirements_met=false
    fi
    
    # Check Python
    if command_exists python3; then
        local python_version=$(python3 --version | cut -d' ' -f2)
        log_success "Python found: $python_version"
    else
        log_error "Python 3 is not installed. Please install Python 3.8+"
        requirements_met=false
    fi
    
    # Check Docker
    if command_exists docker; then
        log_success "Docker found"
    else
        log_warning "Docker is not installed. Docker setup will be skipped."
    fi
    
    # Check Docker Compose
    if command_exists docker-compose || docker compose version >/dev/null 2>&1; then
        log_success "Docker Compose found"
    else
        log_warning "Docker Compose is not installed. Docker setup will be skipped."
    fi
    
    if [ "$requirements_met" = false ]; then
        log_error "Some requirements are missing. Please install them and run the script again."
        exit 1
    fi
}

# Main setup function
main() {
    show_banner
    
    # Check if we're in the right directory
    if [ ! -f "Makefile" ] || [ ! -d "service" ] || [ ! -d "backend" ] || [ ! -d "frontend" ]; then
        log_error "Please run this script from the project root directory"
        exit 1
    fi
    
    check_requirements
    
    log_info "Starting Vulnpilot setup..."
    
    # Run setup using Makefile
    make setup
    
    log_success "Setup completed successfully!"
    echo
    echo -e "${GREEN}Next steps:${NC}"
    echo "1. Update environment files with your actual credentials:"
    echo "   - service/.env"
    echo "   - backend/.env"
    echo "   - frontend/.env"
    echo
    echo "2. Start the services:"
    echo "   - Development: make dev"
    echo "   - Production: make start"
    echo
    echo "3. Access the application:"
    echo "   - Frontend: http://localhost:5173 (dev) or http://localhost (prod)"
    echo "   - Django API: http://localhost:8000"
    echo "   - Node.js API: http://localhost:3000"
    echo
    echo -e "${BLUE}Happy coding! 🚀${NC}"
}

# Run main function
main "$@" 