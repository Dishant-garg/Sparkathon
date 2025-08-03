# 🛡️ Vulnpilot - AI-Powered Security Automation

<div align="center">
  <h1>🛡️ Vulnpilot</h1>
  <p><strong>AI-Powered Vulnerability Detection & Security Automation Platform</strong></p>
  <p>Built for Sparkathon - Advanced Security Scanning with No-Code Workflows</p>
</div>

## 🎯 Overview

Vulnpilot is a comprehensive security automation platform that combines advanced vulnerability detection with AI-powered code analysis and no-code workflow automation. This Sparkathon project demonstrates cutting-edge security tools integration with modern web technologies.

## 🌟 Key Features

- **🔍 Multi-Layer Security Scanning**: OWASP Top 10, SANS 25, and custom vulnerability detection
- **🤖 AI-Powered Code Analysis**: Conversational AI for intelligent vulnerability insights
- **⚡ No-Code Security Workflows**: Visual workflow builder for automated security processes
- **📊 Real-Time Reporting**: Comprehensive security reports with actionable insights
- **🔗 GitHub Integration**: Seamless repository scanning and issue management
- **🎨 Modern UI/UX**: Responsive design with dark/light theme support
- **🐳 Docker Support**: Containerized deployment for easy setup

## 🏗️ Architecture

### Tech Stack
- **Frontend**: React 19 + TypeScript + Tailwind CSS + Vite
- **Backend API**: Node.js + Express + MongoDB
- **Security Engine**: Django + Python + PostgreSQL
- **AI Integration**: Groq SDK for intelligent analysis
- **Containerization**: Docker + Docker Compose
- **Security Tools**: Nmap, Nikto, SQLMap, Gobuster, WPScan

### Project Structure
```
Sparkathon/
├── service/              # Security scanning engine
├── backend/              # API & AI service
├── frontend/             # User interface
├── Makefile              # Build automation
├── docker-compose.yaml   # Multi-service orchestration
└── .gitignore            # Comprehensive exclusions
```

## 🚀 Quick Start

### Automated Setup
```bash
# Clone and setup
git clone <your-repo-url> vulnpilot
cd vulnpilot

# Start development
make dev

# OR start with Docker
make start
```

### Manual Setup
```bash
# Check requirements
make check-dependencies

# Install dependencies
make install-dependencies

# Setup environment
make setup-env

# Start services
make dev
```

## 🔧 Configuration

### Environment Variables

#### Django Backend (.env)
```bash
DEBUG=True
SECRET_KEY=your-django-secret-key
DATABASE_URL=postgresql://user:pass@localhost:5432/vulnpilot
ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0
```

#### Node.js Backend (.env)
```bash
NODE_ENV=development
PORT=3000
MONGODB_URI=mongodb://localhost:27017/vulnpilot
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
GROQ_API_KEY=your-groq-api-key
EMAIL_USER=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

#### React Frontend (.env)
```bash
VITE_API_BASE_URL=http://localhost:3000
VITE_DJANGO_API_URL=http://localhost:8000
VITE_APP_NAME=Vulnpilot
```

## 📧 Email Configuration

VulnPilot can send security reports via email. To enable this feature:

### Quick Setup
```bash
./setup-email.sh
```

### Manual Setup

1. **Enable 2-Factor Authentication** on your Gmail account:
   - Go to [Google Account Security](https://myaccount.google.com/security)
   - Turn on 2-Step Verification

2. **Generate App Password**:
   - Go to [Google App Passwords](https://myaccount.google.com/apppasswords)
   - Select "Mail" → "Other (custom name)"
   - Enter "VulnPilot Scanner"
   - Copy the 16-character password

3. **Update backend/.env**:
   ```bash
   ENABLE_EMAIL_NOTIFICATIONS=true
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASSWORD=your_16_character_app_password
   DEFAULT_EMAIL_RECIPIENT=your-email@gmail.com
   ```

4. **Test Configuration**:
   ```bash
   node test-email.js
   ```

### Troubleshooting Email Issues

- **"Invalid login" error**: Use Gmail App Password, not regular password
- **"Email notifications disabled"**: Set `ENABLE_EMAIL_NOTIFICATIONS=true`
- **Emails not received**: Check spam folder, verify recipient address
- **Connection timeout**: Check firewall/network settings

## 📋 Available Commands

### Core Commands
```bash
make help                # Show all available commands
make setup               # Complete setup (first time)
make dev                 # Start development servers
make start               # Start with Docker
make stop                # Stop all services
make build               # Build for production
make test                # Run all tests
make clean               # Clean build artifacts
```

### Development Commands
```bash
make dev-django          # Start Django backend only
make dev-node            # Start Node.js backend only
make dev-react           # Start React frontend only
make docker-build        # Build Docker images
make docker-up           # Start with Docker Compose
make logs                # Show application logs
make health              # Check service health
```

## 🐳 Docker Deployment

### Quick Docker Start
```bash
# Build and start all services
make docker-build
make docker-up

# Access services
# Frontend: http://localhost
# Django API: http://localhost:8000
# Node.js API: http://localhost:3000
```

## 🔐 Security Tools Integration

### Available Security Scanners
- **Nmap**: Network discovery and port scanning
- **Nikto**: Web vulnerability scanner
- **SQLMap**: SQL injection detection and exploitation
- **Gobuster**: Directory and file brute-forcing
- **WPScan**: WordPress vulnerability scanner

### Security Workflow Examples
1. **Repository Scan**: GitHub repo → AI analysis → Vulnerability report
2. **Web Application Scan**: URL → Multiple scanners → Consolidated report
3. **Network Discovery**: IP range → Port scan → Service enumeration
4. **Code Review**: Source code → AI analysis → Security recommendations

## 🧪 Testing

### Run All Tests
```bash
make test
```

### Individual Test Suites
```bash
make test-django         # Django tests
make test-node           # Node.js tests
make test-react          # React tests
```

## 📊 Monitoring & Logs

### View Logs
```bash
make logs                # All logs
make docker-logs         # Docker logs
```

### Health Checks
```bash
make health              # Check all services
```

## 🚨 Troubleshooting

### Common Issues

#### Port Conflicts
```bash
# Check what's using ports
lsof -i :3000
lsof -i :8000
lsof -i :5173

# Kill processes if needed
pkill -f "npm"
pkill -f "python manage.py runserver"
```

#### Docker Issues
```bash
# Clean Docker environment
docker system prune -a
docker-compose down -v

# Rebuild everything
make clean
make docker-build
make docker-up
```

#### Dependencies Issues
```bash
# Clean and reinstall
make clean
rm -rf */node_modules
rm -rf Django-backend/venv
make install-dependencies
```

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Run tests: `make test`
5. Run linting: `make lint`
6. Commit changes: `git commit -m 'Add amazing feature'`
7. Push to branch: `git push origin feature/amazing-feature`
8. Open a Pull Request

## 📜 License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## 🎉 Sparkathon Project

This project was created for the Sparkathon competition, demonstrating:
- **Innovation**: AI-powered security automation
- **Technical Excellence**: Modern full-stack architecture
- **Practical Value**: Real-world security tools integration
- **User Experience**: Intuitive no-code workflow builder
- **Scalability**: Containerized microservices architecture

## 📞 Support

For support and questions:
- Create an issue in the repository
- Check the troubleshooting section
- Review the logs: `make logs`
- Run health checks: `make health`

---

<div align="center">
  <p><strong>Built with ❤️ for Sparkathon</strong></p>
  <p>🚀 Happy Coding & Secure Development! 🛡️</p>
</div>
