FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Create app user for security
RUN groupadd -r appuser && useradd -r -g appuser appuser

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    git \
    wget \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Copy and install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir -r requirements.txt

# Install essential security tools

# Install Gobuster via pre-compiled binary
RUN wget -q --timeout=30 https://github.com/OJ/gobuster/releases/download/v3.6.0/gobuster_Linux_x86_64.tar.gz -O /tmp/gobuster.tar.gz \
    && tar -xzf /tmp/gobuster.tar.gz -C /tmp \
    && mv /tmp/gobuster /usr/local/bin/gobuster \
    && chmod +x /usr/local/bin/gobuster \
    && rm -rf /tmp/gobuster* \
    && gobuster version || echo "Gobuster installation completed"

# Install SQLMap via Git
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && ln -sf /opt/sqlmap/sqlmap.py /usr/local/bin/sqlmap \
    && chmod +x /usr/local/bin/sqlmap

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/logs /app/scans /app/reports /app/wordlists \
    && chown -R appuser:appuser /app /opt/sqlmap \
    && chmod +x /app/manage.py /app/health_check.py

# Download basic wordlist
RUN wget -q --timeout=30 https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O /app/wordlists/common.txt || \
    echo -e "admin\nadmin.php\nindex.html\nindex.php\nlogin\nlogin.php\ntest\ntest.php\nbackup\nconfig\ndata\ndatabase\napi\napi.php\nwp-admin\nwp-login.php\n.htaccess\nrobots.txt\nsitemap.xml" > /app/wordlists/common.txt

# Switch to non-root user for security
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python3 health_check.py || exit 1

# Start command
CMD ["sh", "-c", "python manage.py migrate --noinput && python manage.py runserver 0.0.0.0:8000"]
