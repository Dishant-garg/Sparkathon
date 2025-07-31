#!/usr/bin/env python3
"""
Health check script for Django backend
"""
import sys
import os
import django
from django.conf import settings

# Add the project directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Labs.settings')
django.setup()

try:
    # Test database connection
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
    
    # Test Redis connection if configured
    try:
        import redis
        redis_url = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
        r = redis.from_url(redis_url)
        r.ping()
    except Exception as e:
        print(f"Redis connection failed: {e}")
        # Don't fail health check for Redis issues
    
    print("Django backend is healthy")
    sys.exit(0)
    
except Exception as e:
    print(f"Django backend health check failed: {e}")
    sys.exit(1) 