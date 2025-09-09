#!/usr/bin/env python3
"""!
********************************************************************************
@brief  Configuration settings for WakeStation application

@file   config.py
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os

# =============================================================================
# APPLICATION SETTINGS
# =============================================================================

# Flask Application Configuration
SECRET_KEY = "your_secret_key_here"  # Change this to a secure random key in production
DEBUG = True  # Enable debug mode (NEVER in production)

# =============================================================================
# DIRECTORY AND FILE PATHS
# =============================================================================

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "db")  # Configuration and database storage
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")  # Template files directory

# Data files
USERS_FILE = os.path.join(DB_DIR, "users.json")  # User authentication data
DAEMON_DATA_FILE = os.path.join(DB_DIR, "daemon_registry.json")  # Daemon configurations
PC_DATA_DIR = os.path.join(DB_DIR, "pcs")  # User PC configurations
ENCRYPTION_KEY_FILE = os.path.join(DB_DIR, "enc.bin")  # Encryption key file

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

# Network Configuration

# WOL Interface - MUST be a specific network interface IP that belongs to this machine
# CANNOT be 0.0.0.0, 127.0.0.1, or localhost - must be actual network interface
WOL_INTERFACE = "10.0.1.13"  # Change this to your server's actual IP address
# To find your interface IP:
# Linux: ip addr show | grep 'inet ' | grep -v 127.0.0.1
# Windows: ipconfig | findstr IPv4
# macOS: ifconfig | grep 'inet ' | grep -v 127.0.0.1

# Server Binding - Separate configuration for Flask development server
FLASK_HOST = os.environ.get(
    "FLASK_HOST", "0.0.0.0"
)  # Development server binding (can be 0.0.0.0)
FLASK_PORT = int(os.environ.get("FLASK_PORT", "8888"))  # Development server port

# Production deployment notes:
# - Gunicorn ignores FLASK_HOST/FLASK_PORT: use --bind 0.0.0.0:8888
# - WOL_INTERFACE is ALWAYS needed for Wake-on-LAN functionality

# Shutdown Daemon Settings
SHUTDOWN_DAEMON_PORT = 8080  # Port for shutdown daemon communication
SHUTDOWN_DAEMON_TIMEOUT = 10  # Connection timeout in seconds

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Log levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "INFO"  # File log level
CONSOLE_LOG_LEVEL = "WARNING"  # Console output level
LOG_FILE = os.path.join(DB_DIR, "wakestation.log")  # Log file location
LOG_FORMAT = "rsyslog"  # Format: 'rsyslog' or 'simple'
LOG_MAX_SIZE = 10 * 1024 * 1024  # 10MB max log file size
LOG_BACKUP_COUNT = 5  # Number of backup log files

# =============================================================================
# FLASK SESSION AND SECURITY
# =============================================================================

# Session Configuration
SESSION_PERMANENT = True
REMEMBER_COOKIE_DURATION = 30 * 24 * 60 * 60  # 30 days in seconds
REMEMBER_COOKIE_SECURE = False  # Set to True with HTTPS in production
REMEMBER_COOKIE_HTTPONLY = True  # Prevent JavaScript access
REMEMBER_COOKIE_SAMESITE = "Lax"  # CSRF protection

# Security Headers
SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year cache for static files
