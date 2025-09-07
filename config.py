#!/usr/bin/env python3
"""!
********************************************************************************
@file   config.py
@brief  Configuration settings for WakeStation application
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
DEBUG = False  # Enable debug mode (NEVER in production)

# =============================================================================
# DIRECTORY AND FILE PATHS
# =============================================================================

# Base directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "db")  # Configuration and database storage
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")  # Template files directory

# Data files
USERS_FILE = os.path.join(DB_DIR, "users.json")  # User authentication data
PC_DATA_DIR = os.path.join(DB_DIR, "pcs")  # User PC configurations
ENCRYPTION_KEY_FILE = os.path.join(DB_DIR, "enc.bin")  # Encryption key file

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

# Wake-on-LAN Settings
WOL_INTERFACE = "10.0.1.13"  # Network interface WakeStation binds to (NOT 0.0.0.0 or 127.0.0.1 or localhost)
# To find your active network interface, run:
# Linux: sudo lshw -C network | awk '/logical name:/ {name=$3} /ip=/ {ip=$2} /link=yes/ {print name, ip}'
# Windows: ipconfig /all

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
