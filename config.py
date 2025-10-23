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
# DIRECTORY PATHS
# =============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "db")
PC_DATA_DIR = os.path.join(DB_DIR, "pcs")
LOG_DIR = os.path.join(BASE_DIR, "logs")

# =============================================================================
# FILE PATHS
# =============================================================================

USERS_FILE = os.path.join(DB_DIR, "users.json")
ENCRYPTION_KEY_FILE = os.path.join(DB_DIR, "enc.bin")
DAEMON_REGISTRY_FILE = os.path.join(DB_DIR, "daemon_registry.json")
LOG_FILE = os.path.join(LOG_DIR, "wakestation.log")

# =============================================================================
# LOGGING CONFIGURATION
# =============================================================================

# Log Levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = "DEBUG"
CONSOLE_LOG_LEVEL = "DEBUG"
LOG_FORMAT = "rsyslog"  # 'rsyslog' or 'simple'
LOG_MAX_SIZE = 10  # MB
LOG_BACKUP_COUNT = 5

# =============================================================================
# NETWORK CONFIGURATION
# =============================================================================

# Server Configuration
# CRITICAL: WOL_SERVER_HOST must be the actual network IP (not 127.0.0.1 or 0.0.0.0)
# This IP is used for:
# - Network interface detection for ARP scanning
# - Wake-on-LAN packet transmission
# - Network discovery and device scanning
WOL_SERVER_HOST = "99.99.99.99.99"

# Port Configuration
# - Standard ports (80/HTTP, 443/HTTPS): No port in URL
#   Requires: root OR CAP_NET_BIND_SERVICE capability (systemd service has this)
# - Custom port (e.g., 8889): Access via https://domain:8889, no special privileges
# Note: Without reverse proxy (Nginx/Apache), WakeStation binds directly to this port
WOL_SERVER_PORT = 9999

# Network Scanning
ARP_SCAN_TIMEOUT = 5  # Seconds

# =============================================================================
# SSL CONFIGURATION
# =============================================================================

# SSL/TLS Configuration
ENABLE_SSL = False  # Enable HTTPS (disable for HTTP-only)

# SSL Certificate Paths
# For development/testing with internal CA:
#   SSL_CERTFILE = "/path/to/cert.pem"
#   SSL_KEYFILE = "/path/to/key.pem"
#   SSL_CA_CERTS = "/path/to/cacert.pem"  # Optional: Internal CA certificate
#
# For production with Let's Encrypt:
#   SSL_CERTFILE = "/etc/letsencrypt/live/your-domain.com/fullchain.pem"
#   SSL_KEYFILE = "/etc/letsencrypt/live/your-domain.com/privkey.pem"
#   SSL_CA_CERTS = None  # Not needed for Let's Encrypt
SSL_CERTFILE = os.path.join(BASE_DIR, "certs", "cert.cert")  # Path to certificate file (fullchain.pem or cert.pem)
SSL_KEYFILE = os.path.join(BASE_DIR, "certs", "cert.key")   # Path to private key file (privkey.pem or key.pem)
SSL_CA_CERTS = os.path.join(BASE_DIR, "certs", "ca-cert.cert")  # Optional: Path to CA certificate bundle (for internal CA)

# =============================================================================
# DAEMON CONFIGURATION
# =============================================================================

# Daemon heartbeat timeout (300s = 5 minutes)
# Current: HTTP-based registration (reduce to 60s when switching to WebSocket)
DAEMON_HEARTBEAT_TIMEOUT = 300
DAEMON_REGISTRATION_TIMEOUT = 30
DAEMON_SHUTDOWN_PORT = "8080"

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================

# Application Secret Key
SECRET_KEY = "ANDREW86-HOME-WOL"

# JWT Token Expiration
ACCESS_TOKEN_EXPIRE_MINUTES = 15  # Access token lifetime
REFRESH_TOKEN_EXPIRE_DAYS = 7  # Refresh token lifetime (auto-refresh)

# JWT Cookie Settings (web UI only)
REMEMBER_COOKIE_SECURE = ENABLE_SSL  # Automatically set based on SSL configuration
REMEMBER_COOKIE_HTTPONLY = True
REMEMBER_COOKIE_SAMESITE = "Lax"

# Static File Cache
SEND_FILE_MAX_AGE_DEFAULT = 31536000  # 1 year