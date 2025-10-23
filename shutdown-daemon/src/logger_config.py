#!/usr/bin/env python3
"""!
********************************************************************************
@file   logger_config.py
@brief  Centralized logging configuration using rsyslog-logger
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import sys
from rsyslog_logger import setup_logger
from .config import LOG_FILE_PATH, LOG_DIR

# Ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# Log level (DEBUG for development, INFO for production)
LOG_LEVEL = "DEBUG"

# Console log level (DEBUG for development, INFO for production, None to disable)
CONSOLE_LOG_LEVEL = "DEBUG"

# Log format (rsyslog style)
LOG_FORMAT = "rsyslog"

# Maximum log file size in MB
LOG_MAX_SIZE = 10

# Number of backup log files to keep
LOG_BACKUP_COUNT = 5

# Cache of logger instances
_logger_cache = {}


def get_daemon_logger(name: str):
    """
    Get a configured logger instance for a daemon component.

    Args:
        name: Logger name (e.g., "shutdown_daemon", "crypto", "network")

    Returns:
        Configured logger instance with rsyslog formatting
    """
    # Create logger with rsyslog-style naming
    logger_name = f"ShutdownDaemon-{name.upper()}"

    # Return cached logger if available
    if logger_name in _logger_cache:
        return _logger_cache[logger_name]

    # Determine if we're in a windowed PyInstaller executable (no console)
    windowed_executable = (
        getattr(sys, "frozen", False)
        and not hasattr(sys, "ps1")  # Not interactive
        and (not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty())  # No real console
    )

    # Use CRITICAL level for console in windowed mode to minimize output
    # (effectively disabling console since we rarely have CRITICAL logs)
    console_level = CONSOLE_LOG_LEVEL if not windowed_executable else "CRITICAL"

    logger = setup_logger(
        name=logger_name,
        log_file=LOG_FILE_PATH,
        log_level=LOG_LEVEL,
        log_format=LOG_FORMAT,
        console_log_level=console_level,
        max_size=LOG_MAX_SIZE,
        backup_count=LOG_BACKUP_COUNT,
    )

    # Cache the logger
    _logger_cache[logger_name] = logger

    return logger
