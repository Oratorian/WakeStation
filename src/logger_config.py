#!/usr/bin/env python3
"""!
********************************************************************************
@file   logger_config.py
@brief  Centralized logger configuration using rsyslog-logger package
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

from rsyslog_logger import setup_logger
import config

# Cache of logger instances
_logger_cache = {}


def get_logger(name="WakeStation"):
    """
    Get or create a logger instance using the rsyslog-logger package.

    Args:
        name: Logger name (appears in rsyslog format logs)

    Returns:
        Logger instance configured with rsyslog formatting
    """
    if name in _logger_cache:
        return _logger_cache[name]

    # Create logger with configuration from config.py
    logger = setup_logger(
        name=name,
        log_file=config.LOG_FILE,
        log_level=config.LOG_LEVEL,
        log_format=config.LOG_FORMAT,
        console_log_level=config.CONSOLE_LOG_LEVEL,
        max_size=config.LOG_MAX_SIZE,
        backup_count=config.LOG_BACKUP_COUNT,
    )

    _logger_cache[name] = logger
    return logger
