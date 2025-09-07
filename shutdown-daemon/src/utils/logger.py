#!/usr/bin/env python3
"""!
********************************************************************************
@file   logger.py
@brief  Logging utilities for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import sys
import os
from datetime import datetime
from ..config import LOG_FILE_PATH


def get_daemon_logger(name="shutdown_daemon"):
    """Get logger for shutdown daemon components."""
    return DaemonLogger(name)


class DaemonLogger:
    """Simple logger for shutdown daemon."""

    def __init__(self, name):
        self.name = name

    def info(self, msg):
        self._write_log(f"INFO: {msg}")

    def debug(self, msg):
        self._write_log(f"DEBUG: {msg}")

    def warning(self, msg):
        self._write_log(f"WARNING: {msg}")

    def error(self, msg):
        self._write_log(f"ERROR: {msg}")

    def critical(self, msg):
        self._write_log(f"CRITICAL: {msg}")

    def _write_log(self, message):
        """Write log message to file and console."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"{timestamp} - {message}"

        try:
            with open(LOG_FILE_PATH, "a") as log_file:
                log_file.write(log_message + "\n")
        except Exception:
            pass  # Ignore file write errors

        # Print to console only if we're not in a windowed PyInstaller environment
        import sys
        import io

        # Don't print if:
        # 1. stdout has been redirected to StringIO (GUI mode)
        # 2. We're in a PyInstaller windowed executable (frozen without console)
        windowed_executable = (
            getattr(sys, "frozen", False)
            and not hasattr(sys, "ps1")  # Not interactive
            and (
                not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty()
            )  # No real console
        )

        if not isinstance(sys.stdout, io.StringIO) and not windowed_executable:
            try:
                print(log_message)
            except (OSError, IOError):
                pass  # Ignore output errors in case of issues


# Legacy compatibility function
def write_log(message):
    """Legacy logging function for backward compatibility."""
    logger = get_daemon_logger()
    logger.info(message)
