#!/usr/bin/env python3
"""!
********************************************************************************
@file   process.py
@brief  Process management utilities for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import signal
import sys
import psutil
from ..config import PID_FILE
from .logger import get_daemon_logger

log = get_daemon_logger("process")


def check_if_daemon_running() -> bool:
    """Check if another instance of the daemon is already running."""
    if not os.path.exists(PID_FILE):
        return False

    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())

        # Check if process with this PID exists and is running
        if psutil.pid_exists(pid):
            try:
                proc = psutil.Process(pid)
                # Check if it's actually our daemon process
                if "shutdown_daemon" in proc.name() or "python" in proc.name():
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        # PID file exists but process is not running, clean it up
        remove_pid_file()
        return False

    except (ValueError, FileNotFoundError, PermissionError):
        # Invalid or inaccessible PID file
        remove_pid_file()
        return False


def create_pid_file() -> None:
    """Create PID file for this daemon instance."""
    try:
        with open(PID_FILE, "w") as f:
            f.write(str(os.getpid()))
        log.info(f"PID file created: {PID_FILE}")
    except Exception as e:
        log.warning(f"Could not create PID file: {e}")


def remove_pid_file() -> None:
    """Remove PID file when daemon exits."""
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
            log.info("PID file removed")
    except Exception as e:
        log.warning(f"Could not remove PID file: {e}")


def signal_handler(sig, frame):
    """Handle termination signals gracefully."""
    log.info(f"Received signal {sig}, shutting down...")
    remove_pid_file()
    sys.exit(0)


def setup_signal_handlers() -> None:
    """Set up signal handlers for graceful shutdown."""
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, signal_handler)

    log.debug("Signal handlers configured")
