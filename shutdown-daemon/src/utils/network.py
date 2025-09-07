#!/usr/bin/env python3
"""!
********************************************************************************
@file   network.py
@brief  Network utilities for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import socket
from .logger import get_daemon_logger

log = get_daemon_logger("network")


def get_local_ip() -> str:
    """Get the local IP address of this machine."""
    try:
        # Create a socket and connect to a remote address to get local IP
        # This doesn't actually send data, just determines the route
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Use Google DNS as target (doesn't actually connect)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception as e:
        log.warning(f"Could not determine local IP address: {e}")
        # Fallback to localhost
        return "127.0.0.1"
