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


def get_local_ip(target_ip: str = "8.8.8.8", target_port: int = 80) -> str:
    """
    Get the local IP address of this machine that would be used to reach a target.

    Args:
        target_ip: Target IP address to route to (defaults to Google DNS)
        target_port: Target port (defaults to 80)

    Returns:
        Local IP address that would be used for the route
    """
    try:
        # Create a socket and connect to the target address to get local IP
        # This doesn't actually send data, just determines the route
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((target_ip, target_port))
            local_ip = s.getsockname()[0]
            log.debug(f"Local IP for route to {target_ip}:{target_port} is {local_ip}")
            return local_ip
    except Exception as e:
        log.warning(f"Could not determine local IP address for {target_ip}:{target_port}: {e}")
        # Fallback to Google DNS method
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
                return local_ip
        except Exception:
            log.warning("All IP detection methods failed, falling back to localhost")
            return "127.0.0.1"
