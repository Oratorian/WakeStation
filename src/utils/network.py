#!/usr/bin/env python3
"""!
********************************************************************************
@file   network.py
@brief  Network utility functions for WakeStation - simplified GUID-based version
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import socket
import re
import sys
import os
import uuid
import subprocess
import platform

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from src import logger_config as logger

log = logger.get_logger("WakeStation-NET")


def ping_host(ip, timeout=2):
    """Ping a host to check if it's online using system ping command"""
    log.debug(f"Pinging {ip} with timeout {timeout}s")
    try:
        # Use system ping command (cross-platform)
        system = platform.system().lower()
        if system == "windows":
            # Windows: ping -n 1 -w timeout_ms ip
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), ip]
        else:
            # Linux/macOS: ping -c 1 -W timeout ip
            cmd = ["ping", "-c", "1", "-W", str(timeout), ip]

        result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
        is_online = result.returncode == 0
        log.debug(f"Ping result for {ip}: {'online' if is_online else 'offline'}")
        return is_online

    except Exception as e:
        log.warning(f"Ping failed for {ip}: {e}")
        return False


def check_daemon_connection(daemon_guid, daemon_registry):
    """Check if a daemon with given GUID is connected and reachable"""
    if not daemon_guid or not daemon_registry:
        return False

    daemon_info = daemon_registry.get(daemon_guid)
    if not daemon_info:
        log.debug(f"Daemon {daemon_guid} not found in registry")
        return False

    # Check if daemon is marked as connected
    return daemon_info.get("connected", False)


def generate_daemon_guid():
    """Generate a unique GUID for daemon identification"""
    return str(uuid.uuid4())


def validate_daemon_guid(daemon_guid):
    """Validate GUID format"""
    if not daemon_guid:
        return False
    try:
        uuid.UUID(daemon_guid)
        return True
    except (ValueError, TypeError):
        log.debug(f"Invalid GUID format: {daemon_guid}")
        return False


def validate_hostname(hostname):
    """Check if hostname format is valid."""
    if not hostname:
        return False
    # Basic hostname validation
    if len(hostname) > 253:
        return False
    # Allow alphanumeric, hyphens, and dots
    return bool(re.match(r"^[a-zA-Z0-9.-]+$", hostname))


def check_daemon_by_guid(daemon_guid, daemon_registry):
    """Check if daemon with GUID is available"""
    if not validate_daemon_guid(daemon_guid):
        return False

    daemon_info = daemon_registry.get(daemon_guid)
    if not daemon_info:
        return False

    # Check connection status and last heartbeat/seen time
    import time
    from datetime import datetime, timedelta

    # Get timeout from config (default 60 seconds for WebSocket heartbeats)
    timeout_seconds = getattr(config, "DAEMON_HEARTBEAT_TIMEOUT", 60)

    # Try last_heartbeat first (for WebSocket), fall back to last_seen (for HTTP registration)
    last_time = daemon_info.get("last_heartbeat") or daemon_info.get("last_seen")
    if last_time:
        try:
            time_obj = datetime.fromisoformat(last_time)
            # Consider daemon available if within configured timeout
            return datetime.now() - time_obj < timedelta(seconds=timeout_seconds)
        except ValueError:
            pass

    # If no timestamp, check connected flag
    return daemon_info.get("connected", False)


def get_machine_identifier():
    """Get a unique identifier for this machine (hostname-based)"""
    try:
        return socket.gethostname().lower()
    except Exception as e:
        log.warning(f"Could not get hostname: {e}")
        return "unknown-host"


def get_server_endpoint():
    """Get the configured server endpoint for daemon communication"""
    try:
        server_host = getattr(config, "WOL_SERVER_HOST", "localhost")
        server_port = getattr(config, "WOL_SERVER_PORT", 8889)
        return f"{server_host}:{server_port}"
    except Exception as e:
        log.warning(f"Could not determine server endpoint: {e}")
        return "localhost:8889"


def get_daemon_registry_path():
    """Get the path to the daemon registry file"""
    import config
    return config.DAEMON_REGISTRY_FILE


def load_daemon_registry():
    """Load the daemon registry from file"""
    registry_path = get_daemon_registry_path()
    if not os.path.exists(registry_path):
        return {}

    try:
        import json

        with open(registry_path, "r") as f:
            return json.load(f)
    except Exception as e:
        log.error(f"Error loading daemon registry: {e}")
        return {}


def save_daemon_registry(daemon_registry):
    """Save the daemon registry to file"""
    registry_path = get_daemon_registry_path()
    try:
        import json

        os.makedirs(os.path.dirname(registry_path), exist_ok=True)
        with open(registry_path, "w") as f:
            json.dump(daemon_registry, f, indent=2)
    except Exception as e:
        log.error(f"Error saving daemon registry: {e}")


def register_daemon(daemon_guid, hostname, connection_info=None):
    """Register a daemon in the registry"""
    if not validate_daemon_guid(daemon_guid):
        raise ValueError(f"Invalid daemon GUID: {daemon_guid}")

    daemon_registry = load_daemon_registry()

    from datetime import datetime

    daemon_entry = {
        "guid": daemon_guid,
        "hostname": hostname,
        "last_seen": datetime.now().isoformat(),
        "connected": True,
        "connection_info": connection_info or {},
    }

    daemon_registry[daemon_guid] = daemon_entry
    save_daemon_registry(daemon_registry)

    log.info(f"Daemon registered: {daemon_guid} ({hostname})")


def resolve_pc_daemon(pc_data, daemon_registry=None):
    """
    Resolve the daemon GUID for a PC using hostname matching.

    Returns: (daemon_guid, daemon_info) or (None, None) if not found
    """
    hostname = pc_data.get("hostname", "Unknown").lower()
    daemon_guid = pc_data.get("daemon_guid")

    log.debug(f"Resolving daemon for PC {hostname}")

    if not daemon_registry:
        daemon_registry = load_daemon_registry()

    # Priority 1: Use stored daemon GUID if valid
    if daemon_guid and validate_daemon_guid(daemon_guid):
        daemon_info = daemon_registry.get(daemon_guid)
        if daemon_info and check_daemon_by_guid(daemon_guid, daemon_registry):
            log.info(f"Found daemon for {hostname}: {daemon_guid}")
            return daemon_guid, daemon_info

    # Priority 2: Search by hostname
    for guid, info in daemon_registry.items():
        daemon_hostname = info.get("hostname", "").lower()
        if daemon_hostname == hostname and check_daemon_by_guid(guid, daemon_registry):
            log.info(f"Matched daemon by hostname for {hostname}: {guid}")
            return guid, info

    # Priority 3: Check localhost
    try:
        local_hostname = socket.gethostname().lower()
        if hostname == local_hostname:
            log.info(f"Detected localhost: {hostname}")
            return "localhost", {"hostname": hostname, "connected": True}
    except Exception as e:
        log.debug(f"Localhost check failed for {hostname}: {e}")

    log.warning(f"Could not resolve daemon for PC {hostname}")
    return None, None


def update_daemon_heartbeat(daemon_guid):
    """Update the last heartbeat time for a daemon"""
    if not validate_daemon_guid(daemon_guid):
        return False

    daemon_registry = load_daemon_registry()
    if daemon_guid not in daemon_registry:
        return False

    from datetime import datetime

    daemon_registry[daemon_guid]["last_heartbeat"] = datetime.now().isoformat()
    daemon_registry[daemon_guid]["connected"] = True

    save_daemon_registry(daemon_registry)
    return True


def disconnect_daemon(daemon_guid):
    """Mark a daemon as disconnected"""
    if not validate_daemon_guid(daemon_guid):
        return False

    daemon_registry = load_daemon_registry()
    if daemon_guid not in daemon_registry:
        return False

    daemon_registry[daemon_guid]["connected"] = False
    save_daemon_registry(daemon_registry)
    return True


def get_connected_daemons():
    """Get list of currently connected daemons"""
    daemon_registry = load_daemon_registry()
    connected_daemons = {}

    for guid, info in daemon_registry.items():
        if check_daemon_by_guid(guid, daemon_registry):
            connected_daemons[guid] = info

    return connected_daemons


def find_daemon_by_hostname(hostname):
    """Find daemon GUID by hostname"""
    daemon_registry = load_daemon_registry()
    hostname_lower = hostname.lower()

    for guid, info in daemon_registry.items():
        daemon_hostname = info.get("hostname", "").lower()
        if daemon_hostname == hostname_lower and check_daemon_by_guid(
            guid, daemon_registry
        ):
            return guid

    return None


# Backward compatibility functions (deprecated - remove in future versions)
def validate_mac_address(mac):
    """Deprecated: MAC addresses no longer used for identification"""
    log.warning("validate_mac_address is deprecated - use GUID-based identification")
    return False


def normalize_mac_address(mac):
    """
    Normalize MAC address to standard format (XX:XX:XX:XX:XX:XX).
    Accepts various formats: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, XXXXXXXXXXXX
    """
    if not mac:
        return None

    # Remove all non-alphanumeric characters and convert to uppercase
    clean_mac = "".join(c for c in mac.upper() if c.isalnum())

    # Check if we have exactly 12 hex characters
    if len(clean_mac) != 12:
        return None

    try:
        # Validate that all characters are hex
        int(clean_mac, 16)
    except ValueError:
        return None

    # Format as XX:XX:XX:XX:XX:XX
    return ":".join(clean_mac[i : i + 2] for i in range(0, 12, 2))