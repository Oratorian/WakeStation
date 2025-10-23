#!/usr/bin/env python3
"""!
********************************************************************************
@file   workers.py
@brief  Background worker functions for Wake-on-LAN and shutdown operations
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import subprocess
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from . import user
from src import logger_config as logger

log = logger.get_logger("WakeStation-WORKER")


def _shutdown_localhost(username, password):
    """Handle shutdown for localhost (same machine)"""
    try:
        # Verify credentials for localhost shutdown
        if not _verify_localhost_credentials(username, password):
            return {
                "success": False,
                "message": "Invalid credentials for localhost shutdown",
            }

        log.info("Executing localhost shutdown")

        # Execute shutdown command based on platform
        import platform

        system = platform.system().lower()

        if system == "windows":
            cmd = [
                "shutdown",
                "/s",
                "/t",
                "5",
                "/c",
                "Shutdown requested via WakeStation",
            ]
        else:
            cmd = ["sudo", "shutdown", "-h", "+1", "Shutdown requested via WakeStation"]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            return {"success": True, "message": "Localhost shutdown initiated"}
        else:
            return {"success": False, "message": f"Shutdown failed: {result.stderr}"}

    except Exception as e:
        log.error(f"Exception during localhost shutdown: {e}")
        return {"success": False, "message": "Internal server error"}


def _shutdown_localhost_encrypted(encrypted_payload):
    """Handle encrypted shutdown for localhost"""
    try:
        # Decrypt the payload
        encryption_key = user.User.load_key()
        decrypted_data = user.User.decrypt_data(encrypted_payload, encryption_key)

        import json

        data_dict = json.loads(decrypted_data)

        username = data_dict.get("username")
        password = data_dict.get("password")

        return _shutdown_localhost(username, password)

    except Exception as e:
        log.error(f"Exception during encrypted localhost shutdown: {e}")
        return {
            "success": False,
            "message": "Failed to decrypt or execute localhost shutdown",
        }


def _verify_localhost_credentials(username, password):
    """Verify credentials for localhost operations"""
    try:
        # Use the same authentication system as web login
        authenticated_user = user.User.authenticate(username, password)
        return authenticated_user is not None
    except Exception as e:
        log.error(f"Credential verification failed: {e}")
        return False


# Backward compatibility functions (deprecated)
def send_shutdown_command(pc_ip, username, password):
    """Deprecated: Use send_shutdown_command_by_guid instead"""
    log.warning(
        "send_shutdown_command is deprecated - use send_shutdown_command_by_guid"
    )
    return {"success": False, "message": "IP-based shutdown is deprecated"}


def send_encrypted_shutdown_command(pc_ip, encrypted_payload):
    """Deprecated: Use send_encrypted_shutdown_command_by_guid instead"""
    log.warning(
        "send_encrypted_shutdown_command is deprecated - use send_encrypted_shutdown_command_by_guid"
    )
    return {"success": False, "message": "IP-based shutdown is deprecated"}


def send_shutdown_command_by_guid(daemon_guid, username, password):
    """Send shutdown command to daemon via GUID-based communication"""
    try:
        from ..utils.network import load_daemon_registry, check_daemon_by_guid

        # Special handling for localhost
        if daemon_guid == "localhost":
            return _shutdown_localhost(username, password)

        # Load daemon registry to find connection info
        daemon_registry = load_daemon_registry()
        daemon_info = daemon_registry.get(daemon_guid)

        if not daemon_info:
            log.error(f"Daemon {daemon_guid} not found in registry")
            return {"success": False, "message": "Daemon not found"}

        if not check_daemon_by_guid(daemon_guid, daemon_registry):
            log.error(f"Daemon {daemon_guid} is not available")
            return {"success": False, "message": "Daemon not available"}

        # Send data as JSON format expected by daemon
        import json

        data_dict = {
            "username": username.strip(),
            "password": password.strip(),
            "action": "shutdown",
            "daemon_guid": daemon_guid,
        }
        combined_data = json.dumps(data_dict)

        encryption_key = user.User.load_key()
        encrypted_data = user.User.encrypt_data(combined_data, encryption_key)

        log.debug(f"Sending encrypted shutdown command to daemon {daemon_guid}")

        # TODO: Replace with WebSocket communication in future
        # For now, use connection info from registry (backward compatibility)
        connection_info = daemon_info.get("connection_info", {})
        daemon_ip = connection_info.get("ip")
        daemon_port = connection_info.get("port", config.DAEMON_SHUTDOWN_PORT)

        if not daemon_ip:
            log.error(f"No connection info available for daemon {daemon_guid}")
            return {"success": False, "message": "No connection info available"}

        # Send data directly to nc via stdin
        result = subprocess.run(
            ["nc", daemon_ip, str(daemon_port)],
            input=encrypted_data + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            output = result.stdout.strip()
            log.debug(f"Shutdown daemon response from {daemon_guid}: {output}")

            if "Error" in output or "Invalid" in output:
                log.warning(f"Shutdown command failed for {daemon_guid}: {output}")
                return {"success": False, "message": output}

            log.info(f"Shutdown command sent successfully to {daemon_guid}")
            return {"success": True, "message": output}
        else:
            log.error(f"Shutdown command failed for {daemon_guid}: {result.stderr}")
            return {
                "success": False,
                "message": f"Failed to send shutdown command: {result.stderr}",
            }
    except Exception as e:
        log.error(f"Exception sending shutdown command to {daemon_guid}: {e}")
        return {"success": False, "message": "Internal server error"}


def send_encrypted_shutdown_command_by_guid(daemon_guid, encrypted_payload):
    """Send pre-encrypted shutdown command to daemon via GUID"""
    try:
        from ..utils.network import load_daemon_registry, check_daemon_by_guid

        # Special handling for localhost
        if daemon_guid == "localhost":
            # For localhost, decode the payload and execute locally
            return _shutdown_localhost_encrypted(encrypted_payload)

        # Load daemon registry to find connection info
        daemon_registry = load_daemon_registry()
        daemon_info = daemon_registry.get(daemon_guid)

        if not daemon_info:
            log.error(f"Daemon {daemon_guid} not found in registry")
            return {"success": False, "message": "Daemon not found"}

        if not check_daemon_by_guid(daemon_guid, daemon_registry):
            log.error(f"Daemon {daemon_guid} is not available")
            return {"success": False, "message": "Daemon not available"}

        log.debug(f"Sending pre-encrypted shutdown command to daemon {daemon_guid}")

        # TODO: Replace with WebSocket communication in future
        # For now, use connection info from registry (backward compatibility)
        connection_info = daemon_info.get("connection_info", {})
        daemon_ip = connection_info.get("ip")
        daemon_port = connection_info.get("port", config.DAEMON_SHUTDOWN_PORT)

        if not daemon_ip:
            log.error(f"No connection info available for daemon {daemon_guid}")
            return {"success": False, "message": "No connection info available"}

        # Send the already encrypted data directly to nc via stdin
        result = subprocess.run(
            ["nc", daemon_ip, str(daemon_port)],
            input=encrypted_payload + "\n",
            capture_output=True,
            text=True,
            timeout=10,
        )

        if result.returncode == 0:
            output = result.stdout.strip()
            log.debug(f"Shutdown daemon response from {daemon_guid}: {output}")

            if "Error" in output or "Invalid" in output:
                log.warning(f"Shutdown command failed for {daemon_guid}: {output}")
                return {"success": False, "message": output}

            log.info(
                f"Pre-encrypted shutdown command sent successfully to {daemon_guid}"
            )
            return {"success": True, "message": output}
        else:
            log.error(f"Shutdown command failed for {daemon_guid}: {result.stderr}")
            return {
                "success": False,
                "message": f"Failed to send shutdown command: {result.stderr}",
            }
    except Exception as e:
        log.error(
            f"Exception sending pre-encrypted shutdown command to {daemon_guid}: {e}"
        )
        return {"success": False, "message": "Internal server error"}
