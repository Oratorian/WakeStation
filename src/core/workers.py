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
from ..logger import logger

log = logger.get_logger("workers")


def send_shutdown_command(pc_ip, username, password):
    """Send shutdown command to remote PC via daemon"""
    try:
        # Send data as JSON format expected by daemon
        import json

        data_dict = {
            "username": username.strip(),
            "password": password.strip(),
            "action": "shutdown",
        }
        combined_data = json.dumps(data_dict)

        encryption_key = user.User.load_key()
        encrypted_data = user.User.encrypt_data(combined_data, encryption_key)

        # Use subprocess.run with input parameter to avoid shell interpretation issues
        log.debug(
            f"Sending encrypted shutdown command to {pc_ip}:{config.SHUTDOWN_DAEMON_PORT}"
        )

        # Send data directly to nc via stdin instead of using echo
        result = subprocess.run(
            ["nc", pc_ip, str(config.SHUTDOWN_DAEMON_PORT)],
            input=encrypted_data + "\n",  # Add newline for proper transmission
            capture_output=True,
            text=True,
            timeout=10,  # Add timeout to prevent hanging
        )

        if result.returncode == 0:
            output = result.stdout.strip()
            log.debug(f"Shutdown daemon response from {pc_ip}: {output}")

            if "Error" in output or "Invalid" in output:
                log.warning(f"Shutdown command failed for {pc_ip}: {output}")
                return {"success": False, "message": output}

            log.info(f"Shutdown command sent successfully to {pc_ip}")
            return {"success": True, "message": output}
        else:
            log.error(f"Shutdown command failed for {pc_ip}: {result.stderr}")
            return {
                "success": False,
                "message": f"Failed to send shutdown command: {result.stderr}",
            }
    except Exception as e:
        log.error(f"Exception sending shutdown command to {pc_ip}: {e}")
        return {"success": False, "message": "Internal server error"}
