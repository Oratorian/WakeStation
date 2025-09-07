#!/usr/bin/env python3
"""!
********************************************************************************
@file   handler.py
@brief  Client connection handler for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import json
import socket
import platform
import subprocess
from typing import Dict, Any
from ..core import authenticate_user, decrypt_data, load_encryption_key
from ..utils import get_daemon_logger
from ..gui import update_last_request

log = get_daemon_logger("handler")


def handle_client_connection(
    client_socket, users: Dict[str, Any], dry_run: bool = False
):
    """Handle incoming client connection and process shutdown request."""
    try:
        # Receive data from client
        data = client_socket.recv(1024)
        if not data:
            return

        # Load encryption key
        encryption_key = load_encryption_key()
        if not encryption_key:
            log.error("No encryption key available")
            client_socket.send(b"ERROR: No encryption key available")
            return

        # The data comes as base64-encoded string, need to decode it first
        try:
            import base64

            # Strip newlines and decode from base64
            base64_data = data.decode("utf-8").strip()
            encrypted_bytes = base64.b64decode(base64_data)
        except Exception as e:
            log.error(f"Failed to decode base64 data: {e}")
            client_socket.send(b"ERROR: Invalid base64 data")
            return

        # Decrypt the received data
        decrypted_data = decrypt_data(encrypted_bytes, encryption_key)
        if not decrypted_data:
            log.error("Failed to decrypt data")
            client_socket.send(b"ERROR: Failed to decrypt data")
            return

        # Parse JSON data
        try:
            request_data = json.loads(decrypted_data)
        except json.JSONDecodeError as e:
            log.error(f"Invalid JSON data: {e}")
            client_socket.send(b"ERROR: Invalid JSON data")
            return

        # Extract credentials
        username = request_data.get("username")
        password = request_data.get("password")

        if not username or not password:
            log.warning("Missing username or password in request")
            client_socket.send(b"ERROR: Missing credentials")
            update_last_request(username or "unknown", False)
            return

        # Authenticate user
        if not authenticate_user(username, password, users):
            log.warning(f"Authentication failed for user: {username}")
            client_socket.send(b"ERROR: Authentication failed")
            update_last_request(username, False)
            return

        log.info(f"Authentication successful for user: {username}")

        # Process shutdown request
        if dry_run:
            log.info(f"DRY RUN: Would execute shutdown for user {username}")
            client_socket.send(b"OK: Dry run - shutdown command would be executed")
            update_last_request(username, True)
        else:
            success = execute_shutdown(username)
            if success:
                client_socket.send(b"OK: Shutdown initiated")
                update_last_request(username, True)
            else:
                client_socket.send(b"ERROR: Failed to initiate shutdown")
                update_last_request(username, False)

    except Exception as e:
        log.error(f"Error handling client connection: {e}")
        try:
            client_socket.send(b"ERROR: Internal server error")
        except:
            pass  # Client may have disconnected
    finally:
        client_socket.close()


def execute_shutdown(username: str) -> bool:
    """Execute system shutdown command."""
    try:
        system = platform.system()

        if system == "Windows":
            # Windows shutdown command
            subprocess.run(["shutdown", "/s", "/f", "/t", "10"], check=True)
            log.info(f"Windows shutdown initiated by user {username}")

        elif system == "Linux" or system == "Darwin":
            # Linux/macOS shutdown command
            subprocess.run(["sudo", "shutdown", "-h", "+1"], check=True)
            log.info(f"Linux/macOS shutdown initiated by user {username}")

        else:
            log.error(f"Unsupported operating system: {system}")
            return False

        return True

    except subprocess.CalledProcessError as e:
        log.error(f"Shutdown command failed: {e}")
        return False
    except Exception as e:
        log.error(f"Error executing shutdown: {e}")
        return False
