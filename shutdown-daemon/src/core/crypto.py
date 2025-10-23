#!/usr/bin/env python3
"""!
********************************************************************************
@file   crypto.py
@brief  Cryptographic utilities for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import sys
import hmac
import hashlib
import base64
import requests
import uuid
import time
import asyncio
from datetime import datetime, timezone
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from ..config import APP_DATA_PATH, DAEMON_GUID_FILE
from ..utils import get_daemon_logger, get_local_ip

log = get_daemon_logger("crypto")

# File path for encryption key
ENCRYPTION_KEY_FILE = os.path.join(APP_DATA_PATH, "encryption.key")


def get_or_create_daemon_guid() -> str:
    """
    Get existing daemon GUID or create a new one.
    The GUID persists across daemon restarts and identifies this daemon uniquely.

    Returns:
        str: The daemon GUID (UUID4 format)
    """
    try:
        # Try to load existing GUID
        if os.path.exists(DAEMON_GUID_FILE):
            with open(DAEMON_GUID_FILE, "r") as f:
                guid = f.read().strip()
                if guid and len(guid) == 36:  # Valid UUID4 length
                    log.debug(f"Loaded existing daemon GUID: {guid}")
                    return guid
                else:
                    log.warning(f"Invalid GUID in file, generating new one")

        # Generate new GUID
        new_guid = str(uuid.uuid4())

        # Save to file
        with open(DAEMON_GUID_FILE, "w") as f:
            f.write(new_guid)

        log.info(f"Generated new daemon GUID: {new_guid}")
        return new_guid

    except Exception as e:
        log.error(f"Error managing daemon GUID: {e}")
        # Return a temporary GUID based on MAC address as fallback
        fallback_guid = str(
            uuid.uuid5(uuid.NAMESPACE_DNS, get_mac_address() or "unknown")
        )
        log.warning(f"Using fallback GUID: {fallback_guid}")
        return fallback_guid


def get_daemon_hostname() -> str:
    """
    Get the hostname of this machine.

    Returns:
        str: The hostname of this daemon
    """
    try:
        import socket

        hostname = socket.gethostname()
        log.debug(f"Detected hostname: {hostname}")
        return hostname
    except Exception as e:
        log.error(f"Error getting hostname: {e}")
        return "unknown-host"


def get_mac_address(bind_ip: str = None) -> Optional[str]:
    """Get the MAC address of the network interface, optionally for a specific bind IP."""
    try:
        import platform
        import subprocess

        system = platform.system().lower()

        if system == "windows":
            # Use PowerShell Get-NetIPConfiguration for reliable MAC detection
            if bind_ip and bind_ip != "0.0.0.0":
                # Find MAC for specific IP address
                ps_command = (
                    f"Get-NetIPConfiguration | "
                    f"Where-Object {{$_.IPv4Address.IPAddress -eq '{bind_ip}'}} | "
                    f"Select-Object -ExpandProperty NetAdapter | "
                    f"Select-Object -ExpandProperty MacAddress"
                )
            else:
                # Get MAC of first active interface with IPv4
                ps_command = (
                    "Get-NetIPConfiguration | "
                    "Where-Object {$_.IPv4Address -and $_.NetAdapter.MacAddress} | "
                    "Select-Object -First 1 -ExpandProperty NetAdapter | "
                    "Select-Object -ExpandProperty MacAddress"
                )

            result = subprocess.run(
                ["powershell", "-Command", ps_command],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if system == "windows" else 0,
            )
            if result.returncode == 0 and result.stdout.strip():
                mac_raw = result.stdout.strip()
                # Convert from Windows format (XX-XX-XX-XX-XX-XX) to standard format (xx:xx:xx:xx:xx:xx)
                if len(mac_raw) == 17 and "-" in mac_raw:
                    mac_formatted = mac_raw.replace("-", ":").lower()
                    return mac_formatted
        else:
            # Linux/macOS - try PowerShell first, then fall back to ip command

            # First try PowerShell (pwsh or powershell) if available
            for ps_cmd in ["pwsh", "powershell"]:
                try:
                    if bind_ip and bind_ip != "0.0.0.0":
                        # Find MAC for specific IP address using PowerShell
                        ps_command = (
                            f"Get-NetIPConfiguration | "
                            f"Where-Object {{$_.IPv4Address.IPAddress -eq '{bind_ip}'}} | "
                            f"Select-Object -ExpandProperty NetAdapter | "
                            f"Select-Object -ExpandProperty MacAddress"
                        )
                    else:
                        # Get MAC of first active interface with IPv4
                        ps_command = (
                            "Get-NetIPConfiguration | "
                            "Where-Object {$_.IPv4Address -and $_.NetAdapter.MacAddress} | "
                            "Select-Object -First 1 -ExpandProperty NetAdapter | "
                            "Select-Object -ExpandProperty MacAddress"
                        )

                    result = subprocess.run(
                        [ps_cmd, "-Command", ps_command],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0 and result.stdout.strip():
                        mac_raw = result.stdout.strip()
                        # Convert from format XX-XX-XX-XX-XX-XX to xx:xx:xx:xx:xx:xx
                        if len(mac_raw) == 17 and "-" in mac_raw:
                            mac_formatted = mac_raw.replace("-", ":").lower()
                            return mac_formatted
                        elif len(mac_raw) == 17 and ":" in mac_raw:
                            return mac_raw.lower()

                except (FileNotFoundError, subprocess.TimeoutExpired):
                    continue  # Try next PowerShell command or fall back to ip

            # Fall back to ip command if PowerShell not available
            try:
                if bind_ip and bind_ip != "0.0.0.0" and bind_ip != "127.0.0.1":
                    # Find interface name for specific IP, then get its MAC
                    ip_result = subprocess.run(
                        ["ip", "addr", "show"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if ip_result.returncode == 0:
                        import re

                        lines = ip_result.stdout.split("\n")
                        interface_name = None

                        # Find interface with the specific IP
                        for i, line in enumerate(lines):
                            if f"inet {bind_ip}/" in line:
                                # Look backward to find interface name
                                for j in range(i - 1, -1, -1):
                                    match = re.match(r"^\d+:\s+(\w+):", lines[j])
                                    if match:
                                        interface_name = match.group(1)
                                        break
                                break

                        if interface_name:
                            # Get MAC for specific interface
                            mac_result = subprocess.run(
                                ["cat", f"/sys/class/net/{interface_name}/address"],
                                capture_output=True,
                                text=True,
                                timeout=5,
                            )
                            if mac_result.returncode == 0:
                                return mac_result.stdout.strip().lower()
                else:
                    # Get MAC of first active non-loopback interface
                    result = subprocess.run(
                        ["ip", "link", "show"],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if result.returncode == 0:
                        import re

                        # Look for the first non-loopback interface with a MAC
                        for line in result.stdout.split("\n"):
                            if "link/ether" in line and "LOOPBACK" not in line:
                                match = re.search(r"link/ether\s+([0-9a-f:]{17})", line)
                                if match:
                                    return match.group(1).lower()
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Fallback to uuid.getnode() if platform-specific methods fail
        mac_int = uuid.getnode()
        mac_hex = f"{mac_int:012x}"
        mac_formatted = ":".join([mac_hex[i : i + 2] for i in range(0, 12, 2)])
        return mac_formatted

    except Exception as e:
        log.error(f"Error getting MAC address: {e}")
        return None


def decrypt_data(encrypted_data: bytes, key: bytes) -> Optional[str]:
    """Decrypt AES encrypted data."""
    try:
        # Extract IV and encrypted content
        iv = encrypted_data[:16]
        encrypted_content = encrypted_data[16:]

        # Create cipher
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt and unpad
        decrypted_padded = decryptor.update(encrypted_content) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        decrypted_data = unpadder.update(decrypted_padded) + unpadder.finalize()

        return decrypted_data.decode("utf-8")
    except Exception as e:
        log.error(f"Decryption failed: {e}")
        return None


def sync_encryption_key(
    wol_server_ip: str,
    wol_server_port: int,
    daemon_port: int = 8080,
    bind_ip: str = None,
    max_retries: int = 5,
    initial_delay: float = 1.0,
) -> bool:
    """Sync encryption key with WakeStation server and register daemon with GUID-based identification."""
    # Get or create persistent GUID for this daemon
    daemon_guid = get_or_create_daemon_guid()
    daemon_hostname = get_daemon_hostname()

    # Use provided bind IP or auto-detect local IP
    if bind_ip and bind_ip != "0.0.0.0":
        daemon_ip = bind_ip
    else:
        daemon_ip = get_local_ip()

    # Get MAC address in background to avoid blocking startup
    daemon_mac = None
    try:
        # Determine the actual IP address used to communicate with the WakeStation server
        # This is the real interface we need the MAC address for
        actual_ip = get_local_ip(wol_server_ip, wol_server_port)

        if actual_ip:
            log.debug(f"Detected actual interface IP: {actual_ip}")
            # Get MAC address for the actual interface being used (with no console window)
            try:
                daemon_mac = get_mac_address(actual_ip)
                log.debug(f"Detected MAC address: {daemon_mac}")
            except Exception as mac_error:
                log.warning(f"MAC detection failed: {mac_error}")
                daemon_mac = None
        else:
            log.warning("Could not determine actual interface IP")
            daemon_mac = None
    except Exception as e:
        log.warning(f"MAC address detection failed: {e}")
        daemon_mac = None

    # Prepare request headers (no HMAC needed for key exchange)
    headers = {
        "Content-Type": "application/json",
    }

    # New GUID-based registration payload
    json_body = {
        "daemon_guid": daemon_guid,
        "hostname": daemon_hostname,
        "daemon_port": daemon_port,
        # Include IP and MAC for backward compatibility and connection info
        "connection_info": {
            "ip": daemon_ip,
            "port": daemon_port,
            "mac": daemon_mac,
        },
    }

    wol_url = f"http://{wol_server_ip}:{wol_server_port}/api/sync_encryption_key"

    # Retry logic with exponential backoff
    for attempt in range(max_retries):
        try:
            if attempt == 0:
                log.info(
                    f"Registering daemon '{daemon_hostname}' (GUID: {daemon_guid[:8]}...) with WakeStation server"
                )
            else:
                delay = initial_delay * (2 ** (attempt - 1))
                log.info(
                    f"Retrying connection to WakeStation server (attempt {attempt + 1}/{max_retries}) in {delay:.1f}s"
                )
                time.sleep(delay)

            # Make request to WakeStation server with timeout
            response = requests.post(
                wol_url,
                headers=headers,
                json=json_body,
                timeout=10,  # 10 second timeout
            )
            response_data = response.json()

            if response.status_code == 200 and response_data.get("success"):
                encryption_key = response_data.get("encryption_key")
                if encryption_key:
                    # Decode and save the encryption key
                    key_bytes = base64.b64decode(encryption_key)
                    with open(ENCRYPTION_KEY_FILE, "wb") as key_file:
                        key_file.write(key_bytes)
                    log.info(
                        "Encryption key synced successfully with WakeStation server."
                    )
                    return True
                else:
                    log.error("No encryption key received from server.")
                    break  # Don't retry if server responds but without key
            else:
                log.warning(
                    f"Server responded with error (attempt {attempt + 1}): {response_data.get('message', 'Unknown error')}"
                )
                # Continue retrying for server errors

        except requests.exceptions.ConnectionError as e:
            log.warning(f"Connection failed (attempt {attempt + 1}/{max_retries}): {e}")
        except requests.exceptions.Timeout as e:
            log.warning(f"Request timeout (attempt {attempt + 1}/{max_retries}): {e}")
        except Exception as e:
            log.warning(f"Unexpected error (attempt {attempt + 1}/{max_retries}): {e}")

        # If this was the last attempt, log final failure
        if attempt == max_retries - 1:
            log.error(
                f"Failed to sync encryption key after {max_retries} attempts. "
                f"Daemon will continue running but may not receive shutdown commands."
            )

    return False


def load_encryption_key() -> Optional[bytes]:
    """Load encryption key from file."""
    try:
        with open(ENCRYPTION_KEY_FILE, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        log.warning("Encryption key file not found.")
        return None
    except Exception as e:
        log.error(f"Error loading encryption key: {e}")
        return None
