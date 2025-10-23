#!/usr/bin/env python3
"""!
********************************************************************************
@file   wol.py
@brief  Wake-on-LAN utilities using Python sockets (cross-platform)
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import socket
import sys
import os
import re

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from src import logger_config as logger

# Import normalize function only (validate is deprecated)
from .network import normalize_mac_address

log = logger.get_logger("WakeStation-WOL")


def validate_mac_for_wol(mac_address):
    """
    Validate MAC address format for Wake-on-LAN.
    Accepts: XX:XX:XX:XX:XX:XX, XX-XX-XX-XX-XX-XX, or XXXXXXXXXXXX

    Args:
        mac_address (str): MAC address to validate

    Returns:
        bool: True if valid MAC format, False otherwise
    """
    if not mac_address:
        return False

    # Remove common separators and check if we have 12 hex characters
    clean_mac = mac_address.replace(":", "").replace("-", "").upper()

    # Must be exactly 12 hexadecimal characters
    if len(clean_mac) != 12:
        return False

    # All characters must be valid hex
    return all(c in "0123456789ABCDEF" for c in clean_mac)


def send_wol_packet(mac_address, broadcast_ip="255.255.255.255", port=9):
    """
    Send Wake-on-LAN magic packet using Python socket library.
    Uses config.WOL_SERVER_HOST as the sending interface.

    Args:
        mac_address (str): MAC address in format AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF
        broadcast_ip (str): Broadcast address to send to (default: 255.255.255.255)
        port (int): UDP port to send to (default: 9)

    Returns:
        bool: True if packet was sent successfully, False otherwise
    """
    try:
        # Get WOL server host from config
        interface_ip = getattr(config, "WOL_SERVER_HOST", None)
        if not interface_ip:
            # Fallback to legacy WOL_INTERFACE for backward compatibility
            interface_ip = getattr(config, "WOL_INTERFACE", "0.0.0.0")

        log.debug(f"Using WOL server host: {interface_ip}")

        # Validate and normalize MAC address
        if not validate_mac_for_wol(mac_address):
            raise ValueError(f"Invalid MAC address format: {mac_address}")

        normalized_mac = normalize_mac_address(mac_address)
        mac_clean = normalized_mac.replace(":", "").upper()

        # Create magic packet (6 bytes of 0xFF + 16 repetitions of MAC)
        mac_bytes = bytes.fromhex(mac_clean)
        magic_packet = b"\xff" * 6 + mac_bytes * 16

        log.debug(f"Magic packet size: {len(magic_packet)} bytes")
        log.debug(f"MAC address: {normalized_mac} -> {mac_clean}")

        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        # Bind to specific WOL interface
        sock.bind((interface_ip, 0))
        log.debug(f"Bound to interface: {interface_ip}")

        # Send the magic packet
        target = (broadcast_ip, port)
        bytes_sent = sock.sendto(magic_packet, target)
        sock.close()

        log.info(
            f"WOL packet sent to {normalized_mac} via {interface_ip} -> {target} ({bytes_sent} bytes)"
        )
        return True

    except Exception as e:
        log.error(f"Failed to send WOL packet to {mac_address}: {e}")
        return False


def wake_device(mac_address, broadcast_ip=None):
    """
    Wake a device using Wake-on-LAN.
    Convenience wrapper for send_wol_packet with automatic broadcast detection.
    Compatible with old send_wol_signal API - returns dict with success/message.

    Args:
        mac_address (str): MAC address of device to wake
        broadcast_ip (str, optional): Specific broadcast address, auto-detected if None

    Returns:
        dict: {"success": bool, "message": str} - Compatible with web UI
    """
    try:
        # Auto-detect broadcast if not specified
        if not broadcast_ip:
            # Simple broadcast detection based on server host
            server_host = getattr(config, "WOL_SERVER_HOST", None)
            if server_host and server_host != "0.0.0.0":
                # Convert 10.0.1.13 to 10.0.1.255
                parts = server_host.split(".")
                if len(parts) == 4:
                    parts[3] = "255"  # Make it 10.0.1.255
                    broadcast_ip = ".".join(parts)
                else:
                    broadcast_ip = "255.255.255.255"
            else:
                broadcast_ip = "255.255.255.255"

        log.info(f"Waking device {mac_address} using broadcast {broadcast_ip}")
        success = send_wol_packet(mac_address, broadcast_ip)

        if success:
            return {"success": True, "message": f"Wake-up signal sent to {mac_address}"}
        else:
            return {
                "success": False,
                "message": f"Failed to send WOL signal to {mac_address}",
            }

    except Exception as e:
        log.error(f"Failed to wake device {mac_address}: {e}")
        return {"success": False, "message": f"WOL error: {str(e)}"}
