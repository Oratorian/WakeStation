#!/usr/bin/env python3
"""
ARP Scanning utilities for MAC-to-IP resolution
Minimal implementation focused on finding IP addresses for known MAC addresses
"""

import platform
import subprocess
import sys
import os

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from src import logger_config as logger
from .network import normalize_mac_address

log = logger.get_logger("WakeStation-ARP")


def validate_ip_address(ip):
    """Simple IP address validation"""
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
    except:
        return False


def _detect_primary_interface():
    """
    Detect the primary network interface for arp-scan on Linux systems.
    Uses WOL_SERVER_HOST from config to determine the correct interface.
    """
    if platform.system().lower() != "linux":
        return None

    try:
        # Use WOL_SERVER_HOST to find the interface
        server_host = getattr(config, "WOL_SERVER_HOST", None)
        log.debug(f"Attempting interface detection for WOL_SERVER_HOST: {server_host}")

        if server_host and server_host not in ["0.0.0.0", "127.0.0.1"]:
            import re

            # Method 1: Try using 'ip addr show' and grep for the IP
            cmd = ["ip", "addr", "show"]
            log.debug(f"Running command: {' '.join(cmd)}")

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=3,
            )

            log.debug(f"Command returncode: {result.returncode}")

            if result.returncode == 0 and result.stdout.strip():
                # Look for the interface that has this IP assigned
                # Split output by interface sections
                current_interface = None
                for line in result.stdout.split('\n'):
                    # Match interface line: "2: br0: <BROADCAST,MULTICAST,UP,LOWER_UP> ..."
                    iface_match = re.match(r"^\d+:\s+(\S+):", line)
                    if iface_match:
                        current_interface = iface_match.group(1)
                        continue

                    # Check if current line contains our server IP
                    if current_interface and f"inet {server_host}/" in line:
                        log.info(f"Detected interface from WOL_SERVER_HOST: {current_interface}")
                        return current_interface

                log.warning(f"Could not find interface with IP {server_host}")

            # Method 2: Fallback - Try ip route show to find interface for local subnet
            log.debug("Trying fallback method with ip route show")
            # Extract network from IP (e.g., 10.0.1.13 -> 10.0.1.0)
            ip_parts = server_host.split('.')
            if len(ip_parts) == 4:
                network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
                cmd = ["ip", "route", "show", network]
                log.debug(f"Running command: {' '.join(cmd)}")

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=3,
                )

                if result.returncode == 0 and result.stdout.strip():
                    # Parse: "10.0.1.0/24 dev br0 proto kernel scope link src 10.0.1.13"
                    match = re.search(r"dev\s+(\S+)", result.stdout)
                    if match:
                        interface = match.group(1)
                        log.info(f"Detected interface from fallback method: {interface}")
                        return interface

    except Exception as e:
        log.error(f"Interface detection failed: {e}", exc_info=True)

    log.warning("Could not detect network interface from WOL_SERVER_HOST")
    return None


def get_local_network(ip=None):
    """Get local network CIDR for scanning"""
    if ip:
        # Convert server IP to network (e.g., 10.0.1.13 -> 10.0.1.0/24)
        parts = ip.split(".")
        if len(parts) == 4:
            network_parts = parts[:3] + ["0"]
            return ".".join(network_parts) + "/24"

    # Use config server host to determine network
    server_host = getattr(config, "WOL_SERVER_HOST", None)
    if server_host and server_host != "0.0.0.0":
        return get_local_network(server_host)

    # Fallback to common private networks
    return "192.168.1.0/24"


def arp_scan_network(network=None, timeout=None):
    """
    Use arp-scan to discover active devices on the network.
    Returns dict of {ip: mac} for online devices.
    """
    if timeout is None:
        timeout = getattr(config, "ARP_SCAN_TIMEOUT", 5)
    log.debug(
        f"Starting arp-scan on network: {network or 'auto-detect'} with timeout {timeout}s"
    )

    try:
        # Try different arp-scan commands in order of preference
        if platform.system().lower() == "windows":
            arp_commands = ["arp-scan.exe", ".\\arp-scan.exe", "arp-scan"]
        else:
            arp_commands = ["arp-scan", "arp-scan.exe"]

        cmd = None
        for arp_cmd in arp_commands:
            try:
                # Test if command exists
                result = subprocess.run(
                    [arp_cmd, "--help"], capture_output=True, timeout=2
                )
                if result.stdout or result.stderr:
                    cmd = [arp_cmd]
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        if not cmd:
            log.error("arp-scan command not found - network discovery will not work")
            return {}

        # Build arp-scan command
        if cmd[0] == "arp-scan.exe":
            # Windows arp-scan.exe syntax
            cmd.append("-t")
            if network:
                cmd.append(network)
            else:
                cmd.append(get_local_network())
        else:
            # Standard Linux arp-scan syntax
            cmd.extend(["--timeout", str(timeout * 1000)])
            cmd.extend(["--format", "${ip}\t${mac}"])

            # Auto-detect network interface for multi-NIC systems
            interface = _detect_primary_interface()
            if interface:
                cmd.extend(["--interface", interface])
                log.debug(f"Using detected interface: {interface}")

            if network:
                cmd.append(network)
            else:
                cmd.append(get_local_network())

        log.debug(f"Executing arp-scan command: {' '.join(cmd)}")

        # Execute arp-scan
        subprocess_timeout = max(timeout * 2, 15)
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=subprocess_timeout
        )

        log.debug(f"arp-scan completed with return code: {result.returncode}")

        if result.returncode <= 1 and result.stdout.strip():
            devices = {}
            log.debug(f"arp-scan raw output:\\n{result.stdout}")

            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if (
                    not line
                    or line.startswith("Interface:")
                    or line.startswith("Starting arp-scan")
                ):
                    continue

                # Check if this is Windows arp-scan.exe format: "Reply that [MAC] is [IP] in [time]"
                if line.startswith("Reply that "):
                    import re

                    # Parse: "Reply that 50:EB:F6:7C:1B:4B is 10.0.1.13 in 0.043500"
                    match = re.search(
                        r"Reply that ([0-9A-Fa-f:]{17}) is (\d+\.\d+\.\d+\.\d+) in",
                        line,
                    )
                    if match:
                        raw_mac = match.group(1)
                        ip = match.group(2)
                        mac = normalize_mac_address(raw_mac)
                        if validate_ip_address(ip) and mac:
                            devices[ip] = mac
                            log.debug(f"Parsed Windows arp-scan result: {ip} -> {mac}")
                    continue

                # Parse tab-separated format: IP\tMAC\tVendor (Linux format)
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    raw_mac = parts[1].strip()
                    mac = normalize_mac_address(raw_mac)
                    if validate_ip_address(ip) and mac:
                        devices[ip] = mac
                        log.debug(f"Parsed arp-scan result: {ip} -> {mac}")
                else:
                    # Fallback for space-separated format
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        raw_mac = parts[1].strip()
                        mac = normalize_mac_address(raw_mac)
                        if validate_ip_address(ip) and mac:
                            devices[ip] = mac
                            log.debug(
                                f"Parsed arp-scan result (fallback): {ip} -> {mac}"
                            )

            log.info(
                f"arp-scan found {len(devices)} devices on {network or 'local network'}"
            )
            return devices

    except (
        FileNotFoundError,
        subprocess.TimeoutExpired,
        subprocess.SubprocessError,
    ) as e:
        log.warning(f"arp-scan command failed: {e}")

    return {}


def find_device_by_mac(target_mac, networks=None):
    """
    Find IP address for a specific MAC address using ARP scanning.
    Returns IP if device is online, None if offline or not found.

    Args:
        target_mac (str): MAC address to find (any format)
        networks (list, optional): Specific networks to scan, auto-detect if None

    Returns:
        str|None: IP address if found, None otherwise
    """
    target_mac = normalize_mac_address(target_mac)
    if not target_mac:
        log.warning(f"Invalid MAC address format: {target_mac}")
        return None

    log.info(f"Searching for MAC address: {target_mac}")

    if networks:
        # Scan specific networks
        for network in networks:
            log.debug(f"Scanning network {network} for MAC {target_mac}")
            devices = arp_scan_network(network)
            for ip, mac in devices.items():
                if mac == target_mac:
                    log.info(f"Found MAC {target_mac} at IP {ip}")
                    return ip
    else:
        # Scan local network
        log.debug(f"Scanning local network for MAC {target_mac}")
        devices = arp_scan_network()
        for ip, mac in devices.items():
            if mac == target_mac:
                log.info(f"Found MAC {target_mac} at IP {ip}")
                return ip

    log.info(f"MAC address {target_mac} not found on network")
    return None


def resolve_ip_for_pc(pc_data):
    """
    Convenience function to resolve IP for a PC entry using its MAC address.

    Args:
        pc_data (dict): PC entry with 'mac' field

    Returns:
        str|None: IP address if found, None otherwise
    """
    mac = pc_data.get("mac")
    if not mac:
        return None

    return find_device_by_mac(mac)
