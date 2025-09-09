#!/usr/bin/env python3
"""!
********************************************************************************
@brief  Network utility functions for WakeStation - ping, MAC validation, daemon checks

@file   network.py
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import socket
import re
import sys
import os
import subprocess
import platform

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from ..logger import logger

log = logger.get_logger("network")


def ping_host(ip, timeout=2):
    """Ping a host to check if it's online using system ping command"""
    log.debug(f"Pinging {ip} with timeout {timeout}s")
    try:
        import subprocess
        import platform

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


def normalize_mac_address(mac):
    """Normalize MAC address to standard format (lowercase with colons)"""
    if not mac:
        return None
    # Remove separators and convert to lowercase
    clean_mac = mac.replace(":", "").replace("-", "").lower()
    # Add colons every 2 characters
    if len(clean_mac) == 12:
        return ":".join([clean_mac[i : i + 2] for i in range(0, 12, 2)])
    return None


def validate_mac_address(mac):
    """Validate MAC address format"""
    normalized = normalize_mac_address(mac)
    if not normalized:
        log.debug(f"Invalid MAC address format: {mac}")
        return False
    return True


def validate_ip_address(ip):
    """Check if IP address format is valid."""
    try:
        import ipaddress

        ipaddress.ip_address(ip)
        return True
    except (ValueError, ImportError):
        return False


def check_shutdown_daemon(ip, timeout=3):
    """Check if shutdown daemon is running on the specified IP"""
    log.debug(f"Checking shutdown daemon on {ip}:{config.SHUTDOWN_DAEMON_PORT}")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, config.SHUTDOWN_DAEMON_PORT))
        sock.close()
        daemon_available = result == 0
        log.debug(
            f"Shutdown daemon on {ip}: {'available' if daemon_available else 'unavailable'}"
        )
        return daemon_available
    except Exception as e:
        log.debug(f"Exception checking daemon on {ip}: {e}")
        return False


def get_machine_interfaces():
    """Get all network interfaces that actually belong to this machine using proper methods"""
    interfaces = []

    # Method 1: Use socket.getaddrinfo with hostname
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ["127.0.0.1", "0.0.0.0"] and ip not in interfaces:
                interfaces.append(ip)
    except Exception:
        pass

    # Method 2: Platform-specific interface enumeration
    try:
        if platform.system().lower() == "windows":
            # Windows: Use ipconfig parsing
            result = subprocess.run(
                ["ipconfig"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                import re

                # Look for IPv4 addresses that aren't loopback
                ip_pattern = r"IPv4.*?:\s*(\d+\.\d+\.\d+\.\d+)"
                for match in re.finditer(ip_pattern, result.stdout):
                    ip = match.group(1)
                    if ip not in ["127.0.0.1", "0.0.0.0"] and ip not in interfaces:
                        interfaces.append(ip)
        else:
            # Linux/Unix: Use 'ip a | grep WOL_INTERFACE' for direct lookup
            try:
                result = subprocess.run(
                    f"ip a | grep 'inet {config.WOL_INTERFACE}/'",
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    import re

                    # Look for inet lines: "inet 10.0.1.2/24 brd 10.0.1.255 scope global br0"
                    ip_pattern = r"inet (\d+\.\d+\.\d+\.\d+)/"
                    for match in re.finditer(ip_pattern, result.stdout):
                        ip = match.group(1)
                        if ip not in ["127.0.0.1", "0.0.0.0"] and ip not in interfaces:
                            interfaces.append(ip)
            except:
                # Fallback to hostname -I
                try:
                    result = subprocess.run(
                        ["hostname", "-I"], capture_output=True, text=True, timeout=5
                    )
                    if result.returncode == 0:
                        for ip in result.stdout.split():
                            if (
                                validate_ip_address(ip)
                                and ip not in ["127.0.0.1", "0.0.0.0"]
                                and ip not in interfaces
                            ):
                                interfaces.append(ip)
                except:
                    pass
    except Exception:
        pass

    return interfaces


def get_wol_interface():
    """Get the configured WOL interface IP, with validation that it belongs to us"""
    wol_interface = getattr(config, "WOL_INTERFACE", None)

    if not wol_interface:
        raise ValueError(
            "WOL_INTERFACE not configured. Please set a specific interface IP."
        )

    # Disallow problematic addresses
    if wol_interface in ["0.0.0.0", "127.0.0.1", "localhost"]:
        raise ValueError(
            f"Invalid WOL_INTERFACE '{wol_interface}'. Use a specific network interface IP."
        )

    # Validate IP format
    if not validate_ip_address(wol_interface):
        raise ValueError(f"Invalid WOL_INTERFACE IP format: {wol_interface}")

    # Critical check: Verify this IP actually belongs to this machine
    # Use direct OS query for validation
    if platform.system().lower() == "windows":
        # Windows: socket.bind() is most reliable
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((wol_interface, 0))
            sock.close()
            log.debug(f"Verified WOL_INTERFACE {wol_interface} belongs to this machine")
        except (socket.error, OSError) as e:
            available_interfaces = get_machine_interfaces()
            raise ValueError(
                f"WOL_INTERFACE '{wol_interface}' does not belong to this machine. "
                f"Available interfaces: {available_interfaces}. Error: {e}"
            )
    else:
        # Linux: Use your elegant ip a | grep approach
        try:
            result = subprocess.run(
                ["ip", "a"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and f"inet {wol_interface}/" in result.stdout:
                log.debug(
                    f"Verified WOL_INTERFACE {wol_interface} belongs to this machine"
                )
            else:
                available_interfaces = get_machine_interfaces()
                raise ValueError(
                    f"WOL_INTERFACE '{wol_interface}' does not belong to this machine. "
                    f"Available interfaces: {available_interfaces}"
                )
        except subprocess.SubprocessError as e:
            # Fallback to socket binding on Linux if ip command fails
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind((wol_interface, 0))
                sock.close()
                log.debug(
                    f"Verified WOL_INTERFACE {wol_interface} belongs to this machine"
                )
            except (socket.error, OSError):
                available_interfaces = get_machine_interfaces()
                raise ValueError(
                    f"WOL_INTERFACE '{wol_interface}' does not belong to this machine. "
                    f"Available interfaces: {available_interfaces}. Error: {e}"
                )

    return wol_interface


def get_local_network(ip=None):
    """Get the network range for given IP or configured WOL interface (assumes /24)"""
    if not ip:
        try:
            ip = get_wol_interface()
        except ValueError:
            return None

    if not ip:
        return None

    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return None


def get_daemon_networks(daemon_registry):
    """Get unique network ranges based on registered daemons"""
    networks = []
    if daemon_registry:
        for daemon_ip in daemon_registry.keys():
            network = get_local_network(daemon_ip)
            if network and network not in networks:
                networks.append(network)
    return networks


def resolve_pc_ip(pc_data, daemon_registry=None):
    """
    Resolve the best IP address for a PC using multiple sources.
    Priority: 1) Localhost check, 2) Daemon IP, 3) ARP IP, 4) Stored IP

    Returns: (ip_address, source) where source is 'localhost', 'daemon', 'arp', 'stored', or None
    """
    mac = pc_data.get("mac")
    hostname = pc_data.get("hostname", "Unknown")
    stored_ip = pc_data.get("ip", "")

    log.debug(f"Resolving IP for PC {hostname} (MAC: {mac}, stored IP: {stored_ip})")

    # Priority 1: Check if this is the localhost (same machine running WakeStation)
    try:
        local_hostname = socket.gethostname().lower()
        if hostname and hostname.lower() == local_hostname:
            wol_ip = get_wol_interface()
            log.info(f"Detected localhost: {hostname} -> {wol_ip}")
            return wol_ip, "localhost"
    except Exception as e:
        log.debug(f"Localhost check failed for {hostname}: {e}")

    # Priority 2: Check daemon registry for matching MAC address
    if daemon_registry and mac and validate_mac_address(mac):
        mac_normalized = normalize_mac_address(mac)
        for daemon_ip, daemon_info in daemon_registry.items():
            daemon_mac = daemon_info.get("mac")
            if daemon_mac:
                daemon_mac_normalized = normalize_mac_address(daemon_mac)
                if daemon_mac_normalized == mac_normalized:
                    # Found matching daemon MAC - return the daemon IP
                    log.info(
                        f"Found matching daemon for {hostname}: {daemon_info['ip']} (MAC: {daemon_mac})"
                    )
                    return daemon_info["ip"], "daemon"

    # Priority 3: Use arp-scan to find online devices by MAC
    if mac and validate_mac_address(mac):
        # First try daemon networks, then local scan
        networks_to_scan = []
        if daemon_registry:
            daemon_networks = get_daemon_networks(daemon_registry)
            networks_to_scan.extend(daemon_networks)

        log.debug(f"Attempting arp-scan for {hostname} (MAC: {mac})")
        found_ip = find_device_by_mac(
            mac, networks_to_scan if networks_to_scan else None
        )
        if found_ip:
            log.info(f"Found {hostname} via arp-scan: {found_ip}")
            return found_ip, "arp-scan"

    # Priority 4: Use stored IP if available and reachable
    if stored_ip:
        log.debug(f"Checking stored IP {stored_ip} for {hostname}")
        if ping_host(stored_ip):
            log.info(f"Verified stored IP for {hostname}: {stored_ip}")
            return stored_ip, "stored"

    # No IP found
    log.warning(f"Could not resolve IP for PC {hostname}")
    return None, None


def arp_scan_network(network=None, timeout=3):
    """
    Use arp-scan to discover active devices on the network.
    Returns dict of {ip: mac} for online devices.
    """
    log.debug(
        f"Starting arp-scan on network: {network or 'auto-detect'} with timeout {timeout}s"
    )
    try:
        # Try different arp-scan commands in order of preference
        # On Windows, try .exe first
        if platform.system().lower() == "windows":
            arp_commands = ["arp-scan.exe", ".\\arp-scan.exe", "arp-scan"]
        else:
            arp_commands = ["arp-scan", "arp-scan.exe"]
        cmd = None

        for arp_cmd in arp_commands:
            try:
                # Test if command exists (arp-scan --help returns exit code 1 but still works)
                result = subprocess.run(
                    [arp_cmd, "--help"], capture_output=True, timeout=2
                )
                # If we get any output (stdout or stderr), the command exists
                if result.stdout or result.stderr:
                    cmd = [arp_cmd]
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        if not cmd:
            log.warning("arp-scan command not found")
            raise FileNotFoundError("arp-scan not found")

        # Handle different arp-scan variants and their syntax
        if cmd[0] == "arp-scan.exe":
            # Windows arp-scan.exe has different syntax
            cmd.append("-t")  # Use -t flag for Windows version
            if network:
                cmd.append(network)
            else:
                # Auto-detect local network or use reasonable default
                local_network = get_local_network()
                cmd.append(
                    local_network or "10.0.0.0/16"
                )  # Default to common private range
        else:
            # Standard Linux arp-scan syntax
            if network:
                cmd.append(network)
            else:
                cmd.append("--local")  # Scan local networks

            # Add timeout option (--quiet might not be available on all versions)
            cmd.extend(["--timeout", str(timeout * 1000)])

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout + 5
        )

        if result.returncode == 0:
            devices = {}
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                # Handle different arp-scan output formats
                if "Reply that" in line:
                    # Format: "Reply that 22:C9:84:0C:0F:BE is 10.0.1.2 in 14.917100"
                    match = re.search(
                        r"Reply that ([0-9A-Fa-f:-]+) is (\d+\.\d+\.\d+\.\d+)", line
                    )
                    if match:
                        raw_mac = match.group(1)
                        ip = match.group(2)
                        mac = normalize_mac_address(raw_mac)
                        if validate_ip_address(ip) and mac:
                            devices[ip] = mac
                else:
                    # Standard format: "192.168.1.100	aa:bb:cc:dd:ee:ff	Vendor"
                    parts = line.split("\t")
                    if len(parts) >= 2:
                        ip = parts[0].strip()
                        raw_mac = parts[1].strip()
                        mac = normalize_mac_address(raw_mac)
                        if validate_ip_address(ip) and mac:
                            devices[ip] = mac
            log.info(
                f"arp-scan found {len(devices)} devices on {network or 'local network'}"
            )
            return devices
        else:
            # arp-scan not available or failed, return empty dict
            return {}

    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.SubprocessError):
        # arp-scan not installed or failed, try Windows fallback
        if platform.system().lower() == "windows":
            return _windows_network_scan(network, timeout)
        return {}


def _windows_network_scan(network=None, timeout=3):
    """
    Windows fallback for arp-scan using arp -a.
    Returns dict of {ip: mac} for devices in ARP table.
    """
    try:
        # Use arp -a to get current ARP table
        result = subprocess.run(
            ["arp", "-a"], capture_output=True, text=True, timeout=timeout
        )

        if result.returncode == 0:
            devices = {}
            import re

            # Parse arp -a output
            for line in result.stdout.split("\n"):
                # Match format: "  10.0.1.2              22-c9-84-0c-0f-be     dynamisch"
                match = re.search(r"\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})", line)
                if match:
                    ip = match.group(1)
                    raw_mac = match.group(2)
                    mac = normalize_mac_address(raw_mac)

                    # Filter by network if specified
                    if network:
                        try:
                            import ipaddress

                            network_obj = ipaddress.ip_network(network, strict=False)
                            if ipaddress.ip_address(ip) not in network_obj:
                                continue
                        except (ValueError, ImportError):
                            continue

                    if validate_ip_address(ip) and mac:
                        devices[ip] = mac

            return devices

    except (subprocess.SubprocessError, subprocess.TimeoutExpired):
        pass

    return {}


def find_device_by_mac(target_mac, networks=None):
    """
    Use arp-scan to find IP address for a specific MAC address.
    Returns IP if device is online, None if offline or not found.
    """
    target_mac = normalize_mac_address(target_mac)
    if not target_mac:
        return None

    if networks:
        # Scan specific networks
        for network in networks:
            devices = arp_scan_network(network)
            for ip, mac in devices.items():
                if mac == target_mac:
                    return ip
    else:
        # Scan local networks
        devices = arp_scan_network()
        for ip, mac in devices.items():
            if mac == target_mac:
                return ip

    return None


# Backward compatibility aliases
def get_wakestation_network():
    """Backward compatibility alias for get_local_network()"""
    return get_local_network()


def get_local_ip():
    """Backward compatibility alias - use get_wol_interface() instead"""
    try:
        return get_wol_interface()
    except ValueError:
        log.warning("WOL_INTERFACE not configured, cannot determine local IP")
        return None


def find_device_by_mac_arpscan(target_mac, networks=None):
    """Backward compatibility alias for find_device_by_mac()"""
    return find_device_by_mac(target_mac, networks)
