#!/usr/bin/env python3
"""!
********************************************************************************
@file   network.py
@brief  Network utility functions for WakeStation - ping, MAC validation, daemon checks
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


def get_interface_name_for_ip(ip_address):
    """
    Get the network interface name for a given IP address.
    Returns interface name (e.g., 'eth0', 'wlan0') or None if not found.
    """
    if not ip_address or not validate_ip_address(ip_address):
        return None

    try:
        if platform.system().lower() == "windows":
            # Windows: Use route command to find interface
            result = subprocess.run(
                ["route", "print", "0.0.0.0"], capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                # Parse routing table to find interface for IP
                import re

                # Look for lines with our IP in the interface column
                for line in result.stdout.split("\n"):
                    if ip_address in line:
                        # Extract interface index from route table
                        parts = line.split()
                        if len(parts) >= 4:
                            return parts[3]  # Interface column
        else:
            # Linux: Parse ip addr show to find interface with this IP
            # Note: ip route get <local_ip> returns 'lo' for local IPs, so we use ip addr instead
            try:
                result = subprocess.run(
                    ["ip", "addr", "show"], capture_output=True, text=True, timeout=5
                )
                if result.returncode == 0:
                    import re

                    lines = result.stdout.split("\n")
                    current_interface = None

                    for line in lines:
                        # Look for interface lines: "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP>"
                        interface_match = re.match(r"^\d+:\s+(\S+):", line)
                        if interface_match:
                            current_interface = interface_match.group(1)
                        # Look for IP lines: "    inet 10.0.1.13/24 brd 10.0.1.255 scope global br0"
                        elif current_interface and f"inet {ip_address}/" in line:
                            # Skip loopback interface
                            if current_interface != "lo":
                                return current_interface
            except subprocess.SubprocessError:
                pass

    except Exception as e:
        log.debug(f"Failed to get interface name for IP {ip_address}: {e}")

    return None


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


def get_network_scan_cache(daemon_registry=None, cache_duration=None):
    """
    Perform network-wide arp-scan and cache results to avoid redundant scans.

    Args:
        daemon_registry: Dict of registered daemons
        cache_duration: Cache duration in seconds (uses config.ARP_SCAN_CACHE_TIMEOUT if None)

    Returns:
        Dict of {mac_address: ip_address} for all discovered devices
    """
    import time

    # Return empty dict if ARP-scan is disabled
    if not config.ENABLE_ARP_SCAN:
        log.debug("ARP-scan disabled, returning empty device cache")
        return {}

    # Use config default if not specified
    if cache_duration is None:
        cache_duration = getattr(config, "ARP_SCAN_CACHE_TIMEOUT", 300)

    # Check if we have a recent cached result
    cache_key = "_network_scan_cache"
    cache_time_key = "_network_scan_time"

    if hasattr(get_network_scan_cache, cache_key):
        cached_time = getattr(get_network_scan_cache, cache_time_key, 0)
        if time.time() - cached_time < cache_duration:
            log.debug("Using cached network scan results")
            return getattr(get_network_scan_cache, cache_key)

    log.debug("Performing fresh network scan for all devices")
    all_devices = {}

    # Get all networks to scan
    networks_to_scan = []

    # Add daemon networks
    if daemon_registry:
        daemon_networks = get_daemon_networks(daemon_registry)
        networks_to_scan.extend(daemon_networks)

    # Add local WOL network
    try:
        local_network = get_local_network()
        if local_network and local_network not in networks_to_scan:
            networks_to_scan.append(local_network)
    except:
        pass

    # If no specific networks, scan local
    if not networks_to_scan:
        networks_to_scan = [None]  # Will use --local

    # Scan each unique network
    for network in networks_to_scan:
        try:
            devices = arp_scan_network(network)
            for ip, mac in devices.items():
                # Use MAC as key for device lookup
                all_devices[mac] = ip
        except Exception as e:
            log.debug(f"Failed to scan network {network}: {e}")

    # Cache the results
    setattr(get_network_scan_cache, cache_key, all_devices)
    setattr(get_network_scan_cache, cache_time_key, time.time())

    log.info(f"Network scan found {len(all_devices)} total devices across all networks")
    return all_devices


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

    # Priority 3: Use cached network scan to find devices by MAC (if enabled)
    if mac and validate_mac_address(mac) and config.ENABLE_ARP_SCAN:
        log.debug(f"Checking cached network scan for {hostname} (MAC: {mac})")

        # Get cached network scan results (or perform fresh scan if needed)
        network_devices = get_network_scan_cache(daemon_registry)
        mac_normalized = normalize_mac_address(mac)

        if mac_normalized in network_devices:
            found_ip = network_devices[mac_normalized]
            log.info(f"Found {hostname} via network scan cache: {found_ip}")
            return found_ip, "arp-scan"
    elif mac and validate_mac_address(mac) and not config.ENABLE_ARP_SCAN:
        log.debug(f"ARP-scan disabled, skipping network scan for {hostname}")

    # Priority 4: Use stored IP if available and reachable
    if stored_ip:
        log.debug(f"Checking stored IP {stored_ip} for {hostname}")
        if ping_host(stored_ip):
            log.info(f"Verified stored IP for {hostname}: {stored_ip}")
            return stored_ip, "stored"

    # No IP found
    log.warning(f"Could not resolve IP for PC {hostname}")
    return None, None


def arp_scan_network(network=None, timeout=None):
    """
    Use arp-scan to discover active devices on the network.
    Returns dict of {ip: mac} for online devices.
    """
    # Check if ARP-scan is disabled
    if not config.ENABLE_ARP_SCAN:
        log.debug("ARP-scan disabled, returning empty results")
        return {}

    # Use config default if not specified
    if timeout is None:
        timeout = getattr(config, "ARP_SCAN_TIMEOUT", 5)

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

        # If arp-scan found but might need sudo, try with sudo first
        if cmd and platform.system().lower() != "windows":
            # Check if we can run arp-scan without sudo first
            try:
                test_result = subprocess.run(
                    cmd + ["--help"], capture_output=True, timeout=2
                )
                # If it needs root, try with sudo
                if (
                    "Operation not permitted" in str(test_result.stderr)
                    or test_result.returncode != 0
                ):
                    cmd = ["sudo"] + cmd
                    log.debug("arp-scan requires sudo privileges")
            except:
                pass

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
            # Build options first, then add network/target as last argument

            # Add timeout option and format for consistent output
            cmd.extend(["--timeout", str(timeout * 1000)])
            cmd.extend(["--format", "${IP}\\t${MAC}\\t${Vendor}"])

            # Add interface specification for multi-NIC systems
            try:
                wol_ip = get_wol_interface()
                interface_name = get_interface_name_for_ip(wol_ip)
                if interface_name:
                    cmd.append(f"--interface={interface_name}")
                    log.debug(f"Using interface {interface_name} for arp-scan")
            except Exception as e:
                log.debug(f"Could not determine interface for arp-scan: {e}")

            # Add network/target as LAST argument
            if network:
                # Network explicitly provided
                cmd.append(network)
                log.debug(f"Using explicit network {network} for arp-scan")
            else:
                # No network specified - try to use WOL_INTERFACE network
                try:
                    wol_ip = get_wol_interface()
                    wol_network = get_local_network(
                        wol_ip
                    )  # Gets network in format like "10.0.1.0/24"

                    if wol_network:
                        cmd.append(wol_network)
                        log.debug(f"Using WOL network {wol_network} for arp-scan")
                    else:
                        cmd.append("--local")  # Fallback to local scan
                        log.debug(
                            "Using --local for arp-scan (WOL network detection failed)"
                        )
                except Exception as e:
                    log.debug(
                        f"Could not determine WOL network for arp-scan, using --local: {e}"
                    )
                    cmd.append("--local")  # Fallback to local scan

        log.debug(f"Executing arp-scan command: {' '.join(cmd)}")
        try:
            # arp-scan can take a while scanning large networks, give it plenty of time
            # The --timeout parameter controls arp-scan's internal timeout per host
            subprocess_timeout = max(
                timeout * 2, 15
            )  # At least 15 seconds for subprocess
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=subprocess_timeout
            )
            log.debug(
                f"arp-scan command completed with return code: {result.returncode}"
            )
            if result.stderr:
                log.debug(f"arp-scan stderr: {result.stderr}")
        except subprocess.TimeoutExpired:
            log.warning(
                f"arp-scan command timed out after {subprocess_timeout} seconds"
            )
            raise
        except Exception as e:
            log.warning(f"arp-scan subprocess error: {e}")
            raise

        # arp-scan returns different exit codes:
        # 0 = success with responses, 1 = success but no responses, 2+ = error
        # We should accept both 0 and 1 as success if we have output
        if result.returncode <= 1 and result.stdout.strip():
            log.debug(
                f"arp-scan completed successfully with return code {result.returncode}"
            )
        elif result.stdout.strip():
            log.debug(
                f"arp-scan had output despite return code {result.returncode}, processing anyway"
            )
        else:
            log.warning(
                f"arp-scan failed - no output and return code {result.returncode}"
            )
            return {}

        if result.stdout.strip():
            devices = {}
            log.debug(f"arp-scan raw output:\n{result.stdout}")
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if not line:
                    continue

                # Skip arp-scan header and footer lines
                if (
                    line.startswith("Interface:")
                    or line.startswith("Starting arp-scan")
                    or line.startswith("Ending arp-scan")
                    or "packets received by filter" in line
                    or "packets dropped by kernel" in line
                    or "hosts scanned in" in line
                ):
                    continue

                # With --format='${IP}\t${MAC}\t${Vendor}', output should be tab-separated
                # Format: "10.0.1.110	90:78:41:68:8a:17	Intel Corporate"
                parts = line.split("\t")
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    raw_mac = parts[1].strip()
                    mac = normalize_mac_address(raw_mac)
                    if validate_ip_address(ip) and mac:
                        devices[ip] = mac
                        log.debug(f"Parsed arp-scan result: {ip} -> {mac}")
                else:
                    # Fallback for cases where format might not work - parse space-separated
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
        # arp-scan not installed or failed, try fallback methods
        log.warning(f"arp-scan command failed with exception: {e}")
        if platform.system().lower() == "windows":
            return _windows_network_scan(network, timeout)
        else:
            # Linux/Unix fallback: try using ARP table
            return _linux_arp_table_scan(network, timeout)


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


def _linux_arp_table_scan(network=None, timeout=3):
    """
    Linux fallback for arp-scan using arp -a and /proc/net/arp.
    Returns dict of {ip: mac} for devices in ARP table.
    """
    try:
        devices = {}

        # Method 1: Try /proc/net/arp (most reliable)
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        # Skip incomplete entries
                        if mac != "00:00:00:00:00:00" and ":" in mac:
                            mac_normalized = normalize_mac_address(mac)
                            if validate_ip_address(ip) and mac_normalized:
                                # Filter by network if specified
                                if network:
                                    try:
                                        import ipaddress

                                        network_obj = ipaddress.ip_network(
                                            network, strict=False
                                        )
                                        if ipaddress.ip_address(ip) not in network_obj:
                                            continue
                                    except (ValueError, ImportError):
                                        continue
                                devices[ip] = mac_normalized

            if devices:
                log.debug(f"Found {len(devices)} devices via /proc/net/arp")
                return devices
        except (FileNotFoundError, PermissionError):
            pass

        # Method 2: Fallback to arp -a command
        try:
            result = subprocess.run(
                ["arp", "-a"], capture_output=True, text=True, timeout=timeout
            )

            if result.returncode == 0:
                import re

                # Parse arp -a output: "hostname (10.0.1.2) at aa:bb:cc:dd:ee:ff [ether] on eth0"
                for line in result.stdout.split("\n"):
                    match = re.search(
                        r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-fA-F:]{17})", line
                    )
                    if match:
                        ip = match.group(1)
                        mac = match.group(2)
                        mac_normalized = normalize_mac_address(mac)

                        # Filter by network if specified
                        if network:
                            try:
                                import ipaddress

                                network_obj = ipaddress.ip_network(
                                    network, strict=False
                                )
                                if ipaddress.ip_address(ip) not in network_obj:
                                    continue
                            except (ValueError, ImportError):
                                continue

                        if validate_ip_address(ip) and mac_normalized:
                            devices[ip] = mac_normalized

            log.debug(f"Found {len(devices)} devices via arp -a fallback")
            return devices

        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

    except Exception as e:
        log.debug(f"Linux ARP table scan failed: {e}")

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
