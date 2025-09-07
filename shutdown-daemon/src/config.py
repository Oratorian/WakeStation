#!/usr/bin/env python3
"""!
********************************************************************************
@file   config.py
@brief  Configuration management for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import argparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Default configuration values
DEFAULT_WOL_SERVER_IP = os.getenv("WOL_SERVER_IP", "")
DEFAULT_WOL_SERVER_PORT = os.getenv("WOL_SERVER_PORT", "8889")
DEFAULT_BIND_IP = os.getenv("BIND_IP", "0.0.0.0")
DEFAULT_BIND_PORT = int(os.getenv("BIND_PORT", 8080))

# File paths
APP_DATA_PATH = os.path.join(os.path.expanduser("~"), ".wakestation")
USERS_FILE_PATH = os.path.join(APP_DATA_PATH, "users.json")
LOG_FILE_PATH = os.path.join(APP_DATA_PATH, "daemon.log")
PID_FILE = os.path.join(APP_DATA_PATH, "daemon.pid")

# Ensure directories exist
os.makedirs(APP_DATA_PATH, exist_ok=True)


def parse_arguments():
    """Parse command line arguments for the shutdown daemon."""
    parser = argparse.ArgumentParser(
        description="WakeStation Shutdown Daemon - Remote shutdown service with system tray integration",
        epilog="""
Examples:
  %(prog)s                                    # Use defaults from .env file
  %(prog)s --wol-server-ip 192.168.1.100     # Override server IP
  %(prog)s --dry-run                          # Test mode without actual shutdowns
  %(prog)s --bind-port 9090 --dry-run         # Custom port with dry-run mode

Configuration:
  Settings can be provided via command-line arguments, environment variables, or .env file.
  Command-line arguments take precedence over environment variables.

System Tray:
  When GUI libraries are available, the daemon runs with a system tray icon providing:
  - Dry-run toggle (orange=enabled, red=disabled)
  - Last request status display
  - Restart and quit options
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--wol-server-ip",
        type=str,
        default=DEFAULT_WOL_SERVER_IP,
        metavar="IP",
        help="IP address of the WakeStation WOL server (default: %(default)s or WOL_SERVER_IP env var)",
    )
    parser.add_argument(
        "--wol-server-port",
        type=int,
        default=int(DEFAULT_WOL_SERVER_PORT),
        metavar="PORT",
        help="Port of the WakeStation WOL server (default: %(default)s or WOL_SERVER_PORT env var)",
    )
    parser.add_argument(
        "--bind-ip",
        type=str,
        default=DEFAULT_BIND_IP,
        metavar="IP",
        help="IP address to bind the shutdown daemon server (default: %(default)s or BIND_IP env var)",
    )
    parser.add_argument(
        "--bind-port",
        type=int,
        default=DEFAULT_BIND_PORT,
        metavar="PORT",
        help="Port to bind the shutdown daemon server (default: %(default)s or BIND_PORT env var)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Enable dry-run mode (test without actual shutdowns)",
    )

    return parser.parse_args()


def is_env_configuration_complete(args):
    """Check if .env file has all required configuration settings."""
    # Check if .env file exists
    if not os.path.exists(".env"):
        return False

    # Check if required variables are available (either from args or env)
    wol_server_ip = args.wol_server_ip or os.getenv("WOL_SERVER_IP")

    # Return True only if all required settings are present
    # Note: SECRET_KEY is not needed as daemon gets enc.bin from WakeStation automatically
    return bool(wol_server_ip)


def validate_required_variables(args):
    """Validate required configuration variables."""
    WOL_SERVER_IP = args.wol_server_ip or os.getenv("WOL_SERVER_IP")
    DRY_RUN = args.dry_run

    # Note: SECRET_KEY is not needed as daemon gets enc.bin from WakeStation automatically
    return WOL_SERVER_IP, None, DRY_RUN
