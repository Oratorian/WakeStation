#!/usr/bin/env python3
"""!
********************************************************************************
@file   tray.py
@brief  System tray functionality for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import sys
import os
import threading
from datetime import datetime
from typing import Dict, Union
from ..utils import get_daemon_logger

log = get_daemon_logger("tray")

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
    import tkinter as tk
    from tkinter import messagebox

    TRAY_AVAILABLE = True
except ImportError:
    # Create dummy classes if imports fail
    class Image:
        @staticmethod
        def new(*args, **kwargs):
            return None

    class ImageDraw:
        @staticmethod
        def Draw(*args, **kwargs):
            return None

    TRAY_AVAILABLE = False


# Global variables for tray functionality
tray_icon = None
last_request: Dict[str, Union[str, datetime, bool, None]] = {
    "username": None,
    "time": None,
    "success": None,
}


def toggle_dry_run(dry_run_state) -> None:
    """Toggle dry-run mode and update tray icon."""
    global tray_icon
    dry_run_state["enabled"] = not dry_run_state["enabled"]
    log.info(f"Dry-run mode {'enabled' if dry_run_state['enabled'] else 'disabled'}")
    if tray_icon:
        tray_icon.icon = create_tray_image(dry_run_state["enabled"])  # type: ignore
        tray_icon.menu = create_tray_menu(dry_run_state)  # type: ignore


def create_tray_image(dry_run_enabled: bool = False):
    """Create system tray icon image."""
    if not TRAY_AVAILABLE:
        return None

    color = "orange" if dry_run_enabled else "red"
    image = Image.new("RGB", (64, 64), color=color)
    draw = ImageDraw.Draw(image)
    draw.rectangle([16, 16, 48, 48], fill="white")
    draw.text((24, 28), "SD", fill="black")
    return image


def create_tray_menu(dry_run_state):
    """Create system tray context menu."""
    dry_run_text = "✓ Dry-Run Mode" if dry_run_state["enabled"] else "✗ Dry-Run Mode"
    status_text = "No requests yet"

    if last_request["username"]:
        time_str = "Unknown"
        if isinstance(last_request["time"], datetime):
            time_str = last_request["time"].strftime("%H:%M:%S")

        status_icon = "✓" if last_request["success"] else "✗"
        status_text = f'{status_icon} {last_request["username"]} at {time_str}'

    return pystray.Menu(
        item(dry_run_text, lambda: toggle_dry_run(dry_run_state)),
        pystray.Menu.SEPARATOR,
        item(f"Last Request: {status_text}", None),
        pystray.Menu.SEPARATOR,
        item("Restart Daemon", lambda: restart_daemon(dry_run_state)),
        item("Quit", lambda icon, item: quit_application()),
    )


def create_tray_icon(dry_run_state):
    """Create and configure system tray icon."""
    if not TRAY_AVAILABLE:
        return None

    # Runtime check for system tray availability on Linux
    if sys.platform.startswith("linux"):
        # Check if we have a display and system tray available
        if not os.environ.get("DISPLAY") and not os.environ.get("WAYLAND_DISPLAY"):
            log.warning(
                "No display environment detected on Linux, skipping system tray"
            )
            return None

        # Try to detect if a system tray is available
        try:
            import subprocess

            # Check if a system tray/notification daemon is running
            result = subprocess.run(
                [
                    "pgrep",
                    "-f",
                    "(gnome-panel|unity-panel-service|xfce4-panel|lxpanel|mate-panel|plasma|systray|notification)",
                ],
                capture_output=True,
                timeout=2,
            )
            if result.returncode != 0:
                log.warning(
                    "No system tray daemon detected on Linux, skipping system tray"
                )
                return None
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            log.warning(f"Could not detect system tray availability on Linux: {e}")
            return None

    global tray_icon

    try:
        icon = pystray.Icon(
            "shutdown_daemon",
            create_tray_image(dry_run_state["enabled"]),
            "WakeStation Shutdown Daemon",
            create_tray_menu(dry_run_state),
        )

        # Store reference globally so quit_application can access it
        tray_icon = icon

        return icon
    except Exception as e:
        log.error(f"Failed to create system tray icon: {e}")
        return None


def restart_daemon(dry_run_state) -> None:
    """Restart the daemon server (without restarting the entire process)."""
    global tray_icon
    log.info("Restarting daemon...")

    try:
        # Import here to avoid circular imports
        from ..server import stop_server, start_server_thread
        from ..core.crypto import sync_encryption_key
        from ..config import validate_required_variables, parse_arguments
        from ..core import initialize_users
        import os

        # Stop the server
        stop_server()

        # Give time for cleanup
        import time

        time.sleep(0.5)

        # Restart server thread (sync will be handled by background worker)
        args = parse_arguments()
        WOL_SERVER_IP, _, _ = validate_required_variables(args)
        WOL_SERVER_PORT = (
            args.wol_server_port
            if args.wol_server_port
            else int(os.getenv("WOL_SERVER_PORT", "8888"))
        )
        BIND_IP = args.bind_ip if args.bind_ip else os.getenv("BIND_IP", "0.0.0.0")
        BIND_PORT = (
            args.bind_port if args.bind_port else int(os.getenv("BIND_PORT", "8080"))
        )

        users = initialize_users()

        # Start server thread (background sync worker will handle WakeStation connection)
        start_server_thread(
            BIND_IP,
            BIND_PORT,
            users,
            WOL_SERVER_IP,
            WOL_SERVER_PORT,
            dry_run_state["enabled"],
            dry_run_state,
        )

        log.info("Daemon restarted successfully.")

        # Update tray menu to reflect restart
        if tray_icon:
            tray_icon.menu = create_tray_menu(dry_run_state)  # type: ignore

    except Exception as e:
        log.error(f"Error during restart: {e}")
        # If restart fails, at least try to update the menu
        if tray_icon:
            tray_icon.menu = create_tray_menu(dry_run_state)  # type: ignore


def quit_application() -> None:
    """Quit the daemon application."""
    global tray_icon
    log.info("Shutting down daemon...")

    # Import here to avoid circular imports
    from ..utils import remove_pid_file
    from ..server import stop_server

    # Stop the server gracefully
    stop_server()

    # Clean up PID file
    remove_pid_file()

    # Stop the tray icon and ensure pystray event loop exits
    if tray_icon:
        try:
            # Set a flag to stop the icon gracefully
            tray_icon.visible = False
            tray_icon.stop()  # type: ignore
        except Exception as e:
            log.warning(f"Error stopping tray icon: {e}")

    # Force exit the application
    # Use os._exit() to ensure immediate termination without cleanup handlers
    log.info("Daemon shutdown complete")
    os._exit(0)


def show_already_running_dialog():
    """Show dialog when daemon is already running."""
    if TRAY_AVAILABLE:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            "Daemon Already Running",
            "Another instance of the shutdown daemon is already running.\n"
            "Please stop the existing instance before starting a new one.",
        )
        root.destroy()


def update_last_request(username: str, success: bool):
    """Update last request information for tray display."""
    global last_request
    last_request["username"] = username
    last_request["time"] = datetime.now()
    last_request["success"] = success
