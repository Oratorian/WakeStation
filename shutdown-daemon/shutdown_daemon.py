#!/usr/bin/env python3
"""!
********************************************************************************
@file   shutdown_daemon.py
@brief  Remote shutdown daemon for WakeStation - main application entry point
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import sys
from dotenv import load_dotenv

# Import modules
from src.config import (
    parse_arguments,
    is_env_configuration_complete,
    validate_required_variables,
    USERS_FILE_PATH,
)
from src.utils import (
    get_daemon_logger,
    check_if_daemon_running,
    create_pid_file,
    remove_pid_file,
    setup_signal_handlers,
)
from src.core import initialize_users
from src.gui import (
    initialize_users_dialog,
    create_tray_icon,
    show_already_running_dialog,
    TRAY_AVAILABLE,
)
from src.server import start_server, start_server_thread

# Initialize logging
log = get_daemon_logger("main")

# Global state for dry-run mode (shared with tray)
dry_run_state = {"enabled": False}


def main():
    """Main application entry point."""
    global dry_run_state

    # Parse command line arguments
    args = parse_arguments()
    dry_run_state["enabled"] = args.dry_run

    # Validate configuration and get variables
    WOL_SERVER_IP, _, _ = validate_required_variables(args)
    # CLI arguments take precedence over environment variables
    WOL_SERVER_PORT = (
        args.wol_server_port
        if args.wol_server_port is not None
        else int(os.getenv("WOL_SERVER_PORT", "8888"))
    )
    BIND_IP = args.bind_ip if args.bind_ip else os.getenv("BIND_IP", "0.0.0.0")
    BIND_PORT = (
        args.bind_port if args.bind_port else int(os.getenv("BIND_PORT", "8080"))
    )

    log.info("WakeStation Shutdown Daemon starting...")
    log.info(
        f"Configuration: Server={WOL_SERVER_IP}:{WOL_SERVER_PORT}, Bind={BIND_IP}:{BIND_PORT}"
    )

    # Check if daemon is already running
    if check_if_daemon_running():
        show_already_running_dialog()
        sys.exit(1)

    # Create PID file for this instance
    create_pid_file()

    # Setup signal handlers for graceful shutdown (skip for GUI mode)
    if not getattr(sys, "frozen", False):
        setup_signal_handlers()

    try:
        # Check if complete configuration is needed
        needs_setup = not os.path.exists(
            USERS_FILE_PATH
        ) or not is_env_configuration_complete(args)

        if needs_setup:
            if TRAY_AVAILABLE:
                # Show setup dialog and wait for completion
                users = initialize_users_dialog()

                # Ensure files are properly written before proceeding
                import time

                time.sleep(0.1)  # Brief pause to ensure file operations complete

                # Reload .env file after configuration is created
                load_dotenv(override=True)
                # Re-validate variables with new configuration
                WOL_SERVER_IP, _, _ = validate_required_variables(args)
                # Also reload other variables that might have changed - CLI args still take precedence
                WOL_SERVER_PORT = (
                    args.wol_server_port
                    if args.wol_server_port is not None
                    else int(os.getenv("WOL_SERVER_PORT", "8888"))
                )
                BIND_IP = (
                    args.bind_ip if args.bind_ip else os.getenv("BIND_IP", "0.0.0.0")
                )
                BIND_PORT = (
                    args.bind_port
                    if args.bind_port
                    else int(os.getenv("BIND_PORT", "8080"))
                )

                log.info(
                    "Configuration completed successfully, proceeding with server startup"
                )
            else:
                # GUI not available - cannot do interactive setup
                log.error("Setup required but GUI not available.")
                log.error("Please provide configuration via command line arguments:")
                log.error("  --wol-server-ip <IP_ADDRESS>")
                log.error("Or create a .env file with required settings.")
                sys.exit(1)
        else:
            users = initialize_users()

        # Final validation - ensure WOL_SERVER_IP is available
        if not WOL_SERVER_IP:
            log.error(
                "WOL_SERVER_IP is required but not configured. Please set it via command line or .env file."
            )
            sys.exit(1)

        # Start the appropriate mode
        if TRAY_AVAILABLE:
            # Attempt system tray mode
            log.info("Attempting to start with system tray")
            tray_icon = create_tray_icon(dry_run_state)

            if tray_icon:
                # System tray is available - run in tray mode
                log.info("System tray available - running in tray mode")

                # Start server in background thread
                start_server_thread(
                    BIND_IP,
                    BIND_PORT,
                    users,
                    WOL_SERVER_IP,
                    WOL_SERVER_PORT,
                    dry_run_state["enabled"],
                    dry_run_state,
                )

                # Run tray (blocks until quit)
                try:
                    tray_icon.run()
                except KeyboardInterrupt:
                    from src.gui import quit_application

                    quit_application()
                return  # Exit after tray mode

        # Console mode (either no tray available or tray failed)
        log.info("System tray not available - starting in console mode")
        try:
            start_server(
                BIND_IP,
                BIND_PORT,
                users,
                WOL_SERVER_IP,
                WOL_SERVER_PORT,
                dry_run_state["enabled"],
                dry_run_state,
            )
        except KeyboardInterrupt:
            log.info("Shutdown daemon stopped.")

    finally:
        # Ensure PID file is cleaned up
        remove_pid_file()


if __name__ == "__main__":
    main()
