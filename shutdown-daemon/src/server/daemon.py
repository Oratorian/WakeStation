#!/usr/bin/env python3
"""!
********************************************************************************
@file   daemon.py
@brief  Server daemon functionality for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import socket
import threading
import time
import asyncio
from typing import Dict, Any
from ..core import sync_encryption_key
from ..utils import get_daemon_logger
from .handler import handle_client_connection

log = get_daemon_logger("daemon")

# Global server state
server_running = False
server_thread = None
sync_thread = None


def background_sync_worker(
    wol_server_ip: str,
    wol_server_port: int,
    bind_port: int,
    bind_ip: str,
    ssl_enabled: bool = True,
    ssl_verify: bool = True,
    retry_interval: int = 300,  # 5 minutes
):
    """Background worker to periodically retry sync if it fails."""
    global server_running

    # Initial sync attempt
    success = sync_encryption_key(wol_server_ip, wol_server_port, bind_port, bind_ip, ssl_enabled=ssl_enabled, ssl_verify=ssl_verify)

    # If initial sync failed, keep retrying periodically while server is running
    while server_running and not success:
        log.info(f"Will retry sync with WakeStation server in {retry_interval} seconds")

        # Wait for retry interval or until server stops
        for _ in range(retry_interval):
            if not server_running:
                break
            time.sleep(1)

        if server_running:
            success = sync_encryption_key(
                wol_server_ip, wol_server_port, bind_port, bind_ip, ssl_enabled=ssl_enabled, ssl_verify=ssl_verify
            )

    if success:
        log.info("Background sync worker completed successfully")
    else:
        log.info("Background sync worker stopped")


def start_server(
    bind_ip: str,
    bind_port: int,
    users: Dict[str, Any],
    wol_server_ip: str,
    wol_server_port: int,
    dry_run: bool = False,
    dry_run_state: dict = None,
    ssl_enabled: bool = True,
    ssl_verify: bool = True,
):
    """Start the shutdown daemon server."""
    global server_running, sync_thread
    server_running = True

    log.info(f"Starting shutdown daemon server on {bind_ip}:{bind_port}")
    log.info(f"Dry-run mode: {'enabled' if dry_run else 'disabled'}")
    log.info(f"WakeStation connection: {'HTTPS' if ssl_enabled else 'HTTP'}, SSL verify: {ssl_verify}")

    # Create server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((bind_ip, bind_port))
        server.listen(5)
        server.settimeout(1)
        log.info(f"Server listening on {bind_ip}:{bind_port}")

        # Start background sync worker to handle WakeStation connection with retries
        sync_thread = threading.Thread(
            target=background_sync_worker,
            args=(wol_server_ip, wol_server_port, bind_port, bind_ip, ssl_enabled, ssl_verify),
            daemon=True,
        )
        sync_thread.start()

        # Main server loop
        while server_running:
            try:
                client_socket, address = server.accept()
                log.debug(f"Connection from {address}")

                # Handle client in a separate thread
                # Use current dry-run state if available, otherwise fall back to initial value
                current_dry_run = dry_run_state["enabled"] if dry_run_state else dry_run
                client_thread = threading.Thread(
                    target=handle_client_connection,
                    args=(client_socket, users, current_dry_run),
                    daemon=True,
                )
                client_thread.start()

            except socket.timeout:
                # Check if we should continue running
                continue
            except OSError as e:
                if server_running:  # Only log if we're supposed to be running
                    log.error(f"Server socket error: {e}")
                break

    except Exception as e:
        log.error(f"Server error: {e}")
    finally:
        server.close()
        log.info("Server stopped")


def start_server_thread(
    bind_ip: str,
    bind_port: int,
    users: Dict[str, Any],
    wol_server_ip: str,
    wol_server_port: int,
    dry_run: bool = False,
    dry_run_state: dict = None,
    ssl_enabled: bool = True,
    ssl_verify: bool = True,
):
    """Start server in a separate thread for GUI applications."""
    global server_thread

    server_thread = threading.Thread(
        target=start_server,
        args=(
            bind_ip,
            bind_port,
            users,
            wol_server_ip,
            wol_server_port,
            dry_run,
            dry_run_state,
            ssl_enabled,
            ssl_verify,
        ),
        daemon=True,
    )
    server_thread.start()
    log.info("Server started in background thread")


def stop_server():
    """Stop the running server."""
    global server_running
    server_running = False
    log.info("Server shutdown requested")
