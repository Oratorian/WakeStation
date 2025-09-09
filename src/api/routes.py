#!/usr/bin/env python3
"""!
********************************************************************************
@brief  Flask API routes and web endpoints for WakeStation

@file   routes.py
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import json
import bcrypt
import glob
import base64
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from flask import request, jsonify, render_template, redirect, url_for
from flask_login import login_user, logout_user, current_user, login_required
from ..core import user
import config
from ..utils import network as sources
from ..utils.wol import wake_device
from ..core import workers  # Still needed for shutdown functionality
from ..logger import logger


def setup_routes(app):
    """!
    @brief Setup all API routes and internal helper functions for the Flask application.

    Main route registration function that defines all web endpoints, API routes,
    and internal helper functions for the WakeStation server. This includes:
    - Authentication routes (login/logout)
    - PC management API (add, delete, wake, shutdown)
    - User management endpoints
    - Daemon registration and synchronization
    - Status checking and monitoring

    The function encapsulates all route handlers and helper functions within
    its scope to maintain proper Flask app context and logging configuration.

    @param app Flask application instance to register routes with

    @note All route handlers are defined as nested functions within this scope
    @note Daemon registry functionality is included for shutdown daemon integration
    @note Logging is initialized once and shared across all route handlers
    @note Routes support both web interface and API clients with appropriate responses

    @warning Routes must be registered after Flask-Login is properly configured

    @throws Exception Various Flask and database errors during route registration
    """
    log = logger.get_logger("routes")

    # Daemon registry file path
    DAEMON_REGISTRY_FILE = config.DAEMON_DATA_FILE

    def register_daemon(daemon_ip: str, daemon_port: int, daemon_mac: str = None):
        """!
        @brief Register a shutdown daemon's connection details for future remote shutdown operations.

        Maintains a persistent registry of active shutdown daemons that can be used
        for remote shutdown operations. Each daemon entry includes network details
        and timestamps for tracking availability.

        Registry entry includes:
        - IP address and port for daemon communication
        - MAC address for network identification (if available)
        - Last seen timestamp for staleness detection

        @param daemon_ip IP address where the shutdown daemon is listening
        @param daemon_port Port number the daemon is bound to (typically 8080)
        @param daemon_mac MAC address of the daemon's network interface (optional)

        @note Creates db directory if it doesn't exist
        @note Uses IP address as unique key (one daemon per IP assumption)
        @note Overwrites existing entries for the same IP address
        @note Registry is persisted to daemon_registry.json for server restarts

        @warning No validation of daemon connectivity - registration is declarative

        @throws json.JSONDecodeError If existing registry file is corrupted
        @throws IOError If registry file cannot be written
        @throws Exception Various file system and serialization errors
        """
        try:
            # Ensure the db directory exists
            os.makedirs("db", exist_ok=True)

            # Load existing registry
            daemon_registry = {}
            if os.path.exists(DAEMON_REGISTRY_FILE):
                with open(DAEMON_REGISTRY_FILE, "r") as f:
                    daemon_registry = json.load(f)

            # Create daemon entry with timestamp and MAC
            from datetime import datetime

            daemon_entry = {
                "ip": daemon_ip,
                "port": daemon_port,
                "mac": daemon_mac,
                "last_seen": datetime.now().isoformat(),
            }

            # Use IP as key (assuming one daemon per IP)
            daemon_registry[daemon_ip] = daemon_entry

            # Save updated registry
            with open(DAEMON_REGISTRY_FILE, "w") as f:
                json.dump(daemon_registry, f, indent=2)

            log.info(f"Daemon registry updated: {daemon_ip}:{daemon_port}")

        except Exception as e:
            log.error(f"Error registering daemon {daemon_ip}:{daemon_port}: {e}")

    def get_daemon_by_ip(daemon_ip: str) -> dict:
        """!
        @brief Retrieve registered daemon information by IP address.

        Looks up daemon details from the persistent registry to enable
        remote shutdown operations. Used when the system needs to contact
        a specific daemon for shutdown requests.

        @param daemon_ip IP address of the daemon to look up
        @return Dictionary containing daemon details (ip, port, mac, last_seen) or empty dict
        @retval dict Daemon information if found, empty dictionary if not found

        @note Returns empty dict if registry file doesn't exist
        @note Returns empty dict if daemon IP is not registered
        @note Logs errors but returns empty dict for graceful degradation
        @note No staleness checking - returns data regardless of last_seen timestamp

        @throws json.JSONDecodeError If registry file is corrupted (logged, returns empty dict)
        @throws IOError If registry file cannot be read (logged, returns empty dict)
        """
        try:
            if os.path.exists(DAEMON_REGISTRY_FILE):
                with open(DAEMON_REGISTRY_FILE, "r") as f:
                    daemon_registry = json.load(f)
                    return daemon_registry.get(daemon_ip, {})
        except Exception as e:
            log.error(f"Error reading daemon registry: {e}")
        return {}

    def update_pcs_with_daemon_ips(username: str) -> bool:
        """!
        @brief Update user PC entries with available daemon IPs for shutdown functionality.

        Automatically updates PC records to use active daemon IP addresses for remote
        shutdown operations. This function ensures PCs have valid daemon connections
        by checking daemon availability and updating stale or missing IP addresses.

        Update logic:
        1. Loads user's PC configuration file
        2. Checks each PC for missing or non-responsive daemon IP
        3. Finds the most recently seen daemon from registry
        4. Updates PC entries with active daemon IPs
        5. Saves updated configuration if changes were made

        @param username The username whose PC entries should be updated
        @return True if any PC entries were updated, False if no changes made
        @retval bool Indicates whether the PC configuration was modified

        @note Only updates PCs that lack IPs or have non-responsive daemons
        @note Selects most recently seen daemon based on last_seen timestamp
        @note Preserves all other PC attributes during IP updates
        @note Logs all IP address changes for audit purposes

        @warning Returns False if user has no PC file or no daemons available
        @warning Simple selection algorithm may not match optimal daemon for each PC

        @throws json.JSONDecodeError If PC file or daemon registry is corrupted
        @throws IOError If PC file cannot be read or written
        @throws Exception Various file system and data processing errors
        """
        try:
            user_pc_file = user.User.get_user_pc_file(username)
            if not os.path.exists(user_pc_file):
                return False

            # Load user PCs
            with open(user_pc_file, "r") as f:
                pcs = json.load(f)

            # Load daemon registry
            daemon_registry = {}
            if os.path.exists(DAEMON_REGISTRY_FILE):
                with open(DAEMON_REGISTRY_FILE, "r") as f:
                    daemon_registry = json.load(f)

            if not daemon_registry:
                return False  # No daemons available

            updated = False
            for pc in pcs:
                # Update PC if it has no IP or daemon is not available
                if not pc.get("ip") or not sources.check_shutdown_daemon(pc["ip"]):
                    # Find the most recent daemon (could be enhanced with hostname matching)
                    most_recent_daemon = None
                    most_recent_time = None

                    for daemon_ip, daemon_info in daemon_registry.items():
                        last_seen = daemon_info.get("last_seen")
                        if last_seen:
                            if most_recent_time is None or last_seen > most_recent_time:
                                most_recent_time = last_seen
                                most_recent_daemon = daemon_info

                    if most_recent_daemon:
                        old_ip = pc.get("ip", "")
                        pc["ip"] = most_recent_daemon["ip"]
                        log.info(
                            f"Updated PC {pc.get('hostname', 'Unknown')} IP: {old_ip} -> {most_recent_daemon['ip']}"
                        )
                        updated = True

            # Save updated PC list if changes were made
            if updated:
                with open(user_pc_file, "w") as f:
                    json.dump(pcs, f, indent=4)
                log.info(f"Updated PC file for user {username} with daemon IPs")

            return updated

        except Exception as e:
            log.error(f"Error updating PCs with daemon IPs for user {username}: {e}")
            return False

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """!
        @brief Handle user authentication for both web and API clients.

        Provides login functionality supporting both form-based web authentication
        and JSON-based API authentication. Handles credential validation, session
        creation, and appropriate response formatting based on client type.

        POST request handling:
        - JSON requests: Extracts credentials from JSON body
        - Form requests: Extracts credentials from form data
        - Validates credentials against user database
        - Creates Flask-Login session with optional remember functionality
        - Returns JSON response for API clients or redirect for web clients

        GET request handling:
        - Returns login form template for web browsers

        @return JSON success/error for API clients, template/redirect for web clients
        @retval Response Authentication result with appropriate content type

        @note Supports both JSON API and HTML form authentication methods
        @note Remember me functionality extends session duration
        @note Logs all authentication attempts and outcomes
        @note Failed authentication returns 401 status for API clients

        @warning Password is validated in plaintext during transmission
        @warning Session security depends on proper HTTPS configuration

        @throws Exception Various authentication and session creation errors
        """
        if request.method == "POST":

            if request.is_json:
                data = request.get_json()
                username = data.get("username")
                password = data.get("password")
                remember = data.get("remember", False)
            else:

                username = request.form.get("username")
                password = request.form.get("password")
                remember = request.form.get("remember") == "on"

            log.debug(f"Attempting to authenticate user: {username}")

            users = user.User.authenticate(username, password)
            if users:
                log.info(f"Authentication successful for user: {username}")
                login_user(users, remember=remember)
                if request.is_json:
                    return jsonify({"message": "Login successful"}), 200
                return redirect(url_for("index"))
            else:
                log.warning(f"Authentication failed for user: {username}")
                if request.is_json:
                    return jsonify({"message": "Invalid credentials"}), 401
                return render_template("login.html", error="Invalid credentials")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        """!
        @brief Handle user logout and session termination.

        Terminates the current user session using Flask-Login and redirects
        to the login page. This endpoint is accessible to any authenticated user.

        @return Redirect response to login page
        @retval Response HTTP redirect to /login endpoint

        @note Uses Flask-Login's logout_user() for proper session cleanup
        @note Always redirects to login page regardless of user state
        @note Clears both session data and remember me cookies

        @throws Exception Session cleanup errors are handled by Flask-Login
        """
        logout_user()
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        """!
        @brief Serve the main WakeStation web interface dashboard.

        Returns the main HTML interface for authenticated users to manage
        their Wake-on-LAN devices. This is the primary entry point for the
        web application after successful authentication.

        @return HTML template response with main interface
        @retval Response Rendered dashboard template

        @note Requires user authentication via @login_required decorator
        @note Serves as the default landing page after login
        @note Template likely contains JavaScript for device management

        @throws Exception Template rendering errors
        """
        return render_template("index.html", user_permission=current_user.permission)

    @app.route("/api/load", methods=["GET"])
    @login_required
    def load_pcs():
        """!
        @brief Load and return comprehensive PC status information for the authenticated user.

        API endpoint that retrieves all PCs owned by the current user along with
        their comprehensive status information including:
        - Basic PC details (hostname, MAC, IP)
        - Network reachability status
        - Wake-on-LAN capability detection
        - Shutdown daemon availability
        - Smart IP resolution using daemon registry

        The function automatically updates PC entries with active daemon IPs
        and saves changes to maintain current connectivity information.

        @return JSON response containing PC list with status or error message
        @retval Response JSON object with success flag and PC data array

        @note Requires user authentication via @login_required decorator
        @note Automatically resolves missing/stale IP addresses using daemon registry
        @note Updates user PC file if IP addresses are resolved/changed
        @note Comprehensive status includes multiple network connectivity tests
        @note Logs detailed processing information for debugging

        @warning Large PC lists may take significant time to process due to network tests
        @warning Network timeouts can cause slow response times

        @throws json.JSONDecodeError If user PC file or daemon registry is corrupted
        @throws IOError If user PC file cannot be read or written
        @throws Exception Various network and data processing errors
        """
        log.info(
            f"API /api/load called by user: {current_user.username if current_user.is_authenticated else 'NOT AUTHENTICATED'}"
        )
        try:
            user_pc_file = user.User.get_user_pc_file(current_user.username)
            log.info(f"User PC file path: {user_pc_file}")
            log.debug(
                f"Loading PCs for user {current_user.username} from {user_pc_file}"
            )
        except Exception as e:
            log.error(f"Error getting user PC file: {e}")
            return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

        try:
            # Load daemon registry for IP resolution
            daemon_registry = {}
            if os.path.exists(DAEMON_REGISTRY_FILE):
                with open(DAEMON_REGISTRY_FILE, "r") as f:
                    daemon_registry = json.load(f)

            if os.path.exists(user_pc_file):
                with open(user_pc_file, "r") as file:
                    pcs = json.load(file)

                # Get comprehensive status for each PC using smart IP resolution
                pc_data_changed = False
                log.info(f"Processing {len(pcs)} PCs for status info")
                for i, pc in enumerate(pcs):
                    log.info(f"Processing PC {i+1}: {pc.get('hostname', 'Unknown')}")
                    original_ip = pc.get("ip", "")
                    log.info(
                        f"About to call get_pc_status_info for {pc.get('hostname')}"
                    )

                    # Use comprehensive IP resolution with daemon registry
                    log.info("Using comprehensive IP resolution with daemon registry")

                    try:
                        from src.utils.network import resolve_pc_ip

                        # Try to resolve IP using all available methods (localhost, daemon, ARP, stored)
                        resolved_ip, ip_source = resolve_pc_ip(pc, daemon_registry)

                        status_info = {
                            "ip": resolved_ip if resolved_ip else "",
                            "ip_source": ip_source,
                            "status": "unknown",
                            "daemon_available": False,
                        }

                        log.info(
                            f"Resolved {pc.get('hostname')} -> IP: {resolved_ip} via {ip_source}"
                        )

                    except Exception as e:
                        log.error(f"IP resolution failed for {pc.get('hostname')}: {e}")
                        # Fallback to stored IP
                        status_info = {
                            "ip": pc.get("ip", ""),
                            "ip_source": "stored",
                            "status": "unknown",
                            "daemon_available": False,
                        }

                    # Only do basic daemon check if we have a resolved IP
                    if status_info["ip"]:
                        try:
                            from src.utils.network import (
                                check_shutdown_daemon,
                                ping_host,
                            )

                            is_online = ping_host(status_info["ip"], timeout=1)
                            status_info["status"] = "online" if is_online else "offline"
                            if is_online:
                                status_info["daemon_available"] = check_shutdown_daemon(
                                    status_info["ip"], timeout=2
                                )
                        except Exception as e:
                            log.warning(
                                f"Quick status check failed for {pc.get('hostname')}: {e}"
                            )

                    log.info(f"Status info for {pc.get('hostname')}: {status_info}")

                    # Update PC with resolved information
                    pc["ip"] = status_info["ip"]
                    pc["status"] = status_info["status"]
                    pc["daemon_available"] = status_info["daemon_available"]
                    pc["ip_source"] = status_info["ip_source"]  # For debugging/info

                    # Check if IP was resolved and is different from stored
                    if (
                        status_info["ip"]
                        and status_info["ip"] != original_ip
                        and status_info["ip_source"] in ["daemon", "arp"]
                    ):
                        pc_data_changed = True
                        log.info(
                            f"PC {pc.get('hostname', 'Unknown')}: IP updated {original_ip} -> {status_info['ip']} via {status_info['ip_source']}"
                        )

                # Save updated IPs back to file if any changed
                if pc_data_changed:
                    try:
                        with open(user_pc_file, "w") as file:
                            json.dump(pcs, file, indent=2)
                        log.info(
                            f"Updated PC file with resolved IPs for user {current_user.username}"
                        )
                    except Exception as e:
                        log.error(f"Failed to save updated PC file: {e}")

                return jsonify({"success": True, "pcs_list": pcs})
            else:
                return jsonify({"success": True, "pcs_list": []})
        except Exception as e:
            log.error(f"Error loading PCs for user {current_user.username}: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/status", methods=["GET"])
    @login_required
    def check_pc_status():
        """!
        @brief Check the network status and daemon availability of a specific IP address.

        API endpoint that performs network connectivity tests for a given IP address:
        - Ping test to determine if host is reachable
        - Shutdown daemon availability test on port 8080

        Expected query parameter:
        - ip: The IP address to check

        @return JSON response with status and daemon availability
        @retval Response JSON with success flag, status (online/offline), and daemon_available flag

        @note Requires user authentication via @login_required decorator
        @note Uses ping_host() for basic connectivity testing
        @note Uses check_shutdown_daemon() for daemon service detection
        @note Returns 400 error if IP parameter is missing
        @note Returns 500 error if network tests fail with exceptions

        @warning Network tests may timeout causing slow response times

        @throws Exception Various network connectivity and testing errors
        """
        ip = request.args.get("ip")
        if not ip:
            return jsonify({"success": False, "message": "IP address required"}), 400

        try:
            status = "online" if sources.ping_host(ip) else "offline"
            daemon_available = sources.check_shutdown_daemon(ip)
            return jsonify(
                {
                    "success": True,
                    "status": status,
                    "daemon_available": daemon_available,
                }
            )
        except Exception as e:
            log.error(f"Error checking status for {ip}: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/add", methods=["POST"])
    @login_required
    def add_pc():
        """!
        @brief Add a new PC to the authenticated user's device list.

        API endpoint that allows users to register new Wake-on-LAN devices.
        Validates input data, checks for duplicates, and stores the PC configuration
        in the user's personal PC file.

        Expected JSON payload:
        - hostname: Display name for the PC
        - mac: MAC address for Wake-on-LAN
        - ip: Optional IP address for shutdown daemon

        @return JSON response indicating success or failure with appropriate message
        @retval Response JSON with success flag and descriptive message

        @note Requires user authentication via @login_required decorator
        @note Validates MAC address format and uniqueness within user's PC list
        @note Creates user PC file if it doesn't exist
        @note Automatically attempts to resolve IP if daemon registry is available
        @note Returns 400 error for invalid JSON or missing required fields
        @note Returns 409 error for duplicate MAC addresses

        @warning Duplicate MAC addresses are rejected to prevent conflicts
        @warning Large PC lists may impact performance during duplicate checking

        @throws json.JSONDecodeError If request body contains invalid JSON
        @throws IOError If user PC file cannot be read or written
        @throws Exception Various data validation and file system errors
        """
        user_pc_file = user.User.get_user_pc_file(current_user.username)
        try:
            post_data = request.get_json()
            if post_data is None:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "No JSON data received or incorrect Content-Type",
                        }
                    ),
                    400,
                )

            mac = post_data.get("mac")
            hostname = post_data.get("hostname")

            if not mac or not hostname:
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Missing required parameters: mac and hostname",
                        }
                    ),
                    400,
                )

            # Validate MAC address format
            if not sources.validate_mac_address(mac):
                return (
                    jsonify(
                        {
                            "success": False,
                            "message": "Invalid MAC address format. Use format: AA:BB:CC:DD:EE:FF",
                        }
                    ),
                    400,
                )

            # Try to find a daemon IP from the registry
            daemon_ip = None
            try:
                if os.path.exists(DAEMON_REGISTRY_FILE):
                    with open(DAEMON_REGISTRY_FILE, "r") as f:
                        daemon_registry = json.load(f)

                    if daemon_registry:
                        # For now, use the most recently seen daemon
                        # In future, could implement hostname matching or user selection
                        most_recent_daemon = None
                        most_recent_time = None

                        for ip, daemon_info in daemon_registry.items():
                            last_seen = daemon_info.get("last_seen")
                            if last_seen:
                                if (
                                    most_recent_time is None
                                    or last_seen > most_recent_time
                                ):
                                    most_recent_time = last_seen
                                    most_recent_daemon = daemon_info

                        if most_recent_daemon:
                            daemon_ip = most_recent_daemon["ip"]
                            log.info(
                                f"Using daemon IP {daemon_ip} for new PC {hostname}"
                            )
            except Exception as e:
                log.warning(f"Error reading daemon registry: {e}")

            # Create PC entry with daemon IP if found, otherwise with placeholder
            if daemon_ip:
                new_pc = {"mac": mac, "ip": daemon_ip, "hostname": hostname}
                message = f"PC added successfully with daemon IP {daemon_ip}"
            else:
                # Store without IP - could be updated later when daemon becomes available
                new_pc = {"mac": mac, "ip": "", "hostname": hostname}
                message = "PC added successfully (no shutdown daemon detected yet)"

            pcs = []
            if os.path.exists(user_pc_file):
                with open(user_pc_file, "r") as file:
                    pcs = json.load(file)

            pcs.append(new_pc)

            with open(user_pc_file, "w") as file:
                json.dump(pcs, file, indent=4)

            return jsonify({"success": True, "message": message, "pcs_list": pcs})

        except ValueError as e:
            log.error(
                f"ValueError while adding PC for user {current_user.username}: {e}"
            )
            return jsonify({"success": False, "message": str(e)}), 400
        except Exception as e:
            log.error(
                f"Unexpected error while adding PC for user {current_user.username}: {e}"
            )
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/delete", methods=["GET"])
    @login_required
    def delete_pc():
        """!
        @brief Delete a PC from the authenticated user's device list.

        API endpoint that removes a PC entry from the user's device configuration
        based on the MAC address. The PC is identified and removed from the user's
        personal PC file.

        Expected query parameter:
        - mac: The MAC address of the PC to delete

        @return JSON response indicating success or failure with appropriate message
        @retval Response JSON with success flag and descriptive message

        @note Requires user authentication via @login_required decorator
        @note Uses MAC address as unique identifier for PC deletion
        @note Returns 400 error if MAC parameter is missing
        @note Returns 404 error if PC with specified MAC is not found
        @note Automatically saves updated PC list after successful deletion

        @warning Deletion is permanent and cannot be undone
        @warning Deletes only from the current user's PC list

        @throws json.JSONDecodeError If user PC file is corrupted
        @throws IOError If user PC file cannot be read or written
        @throws Exception Various file system and data processing errors
        """
        mac = request.args.get("mac")
        if mac:
            try:

                user_json_file = user.User.get_user_pc_file(current_user.username)

                with open(user_json_file, "r") as file:
                    pcs = json.load(file)

                pcs_before = len(pcs)
                pcs = [pc for pc in pcs if pc["mac"] != mac]
                pcs_after = len(pcs)

                if pcs_before == pcs_after:
                    return (
                        jsonify(
                            {
                                "success": False,
                                "message": f"MAC address {mac} not found",
                            }
                        ),
                        404,
                    )

                with open(user_json_file, "w") as file:
                    json.dump(pcs, file, indent=4)

                return jsonify(
                    {
                        "success": True,
                        "message": f"Deleted PC with MAC {mac}",
                        "pcs_list": pcs,
                    }
                )
            except Exception as e:
                log.error(f"Error deleting PC: {e}")
                return (
                    jsonify({"success": False, "message": "Internal server error"}),
                    500,
                )
        else:
            return (
                jsonify({"success": False, "message": "MAC address not provided"}),
                400,
            )

    @app.route("/api/shutdown", methods=["POST"])
    @login_required
    def shutdown_pc():
        try:
            data = request.get_json()
            pc_ip = data.get("pc_ip")
            if not pc_ip:
                return (
                    jsonify({"success": False, "message": "PC IP address is required"}),
                    400,
                )

            username = data.get("username")
            password = data.get("password")

            result = workers.send_shutdown_command(pc_ip, username, password)
            status_code = (
                200
                if result["success"]
                else (
                    400
                    if "Error" in result["message"] or "Invalid" in result["message"]
                    else 500
                )
            )
            return jsonify(result), status_code

        except Exception as e:
            log.error(f"Exception in shutdown_pc: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/create_user", methods=["POST"])
    @login_required
    def create_user():
        log.info("Create user route accessed")
        if current_user.permission != "admin":
            log.error("Unauthorized access attempt by user: %s", current_user.username)
            return jsonify({"error": "Unauthorized"}), 403

        data = request.get_json()
        log.info("Received data: %s", data)
        username = data.get("username")
        password = data.get("password")
        permission = data.get("permission")
        try:
            user.User.create(username, password, permission)
            log.info("User %s created successfully", username)
            return jsonify({"success": True, "message": "User added successfully"}), 200
        except Exception as e:
            log.error("Error creating user: %s", str(e))
            return jsonify({"error": str(e)}), 400

    @app.route("/api/users", methods=["GET"])
    @login_required
    def get_users():
        try:
            if os.path.exists(config.USERS_FILE):
                with open(config.USERS_FILE, "r") as f:
                    users = json.load(f)
                return jsonify({"success": True, "users": users})
            else:
                return (
                    jsonify({"success": False, "message": "Users file not found."}),
                    404,
                )
        except Exception as e:
            log.error(f"Error retrieving users: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/change_permission", methods=["POST"])
    @login_required
    def change_permission():
        if current_user.permission != "admin":
            return jsonify({"success": False, "message": "Unauthorized access"}), 403
        try:
            data = request.get_json()
            username = data["username"]
            new_permission = data["permission"]

            if os.path.exists(config.USERS_FILE):
                with open(config.USERS_FILE, "r") as f:
                    users = json.load(f)

                if username in users:
                    users[username]["permission"] = new_permission
                else:
                    return jsonify({"success": False, "message": "User not found"}), 404

                with open(config.USERS_FILE, "w") as f:
                    json.dump(users, f)

                return jsonify(
                    {"success": True, "message": "Permission updated successfully"}
                )

            else:
                return (
                    jsonify({"success": False, "message": "Users file not found."}),
                    404,
                )
        except Exception as e:
            log.error(f"Error changing permission: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/delete_user", methods=["POST"])
    @login_required
    def delete_user():
        if current_user.permission != "admin":
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        try:
            data = request.get_json()
            username = data.get("username")

            if os.path.exists(config.USERS_FILE):
                with open(config.USERS_FILE, "r") as f:
                    users = json.load(f)

                if username in users:
                    del users[username]
                else:
                    return jsonify({"success": False, "message": "User not found"}), 404

                with open(config.USERS_FILE, "w") as f:
                    json.dump(users, f)

                user_pc_files_pattern = os.path.join(
                    config.PC_DATA_DIR, f"{username}_pcs.json"
                )
                for file_path in glob.glob(user_pc_files_pattern):
                    os.remove(file_path)

                return jsonify(
                    {
                        "success": True,
                        "message": "User and associated PC files deleted successfully",
                    }
                )

            else:
                return (
                    jsonify({"success": False, "message": "Users file not found."}),
                    404,
                )
        except Exception as e:
            log.error(f"Error deleting user: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/wake", methods=["GET"])
    @login_required
    def wake_pc():
        """!
        @brief Send Wake-on-LAN packet to wake up a target PC.

        API endpoint that sends a Wake-on-LAN (WOL) magic packet to wake up
        a sleeping or powered-off PC using its MAC address. This is the core
        functionality of the WakeStation server.

        Expected query parameter:
        - mac: The MAC address of the PC to wake up

        @return JSON response indicating success or failure of the wake operation
        @retval Response JSON with success flag and descriptive message

        @note Requires user authentication via @login_required decorator
        @note Uses wake_device() utility function to send the magic packet
        @note Logs all wake requests with user and MAC address for auditing
        @note Returns 200 status for successful wake, 500 for failures
        @note Returns 400 error if MAC parameter is missing

        @warning Wake-on-LAN requires target PC to have WOL enabled in BIOS/UEFI
        @warning PC must be connected to power and network for wake to succeed

        @throws Exception Various network and wake packet transmission errors
        """
        mac = request.args.get("mac")
        if mac:
            log.info(f"Wake-on-LAN request for MAC: {mac} by user: {current_user.id}")
            result = wake_device(mac)  # Returns dict with success/message
            status_code = 200 if result["success"] else 500
            return jsonify(result), status_code
        else:
            return (
                jsonify({"success": False, "message": "MAC address is required"}),
                400,
            )

    @app.route("/api/change_password", methods=["POST"])
    @login_required
    def change_password():
        if current_user.permission != "admin":
            return jsonify({"success": False, "message": "Unauthorized access"}), 403

        try:
            salt = bcrypt.gensalt()
            data = request.get_json()
            username = data.get("username")
            new_password = data.get("password")

            if os.path.exists(config.USERS_FILE):
                with open(config.USERS_FILE, "r") as f:
                    users = json.load(f)

                if username in users:
                    users[username]["password_hash"] = bcrypt.hashpw(
                        new_password.encode("utf-8"), salt
                    ).decode("utf-8")
                else:
                    return jsonify({"success": False, "message": "User not found"}), 404

                with open(config.USERS_FILE, "w") as f:
                    json.dump(users, f)

                return jsonify(
                    {"success": True, "message": "Password updated successfully"}
                )

            else:
                return (
                    jsonify({"success": False, "message": "Users file not found."}),
                    404,
                )
        except Exception as e:
            log.error(f"Error changing password: {e}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/sync_encryption_key", methods=["POST"])
    def sync_encryption_key():
        try:
            log.info("Received data: %s", request.get_data(as_text=True))

            data = request.get_json()
            if data is None:
                data = {}  # Allow empty JSON body for key sync requests

            provided_signature = data.get("signature")
            timestamp = data.get("timestamp")

            log.info("Signature: %s, Timestamp: %s", provided_signature, timestamp)

            # If signature and timestamp are provided, verify them
            if provided_signature and timestamp:
                if user.User.verify_signature(
                    app.secret_key, provided_signature, str(timestamp)
                ):
                    authenticated = True
                else:
                    return (
                        jsonify({"success": False, "message": "Invalid signature"}),
                        403,
                    )
            else:
                # Allow key sync without authentication for initial daemon setup
                authenticated = True
                log.info(
                    "Key sync request without HMAC authentication - allowing for initial setup"
                )

            if authenticated:
                # Extract daemon registration info if provided
                daemon_ip = data.get("daemon_ip")
                daemon_port = data.get("daemon_port")
                daemon_mac = data.get("daemon_mac")

                if daemon_ip and daemon_port:
                    # Register daemon with the server including MAC address
                    register_daemon(daemon_ip, daemon_port, daemon_mac)
                    log.info(f"Registered daemon at {daemon_ip}:{daemon_port}")

                encryption_key = user.User.load_key()

                encryption_key_encoded = base64.b64encode(encryption_key).decode(
                    "utf-8"
                )

                return (
                    jsonify(
                        {
                            "success": True,
                            "encryption_key": encryption_key_encoded,
                        }
                    ),
                    200,
                )

        except Exception as e:
            log.error(f"Error in syncing encryption key: {str(e)}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/llm_command", methods=["POST"])
    @login_required
    def llm_command():
        """!
        @brief Process natural language Wake-on-LAN commands via LLM integration.

        API endpoint that allows users to send natural language commands like
        "wake andrew-pc" to control their registered PCs using an LLM for parsing.
        The LLM analyzes the command against the user's PC list and executes
        appropriate actions.

        Expected JSON payload:
        - command: Natural language command (e.g., "wake andrew-pc", "status of all computers")
        - llm_endpoint: Optional custom LLM endpoint URL

        @return JSON response with LLM interpretation and action results
        @retval Response JSON with success flag, LLM response, and action details

        @note Requires user authentication via @login_required decorator
        @note Uses existing PC data and wake functions for actual operations
        @note Communicates with local LLM at http://127.0.0.1:1234/v1/chat/completions by default
        @note Returns detailed response including LLM interpretation and execution results

        @warning Requires local LLM service to be running at specified endpoint
        @warning Network timeouts may occur if LLM service is slow or unavailable

        @throws Exception Various LLM communication and command execution errors
        """
        try:
            data = request.get_json()
            if not data:
                return (
                    jsonify({"success": False, "message": "No JSON data received"}),
                    400,
                )

            command = data.get("command")
            if not command:
                return (
                    jsonify(
                        {"success": False, "message": "Command parameter is required"}
                    ),
                    400,
                )

            llm_endpoint = data.get(
                "llm_endpoint", "http://127.0.0.1:1234/v1/chat/completions"
            )

            # Import and use the LLM integration
            from ..utils.llm_integration import process_natural_language_command

            log.info(
                f"Processing LLM command for user {current_user.username}: {command}"
            )

            # Generate session ID for conversation context (use username as simple session)
            session_id = f"{current_user.username}_{request.remote_addr}"

            result = process_natural_language_command(
                username=current_user.username,
                command=command,
                llm_endpoint=llm_endpoint,
                session_id=session_id,
            )

            status_code = 200 if result["success"] else 500
            return jsonify(result), status_code

        except Exception as e:
            log.error(f"Error processing LLM command: {e}")
            return (
                jsonify(
                    {
                        "success": False,
                        "message": "Internal server error",
                        "error": str(e),
                    }
                ),
                500,
            )
