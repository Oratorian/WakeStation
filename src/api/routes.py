#!/usr/bin/env python3
"""!
********************************************************************************
@file   routes.py
@brief  Flask API routes and web endpoints for WakeStation
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
    """Setup all API routes for the Flask app"""
    log = logger.get_logger("routes")

    # Daemon registry file path
    DAEMON_REGISTRY_FILE = os.path.join("db", "daemon_registry.json")

    def register_daemon(daemon_ip: str, daemon_port: int, daemon_mac: str = None):
        """Register a daemon's IP, port, and MAC address for later use."""
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
        """Get daemon information by IP address."""
        try:
            if os.path.exists(DAEMON_REGISTRY_FILE):
                with open(DAEMON_REGISTRY_FILE, "r") as f:
                    daemon_registry = json.load(f)
                    return daemon_registry.get(daemon_ip, {})
        except Exception as e:
            log.error(f"Error reading daemon registry: {e}")
        return {}

    def update_pcs_with_daemon_ips(username: str) -> bool:
        """Update user PC entries with available daemon IPs."""
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
                    return jsonify({"success": True, "message": "Login successful"}), 200
                return redirect(url_for("index"))
            else:
                log.warning(f"Authentication failed for user: {username}")
                if request.is_json:
                    return jsonify({"success": False, "message": "Invalid credentials"}), 401
                return render_template("login.html", error="Invalid credentials")

        return render_template("login.html")

    @app.route("/api/login", methods=["POST"])
    def api_login():
        """Dedicated login endpoint for API clients (Android app)"""
        try:
            if not request.is_json:
                return jsonify({"success": False, "message": "Content-Type must be application/json"}), 400

            data = request.get_json()
            username = data.get("username")
            password = data.get("password")
            remember = data.get("remember", False)

            if not username or not password:
                return jsonify({"success": False, "message": "Username and password are required"}), 400

            log.debug(f"API login attempt for user: {username}")

            users = user.User.authenticate(username, password)
            if users:
                log.info(f"API authentication successful for user: {username}")
                login_user(users, remember=remember)

                # Update PC list with daemon IPs after successful login
                update_pcs_with_daemon_ips(username)

                response = jsonify({"success": True, "message": "Login successful"})
                return response, 200
            else:
                log.warning(f"API authentication failed for user: {username}")
                response = jsonify({"success": False, "message": "Invalid credentials"})
                response.headers["Content-Length"] = str(len(response.get_data()))
                return response, 401

        except Exception as e:
            log.error(f"API login exception: {e}")
            response = jsonify({"success": False, "message": "Internal server error"})
            response.headers["Content-Length"] = str(len(response.get_data()))
            return response, 500

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        logout_user()

        # Check if this is an API request (Accept: application/json)
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"success": True, "message": "Logged out successfully"})

        # For web UI, redirect to login page
        return redirect(url_for("login"))

    @app.route("/")
    @login_required
    def index():
        return render_template("index.html", user_permission=current_user.permission)

    @app.route("/api/load", methods=["GET"])
    @login_required
    def load_pcs():
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

            # Check if we received an encrypted payload (new method)
            encrypted_payload = data.get("encrypted_payload")
            if encrypted_payload:
                # Pass encrypted payload directly to daemon (end-to-end encryption)
                log.info(f"Shutdown request for {pc_ip}: Using end-to-end encryption")
                result = workers.send_encrypted_shutdown_command(
                    pc_ip, encrypted_payload
                )
            else:
                # Legacy method: encrypt on server side
                username = data.get("username")
                password = data.get("password")
                fallback_reason = data.get("fallback_reason")

                if fallback_reason:
                    log.critical(
                        f"Shutdown request for {pc_ip}: End-to-end encryption failed - {fallback_reason}"
                    )
                    log.info(
                        f"Shutdown request for {pc_ip}: Falling back to server-side encryption"
                    )
                else:
                    log.info(
                        f"Shutdown request for {pc_ip}: Using server-side encryption (legacy)"
                    )

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

    @app.route("/api/get_encryption_key", methods=["GET"])
    @login_required
    def get_encryption_key():
        """Serve encryption key to authenticated browser clients"""
        try:
            encryption_key = user.User.load_key()
            encryption_key_encoded = base64.b64encode(encryption_key).decode("utf-8")

            return (
                jsonify({"success": True, "encryption_key": encryption_key_encoded}),
                200,
            )

        except Exception as e:
            log.error(f"Error serving encryption key to browser: {str(e)}")
            return jsonify({"success": False, "message": "Internal server error"}), 500

    @app.route("/api/log_encryption_failure", methods=["POST"])
    @login_required
    def log_encryption_failure():
        """Log encryption failures reported by browser clients"""
        try:
            data = request.get_json()
            failure_reason = data.get("failure_reason", "Unknown failure")
            failure_type = data.get("failure_type", "unknown")

            log.critical(
                f"Browser encryption failure ({failure_type}): {failure_reason}"
            )
            return jsonify({"success": True}), 200

        except Exception as e:
            log.error(f"Error logging encryption failure: {str(e)}")
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
