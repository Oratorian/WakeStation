#!/usr/bin/env python3
"""!
********************************************************************************
@file   auth.py
@brief  Authentication and user management for WakeStation shutdown daemon
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import json
import bcrypt
from typing import Dict, Any
from ..config import USERS_FILE_PATH
from ..utils import get_daemon_logger

log = get_daemon_logger("auth")


def initialize_users():
    """Initialize user data from file or create first user."""
    if not os.path.exists(USERS_FILE_PATH):
        log.info(
            "No users file found. Prompting user to set up the first username and password."
        )

        # Check if GUI is available for setup dialog
        try:
            from ..gui.setup_dialog import TRAY_AVAILABLE, get_user_credentials_gui

            if TRAY_AVAILABLE:
                username, password = get_user_credentials_gui()
                if not username or not password:
                    log.error("User setup cancelled or invalid credentials provided")
                    return {}
            else:
                raise ImportError("GUI not available")
        except ImportError:
            # Fallback to console input
            username = input("Enter the first username: ").strip()
            while not username:
                log.warning("Username cannot be empty!")
                username = input("Enter the first username: ").strip()

            password = input("Enter the password: ").strip()
            while not password:
                log.warning("Password cannot be empty!")
                password = input("Enter the password: ").strip()

        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        users = {
            username: {
                "username": username,
                "password_hash": password_hash,
                "permission": "user",
            }
        }

        with open(USERS_FILE_PATH, "w") as users_file:
            json.dump(users, users_file, indent=4)
        log.info("First user has been set up and saved successfully.")
        return users
    else:
        with open(USERS_FILE_PATH, "r") as users_file:
            return json.load(users_file)


def authenticate_user(username: str, password: str, users: Dict[str, Any]) -> bool:
    """Authenticate user credentials against user database."""
    if username in users:
        hashed_password = users[username]["password_hash"].encode()
        return bcrypt.checkpw(password.encode(), hashed_password)
    return False
