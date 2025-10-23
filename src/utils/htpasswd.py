#!/usr/bin/env python3
"""!
********************************************************************************
@file   htpasswd.py
@brief  User management and password hashing utilities for WakeStation
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import bcrypt
import getpass
import os
import sys
import config

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
from src import logger_config as logger
from src.core.user import User

log = logger.get_logger("WakeStation-AUTH")


def hash_password(password):
    """Hash a password using bcrypt."""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
    return hashed


def save_to_users_json(username, hashed_password, permission="user"):
    """Save the username, hashed password, and permission to the users.json file."""
    users = User.load_users()
    users[username] = {
        "username": username,
        "password_hash": hashed_password,
        "permission": "admin",  # Hardcoded admin for CLI user creation
    }
    User.save_users(users)


def user_exists(username):
    """Check if the username already exists in the users.json file."""
    users = User.load_users()
    return username in users


def generate_key():
    if os.path.exists(config.ENCRYPTION_KEY_FILE):
        print(
            f"Key file already exists at {config.ENCRYPTION_KEY_FILE}. No new key generated."
        )
        return
    os.makedirs(config.DB_DIR, exist_ok=True)
    key = os.urandom(32)
    with open(config.ENCRYPTION_KEY_FILE, "wb") as key_file:
        key_file.write(key)
    print(
        f"We generated a {config.ENCRYPTION_KEY_FILE}. \r\nIt is used to en/decrypt all commands and Data send between the WOL-server and the Shutdown-daemon\r\nMake sure to keep it safe!"
    )


def create_user():
    print("Create a new user")
    log.info("Interactive user creation started")
    username = input("Enter username: ")
    if user_exists(username):
        print("Error: Username already exists.")
        log.warning(f"Attempted to create existing username: {username}")
        return

    password = getpass.getpass("Enter password: ")
    confirm_password = getpass.getpass("Confirm password: ")

    if password != confirm_password:
        print("Error: Passwords do not match.")
        log.warning("Password confirmation failed during user creation")
        return

    hashed_password = hash_password(password)
    save_to_users_json(username, hashed_password)
    print("User added successfully.")
    log.info(f"User created successfully: {username}")
    generate_key()
