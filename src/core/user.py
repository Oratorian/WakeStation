#!/usr/bin/env python3
"""!
********************************************************************************
@brief  User authentication and encryption utilities for WakeStation

@file   user.py
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import json
import bcrypt
from flask_login import UserMixin
import logging
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hmac
import hashlib
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
import config
from ..logger import logger

log = logger.get_logger("user")


class User(UserMixin):
    """!
    @brief User authentication and management class for WakeStation.

    Extends Flask-Login's UserMixin to provide user authentication, password
    verification, encryption services, and user data management for the
    WakeStation Wake-on-LAN server.

    Features:
    - Bcrypt password hashing and verification
    - AES encryption for secure data transmission
    - HMAC signature verification for API security
    - User file management and PC data storage
    - Flask-Login integration for session management

    @note Integrates with Flask-Login for session management
    @note Uses bcrypt for secure password storage
    @note Provides AES-256 encryption for sensitive data
    @note Manages per-user PC configuration files
    """

    def __init__(self, id, username, password_hash, permission):
        """!
        @brief Initialize User instance with authentication details.

        @param id Unique user identifier (typically username)
        @param username Display name for the user
        @param password_hash Bcrypt-hashed password for authentication
        @param permission User permission level ('admin' or 'user')
        """
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.permission = permission

    @staticmethod
    def load_users():
        """!
        @brief Load all users from the persistent JSON users file.

        Reads and parses the users.json file containing all registered user
        accounts with their hashed passwords and permissions.

        @return Dictionary of users with usernames as keys
        @retval dict User data structure or empty dict if file doesn't exist

        @note Returns empty dictionary if users file doesn't exist
        @note File location defined by config.USERS_FILE
        @note Contains password hashes, not plaintext passwords

        @throws json.JSONDecodeError If users file is corrupted
        @throws IOError If users file cannot be read
        """
        if os.path.exists(config.USERS_FILE):
            with open(config.USERS_FILE, "r") as f:
                return json.load(f)
        return {}

    @staticmethod
    def save_users(users):
        """!
        @brief Save users dictionary to the persistent JSON users file.

        Writes the complete users dictionary to disk, preserving all user
        accounts, password hashes, and permissions.

        @param users Dictionary of user data to save

        @note Overwrites existing users file completely
        @note File location defined by config.USERS_FILE
        @note Uses JSON format with proper indentation for readability

        @throws json.JSONEncoder If user data cannot be serialized
        @throws IOError If users file cannot be written
        """
        with open(config.USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

    @staticmethod
    def get(user_id):
        """!
        @brief Retrieve a User instance by user ID for Flask-Login integration.

        Required method for Flask-Login that loads a user from the persistent
        storage using their unique identifier. Used during session restoration
        and authentication checks.

        @param user_id Unique identifier of the user to retrieve
        @return User instance if found, None if user doesn't exist
        @retval User|None User object for successful lookups

        @note Required by Flask-Login for session management
        @note User ID is typically the same as username in WakeStation
        @note Returns None for invalid/deleted user accounts

        @throws json.JSONDecodeError If users file is corrupted
        @throws IOError If users file cannot be read
        """
        users = User.load_users()
        user_data = users.get(user_id)
        if user_data:
            return User(
                id=user_id,
                username=user_data["username"],
                password_hash=user_data["password_hash"],
                permission=user_data["permission"],
            )
        return None

    @staticmethod
    def authenticate(username, password):
        """!
        @brief Authenticate user credentials and return User instance if valid.

        Verifies username and password against stored user data using bcrypt
        password hashing. Returns a User instance for successful authentication
        or None for failed attempts.

        @param username The username to authenticate
        @param password The plaintext password to verify
        @return User instance if authentication succeeds, None if failed
        @retval User|None User object for valid credentials

        @note Uses bcrypt for secure password verification
        @note Logs all authentication attempts and outcomes
        @note Password is compared against stored bcrypt hash
        @note Essential for Flask-Login integration

        @warning Logs authentication failures for security monitoring

        @throws json.JSONDecodeError If users file is corrupted
        @throws IOError If users file cannot be read
        @throws Exception Various bcrypt verification errors
        """
        log.debug(f"Authenticating user: {username}")
        users = User.load_users()
        user_data = users.get(username)
        if user_data and User.verify_bcrypt_password(
            user_data["password_hash"], password
        ):
            log.info(f"User authentication successful: {username}")
            return User(
                id=username,
                username=user_data["username"],
                password_hash=user_data["password_hash"],
                permission=user_data["permission"],
            )
        log.warning(f"User authentication failed: {username}")
        return None

    @staticmethod
    def verify_bcrypt_password(stored_password, provided_password):
        """!
        @brief Verify plaintext password against stored bcrypt hash.

        Uses bcrypt's secure password verification to compare the provided
        plaintext password against the stored hash. Handles both string and
        bytes input gracefully.

        @param stored_password The stored bcrypt hash (string or bytes)
        @param provided_password The plaintext password to verify (string)
        @return True if password matches hash, False otherwise
        @retval bool Password verification result

        @note Automatically handles string/bytes conversion for bcrypt
        @note Uses bcrypt.checkpw() for secure constant-time comparison
        @note Logs verification process for debugging
        @note Returns False for any verification errors

        @warning Password timing attacks are mitigated by bcrypt

        @throws Exception Various bcrypt errors (logged, returns False)
        """
        try:
            log.debug(f"Verifying bcrypt password for user authentication")
            return bcrypt.checkpw(
                provided_password.encode("utf-8"), stored_password.encode("utf-8")
            )
        except ValueError as e:
            log.error(f"Error during password verification: {e}")
            return False

    @staticmethod
    def create(username, password, permission):
        log.info(f"Creating new user: {username} with permission: {permission}")
        users = User.load_users()
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
        users[username] = {
            "username": username,
            "password_hash": password_hash,
            "permission": permission,
        }
        User.save_users(users)
        log.info(f"User created successfully: {username}")
        return User(username, username, password_hash, permission)

    @staticmethod
    def load_key():
        with open(config.ENCRYPTION_KEY_FILE, "rb") as key_file:
            key = key_file.read()
        return key

    @staticmethod
    def encrypt_data(data, key):
        # Ensure the key length is appropriate for AES (16, 24, or 32 bytes)
        if len(key) not in [16, 24, 32]:
            raise ValueError("Invalid key size: key must be 16, 24, or 32 bytes long")

        # Generate a random 16-byte IV (Initialization Vector)
        iv = os.urandom(16)

        # Create an AES cipher object with the given key and IV in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Pad the data to make it compatible with AES block size (16 bytes)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode()) + padder.finalize()

        # Encrypt the padded data
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        # Prepend the IV to the encrypted data for use in decryption
        encrypted_message = iv + encrypted_data

        # Encode the combined IV and encrypted data to base64 for safe transmission
        return base64.b64encode(encrypted_message).decode("utf-8")

    @staticmethod
    def get_user_pc_file(username):
        return os.path.join(config.PC_DATA_DIR, f"{username}_pcs.json")

    @staticmethod
    def verify_signature(secret_key, provided_signature, timestamp):
        if not isinstance(timestamp, str):
            timestamp = str(timestamp)
        computed_signature = hmac.new(
            secret_key.encode("utf-8"), timestamp.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(provided_signature, computed_signature)
