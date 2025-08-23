import os
import json
import bcrypt
from flask import (
    Flask,
    request,
    jsonify,
    send_from_directory,
    redirect,
    url_for,
    session,
    render_template,
    abort,
)
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    current_user,
    login_required,
    UserMixin,
)
import logging
import subprocess
import glob
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import hmac
import hashlib
import config


class User(UserMixin):
    def __init__(self, id, username, password_hash, permission):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.permission = permission

    @staticmethod
    def load_users():
        """Load users from the JSON file."""
        if os.path.exists(config.USERS_FILE):
            with open(config.USERS_FILE, "r") as f:
                return json.load(f)
        return {}

    @staticmethod
    def save_users(users):
        """Save users to the JSON file."""
        with open(config.USERS_FILE, "w") as f:
            json.dump(users, f, indent=4)

    @staticmethod
    def get(user_id):
        """Retrieve a user by ID."""
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
        users = User.load_users()
        user_data = users.get(username)
        if user_data and User.verify_bcrypt_password(
            user_data["password_hash"], password
        ):
            return User(
                id=username,
                username=user_data["username"],
                password_hash=user_data["password_hash"],
                permission=user_data["permission"],
            )
        return None

    @staticmethod
    def verify_bcrypt_password(stored_password, provided_password):
        try:
            logging.debug(f"Verifying stored password: {stored_password}")
            return bcrypt.checkpw(
                provided_password.encode("utf-8"), stored_password.encode("utf-8")
            )
        except ValueError as e:
            logging.error(f"Error during password verification: {e}")
            return False

    @staticmethod
    def create(username, password, permission):
        users = User.load_users()
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")
        users[username] = {
            "username": username,
            "password_hash": password_hash,
            "permission": permission,
        }
        User.save_users(users)
        return User(username, username, password_hash, permission)

    @staticmethod
    def load_key():
        with open(config.KEY_DIR, "rb") as key_file:
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
