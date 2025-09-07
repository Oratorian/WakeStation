#!/usr/bin/env python3
"""!
********************************************************************************
@file   wakestation.py
@brief  Main Flask application for WakeStation - Wake-on-LAN server with web interface
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

## Version 2.9.1


import os
from flask import Flask, send_from_directory, redirect, url_for, request, jsonify
from flask_login import LoginManager
from src.core import user
import config
from src.utils import htpasswd
from src.api import routes as api
from src.logger import logger

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.config["REMEMBER_COOKIE_DURATION"] = config.REMEMBER_COOKIE_DURATION
app.config["REMEMBER_COOKIE_SECURE"] = config.REMEMBER_COOKIE_SECURE
app.config["REMEMBER_COOKIE_HTTPONLY"] = config.REMEMBER_COOKIE_HTTPONLY
app.config["REMEMBER_COOKIE_SAMESITE"] = config.REMEMBER_COOKIE_SAMESITE
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = config.SEND_FILE_MAX_AGE_DEFAULT
app.config["SESSION_PERMANENT"] = config.SESSION_PERMANENT

if not os.path.exists(config.PC_DATA_DIR):
    os.makedirs(config.PC_DATA_DIR)

# Check for missing configuration files and initialize if needed
if not os.path.exists(config.USERS_FILE) or not os.path.exists(
    config.ENCRYPTION_KEY_FILE
):
    # Initialize logging system first
    log = logger.get_logger("wakestation")
    print("Missing configuration files detected. Running initialization...")
    print("This will create an admin user and generate encryption keys.")
    log.info("Missing configuration files detected. Running initialization...")
    htpasswd.create_user()
else:
    # Initialize logging system
    log = logger.get_logger("wakestation")

log.info("WakeStation server starting up...")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"  # type: ignore


@login_manager.user_loader
def load_user(user_id):
    return user.User.get(user_id)


# Setup all API routes
api.setup_routes(app)


@app.route("/js/wol.js")
def serve_js():
    """Serve the wol.js file specifically."""
    return send_from_directory("js", "wol.js")


@app.errorhandler(404)
def page_not_found(e):
    if (
        request.accept_mimetypes.accept_json
        and not request.accept_mimetypes.accept_html
    ):
        response = jsonify({"success": False, "message": "Resource not found"})
        response.status_code = 404
        return response
    else:
        return redirect(url_for("login"))


if __name__ == "__main__":
    log.info(f"Starting WakeStation Flask application on {config.WOL_INTERFACE}:8888")
    app.run(host=config.WOL_INTERFACE, port=8888, debug=False)
# Note: In production, use a WSGI server like Gunicorn or uWSGI
# to run the Flask application for better performance and security.
