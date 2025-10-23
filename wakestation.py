#!/usr/bin/env python3
"""!
********************************************************************************
@file   wakestation.py
@brief  Hybrid Flask + FastAPI application for WakeStation
        Flask handles web UI, FastAPI handles API
        JWT-only authentication (no Flask-Login/Flask-Session)
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

## Version 3.1.0 - JWT-Only Authentication (removed Flask-Login/Flask-Session)

import os
from flask import Flask, redirect, url_for
from fastapi import FastAPI, Response
from fastapi.middleware.wsgi import WSGIMiddleware
from fastapi.responses import RedirectResponse, FileResponse
import config
from src.utils import htpasswd
from src.api.fastapi_app import create_fastapi_app
from src.api.flask_ui_routes import setup_flask_ui_routes
from src import logger_config as logger

# Initialize Flask app for web UI with hardcoded src/ui paths
flask_app = Flask(
    __name__,
    template_folder="src/ui/templates",
    static_folder="src/ui/static",
    static_url_path="/static"
)
flask_app.config["SEND_FILE_MAX_AGE_DEFAULT"] = config.SEND_FILE_MAX_AGE_DEFAULT

if not os.path.exists(config.USERS_FILE) or not os.path.exists(
    config.ENCRYPTION_KEY_FILE
):
    log = logger.get_logger("WakeStation")
    print("Missing configuration files detected. Running initialization...")
    print("This will create an admin user and generate encryption keys.")
    log.info("Missing configuration files detected. Running initialization...")
    htpasswd.create_user()
else:
    log = logger.get_logger("WakeStation")

# Create necessary directories
if not os.path.exists(config.PC_DATA_DIR):
    os.makedirs(config.PC_DATA_DIR)

log.info("WakeStation FastAPI server starting up with JWT-only authentication...")


# ============================================================================
# Flask Routes for Web UI
# ============================================================================

# Setup Flask UI routes (login, logout, index) from src/api/flask_ui_routes.py
setup_flask_ui_routes(flask_app)


@flask_app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors"""
    return redirect(url_for("login"))


# ============================================================================
# Create FastAPI application and mount Flask as sub-application
# ============================================================================

# Create FastAPI app with all API routes
app = create_fastapi_app()

# Mount Flask app to handle web UI routes
# FastAPI handles /api/*, /docs, /redoc
# Flask handles /, /login, /logout, and other web UI routes
app.mount("/ui", WSGIMiddleware(flask_app))


# Add root redirect
@app.get("/", include_in_schema=False)
async def root():
    """Redirect root to web UI"""
    return RedirectResponse(url="/ui/")


# Serve static files at root level (Flask static is at /ui/static/)
@app.get("/static/js/wol.js", include_in_schema=False)
async def serve_js_file():
    """Serve wol.js at root level for the web UI"""
    return FileResponse("src/ui/static/js/wol.js", media_type="application/javascript")


@app.get("/favicon.ico", include_in_schema=False)
async def serve_favicon():
    """Serve favicon from UI static directory"""
    favicon_path = "src/ui/static/favicon.ico"
    if os.path.exists(favicon_path):
        return FileResponse(favicon_path, media_type="image/x-icon")
    # Return 204 No Content if favicon doesn't exist
    return Response(status_code=204)


if __name__ == "__main__":
    import uvicorn
    import logging
    import logging.handlers

    # Determine protocol based on SSL configuration
    protocol = "https" if config.ENABLE_SSL else "http"

    log.info(
        f"Starting WakeStation FastAPI application on {config.WOL_SERVER_HOST}:{config.WOL_SERVER_PORT}"
    )

    if config.ENABLE_SSL:
        log.info("SSL/TLS enabled - using HTTPS")
        log.info(f"Certificate: {config.SSL_CERTFILE}")
        log.info(f"Private key: {config.SSL_KEYFILE}")
        if config.SSL_CA_CERTS:
            log.info(f"CA certificate: {config.SSL_CA_CERTS}")
    else:
        log.warning("SSL/TLS disabled - using HTTP (not recommended for production)")

    log.info(
        f"API Documentation available at: {protocol}://{config.WOL_SERVER_HOST}:{config.WOL_SERVER_PORT}/docs"
    )
    log.info(
        f"Web UI available at: {protocol}://{config.WOL_SERVER_HOST}:{config.WOL_SERVER_PORT}/ui/"
    )

    # Convert config log level to lowercase for uvicorn
    uvicorn_log_level = config.CONSOLE_LOG_LEVEL.lower()

    # Get our WakeStation logger handlers to attach to uvicorn loggers
    wakestation_logger = logger.get_logger("WakeStation-UVICORN")

    # Redirect uvicorn logs to WakeStation logger system
    uvicorn_logger = logging.getLogger("uvicorn")
    uvicorn_access = logging.getLogger("uvicorn.access")
    uvicorn_error = logging.getLogger("uvicorn.error")
    uvicorn_info = logging.getLogger("uvicorn.info")

    # Clear default handlers and use our custom logger handlers
    uvicorn_logger.handlers = wakestation_logger.handlers.copy()
    uvicorn_error.handlers = wakestation_logger.handlers.copy()

    # Configure access logging to separate file (hardcoded to prevent misconfiguration crashes)
    os.makedirs(config.LOG_DIR, exist_ok=True)
    access_handler = logging.handlers.RotatingFileHandler(
        os.path.join(config.LOG_DIR, "access.log"),
        maxBytes=config.LOG_MAX_SIZE * 1024 * 1024,
        backupCount=config.LOG_BACKUP_COUNT
    )
    access_formatter = logging.Formatter('%(message)s')  # Access logs already formatted by uvicorn
    access_handler.setFormatter(access_formatter)

    uvicorn_access.handlers = [access_handler]
    uvicorn_access.setLevel(logging.INFO)

    # Set propagate to False to prevent duplicate logs
    uvicorn_logger.propagate = False
    uvicorn_access.propagate = False
    uvicorn_error.propagate = False

    # Build uvicorn configuration
    uvicorn_config = {
        "app": app,
        "host": config.WOL_SERVER_HOST,
        "port": config.WOL_SERVER_PORT,
        "log_level": uvicorn_log_level,
        "log_config": None,  # Disable uvicorn's default logging, use our custom handlers
    }

    # Add SSL configuration if enabled
    if config.ENABLE_SSL:
        if not config.SSL_CERTFILE or not config.SSL_KEYFILE:
            log.error("SSL enabled but SSL_CERTFILE or SSL_KEYFILE not configured!")
            log.error("Please set SSL_CERTFILE and SSL_KEYFILE in config.py")
            exit(1)

        # Check if certificate files exist
        if not os.path.exists(config.SSL_CERTFILE):
            log.error(f"SSL certificate file not found: {config.SSL_CERTFILE}")
            exit(1)
        if not os.path.exists(config.SSL_KEYFILE):
            log.error(f"SSL private key file not found: {config.SSL_KEYFILE}")
            exit(1)
        if config.SSL_CA_CERTS and not os.path.exists(config.SSL_CA_CERTS):
            log.error(f"SSL CA certificate file not found: {config.SSL_CA_CERTS}")
            exit(1)

        uvicorn_config["ssl_certfile"] = config.SSL_CERTFILE
        uvicorn_config["ssl_keyfile"] = config.SSL_KEYFILE

        # Add CA certificate if provided (for internal CA)
        if config.SSL_CA_CERTS:
            uvicorn_config["ssl_ca_certs"] = config.SSL_CA_CERTS

        log.info("SSL certificate validation successful")

    uvicorn.run(**uvicorn_config)
