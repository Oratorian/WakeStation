#!/usr/bin/env python3
"""!
********************************************************************************
@file   flask_ui_routes.py
@brief  Flask routes for web UI (login, logout, index)
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

from flask import (
    Flask,
    request,
    render_template,
    make_response,
    redirect,
    url_for,
)
from datetime import timedelta
from ..core import user
from ..core.jwt_auth import (
    create_access_token,
    create_refresh_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from ..core.flask_jwt_auth import jwt_required
from src import logger_config as logger
import config

log = logger.get_logger("WakeStation-UI")


def setup_flask_ui_routes(app: Flask):
    """
    Setup Flask web UI routes (login, logout, index)

    Args:
        app: Flask application instance
    """

    @app.route("/")
    @jwt_required
    def index(current_user):
        """Main dashboard page"""
        return render_template("index.html", current_user=current_user, user_permission=current_user.permission)

    @app.route("/login", methods=["GET", "POST"])
    def login():
        """Web UI login page - now sets JWT tokens for API access"""
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")
            remember = request.form.get("remember") == "on"

            log.debug(f"Web UI login attempt for user: {username}")

            authenticated_user = user.User.authenticate(username, password)
            if authenticated_user:
                log.info(f"Web UI authentication successful for user: {username}")

                # Create JWT tokens for API access
                token_data = {
                    "sub": authenticated_user.username,
                    "permission": authenticated_user.permission,
                }
                access_token = create_access_token(
                    data=token_data,
                    expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
                )
                refresh_token = create_refresh_token(data=token_data)

                # Create response and set JWT cookies
                response = make_response(redirect(url_for("index")))
                response.set_cookie(
                    key="access_token",
                    value=access_token,
                    httponly=True,
                    secure=config.REMEMBER_COOKIE_SECURE,
                    samesite="strict",
                    max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
                )
                response.set_cookie(
                    key="refresh_token",
                    value=refresh_token,
                    httponly=True,
                    secure=config.REMEMBER_COOKIE_SECURE,
                    samesite="strict",
                    max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
                )

                return response
            else:
                log.warning(f"Web UI authentication failed for user: {username}")
                return render_template("login.html", error="Invalid credentials")

        return render_template("login.html")

    @app.route("/logout", methods=["GET", "POST"])
    def logout():
        """Web UI logout - clears JWT cookies"""
        log.info("User logout requested")

        response = make_response(redirect(url_for("login")))

        # Clear JWT cookies
        response.delete_cookie("access_token")
        response.delete_cookie("refresh_token")

        return response
