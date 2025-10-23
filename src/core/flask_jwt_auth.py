#!/usr/bin/env python3
"""!
********************************************************************************
@file   flask_jwt_auth.py
@brief  JWT authentication middleware for Flask routes
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

from functools import wraps
from datetime import timedelta
from flask import request, redirect, url_for, make_response
from src.core.jwt_auth import verify_token, create_access_token, ACCESS_TOKEN_EXPIRE_MINUTES
from src.core.user import User
from src import logger_config as logger
import config

log = logger.get_logger("WakeStation-AUTH")


def jwt_required(f):
    """
    Decorator for Flask routes that require JWT authentication.
    Checks for access_token cookie and validates it.
    If access_token is expired, attempts to refresh using refresh_token.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get tokens from cookies
        access_token = request.cookies.get("access_token")
        refresh_token = request.cookies.get("refresh_token")

        payload = None
        needs_refresh = False

        # Try to verify access token
        if access_token:
            payload = verify_token(access_token, token_type="access")
            if payload:
                log.debug("Valid access token found")
            else:
                log.debug("Access token expired or invalid, attempting refresh")
                needs_refresh = True

        # If no valid access token, try to refresh using refresh token
        if not payload and refresh_token:
            refresh_payload = verify_token(refresh_token, token_type="refresh")

            if refresh_payload:
                log.info("Refresh token valid, issuing new access token")
                # Use the refresh token payload as our payload
                payload = refresh_payload
                needs_refresh = True
            else:
                log.warning("Refresh token also expired or invalid")

        # If still no valid payload, redirect to login
        if not payload:
            log.warning("No valid tokens found, redirecting to login")
            response = make_response(redirect(url_for("login")))
            response.delete_cookie("access_token")
            response.delete_cookie("refresh_token")
            return response

        # Get user from payload
        username = payload.get("sub")
        permission = payload.get("permission")

        if not username:
            log.warning("No username in token payload")
            return redirect(url_for("login"))

        # Load user object
        current_user = User.get(username)
        if not current_user:
            log.warning(f"User {username} not found in database")
            return redirect(url_for("login"))

        # Add current_user to kwargs so routes can access it
        kwargs["current_user"] = current_user

        # Execute the route function
        response = make_response(f(*args, **kwargs))

        # If we needed to refresh, set new access token cookie
        if needs_refresh:
            log.info(f"Refreshing access token for user: {username}")
            new_access_token = create_access_token(
                data={"sub": username, "permission": permission},
                expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
            )
            response.set_cookie(
                key="access_token",
                value=new_access_token,
                httponly=True,
                secure=config.REMEMBER_COOKIE_SECURE,
                samesite="strict",
                max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            )
            log.debug("New access token cookie set")

        return response

    return decorated_function
