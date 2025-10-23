#!/usr/bin/env python3
"""!
********************************************************************************
@file   dependencies.py
@brief  FastAPI dependencies for authentication and authorization
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

from fastapi import Depends, HTTPException, Cookie, Header, status
from typing import Optional
from ..core.jwt_auth import verify_token
from ..core import user
from src import logger_config as logger

log = logger.get_logger("WakeStation-AUTH")


class CurrentUser:
    """User object for authenticated requests"""

    def __init__(self, username: str, permission: str):
        self.username = username
        self.permission = permission
        self.is_authenticated = True

    def __repr__(self):
        return f"<CurrentUser {self.username} ({self.permission})>"


async def get_current_user(
    access_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
) -> CurrentUser:
    """
    Dual authentication dependency - accepts both cookies and Bearer tokens

    For Web UI: Reads JWT from HttpOnly cookie
    For API: Reads JWT from Authorization: Bearer header

    Args:
        access_token: JWT token from cookie (web UI)
        authorization: Authorization header (API clients)

    Returns:
        CurrentUser object with username and permission

    Raises:
        HTTPException: 401 if not authenticated or token invalid
    """
    token = None

    # Try Bearer token first (API clients)
    if authorization and authorization.startswith("Bearer "):
        token = authorization.replace("Bearer ", "")
        log.debug("Authentication via Bearer token")

    # Fallback to cookie (web UI)
    elif access_token:
        token = access_token
        log.debug("Authentication via cookie")

    # No authentication provided
    if not token:
        log.warning("Authentication failed: No token provided")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Verify JWT token
    payload = verify_token(token, token_type="access")
    if not payload:
        log.warning("Authentication failed: Invalid or expired token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Extract user information from token
    username = payload.get("sub")
    permission = payload.get("permission")

    if not username:
        log.error("Authentication failed: Token missing username")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate": "Bearer"},
        )

    log.debug(f"User authenticated: {username} ({permission})")
    return CurrentUser(username=username, permission=permission)


async def require_admin(
    current_user: CurrentUser = Depends(get_current_user),
) -> CurrentUser:
    """
    Require admin permission for endpoint access

    Args:
        current_user: Current authenticated user

    Returns:
        CurrentUser object if admin

    Raises:
        HTTPException: 403 if user is not admin
    """
    if current_user.permission != "admin":
        log.warning(f"Authorization failed: User {current_user.username} is not admin")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin permission required"
        )

    return current_user


async def get_current_user_optional(
    access_token: Optional[str] = Cookie(None),
    authorization: Optional[str] = Header(None),
) -> Optional[CurrentUser]:
    """
    Optional authentication - returns None if not authenticated

    Args:
        access_token: JWT token from cookie (web UI)
        authorization: Authorization header (API clients)

    Returns:
        CurrentUser object if authenticated, None otherwise
    """
    try:
        return await get_current_user(access_token, authorization)
    except HTTPException:
        return None
