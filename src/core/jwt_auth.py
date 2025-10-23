#!/usr/bin/env python3
"""!
********************************************************************************
@file   jwt_auth.py
@brief  JWT authentication utilities for FastAPI
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
import os
import secrets
import config
from src import logger_config as logger

log = logger.get_logger("WakeStation-AUTH")

# JWT Configuration
SECRET_KEY = config.SECRET_KEY
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = config.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_DAYS = config.REFRESH_TOKEN_EXPIRE_DAYS

# Log configuration on module load
log.info(f"JWT authentication initialized (algorithm: {ALGORITHM})")
log.debug(f"Access token expiry: {ACCESS_TOKEN_EXPIRE_MINUTES} minutes")
log.debug(f"Refresh token expiry: {REFRESH_TOKEN_EXPIRE_DAYS} days")

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password"""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()

    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "type": "access"})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    username = data.get("sub", "unknown")
    log.debug(f"Created access token for user: {username} (expires: {expire.strftime('%Y-%m-%d %H:%M:%S')} UTC)")

    return encoded_jwt


def create_refresh_token(data: dict) -> str:
    """Create a JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire, "type": "refresh"})

    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    username = data.get("sub", "unknown")
    log.debug(f"Created refresh token for user: {username} (expires: {expire.strftime('%Y-%m-%d %H:%M:%S')} UTC)")

    return encoded_jwt


def verify_token(token: str, token_type: str = "access") -> Optional[dict]:
    """
    Verify and decode a JWT token

    Args:
        token: The JWT token to verify
        token_type: Expected token type ("access" or "refresh")

    Returns:
        Decoded token payload if valid, None otherwise
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Verify token type
        if payload.get("type") != token_type:
            log.warning(f"Token type mismatch: expected {token_type}, got {payload.get('type')}")
            return None

        # Check expiration (jose does this automatically, but we can add logging)
        exp = payload.get("exp")
        if exp and datetime.utcnow().timestamp() > exp:
            username = payload.get("sub", "unknown")
            log.debug(f"Token expired for user: {username} (type: {token_type})")
            return None

        username = payload.get("sub", "unknown")
        log.debug(f"Token verified successfully for user: {username} (type: {token_type})")
        return payload

    except JWTError as e:
        log.warning(f"JWT verification failed: {str(e)}")
        return None


def decode_token(token: str) -> Optional[dict]:
    """
    Decode a JWT token without verification (for debugging)

    Args:
        token: The JWT token to decode

    Returns:
        Decoded token payload or None
    """
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        return None
