#!/usr/bin/env python3
"""!
********************************************************************************
@file   models.py
@brief  Pydantic models for FastAPI request/response validation
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

from pydantic import BaseModel, Field
from typing import Optional, List


# Authentication Models
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, description="Username")
    password: str = Field(..., min_length=1, description="Password")
    remember: bool = Field(default=False, description="Remember me")


class TokenResponse(BaseModel):
    success: bool
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int = Field(..., description="Token expiry in seconds")
    message: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    refresh_token: str = Field(..., description="Refresh token")


class MessageResponse(BaseModel):
    success: bool
    message: str


# PC Management Models
class PCBase(BaseModel):
    mac: str = Field(..., description="MAC address (AA:BB:CC:DD:EE:FF)")
    hostname: str = Field(..., min_length=1, description="Hostname")
    ip: Optional[str] = Field(default="", description="IP address (optional)")
    daemon_guid: Optional[str] = Field(default="", description="Daemon GUID")


class PCAdd(PCBase):
    pass


class PCResponse(PCBase):
    status: str = Field(default="unknown", description="Online status")
    daemon_available: bool = Field(default=False, description="Daemon availability")


class PCListResponse(BaseModel):
    success: bool
    pcs_list: List[PCResponse]
    message: Optional[str] = None


class PCEditIP(BaseModel):
    mac: str = Field(..., description="MAC address to update")
    ip: str = Field(..., description="New IP address")


# Wake-on-LAN Models
class WakeRequest(BaseModel):
    mac: str = Field(..., description="MAC address to wake")


# Shutdown Models
class ShutdownRequest(BaseModel):
    daemon_guid: str = Field(..., description="Daemon GUID")
    username: Optional[str] = Field(
        None, description="Username for authentication (legacy)"
    )
    password: Optional[str] = Field(
        None, description="Password for authentication (legacy)"
    )
    encrypted_payload: Optional[str] = Field(
        None, description="Encrypted shutdown payload"
    )
    fallback_reason: Optional[str] = Field(
        None, description="Reason for fallback to server-side encryption"
    )


# Status Models
class StatusResponse(BaseModel):
    success: bool
    status: str = Field(..., description="Device status (online/offline/unknown)")
    daemon_available: bool = Field(..., description="Daemon availability")


# User Management Models
class UserCreate(BaseModel):
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    permission: str = Field(..., description="User permission level (admin/user)")


class UserInfo(BaseModel):
    username: str
    permission: str


class UserListResponse(BaseModel):
    success: bool
    users: dict


class UserPermissionChange(BaseModel):
    username: str
    permission: str


class UserPasswordChange(BaseModel):
    username: str
    password: str


class UserDelete(BaseModel):
    username: str


# Encryption Models
class EncryptionKeyResponse(BaseModel):
    success: bool
    encryption_key: str


class EncryptionFailureLog(BaseModel):
    failure_reason: str
    failure_type: str = Field(default="unknown")


# IP Rediscovery Models
class DeviceRediscoveryResult(BaseModel):
    hostname: str
    mac: str
    old_ip: Optional[str]
    new_ip: Optional[str]
    updated: bool
    error: Optional[str] = None


class RediscoveryResponse(BaseModel):
    success: bool
    message: str
    results: Optional[dict] = None
