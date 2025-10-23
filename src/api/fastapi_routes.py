#!/usr/bin/env python3
"""!
********************************************************************************
@file   fastapi_routes.py
@brief  FastAPI routes with JWT authentication and dual auth support
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import json
import glob
from datetime import timedelta
from fastapi import APIRouter, Depends, HTTPException, Response, status
from fastapi.responses import JSONResponse
from typing import Optional

from .models import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    MessageResponse,
    PCAdd,
    PCListResponse,
    PCEditIP,
    PCResponse,
    WakeRequest,
    ShutdownRequest,
    StatusResponse,
    UserCreate,
    UserListResponse,
    UserPermissionChange,
    UserPasswordChange,
    UserDelete,
    EncryptionKeyResponse,
    EncryptionFailureLog,
    RediscoveryResponse,
)
from .dependencies import get_current_user, require_admin, CurrentUser
from ..core.jwt_auth import (
    create_access_token,
    create_refresh_token,
    verify_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
)
from ..core import user
from ..utils import network as sources
from ..utils import network
from ..utils import arp
from ..utils.wol import wake_device
from ..core import workers
from src import logger_config as logger
import config
import base64

log = logger.get_logger("WakeStation-API")

# Create router
router = APIRouter(prefix="/api", tags=["api"])


# ============================================================================
# Authentication Endpoints
# ============================================================================


@router.post("/login", response_model=TokenResponse, status_code=200)
async def login(credentials: LoginRequest, response: Response):
    """
    Login endpoint with dual-mode authentication:
    - Returns JWT tokens in JSON response (for API clients)
    - Sets HttpOnly cookie with access token (for web UI)

    Example curl usage:
    ```bash
    curl -X POST http://localhost:8889/api/login \\
      -H "Content-Type: application/json" \\
      -d '{"username": "john", "password": "secret123"}'
    ```

    Returns:
        TokenResponse with access_token and refresh_token
    """
    log.debug(f"API login attempt for user: {credentials.username}")

    authenticated_user = user.User.authenticate(
        credentials.username, credentials.password
    )
    if not authenticated_user:
        log.warning(f"API authentication failed for user: {credentials.username}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

    log.info(f"API authentication successful for user: {credentials.username}")

    # Create JWT tokens
    token_data = {
        "sub": authenticated_user.username,
        "permission": authenticated_user.permission,
    }

    access_token = create_access_token(
        data=token_data, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    refresh_token = create_refresh_token(data=token_data)

    # Set HttpOnly cookie for web UI
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,  # Only send over HTTPS (disable for local development if needed)
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    # Also set refresh token cookie
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
    )

    return TokenResponse(
        success=True,
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        message="Login successful",
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_access_token(request: RefreshTokenRequest, response: Response):
    """
    Refresh access token using refresh token

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/refresh \\
      -H "Content-Type: application/json" \\
      -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
    ```
    """
    payload = verify_token(request.refresh_token, token_type="refresh")
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )

    username = payload.get("sub")
    permission = payload.get("permission")

    # Create new access token
    token_data = {"sub": username, "permission": permission}
    access_token = create_access_token(
        data=token_data, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Update cookie
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )

    return TokenResponse(
        success=True,
        access_token=access_token,
        refresh_token=request.refresh_token,
        token_type="bearer",
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout(response: Response):
    """
    Logout endpoint - clears authentication cookies

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/logout \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    # Clear cookies
    response.delete_cookie(key="access_token")
    response.delete_cookie(key="refresh_token")

    return MessageResponse(success=True, message="Logged out successfully")


# ============================================================================
# PC Management Endpoints
# ============================================================================


@router.get("/load", response_model=PCListResponse)
async def load_pcs(current_user: CurrentUser = Depends(get_current_user)):
    """
    Load all PCs for the authenticated user

    Example:
    ```bash
    curl -X GET http://localhost:8889/api/load \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    log.info(f"API /api/load called by user: {current_user.username}")

    try:
        user_pc_file = user.User.get_user_pc_file(current_user.username)
        log.debug(f"Loading PCs for user {current_user.username} from {user_pc_file}")

        # Load daemon registry
        daemon_registry = {}
        daemon_registry_file = network.get_daemon_registry_path()
        if os.path.exists(daemon_registry_file):
            with open(daemon_registry_file, "r") as f:
                daemon_registry = json.load(f)

        if os.path.exists(user_pc_file):
            with open(user_pc_file, "r") as file:
                pcs = json.load(file)

            # Filter out invalid PC entries
            valid_pcs = [pc for pc in pcs if pc.get("mac") and pc.get("hostname")]
            if len(valid_pcs) != len(pcs):
                log.warning(
                    f"Filtered out {len(pcs) - len(valid_pcs)} invalid PC entries"
                )
                pcs = valid_pcs
                pc_data_changed = True
            else:
                pc_data_changed = False

            # Get status for each PC
            for pc in pcs:
                hostname = pc.get("hostname", "Unknown")
                stored_ip = pc.get("ip", "")
                daemon_guid = pc.get("daemon_guid", "")

                status_info = {
                    "status": "unknown",
                    "daemon_available": False,
                }

                # Check IP status via ping if IP is set
                if stored_ip:
                    try:
                        is_online = network.ping_host(stored_ip, timeout=1)
                        status_info["status"] = "online" if is_online else "offline"
                    except Exception as e:
                        log.warning(f"Ping failed for {hostname}: {e}")
                        status_info["status"] = "unknown"
                else:
                    # No IP set - try ARP resolution
                    mac_address = pc.get("mac")
                    if mac_address:
                        try:
                            resolved_ip = arp.find_device_by_mac(mac_address)
                            if resolved_ip:
                                pc["ip"] = resolved_ip
                                pc_data_changed = True
                                is_online = network.ping_host(resolved_ip, timeout=1)
                                status_info["status"] = (
                                    "online" if is_online else "offline"
                                )
                            else:
                                status_info["status"] = "no_ip"
                        except Exception as e:
                            log.warning(f"ARP resolution failed for {hostname}: {e}")
                            status_info["status"] = "no_ip"

                # Try to find daemon GUID by hostname if not set
                if not daemon_guid:
                    try:
                        found_guid = network.find_daemon_by_hostname(hostname)
                        if found_guid:
                            daemon_guid = found_guid
                            pc["daemon_guid"] = daemon_guid
                            pc_data_changed = True
                            log.info(
                                f"Automatically linked {hostname} to daemon GUID {daemon_guid[:8]}..."
                            )
                    except Exception as e:
                        log.warning(
                            f"Error finding daemon by hostname for {hostname}: {e}"
                        )

                # Check daemon availability
                if daemon_guid:
                    try:
                        if daemon_guid == "localhost":
                            status_info["daemon_available"] = True
                        else:
                            status_info["daemon_available"] = network.check_daemon_by_guid(
                                daemon_guid, daemon_registry
                            )
                    except Exception as e:
                        log.warning(f"Daemon check failed for {hostname}: {e}")

                # Update PC with status
                pc["status"] = status_info["status"]
                pc["daemon_available"] = status_info["daemon_available"]

                # Ensure all required fields exist
                if "ip" not in pc:
                    pc["ip"] = ""
                if "daemon_guid" not in pc:
                    pc["daemon_guid"] = ""

            # Save status updates
            if pc_data_changed:
                try:
                    with open(user_pc_file, "w") as file:
                        json.dump(pcs, file, indent=2)
                    log.info(f"Updated PC status for user {current_user.username}")
                except Exception as e:
                    log.error(f"Failed to save updated PC file: {e}")

            return PCListResponse(success=True, pcs_list=pcs)
        else:
            return PCListResponse(success=True, pcs_list=[])

    except Exception as e:
        log.error(f"Error loading PCs for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/add", response_model=PCListResponse)
async def add_pc(pc_data: PCAdd, current_user: CurrentUser = Depends(get_current_user)):
    """
    Add a new PC to the user's list

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/add \\
      -H "Authorization: Bearer YOUR_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"mac": "AA:BB:CC:DD:EE:FF", "hostname": "MyPC", "ip": "192.168.1.100"}'
    ```
    """
    user_pc_file = user.User.get_user_pc_file(current_user.username)

    try:
        # Try to find daemon GUID by hostname
        daemon_guid = None
        try:
            daemon_guid = network.find_daemon_by_hostname(pc_data.hostname)
            if daemon_guid:
                log.info(
                    f"Found daemon GUID {daemon_guid} for new PC {pc_data.hostname}"
                )
        except Exception as e:
            log.warning(f"Error finding daemon by hostname: {e}")

        # Create PC entry
        new_pc = {
            "mac": pc_data.mac,
            "hostname": pc_data.hostname,
            "ip": pc_data.ip or "",
            "daemon_guid": daemon_guid if daemon_guid else "",
            "status": "unknown",
            "daemon_available": bool(daemon_guid),
        }

        if daemon_guid:
            message = f"PC added successfully with daemon GUID {daemon_guid}"
        elif pc_data.ip:
            message = f"PC added successfully with IP {pc_data.ip}"
        else:
            message = "PC added successfully (no IP or daemon detected yet)"

        pcs = []
        if os.path.exists(user_pc_file):
            with open(user_pc_file, "r") as file:
                pcs = json.load(file)

        pcs.append(new_pc)

        with open(user_pc_file, "w") as file:
            json.dump(pcs, file, indent=4)

        return PCListResponse(success=True, pcs_list=pcs, message=message)

    except Exception as e:
        log.error(f"Error adding PC for user {current_user.username}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.delete("/delete", response_model=PCListResponse)
async def delete_pc(mac: str, current_user: CurrentUser = Depends(get_current_user)):
    """
    Delete a PC by MAC address

    Example:
    ```bash
    curl -X DELETE "http://localhost:8889/api/delete?mac=AA:BB:CC:DD:EE:FF" \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        user_json_file = user.User.get_user_pc_file(current_user.username)

        with open(user_json_file, "r") as file:
            pcs = json.load(file)

        pcs_before = len(pcs)
        pcs = [pc for pc in pcs if pc["mac"] != mac]
        pcs_after = len(pcs)

        if pcs_before == pcs_after:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"MAC address {mac} not found",
            )

        with open(user_json_file, "w") as file:
            json.dump(pcs, file, indent=4)

        return PCListResponse(
            success=True, pcs_list=pcs, message=f"Deleted PC with MAC {mac}"
        )

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error deleting PC: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/edit_ip", response_model=PCListResponse)
async def edit_pc_ip(
    data: PCEditIP, current_user: CurrentUser = Depends(get_current_user)
):
    """
    Update the IP address of an existing PC

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/edit_ip \\
      -H "Authorization: Bearer YOUR_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.200"}'
    ```
    """
    try:
        user_pc_file = user.User.get_user_pc_file(current_user.username)

        if not os.path.exists(user_pc_file):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No PCs found for user"
            )

        with open(user_pc_file, "r") as file:
            pcs = json.load(file)

        pc_found = False
        for pc in pcs:
            if pc["mac"] == data.mac:
                old_ip = pc.get("ip", "")
                pc["ip"] = data.ip
                pc_found = True
                log.info(
                    f"Updated PC {pc.get('hostname', 'Unknown')} IP: {old_ip} -> {data.ip}"
                )
                break

        if not pc_found:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"PC with MAC {data.mac} not found",
            )

        with open(user_pc_file, "w") as file:
            json.dump(pcs, file, indent=2)

        return PCListResponse(
            success=True, pcs_list=pcs, message="IP address updated successfully"
        )

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error updating PC IP: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/rediscover_ips", response_model=RediscoveryResponse)
async def rediscover_all_ips(current_user: CurrentUser = Depends(get_current_user)):
    """
    Rediscover IP addresses for all devices using ARP scanning

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/rediscover_ips \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    log.info(f"Global IP rediscovery requested by user: {current_user.username}")

    try:
        user_pc_file = user.User.get_user_pc_file(current_user.username)

        if not os.path.exists(user_pc_file):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="No devices found"
            )

        with open(user_pc_file, "r") as file:
            pcs = json.load(file)

        valid_pcs = [pc for pc in pcs if pc.get("mac") and pc.get("hostname")]

        if not valid_pcs:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No valid devices to scan",
            )

        results = {"scanned": 0, "found": 0, "updated": 0, "devices": []}

        for pc in valid_pcs:
            mac_address = pc.get("mac")
            hostname = pc.get("hostname")
            old_ip = pc.get("ip", "")

            results["scanned"] += 1

            try:
                resolved_ip = arp.find_device_by_mac(mac_address)

                if resolved_ip:
                    results["found"] += 1
                    if resolved_ip != old_ip:
                        pc["ip"] = resolved_ip
                        results["updated"] += 1

                    results["devices"].append(
                        {
                            "hostname": hostname,
                            "mac": mac_address,
                            "old_ip": old_ip,
                            "new_ip": resolved_ip,
                            "updated": resolved_ip != old_ip,
                        }
                    )
                else:
                    results["devices"].append(
                        {
                            "hostname": hostname,
                            "mac": mac_address,
                            "old_ip": old_ip,
                            "new_ip": None,
                            "updated": False,
                        }
                    )

            except Exception as e:
                log.error(f"Failed to rediscover IP for {hostname}: {e}")
                results["devices"].append(
                    {
                        "hostname": hostname,
                        "mac": mac_address,
                        "old_ip": old_ip,
                        "new_ip": None,
                        "updated": False,
                        "error": str(e),
                    }
                )

        with open(user_pc_file, "w") as file:
            json.dump(pcs, file, indent=2)

        message = f"Scanned {results['scanned']} devices, found {results['found']}, updated {results['updated']} IPs"
        log.info(f"IP rediscovery completed for {current_user.username}: {message}")

        return RediscoveryResponse(success=True, message=message, results=results)

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Failed to rediscover IPs: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


# ============================================================================
# Device Control Endpoints
# ============================================================================


@router.get("/status", response_model=StatusResponse)
async def check_pc_status(
    ip: str, current_user: CurrentUser = Depends(get_current_user)
):
    """
    Check if a PC is online by IP address

    Example:
    ```bash
    curl -X GET "http://localhost:8889/api/status?ip=192.168.1.100" \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        status_result = "online" if network.ping_host(ip) else "offline"
        daemon_available = False

        return StatusResponse(
            success=True, status=status_result, daemon_available=daemon_available
        )
    except Exception as e:
        log.error(f"Error checking status for {ip}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/wake", response_model=MessageResponse)
async def wake_pc(mac: str, current_user: CurrentUser = Depends(get_current_user)):
    """
    Send Wake-on-LAN packet to a PC

    Example:
    ```bash
    curl -X POST "http://localhost:8889/api/wake?mac=AA:BB:CC:DD:EE:FF" \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    log.info(f"Wake-on-LAN request for MAC: {mac} by user: {current_user.username}")
    result = wake_device(mac)

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=result["message"]
        )

    return MessageResponse(success=result["success"], message=result["message"])


@router.post("/shutdown", response_model=MessageResponse)
async def shutdown_pc(
    data: ShutdownRequest, current_user: CurrentUser = Depends(get_current_user)
):
    """
    Send shutdown command to a PC via daemon

    Example (with end-to-end encryption):
    ```bash
    curl -X POST http://localhost:8889/api/shutdown \\
      -H "Authorization: Bearer YOUR_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"daemon_guid": "abc123", "encrypted_payload": "base64_encrypted_data"}'
    ```
    """
    try:
        # Check if encrypted payload provided (new method)
        if data.encrypted_payload:
            log.info(
                f"Shutdown request for daemon {data.daemon_guid}: Using end-to-end encryption"
            )
            result = workers.send_encrypted_shutdown_command_by_guid(
                data.daemon_guid, data.encrypted_payload
            )
        else:
            # Legacy method
            if data.fallback_reason:
                log.critical(
                    f"Shutdown request for daemon {data.daemon_guid}: "
                    f"End-to-end encryption failed - {data.fallback_reason}"
                )
                log.info(
                    f"Shutdown request for daemon {data.daemon_guid}: Falling back to server-side encryption"
                )
            else:
                log.info(
                    f"Shutdown request for daemon {data.daemon_guid}: Using server-side encryption (legacy)"
                )

            result = workers.send_shutdown_command_by_guid(
                data.daemon_guid, data.username, data.password
            )

        if not result["success"]:
            status_code = (
                status.HTTP_400_BAD_REQUEST
                if "Error" in result["message"] or "Invalid" in result["message"]
                else status.HTTP_500_INTERNAL_SERVER_ERROR
            )
            raise HTTPException(status_code=status_code, detail=result["message"])

        return MessageResponse(success=result["success"], message=result["message"])

    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Exception in shutdown_pc: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


# ============================================================================
# User Management Endpoints (Admin Only)
# ============================================================================


@router.post("/users/create", response_model=MessageResponse)
async def create_user_endpoint(
    user_data: UserCreate, admin: CurrentUser = Depends(require_admin)
):
    """
    Create a new user (admin only)

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/users/create \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"username": "newuser", "password": "pass123", "permission": "user"}'
    ```
    """
    try:
        user.User.create(user_data.username, user_data.password, user_data.permission)
        log.info(f"User {user_data.username} created by admin {admin.username}")
        return MessageResponse(success=True, message="User added successfully")
    except Exception as e:
        log.error(f"Error creating user: {e}")
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/users", response_model=UserListResponse)
async def get_users(current_user: CurrentUser = Depends(get_current_user)):
    """
    Get all users

    Example:
    ```bash
    curl -X GET http://localhost:8889/api/users \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        if os.path.exists(config.USERS_FILE):
            with open(config.USERS_FILE, "r") as f:
                users = json.load(f)
            return UserListResponse(success=True, users=users)
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Users file not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error retrieving users: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/users/change_permission", response_model=MessageResponse)
async def change_permission(
    data: UserPermissionChange, admin: CurrentUser = Depends(require_admin)
):
    """
    Change user permission (admin only)

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/users/change_permission \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"username": "john", "permission": "admin"}'
    ```
    """
    try:
        if os.path.exists(config.USERS_FILE):
            with open(config.USERS_FILE, "r") as f:
                users = json.load(f)

            if data.username in users:
                users[data.username]["permission"] = data.permission
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )

            with open(config.USERS_FILE, "w") as f:
                json.dump(users, f)

            return MessageResponse(
                success=True, message="Permission updated successfully"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Users file not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error changing permission: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/users/change_password", response_model=MessageResponse)
async def change_password(
    data: UserPasswordChange, admin: CurrentUser = Depends(require_admin)
):
    """
    Change user password (admin only)

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/users/change_password \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"username": "john", "password": "newpass123"}'
    ```
    """
    try:
        import bcrypt

        salt = bcrypt.gensalt()

        if os.path.exists(config.USERS_FILE):
            with open(config.USERS_FILE, "r") as f:
                users = json.load(f)

            if data.username in users:
                users[data.username]["password_hash"] = bcrypt.hashpw(
                    data.password.encode("utf-8"), salt
                ).decode("utf-8")
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )

            with open(config.USERS_FILE, "w") as f:
                json.dump(users, f)

            return MessageResponse(
                success=True, message="Password updated successfully"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Users file not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error changing password: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/users/delete", response_model=MessageResponse)
async def delete_user(data: UserDelete, admin: CurrentUser = Depends(require_admin)):
    """
    Delete a user (admin only)

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/users/delete \\
      -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"username": "john"}'
    ```
    """
    try:
        if os.path.exists(config.USERS_FILE):
            with open(config.USERS_FILE, "r") as f:
                users = json.load(f)

            if data.username in users:
                del users[data.username]
            else:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="User not found"
                )

            with open(config.USERS_FILE, "w") as f:
                json.dump(users, f)

            # Delete user PC files
            user_pc_files_pattern = os.path.join(
                config.PC_DATA_DIR, f"{data.username}_pcs.json"
            )
            for file_path in glob.glob(user_pc_files_pattern):
                os.remove(file_path)

            return MessageResponse(
                success=True,
                message="User and associated PC files deleted successfully",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Users file not found"
            )
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Error deleting user: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


# ============================================================================
# Encryption Endpoints
# ============================================================================


@router.get("/get_encryption_key", response_model=EncryptionKeyResponse)
async def get_encryption_key(current_user: CurrentUser = Depends(get_current_user)):
    """
    Get encryption key for authenticated clients

    Example:
    ```bash
    curl -X GET http://localhost:8889/api/get_encryption_key \\
      -H "Authorization: Bearer YOUR_TOKEN"
    ```
    """
    try:
        encryption_key = user.User.load_key()
        encryption_key_encoded = base64.b64encode(encryption_key).decode("utf-8")

        return EncryptionKeyResponse(
            success=True, encryption_key=encryption_key_encoded
        )
    except Exception as e:
        log.error(f"Error serving encryption key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.post("/log_encryption_failure", response_model=MessageResponse)
async def log_encryption_failure(
    data: EncryptionFailureLog, current_user: CurrentUser = Depends(get_current_user)
):
    """
    Log encryption failures from clients

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/log_encryption_failure \\
      -H "Authorization: Bearer YOUR_TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"failure_reason": "Key mismatch", "failure_type": "encryption"}'
    ```
    """
    log.critical(
        f"Browser encryption failure ({data.failure_type}): {data.failure_reason}"
    )
    return MessageResponse(success=True, message="Failure logged")


@router.post("/sync_encryption_key")
async def sync_encryption_key(data: Optional[dict] = None):
    """
    Daemon registration and encryption key sync endpoint (no auth required)

    Example:
    ```bash
    curl -X POST http://localhost:8889/api/sync_encryption_key \\
      -H "Content-Type: application/json" \\
      -d '{"daemon_guid": "abc123", "hostname": "MyPC", "connection_info": {"ip": "192.168.1.100", "port": 8080}}'
    ```
    """
    try:
        log.info("Received daemon registration request")

        if data is None:
            data = {}

        # Extract daemon info
        daemon_guid = data.get("daemon_guid")
        daemon_hostname = data.get("hostname")
        connection_info = data.get("connection_info", {})

        # GUID-based registration (required)
        if not daemon_guid or not daemon_hostname:
            log.error("Missing required daemon_guid or hostname in registration request")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="daemon_guid and hostname are required"
            )

        network.register_daemon(daemon_guid, daemon_hostname, connection_info)
        log.info(
            f"Registered daemon '{daemon_hostname}' (GUID: {daemon_guid[:8]}...) "
            f"at {connection_info.get('ip')}:{connection_info.get('port')}"
        )

        encryption_key = user.User.load_key()
        encryption_key_encoded = base64.b64encode(encryption_key).decode("utf-8")

        return JSONResponse(
            content={
                "success": True,
                "encryption_key": encryption_key_encoded,
            },
            status_code=200,
        )

    except Exception as e:
        log.error(f"Error in syncing encryption key: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )
