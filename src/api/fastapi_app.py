#!/usr/bin/env python3
"""!
********************************************************************************
@file   fastapi_app.py
@brief  FastAPI application setup with CORS and documentation
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .fastapi_routes import router
import config


def create_fastapi_app() -> FastAPI:
    """
    Create and configure FastAPI application

    Returns:
        Configured FastAPI instance
    """
    app = FastAPI(
        title="WakeStation API",
        description="""
        Professional Wake-on-LAN Command Center with Remote Shutdown

        ## Features
        - 🔐 **Dual Authentication**: Cookie-based (web) + Bearer token (API)
        - 🌐 **Wake-on-LAN**: Send magic packets to wake devices
        - 💤 **Remote Shutdown**: Secure shutdown via daemon
        - 📊 **Device Management**: Track and manage multiple PCs
        - 👥 **User Management**: Multi-user support with permissions

        ## Authentication

        ### For Web UI
        Login via `/api/login` - authentication cookie is set automatically.

        ### For API Clients
        1. Login to get JWT token:
        ```bash
        curl -X POST http://localhost:8889/api/login \\
          -H "Content-Type: application/json" \\
          -d '{"username": "admin", "password": "password"}'
        ```

        2. Use token in Authorization header:
        ```bash
        curl -X GET http://localhost:8889/api/load \\
          -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
        ```

        3. Refresh token before expiry (15 minutes):
        ```bash
        curl -X POST http://localhost:8889/api/refresh \\
          -H "Content-Type: application/json" \\
          -d '{"refresh_token": "YOUR_REFRESH_TOKEN"}'
        ```

        ## Security
        - JWT tokens with configurable expiry
        - HttpOnly cookies for web clients
        - Bcrypt password hashing
        - Hardware-based encryption for shutdown commands
        - HMAC authentication for daemon communication
        """,
        version="3.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8889",
            "http://127.0.0.1:8889",
            f"http://localhost:{config.WOL_SERVER_PORT}",
            f"http://127.0.0.1:{config.WOL_SERVER_PORT}",
            f"http://{config.WOL_SERVER_HOST}:{config.WOL_SERVER_PORT}",
            # Add your production domain here
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Include API routes
    app.include_router(router)

    return app
