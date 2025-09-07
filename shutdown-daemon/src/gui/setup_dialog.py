#!/usr/bin/env python3
"""!
********************************************************************************
@file   setup_dialog.py
@brief  GUI setup dialog for WakeStation shutdown daemon configuration
@author Mahesvara ( https://github.com/Oratorian )
@copyright Mahesvara ( https://github.com/Oratorian )
********************************************************************************
"""

import os
import json
import sys
import bcrypt
from typing import Dict, Any
from dotenv import load_dotenv
from ..config import (
    USERS_FILE_PATH,
    DEFAULT_WOL_SERVER_IP,
    DEFAULT_WOL_SERVER_PORT,
    DEFAULT_BIND_IP,
    DEFAULT_BIND_PORT,
)
from ..utils import get_daemon_logger
from ..core import initialize_users

log = get_daemon_logger("setup_dialog")

try:
    import tkinter as tk
    import tkinter.ttk as ttk
    from tkinter import font, messagebox

    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False


def initialize_users_dialog() -> Dict[str, Any]:
    """Initialize users through GUI dialog or fall back to console."""
    if not TRAY_AVAILABLE:
        return initialize_users()

    # Create main window
    root = tk.Tk()
    root.title("WakeStation - Complete Setup")
    root.geometry("520x750")
    root.resizable(True, True)  # Allow resizing
    root.minsize(500, 650)  # Set minimum size

    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (520 // 2)
    y = (root.winfo_screenheight() // 2) - (750 // 2)
    root.geometry(f"520x750+{x}+{y}")

    # Configure style
    style = ttk.Style()
    try:
        style.theme_use("vista")  # Modern Windows theme
    except:
        style.theme_use("clam")  # Fallback theme

    # Create canvas and scrollbar for scrollable content
    canvas = tk.Canvas(root, highlightthickness=0)
    scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
    scrollable_frame = ttk.Frame(canvas)

    scrollable_frame.bind(
        "<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    # Main frame with reduced padding inside scrollable area
    main_frame = ttk.Frame(scrollable_frame, padding="15")
    main_frame.pack(fill="both", expand=True)

    # Title
    title_font = font.Font(family="Segoe UI", size=14, weight="bold")
    title_label = ttk.Label(
        main_frame, text="WakeStation Complete Setup", font=title_font
    )
    title_label.pack(pady=(0, 8))

    # Description
    description_text = (
        "Configure all settings and create the first user account.\n"
        "This will create the .env file and users.json automatically."
    )
    description_label = ttk.Label(
        main_frame,
        text=description_text,
        foreground="#666666",
        font=("Segoe UI", 9),
        justify="center",
    )
    description_label.pack(pady=(0, 12))

    # Server Configuration Section
    server_frame = ttk.LabelFrame(
        main_frame, text="WakeStation Server Configuration", padding="10"
    )
    server_frame.pack(fill="x", pady=(0, 10))

    # WOL Server IP
    ttk.Label(server_frame, text="WakeStation Server IP:").pack(anchor="w", pady=(0, 5))
    ttk.Label(
        server_frame,
        text="IP address where your WakeStation web server is running",
        foreground="gray",
        font=("Segoe UI", 8),
    ).pack(anchor="w", pady=(0, 5))
    wol_server_ip_var = tk.StringVar(value=DEFAULT_WOL_SERVER_IP or "192.168.1.100")
    wol_server_ip_entry = ttk.Entry(
        server_frame, textvariable=wol_server_ip_var, font=("Segoe UI", 10)
    )
    wol_server_ip_entry.pack(fill="x", pady=(0, 10))

    # WOL Server Port
    ttk.Label(server_frame, text="WakeStation Server Port:").pack(
        anchor="w", pady=(0, 5)
    )
    wol_server_port_var = tk.StringVar(
        value=str(DEFAULT_WOL_SERVER_PORT) if DEFAULT_WOL_SERVER_PORT else "8889"
    )
    wol_server_port_entry = ttk.Entry(
        server_frame, textvariable=wol_server_port_var, font=("Segoe UI", 10)
    )
    wol_server_port_entry.pack(fill="x", pady=(0, 10))

    # Info about encryption key
    info_label = ttk.Label(
        server_frame,
        text="Note: Encryption key (enc.bin) will be automatically received from WakeStation server",
        foreground="gray",
        font=("Segoe UI", 8),
        wraplength=450,
    )
    info_label.pack(anchor="w", pady=(0, 10))

    # Daemon Configuration Section
    daemon_frame = ttk.LabelFrame(
        main_frame, text="Shutdown Daemon Configuration", padding="10"
    )
    daemon_frame.pack(fill="x", pady=(0, 10))

    # Bind IP
    ttk.Label(daemon_frame, text="Bind IP Address:").pack(anchor="w", pady=(0, 5))
    ttk.Label(
        daemon_frame,
        text="IP address for this daemon to listen on (0.0.0.0 = all interfaces)",
        foreground="gray",
        font=("Segoe UI", 8),
    ).pack(anchor="w", pady=(0, 5))
    bind_ip_var = tk.StringVar(value=DEFAULT_BIND_IP if DEFAULT_BIND_IP else "0.0.0.0")
    bind_ip_entry = ttk.Entry(
        daemon_frame, textvariable=bind_ip_var, font=("Segoe UI", 10)
    )
    bind_ip_entry.pack(fill="x", pady=(0, 10))

    # Bind Port
    ttk.Label(daemon_frame, text="Bind Port:").pack(anchor="w", pady=(0, 5))
    bind_port_var = tk.StringVar(
        value=str(DEFAULT_BIND_PORT) if DEFAULT_BIND_PORT else "8080"
    )
    bind_port_entry = ttk.Entry(
        daemon_frame, textvariable=bind_port_var, font=("Segoe UI", 10)
    )
    bind_port_entry.pack(fill="x", pady=(0, 10))

    # User Account Section
    user_frame = ttk.LabelFrame(
        main_frame, text="Create First User Account", padding="10"
    )
    user_frame.pack(fill="x", pady=(0, 10))

    # Username field
    ttk.Label(user_frame, text="Username:").pack(anchor="w", pady=(0, 5))
    username_var = tk.StringVar(value="admin")
    username_entry = ttk.Entry(
        user_frame, textvariable=username_var, font=("Segoe UI", 10)
    )
    username_entry.pack(fill="x", pady=(0, 10))

    # Password field
    ttk.Label(user_frame, text="Password:").pack(anchor="w", pady=(0, 5))
    password_var = tk.StringVar()
    password_entry = ttk.Entry(
        user_frame, textvariable=password_var, show="*", font=("Segoe UI", 10)
    )
    password_entry.pack(fill="x", pady=(0, 10))

    # Result variables
    result = {"cancelled": True, "config": {}, "user_data": {}}

    def validate_and_save():
        # Validate required fields
        if not username_var.get().strip():
            messagebox.showerror("Error", "Username cannot be empty!", parent=root)
            return
        if not password_var.get().strip():
            messagebox.showerror("Error", "Password cannot be empty!", parent=root)
            return
        if not wol_server_ip_var.get().strip():
            messagebox.showerror(
                "Error", "WakeStation Server IP cannot be empty!", parent=root
            )
            return

        # Validate port numbers
        try:
            wol_port = int(wol_server_port_var.get())
            bind_port = int(bind_port_var.get())
            if not (1 <= wol_port <= 65535) or not (1 <= bind_port <= 65535):
                raise ValueError("Port out of range")
        except ValueError:
            messagebox.showerror(
                "Error", "Ports must be valid numbers between 1-65535!", parent=root
            )
            return

        # Prepare configuration data
        config_data = {
            "WOL_SERVER_IP": wol_server_ip_var.get().strip(),
            "WOL_SERVER_PORT": wol_server_port_var.get().strip(),
            "BIND_IP": bind_ip_var.get().strip(),
            "BIND_PORT": bind_port_var.get().strip(),
        }

        # Prepare user data
        password_hash = bcrypt.hashpw(
            password_var.get().strip().encode(), bcrypt.gensalt()
        ).decode()
        user_data = {
            username_var.get().strip(): {
                "username": username_var.get().strip(),
                "password_hash": password_hash,
                "permission": "user",
            }
        }

        result["cancelled"] = False
        result["config"] = config_data
        result["user_data"] = user_data
        root.destroy()

    def on_cancel():
        root.destroy()

    # Buttons frame
    buttons_frame = ttk.Frame(main_frame)
    buttons_frame.pack(fill="x", pady=(15, 0))

    # Cancel button
    cancel_btn = ttk.Button(buttons_frame, text="Cancel", command=on_cancel)
    cancel_btn.pack(side="right", padx=(10, 0))

    # OK button (primary)
    ok_btn = ttk.Button(buttons_frame, text="OK", command=validate_and_save)
    ok_btn.pack(side="right")

    # Focus on first empty field
    if not wol_server_ip_var.get():
        wol_server_ip_entry.focus()
    else:
        username_entry.focus()

    # Mouse wheel scrolling
    def on_mousewheel(event):
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    # Bind mouse wheel to canvas
    canvas.bind("<MouseWheel>", on_mousewheel)
    root.bind("<MouseWheel>", on_mousewheel)

    # Enter key binding
    def on_enter(event):
        validate_and_save()

    root.bind("<Return>", on_enter)

    # Show window and wait
    root.mainloop()

    # Handle result
    if result["cancelled"]:
        sys.exit(1)

    # Save .env file
    env_path = ".env"
    try:
        with open(env_path, "w") as env_file:
            env_file.write("# WakeStation Shutdown Daemon Configuration\n")
            env_file.write("# Generated by setup wizard\n\n")
            for key, value in result["config"].items():
                env_file.write(f"{key}={value}\n")
        log.info(f".env configuration file created successfully at {env_path}")
    except Exception as e:
        log.warning(f"Could not create .env file: {e}")

    # Save users.json file
    try:
        with open(USERS_FILE_PATH, "w") as users_file:
            json.dump(result["user_data"], users_file, indent=4)
        log.info("First user has been set up and saved successfully.")
    except Exception as e:
        log.error(f"Could not create users.json file: {e}")
        sys.exit(1)

    return result["user_data"]
