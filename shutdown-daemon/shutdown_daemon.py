import os
import json
import bcrypt
import hmac
import hashlib
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from datetime import datetime, timezone
import requests
import socket
import signal
import sys
import platform
from dotenv import load_dotenv
import argparse
import threading
import time
from typing import Optional, Dict, Any, Union

try:
    import pystray
    from pystray import MenuItem as item
    from PIL import Image, ImageDraw
    import tkinter as tk
    from tkinter import messagebox, simpledialog

    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False


load_dotenv()


DEFAULT_WOL_SERVER_IP = os.getenv("WOL_SERVER_IP", "")
DEFAULT_WOL_SERVER_PORT = os.getenv("WOL_SERVER_PORT", "8889")
DEFAULT_SECRET_KEY = os.getenv("SECRET_KEY", "")
DEFAULT_BIND_IP = os.getenv("BIND_IP", "0.0.0.0")
DEFAULT_BIND_PORT = int(os.getenv("BIND_PORT", 8080))


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="WakeStation Shutdown Daemon - Remote shutdown service with system tray integration",
        epilog="""
Examples:
  %(prog)s                                    # Use defaults from .env file
  %(prog)s --wol-server-ip 192.168.1.100     # Override server IP
  %(prog)s --dry-run                          # Test mode without actual shutdowns
  %(prog)s --bind-port 9090 --dry-run         # Custom port with dry-run mode

Configuration:
  Settings can be provided via command-line arguments, environment variables, or .env file.
  Command-line arguments take precedence over environment variables.

System Tray:
  When GUI libraries are available, the daemon runs with a system tray icon providing:
  - Dry-run toggle (orange=enabled, red=disabled)
  - Last request status display
  - Restart and quit options
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--wol-server-ip",
        type=str,
        default=DEFAULT_WOL_SERVER_IP,
        metavar="IP",
        help="IP address of the WakeStation WOL server (default: %(default)s or WOL_SERVER_IP env var)",
    )
    parser.add_argument(
        "--wol-server-port",
        type=int,
        default=int(DEFAULT_WOL_SERVER_PORT),
        metavar="PORT",
        help="Port of the WakeStation WOL server (default: %(default)s or WOL_SERVER_PORT env var)",
    )
    parser.add_argument(
        "--secret-key",
        type=str,
        default=DEFAULT_SECRET_KEY,
        metavar="KEY",
        help="Secret key for HMAC authentication (default: SECRET_KEY env var)",
    )
    parser.add_argument(
        "--bind-ip",
        type=str,
        default=DEFAULT_BIND_IP,
        metavar="IP",
        help="IP address to bind the shutdown daemon server (default: %(default)s or BIND_IP env var)",
    )
    parser.add_argument(
        "--bind-port",
        type=int,
        default=DEFAULT_BIND_PORT,
        metavar="PORT",
        help="Port to bind the shutdown daemon server (default: %(default)s or BIND_PORT env var)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Enable dry-run mode - log shutdown requests but don't execute them",
    )
    parser.add_argument(
        "--version", action="version", version="WakeStation Shutdown Daemon v2.6.0"
    )

    return parser.parse_args()


def check_if_daemon_running() -> bool:
    """Check if another instance of the daemon is already running."""
    if not os.path.exists(PID_FILE):
        return False

    try:
        with open(PID_FILE, "r") as f:
            pid = int(f.read().strip())

        # Check if process is still running
        process_running = False
        if platform.system() == "Windows":
            import subprocess

            try:
                result = subprocess.run(
                    ["tasklist", "/FI", f"PID eq {pid}"],
                    capture_output=True,
                    text=True,
                    check=True,
                    encoding="utf-8",
                    errors="ignore",
                )
                # Check if result.stdout is not None and contains the PID
                if result.stdout:
                    process_running = str(pid) in result.stdout
                else:
                    process_running = False
            except (subprocess.CalledProcessError, UnicodeDecodeError, Exception) as e:
                # If any error occurs, assume process is not running
                print(f"Error checking process {pid}: {e}")
                process_running = False
        else:
            # Unix/Linux
            try:
                os.kill(pid, 0)  # Signal 0 checks if process exists
                process_running = True
            except OSError:
                process_running = False

        # If process is not running, clean up stale PID file
        if not process_running:
            print(
                f"Found stale PID file (process {pid} no longer running), cleaning up..."
            )
            remove_pid_file()
            return False

        return True

    except (ValueError, FileNotFoundError):
        # Invalid or missing PID file, clean it up
        remove_pid_file()
        return False


def create_pid_file() -> None:
    """Create a PID file with the current process ID."""
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def remove_pid_file() -> None:
    """Remove the PID file."""
    try:
        if os.path.exists(PID_FILE):
            os.remove(PID_FILE)
    except OSError:
        pass


def write_log(message):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_message = f"{timestamp} - {message}"
    with open(LOG_FILE_PATH, "a") as log_file:
        log_file.write(log_message + "\n")
    print(log_message)


def validate_required_variables(args):
    WOL_SERVER_IP = args.wol_server_ip or os.getenv("WOL_SERVER_IP")
    SECRET_KEY = args.secret_key or os.getenv("SECRET_KEY")
    DRY_RUN = args.dry_run

    if not WOL_SERVER_IP:
        print(
            "WOL_SERVER_IP is missing. Please enter the IP address of the WOL server:"
        )
        WOL_SERVER_IP = input("WOL_SERVER_IP: ").strip()

    if not SECRET_KEY:
        print("SECRET_KEY is missing. Please enter the secret key:")
        SECRET_KEY = input("SECRET_KEY: ").strip()

    return WOL_SERVER_IP, SECRET_KEY, DRY_RUN


args = parse_arguments()
WOL_SERVER_IP, SECRET_KEY, DRY_RUN = validate_required_variables(args)
WOL_SERVER_PORT = args.wol_server_port
BIND_IP = args.bind_ip
BIND_PORT = args.bind_port

if platform.system() == "Windows":
    APP_DATA_PATH = os.path.join(os.getenv("APPDATA", ""), "shutdown-daemon")
else:
    APP_DATA_PATH = os.path.join(
        os.getenv("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "shutdown-daemon"
    )

# Ensure the directory exists
if not os.path.exists(APP_DATA_PATH):
    os.makedirs(APP_DATA_PATH)

KEY_FILE = os.path.join(APP_DATA_PATH, "enc.bin")
USERS_FILE_PATH = os.path.join(APP_DATA_PATH, "users.json")
LOG_FILE_PATH = os.path.join(APP_DATA_PATH, "daemon.log")
PID_FILE = os.path.join(APP_DATA_PATH, "daemon.pid")


def initialize_users():
    if not os.path.exists(USERS_FILE_PATH):
        write_log(
            "No users file found. Prompting user to set up the first username and password."
        )
        username = input("Enter username: ")
        password = bcrypt.hashpw(
            input("Enter password: ").encode(), bcrypt.gensalt()
        ).decode()
        permission = input("Enter permission level (e.g., 'admin', 'user'): ")

        users = {
            username: {
                "username": username,
                "password_hash": password,
                "permission": permission,
            }
        }

        with open(USERS_FILE_PATH, "w") as users_file:
            json.dump(users, users_file, indent=4)
        write_log("First user has been set up and saved successfully.")
        return users
    else:
        with open(USERS_FILE_PATH, "r") as users_file:
            return json.load(users_file)


def initialize_users_dialog() -> Dict[str, Any]:
    if not TRAY_AVAILABLE:
        return initialize_users()

    import tkinter.ttk as ttk
    from tkinter import font

    # Create main window
    root = tk.Tk()
    root.title("WakeStation - Initial Setup")
    root.geometry("400x300")
    root.resizable(False, False)

    # Center the window
    root.update_idletasks()
    x = (root.winfo_screenwidth() // 2) - (400 // 2)
    y = (root.winfo_screenheight() // 2) - (300 // 2)
    root.geometry(f"400x300+{x}+{y}")

    # Configure style
    style = ttk.Style()
    try:
        style.theme_use("vista")  # Modern Windows theme
    except:
        style.theme_use("clam")  # Fallback theme

    # Main frame
    main_frame = ttk.Frame(root, padding="20")
    main_frame.pack(fill="both", expand=True)

    # Title
    title_font = font.Font(family="Segoe UI", size=16, weight="bold")
    title_label = ttk.Label(main_frame, text="WakeStation Setup", font=title_font)
    title_label.pack(pady=(0, 10))

    # Subtitle
    subtitle_label = ttk.Label(
        main_frame,
        text="Please create the first user account",
        foreground="gray",
    )
    subtitle_label.pack(pady=(0, 10))

    # Description
    description_text = (
        "This account will be used to authorize shutdown commands\n"
        "sent from the WakeStation web interface."
    )
    description_label = ttk.Label(
        main_frame,
        text=description_text,
        foreground="#666666",
        font=("Segoe UI", 9),
        justify="center",
    )
    description_label.pack(pady=(0, 20))

    # Username field
    ttk.Label(main_frame, text="Username:").pack(anchor="w", pady=(0, 5))
    username_var = tk.StringVar()
    username_entry = ttk.Entry(
        main_frame, textvariable=username_var, font=("Segoe UI", 10)
    )
    username_entry.pack(fill="x", pady=(0, 15))
    username_entry.focus()

    # Password field
    ttk.Label(main_frame, text="Password:").pack(anchor="w", pady=(0, 5))
    password_var = tk.StringVar()
    password_entry = ttk.Entry(
        main_frame, textvariable=password_var, show="*", font=("Segoe UI", 10)
    )
    password_entry.pack(fill="x", pady=(0, 15))

    # Result variables
    result = {"cancelled": True, "username": None, "password": None, "permission": None}

    def on_create():
        if not username_var.get().strip():
            messagebox.showerror("Error", "Username cannot be empty!", parent=root)
            return
        if not password_var.get().strip():
            messagebox.showerror("Error", "Password cannot be empty!", parent=root)
            return

        result["cancelled"] = False
        result["username"] = username_var.get().strip()
        result["password"] = password_var.get().strip()
        result["permission"] = "user"  # Default to user permission
        root.destroy()

    def on_cancel():
        root.destroy()

    # Buttons frame
    buttons_frame = ttk.Frame(main_frame)
    buttons_frame.pack(fill="x", pady=(10, 0))

    # Cancel button
    cancel_btn = ttk.Button(buttons_frame, text="Cancel", command=on_cancel)
    cancel_btn.pack(side="right", padx=(10, 0))

    # Create button (primary)
    create_btn = ttk.Button(buttons_frame, text="Create Account", command=on_create)
    create_btn.pack(side="right")

    # Enter key binding
    def on_enter(event):
        on_create()

    root.bind("<Return>", on_enter)

    # Show window and wait
    root.mainloop()

    # Handle result
    if result["cancelled"]:
        sys.exit(1)

    username = result["username"]
    password = result["password"]
    permission = result["permission"]

    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    users = {
        username: {
            "username": username,
            "password_hash": password_hash,
            "permission": permission,
        }
    }

    with open(USERS_FILE_PATH, "w") as users_file:
        json.dump(users, users_file, indent=4)
    write_log("First user has been set up and saved successfully.")
    return users


server_running = False
server_thread = None
tray_icon = None
last_request: Dict[str, Union[str, datetime, bool, None]] = {
    "username": None,
    "time": None,
    "success": None,
}


def toggle_dry_run() -> None:
    global DRY_RUN, tray_icon
    DRY_RUN = not DRY_RUN
    write_log(f"Dry-run mode {'enabled' if DRY_RUN else 'disabled'}")
    if tray_icon:
        tray_icon.icon = create_tray_image()  # type: ignore
        tray_icon.menu = create_tray_menu()  # type: ignore


def create_tray_image() -> Image.Image:
    color = "orange" if DRY_RUN else "red"
    image = Image.new("RGB", (64, 64), color=color)
    draw = ImageDraw.Draw(image)
    draw.rectangle([16, 16, 48, 48], fill="white")
    draw.text((24, 28), "SD", fill="black")
    return image


def create_tray_menu():
    dry_run_text = "✓ Dry-Run Mode" if DRY_RUN else "✗ Dry-Run Mode"
    status_text = "No requests yet"

    if last_request["username"]:
        time_str = "Unknown"
        if isinstance(last_request["time"], datetime):
            time_str = last_request["time"].strftime("%H:%M:%S")

        status_icon = "✓" if last_request["success"] else "✗"
        status_text = f'{status_icon} {last_request["username"]} at {time_str}'

    return pystray.Menu(
        item(dry_run_text, toggle_dry_run),
        pystray.Menu.SEPARATOR,
        item(f"Last Request: {status_text}", None),
        pystray.Menu.SEPARATOR,
        item("Restart Daemon", restart_daemon),
        item("Quit", quit_application),
    )


def create_tray_icon():
    if not TRAY_AVAILABLE:
        return None

    image = create_tray_image()
    menu = create_tray_menu()

    return pystray.Icon("shutdown_daemon", image, "Shutdown Daemon", menu)


def restart_daemon() -> None:
    global server_running, server_thread, tray_icon

    if server_thread and server_thread.is_alive():
        write_log("Restarting daemon...")
        server_running = False
        server_thread.join(timeout=5)

    sync_encryption_key()
    start_server_thread()
    write_log("Daemon restarted successfully.")

    if tray_icon:
        tray_icon.menu = create_tray_menu()  # type: ignore


def quit_application() -> None:
    global server_running, tray_icon
    write_log("Shutting down daemon...")
    server_running = False
    remove_pid_file()
    if tray_icon:
        tray_icon.stop()  # type: ignore


users = (
    initialize_users_dialog()
    if not os.path.exists(USERS_FILE_PATH) and TRAY_AVAILABLE
    else initialize_users()
)


def authenticate_user(username: str, password: str) -> bool:
    if username in users:
        hashed_password = users[username]["password_hash"].encode()
        return bcrypt.checkpw(password.encode(), hashed_password)
    return False


def decrypt_data(encrypted_data: bytes, key: bytes) -> Optional[str]:
    try:
        encrypted_message = base64.b64decode(encrypted_data)
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()  # AES block size is 128 bits
        decrypted_data = unpadder.update(padded_data) + unpadder.finalize()
        return decrypted_data.decode("utf-8")

    except Exception as e:
        write_log(f"Decryption error: {e}")
        return None


def sync_encryption_key() -> bool:
    try:

        timestamp = str(int(datetime.now(timezone.utc).timestamp()))

        signature = hmac.new(
            SECRET_KEY.encode(), timestamp.encode(), hashlib.sha256
        ).hexdigest()

        headers = {"Content-Type": "application/json"}
        json_body = {"signature": signature, "timestamp": timestamp}

        wol_url = f"http://{WOL_SERVER_IP}:{WOL_SERVER_PORT}/api/sync_encryption_key"
        response = requests.post(wol_url, headers=headers, json=json_body)
        response_data = response.json()

        if response.status_code == 200 and response_data.get("success"):
            encryption_key_base64 = response_data.get("encryption_key")
            if encryption_key_base64:
                encryption_key_binary = base64.b64decode(encryption_key_base64)

                with open(KEY_FILE, "wb") as key_file:
                    key_file.write(encryption_key_binary)
                write_log(f"Encryption key sync complete: {KEY_FILE}")
            else:
                write_log("Error: Failed to retrieve encryption key from server.")
                return False
        else:
            write_log(f"Error: {response_data.get('message', 'Unknown error')}")
            return False
    except Exception as e:
        write_log(f"Exception during key sync: {e}")
        return False
    return True


def load_encryption_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as key_file:
            return key_file.read()
    else:
        write_log("Encryption key file not found.")
        return None


def handle_client_connection(client_socket):
    global last_request, tray_icon
    try:
        data = client_socket.recv(1024).strip()
        write_log(f"Received raw data: {data}")

        key = load_encryption_key()
        if not key:
            client_socket.send(b"Encryption key missing.\n")
            return

        decrypted_data = decrypt_data(data, key)
        if not decrypted_data:
            client_socket.send(b"Invalid encrypted data.\n")
            return

        parts = decrypted_data.split("|")
        if len(parts) != 3:
            client_socket.send(b"Invalid data format.\n")
            return

        username, password, command = parts

        if authenticate_user(username, password):
            last_request["username"] = username
            last_request["time"] = datetime.now()
            last_request["success"] = True

            if command.lower() == "shutdown":
                client_socket.send(b"Shutdown command received.")
                if DRY_RUN:
                    write_log(f"Dry-run enabled, no shutdown initilized")
                    write_log(f"Shutdown recieved from: {username}")
                    client_socket.close()
                else:
                    os.system("shutdown /s /t 1")
                    write_log(f"Shutdown recieved from: {username}")
                    client_socket.close()
            else:
                client_socket.send(b"Invalid command.")
                last_request["success"] = False
        else:
            last_request["username"] = username if "username" in locals() else "Unknown"
            last_request["time"] = datetime.now()
            last_request["success"] = False
            client_socket.send(b"Unauthorized.")

        if tray_icon:
            tray_icon.menu = create_tray_menu()  # type: ignore

    except Exception as e:
        write_log(f"Error handling client: {e}")
        last_request["username"] = "Error"
        last_request["time"] = datetime.now()
        last_request["success"] = False
        if tray_icon:
            tray_icon.menu = create_tray_menu()  # type: ignore
    finally:
        client_socket.close()


def signal_handler(sig, frame):
    print("\nShutting down server...")
    remove_pid_file()
    sys.exit(0)


def setup_signal_handlers() -> None:
    """Setup signal handlers for graceful shutdown."""
    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, signal_handler)  # Termination request
    if platform.system() == "Windows":
        # Windows-specific signals
        if hasattr(signal, "SIGBREAK"):
            signal.signal(signal.SIGBREAK, signal_handler)  # Ctrl+Break


setup_signal_handlers()


def start_server():
    global server_running
    server_running = True
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind((BIND_IP, BIND_PORT))
        server.listen(5)
        server.settimeout(1)
        print(f"Server listening on {BIND_IP}:{BIND_PORT}, Using DRY_RUN: {DRY_RUN}")
        sync_encryption_key()

        while server_running:
            try:
                client_socket, addr = server.accept()
                print(f"Accepted connection from {addr}")
                handle_client_connection(client_socket)
            except socket.timeout:
                continue
            except Exception as e:
                if server_running:
                    write_log(f"Server error: {e}")
    except KeyboardInterrupt:
        print("\nServer interrupted by Ctrl+C")
    except Exception as e:
        write_log(f"Failed to start server: {e}")
    finally:
        server_running = False
        try:
            server.close()
        except:
            pass
        print("Server stopped.")


def start_server_thread():
    global server_thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    return server_thread


if __name__ == "__main__":
    # Check if daemon is already running
    if check_if_daemon_running():
        print("Another instance of shutdown daemon is already running!")
        if TRAY_AVAILABLE:
            import tkinter as tk
            from tkinter import messagebox

            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Daemon Already Running",
                "Another instance of the shutdown daemon is already running.\n"
                "Please stop the existing instance before starting a new one.",
            )
            root.destroy()
        sys.exit(1)

    # Create PID file for this instance
    create_pid_file()

    try:
        if TRAY_AVAILABLE:
            tray_icon = create_tray_icon()
            start_server_thread()

            try:
                if tray_icon:  # Add None check
                    tray_icon.run()  # type: ignore
            except KeyboardInterrupt:
                quit_application()
        else:
            print("System tray not available. Running in console mode...")
            try:
                start_server()
            except KeyboardInterrupt:
                print("\nShutdown daemon stopped.")
    finally:
        # Ensure PID file is cleaned up
        remove_pid_file()
