# 🚀 WakeStation - Wake-on-LAN Command Center

<div align="center">

![WakeStation](https://img.shields.io/badge/WakeStation-v3.0.0-00ff88?style=for-the-badge&logo=wifi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-0099ff?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-red?style=for-the-badge&logo=gnu&logoColor=white)
![Build Status](https://img.shields.io/github/actions/workflow/status/Oratorian/WakeStation/release.yml?style=for-the-badge&logo=github&logoColor=white&label=Build)
![Release](https://img.shields.io/github/v/release/Oratorian/WakeStation?style=for-the-badge&logo=github&logoColor=white&label=Release)


**Professional network device management with remote wake & shutdown capabilities**

</div>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🆕 What's New in v3.0.0](#-whats-new-in-v300)
- [⚙️ Requirements](#️-requirements)
- [🚀 Installation Guide](#-installation-guide)
  - [📦 Install arp-scan](#-1-install-arp-scan-linux-only)
  - [⬇️ Download WakeStation](#️-2-download-wakestation)
  - [🐍 Python Setup](#-3-python-setup)
  - [🔧 Install Dependencies](#-4-install-dependencies)
  - [🔧 Configuration](#-5-configuration)
- [🖥️ WakeStation Server Setup](#️-wakestation-server-setup)
- [🔒 SSL/TLS Configuration](#-ssltls-configuration)
- [💻 Shutdown Daemon Setup](#-shutdown-daemon-setup)
- [📱 Android App](#-android-app)
- [🔧 Command Line Usage](#-command-line-usage)
- [🔨 Building Binaries](#-building-binaries)
- [🌐 API Documentation](#-api-documentation)
- [📄 License](#-license)

---

## ✨ Features

- **Wake-on-LAN Support**: Trigger WOL requests for devices in your network using their MAC addresses.
- **Remote Shutdown Support**: Includes Python-based shutdown daemon for remote shutdown commands with end-to-end encryption.
- **JWT Authentication**: Secure token-based authentication with automatic token refresh.
- **SSL/TLS Support**: Native HTTPS support without reverse proxy (internal CA and Let's Encrypt).
- **FastAPI + Flask**: Modern REST API with automatic OpenAPI documentation and interactive web UI.
- **Android Application**: Native Android app with JWT authentication and biometric support.
- **System Tray Integration**: Shutdown daemon runs with system tray icon, dry-run toggle, and status monitoring.
- **GUID-Based Daemon Registry**: Network-agnostic daemon identification and discovery.
- **REST API**: Direct API access with JWT tokens for automation and scripting.
- **Database Integration**: Stores user and device information in a local JSON-based database.
- **Comprehensive Logging**: Separate access logs and application logs with rotation.

---

## 🆕 What's New in v3.0.0

### Major Changes

- **JWT-Only Authentication**: Removed Flask-Login/Flask-Session in favor of unified JWT authentication
  - Access tokens (15 min expiry) and refresh tokens (7 day expiry)
  - Tokens persist across server restarts
  - Automatic token refresh mechanism

- **SSL/TLS Support**: Native HTTPS without reverse proxy
  - Support for internal CA certificates
  - Let's Encrypt integration
  - Configurable in `config.py`

- **FastAPI Integration**: Hybrid FastAPI + Flask architecture
  - FastAPI for REST API with automatic OpenAPI docs
  - Flask for web UI rendering
  - Interactive API documentation at `/docs` and `/redoc`

- **GUID-Based Daemon Registry**: Network-agnostic daemon identification
  - Daemons identified by GUID instead of IP
  - Survives network changes and DHCP reassignments

- **Android Application**: Native Android app included
  - JWT authentication with secure token storage
  - Biometric authentication for shutdown operations
  - Material Design UI with proper system bar handling
  - Network security config for internal CA support

- **Code Cleanup**: Removed 700+ lines of redundant code
  - Removed duplicate functions and obsolete Docker infrastructure
  - Consolidated logging system with rsyslog-logger
  - Reorganized UI structure to `src/ui/`

- **Separate Access Logging**: HTTP access logs in dedicated file
  - `logs/access.log` for HTTP requests
  - `logs/wakestation.log` for application logs

### Breaking Changes

- **Authentication**: Cookie-based auth replaced with JWT tokens
- **API Endpoints**: All endpoints now require `Authorization: Bearer <token>` header
- **Port**: Default changed from 8889 to 443 (HTTPS)
- **Daemon Registration**: Now requires GUID-based identification

---

## ⚙️ Requirements

### Linux Systems:
- **Python 3.11+**
- **arp-scan** (for network device discovery)

### Windows Systems:
- **Python 3.11+**
- **Included tools** (pre-bundled with WakeStation):
  - **arp-scan.exe** - Network scanning (compiled from [arp-scan-windows](https://github.com/QbsuranAlang/arp-scan-windows-))
  - **nc.exe** - Network connectivity testing (from [Nmap](https://nmap.org/download.html#windows))
  - **libcrypto-3.dll, libssl-3.dll** - OpenSSL libraries (from [Nmap](https://nmap.org/download.html#windows))

---

## 🚀 Installation Guide

### 📦 1. Install arp-scan (Linux Only)

**Note:** WakeStation v2.9.2+ uses cross-platform Python socket implementation for Wake-on-LAN packets (no more etherwake dependency required).

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install arp-scan
```

**CentOS/RHEL/Rocky Linux/AlmaLinux:**
```bash
sudo yum install arp-scan
# or for newer versions:
sudo dnf install arp-scan
```

**Fedora:**
```bash
sudo dnf install arp-scan
```

**Arch Linux:**
```bash
sudo pacman -S arp-scan
```

**openSUSE:**
```bash
sudo zypper install arp-scan
```

**⚠️ Important: arp-scan Packet Capture Permissions**

arp-scan requires raw packet capture capabilities. Choose one of these methods:

**Method 1: Grant capabilities to arp-scan binary (recommended for manual/development setups):**
```bash
sudo setcap cap_net_raw+ep /usr/bin/arp-scan
```

**Method 2: Use systemd service (recommended for production):**
The included `wakestation.service` file automatically handles arp-scan capabilities. See [WakeStation Server Setup](#️-wakestation-server-setup) section.

**Method 3: Add user to network group (varies by distribution):**
```bash
# Some distributions (check your system documentation)
sudo usermod -a -G netdev $USER  # or wireshark group
# Logout and login required
```

### ⬇️ 2. Download WakeStation
Download the latest release: **[WakeStation Releases](https://github.com/Oratorian/WakeStation/releases)**

**Windows users:** All required tools (arp-scan.exe, nc.exe, OpenSSL libraries) are included in the release package - no additional downloads needed!

### 🐍 3. Python Setup
```bash
# Navigate to unpacked directory
cd wakestation

# Set up virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 🔧 4. Install Dependencies

Install all required dependencies using the unified requirements file:

```bash
pip install -r requirements.txt
```

This single requirements file contains all dependencies needed for both WakeStation server and shutdown daemon components.

### 🔧 5. Configuration

**Configure `config.py` for WakeStation server:**

Key settings to configure:

```python
# Network Configuration
WOL_SERVER_HOST = "10.0.1.13"  # Must be actual network IP (not 127.0.0.1)
WOL_SERVER_PORT = 443           # Port 443 for HTTPS, 80 for HTTP

# SSL/TLS Configuration
ENABLE_SSL = True
SSL_CERTFILE = "/path/to/fullchain.pem"
SSL_KEYFILE = "/path/to/privkey.pem"
SSL_CA_CERTS = None  # Optional: Internal CA certificate

# Security Configuration
SECRET_KEY = "your-secret-key-here"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
```

**Configure the `.env` file for the shutdown daemon:**

Create a `.env` file in the `shutdown-daemon/` directory:

```plaintext
WOL_SERVER_IP = 10.0.1.13
WOL_SERVER_PORT = 443
BIND_IP = 0.0.0.0
BIND_PORT = 8080
SECRET_KEY = your-secret-key-here
```

Replace values with your specific configuration. The `SECRET_KEY` must match the one in `config.py`.

---

## 🖥️ WakeStation Server Setup

### Option A: Systemd Service (Recommended for Production)

**1. Update wakestation.service paths:**

Edit the service file to match your installation:

```bash
sudo nano wakestation.service
```

Update these paths:
```ini
[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/wol
ExecStart=/opt/wol/.wol/bin/python wakestation.py

# Capabilities for privileged port binding and arp-scan
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SETFCAP
```

**2. Install and activate the service:**

```bash
# Copy the service file to systemd directory
sudo cp wakestation.service /etc/systemd/system/

# Reload systemd to recognize the new service
sudo systemctl daemon-reload

# Enable the service to start on boot
sudo systemctl enable wakestation

# Start the service immediately
sudo systemctl start wakestation

# Check service status
sudo systemctl status wakestation

# View service logs
sudo journalctl -u wakestation -f
```

### Option B: Manual Execution (Development/Testing)

For temporary testing or development:

```bash
# Activate virtual environment
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Run WakeStation
python wakestation.py
```

**Using tmux for persistent sessions:**
```bash
tmux new-session -d -s wakestation
tmux send-keys -t wakestation "source venv/bin/activate" Enter
tmux send-keys -t wakestation "python wakestation.py" Enter
```

### 🌐 Access WakeStation

- **HTTPS**: `https://your-server-ip` (default port 443)
- **HTTP**: `http://your-server-ip:8889` (if SSL disabled)
- **API Docs**: `https://your-server-ip/docs` (Swagger UI)
- **ReDoc**: `https://your-server-ip/redoc` (Alternative API docs)

---

## 🔒 SSL/TLS Configuration

WakeStation v3.0.0+ supports native HTTPS without requiring a reverse proxy.

### Self-Signed Certificate (Testing)

Generate a self-signed certificate for testing:

```bash
bash generate_ssl_cert.sh
```

This creates:
- `ssl/cert.pem` - Self-signed certificate
- `ssl/key.pem` - Private key

### Internal CA Certificate

For internal networks with a custom CA:

```bash
# Generate certificate request
openssl req -new -newkey rsa:4096 -nodes \
  -keyout key.pem -out csr.pem \
  -subj "/CN=wakestation.yourdomain.local"

# Sign with your internal CA
# (varies by CA setup)

# Update config.py
SSL_CERTFILE = "/path/to/fullchain.crt"
SSL_KEYFILE = "/path/to/key.pem"
SSL_CA_CERTS = None
```

### Let's Encrypt (Production)

For public-facing servers:

```bash
# Install certbot
sudo apt install certbot  # Ubuntu/Debian

# Obtain certificate
sudo certbot certonly --standalone -d wakestation.yourdomain.com

# Update config.py
SSL_CERTFILE = "/etc/letsencrypt/live/wakestation.yourdomain.com/fullchain.pem"
SSL_KEYFILE = "/etc/letsencrypt/live/wakestation.yourdomain.com/privkey.pem"
SSL_CA_CERTS = None
```

See [SSL_SETUP.md](SSL_SETUP.md) for detailed SSL configuration guide.

---

## 💻 Shutdown Daemon Setup

The shutdown daemon must be installed on each computer you want to remotely shutdown. Choose the appropriate method for your operating system:

### Linux Systems:

**Option A: Systemd Service (recommended for all Linux systems):**

Configure and install the shutdown daemon as a system service:

```bash
# Edit the service file paths for your installation
sudo nano shutdown-daemon/shutdown_daemon.service

# Update these paths in the service file:
WorkingDirectory=/opt/wol/shutdown-daemon
ExecStart=/opt/wol/.wol/bin/python shutdown_daemon.py

# Copy service file to systemd directory
sudo cp shutdown-daemon/shutdown_daemon.service /etc/systemd/system/

# Reload systemd and enable service
sudo systemctl daemon-reload
sudo systemctl enable shutdown_daemon
sudo systemctl start shutdown_daemon

# Check service status
sudo systemctl status shutdown_daemon

# View service logs
sudo journalctl -u shutdown_daemon -f
```

**Option B: GUI Mode (desktop environment with user session):**
```bash
# Using Python directly (for testing or desktop environments)
cd shutdown-daemon
python shutdown_daemon.py

# The daemon will run with system tray integration if available
```

**Option C: Manual CLI Mode (temporary/testing):**
```bash
# Using tmux for persistent session
tmux new-session -d -s shutdown-daemon
tmux send-keys -t shutdown-daemon "cd shutdown-daemon" Enter
tmux send-keys -t shutdown-daemon "python shutdown_daemon.py" Enter

# Using screen (alternative)
screen -dmS shutdown-daemon bash -c 'cd shutdown-daemon && python shutdown_daemon.py'

# Direct execution (will stop when terminal closes)
cd shutdown-daemon
python shutdown_daemon.py
```

### Windows Systems:

**Option A: GUI Mode (desktop/workstation):**
- Download precompiled binaries from releases
- Double-click `shutdown_daemon-gui.exe` to run with system tray
- System tray provides:
  - Dry-run mode toggle (orange icon = dry-run, red icon = normal)
  - Last request status display
  - Restart daemon and quit options

**Option B: CLI Mode (servers/command line):**
```cmd
# Run from command prompt
shutdown_daemon-cli.exe

# Or using Python directly
python shutdown-daemon/shutdown_daemon.py
```

**⚠️ Important for Windows Systems without Auto-Login:**

For remote shutdowns to work on systems **without auto-login**, the daemon must run as a **Windows service**:

```cmd
# Install NSSM: Download from https://nssm.cc/
# Install daemon as service (use CLI version for services):
nssm install WakeStationDaemon "C:\path\to\shutdown_daemon-cli.exe"
nssm set WakeStationDaemon Description "WakeStation Remote Shutdown Daemon"
nssm start WakeStationDaemon
```

**Alternative for auto-login systems:** Add the GUI version to startup via Startup folder or Task Scheduler.

---

## 📱 Android App

WakeStation v3.0.0 includes a native Android application located in `android-app/`.

### Features

- **JWT Authentication**: Secure token-based login with automatic refresh
- **Biometric Authentication**: Optional biometric auth for shutdown operations
- **Secure Credential Storage**: Encrypted storage using Android Keystore
- **Material Design**: Modern UI following Material Design 3 guidelines
- **Network Security**: Supports internal CA certificates for HTTPS

### Building the Android App

1. **Open in Android Studio**:
   ```bash
   # Open the android-app directory in Android Studio
   ```

2. **Configure Server URL**:
   Edit `android-app/src/main/java/com/wakestation/android/network/VolleyApiService.kt`:
   ```kotlin
   private val BASE_URL = "https://wakestation.yourdomain.com"
   ```

3. **Build APK**:
   - Build → Build Bundle(s) / APK(s) → Build APK(s)
   - APK will be in `android-app/build/outputs/apk/`

### Installing on Android Device

1. **Install CA Certificate** (if using internal CA):
   - Settings → Security → Install from storage
   - Select your CA certificate file
   - Name it and set usage to "VPN and apps"

2. **Install APK**:
   - Transfer APK to device
   - Enable "Install from unknown sources"
   - Install the APK

3. **Configure and Login**:
   - Open WakeStation app
   - Settings → Configure server URL (if not embedded)
   - Login with your WakeStation credentials

### Network Security Configuration

The app includes network security configuration to trust user-installed CA certificates. This is required for Android 7+ devices using internal CAs.

Location: `android-app/src/main/res/xml/network_security_config.xml`

---

## 🔧 Command Line Usage

If you prefer, you can configure the `shutdown_daemon` using command-line arguments instead of a `.env` file. Use the following flags:
- `--wol-server-ip`: Set the WakeStation IP address.
- `--wol-server-port`: Set the WakeStation port.
- `--secret-key`: Set the HMAC secret key.
- `--bind-ip`: Set the IP address to bind the daemon server.
- `--bind-port`: Set the port to bind the daemon server.
- `--dry-run`: Enable dry-run mode for testing without executing shutdown commands.

### Examples:

**Using Python:**
```bash
python shutdown_daemon.py --wol-server-ip 10.0.1.13 --wol-server-port 443 --secret-key your_secret_key --bind-ip 0.0.0.0 --bind-port 8080 --dry-run
```

**Using precompiled Windows binary (command-line version):**
```bash
shutdown_daemon-cli.exe --wol-server-ip 10.0.1.13 --wol-server-port 443 --secret-key your_secret_key --bind-ip 0.0.0.0 --bind-port 8080 --dry-run
```

**Show help (Windows binary):**
```bash
shutdown_daemon-cli.exe --help
```

**Using precompiled Windows binary (GUI version):**
```bash
# For GUI mode, just run the executable (configure .env file first)
shutdown_daemon-gui.exe
```

**Note**: The system tray dry-run toggle can override the `--dry-run` flag at runtime, providing convenient testing control without restarting the daemon.

---

## 🔨 Building Binaries

Build standalone executables for the shutdown daemon using the automated build scripts.

### 🚀 Automated Build Process

The easiest way to build executables is using the included batch files:

**Windows:**
```cmd
# Build CLI version (for servers and Windows services)
cd shutdown-daemon
build_cli.bat

# Build GUI version (for desktop systems with system tray)
build_gui.bat
```

**What the build scripts do automatically:**
- ✅ **Python Detection** - Detects Python 3.12+ or offers to install it
- ✅ **Environment Setup** - Creates virtual environment if needed
- ✅ **Dependency Installation** - Installs all required packages automatically
- ✅ **Version Integration** - Embeds proper version information in executables
- ✅ **Professional Output** - Creates `bin/Release/` directory with built executables
- ✅ **Cleanup** - Removes build artifacts and opens output directory
- ✅ **Debug Support** - Use `--debug` flag for troubleshooting (e.g., `build_cli.bat --debug`)

### 📁 Output Location

Built executables will be located in:
- **`bin/Release/shutdown_daemon-cli.exe`** - CLI version for servers
- **`bin/Release/shutdown_daemon-gui.exe`** - GUI version for desktop

### 🐧 Linux Build Notes

For Linux systems, you can use PyInstaller directly since the batch files are Windows-specific:

**Install dependencies:**
```bash
# Ubuntu/Debian
sudo apt install python3-tk python3-dev

# CentOS/RHEL/Fedora
sudo dnf install python3-tkinter python3-devel

# Install PyInstaller
pip install pyinstaller
```

**Build commands:**
```bash
cd shutdown-daemon

# CLI version
pyinstaller shutdown_daemon_cli.spec

# GUI version
pyinstaller shutdown_daemon_gui.spec
```

### ⚠️ Build Troubleshooting

**Windows Build Issues:**
- Run `build_cli.bat --debug` or `build_gui.bat --debug` for detailed error information
- Check `buildlog/` folder for detailed build logs if build fails
- Ensure you have sufficient disk space (builds require ~500MB temporarily)

**Missing modules error:**
The spec files include all necessary hidden imports. If you encounter missing module errors, they will be logged in the debug output.

---

## 🌐 API Documentation

WakeStation v3.0.0 uses **JWT token authentication** instead of cookies. All API requests require an `Authorization` header with a valid JWT token.

### Interactive API Documentation

- **Swagger UI**: `https://your-server/docs`
- **ReDoc**: `https://your-server/redoc`

### Authentication

**Login and obtain JWT tokens:**
```bash
# Login to get access and refresh tokens
curl -k -X POST "https://localhost/api/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=admin123"

# Response:
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
#   "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
#   "token_type": "bearer"
# }

# Save the access_token for subsequent requests
export TOKEN="eyJ0eXAiOiJKV1QiLCJhbGc..."
```

**Refresh access token (when expired):**
```bash
# Use refresh token to get a new access token
curl -k -X POST "https://localhost/api/refresh" \
  -H "Authorization: Bearer $REFRESH_TOKEN"

# Response:
# {
#   "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
# }
```

### API Endpoints

All endpoints require `Authorization: Bearer <access_token>` header.

**Load PCs list:**
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/load"
```

**Wake a PC:**
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/wake?mac=AA:BB:CC:DD:EE:FF"
```

**Add a new PC:**
```bash
curl -k -X POST "https://localhost/api/add" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "pc_name": "TestPC",
    "ip": "192.168.1.100",
    "mac": "AA:BB:CC:DD:EE:FF",
    "hostname": "testpc"
  }'
```

**Delete a PC:**
```bash
curl -k -X DELETE "https://localhost/api/delete?mac=AA:BB:CC:DD:EE:FF" \
  -H "Authorization: Bearer $TOKEN"
```

**Shutdown a PC (encrypted):**
```bash
curl -k -X POST "https://localhost/api/shutdown_encrypted" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mac": "AA:BB:CC:DD:EE:FF",
    "username": "admin",
    "password": "password123"
  }'
```

**Get current user info:**
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/me"
```

**Get users list (admin only):**
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/users"
```

**Change user password:**
```bash
curl -k -X POST "https://localhost/api/change_password" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "current_password": "oldpass",
    "new_password": "newpass"
  }'
```

**Change user permissions (admin only):**
```bash
curl -k -X POST "https://localhost/api/change_permission" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1",
    "permission": "admin"
  }'
```

**Delete user (admin only):**
```bash
curl -k -X POST "https://localhost/api/delete_user" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "user1"
  }'
```

**Sync encryption key (admin only):**
```bash
curl -k -X POST "https://localhost/api/sync_encryption_key" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "guid": "daemon-guid-here",
    "target_port": 8080
  }'
```

**Get daemon registry (admin only):**
```bash
curl -k -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/daemon_registry"
```

**Note:** The `-k` flag bypasses SSL certificate verification (useful for self-signed certificates). Remove it when using valid certificates.

---

## 📄 License

This script is released under the GPL-3.0 license. You are free to reproduce, modify, and distribute this script as long as the original author is credited.

---

**Author**: Oration 'Mahesvara'
**GitHub**: [Oratorian@github.com](https://github.com/Oratorian)
