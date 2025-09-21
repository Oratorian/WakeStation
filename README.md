# 🚀 WakeStation - Wake-on-LAN Command Center

<div align="center">

![WakeStation](https://img.shields.io/badge/WakeStation-v2.9.3-00ff88?style=for-the-badge&logo=wifi&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-0099ff?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-GPL--3.0-red?style=for-the-badge&logo=gnu&logoColor=white)
![Build Status](https://img.shields.io/github/actions/workflow/status/Oratorian/WakeStation/release.yml?style=for-the-badge&logo=github&logoColor=white&label=Build)
![Release](https://img.shields.io/github/v/release/Oratorian/WakeStation?style=for-the-badge&logo=github&logoColor=white&label=Release)


**Professional network device management with remote wake & shutdown capabilities**

</div>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [⚙️ Requirements](#️-requirements)
- [🚀 Installation Guide](#-installation-guide)
  - [📦 Install arp-scan](#-1-install-arp-scan-linux-only)
  - [⬇️ Download WakeStation](#️-2-download-wakestation)
  - [🐍 Python Setup](#-3-python-setup)
  - [🔧 Install Dependencies](#-4-install-dependencies)
  - [🔧 Configuration](#-5-configuration)
- [🖥️ WakeStation Server Setup](#️-wakestation-server-setup)
- [💻 Shutdown Daemon Setup](#-shutdown-daemon-setup)
- [🔧 Command Line Usage](#-command-line-usage)
- [🔨 Building Binaries](#-building-binaries)
- [🌐 API Documentation](#-api-documentation)
- [📄 License](#-license)

---

## ✨ Features

- **Wake-on-LAN Support**: Trigger WOL requests for devices in your network using their MAC addresses.
- **Remote Shutdown Support**: Includes Python-based shutdown daemon for remote shutdown commands.
- **System Tray Integration**: Shutdown daemon runs with system tray icon, dry-run toggle, and status monitoring.
- **User Authentication**: Secure access to the server using Flask-Login and bcrypt for password management.
- **Web Interface**: Built-in web interface using Flask to send WOL and shutdown requests.
- **REST API**: Direct API access with curl or other tools using session cookies for automation and scripting.
- **Database Integration**: Stores user and device information in a local JSON-based database.
- **GUI User Setup**: Automatic GUI dialog for initial user configuration when users.json is missing.
- **.env File Support**: Easily configure important variables for the server and shutdown daemon.

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

**Configure the `.env` file for the shutdown daemon:**
   - Create a `.env` file in the same directory as the `shutdown_daemon.py` script.
   - Add the following lines to configure the daemon:
     ```plaintext
     WOL_SERVER_IP = 127.0.0.1
     WOL_SERVER_PORT = 8889
     BIND_IP = 127.0.0.1
     BIND_PORT = 8080
     SECRET_KEY=<Your secret key for HMAC authentication>
     ```
   - Replace `<Your WakeStation IP>`, `<Your WakeStation port>`, and `<Your secret key>` with your specific configuration.

---

## 🖥️ WakeStation Server Setup

If you want to run WakeStation as a systemd service, you'll need to:

**A. Update wakestation.service paths:**
The included `wakestation.service` file needs to be configured for your virtual environment:

```bash
# Edit the service file
sudo nano wakestation.service

# Update these paths in the service file:
WorkingDirectory=/path/to/your/wakestation/directory
ExecStart=/path/to/your/wakestation-venv/bin/gunicorn --workers 1 --bind 0.0.0.0:8889 wakestation:app
```

**Important:** Replace `/usr/local/bin/gunicorn` with your virtual environment's gunicorn path:
- If using venv: `/path/to/wakestation-venv/bin/gunicorn`
- To find your venv path: `which gunicorn` (while venv is activated)

**B. Install and activate the systemd service:**

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

# View service logs if needed
sudo journalctl -u wakestation -f
```

### 9. Run the WakeStation:

**Option A: Using systemd service (recommended for production):**
If you completed step 8, the service is already running! Access it at `http://your-server-ip:8889`

**Option B: Manual execution (for development/testing):**
For temporary testing or development, you can run WakeStation manually:

```bash
# Using tmux (recommended for persistent sessions)
tmux new-session -d -s wakestation
tmux send-keys -t wakestation "source venv/bin/activate" Enter
tmux send-keys -t wakestation "gunicorn --bind 0.0.0.0:8889 wakestation:app" Enter

# Using screen (alternative)
screen -dmS wakestation bash -c 'source venv/bin/activate && gunicorn --bind 0.0.0.0:8889 wakestation:app'

# Direct execution (will stop when terminal closes)
source venv/bin/activate
gunicorn --bind 0.0.0.0:8889 wakestation:app
```

**Note:** Replace `8889` with `5000` if you prefer port 5000, but remember to update firewall rules accordingly.

---

## 💻 Shutdown Daemon Setup

The shutdown daemon must be installed on each computer you want to remotely shutdown. Choose the appropriate method for your operating system:

## **Linux Systems:**

**Option A: Systemd Service (recommended for all Linux systems):**

Configure and install the shutdown daemon as a system service:

```bash
# Edit the service file paths for your installation
sudo nano shutdown-daemon/shutdown_daemon.service

# Update these paths in the service file:
WorkingDirectory=/path/to/your/wakestation/shutdown-daemon
ExecStart=/path/to/your/shutdown-daemon-venv/bin/python shutdown_daemon.py

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

## **Windows Systems:**

**Option A: GUI Mode (desktop/workstation):**
- Download precompiled binaries from releases
- Double-click `shutdown_daemon-v2.7.1-x64.exe` to run with system tray
- System tray provides:
  - Dry-run mode toggle (orange icon = dry-run, red icon = normal)
  - Last request status display
  - Restart daemon and quit options
  - Automatic GUI setup dialog if users.json is missing

**Option B: CLI Mode (servers/command line):**
```cmd
# Run from command prompt
shutdown_daemon-v2.7.1-x64-cli.exe

# Or using Python directly
python shutdown-daemon/shutdown_daemon.py
```

**⚠️ Important for Windows Systems without Auto-Login:**

For remote shutdowns to work on systems **without auto-login**, the daemon must run as a **Windows service**:

```cmd
# Install NSSM: Download from https://nssm.cc/
# Install daemon as service (use CLI version for services):
nssm install WakeStationDaemon "C:\path\to\shutdown_daemon-v2.7.1-x64-cli.exe"
nssm set WakeStationDaemon Description "WakeStation Remote Shutdown Daemon"
nssm start WakeStationDaemon
```

**Alternative for auto-login systems:** Add the GUI version to startup via Startup folder or Task Scheduler.

### 🌐 Access WakeStation
```
http://localhost:8889
```

---

## 🔧 Command Line Usage

If you prefer, you can configure the `shutdown_daemon` using command-line arguments instead of a `.env` file. Use the following flags:
- `--wol-server-ip`: Set the WakeStation IP address.
- `--wol-server-port`: Set the WakeStation port.
- `--secret-key`: Set the HMAC secret key.
- `--bind-ip`: Set the IP address to bind the daemon server.
- `--bind-port`: Set the port to bind the daemon server.
- `--dry-run`: Enable dry-run mode for testing without executing shutdown commands.

# Examples:
### Using Python
```bash
python shutdown_daemon.py --wol-server-ip 127.0.0.1 --wol-server-port 8889 --secret-key your_secret_key --bind-ip 0.0.0.0 --bind-port 8080 --dry-run
```
### Using precompiled Windows binary (command-line version)
```bash
WakeStation-CLI.exe --wol-server-ip 127.0.0.1 --wol-server-port 8889 --secret-key your_secret_key --bind-ip 0.0.0.0 --bind-port 8080 --dry-run
```
### Show help (Windows binary)
```bash
WakeStation-CLI.exe --help
```

## Using precompiled Windows binary (GUI version)
##### For GUI mode, just run the executable (configure .env file first)
```bash
Just run WakeStation.exe
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

**Note:** Build files are created in `/bin/Release/` where the `build-<>.bat` scripts reside.

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

**Build artifacts:**
Build scripts automatically clean up temporary files and organize output in a professional `bin/Release/` structure.

---

## 🌐 API Documentation

Once authenticated, you can use curl with saved cookies to interact with the API endpoints:

### Authentication
```bash
# Login and save cookies to file
curl -c cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' \
  http://localhost:8889/login
```

### API Endpoints

**Load PCs list:**
```bash
curl -b cookies.txt "http://localhost:8889/api/load"
```

**Wake a PC:**
```bash
curl -b cookies.txt "http://localhost:8889/api/wake?pc_name=MyPC"
```

**Add a new PC:**
```bash
curl -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"pc_name":"TestPC","ip":"192.168.1.100","mac":"AA:BB:CC:DD:EE:FF","hostname":"testpc"}' \
  http://localhost:8889/api/add
```

**Delete a PC:**
```bash
curl -b cookies.txt "http://localhost:8889/api/delete?pc_name=TestPC"
```

**Shutdown a PC:**
```bash
curl -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"pc_name":"TestPC"}' \
  http://localhost:8889/api/shutdown
```

**Get users list (admin only):**
```bash
curl -b cookies.txt "http://localhost:8889/api/users"
```

**Change user password:**
```bash
curl -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"current_password":"oldpass","new_password":"newpass"}' \
  http://localhost:8889/api/change_password
```

**Change user permissions (admin only):**
```bash
curl -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"username":"user1","permission":"admin"}' \
  http://localhost:8889/api/change_permission
```

**Delete user (admin only):**
```bash
curl -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"username":"user1"}' \
  http://localhost:8889/api/delete_user
```

**Sync encryption key (admin only):**
```bash
curl -b cookies.txt -X POST -H "Content-Type: application/json" \
  -d '{"target_ip":"192.168.1.100","target_port":"8080"}' \
  http://localhost:8889/api/sync_encryption_key
```

The `-c cookies.txt` flag saves cookies during login, and `-b cookies.txt` uses those saved cookies for subsequent API requests.

---

## 📄 License

This script is released under the GPL-3.0 license. You are free to reproduce, modify, and distribute this script as long as the original author is credited.

---

**Author**: Oration 'Mahesvara'
**GitHub**: [Oratorian@github.com](https://github.com/Oratorian)