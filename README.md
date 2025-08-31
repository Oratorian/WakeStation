# Wake-on-LAN (WOL) Server - WakeStation

This Python-based Wake-on-LAN server allows users to wake up computers in their local network via a web interface. It also supports remote shutdowns of network devices. The server includes user authentication for added security and can be configured using environment variables.

## Features

- **Wake-on-LAN Support**: Trigger WOL requests for devices in your network using their MAC addresses.
- **Remote Shutdown Support**: Includes Python-based shutdown daemon for remote shutdown commands.
- **System Tray Integration**: Shutdown daemon runs with system tray icon, dry-run toggle, and status monitoring.
- **User Authentication**: Secure access to the server using Flask-Login and bcrypt for password management.
- **Web Interface**: Built-in web interface using Flask to send WOL and shutdown requests.
- **REST API**: Direct API access with curl or other tools using session cookies for automation and scripting.
- **Database Integration**: Stores user and device information in a local JSON-based database.
- **GUI User Setup**: Automatic GUI dialog for initial user configuration when users.json is missing.
- **.env File Support**: Easily configure important variables for the server and shutdown daemon.

## Requirements

- **Python 3.11+**
- **etherwake** (for sending WOL packets)

## Installation Instructions

### 1. Install etherwake

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install etherwake
```

**CentOS/RHEL/Rocky Linux/AlmaLinux:**
```bash
sudo yum install etherwake
# or for newer versions:
sudo dnf install etherwake
```

**Fedora:**
```bash
sudo dnf install etherwake
```

**Arch Linux:**
```bash
sudo pacman -S etherwake
```

**openSUSE:**
```bash
sudo zypper install etherwake
```

### 2. Download the script to your local machine:
## [WakeStation/releases](https://github.com/Oratorian/WakeStation/releases)


### 3. Unpack the files.

### 4. Navigate to the unpacked directory.

### 5. Set up a virtual environment (optional but recommended):
   ```
   python -m venv venv
   source venv/bin/activate   # On Windows use: venv\Scripts\activate
   ```

### 6. Install the dependencies:

   **For the WakeStation (main system):**
   ```
   pip install -r server/requirements.txt
   ```

   **For the Shutdown Daemon (target systems):**
   ```
   pip install -r shutdown-daemon/requirements.txt
   ```

   **For development/testing (all dependencies):**
   ```
   pip install -r requirements.txt
   ```

### 7. Configure the `.env` file for the `shutdown_daemon`:
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

### 8. Configure sudo permissions for etherwake (if using systemd service):

If you're using the `wakestation.service` systemd service file, you need to allow the `www-data` user to run `etherwake` without a password prompt. Add this line to your sudoers file:

```bash
# Edit sudoers file
sudo visudo

# Add this line (replace /usr/bin/etherwake with the actual path to etherwake):
www-data ALL=(ALL) NOPASSWD: /usr/bin/etherwake

# To find the path to etherwake, use:
which etherwake
```

### 9. Run the WakeStation:
   ```
   gunicorn --bind 0.0.0.0:5000 wol_server:app
   ```

### 10. Run the `shutdown_daemon` on the target system:

   **Using Python directly:**
   ```
   python shutdown_daemon.py
   ```

   **Using precompiled Windows binaries (if downloaded from releases):**
   - For GUI mode: Double-click `shutdown_daemon-v2.7.0-x64.exe` or run it directly
   - For command-line mode: Use `shutdown_daemon-v2.7.0-x64-cli.exe` from command prompt

   The daemon will run with a system tray icon (if GUI libraries are available) or in console mode. The system tray provides:
   - Dry-run mode toggle (orange icon = dry-run enabled, red icon = normal mode)
   - Last request status display (shows username and timestamp)
   - Restart daemon and quit options
   - Automatic GUI setup dialog if users.json is missing

   **⚠️ Important for Windows Systems:**
   
   For remote shutdowns to work properly on Windows systems **without auto-login configured**, the shutdown daemon must be run as a **Windows service**. This ensures the daemon remains active even when no user is logged in.

   **Running as Windows Service:**
   1. Use a service wrapper like NSSM (Non-Sucking Service Manager) or create a proper Windows service
   2. Install NSSM: Download from https://nssm.cc/
   3. Install the daemon as service:
      ```cmd
      nssm install WakeStationDaemon "C:\path\to\shutdown_daemon-v2.7.0-x64-cli.exe"
      nssm set WakeStationDaemon Description "WakeStation Remote Shutdown Daemon"
      nssm start WakeStationDaemon
      ```
   4. The service will automatically start with Windows and run in the background

   **Alternative for systems with auto-login:** If your Windows system has auto-login configured, you can run the GUI version at startup via the Startup folder or Task Scheduler instead of using a service.

### 11. Access the WakeStation in your web browser at:
   ```
   http://localhost:8889
   ```

## Using Command-line Arguments for `shutdown_daemon`

If you prefer, you can configure the `shutdown_daemon` using command-line arguments instead of a `.env` file. Use the following flags:
- `--wol-server-ip`: Set the WakeStation IP address.
- `--wol-server-port`: Set the WakeStation port.
- `--secret-key`: Set the HMAC secret key.
- `--bind-ip`: Set the IP address to bind the daemon server.
- `--bind-port`: Set the port to bind the daemon server.
- `--dry-run`: Enable dry-run mode for testing without executing shutdown commands.

Examples:
## Using Python
```bash
python shutdown_daemon.py --wol-server-ip 127.0.0.1 --wol-server-port 8889 --secret-key your_secret_key --bind-ip 0.0.0.0 --bind-port 8080 --dry-run
```
## Using precompiled Windows binary (command-line version)
```bash
WakeStation-CLI.exe --wol-server-ip 127.0.0.1 --wol-server-port 8889 --secret-key your_secret_key --bind-ip 0.0.0.0 --bind-port 8080 --dry-run
```
## Show help (Windows binary)
```bash
WakeStation-CLI.exe --help
```
## Using precompiled Windows binary (GUI version)
##### For GUI mode, just run the executable (configure .env file first)
```bash
Just run WakeStation.exe
```

**Note**: The system tray dry-run toggle can override the `--dry-run` flag at runtime, providing convenient testing control without restarting the daemon.

## API Usage with curl

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

## License

This script is released under the GPL-3.0 license. You are free to reproduce, modify, and distribute this script as long as the original author is credited.

---

**Author**: Oration 'Mahesvara'
**GitHub**: [Oratorian@github.com](https://github.com/Oratorian)