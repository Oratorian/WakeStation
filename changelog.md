# Changelog

## 🚀 [v2.6.0] - 23-August-2025
**Summary:** Enhanced shutdown daemon with system tray functionality, dry-run toggle, and GUI user initialization.

### 🆕 Added
- 🖥️ System tray integration for shutdown daemon with visual status indicators
- 🔄 Dry-run toggle functionality accessible via system tray menu
- 📊 Real-time request status display showing last connection attempt and user
- 🛠️ GUI dialog for user initialization when users.json is missing in AppData
- 🎨 Visual status indicators: orange icon for dry-run mode, red for normal operation
- 🔄 Restart daemon option via system tray context menu
- ✅ Success/failure indicators for shutdown requests in tray menu
- 🔒 PID file-based instance management to prevent multiple daemon instances
- 🛡️ Automatic stale PID file cleanup for crash recovery
- 🎯 Enhanced signal handling for graceful shutdown (SIGINT, SIGTERM, SIGBREAK)

### 🔄 Changed
- 🔧 Improved daemon shutdown handling with proper tray icon cleanup
- 📁 Enhanced cross-platform AppData directory handling for configuration files
- 🚀 Transitioned daemon to background operation with threaded server architecture
- 📝 Updated requirements.txt to include pystray, pillow, and GUI dependencies

### 🐛 Fixed
- 🛠️ Resolved deprecated datetime.utcnow() usage with timezone-aware datetime.now(timezone.utc)
- 📝 Added comprehensive type annotations to resolve Pylance warnings
- ⚙️ Fixed config import issues in wol_server.py (interface and PC_DATA_DIR variables)

---

## 🚀 [v2.5.0] - 23-November-2024
**Summary:** Transitioned to Python-based server daemon with improved configuration and encryption handling.

### 🆕 Added
- 🚀 Introduced support for Python-based server daemon (`shutdown_daemon.py`), replacing the PowerShell implementation.
- 🚀 Introduced a `.env` file for configuring `BIND_IP`, `BIND_PORT`, `WOL_SERVER_IP`, `WOL_SERVER_PORT`, and `SECRET_KEY` in `shutdown_daemon.py`.
- 🛠️ Added `argparse` integration for configuring `WOL_SERVER_IP`, `WOL_SERVER_PORT`, and `SECRET_KEY` via command-line arguments.
- 🔑 Implemented `.env` file support for setting `WOL_SERVER_IP`, `WOL_SERVER_PORT`, and `SECRET_KEY`.

### 🔄 Changed
- 🔄 Transitioned from a PowerShell script to a Python-based server using `socket` for communication.
- 📝 Enhanced logging system to write logs to a file (`daemon.log`) instead of relying solely on console logging.
- 🔧 Updated decryption logic to handle Python-specific AES decryption using the `cryptography` library.

### 🐛 Fixed
- 🛠️ Resolved an issue where user input validation did not prompt for missing variables (e.g., `WOL_SERVER_IP`, `SECRET_KEY`).
- 🔧 Fixed handling of padding removal in decrypted data for compatibility with Python's `cryptography` library.
- 🛑 Addressed improper server shutdown handling with improved signal management for graceful termination.
- 🖥️ Fixed an error where `wol.js` failed to create the user's specific PC database.

---

## 🌟 [v2.4.0] - 01-November-2024
**Summary:** Introduced centralized configuration and resolved form-related issues.

### 🆕 Added
- *No new features.*

### 🔄 Changed
- 🔄 Switched to a centralized configuration via `config.py`.

### 🐛 Fixed
- 🛠️ Addressed an issue where the shutdown command would trigger multiple times.
- 🛠️ Fixed a bug where the "Manage Users" section displayed the "Add-PC Form" unnecessarily.

---

## 📜 [1.0.0 - 2.3.9] 
**Summary:** No changelogs were created for these versions.