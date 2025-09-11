# Changelog

## 🚀 [v2.9.2] - 11-September-2025
**Summary:** Critical network discovery and configuration bug fixes for multi-NIC systems and shutdown daemon reliability.

### 🐛 Fixed
- 🚀 **Fixed shutdown daemon race condition on fresh start** - Added synchronization after GUI dialog completion to ensure config files are written before server startup
- 🌐 **Fixed arp-scan multi-NIC interface issues** - Complete resolution for systems with multiple network interfaces:
  - Added reliable interface detection from IP addresses using `ip addr show` parsing
  - Fixed `--interface=<name>` parameter format (requires equals sign)
  - Corrected command argument order (network/CIDR must be last argument)
  - Implemented proper `--format` parameter with correct field names (`${IP}`, `${MAC}`, `${Vendor}`)
  - Fixed arp-scan return code handling (accepts 0-1 as success, not just 0)
  - Added robust fallback methods (`/proc/net/arp`, `arp -a`) when arp-scan fails
  - Increased subprocess timeout to handle network scans properly
- 🔧 **Fixed WOL_SERVER_PORT configuration persistence** - Resolved issue where shutdown daemon ignored GUI-configured port values:
  - Fixed CLI argument vs `.env` file precedence detection
  - Ensured GUI setup dialog values are properly used by daemon
  - Corrected port value loading after configuration completion
- 🔍 **Enhanced error handling and debugging** - Added comprehensive debug logging for arp-scan operations, better subprocess error detection, and enhanced network interface validation
- 🛡️ **Fixed systemd service capabilities** - Added proper CAP_SETFCAP capabilities and setcap commands to resolve arp-scan packet capture permissions

### 🔄 Changed
- 🌐 **Improved network interface detection** - Now uses `ip addr show` instead of unreliable `ip route get` for local IP interface resolution
- ⏱️ **Enhanced timeout handling** - Increased arp-scan subprocess timeout to minimum 15 seconds to accommodate network scanning
- 🔧 **Better configuration precedence** - CLI arguments properly detected vs defaults to allow `.env` file values when appropriate

### ⚡ Performance
- 🚀 **Optimized network scanning** - Implemented single arp-scan per network with 30-second caching instead of per-device scanning:
  - Network-wide scanning reduces multiple arp-scan calls to single scan per network
  - 30-second result caching for instant subsequent device lookups
  - Dramatically improved page load times when viewing multiple devices
  - Smart cache invalidation ensures fresh data when needed

---

## 🚀 [v2.9.1] - 07-September-2025
**Summary:** Critical bug fixes for shutdown daemon functionality and cross-platform Wake-on-LAN implementation.

### 🐛 Fixed
- 🖥️ **Fixed shutdown daemon console flashing on Windows** - Eliminated 4-second console window flash during GUI startup
- 🔄 **Fixed daemon restart functionality** - Changed from process-based to thread-based restart mechanism
- 🔐 **Fixed shutdown decryption errors** - Resolved "length not multiple of block length" by adding proper base64 decoding
- 🌐 **Fixed daemon connectivity resilience** - Added exponential backoff retry logic for WakeStation server connection
- 📡 **Fixed shutdown command transmission** - Replaced shell-based echo with direct subprocess input to prevent data corruption
- 🔧 **Fixed network interface validation** - Added proper IP ownership verification using socket binding
- 📋 **Updated data format for shutdown commands** - Changed from pipe-separated to JSON format for better reliability

### 🆕 Added
- 🚀 **Cross-platform Wake-on-LAN implementation** using Python sockets (replaces etherwake dependency)
- 🔄 **Robust daemon retry logic** - Continuous retry with exponential backoff (5 attempts + periodic 5-minute retries)
- 🖥️ **Windows compatibility tools** - Bundled arp-scan.exe, nc.exe, and OpenSSL libraries for full Windows support
- 📊 **Enhanced network interface detection** - Platform-specific methods (Windows ipconfig, Linux ip a)
- 🎯 **Smart broadcast address detection** - Automatic network-specific broadcast calculation
- ✅ **Comprehensive interface validation** - Prevents misconfiguration of network interfaces

### 🔄 Changed  
- 🌐 **Improved network utility organization** - Consolidated redundant functions and added MAC address normalization
- 📡 **Enhanced WOL API compatibility** - Maintained backward compatibility with existing web UI JSON responses
- 🔧 **Simplified Docker-friendly network detection** - Direct IP lookup to avoid parsing hundreds of veth interfaces
- 🧹 **Cleaned up build configurations** - Removed excessive cryptography imports from PyInstaller specs

### 📖 Documentation
- 📋 **Updated README with Windows requirements** - Documented included tools and their sources
- 🔧 **Added network interface configuration guide** - Clear instructions for WOL_INTERFACE setup

---

## 🚀 [v2.9.0] - 07-September-2025
**Summary:** Major codebase refactoring with modular architecture, professional logging system, and automated build improvements.

### 🆕 Added
- 🏗️ **Professional logging system** with rsyslog-style formatting and automatic rotation:
  - Named loggers for different modules (wakestation, routes, workers, network, user)
  - Multi-level logging support with separate file and console output levels
  - Configurable file size limits and backup rotation system
  - Dynamic log.debug() statements that respect LOG_LEVEL configuration

### 🔄 Changed
- 🏗️ **Major shutdown-daemon refactoring** with modular architecture:
  - `src/config.py` - Centralized configuration and argument parsing
  - `src/core/auth.py` - User authentication and validation
  - `src/core/crypto.py` - Encryption/decryption and MAC address detection
  - `src/server/daemon.py` - Core daemon server functionality
  - `src/server/handler.py` - Request handling and command processing
  - `src/gui/setup_dialog.py` - GUI configuration dialogs
  - `src/gui/tray.py` - System tray integration
  - `src/utils/logger.py` - Daemon-specific logging utilities
  - `src/utils/network.py` - Network utilities and MAC detection
  - `src/utils/process.py` - Process management and system operations
- 🧹 **Improved initialization handling** with seamless user/key creation process

### 🐛 Fixed
- ✅ **Removed redundant initialization code** from wakestation.py
- 🧹 **Removed backwards compatibility mappings** for cleaner architecture
- 📊 **Improved error handling and configuration validation** throughout the system
- 🛠️ **Better separation of concerns** with clean module interfaces

---

## 🚀 [v2.8.0] - 06-September-2025 (No Release created on GitHub)
**Summary:** Complete codebase refactoring with modular architecture, professional build automation, and enhanced developer experience.

### 🆕 Added
- 🏗️ Professional automated build system with `build_cli.bat` and `build_gui.bat`:
  - 🐍 Automatic Python 3.12 detection and installation with user prompts
  - 🔧 Intelligent virtual environment creation and dependency management
  - 🐛 Debug mode support (`--debug` flag) with comprehensive PyInstaller logging
  - 📁 VS2022-style `bin/Release/` output directory structure
  - 🔍 Smart executable detection supporting multiple naming patterns
  - 📊 Build success validation with detailed error reporting and troubleshooting
  - 🗂️ Automatic build log collection to `buildlog/` folder on failures
  - 📂 Auto-opening of output directory on successful builds
  - 📋 Complete hidden imports support for builds without spec files
- 🔗 Dynamic version info generation from git tags in GitHub Actions workflow
- 🔧 Professional logging system with rsyslog-style formatting and automatic log rotation
- 📝 Comprehensive logging configuration with file size limits and backup rotation
- 🏷️ Named loggers for different modules (wakestation, routes, workers)
- 📊 Multi-level logging support (file vs console output levels)

### 🔄 Changed
- 🏗️ **Major refactoring**: Extracted 500+ lines from `wakestation.py` into organized modules:
  - `src/utils/network.py` - Network utilities (ping, MAC validation, daemon checks)
  - `src/core/workers.py` - Background tasks (WOL, shutdown operations)
  - `src/api/routes.py` - Flask route handlers and API endpoints
  - `src/core/user.py` - User authentication and management
  - `src/utils/htpasswd.py` - Password hashing utilities
- 📦 Unified `requirements.txt` for streamlined dependency management
- 📝 Updated README.md with corrected table of contents and unified installation instructions
- 🔧 Enhanced GitHub Actions workflow with environment variable-based versioning
- 🧹 Improved cleanup process with thorough `dist/` folder removal after builds
- 🔧 **Major config.py refactoring**: Organized configuration into logical sections with clear documentation
- 📋 Standardized all configuration variables to UPPERCASE naming convention
- 🗂️ Improved path management with BASE_DIR and absolute path handling
- 🔒 Enhanced security settings with additional Flask session configuration
- 📚 Added comprehensive inline documentation and production warnings

### 🐛 Fixed
- ✅ Corrected executable detection logic to handle PyInstaller naming variations
- 🗂️ Fixed spec file handling to preserve permanent files while cleaning temporaries
- 📁 Resolved dist folder remaining after executable moves
- 🔗 Added missing `--hidden-import` flags to manual PyInstaller commands
- 📋 Fixed broken table of contents links in README.md
- 🔗 Updated all configuration references to use new uppercase variable names
- 🧹 Removed backwards compatibility variables for cleaner codebase
- 📂 Improved file path handling with proper base directory resolution

---

## 🚀 [v2.7.1] - 31-August-2025
**Summary:** Automated executable builds, mobile daemon status improvements, and enhanced documentation.

### 🆕 Added
- 🏗️ Automated GitHub Actions workflow for building Windows executables on release tags
- 📱 Mobile-friendly daemon status text indicators replacing tooltips for touch devices
- 📝 Windows service installation documentation with NSSM instructions
- 🔧 PyInstaller spec files for consistent executable builds with proper icons

### 🔄 Changed
- 🎯 Mobile interface now displays daemon availability status as visible text instead of tooltips
- 📦 Release workflow now builds two executable variants: CLI and GUI versions
- 🏷️ Executable naming convention includes version tags (e.g., shutdown_daemon-v2.7.1-x64.exe)

### 🐛 Fixed
- 📱 Mobile users can now clearly see daemon status without relying on hover tooltips

---

## 🚀 [v2.7.0] - 31-August-2025
**Summary:** Enhanced UI with device status indicators, MAC validation, persistent sessions, mobile improvements, and shutdown daemon detection.

### 🆕 Added
- 🟢 Real-time device status indicators with colored dots (green=online, red=offline, gray=unknown)
- ⏱️ Auto-refresh device status every 30 seconds while on devices page
- ✅ MAC address syntax validation (both frontend and backend) with helpful error messages
- 🔒 "Remember Me" checkbox for 30-day persistent login sessions
- 📱 Comprehensive mobile device support improvements
- 🛡️ Shutdown daemon detection with automatic button state management
- ❌ Visual disabled state for shutdown buttons with diagonal strikethrough when daemon unavailable
- 🎯 Enhanced tooltips showing daemon availability status
- 📶 Individual device status checking via `/api/status` endpoint

### 🔄 Changed
- 🔧 Moved Flask session configuration to `config.py` for consistent structure
- 📱 Improved mobile layout for user management section with better button sizing
- 📱 Repositioned toast messages to bottom of screen on mobile for better visibility
- 📱 Enhanced logout button positioning and sizing for mobile devices
- 🎨 Improved toast message contrast and readability on mobile (95% opacity background)

### 🐛 Fixed
- 📱 Fixed logout button being hidden behind page header on mobile
- 📱 Resolved toast messages being too transparent to read on mobile
- 📱 Fixed System Admin User Management layout issues on mobile devices
- 🔧 Improved MAC address input field with pattern validation and helpful placeholder

---

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