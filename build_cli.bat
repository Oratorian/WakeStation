@echo off
setlocal EnableDelayedExpansion

REM     """!
REM     ********************************************************************************
REM     @file  build_cli.bat
REM     @brief  Build script for WakeStation Shutdown Daemon CLI executable
REM     @author Mahesvara ( https://github.com/Oratorian )
REM     @copyright Mahesvara ( https://github.com/Oratorian )
REM     ********************************************************************************
REM     """

REM Check for debug parameter
set DEBUG_MODE=false
if /i "%1"=="--debug" set DEBUG_MODE=true
if /i "%1"=="-d" set DEBUG_MODE=true

echo ============================================
echo WakeStation Shutdown Daemon CLI Builder
echo ============================================
if "%DEBUG_MODE%"=="true" (
    echo [DEBUG] Debug mode enabled
)
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH
    echo.
    set /p install_python="Would you like to install Python 3.12? (y/n): "
    if /i "!install_python!"=="y" (
        echo [INFO] Downloading and installing Python 3.12...
        echo Please wait while Python is being downloaded...

        REM Download Python 3.12 installer
        powershell -Command "Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.0/python-3.12.0-amd64.exe' -OutFile 'python-installer.exe'"

        if exist python-installer.exe (
            echo [INFO] Installing Python 3.12...
            python-installer.exe /quiet InstallAllUsers=1 PrependPath=1 Include_test=0

            REM Clean up installer
            del python-installer.exe

            echo [INFO] Python installation completed. Please restart this script.
            pause
            exit /b 1
        ) else (
            echo [ERROR] Failed to download Python installer
            pause
            exit /b 1
        )
    ) else (
        echo [INFO] Python installation cancelled. Please install Python 3.11+ manually.
        pause
        exit /b 1
    )
)

REM Get Python version
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [INFO] Found Python %PYTHON_VERSION%

REM Check if we're in the shutdown-daemon directory, if not navigate to it
if not exist "shutdown_daemon.py" (
    if exist "shutdown-daemon\shutdown_daemon.py" (
        cd shutdown-daemon
        echo [INFO] Navigated to shutdown-daemon directory
    ) else (
        echo [ERROR] shutdown_daemon.py not found. Please run this script from the project root or shutdown-daemon directory.
        pause
        exit /b 1
    )
)

REM Check if virtual environment exists
if not exist ".venv" (
    echo [INFO] Creating virtual environment...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Failed to create virtual environment
        pause
        exit /b 1
    )
    echo [INFO] Virtual environment created successfully
) else (
    echo [INFO] Virtual environment already exists
)

REM Activate virtual environment
echo [INFO] Activating virtual environment...
call .venv\Scripts\activate.bat
if errorlevel 1 (
    echo [ERROR] Failed to activate virtual environment
    pause
    exit /b 1
)

REM Check if requirements are already installed
pip show pyinstaller >nul 2>&1
if errorlevel 1 (
    echo [INFO] Installing requirements...

    REM Try to find requirements.txt
    if exist "..\requirements.txt" (
        pip install -r ..\requirements.txt
    ) else if exist "requirements.txt" (
        pip install -r requirements.txt
    ) else (
        echo [WARNING] requirements.txt not found, installing essential packages...
        pip install pyinstaller bcrypt cryptography requests python-dotenv pystray pillow
    )

    if errorlevel 1 (
        echo [ERROR] Failed to install requirements
        pause
        exit /b 1
    )
    echo [INFO] Requirements installed successfully
) else (
    echo [INFO] Requirements already satisfied
)

REM Generate version info files
echo [INFO] Generating version info files...
if exist "..\src\helper\gen_version.py" (
    python ..\src\helper\gen_version.py . --type cli
    if errorlevel 1 (
        echo [WARNING] Failed to generate version info, continuing without version info
    ) else (
        echo [INFO] Version info generated successfully
    )
) else (
    echo [WARNING] Version generator not found at ..\src\helper\gen_version.py, building without version info
)

REM Set CLI_MODE flag for compilation
echo [INFO] Setting CLI mode flag for compilation...
if not exist "shutdown_daemon_original.py" (
    copy "shutdown_daemon.py" "shutdown_daemon_original.py" >nul
    echo [INFO] Backed up original shutdown_daemon.py
)
REM Prepare debug flags and hidden imports for PyInstaller
set PYINSTALLER_FLAGS=
set HIDDEN_IMPORTS=--hidden-import=bcrypt --hidden-import=cryptography --hidden-import=cryptography.hazmat.bindings._rust --hidden-import=cryptography.hazmat.bindings.openssl --hidden-import=cryptography.hazmat.bindings.openssl.binding --hidden-import=cryptography.hazmat.primitives --hidden-import=cryptography.hazmat.primitives.ciphers --hidden-import=cryptography.hazmat.primitives.ciphers.algorithms --hidden-import=cryptography.hazmat.primitives.ciphers.modes --hidden-import=cryptography.hazmat.primitives.ciphers.base --hidden-import=cryptography.hazmat.primitives.padding --hidden-import=cryptography.hazmat.backends --hidden-import=cryptography.hazmat.backends.openssl --hidden-import=cryptography.hazmat.backends.openssl.backend --hidden-import=requests --hidden-import=dotenv --hidden-import=pystray --hidden-import=PIL --hidden-import=tkinter

if "%DEBUG_MODE%"=="true" (
    set PYINSTALLER_FLAGS=--debug all --log-level DEBUG
    echo [DEBUG] PyInstaller will run with debug logging enabled
)

REM Check if spec file exists
if exist "shutdown_daemon_cli.spec" (
    echo [INFO] Building CLI executable using spec file...
    if exist "version_info_cli.txt" (
        echo [INFO] Using generated version info file
    )
    if "%DEBUG_MODE%"=="true" (
        pyinstaller %PYINSTALLER_FLAGS% shutdown_daemon_cli.spec
    ) else (
        pyinstaller shutdown_daemon_cli.spec
    )
) else (
    echo [INFO] Spec file not found, using manual build command with hidden imports...
    if exist "version_info_cli.txt" (
        pyinstaller %PYINSTALLER_FLAGS% %HIDDEN_IMPORTS% --onefile --console --name shutdown_daemon-cli --icon=shutdown_daemon_icon.ico --version-file=version_info_cli.txt shutdown_daemon.py
    ) else (
        pyinstaller %PYINSTALLER_FLAGS% %HIDDEN_IMPORTS% --onefile --console --name shutdown_daemon-cli --icon=shutdown_daemon_icon.ico shutdown_daemon.py
    )
)

REM Check if build was actually successful by looking for output file
echo [INFO] Validating build success...
echo [DEBUG] Checking for executable files...
if exist "dist" (
    echo [DEBUG] Contents of dist folder:
    dir "dist" /b
) else (
    echo [DEBUG] No dist folder found
)

REM Check for various possible executable names
set EXE_FOUND=false
if exist "dist\shutdown_daemon-cli.exe" (
    set EXE_FOUND=true
    set EXE_NAME=shutdown_daemon-cli.exe
    echo [INFO] Build successful - executable found: shutdown_daemon-cli.exe
) else if exist "dist\shutdown_daemon.exe" (
    set EXE_FOUND=true
    set EXE_NAME=shutdown_daemon.exe
    echo [INFO] Build successful - executable found: shutdown_daemon.exe
) else if exist "dist\shutdown-daemon.exe" (
    set EXE_FOUND=true
    set EXE_NAME=shutdown-daemon.exe
    echo [INFO] Build successful - executable found: shutdown-daemon.exe
)

if "%EXE_FOUND%"=="false" (
    echo.
    echo ============================================
    echo [ERROR] BUILD FAILED!
    echo ============================================
    echo.
    echo [ERROR] PyInstaller completed but no executable was generated.
    echo [INFO] This usually indicates:
    echo   - Missing dependencies or hidden imports
    echo   - Python version compatibility issues
    echo   - Corrupted virtual environment
    echo   - Icon file not found
    echo.
    echo [INFO] Check the PyInstaller output above for specific error messages.
    echo [INFO] To get detailed debug logs, run: build_cli.bat --debug
    echo.
    echo [INFO] Collecting build logs and cleaning up...

    REM Create buildlog directory in project root
    if not exist "..\buildlog" mkdir "..\buildlog"

    REM Collect any available log files
    if exist "build" (
        echo [INFO] Moving build logs to ..\buildlog\cli-failed-build\
        if not exist "..\buildlog\cli-failed-build" mkdir "..\buildlog\cli-failed-build"
        xcopy "build\*" "..\buildlog\cli-failed-build\" /E /I /Q >nul 2>&1
        rmdir /s /q "build"
        echo [INFO] Build logs saved and build folder removed
    )

    REM Copy the spec file used for build (if any) - don't delete the original
    if exist "shutdown_daemon_cli.spec" (
        copy "shutdown_daemon_cli.spec" "..\buildlog\cli-failed-build\" >nul 2>&1
        echo [INFO] Copied shutdown_daemon_cli.spec to build log
    )

    if exist "dist" (
        rmdir /s /q "dist"
        echo [INFO] Removed dist folder
    )
    if exist "version_info_cli.txt" (
        copy "version_info_cli.txt" "..\buildlog\cli-failed-build\" >nul 2>&1
        del "version_info_cli.txt"
        echo [INFO] Removed version info file
    )

    echo [INFO] Debug information saved to: buildlog\cli-failed-build\

    REM Restore original source file in error case
    if exist "shutdown_daemon_original.py" (
        move "shutdown_daemon_original.py" "shutdown_daemon.py" >nul
        echo [INFO] Restored original shutdown_daemon.py
    )

    echo.
    pause
    exit /b 1
)

echo [INFO] Organizing build output...

REM Create VS2022-style directory structure in project root
if not exist "..\bin" mkdir "..\bin"
if not exist "..\bin\Release" mkdir "..\bin\Release"

REM Move executable to project root bin\Release folder
if exist "dist\shutdown_daemon-cli.exe" (
    move "dist\shutdown_daemon-cli.exe" "..\bin\Release\shutdown_daemon-cli.exe" >nul
    if errorlevel 1 (
        echo [WARNING] Failed to move executable to project bin\Release, keeping in dist folder
    ) else (
        echo [INFO] Executable moved to project bin\Release\
    )
)

REM Clean up build artifacts
echo [INFO] Cleaning up build artifacts...
if exist "build" (
    rmdir /s /q "build"
    echo [INFO] Removed build folder
)
if exist "dist" (
    rmdir /s /q "dist"
    echo [INFO] Removed dist folder
)
REM Only remove auto-generated spec files, keep permanent ones
if exist "shutdown_daemon.spec" (
    del "shutdown_daemon.spec"
    echo [INFO] Removed auto-generated spec file: shutdown_daemon.spec
)
REM Clean up generated version files
if exist "version_info_cli.txt" (
    del "version_info_cli.txt"
    echo [INFO] Removed temporary version info file
)
REM Restore original source file
if exist "shutdown_daemon_original.py" (
    move "shutdown_daemon_original.py" "shutdown_daemon.py" >nul
    echo [INFO] Restored original shutdown_daemon.py
)

REM Final validation - check if executable is in final location
if exist "..\bin\Release\shutdown_daemon-cli.exe" (
    echo.
    echo ============================================
    echo [SUCCESS] CLI BUILD COMPLETED!
    echo ============================================
    echo.
    echo Executable location: bin\Release\shutdown_daemon-cli.exe
    echo [INFO] File size:
    for %%A in ("..\bin\Release\shutdown_daemon-cli.exe") do echo         %%~zA bytes
    echo.
    echo [INFO] Build artifacts cleaned up
    echo [INFO] Ready for distribution
    echo.
    REM Open target directory
    echo [INFO] Opening output directory...
    start "" "..\bin\Release"
) else if exist "dist\shutdown_daemon-cli.exe" (
    echo.
    echo ============================================
    echo [WARNING] PARTIAL SUCCESS
    echo ============================================
    echo.
    echo [WARNING] Executable built but failed to move to bin\Release
    echo Executable location: shutdown-daemon\dist\shutdown_daemon-cli.exe
    echo [INFO] File size:
    for %%A in ("dist\shutdown_daemon-cli.exe") do echo         %%~zA bytes
    echo.
    echo [INFO] You can manually move the file to bin\Release if needed
) else (
    echo.
    echo ============================================
    echo [ERROR] CRITICAL ERROR!
    echo ============================================
    echo.
    echo [ERROR] Executable was built but then disappeared!
    echo [INFO] Check if antivirus software is blocking the file
    echo [INFO] Check disk space and permissions
)
echo.
pause