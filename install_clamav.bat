@echo off
REM ============================================
REM  ClamAV Installation Script for Windows
REM ============================================
REM  This script downloads and installs ClamAV.
REM  Run as Administrator!
REM ============================================

echo ========================================
echo   ClamAV Installer for MFDS
echo ========================================
echo.

REM Check for admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] This script requires Administrator privileges!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

set CLAMAV_VERSION=1.5.4
set DOWNLOAD_URL=https://www.clamav.net/downloads/attached/clamav-%CLAMAV_VERSION%.win.x64.msi
set INSTALLER_PATH=%TEMP%\clamav-%CLAMAV_VERSION%-win-x64.msi
set INSTALL_DIR=C:\Program Files\ClamAV

echo [1/5] Downloading ClamAV %CLAMAV_VERSION%...
echo URL: %DOWNLOAD_URL%
echo.

REM Try curl first (available on Windows 10+)
where curl >nul 2>&1
if %errorLevel% equ 0 (
    curl -L -o "%INSTALLER_PATH%" "%DOWNLOAD_URL%"
) else (
    REM Fall back to PowerShell
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri '%DOWNLOAD_URL%' -OutFile '%INSTALLER_PATH%'"
)

if not exist "%INSTALLER_PATH%" (
    echo [ERROR] Download failed!
    echo.
    echo Please download ClamAV manually from:
    echo https://www.clamav.net/downloads
    echo.
    echo Choose: clamav-%CLAMAV_VERSION%.win.x64.msi
    echo.
    pause
    exit /b 1
)

echo [2/5] Installing ClamAV...
echo Installing to: %INSTALL_DIR%
echo.

msiexec /i "%INSTALLER_PATH%" /qn INSTALLDIR="%INSTALL_DIR%" /l*v "%TEMP%\clamav_install.log"

if %errorLevel% neq 0 (
    echo [WARNING] Silent install may have failed. Trying interactive install...
    msiexec /i "%INSTALLER_PATH%" INSTALLDIR="%INSTALL_DIR%"
)

echo [3/5] Updating virus database...
echo This may take a few minutes on first run...
echo.

if exist "%INSTALL_DIR%\freshclam.exe" (
    "%INSTALL_DIR%\freshclam.exe"
) else if exist "C:\Program Files (x86)\ClamAV\freshclam.exe" (
    "C:\Program Files (x86)\ClamAV\freshclam.exe"
) else (
    echo [WARNING] freshclam.exe not found at expected location.
    echo Please run freshclam manually after installation.
)

echo [4/5] Installing ClamAV daemon as Windows service...
echo.

if exist "%INSTALL_DIR%\clamd.exe" (
    "%INSTALL_DIR%\clamd.exe" --install-service
    net start clamd
) else if exist "C:\Program Files (x86)\ClamAV\clamd.exe" (
    "C:\Program Files (x86)\ClamAV\clamd.exe" --install-service
    net start clamd
) else (
    echo [WARNING] clamd.exe not found. Please install the service manually.
)

echo [5/5] Verifying installation...
echo.

REM Check if clamscan exists
where clamscan >nul 2>&1
if %errorLevel% equ 0 (
    echo [OK] clamscan found in PATH
    clamscan --version
) else (
    if exist "%INSTALL_DIR%\clamscan.exe" (
        echo [OK] clamscan found at %INSTALL_DIR%\clamscan.exe
        "%INSTALL_DIR%\clamscan.exe" --version
    ) else (
        echo [WARNING] clamscan not found. Check installation.
    )
)

echo.
echo ========================================
echo   ClamAV Installation Complete
echo ========================================
echo.
echo Next steps:
echo 1. Verify clamd service is running: net start clamd
echo 2. Update virus DB: freshclam.exe
echo 3. The Python backend will auto-detect ClamAV
echo.
echo If clamd is not in PATH, set these in backend\.env:
echo   CLAMAV_HOST=127.0.0.1
echo   CLAMAV_PORT=3310
echo.

REM Cleanup
if exist "%INSTALLER_PATH%" del "%INSTALLER_PATH%"

pause
