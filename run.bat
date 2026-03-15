@echo off
cd /d "%~dp0"
chcp 65001 >nul 2>&1
title PLGames Svoboda - DPI Bypass
color 0A

echo.
echo  ====================================================
echo   PLGames Svoboda - DPI Bypass Tool
echo  ====================================================
echo.

:: ─── Admin check ───────────────────────────────────────────────
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] Administrator rights required for WinDivert driver
    echo  [!] Restarting as administrator...
    echo.
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)
echo  [OK] Running as administrator

:: ─── Kill leftover winws2 from previous run ─────────────────────
taskkill /F /IM winws2.exe >nul 2>&1
:: Unload WinDivert driver if stuck
sc stop WinDivert >nul 2>&1
sc stop WinDivert14 >nul 2>&1
timeout /t 1 /nobreak >nul

:: ─── Python check ──────────────────────────────────────────────
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERROR] Python not found!
    echo  Install Python 3.10+ from https://python.org
    echo  Make sure to check "Add Python to PATH"
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%a in ('python --version 2^>^&1') do set PY_VER=%%a
echo  [OK] Python %PY_VER%

:: ─── Dependencies ──────────────────────────────────────────────
python -c "import requests" >nul 2>&1
if %errorLevel% neq 0 (
    echo  Installing dependencies...
    python -m pip install --quiet -r requirements.txt
    echo  [OK] Dependencies installed
) else (
    echo  [OK] Dependencies OK
)

:: ─── Config ────────────────────────────────────────────────────
if not exist "config.json" (
    if exist "config.example.json" (
        copy config.example.json config.json >nul
        echo  [OK] Config created
    ) else (
        echo  [ERROR] config.example.json not found!
        pause
        exit /b 1
    )
)

:: ─── zapret2 binaries ─────────────────────────────────────────
set ZAPRET_DIR=zapret2
set ZAPRET_BIN=%ZAPRET_DIR%\binaries\windows-x86_64\winws2.exe
set ZAPRET_REPO=https://github.com/bol-van/zapret2.git

:: Check if zapret2 dir exists with git
if exist "%ZAPRET_DIR%\.git" goto :zapret_update

:: Check if binary exists (manual install or versioned dir)
if exist "%ZAPRET_BIN%" goto :zapret_ok
for /d %%d in (zapret2-*) do (
    if exist "%%d\binaries\windows-x86_64\winws2.exe" (
        set ZAPRET_BIN=%%d\binaries\windows-x86_64\winws2.exe
        goto :zapret_ok
    )
)

:: Not found — clone or download
echo.
echo  [!] zapret2 not found. Downloading...
echo.

:: Try git clone first (enables future updates)
git --version >nul 2>&1
if %errorLevel% equ 0 (
    echo  Cloning zapret2 via git (enables auto-updates)...
    git clone --depth 1 "%ZAPRET_REPO%" "%ZAPRET_DIR%" 2>&1
    if exist "%ZAPRET_BIN%" goto :zapret_ok
)

:: Fallback: download zip
echo  Downloading zapret2 as zip...
set ZAPRET_ZIP=zapret2-download.zip
curl -L -o "%ZAPRET_ZIP%" "https://github.com/bol-van/zapret2/archive/refs/heads/main.zip" --progress-bar
if %errorLevel% neq 0 (
    echo  [ERROR] Download failed!
    echo  Manual download: https://github.com/bol-van/zapret2
    echo  Extract to: %CD%\zapret2\
    pause
    exit /b 1
)

echo  Extracting...
tar -xf "%ZAPRET_ZIP%" >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Expand-Archive -Path '%ZAPRET_ZIP%' -DestinationPath '.' -Force"
)

:: Rename extracted dir to zapret2
for /d %%d in (zapret2-*) do (
    if not "%%d"=="zapret2" (
        if exist "%%d\binaries" (
            ren "%%d" "zapret2" >nul 2>&1
        )
    )
)
del "%ZAPRET_ZIP%" >nul 2>&1

:: Re-check after download
if exist "%ZAPRET_BIN%" goto :zapret_ok
for /d %%d in (zapret2-*) do (
    if exist "%%d\binaries\windows-x86_64\winws2.exe" (
        set ZAPRET_BIN=%%d\binaries\windows-x86_64\winws2.exe
        goto :zapret_ok
    )
)
echo  [ERROR] winws2.exe not found after download!
echo  Please download zapret2 manually from:
echo  https://github.com/bol-van/zapret2
pause
exit /b 1

:zapret_update
:: zapret2 installed via git — check for updates
echo  Checking zapret2 updates...
pushd "%ZAPRET_DIR%"
git fetch --depth 1 origin main >nul 2>&1
for /f %%h in ('git rev-parse HEAD') do set LOCAL_HEAD=%%h
for /f %%h in ('git rev-parse origin/main') do set REMOTE_HEAD=%%h
if not "%LOCAL_HEAD%"=="%REMOTE_HEAD%" (
    echo  [!] New zapret2 version available, updating...
    git reset --hard origin/main >nul 2>&1
    echo  [OK] zapret2 updated
) else (
    echo  [OK] zapret2 is up to date
)
popd

:zapret_ok
echo  [OK] zapret2 binary found
echo.

:: ─── Create directories ───────────────────────────────────────
if not exist "lua" mkdir lua

:: ─── Launch ───────────────────────────────────────────────────
:: Check if --tray flag was passed or if user wants tray mode
if "%1"=="--tray" goto :tray_mode
if "%1"=="--console" goto :console_mode

echo.
echo  [1] Background mode (system tray icon)
echo  [2] Console mode (see all output)
echo.
set /p LAUNCH_MODE="  Choose [1/2]: "
if "%LAUNCH_MODE%"=="1" goto :tray_mode
goto :console_mode

:tray_mode
echo.
echo  Starting in background (system tray)...
echo  Right-click the tray icon for options.
echo.
pythonw svoboda_tray.py
goto :done

:console_mode
echo.
python run_real.py

:done
:: ─── Cleanup: kill any remaining winws2 on exit ─────────────
taskkill /F /IM winws2.exe >nul 2>&1

echo.
pause
