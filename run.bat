@echo off
chcp 65001 >nul 2>&1
title PLGames Svoboda Brain - Shadow Mode
color 0A

echo.
echo  ====================================================
echo   PLGames Svoboda Brain - Shadow Mode
echo  ====================================================
echo.
echo  Okno ostaetsya otkrytym. Dannye sobirayutsya nepreryvno.
echo  Dlya ostanovki: Ctrl+C
echo.

:: Check Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERROR] Python not found!
    echo  Install Python 3.10+ from https://python.org
    echo  Make sure to check "Add Python to PATH" during install
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%a in ('python --version 2^>^&1') do set PY_VER=%%a
echo  [OK] Python %PY_VER%

:: Auto-install dependencies
echo  Checking dependencies...
python -c "import requests" >nul 2>&1
if %errorLevel% neq 0 (
    echo  Installing dependencies...
    python -m pip install --quiet -r requirements.txt
    if %errorLevel% neq 0 (
        echo  [WARN] Trying individually...
        python -m pip install --quiet requests>=2.31
        python -m pip install --quiet scapy>=2.5.0
        python -m pip install --quiet schedule>=1.2
    )
    echo  [OK] Dependencies installed
) else (
    echo  [OK] Dependencies OK
)

:: Auto-create config.json from template (no manual editing needed)
if not exist "config.json" (
    if exist "config.example.json" (
        echo  [INFO] Creating config.json from template...
        copy config.example.json config.json >nul
        echo  [OK] Config created. App will auto-register with server.
    ) else (
        echo  [ERROR] config.example.json not found!
        pause
        exit /b 1
    )
)

:: Create required directories
if not exist "lua" mkdir lua

echo.

:: Run continuous shadow mode
python run_shadow.py

echo.
pause
