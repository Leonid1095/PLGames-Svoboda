@echo off
:: PLGames Svoboda — Windows installer
echo === PLGames Svoboda Installer ===

:: Check admin rights
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Run as Administrator
    pause
    exit /b 1
)

:: Check Python
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Python 3.10+ required. Install from python.org
    pause
    exit /b 1
)

:: Check Python version
for /f "tokens=2 delims= " %%a in ('python --version 2^>^&1') do set PY_VER=%%a
echo [OK] Python %PY_VER%

:: Install Python dependencies
echo Installing Python dependencies...
python -m pip install --quiet ^
    scapy>=2.5.0 ^
    requests>=2.31 ^
    python-telegram-bot>=21.0 ^
    schedule>=1.2 ^
    psutil>=5.9

if %errorLevel% neq 0 (
    echo Warning: Some dependencies failed to install
) else (
    echo [OK] Python dependencies installed
)

:: Download zapret2 (winws2)
if not exist "bin\winws2.exe" (
    echo.
    echo ============================================
    echo  zapret2 (winws2.exe) not found!
    echo  Download manually from:
    echo  https://github.com/bol-van/zapret2/releases
    echo  Place winws2.exe in the 'bin' folder
    echo ============================================
    mkdir bin 2>nul
) else (
    echo [OK] winws2.exe found in bin\
)

:: Download WinDivert if needed
if not exist "bin\WinDivert.dll" (
    echo.
    echo ============================================
    echo  WinDivert.dll not found!
    echo  Download from: https://reqrypt.org/windivert.html
    echo  Place WinDivert.dll and WinDivert64.sys in 'bin'
    echo ============================================
) else (
    echo [OK] WinDivert found in bin\
)

echo.
echo === Installation complete ===
echo.
echo To run:
echo   python -m brain.svoboda_brain
echo.
echo To run as background service:
echo   Start-Process python -ArgumentList "-m brain.svoboda_brain" -WindowStyle Hidden
echo.
echo Config: config.json
echo Logs: svoboda.log
echo.
pause
