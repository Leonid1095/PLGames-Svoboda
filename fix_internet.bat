@echo off
cd /d "%~dp0"
title PLGames Svoboda - Fix Internet
color 0C

echo.
echo  ============================================
echo   Fixing internet after winws2 crash
echo  ============================================
echo.

:: Need admin
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] Need admin rights, restarting...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)

:: 1. Kill winws2
echo  [1/4] Killing winws2 processes...
taskkill /F /IM winws2.exe >nul 2>&1
if %errorLevel% equ 0 (
    echo        Found and killed winws2.exe
) else (
    echo        No winws2.exe running
)

:: 2. Stop WinDivert driver
echo  [2/4] Unloading WinDivert driver...
sc stop WinDivert >nul 2>&1
sc stop WinDivert14 >nul 2>&1
sc delete WinDivert >nul 2>&1
sc delete WinDivert14 >nul 2>&1
echo        Done

:: 3. Flush DNS
echo  [3/4] Flushing DNS cache...
ipconfig /flushdns >nul 2>&1
echo        Done

:: 4. Reset Winsock
echo  [4/4] Resetting network stack...
netsh winsock reset >nul 2>&1
netsh int ip reset >nul 2>&1
echo        Done

echo.
echo  ============================================
echo   Internet should be fixed now.
echo   If not, reboot your PC.
echo  ============================================
echo.
pause
