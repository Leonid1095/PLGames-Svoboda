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

:: 1. Kill winws2 + gost
echo  [1/6] Killing winws2 and gost processes...
taskkill /F /IM winws2.exe >nul 2>&1
if %errorLevel% equ 0 (
    echo        Killed winws2.exe
) else (
    echo        No winws2.exe running
)
taskkill /F /IM gost.exe >nul 2>&1
if %errorLevel% equ 0 (
    echo        Killed gost.exe
) else (
    echo        No gost.exe running
)

:: 2. Stop WinDivert driver
echo  [2/6] Unloading WinDivert driver...
sc stop WinDivert >nul 2>&1
sc stop WinDivert14 >nul 2>&1
sc delete WinDivert >nul 2>&1
sc delete WinDivert14 >nul 2>&1
echo        Done

:: 3. Remove system proxy (PAC file from registry)
echo  [3/6] Removing system proxy settings...
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL >nul 2>&1
if %errorLevel% equ 0 (
    reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v AutoConfigURL /f >nul 2>&1
    echo        Removed PAC proxy
) else (
    echo        No PAC proxy set
)
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f >nul 2>&1
echo        Manual proxy disabled

:: 4. Flush DNS
echo  [4/6] Flushing DNS cache...
ipconfig /flushdns >nul 2>&1
echo        Done

:: 5. Reset Winsock
echo  [5/6] Resetting network stack...
netsh winsock reset >nul 2>&1
netsh int ip reset >nul 2>&1
echo        Done

:: 6. Notify system of proxy change
echo  [6/6] Refreshing network settings...
powershell -Command "[System.Runtime.InteropServices.RuntimeEnvironment]" >nul 2>&1
rundll32 wininet.dll,InternetSetOptionW >nul 2>&1
echo        Done

echo.
echo  ============================================
echo   Internet should be fixed now.
echo   If still broken, reboot your PC.
echo  ============================================
echo.
pause
