@echo off
cd /d "%~dp0"
chcp 65001 >nul 2>&1
title PLGames Svoboda - DPI Bypass
color 0A

:: ─── Detect system language ──────────────────────────────────
set LANG_RU=0
for /f "tokens=3" %%a in ('reg query "HKCU\Control Panel\International" /v LocaleName 2^>nul') do (
    echo %%a | findstr /i "ru-" >nul && set LANG_RU=1
)

if %LANG_RU%==1 (
    set MSG_TITLE=PLGames Svoboda - Обход блокировок
    set MSG_ADMIN=Требуются права администратора для WinDivert
    set MSG_RESTARTING=Перезапуск с правами администратора...
    set MSG_PYTHON_ERR=Python не найден! Установите Python 3.10+ с python.org
    set MSG_DEPS=Установка зависимостей...
    set MSG_DEPS_OK=Зависимости установлены
    set MSG_CONFIG_OK=Конфигурация создана
    set MSG_CONFIG_ERR=config.example.json не найден!
    set MSG_ZAPRET_DL=zapret2 не найден. Скачивание...
    set MSG_ZAPRET_UPD=Проверка обновлений zapret2...
    set MSG_ZAPRET_NEW=Доступна новая версия zapret2, обновление...
    set MSG_ZAPRET_OK=zapret2 актуален
    set MSG_SELF_UPD=Проверка обновлений Svoboda...
    set MSG_SELF_NEW=Доступно обновление Svoboda, скачивание...
    set MSG_SELF_OK=Svoboda актуальна
    set MSG_MODE1=Фоновый режим ^(иконка в трее^)
    set MSG_MODE2=Консольный режим ^(полный вывод^)
    set MSG_CHOOSE=Выберите [1/2]:
    set MSG_TRAY=Запуск в фоновом режиме...
    set MSG_TRAY2=Нажмите правой кнопкой на иконку в трее.
) else (
    set MSG_TITLE=PLGames Svoboda - DPI Bypass Tool
    set MSG_ADMIN=Administrator rights required for WinDivert driver
    set MSG_RESTARTING=Restarting as administrator...
    set MSG_PYTHON_ERR=Python not found! Install Python 3.10+ from python.org
    set MSG_DEPS=Installing dependencies...
    set MSG_DEPS_OK=Dependencies installed
    set MSG_CONFIG_OK=Config created
    set MSG_CONFIG_ERR=config.example.json not found!
    set MSG_ZAPRET_DL=zapret2 not found. Downloading...
    set MSG_ZAPRET_UPD=Checking zapret2 updates...
    set MSG_ZAPRET_NEW=New zapret2 version available, updating...
    set MSG_ZAPRET_OK=zapret2 is up to date
    set MSG_SELF_UPD=Checking Svoboda updates...
    set MSG_SELF_NEW=Svoboda update available, downloading...
    set MSG_SELF_OK=Svoboda is up to date
    set MSG_MODE1=Background mode ^(system tray icon^)
    set MSG_MODE2=Console mode ^(see all output^)
    set MSG_CHOOSE=Choose [1/2]:
    set MSG_TRAY=Starting in background...
    set MSG_TRAY2=Right-click the tray icon for options.
)

title %MSG_TITLE%

echo.
echo  ====================================================
echo   %MSG_TITLE%
echo  ====================================================
echo.

:: ─── Admin check ───────────────────────────────────────────────
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] %MSG_ADMIN%
    echo  [!] %MSG_RESTARTING%
    echo.
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b 0
)
echo  [OK] Administrator

:: ─── Kill leftover winws2 from previous run ─────────────────────
taskkill /F /IM winws2.exe >nul 2>&1
sc stop WinDivert >nul 2>&1
sc stop WinDivert14 >nul 2>&1
timeout /t 1 /nobreak >nul

:: ─── Python check ──────────────────────────────────────────────
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo  [ERROR] %MSG_PYTHON_ERR%
    echo  https://python.org
    pause
    exit /b 1
)
for /f "tokens=2 delims= " %%a in ('python --version 2^>^&1') do set PY_VER=%%a
echo  [OK] Python %PY_VER%

:: ─── Dependencies ──────────────────────────────────────────────
python -c "import requests" >nul 2>&1
if %errorLevel% neq 0 (
    echo  %MSG_DEPS%
    python -m pip install --quiet -r requirements.txt
    echo  [OK] %MSG_DEPS_OK%
) else (
    echo  [OK] Dependencies OK
)

:: ─── Config ────────────────────────────────────────────────────
if not exist "config.json" (
    if exist "config.example.json" (
        copy config.example.json config.json >nul
        echo  [OK] %MSG_CONFIG_OK%
    ) else (
        echo  [ERROR] %MSG_CONFIG_ERR%
        pause
        exit /b 1
    )
)

:: ─── Self-update (PLGames Svoboda) ──────────────────────────────
if exist ".git" (
    git --version >nul 2>&1
    if %errorLevel% equ 0 (
        echo  %MSG_SELF_UPD%
        git fetch --depth 1 origin main >nul 2>&1
        for /f %%h in ('git rev-parse HEAD 2^>nul') do set SV_LOCAL=%%h
        for /f %%h in ('git rev-parse origin/main 2^>nul') do set SV_REMOTE=%%h
        if not "%SV_LOCAL%"=="%SV_REMOTE%" (
            echo  [!] %MSG_SELF_NEW%
            git pull --ff-only origin main >nul 2>&1
            echo  [OK] Svoboda updated
        ) else (
            echo  [OK] %MSG_SELF_OK%
        )
    )
)

:: ─── zapret2 binaries ─────────────────────────────────────────
set ZAPRET_DIR=zapret2
set ZAPRET_BIN=%ZAPRET_DIR%\binaries\windows-x86_64\winws2.exe
set ZAPRET_REPO=https://github.com/bol-van/zapret2.git

:: Check if zapret2 dir exists with git
if exist "%ZAPRET_DIR%\.git" goto :zapret_update

:: Check if binary exists
if exist "%ZAPRET_BIN%" goto :zapret_ok
for /d %%d in (zapret2-*) do (
    if exist "%%d\binaries\windows-x86_64\winws2.exe" (
        set ZAPRET_BIN=%%d\binaries\windows-x86_64\winws2.exe
        goto :zapret_ok
    )
)

:: Not found — clone or download
echo.
echo  [!] %MSG_ZAPRET_DL%
echo.

git --version >nul 2>&1
if %errorLevel% equ 0 (
    git clone --depth 1 "%ZAPRET_REPO%" "%ZAPRET_DIR%" 2>&1
    if exist "%ZAPRET_BIN%" goto :zapret_ok
)

:: Fallback: download zip
set ZAPRET_ZIP=zapret2-download.zip
curl -L -o "%ZAPRET_ZIP%" "https://github.com/bol-van/zapret2/archive/refs/heads/main.zip" --progress-bar
if %errorLevel% neq 0 (
    echo  [ERROR] Download failed!
    echo  https://github.com/bol-van/zapret2
    pause
    exit /b 1
)

tar -xf "%ZAPRET_ZIP%" >nul 2>&1
if %errorLevel% neq 0 (
    powershell -Command "Expand-Archive -Path '%ZAPRET_ZIP%' -DestinationPath '.' -Force"
)

for /d %%d in (zapret2-*) do (
    if not "%%d"=="zapret2" (
        if exist "%%d\binaries" ren "%%d" "zapret2" >nul 2>&1
    )
)
del "%ZAPRET_ZIP%" >nul 2>&1

if exist "%ZAPRET_BIN%" goto :zapret_ok
for /d %%d in (zapret2-*) do (
    if exist "%%d\binaries\windows-x86_64\winws2.exe" (
        set ZAPRET_BIN=%%d\binaries\windows-x86_64\winws2.exe
        goto :zapret_ok
    )
)
echo  [ERROR] winws2.exe not found!
echo  https://github.com/bol-van/zapret2
pause
exit /b 1

:zapret_update
echo  %MSG_ZAPRET_UPD%
pushd "%ZAPRET_DIR%"
git fetch --depth 1 origin main >nul 2>&1
for /f %%h in ('git rev-parse HEAD') do set LOCAL_HEAD=%%h
for /f %%h in ('git rev-parse origin/main') do set REMOTE_HEAD=%%h
if not "%LOCAL_HEAD%"=="%REMOTE_HEAD%" (
    echo  [!] %MSG_ZAPRET_NEW%
    git reset --hard origin/main >nul 2>&1
    echo  [OK] zapret2 updated
) else (
    echo  [OK] %MSG_ZAPRET_OK%
)
popd

:zapret_ok
echo  [OK] zapret2 binary found
echo.

:: ─── Create directories ───────────────────────────────────────
if not exist "lua" mkdir lua

:: ─── Launch ───────────────────────────────────────────────────
if "%1"=="--tray" goto :tray_mode
if "%1"=="--console" goto :console_mode

echo.
echo  [1] %MSG_MODE1%
echo  [2] %MSG_MODE2%
echo.
set /p LAUNCH_MODE="  %MSG_CHOOSE% "
if "%LAUNCH_MODE%"=="1" goto :tray_mode
goto :console_mode

:tray_mode
echo.
echo  %MSG_TRAY%
echo  %MSG_TRAY2%
echo.
pythonw svoboda_tray.py
goto :done

:console_mode
echo.
python run_real.py

:done
taskkill /F /IM winws2.exe >nul 2>&1
echo.
pause
