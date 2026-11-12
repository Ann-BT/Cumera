@echo off
pushd "%~dp0"
title Cumera

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

set "PYTHON_BIN="
if exist "%~dp0.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0.venv\Scripts\python.exe"
if not defined PYTHON_BIN if exist "%~dp0..\.venv\Scripts\python.exe" set "PYTHON_BIN=%~dp0..\.venv\Scripts\python.exe"

if not defined PYTHON_BIN (
    for /f "usebackq delims=" %%I in (`python -c "import sys; assert sys.version_info >= (3,9); print(sys.executable)" 2^>nul`) do (
        if exist "%%I" set "PYTHON_BIN=%%I"
    )
)
if not defined PYTHON_BIN (
    for /f "usebackq delims=" %%I in (`py -3 -c "import sys; assert sys.version_info >= (3,9); print(sys.executable)" 2^>nul`) do (
        if exist "%%I" set "PYTHON_BIN=%%I"
    )
)

if not defined PYTHON_BIN (
    echo [ERROR] Khong tim thay moi truong Python! Vui long chay setup.bat truoc.
    pause
    popd
    exit /b 1
)

echo ==========================================================
echo   CUMERA - KHOI CHAY UNG DUNG
echo ==========================================================

set "APP_URL=http://127.0.0.1:8765"

:: 1. Kiem tra neu Backend Server da chay san tren cong 8765
"%PYTHON_BIN%" -c "import urllib.request; urllib.request.urlopen('%APP_URL%/', timeout=1)" >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [OK] Backend Server da san sang tai %APP_URL%
    goto :OPEN_APP
)

:: 2. Khoi chay Backend Web Server o cua so thu nho (/MIN)
echo [*] Dang khoi dong Backend Web Server tren cong 8765...
start "Cumera Web Server" /MIN "%PYTHON_BIN%" "%~dp0toolkit_web_server.py"

:: 3. Cho toi khi Server phan hoi HTTP 200 (toi da ~15 giay)
echo [*] Dang cho Backend Server san sang...
"%PYTHON_BIN%" -c "import time,sys,urllib.request; exec('for i in range(38):\n try: urllib.request.urlopen(sys.argv[1],timeout=1); sys.exit(0)\n except Exception: time.sleep(0.4)\nsys.exit(1)')" "%APP_URL%/" >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Backend Server khong the khoi dong tren cong 8765!
    echo         Vui long chay thu cong "%PYTHON_BIN%" "%~dp0toolkit_web_server.py" de xem chi tiet loi.
    pause
    popd
    exit /b 1
)

:OPEN_APP
echo [*] Dang mo giao dien ung dung Cumera...
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_edge_profile" --no-first-run
    popd
    exit /b 0
)
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_edge_profile" --no-first-run
    popd
    exit /b 0
)
if exist "%LocalAppData%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%LocalAppData%\Microsoft\Edge\Application\msedge.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_edge_profile" --no-first-run
    popd
    exit /b 0
)

if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_chrome_profile" --no-first-run
    popd
    exit /b 0
)
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_chrome_profile" --no-first-run
    popd
    exit /b 0
)
if exist "%LocalAppData%\Google\Chrome\Application\chrome.exe" (
    start "" "%LocalAppData%\Google\Chrome\Application\chrome.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_chrome_profile" --no-first-run
    popd
    exit /b 0
)

echo [*] Mo tren trinh duyet mac dinh...
start "" "%APP_URL%"
popd
exit /b 0
