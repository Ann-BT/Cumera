@echo off
chcp 65001 > nul
title Cumera - Camera Cybersecurity Auditor
set "DIR=%~dp0"
set "PYTHON_BIN=python"

if exist "%DIR%.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%.venv\Scripts\python.exe"
) else if exist "%DIR%..\.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%..\.venv\Scripts\python.exe"
)

echo ==========================================================
echo   KHỞI CHẠY CUMERA - CAMERA SECURITY AUDITOR
echo ==========================================================

:: 1. Khởi chạy Backend Web Server ngầm trên cổng 8765
echo [*] Đang khởi động Backend Web Server (Port 8765)...
start "Cumera Web Server" /B "%PYTHON_BIN%" "%DIR%toolkit_web_server.py"

:: 2. Đợi máy chủ sẵn sàng
echo [*] Đang đợi Backend Server sẵn sàng...
timeout /t 2 /nobreak > nul

set "APP_URL=http://127.0.0.1:8765"

:: 3. Khởi chạy Giao diện App Window độc lập (Native Window App Mode)
:: Microsoft Edge (mặc định có sẵn trên 100% Windows 10/11)
if exist "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_edge_profile" --no-first-run
    exit /b 0
)
if exist "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" (
    start "" "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_edge_profile" --no-first-run
    exit /b 0
)

:: Google Chrome nếu có
if exist "%ProgramFiles%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles%\Google\Chrome\Application\chrome.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_chrome_profile" --no-first-run
    exit /b 0
)
if exist "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" (
    start "" "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe" --app="%APP_URL%" --user-data-dir="%TEMP%\cumera_chrome_profile" --no-first-run
    exit /b 0
)

:: Trình duyệt mặc định nếu không tìm thấy Chrome/Edge app mode
echo [*] Mở trên trình duyệt mặc định...
start "" "%APP_URL%"
