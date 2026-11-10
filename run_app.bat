@echo off
chcp 65001 > nul
title Camera Security Auditor - Web Dashboard (QCVN 11:2026/BCA)
set "DIR=%~dp0"
set "PYTHON_BIN=python"

if exist "%DIR%.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%.venv\Scripts\python.exe"
) else if exist "%DIR%..\.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%..\.venv\Scripts\python.exe"
)

echo ==========================================================
echo   KHỞI CHẠY BỘ ĐO KIỂM AN TOÀN CAMERA (QCVN 11)
echo ==========================================================
echo [*] Đang khởi động Backend Web Server (Port 8765)...
start "Camera Auditor Web Server" /B "%PYTHON_BIN%" "%DIR%toolkit_web_server.py"

echo [*] Đang đợi Backend Server sẵn sàng...
timeout /t 2 /nobreak > nul

echo [*] Đang mở Dashboard trên trình duyệt mặc định: http://127.0.0.1:8765 ...
start "" http://127.0.0.1:8765
