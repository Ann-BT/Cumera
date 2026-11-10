@echo off
chcp 65001 > nul
title Bộ công cụ đo kiểm mật mã Camera IP - QCVN 11:2026/BCA
set "DIR=%~dp0"
set "PYTHON_BIN=python"

if exist "%DIR%.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%.venv\Scripts\python.exe"
) else if exist "%DIR%..\.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%..\.venv\Scripts\python.exe"
)

"%PYTHON_BIN%" "%DIR%toolkit_menu.py" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo [Lỗi] Không thể khởi chạy công cụ hoặc có lỗi phát sinh.
    echo Vui lòng đảm bảo đã cài đặt thư viện bằng cách chạy setup.bat
    pause
)
