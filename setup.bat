@echo off
chcp 65001 > nul
title Cài đặt Môi trường - Bộ công cụ đo kiểm mật mã Camera IP (QCVN 11:2026/BCA)
echo ==========================================================
echo   CÀI ĐẶT MÔI TRƯỜNG: BỘ ĐO KIỂM AN TOÀN CAMERA (QCVN 11)
echo ==========================================================
cd /d "%~dp0"

where python >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [-] Lỗi: Không tìm thấy Python trên hệ thống!
    echo     Vui lòng tải và cài đặt Python ^>= 3.9 từ https://www.python.org/
    echo     LƯU Ý: Nhớ tích chọn "Add python.exe to PATH" khi cài đặt.
    echo.
    pause
    exit /b 1
)

echo [*] Kiểm tra phiên bản Python...
python --version

if not exist ".venv" (
    echo [*] Đang khởi tạo môi trường ảo Python (.venv)...
    python -m venv .venv
    if %ERRORLEVEL% neq 0 (
        echo [-] Không thể khởi tạo môi trường ảo .venv!
        pause
        exit /b 1
    )
)

echo [*] Nâng cấp pip và cài đặt các thư viện cần thiết...
.venv\Scripts\python.exe -m pip install --upgrade pip
.venv\Scripts\python.exe -m pip install -r requirements.txt

if %ERRORLEVEL% neq 0 (
    echo.
    echo [-] Có lỗi xảy ra trong quá trình cài đặt thư viện!
    pause
    exit /b 1
)

if not exist "config.json" if exist "config.example.json" (
    echo [*] Khởi tạo config.json từ file mẫu config.example.json...
    copy config.example.json config.json > nul
)

if not exist "captures" mkdir captures
if not exist "captures\evidence\ComMech" mkdir captures\evidence\ComMech
if not exist "captures\evidence\AuthMech" mkdir captures\evidence\AuthMech

echo.
echo [OK] Hoàn tất cài đặt môi trường thành công!
echo Bạn có thể khởi chạy bộ công cụ bằng một trong các cách sau:
echo     1. Giao diện Đồ họa Web Dashboard:    nhấp đúp run_app.bat
echo     2. Menu điều khiển dòng lệnh CLI:     nhấp đúp run_suite.bat
echo ==========================================================
pause
