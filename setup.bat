@echo off
chcp 65001 > nul
title Cài đặt Môi trường - Cumera (Camera Cybersecurity Auditor)
echo ==========================================================
echo   CÀI ĐẶT MÔI TRƯỜNG: CUMERA (CAMERA SECURITY AUDITOR)
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

:: Tạo phím tắt Desktop với biểu tượng Cumera (nếu có PowerShell)
powershell -Command "$s=(New-Object -COM WScript.Shell).CreateShortcut([Environment]::GetFolderPath('Desktop') + '\Cumera.lnk'); $s.TargetPath='%~dp0run_app.bat'; $s.IconLocation='%~dp0assets\cumera.ico'; $s.WorkingDirectory='%~dp0'; $s.Save()" 2>nul
if exist "%USERPROFILE%\Desktop\Cumera.lnk" (
    echo [*] Đã tạo biểu tượng Cumera trên Desktop của bạn!
)

echo.
echo ==========================================================
echo [OK] HOÀN TẤT CÀI ĐẶT CUMERA THÀNH CÔNG!
echo.
echo Cách khởi chạy:
echo     1. Giao diện Đồ họa Desktop (Khuyên dùng): Nhấp đúp run_app.bat (hoặc icon Cumera trên Desktop)
echo     2. Menu điều khiển dòng lệnh:             Nhấp đúp run_suite.bat
echo     3. Cập nhật app khi có bản mới:           Nhấp đúp update.bat (hoặc bấm nút Cập nhật trong App)
echo ==========================================================
pause
