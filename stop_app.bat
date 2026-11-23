@echo off
pushd "%~dp0"
title Cumera Stopper
echo ==========================================================
echo   DUNG TIEN TRINH CUMERA WEB SERVER
echo ==========================================================
echo.
echo [*] Dang tim va tat tien trinh web server tren cong 8765...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8765" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%a >nul 2>&1
)
echo [OK] Da dong web server thanh cong!
timeout /t 2 >nul
popd
exit /b 0
