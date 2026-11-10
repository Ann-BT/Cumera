@echo off
chcp 65001 > nul
title Cập nhật Cumera - Camera Cybersecurity Auditor
set "DIR=%~dp0"
cd /d "%DIR%"

echo ==========================================================
echo   CẬP NHẬT ỨNG DỤNG CUMERA TỪ GITHUB (Ann-BT/Cumera)
echo ==========================================================

set "PYTHON_BIN=python"
if exist "%DIR%.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%.venv\Scripts\python.exe"
) else if exist "%DIR%..\.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%DIR%..\.venv\Scripts\python.exe"
)

where git >nul 2>nul
if %ERRORLEVEL% equ 0 if exist ".git" (
    echo [*] Đang đồng bộ mã nguồn mới qua Git...
    git pull origin main
    goto :INSTALL_DEPS
)

echo [*] Đang tải bản cập nhật mới nhất từ GitHub qua Python...
"%PYTHON_BIN%" -c "import urllib.request, zipfile, io, os, shutil; url='https://github.com/Ann-BT/Cumera/archive/refs/heads/main.zip'; req=urllib.request.Request(url, headers={'User-Agent': 'Cumera-Updater'}); resp=urllib.request.urlopen(req, timeout=30); z=zipfile.ZipFile(io.BytesIO(resp.read())); [shutil.copyfileobj(z.open(m), open(os.path.join('.', m.filename.split('/', 1)[1]), 'wb')) for m in z.infolist() if len(m.filename.split('/', 1)) > 1 and m.filename.split('/', 1)[1] and not m.is_dir() and m.filename.split('/', 1)[1] != 'config.json' and not m.filename.split('/', 1)[1].startswith('captures/') and (os.makedirs(os.path.dirname(os.path.join('.', m.filename.split('/', 1)[1])), exist_ok=True) or True)]; print('[OK] Da dong bo ma nguon moi tu GitHub!')"

:INSTALL_DEPS
echo [*] Đang đồng bộ thư viện phụ thuộc...
"%PYTHON_BIN%" -m pip install -r requirements.txt

echo.
echo ==========================================================
echo [OK] ĐÃ CẬP NHẬT CUMERA THÀNH CÔNG!
echo Bạn có thể khởi động lại ứng dụng bằng cách nhấp đúp: run_app.bat
echo ==========================================================
pause
