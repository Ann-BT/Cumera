@echo off
pushd "%~dp0"
title Cumera Updater

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

echo ==========================================================
echo   CAP NHAT UNG DUNG CUMERA TU GITHUB
echo ==========================================================
echo.

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
    echo [ERROR] Khong tim thay Python! Vui long chay setup.bat truoc.
    pause
    popd
    exit /b 1
)

where git >nul 2>nul
if %ERRORLEVEL% equ 0 (
    if exist ".git" (
        echo [*] Dang dong bo ma nguon moi qua Git...
        git pull origin main
        if %ERRORLEVEL% equ 0 goto :INSTALL_DEPS
        echo [!] Git pull that bai, chuyen sang tai ban cap nhat ZIP qua Python...
    )
)

echo [*] Dang tai ban cap nhat moi nhat tu GitHub qua Python...
"%PYTHON_BIN%" -c "import urllib.request, zipfile, io, os, shutil; url='https://github.com/Ann-BT/Cumera/archive/refs/heads/main.zip'; req=urllib.request.Request(url, headers={'User-Agent': 'Cumera-Updater'}); resp=urllib.request.urlopen(req, timeout=30); z=zipfile.ZipFile(io.BytesIO(resp.read())); [shutil.copyfileobj(z.open(m), open(os.path.join('.', m.filename.split('/', 1)[1]), 'wb')) for m in z.infolist() if len(m.filename.split('/', 1)) > 1 and m.filename.split('/', 1)[1] and not m.is_dir() and m.filename.split('/', 1)[1] != 'config.json' and not m.filename.split('/', 1)[1].startswith('captures/') and (os.makedirs(os.path.dirname(os.path.abspath(os.path.join('.', m.filename.split('/', 1)[1]))), exist_ok=True) or True)]; print('[OK] Da dong bo ma nguon moi tu GitHub!')"
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Khong the tai cap nhat tu GitHub! Vui long kiem tra ket noi mang.
    pause
    popd
    exit /b 1
)

:INSTALL_DEPS
echo [*] Dang dong bo thu vien phu thuoc...
"%PYTHON_BIN%" -m pip install --prefer-binary --disable-pip-version-check -r requirements.txt

echo.
echo ==========================================================
echo [OK] DA CAP NHAT CUMERA THANH CONG!
echo Ban co the khoi dong lai app bang cach nhap dup: run_app.bat
echo ==========================================================
pause
popd
