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
if exist ".venv\Scripts\python.exe" set "PYTHON_BIN=.venv\Scripts\python.exe"
if not defined PYTHON_BIN if exist "..\.venv\Scripts\python.exe" set "PYTHON_BIN=..\.venv\Scripts\python.exe"
if not defined PYTHON_BIN (
    for /f "usebackq delims=" %%I in (`python -c "import sys;print(sys.executable)" 2^>nul`) do call :CHECK_PY "%%I"
)
if not defined PYTHON_BIN (
    for /f "usebackq delims=" %%I in (`py -3 -c "import sys;print(sys.executable)" 2^>nul`) do call :CHECK_PY "%%I"
)
goto :AFTER_DETECT

:CHECK_PY
if defined PYTHON_BIN goto :EOF
if "%~1"=="" goto :EOF
if not exist "%~1" goto :EOF
"%~1" -c "import sys; raise SystemExit(0 if sys.version_info[:2]>=(3,9) else 1)" >nul 2>nul
if not errorlevel 1 set "PYTHON_BIN=%~1"
goto :EOF

:AFTER_DETECT
if not defined PYTHON_BIN (
    echo [ERROR] Khong tim thay Python! Vui long chay setup.bat truoc.
    pause
    popd
    exit /b 1
)

where git >nul 2>nul
if errorlevel 1 goto :DOWNLOAD_ZIP
if not exist ".git" goto :DOWNLOAD_ZIP

echo [*] Dang dong bo ma nguon moi qua Git...
git pull origin main
if not errorlevel 1 goto :INSTALL_DEPS
echo [!] Git pull that bai, chuyen sang tai ban cap nhat ZIP qua Python...

:DOWNLOAD_ZIP
echo [*] Dang tai ban cap nhat moi nhat tu GitHub qua Python...
"%PYTHON_BIN%" -c "import urllib.request, zipfile, io, os, shutil; url='https://github.com/Ann-BT/Cumera/archive/refs/heads/main.zip'; req=urllib.request.Request(url, headers={'User-Agent': 'Cumera-Updater'}); resp=urllib.request.urlopen(req, timeout=30); z=zipfile.ZipFile(io.BytesIO(resp.read())); [shutil.copyfileobj(z.open(m), open(os.path.join('.', m.filename.split('/', 1)[1]), 'wb')) for m in z.infolist() if len(m.filename.split('/', 1)) > 1 and m.filename.split('/', 1)[1] and not m.is_dir() and m.filename.split('/', 1)[1] != 'config.json' and not m.filename.split('/', 1)[1].startswith('captures/') and (os.makedirs(os.path.dirname(os.path.abspath(os.path.join('.', m.filename.split('/', 1)[1]))), exist_ok=True) or True)]; print('[OK] Da dong bo ma nguon moi tu GitHub!')"
if errorlevel 1 (
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
