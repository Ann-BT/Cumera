@echo off
pushd "%~dp0"
title Cumera Setup - Environment Installer

echo ==========================================================
echo   CUMERA - CAI DAT MOI TRUONG TREN WINDOWS
echo ==========================================================
echo.

set "SYS_PYTHON="

:: 1. Kiem tra 'python' trong PATH (bo qua Microsoft Store stub)
for /f "usebackq delims=" %%I in (`python -c "import sys, venv; assert sys.version_info >= (3,9); print(sys.executable)" 2^>nul`) do call :CHECK_PY "%%I"
if defined SYS_PYTHON goto :FOUND_PYTHON

:: 2. Kiem tra 'python3' trong PATH
for /f "usebackq delims=" %%I in (`python3 -c "import sys, venv; assert sys.version_info >= (3,9); print(sys.executable)" 2^>nul`) do call :CHECK_PY "%%I"
if defined SYS_PYTHON goto :FOUND_PYTHON

:: 3. Kiem tra Windows Python Launcher 'py -3'
for /f "usebackq delims=" %%I in (`py -3 -c "import sys, venv; assert sys.version_info >= (3,9); print(sys.executable)" 2^>nul`) do call :CHECK_PY "%%I"
if defined SYS_PYTHON goto :FOUND_PYTHON

:: 4. Quet cac thu muc cai dat Python pho bien tren Windows
for %%V in (315 314 313 312 311 310 39) do (
    call :CHECK_PY "%LocalAppData%\Programs\Python\Python%%V\python.exe"
    call :CHECK_PY "%ProgramFiles%\Python%%V\python.exe"
    call :CHECK_PY "C:\Python%%V\python.exe"
)
if defined SYS_PYTHON goto :FOUND_PYTHON

echo [ERROR] Khong tim thay Python ^>= 3.9 hop le tren he thong!
echo.
echo Huong dan khac phuc:
echo   1. Tai Python tu: https://www.python.org/downloads/
echo   2. Khi cai dat, nho tich chon "Add python.exe to PATH"
echo   3. Chay lai file setup.bat nay sau khi cai xong
echo.
pause
popd
exit /b 1

:CHECK_PY
if defined SYS_PYTHON goto :EOF
if "%~1"=="" goto :EOF
if not exist "%~1" goto :EOF
"%~1" -c "import sys, venv; assert sys.version_info >= (3,9)" >nul 2>nul
if %ERRORLEVEL% equ 0 set "SYS_PYTHON=%~1"
goto :EOF

:FOUND_PYTHON
echo [OK] Phat hien Python: "%SYS_PYTHON%"
"%SYS_PYTHON%" --version

:: Don dep .venv neu bi tao do dang truoc do
if exist ".venv" (
    if not exist ".venv\Scripts\python.exe" (
        echo [*] Phat hien .venv chua hoan chinh, dang tao lai...
        rmdir /s /q ".venv"
    )
)

if not exist ".venv\Scripts\python.exe" (
    echo [*] Dang khoi tao moi truong ao Python .venv...
    "%SYS_PYTHON%" -m venv ".venv"
    if %ERRORLEVEL% neq 0 (
        echo [ERROR] Khong the tao moi truong ao .venv!
        echo         Thu chuot phai vao setup.bat va chon "Run as administrator".
        pause
        popd
        exit /b 1
    )
) else (
    echo [OK] Moi truong ao .venv da san sang.
)

set "VENV_PY=%~dp0.venv\Scripts\python.exe"

"%VENV_PY%" -m pip --version >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [*] Dang khoi tao pip trong .venv...
    "%VENV_PY%" -m ensurepip --upgrade
)

echo [*] Dang nang cap pip...
"%VENV_PY%" -m pip install --upgrade pip --disable-pip-version-check

echo [*] Dang cai dat thu vien tu requirements.txt...
"%VENV_PY%" -m pip install --prefer-binary --disable-pip-version-check -r requirements.txt
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Co loi xay ra khi cai dat thu vien Python!
    echo         Kiem tra ket noi Internet hoac thu tat Firewall/Proxy roi chay lai setup.bat.
    pause
    popd
    exit /b 1
)

if not exist "config.json" (
    if exist "config.example.json" (
        echo [*] Dang tao config.json tu config.example.json...
        copy /Y "config.example.json" "config.json" >nul
    )
)

if not exist "captures" mkdir "captures"
if not exist "captures\evidence" mkdir "captures\evidence"
if not exist "captures\evidence\ComMech" mkdir "captures\evidence\ComMech"
if not exist "captures\evidence\AuthMech" mkdir "captures\evidence\AuthMech"

echo [*] Dang tao bieu tuong Cumera tren Desktop...
set "CUMERA_DIR=%~dp0"
if "%CUMERA_DIR:~-1%"=="\" set "CUMERA_DIR=%CUMERA_DIR:~0,-1%"
powershell -NoProfile -ExecutionPolicy Bypass -Command "$ws = New-Object -ComObject WScript.Shell; $desk = [Environment]::GetFolderPath('Desktop'); $s = $ws.CreateShortcut((Join-Path $desk 'Cumera.lnk')); $s.TargetPath = Join-Path $env:CUMERA_DIR 'run_app.bat'; $s.IconLocation = Join-Path $env:CUMERA_DIR 'assets\cumera.ico'; $s.WorkingDirectory = $env:CUMERA_DIR; $s.Save()" >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo [OK] Da tao shortcut Cumera tren Desktop!
) else (
    echo [!] Khong the tu dong tao icon Desktop, ban hay chay truc tiep run_app.bat.
)

echo.
echo ==========================================================
echo [OK] CAI DAT CUMERA HOAN TAT THANH CONG!
echo.
echo Cach su dung:
echo   1. Mo Giao dien App:  Nhap dup run_app.bat (hoac icon Cumera tren Desktop)
echo   2. Giao dien CLI:     Nhap dup run_suite.bat
echo   3. Cap nhat App:      Nhap dup update.bat (hoac nut Cap nhat trong App)
echo ==========================================================
pause
popd
exit /b 0
