@echo off
pushd "%~dp0"
title Cumera CLI Suite

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

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

"%PYTHON_BIN%" "%~dp0toolkit_menu.py" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] Khong the khoi chay cong cu hoac co loi phat sinh.
    echo         Vui long dam bao da cai dat thu vien bang cach chay setup.bat
    pause
)
popd
