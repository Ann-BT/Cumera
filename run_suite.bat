@echo off
pushd "%~dp0"
title Cumera CLI Suite

set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"

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

"%PYTHON_BIN%" toolkit_menu.py %*
if errorlevel 1 (
    echo.
    echo [ERROR] Khong the khoi chay cong cu hoac co loi phat sinh.
    echo         Vui long dam bao da cai dat thu vien bang cach chay setup.bat
    pause
)
popd
