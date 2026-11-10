@echo off
title PBL4 Network IDS - Web Dashboard
cd /d "%~dp0"
echo ======================================================================
echo    PBL4 NETWORK INTRUSION DETECTION SYSTEM (NIDS) - WINDOWS 11
echo ======================================================================
echo.

if exist ".venv\bin\python.exe" (
    set "PYTHON_EXE=.venv\bin\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

echo [+] Khoi dong he thong NIDS tai: http://127.0.0.1:5000 ...
echo [+] Nhan Ctrl + C de dung may chu.
echo.

REM Tu dong mo trinh duyet sau 1 giay
start "" "http://127.0.0.1:5000"

"%PYTHON_EXE%" main.py --port 5000
pause
