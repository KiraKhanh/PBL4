@echo off
title PBL4 Network IDS - Chay 43 Tests Tu Dong
cd /d "%~dp0"
echo ======================================================================
echo    PBL4 NETWORK IDS - KIEM THU TU DONG (43 PYTEST TESTS)
echo ======================================================================
echo.

if exist ".venv\bin\python.exe" (
    set "PYTHON_EXE=.venv\bin\python.exe"
) else if exist ".venv\Scripts\python.exe" (
    set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
    set "PYTHON_EXE=python"
)

"%PYTHON_EXE%" -m pytest -v
echo.
echo ======================================================================
echo    DA HOAN THANH KIEM THU TU DONG!
echo ======================================================================
pause
