@echo off
setlocal EnableExtensions DisableDelayedExpansion
title EventSage Local v2.4
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" goto ready
where py >nul 2>&1
if not errorlevel 1 goto use_py
where python >nul 2>&1
if errorlevel 1 goto missing
python -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 goto missing
python -m venv .venv
if errorlevel 1 goto failed
goto install
:use_py
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,10) else 1)"
if errorlevel 1 goto missing
py -3 -m venv .venv
if errorlevel 1 goto failed
:install
echo First-run setup: downloading Python dependencies. Internet access is required.
".venv\Scripts\python.exe" -m pip install -r requirements.txt
if errorlevel 1 goto failed
:ready
".venv\Scripts\python.exe" -c "import flask, Evtx, defusedxml" >nul 2>&1
if errorlevel 1 goto install
".venv\Scripts\python.exe" run_local.py
pause
exit /b
:missing
echo Install Python 3.10 or newer from https://www.python.org/downloads/windows/
echo Enable the Python launcher or Add Python to PATH, then run this file again.
pause
exit /b 1
:failed
echo Setup failed. Check the error above and your internet connection, then retry.
pause
exit /b 1
