@echo off
setlocal
chcp 65001 >nul
set "PYTHONUTF8=1"
set "PYTHONIOENCODING=utf-8"
cd /d "%~dp0"

REM Everything (venv, pip cache) stays inside the project folder - never the C: drive.
set "PIP_CACHE_DIR=%~dp0backend\.pip-cache"
set "VENV_PY=%~dp0backend\.venv\Scripts\python.exe"
set "REQ=%~dp0backend\requirements.txt"
set "IMPORTS=import fastapi,uvicorn,httpx,pydantic,cryptography"

REM 1) The virtual environment must exist.
if not exist "%VENV_PY%" (
  echo.
  echo First run: creating the virtual environment...
  where python >nul 2>nul
  if errorlevel 1 (
    echo Python was not found. Install Python 3.10+ and add it to PATH, then retry.
    goto :fail
  )
  python -m venv "%~dp0backend\.venv"
  if errorlevel 1 (
    echo Failed to create the virtual environment.
    goto :fail
  )
  "%VENV_PY%" -m pip install --upgrade pip
  "%VENV_PY%" -m pip install -r "%REQ%"
  if errorlevel 1 (
    echo Dependency installation FAILED. See the pip output above.
    goto :fail
  )
)

REM 2) Verify the dependencies actually import; install only if something is missing.
"%VENV_PY%" -c "%IMPORTS%" >nul 2>nul
if errorlevel 1 (
  echo.
  echo [setup] Some dependencies are missing - installing now...
  "%VENV_PY%" -m pip install -r "%REQ%"
  if errorlevel 1 (
    echo [setup] Dependency installation FAILED. See the pip output above.
    goto :fail
  )
  "%VENV_PY%" -c "%IMPORTS%" >nul 2>nul
  if errorlevel 1 (
    echo [setup] Dependencies are still missing after installation.
    goto :fail
  )
)

REM 3) Start the service. Pass through any arguments (e.g. --port 18900 --probe).
"%VENV_PY%" "%~dp0backend\run.py" %*
echo.
echo Service stopped.
pause
exit /b 0

:fail
echo.
echo Startup aborted. Run this file from a terminal to read the full message above.
pause
exit /b 1
