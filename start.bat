@echo off
REM Starts the monitor with the settings in config.toml (live feed).
cd /d "%~dp0"
if not exist config.toml (
  copy config.example.toml config.toml >nul
  echo Created config.toml - set the Graylog address and token, save it, then run start.bat again.
  notepad config.toml
  exit /b
)
where py >nul 2>nul && (set "PY=py -3") || (set "PY=python")
if not exist .venv\Scripts\python.exe (
  echo Setting up for the first time - this takes about a minute...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo Python 3.10 or newer is required. Install it from python.org and tick "Add python.exe to PATH".
    pause
    exit /b 1
  )
)
REM Install / update packages when requirements.txt has changed since last time
fc /b requirements.txt .venv\installed-requirements.txt >nul 2>nul
if errorlevel 1 (
  echo Installing required packages...
  .venv\Scripts\python -m pip install -q -r requirements.txt && copy /y requirements.txt .venv\installed-requirements.txt >nul
)
.venv\Scripts\python -m vship_monitor
pause
