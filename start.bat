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
  .venv\Scripts\python -m pip install -r requirements.txt
)
.venv\Scripts\python -m vship_monitor
pause
