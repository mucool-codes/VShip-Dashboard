@echo off
REM Demo: plays a Graylog CSV export through the dashboard.
REM   - double-click: uses the first .csv in this folder, or asks for the path
REM   - or drag a .csv file onto this script
REM   - or: start_demo.bat "C:\path\to\export.csv"
cd /d "%~dp0"

set "CSV=%~1"
if "%CSV%"=="" for %%F in ("%~dp0*.csv") do if not defined CSV set "CSV=%%~fF"
if "%CSV%"=="" (
  echo No CSV found in this folder.
  set /p CSV=Paste the full path to the CSV export, then press Enter: 
)
set "CSV=%CSV:"=%"
if not exist "%CSV%" (
  echo File not found: %CSV%
  pause
  exit /b 1
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
echo Playing "%CSV%" - the dashboard opens in your browser. Close this window to stop.
echo (Next time it continues where it stopped. To start the file over, delete the "data" folder.)
.venv\Scripts\python -m vship_monitor --replay "%CSV%" --speed 60
pause
