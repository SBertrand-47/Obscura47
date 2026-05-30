@echo off
REM Obscura47 System Tray Launcher (Windows)
REM Runs the tray application in the background using pythonw

REM Prefer the project venv (created by run.bat); fall back to system pythonw.
set "VPYW=%~dp0..\venv\Scripts\pythonw.exe"
if exist "%VPYW%" (
    start "Obscura47" "%VPYW%" "%~dp0..\tray_app.py" %*
) else (
    pythonw.exe "%~dp0..\tray_app.py" %*
)
