@echo off
REM Obscura47 - legacy launcher name kept for compatibility.
REM The real, robust launcher is run.bat: it creates or reuses the venv, calls
REM the venv's own python.exe directly (no fragile "activate"), syncs deps, and
REM opens the desktop app. This file just hands off to it.
cd /d "%~dp0"
call "%~dp0run.bat" %*
