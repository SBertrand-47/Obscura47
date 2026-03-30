@echo off
REM Build Obscura47 into a standalone Windows .exe
REM Requires: pip install pyinstaller

cd /d "%~dp0"
call venv\Scripts\activate
pip install pyinstaller
pyinstaller --onefile --noconsole --name Obscura47 --add-data "src;src" app.py
echo.
echo Done! Your .exe is in the dist\ folder.
pause
