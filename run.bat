@echo off
REM Obscura47 - one-command launcher (Windows).
REM
REM Creates an isolated virtualenv on first run, keeps dependencies in sync, and
REM opens the desktop app. No manual "activate" step - it calls the venv's own
REM python.exe directly. Double-click run.bat (or run it from a terminal), then
REM click Connect.
setlocal enableextensions
cd /d "%~dp0"

REM 1. find Python (prefer the 'py' launcher that ships with python.org)
set "PY="
where py >nul 2>&1 && set "PY=py -3"
if not defined PY ( where python >nul 2>&1 && set "PY=python" )
if not defined PY (
    echo [x] Python 3.10+ not found. Install from https://www.python.org/downloads/
    echo     During install, tick "Add python.exe to PATH".
    pause & exit /b 1
)

REM 2. reuse an existing venv if present, else create one. This is the
REM    platform-specific step; afterwards we only call venv\Scripts\python.exe,
REM    never "activate". Existing setups are never recreated or wiped.
if exist "venv\Scripts\python.exe" (
    echo [*] Reusing existing virtual environment.
) else (
    echo [*] Creating virtual environment ^(first run^)...
    %PY% -m venv venv || ( echo [x] venv creation failed & pause & exit /b 1 )
)
set "VPY=%~dp0venv\Scripts\python.exe"

REM 3. install/update deps only when requirements.txt changes. Write the hash
REM    to a file and read it back with set /p - avoids fragile for/f quoting.
"%VPY%" -c "import hashlib;open('venv/.req-new','w').write(hashlib.md5(open('requirements.txt','rb').read()).hexdigest())"
set "REQHASH=" & set "OLDHASH="
if exist "venv\.req-new" set /p REQHASH=<venv\.req-new
if exist "venv\.req-hash" set /p OLDHASH=<venv\.req-hash
if not "%REQHASH%"=="%OLDHASH%" (
    echo [*] Installing dependencies...
    "%VPY%" -m pip install --quiet --upgrade pip
    "%VPY%" -m pip install --quiet -r requirements.txt
    copy /y "venv\.req-new" "venv\.req-hash" >nul
)
del "venv\.req-new" >nul 2>&1

REM 4. launch the GUI without a leftover console window (pythonw)
echo [+] Launching Obscura47...
start "Obscura47" "%~dp0venv\Scripts\pythonw.exe" "%~dp0app.py" %*
