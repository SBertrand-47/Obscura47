@echo off
title Obscura47
cd /d "%~dp0"
call venv\Scripts\activate
python app.py
pause
