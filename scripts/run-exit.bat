@echo off
setlocal enableextensions enabledelayedexpansion
if exist .env.exit (
  for /f "usebackq tokens=*" %%a in (".env.exit") do set %%a
)
python -m src.main exit --port %OBSCURA_EXIT_LISTEN_PORT%
