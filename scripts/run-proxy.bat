@echo off
setlocal enableextensions enabledelayedexpansion
if exist .env.proxy (
  for /f "usebackq tokens=*" %%a in (".env.proxy") do set %%a
)
python -m src.main proxy
