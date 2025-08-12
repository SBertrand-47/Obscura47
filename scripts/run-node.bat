@echo off
setlocal enableextensions enabledelayedexpansion
if exist .env.node (
  for /f "usebackq tokens=*" %%a in (".env.node") do set %%a
)
python -m src.main node --port %OBSCURA_NODE_LISTEN_PORT%
