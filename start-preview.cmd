@echo off
cd /d "%~dp0"
python scripts\run_local.py --built --full --no-demo --enable-email
if errorlevel 1 pause
