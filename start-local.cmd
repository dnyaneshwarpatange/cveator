@echo off
cd /d "%~dp0"
python scripts\deploy.py
if errorlevel 1 pause
