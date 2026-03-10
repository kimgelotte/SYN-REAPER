@echo off
REM SYN-REAPER Security Scanner - Launch script
cd /d "%~dp0"
call venv\Scripts\activate.bat
python main.py %*
