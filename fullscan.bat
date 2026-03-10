@echo off
REM Full network scan: all devices, all ports, report output
REM Edit SUBNET below for your network (run ipconfig to find it)
set SUBNET=192.168.1.0/24
cd /d "%~dp0"
call venv\Scripts\activate.bat
echo Full scan: %SUBNET% - all 65535 ports - this may take a while...
python main.py %SUBNET% --scan-all --all-ports -t 0.3 -o report.html
echo.
echo Report saved to report.html
pause
