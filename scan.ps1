# SYN-REAPER Security Scanner - Launch script
# Uses venv Python directly (no activation needed)
Set-Location $PSScriptRoot
& "$PSScriptRoot\venv\Scripts\python.exe" main.py @args
