@echo off
rem Launches the toolkit GUI without leaving a console window open.
start "" "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -STA -ExecutionPolicy Bypass -WindowStyle Hidden -File "%~dp0Start-ToolkitGui.ps1"
