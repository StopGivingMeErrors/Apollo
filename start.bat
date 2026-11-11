@echo off
REM Sentinel SOC launcher — frees ports then starts API
cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "%~dp0start.ps1"
