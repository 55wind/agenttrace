@echo off
cd /d "%~dp0"
set AGENTTRACE_PORT=8787
start "" pythonw -m agenttrace.monitor_app
