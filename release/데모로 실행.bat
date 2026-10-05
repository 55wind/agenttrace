@echo off
cd /d "%~dp0"
set AGENTTRACE_DB=%~dp0sample.db
start "" "%~dp0AgentTrace.exe"
