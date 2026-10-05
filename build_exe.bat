@echo off
REM AgentTrace 단일 실행파일(.exe) 빌드 — Windows
REM 준비: pip install pyinstaller pywebview
pyinstaller --onefile --name AgentTrace --noconsole ^
  --add-data "agenttrace/policy.yaml;agenttrace" ^
  run_desktop.py
echo.
echo 완료: dist\AgentTrace.exe  (더블클릭으로 실행)
