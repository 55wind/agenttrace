@echo off
REM AgentTrace 단일 실행파일(.exe) 빌드 — Windows
REM 준비: pip install pyinstaller pywebview pystray Pillow
pyinstaller --onefile --name AgentTrace --noconsole --icon assets\icon.ico ^
  --add-data "agenttrace/policy.yaml;agenttrace" ^
  run_desktop.py
echo.
echo 완료: dist\AgentTrace.exe  (더블클릭으로 실행)
