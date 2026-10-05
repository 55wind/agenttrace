"""AgentTrace 데스크톱 진입점 (PyInstaller 빌드 대상).
대시보드를 네이티브 창(GUI)으로 띄운다. `python -m agenttrace.app` 와 동일.
상시 백그라운드(트레이)로 돌리려면 `python -m agenttrace.monitor_app`."""
from agenttrace.app import main

if __name__ == "__main__":
    main()
