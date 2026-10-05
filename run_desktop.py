"""AgentTrace 데스크톱 진입점 (PyInstaller 빌드 대상).
상시 감시 트레이 앱을 띄운다. `python -m agenttrace.monitor_app` 와 동일.
창만 필요하면 `python -m agenttrace.app`."""
from agenttrace.monitor_app import main

if __name__ == "__main__":
    main()
