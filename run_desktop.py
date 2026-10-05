"""AgentTrace 데스크톱 진입점 (PyInstaller 빌드 대상).
`python run_desktop.py` 또는 빌드한 AgentTrace.exe 로 실행.
Python이 있으면 `python -m agenttrace.app` 도 동일하게 동작."""
from agenttrace.app import main

if __name__ == "__main__":
    main()
