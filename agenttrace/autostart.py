"""Windows 시작 시 자동 실행 등록 (stdlib winreg, 관리자 권한 불필요).

HKCU\...\Run 에 값 하나를 쓴다. 사용자 단위라 admin이 필요 없고 되돌리기 쉽다.
"""
import os
import sys
import winreg

_RUN = r"Software\Microsoft\Windows\CurrentVersion\Run"
NAME = "AgentTrace"


def _default_command():
    """콘솔 창 없이 트레이 앱을 띄우는 명령. 패키징된 exe면 그 경로."""
    if getattr(sys, "frozen", False):          # PyInstaller exe
        return f'"{sys.executable}"'
    pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    exe = pyw if os.path.exists(pyw) else sys.executable
    return f'"{exe}" -m agenttrace.monitor_app'


def enable(name=NAME, command=None):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN, 0, winreg.KEY_SET_VALUE) as k:
        winreg.SetValueEx(k, name, 0, winreg.REG_SZ, command or _default_command())


def disable(name=NAME):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
    except FileNotFoundError:
        pass


def is_enabled(name=NAME):
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN) as k:
            winreg.QueryValueEx(k, name)
            return True
    except FileNotFoundError:
        return False
