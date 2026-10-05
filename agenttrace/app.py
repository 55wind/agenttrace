"""AgentTrace 데스크톱 앱 런처.

기존 로컬 대시보드를 그대로 재사용한다. 서버는 백그라운드 스레드로 띄우고,
pywebview가 있으면 네이티브 앱 창으로, 없으면 기본 브라우저로 연다.
PyInstaller로 단일 .exe 패키징하면 비전공자는 더블클릭만 하면 된다
(Python 설치 불필요).

실행: python -m agenttrace.app   (또는 패키징한 AgentTrace.exe 더블클릭)
"""
import os
import time
import socket
import threading

from .dashboard import serve
from .store import Store

# 개인 사용자 기본 저장 위치: 홈\AgentTrace\agenttrace.db
DEFAULT_DB = os.path.join(os.path.expanduser("~"), "AgentTrace", "agenttrace.db")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _ensure_db(path):
    """DB가 없으면 스키마만 만들어 둔다(빈 대시보드라도 뜨도록)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    Store(path).db.close()


def _wait_ready(port, timeout=5.0):
    """서버가 연결을 받을 때까지 대기(창이 빈 화면으로 먼저 뜨는 것 방지)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def main():
    db = os.environ.get("AGENTTRACE_DB", DEFAULT_DB)
    _ensure_db(db)
    port = int(os.environ.get("AGENTTRACE_PORT") or _free_port())
    threading.Thread(target=serve, args=(db, port), daemon=True).start()
    _wait_ready(port)
    url = f"http://127.0.0.1:{port}"

    try:
        import webview       # 있으면 네이티브 앱 창
        webview.create_window("AgentTrace 보안 관리자", url, width=1200, height=900)
        webview.start()
        return
    except Exception:
        # pywebview 미설치 또는 WebView 백엔드 없음 → 기본 브라우저로 폴백
        pass
    import webbrowser
    webbrowser.open(url)
    print(f"AgentTrace 실행 중: {url}  (종료: Ctrl+C)")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
