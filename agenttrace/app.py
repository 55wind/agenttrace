"""AgentTrace 데스크톱 앱 런처.

대시보드를 **네이티브 창(GUI)**으로 띄우는 데스크톱 앱. 서버는 백그라운드 스레드,
창은 pywebview(없으면 기본 브라우저로 폴백). 창이 떠 있는 동안 Sysmon 수집도
백그라운드로 돈다(설치돼 있으면). 창을 닫으면 앱이 종료된다.
PyInstaller로 단일 .exe 패키징하면 더블클릭만으로 창이 뜬다(Python 불필요).

실행: python -m agenttrace.app   (또는 패키징한 AgentTrace.exe 더블클릭)
상시 백그라운드(트레이)로 돌리려면: python -m agenttrace.monitor_app
"""
import os
import time
import socket
import threading

from .dashboard import serve
from .store import Store
from . import collector

COLLECT_EVERY = 10          # 초. Sysmon 폴링 주기

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


def _collect_loop(db_path, stop):
    """Sysmon 이벤트를 주기적으로 수집. 미설치면 조용히 종료(앱은 계속)."""
    store = Store(db_path)
    try:
        while not stop.is_set():
            try:
                collector.collect(store)
            except RuntimeError:
                return      # Sysmon 없음 → OS 수집 비활성, 나머지는 동작
            stop.wait(COLLECT_EVERY)
    finally:
        store.db.close()


def main():
    db = os.environ.get("AGENTTRACE_DB", DEFAULT_DB)
    _ensure_db(db)
    port = int(os.environ.get("AGENTTRACE_PORT") or _free_port())
    threading.Thread(target=serve, args=(db, port), daemon=True).start()
    stop = threading.Event()
    threading.Thread(target=_collect_loop, args=(db, stop), daemon=True).start()
    _wait_ready(port)
    url = f"http://127.0.0.1:{port}"

    try:
        import webview       # 네이티브 앱 창(GUI)
        webview.create_window("AgentTrace 보안 관리자", url, width=1280, height=860,
                              min_size=(960, 640))
        webview.start()      # 창을 닫을 때까지 블록
        stop.set()
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
        stop.set()


if __name__ == "__main__":
    main()
