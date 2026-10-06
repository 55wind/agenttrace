"""상시 감시 트레이 앱 — 개인용 보안 프로그램의 "항상 켜짐" 조각.

- 백그라운드: 대시보드 서버 + 상시 Sysmon 수집(설치돼 있으면).
- 트레이 아이콘: 대시보드 열기 / Windows 시작 시 자동 실행 토글 / 종료.
- pystray·Pillow가 있으면 트레이, 없으면 브라우저만 열고 유지(폴백).

실행: pythonw -m agenttrace.monitor_app   (또는 패키징한 exe)

ponytail: 대시보드는 DB를 읽기전용으로, 수집 루프는 쓰기로 같은 SQLite 파일을 쓴다.
저빈도라 기본 잠금으로 충분. 동시성이 올라가면 WAL + busy_timeout.
"""
import os
import time
import threading
import webbrowser

from .dashboard import serve
from .app import _free_port, _ensure_db, _wait_ready, _collect_loop, DEFAULT_DB
from . import autostart


def _icon_image():
    """로고와 동일: 파란 방패 + 흰 노드 그래프(에이전트)."""
    from PIL import Image, ImageDraw
    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    blue = (37, 99, 235, 255)
    d.polygon([(32, 4), (54, 12), (54, 31), (32, 60), (10, 31), (10, 12)], fill=blue)
    d.line([(32, 24), (22, 41)], fill="white", width=3)
    d.line([(32, 24), (42, 41)], fill="white", width=3)
    for x, y in [(32, 24), (22, 41), (42, 41)]:
        d.ellipse([x - 5, y - 5, x + 5, y + 5], fill="white")
    return img


def main():
    db = os.environ.get("AGENTTRACE_DB", DEFAULT_DB)
    _ensure_db(db)
    port = int(os.environ.get("AGENTTRACE_PORT") or _free_port())
    threading.Thread(target=serve, args=(db, port), daemon=True).start()
    stop = threading.Event()
    threading.Thread(target=_collect_loop, args=(db, stop), daemon=True).start()
    url = f"http://127.0.0.1:{port}"
    _wait_ready(port)
    webbrowser.open(url)        # 켜지면 대시보드 한 번 열기

    try:
        import pystray
        from pystray import MenuItem as Item, Menu
    except ImportError:         # 트레이 불가 → 브라우저만 유지
        print(f"AgentTrace 감시 중: {url}  (종료: Ctrl+C)")
        try:
            while not stop.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        return

    def _open(icon=None, item=None):
        webbrowser.open(url)

    def _toggle(icon, item):
        autostart.disable() if autostart.is_enabled() else autostart.enable()

    def _quit(icon, item):
        stop.set()
        icon.stop()

    menu = Menu(
        Item("대시보드 열기", _open, default=True),
        Item("Windows 시작 시 자동 실행", _toggle,
             checked=lambda item: autostart.is_enabled()),
        Item("종료", _quit),
    )
    pystray.Icon("AgentTrace", _icon_image(), "AgentTrace 보안 감시", menu).run()


if __name__ == "__main__":
    main()
