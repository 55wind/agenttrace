"""Sysmon 수집기 (제안서 ③ 수집기, §A).

Windows 내장 `wevtutil`로 Sysmon Operational 로그를 읽어 os_event로 넣는다.
`pywin32` 없이 stdlib(subprocess + ElementTree)만 쓴다 — Sysmon만 설치돼 있으면 됨.

관심 ID: 1(프로세스 생성) · 3(네트워크) · 11(파일 생성) · 13(레지스트리 값 설정,
자동 실행 등록이 여기 걸림). 수집기는 SYSTEM 권한 서비스로 돌리는 전제라 사용자 권한
에이전트가 지울 수 없다(§5.5).
"""
import subprocess
import xml.etree.ElementTree as ET

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
INTERESTING = {1, 3, 11, 13}


def _local(tag):
    return tag.split("}", 1)[-1]        # '{ns}Event' -> 'Event'


def parse_events(xml_text):
    """wevtutil XML(루트 없이 <Event> 나열)을 dict 목록으로. 순수 함수 → 테스트 대상.
    각 dict: {event_id, process_guid, image, data{Name: value}}."""
    root = ET.fromstring(f"<Events>{xml_text}</Events>")
    out = []
    for ev in root:
        if _local(ev.tag) != "Event":
            continue
        rec = {"event_id": None, "process_guid": None, "image": None, "data": {}}
        for node in ev.iter():
            name = _local(node.tag)
            if name == "EventID":
                rec["event_id"] = int((node.text or "0").strip())
            elif name == "Data":
                key = node.get("Name")
                rec["data"][key] = node.text
                if key == "ProcessGuid":
                    rec["process_guid"] = node.text
                elif key == "Image":
                    rec["image"] = node.text
        out.append(rec)
    return out


def query_sysmon(count=50, channel=CHANNEL):
    """최근 이벤트를 wevtutil로 조회. Sysmon 미설치/채널 없음이면 RuntimeError."""
    try:
        xml = subprocess.run(
            ["wevtutil", "qe", channel, "/f:xml", f"/c:{count}", "/rd:true"],
            capture_output=True, text=True, check=True,
        ).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise RuntimeError(f"Sysmon 로그를 읽을 수 없음 (설치/권한 확인): {e}") from e
    return parse_events(xml)


def collect(store, count=50):
    """Sysmon 이벤트 중 관심 ID를 os_event로 저장. 저장한 건수 반환."""
    n = 0
    for rec in query_sysmon(count):
        if rec["event_id"] in INTERESTING:
            store.append("os_event", {
                "event_id": rec["event_id"],
                "process_guid": rec["process_guid"],
                "image": rec["image"],
                "detail": rec["data"],
            }, agent=rec["image"])
            n += 1
    return n
