"""Sysmon 수집기 (제안서 ③ 수집기, §A).

Windows 내장 `wevtutil`로 Sysmon Operational 로그를 읽어 os_event로 넣는다.
`pywin32` 없이 stdlib(subprocess + ElementTree)만 쓴다 — Sysmon만 설치돼 있으면 됨.

수집 방식:
  - `watch()` 가 EventRecordID 북마크로 **새 이벤트만 증분 수집**하며 짧은 간격(기본 1초)
    으로 끊김 없이 돈다 → 상시(실시간에 준하는) 수집. 트레이/창 앱이 이걸 돌린다.
  - `collect()` 는 한 번만 수집(대시보드 "지금 가져오기" 버튼). RecordID로 중복 제거.

관심 ID: 1(프로세스 생성) · 3(네트워크) · 11(파일 생성) · 13(레지스트리 값 설정).
수집기는 SYSTEM 권한 서비스로 돌리는 전제라 사용자 권한 에이전트가 지울 수 없다(§5.5).
"""
import time
import subprocess
import xml.etree.ElementTree as ET

CHANNEL = "Microsoft-Windows-Sysmon/Operational"
INTERESTING = {1, 3, 11, 13}


def _local(tag):
    return tag.split("}", 1)[-1]        # '{ns}Event' -> 'Event'


def parse_events(xml_text):
    """wevtutil XML(루트 없이 <Event> 나열)을 dict 목록으로. 순수 함수 → 테스트 대상.
    각 dict: {event_id, record_id, process_guid, image, data{Name: value}}."""
    root = ET.fromstring(f"<Events>{xml_text}</Events>")
    out = []
    for ev in root:
        if _local(ev.tag) != "Event":
            continue
        rec = {"event_id": None, "record_id": None, "process_guid": None,
               "image": None, "data": {}}
        for node in ev.iter():
            name = _local(node.tag)
            if name == "EventID":
                rec["event_id"] = int((node.text or "0").strip())
            elif name == "EventRecordID":
                rec["record_id"] = int((node.text or "0").strip())
            elif name == "Data":
                key = node.get("Name")
                rec["data"][key] = node.text
                if key == "ProcessGuid":
                    rec["process_guid"] = node.text
                elif key == "Image":
                    rec["image"] = node.text
        out.append(rec)
    return out


def query_sysmon(count=50, channel=CHANNEL, after_record=None):
    """wevtutil로 조회. after_record가 있으면 그 RecordID보다 큰 새 이벤트만 가져온다.
    Sysmon 미설치/채널 없음/권한 없음이면 RuntimeError."""
    if after_record:
        args = ["wevtutil", "qe", channel, "/f:xml", "/c:1000",
                f"/q:*[System[EventRecordID>{after_record}]]"]
    else:
        args = ["wevtutil", "qe", channel, "/f:xml", f"/c:{count}", "/rd:true"]
    try:
        xml = subprocess.run(args, capture_output=True, text=True, check=True).stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        raise RuntimeError(f"Sysmon 로그를 읽을 수 없음 (설치/권한 확인): {e}") from e
    return parse_events(xml)


def _store_event(store, rec):
    store.append("os_event", {
        "event_id": rec["event_id"], "record_id": rec.get("record_id"),
        "process_guid": rec["process_guid"], "image": rec["image"],
        "detail": rec["data"],
    }, agent=rec["image"])


def _max_rid(store):
    """저장소에 이미 쌓인 os_event 중 최대 RecordID(북마크 복원용)."""
    row = store.db.execute(
        "SELECT MAX(json_extract(data,'$.record_id')) FROM event WHERE kind='os_event'"
    ).fetchone()
    return (row[0] or 0) if row else 0


def collect(store, count=200):
    """Sysmon 이벤트를 한 번 수집(수동). 이미 저장한 RecordID는 건너뛴다. 저장 건수 반환."""
    seen = _max_rid(store)
    n = 0
    for rec in query_sysmon(count):
        rid = rec.get("record_id") or 0
        if rec["event_id"] in INTERESTING and rid > seen:
            _store_event(store, rec)
            n += 1
    return n


def watch(store, interval=1.0, stop=None):
    """상시 수집: EventRecordID 북마크로 새 이벤트만 증분 수집하며 interval초마다 반복.
    Sysmon 미설치/권한 없음이면 조용히 종료(앱은 계속). 저장된 마지막 지점부터 이어받는다."""
    last = _max_rid(store)
    while stop is None or not stop.is_set():
        try:
            evs = query_sysmon(after_record=last or None)
        except RuntimeError:
            return      # Sysmon 없음 → 상시 수집 비활성, 나머지는 동작
        for rec in sorted(evs, key=lambda r: r.get("record_id") or 0):
            rid = rec.get("record_id") or 0
            if rid > last and rec["event_id"] in INTERESTING:
                _store_event(store, rec)
            last = max(last, rid)
        if stop is not None:
            stop.wait(interval)
        else:
            time.sleep(interval)
