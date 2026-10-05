"""로컬 웹 대시보드 (제안서 ⑧), 비전공자용 데스크톱 앱 화면.

외부 의존 0: stdlib http.server + 바닐라 JS. 그래프 라이브러리/CDN 없음 →
외부망 차단 환경(§A)에서도 동작, 127.0.0.1에만 바인딩. 조회는 읽기 전용.

디자인(앱 셸): 좌측 사이드바(상태 방패 + 로고 + 대시보드/위협/행동 기록/기록 무결성/
설정) + 상단 "오프라인" 배지. 전문용어 대신 평이한 말(메일/파일/메시지, 자가복제,
감염/외부유입), "무슨 일 → 전파 경로 → 지금 할 일" 흐름, 기술 상세는 접어둠.

실행: python -m agenttrace.dashboard <db경로> [포트]
"""
import os
import sys
import json
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import mcp_server, report, trace
from ._fonts import FONTS

KIND_LABEL = {"file": "파일", "mail": "메일", "message": "메시지", "memory": "메모리"}
KIND_ICON = {"file": "file-text", "mail": "mail", "message": "message-square", "memory": "database"}
ACTION_LABEL = {"exec": "명령 실행", "send": "외부로 보내기",
                "write": "파일 쓰기", "autorun": "자동 실행 등록"}
VERDICT_LABEL = {"allow": "허용", "ask": "확인 필요", "block": "막음"}
RULE_EXPLAIN = {
    "encoded-powershell": "내용을 숨긴(인코딩한) PowerShell 명령이라 막았습니다.",
    "remote-code-exec": "원격 코드를 내려받아 바로 실행하려 해서 막았습니다.",
    "eicar-test-string": "테스트용 악성 문자열(EICAR)이라 막았습니다.",
    "credential-access": "비밀번호와 키 파일에 접근하려 해서 확인을 요청했습니다.",
    "autorun-registration": "컴퓨터 시작 시 자동 실행을 등록하려 해서 확인을 요청했습니다.",
}


def _artifact(db, aid):
    return db.execute("SELECT * FROM artifact WHERE id=?", (aid,)).fetchone()


def _count(db, sql, args=()):
    return db.execute(sql, args).fetchone()[0]


def summary(db):
    threats = _count(db, "SELECT COUNT(*) FROM incident")
    blocked = _count(db, "SELECT COUNT(*) FROM event WHERE kind='verdict' "
                         "AND data LIKE '%\"verdict\": \"block\"%'")
    review = _count(db, "SELECT COUNT(*) FROM event WHERE kind='verdict' "
                        "AND data LIKE '%\"verdict\": \"ask\"%'")
    infected = _count(db, "SELECT COUNT(*) FROM artifact WHERE infected=1")
    records = _count(db, "SELECT COUNT(*) FROM event")
    safe = threats == 0
    return {
        "state": "safe" if safe else "threat",
        "threats": threats, "blocked": blocked, "review": review,
        "infected": infected, "records": records,
        "headline": "안전합니다" if safe else f"위협 {threats}건이 발견되었습니다",
        "subtitle": ("AI 에이전트의 행동을 실행하기 전에 하나씩 확인하고 있습니다."
                     if safe else
                     "AI 에이전트가 외부 메일 속 숨은 지시를 따라 내용을 다른 곳으로 퍼뜨렸습니다."),
    }


def _chain_order(tr):
    adj = {}
    for u, v, _ in tr["edges"]:
        adj.setdefault(u, []).append(v)
    order, seen, queue, i = {}, set(), [tr["origin"]], 0
    while queue:
        n = queue.pop(0)
        if n in seen:
            continue
        seen.add(n); order[n] = i; i += 1
        queue.extend(adj.get(n, []))
    return order


def friendly_incident(db, inc):
    tr = trace.analyze(mcp_server._RoStore(db), inc["source"])
    o = _artifact(db, tr["origin"])
    scope = len(tr["scope"])
    origin_name = (o["location"] if o and o["location"] else tr["origin"][:10])
    return {
        "id": inc["id"], "ts": inc["ts"], "status": inc["status"],
        "title": "자가복제 위협 (웜)", "severity": "높음",
        "origin": origin_name, "scope_count": scope,
        "summary": f"{scope}곳으로 퍼졌습니다. 격리하기 전까지 이 내용을 외부로 보내지 마세요.",
    }


def _creator(db, aid):
    r = db.execute("SELECT agent FROM event WHERE kind='write' AND data LIKE ? "
                   "ORDER BY id LIMIT 1", (f'%"artifact": "{aid}"%',)).fetchone()
    return r["agent"] if r else None


def incident_detail(db, iid):
    inc = db.execute("SELECT * FROM incident WHERE id=?", (iid,)).fetchone()
    if not inc:
        return None
    store = mcp_server._RoStore(db)
    tr = trace.analyze(store, inc["source"])
    order = _chain_order(tr)
    nodes = []
    for aid in tr["scope"]:
        a = _artifact(db, aid)
        kind = (a["kind"] if a and a["kind"] else "file")
        is_origin = aid == tr["origin"]
        by = None if is_origin else _creator(db, aid)
        verb = "포함" if kind == "mail" else "저장"
        nodes.append({
            "id": aid, "name": (a["location"] if a and a["location"] else aid[:10]),
            "kind": kind, "kind_label": KIND_LABEL.get(kind, "항목"),
            "icon": KIND_ICON.get(kind, "file-text"),
            "from_internet": bool(a and a["from_internet"]),
            "infected": bool(a and a["infected"]), "is_origin": is_origin,
            "note": (f"{by}가 {KIND_LABEL.get(kind,'항목')}에 {verb}" if by else None),
        })
    nodes.sort(key=lambda n: order.get(n["id"], 999))
    origin_name = next((n["name"] for n in nodes if n["is_origin"]), "")
    steps = [f"{n['kind_label']} ‘{n['name']}’ 을(를) 격리하거나 삭제하세요." for n in nodes]
    steps.append("외부로 보내기 전에 원본 내용을 사람이 직접 확인하세요.")
    return {
        "id": iid, "ts": inc["ts"], "trace": tr, "nodes": nodes,
        "headline": (f"인터넷에서 들어온 {nodes[0]['kind_label']} ‘{origin_name}’에 숨은 지시가 "
                     f"있었습니다. AI 에이전트가 이 지시를 따라 같은 내용을 다른 곳에 옮겨 적어, "
                     f"총 {len(nodes)}곳으로 퍼졌습니다."),
        "steps": steps,
        "report": report.incident_report(store, inc),
        "timeline": mcp_server.get_timeline(db, iid)["events"],
    }


def _explain(action, verdict, reason):
    if action == "exec" and verdict == "allow":
        return "규칙에 걸리지 않는 일반 작업입니다."
    if "오염" in (reason or "") or (verdict == "ask" and action == "send"):
        return "외부(감염) 내용을 읽은 뒤 외부로 보내려 해서, 허용 대신 확인을 요청했습니다."
    if reason in RULE_EXPLAIN:
        return RULE_EXPLAIN[reason]
    return {"allow": "규칙에 걸리지 않는 일반 작업입니다.",
            "ask": "확인이 필요한 행동입니다.",
            "block": "위험한 행동이라 막았습니다."}.get(verdict, reason or "")


def actions(db):
    """행동 기록: 실행 전 관문이 내린 판정 로그(에이전트 자기보고 'report'는 제외)."""
    out = []
    for r in db.execute("SELECT * FROM event WHERE kind='verdict' ORDER BY id DESC"):
        d = json.loads(r["data"])
        act = d.get("action")
        if act not in ACTION_LABEL:          # report 등은 행동 로그에서 제외
            continue
        v = d.get("verdict")
        out.append({
            "ts": r["ts"], "agent": r["agent"],
            "action": act, "action_label": ACTION_LABEL[act],
            "content": d.get("content", ""),
            "verdict": v, "verdict_label": VERDICT_LABEL.get(v, v),
            "explain": _explain(act, v, d.get("reason")),
        })
    return out


def integrity(db):
    """기록 무결성: 해시 사슬 검증 + '말과 기록 불일치'(에이전트 보고 vs Sysmon)."""
    ok, broken = _verify_chain(db)
    total = _count(db, "SELECT COUNT(*) FROM event")
    mismatches = []
    reports = [r for r in db.execute("SELECT * FROM event WHERE kind='verdict'")
               if json.loads(r["data"]).get("action") == "report"]
    for r in reports:
        sess = r["session"]
        os_evs = db.execute("SELECT * FROM event WHERE kind='os_event' AND session=?",
                            (sess,)).fetchall()
        for oe in os_evs:
            od = json.loads(oe["data"])
            mismatches.append({
                "session": sess, "agent": r["agent"],
                "report": json.loads(r["data"]).get("reason", ""),
                "os_title": "컴퓨터 시작 시 자동 실행 항목이 등록됨"
                            if od.get("event_id") == 13 else "시스템 변경 기록",
                "os_detail": (od.get("detail") if isinstance(od.get("detail"), str)
                              else od.get("detail", {}).get("TargetObject")
                              or f"Sysmon 이벤트 {od.get('event_id')}"),
                "os_event_id": od.get("event_id"),
            })
    return {"ok": ok, "broken": broken, "total": total, "mismatches": mismatches}


def _verify_chain(db):
    """읽기 전용 연결로 해시 체인 검증(Store.verify_chain과 동일 로직)."""
    import hashlib
    prev = "0" * 64
    for r in db.execute("SELECT * FROM event ORDER BY id"):
        h = hashlib.sha256(
            f"{prev}|{r['ts']}|{r['kind']}|{r['session']}|{r['agent']}|{r['data']}".encode()
        ).hexdigest()
        if h != r["hash"] or r["prev_hash"] != prev:
            return False, r["id"]
        prev = h
    return True, None


# --- 로고 (방패 + 노드 그래프), 라이트/다크 공용 ---
LOGO_SVG = ('<svg viewBox="0 0 64 64" class="logo" aria-hidden="true">'
            '<path d="M32 4 L54 12 V31 C54 44 44 54 32 60 C20 54 10 44 10 31 V12 Z" '
            'fill="var(--brand)"/>'
            '<circle cx="32" cy="24" r="4.5" fill="#fff"/>'
            '<circle cx="22" cy="41" r="4.5" fill="#fff"/>'
            '<circle cx="42" cy="41" r="4.5" fill="#fff"/>'
            '<path d="M32 24 L22 41 M32 24 L42 41" stroke="#fff" stroke-width="3" '
            'stroke-linecap="round"/></svg>')


# Lucide 아이콘(ISC 라이선스) inner SVG를 인라인, 오프라인/단일파일 유지
ICONS = {"arrow-right": "<path d=\"M5 12h14\" /> <path d=\"m12 5 7 7-7 7\" />", "bell": "<path d=\"M10.268 21a2 2 0 0 0 3.464 0\" /> <path d=\"M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326\" />", "circle-check": "<circle cx=\"12\" cy=\"12\" r=\"10\" /> <path d=\"m16 9-5.5 5.5L8 12\" />", "circle-help": "<circle cx=\"12\" cy=\"12\" r=\"10\" /> <path d=\"M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3\" /> <path d=\"M12 17h.01\" />", "clock": "<circle cx=\"12\" cy=\"12\" r=\"10\" /> <path d=\"M12 6v6l4 2\" />", "database": "<ellipse cx=\"12\" cy=\"5\" rx=\"9\" ry=\"3\" /> <path d=\"M3 5V19A9 3 0 0 0 21 19V5\" /> <path d=\"M3 12A9 3 0 0 0 21 12\" />", "download": "<path d=\"M12 15V3\" /> <path d=\"M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4\" /> <path d=\"m7 10 5 5 5-5\" />", "file-check": "<path d=\"M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z\" /> <path d=\"M14 2v5a1 1 0 0 0 1 1h5\" /> <path d=\"m9 15 2 2 4-4\" />", "file-text": "<path d=\"M6 22a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h8a2.4 2.4 0 0 1 1.704.706l3.588 3.588A2.4 2.4 0 0 1 20 8v12a2 2 0 0 1-2 2z\" /> <path d=\"M14 2v5a1 1 0 0 0 1 1h5\" /> <path d=\"M10 9H8\" /> <path d=\"M16 13H8\" /> <path d=\"M16 17H8\" />", "git-branch": "<path d=\"M15 6a9 9 0 0 0-9 9V3\" /> <circle cx=\"18\" cy=\"6\" r=\"3\" /> <circle cx=\"6\" cy=\"18\" r=\"3\" />", "layout-dashboard": "<rect width=\"7\" height=\"9\" x=\"3\" y=\"3\" rx=\"1\" /> <rect width=\"7\" height=\"5\" x=\"14\" y=\"3\" rx=\"1\" /> <rect width=\"7\" height=\"9\" x=\"14\" y=\"12\" rx=\"1\" /> <rect width=\"7\" height=\"5\" x=\"3\" y=\"16\" rx=\"1\" />", "link": "<path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\" /> <path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\" />", "lock-keyhole": "<circle cx=\"12\" cy=\"16\" r=\"1\" /> <rect x=\"3\" y=\"10\" width=\"18\" height=\"12\" rx=\"2\" /> <path d=\"M7 10V7a5 5 0 0 1 10 0v3\" />", "lock": "<rect width=\"18\" height=\"11\" x=\"3\" y=\"11\" rx=\"2\" ry=\"2\" /> <path d=\"M7 11V7a5 5 0 0 1 10 0v4\" />", "mail": "<path d=\"m22 7-8.991 5.727a2 2 0 0 1-2.009 0L2 7\" /> <rect x=\"2\" y=\"4\" width=\"20\" height=\"16\" rx=\"2\" />", "message-square": "<path d=\"M22 17a2 2 0 0 1-2 2H6.828a2 2 0 0 0-1.414.586l-2.202 2.202A.71.71 0 0 1 2 21.286V5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2z\" />", "plus": "<path d=\"M5 12h14\" /> <path d=\"M12 5v14\" />", "scroll-text": "<path d=\"M15 12h-5\" /> <path d=\"M15 8h-5\" /> <path d=\"M19 17V5a2 2 0 0 0-2-2H4\" /> <path d=\"M8 21h12a2 2 0 0 0 2-2v-1a1 1 0 0 0-1-1H11a1 1 0 0 0-1 1v1a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v2a1 1 0 0 0 1 1h3\" />", "search": "<path d=\"m21 21-4.34-4.34\" /> <circle cx=\"11\" cy=\"11\" r=\"8\" />", "settings": "<path d=\"M9.671 4.136a2.34 2.34 0 0 1 4.659 0 2.34 2.34 0 0 0 3.319 1.915 2.34 2.34 0 0 1 2.33 4.033 2.34 2.34 0 0 0 0 3.831 2.34 2.34 0 0 1-2.33 4.033 2.34 2.34 0 0 0-3.319 1.915 2.34 2.34 0 0 1-4.659 0 2.34 2.34 0 0 0-3.32-1.915 2.34 2.34 0 0 1-2.33-4.033 2.34 2.34 0 0 0 0-3.831A2.34 2.34 0 0 1 6.35 6.051a2.34 2.34 0 0 0 3.319-1.915\" /> <circle cx=\"12\" cy=\"12\" r=\"3\" />", "shield-alert": "<path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\" /> <path d=\"M12 8v4\" /> <path d=\"M12 16h.01\" />", "shield-check": "<path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\" /> <path d=\"m9 12 2 2 4-4\" />", "shield": "<path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\" />", "triangle-alert": "<path d=\"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3\" /> <path d=\"M12 9v4\" /> <path d=\"M12 17h.01\" />", "wifi-off": "<path d=\"M12 20h.01\" /> <path d=\"M8.5 16.429a5 5 0 0 1 7 0\" /> <path d=\"M5 12.859a10 10 0 0 1 5.17-2.69\" /> <path d=\"M19 12.859a10 10 0 0 0-2.007-1.523\" /> <path d=\"M2 8.82a15 15 0 0 1 4.177-2.643\" /> <path d=\"M22 8.82a15 15 0 0 0-11.288-3.764\" /> <path d=\"m2 2 20 20\" />"}


PAGE = r"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentTrace</title>
<style>
__FONTS__
:root{
 --bg:#eef0f3; --surface:#ffffff; --surface2:#f4f6f8; --line:#e4e7ec;
 --fg:#111827; --mut:#6b7280; --brand:#2563eb; --brand-ink:#1d4ed8;
 --danger:#dc2626; --danger-bg:#fef2f2; --warn:#d97706; --warn-bg:#fffbeb;
 --safe:#16a34a; --safe-bg:#f0fdf4; --origin:#ea7a0c; --origin-bg:#fff7ed;
 --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08);
 --radius:12px;
}
@media (prefers-color-scheme:dark){:root{
 --bg:#0d0f13; --surface:#161922; --surface2:#1d212b; --line:#2a2f3a;
 --fg:#e8eaed; --mut:#9aa3b2; --brand:#5b8def; --brand-ink:#7aa5f5;
 --danger:#f0685f; --danger-bg:#2a1718; --warn:#e0a458; --warn-bg:#2a2215;
 --safe:#5bbf7a; --safe-bg:#132018; --origin:#e0a458; --origin-bg:#2a2215;
 --shadow:0 1px 3px rgba(0,0,0,.35);
}}
*{box-sizing:border-box}
.licon{vertical-align:-.18em;flex:none}
body{margin:0;background:var(--bg);color:var(--fg);
 font:15px/1.6 'IBM Plex Sans KR',"Pretendard",system-ui,"Malgun Gothic",sans-serif}
.app{display:grid;grid-template-columns:232px 1fr;min-height:100vh}
/* sidebar */
aside{background:var(--surface);border-right:1px solid var(--line);
 display:flex;flex-direction:column;padding:16px 12px;gap:8px}
.brand{display:flex;align-items:center;gap:9px;padding:6px 8px 10px}
.logo{width:28px;height:28px}
.brand b{font-size:16px} .brand b span{color:var(--brand)}
.brand small{display:block;color:var(--mut);font-size:11px;font-weight:400}
.statusshield{display:flex;flex-direction:column;align-items:center;gap:6px;
 padding:14px 0 10px}
.statusshield .big{width:76px;height:76px;border-radius:18px;display:flex;
 align-items:center;justify-content:center;font-size:40px}
.statusshield.threat .big{background:var(--danger-bg);color:var(--danger)}
.statusshield.safe .big{background:var(--safe-bg);color:var(--safe)}
nav{display:flex;flex-direction:column;gap:2px;margin-top:4px}
.navitem{display:flex;align-items:center;gap:11px;padding:10px 12px;border-radius:9px;
 cursor:pointer;color:var(--fg);font-weight:500}
.navitem:hover{background:var(--surface2)}
.navitem.on{background:#eaf1fe;color:var(--brand-ink)}
@media (prefers-color-scheme:dark){.navitem.on{background:#1b2740;color:var(--brand-ink)}}
.navitem .i{width:20px;text-align:center}
.navitem .badge{margin-left:auto;background:var(--danger);color:#fff;font-size:11px;
 font-weight:700;border-radius:999px;padding:1px 7px}
/* topbar */
main{display:flex;flex-direction:column;min-width:0}
.topbar{display:flex;align-items:center;justify-content:flex-end;gap:10px;
 padding:12px 24px;border-bottom:1px solid var(--line);background:var(--surface)}
.offline{display:inline-flex;align-items:center;gap:7px;background:var(--surface2);
 border:1px solid var(--line);border-radius:999px;padding:6px 13px;font-size:13px;color:var(--mut)}
.offline .dot{width:8px;height:8px;border-radius:50%;background:var(--safe)}
.help{width:30px;height:30px;border-radius:50%;border:1px solid var(--line);
 background:var(--surface2);color:var(--mut);display:flex;align-items:center;justify-content:center}
.content{padding:28px 32px;max-width:1120px;width:100%;overflow:auto}
/* generic */
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
 box-shadow:var(--shadow);padding:20px}
h1.page{font-size:34px;font-weight:800;margin:0 0 6px}
.sub{color:var(--mut);font-size:16px;margin:0}
.kpirow{display:flex;gap:26px}
.kpirow .k{text-align:center} .kpirow .k b{font-size:30px;display:block;line-height:1.1}
.kpirow .k.red b{color:var(--danger)} .kpirow .k.amber b{color:var(--warn)}
.kpirow .k.blue b{color:var(--brand)} .kpirow .k span{color:var(--mut);font-size:13px}
.headrow{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;
 flex-wrap:wrap;margin-bottom:22px}
.btn{border:0;border-radius:9px;padding:11px 20px;font-weight:700;font-size:15px;
 cursor:pointer;font-family:inherit}
.btn.primary{background:var(--brand);color:#fff}
.btn.danger{background:var(--danger);color:#fff}
.btn.ghost{background:var(--surface);border:1px solid var(--line);color:var(--fg)}
.linkbtn{background:0;border:0;color:var(--brand-ink);font-weight:700;cursor:pointer;
 font-family:inherit;font-size:15px}
.feature{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:18px}
.feature .t{font-size:18px;font-weight:700;display:flex;align-items:center;gap:9px;margin-bottom:6px}
.feature .t .ic{width:30px;height:30px;border-radius:50%;background:var(--danger-bg);
 color:var(--danger);display:flex;align-items:center;justify-content:center}
.feature .m{color:var(--fg)} .feature .meta{color:var(--mut);font-size:13px;margin-top:8px}
.feature .right{text-align:center;display:flex;flex-direction:column;gap:8px;align-items:center}
.tiles{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-top:18px}
.tile{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
 box-shadow:var(--shadow);padding:22px;text-align:center;cursor:pointer}
.tile:hover{border-color:var(--brand)}
.tile.add{border-style:dashed;box-shadow:none}
.tile .ic{width:58px;height:58px;border-radius:50%;background:#eaf1fe;color:var(--brand);
 display:flex;align-items:center;justify-content:center;font-size:26px;margin:0 auto 12px}
@media (prefers-color-scheme:dark){.tile .ic{background:#1b2740}}
.tile b{display:block;font-size:15px} .tile span{color:var(--mut);font-size:13px}
.foot{display:flex;align-items:center;gap:8px;color:var(--mut);font-size:14px;margin-top:20px}
/* threat detail */
.badge{display:inline-flex;align-items:center;gap:5px;font-size:12px;font-weight:700;
 padding:4px 11px;border-radius:999px}
.badge.high{background:var(--danger-bg);color:var(--danger)}
.flow{display:flex;align-items:stretch;gap:0;overflow-x:auto;padding:4px 2px 6px}
.fnode{min-width:180px;background:var(--surface);border:2px solid var(--line);
 border-radius:12px;padding:14px 16px;flex:0 0 auto}
.fnode.infected{border-color:var(--danger)}
.fnode.origin{border-color:var(--origin);background:var(--origin-bg)}
.fnode .k{font-size:12px;color:var(--mut)} .fnode .nm{font-weight:700;font-family:'IBM Plex Mono',ui-monospace,monospace;
 font-size:14px;word-break:break-all;margin:3px 0 8px}
.chip{display:inline-block;font-size:11px;font-weight:700;padding:3px 9px;border-radius:999px;margin-right:4px}
.chip.start{background:var(--origin-bg);color:var(--origin)}
.chip.net{background:var(--warn-bg);color:var(--warn)}
.chip.inf{background:var(--danger-bg);color:var(--danger)}
.arrow{display:flex;flex-direction:column;align-items:center;justify-content:center;
 padding:0 14px;min-width:120px;text-align:center}
.arrow .a{font-size:24px;color:var(--danger)}
.arrow .s{font-weight:700;font-size:13px;margin-top:4px}
.arrow .n{color:var(--mut);font-size:12px}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
ul.steps{list-style:none;margin:0;padding:0}
ul.steps li{display:flex;gap:11px;padding:11px 0;border-bottom:1px solid var(--line)}
ul.steps li:last-child{border-bottom:0}
ul.steps input{width:20px;height:20px;margin:2px 0 0;accent-color:var(--brand);cursor:pointer}
ul.steps li.done label{text-decoration:line-through;color:var(--mut)}
.tabs{display:inline-flex;background:var(--surface2);border-radius:9px;padding:3px;gap:2px;margin-bottom:12px}
.tabs button{border:0;background:0;padding:7px 14px;border-radius:7px;cursor:pointer;
 font-weight:600;color:var(--mut);font-family:inherit}
.tabs button.on{background:var(--surface);color:var(--fg);box-shadow:var(--shadow)}
details{background:var(--surface2);border:1px solid var(--line);border-radius:10px;padding:0 16px;margin-top:16px}
details summary{cursor:pointer;padding:13px 0;font-weight:600;color:var(--mut)}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut)} code{font-family:'IBM Plex Mono',ui-monospace,monospace;background:var(--surface2);
 padding:2px 6px;border-radius:5px;font-size:13px}
.note{color:var(--warn);font-size:13px;margin:10px 0 4px}
.rep ul{margin:4px 0;padding-left:20px}
/* actions log */
.act{border-bottom:1px solid var(--line);padding:16px 0}
.act:last-child{border-bottom:0}
.act .r1{display:flex;align-items:center;gap:12px}
.act .time{color:var(--mut);font-size:13px;font-variant-numeric:tabular-nums;min-width:66px}
.act .who{color:var(--mut);font-size:13px;min-width:60px}
.act .what{font-weight:700} .act .v{margin-left:auto}
.v.allow{color:var(--safe);background:var(--safe-bg)} .v.ask{color:var(--warn);background:var(--warn-bg)}
.v.block{color:var(--danger);background:var(--danger-bg)}
.act .cmd{margin:8px 0 0 78px} .act .ex{color:var(--mut);font-size:14px;margin:6px 0 0 78px}
.act .btns{margin:10px 0 0 78px;display:flex;gap:8px}
.filters{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.filters button{border:1px solid var(--line);background:var(--surface);border-radius:999px;
 padding:7px 16px;cursor:pointer;font-weight:600;font-family:inherit;color:var(--fg)}
.filters button.on{background:var(--brand);color:#fff;border-color:var(--brand)}
.ruleblk{border-radius:10px;padding:4px 0 8px}
.ruletag{display:inline-block;font-weight:700;font-size:13px;padding:4px 12px;border-radius:999px;margin:12px 0 6px}
/* integrity */
.chain{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 6px}
.chain .b{width:42px;height:42px;border-radius:9px;display:flex;align-items:center;
 justify-content:center;font-weight:700;background:var(--safe-bg);color:var(--safe)}
.chain .b.bad{background:var(--danger-bg);color:var(--danger)}
.legend{color:var(--mut);font-size:13px;display:flex;gap:16px}
.legend i{width:12px;height:12px;border-radius:3px;display:inline-block;margin-right:5px;vertical-align:-1px}
.mm{display:grid;grid-template-columns:1fr auto 1fr;gap:14px;align-items:center;margin:12px 0}
.mm .box{background:var(--surface2);border:1px solid var(--line);border-radius:10px;padding:14px}
.mm .box .lab{color:var(--mut);font-size:12px} .mm .neq{font-size:26px;color:var(--warn);text-align:center}
.pagehead{display:flex;align-items:center;gap:14px;margin-bottom:8px}
.pagehead .ic{width:46px;height:46px;border-radius:50%;display:flex;align-items:center;
 justify-content:center;font-size:24px}
.pagehead .ic.ok{background:var(--safe-bg);color:var(--safe)}
.pagehead .ic.warn{background:var(--warn-bg);color:var(--warn)}
.back{background:0;border:0;color:var(--brand-ink);font-weight:700;cursor:pointer;
 font-family:inherit;margin-bottom:10px;font-size:15px}
.mut{color:var(--mut)}
@media (max-width:860px){.app{grid-template-columns:1fr}aside{display:none}
 .grid2{grid-template-columns:1fr}.tiles{grid-template-columns:1fr 1fr}.mm{grid-template-columns:1fr}}
</style></head><body>
<div class="app">
 <aside>
  <div class="brand">__LOGO__<b>Agent<span>Trace</span><small>개인용 에이전트 보안</small></b></div>
  <div class="statusshield" id="shield"><div class="big"></div></div>
  <nav id="nav"></nav>
 </aside>
 <main>
  <div class="topbar">
   <span class="offline"><span class="dot"></span>오프라인, 이 PC 안에서만 동작</span>
   <span class="help"><svg class="licon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><path d="M12 17h.01"/></svg></span>
  </div>
  <div class="content" id="view"></div>
 </main>
</div>
<script>
const $=s=>document.querySelector(s);
const j=async u=>(await fetch(u)).json();
const esc=s=>String(s==null?'':s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const hhmmss=ts=>new Date(ts*1000).toLocaleTimeString('ko-KR',{hour12:false});
const when=ts=>new Date(ts*1000).toLocaleString('ko-KR',{hour12:false});
let SUM={};
const ICONS=__ICONS__;
const ic=(n,s=20)=>`<svg class="licon" width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[n]||''}</svg>`;
const kindIcon=k=>({file:'file-text',mail:'mail',message:'message-square',memory:'database'}[k]||'file-text');

const NAV=[['dashboard','layout-dashboard','대시보드'],['threats','shield-alert','위협'],
 ['actions','scroll-text','행동 기록'],['integrity','link','기록 무결성'],['settings','settings','설정']];
let route='dashboard', curIncident=null;

function renderNav(){
 $('#nav').innerHTML=NAV.map(([k,icn,l])=>{
  const b=(k==='threats'&&SUM.threats)?`<span class="badge">${SUM.threats}</span>`:'';
  return `<div class="navitem ${k===route?'on':''}" data-k="${k}"><span class="i">${ic(icn,20)}</span>${l}${b}</div>`;
 }).join('');
 $('#nav').querySelectorAll('.navitem').forEach(n=>n.onclick=()=>go(n.dataset.k));
 const sh=$('#shield'); sh.className='statusshield '+(SUM.state||'safe');
 sh.querySelector('.big').innerHTML=ic(SUM.state==='safe'?'shield-check':'shield-alert',40);
}
async function refreshSummary(){ SUM=await j('/api/summary'); renderNav(); }
function go(k){ route=k; curIncident=null; renderNav(); render(); }

async function render(){
 const v=$('#view');
 if(route==='dashboard')      return v.innerHTML=await dashboard();
 if(route==='threats')        return curIncident?detail(curIncident):(v.innerHTML=await threats());
 if(route==='actions')        return v.innerHTML=await actions();
 if(route==='integrity')      return v.innerHTML=await integrity();
 if(route==='settings')       return v.innerHTML=settings();
}

/* ---- 대시보드 ---- */
async function dashboard(){
 const s=SUM;
 const kpi=`<div class="kpirow">
  <div class="k red"><b>${s.threats}</b><span>발견된 위협</span></div>
  <div class="k blue"><b>${s.blocked}</b><span>막은 행동</span></div>
  <div class="k red"><b>${s.infected}</b><span>감염된 항목</span></div>
  <div class="k amber"><b>${s.review}</b><span>확인 필요</span></div></div>`;
 let feature;
 if(s.state==='safe'){
  feature=`<div class="card"><div class="feature"><div>
   <div class="t"><span class="ic" style="background:var(--safe-bg);color:var(--safe)">${ic('lock-keyhole',18)}</span>Claude에게 직접 물어보세요</div>
   <div class="m">읽기 전용 MCP 서버를 연결하면 Claude에서 ‘이번 주에 위협 있었어?’처럼 물어볼 수 있습니다. 기록은 바뀌지 않습니다.</div>
   <div class="meta">추천, 설정 2분</div></div>
   <div class="right"><button class="btn primary" onclick="go('settings')">방법 보기</button>
   <button class="linkbtn">나중에</button></div></div></div>`;
 }else{
  const inc=(await j('/api/incidents')).incidents[0];
  feature=`<div class="card"><div class="feature"><div>
   <div class="t"><span class="ic">${ic('shield-alert',18)}</span>${esc(inc.title)}, ${esc(inc.origin)}에서 시작</div>
   <div class="m">${esc(inc.summary)}</div>
   <div class="meta">사건 #${inc.id}, ${when(inc.ts)}, 심각도 ${esc(inc.severity)}</div></div>
   <div class="right"><button class="btn primary" onclick="openIncident(${inc.id})">자세히 보기</button>
   <button class="linkbtn">나중에</button></div></div></div>`;
 }
 const tiles=[['search','빠른 점검','기록을 처음부터 다시 분석','go("threats")'],
  ['git-branch','역추적','최초 감염원과 퍼진 범위','go("threats")'],
  ['link','기록 무결성 검사','기록이 고쳐졌는지 확인','go("integrity")'],
  ['scroll-text','행동 기록','막거나 확인한 행동 보기','go("actions")'],
  ['download','Windows 기록 수집','Sysmon에서 새 기록 가져오기','alert("Sysmon이 설치돼 있으면 트레이 앱이 주기적으로 수집합니다.")'],
  ['plus','빠른 작업 추가','자주 쓰는 기능 고정','']];
 const tileHtml=tiles.map(([icn,t,d,act],i)=>`<div class="tile ${i===5?'add':''}" ${act?`onclick='${act}'`:''}>
  <div class="ic">${ic(icn,26)}</div><b>${t}</b><span>${d}</span></div>`).join('');
 return `<div class="headrow"><div><h1 class="page">${esc(s.headline)}</h1>
   <p class="sub">${esc(s.subtitle)}</p></div>${kpi}</div>
  ${feature}<div class="tiles">${tileHtml}</div>
  <div class="foot">${ic('file-check',16)} 저장된 기록 ${s.records}건이 변조 없이 보관되어 있습니다.
   <button class="linkbtn" onclick="go('integrity')">기록 무결성 보기</button></div>`;
}
window.openIncident=async id=>{ route='threats'; curIncident=id; renderNav(); detail(id); };

/* ---- 위협 목록 ---- */
async function threats(){
 const d=await j('/api/incidents');
 if(!d.incidents.length) return `<h1 class="page">위협</h1><div class="card mut">발견된 위협이 없습니다. 안전합니다. ${ic('circle-check',16)}</div>`;
 const cards=d.incidents.map(i=>`<div class="card" style="margin-bottom:12px;cursor:pointer" onclick="openIncident(${i.id})">
  <div class="feature" style="margin:0"><div>
   <div class="t"><span class="ic">${ic('shield-alert',18)}</span>${esc(i.title)}</div>
   <div class="m">${esc(i.origin)}에서 시작, ${esc(i.summary)}</div>
   <div class="meta">사건 #${i.id}, ${when(i.ts)}</div></div>
   <span class="badge high">심각도 ${esc(i.severity)}</span></div></div>`).join('');
 return `<h1 class="page">위협</h1><p class="sub">발견된 자가복제 전파 위협입니다.</p><div style="margin-top:18px">${cards}</div>`;
}

/* ---- 위협 상세 ---- */
async function detail(id){
 const d=await j('/api/incident/'+id);
 const emap={}; d.trace.edges.forEach(e=>emap[e[0]+'>'+e[1]]=e[2]);
 let flow='<div class="flow">';
 d.nodes.forEach((n,i)=>{
  if(i>0){ const s=emap[d.nodes[i-1].id+'>'+n.id];
   flow+=`<div class="arrow"><div class="a">${ic('arrow-right',24)}</div>${s?`<div class="s">닮음 ${Math.round(s*100)}%</div>`:''}
    ${n.note?`<div class="n">${esc(n.note)}</div>`:''}</div>`; }
  let chips=''; if(n.is_origin)chips+='<span class="chip start">시작점</span>';
  if(n.from_internet)chips+='<span class="chip net">인터넷에서 들어옴</span>';
  if(n.infected)chips+='<span class="chip inf">감염</span>';
  flow+=`<div class="fnode ${n.is_origin?'origin':''} ${n.infected?'infected':''}">
   <div class="k">${ic(n.icon,16)} ${esc(n.kind_label)}</div><div class="nm">${esc(n.name)}</div>${chips}</div>`;
 });
 flow+='</div>';
 const steps=d.steps.map((s,i)=>`<li><input type="checkbox" id="st${i}"
  onchange="this.closest('li').classList.toggle('done',this.checked);upd()">
  <label for="st${i}">${esc(s)}</label></li>`).join('');
 const R=d.report, keys=Object.keys(R);
 const tabs=keys.map((k,i)=>`<button class="${i===0?'on':''}" onclick="jtab(this,${i})">${esc(k)}</button>`).join('');
 const panes=keys.map((k,i)=>`<ul class="rp" data-i="${i}" style="${i?'display:none':''}">${R[k].map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`).join('');
 const tl=d.timeline.map(e=>`<tr><td>${e.id}</td><td>${hhmmss(e.ts)}</td><td>${esc(e.kind)}</td>
  <td>${esc(e.session||'')} / ${esc(e.agent||'')}</td><td>${esc(e.data)}</td></tr>`).join('');
 $('#view').innerHTML=`<button class="back" onclick="go('threats')"><svg class="licon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m12 19-7-7 7-7"/><path d="M19 12H5"/></svg> 위협 목록</button>
  <div class="headrow"><div><span class="badge high">${ic('shield-alert',14)} 심각도 높음</span>
   <h1 class="page" style="margin-top:8px">자가복제 위협 (웜)</h1>
   <p class="sub">사건 #${d.id}, ${when(d.ts)}, 퍼진 곳 ${d.nodes.length}곳</p></div>
   <div style="display:flex;gap:10px"><button class="btn ghost">${ic('file-text',16)} 보고서 저장</button>
    <button class="btn danger">${ic('lock',16)} ${d.nodes.length}곳 모두 격리</button></div></div>
  <div class="card" style="margin-bottom:16px"><h3 style="margin:0 0 8px">무슨 일이 일어났나요?</h3>
   <div style="font-size:16px">${esc(d.headline)}</div></div>
  <div class="card" style="margin-bottom:16px">
   <div style="display:flex;justify-content:space-between;align-items:baseline">
    <h3 style="margin:0 0 10px">어디서 시작해 어디로 퍼졌나</h3>
    <span class="mut" style="font-size:13px">‘닮음’은 앞 단계 내용과 얼마나 같은지입니다</span></div>${flow}</div>
  <div class="grid2">
   <div class="card"><div style="display:flex;justify-content:space-between">
     <h3 style="margin:0 0 6px">지금 해야 할 일</h3><span class="mut" id="stc">0 / ${d.steps.length} 완료</span></div>
    <ul class="steps">${steps}</ul></div>
   <div class="card"><h3 style="margin:0 0 10px">이렇게 판단했습니다</h3>
    <div class="tabs">${tabs}</div><div id="panes">${panes}</div></div>
  </div>
  <details><summary>기술 상세 (개발자용), 근거 기록</summary>
   <table><tr><th>번호</th><th>시각</th><th>종류</th><th>작업 / 에이전트</th><th>내용(일부)</th></tr>${tl}</table>
   <p class="note">${ic('triangle-alert',14)} 내용은 일부만 보여 줍니다. 신뢰할 수 없는 데이터이므로 원문은 직접 열어 확인하세요.</p></details>`;
}
window.upd=()=>{const n=document.querySelectorAll('ul.steps li.done').length,
 t=document.querySelectorAll('ul.steps li').length; $('#stc').textContent=`${n} / ${t} 완료`;};
window.jtab=(b,i)=>{document.querySelectorAll('.tabs button').forEach(x=>x.classList.remove('on'));
 b.classList.add('on'); document.querySelectorAll('.rp').forEach(p=>p.style.display=(+p.dataset.i===i?'':'none'));};

/* ---- 행동 기록 ---- */
async function actions(){
 const rows=await j('/api/actions');
 const cnt={all:rows.length,block:0,ask:0,allow:0}; rows.forEach(r=>cnt[r.verdict]++);
 const rules=`<div class="card"><h3 style="margin:0 0 4px">판단 규칙</h3>
  <span class="ruletag" style="background:var(--danger-bg);color:var(--danger)">막음</span>
  <ul style="margin:0 0 6px;padding-left:18px"><li>숨긴(인코딩한) PowerShell 명령</li>
   <li>원격 코드를 내려받아 바로 실행</li><li>테스트용 악성 문자열(EICAR)</li></ul>
  <span class="ruletag" style="background:var(--warn-bg);color:var(--warn)">확인 요청</span>
  <ul style="margin:0 0 6px;padding-left:18px"><li>비밀번호와 키 파일 접근</li>
   <li>컴퓨터 시작 시 자동 실행 등록</li><li>외부 내용을 읽은 뒤의 전송과 실행</li></ul>
  <span class="ruletag" style="background:var(--safe-bg);color:var(--safe)">허용</span>
  <ul style="margin:0;padding-left:18px"><li>위에 해당하지 않는 행동</li></ul>
  <p class="mut" style="font-size:13px;margin:10px 0 0">규칙 파일 <code>policy.yaml</code></p></div>`;
 const list=rows.map(r=>`<div class="act" data-v="${r.verdict}">
  <div class="r1"><span class="time">${hhmmss(r.ts)}</span><span class="who">${esc(r.agent)}</span>
   <span class="what">${esc(r.action_label)}</span>
   <span class="badge v ${r.verdict}">${esc(r.verdict_label)}</span></div>
  <div class="cmd"><code>${esc(r.content)}</code></div>
  <div class="ex">${esc(r.explain)}</div>
  ${r.verdict==='ask'?`<div class="btns"><button class="btn ghost">한 번 허용</button><button class="btn danger">막기</button></div>`:''}</div>`).join('');
 return `<h1 class="page">행동 기록</h1>
  <p class="sub">AI 에이전트가 하려던 행동과 AgentTrace의 판단입니다. 위험한 행동은 실행되기 전에 막습니다.</p>
  <div class="filters" style="margin-top:16px">
   <button class="on" onclick="fAct(this,'all')">전체 ${cnt.all}</button>
   <button onclick="fAct(this,'block')">막음 ${cnt.block}</button>
   <button onclick="fAct(this,'ask')">확인 필요 ${cnt.ask}</button>
   <button onclick="fAct(this,'allow')">허용 ${cnt.allow}</button></div>
  <div class="grid2" style="grid-template-columns:1fr 320px;align-items:start">
   <div class="card" id="actlist">${list||'<span class="mut">행동 기록이 없습니다.</span>'}</div>${rules}</div>`;
}
window.fAct=(b,f)=>{document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('on'));
 b.classList.add('on'); document.querySelectorAll('#actlist .act').forEach(a=>
  a.style.display=(f==='all'||a.dataset.v===f)?'':'none');};

/* ---- 기록 무결성 ---- */
async function integrity(){
 const d=await j('/api/integrity');
 let chain='<div class="chain">';
 for(let i=1;i<=d.total;i++){const bad=!d.ok&&d.broken&&i>=d.broken;
  chain+=`<div class="b ${bad?'bad':''}">${i}</div>`;}
 chain+='</div>';
 const okHead=d.ok?['ok','circle-check','기록이 변조되지 않았습니다']:['warn','triangle-alert','기록이 변조되었습니다'];
 const mm=d.mismatches.map(m=>`<div style="margin:8px 0">
  <div class="mm"><div class="box"><div class="lab">Windows 시스템 기록, Sysmon 이벤트 ${esc(m.os_event_id)}</div>
    <b>${esc(m.os_title)}</b><div><code>${esc(m.os_detail)}</code></div></div>
   <div class="neq">≠</div>
   <div class="box"><div class="lab">에이전트의 보고, ${esc(m.agent)}</div>
    <b>“${esc(m.report)}”</b></div></div>
  <p class="mut">에이전트가 실행 전 관문을 거치지 않고 시스템을 바꾼 뒤, 사실과 다르게 보고했을 수 있습니다.</p>
  <div style="display:flex;gap:12px"><button class="btn primary">자동 실행 항목 확인</button>
   <button class="linkbtn">문제없음으로 표시</button></div></div>`).join('');
 const mmCard=d.mismatches.length?`<div class="card" style="margin-top:16px;border-color:var(--warn)">
  <h3 style="margin:0 0 4px">${ic('triangle-alert',18)} 말과 기록이 다른 곳이 ${d.mismatches.length}건 있습니다</h3>${mm}</div>`:'';
 return `<div class="pagehead"><span class="ic ${okHead[0]}">${ic(okHead[1],24)}</span>
   <div><h1 class="page" style="margin:0">${okHead[2]}</h1>
   <p class="sub">저장된 기록 ${d.total}건을 모두 검사했습니다.</p></div></div>
  <div class="card" style="margin-top:14px">
   <div style="display:flex;justify-content:space-between;align-items:baseline">
    <h3 style="margin:0">기록 사슬</h3>
    <span class="mut" style="font-size:13px">각 기록이 앞 기록의 지문을 품고 있어, 하나라도 고치면 그 자리부터 끊어집니다</span></div>
   ${chain}<div class="legend"><span><i style="background:var(--safe-bg)"></i>정상</span>
    <span><i style="background:var(--danger-bg)"></i>변조됨 ${d.ok?'(없음)':''}</span></div></div>${mmCard}`;
}

/* ---- 설정 ---- */
function settings(){
 return `<h1 class="page">설정</h1><p class="sub">이 PC 안에서만 동작하는 개인용 보안 도구입니다.</p>
  <div class="card" style="margin-top:18px"><h3 style="margin:0 0 10px">실행</h3>
   <p>상시 감시는 트레이 앱으로 켭니다: <code>pythonw -m agenttrace.monitor_app</code> 또는 <code>start_monitor.bat</code>.</p>
   <p class="mut">트레이 아이콘 우클릭하면 <b>Windows 시작 시 자동 실행</b> 토글(관리자 권한 불필요).</p></div>
  <div class="card" style="margin-top:14px"><h3 style="margin:0 0 10px">Claude 연결 (읽기 전용 MCP)</h3>
   <p><code>pip install mcp</code> 후 <code>python -m agenttrace.mcp_server &lt;db&gt;</code> 를 Claude Desktop/Code에 stdio로 연결하면 ‘이번 주 위협 있었어?’처럼 물어볼 수 있습니다. 기록은 바뀌지 않습니다.</p></div>
  <div class="card" style="margin-top:14px"><h3 style="margin:0 0 10px">데이터</h3>
   <p class="mut">기록은 이 PC의 <code>내 사용자 폴더\AgentTrace\agenttrace.db</code> 에만 저장됩니다. 외부 전송 없음.</p></div>`;
}

(async()=>{ await refreshSummary(); render(); })();
</script></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    db_path = None

    def _send(self, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else body.encode()
        self.send_response(200)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p == "/":
            return self._send(PAGE, "text/html")
        db = mcp_server._ro(self.db_path)
        try:
            if p == "/api/summary":
                return self._send(json.dumps(summary(db), ensure_ascii=False))
            if p == "/api/incidents":
                incs = [friendly_incident(db, r)
                        for r in db.execute("SELECT * FROM incident ORDER BY id DESC "
                                            f"LIMIT {mcp_server.MAX_ROWS}")]
                return self._send(json.dumps({"incidents": incs}, ensure_ascii=False))
            if p == "/api/actions":
                return self._send(json.dumps(actions(db), ensure_ascii=False))
            if p == "/api/integrity":
                return self._send(json.dumps(integrity(db), ensure_ascii=False))
            if p.startswith("/api/incident/"):
                d = incident_detail(db, int(p.rsplit("/", 1)[1]))
                if d is None:
                    self.send_error(404); return
                return self._send(json.dumps(d, ensure_ascii=False))
        finally:
            db.close()
        self.send_error(404)

    def log_message(self, *a):
        pass


PAGE = PAGE.replace("__LOGO__", LOGO_SVG)
_FF = ''.join("@font-face{font-family:'IBM Plex Sans KR';font-style:normal;font-weight:"+str(w)+";font-display:swap;src:url("+FONTS[k]+") format('woff2')}" for k,w in (('sans400',400),('sans700',700)) if k in FONTS)
_FF += ''.join("@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:"+str(w)+";font-display:swap;src:url("+FONTS[k]+") format('woff2')}" for k,w in (('mono400',400),('mono500',500)) if k in FONTS)
PAGE = PAGE.replace("__FONTS__", _FF)
import json as _json
PAGE = PAGE.replace("__ICONS__", _json.dumps(ICONS, ensure_ascii=False))


def serve(db_path, port=8787):
    _Handler.db_path = db_path
    srv = ThreadingHTTPServer(("127.0.0.1", port), _Handler)
    print(f"AgentTrace 대시보드: http://127.0.0.1:{port}  (Ctrl+C 종료)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("AGENTTRACE_DB", "agenttrace.db")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8787
    serve(path, port)


if __name__ == "__main__":
    main()
