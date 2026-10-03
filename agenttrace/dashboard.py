"""로컬 웹 대시보드 (제안서 ⑧) — 비전공자용 관리자 화면.

외부 의존 0: stdlib http.server + 바닐라 JS. 그래프 라이브러리/CDN을 쓰지 않아
외부망 차단 환경(§A)에서도 뜬다. 조회는 읽기 전용(mcp_server의 ro 쿼리 재사용).
127.0.0.1에만 바인딩.

화면 원칙: 전문용어 대신 평이한 말(메일/파일/메시지, 자가복제 위협, 감염/외부유입),
"무슨 일 → 어디서 시작 → 지금 할 일" 순서, 기술 상세는 접어둠.

실행: python -m agenttrace.dashboard <db경로> [포트]
"""
import os
import sys
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import mcp_server, report, trace

# 종류를 비전공자가 알아보는 라벨/아이콘으로
KIND_LABEL = {"file": "파일", "mail": "메일", "message": "메시지", "memory": "메모리"}
KIND_ICON = {"file": "📄", "mail": "📧", "message": "💬", "memory": "🧠"}


def _artifact(db, aid):
    return db.execute("SELECT * FROM artifact WHERE id=?", (aid,)).fetchone()


def _count(db, sql, args=()):
    return db.execute(sql, args).fetchone()[0]


def summary(db):
    """상단 요약 카드용 집계 (전부 평이한 숫자)."""
    return {
        "threats": _count(db, "SELECT COUNT(*) FROM incident"),
        "blocked": _count(db, "SELECT COUNT(*) FROM event WHERE kind='verdict' "
                              "AND data LIKE '%\"verdict\": \"block\"%'"),
        "review": _count(db, "SELECT COUNT(*) FROM event WHERE kind='verdict' "
                             "AND data LIKE '%\"verdict\": \"ask\"%'"),
        "infected": _count(db, "SELECT COUNT(*) FROM artifact WHERE infected=1"),
    }


def _chain_order(tr):
    """전파 경로를 최초 감염원부터 순서대로 늘어놓기 위한 노드 정렬 인덱스(BFS)."""
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
    """사건 목록 카드용 — 제목/심각도/한 줄 요약/출처/범위."""
    tr = trace.analyze(mcp_server._RoStore(db), inc["source"])
    o = _artifact(db, tr["origin"])
    scope = len(tr["scope"])
    origin_name = (o["location"] if o and o["location"] else tr["origin"][:10])
    return {
        "id": inc["id"], "ts": inc["ts"], "status": inc["status"],
        "title": "자가복제 위협 (웜)", "severity": "높음",
        "origin": origin_name, "scope_count": scope,
        "summary": f"외부에서 들어온 내용이 스스로 복제되어 {scope}곳으로 퍼졌습니다.",
    }


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
        nodes.append({
            "id": aid, "name": (a["location"] if a and a["location"] else aid[:10]),
            "kind_label": KIND_LABEL.get(kind, "항목"), "icon": KIND_ICON.get(kind, "📦"),
            "from_internet": bool(a and a["from_internet"]),
            "infected": bool(a and a["infected"]), "is_origin": aid == tr["origin"],
        })
    nodes.sort(key=lambda n: order.get(n["id"], 999))
    origin_name = next((n["name"] for n in nodes if n["is_origin"]), "")
    steps = [f"{n['kind_label']} ‘{n['name']}’ 을(를) 격리하거나 삭제하세요." for n in nodes]
    steps.append("외부로 보내기 전에 원본 내용을 사람이 직접 확인하세요.")
    return {
        "trace": tr, "nodes": nodes,
        "headline": f"외부에서 들어온 내용이 스스로 복제되어 총 {len(nodes)}곳으로 "
                    f"퍼졌습니다. 최초 출처는 ‘{origin_name}’ 입니다.",
        "steps": steps,
        "report": report.incident_report(store, inc),
        "timeline": mcp_server.get_timeline(db, iid)["events"],
    }


PAGE = r"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentTrace 보안 관리자</title>
<style>
:root{
 --bg:#f5f6f8; --surface:#ffffff; --surface2:#f0f2f5; --line:#e3e6ea;
 --fg:#1a1d24; --mut:#5b6472; --brand:#2563eb;
 --danger:#dc2626; --danger-bg:#fef2f2; --warn:#d97706; --warn-bg:#fffbeb;
 --safe:#16a34a; --safe-bg:#f0fdf4; --origin:#ea7a0c;
 --shadow:0 1px 3px rgba(20,24,33,.06),0 1px 2px rgba(20,24,33,.04);
 --radius:14px;
}
@media (prefers-color-scheme:dark){:root{
 --bg:#0f1115; --surface:#181b21; --surface2:#1f232b; --line:#2a2f3a;
 --fg:#e8eaed; --mut:#9aa3b2; --brand:#5b8def;
 --danger:#f0685f; --danger-bg:#2a1718; --warn:#e0a458; --warn-bg:#2a2215;
 --safe:#5bbf7a; --safe-bg:#132018; --origin:#e0a458;
 --shadow:0 1px 3px rgba(0,0,0,.3);
}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);
 font:16px/1.6 "Pretendard",system-ui,"Segoe UI","Malgun Gothic",sans-serif}
.wrap{max-width:1160px;margin:0 auto;padding:0 16px 48px}
header{background:var(--surface);border-bottom:1px solid var(--line)}
.hinner{max-width:1160px;margin:0 auto;padding:16px;display:flex;align-items:center;
 justify-content:space-between;gap:12px;flex-wrap:wrap}
.brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:18px}
.brand .logo{font-size:24px}
.brand small{display:block;font-weight:400;font-size:12px;color:var(--mut)}
.pill{display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:999px;
 font-weight:700;font-size:15px}
.pill.bad{background:var(--danger-bg);color:var(--danger)}
.pill.ok{background:var(--safe-bg);color:var(--safe)}
.dot{width:9px;height:9px;border-radius:50%;background:currentColor}
/* KPI */
.kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin:20px 0}
.kpi{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
 padding:16px 18px;box-shadow:var(--shadow)}
.kpi .n{font-size:30px;font-weight:800;line-height:1.1}
.kpi .l{color:var(--mut);font-size:14px;margin-top:4px}
.kpi.red .n{color:var(--danger)} .kpi.amber .n{color:var(--warn)}
.kpi.blue .n{color:var(--brand)} .kpi.green .n{color:var(--safe)}
/* layout */
main{display:grid;grid-template-columns:340px 1fr;gap:16px;align-items:start}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
 box-shadow:var(--shadow);overflow:hidden}
.panel h2{margin:0;padding:14px 18px;font-size:14px;color:var(--mut);
 border-bottom:1px solid var(--line);letter-spacing:.02em}
/* incident list */
.inc{padding:16px 18px;border-bottom:1px solid var(--line);cursor:pointer;
 border-left:4px solid transparent;transition:background .12s}
.inc:hover{background:var(--surface2)}
.inc.sel{background:var(--surface2);border-left-color:var(--brand)}
.inc .top{display:flex;justify-content:space-between;align-items:center;gap:8px}
.inc .title{font-weight:700}
.inc .sum{color:var(--mut);font-size:14px;margin-top:4px}
.inc .when{color:var(--mut);font-size:12px;margin-top:6px}
.badge{font-size:12px;font-weight:700;padding:3px 10px;border-radius:999px;white-space:nowrap}
.badge.high{background:var(--danger-bg);color:var(--danger)}
/* detail */
#detail{display:flex;flex-direction:column;gap:16px}
.empty{display:flex;flex-direction:column;align-items:center;justify-content:center;
 min-height:320px;color:var(--mut);text-align:center;gap:10px}
.empty .big{font-size:48px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);
 box-shadow:var(--shadow);padding:20px}
.card h3{margin:0 0 4px;font-size:13px;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}
.headline{font-size:19px;font-weight:700;line-height:1.5}
.headline .warnmark{color:var(--danger)}
/* flow */
.flow{display:flex;align-items:stretch;gap:0;overflow-x:auto;padding:4px 2px 8px}
.fnode{min-width:150px;background:var(--surface2);border:2px solid var(--line);
 border-radius:12px;padding:12px 14px;position:relative;flex:0 0 auto}
.fnode.infected{border-color:var(--danger);background:var(--danger-bg)}
.fnode.origin{border-color:var(--origin)}
.fnode .ic{font-size:22px}
.fnode .k{font-size:12px;color:var(--mut);margin-top:2px}
.fnode .nm{font-weight:700;word-break:break-all;font-size:14px}
.fnode .chip{display:inline-block;margin-top:8px;font-size:11px;font-weight:700;
 padding:2px 8px;border-radius:999px}
.chip.net{background:var(--warn-bg);color:var(--warn)}
.chip.inf{background:var(--danger-bg);color:var(--danger)}
.ribbon{position:absolute;top:-10px;left:10px;background:var(--origin);color:#fff;
 font-size:11px;font-weight:700;padding:2px 8px;border-radius:999px}
.arrow{display:flex;flex-direction:column;align-items:center;justify-content:center;
 color:var(--mut);padding:0 8px;min-width:64px}
.arrow .a{font-size:22px;line-height:1}
.arrow .s{font-size:11px;margin-top:2px}
/* steps checklist */
ul.steps{list-style:none;margin:0;padding:0}
ul.steps li{display:flex;align-items:flex-start;gap:12px;padding:12px 0;
 border-bottom:1px solid var(--line)}
ul.steps li:last-child{border-bottom:0}
ul.steps input{width:22px;height:22px;margin:2px 0 0;flex:0 0 auto;cursor:pointer;accent-color:var(--brand)}
ul.steps label{cursor:pointer}
ul.steps li.done label{text-decoration:line-through;color:var(--mut)}
/* tech details */
details{background:var(--surface2);border:1px solid var(--line);border-radius:12px;padding:0 16px}
details summary{cursor:pointer;padding:14px 0;font-weight:600;color:var(--mut)}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--mut)}
.note{color:var(--warn);font-size:13px;margin:10px 0 4px}
.rep h4{margin:14px 0 4px;font-size:13px;color:var(--brand)}
.rep ul{margin:0 0 4px;padding-left:20px;color:var(--fg)}
@media (max-width:820px){
 main{grid-template-columns:1fr}
 .kpis{grid-template-columns:repeat(2,1fr)}
}
</style></head><body>
<header><div class="hinner">
 <div class="brand"><span class="logo">🛡️</span><span>AgentTrace
   <small>에이전트 보안 관리자</small></span></div>
 <div id="status" class="pill ok"><span class="dot"></span>확인 중…</div>
</div></header>
<div class="wrap">
 <section class="kpis" id="kpis"></section>
 <main>
  <div class="panel"><h2>발견된 위협</h2><div id="list"></div></div>
  <div id="detail"><div class="card empty"><div class="big">🔎</div>
    <div>왼쪽에서 위협을 선택하면<br>자세한 내용과 할 일을 보여드립니다.</div></div></div>
 </main>
</div>
<script>
const $=s=>document.querySelector(s);
const j=async u=>(await fetch(u)).json();
const esc=s=>String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
function ago(ts){const d=Math.floor(Date.now()/1000-ts);
 if(d<60)return'방금 전';if(d<3600)return Math.floor(d/60)+'분 전';
 if(d<86400)return Math.floor(d/3600)+'시간 전';return Math.floor(d/86400)+'일 전';}

async function load(){
 const s=await j('/api/summary');
 $('#status').className='pill '+(s.threats>0?'bad':'ok');
 $('#status').innerHTML='<span class="dot"></span>'+
   (s.threats>0?('위협 '+s.threats+'건 발견'):'이상 없음');
 $('#kpis').innerHTML=[
   ['red','🚨',s.threats,'발견된 위협'],
   ['blue','🛡️',s.blocked,'차단된 행동'],
   ['red','☣️',s.infected,'감염된 항목'],
   ['amber','⚠️',s.review,'확인 필요'],
 ].map(([c,ic,n,l])=>`<div class="kpi ${c}"><div class="n">${ic} ${n}</div>
   <div class="l">${l}</div></div>`).join('');

 const d=await j('/api/incidents');
 const el=$('#list');
 if(!d.incidents.length){el.innerHTML='<div class="inc" style="cursor:default;color:var(--mut)">발견된 위협이 없습니다. 안전합니다. ✅</div>';return;}
 el.innerHTML=d.incidents.map(i=>`<div class="inc" data-id="${i.id}">
   <div class="top"><span class="title">🪱 ${esc(i.title)}</span>
     <span class="badge high">심각도 ${esc(i.severity)}</span></div>
   <div class="sum">${esc(i.summary)}</div>
   <div class="when">출처: ${esc(i.origin)} · ${ago(i.ts)}</div></div>`).join('');
 el.querySelectorAll('.inc[data-id]').forEach(n=>n.onclick=()=>{
   el.querySelectorAll('.inc').forEach(x=>x.classList.remove('sel'));
   n.classList.add('sel');detail(n.dataset.id);});
}

function flow(d){
 let h='<div class="flow">';
 const emap={};d.trace.edges.forEach(e=>emap[e[0]+'>'+e[1]]=e[2]);
 d.nodes.forEach((n,i)=>{
   const cls=(n.is_origin?' origin':'')+(n.infected?' infected':'');
   let chips='';
   if(n.from_internet)chips+='<span class="chip net">외부 유입</span> ';
   if(n.infected)chips+='<span class="chip inf">감염</span>';
   h+=`<div class="fnode${cls}">${n.is_origin?'<span class="ribbon">⚑ 시작점</span>':''}
     <div class="ic">${n.icon}</div><div class="k">${esc(n.kind_label)}</div>
     <div class="nm">${esc(n.name)}</div><div>${chips||'<span class="chip" style="color:var(--mut)">정상</span>'}</div></div>`;
   if(i<d.nodes.length-1){
     const s=emap[n.id+'>'+d.nodes[i+1].id];
     h+=`<div class="arrow"><div class="a">→</div>${s?`<div class="s">닮음 ${Math.round(s*100)}%</div>`:''}</div>`;
   }
 });
 return h+'</div>';
}

async function detail(id){
 const d=await j('/api/incident/'+id);
 const steps=d.steps.map((s,i)=>`<li><input type="checkbox" id="st${i}"
   onchange="this.closest('li').classList.toggle('done',this.checked)">
   <label for="st${i}">${esc(s)}</label></li>`).join('');
 const rep=Object.entries(d.report).map(([k,v])=>
   `<h4>${esc(k)}</h4><ul>${v.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`).join('');
 const tl=d.timeline.map(e=>`<tr><td>${e.id}</td><td>${esc(e.kind)}</td>
   <td>${esc(e.session||'')}/${esc(e.agent||'')}</td><td>${esc(e.data)}</td></tr>`).join('');
 $('#detail').innerHTML=`
  <div class="card"><h3>무슨 일이 일어났나요?</h3>
    <p class="headline"><span class="warnmark">⚠️</span> ${esc(d.headline)}</p></div>
  <div class="card"><h3>전파 경로 — 어디서 시작해 어디로 퍼졌나</h3>${flow(d)}</div>
  <div class="card"><h3>지금 해야 할 일</h3><ul class="steps">${steps}</ul></div>
  <div class="card rep"><h3>자세한 근거</h3>${rep}
    <details><summary>기술 상세 (개발자용) — 근거 타임라인</summary>
      <table><tr><th>id</th><th>종류</th><th>작업/에이전트</th><th>데이터(마스킹)</th></tr>${tl}</table>
      <p class="note">⚠ 콘텐츠는 마스킹됨 · 신뢰할 수 없는 데이터 — 원문은 직접 열람하세요.</p>
    </details></div>`;
}
load();
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
                return self._send(json.dumps(summary(db)))
            if p == "/api/incidents":
                incs = [friendly_incident(db, r)
                        for r in db.execute("SELECT * FROM incident ORDER BY id DESC "
                                            f"LIMIT {mcp_server.MAX_ROWS}")]
                return self._send(json.dumps({"incidents": incs}, ensure_ascii=False))
            if p.startswith("/api/incident/"):
                d = incident_detail(db, int(p.rsplit("/", 1)[1]))
                if d is None:
                    self.send_error(404); return
                return self._send(json.dumps(d, ensure_ascii=False))
        finally:
            db.close()
        self.send_error(404)

    def log_message(self, *a):
        pass        # 콘솔 소음 억제


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
