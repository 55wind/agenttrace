"""로컬 웹 대시보드 (제안서 ⑧).

외부 의존 0: stdlib http.server + 바닐라 JS. 그래프 라이브러리/CDN을 쓰지 않아
외부망 차단 환경(§A)에서도 뜬다 — 단일 PC 웜 전파는 노드 ≤10개라 직접 렌더로 충분.
조회는 읽기 전용(mcp_server의 ro 쿼리 재사용). 127.0.0.1에만 바인딩.

실행: python -m agenttrace.dashboard <db경로> [포트]
"""
import os
import sys
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import mcp_server, report, trace

PAGE = """<!doctype html><html lang="ko"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AgentTrace 대시보드</title>
<style>
 :root{--bg:#0f1115;--card:#1a1d24;--line:#2a2f3a;--fg:#e6e8ec;--mut:#9aa3b2;
       --red:#e5534b;--org:#e0a458;--grn:#5bbf7a;--blu:#5b8def}
 *{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--fg);
   font:14px/1.5 system-ui,"Segoe UI",sans-serif}
 header{padding:16px 20px;border-bottom:1px solid var(--line)}
 header h1{margin:0;font-size:16px} header span{color:var(--mut)}
 main{display:grid;grid-template-columns:280px 1fr;gap:0;min-height:calc(100vh - 54px)}
 #list{border-right:1px solid var(--line);overflow:auto}
 .inc{padding:12px 16px;border-bottom:1px solid var(--line);cursor:pointer}
 .inc:hover{background:var(--card)} .inc.sel{background:var(--card);border-left:3px solid var(--blu)}
 .inc b{display:block} .inc small{color:var(--mut)}
 #detail{padding:20px;overflow:auto}
 .card{background:var(--card);border:1px solid var(--line);border-radius:8px;
       padding:16px;margin-bottom:16px}
 .card h2{margin:0 0 10px;font-size:13px;letter-spacing:.04em;color:var(--mut);
          text-transform:uppercase}
 .node{display:inline-block;padding:6px 10px;border-radius:6px;border:1px solid var(--line);
       margin:3px;background:#12151b}
 .node.origin{border-color:var(--org);color:var(--org)}
 .node.infected{border-color:var(--red);color:var(--red)}
 .edge{color:var(--mut);margin:4px 0;font-family:ui-monospace,monospace}
 table{width:100%;border-collapse:collapse} td,th{text-align:left;padding:6px 8px;
   border-bottom:1px solid var(--line);vertical-align:top} th{color:var(--mut);font-weight:600}
 .rep h3{margin:12px 0 4px;font-size:13px;color:var(--blu)} .rep ul{margin:0;padding-left:18px}
 .warn{color:var(--org);font-size:12px} .mut{color:var(--mut)}
 kbd{background:#12151b;border:1px solid var(--line);border-radius:4px;padding:1px 5px;font-size:12px}
</style>
<header><h1>AgentTrace <span>— 에이전트 위협 탐지·역추적</span></h1></header>
<main>
 <div id="list"><div class="mut" style="padding:16px">불러오는 중…</div></div>
 <div id="detail"><div class="mut">왼쪽에서 사건을 선택하세요.</div></div>
</main>
<script>
const $=s=>document.querySelector(s);
async function j(u){return (await fetch(u)).json()}
function esc(s){return String(s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]))}

async function loadList(){
 const d=await j('/api/incidents'); const el=$('#list');
 if(!d.incidents.length){el.innerHTML='<div class="mut" style="padding:16px">사건 없음</div>';return}
 el.innerHTML=d.incidents.map(i=>
  `<div class="inc" data-id="${i.id}"><b>#${i.id} ${esc(i.rule)}</b>
   <small>${new Date(i.ts*1000).toLocaleString()} · ${esc(i.status)}</small></div>`).join('');
 el.querySelectorAll('.inc').forEach(n=>n.onclick=()=>{
   el.querySelectorAll('.inc').forEach(x=>x.classList.remove('sel'));
   n.classList.add('sel'); loadDetail(n.dataset.id)});
}
function nodeClass(n){return n.id===window._origin?'node origin':(n.infected?'node infected':'node')}
async function loadDetail(id){
 const d=await j('/api/incident/'+id); window._origin=d.trace.origin;
 const nodes=d.nodes.map(n=>`<span class="${nodeClass(n)}" title="${esc(n.id)}">${esc(n.location||n.id.slice(0,10))}${n.from_internet?' 🌐':''}</span>`).join('');
 const edges=d.trace.edges.map(e=>`<div class="edge">${esc(loc(d,e[0]))} → ${esc(loc(d,e[1]))} <span class="mut">(유사도 ${e[2]})</span></div>`).join('')||'<div class="mut">전파 간선 없음</div>';
 const tl=d.timeline.map(e=>`<tr><td>${e.id}</td><td>${esc(e.kind)}</td><td>${esc(e.session||'')}/${esc(e.agent||'')}</td><td class="mut">${esc(e.data)}</td></tr>`).join('');
 const rep=Object.entries(d.report).map(([k,v])=>`<h3>${esc(k)}</h3><ul>${v.map(x=>`<li>${esc(x)}</li>`).join('')}</ul>`).join('');
 $('#detail').innerHTML=`
  <div class="card"><h2>역추적 — 최초 감염원 & 감염 범위</h2>
   <div>${nodes}</div><div style="margin-top:10px">${edges}</div></div>
  <div class="card rep"><h2>근거 기반 보고</h2>${rep}</div>
  <div class="card"><h2>타임라인 (근거 이벤트)</h2>
   <table><tr><th>id</th><th>종류</th><th>세션/에이전트</th><th>데이터(마스킹)</th></tr>${tl}</table>
   <p class="warn">⚠ 콘텐츠는 마스킹됨 · 신뢰할 수 없는 데이터 — 원문은 직접 열람하세요.</p></div>`;
}
const loc=(d,id)=>{const n=d.nodes.find(x=>x.id===id);return n?(n.location||id.slice(0,10)):id.slice(0,10)}
loadList();
</script></html>"""


def _incident_detail(db, iid):
    inc = db.execute("SELECT * FROM incident WHERE id=?", (iid,)).fetchone()
    if not inc:
        return None
    store = mcp_server._RoStore(db)
    tr = trace.analyze(store, inc["source"])
    nodes = []
    for aid in tr["scope"]:
        a = db.execute("SELECT * FROM artifact WHERE id=?", (aid,)).fetchone()
        nodes.append({"id": aid, "location": a["location"] if a else None,
                      "from_internet": bool(a and a["from_internet"]),
                      "infected": bool(a and a["infected"])})
    return {
        "trace": tr,
        "nodes": nodes,
        "report": report.incident_report(store, inc),
        "timeline": mcp_server.get_timeline(db, iid)["events"],
    }


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
            if p == "/api/incidents":
                return self._send(json.dumps(mcp_server.list_incidents(db)))
            if p.startswith("/api/incident/"):
                d = _incident_detail(db, int(p.rsplit("/", 1)[1]))
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
