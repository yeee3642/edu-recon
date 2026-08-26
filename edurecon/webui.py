"""Stdlib web control panel: submit targets, watch progress, review triaged findings."""
from __future__ import annotations

import json
import os
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .config import Config
from .engine import Engine
from .report import write_reports
from .store import RunStore


def serve(cfg: Config, host: str = "127.0.0.1", port: int = 8770) -> None:
    store = RunStore(cfg.workdir)
    store.load_existing()
    engine = Engine(cfg, store)

    class Handler(BaseHTTPRequestHandler):
        server_version = "edu-recon/0.1"

        def log_message(self, *a):  # quiet
            pass

        # -- helpers --
        def _send(self, code, body, ctype="application/json"):
            if isinstance(body, (dict, list)):
                body = json.dumps(body, ensure_ascii=False).encode("utf-8")
            elif isinstance(body, str):
                body = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _body_json(self):
            n = int(self.headers.get("Content-Length", "0") or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n).decode("utf-8"))
            except json.JSONDecodeError:
                return {}

        def _run_dict(self, rid):
            run = store.get(rid)
            if run is not None and run.targets:
                return run.to_dict()
            if run is not None and getattr(run, "_raw", None):
                return run._raw
            path = os.path.join(cfg.workdir, rid, "run.json")
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as fh:
                    return json.load(fh)
            return None

        # -- GET --
        def do_GET(self):
            u = urlparse(self.path)
            p = u.path
            if p == "/" or p == "/index.html":
                return self._send(200, PAGE, "text/html; charset=utf-8")
            if p == "/api/runs":
                out = [{"id": r.id, "created": r.created, "status": r.status,
                        "summary": r.summary() if r.targets else
                        (getattr(r, "_raw", {}) or {}).get("summary", {}),
                        "intensity": r.options.get("intensity")}
                       for r in store.list()]
                return self._send(200, out)
            m = re.match(r"^/api/runs/([^/]+)/artifact$", p)
            if m:
                return self._serve_artifact(m.group(1), parse_qs(u.query))
            m = re.match(r"^/api/runs/([^/]+)$", p)
            if m:
                d = self._run_dict(m.group(1))
                return self._send(200 if d else 404, d or {"error": "not found"})
            return self._send(404, {"error": "not found"})

        # -- POST --
        def do_POST(self):
            p = urlparse(self.path).path
            if p == "/api/runs":
                body = self._body_json()
                targets = _split_targets(body.get("targets", ""))
                if not targets:
                    return self._send(400, {"error": "no targets"})
                opts = {"intensity": body.get("intensity", cfg.intensity),
                        "concurrency": body.get("concurrency", cfg.concurrency)}
                run = engine.start_run(targets, opts)
                return self._send(200, {"id": run.id})
            m = re.match(r"^/api/runs/([^/]+)/cancel$", p)
            if m:
                return self._send(200, {"cancelled": engine.cancel(m.group(1))})
            m = re.match(r"^/api/runs/([^/]+)/report$", p)
            if m:
                run = store.get(m.group(1))
                if not run:
                    return self._send(404, {"error": "not found"})
                paths = write_reports(run, os.path.join(cfg.workdir, run.id))
                return self._send(200, {"report": {k: os.path.basename(v)
                                                   for k, v in paths.items()}})
            m = re.match(r"^/api/runs/([^/]+)/finding$", p)
            if m:
                return self._toggle_finding(m.group(1), self._body_json())
            return self._send(404, {"error": "not found"})

        def _toggle_finding(self, rid, body):
            run = store.get(rid)
            if not run or not run.targets:
                return self._send(409, {"error": "run not live"})
            fid = body.get("finding_id")
            for t in run.targets:
                for f in t.findings:
                    if f.id == fid:
                        if "false_positive" in body:
                            f.false_positive = bool(body["false_positive"])
                        if "reviewed" in body:
                            f.reviewed = bool(body["reviewed"])
                        store.save(run)
                        return self._send(200, {"ok": True})
            return self._send(404, {"error": "finding not found"})

        def _serve_artifact(self, rid, qs):
            rel = (qs.get("path", [""])[0]).replace("\\", "/")
            run_dir = os.path.realpath(os.path.join(cfg.workdir, rid))
            target = os.path.realpath(os.path.join(run_dir, rel))
            if not target.startswith(run_dir + os.sep) or not os.path.isfile(target):
                return self._send(404, {"error": "artifact not found"})
            with open(target, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"[edu-recon] control panel: http://{host}:{port}  (workdir={cfg.workdir})")
    print(f"[edu-recon] intensity={cfg.intensity} concurrency={cfg.concurrency}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[edu-recon] shutting down")
        httpd.shutdown()


def _split_targets(raw) -> list[str]:
    if isinstance(raw, list):
        items = raw
    else:
        items = re.split(r"[\s,]+", str(raw))
    return [x.strip() for x in items if x.strip() and not x.strip().startswith("#")]


PAGE = r"""<!doctype html><html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>edu-recon</title>
<style>
 :root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--mut:#8b949e;--line:#30363d;--acc:#1f6feb}
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
 header{padding:12px 20px;border-bottom:1px solid var(--line);display:flex;gap:16px;align-items:center}
 h1{font-size:16px;margin:0}
 .wrap{display:grid;grid-template-columns:320px 1fr;min-height:calc(100vh - 50px)}
 .side{border-right:1px solid var(--line);padding:16px;overflow:auto}
 .main{padding:16px 20px;overflow:auto}
 textarea{width:100%;height:150px;background:#0b0f14;color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:8px;font-family:ui-monospace,Consolas,monospace}
 select,input,button{background:var(--card);color:var(--fg);border:1px solid var(--line);border-radius:6px;padding:7px 10px}
 button{cursor:pointer}
 button.primary{background:var(--acc);border-color:var(--acc);font-weight:600}
 .row{display:flex;gap:8px;align-items:center;margin:8px 0;flex-wrap:wrap}
 label{color:var(--mut);font-size:12px}
 .runitem{padding:8px;border:1px solid var(--line);border-radius:6px;margin:6px 0;cursor:pointer}
 .runitem:hover{background:#161b2288}.runitem.active{border-color:var(--acc)}
 .chips{display:flex;gap:6px;flex-wrap:wrap;margin:8px 0}
 .chip{padding:2px 9px;border-radius:999px;border:1px solid var(--line);cursor:pointer;font-size:12px}
 .chip.active{background:#1f6feb33;border-color:var(--acc)}
 table{width:100%;border-collapse:collapse}
 th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--mut);font-size:12px}
 .badge{padding:1px 7px;border-radius:6px;border:1px solid var(--line);font-size:12px;white-space:nowrap}
 .sev-critical{color:#ff7b72;border-color:#ff7b7255}.sev-high{color:#ffa657;border-color:#ffa65755}
 .sev-medium{color:#e3b341}.sev-low{color:#79c0ff}.sev-info{color:#8b949e}
 code{background:#0b0f14;padding:1px 5px;border-radius:4px;color:#9ecbff;word-break:break-all}
 .grid{display:flex;gap:3px;flex-wrap:wrap}
 .st{font-size:11px;padding:1px 6px;border-radius:4px;border:1px solid var(--line);color:var(--mut)}
 .st.done{color:#3fb950;border-color:#3fb95055}.st.running{color:#d29922;border-color:#d2992255}
 .st.error{color:#ff7b72}.st.skipped{opacity:.5}
 .muted{color:var(--mut)} a{color:#58a6ff} details{margin:3px 0}
 .tgt{border:1px solid var(--line);border-radius:8px;padding:10px;margin:8px 0}
</style></head><body>
<header><h1>🛰️ edu-recon</h1><span class="muted">authorized education-sector recon &amp; triage</span>
 <span id="scope" class="muted" style="margin-left:auto"></span></header>
<div class="wrap">
 <div class="side">
  <label>Targets（每行一個：IP / host / URL / CIDR / domain）</label>
  <textarea id="targets" placeholder="10.0.0.0/24&#10;https://portal.school.edu.tw&#10;lab.school.edu.tw&#10;192.168.1.10:8080"></textarea>
  <div class="row"><label>強度</label>
   <select id="intensity"><option value="full">full（全自動最大化）</option>
    <option value="recon">recon（注入僅列候選）</option>
    <option value="passive">passive（被動盤點）</option></select>
   <label>併發</label><input id="conc" type="number" value="4" style="width:64px">
   <button class="primary" onclick="startRun()">開始掃描</button></div>
  <hr style="border-color:var(--line)">
  <div class="row"><b>Runs</b><button onclick="loadRuns()" style="margin-left:auto">↻</button></div>
  <div id="runs"></div>
 </div>
 <div class="main" id="main"><p class="muted">選一個 run，或貼上 target 開始掃描。</p></div>
</div>
<script>
const ORDER={critical:4,high:3,medium:2,low:1,info:0};
let CUR=null, TIMER=null, FILT=new Set(['critical','high','medium','low']);
async function api(m,u,b){const o={method:m,headers:{'Content-Type':'application/json'}};
 if(b)o.body=JSON.stringify(b);const r=await fetch(u,o);return r.json();}
function esc(s){return (s==null?'':s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
async function startRun(){const targets=document.getElementById('targets').value;
 if(!targets.trim())return alert('請貼上 target');
 const r=await api('POST','/api/runs',{targets,intensity:document.getElementById('intensity').value,
   concurrency:+document.getElementById('conc').value});
 if(r.id){CUR=r.id;await loadRuns();select(r.id);}else alert(r.error||'error');}
async function loadRuns(){const rs=await api('GET','/api/runs');
 document.getElementById('runs').innerHTML=rs.map(r=>{const s=r.summary||{severity:{}};
  const sv=s.severity||{};return `<div class="runitem ${r.id===CUR?'active':''}" onclick="select('${r.id}')">
  <div><b>${esc(r.id)}</b> <span class="badge">${esc(r.status)}</span></div>
  <div class="muted" style="font-size:12px">${esc(r.intensity||'')} · ${s.targets||0} targets ·
   <span class="sev-critical">C${sv.critical||0}</span> <span class="sev-high">H${sv.high||0}</span>
   <span class="sev-medium">M${sv.medium||0}</span></div></div>`;}).join('')||'<p class="muted">尚無 run</p>';}
function select(id){CUR=id;loadRuns();refresh();if(TIMER)clearInterval(TIMER);
 TIMER=setInterval(refresh,2500);}
async function refresh(){if(!CUR)return;const d=await api('GET','/api/runs/'+CUR);render(d);
 if(['done','cancelled','error'].includes(d.status)&&TIMER){clearInterval(TIMER);TIMER=null;}}
function render(d){if(!d||d.error)return;const s=d.summary||{severity:{}};const sv=s.severity||{};
 const chips=['critical','high','medium','low','info'].map(k=>`<span class="chip ${FILT.has(k)?'active':''}"
   onclick="tgl('${k}')">${k} ${sv[k]||0}</span>`).join('');
 let h=`<div class="row"><b>${esc(d.id)}</b><span class="badge">${esc(d.status)}</span>
   <span class="muted">intensity ${esc((d.options||{}).intensity)} · ${s.targets||0} targets · ${s.findings||0} findings</span>
   <button onclick="cancelRun()" ${['done','cancelled','error'].includes(d.status)?'disabled':''}>Cancel</button>
   <button onclick="mkReport()">匯出報告</button></div><div class="chips">${chips}</div>`;
 const tgts=(d.targets||[]).slice().sort((a,b)=>score(b)-score(a));
 for(const t of tgts){h+=renderTarget(d.id,t);}
 if(!tgts.length)h+='<p class="muted">展開中…</p>';
 document.getElementById('main').innerHTML=h;}
function score(t){let s=0;for(const f of (t.findings||[]))if(!f.false_positive)
  s+=({critical:100,high:40,medium:12,low:3,info:0})[f.severity]||0;return s;}
function renderTarget(rid,t){const stages=Object.values(t.stages||{});
 const grid=stages.map(st=>`<span class="st ${st.status}">${esc(st.name)}${st.duration?(' '+st.duration+'s'):''}</span>`).join('');
 const rows=(t.findings||[]).filter(f=>FILT.has(f.severity)).map(f=>{const ev=f.evidence||{};
  const url=ev.url||ev.value||ev.cgipoint||ev.poc||'';
  const arts=(f.artifacts||[]).map(a=>`<a href="/api/runs/${rid}/artifact?path=${encodeURIComponent(a)}" target="_blank">${esc(a.split('/').pop())}</a>`).join(' ');
  return `<tr style="${f.false_positive?'opacity:.4':''}">
   <td><span class="badge sev-${f.severity}">${f.severity}</span></td>
   <td>${esc(f.category)}<div class="muted" style="font-size:11px">${esc(f.confidence)}</div></td>
   <td>${esc(f.title)}
     <details><summary class="muted">evidence</summary><code>${esc(JSON.stringify(ev))}</code>
     <div>${arts}</div></details></td>
   <td><code>${esc((url+'').slice(0,90))}</code></td>
   <td><button onclick="fp('${rid}','${f.id}',${!f.false_positive})">${f.false_positive?'↺':'FP'}</button></td></tr>`;}).join('');
 const ports=(t.services||[]).map(s=>s.port+'/'+esc(s.name)).join(', ')||'—';
 return `<div class="tgt"><div class="row"><b>${esc(t.host)}</b>
   <span class="badge">${esc(t.status)}</span>${t.is_wordpress?'<span class="badge">WordPress</span>':''}
   <span class="muted">score ${score(t)} · ports ${ports}</span></div>
  <div class="grid" style="margin:6px 0">${grid}</div>
  <table><thead><tr><th>Sev</th><th>Category</th><th>Finding</th><th>Evidence</th><th></th></tr></thead>
  <tbody>${rows||'<tr><td colspan=5 class="muted">no findings in filter</td></tr>'}</tbody></table></div>`;}
function tgl(k){FILT.has(k)?FILT.delete(k):FILT.add(k);refresh();}
async function cancelRun(){await api('POST','/api/runs/'+CUR+'/cancel');refresh();}
async function fp(rid,fid,val){await api('POST','/api/runs/'+rid+'/finding',{finding_id:fid,false_positive:val});refresh();}
async function mkReport(){const r=await api('POST','/api/runs/'+CUR+'/report');
 if(r.report)window.open('/api/runs/'+CUR+'/artifact?path='+r.report.html,'_blank');}
loadRuns();
</script></body></html>"""
