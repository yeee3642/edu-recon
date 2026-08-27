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
            m = re.match(r"^/api/runs/([^/]+)/logs$", p)
            if m:
                return self._serve_logs(m.group(1), parse_qs(u.query))
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

        def _serve_logs(self, rid, qs):
            """Incremental run-log tail for the live console: ?since=<idx>."""
            run = store.get(rid)
            if run is not None:
                logs, status = list(run.logs), run.status
            else:
                d = self._run_dict(rid) or {}
                logs, status = d.get("logs", []), d.get("status", "done")
            try:
                since = max(0, int(qs.get("since", ["0"])[0]))
            except (ValueError, TypeError):
                since = 0
            tail = logs[since:] if since < len(logs) else []
            return self._send(200, {"status": status, "logs": tail, "next": len(logs)})

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
 :root{
  --bg:#080b11;--bg2:#0b1019;--panel:#0f1622;--panel2:#131c2b;--elev:#18202f;
  --fg:#e8eef7;--mut:#7f8da4;--dim:#586377;--line:#212c3d;
  --line2:#2b384d;--acc:#22d3ee;--acc2:#2dd4bf;--accdim:#0e3b45;
  --crit:#ff5f57;--high:#ff9f43;--med:#f7c948;--low:#4aa8ff;--info:#7f8da4;
  --ok:#3fe08f;--run:#f7c948;--err:#ff5f57;
  --term:#0a0f16;--termln:#9fb0c9;--cmd:#3ad6ff;--green:#3fe08f;
  --shadow:0 10px 40px -12px rgba(0,0,0,.7);
 }
 *{box-sizing:border-box}
 html,body{height:100%}
 body{margin:0;background:radial-gradient(1200px 600px at 80% -10%,#0d1a24 0,var(--bg) 55%);color:var(--fg);
  font:14px/1.55 -apple-system,"Segoe UI",Roboto,"Noto Sans TC",system-ui,sans-serif;-webkit-font-smoothing:antialiased}
 .mono{font-family:ui-monospace,"SF Mono",Consolas,"Noto Sans Mono",monospace}
 ::-webkit-scrollbar{width:10px;height:10px}::-webkit-scrollbar-thumb{background:#1e293b;border-radius:8px}
 ::-webkit-scrollbar-thumb:hover{background:#2a3a52}::-webkit-scrollbar-track{background:transparent}
 a{color:var(--acc);text-decoration:none}a:hover{text-decoration:underline}
 button{cursor:pointer;font:inherit}
 /* top bar */
 .topbar{display:flex;align-items:center;gap:14px;padding:12px 22px;border-bottom:1px solid var(--line);
  background:linear-gradient(180deg,rgba(20,30,44,.6),rgba(12,18,28,.3));backdrop-filter:blur(6px);position:sticky;top:0;z-index:20}
 .brand{display:flex;align-items:center;gap:10px;font-weight:700;font-size:16px;letter-spacing:.3px}
 .logo{width:26px;height:26px;border-radius:7px;display:grid;place-items:center;
  background:conic-gradient(from 210deg,var(--acc),var(--acc2),#4aa8ff,var(--acc));box-shadow:0 0 18px -2px var(--acc);color:#04222a;font-weight:900}
 .sub{color:var(--mut);font-size:12.5px}
 .spacer{flex:1}
 .livepill{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--mut);padding:5px 11px;border:1px solid var(--line);border-radius:999px;background:var(--panel)}
 .dot{width:8px;height:8px;border-radius:50%;background:var(--dim)}
 .dot.live{background:var(--ok);box-shadow:0 0 8px var(--ok);animation:pulse 1.4s infinite}
 @keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
 /* app grid */
 .app{display:grid;grid-template-columns:340px 1fr;height:calc(100vh - 55px)}
 .sidebar{border-right:1px solid var(--line);padding:16px;overflow:auto;background:linear-gradient(180deg,var(--bg2),var(--bg))}
 .content{display:grid;grid-template-rows:1fr minmax(220px,34vh);min-width:0}
 .detail{overflow:auto;padding:18px 22px}
 /* cards / inputs */
 .card{background:linear-gradient(180deg,var(--panel2),var(--panel));border:1px solid var(--line);border-radius:14px;box-shadow:var(--shadow)}
 .pad{padding:14px}
 .lbl{color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.7px;margin:0 0 6px}
 textarea,select,input{width:100%;background:#070b12;color:var(--fg);border:1px solid var(--line2);border-radius:9px;padding:9px 11px;font-family:ui-monospace,Consolas,monospace;font-size:12.5px;outline:none;transition:border .15s,box-shadow .15s}
 textarea{height:120px;resize:vertical}
 textarea:focus,select:focus,input:focus{border-color:var(--acc);box-shadow:0 0 0 3px rgba(34,211,238,.12)}
 .field{margin:10px 0}
 .two{display:grid;grid-template-columns:1fr 88px;gap:9px}
 .btn{background:var(--elev);color:var(--fg);border:1px solid var(--line2);border-radius:9px;padding:9px 13px;transition:.15s}
 .btn:hover{border-color:#3a4a66;background:#1d2839}
 .btn:disabled{opacity:.4;cursor:not-allowed}
 .btn.primary{background:linear-gradient(180deg,var(--acc),#12b9d6);border:none;color:#04222a;font-weight:800;box-shadow:0 6px 20px -6px var(--acc)}
 .btn.primary:hover{filter:brightness(1.07)}
 .btn.sm{padding:5px 10px;font-size:12px;border-radius:8px}
 .btn.ghost{background:transparent}
 .icobtn{background:transparent;border:1px solid var(--line);border-radius:8px;color:var(--mut);width:30px;height:30px;display:grid;place-items:center}
 .icobtn:hover{color:var(--fg);border-color:var(--acc)}
 hr{border:none;border-top:1px solid var(--line);margin:16px 0}
 .sechead{display:flex;align-items:center;gap:8px;margin:0 0 8px}
 .sechead b{font-size:13px;letter-spacing:.3px}
 /* runs list */
 .runitem{border:1px solid var(--line);border-radius:11px;padding:10px 11px;margin:8px 0;cursor:pointer;background:var(--panel);transition:.15s;position:relative;overflow:hidden}
 .runitem:hover{border-color:#33455f;transform:translateY(-1px)}
 .runitem.active{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc) inset,0 8px 24px -12px var(--acc)}
 .runitem.active:before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--acc)}
 .runid{font-weight:700;font-size:12.5px;font-family:ui-monospace,monospace}
 .runmeta{color:var(--mut);font-size:11.5px;margin-top:4px;display:flex;gap:9px;flex-wrap:wrap;align-items:center}
 .badge{font-size:11px;padding:1.5px 8px;border-radius:999px;border:1px solid var(--line2);white-space:nowrap;text-transform:lowercase}
 .st-running,.st-expanding{color:var(--run);border-color:#5a4a12;background:#241d07}
 .st-done{color:var(--ok);border-color:#155e3a;background:#082018}
 .st-cancelled{color:var(--mut)}
 .st-error{color:var(--err);border-color:#5e1a17;background:#230d0c}
 .st-pending{color:var(--mut)}
 .cc{font-family:ui-monospace,monospace;font-weight:700;font-size:11.5px}
 .cC{color:var(--crit)}.cH{color:var(--high)}.cM{color:var(--med)}
 /* detail header */
 .dhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px}
 .dhead .title{font-size:16px;font-weight:800;font-family:ui-monospace,monospace}
 .kv{color:var(--mut);font-size:12.5px}
 .chips{display:flex;gap:7px;flex-wrap:wrap;margin:12px 0}
 .chip{padding:4px 12px;border-radius:999px;border:1px solid var(--line2);cursor:pointer;font-size:12px;color:var(--mut);user-select:none;transition:.12s;display:flex;gap:6px;align-items:center}
 .chip:hover{border-color:#3a4a66}
 .chip .n{font-family:ui-monospace,monospace;font-weight:700}
 .chip.on.critical{color:var(--crit);border-color:var(--crit);background:#ff5f5715}
 .chip.on.high{color:var(--high);border-color:var(--high);background:#ff9f4315}
 .chip.on.medium{color:var(--med);border-color:var(--med);background:#f7c94815}
 .chip.on.low{color:var(--low);border-color:var(--low);background:#4aa8ff15}
 .chip.on.info{color:var(--info);border-color:#43506a;background:#7f8da415}
 .chip.off{opacity:.5}
 /* target card */
 .tgt{margin:14px 0;overflow:hidden}
 .tgthead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:13px 15px;border-bottom:1px solid var(--line);background:linear-gradient(180deg,#141d2b,#0f1723)}
 .host{font-weight:800;font-family:ui-monospace,monospace;font-size:14px}
 .tag{font-size:11px;padding:1.5px 8px;border-radius:6px;border:1px solid var(--line2);color:var(--mut)}
 .tag.wp{color:#79c0ff;border-color:#1f4b7a}
 .score{margin-left:auto;font-family:ui-monospace,monospace;font-weight:800}
 .score .lab{color:var(--mut);font-weight:400;font-size:11px;margin-right:4px}
 .grid{display:flex;gap:5px;flex-wrap:wrap;padding:12px 15px}
 .step{font-size:11px;font-family:ui-monospace,monospace;padding:3px 9px;border-radius:7px;border:1px solid var(--line);color:var(--dim);cursor:default;transition:.12s;display:flex;gap:6px;align-items:center;background:#0c131e}
 .step .s-dot{width:6px;height:6px;border-radius:50%;background:var(--dim)}
 .step.clk{cursor:pointer}.step.clk:hover{border-color:var(--acc);color:var(--fg)}
 .step.done{color:#9fe8c4;border-color:#12492f}.step.done .s-dot{background:var(--ok)}
 .step.running{color:#f6dd93;border-color:#4a3d10}.step.running .s-dot{background:var(--run);box-shadow:0 0 7px var(--run);animation:pulse 1.2s infinite}
 .step.error{color:#ffb3ae;border-color:#4e1714}.step.error .s-dot{background:var(--err)}
 .step.skipped{opacity:.4}
 /* findings table */
 table{width:100%;border-collapse:collapse}
 thead th{text-align:left;color:var(--mut);font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:8px 12px;border-bottom:1px solid var(--line);font-weight:600}
 tbody td{padding:9px 12px;border-bottom:1px solid #172234;vertical-align:top;font-size:13px}
 tbody tr:hover{background:#0f1826}
 tr.fp{opacity:.38}
 .sev{font-size:11px;font-weight:800;padding:2px 9px;border-radius:7px;font-family:ui-monospace,monospace;text-transform:uppercase}
 .sev.critical{color:#fff;background:linear-gradient(180deg,#ff5f57,#d23b34)}
 .sev.high{color:#20140a;background:linear-gradient(180deg,#ff9f43,#e07d1a)}
 .sev.medium{color:#241f07;background:linear-gradient(180deg,#f7c948,#d1a412)}
 .sev.low{color:#04213f;background:linear-gradient(180deg,#4aa8ff,#1f7fdc)}
 .sev.info{color:#d7deea;background:#2a3646}
 .cat{font-family:ui-monospace,monospace;font-size:12px}
 .conf{color:var(--mut);font-size:11px}
 code{background:#070b12;padding:1.5px 6px;border-radius:5px;color:#8fe3ff;font-family:ui-monospace,monospace;word-break:break-all;font-size:12px}
 details.ev{margin-top:5px}details.ev>summary{color:var(--mut);cursor:pointer;font-size:12px;list-style:none}
 details.ev>summary:hover{color:var(--acc)} .evbody{margin-top:6px;background:#070b12;border:1px solid var(--line);border-radius:8px;padding:9px;white-space:pre-wrap;font-family:ui-monospace,monospace;font-size:11.5px;color:#b7c4da;max-height:230px;overflow:auto}
 .arts{margin-top:6px;display:flex;gap:8px;flex-wrap:wrap}
 .artlink{font-size:11.5px;padding:2px 9px;border:1px solid var(--line2);border-radius:7px;color:var(--acc);cursor:pointer;font-family:ui-monospace,monospace}
 .artlink:hover{border-color:var(--acc);background:#0e2b32}
 .muted{color:var(--mut)}.empty{color:var(--mut);padding:40px;text-align:center}
 /* console dock */
 .console{border-top:1px solid var(--line);background:var(--term);display:flex;flex-direction:column;min-height:0}
 .cbar{display:flex;align-items:center;gap:10px;padding:8px 14px;border-bottom:1px solid #16202e;background:#0c121b}
 .lights{display:flex;gap:7px}.light{width:11px;height:11px;border-radius:50%}
 .light.r{background:#ff5f57}.light.y{background:#febc2e}.light.g{background:#28c840}
 .ctitle{font-family:ui-monospace,monospace;font-size:12px;color:var(--mut);letter-spacing:.4px}
 .cbar .spacer{flex:1}
 .ctog{font-size:11.5px;color:var(--mut);border:1px solid var(--line);background:transparent;border-radius:7px;padding:4px 9px}
 .ctog:hover{color:var(--fg);border-color:var(--acc)} .ctog.on{color:var(--acc);border-color:var(--acc)}
 .cbody{flex:1;overflow:auto;padding:12px 14px;font-family:ui-monospace,"SF Mono",Consolas,monospace;font-size:12.5px;line-height:1.55}
 .ln{white-space:pre-wrap;word-break:break-word;color:var(--termln)}
 .ln .tm{color:#48566e;margin-right:8px}
 .ln.cmd{color:var(--cmd)}.ln.cmd .glyph{color:var(--green);margin-right:6px}
 .ln.f-critical{color:#ff8079}.ln.f-high{color:#ffbe7d}.ln.f-medium{color:#f7d675}.ln.f-low{color:#8cc6ff}
 .ln.err{color:#ff726b;font-weight:600}.ln.host{color:#65758f}
 .cursor{display:inline-block;width:8px;height:15px;background:var(--green);vertical-align:-2px;animation:blink 1.05s steps(1) infinite;box-shadow:0 0 8px var(--green)}
 @keyframes blink{50%{opacity:0}}
 /* modal */
 .modal{position:fixed;inset:0;background:rgba(4,7,12,.72);backdrop-filter:blur(4px);display:none;z-index:50;padding:5vh 4vw}
 .modal.show{display:block}
 .sheet{max-width:1000px;margin:0 auto;height:90vh;display:flex;flex-direction:column;background:var(--term);border:1px solid var(--line2);border-radius:14px;box-shadow:0 30px 80px -20px #000;overflow:hidden}
 .shead{display:flex;align-items:center;gap:10px;padding:11px 15px;border-bottom:1px solid #17212f;background:#0c121b}
 .shead .ttl{font-family:ui-monospace,monospace;font-size:13px;color:var(--fg);font-weight:700}
 .sbody{flex:1;overflow:auto;padding:14px 16px;font-family:ui-monospace,monospace;font-size:12.5px;line-height:1.55;white-space:pre-wrap;word-break:break-word;color:#aebccd}
 .sbody .prompt{color:var(--green)}.sbody .prompt b{color:var(--cmd)}
 .sbody .meta{color:#5a6b86}
 @media(max-width:1100px){.app{grid-template-columns:280px 1fr}}
</style></head>
<body>
<header class="topbar">
 <div class="brand"><span class="logo">e</span>edu-recon</div>
 <span class="sub">authorized education-sector recon &amp; triage</span>
 <span class="spacer"></span>
 <span class="livepill"><span class="dot" id="livedot"></span><span id="livetxt">idle</span></span>
</header>
<div class="app">
 <aside class="sidebar">
  <div class="card pad">
   <p class="lbl">Targets（每行一個）</p>
   <textarea id="targets" spellcheck="false" placeholder="10.0.0.0/24&#10;https://portal.school.edu.tw&#10;lab.school.edu.tw&#10;192.168.1.10:8080"></textarea>
   <div class="field">
    <p class="lbl">強度 Intensity</p>
    <select id="intensity">
     <option value="full">full — 全自動最大化</option>
     <option value="recon">recon — 注入僅列候選</option>
     <option value="passive">passive — 被動盤點</option>
    </select>
   </div>
   <div class="field two">
    <div><p class="lbl">併發</p><input id="conc" type="number" min="1" max="32" value="4"></div>
    <div style="display:flex;align-items:flex-end"><button class="btn primary" style="width:100%" onclick="startRun()">開始掃描</button></div>
   </div>
  </div>
  <div class="sechead" style="margin-top:18px"><b>Runs</b><span class="spacer" style="flex:1"></span><button class="icobtn" onclick="loadRuns()" title="refresh">&#8635;</button></div>
  <div id="runs"></div>
 </aside>
 <section class="content">
  <div class="detail" id="detail"><div class="empty">選一個 run，或貼上 target 開始掃描。</div></div>
  <div class="console">
   <div class="cbar">
    <span class="lights"><span class="light r"></span><span class="light y"></span><span class="light g"></span></span>
    <span class="ctitle" id="ctitle">console — 尚未選擇 run</span>
    <span class="spacer"></span>
    <button class="ctog on" id="locktog" onclick="toggleLock()">autoscroll</button>
    <button class="ctog" onclick="clearConsole()">clear</button>
   </div>
   <div class="cbody" id="cbody"></div>
  </div>
 </section>
</div>
<div class="modal" id="modal" onclick="if(event.target===this)closeModal()">
 <div class="sheet">
  <div class="shead">
   <span class="lights"><span class="light r"></span><span class="light y"></span><span class="light g"></span></span>
   <span class="ttl" id="mttl">log</span>
   <span class="spacer" style="flex:1"></span>
   <select id="martsel" style="width:auto;display:none" onchange="loadArt()"></select>
   <button class="btn sm" onclick="copyCmd()">複製指令</button>
   <button class="btn sm" onclick="closeModal()">關閉 ✕</button>
  </div>
  <div class="sbody mono" id="sbody"></div>
 </div>
</div>
<script>
const ORDER={critical:4,high:3,medium:2,low:1,info:0};
const SEVW={critical:100,high:40,medium:12,low:3,info:0};
let CUR=null,DTIMER=null,LTIMER=null,RTIMER=null;
let FILT=new Set(['critical','high','medium','low','info']);
let LOGIDX=0,LOCK=true,LAST=null,MRID=null,MCMD='';
function api(m,u,b){const o={method:m,headers:{'Content-Type':'application/json'}};if(b)o.body=JSON.stringify(b);
 return fetch(u,o).then(r=>r.json()).catch(()=>({}));}
function esc(s){return (s==null?'':''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function fin(list){return (list||[]);}
/* ---- runs list ---- */
async function loadRuns(){const rs=await api('GET','/api/runs');const el=document.getElementById('runs');
 if(!Array.isArray(rs)||!rs.length){el.innerHTML='<div class="muted" style="padding:8px">尚無 run</div>';return;}
 el.innerHTML=rs.map(r=>{const s=r.summary||{},sv=s.severity||{};
  return `<div class="runitem ${r.id===CUR?'active':''}" onclick="selectRun('${r.id}')">
   <div class="runid">${esc(r.id)}</div>
   <div class="runmeta"><span class="badge st-${esc(r.status)}">${esc(r.status)}</span>
    <span>${esc(r.intensity||'')}</span><span>· ${s.targets||0} 標的</span>
    <span class="cc cC">C${sv.critical||0}</span><span class="cc cH">H${sv.high||0}</span><span class="cc cM">M${sv.medium||0}</span>
   </div></div>`;}).join('');}
/* ---- start ---- */
async function startRun(){const t=document.getElementById('targets').value;
 if(!t.trim())return alert('請貼上 target');
 const r=await api('POST','/api/runs',{targets:t,intensity:document.getElementById('intensity').value,concurrency:+document.getElementById('conc').value});
 if(r&&r.id){selectRun(r.id);loadRuns();}else alert((r&&r.error)||'error');}
/* ---- select + polling ---- */
function selectRun(id){CUR=id;LOGIDX=0;clearConsole();loadRuns();
 if(DTIMER)clearInterval(DTIMER);if(LTIMER)clearInterval(LTIMER);
 document.getElementById('ctitle').textContent='console — '+id;
 refreshDetail();tailLogs();
 DTIMER=setInterval(refreshDetail,2500);LTIMER=setInterval(tailLogs,1200);}
function live(on){document.getElementById('livedot').className='dot'+(on?' live':'');
 document.getElementById('livetxt').textContent=on?'scanning':'idle';}
async function refreshDetail(){if(!CUR)return;const d=await api('GET','/api/runs/'+CUR);
 if(!d||d.error){return;}LAST=d;renderDetail(d);
 const done=['done','cancelled','error'].includes(d.status);live(!done);
 if(done&&DTIMER){clearInterval(DTIMER);DTIMER=null;}}
/* ---- detail render ---- */
function score(t){let s=0;for(const f of fin(t.findings))if(!f.false_positive)s+=SEVW[f.severity]||0;return s;}
function renderDetail(d){const s=d.summary||{},sv=s.severity||{};const done=['done','cancelled','error'].includes(d.status);
 const chips=['critical','high','medium','low','info'].map(k=>`<span class="chip ${FILT.has(k)?'on':'off'} ${k}" onclick="tgl('${k}')">${k}<span class="n">${sv[k]||0}</span></span>`).join('');
 let h=`<div class="dhead"><span class="title">${esc(d.id)}</span>
  <span class="badge st-${esc(d.status)}">${esc(d.status)}</span>
  <span class="kv">intensity <b>${esc((d.options||{}).intensity||'')}</b> · ${s.targets||0} 標的 · ${s.findings||0} findings</span>
  <span class="spacer" style="flex:1"></span>
  <button class="btn sm" onclick="cancelRun()" ${done?'disabled':''}>Cancel</button>
  <button class="btn sm primary" onclick="mkReport()">匯出報告</button></div>
  <div class="chips">${chips}</div>`;
 const tg=(d.targets||[]).slice().sort((a,b)=>score(b)-score(a));
 h+=tg.map(t=>renderTarget(d.id,t)).join('');
 if(!tg.length)h+='<div class="empty">展開中…</div>';
 document.getElementById('detail').innerHTML=h;}
function renderTarget(rid,t){const stages=Object.values(t.stages||{});
 const grid=stages.map(st=>{const cl=st.status;const has=(st.artifacts||[]).length;
  return `<span class="step ${cl} ${has?'clk':''}" ${has?`onclick="openStage('${encodeURIComponent(t.raw||t.host)}','${esc(st.name)}')"`:''} title="${esc(st.note||st.status)}">
   <span class="s-dot"></span>${esc(st.name)}${st.duration!=null?(' '+st.duration+'s'):''}</span>`;}).join('');
 const rows=fin(t.findings).filter(f=>FILT.has(f.severity)).map(f=>{const ev=f.evidence||{};
  const prim=ev.url||ev.value||ev.reproduce||ev.cgipoint||ev.poc||ev.location||ev.computed||ev.marker||'';
  const arts=(f.artifacts||[]).map(a=>`<span class="artlink" onclick="openArtifact('${rid}','${encodeURIComponent(a)}')">${esc(a.split('/').pop())}</span>`).join('');
  return `<tr class="${f.false_positive?'fp':''}">
   <td><span class="sev ${f.severity}">${f.severity}</span></td>
   <td><div class="cat">${esc(f.category)}</div><div class="conf">${esc(f.confidence)}</div></td>
   <td><div>${esc(f.title)}</div>
     <details class="ev"><summary>evidence ▾</summary><div class="evbody">${esc(JSON.stringify(ev,null,2))}</div>${arts?`<div class="arts">${arts}</div>`:''}</details></td>
   <td>${prim?`<code>${esc((''+prim).slice(0,120))}</code>`:'<span class="muted">—</span>'}</td>
   <td><button class="btn sm ghost" onclick="fp('${rid}','${f.id}',${!f.false_positive})">${f.false_positive?'↺ 復原':'標 FP'}</button></td></tr>`;}).join('');
 const ports=(t.services||[]).map(x=>x.port+'/'+esc(x.name||'?')).join(' · ')||'—';
 return `<div class="card tgt"><div class="tgthead">
   <span class="host">${esc(t.host)}</span>
   <span class="badge st-${esc(t.status)}">${esc(t.status)}</span>
   ${t.is_wordpress?'<span class="tag wp">WordPress</span>':''}
   <span class="kv" style="font-size:12px">${ports}</span>
   <span class="score"><span class="lab">score</span>${score(t)}</span></div>
  <div class="grid">${grid||'<span class="muted">no stages</span>'}</div>
  <table><thead><tr><th style="width:78px">Sev</th><th style="width:140px">Category</th><th>Finding</th><th>Evidence</th><th style="width:88px"></th></tr></thead>
   <tbody>${rows||'<tr><td colspan="5" class="muted" style="padding:14px">此篩選下無 findings</td></tr>'}</tbody></table></div>`;}
function tgl(k){FILT.has(k)?FILT.delete(k):FILT.add(k);if(LAST)renderDetail(LAST);}
async function cancelRun(){if(!CUR)return;await api('POST','/api/runs/'+CUR+'/cancel');refreshDetail();}
async function fp(rid,fid,v){await api('POST','/api/runs/'+rid+'/finding',{finding_id:fid,false_positive:v});refreshDetail();}
async function mkReport(){if(!CUR)return;const r=await api('POST','/api/runs/'+CUR+'/report');
 if(r&&r.report&&r.report.html)window.open('/api/runs/'+CUR+'/artifact?path='+encodeURIComponent(r.report.html),'_blank');
 else alert('報告尚未就緒');}
/* ---- live console ---- */
function clearConsole(){document.getElementById('cbody').innerHTML='';}
function toggleLock(){LOCK=!LOCK;document.getElementById('locktog').classList.toggle('on',LOCK);
 document.getElementById('locktog').textContent=LOCK?'autoscroll':'scroll鎖';if(LOCK)scrollC();}
function scrollC(){const b=document.getElementById('cbody');b.scrollTop=b.scrollHeight;}
function clsFor(line){const l=line;
 if(/FINDING \[critical\]/.test(l))return 'f-critical';
 if(/FINDING \[high\]/.test(l))return 'f-high';
 if(/FINDING \[medium\]/.test(l))return 'f-medium';
 if(/FINDING \[low\]/.test(l))return 'f-low';
 if(/\bERROR\b|\bFATAL\b/.test(l))return 'err';
 if(/ \$ /.test(l))return 'cmd';
 if(/^\d\d:\d\d:\d\d \[/.test(l))return 'host';
 return '';}
function appendLog(line){const b=document.getElementById('cbody');const d=document.createElement('div');
 const c=clsFor(line);d.className='ln'+(c?' '+c:'');
 const m=line.match(/^(\d\d:\d\d:\d\d)\s([\s\S]*)$/);
 let rest=m?m[2]:line,tm=m?m[1]:'';
 if(c==='cmd')d.innerHTML=(tm?`<span class="tm">${esc(tm)}</span>`:'')+'<span class="glyph">$</span>'+esc(rest.replace(/^.*?\$\s/,''));
 else d.innerHTML=(tm?`<span class="tm">${esc(tm)}</span>`:'')+esc(rest);
 b.appendChild(d);}
async function tailLogs(){if(!CUR)return;const r=await api('GET','/api/runs/'+CUR+'/logs?since='+LOGIDX);
 if(!r)return;const b=document.getElementById('cbody');
 const old=b.querySelector('.cursorline');if(old)old.remove();
 if(Array.isArray(r.logs)&&r.logs.length){for(const ln of r.logs)appendLog(ln);LOGIDX=r.next||LOGIDX;}
 const running=['running','expanding','pending'].includes(r.status);
 if(running){const cl=document.createElement('div');cl.className='ln cursorline';cl.innerHTML='<span class="cursor"></span>';b.appendChild(cl);}
 else if(LTIMER){clearInterval(LTIMER);LTIMER=null;}
 if(LOCK)scrollC();}
/* ---- log-file viewer (shell) ---- */
function findStage(key,name){if(!LAST)return null;for(const t of (LAST.targets||[]))if((t.raw||t.host)===key||t.host===key)return (t.stages||{})[name];return null;}
function openStage(enckey,name){const key=decodeURIComponent(enckey);const st=findStage(key,name);if(!st||!(st.artifacts||[]).length)return;
 MRID=CUR;const sel=document.getElementById('martsel');
 sel.innerHTML=st.artifacts.map(a=>`<option value="${encodeURIComponent(a)}">${esc(a.split('/').pop())}</option>`).join('');
 sel.style.display=st.artifacts.length>1?'':'none';
 document.getElementById('mttl').textContent=name+' — '+key;
 document.getElementById('modal').classList.add('show');loadArt();}
function openArtifact(rid,encpath){MRID=rid;const sel=document.getElementById('martsel');sel.style.display='none';
 sel.innerHTML=`<option value="${encpath}">art</option>`;
 document.getElementById('mttl').textContent=decodeURIComponent(encpath).split('/').pop();
 document.getElementById('modal').classList.add('show');loadArt();}
async function loadArt(){const sel=document.getElementById('martsel');const enc=sel.value;
 const body=document.getElementById('sbody');body.textContent='載入中…';
 const txt=await fetch('/api/runs/'+MRID+'/artifact?path='+enc).then(r=>r.text()).catch(()=>'（讀取失敗）');
 const lines=txt.split(/\r?\n/);let html='';MCMD='';
 for(const ln of lines){
  if(/^#\s\$\s/.test(ln)){MCMD=ln.replace(/^#\s\$\s/,'');html+=`<div class="prompt">$ <b>${esc(MCMD)}</b></div>`;}
  else if(/^#\s/.test(ln)){html+=`<div class="meta">${esc(ln)}</div>`;}
  else html+='<div>'+esc(ln)+'</div>';}
 body.innerHTML=html;body.scrollTop=0;}
function copyCmd(){if(MCMD&&navigator.clipboard)navigator.clipboard.writeText(MCMD);}
function closeModal(){document.getElementById('modal').classList.remove('show');}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});
/* ---- boot ---- */
loadRuns();RTIMER=setInterval(loadRuns,5000);
</script></body></html>"""
