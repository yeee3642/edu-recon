"""Stdlib web control panel: submit targets, watch progress, review triaged findings."""
from __future__ import annotations

import json
import os
import re
import ssl
import urllib.request
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from .config import Config
from .engine import Engine
from .report import write_reports
from .store import RunStore
from . import gitdump
from . import payout as _payout
from . import repro as _repro

_DUMP_MAX = 8 * 1024 * 1024        # 8 MiB cap per dumped resource
_DUMP_CTX = ssl.create_default_context()
_DUMP_CTX.check_hostname = False
_DUMP_CTX.verify_mode = ssl.CERT_NONE


def _raw_fetch(url: str):
    """Fetch a URL's raw bytes (no TLS verify), following redirects. -> (bytes, ctype, err)."""
    req = urllib.request.Request(url, headers={"User-Agent": "edu-recon-dump"})
    try:
        resp = urllib.request.urlopen(req, timeout=20, context=_DUMP_CTX)
        return resp.read(_DUMP_MAX), (resp.headers.get("Content-Type") or ""), None
    except Exception as e:                       # HTTPError / URLError / timeout
        return b"", "", f"{type(e).__name__}: {e}"


def _dump_slug(url: str) -> str:
    u = urlparse(url)
    base = (u.netloc + u.path).replace("\\", "/")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("_") or "resource"
    return base[:120]


def _uniq(dirpath: str, name: str) -> str:
    fn, n = name, 1
    while os.path.exists(os.path.join(dirpath, fn)):
        fn = f"{name}.{n}"
        n += 1
    return fn


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
            m = re.match(r"^/api/runs/([^/]+)/payout$", p)
            if m:
                d = self._run_dict(m.group(1))
                return self._send(200 if d else 404,
                                  _payout.directives_for_run(d) if d else {"error": "not found"})
            m = re.match(r"^/api/runs/([^/]+)/repro$", p)
            if m:
                d = self._run_dict(m.group(1))
                if not d:
                    return self._send(404, {"error": "not found"})
                scripts = _repro.scripts_for_run(d)
                fid = parse_qs(u.query).get("finding_id", [None])[0]
                if fid:
                    scripts = [s for s in scripts if s["id"] == fid]
                return self._send(200, scripts)
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
                        "concurrency": body.get("concurrency", cfg.concurrency),
                        "scope_enforce": body.get("scope_enforce")}
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
            m = re.match(r"^/api/runs/([^/]+)/dump$", p)
            if m:
                return self._dump(m.group(1), self._body_json())
            m = re.match(r"^/api/runs/([^/]+)/dumps/clear$", p)
            if m:
                import shutil as _sh
                dd = os.path.join(cfg.workdir, m.group(1), "dumps")
                n = 0
                if os.path.isdir(dd):
                    for name in os.listdir(dd):
                        pth = os.path.join(dd, name)
                        try:
                            _sh.rmtree(pth) if os.path.isdir(pth) else os.remove(pth)
                            n += 1
                        except OSError:
                            pass
                return self._send(200, {"ok": True, "cleared": n})
            return self._send(404, {"error": "not found"})

        def _run_hosts(self, rid) -> set:
            """Hosts the run is authorized against — the dump allowlist."""
            hosts: set[str] = set()
            d = self._run_dict(rid) or {}
            for t in d.get("targets", []):
                if t.get("host"):
                    hosts.add(t["host"])
                bu = t.get("base_url") or ""
                if bu:
                    h = urlparse(bu).hostname
                    if h:
                        hosts.add(h)
            return hosts

        def _dump(self, rid, body):
            """Immediately capture a leak server-side, before it vanishes.

            Dispatches by finding type: an exposed .git/ is fully dumped and the
            source reconstructed; a leaked key is captured with its context; any
            other exposed URL is fetched raw. Scope-locked: only hosts that were
            targets of THIS run may be touched. Saved under runs/<rid>/dumps/.
            """
            fid = body.get("finding_id")
            url = (body.get("url") or "").strip()
            hosts = self._run_hosts(rid)
            finding = None
            if fid:
                for t in (self._run_dict(rid) or {}).get("targets", []):
                    for f in t.get("findings", []):
                        if f.get("id") == fid:
                            finding = f
                            break
                    if finding:
                        break
            ev = (finding or {}).get("evidence", {}) or {}
            cat = (finding or {}).get("category", "")
            if not url:
                url = ev.get("url", "")

            if url and re.search(r"/\.git($|/)", url, re.I):
                return self._dump_git(rid, url, hosts)
            if cat == "secret-leak" and finding and (ev.get("value") or ev.get("match")) \
                    and not url.rstrip("/").lower().endswith((".env", ".htpasswd", ".bak", ".sql")):
                return self._dump_key(rid, finding, hosts)

            if not url.lower().startswith(("http://", "https://")):
                return self._send(400, {"error": "nothing to dump (no url/value)"})
            host = urlparse(url).hostname or ""
            if cfg.scope_enforce and host not in hosts:
                return self._send(403, {"error": f"out of scope: {host!r} not a target of this run"})
            data, ctype, err = _raw_fetch(url)
            if err:
                return self._send(502, {"error": f"fetch failed (already taken down?): {err}"})
            dump_dir = os.path.join(cfg.workdir, rid, "dumps")
            os.makedirs(dump_dir, exist_ok=True)
            fn = _uniq(dump_dir, datetime.now().strftime("%H%M%S") + "_" + _dump_slug(url))
            with open(os.path.join(dump_dir, fn), "wb") as fh:
                fh.write(data)
            return self._send(200, {
                "ok": True, "kind": "file", "saved": "dumps/" + fn, "size": len(data),
                "content_type": ctype, "truncated": len(data) >= _DUMP_MAX,
                "preview": data[:4096].decode("utf-8", "replace"),
            })

        def _dump_git(self, rid, url, hosts):
            host = urlparse(url).hostname or ""
            if cfg.scope_enforce and host not in hosts:
                return self._send(403, {"error": f"out of scope: {host!r}"})
            low = url.lower()
            base = url[:low.find("/.git")] + "/.git/"
            stamp = datetime.now().strftime("%H%M%S")
            out_root = os.path.join(cfg.workdir, rid, "dumps", f"{stamp}_{_dump_slug(host)}_git")
            os.makedirs(out_root, exist_ok=True)

            def gfetch(u):
                b, _c, e = _raw_fetch(u)
                return b, e
            res = gitdump.dump_git(base, out_root, gfetch)
            summ = [f"# git dump: {base}",
                    f"# reconstructed {res['files_reconstructed']} file(s) · "
                    f"{res['objects']} object(s) · {res['packs']} pack(s)"
                    + ("  [truncated]" if res["truncated"] else ""), ""]
            summ += res["sample_files"]
            if res["packed_only"]:
                summ.append("\n(objects are packed — run `git` on the saved .git/ to check out)")
            with open(os.path.join(out_root, "SUMMARY.txt"), "w", encoding="utf-8") as fh:
                fh.write("\n".join(summ) + "\n")
            rel = os.path.relpath(out_root, os.path.join(cfg.workdir, rid)).replace("\\", "/")
            return self._send(200, {"ok": True, "kind": "git", "saved": rel + "/SUMMARY.txt",
                                    "dir": rel, "files": res["files_reconstructed"],
                                    "objects": res["objects"], "packs": res["packs"],
                                    "packed_only": res["packed_only"], "preview": "\n".join(summ)})

        def _dump_key(self, rid, finding, hosts):
            ev = finding.get("evidence", {}) or {}
            typ = finding.get("title", "").replace("Leaked secret:", "").strip() or "secret"
            lines = [f"type: {typ}", f"value: {ev.get('value', '')}",
                     f"found_in: {ev.get('url', '')}", f"match: {ev.get('match', '')}",
                     f"severity: {finding.get('severity', '')}"]
            dump_dir = os.path.join(cfg.workdir, rid, "dumps")
            os.makedirs(dump_dir, exist_ok=True)
            stamp = datetime.now().strftime("%H%M%S")
            fn = _uniq(dump_dir, f"{stamp}_key_{re.sub(r'[^A-Za-z0-9]+', '_', typ)[:40]}.txt")
            with open(os.path.join(dump_dir, fn), "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines) + "\n")
            asset = ""
            aurl = ev.get("url", "")
            if aurl.lower().startswith(("http://", "https://")) and (urlparse(aurl).hostname in hosts):
                data, _c, err = _raw_fetch(aurl)
                if data:
                    afn = _uniq(dump_dir, f"{stamp}_{_dump_slug(aurl)}")
                    with open(os.path.join(dump_dir, afn), "wb") as fh:
                        fh.write(data)
                    asset = "dumps/" + afn
            return self._send(200, {"ok": True, "kind": "key", "saved": "dumps/" + fn,
                                    "asset": asset, "preview": "\n".join(lines)})

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
<meta name="viewport" content="width=device-width, initial-scale=1"><title>edu-recon console</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600;700;800&display=swap" rel="stylesheet">
<style>
 :root{
  --bg:#0B0B09;--panel:#101010;--deep:#070707;--scrim:rgba(4,3,12,.8);
  --line:rgba(150,146,120,.14);--line2:rgba(150,146,120,.20);--line1:rgba(150,146,120,.06);
  --fg0:#F1EFE2;--fg:#DAD8C8;--soft:#C8C6B4;--dim:#8F8B72;--faint:#82806A;--faintest:#4E4C3C;
  --y:#F2E409;--y2:#FFF64D;--mag:#FF3DAE;--teal:#15707F;--blue:#3AA0FF;
  --crit:#FF3D5E;--high:#FF7A2A;--med:#F6C63A;--low:#3AA0FF;--info:#8E8CEA;
 }
 *{box-sizing:border-box}
 html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);
  font-family:'JetBrains Mono',ui-monospace,Consolas,monospace;-webkit-font-smoothing:antialiased}
 a{color:var(--y);text-decoration:none}a:hover{color:var(--y2)}
 ::selection{background:rgba(242,228,9,.22);color:#111}
 ::-webkit-scrollbar{width:9px;height:9px}::-webkit-scrollbar-track{background:var(--bg)}
 ::-webkit-scrollbar-thumb{background:#26241a}::-webkit-scrollbar-thumb:hover{background:#3a3826}
 textarea,input,select{font-family:inherit;outline:none}
 button{font-family:inherit;cursor:pointer;background:none;border:none;color:inherit}
 @keyframes erpulse{0%,100%{opacity:.45}50%{opacity:1}}
 @keyframes erblink{0%,49%{opacity:1}50%,100%{opacity:0}}
 @keyframes erfade{from{opacity:0;transform:translateY(3px)}to{opacity:1;transform:none}}
 .app{height:100vh;display:flex;flex-direction:column;overflow:hidden;position:relative;
  background:var(--bg);
  background-image:
   repeating-linear-gradient(0deg,rgba(0,0,0,.20) 0 1px,transparent 1px 3px),
   radial-gradient(1100px 700px at 86% -12%,rgba(255,61,174,.08),transparent 58%),
   radial-gradient(1000px 680px at -6% 112%,rgba(242,228,9,.06),transparent 55%),
   linear-gradient(rgba(150,146,120,.05) 1px,transparent 1px),
   linear-gradient(90deg,rgba(150,146,120,.05) 1px,transparent 1px);
  background-size:100% 100%,100% 100%,100% 100%,42px 42px,42px 42px}
 .notch{clip-path:polygon(0 0,100% 0,100% calc(100% - 13px),calc(100% - 13px) 100%,0 100%)}
 .notch7{clip-path:polygon(0 0,100% 0,100% calc(100% - 7px),calc(100% - 7px) 100%,0 100%)}
 /* top bar */
 .top{display:flex;align-items:stretch;height:52px;border-bottom:1px solid rgba(150,146,120,.16);background:#101010;flex:none;position:relative;z-index:5}
 .brand{display:flex;align-items:center;gap:10px;padding:0 18px;border-right:1px solid var(--line)}
 .bdot{width:9px;height:9px;background:var(--y);box-shadow:0 0 0 3px rgba(242,228,9,.12),0 0 12px rgba(242,228,9,.75)}
 .btitle{font-weight:800;letter-spacing:1px;color:var(--y);text-shadow:0 0 10px rgba(242,228,9,.55);font-size:14px}
 .bver{font-size:9px;color:var(--faint);align-self:flex-start;margin-top:12px}
 .topmid{display:flex;align-items:center;gap:14px;padding:0 16px;flex:1;font-size:11px}
 .lab{font-size:10px;color:var(--faint);letter-spacing:1px}
 .vbar{width:1px;height:20px;background:var(--line)}
 .topbtns{display:flex;align-items:center;gap:6px;padding:0 12px}
 .tbtn{padding:7px 13px;border:1px solid var(--line2);color:var(--faint);font-size:11px;font-weight:700;letter-spacing:1px}
 .tbtn:hover{color:var(--fg);border-color:rgba(150,146,120,.4)}
 .tbtn.run{border-color:var(--y);color:var(--y);background:rgba(242,228,9,.05)}
 .tbtn.run:hover{background:rgba(242,228,9,.14)}
 .tbtn.stop:hover{color:var(--crit);border-color:rgba(255,61,94,.45)}
 select.runs{background:#0d0d0b;border:1px solid var(--line2);color:var(--fg);font-size:10px;padding:5px 7px;max-width:190px}
 /* tabs */
 .tabs{display:flex;align-items:center;height:38px;border-bottom:1px solid rgba(150,146,120,.16);background:#0B0B09;flex:none;padding:0 8px;gap:2px;position:relative;z-index:5}
 .tab{padding:9px 16px;font-size:11px;letter-spacing:1px;font-weight:600;color:var(--faint);border-bottom:2px solid transparent}
 .tab:hover{color:var(--fg)}.tab.on{color:var(--y);border-bottom-color:var(--y)}
 .tally{display:flex;align-items:center;gap:12px;padding-right:14px;font-size:10px}
 .view{flex:1;min-height:0;position:relative}
 .pane{position:absolute;inset:0;overflow:auto}
 /* generic */
 .eyebrow{font-size:11px;color:var(--faint);letter-spacing:2px;margin-bottom:4px}
 .vtitle{font-size:19px;font-weight:800;color:var(--fg0);letter-spacing:.5px}
 .help{font-size:11px;color:var(--faint);margin-top:5px;line-height:1.6}
 textarea.tg{width:100%;height:150px;background:#101010;border:1px solid var(--line2);color:var(--fg);font-size:13px;line-height:1.7;padding:12px 14px;resize:vertical;letter-spacing:.3px}
 .prow{display:flex;align-items:center;gap:12px;padding:8px 12px;background:rgba(242,228,9,.05);border:1px solid rgba(242,228,9,.25)}
 .pkind{width:52px;font-size:9px;color:var(--faint);letter-spacing:1px;text-transform:uppercase}
 .icard{cursor:pointer;padding:13px 15px;border:1px solid var(--line2);background:rgba(242,228,9,.03);display:flex;align-items:center;gap:14px}
 .icard:hover{border-color:rgba(242,228,9,.5)}
 .icard.on{border-color:var(--y)}
 .ibox{width:14px;height:14px;border:1px solid var(--faint);display:flex;align-items:center;justify-content:center}
 .icard.on .ibox{border-color:var(--y)} .icard.on .ibox>i{background:var(--y)}
 .ibox>i{width:7px;height:7px;background:transparent;display:block}
 .iname{font-size:14px;font-weight:800;letter-spacing:1px;width:78px}
 .itag{font-size:9px;color:var(--faint);border:1px solid var(--line2);padding:2px 7px;letter-spacing:1px}
 .arm{margin-top:4px;padding:15px;text-align:center;border:1px solid var(--y);background:rgba(242,228,9,.06);color:var(--y);font-size:14px;font-weight:800;letter-spacing:2px}
 .arm:hover{background:rgba(242,228,9,.14)}
 .stgp{display:flex;align-items:center;gap:8px;padding:7px 9px;border:1px solid var(--line1);background:#101010}
 .card{border:1px solid var(--line);background:#101010}
 .khead{display:flex;align-items:center;justify-content:space-between;padding:9px 13px;border-bottom:1px solid var(--line)}
 .mono{font-family:inherit}
 /* kpi */
 .kpi{flex:1;border:1px solid var(--line);background:#101010;padding:10px 14px}
 .kpi .n{font-size:20px;font-weight:800;color:var(--fg);margin-top:2px}
 /* matrix */
 .cell{height:26px;border:1px solid var(--line2);cursor:pointer}
 .cell:hover{outline:1px solid rgba(242,228,9,.55);outline-offset:-1px}
 /* log */
 .logwrap{height:230px;flex:none;border:1px solid var(--line);background:#070707;display:flex;flex-direction:column}
 .logbody{flex:1;min-height:0;overflow:auto;padding:8px 12px;font-size:11px;line-height:1.65}
 .lln{display:flex;gap:8px}
 .lln .tag{flex:none;min-width:52px}
 .cur{width:8px;height:14px;background:var(--y);box-shadow:0 0 8px var(--y);animation:erblink 1s step-end infinite;display:inline-block}
 /* feed */
 .fcard{border:1px solid var(--line1);border-left:3px solid var(--faint);padding:8px 10px;background:#070707;animation:erfade .2s ease}
 /* findings */
 .chip{cursor:pointer;display:flex;align-items:center;gap:6px;padding:5px 11px;border:1px solid var(--line2);font-size:10px;font-weight:700;letter-spacing:.5px;color:var(--faint)}
 .chip.on{color:var(--fg)}
 .srch{width:220px;background:#101010;border:1px solid var(--line2);color:var(--fg);font-size:11px;padding:7px 11px}
 .ftable{display:grid;grid-template-columns:88px 60px 1fr 200px 150px 120px;gap:12px;padding:12px 18px;align-items:center;cursor:pointer}
 .ftable:hover{background:rgba(150,146,120,.04)}
 .sevb{font-size:9px;font-weight:800;letter-spacing:.5px;color:#0B0B09;padding:3px 7px}
 .statb{font-size:9px;font-weight:700;letter-spacing:.5px;padding:3px 8px;border:1px solid}
 .exp{padding:0 18px 20px;display:grid;grid-template-columns:1.3fr 1fr;gap:18px;background:#070707;animation:erfade .18s ease}
 .oracle{border:1px solid var(--line2);background:#0B0B09;padding:12px 14px}
 .metagrid{display:grid;grid-template-columns:auto 1fr;gap:5px 12px;font-size:11px}
 .abtn{cursor:pointer;font-size:10px;font-weight:700;letter-spacing:.5px;padding:7px 13px;border:1px solid var(--line2);color:var(--fg)}
 .abtn:hover{border-color:rgba(242,228,9,.5)}
 .abtn.y{border-color:var(--y);color:var(--y)}.abtn.on{background:var(--y);color:#0B0B09;border-color:var(--y)}
 .abtn.blue{border-color:var(--blue);color:var(--blue)}
 code{color:var(--y);word-break:break-all}
 /* shell overlay */
 .scrim{position:fixed;inset:0;background:var(--scrim);display:flex;justify-content:flex-end;z-index:50}
 .shell{width:min(680px,92vw);height:100%;background:#0B0B09;border-left:1px solid rgba(242,228,9,.25);display:flex;flex-direction:column;box-shadow:-20px 0 60px rgba(0,0,0,.6)}
 .shead{flex:none;padding:14px 18px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:12px}
 .scmd{flex:none;padding:10px 18px;border-bottom:1px solid var(--line1);background:#101010}
 .sbody{flex:1;min-height:0;overflow:auto;padding:14px 18px;font-size:11px;line-height:1.7;white-space:pre-wrap;word-break:break-all}
 .toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%) translateY(16px);background:#101010;border:1px solid var(--y);color:var(--fg);padding:9px 16px;font-size:12px;opacity:0;transition:.25s;z-index:80;max-width:70vw}
 .toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
 .muted{color:var(--faint)}
 .demo{display:flex;align-items:center;gap:6px;font-size:9px;letter-spacing:1px;color:var(--mag);border:1px solid rgba(255,61,174,.35);padding:4px 8px;margin-left:2px}
 .haz{height:2px;flex:none;background:repeating-linear-gradient(45deg,rgba(242,228,9,.55) 0 13px,transparent 13px 26px)}
 .sens{display:inline-flex;align-items:center;gap:3px;font-size:8px;font-weight:800;letter-spacing:.5px;color:var(--mag);border:1px solid rgba(255,61,174,.4);padding:1px 5px;margin-left:6px}
 .modetag{font-size:9px;font-weight:800;letter-spacing:1px;padding:2px 8px;border:1px solid}
 .mt-log{color:var(--blue);border-color:var(--blue)}.mt-dump{color:var(--mag);border-color:var(--mag)}.mt-poc{color:var(--y);border-color:var(--y)}
 .reveal{cursor:pointer;font-size:9px;color:var(--mag);border:1px solid rgba(255,61,174,.4);padding:2px 7px;margin-left:8px}
 .shell{clip-path:polygon(0 24px,24px 0,100% 0,100% 100%,0 100%)}
 .authnote{font-size:9px;color:var(--dim)}
 @keyframes erhit{0%,100%{box-shadow:0 0 0 0 currentColor}50%{box-shadow:0 0 8px 0 currentColor}}
 @keyframes erscan{0%{background-position:-40px 0}100%{background-position:40px 0}}
</style></head>
<body>
<div class="app">
 <div class="top">
  <div class="brand"><span class="bdot"></span><span class="btitle">edu-recon</span><span class="bver">v3</span></div>
  <div class="demo" title="scope-lock 已關,貼什麼掃什麼">◈ DEMO · 不鎖範圍 · scope off</div>
  <div class="topmid">
   <span class="lab">INTENSITY</span><span id="t-int" style="font-size:11px;font-weight:700;color:var(--mag)">FULL</span>
   <span class="vbar"></span>
   <span id="t-pdot" style="width:7px;height:7px;border-radius:50%;background:var(--faint)"></span>
   <span id="t-phase" style="font-size:11px;font-weight:700;letter-spacing:1px;color:var(--faint)">IDLE</span>
   <span class="lab">▸ elapsed</span><span id="t-elapsed" style="font-size:12px;color:var(--fg);font-weight:600">00:00</span>
   <span class="lab">▸ <span id="t-pct">0%</span></span>
   <span class="vbar"></span>
   <span class="lab">RUN</span>
   <select class="runs" id="runsSel" onchange="onPickRun(this.value)"><option value="">— 選既有 run —</option></select>
  </div>
  <div class="topbtns">
   <button class="tbtn run" onclick="armRun()" id="runBtn">▶ ARM &amp; RUN</button>
   <button class="tbtn stop" onclick="cancelRun()">■ CANCEL</button>
  </div>
 </div>
 <div class="tabs">
  <div class="tab on" data-v="setup"    onclick="setView('setup')">01 · SETUP / 掃描設定</div>
  <div class="tab"    data-v="monitor"  onclick="setView('monitor')">02 · MONITOR / 即時監控</div>
  <div class="tab"    data-v="findings" onclick="setView('findings')">03 · FINDINGS / 弱點清單</div>
  <div class="tab"    data-v="report"   onclick="setView('report')">04 · REPORT / 匯出報告</div>
  <div style="flex:1"></div>
  <div class="tally" id="tally"></div>
 </div>
 <div class="haz"></div>
 <div class="view"><div class="pane" id="pane"></div></div>
</div>
<div id="overlay"></div><div class="toast" id="toast"></div>
<script>
const SM={critical:{c:'var(--crit)',k:'CRIT',r:5,cvss:9.6},high:{c:'var(--high)',k:'HIGH',r:4,cvss:8.1},
 medium:{c:'var(--med)',k:'MED',r:3,cvss:6.1},low:{c:'var(--low)',k:'LOW',r:2,cvss:4.0},info:{c:'var(--info)',k:'INFO',r:1,cvss:0}};
const SORD=['portscan','webdisco','exposures','secrets','phpcgi','react2shell','webcve','moodle','xss','sqli','cred','wp'];
const SMETA={portscan:{s:'PORT',n:'PORTSCAN',cn:'連接埠指紋 + CVE',tool:'nmap -sV -sC --script vuln'},
 webdisco:{s:'WEB',n:'WEB-DISCO',cn:'目錄爆破・WP 偵測',tool:'dirsearch'},
 exposures:{s:'EXPO',n:'EXPOSURES',cn:'.git/.env/面板/列表',tool:'edu-recon/expose'},
 secrets:{s:'SEC',n:'SECRETS',cn:'金鑰・Swagger/GraphQL',tool:'edu-recon/secrets'},
 phpcgi:{s:'PCGI',n:'PHP-CGI',cn:'CVE-2024-4577',tool:'php-cgi-Injector'},
 react2shell:{s:'RSC',n:'REACT2SHELL',cn:'CVE-2025-55182',tool:'react2shell'},
 webcve:{s:'WCVE',n:'WEB-CVE',cn:'6 顆經典 CVE',tool:'edu-recon/webcve'},
 moodle:{s:'MDL',n:'MOODLE',cn:'LMS 指紋・moodledata',tool:'edu-recon/moodle'},
 xss:{s:'XSS',n:'XSS',cn:'dalfox・反射探針',tool:'dalfox'},
 sqli:{s:'SQLI',n:'SQLI',cn:'error 快掃・sqlmap',tool:'sqlmap'},
 cred:{s:'CRED',n:'CREDENTIALS',cn:'hydra 弱密碼',tool:'hydra'},
 wp:{s:'WP',n:'WP2SHELL',cn:'WordPress SQLi→shell',tool:'wp2shell'}};
const ALWAYS=['portscan','webdisco','exposures','secrets','moodle'];
const ACTIVE=['phpcgi','react2shell','webcve','xss','sqli','cred','wp'];
const REMED={cve:'升級受影響元件至修補版本;下架對外 CGI/管理端點。',
 'secret-leak':'移除外露資源、輪換洩漏憑證、加存取控制。','vcs-leak':'移除對外 .git;封鎖點目錄;改部署產物。',
 'backup-leak':'移除備份檔;禁止 web 存取備份路徑。','admin-panel':'面板限內網/VPN;IP 白名單。',
 'dir-listing':'關閉 autoindex (Options -Indexes)。','weak-cred':'停用預設帳號;強密碼 + MFA。',
 'xss':'輸出編碼;CSP;參數過濾。','sqli':'參數化查詢;最小權限 DB;WAF。','edtech':'升級至受支援分支;資料目錄移出 web root。','vuln-version':'升級至受支援版本。'};
let ST={view:'setup',runId:null,run:null,logs:[],logIdx:0,intensity:'full',
 targetsText:'http://127.0.0.1:8081\nhttp://127.0.0.1:8082',
 sev:new Set(['critical','high','medium','low','info']),statF:'all',q:'',sortBy:'sev',
 openF:null,fmt:'html',opt:{evidence:true,plaintext:false,scope:true,rawlog:false,minSev:'low'},
 reveal:new Set(),dumps:{},dtimer:null,ltimer:null,elapsed:0,t0:0};
const LEAK_CATS=['secret-leak','vcs-leak','backup-leak','admin-panel','dir-listing','info-leak'];
function isLeak(f){const ev=f.evidence||{};return LEAK_CATS.includes(f.category)&&(ev.url||ev.value);}
function isSensitive(f){const ev=f.evidence||{};return !!ev.value||['secret-leak','vcs-leak'].includes(f.category)
 ||/password|secret|token|private key|BEGIN [A-Z ]*PRIVATE/i.test(JSON.stringify(ev));}
function dumpKind(f){const ev=f.evidence||{};if(/\/\.git($|\/)/i.test(ev.url||''))return 'git';
 if(f.category==='secret-leak'&&ev.value&&!/\.(env|bak|sql|htpasswd)$/i.test((ev.url||'').replace(/\/$/,'')))return 'key';return 'file';}
function maskVal(s){s=''+s;if(s.length<=8)return s.slice(0,2)+'•••';const m=s.match(/^(AKIA|ghp_|gho_|xox.-|sk-|eyJ|-----BEGIN)/);
 return (m?m[1]:s.slice(0,4))+'•••'+s.slice(-4);}
function maskText(t){return (''+t)
 .replace(/AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|eyJ[A-Za-z0-9_-]{10,}|[A-Za-z0-9\/+]{28,}={0,2}/g,x=>maskVal(x))
 .replace(/(password|secret|pass|pwd|token|api[_-]?key)([=:"'\s]+)([^\s"'&,]+)/gi,(_,a,b,c)=>a+b+maskVal(c))
 .replace(/(root:)[^\n]+/g,'$1x:0:0:••••');}
function api(m,u,b){const o={method:m,headers:{'Content-Type':'application/json'}};if(b)o.body=JSON.stringify(b);
 return fetch(u,o).then(r=>r.json()).catch(()=>null);}
function esc(s){return (s==null?'':''+s).replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function cssvar(v){return v&&v.startsWith('var(')?getComputedStyle(document.documentElement).getPropertyValue(v.slice(4,-1)).trim():v;}
function fmtT(s){const m=Math.floor(s/60),ss=Math.floor(s%60);return String(m).padStart(2,'0')+':'+String(ss).padStart(2,'0');}
function included(sid){return ST.intensity==='passive'?ALWAYS.includes(sid):(ALWAYS.includes(sid)||ACTIVE.includes(sid));}
/* ---- data helpers ---- */
function targets(){return (ST.run&&ST.run.targets)||[];}
function allFindings(){const o=[];for(const t of targets())for(const f of (t.findings||[]))o.push({...f,host:t.host,tid:t.raw||t.host});return o;}
function counts(){const c={critical:0,high:0,medium:0,low:0,info:0};for(const f of allFindings())if(!f.false_positive)c[f.severity]=(c[f.severity]||0)+1;return c;}
function fstat(f){return f.reviewed?'confirmed':f.false_positive?'false-positive':(f.category==='candidate'?'candidate':'new');}
function phase(){if(!ST.run)return 'idle';const s=ST.run.status;return s==='running'||s==='expanding'||s==='pending'?'running':s==='cancelled'?'idle':s;}
/* ---- runs / submit ---- */
async function loadRuns(){const rs=await api('GET','/api/runs');if(!Array.isArray(rs))return;
 const sel=document.getElementById('runsSel');const cur=sel.value;
 sel.innerHTML='<option value="">— 選既有 run —</option>'+rs.map(r=>{const sv=(r.summary||{}).severity||{};
  return `<option value="${r.id}">${esc(r.id)} · ${esc(r.status)} · C${sv.critical||0}H${sv.high||0}</option>`;}).join('');
 sel.value=ST.runId||cur||'';}
function onPickRun(id){if(!id)return;selectRun(id);}
async function armRun(){const t=ST.targetsText.trim();if(!t)return toast('請貼上標的');
 const r=await api('POST','/api/runs',{targets:t,intensity:ST.intensity,concurrency:4,scope_enforce:false});
 if(r&&r.id){selectRun(r.id);loadRuns();}else toast((r&&r.error)||'啟動失敗');}
function selectRun(id){ST.runId=id;ST.logs=[];ST.logIdx=0;ST.run=null;ST.t0=Date.now();ST.view='monitor';
 if(ST.dtimer)clearInterval(ST.dtimer);if(ST.ltimer)clearInterval(ST.ltimer);
 pollDetail();tailLog();ST.dtimer=setInterval(pollDetail,2500);ST.ltimer=setInterval(tailLog,1200);render();}
async function cancelRun(){if(ST.runId)await api('POST','/api/runs/'+ST.runId+'/cancel');pollDetail();}
async function pollDetail(){if(!ST.runId)return;const d=await api('GET','/api/runs/'+ST.runId);if(!d||d.error)return;
 ST.run=d;if(d.options&&d.options.intensity)ST.intensity=d.options.intensity;
 const ph=phase();if(ph!=='running'&&ST.dtimer){clearInterval(ST.dtimer);ST.dtimer=null;}
 render();}
async function tailLog(){if(!ST.runId)return;const r=await api('GET','/api/runs/'+ST.runId+'/logs?since='+ST.logIdx);
 if(!r)return;if(Array.isArray(r.logs)&&r.logs.length){ST.logs.push(...r.logs);ST.logIdx=r.next||ST.logIdx;
  if(ST.view==='monitor')appendLogs(r.logs);}
 if(!['running','expanding','pending'].includes(r.status)&&ST.ltimer){clearInterval(ST.ltimer);ST.ltimer=null;}}
/* ---- render ---- */
function setView(v){ST.view=v;render();}
function chrome(){
 document.getElementById('t-int').textContent=ST.intensity.toUpperCase();
 const ph=phase();const pc={idle:'var(--faint)',running:'var(--mag)',done:'var(--y)',error:'var(--crit)'}[ph]||'var(--faint)';
 document.getElementById('t-phase').textContent={idle:'IDLE',running:'SCANNING',done:'COMPLETE',error:'ERROR'}[ph]||ph.toUpperCase();
 document.getElementById('t-phase').style.color=pc;document.getElementById('t-pdot').style.background=pc;
 const tg=targets();const done=tg.filter(t=>t.status==='done').length;
 document.getElementById('t-pct').textContent=(tg.length?Math.round(done/tg.length*100):0)+'%';
 if(ST.run&&ph==='running')ST.elapsed=(Date.now()-ST.t0)/1000;
 document.getElementById('t-elapsed').textContent=fmtT(ST.elapsed);
 document.getElementById('runBtn').textContent=ph==='running'?'▶ RUNNING…':ph==='done'?'↻ RE-RUN':'▶ ARM & RUN';
 const c=counts();document.getElementById('tally').innerHTML=
  [['crit','critical'],['high','high'],['med','medium'],['low','low'],['info','info']]
  .map(([l,k])=>`<span style="color:${SM[k].c}">■ ${c[k]||0} ${SM[k].k}</span>`).join('');
 document.querySelectorAll('.tab').forEach(t=>t.classList.toggle('on',t.dataset.v===ST.view));
}
function render(){chrome();const p=document.getElementById('pane');
 if(ST.view==='setup')p.innerHTML=vSetup();
 else if(ST.view==='monitor'){p.innerHTML=vMonitor();appendLogs(ST.logs,true);}
 else if(ST.view==='findings')p.innerHTML=vFindings();
 else p.innerHTML=vReport();
 renderOverlay();}
/* ---- setup ---- */
function vSetup(){const rows=ST.targetsText.split('\n').map(x=>x.trim()).filter(Boolean)
  .map(h=>({host:h,kind:h.includes('/')&&/\d\/\d/.test(h)?'cidr':(/^https?:|[a-z]/i.test(h)?'url/host':'host')}));
 const intens=[['full','FULL','全跑 · 注入 + 弱密碼實際執行','預設'],['recon','RECON','探測全跑 · sqli/cred/wp 只列候選','候選'],['passive','PASSIVE','純被動盤點 · 只發良性 GET','唯讀']];
 const stg=SORD.map(id=>{const on=included(id);const act=ACTIVE.includes(id);
  const c=on?(act?'var(--mag)':'var(--y)'):'var(--faint)';
  return `<div class="stgp"><span style="width:5px;height:5px;border-radius:50%;background:${c}"></span>
   <span style="font-size:10px;font-weight:700;color:${c};width:42px">${SMETA[id].s}</span>
   <span style="flex:1;font-size:10px;color:var(--dim);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${SMETA[id].cn}</span></div>`;}).join('');
 return `<div style="padding:26px 30px;display:grid;grid-template-columns:1.15fr 1fr;gap:26px;align-content:start">
  <div style="display:flex;flex-direction:column;gap:18px">
   <div><div class="eyebrow">STEP 01</div><div class="vtitle">貼上標的 · TARGET LIST</div>
    <div class="help">主機 / 網域 / 授權 CIDR / URL,一行一個。scope-lock 已依需求移除,貼什麼掃什麼。</div></div>
   <textarea class="tg" spellcheck="false" oninput="ST.targetsText=this.value;refreshRows()">${esc(ST.targetsText)}</textarea>
   <div id="prows" style="display:flex;flex-direction:column;gap:5px">${rows.map(r=>`<div class="prow"><span class="pkind">${esc(r.kind)}</span><span style="flex:1;font-size:12px;color:var(--fg)">${esc(r.host)}</span></div>`).join('')}</div>
  </div>
  <div style="display:flex;flex-direction:column;gap:18px">
   <div><div class="eyebrow">STEP 02</div><div class="vtitle">選擇強度 · INTENSITY</div></div>
   <div style="display:flex;flex-direction:column;gap:8px">
    ${intens.map(([id,nm,cn,tag])=>`<div class="icard ${ST.intensity===id?'on':''}" onclick="ST.intensity='${id}';render()">
     <span class="ibox"><i></i></span>
     <span class="iname" style="color:${ST.intensity===id?'var(--y)':'var(--faint)'}">${nm}</span>
     <span style="flex:1;font-size:11px;color:var(--dim)">${cn}</span><span class="itag">${tag}</span></div>`).join('')}
   </div>
   <div><div class="lab" style="letter-spacing:2px;margin-bottom:8px">PIPELINE · 此強度下執行的 STAGE</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:5px">${stg}</div>
    <div style="font-size:9px;color:var(--faint);margin-top:9px"><span style="color:var(--y)">●</span> 被動探測　<span style="color:var(--mag)">●</span> 主動注入　<span style="color:var(--faint)">●</span> 此強度略過</div></div>
   <div class="arm notch" onclick="armRun()">▶ ARM & RUN →</div>
  </div></div>`;}
function refreshRows(){const el=document.getElementById('prows');if(!el)return;
 const rows=ST.targetsText.split('\n').map(x=>x.trim()).filter(Boolean);
 el.innerHTML=rows.map(h=>`<div class="prow"><span class="pkind">${h.includes('/')&&/\d\/\d/.test(h)?'cidr':'url/host'}</span><span style="flex:1;font-size:12px;color:var(--fg)">${esc(h)}</span></div>`).join('');}
/* ---- monitor ---- */
function stageHit(t,sid){let mx=null;for(const f of (t.findings||[]))if(f.stage===sid&&!f.false_positive){if(!mx||SM[f.severity].r>SM[mx].r)mx=f.severity;}return mx;}
function cellStyle(t,sid){const st=(t.stages||{})[sid];const s=st?st.status:'na';const hit=stageHit(t,sid);
 let bg='transparent',bd='var(--line2)',anim='none';
 if(hit){bg=SM[hit].c;bd='transparent';}
 else if(s==='running'){bg='var(--mag)';bd='transparent';anim='erpulse 1s ease-in-out infinite';}
 else if(s==='done'){bg='var(--teal)';bd='transparent';}
 else if(s==='skipped'){bg='repeating-linear-gradient(45deg,rgba(150,146,120,.10) 0 3px,transparent 3px 6px)';bd='var(--line1)';}
 else if(s==='error'){bg='var(--crit)';bd='transparent';}
 else if(s==='pending'||!st){bd='var(--line2)';}
 return {bg,bd,anim,s};}
function vMonitor(){const tg=targets();const c=counts();const done=tg.filter(t=>t.status==='done').length;
 const pct=tg.length?Math.round(done/tg.length*100):0;const nF=allFindings().filter(f=>!f.false_positive).length;
 const heads=SORD.map(id=>`<div title="${SMETA[id].n}" style="font-size:8px;color:var(--faint);text-align:center;transform:rotate(-90deg);height:34px;display:flex;align-items:center;justify-content:center;white-space:nowrap">${SMETA[id].s}</div>`).join('');
 const rows=tg.map(t=>{const cells=SORD.map(id=>{const cs=cellStyle(t,id);
   return `<div class="cell" title="${id} · ${cs.s}" onclick="openCell('${esc(t.raw||t.host)}','${id}')" style="background:${cs.bg};border-color:${cs.bd};animation:${cs.anim}"></div>`;}).join('');
  const dn=Object.values(t.stages||{}).filter(s=>['done','error'].includes(s.status)||stageHitAny(t,s)).length;
  const tot=Object.keys(t.stages||{}).length||1;const rp=Math.round(dn/tot*100);
  const run=Object.values(t.stages||{}).some(s=>s.status==='running');
  const sc=run?'var(--mag)':(t.status==='done'?'var(--y)':'var(--faint)');
  return `<div style="display:grid;grid-template-columns:190px repeat(12,1fr);gap:3px;margin-bottom:3px;align-items:center">
   <div style="padding-right:8px;overflow:hidden">
    <div style="display:flex;align-items:center;gap:6px"><span style="width:5px;height:5px;border-radius:50%;background:${sc};flex:none"></span>
     <span style="font-size:11px;color:var(--fg);white-space:nowrap;overflow:hidden;text-overflow:ellipsis">${esc(t.host)}</span></div>
    <div style="padding-left:11px;display:flex;gap:6px;align-items:center;flex-wrap:wrap"><span style="font-size:8px;color:var(--faint)">${esc(t.status)} · ${rp}%</span>${(t.webpaths||[]).length?`<span onclick="event.stopPropagation();openPaths('${esc(t.host)}')" style="cursor:pointer;font-size:8px;color:var(--blue);border:1px solid rgba(58,160,255,.4);padding:0 4px">🗂 ${(t.webpaths||[]).length} 路徑</span>`:''}</div></div>${cells}</div>`;}).join('');
 const feed=allFindings().filter(f=>!f.false_positive).slice().reverse().slice(0,16).map(f=>`
   <div class="fcard" style="border-left-color:${SM[f.severity].c}">
    <div style="display:flex;align-items:center;gap:7px;margin-bottom:3px">
     <span style="font-size:8px;font-weight:800;color:${SM[f.severity].c}">${SM[f.severity].k}</span>
     <span style="font-size:9px;color:var(--faint)">CVSS ${SM[f.severity].cvss}</span><span style="flex:1"></span>
     <span style="font-size:8px;color:var(--faint)">${esc((f.evidence||{}).cve||'—')}</span></div>
    <div style="font-size:11px;color:var(--fg);line-height:1.4">${esc(f.title)}${isSensitive(f)?'<span class="sens">🔒</span>':''}</div>
    <div style="font-size:9px;color:var(--dim);margin-top:3px">${esc(f.host)}</div></div>`).join('')||'<div class="muted" style="padding:20px;font-size:11px">尚無 finding…</div>';
 return `<div style="position:absolute;inset:0;display:flex;flex-direction:column;padding:14px 16px;gap:12px;overflow:hidden">
  <div style="display:flex;gap:10px;flex:none">
   <div class="kpi"><div class="lab">TARGETS</div><div class="n">${done}<span style="font-size:12px;color:var(--faint)">/${tg.length}</span></div></div>
   <div class="kpi"><div class="lab">PROGRESS</div><div class="n" style="color:var(--mag)">${pct}%</div><div style="height:3px;background:var(--line2);margin-top:5px"><div style="height:100%;width:${pct}%;background:var(--mag)"></div></div></div>
   <div class="kpi" style="flex:2;display:flex;align-items:center;gap:18px"><div><div class="lab">FINDINGS</div><div class="n">${nF}</div></div>
    <div style="display:flex;gap:14px;flex:1">${[['critical'],['high'],['medium'],['low'],['info']].map(([k])=>`<div style="text-align:center"><div style="font-size:16px;font-weight:800;color:${SM[k].c}">${c[k]||0}</div><div style="font-size:8px;color:var(--faint)">${SM[k].k}</div></div>`).join('')}</div></div>
  </div>
  <div style="flex:1;min-height:0;display:grid;grid-template-columns:1fr 320px;gap:12px">
   <div style="display:flex;flex-direction:column;gap:12px;min-height:0">
    <div class="card" style="flex:1;min-height:0;display:flex;flex-direction:column">
     <div class="khead"><span style="font-size:10px;color:var(--dim);letter-spacing:1px">PIPELINE MATRIX · 標的 × STAGE <span class="muted">(點色塊看原始 log)</span></span></div>
     <div style="flex:1;min-height:0;overflow:auto;padding:10px 13px">
      <div style="display:grid;grid-template-columns:190px repeat(12,1fr);gap:3px;margin-bottom:4px;position:sticky;top:0;background:#101010;padding-bottom:3px"><div></div>${heads}</div>
      ${rows||'<div class="muted" style="padding:20px;font-size:11px">展開標的中…</div>'}
     </div></div>
    <div class="logwrap">
     <div class="khead" style="border-bottom:1px solid var(--line1)"><span style="display:flex;align-items:center;gap:8px"><span style="width:7px;height:7px;border-radius:50%;background:var(--y)"></span><span style="font-size:10px;color:var(--dim);letter-spacing:1px">LIVE LOG · edu-recon@orchestrator</span></span><span style="font-size:9px;color:var(--faint)">stream · ${fmtT(ST.elapsed)}</span></div>
     <div class="logbody" id="er-log"></div></div>
   </div>
   <div class="card" style="display:flex;flex-direction:column;min-height:0">
    <div class="khead"><span style="font-size:10px;color:var(--dim);letter-spacing:1px">LIVE FINDINGS</span><span onclick="setView('findings')" style="cursor:pointer;font-size:9px;color:var(--y)">全部 →</span></div>
    <div style="flex:1;min-height:0;overflow:auto;padding:8px;display:flex;flex-direction:column;gap:6px">${feed}</div></div>
  </div></div>`;}
function stageHitAny(t,s){return false;}
function logCls(line){if(/FINDING \[critical\]/.test(line))return 'var(--crit)';if(/FINDING \[high\]/.test(line))return 'var(--high)';
 if(/FINDING \[medium\]/.test(line))return 'var(--med)';if(/FINDING \[low\]/.test(line))return 'var(--low)';
 if(/\bERROR\b|\bFATAL\b/.test(line))return 'var(--crit)';if(/ \$ /.test(line))return 'var(--y)';return 'var(--faint)';}
function appendLogs(lines,rebuild){const el=document.getElementById('er-log');if(!el)return;
 if(rebuild){el.innerHTML='';lines=ST.logs;}
 for(const ln of lines){const m=ln.match(/^(\d\d:\d\d:\d\d)\s([\s\S]*)$/);const tm=m?m[1]:'';const rest=m?m[2]:ln;
  const col=logCls(ln);const cmd=/ \$ /.test(ln);
  const d=document.createElement('div');d.className='lln';
  d.innerHTML=`<span class="tag" style="color:var(--faint)">${esc(tm)}</span><span style="color:${col};white-space:pre-wrap;word-break:break-all">${cmd?'❯ ':''}${esc(cmd?rest.replace(/^.*?\$\s/,''):rest)}</span>`;
  el.appendChild(d);}
 if(!document.getElementById('er-cur')){const c=document.createElement('div');c.id='er-cur';c.className='lln';c.innerHTML='<span style="color:var(--y)">❯</span><span class="cur"></span>';el.appendChild(c);}
 else el.appendChild(document.getElementById('er-cur'));
 el.scrollTop=el.scrollHeight;}
/* ---- findings ---- */
function dispFindings(){let l=allFindings().map(f=>({...f,stat:fstat(f)}));
 const q=ST.q.trim().toLowerCase();
 l=l.filter(f=>ST.sev.has(f.severity)&&(ST.statF==='all'||f.stat===ST.statF)
   &&(!q||(f.title+f.category+((f.evidence||{}).cve||'')+f.host).toLowerCase().includes(q)));
 l.sort((a,b)=>ST.sortBy==='cvss'?SM[b.severity].cvss-SM[a.severity].cvss:(SM[b.severity].r-SM[a.severity].r));
 return l;}
function vFindings(){const c=counts();const list=dispFindings();
 const sevChips=['critical','high','medium','low','info'].map(k=>{const on=ST.sev.has(k);
  return `<div class="chip ${on?'on':''}" style="border-color:${on?SM[k].c:'var(--line2)'};background:${on?'rgba(150,146,120,.05)':'transparent'}" onclick="togSev('${k}')"><span style="width:8px;height:8px;background:${SM[k].c};opacity:${on?1:.25}"></span>${SM[k].k} <span class="muted">${c[k]||0}</span></div>`;}).join('');
 const statChips=[['all','ALL'],['new','NEW'],['confirmed','CONFIRMED'],['false-positive','FALSE-POS'],['candidate','CANDIDATE']]
  .map(([k,l])=>`<div onclick="ST.statF='${k}';render()" style="cursor:pointer;font-size:10px;letter-spacing:.5px;color:${ST.statF===k?'var(--y)':'var(--faint)'};border-bottom:1px solid ${ST.statF===k?'var(--y)':'transparent'};padding-bottom:2px">${l}</div>`).join('');
 const rows=list.map(f=>{const ev=f.evidence||{};const st=f.stat;const sens=isSensitive(f);const rev=ST.reveal.has(f.id);
  const statC={confirmed:'var(--y)','false-positive':'var(--faint)',candidate:'var(--mag)',new:'var(--blue)'}[st];
  const open=ST.openF===f.id;
  const proofRaw=Object.entries(ev).filter(([k])=>k!=='reproduce').map(([k,v])=>`${k}: ${typeof v==='object'?JSON.stringify(v):v}`);
  const proof=proofRaw.map(p=>(sens&&!rev)?maskText(p):p);
  const dk=dumpKind(f);const dl={git:'⤓ DUMP .git',key:'⤓ DUMP KEY',file:'⤓ DUMP'}[dk];
  const ds=ST.dumps[f.id];const dlabel=ds?({dumping:'⟳ DUMPING…',ok:'✓ 已抓存 '+(ds.size||''),fail:'✗ 失敗',oos:'⛔ 越界'}[ds.state]||dl):dl;
  const revBtn=sens?`<span class="reveal" onclick="event.stopPropagation();togReveal('${f.id}')">${rev?'🙈 遮蔽':'👁 顯示'}</span>`:'';
  const expand=open?`<div class="exp">
    <div style="padding-top:14px">
     <div style="font-size:10px;color:var(--blue);letter-spacing:1px;margin-bottom:8px;display:flex;align-items:center">◈ SAFE-CHECK ORACLE · ${esc(ev.mode||f.confidence||'benign')}${revBtn}</div>
     <div style="font-size:10px;color:var(--dim);margin-bottom:8px">${esc(ev.note||'非破壞式驗證 · 未執行 OS 指令 · 不改狀態')}</div>
     <div class="oracle"><div style="font-size:11px;color:var(--y);margin-bottom:8px;word-break:break-all">❯ ${esc(ev.reproduce||SMETA[f.stage]?.tool||f.stage)}</div>
      ${sens&&!rev?'<div style="font-size:10px;color:var(--mag);margin-bottom:6px">🔒 機敏證據已遮蔽 · 點「👁 顯示」揭露</div>':''}
      ${proof.map(p=>`<div style="font-size:11px;color:var(--fg);line-height:1.7;word-break:break-all">${esc(p)}</div>`).join('')}</div></div>
    <div style="padding-top:14px;display:flex;flex-direction:column;gap:11px">
     <div class="metagrid"><span class="muted">URL</span><span style="word-break:break-all">${esc(ev.url||'—')}</span>
      <span class="muted">TOOL</span><span>${esc(SMETA[f.stage]?.tool||f.stage)}</span>
      <span class="muted">STAGE</span><span>${esc(f.stage)}</span>
      <span class="muted">CVE / CVSS</span><span>${esc(ev.cve||'—')} · ${SM[f.severity].cvss}</span></div>
     <div><div class="lab" style="margin-bottom:4px">REMEDIATION / 修補建議</div><div style="font-size:11px;color:var(--soft);line-height:1.65">${esc(REMED[f.category]||'依 finding 修補。')}</div></div>
     <div style="display:flex;gap:8px;flex-wrap:wrap">
      <div class="abtn ${st==='confirmed'?'on':'y'}" onclick="event.stopPropagation();confirmF('${f.id}')">✓ 確認 CONFIRM</div>
      <div class="abtn ${st==='false-positive'?'on':''}" onclick="event.stopPropagation();fpF('${f.id}')">⊘ 誤報 FALSE-POS</div>
      <div class="abtn blue" onclick="event.stopPropagation();openRepro('${f.id}')">🔁 重現腳本</div>
      ${isLeak(f)?`<div class="abtn ${ds&&ds.state==='ok'?'on':''}" onclick="event.stopPropagation();openDump('${f.id}','${dk}')">${dlabel}</div>`:''}
     </div></div></div>`:'';
  return `<div style="border-bottom:1px solid var(--line1)">
   <div class="ftable" onclick="ST.openF=ST.openF==='${f.id}'?null:'${f.id}';render()">
    <div><span class="sevb" style="background:${SM[f.severity].c}">${SM[f.severity].k}</span></div>
    <div style="font-size:13px;font-weight:700;color:${SM[f.severity].c}">${SM[f.severity].cvss}</div>
    <div><div style="font-size:12px;color:var(--fg0);font-weight:600">${esc(f.title)}${sens?'<span class="sens">🔒 SENSITIVE</span>':''}</div><div style="font-size:10px;color:var(--dim);margin-top:2px">${esc(f.category)} · ${esc(f.confidence)}</div></div>
    <div style="font-size:11px;color:var(--fg);word-break:break-all">${esc(f.host)}</div>
    <div style="font-size:10px;color:var(--dim)">${esc(f.stage)}<br><span class="muted">${esc(ev.cve||'—')}</span></div>
    <div><span class="statb" style="color:${statC};border-color:${statC}">${st.toUpperCase()}</span></div></div>${expand}</div>`;}).join('');
 return `<div style="position:absolute;inset:0;display:flex;flex-direction:column;overflow:hidden">
  <div style="flex:none;border-bottom:1px solid var(--line);padding:12px 18px;display:flex;flex-direction:column;gap:10px">
   <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><span class="lab">SEVERITY</span>${sevChips}<span style="flex:1"></span>
    <input class="srch" placeholder="搜尋 title / host / CVE…" value="${esc(ST.q)}" oninput="ST.q=this.value;render()"></div>
   <div style="display:flex;align-items:center;gap:14px"><span class="lab">STATUS</span>${statChips}<span style="flex:1"></span>
    <span class="lab">SORT</span><span onclick="ST.sortBy='sev';render()" style="cursor:pointer;font-size:10px;color:${ST.sortBy==='sev'?'var(--y)':'var(--faint)'}">SEVERITY</span>
    <span onclick="ST.sortBy='cvss';render()" style="cursor:pointer;font-size:10px;color:${ST.sortBy==='cvss'?'var(--y)':'var(--faint)'}">CVSS</span>
    <span onclick="openPaths()" class="reveal" style="color:var(--blue);border-color:rgba(58,160,255,.4)">🗂 網站路徑</span>
    <span onclick="dumpAll()" class="reveal" style="color:var(--mag);border-color:rgba(255,61,174,.4)">⤓ Dump 全部洩漏</span>
    <span onclick="clearDumps()" class="reveal" style="color:var(--faint);border-color:var(--line2)">🧹 清除 dumps</span>
    <span onclick="setView('report')" style="cursor:pointer;font-size:10px;font-weight:700;color:var(--y);border:1px solid var(--y);padding:6px 13px">匯出報告 →</span></div></div>
  <div style="flex:none;display:grid;grid-template-columns:88px 60px 1fr 200px 150px 120px;gap:12px;padding:8px 18px;border-bottom:1px solid var(--line1);font-size:9px;color:var(--faint);letter-spacing:1px">
   <div>SEVERITY</div><div>CVSS</div><div>FINDING</div><div>TARGET</div><div>STAGE / CVE</div><div>STATUS</div></div>
  <div style="flex:1;min-height:0;overflow:auto">${rows||'<div class="muted" style="padding:30px;font-size:11px">此篩選下無 findings。</div>'}
   <div style="padding:16px 18px;font-size:10px;color:var(--faint)">${list.length} 筆 · 依 ${ST.sortBy} 排序 · 展開列看非破壞式證據、重現腳本與修補建議</div></div></div>`;}
async function confirmF(id){await api('POST','/api/runs/'+ST.runId+'/finding',{finding_id:id,reviewed:true});pollDetail();}
async function fpF(id){const f=allFindings().find(x=>x.id===id);await api('POST','/api/runs/'+ST.runId+'/finding',{finding_id:id,false_positive:!(f&&f.false_positive)});pollDetail();}
function togSev(k){ST.sev.has(k)?ST.sev.delete(k):ST.sev.add(k);render();}
/* ---- repro / dump -> shell overlay ---- */
async function openRepro(id){toast('產生重現腳本…');const r=await api('GET','/api/runs/'+ST.runId+'/repro?finding_id='+id);
 if(!Array.isArray(r)||!r.length)return toast('此 finding 無自動化重現');const s=r[0];
 showShell({mode:'repro',title:'重現腳本 · '+(s.cve||s.category),sub:s.filename+(s.expect?' · expect: '+s.expect:''),cmd:s.filename,status:'PoC',statC:'var(--y)',body:s.script,copy:s.script,dl:{name:s.filename,text:s.script}});}
function fmtSize(n){return n<1024?n+'B':n<1048576?(n/1024).toFixed(1)+'K':(n/1048576).toFixed(1)+'M';}
function togReveal(id){ST.reveal.has(id)?ST.reveal.delete(id):ST.reveal.add(id);render();}
async function openDump(id,kind){ST.dumps[id]={state:'dumping'};render();
 const r=await api('POST','/api/runs/'+ST.runId+'/dump',{finding_id:id});
 if(!r||!r.ok){ST.dumps[id]={state:(r&&/out of scope/i.test(r.error||''))?'oos':'fail'};render();return toast((r&&r.error)||'dump 失敗（可能已下架）');}
 const sz=fmtSize(r.size||0);ST.dumps[id]={state:'ok',size:sz,kind:r.kind};render();
 let body;
 if(r.kind==='key')body='# KEY CARD · ⚠ 已落地磁碟,請自行保管/清除\n\n'+(r.preview||'');
 else if(r.kind==='git')body='# GIT DUMP · 重建原始碼 · ⚠ 已落地 runs/…/dumps/\n\n'+(r.preview||'');
 else body=r.preview||'(saved)';
 showShell({mode:'dump',title:'DUMP · '+(r.kind||'file').toUpperCase(),sub:(r.saved||r.dir)+' · '+sz,cmd:r.saved||r.dir,
  status:'SAVED',statC:'var(--mag)',body,copy:r.preview,land:'已落地 runs/'+ST.runId+'/dumps/ · 請自行保管/清除'});
 toast('已抓存 → '+(r.saved||r.dir)+' · '+sz);}
async function dumpAll(){const leaks=allFindings().filter(f=>!f.false_positive&&isLeak(f));if(!leaks.length)return toast('無可 dump 的 leak');
 toast('dumping '+leaks.length+' 個…');let ok=0;
 for(const f of leaks){ST.dumps[f.id]={state:'dumping'};const r=await api('POST','/api/runs/'+ST.runId+'/dump',{finding_id:f.id});
  ST.dumps[f.id]=r&&r.ok?{state:'ok',size:fmtSize(r.size||0),kind:r.kind}:{state:'fail'};if(r&&r.ok)ok++;}
 render();toast('已抓存 '+ok+'/'+leaks.length+' → runs/'+ST.runId+'/dumps/');}
async function clearDumps(){if(!ST.runId)return;const r=await api('POST','/api/runs/'+ST.runId+'/dumps/clear');ST.dumps={};render();toast('已清除 '+((r&&r.cleared)||0)+' 個 dump');}
async function openCell(tid,sid){const t=targets().find(x=>(x.raw||x.host)===tid);if(!t)return;
 const st=(t.stages||{})[sid];const arts=(st&&st.artifacts)||[];
 const meta=SMETA[sid]||{n:sid,tool:sid};const hit=stageHit(t,sid);
 const statC=hit?SM[hit].c:(st&&st.status==='done'?'var(--y)':st&&st.status==='running'?'var(--mag)':'var(--faint)');
 const statLabel=hit?'HIT':(st?st.status.toUpperCase():'N/A');
 if(!arts.length){showShell({title:meta.n+' / '+meta.cn,sub:t.host,cmd:meta.tool,status:statLabel,statC,
   body:'# '+(st?st.status:'no data')+(st&&st.note?' · '+st.note:'')+'\n# clean · no artifact / benign\n'});return;}
 const txt=await fetch('/api/runs/'+ST.runId+'/artifact?path='+encodeURIComponent(arts[0])).then(r=>r.text()).catch(()=>'(讀取失敗)');
 const cmdm=txt.match(/^#\s\$\s(.+)/m);
 showShell({title:meta.n+' / '+meta.cn,sub:t.host+' · '+meta.tool,cmd:cmdm?cmdm[1]:meta.tool,status:statLabel,statC,body:txt,copy:cmdm?cmdm[1]:''});}
function openPaths(host){const tg=host?targets().filter(t=>t.host===host):targets();
 let lines=[];let n=0;
 for(const t of tg){const wp=(t.webpaths||[]).slice().sort((a,b)=>(''+a.url).localeCompare(''+b.url));
  if(host||wp.length)lines.push('# '+t.host+'  ('+wp.length+' paths)');
  for(const w of wp){n++;lines.push('  '+String(w.status).padEnd(4)+' '+String(w.length||0).padStart(8)+'B  '+w.url+(w.redirect?' → '+w.redirect:''));}
  if(host||wp.length)lines.push('');}
 if(!n)lines=['# 尚無掃到的路徑。','# webdisco 這輪沒產出(標的無 HTTP、或尚未跑到該 stage)。','# 安裝 dirsearch 可跑完整字典;未安裝時走內建 common-paths 探測。'];
 showShell({mode:'log',title:'網站路徑 · WEB PATHS'+(host?' · '+host:''),sub:n+' paths · dirsearch / 內建探測',cmd:'webdisco',status:'PATHS',statC:'var(--blue)',body:lines.join('\n'),copy:lines.filter(l=>/^\s+\d/.test(l)).map(l=>l.trim().split(/\s+/).pop()).join('\n')});}
function showShell(o){ST._shell=o;renderOverlay();}
function closeShell(){ST._shell=null;renderOverlay();}
function renderOverlay(){const el=document.getElementById('overlay');const o=ST._shell;
 if(!o){el.innerHTML='';return;}
 const mt={log:['LOG','mt-log'],dump:['DUMP','mt-dump'],repro:['PoC','mt-poc']}[o.mode||'log'];
 el.innerHTML=`<div class="scrim" onclick="if(event.target===this)closeShell()"><div class="shell">
  <div class="shead"><span style="width:8px;height:8px;border-radius:50%;background:${o.statC}"></span>
   <span class="modetag ${mt[1]}">${mt[0]}</span>
   <div style="flex:1"><div style="font-size:13px;color:var(--fg0);font-weight:700">${esc(o.title)}</div><div style="font-size:10px;color:var(--dim);margin-top:2px">${esc(o.sub||'')}</div></div>
   <span class="statb" style="color:${o.statC};border-color:${o.statC}">${esc(o.status||'')}</span>
   <span onclick="closeShell()" style="cursor:pointer;font-size:16px;color:var(--faint);padding:0 4px">✕</span></div>
  <div class="scmd"><div class="lab" style="margin-bottom:4px">COMMAND</div><div style="font-size:11px;color:var(--y);word-break:break-all">${esc(o.cmd||'')}</div></div>
  <div class="sbody">${renderShellBody(o.body)}</div>
  <div style="flex:none;padding:10px 18px;border-top:1px solid var(--line);display:flex;align-items:center;gap:10px">
   <span class="authnote">◈ 僅限授權標的 / authorized targets only${o.land?' · '+esc(o.land):''}</span>
   <span style="flex:1"></span>
   ${o.copy?`<div class="abtn" onclick="shellCopy()">複製</div>`:''}
   ${o.dl?`<div class="abtn y" onclick="shellDl()">⭳ 下載 .sh</div>`:''}
   <div class="abtn" onclick="closeShell()">關閉</div></div>
 </div></div>`;}
function renderShellBody(txt){return (txt||'').split(/\r?\n/).map(l=>{
  if(/^#\s\$\s/.test(l))return `<div style="color:var(--y)">${esc(l)}</div>`;
  if(/^#/.test(l))return `<div style="color:var(--blue)">${esc(l)}</div>`;
  if(/VULNERABLE|\[\+\]/.test(l))return `<div style="color:var(--crit)">${esc(l)}</div>`;
  return `<div style="color:var(--soft)">${esc(l)}</div>`;}).join('');}
function shellCopy(){const o=ST._shell;if(o&&o.copy&&navigator.clipboard){navigator.clipboard.writeText(o.copy);toast(o.mode==='dump'?'已複製機敏內容,注意保管':'已複製');}}
function evProof(f){const ev=f.evidence||{};if(!ST.opt.plaintext&&isSensitive(f)){const c={};for(const [k,v] of Object.entries(ev))c[k]=(typeof v==='string')?maskText(v):v;return c;}return ev;}
function shellDl(){const o=ST._shell;if(o&&o.dl)dlText(o.dl.name,o.dl.text);}
function dlText(name,text){const b=new Blob([text],{type:'text/plain'});const u=URL.createObjectURL(b);
 const a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),1500);}
/* ---- report (client-side gen from live findings) ---- */
function reportText(fmt){const min=SM[ST.opt.minSev].r;
 const F=allFindings().filter(f=>!f.false_positive&&SM[f.severity].r>=min);
 const scope=(targets().map(t=>t.host).join(', '))||'—';const c=counts();
 if(fmt==='json')return JSON.stringify({tool:'edu-recon',intensity:ST.intensity,scope,summary:c,
   findings:F.map(f=>({id:f.id,severity:f.severity,cvss:SM[f.severity].cvss,cve:(f.evidence||{}).cve||'',title:f.title,target:f.host,stage:f.stage,category:f.category,sensitive:isSensitive(f),...(ST.opt.evidence?{evidence:evProof(f)}:{})}))},null,2);
 if(fmt==='md'){let s='# edu-recon report\n\n- intensity: '+ST.intensity+'\n'+(ST.opt.scope?'- scope: '+scope+'\n':'')+'\n## Summary\n\n'+Object.entries(c).map(([k,v])=>'- '+k+': '+v).join('\n')+'\n\n## Findings\n\n';
  F.forEach(f=>{s+='### ['+SM[f.severity].k+'] '+f.title+'\n\n- target: `'+f.host+'`\n- cve: '+((f.evidence||{}).cve||'—')+' · cvss '+SM[f.severity].cvss+'\n- stage: '+f.stage+'\n'+(ST.opt.evidence?'- evidence: `'+esc(JSON.stringify(evProof(f)))+'`\n':'')+'- remediation: '+(REMED[f.category]||'—')+'\n\n';});return s;}
 const rows=F.map(f=>'<tr><td class="s" style="color:'+cssvar(SM[f.severity].c)+'">'+SM[f.severity].k+'</td><td>'+SM[f.severity].cvss+'</td><td><b>'+esc(f.title)+'</b><br><span style="color:#82806A">'+esc(f.category)+'</span></td><td><code>'+esc(f.host)+'</code></td><td>'+esc((f.evidence||{}).cve||'—')+'</td></tr>').join('');
 return '<!doctype html><meta charset=utf-8><title>edu-recon report</title><style>body{background:#0B0B09;color:#DAD8C8;font:13px/1.5 "JetBrains Mono",monospace;margin:0;padding:32px}h1{color:#F2E409;letter-spacing:2px}table{border-collapse:collapse;width:100%;margin-top:16px}td,th{border:1px solid rgba(150,146,120,.18);padding:8px 10px;text-align:left;vertical-align:top}code{color:#F2E409}.s{font-weight:700}</style><h1>EDU-RECON REPORT</h1><div style="color:#82806A">intensity '+ST.intensity+(ST.opt.scope?' · scope '+esc(scope):'')+'</div><table><tr><th>SEV</th><th>CVSS</th><th>FINDING</th><th>TARGET</th><th>CVE</th></tr>'+rows+'</table>';}
function vReport(){const min=SM[ST.opt.minSev].r;const F=allFindings().filter(f=>!f.false_positive&&SM[f.severity].r>=min);const c=counts();
 const fmts=[['html','HTML'],['md','MARKDOWN'],['json','JSON']];
 const opt=(k,l)=>`<div onclick="ST.opt.${k}=!ST.opt.${k};render()" style="cursor:pointer;display:flex;align-items:center;gap:9px;font-size:11px;color:var(--fg)"><span style="width:14px;height:14px;border:1px solid ${ST.opt[k]?'var(--y)':'var(--line2)'};background:${ST.opt[k]?'var(--y)':'transparent'};color:#0B0B09;text-align:center;line-height:12px;font-size:10px">${ST.opt[k]?'✓':''}</span>${l}</div>`;
 const mn=(v,l)=>`<div onclick="ST.opt.minSev='${v}';render()" style="cursor:pointer;flex:1;text-align:center;padding:7px;font-size:10px;border:1px solid ${ST.opt.minSev===v?'var(--y)':'var(--line2)'};color:${ST.opt.minSev===v?'var(--y)':'var(--faint)'}">${l}</div>`;
 return `<div style="position:absolute;inset:0;display:grid;grid-template-columns:300px 1fr;overflow:hidden">
  <div style="border-right:1px solid var(--line);padding:20px 18px;overflow:auto;display:flex;flex-direction:column;gap:20px">
   <div><div class="eyebrow">STEP 04</div><div class="vtitle" style="font-size:17px">匯出報告 · EXPORT</div></div>
   <div><div class="lab" style="margin-bottom:8px">FORMAT / 格式</div><div style="display:flex;flex-direction:column;gap:6px">
    ${fmts.map(([k,l])=>`<div onclick="ST.fmt='${k}';render()" style="cursor:pointer;padding:10px 13px;border:1px solid ${ST.fmt===k?'var(--y)':'var(--line2)'};color:${ST.fmt===k?'var(--y)':'var(--faint)'};font-size:12px;font-weight:700;letter-spacing:1px;display:flex;align-items:center;gap:10px"><span style="width:7px;height:7px;background:${ST.fmt===k?'var(--y)':'var(--faint)'}"></span>${l}</div>`).join('')}</div></div>
   <div><div class="lab" style="margin-bottom:8px">OPTIONS / 選項</div><div style="display:flex;flex-direction:column;gap:8px">${opt('evidence','附證據(遮蔽 masked)')}${opt('plaintext','附機敏明文(危險 DANGER)')}${opt('scope','附上授權範圍聲明')}${opt('rawlog','附上原始工具 log')}
    ${ST.opt.plaintext?'<div style="font-size:9px;color:var(--crit);border:1px solid rgba(255,61,94,.4);padding:5px 8px">⚠ 危險:金鑰/密碼將以明文寫入匯出報告</div>':''}</div></div>
   <div><div class="lab" style="margin-bottom:8px">MIN SEVERITY / 門檻</div><div style="display:flex;gap:6px">${mn('low','LOW+')}${mn('medium','MED+')}${mn('high','HIGH+')}</div></div>
   <div class="arm notch" style="padding:14px;font-size:13px;letter-spacing:1px" onclick="downloadReport()">⭳ 下載 ${ST.fmt.toUpperCase()} · ${F.length} 筆</div>
   <div style="font-size:9px;color:var(--faint);line-height:1.7">報告可複審:每筆 finding 含嚴重度、標的、非破壞式 oracle 證據與修補建議。</div></div>
  <div style="overflow:auto;padding:24px 28px;background:#070707">
   <div style="max-width:840px;margin:0 auto;border:1px solid var(--line);background:#0B0B09">
    <div style="padding:22px 26px;border-bottom:1px solid var(--line)">
     <div style="font-size:20px;font-weight:800;color:var(--y);letter-spacing:2px">EDU-RECON REPORT</div>
     <div style="font-size:10px;color:var(--dim);margin-top:6px">intensity ${ST.intensity} · preview · ${ST.fmt.toUpperCase()}</div>
     <div class="authnote" style="margin-top:4px">◈ 僅限授權標的 · 報告金鑰/密碼預設遮蔽${ST.opt.plaintext?' · <span style="color:var(--crit)">明文模式(危險)</span>':''}</div>
     <div style="display:flex;gap:16px;margin-top:14px">${['critical','high','medium','low','info'].map(k=>`<span style="font-size:11px;color:${SM[k].c}">${SM[k].k} ${c[k]||0}</span>`).join('')}</div></div>
    <div style="padding:8px 0">${F.map(f=>`<div style="padding:12px 26px;border-bottom:1px solid var(--line1)">
      <div style="display:flex;align-items:center;gap:10px"><span class="sevb" style="background:${SM[f.severity].c}">${SM[f.severity].k}</span>
       <span style="font-size:11px;color:var(--faint)">CVSS ${SM[f.severity].cvss}</span>
       <span style="font-size:12px;color:var(--fg0);font-weight:600">${esc(f.title)}</span><span style="flex:1"></span>
       <span style="font-size:10px;color:var(--dim)">${esc((f.evidence||{}).cve||'—')}</span></div>
      <div style="font-size:10px;color:var(--dim);margin-top:5px">${esc(f.host)} · ${esc(f.stage)}</div>
      ${ST.opt.evidence?`<div style="margin-top:7px;padding:8px 11px;background:#070707;border-left:2px solid ${SM[f.severity].c};font-size:10px;color:var(--dim);word-break:break-all">${esc(JSON.stringify(evProof(f)))}${isSensitive(f)?'<span class="sens">🔒</span>':''}</div>`:''}</div>`).join('')||'<div class="muted" style="padding:30px">無符合門檻的 finding。</div>'}</div></div></div></div>`;}
function downloadReport(){dlText('edu-recon-report.'+ST.fmt,reportText(ST.fmt));}
/* ---- toast / boot ---- */
function toast(m){const el=document.getElementById('toast');el.textContent=m;el.classList.add('show');clearTimeout(window._tt);window._tt=setTimeout(()=>el.classList.remove('show'),2600);}
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeShell();});
loadRuns();setInterval(loadRuns,6000);render();
</script></body></html>"""
