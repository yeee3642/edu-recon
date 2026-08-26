"""Static report export: report.json / report.md / report.html (self-contained)."""
from __future__ import annotations

import html
import json
import os

from .models import SEVERITY_ORDER
from .store import Run
from .triage import target_score

SEV_EMOJI = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "🟦", "info": "⬜"}


def write_reports(run: Run, out_dir: str) -> dict[str, str]:
    os.makedirs(out_dir, exist_ok=True)
    data = run.to_dict()
    paths = {
        "json": os.path.join(out_dir, "report.json"),
        "md": os.path.join(out_dir, "report.md"),
        "html": os.path.join(out_dir, "report.html"),
    }
    with open(paths["json"], "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False, indent=2)
    with open(paths["md"], "w", encoding="utf-8") as fh:
        fh.write(render_markdown(run))
    with open(paths["html"], "w", encoding="utf-8") as fh:
        fh.write(render_html(data))
    return paths


def render_markdown(run: Run) -> str:
    s = run.summary()
    out = [f"# edu-recon report — {run.id}", ""]
    out.append(f"- Generated: {run.created}")
    out.append(f"- Intensity: {run.options.get('intensity')}")
    out.append(f"- Targets: {s['targets']}  |  Findings: {s['findings']}")
    sev = s["severity"]
    out.append("- Severity: " + ", ".join(
        f"{SEV_EMOJI[k]} {k} {sev[k]}" for k in reversed(SEVERITY_ORDER) if sev[k]))
    out.append("")

    # review queue (medium+), ranked
    rows = []
    for t in run.targets:
        for f in t.findings:
            if f.false_positive or f.severity in ("info", "low"):
                continue
            ev = f.evidence.get("url") or f.evidence.get("value") or \
                f.evidence.get("cgipoint") or ""
            rows.append((f.severity, t.host, f.category, f.title, str(ev)))
    order = {s: i for i, s in enumerate(reversed(SEVERITY_ORDER))}
    rows.sort(key=lambda r: order.get(r[0], 99))
    out += ["## Review queue (medium and above)", "",
            "| Severity | Target | Category | Finding | Evidence |",
            "|---|---|---|---|---|"]
    for sev_, host, cat, title, ev in rows:
        out.append(f"| {SEV_EMOJI.get(sev_,'')} {sev_} | {host} | {cat} | "
                   f"{_md(title)} | {_md(ev)[:80]} |")
    if not rows:
        out.append("| — | — | — | no medium+ findings | — |")
    out.append("")

    # per target
    out.append("## Per-target detail")
    for t in sorted(run.targets, key=target_score, reverse=True):
        out.append(f"\n### {t.host}  (score {target_score(t)})")
        ports = ", ".join(f"{s.port}/{s.name}" for s in t.services) or "—"
        out.append(f"- Open ports: {ports}")
        if t.is_wordpress:
            out.append("- WordPress: detected")
        for f in t.findings:
            if f.false_positive:
                continue
            ev = json.dumps(f.evidence, ensure_ascii=False)[:200]
            out.append(f"  - {SEV_EMOJI.get(f.severity,'')} **{f.severity}** "
                       f"[{f.category}] {f.title} — `{_md(ev)}`")
    return "\n".join(out) + "\n"


def _md(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_html(data: dict) -> str:
    payload = html.escape(json.dumps(data, ensure_ascii=False), quote=True)
    return _HTML_TEMPLATE.replace("__DATA__", payload)


_HTML_TEMPLATE = r"""<!doctype html>
<html lang="zh-Hant"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>edu-recon report</title>
<style>
 :root{--bg:#0d1117;--card:#161b22;--fg:#e6edf3;--mut:#8b949e;--line:#30363d}
 body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,Roboto,sans-serif}
 header{padding:16px 22px;border-bottom:1px solid var(--line);position:sticky;top:0;background:var(--bg);z-index:5}
 h1{font-size:18px;margin:0 0 6px}
 .muted{color:var(--mut)}
 .chips{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
 .chip{padding:3px 10px;border-radius:999px;border:1px solid var(--line);cursor:pointer;user-select:none}
 .chip.active{background:#1f6feb33;border-color:#1f6feb}
 .sev-critical{color:#ff7b72}.sev-high{color:#ffa657}.sev-medium{color:#e3b341}.sev-low{color:#79c0ff}.sev-info{color:#8b949e}
 .badge{padding:1px 7px;border-radius:6px;border:1px solid var(--line);font-size:12px}
 main{padding:16px 22px}
 table{width:100%;border-collapse:collapse}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
 th{color:var(--mut);font-weight:600;cursor:pointer}
 tr:hover{background:#161b2288}
 code{background:#0b0f14;padding:1px 5px;border-radius:4px;color:#9ecbff;word-break:break-all}
 details{margin:2px 0}
 input{background:var(--card);border:1px solid var(--line);color:var(--fg);padding:6px 10px;border-radius:6px;width:260px}
 a{color:#58a6ff}
</style></head><body>
<header>
 <h1>edu-recon report <span class="muted" id="rid"></span></h1>
 <div class="muted" id="meta"></div>
 <div class="chips" id="filters"></div>
 <div style="margin-top:8px"><input id="q" placeholder="filter by target / title / url…"></div>
</header>
<main><table id="tbl"><thead><tr>
 <th data-k="severity">Severity</th><th data-k="target">Target</th>
 <th data-k="category">Category</th><th data-k="title">Finding</th><th>Evidence</th>
</tr></thead><tbody id="rows"></tbody></table></main>
<script>
const DATA = JSON.parse(document.getElementById('x').textContent);
const ORDER={critical:4,high:3,medium:2,low:1,info:0};
let active=new Set(['critical','high','medium']); let sortK='severity',sortDir=-1;
const rows=[];
for(const t of (DATA.targets||[])){for(const f of (t.findings||[])){ if(f.false_positive) continue;
  const ev=f.evidence||{}; const url=ev.url||ev.value||ev.cgipoint||ev.poc||'';
  rows.push({severity:f.severity,target:t.host,category:f.category,title:f.title,
    evidence:url,full:JSON.stringify(ev,null,1),conf:f.confidence,arts:f.artifacts||[]});}}
document.getElementById('rid').textContent='· '+(DATA.id||'');
const s=DATA.summary||{severity:{}};
document.getElementById('meta').textContent=
 `${DATA.created||''} · intensity ${(DATA.options||{}).intensity||''} · ${s.targets||0} targets · ${s.findings||0} findings`;
const fc=document.getElementById('filters');
for(const k of ['critical','high','medium','low','info']){const c=document.createElement('span');
 c.className='chip'+(active.has(k)?' active':'');c.textContent=`${k} ${(s.severity||{})[k]||0}`;
 c.onclick=()=>{active.has(k)?active.delete(k):active.add(k);c.classList.toggle('active');draw();};fc.appendChild(c);}
document.querySelectorAll('th[data-k]').forEach(th=>th.onclick=()=>{
 const k=th.dataset.k; sortDir=(sortK===k?-sortDir:-1); sortK=k; draw();});
document.getElementById('q').oninput=draw;
function esc(s){return (s+'').replace(/[&<>]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));}
function draw(){const q=document.getElementById('q').value.toLowerCase();
 let r=rows.filter(x=>active.has(x.severity)).filter(x=>!q||
   (x.target+x.title+x.evidence+x.category).toLowerCase().includes(q));
 r.sort((a,b)=>{let av=a[sortK],bv=b[sortK]; if(sortK==='severity'){av=ORDER[av];bv=ORDER[bv];}
   return av<bv?sortDir:av>bv?-sortDir:0;});
 document.getElementById('rows').innerHTML=r.map(x=>`<tr>
  <td><span class="badge sev-${x.severity}">${x.severity}</span></td>
  <td>${esc(x.target)}</td><td>${esc(x.category)}</td>
  <td>${esc(x.title)}<div class="muted" style="font-size:12px">conf: ${esc(x.conf||'')}</div>
   <details><summary class="muted">evidence</summary><code>${esc(x.full)}</code>
   ${x.arts.map(a=>`<div><a href="${esc(a)}">${esc(a)}</a></div>`).join('')}</details></td>
  <td><code>${esc((x.evidence||'').slice(0,120))}</code></td></tr>`).join('')
  ||'<tr><td colspan=5 class="muted">no findings for this filter</td></tr>';}
draw();
</script>
<script type="application/json" id="x">__DATA__</script>
</body></html>"""
