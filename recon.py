#!/usr/bin/env python3
"""edu-recon — authorized recon & triage orchestrator.

  python recon.py serve                 # launch the web control panel
  python recon.py scan -t targets.txt   # run headless, write reports
  python recon.py setup                 # clone php-cgi-Injector + wp2shell, deps
  python recon.py doctor                # check which external tools are available

Only scans hosts present in the target file (plus configured CIDRs / their
subdomains). Intended for authorized education-sector red/blue exercises.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from edurecon.config import Config, ROOT, INTENSITY_STAGES
from edurecon.store import RunStore
from edurecon.engine import Engine
from edurecon.report import write_reports
from edurecon.triage import target_score
from edurecon.models import SEVERITY_ORDER


def _load_cfg(args) -> Config:
    cfg = Config.load(getattr(args, "config", None))
    if getattr(args, "intensity", None):
        cfg.intensity = args.intensity
    if getattr(args, "workdir", None):
        cfg.workdir = args.workdir
        os.makedirs(cfg.workdir, exist_ok=True)
    if getattr(args, "concurrency", None):
        cfg.concurrency = args.concurrency
    return cfg


def cmd_serve(args) -> int:
    from edurecon.webui import serve
    cfg = _load_cfg(args)
    serve(cfg, host=args.host, port=args.port)
    return 0


def cmd_scan(args) -> int:
    cfg = _load_cfg(args)
    targets: list[str] = []
    if args.target_file:
        with open(args.target_file, "r", encoding="utf-8") as fh:
            for line in fh:
                s = line.split("#", 1)[0].strip()
                if s:
                    targets.append(s)
    targets += args.targets or []
    if not targets:
        print("no targets (use -t FILE or positional targets)", file=sys.stderr)
        return 2
    print(f"[*] {len(targets)} target line(s), intensity={cfg.intensity}, "
          f"concurrency={cfg.concurrency}")

    store = RunStore(cfg.workdir)
    engine = Engine(cfg, store)
    run = engine.start_run(targets, {"intensity": cfg.intensity,
                                     "concurrency": cfg.concurrency}, block=True)

    out_dir = args.out or os.path.join(cfg.workdir, run.id)
    paths = write_reports(run, out_dir)
    _print_summary(run)
    print(f"\n[*] reports: {paths['md']}\n              {paths['html']}\n              {paths['json']}")
    return 0


def _print_summary(run) -> None:
    s = run.summary()
    print(f"\n=== {run.id}  status={run.status} ===")
    print("severity: " + "  ".join(f"{k}={s['severity'][k]}"
                                    for k in reversed(SEVERITY_ORDER)))
    for t in sorted(run.targets, key=target_score, reverse=True):
        hi = [f for f in t.findings
              if not f.false_positive and f.severity in ("critical", "high", "medium")]
        if not hi:
            continue
        print(f"\n# {t.host}  (score {target_score(t)})")
        for f in hi:
            ev = f.evidence.get("url") or f.evidence.get("value") or \
                f.evidence.get("cgipoint") or ""
            print(f"  [{f.severity:>8}] {f.category:<14} {f.title}  {str(ev)[:70]}")


def cmd_setup(args) -> int:
    cfg = _load_cfg(args)
    tp = os.path.join(ROOT, "third_party")
    os.makedirs(tp, exist_ok=True)
    repos = [
        ("php-cgi-Injector", "https://github.com/Night-have-dreams/php-cgi-Injector.git",
         ["requests", "requests-tor", "chardet", "urllib3", "rich"]),
        ("wp2shell", "https://github.com/xAL6/wp2shell.git", []),
    ]
    for name, url, pips in repos:
        dest = os.path.join(tp, name)
        if os.path.isdir(os.path.join(dest, ".git")):
            print(f"[=] {name} present, pulling…")
            subprocess.run(["git", "-C", dest, "pull", "--ff-only"], check=False)
        else:
            print(f"[+] cloning {name}")
            subprocess.run(["git", "clone", "--depth", "1", url, dest], check=False)
        if pips:
            print(f"[+] pip install for {name}: {' '.join(pips)}")
            subprocess.run([sys.executable, "-m", "pip", "install", "-q", *pips], check=False)
    print("\n[i] External scanners (install via your distro / go):")
    print("    nmap sqlmap hydra dirsearch   # apt install ...")
    print("    subfinder dalfox              # go install ... (optional)")
    cmd_doctor(args)
    return 0


def cmd_doctor(args) -> int:
    cfg = _load_cfg(args)
    print("\n[tool availability]")
    bins = cfg.resolve_bins()
    for name, path in bins.items():
        mark = "OK " if path else "-- "
        print(f"  {mark} {name:<10} {path or 'NOT FOUND'}")
    missing = [n for n, p in bins.items() if not p]
    core = {"nmap", "dirsearch", "sqlmap", "hydra"}
    if core & set(missing):
        print(f"\n[!] core scanners missing: {sorted(core & set(missing))}")
    print(f"\n[i] intensity levels: {', '.join(INTENSITY_STAGES)}")
    print(f"[i] workdir: {cfg.workdir}")
    return 0


def main() -> int:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="path to config.yaml / config.json")
    common.add_argument("--workdir", help="override run output directory")
    common.add_argument("--intensity", choices=list(INTENSITY_STAGES))
    common.add_argument("--concurrency", type=int)

    ap = argparse.ArgumentParser(prog="recon.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("serve", parents=[common], help="launch web control panel")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8770)
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("scan", parents=[common], help="run headless and write reports")
    s.add_argument("-t", "--target-file", help="file with one target per line")
    s.add_argument("targets", nargs="*", help="inline targets")
    s.add_argument("--out", help="report output dir")
    s.set_defaults(func=cmd_scan)

    s = sub.add_parser("setup", parents=[common],
                       help="clone php-cgi-Injector + wp2shell and deps")
    s.set_defaults(func=cmd_setup)

    s = sub.add_parser("doctor", parents=[common],
                       help="check external tool availability")
    s.set_defaults(func=cmd_doctor)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
