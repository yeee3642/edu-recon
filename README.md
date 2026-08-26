# edu-recon

Authorized recon & triage orchestrator for **education-sector red/blue exercises**.
Drop targets in, it runs the scanners, filters the noise, and hands you a ranked
review queue in a web UI. Built to be deployed on your Linux box (Kali / infra),
driven from a browser.

> ⚠️ **Scope-locked.** It only touches hosts listed in your target file (plus
> configured CIDRs and their subdomains). Every stage re-checks scope before it
> acts. Use only against systems you are authorized to test.

## What it does

```
targets ─▶ expand (CIDR ping-sweep, subdomain enum)
        ─▶ per target:
             portscan   nmap -sV -sC (+ --script vuln)
             webdisco   dirsearch  (+ WordPress detect)
             exposures  .git / .env / backups / phpinfo / server-status / actuator …
             secrets    JS/HTML key-leak scan (AWS/GCP/GitHub/Slack/Stripe/JWT/私鑰/…)
                        + API-doc / GraphQL-introspection exposure   ← api leak
             phpcgi     CVE-2024-4577 / 8926  via Night-have-dreams/php-cgi-Injector
             xss        dalfox + built-in reflected-XSS canary
             sqli       built-in SQL-error quick pass  +  sqlmap deep
             cred       hydra weak/default passwords (ssh/ftp/rdp/db/…)
             wp         xAL6/wp2shell WordPress SQLi→shell
        ─▶ triage: infer findings from services, drop soft-404 noise,
                   dedupe, rank by severity → review queue
        ─▶ report: JSON / Markdown / self-contained HTML
```

## Install

```bash
git clone <this> edu-recon && cd edu-recon
python recon.py setup          # clones php-cgi-Injector + wp2shell, installs their deps
python recon.py doctor         # shows which external scanners are present
# install scanners as needed:  apt install nmap sqlmap hydra dirsearch
#                              (optional) go install subfinder, dalfox
```

## Use — web control panel

```bash
python recon.py serve --host 127.0.0.1 --port 8770
```

Open the URL, paste targets (one per line: `IP` / `host` / `URL` / `CIDR` /
`domain` / `host:port`), pick an **intensity**, hit **開始掃描**. Watch each
target's stage grid fill in live, filter findings by severity, expand evidence,
open raw tool logs, mark false positives, and export the HTML report.

## Use — headless

```bash
python recon.py scan -t targets.txt --intensity full
# reports land in runs/<run-id>/report.{md,html,json}
```

## Intensity

| level    | what runs |
|----------|-----------|
| `full`   | everything, injection + weak-password executed (default) |
| `recon`  | phpcgi + XSS + exposures run; **sqli/cred only list candidates** |
| `passive`| portscan + webdisco + exposures + secrets (benign GETs only) |

## Config

Edit `config.yaml` (see comments) or pass `--config`. Wordlists live in
`wordlists/` (`default-creds.txt`, `users.txt`, `passwords.txt`, `web-common.txt`).
Tune `hydra_tasks` low to avoid account lockouts; raise `nmap_top_ports: 0` for
a full-port scan.

## Layout

```
recon.py              CLI (serve / scan / setup / doctor)
edurecon/
  config.py           defaults + yaml/json loader + intensity gating
  scope.py            target parsing + scope allowlist (subdomain-aware)
  engine.py           expansion + concurrent per-target pipeline + cancel
  stages.py           every scan stage
  webscan.py          crawler + reflected-XSS + SQL-error heuristics
  secrets.py          key-leak regexes + API-doc/GraphQL probes
  parse.py            nmap/dirsearch/sqlmap/hydra/phpcgi output parsers
  triage.py           service inference, soft-404 filter, dedupe, ranking
  report.py           JSON / Markdown / HTML export
  store.py            run state + JSON persistence
  webui.py            stdlib web control panel
third_party/          php-cgi-Injector, wp2shell (via `setup`)
runs/                 per-run artifacts + reports
```
