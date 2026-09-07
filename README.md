# edu-recon

Authorized recon & triage orchestrator for **education-sector red/blue exercises**.
Drop targets in, it runs the scanners, filters the noise, and hands you a ranked
review queue in a web UI. Built to be deployed on your Linux box (Kali / infra),
driven from a browser.

> ⚠️ **Authorized use only.** Point it only at systems you are authorized to test.
> Scope-lock is **off by default** — the operator owns authorization. For a real
> engagement you can re-arm a locked scope allowlist with `scope_enforce: true`
> in `config.yaml` (every stage then re-checks scope before it acts).

## What it does

```
targets ─▶ expand (CIDR ping-sweep, subdomain enum)
        ─▶ per target:
             portscan   nmap -sV -sC (+ --script vuln)
             webdisco   dirsearch  (+ WordPress detect)
             exposures  .git / .env / backups / phpinfo / server-status / actuator …
                        + phpMyAdmin/Adminer exposure + open directory listing
             secrets    JS/HTML key-leak scan (AWS/GCP/GitHub/Slack/Stripe/JWT/私鑰/…)
                        + API-doc / GraphQL-introspection exposure   ← api leak
             phpcgi     CVE-2024-4577 / 8926  via Night-have-dreams/php-cgi-Injector
             react2shell CVE-2025-55182 React Server Components RCE
                        via hidden-investigations/react2shell-scanner (safe-check by default)
             webcve     built-in non-destructive safe-check probes for famous CVEs:
                        PHPUnit 2017-9841 · Apache-traversal 2021-41773 · Struts2 2017-5638
                        · Confluence 2022-26134 · Drupalgeddon2 2018-7600 · Next.js 2025-29927
             moodle     Moodle LMS fingerprint + version + outdated-branch +
                        web-exposed moodledata (the dominant .edu system)
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
git clone https://github.com/ericchen913900/edu-recon.git && cd edu-recon
python3 -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
python recon.py setup          # clones php-cgi-Injector + react2shell-scanner + wp2shell + dirsearch, installs deps
python recon.py doctor         # shows which scanners resolved
```

On **Kali** the heavy scanners (nmap/sqlmap/hydra/dirsearch) are already native —
see **[Deploy on Kali Linux](#deploy-on-kali-linux)** for the full recipe.

## Deploy on Kali Linux

Kali is the intended box: `nmap`, `sqlmap`, `hydra`, `dirsearch` ship in the
distro, so the whole pipeline (incl. injection + weak-password) runs natively.

```bash
# 1) system tools — most are already on Kali; this is the complete set
sudo apt update
sudo apt install -y python3 python3-venv git nmap sqlmap hydra dirsearch
#   optional (better XSS + subdomain enum):
#   sudo apt install -y dalfox subfinder      # or: go install github.com/hahwul/dalfox/v2@latest ; \
#                                             #     go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 2) get the code
git clone https://github.com/ericchen913900/edu-recon.git
cd edu-recon

# 3) isolated venv + Python deps + bundled script-tools
python3 -m venv .venv
source .venv/bin/activate
python recon.py setup          # clones php-cgi-Injector / react2shell-scanner / wp2shell / dirsearch, pip-installs deps

# 4) sanity check — on Kali nmap/sqlmap/hydra/dirsearch should all be OK (native)
python recon.py doctor

# 5a) web console — bind to localhost, drive from a browser
python recon.py serve --host 127.0.0.1 --port 8770
#     → http://127.0.0.1:8770   (paste targets → pick intensity → ARM & RUN)
#     remote Kali? tunnel instead of exposing it:
#         ssh -L 8770:127.0.0.1:8770 user@kali      # then browse http://localhost:8770

# 5b) or headless
python recon.py scan -t targets.txt --intensity full
python recon.py repro  <run-id>          # runnable reproduction PoC per confirmed finding
python recon.py payout <run-id>          # legal disclosure / bounty routing per finding
```

**Kali notes**
- **dirsearch**: the native `dirsearch` is used automatically for a full
  `db/dicc.txt` sweep (every discovered dir/file lists in the console under
  `🗂 網站路徑`). Skip the apt package and `setup` clones dirsearch and runs it via
  Python instead — either way `webdisco` works.
- **Full pipeline**: with native `sqlmap`/`hydra`/`nmap`, `--intensity full`
  actually executes injection + weak-password checks (non-destructive safe-checks
  elsewhere).
- **Scope-lock is off by default** (operator owns authorization). Lock it for a
  paid engagement: `scope_enforce: true` in `config.yaml` + list your authorized
  scope in the target file / `extra_allowed_cidrs`.
- **Don't expose the console.** Keep `--host 127.0.0.1` and reach it over an SSH
  tunnel; it has no auth of its own.
- **systemd (optional)** to keep the console up:
  ```ini
  # /etc/systemd/system/edu-recon.service
  [Service]
  WorkingDirectory=/home/kali/edu-recon
  ExecStart=/home/kali/edu-recon/.venv/bin/python recon.py serve --host 127.0.0.1 --port 8770
  Restart=on-failure
  User=kali
  [Install]
  WantedBy=multi-user.target
  ```
  `sudo systemctl enable --now edu-recon`

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
| `recon`  | phpcgi + react2shell + webcve + XSS + exposures run; **sqli/cred only list candidates** |
| `passive`| portscan + webdisco + exposures + secrets (benign GETs only) |

## Config

Edit `config.yaml` (see comments) or pass `--config`. Wordlists live in
`wordlists/` (`default-creds.txt`, `users.txt`, `passwords.txt`, `web-common.txt`).
Tune `hydra_tasks` low to avoid account lockouts; raise `nmap_top_ports: 0` for
a full-port scan.

## Layout

```
recon.py              CLI (serve / scan / setup / doctor / repro / payout)
edurecon/
  config.py           defaults + yaml/json loader + intensity gating
  scope.py            target parsing + scope allowlist (subdomain-aware)
  engine.py           expansion + concurrent per-target pipeline + cancel
  stages.py           every scan stage
  webscan.py          crawler + reflected-XSS + SQL-error heuristics
  secrets.py          key-leak regexes + API-doc/GraphQL probes
  cveprobes.py        built-in non-destructive famous-CVE safe-check probes
  edusys.py           education-sector system audit (Moodle)
  parse.py            nmap/dirsearch/sqlmap/hydra/phpcgi/react2shell parsers
  triage.py           service inference, soft-404 filter, dedupe, ranking
  report.py           JSON / Markdown / HTML export
  store.py            run state + JSON persistence
  webui.py            stdlib web control panel
third_party/          php-cgi-Injector, react2shell-scanner, wp2shell, dirsearch (via `setup`)
runs/                 per-run artifacts + reports
```
