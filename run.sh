#!/usr/bin/env bash
# edu-recon — one-command FULL-POWER launch.
#   ./run.sh                     # console on 127.0.0.1:8770 + auto-open browser
#   HOST=0.0.0.0 PORT=9000 ./run.sh
# Full power = default config: intensity full · nmap -sC --script vuln ·
# full dirsearch db/dicc.txt sweep · all resolved scanners · scope-lock off.
set -e
cd "$(cd "$(dirname "$0")" && pwd)"
HOST="${HOST:-127.0.0.1}"; PORT="${PORT:-8770}"

# 1) venv (first run)
if [ ! -d .venv ]; then
  echo "[edu-recon] creating venv…"
  python3 -m venv .venv 2>/dev/null || python -m venv .venv
fi
VPY=".venv/bin/python"; [ -x "$VPY" ] || VPY=".venv/Scripts/python.exe"

# 2) first-run setup: clone bundled tools + install deps
if [ ! -f third_party/dirsearch/dirsearch.py ]; then
  echo "[edu-recon] first-run setup (clone tools + deps)…"
  "$VPY" recon.py setup || true
fi

# 3) capability check
"$VPY" recon.py doctor || true

# 4) open the browser once the port answers
URL="http://127.0.0.1:$PORT"
( for _ in $(seq 1 40); do curl -s -o /dev/null "$URL" && break; sleep 0.5; done
  if   command -v xdg-open >/dev/null 2>&1; then xdg-open "$URL"
  elif command -v open     >/dev/null 2>&1; then open "$URL"
  elif command -v cmd.exe  >/dev/null 2>&1; then cmd.exe /c start "" "$URL"
  fi ) >/dev/null 2>&1 &

# 5) full-power console (foreground; Ctrl-C to stop)
echo "[edu-recon] FULL-POWER console → http://$HOST:$PORT   (open $URL)"
exec "$VPY" recon.py serve --host "$HOST" --port "$PORT"
