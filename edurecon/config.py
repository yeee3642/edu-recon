"""Configuration: sane defaults overridable by config.yaml / config.json.

Command *templates* live here so tool flags can be tuned without touching stage code.
The engine injects dynamic values (host, output paths, port lists) at run time.
"""
from __future__ import annotations

import json
import os
import shutil
import sys
from dataclasses import dataclass, field, asdict
from typing import Any

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# Run-level expansion (always available, gated by flags below): CIDR ping-sweep
# and subdomain enumeration. These produce the concrete target list.
EXPANSION_STAGES = ["hostdiscovery", "subdomain"]

# Per-target intensity -> which stages execute vs. only list candidates.
INTENSITY_STAGES = {
    # passive: never touches auth or injection; benign GETs + fingerprinting only
    "passive": {"portscan", "webdisco", "exposures", "secrets"},
    # recon: phpcgi + react2shell + wordpress + reflected-XSS (benign) execute; sqli/cred are CANDIDATE lists
    "recon": {"portscan", "webdisco", "exposures", "secrets", "phpcgi", "react2shell",
              "wp", "xss", "sqli_candidate", "cred_candidate"},
    # full: everything runs for real
    "full": {"portscan", "webdisco", "exposures", "secrets", "phpcgi", "react2shell",
             "wp", "xss", "sqli", "cred"},
}

ALL_STAGES = ["portscan", "webdisco", "exposures", "secrets", "phpcgi", "react2shell",
              "xss", "sqli", "cred", "wp"]


@dataclass
class Config:
    # --- global ---
    workdir: str = os.path.join(ROOT, "runs")
    intensity: str = "full"            # full | recon | passive
    concurrency: int = 4               # targets scanned in parallel
    http_timeout: int = 12
    user_agent: str = ("Mozilla/5.0 (edu-recon; authorized-exercise) "
                       "AppleWebKit/537.36 Safari/537.36")

    # --- tool binaries (auto-discovered on PATH if left as name) ---
    nmap_bin: str = "nmap"
    dirsearch_bin: str = "dirsearch"
    sqlmap_bin: str = "sqlmap"
    hydra_bin: str = "hydra"
    subfinder_bin: str = "subfinder"
    curl_bin: str = "curl"

    # --- wp2shell (xAL6/php WordPress SQLi->shell engine, cloned repo) ---
    wp2shell_dir: str = os.path.join(ROOT, "third_party", "wp2shell")
    # Run bundled Python tools under the SAME interpreter as edu-recon so they
    # inherit the deps installed by `recon.py setup`. On Windows a bare "python3"
    # often resolves to a depless Store shim; sys.executable avoids that.
    wp2shell_python: str = field(default_factory=lambda: sys.executable)
    # {target} -> host[:port]; assessment/--json is non-interactive
    wp2shell_argtmpl: list[str] = field(
        default_factory=lambda: ["{target}", "--json", "--path-guess"])

    # --- subdomain enumeration (run-level expansion) ---
    subdomain_enabled: bool = True
    subdomain_allow_scope: bool = True   # authorize *.domain for every listed domain
    subdomain_use_crtsh: bool = True     # crt.sh fallback when subfinder is absent
    subdomain_resolve: bool = True       # keep only subs that resolve to an A record
    subdomain_max: int = 200             # cap per parent domain
    # --- host discovery (CIDR ping sweep) ---
    hostdiscovery_enabled: bool = True

    # --- nmap ---
    nmap_top_ports: int = 1000         # 0 => full -p-
    nmap_min_rate: int = 1500
    nmap_timing: str = "-T4"
    nmap_default_scripts: bool = True   # -sC
    nmap_vuln_scripts: bool = True      # --script vuln (best-effort CVE hints)

    # --- web discovery (dirsearch) ---
    web_wordlist: str = os.path.join(ROOT, "wordlists", "web-common.txt")
    web_extensions: str = "php,asp,aspx,jsp,html,txt,zip,tar.gz,sql,bak,json,env,git"
    web_threads: int = 25
    web_exclude_status: str = "404"

    # --- exposures (built-in active probes: info-leak / VCS / backups) ---
    exposures_enabled: bool = True
    git_leak: bool = True
    env_leak: bool = True
    backup_leak: bool = True

    # --- secrets / API-key leak scanning + API doc exposure ---
    secret_scan: bool = True             # regex-scan JS/HTML for leaked keys/tokens
    api_doc_probe: bool = True           # swagger/openapi/graphql introspection
    secrets_max_assets: int = 60         # cap JS/HTML assets fetched per target

    # --- CVE-2024-4577 / 8926 via Night-have-dreams/php-cgi-Injector ---
    phpcgi_enabled: bool = True
    phpcgi_dir: str = os.path.join(ROOT, "third_party", "php-cgi-Injector")
    phpcgi_python: str = field(default_factory=lambda: sys.executable)
    # NOTE: php-cgi-Injector's --bypass opens an INTERACTIVE tamper-selection
    # menu (two input() prompts) with no headless flag, so it deadlocks/EOFs
    # under edu-recon's stdin-closed invocation. Keep off for automated runs;
    # use the tool by hand if a WAF needs evasion.
    phpcgi_bypass: bool = False           # --bypass WAF evasion (interactive; headless-incompatible)
    phpcgi_target_timeout: int = 90      # per-URL wall-clock before we move on
    phpcgi_cgipoints: list[str] = field(default_factory=list)  # empty => tool defaults

    # --- CVE-2025-55182 React Server Components RCE via
    #     hidden-investigations/react2shell-scanner (Next.js / RSC apps) ---
    react2shell_enabled: bool = True
    react2shell_dir: str = os.path.join(ROOT, "third_party", "react2shell-scanner")
    react2shell_python: str = field(default_factory=lambda: sys.executable)
    react2shell_safe_check: bool = True  # SAFE_CHECK marker payload — no OS command run
    react2shell_command: str = "id"      # only used when react2shell_safe_check is False
    react2shell_paths: list[str] = field(default_factory=lambda: ["/"])
    react2shell_waf_bypass: bool = False        # prepend junk multipart field
    react2shell_vercel_waf_bypass: bool = False  # alternate multipart layout for Vercel WAF
    react2shell_insecure: bool = True    # tolerate self-signed certs on internal targets
    react2shell_windows: bool = False    # use whoami instead of id when command == id
    react2shell_target_timeout: int = 25  # per-URL request timeout

    # --- crawler (feeds sqli + xss with param URLs / forms) ---
    crawl_max_pages: int = 40
    crawl_max_targets: int = 40          # cap param-urls + forms actually injected

    # --- sqlmap (deep) + built-in SQL-error quick pass ---
    sqlmap_level: int = 2
    sqlmap_risk: int = 1
    sqlmap_crawl: int = 2
    sqlmap_forms: bool = True
    sqlmap_extra: list[str] = field(default_factory=list)
    sqlerr_quickpass: bool = True        # built-in error-based heuristic before sqlmap

    # --- XSS ---
    xss_enabled: bool = True
    dalfox_bin: str = "dalfox"           # preferred engine when present
    xss_builtin: bool = True             # reflected-XSS canary probe fallback

    # --- hydra weak-password ---
    userlist: str = os.path.join(ROOT, "wordlists", "users.txt")
    passlist: str = os.path.join(ROOT, "wordlists", "passwords.txt")
    default_creds: str = os.path.join(ROOT, "wordlists", "default-creds.txt")  # user:pass per line
    hydra_tasks: int = 4               # parallel per service (low => avoid lockout)
    hydra_stop_on_first: bool = True
    hydra_services: list[str] = field(default_factory=lambda: [
        "ssh", "ftp", "rdp", "mysql", "postgres", "vnc", "smb", "telnet", "redis",
    ])

    # --- per-stage timeouts (seconds) ---
    timeouts: dict[str, int] = field(default_factory=lambda: {
        "hostdiscovery": 600, "subdomain": 600, "portscan": 3600, "webdisco": 1800,
        "exposures": 300, "secrets": 600, "phpcgi": 1200, "react2shell": 900,
        "xss": 1200, "sqli": 2400, "cred": 1800, "wp": 1200,
    })

    # --- scope safety ---
    extra_allowed_cidrs: list[str] = field(default_factory=list)

    # ---------------------------------------------------------------
    def stage_runs(self, name: str) -> bool:
        return name in INTENSITY_STAGES.get(self.intensity, set())

    def resolve_bins(self) -> dict[str, str | None]:
        """Return {logical_name: resolved_path_or_None} for reporting availability."""
        out = {}
        for attr in ("nmap", "dirsearch", "sqlmap", "hydra", "subfinder",
                     "dalfox", "curl"):
            b = getattr(self, f"{attr}_bin")
            out[attr] = b if (os.path.isabs(b) and os.path.exists(b)) else shutil.which(b)
        # cloned script tools (not PATH binaries)
        exploit = os.path.join(self.phpcgi_dir, "exploit.py")
        out["phpcgi"] = exploit if os.path.exists(exploit) else None
        r2s = os.path.join(self.react2shell_dir, "react2shell-scanner.py")
        out["react2shell"] = r2s if os.path.exists(r2s) else None
        wp = os.path.join(self.wp2shell_dir, "wp2shell.py")
        out["wp2shell"] = wp if os.path.exists(wp) else shutil.which("wp2shell")
        return out

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    # ---------------------------------------------------------------
    @classmethod
    def load(cls, path: str | None) -> "Config":
        cfg = cls()
        data: dict[str, Any] = {}
        if path and os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
            if path.endswith((".yaml", ".yml")):
                data = _load_yaml(text)
            else:
                data = json.loads(text)
        for k, v in (data or {}).items():
            if hasattr(cfg, k) and v is not None:
                setattr(cfg, k, v)
        # normalize
        if cfg.intensity not in INTENSITY_STAGES:
            cfg.intensity = "full"
        os.makedirs(cfg.workdir, exist_ok=True)
        return cfg


def _load_yaml(text: str) -> dict[str, Any]:
    try:
        import yaml  # type: ignore
        return yaml.safe_load(text) or {}
    except Exception:
        # Minimal fallback parser: flat "key: value" and simple lists. Good enough
        # for the shipped config.yaml; install pyyaml for nested structures.
        out: dict[str, Any] = {}
        cur_list_key: str | None = None
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if line.lstrip().startswith("- ") and cur_list_key:
                out.setdefault(cur_list_key, []).append(_coerce(line.lstrip()[2:].strip()))
                continue
            if ":" in line and not line.startswith(" "):
                key, _, val = line.partition(":")
                key, val = key.strip(), val.strip()
                if val == "":
                    cur_list_key = key
                    out.setdefault(key, [])
                else:
                    cur_list_key = None
                    out[key] = _coerce(val)
        return out


def _coerce(v: str) -> Any:
    v = v.strip().strip('"').strip("'")
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    if v.lower() in ("null", "none", "~"):
        return None
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return v
