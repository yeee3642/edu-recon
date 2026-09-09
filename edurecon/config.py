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
    "passive": {"shodan", "portscan", "webdisco", "exposures", "secrets", "moodle"},
    # recon: phpcgi + react2shell + webcve + moodle + wordpress + reflected-XSS (benign) execute; sqli/cred are CANDIDATE lists
    "recon": {"shodan", "portscan", "webdisco", "exposures", "secrets", "phpcgi", "react2shell",
              "webcve", "moodle", "wp", "xss", "sqli_candidate", "cred_candidate"},
    # full: everything runs for real
    "full": {"shodan", "portscan", "webdisco", "exposures", "secrets", "phpcgi", "react2shell",
             "webcve", "moodle", "wp", "xss", "sqli", "cred"},
}

# shodan first: passive intel that can seed ports/services before the active stages
ALL_STAGES = ["shodan", "portscan", "webdisco", "exposures", "secrets", "phpcgi", "react2shell",
              "webcve", "moodle", "xss", "sqli", "cred", "wp"]


@dataclass
class Config:
    # --- global ---
    workdir: str = os.path.join(ROOT, "runs")
    intensity: str = "full"            # full | recon | passive
    concurrency: int = 4               # targets scanned in parallel
    http_timeout: int = 12
    user_agent: str = ("Mozilla/5.0 (edu-recon; authorized-exercise) "
                       "AppleWebKit/537.36 Safari/537.36")

    # --- Shodan passive enrichment (needs an API key) ---
    shodan_enabled: bool = True          # only actually runs when a key is present
    shodan_api_key: str = ""             # config.yaml, or the SHODAN_API_KEY env var
    shodan_timeout: int = 25
    shodan_vuln_findings: bool = False   # Shodan CVEs are version-inferred (like nmap
    #                                      --script vuln) -> listed as candidates, not
    #                                      counted as findings unless this is True.
    shodan_seed_services: bool = False   # merge Shodan-known ports into the service list
    #                                      (off by default: keeps passive intel from
    #                                      auto-driving active stages such as hydra/cred).

    # --- tool binaries (auto-discovered on PATH if left as name) ---
    nmap_bin: str = "nmap"
    dirsearch_bin: str = "dirsearch"
    sqlmap_bin: str = "sqlmap"
    hydra_bin: str = "hydra"
    subfinder_bin: str = "subfinder"
    curl_bin: str = "curl"

    # cloned dirsearch (maurosoria/dirsearch) — run via python when there's no
    # PATH binary. Its bundled db/dicc.txt (~9.7k entries) is the full sweep.
    dirsearch_dir: str = os.path.join(ROOT, "third_party", "dirsearch")
    dirsearch_python: str = field(default_factory=lambda: sys.executable)

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
    nmap_vuln_findings: bool = False    # promote NSE vuln output to findings?
    #   OFF (default): nmap's "VULNERABLE"/CVE hits are version/banner inference with no
    #   SAFE-CHECK oracle, so they don't count as findings -- the raw output still lands
    #   in the nmap.xml / nmap.stdout.log artifacts for human review. Confirmed CVEs come
    #   from the oracle-backed stages (webcve/phpcgi/react2shell/moodle) instead.

    # --- web discovery (dirsearch) ---
    web_wordlist: str = os.path.join(ROOT, "wordlists", "web-common.txt")
    web_fulldict: bool = True             # use dirsearch's full db/dicc.txt (全掃); ignore web_wordlist
    web_extensions: str = "php,asp,aspx,jsp,html,txt,zip,tar.gz,sql,bak,json,env,git"
    web_threads: int = 25
    web_exclude_status: str = "404"

    # --- exposures (built-in active probes: info-leak / VCS / backups) ---
    exposures_enabled: bool = True
    git_leak: bool = True
    env_leak: bool = True
    backup_leak: bool = True
    admin_panel_probe: bool = True       # phpMyAdmin / Adminer DB-admin exposure
    dir_listing_probe: bool = True       # open directory listing (Index of /)

    # --- education-sector system audit (Moodle) ---
    moodle_enabled: bool = True
    moodle_min_supported: str = "4.1"    # branches below this are flagged outdated

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

    # --- built-in famous-CVE safe-check probes (non-destructive; no ext tool) ---
    webcve_enabled: bool = True
    webcve_phpunit: bool = True           # CVE-2017-9841  PHPUnit eval-stdin RCE
    webcve_apache_traversal: bool = True  # CVE-2021-41773 Apache path traversal/LFI
    webcve_struts2: bool = True           # CVE-2017-5638  Struts2 S2-045 OGNL RCE
    webcve_confluence: bool = True        # CVE-2022-26134 Confluence OGNL RCE
    webcve_drupalgeddon2: bool = True     # CVE-2018-7600  Drupalgeddon2 RCE
    webcve_nextjs_mw: bool = True         # CVE-2025-29927 Next.js middleware auth bypass

    # --- crawler (feeds sqli + xss with param URLs / forms) ---
    crawl_max_pages: int = 40
    crawl_max_targets: int = 40          # cap param-urls + forms actually injected

    # --- sqlmap (deep) + built-in SQL-error quick pass ---
    sqlmap_level: int = 2
    sqlmap_risk: int = 1
    sqlmap_crawl: int = 2
    sqlmap_forms: bool = True
    sqlmap_extra: list[str] = field(default_factory=list)
    sqlerr_quickpass: bool = True        # built-in SQLi quick pass before sqlmap
    # built-in SQLi breadth ("大量嘗試"): error + boolean-blind + time-blind, all benign
    sqli_error_based: bool = True        # DB error-signature differential
    sqli_boolean_blind: bool = True      # 1=1 vs 1=2 response differential (SELECT-only)
    sqli_time_blind: bool = True         # SLEEP/pg_sleep/WAITFOR timing oracle
    sqli_time_delay: int = 5             # seconds the sleep payload asks for
    sqli_time_budget: int = 8            # max time-based probes per target (they're slow)
    sqli_max_params: int = 40            # cap params/inputs injected per target

    # --- XSS ---
    xss_enabled: bool = True
    dalfox_bin: str = "dalfox"           # preferred engine when present
    xss_builtin: bool = True             # built-in reflected-XSS probe (breadth backstop)
    xss_payload_budget: int = 400        # max injected XSS requests per target ("大量嘗試")
    xss_stop_on_first_ctx: bool = True   # one confirmed context per param is enough
    xss_max_params: int = 40             # cap params/inputs injected per target

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
        "webcve": 600, "moodle": 300, "xss": 1200, "sqli": 2400, "cred": 1800, "wp": 1200,
    })

    # --- scope safety ---
    extra_allowed_cidrs: list[str] = field(default_factory=list)
    scope_enforce: bool = False          # default OFF: operator owns authorization,
    #                                      scan/dump whatever you type. Set True for a
    #                                      real engagement with a locked scope allowlist.

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
        if not out.get("dirsearch"):            # cloned dirsearch fallback (no PATH binary)
            dds = os.path.join(self.dirsearch_dir, "dirsearch.py")
            out["dirsearch"] = dds if os.path.exists(dds) else None
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
        if not cfg.shodan_api_key:                       # env fallback; never hard-code a key
            cfg.shodan_api_key = os.environ.get("SHODAN_API_KEY", "").strip()
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
