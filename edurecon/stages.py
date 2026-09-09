"""Pipeline stages.

Run-level expansion:  host_discovery(), subdomain_enum()
Per-target stages:    stage_portscan / webdisco / exposures / phpcgi / sqli / cred / wp

Every per-target stage takes a StageCtx, mutates ctx.ts, and never raises for a
missing tool or a single failed probe — it records a stage note instead so one
weak target can't abort the run.
"""
from __future__ import annotations

import json
import os
import shutil
import socket

from .config import Config
from .context import StageCtx
from .models import Service, WebPath
from . import parse, webhttp, webscan
from . import secrets as secretscan
from . import cveprobes
from . import edusys

# nmap service name / port  ->  hydra module
HYDRA_MODULES = {
    "ssh": "ssh", "ftp": "ftp", "telnet": "telnet", "mysql": "mysql",
    "postgresql": "postgres", "postgres": "postgres", "vnc": "vnc",
    "ms-wbt-server": "rdp", "rdp": "rdp", "microsoft-ds": "smb",
    "netbios-ssn": "smb", "smb": "smb", "redis": "redis", "rsh": "rsh",
    "smtp": "smtp", "pop3": "pop3", "imap": "imap", "http": "http-get",
}

# high-signal info-leak / VCS / backup probes: path -> (signature-substr, category, severity, title)
EXPOSURE_PROBES = [
    ("/.git/HEAD",        "ref:",                 "vcs-leak",   "high",   "Exposed .git repository (/.git/HEAD)"),
    ("/.git/config",      "[core]",               "vcs-leak",   "high",   "Exposed .git config"),
    ("/.svn/entries",     "",                     "vcs-leak",   "medium", "Exposed .svn directory"),
    ("/.hg/requires",     "",                     "vcs-leak",   "medium", "Exposed Mercurial repository"),
    ("/.env",             "=",                    "secret-leak","high",   "Exposed .env file"),
    ("/.DS_Store",        "\x00\x00\x00",         "info-leak",  "low",    "Exposed .DS_Store"),
    ("/server-status",    "Apache Server Status", "info-leak",  "medium", "Apache mod_status exposed"),
    ("/server-info",      "Apache Server Info",   "info-leak",  "medium", "Apache mod_info exposed"),
    ("/phpinfo.php",      "phpinfo()",            "info-leak",  "medium", "phpinfo() exposed"),
    ("/info.php",         "phpinfo()",            "info-leak",  "medium", "phpinfo() exposed"),
    ("/actuator",         "\"_links\"",           "info-leak",  "medium", "Spring Boot actuator exposed"),
    ("/actuator/env",     "",                     "secret-leak","high",   "Spring actuator /env exposed"),
    ("/.htpasswd",        ":",                    "secret-leak","high",   "Exposed .htpasswd"),
    ("/wp-config.php.bak","DB_PASSWORD",          "secret-leak","critical","WordPress wp-config backup exposed"),
    ("/config.php.bak",   "",                     "secret-leak","high",   "PHP config backup exposed"),
    ("/.aws/credentials", "aws_access_key",       "secret-leak","critical","Exposed AWS credentials"),
]

# backup archive candidates (checked for 200 + non-html content-type)
BACKUP_NAMES = ["backup.zip", "backup.tar.gz", "www.zip", "web.zip", "site.zip",
                "backup.sql", "database.sql", "db.sql", "dump.sql", "web.config",
                "wp-config.php~", ".htaccess.bak"]

WP_MARKERS = ["/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php"]

DANGEROUS_PORTS = {
    23: ("telnet", "high", "Telnet exposed (cleartext credentials)"),
    3389: ("rdp", "medium", "RDP exposed to network"),
    445: ("smb", "medium", "SMB exposed to network"),
    3306: ("mysql", "high", "MySQL exposed to network"),
    5432: ("postgres", "high", "PostgreSQL exposed to network"),
    1433: ("mssql", "high", "MSSQL exposed to network"),
    27017: ("mongodb", "high", "MongoDB exposed to network"),
    6379: ("redis", "high", "Redis exposed to network (often no auth)"),
    9200: ("elasticsearch", "high", "Elasticsearch exposed to network"),
    11211: ("memcached", "high", "Memcached exposed to network"),
    5900: ("vnc", "high", "VNC exposed to network"),
    2375: ("docker", "critical", "Docker API exposed (unauthenticated RCE)"),
}


# ===================================================================== #
# helpers
# ===================================================================== #
def _bin(cfg: Config, name: str) -> str | None:
    b = getattr(cfg, f"{name}_bin")
    if os.path.isabs(b):
        return b if os.path.exists(b) else None
    return shutil.which(b)


def _root_bases(ts) -> list[str]:
    """Root URLs for dirsearch / exposures (scheme://host:port/)."""
    bases: set[str] = set()
    for s in ts.http_services():
        bases.add(f"{s.scheme}://{ts.host}:{s.port}/")
    if not bases:
        if ts.base_url:
            from urllib.parse import urlparse
            u = urlparse(ts.base_url)
            netloc = u.netloc
            bases.add(f"{u.scheme}://{netloc}/")
        elif ts.port_hint:
            bases.add(f"{ts.scheme}://{ts.host}:{ts.port_hint}/")
        else:
            bases.add(f"{ts.scheme}://{ts.host}/")
    return sorted(bases)


def _app_urls(ts) -> list[str]:
    """Full app URLs for sqlmap / phpcgi (keep path+query of a URL target)."""
    if ts.base_url:
        return [ts.base_url]
    return _root_bases(ts)


def ensure_crawl(ctx: StageCtx) -> None:
    """Populate ts.param_urls / ts.forms once (shared by sqli + xss)."""
    if ctx.ts.crawled:
        return
    ctx.ts.crawled = True
    bases = _root_bases(ctx.ts) + [u for u in _app_urls(ctx.ts) if u not in _root_bases(ctx.ts)]
    try:
        param_urls, forms = webscan.crawl(sorted(set(bases)), ctx.cfg)
    except Exception as e:  # crawler must never kill a target
        ctx.logger(f"[{ctx.ts.host}] crawl error: {e}")
        param_urls, forms = [], []
    # seed param urls from an explicit URL target that already has a query string
    for u in _app_urls(ctx.ts):
        if "?" in u and u not in param_urls:
            param_urls.append(u)
    ctx.ts.param_urls = param_urls
    ctx.ts.forms = forms


# ===================================================================== #
# run-level expansion
# ===================================================================== #
def host_discovery(pt, cfg: Config, run_dir: str, logger) -> list[str]:
    """Expand a CIDR to live IPs via nmap -sn; pass through single hosts."""
    if pt.kind != "cidr":
        return [pt.host]
    nmap = _bin(cfg, "nmap")
    if not nmap:
        logger(f"hostdiscovery: nmap missing, cannot expand {pt.cidr}")
        return []
    xml = os.path.join(run_dir, f"discovery-{pt.cidr.replace('/', '_')}.xml")
    from .runner import run as _run
    _run([nmap, "-sn", "-n", "-oX", xml, pt.cidr],
         timeout=cfg.timeouts.get("hostdiscovery", 600),
         log_path=xml + ".log")
    hosts = parse.parse_nmap_up_hosts(xml)
    logger(f"hostdiscovery: {pt.cidr} -> {len(hosts)} live host(s)")
    return hosts


def subdomain_enum(domain: str, cfg: Config, run_dir: str, logger) -> list[str]:
    """Enumerate subdomains via subfinder, else crt.sh; optionally keep resolvable."""
    if _is_ip(domain):
        return [domain]
    found: set[str] = {domain}
    sub = _bin(cfg, "subfinder")
    if sub:
        from .runner import run as _run
        out = os.path.join(run_dir, f"subfinder-{domain}.txt")
        res = _run([sub, "-d", domain, "-silent", "-all"],
                   timeout=cfg.timeouts.get("subdomain", 600), log_path=out)
        for line in res.stdout.splitlines():
            h = line.strip().lower()
            if h.endswith(domain):
                found.add(h)
    elif cfg.subdomain_use_crtsh:
        found |= _crtsh(domain, cfg, logger)

    subs = sorted(found)[: cfg.subdomain_max]
    if cfg.subdomain_resolve:
        subs = [h for h in subs if _resolves(h)]
        if domain not in subs and _resolves(domain):
            subs.append(domain)
    logger(f"subdomain: {domain} -> {len(subs)} subdomain(s)")
    return subs


def _crtsh(domain: str, cfg: Config, logger) -> set[str]:
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    status, _, body = webhttp.get(url, cfg.http_timeout, cfg.user_agent, max_bytes=4_000_000)
    out: set[str] = set()
    if status != 200 or not body:
        logger(f"subdomain: crt.sh returned {status} for {domain}")
        return out
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return out
    for row in data:
        for name in str(row.get("name_value", "")).splitlines():
            name = name.strip().lstrip("*.").lower()
            if name.endswith(domain) and "@" not in name:
                out.add(name)
    return out


# ===================================================================== #
# per-target stages
# ===================================================================== #
def stage_portscan(ctx: StageCtx) -> None:
    cfg = ctx.cfg
    nmap = _bin(cfg, "nmap")
    if not nmap:
        ctx.ts.stage("portscan").note = "nmap not found; skipped"
        return
    ctx.scope.check(ctx.ts.host)
    xml = ctx.artifact("nmap.xml")
    argv = [nmap, cfg.nmap_timing, "-Pn", "-sV", "-n",
            "--min-rate", str(cfg.nmap_min_rate)]
    if ctx.ts.port_hint:                 # explicit port target -> scan it (fast, exact)
        argv += ["-p", str(ctx.ts.port_hint)]
    elif cfg.nmap_top_ports and cfg.nmap_top_ports > 0:
        argv += ["--top-ports", str(cfg.nmap_top_ports)]
    else:
        argv += ["-p-"]
    if cfg.nmap_default_scripts:
        argv += ["-sC"]
    if cfg.nmap_vuln_scripts:
        argv += ["--script", "vuln"]
    argv += ["-oX", xml, ctx.ts.host]

    ctx.run(argv, stage="portscan", log_name="nmap.stdout.log")
    ctx.record_artifact("portscan", xml)
    parsed = parse.parse_nmap_xml(xml)
    entry = parsed.get(ctx.ts.host)
    if entry is None and parsed:
        entry = next(iter(parsed.values()))
    if entry:
        ctx.ts.services = entry["services"]
        # host-level nse vuln output -> finding only if opted in (default off); nmap's
        # version-inferred "VULNERABLE"/CVE hits are not oracle-verified, so by default
        # they stay in the nmap.xml/stdout artifact and are not counted as findings.
        if cfg.nmap_vuln_findings:
            for sid, out in entry.get("hostscripts", {}).items():
                if "VULNERABLE" in out or "CVE-" in out:
                    ctx.finding(stage="portscan", category="nmap-vuln",
                                title=f"nmap {sid} flagged VULNERABLE",
                                severity="high", confidence="medium",
                                evidence={"script": sid, "output": out[:800]})
    ctx.ts.stage("portscan").note = f"{len(ctx.ts.services)} open port(s)"


# common web paths probed by the built-in web-discovery fallback (no dirsearch).
WEBDISCO_COMMON = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/favicon.ico",
    "/admin", "/admin/", "/administrator/", "/login", "/login.php", "/admin.php",
    "/wp-login.php", "/wp-admin/", "/wp-json/", "/xmlrpc.php", "/wp-content/",
    "/phpmyadmin/", "/adminer.php", "/dbadmin/", "/server-status", "/server-info",
    "/phpinfo.php", "/info.php", "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/.env", "/.htaccess", "/.htpasswd", "/config.php", "/config.php.bak",
    "/configuration.php", "/web.config", "/backup/", "/backups/", "/backup.zip",
    "/backup.sql", "/db.sql", "/dump.sql", "/database.sql", "/uploads/", "/files/",
    "/images/", "/img/", "/assets/", "/static/", "/js/", "/css/", "/api", "/api/",
    "/api/v1/", "/swagger/", "/swagger-ui/", "/openapi.json", "/graphql",
    "/actuator", "/actuator/env", "/health", "/status", "/metrics", "/debug",
    "/test/", "/tmp/", "/temp/", "/old/", "/dev/", "/staging/", "/readme.txt",
    "/README.md", "/CHANGELOG.md", "/LICENSE", "/package.json", "/composer.json",
    "/composer.lock", "/wp-config.php.bak", "/user/login", "/user/register",
    "/console", "/cgi-bin/", "/.DS_Store", "/crossdomain.xml", "/index.php",
    "/index.html", "/home", "/dashboard", "/portal", "/cpanel", "/webmail",
]
_WEBDISCO_KEEP = {200, 204, 301, 302, 303, 307, 308, 401, 403, 405}


def _builtin_webdisco(ctx: StageCtx, bases: list[str]) -> int:
    """dirsearch-free path discovery: probe a common-paths list, record hits."""
    cfg = ctx.cfg
    seen: set[str] = set()
    added = 0
    for base in bases:
        if ctx.aborted() or added >= 500:
            break
        ctx.scope.check(ctx.ts.host)
        root = base.rstrip("/")
        for path in WEBDISCO_COMMON:
            if ctx.aborted() or added >= 500:
                break
            url = root + path
            if url in seen:
                continue
            seen.add(url)
            st, hdrs, body = webhttp.get(url, cfg.http_timeout, cfg.user_agent, max_bytes=4096)
            if st not in _WEBDISCO_KEEP:
                continue
            if st == 200 and _looks_like_html_404(body):
                continue
            clen = hdrs.get("Content-Length") or hdrs.get("content-length")
            length = int(clen) if (clen and str(clen).isdigit()) else len(body)
            redirect = hdrs.get("Location") or hdrs.get("location") or ""
            ctx.ts.webpaths.append(WebPath(url=url, status=st, length=length, redirect=redirect))
            added += 1
    return added


def _dirsearch_cmd(cfg: Config) -> list[str] | None:
    """Native dirsearch binary (Kali) first, else cloned dirsearch.py via python."""
    b = _bin(cfg, "dirsearch")
    if b and b.lower().endswith(".py"):
        return [cfg.dirsearch_python, b]
    if b:
        return [b]
    script = os.path.join(cfg.dirsearch_dir, "dirsearch.py")
    if os.path.exists(script):
        return [cfg.dirsearch_python, script]
    return None


def stage_webdisco(ctx: StageCtx) -> None:
    cfg = ctx.cfg
    bases = _root_bases(ctx.ts)
    if not bases:
        ctx.ts.stage("webdisco").note = "no http service"
        return
    ds_cmd = _dirsearch_cmd(cfg)
    if not ds_cmd:                               # built-in fallback path discovery
        n = _builtin_webdisco(ctx, bases)
        _detect_wordpress(ctx)
        ctx.ts.stage("webdisco").note = f"{n} path(s) · built-in (install dirsearch for full)"
        return
    for i, base in enumerate(bases):
        if ctx.aborted():
            return
        ctx.scope.check(ctx.ts.host)
        out_json = ctx.artifact(f"dirsearch-{i}.json")
        argv = [*ds_cmd, "-u", base, "-e", cfg.web_extensions,
                "-t", str(cfg.web_threads), "--exclude-status", cfg.web_exclude_status,
                "-O", "json", "-o", out_json, "-q", "--random-agent"]
        # full sweep uses dirsearch's built-in db/dicc.txt (~9.7k); a configured
        # wordlist only overrides when web_fulldict is off.
        if not cfg.web_fulldict and cfg.web_wordlist and os.path.exists(cfg.web_wordlist):
            argv += ["-w", cfg.web_wordlist]
        ctx.run(argv, stage="webdisco", log_name=f"dirsearch-{i}.log")
        ctx.record_artifact("webdisco", out_json)
        paths = parse.parse_dirsearch_json(out_json)
        if not paths:
            paths = parse.parse_dirsearch_text(ctx.artifact(f"dirsearch-{i}.log"))
        ctx.ts.webpaths.extend(paths)
    _detect_wordpress(ctx)
    ctx.ts.stage("webdisco").note = f"{len(ctx.ts.webpaths)} path(s)"


def _detect_wordpress(ctx: StageCtx) -> None:
    for w in ctx.ts.webpaths:
        low = w.url.lower()
        if any(m in low for m in WP_MARKERS) and w.status in (200, 301, 302, 401, 403):
            ctx.ts.is_wordpress = True
            return
    # cheap direct probe
    for base in _root_bases(ctx.ts):
        st, _, _ = webhttp.get(base.rstrip("/") + "/wp-login.php",
                            ctx.cfg.http_timeout, ctx.cfg.user_agent)
        if st in (200, 302, 403):
            ctx.ts.is_wordpress = True
            return


def stage_exposures(ctx: StageCtx) -> None:
    cfg = ctx.cfg
    if not cfg.exposures_enabled:
        ctx.ts.stage("exposures").note = "disabled"
        return
    bases = _root_bases(ctx.ts)
    if not bases:
        ctx.ts.stage("exposures").note = "no http service"
        return
    hits = 0
    for base in bases:
        if ctx.aborted():
            return
        ctx.scope.check(ctx.ts.host)
        root = base.rstrip("/")
        for path, sig, category, severity, title in EXPOSURE_PROBES:
            if category == "vcs-leak" and not cfg.git_leak and "git" in path:
                continue
            if category == "secret-leak" and not cfg.env_leak:
                pass  # still allow other secret probes; env toggle only gates /.env
            if path == "/.env" and not cfg.env_leak:
                continue
            st, hdrs, body = webhttp.get(root + path, cfg.http_timeout, cfg.user_agent)
            if st != 200:
                continue
            if sig and sig not in body:
                continue
            if _looks_like_html_404(body):
                continue
            hits += 1
            ctx.finding(stage="exposures", category=category, title=title,
                        severity=severity, confidence="high",
                        evidence={"url": root + path, "status": st,
                                  "snippet": body[:400].strip()})
        if cfg.backup_leak:
            hits += _probe_backups(ctx, root)
        if cfg.admin_panel_probe:
            hits += _probe_admin_panels(ctx, root)
        if cfg.dir_listing_probe:
            hits += _probe_dir_listing(ctx, root)
    ctx.ts.stage("exposures").note = f"{hits} exposure(s)"


# phpMyAdmin / Adminer DB-admin panels commonly left exposed on edu hosts.
PMA_PATHS = ["/phpmyadmin/", "/phpMyAdmin/", "/pma/", "/PMA/", "/mysql/",
             "/dbadmin/", "/phpmyadmin2/", "/phpMyAdmin2/", "/phpmyadmin/index.php"]
ADMINER_PATHS = ["/adminer.php", "/adminer/", "/adminer/adminer.php",
                 "/adminer-4.8.1.php", "/adminer-4.8.1-en.php", "/db.php"]
DIR_LISTING_DIRS = ["/", "/uploads/", "/files/", "/backup/", "/backups/",
                    "/images/", "/img/", "/data/", "/tmp/", "/old/", "/test/",
                    "/download/", "/upload/"]


def _probe_admin_panels(ctx: StageCtx, root: str) -> int:
    cfg = ctx.cfg
    hits = 0
    # phpMyAdmin — flag the login, escalate if the setup script is reachable
    for path in PMA_PATHS:
        st, _h, body = webhttp.get(root + path, cfg.http_timeout, cfg.user_agent)
        if st == 200 and "phpmyadmin" in body.lower():
            sev, title = "medium", f"phpMyAdmin exposed: {path}"
            sst, _sh, sbody = webhttp.get(root + "/phpmyadmin/setup/",
                                          cfg.http_timeout, cfg.user_agent)
            if sst == 200 and "setup" in sbody.lower() and "phpmyadmin" in sbody.lower():
                sev, title = "high", "phpMyAdmin setup script exposed (/phpmyadmin/setup/)"
            hits += 1
            ctx.finding(stage="exposures", category="admin-panel", title=title,
                        severity=sev, confidence="high",
                        evidence={"url": root + path, "software": "phpMyAdmin"})
            break
    # Adminer — single-file DB client, known SSRF / brute surface
    for path in ADMINER_PATHS:
        st, _h, body = webhttp.get(root + path, cfg.http_timeout, cfg.user_agent)
        if st == 200 and "adminer" in body.lower() and "login" in body.lower():
            hits += 1
            ctx.finding(stage="exposures", category="admin-panel",
                        title=f"Adminer DB client exposed: {path}",
                        severity="medium", confidence="high",
                        evidence={"url": root + path, "software": "Adminer"})
            break
    return hits


def _probe_dir_listing(ctx: StageCtx, root: str) -> int:
    cfg = ctx.cfg
    hits = 0
    for d in DIR_LISTING_DIRS:
        if hits >= 3:                      # cap noise: a few examples is enough
            break
        st, _h, body = webhttp.get(root + d, cfg.http_timeout, cfg.user_agent)
        low = body.lower()
        if st == 200 and ("<title>index of /" in low or "directory listing for" in low
                          or ">index of /" in low):
            hits += 1
            ctx.finding(stage="exposures", category="dir-listing",
                        title=f"Directory listing enabled: {d}",
                        severity="medium", confidence="high",
                        evidence={"url": root + d,
                                  "snippet": body[:200].strip()})
    return hits


def _probe_backups(ctx: StageCtx, root: str) -> int:
    cfg = ctx.cfg
    host_label = ctx.ts.host.split(":")[0]
    names = list(BACKUP_NAMES) + [f"{host_label}.zip", f"{host_label}.tar.gz"]
    hits = 0
    for name in names:
        st, hdrs, body = webhttp.get(root + "/" + name, cfg.http_timeout, cfg.user_agent,
                                  max_bytes=512)
        if st != 200:
            continue
        ctype = (hdrs.get("Content-Type") or hdrs.get("content-type") or "").lower()
        if "text/html" in ctype and _looks_like_html_404(body):
            continue
        hits += 1
        ctx.finding(stage="exposures", category="backup-leak",
                    title=f"Exposed backup/archive: /{name}",
                    severity="high", confidence="medium",
                    evidence={"url": root + "/" + name, "content_type": ctype})
    return hits


def _looks_like_html_404(body: str) -> bool:
    low = body.lower()
    return ("<html" in low and ("not found" in low or "404" in low)) and "<title" in low


def stage_secrets(ctx: StageCtx) -> None:
    cfg = ctx.cfg
    bases = _root_bases(ctx.ts)
    if not bases:
        ctx.ts.stage("secrets").note = "no http service"
        return
    ctx.scope.check(ctx.ts.host)
    ensure_crawl(ctx)

    # 1) gather HTML/JS/JSON assets (bounded)
    assets: dict[str, str] = {}
    to_fetch: list[str] = []
    for b in bases:
        _, _, body = webhttp.get(b, cfg.http_timeout, cfg.user_agent, max_bytes=300_000)
        if body:
            assets[b] = body
            to_fetch += secretscan.extract_assets(b, body)
    to_fetch += ctx.ts.param_urls
    for w in ctx.ts.webpaths:
        if w.status == 200 and w.url.lower().endswith(
                (".js", ".json", ".map", ".txt", ".env", ".config", ".cfg", ".yml", ".yaml")):
            to_fetch.append(w.url)
    seen = set(assets)
    for u in to_fetch:
        if len(assets) >= cfg.secrets_max_assets:
            break
        if u in seen:
            continue
        seen.add(u)
        _, _, body = webhttp.get(u, cfg.http_timeout, cfg.user_agent, max_bytes=300_000)
        if body:
            assets[u] = body

    hits = 0
    # 2) scan for leaked secrets / API keys
    if cfg.secret_scan:
        seen_secret: set[tuple] = set()
        for url, text in assets.items():
            for h in secretscan.scan_text(url, text):
                key = (h["type"], h["value"])
                if key in seen_secret:
                    continue
                seen_secret.add(key)
                hits += 1
                cat = h.get("category", "secret-leak")
                title = (f"Exposed DB credential: {h['type']}" if cat == "db-cred"
                         else f"Leaked secret: {h['type']}")
                ctx.finding(stage="secrets", category=cat, title=title,
                            severity=h["severity"], confidence="high",
                            evidence={"url": h["url"], "match": h["match"],
                                      "value": h["value"]})
    # 3) exposed API docs / GraphQL introspection
    if cfg.api_doc_probe:
        for b in bases:
            if ctx.aborted():
                break
            for r in secretscan.probe_api_docs(b, cfg):
                hits += 1
                ctx.finding(stage="secrets", category="api-leak",
                            title=r["title"], severity=r["severity"], confidence="high",
                            evidence={"url": r["url"], "kind": r["kind"],
                                      "snippet": r["evidence"]})
    ctx.ts.stage("secrets").note = f"{hits} leak(s)"


def stage_phpcgi(ctx: StageCtx) -> None:
    cfg = ctx.cfg
    exploit = os.path.join(cfg.phpcgi_dir, "exploit.py")
    if not os.path.exists(exploit):
        ctx.ts.stage("phpcgi").note = "php-cgi-Injector not installed (run: recon.py setup)"
        return
    urls = _app_urls(ctx.ts)
    found = 0
    for i, url in enumerate(urls):
        if ctx.aborted():
            return
        ctx.scope.check(ctx.ts.host)
        argv = [cfg.phpcgi_python, exploit, "-u", url, "--no-effects",
                "--timeout", str(cfg.phpcgi_target_timeout)]
        if cfg.phpcgi_bypass:
            argv += ["--bypass"]
        if cfg.phpcgi_cgipoints:
            argv += ["--cgipoint", *cfg.phpcgi_cgipoints]
        # stdin closed -> the tool's interactive input() hits EOF and exits after
        # printing the detection line we care about.
        res = ctx.run(argv, stage="phpcgi", log_name=f"phpcgi-{i}.log",
                      timeout=cfg.phpcgi_target_timeout + 30)
        info = parse.parse_phpcgi_stdout(res.stdout)
        if info["vulnerable"]:
            found += 1
            repro = f"cd {cfg.phpcgi_dir} && {cfg.phpcgi_python} exploit.py -u {url}"
            ctx.finding(stage="phpcgi", category="cve",
                        title=f"{info['cve']} PHP-CGI argument injection (RCE)",
                        severity="critical", confidence="confirmed",
                        evidence={"url": url, "cve": info["cve"],
                                  "cgipoint": info["cgipoint"], "payload": info["payload"],
                                  "reproduce": repro})
    ctx.ts.stage("phpcgi").note = f"{found} vulnerable endpoint(s)"


def stage_react2shell(ctx: StageCtx) -> None:
    """CVE-2025-55182 React Server Components RCE via react2shell-scanner.

    Defaults to --safe-check (a SAFE_CHECK_OK marker payload, no OS command) so a
    positive confirms the RSC injection reaches code execution without running a
    shell command. Set react2shell_safe_check=false to prove RCE with a benign
    command (react2shell_command, default `id`).
    """
    cfg = ctx.cfg
    if not cfg.react2shell_enabled:
        ctx.ts.stage("react2shell").note = "disabled"
        return
    script = os.path.join(cfg.react2shell_dir, "react2shell-scanner.py")
    if not os.path.exists(script):
        ctx.ts.stage("react2shell").note = "react2shell-scanner not installed (run: recon.py setup)"
        return
    bases = _root_bases(ctx.ts)
    if not bases:
        ctx.ts.stage("react2shell").note = "no http service"
        return

    found = 0
    for i, base in enumerate(bases):
        if ctx.aborted():
            return
        ctx.scope.check(ctx.ts.host)
        paths = _react2shell_paths(ctx.ts, cfg)
        out_json = ctx.artifact(f"react2shell-{i}.json")
        argv = [cfg.react2shell_python, script, "-t", base, "-o", out_json,
                "-q", "--no-color", "--timeout", str(cfg.react2shell_target_timeout)]
        for p in paths:
            argv += ["--path", p]
        if cfg.react2shell_safe_check:
            argv += ["--safe-check"]
        else:
            argv += ["-c", cfg.react2shell_command]
            if cfg.react2shell_windows:
                argv += ["--windows"]
        if cfg.react2shell_insecure:
            argv += ["-k"]
        if cfg.react2shell_waf_bypass:
            argv += ["--waf-bypass"]
        if cfg.react2shell_vercel_waf_bypass:
            argv += ["--vercel-waf-bypass"]
        ctx.run(argv, stage="react2shell", log_name=f"react2shell-{i}.log")
        ctx.record_artifact("react2shell", out_json)
        for hit in parse.parse_react2shell_json(out_json):
            found += 1
            mode = "safe-check marker" if cfg.react2shell_safe_check else "command output"
            repro = (f"cd {cfg.react2shell_dir} && {cfg.react2shell_python} "
                     f"react2shell-scanner.py -t {base} --path {hit['path'] or '/'} "
                     + ("--safe-check" if cfg.react2shell_safe_check
                        else f"-c {cfg.react2shell_command!r}"))
            ctx.finding(stage="react2shell", category="cve",
                        title="CVE-2025-55182 React Server Components RCE (React2Shell)",
                        severity="critical", confidence="confirmed",
                        evidence={"url": hit["url"], "path": hit["path"],
                                  "cve": "CVE-2025-55182", "mode": mode,
                                  "output": hit["output"][:400],
                                  "status_code": hit["status_code"],
                                  "reproduce": repro})
    ctx.ts.stage("react2shell").note = f"{found} vulnerable endpoint(s)"


def _react2shell_paths(ts, cfg: Config) -> list[str]:
    """Configured paths, plus an explicit URL target's own path when present."""
    paths = list(cfg.react2shell_paths) or ["/"]
    if ts.base_url:
        from urllib.parse import urlparse
        p = urlparse(ts.base_url).path or "/"
        if p not in paths:
            paths.append(p)
    return paths


def stage_webcve(ctx: StageCtx) -> None:
    """Built-in non-destructive safe-check probes for famous web CVEs.

    Runs entirely in-process (no external tool): PHPUnit eval-stdin (2017-9841),
    Apache traversal (2021-41773), Struts2 S2-045 (2017-5638), Confluence OGNL
    (2022-26134), Drupalgeddon2 (2018-7600) and Next.js middleware bypass
    (2025-29927). Each proves exploitability with a benign oracle only.
    """
    cfg = ctx.cfg
    if not cfg.webcve_enabled:
        ctx.ts.stage("webcve").note = "disabled"
        return
    bases = _root_bases(ctx.ts)
    if not bases:
        ctx.ts.stage("webcve").note = "no http service"
        return
    found = 0
    for base in bases:
        if ctx.aborted():
            return
        ctx.scope.check(ctx.ts.host)
        for hit in cveprobes.run_probes(base, cfg, aborted=ctx.aborted):
            found += 1
            ctx.finding(stage="webcve", category="cve", title=hit["title"],
                        severity=hit["severity"], confidence=hit["confidence"],
                        evidence={"cve": hit["cve"], "url": hit["url"],
                                  **hit.get("evidence", {})})
    ctx.ts.stage("webcve").note = f"{found} CVE hit(s)"


def stage_moodle(ctx: StageCtx) -> None:
    """Education-sector system audit: Moodle fingerprint + version + data-dir leak."""
    cfg = ctx.cfg
    if not cfg.moodle_enabled:
        ctx.ts.stage("moodle").note = "disabled"
        return
    bases = _root_bases(ctx.ts)
    if not bases:
        ctx.ts.stage("moodle").note = "no http service"
        return
    found = 0
    detected = False
    for base in bases:
        if ctx.aborted():
            return
        ctx.scope.check(ctx.ts.host)
        try:
            hits = edusys.probe_moodle(base, cfg)
        except Exception as e:
            ctx.logger(f"[{ctx.ts.host}] moodle probe error: {e}")
            continue
        for hit in hits:
            detected = True
            if hit["severity"] in ("medium", "high", "critical"):
                found += 1
            ctx.finding(stage="moodle", category=hit["category"], title=hit["title"],
                        severity=hit["severity"], confidence=hit["confidence"],
                        evidence={"url": hit["url"], **hit.get("evidence", {})})
    if not detected:
        ctx.ts.stage("moodle").note = "no Moodle detected"
    else:
        ctx.ts.stage("moodle").note = f"Moodle found; {found} issue(s)"


def stage_sqli(ctx: StageCtx, candidate_only: bool = False) -> None:
    cfg = ctx.cfg
    ensure_crawl(ctx)
    urls = _app_urls(ctx.ts)
    if candidate_only:
        ctx.finding(stage="sqli", category="candidate",
                    title="SQLi test candidates (not executed at this intensity)",
                    severity="info", confidence="low",
                    evidence={"base_urls": urls, "param_urls": ctx.ts.param_urls,
                              "forms": len(ctx.ts.forms),
                              "run": "set intensity=full to execute sqlmap"})
        ctx.ts.stage("sqli").note = "candidate list only"
        return

    hits = 0
    # (1) built-in error-based quick pass (works even without sqlmap)
    if cfg.sqlerr_quickpass:
        try:
            _TT = {"error-based": "error-based", "boolean-blind": "boolean-blind",
                   "time-based": "time-based / SLEEP"}
            for r in webscan.probe_sqli(ctx.ts.param_urls, ctx.ts.forms, cfg):
                hits += 1
                tech = r.get("technique", "sqli")
                ev = {"url": r["url"], "method": r["method"],
                      "parameter": r["param"], "technique": tech,
                      "payload": r.get("payload", "")}
                ev.update(r.get("evidence", {}))
                ctx.finding(stage="sqli", category="sqli",
                            title=f"SQL injection ({_TT.get(tech, tech)}) in {r['param']}",
                            severity="high", confidence="high", evidence=ev)
        except Exception as e:
            ctx.logger(f"[{ctx.ts.host}] sqli quickpass error: {e}")

    # (2) sqlmap deep pass
    sqlmap = _bin(cfg, "sqlmap")
    if sqlmap:
        for i, url in enumerate(urls):
            if ctx.aborted():
                return
            ctx.scope.check(ctx.ts.host)
            outdir = ctx.artifact(f"sqlmap-{i}")
            argv = [sqlmap, "-u", url, "--batch", "--random-agent", "--smart",
                    "--level", str(cfg.sqlmap_level), "--risk", str(cfg.sqlmap_risk),
                    "--crawl", str(cfg.sqlmap_crawl), "--threads", "4",
                    "--output-dir", outdir, "-v", "1"]
            if cfg.sqlmap_forms:
                argv += ["--forms"]
            argv += cfg.sqlmap_extra
            res = ctx.run(argv, stage="sqli", log_name=f"sqlmap-{i}.log")
            hits += _record_sqlmap(ctx, res.stdout, url)
        # discovered param URLs in one -m batch (no crawl needed)
        if ctx.ts.param_urls:
            mfile = ctx.artifact("sqli-targets.txt")
            with open(mfile, "w", encoding="utf-8") as fh:
                fh.write("\n".join(ctx.ts.param_urls))
            argv = [sqlmap, "-m", mfile, "--batch", "--random-agent", "--smart",
                    "--level", str(cfg.sqlmap_level), "--risk", str(cfg.sqlmap_risk),
                    "--threads", "4", "--output-dir", ctx.artifact("sqlmap-params"),
                    "-v", "1"] + cfg.sqlmap_extra
            res = ctx.run(argv, stage="sqli", log_name="sqlmap-params.log")
            hits += _record_sqlmap(ctx, res.stdout, "param-urls")
    elif not cfg.sqlerr_quickpass:
        ctx.ts.stage("sqli").note = "sqlmap not found; skipped"
        return
    ctx.ts.stage("sqli").note = f"{hits} sqli finding(s)"


def _record_sqlmap(ctx: StageCtx, stdout: str, url: str) -> int:
    info = parse.parse_sqlmap_stdout(stdout)
    if not info["vulnerable"]:
        return 0
    ctx.finding(stage="sqli", category="sqli",
                title="SQL injection confirmed by sqlmap",
                severity="critical", confidence="confirmed",
                evidence={"url": info.get("target_url") or url,
                          "parameters": info["parameters"],
                          "types": info["types"], "dbms": info["dbms"]})
    return 1


def stage_xss(ctx: StageCtx) -> None:
    cfg = ctx.cfg
    if not cfg.xss_enabled:
        ctx.ts.stage("xss").note = "disabled"
        return
    ensure_crawl(ctx)
    hits = 0
    # preferred engine: dalfox on discovered param URLs
    dalfox = _bin(cfg, "dalfox")
    if dalfox and ctx.ts.param_urls:
        mfile = ctx.artifact("xss-targets.txt")
        with open(mfile, "w", encoding="utf-8") as fh:
            fh.write("\n".join(ctx.ts.param_urls))
        out_json = ctx.artifact("dalfox.json")
        argv = [dalfox, "file", mfile, "--format", "json", "-o", out_json,
                "--silence", "--no-spinner"]
        res = ctx.run(argv, stage="xss", log_name="dalfox.log")
        hits += _record_dalfox(ctx, out_json, res.stdout)
    # built-in reflected-XSS probe (always runs as breadth/backstop)
    if cfg.xss_builtin:
        try:
            for r in webscan.probe_xss(ctx.ts.param_urls, ctx.ts.forms, cfg):
                if r["severity"] != "high":
                    continue          # skip encoded-only reflections (noise)
                hits += 1
                ctx.finding(stage="xss", category="xss",
                            title=f"Reflected XSS ({r['context']}) in {r['param']}",
                            severity="high", confidence="high",
                            evidence={"url": r["url"], "method": r["method"],
                                      "parameter": r["param"], "context": r["context"],
                                      "payload": r.get("payload", "")})
        except Exception as e:
            ctx.logger(f"[{ctx.ts.host}] xss probe error: {e}")
    ctx.ts.stage("xss").note = f"{hits} xss finding(s)"


def _record_dalfox(ctx: StageCtx, out_json: str, stdout: str) -> int:
    count = 0
    entries = []
    try:
        with open(out_json, "r", encoding="utf-8", errors="replace") as fh:
            txt = fh.read().strip()
        if txt.startswith("["):
            entries = json.loads(txt)
        else:
            for line in txt.splitlines():
                line = line.strip()
                if line.startswith("{"):
                    entries.append(json.loads(line))
    except (FileNotFoundError, json.JSONDecodeError):
        entries = []
    for e in entries:
        if not isinstance(e, dict):
            continue
        etype = (e.get("type") or "").upper()
        if etype in ("G", "R", "V", "VERIFY", "GREP", "REFLECTED", "POC"):
            count += 1
            ctx.finding(stage="xss", category="xss",
                        title=f"XSS confirmed by dalfox ({e.get('param', '')})",
                        severity="high", confidence="confirmed",
                        evidence={"poc": e.get("data") or e.get("poc") or "",
                                  "param": e.get("param", ""),
                                  "method": e.get("method", ""),
                                  "cwe": e.get("cwe", "")})
    return count


def stage_cred(ctx: StageCtx, candidate_only: bool = False) -> None:
    cfg = ctx.cfg
    targets = []
    for s in ctx.ts.services:
        mod = HYDRA_MODULES.get(s.name.lower())
        if mod and mod not in ("http-get",):   # skip http-form auto (needs form spec)
            targets.append((s, mod))
    if candidate_only:
        if targets:
            ctx.finding(stage="cred", category="candidate",
                        title="Weak-password test candidates (not executed)",
                        severity="info", confidence="low",
                        evidence={"services": [f"{s.name}:{s.port}->{m}" for s, m in targets]})
        ctx.ts.stage("cred").note = "candidate list only"
        return
    hydra = _bin(cfg, "hydra")
    if not hydra:
        ctx.ts.stage("cred").note = "hydra not found; skipped"
        return
    creds_found = 0
    for idx, (svc, mod) in enumerate(targets):
        if ctx.aborted():
            return
        ctx.scope.check(ctx.ts.host)
        out = ctx.artifact(f"hydra-{mod}-{svc.port}.txt")
        argv = [hydra, "-I", "-t", str(cfg.hydra_tasks), "-o", out]
        if cfg.hydra_stop_on_first:
            argv += ["-f"]
        if os.path.exists(cfg.default_creds):
            argv += ["-C", cfg.default_creds]
        else:
            argv += ["-L", cfg.userlist, "-P", cfg.passlist]
        argv += ["-s", str(svc.port), ctx.ts.host, mod]
        ctx.run(argv, stage="cred", log_name=f"hydra-{mod}-{svc.port}.log")
        ctx.record_artifact("cred", out)
        for c in parse.parse_hydra_output(out):
            creds_found += 1
            sev = "critical" if mod in ("ssh", "rdp", "mysql", "postgres", "vnc", "smb") else "high"
            ctx.finding(stage="cred", category="weak-cred",
                        title=f"Weak/default credential on {mod} ({svc.port})",
                        severity=sev, confidence="confirmed",
                        evidence={"service": mod, "port": svc.port,
                                  "login": c.get("login"), "password": c.get("password")})
    ctx.ts.stage("cred").note = f"{creds_found} credential(s) found"


def stage_wp(ctx: StageCtx) -> None:
    cfg = ctx.cfg
    if not ctx.ts.is_wordpress:
        ctx.ts.stage("wp").note = "not WordPress; skipped"
        return
    script = os.path.join(cfg.wp2shell_dir, "wp2shell.py")
    if os.path.exists(script):
        base_cmd = [cfg.wp2shell_python, script]
    elif shutil.which("wp2shell"):
        base_cmd = [shutil.which("wp2shell")]
    else:
        ctx.ts.stage("wp").note = "wp2shell not installed (run: recon.py setup)"
        return
    ctx.scope.check(ctx.ts.host)
    target = _wp_target(ctx.ts)
    url = ctx.ts.base_url or f"{ctx.ts.scheme}://{target}/"
    argv = base_cmd + [a.format(target=target, url=url) for a in cfg.wp2shell_argtmpl]
    res = ctx.run(argv, stage="wp", log_name="wp2shell.log")
    verdict = _parse_wp2shell(res.stdout)
    if verdict["vulnerable"]:
        ctx.finding(stage="wp", category="wordpress",
                    title="WordPress exploitable via wp2shell (SQLi/RCE path)",
                    severity="critical", confidence="high",
                    evidence={"target": target, "signals": verdict["signals"],
                              "output_tail": res.stdout[-800:]})
    else:
        ctx.finding(stage="wp", category="wordpress",
                    title="WordPress detected; wp2shell found no confirmed exploit",
                    severity="info", confidence="medium",
                    evidence={"target": target, "output_tail": res.stdout[-500:]})
    ctx.ts.stage("wp").note = "exploitable" if verdict["vulnerable"] else "no confirmed exploit"


def _wp_target(ts) -> str:
    from urllib.parse import urlparse
    if ts.base_url:
        return urlparse(ts.base_url).netloc
    if ts.port_hint and ts.port_hint not in (80, 443):
        return f"{ts.host}:{ts.port_hint}"
    return ts.host


def _parse_wp2shell(stdout: str) -> dict:
    """wp2shell --json emits NDJSON; flag confirmed exploitation heuristically."""
    signals: list[str] = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            for k in ("vulnerable", "exploitable", "sqli", "shell", "rce"):
                if obj.get(k) in (True, "true", "yes"):
                    signals.append(f"{k}={obj.get(k)}")
            status = str(obj.get("status") or obj.get("result") or "").lower()
            if status in ("vulnerable", "exploitable", "success", "pwned"):
                signals.append(f"status={status}")
    low = stdout.lower()
    for kw in ("sqli confirmed", "shell uploaded", "admin created", "rce achieved",
               "exploitable"):
        if kw in low:
            signals.append(kw)
    return {"vulnerable": bool(signals), "signals": sorted(set(signals))}


# ===================================================================== #
def _is_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _resolves(host: str) -> bool:
    try:
        socket.getaddrinfo(host, None)
        return True
    except socket.gaierror:
        return False
