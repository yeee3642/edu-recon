"""Built-in light crawler + reflected-XSS probe + SQL-error heuristic.

These give "various SQLi & XSS" coverage even without sqlmap/dalfox, and produce
the param-URL / form inventory that sqlmap and dalfox then attack in depth.
All probes are read-only GET/POST reflections — no data is modified.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urldefrag

from .config import Config
from . import webhttp

_HREF_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#>]+)""", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)""", re.I)
_METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']*)""", re.I)
_INPUT_RE = re.compile(r"""<(?:input|textarea|select)\b[^>]*\bname\s*=\s*["']([^"']+)""", re.I)

# SQL error fingerprints (DB-agnostic)
SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "supplied argument is not a valid mysql", "unclosed quotation mark after the character string",
    "quoted string not properly terminated", "microsoft ole db provider for sql server",
    "odbc sql server driver", "sqlstate", "pg_query()", "postgresql query failed",
    "syntax error at or near", "sqlite3::", "sqlite error", "ora-01756", "ora-00933",
    "ora-00921", "you have an error in your", "native client",
]


def crawl(bases: list[str], cfg: Config) -> tuple[list[str], list[dict]]:
    """BFS the same host to depth ~1-2, collecting param URLs and forms."""
    seen: set[str] = set()
    param_urls: dict[str, str] = {}      # normalized-key -> url
    forms: list[dict] = []
    queue = list(bases)
    host_of = {urlparse(b).netloc for b in bases}
    pages = 0
    while queue and pages < cfg.crawl_max_pages:
        url = queue.pop(0)
        url, _ = urldefrag(url)
        if url in seen:
            continue
        seen.add(url)
        if urlparse(url).netloc not in host_of:
            continue
        st, hdrs, body = webhttp.get(url, cfg.http_timeout, cfg.user_agent, max_bytes=200_000)
        if st == 0 or "html" not in (hdrs.get("Content-Type", "") + hdrs.get("content-type", "")).lower():
            continue
        pages += 1
        # param urls from links
        for m in _HREF_RE.finditer(body):
            link = urljoin(url, m.group(1).strip())
            if urlparse(link).netloc not in host_of:
                continue
            if urlparse(link).query:
                key = _param_key(link)
                param_urls.setdefault(key, link)
            if link not in seen and len(seen) + len(queue) < cfg.crawl_max_pages * 3:
                queue.append(link)
        # forms
        for fm in _FORM_RE.finditer(body):
            block = fm.group(0)
            am = _ACTION_RE.search(block)
            action = urljoin(url, am.group(1)) if am and am.group(1) else url
            if urlparse(action).netloc not in host_of:
                continue
            method = (_METHOD_RE.search(block).group(1).upper()
                      if _METHOD_RE.search(block) else "GET")
            inputs = list(dict.fromkeys(_INPUT_RE.findall(block)))
            if inputs:
                forms.append({"action": action, "method": method, "inputs": inputs})
        # also treat the base itself if it had params
        if urlparse(url).query:
            param_urls.setdefault(_param_key(url), url)
    return list(param_urls.values()), _dedupe_forms(forms)


def _param_key(url: str) -> str:
    u = urlparse(url)
    names = sorted(k for k, _ in parse_qsl(u.query))
    return f"{u.scheme}://{u.netloc}{u.path}?{','.join(names)}"


def _dedupe_forms(forms: list[dict]) -> list[dict]:
    out, seen = [], set()
    for f in forms:
        key = (f["action"], f["method"], tuple(f["inputs"]))
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


# --------------------------------------------------------------------------- #
# reflected XSS
# --------------------------------------------------------------------------- #
def probe_xss(param_urls: list[str], forms: list[dict], cfg: Config) -> list[dict]:
    findings: list[dict] = []
    budget = cfg.crawl_max_targets
    for url in param_urls[:budget]:
        findings.extend(_xss_on_url(url, cfg))
    for form in forms[: max(0, budget - len(param_urls))]:
        findings.extend(_xss_on_form(form, cfg))
    return findings


def _xss_marker():
    n = uuid.uuid4().hex[:6]
    marker = f"edurx{n}"
    payload = f'{marker}"\'><svg/onload=1>'
    return marker, payload


def _classify(marker: str, payload: str, body: str) -> str | None:
    if f'{marker}"\'><svg/onload=1>' in body or f"{marker}'\"><svg" in body:
        return "html-tag-injection"        # raw < > reflected -> executable
    if f"{marker}" in body and ("<svg" in body.split(marker, 1)[-1][:40].lower()):
        return "html-tag-injection"
    if marker in body:
        after = body.split(marker, 1)[-1][:40]
        if "&lt;" in after or "&gt;" in after:
            return "reflected-encoded"     # reflected but encoded (low)
        return "reflected-encoded"
    return None


def _xss_on_url(url: str, cfg: Config) -> list[dict]:
    u = urlparse(url)
    params = parse_qsl(u.query, keep_blank_values=True)
    out = []
    for i, (name, _) in enumerate(params):
        marker, payload = _xss_marker()
        newq = params.copy()
        newq[i] = (name, payload)
        test = f"{u.scheme}://{u.netloc}{u.path}?{urlencode(newq)}"
        st, _, body = webhttp.get(test, cfg.http_timeout, cfg.user_agent, max_bytes=200_000)
        ctx = _classify(marker, payload, body)
        if ctx:
            out.append({"url": test, "method": "GET", "param": name, "context": ctx,
                        "severity": "high" if ctx == "html-tag-injection" else "low"})
    return out


def _xss_on_form(form: dict, cfg: Config) -> list[dict]:
    out = []
    for name in form["inputs"]:
        marker, payload = _xss_marker()
        data = {inp: (payload if inp == name else "1") for inp in form["inputs"]}
        if form["method"] == "POST":
            st, _, body = webhttp.request(form["action"], method="POST", data=data,
                                          timeout=cfg.http_timeout, ua=cfg.user_agent,
                                          max_bytes=200_000)
            test = form["action"]
        else:
            test = f"{form['action']}?{urlencode(data)}"
            st, _, body = webhttp.get(test, cfg.http_timeout, cfg.user_agent, max_bytes=200_000)
        ctx = _classify(marker, payload, body)
        if ctx:
            out.append({"url": test, "method": form["method"], "param": name,
                        "context": ctx,
                        "severity": "high" if ctx == "html-tag-injection" else "low"})
    return out


# --------------------------------------------------------------------------- #
# SQL error-based heuristic
# --------------------------------------------------------------------------- #
def probe_sql_errors(param_urls: list[str], forms: list[dict], cfg: Config) -> list[dict]:
    findings: list[dict] = []
    budget = cfg.crawl_max_targets
    for url in param_urls[:budget]:
        findings.extend(_sqlerr_on_url(url, cfg))
    for form in forms[: max(0, budget - len(param_urls))]:
        findings.extend(_sqlerr_on_form(form, cfg))
    return findings


def _new_errors(baseline: str, injected: str) -> list[str]:
    bl, inj = baseline.lower(), injected.lower()
    return [sig for sig in SQL_ERRORS if sig in inj and sig not in bl]


def _sqlerr_on_url(url: str, cfg: Config) -> list[dict]:
    u = urlparse(url)
    params = parse_qsl(u.query, keep_blank_values=True)
    out = []
    for i, (name, val) in enumerate(params):
        _, _, baseline = webhttp.get(url, cfg.http_timeout, cfg.user_agent, max_bytes=200_000)
        newq = params.copy()
        newq[i] = (name, (val or "1") + "'\"")
        test = f"{u.scheme}://{u.netloc}{u.path}?{urlencode(newq)}"
        _, _, injected = webhttp.get(test, cfg.http_timeout, cfg.user_agent, max_bytes=200_000)
        errs = _new_errors(baseline, injected)
        if errs:
            out.append({"url": test, "method": "GET", "param": name,
                        "errors": errs[:3], "severity": "high"})
    return out


def _sqlerr_on_form(form: dict, cfg: Config) -> list[dict]:
    out = []
    for name in form["inputs"]:
        base_data = {inp: "1" for inp in form["inputs"]}
        inj_data = dict(base_data, **{name: "1'\""})
        if form["method"] == "POST":
            _, _, baseline = webhttp.request(form["action"], method="POST", data=base_data,
                                             timeout=cfg.http_timeout, ua=cfg.user_agent,
                                             max_bytes=200_000)
            _, _, injected = webhttp.request(form["action"], method="POST", data=inj_data,
                                             timeout=cfg.http_timeout, ua=cfg.user_agent,
                                             max_bytes=200_000)
            test = form["action"]
        else:
            _, _, baseline = webhttp.get(f"{form['action']}?{urlencode(base_data)}",
                                         cfg.http_timeout, cfg.user_agent, max_bytes=200_000)
            test = f"{form['action']}?{urlencode(inj_data)}"
            _, _, injected = webhttp.get(test, cfg.http_timeout, cfg.user_agent, max_bytes=200_000)
        errs = _new_errors(baseline, injected)
        if errs:
            out.append({"url": test, "method": form["method"], "param": name,
                        "errors": errs[:3], "severity": "high"})
    return out
