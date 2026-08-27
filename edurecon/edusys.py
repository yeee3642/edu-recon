"""Education-sector system probes (non-destructive).

Currently: Moodle — the LMS that dominates the .edu attack surface. Fingerprint
the app, read its version, and flag the two things that actually hurt: an
unsupported branch (known CVEs apply) and a web-exposed moodledata directory
(sessions / uploaded files / sometimes config). All benign GETs; no state change.
"""
from __future__ import annotations

import re

from . import webhttp

_VER_RE = re.compile(r"===+\s*([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.M)
_GEN_RE = re.compile(r"Moodle\s+([0-9]+\.[0-9]+(?:\.[0-9]+)?)")


def _get(url, cfg, max_bytes=8192):
    return webhttp.get(url, cfg.http_timeout, cfg.user_agent, max_bytes=max_bytes)


def _ver_tuple(v: str) -> tuple[int, ...]:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return ()


def probe_moodle(base: str, cfg) -> list[dict]:
    root = base.rstrip("/")
    detected = False
    version = ""
    markers: list[str] = []

    # 1) login page + landing page fingerprint (MoodleSession cookie is decisive)
    for path in ("/login/index.php", "/"):
        st, hdrs, body = _get(root + path, cfg)
        cookie = (hdrs.get("Set-Cookie") or hdrs.get("set-cookie") or "")
        low = body.lower()
        if "moodlesession" in cookie.lower():
            detected = True
            markers.append("MoodleSession cookie")
        if "content=\"moodle" in low or "powered by moodle" in low or \
                ("moodle" in low and "login" in low and "/theme/" in low):
            detected = True
            markers.append(f"moodle markers @ {path or '/'}")
        gm = _GEN_RE.search(body)
        if gm and not version:
            version = gm.group(1)

    # 2) version via public /lib/upgrade.txt
    st, _h, body = _get(root + "/lib/upgrade.txt", cfg, max_bytes=4096)
    if st == 200 and ("Moodle" in body or "===" in body):
        detected = True
        markers.append("/lib/upgrade.txt readable")
        vm = _VER_RE.search(body)
        if vm:
            version = vm.group(1)

    if not detected:
        return []

    hits: list[dict] = [{
        "category": "edtech", "severity": "info", "confidence": "high",
        "title": "Moodle LMS detected" + (f" (v{version})" if version else ""),
        "url": root + "/",
        "evidence": {"system": "moodle", "version": version or "unknown",
                     "markers": sorted(set(markers))},
    }]

    # 3) unsupported branch -> known CVEs apply
    floor = _ver_tuple(getattr(cfg, "moodle_min_supported", "4.1"))
    vt = _ver_tuple(version)
    if vt and floor and vt < floor:
        hits.append({
            "category": "vuln-version", "severity": "medium", "confidence": "medium",
            "title": f"Outdated Moodle branch v{version} (< {cfg.moodle_min_supported}) — known CVEs apply",
            "url": root + "/",
            "evidence": {"system": "moodle", "version": version,
                         "min_supported": cfg.moodle_min_supported,
                         "note": "cross-check moodle.org/security for this branch"},
        })

    # 4) web-exposed moodledata (sessions / files / config) = critical
    for p in ("/moodledata/", "/moodledata/sessions/", "/moodledata/muc/",
              "/../moodledata/"):
        st, _h, body = _get(root + p, cfg, max_bytes=4096)
        low = body.lower()
        if st == 200 and ("index of /" in low or "sess_" in low or
                          "directory listing" in low):
            hits.append({
                "category": "secret-leak", "severity": "critical", "confidence": "high",
                "title": "Moodle data directory (moodledata) exposed over HTTP",
                "url": root + p,
                "evidence": {"system": "moodle", "path": p,
                             "snippet": body[:200].strip()},
            })
            break

    return hits
