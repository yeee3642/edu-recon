"""Triage: turn raw stage output into a ranked, de-duplicated, low-noise review queue.

- infers findings from nmap services (dangerous ports, per-port VULNERABLE scripts)
- classifies dirsearch paths (admin panels, sensitive files) AFTER soft-404 filtering
- dedupes across all stages and ranks by severity then confidence
"""
from __future__ import annotations

from collections import Counter

from .config import Config
from .models import Finding, TargetState, severity_rank, CONFIDENCE_ORDER
from .stages import DANGEROUS_PORTS

SEVERITY_WEIGHT = {"critical": 100, "high": 40, "medium": 12, "low": 3, "info": 0}

# dirsearch path classification: substring -> (category, severity, title)
PATH_RULES = [
    ("/.git", "vcs-leak", "high", "VCS metadata exposed"),
    ("/.svn", "vcs-leak", "medium", "VCS metadata exposed"),
    ("/.env", "secret-leak", "high", "Environment file exposed"),
    ("phpmyadmin", "admin-panel", "medium", "phpMyAdmin exposed"),
    ("adminer", "admin-panel", "medium", "Adminer exposed"),
    ("/wp-admin", "admin-panel", "medium", "WordPress admin exposed"),
    ("/manager/html", "admin-panel", "high", "Tomcat manager exposed"),
    ("/admin", "admin-panel", "medium", "Admin panel exposed"),
    ("/login", "admin-panel", "low", "Login page discovered"),
    ("/.htaccess", "info-leak", "medium", "Apache .htaccess exposed"),
    ("/web.config", "info-leak", "medium", "IIS web.config exposed"),
]
SENSITIVE_SUFFIX = (".sql", ".bak", ".old", ".swp", ".zip", ".tar.gz", ".tgz",
                    ".7z", ".rar", ".conf", ".config", ".pem", ".key", ".log")


def triage_target(ts: TargetState, cfg: Config) -> None:
    _from_services(ts, cfg)
    _from_webpaths(ts)
    _dedupe_and_rank(ts)


def _from_services(ts: TargetState, cfg: Config) -> None:
    existing = {(f.category, f.evidence.get("port")) for f in ts.findings}
    for s in ts.services:
        if s.port in DANGEROUS_PORTS and ("dangerous-port", s.port) not in existing:
            svc, sev, title = DANGEROUS_PORTS[s.port]
            ts.findings.append(Finding(
                target=ts.host, stage="triage", category="dangerous-port",
                title=title, severity=sev, confidence="medium",
                evidence={"port": s.port, "service": s.name, "banner": s.banner()}))
        # per-port NSE vuln output -> finding only if opted in (default off); nmap's
        # version-inferred hits have no SAFE-CHECK oracle, so they are not counted.
        if cfg.nmap_vuln_findings:
            for sid, out in s.scripts.items():
                if "VULNERABLE" in out or "CVE-" in out:
                    ts.findings.append(Finding(
                        target=ts.host, stage="triage", category="nmap-vuln",
                        title=f"nmap {sid} flagged VULNERABLE on {s.port}",
                        severity="high", confidence="medium",
                        evidence={"port": s.port, "script": sid, "output": out[:800]}))
        # anonymous FTP
        if s.name.lower() == "ftp":
            anon = s.scripts.get("ftp-anon", "")
            if "Anonymous FTP login allowed" in anon:
                ts.findings.append(Finding(
                    target=ts.host, stage="triage", category="weak-cred",
                    title=f"Anonymous FTP login allowed ({s.port})",
                    severity="high", confidence="confirmed",
                    evidence={"port": s.port, "detail": anon[:300]}))


def _from_webpaths(ts: TargetState) -> None:
    paths = [w for w in ts.webpaths if w.status]
    if not paths:
        return
    noise_sig = _soft404_signature(paths)
    known_urls = {str(f.evidence.get("url", "")).rstrip("/") for f in ts.findings}
    for w in paths:
        if (w.status, w.length) == noise_sig:
            continue
        if w.status in (200, 301, 302, 401, 403):
            low = w.url.lower()
            if w.url.rstrip("/") in known_urls:
                continue          # already reported by exposures stage
            matched = False
            for sub, cat, sev, title in PATH_RULES:
                if sub in low:
                    ts.findings.append(Finding(
                        target=ts.host, stage="webdisco", category=cat, title=title,
                        severity=sev if w.status in (200, 401, 403) else "low",
                        confidence="medium",
                        evidence={"url": w.url, "status": w.status}))
                    matched = True
                    break
            if not matched and w.status == 200 and low.endswith(SENSITIVE_SUFFIX):
                ts.findings.append(Finding(
                    target=ts.host, stage="webdisco", category="info-leak",
                    title="Potentially sensitive file exposed",
                    severity="medium", confidence="low",
                    evidence={"url": w.url, "status": w.status}))
        elif w.status >= 500:
            ts.findings.append(Finding(
                target=ts.host, stage="webdisco", category="server-error",
                title="Server error page (possible injection surface)",
                severity="low", confidence="low",
                evidence={"url": w.url, "status": w.status}))


def _soft404_signature(paths) -> tuple[int, int] | None:
    """A (status,length) pair shared by a dominant fraction of paths is a wildcard."""
    if len(paths) < 6:
        return None
    counter = Counter((w.status, w.length) for w in paths if w.status in (200, 403))
    if not counter:
        return None
    (sig, count), = counter.most_common(1)
    if count >= 5 and count >= 0.4 * len(paths):
        return sig
    return None


def _dedupe_and_rank(ts: TargetState) -> None:
    merged: dict[str, Finding] = {}
    for f in ts.findings:
        cur = merged.get(f.dedup_key)
        if cur is None:
            merged[f.dedup_key] = f
            continue
        if _stronger(f, cur):
            for a in cur.artifacts:
                if a not in f.artifacts:
                    f.artifacts.append(a)
            merged[f.dedup_key] = f
        else:
            for a in f.artifacts:
                if a not in cur.artifacts:
                    cur.artifacts.append(a)
    ranked = sorted(
        merged.values(),
        key=lambda f: (severity_rank(f.severity),
                       CONFIDENCE_ORDER.index(f.confidence)
                       if f.confidence in CONFIDENCE_ORDER else 0),
        reverse=True)
    ts.findings = ranked


def _stronger(a: Finding, b: Finding) -> bool:
    if severity_rank(a.severity) != severity_rank(b.severity):
        return severity_rank(a.severity) > severity_rank(b.severity)
    ca = CONFIDENCE_ORDER.index(a.confidence) if a.confidence in CONFIDENCE_ORDER else 0
    cb = CONFIDENCE_ORDER.index(b.confidence) if b.confidence in CONFIDENCE_ORDER else 0
    return ca > cb


def target_score(ts: TargetState) -> int:
    return sum(SEVERITY_WEIGHT.get(f.severity, 0)
               for f in ts.findings if not f.false_positive)
