"""Data models shared across the pipeline. All are JSON-serializable via to_dict()."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from typing import Any


SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
CONFIDENCE_ORDER = ["low", "medium", "high", "confirmed"]


def severity_rank(sev: str) -> int:
    try:
        return SEVERITY_ORDER.index(sev)
    except ValueError:
        return 0


def make_id(*parts: str) -> str:
    h = hashlib.sha1("|".join(p for p in parts if p).encode("utf-8", "replace")).hexdigest()
    return h[:12]


@dataclass
class Service:
    port: int
    proto: str = "tcp"
    state: str = "open"
    name: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""            # "ssl" when the port speaks TLS
    cpe: list[str] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)   # nse id -> output

    @property
    def is_http(self) -> bool:
        n = self.name.lower()
        if n in ("http", "https", "http-proxy", "http-alt", "https-alt"):
            return True
        if "http" in n:
            return True
        return self.port in (80, 443, 8000, 8008, 8080, 8443, 8888, 9090, 3000, 5000)

    @property
    def scheme(self) -> str:
        if self.tunnel == "ssl" or "https" in self.name.lower() or self.port in (443, 8443):
            return "https"
        return "http"

    def banner(self) -> str:
        return " ".join(x for x in (self.product, self.version, self.extrainfo) if x).strip()

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scheme"] = self.scheme
        d["is_http"] = self.is_http
        d["banner"] = self.banner()
        return d


@dataclass
class WebPath:
    url: str
    status: int
    length: int = 0
    redirect: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    target: str
    stage: str
    category: str
    title: str
    severity: str = "info"
    confidence: str = "medium"
    evidence: dict[str, Any] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)
    dedup_key: str = ""
    id: str = ""
    reviewed: bool = False
    false_positive: bool = False

    def __post_init__(self) -> None:
        if not self.dedup_key:
            self.dedup_key = f"{self.target}:{self.category}:{self.title}"
        if not self.id:
            self.id = make_id(self.dedup_key)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity_rank"] = severity_rank(self.severity)
        return d


@dataclass
class StageState:
    name: str
    status: str = "pending"     # pending|running|done|skipped|error
    started: float | None = None
    ended: float | None = None
    error: str = ""
    note: str = ""
    artifacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        if self.started and self.ended:
            d["duration"] = round(self.ended - self.started, 1)
        else:
            d["duration"] = None
        return d


@dataclass
class TargetState:
    raw: str                    # original line from targets file
    host: str                   # resolved host / ip
    scheme: str = "http"
    port_hint: int | None = None
    base_url: str = ""          # for URL targets, the full url
    status: str = "pending"     # pending|running|done|error
    error: str = ""
    stages: dict[str, StageState] = field(default_factory=dict)
    services: list[Service] = field(default_factory=list)
    webpaths: list[WebPath] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    is_wordpress: bool = False
    param_urls: list[str] = field(default_factory=list)   # URLs carrying ?params
    forms: list[dict] = field(default_factory=list)        # {action,method,inputs[]}
    crawled: bool = False

    def stage(self, name: str) -> StageState:
        st = self.stages.get(name)
        if st is None:
            st = StageState(name=name)
            self.stages[name] = st
        return st

    def http_services(self) -> list[Service]:
        return [s for s in self.services if s.is_http and s.state == "open"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "raw": self.raw,
            "host": self.host,
            "scheme": self.scheme,
            "port_hint": self.port_hint,
            "base_url": self.base_url,
            "status": self.status,
            "error": self.error,
            "is_wordpress": self.is_wordpress,
            "param_urls": self.param_urls,
            "forms": self.forms,
            "stages": {k: v.to_dict() for k, v in self.stages.items()},
            "services": [s.to_dict() for s in self.services],
            "webpaths": [w.to_dict() for w in self.webpaths],
            "findings": [f.to_dict() for f in self.findings],
            "counts": self.finding_counts(),
        }

    def finding_counts(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITY_ORDER}
        for f in self.findings:
            if f.false_positive:
                continue
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts
