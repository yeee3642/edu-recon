"""Target parsing + scope enforcement.

Scope lock: the pipeline will ONLY act against hosts covered by the target file
(plus any extra_allowed_cidrs in config). Every stage calls ScopeGuard.check()
before touching a host, so an expanded CIDR or a redirect can never drag a scan
onto an out-of-scope address.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

_CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
_HOSTPORT_RE = re.compile(r"^([A-Za-z0-9_.\-]+):(\d{1,5})$")


class ScopeError(Exception):
    pass


@dataclass
class ParsedTarget:
    raw: str
    kind: str                 # "url" | "host" | "cidr"
    host: str = ""
    scheme: str = "http"
    port: int | None = None
    path: str = "/"
    cidr: str = ""

    @property
    def base_url(self) -> str:
        if self.kind != "url":
            return ""
        netloc = self.host
        if self.port and not ((self.scheme == "http" and self.port == 80) or
                              (self.scheme == "https" and self.port == 443)):
            netloc = f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}{self.path}"


def parse_target(line: str) -> ParsedTarget:
    raw = line.strip()
    if not raw:
        raise ScopeError("empty target")

    if "://" in raw:
        u = urlparse(raw)
        scheme = u.scheme.lower() if u.scheme in ("http", "https") else "http"
        host = u.hostname or ""
        port = u.port
        path = u.path or "/"
        if u.query:                       # keep ?params so sqli/xss can test them
            path += "?" + u.query
        if not host:
            raise ScopeError(f"cannot parse URL host: {raw}")
        return ParsedTarget(raw=raw, kind="url", host=host, scheme=scheme,
                            port=port, path=path)

    if _CIDR_RE.match(raw):
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError as e:
            raise ScopeError(f"bad CIDR {raw}: {e}") from e
        return ParsedTarget(raw=raw, kind="cidr", cidr=str(net), host=str(net))

    m = _HOSTPORT_RE.match(raw)
    if m:
        host, port = m.group(1), int(m.group(2))
        scheme = "https" if port in (443, 8443) else "http"
        return ParsedTarget(raw=raw, kind="host", host=host, port=port, scheme=scheme)

    # bare host or IP
    return ParsedTarget(raw=raw, kind="host", host=raw)


def load_targets(path: str) -> list[ParsedTarget]:
    out: list[ParsedTarget] = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            s = line.split("#", 1)[0].strip()
            if not s:
                continue
            out.append(parse_target(s))
    return out


class ScopeGuard:
    """Allowlist of hosts / networks the engagement authorizes.

    When allow_subdomains is on (default), listing a domain authorizes every
    subdomain of it too, so enumerated/discovered subdomains stay in scope.
    """

    def __init__(self, extra_cidrs: list[str] | None = None,
                 allow_subdomains: bool = True) -> None:
        self.networks: list[ipaddress._BaseNetwork] = []
        self.hostnames: set[str] = set()      # exact hostnames
        self.domains: set[str] = set()         # apex/parent domains for *.suffix match
        self.allow_subdomains = allow_subdomains
        for c in (extra_cidrs or []):
            try:
                self.networks.append(ipaddress.ip_network(c, strict=False))
            except ValueError:
                pass

    def add(self, pt: ParsedTarget) -> None:
        if pt.kind == "cidr":
            self.networks.append(ipaddress.ip_network(pt.cidr, strict=False))
            return
        self.add_host(pt.host)

    def add_host(self, host: str) -> None:
        ip = _as_ip(host)
        if ip is not None:
            self.networks.append(ipaddress.ip_network(f"{ip}/32", strict=False))
        else:
            h = host.lower().rstrip(".")
            self.hostnames.add(h)
            if self.allow_subdomains:
                self.domains.add(h)

    def is_allowed(self, host: str) -> bool:
        ip = _as_ip(host)
        if ip is not None:
            return any(ip in net for net in self.networks)
        h = host.lower().rstrip(".")
        if h in self.hostnames:
            return True
        return any(h == d or h.endswith("." + d) for d in self.domains)

    def check(self, host: str) -> None:
        if not self.is_allowed(host):
            raise ScopeError(
                f"OUT OF SCOPE: {host!r} is not in the target file / allowed CIDRs. "
                f"Refusing to scan.")


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None
