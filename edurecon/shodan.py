"""Shodan passive enrichment client.

Resolve a target hostname to an IP and pull host intel (open ports, service
banners, product/version, known CVEs, org/ASN) from Shodan's REST API. This is
READ-ONLY against Shodan's database — it never sends a packet to the target
itself. Needs a Shodan API key (Config.shodan_api_key or the SHODAN_API_KEY env
var); without one the stage skips cleanly. The key is never logged.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

API_BASE = "https://api.shodan.io"
_CTX = ssl.create_default_context()


def _get(path: str, params: dict, timeout: int):
    """GET a Shodan endpoint -> (status:int, json_or_None, err:str). Never raises."""
    url = API_BASE + path + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers={"User-Agent": "edu-recon-shodan"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=_CTX)
        raw = resp.read(4_000_000)
        try:
            return getattr(resp, "status", 200), json.loads(raw.decode("utf-8", "replace")), ""
        except json.JSONDecodeError:
            return getattr(resp, "status", 200), None, "non-JSON response"
    except urllib.error.HTTPError as e:                    # 401 bad key / 403 no plan / 404 / 429
        body, msg = "", ""
        try:
            body = e.read(4000).decode("utf-8", "replace")
            msg = (json.loads(body) or {}).get("error", "")
        except Exception:
            msg = body[:200]
        return e.code, None, msg or f"HTTP {e.code}"
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        return 0, None, f"{type(e).__name__}: {e}"
    except Exception as e:                                  # never let recon die on the client
        return 0, None, f"{type(e).__name__}: {e}"


def api_info(key: str, timeout: int = 15):
    """Validate the key and read plan / remaining credits. -> (dict|None, err)."""
    st, j, err = _get("/api-info", {"key": key}, timeout)
    if st == 200 and isinstance(j, dict):
        return j, ""
    return None, err or f"HTTP {st}"


def resolve(hostname: str, key: str, timeout: int = 15) -> str | None:
    """Resolve a hostname to an IP via Shodan DNS (free, no query credit)."""
    st, j, _err = _get("/dns/resolve", {"hostnames": hostname, "key": key}, timeout)
    if st == 200 and isinstance(j, dict):
        return j.get(hostname)
    return None


def host_lookup(ip: str, key: str, timeout: int = 25, minify: bool = False):
    """Pull Shodan host intel for an IP. -> (dict|None, err). Costs 1 query credit."""
    st, j, err = _get(f"/shodan/host/{ip}",
                      {"key": key, "minify": "true" if minify else "false"}, timeout)
    if st == 200 and isinstance(j, dict):
        return j, ""
    if st == 404:
        return None, "no Shodan data for this host"
    return None, err or f"HTTP {st}"


def summarize(host: dict) -> dict:
    """Reduce a raw Shodan host document to the fields the pipeline consumes."""
    services = []
    for item in host.get("data", []) or []:
        if not isinstance(item, dict):
            continue
        sh = item.get("_shodan", {}) or {}
        raw_vulns = item.get("vulns")
        svc_vulns = sorted(raw_vulns.keys()) if isinstance(raw_vulns, dict) else list(raw_vulns or [])
        services.append({
            "port": item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product": item.get("product", "") or sh.get("module", ""),
            "version": item.get("version", ""),
            "module": sh.get("module", ""),
            "cpe": item.get("cpe23") or item.get("cpe") or [],
            "ssl": bool(item.get("ssl")),
            "vulns": svc_vulns,
            "banner": (item.get("data") or "")[:400],
        })
    top_vulns = host.get("vulns")
    top_vulns = sorted(top_vulns.keys()) if isinstance(top_vulns, dict) else list(top_vulns or [])
    return {
        "ip": host.get("ip_str") or host.get("ip"),
        "ports": sorted([p for p in (host.get("ports") or []) if isinstance(p, int)]),
        "hostnames": host.get("hostnames") or [],
        "domains": host.get("domains") or [],
        "org": host.get("org") or "",
        "isp": host.get("isp") or "",
        "asn": host.get("asn") or "",
        "os": host.get("os") or "",
        "country": host.get("country_name") or "",
        "vulns": sorted(top_vulns),
        "services": services,
        "last_update": host.get("last_update", ""),
    }


def all_vulns(summary: dict) -> list[str]:
    """Union of host-level and per-service CVEs from a summarize() result."""
    v = set(summary.get("vulns") or [])
    for svc in summary.get("services", []):
        v |= set(svc.get("vulns") or [])
    return sorted(v)
