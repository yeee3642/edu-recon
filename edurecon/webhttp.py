"""Minimal stdlib HTTP client shared by exposures / crawler / injectors.

Does not follow redirects (so a 200 is a real 200) and never verifies TLS
(education targets frequently use self-signed certs).
"""
from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request

_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _opener():
    return urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPSHandler(context=_SSL_CTX))


def request(url: str, *, method: str = "GET", data: dict | None = None,
            timeout: int = 12, ua: str = "edu-recon",
            headers: dict | None = None, max_bytes: int = 8192):
    """Return (status:int, headers:dict, body:str). status 0 on transport error."""
    body_bytes = None
    hdrs = {"User-Agent": ua}
    if headers:
        hdrs.update(headers)
    if data is not None and method.upper() == "POST":
        body_bytes = urllib.parse.urlencode(data).encode()
        hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
    req = urllib.request.Request(url, data=body_bytes, headers=hdrs,
                                 method=method.upper())
    try:
        resp = _opener().open(req, timeout=timeout)
        return resp.status, dict(resp.headers), _decode(resp.read(max_bytes))
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(max_bytes)
        except Exception:
            raw = b""
        return e.code, dict(e.headers or {}), _decode(raw)
    except Exception:
        return 0, {}, ""


def get(url: str, timeout: int, ua: str, max_bytes: int = 8192):
    return request(url, method="GET", timeout=timeout, ua=ua, max_bytes=max_bytes)


def _decode(b: bytes) -> str:
    for enc in ("utf-8", "latin-1"):
        try:
            return b.decode(enc, "replace")
        except Exception:
            continue
    return ""
