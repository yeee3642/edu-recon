"""Secret / API-key leak scanning and API-surface exposure probes."""
from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlparse

from .config import Config
from . import webhttp

# (name, regex, severity) — broad multi-provider key/secret coverage
SECRET_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # --- cloud providers ---
    ("AWS Access Key ID", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"), "critical"),
    ("AWS Secret Access Key",
     re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), "critical"),
    ("Azure Storage AccountKey",
     re.compile(r"AccountKey=[A-Za-z0-9+/=]{86,88}"), "critical"),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high"),
    ("Google OAuth Client",
     re.compile(r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b"), "medium"),
    ("GCP Service Account JSON",
     re.compile(r'"type"\s*:\s*"service_account"'), "critical"),
    ("DigitalOcean Token", re.compile(r"\bdop_v1_[0-9a-f]{64}\b"), "critical"),
    ("Firebase Cloud Messaging Key",
     re.compile(r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b"), "high"),
    # --- VCS / package registries ---
    ("GitHub Token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{36}\b"), "critical"),
    ("GitHub Fine-grained PAT", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"), "critical"),
    ("GitLab PAT", re.compile(r"\bglpat-[0-9A-Za-z_\-]{20}\b"), "critical"),
    ("npm Token", re.compile(r"\bnpm_[0-9A-Za-z]{36}\b"), "high"),
    # --- LLM / AI ---
    ("Anthropic API Key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), "critical"),
    ("OpenAI API Key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9]{20,}\b"), "high"),
    ("Hugging Face Token", re.compile(r"\bhf_[A-Za-z0-9]{34,}\b"), "high"),
    # --- messaging / collaboration ---
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "high"),
    ("Slack Webhook",
     re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Za-z_]+/B[0-9A-Za-z_]+/[0-9A-Za-z]+"), "medium"),
    ("Telegram Bot Token", re.compile(r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b"), "high"),
    ("Discord Bot Token",
     re.compile(r"\b[MNO][A-Za-z\d_-]{23}\.[\w-]{6}\.[\w-]{27,}\b"), "medium"),
    ("Discord Webhook",
     re.compile(r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]+"), "medium"),
    # --- payments ---
    ("Stripe Live Secret", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{24,}\b"), "critical"),
    ("Square Access Token", re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z_\-]{22,}\b"), "high"),
    ("Braintree/PayPal Token",
     re.compile(r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"), "high"),
    ("Shopify Token", re.compile(r"\bshp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}\b"), "high"),
    # --- email / SMS providers ---
    ("Twilio API Key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("SendGrid Key", re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"), "high"),
    ("Mailgun Key", re.compile(r"\bkey-[0-9a-f]{32}\b"), "medium"),
    ("Mailchimp Key", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), "medium"),
    ("Cloudinary URL",
     re.compile(r"cloudinary://[0-9]{12,}:[0-9A-Za-z_\-]+@[0-9A-Za-z_\-]+"), "high"),
    # --- generic / structural ---
    ("Private Key Block",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "critical"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
    ("Credentials in URL",
     re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]*://[^/\s:@]{2,}:[^/\s:@]{2,}@[A-Za-z0-9.\-]+"), "high"),
    ("Bearer Token",
     re.compile(r"(?i)\bbearer\s+[A-Za-z0-9\-_.=]{24,}"), "medium"),
    ("Generic Secret Assignment",
     re.compile(r"""(?i)\b(?:api[_-]?key|secret|passwd|password|token|access[_-]?key|"""
                r"""client[_-]?secret|private[_-]?key)\b"""
                r"""\s*[=:]\s*['\"]([A-Za-z0-9_\-\/+]{12,64})['\"]"""), "medium"),
]

API_DOC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/openapi.json", "/v2/api-docs",
    "/v3/api-docs", "/api-docs", "/api/swagger.json", "/swagger-ui.html",
    "/swagger-ui/index.html", "/.well-known/openapi.json", "/api/docs",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
_INTROSPECT = json.dumps({"query": "{__schema{queryType{name}}}"})

_JS_SRC_RE = re.compile(r"""<script[^>]+src\s*=\s*['\"]([^'\"]+)""", re.I)
_LINK_RE = re.compile(r"""(?:href|src)\s*=\s*['\"]([^'\"]+\.(?:js|json|map|txt|cfg|config|env))""", re.I)


def scan_text(url: str, text: str) -> list[dict]:
    hits: list[dict] = []
    for name, rx, sev in SECRET_PATTERNS:
        for m in rx.finditer(text):
            val = m.group(0)
            hits.append({"type": name, "severity": sev, "url": url,
                         "match": _mask(val), "value": val[:120]})
    return hits


def _mask(v: str) -> str:
    if len(v) <= 10:
        return v[0] + "***"
    return f"{v[:4]}...{v[-4:]} (len={len(v)})"


def extract_assets(base_url: str, html: str) -> list[str]:
    urls: set[str] = set()
    for rx in (_JS_SRC_RE, _LINK_RE):
        for m in rx.finditer(html):
            link = urljoin(base_url, m.group(1).strip())
            if urlparse(link).netloc == urlparse(base_url).netloc:
                urls.add(link)
    return list(urls)


def probe_api_docs(root: str, cfg: Config) -> list[dict]:
    root = root.rstrip("/")
    out: list[dict] = []
    for path in API_DOC_PATHS:
        st, hdrs, body = webhttp.get(root + path, cfg.http_timeout, cfg.user_agent,
                                     max_bytes=20000)
        if st != 200:
            continue
        low = body.lower()
        if ('"swagger"' in low or '"openapi"' in low or '"paths"' in low
                or "swagger-ui" in low):
            out.append({"url": root + path, "kind": "api-doc", "severity": "medium",
                        "title": "API documentation / schema exposed",
                        "evidence": body[:200]})
    for path in GRAPHQL_PATHS:
        st, hdrs, body = webhttp.request(root + path, method="POST", data=None,
                                         timeout=cfg.http_timeout, ua=cfg.user_agent,
                                         headers={"Content-Type": "application/json"},
                                         max_bytes=20000)
        # some servers need a raw JSON body; retry with introspection payload
        if st in (400, 405, 415) or "__schema" not in body:
            st, hdrs, body = _post_json(root + path, _INTROSPECT, cfg)
        if st == 200 and ("__schema" in body or '"queryType"' in body):
            out.append({"url": root + path, "kind": "graphql", "severity": "high",
                        "title": "GraphQL introspection enabled",
                        "evidence": body[:200]})
            break
    return out


def _post_json(url: str, payload: str, cfg: Config):
    import urllib.request
    req = urllib.request.Request(
        url, data=payload.encode(), method="POST",
        headers={"Content-Type": "application/json", "User-Agent": cfg.user_agent})
    try:
        resp = webhttp._opener().open(req, timeout=cfg.http_timeout)
        return resp.status, dict(resp.headers), webhttp._decode(resp.read(20000))
    except Exception as e:  # noqa
        code = getattr(e, "code", 0)
        try:
            body = webhttp._decode(e.read(20000))  # type: ignore
        except Exception:
            body = ""
        return code, {}, body
