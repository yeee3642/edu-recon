"""Parsers that turn raw tool output into structured objects."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Any

from .models import Service, WebPath


# --------------------------------------------------------------------------- #
# nmap
# --------------------------------------------------------------------------- #
def parse_nmap_xml(path: str) -> dict[str, dict[str, Any]]:
    """Return {host_ip: {"hostnames": [...], "services": [Service], "hostscripts": {}}}."""
    out: dict[str, dict[str, Any]] = {}
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError):
        return out
    root = tree.getroot()
    for host in root.findall("host"):
        status = host.find("status")
        if status is not None and status.get("state") == "down":
            continue
        addr = ""
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                addr = a.get("addr", "")
                break
        if not addr:
            continue
        hostnames = [h.get("name", "") for h in host.findall("hostnames/hostname")]
        services: list[Service] = []
        for port in host.findall("ports/port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc_el = port.find("service")
            scripts = {s.get("id", ""): (s.get("output", "") or "")
                       for s in port.findall("script")}
            svc = Service(
                port=int(port.get("portid", "0")),
                proto=port.get("protocol", "tcp"),
                state="open",
                name=(svc_el.get("name", "") if svc_el is not None else ""),
                product=(svc_el.get("product", "") if svc_el is not None else ""),
                version=(svc_el.get("version", "") if svc_el is not None else ""),
                extrainfo=(svc_el.get("extrainfo", "") if svc_el is not None else ""),
                tunnel=(svc_el.get("tunnel", "") if svc_el is not None else ""),
                cpe=[c.text for c in (svc_el.findall("cpe") if svc_el is not None else []) if c.text],
                scripts=scripts,
            )
            services.append(svc)
        hostscripts = {s.get("id", ""): (s.get("output", "") or "")
                       for s in host.findall("hostscript/script")}
        out[addr] = {"hostnames": [h for h in hostnames if h],
                     "services": services, "hostscripts": hostscripts}
    return out


def parse_nmap_up_hosts(path: str) -> list[str]:
    """Hosts reported 'up' by an nmap -sn ping sweep."""
    hosts: list[str] = []
    try:
        tree = ET.parse(path)
    except (ET.ParseError, FileNotFoundError):
        return hosts
    for host in tree.getroot().findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        for a in host.findall("address"):
            if a.get("addrtype") in ("ipv4", "ipv6"):
                hosts.append(a.get("addr", ""))
                break
    return [h for h in hosts if h]


# --------------------------------------------------------------------------- #
# dirsearch
# --------------------------------------------------------------------------- #
def parse_dirsearch_json(path: str) -> list[WebPath]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, FileNotFoundError):
        return []
    entries: list[dict] = []
    if isinstance(data, dict):
        if isinstance(data.get("results"), list):
            entries = data["results"]
        else:
            for v in data.values():             # older: {target: [ {...} ]}
                if isinstance(v, list):
                    entries.extend(x for x in v if isinstance(x, dict))
    elif isinstance(data, list):
        entries = [x for x in data if isinstance(x, dict)]

    out: list[WebPath] = []
    for e in entries:
        url = e.get("url") or e.get("path") or ""
        if not url:
            continue
        status = _int(e.get("status") or e.get("status-code") or e.get("code"))
        length = _int(e.get("content-length") or e.get("length") or e.get("content_length"))
        redirect = e.get("redirect") or e.get("location") or ""
        out.append(WebPath(url=url, status=status, length=length, redirect=redirect or ""))
    return out


def parse_dirsearch_text(path: str) -> list[WebPath]:
    """Fallback: dirsearch plain report lines like '200   1KB  http://h/p  -> REDIR'."""
    out: list[WebPath] = []
    line_re = re.compile(r"^\s*(\d{3})\s+\S+\s+(https?://\S+)(?:\s+->\s+REDIRECTS TO:\s+(\S+))?")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = line_re.match(line)
                if m:
                    out.append(WebPath(url=m.group(2), status=int(m.group(1)),
                                       redirect=m.group(3) or ""))
    except FileNotFoundError:
        pass
    return out


# --------------------------------------------------------------------------- #
# sqlmap
# --------------------------------------------------------------------------- #
def parse_sqlmap_stdout(text: str) -> dict[str, Any]:
    vulnerable = bool(
        re.search(r"identified the following injection point", text)
        or re.search(r"\bis vulnerable\b", text)
        or re.search(r"^Parameter:\s", text, re.M)
    )
    params = re.findall(r"^Parameter:\s*(.+?)\s*$", text, re.M)
    types = re.findall(r"^\s*Type:\s*(.+?)\s*$", text, re.M)
    dbms_m = re.search(r"back-end DBMS:\s*(.+)", text) or \
        re.search(r"the back-end DBMS is\s*(.+)", text)
    dbms = dbms_m.group(1).strip() if dbms_m else ""
    urls = re.findall(r"testing URL '([^']+)'", text)
    return {
        "vulnerable": vulnerable,
        "parameters": [p.strip() for p in params],
        "types": [t.strip() for t in types],
        "dbms": dbms,
        "target_url": urls[-1] if urls else "",
    }


# --------------------------------------------------------------------------- #
# hydra
# --------------------------------------------------------------------------- #
_HYDRA_RE = re.compile(
    r"\[(\d+)\]\[([\w\-]+)\]\s+host:\s*(\S+)\s+login:\s*(.*?)\s+password:\s*(.*?)\s*$")


def parse_hydra_output(path: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            content = fh.read()
    except FileNotFoundError:
        return out
    # hydra -o may write JSON when -b json used; try that first
    try:
        data = json.loads(content)
        for r in data.get("results", []):
            out.append({"port": str(r.get("port", "")), "service": r.get("service", ""),
                        "host": r.get("host", ""), "login": r.get("login", ""),
                        "password": r.get("password", "")})
        if out:
            return out
    except json.JSONDecodeError:
        pass
    for line in content.splitlines():
        m = _HYDRA_RE.search(line)
        if m:
            out.append({"port": m.group(1), "service": m.group(2), "host": m.group(3),
                        "login": m.group(4), "password": m.group(5)})
    return out


# --------------------------------------------------------------------------- #
# php-cgi-Injector (Night-have-dreams/php-cgi-Injector exploit.py)
# --------------------------------------------------------------------------- #
def parse_phpcgi_stdout(text: str) -> dict[str, Any]:
    """Detect confirmation without touching the interactive menu.

    Success line (rich-rendered, markup stripped):
        [+] 找到 CGI 注入點: /php-cgi/php-cgi.exe (漏洞: CVE-2024-4577)
    Internal oracle string: 'TEST_VULNTEST_CVE-2024-4577' echoed back.
    """
    norm = re.sub(r"\s+", " ", text)
    vulnerable = ("找到 CGI 注入點" in norm) or ("TEST_VULNTEST" in text)
    cgipoint = ""
    m = re.search(r"找到\s*CGI\s*注入點[：:]\s*([^\s(（]+)", norm)
    if m:
        cgipoint = m.group(1)
    # The CVE is whatever the detection line reports as the payload group
    # (漏洞: CVE-…). Do NOT substring-scan the whole output — the tool's banner
    # names both CVEs, so that would always mislabel the finding.
    payload = ""
    pm = re.search(r"漏洞[：:]\s*(CVE-\d{4}-\d+)", norm)
    if pm:
        payload = pm.group(1).strip()
    cve = payload if payload.upper().startswith("CVE-") else "CVE-2024-4577"
    return {"vulnerable": vulnerable, "cgipoint": cgipoint, "cve": cve, "payload": payload}


# --------------------------------------------------------------------------- #
# react2shell-scanner (hidden-investigations/react2shell-scanner, CVE-2025-55182)
# --------------------------------------------------------------------------- #
def parse_react2shell_json(path: str) -> list[dict[str, Any]]:
    """Return the successful React2Shell results written to the -o JSON file.

    The tool writes an array of objects: {url, path, success, status, output,
    http:{status_code, headers}}. Only entries with success==True are exploited
    endpoints (a SAFE_CHECK_OK marker in --safe-check mode, else command output).
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, FileNotFoundError):
        return []
    if not isinstance(data, list):
        return []
    out: list[dict[str, Any]] = []
    for e in data:
        if not isinstance(e, dict):
            continue
        if e.get("success") is True or str(e.get("status")).lower() == "success":
            http = e.get("http") or {}
            out.append({
                "url": e.get("url", ""),
                "path": e.get("path", ""),
                "output": (e.get("output") or "").strip(),
                "status_code": http.get("status_code") if isinstance(http, dict) else None,
            })
    return out


def _int(v: Any) -> int:
    try:
        return int(str(v).strip())
    except (ValueError, TypeError):
        return 0
