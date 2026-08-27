"""Payout directives — for a CONFIRMED finding, the legal ways to turn it into money.

HARD BOUNDARY: findings here come from an authorized scan of a specific target.
Monetizing access to that target (extortion, selling access/data, "cashing out"
the popped box) is a crime and is NOT a path this module will ever emit. The only
legitimate payout lanes are:
  A. ENGAGEMENT  — it goes in your pentest deliverable; the asset owner pays you.
  B. IN-SCOPE BOUNTY — IF that exact target is in a published bounty/VDP scope,
     submit it there (verify scope first).
  C. UPSTREAM — if you can turn it into a *novel* bug in the software itself
     (not the known CVE), sell that to the vendor's program / a broker.

Almost everything this tool finds is a KNOWN CVE / misconfig exposure on the
target, i.e. Lane A by default (Lane B only if scope allows). Direct bounty cash
for detecting an n-day on someone's box is usually $0 — this module says so
honestly instead of implying otherwise.
"""
from __future__ import annotations

LEGAL = "合法付現三條:A 委託報酬 · B 標的在 bounty scope 才投稿 · C 軟體新洞送廠商。"

# software -> where the SOFTWARE bug (not the target) is legitimately reported/sold.
# Programs change; always re-verify a program is live before submitting.
SOFTWARE_CHANNELS = {
    "php-cgi":   ("PHP", "PHP security (git.php.net) · Internet Bug Bounty (HackerOne)", "ZDI"),
    "php":       ("PHP", "PHP security · Internet Bug Bounty (HackerOne)", "ZDI"),
    "phpunit":   ("Sebastian Bergmann/PHPUnit", "GitHub Security Advisory (upstream)", "—"),
    "nextjs":    ("Vercel / Next.js", "Vercel Security · GitHub advisory", "ZDI"),
    "struts":    ("Apache Struts", "security@apache.org · Internet Bug Bounty", "ZDI"),
    "confluence":("Atlassian", "Atlassian Bug Bounty (Bugcrowd)", "ZDI"),
    "drupal":    ("Drupal", "Drupal Security Team (security@drupal.org)", "ZDI"),
    "apache-httpd":("Apache httpd", "security@apache.org · Internet Bug Bounty", "ZDI"),
    "moodle":    ("Moodle", "Moodle security (moodle.org/security) · HackerOne", "ZDI"),
    "wordpress": ("WordPress / plugin author", "Wordfence Intelligence · Patchstack bounty", "ZDI"),
    "phpmyadmin":("phpMyAdmin", "phpMyAdmin security team (upstream)", "ZDI"),
    "adminer":   ("Adminer (Jakub Vrána)", "GitHub advisory (upstream)", "—"),
}

# category/cve -> which software the finding is about
_CVE_SOFT = {
    "CVE-2024-4577": "php-cgi", "CVE-2024-8926": "php-cgi",
    "CVE-2017-9841": "phpunit", "CVE-2021-41773": "apache-httpd",
    "CVE-2017-5638": "struts", "CVE-2022-26134": "confluence",
    "CVE-2018-7600": "drupal", "CVE-2025-29927": "nextjs",
    "CVE-2025-55182": "nextjs",
}


def _software(f: dict) -> str | None:
    ev = f.get("evidence", {}) or {}
    cve = ev.get("cve", "") or ""
    if cve in _CVE_SOFT:
        return _CVE_SOFT[cve]
    cat = f.get("category", "")
    title = (f.get("title") or "").lower()
    if ev.get("system") == "moodle" or "moodle" in title:
        return "moodle"
    if f.get("stage") == "wp" or "wordpress" in title:
        return "wordpress"
    if "phpmyadmin" in title:
        return "phpmyadmin"
    if "adminer" in title:
        return "adminer"
    return None


def _is_confirmed(f: dict) -> bool:
    if f.get("false_positive"):
        return False
    if f.get("confidence") in ("confirmed", "high") and f.get("severity") in ("critical", "high"):
        return True
    return f.get("category") == "cve"


def directive(f: dict) -> dict:
    """Return the legal payout directive for one finding."""
    cat = f.get("category", "")
    ev = f.get("evidence", {}) or {}
    soft = _software(f)
    sev = f.get("severity", "")
    cve = ev.get("cve", "")

    # Lane A always applies.
    lane_a = "列入委託 pentest 交付報告 + 通知資產擁有者修補（你的主要收入）。"
    # Lane B — only if the target is in a published bounty/VDP scope.
    lane_b = ("若此標的在某 bounty/VDP scope（HackerOne/Bugcrowd/校方 VDP）→ "
              "用下方 writeup 投稿；先確認 scope 有涵蓋此資產與此弱點類別。")
    # Lane C — sell a *novel* software bug, not the known n-day.
    if soft and soft in SOFTWARE_CHANNELS:
        vendor, program, broker = SOFTWARE_CHANNELS[soft]
        lane_c = (f"若你能把它做成 {vendor} 的*新*漏洞（非已知 CVE）→ 送 {program}"
                  + (f"；或經 {broker} 收購" if broker not in ("—",) else "") + "。")
    else:
        lane_c = "若這其實是某軟體的*新*漏洞 → 走該軟體 vendor 的 security/bounty 窗口。"

    known_nday = bool(cve)  # this tool confirms KNOWN CVEs
    cash_now = ("已知 n-day，對此標的『直接 bounty 收入 ≈ $0』——付現走 A（委託報酬）；"
                "B 僅在標的入 scope 時成立。") if known_nday else \
               ("非固定 CVE 的暴露/弱設定；付現走 A，B 視 scope。")

    return {
        "finding": f.get("title", ""),
        "id": f.get("id", ""),
        "severity": sev,
        "cve": cve,
        "software": soft or "—",
        "eligibility": "engagement" + ("+scope-bounty" if True else ""),
        "cash_now": cash_now,
        "lanes": {"A_engagement": lane_a, "B_inscope_bounty": lane_b, "C_upstream_novel": lane_c},
        "legal": LEGAL,
        "writeup": _writeup(f),
    }


def _writeup(f: dict) -> dict:
    ev = f.get("evidence", {}) or {}
    repro = ev.get("reproduce") or ev.get("url") or ev.get("poc") or ev.get("value") or ""
    return {
        "title": f.get("title", ""),
        "severity": f.get("severity", ""),
        "affected": ev.get("url") or f.get("target", ""),
        "reproduce": repro,
        "impact": _impact(f),
        "remediation": _remediation(f),
    }


def _impact(f: dict) -> str:
    cat = f.get("category", "")
    if cat == "cve":
        return "遠端程式碼執行 / 未授權存取（依 CVE）。"
    if cat in ("secret-leak", "vcs-leak", "backup-leak"):
        return "憑證/原始碼/資料洩漏 → 可橫向擴權。"
    if cat == "admin-panel":
        return "DB 管理介面外露 → 憑證爆破 / 直接操作資料庫。"
    if cat == "dir-listing":
        return "目錄列表 → 敏感檔案枚舉。"
    if cat == "weak-cred":
        return "弱/預設憑證 → 直接登入。"
    return f.get("title", "")


def _remediation(f: dict) -> str:
    soft = _software(f)
    if f.get("evidence", {}).get("cve"):
        return f"升級 {soft or '受影響元件'} 至修補版本；下架對外的 CGI/管理端點。"
    cat = f.get("category", "")
    if cat in ("secret-leak", "vcs-leak", "backup-leak"):
        return "移除外露資源、輪換所有洩漏憑證、加存取控制。"
    if cat == "admin-panel":
        return "限制來源 IP / 加認證 / 下架公網存取。"
    if cat == "weak-cred":
        return "改強密碼、停用預設帳號、上 MFA。"
    return "依 finding 修補。"


def directives_for_run(run: dict) -> list[dict]:
    out = []
    for t in run.get("targets", []):
        for f in t.get("findings", []):
            if _is_confirmed(f):
                d = directive(f)
                d["target"] = t.get("host", "")
                out.append(d)
    return out
