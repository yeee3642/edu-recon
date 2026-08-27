# Handoff: edu-recon Web Console (v2 — adds Leak Dump, sensitive-data handling, Repro, Demo)

## Overview
`edu-recon` is a **scan → triage → report orchestrator** for authorized education-sector security exercises. An operator pastes targets, picks a scan intensity, and the tool runs a fixed recon/vuln pipeline per target, streams logs live, ranks findings by severity, and produces a reviewable list + exportable report. This handoff covers the **web control console** — a single-page, information-dense "ops-center" UI.

Visual direction: an **original Cyberpunk-2077-inspired** treatment (not a copy of the game) — hazard/acid **yellow** hero accent, **hot-magenta** for in-progress/alert/sensitive, **cyan/blue** as the secondary + "oracle/PoC" color, warm near-black, CRT scanlines, a warm HUD grid, angular notched corners, and neon glow on the brand/active-tab. All-monospace type (JetBrains Mono).

> This v2 supersedes the earlier handoff. Two things changed since v1: (a) the palette is now the CP2077 hazard-yellow set below — **use these tokens, ignore any green/cyan values from v1**; (b) four new capability areas were designed in (sections **A–D**), driven by real implementation needs around **capturing/displaying sensitive data**.

## About the Design Files
`Edu-Recon Console.dc.html` is a **design reference created in HTML** — a working prototype that demonstrates intended look, layout, and behavior, driven by an in-file mock "scan engine." It is **not production code to copy directly**. Recreate it in the target codebase's existing environment (React/Vue/etc.) using its established patterns, component library, state, and a real streaming back-end. `support.js` is only the prototype runtime — **ignore it for reimplementation**.

## Fidelity
**High-fidelity.** Colors, type, spacing, layout, and interactions are final and meant to be matched closely.

---

## Screens / Views (base)

### Top bar (52px)
Brand chip (neon-yellow wordmark + glow) · **`◈ DEMO · 不鎖範圍 · scope off`** indicator (see D) · intensity readout · phase dot + label + elapsed + % · run controls **RUN / SKIP / RESET** (RUN is phase-aware: ARM & RUN → ⏸ PAUSE → ▶ RESUME → ↻ RE-RUN; notched corner).

### Tab bar (38px) + hazard-stripe divider
Four tabs `01 SETUP / 02 MONITOR / 03 FINDINGS / 04 REPORT`; **active tab = yellow text + yellow 2px underline + neon text-shadow**. Right side: live severity tally. Directly beneath the tab bar is a 2px **diagonal hazard-stripe** accent line.

### 1. SETUP / 掃描設定
Two-column grid (`1.15fr 1fr`). Left: targets `<textarea>` (default 6 seed targets) + parsed-target rows (KIND · host). Right: three **intensity** cards (FULL default / RECON / PASSIVE, radio-style) + **pipeline preview** (14 stages; dot/label yellow = passive probe, magenta = active injection, faint = skipped at current intensity) + **ARM & RUN** (notched).
> Scope-lock **blocking was removed** (see D — DEMO). `inScope()` always true; all pasted targets are accepted.

### 2. MONITOR / 即時監控
KPI strip (TARGETS / PROGRESS / FINDINGS+per-severity; cards notched). Body grid `1fr 320px`:
- **Pipeline matrix** (`matrix` layout): grid `190px repeat(14,1fr)`, first cell = target host + note + %, then 14 stage cells. Cell status colors: pending (outline) · **running = magenta with a horizontal scanning shimmer** (`erscan`) · clean/done = teal `#15707F` · hit = severity color **with a breathing glow** (`erhit`, box-shadow uses the cell's `currentColor`) · skip = diagonal hatch · n/a = empty. A **light bar sweeps** across the matrix while scanning (`ersweep`). Click a cell → Shell overlay. Alternate **`rail`** layout (tweak `pipelineLayout`): per-target horizontal 14-node row.
- **Live log terminal** (`#er-log`, deep bg, notched): streaming lines, auto-scrolled while running, blinking neon cursor. Line colors by level (sys/info faint, ok/cmd yellow, scope blue, warn magenta, hit red, raw-out faintest).
- **Live findings feed** (right, notched): cards appended as findings surface, `border-left` = severity, `erfade` entry.
- **PROGRESS bar** = flowing glowing magenta hazard stripe (`erflow`) while running.
- **Done banner** (bottom pill) on completion.
All animations gated by the `reduceMotion` tweak.

### 3. Raw-log "Shell" overlay (right-docked, diagonal top-left cut)
Opened by clicking a matrix cell (mode `log`) — or by DUMP / Repro (modes `dump` / `repro`, see A & C). Header: status dot + **mode tag chip** (`LOG` blue / `DUMP` magenta / `PoC` yellow) + title + host·ip·tool + status chip + close. COMMAND block (the literal CLI). Output body (monospace lines; for a hit: tool output → `# SAFE-CHECK ORACLE` section (cyan) with the benign proof → severity summary). Footer is **persistent**: `◈ 僅限授權標的 / authorized targets only` + optional **download** button (dump/PoC) + optional "在 FINDINGS 開啟 →".

### 4. FINDINGS / 弱點清單
Toolbar: severity chips (toggle filters + counts), search, status filter (ALL/NEW/CONFIRMED/FALSE-POS/CANDIDATE), sort (SEVERITY|CVSS), **`⤓ Dump 全部洩漏`**, **`🧹 清除 dumps`**, `匯出報告 →`. Table columns `88 60 1fr 200 150 120` = severity badge · CVSS · finding (title + **`🔒 SENSITIVE`** badge when applicable + CN) · target · stage/CVE · status. Row expand → evidence panel (see B for the mask/reveal + action buttons).

### 5. REPORT / 匯出報告
Grid `300px 1fr`. Controls: FORMAT (HTML/MD/JSON) · **OPTIONS** (see B: `附證據(遮蔽)`, `附機敏明文(危險)`, scope, raw log) · MIN SEVERITY (LOW+/MED+/HIGH+) · download (notched, real Blob export). Preview: styled report card with an `◈ 僅限授權標的 · 報告金鑰/密碼預設遮蔽` note, severity summary, per-finding rows (evidence shown masked unless plaintext option is on).

---

## A. Leak Dump — 立即抓存外露資源
On leak-category findings (`.git` / `.env` / backups / keys / phpMyAdmin·Adminer / dir-listing), the expanded row shows a **type-dispatched** dump button next to CONFIRM / FALSE-POS, and the toolbar shows a batch button:
- **Per-finding button** label by kind: `⤓ DUMP` (file) / `⤓ DUMP .git` (git) / `⤓ DUMP KEY` (key).
- **`⤓ Dump 全部洩漏`** (toolbar) — one-click dump of every leak in the current filtered list.
- **`🧹 清除 dumps`** (toolbar) — run-level clear of captured dumps.
- **Button states** (design each): `idle` (gold outline) → `⟳ DUMPING…` (magenta) → `✓ 已抓存 (size)` (filled yellow) → `✗ 失敗(可能已下架)` (red) → `⛔ 越界(非本 run 標的)` (grey, back-end 403 for out-of-run targets).
- **On success** the Shell overlay opens in **`dump` mode**: `git` → SUMMARY + reconstructed file list (flags files that contain secrets); `key` → a **key card** (type / value / source / severity + a ⚠ landed-to-disk warning); `file` → original contents. A **toast** confirms `已抓存 → runs/<id>/dumps/… · <size>`, and the drawer offers a download.
- Rationale to preserve in UX copy: these exposures often disappear within minutes — the button is a **grab-now** affordance.

## B. Sensitive-data visual / privacy rules ★most important★
The UI can surface and land **real** sensitive content (leaked passwords, AWS/GitHub keys, private keys, reconstructed source, `/etc/passwd`). Rules implemented:
- **Default mask** — in evidence, secrets/keys/passwords render masked (`AKIA…`, `ghp_****…`, `DB_PASSWORD=•••`, `root:x:0:0:••••`). The evidence block header has a **`👁 顯示` / `🙈 遮蔽`** toggle (per finding) to reveal the full value; a finding with sensitive evidence but no single value gates the whole block behind reveal (`🔒 機敏證據已遮蔽`).
- **`🔒 SENSITIVE` badge** (magenta) on any finding whose evidence contains a value / password / private key / source, on the row and in the live feed.
- **Copy warning** — copying a key or dumped content raises a toast `已複製機敏內容,注意保管` (wire to your copy affordances).
- **Report red-line** — the old single "evidence" toggle is split into **`附證據(遮蔽 masked)`** and **`附機敏明文(危險 DANGER)`**. Plaintext is **off by default**; turning it on shows a red inline warning and only then are `value`s written unmasked into JSON/MD/HTML exports (`evProof()` masks otherwise).
- **Dump landing notice** — dumps write to `runs/<id>/dumps/`; the drawer states `已落地 runs/…/dumps/ · 請自行保管/清除`, and the toolbar `🧹 清除 dumps` clears them.
- **Authorized reminder persistent** — dump only allows in-run targets (back-end 403 otherwise); the Shell footer and Report both carry `僅限授權標的 / authorized targets only`.

## C. Repro / PoC viewer
Expanded row shows **`🔁 重現腳本`** → opens the Shell overlay in **`repro` mode**: a runnable **benign PoC** (bash/curl) with a top COMMAND line, the script body, and `# expect:` assertions. Header uses a distinct **`PoC`** tag (yellow) to separate it visually from the blue `LOG` (raw tool output) drawer; footer offers **`⭳ 下載 .sh`** (real download) and the authorized-only note.

## D. Demo mode / scope
Scope blocking was removed (demo). A back-end `scope_enforce` flag = off in demo. The top bar carries a persistent **`◈ DEMO · 不鎖範圍 · scope off`** indicator so the operator knows scope is not enforced. (Re-introduce a real lock + BLOCKED state when `scope_enforce` is on.)

*(Section 5 — payout / disclosure routing — was marked optional and is not designed yet.)*

---

## Interactions & Behavior
- **Run control** phase-aware (idle/done→run, running→pause, paused→resume); SKIP fast-forwards; RESET clears.
- **Intensity gating**: `passive` = only the 7 always-on stages run (active-injection stages marked skip; only passively-observable findings); `recon` = all stages, but `sqli`/`cred`/`wp` are **candidate-only** (status CANDIDATE); `full` = everything.
- **Streaming**: a timeline of ops (stage transitions, log lines, findings) plays on an interval; matrix fills, logs stream, feed grows, KPIs update.
- **Triage**: confirm / mark-false-positive per finding (toggles status + button fill).
- **Reveal / Dump / Repro / Export**: as in A–C; exports are real client-side Blobs.
- **Animations**: `erpulse/erblink/erfade/erscan/erhit/erflow/ersweep` — all suppressed by `reduceMotion`.

## State Management
`view · intensity · phase · targetsText · active[] · status{tid:{sid:state}} · logs[] · findings[] · elapsed · progress · cursor/total · shell{tid,sid,mode,fid} · openFinding · sevFilter[] · statFilter · q · sortBy · marks{id:status} · reveal[] · dumps{id:{state,size,kind}} · demoMode · toast · expOpts{evidence,plaintext,rawlog,scope,minSev} · banner`.
**Tweaks / props:** `scanSpeed` (0.25–4×), `pipelineLayout` (`matrix|rail`), `reduceMotion` (bool).

### Data / Back-end expectations
Replace the mock engine with a streaming source (SSE/WebSocket). Per target×stage: status transitions, a raw command + stdout lines, zero-or-more findings.
- **finding** = `{id, severity, confidence, category, stage, title, cn, url, tool, cmd, cve, cvss, ok (oracleKind), okLabel, evidence: proof[], sensitive, secret, masked, dumpKind: 'file'|'git'|'key'|null, remediation, status, reviewed, false_positive}`. Leak categories: `secret-leak / vcs-leak / backup-leak / admin-panel / dir-listing / info-leak`.
- **dump return** = `{ok, kind: file|git|key, saved, size, preview, dir, files}`.
- **repro return** = `{id, cve, category, title, severity, filename, script, expect}`.
- **Redaction rule**: never emit `secret`/`value` unmasked unless the caller explicitly set the "plaintext (danger)" report flag; dumps land under `runs/<id>/dumps/` and require in-scope targets (else 403).

---

## Design Tokens (current — CP2077-inspired)

### Neutrals / surfaces
| token | value |
|---|---|
| app base bg | `#0B0B09` |
| panel / card bg | `#101010` |
| deep / log / evidence bg | `#070707` |
| overlay scrim | `rgba(4,3,12,.8)` |
| hairline border | `rgba(150,146,120,.14)` (variants .05–.20) |
| warm grid lines | `rgba(150,146,120,.05)` @ 42px |

### Text
| token | value |
|---|---|
| brightest (headings) | `#F1EFE2` |
| body | `#DAD8C8` |
| soft | `#C8C6B4` |
| dim-2 | `#AEA98C` |
| dim | `#8F8B72` |
| faint (labels) | `#82806A` |
| faintest | `#4E4C3C` |

### Accents & semantics
| token | value | use |
|---|---|---|
| **hero yellow** | `#F2E409` | brand, primary/active, buttons, ok/clean status, links, tab underline |
| yellow bright | `#FFF64D` | link/emphasis hover |
| yellow tint | `rgba(242,228,9,.04–.16)` | button fills, hovers; glow `rgba(242,228,9,.55–.75)` |
| **magenta** | `#FF3DAE` | running / progress / alert / SENSITIVE / DUMP |
| teal | `#15707F` | clean/done matrix cells |
| secondary blue | `#3AA0FF` | oracle / repro / LOW severity; tint `rgba(58,160,255,.04–.22)` |
| severity CRITICAL | `#FF3D5E` | tint `rgba(255,61,94,.06–.07)` |
| severity HIGH | `#FF7A2A` | |
| severity MEDIUM | `#F6C63A` | |
| severity LOW | `#3AA0FF` | |
| severity INFO | `#8E8CEA` | |

### Effects / motion
- **Scanlines**: `repeating-linear-gradient(0deg, rgba(0,0,0,.20) 0 1px, transparent 1px 3px)` full-bleed.
- **Corner glows**: magenta `rgba(255,61,174,.08)` top-right, yellow `rgba(242,228,9,.06)` bottom-left.
- **Hazard stripe** (divider / progress): `repeating-linear-gradient(45deg, <accent> 0 13px, transparent 13px 26px)`.
- **Notched corners** (signature): `clip-path: polygon(0 0,100% 0,100% calc(100% - Npx),calc(100% - Npx) 100%,0 100%)` — N≈7 (small controls) to 13 (hero buttons); cards use 10. Shell panel uses a top-left cut `polygon(0 24px,24px 0,100% 0,100% 100%,0 100%)`.
- **Keyframes**: `erscan` (running-cell shimmer), `erhit` (hit-cell glow, currentColor), `erflow` (progress stripe), `ersweep` (matrix light bar), `erpulse/erblink/erfade`.
- **Neon glow**: brand + cursor + active tab via `box-shadow`/`text-shadow` in yellow tints.

### Typography
`JetBrains Mono` (Google Fonts), weights 400/500/600/700/800 — **mono only**. Sizes 8–9px (micro) · 10–11px (labels/log/body) · 12–14px (titles/buttons) · 16–20px (KPI numbers / view titles). Uppercase heavy on chrome; letter-spacing 0.3–2px.

### Spacing / sizing
Top bar 52px · tab bar 38px · hazard stripe 2px · log terminal 230px · feed column 320px · report controls 300px · matrix first column 190px. Card padding 9–14px; view padding 14–30px; gaps 3px (matrix cells) / 6–12px (cards) / 20–26px (setup). No border-radius (square/notched).

## Assets
Fonts: JetBrains Mono via Google Fonts `<link>`. Icons/glyphs are all Unicode/text (`◈ ❯ ⏭ ■ ▶ ⏸ ↻ ✓ ⊘ ⤓ ⟳ 🔒 👁 🙈 🔁 🧹 ⭳ ✕ ● ⚠`). No image/SVG assets. The 14 stages, 6 sample targets, and 15 sample findings are demo data — replace with live results.

## Files
- `Edu-Recon Console.dc.html` — full design reference (all views + Shell log/dump/repro modes + mock engine).
- `support.js` — prototype runtime only; not part of the design.
