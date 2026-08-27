# edu-recon Console — 回饋給 Designer(handoff 缺的幾塊,重點:機敏資料處理)

你交付的 handoff(Setup / Monitor / Findings / Report + shell overlay + pipeline matrix)
很完整,已照它接上真後端。但實作階段工具多了幾個**「抓取/顯示機敏資料」**的功能,
你的設計還沒涵蓋,需要你補設計或給規範。以下是清單、資料、狀態,以及**最重要的第 2 節
——機敏資料的視覺與隱私規範**。

---

## 1. Leak Dump —「立即抓存外露資源」(最需要設計)

**情境**:掃到 leak 類 finding(`.git` / `.env` / 備份 / 金鑰 / phpMyAdmin·Adminer / 目錄列表)
時,operator 要「馬上把外露內容抓存到本地」——這類暴露常常幾分鐘後就被下架/修掉,**不抓就沒了**。

- **位置**:finding 展開列的動作區(CONFIRM / FALSE-POS 旁)多一顆 **⤓ DUMP**;
  Findings 工具列或頂部再一顆 **⤓ Dump 全部洩漏**(一鍵抓所有 leak)。
- **型別分派**(按鈕文字/圖示要能區分,後端已自動判斷):
  - 一般檔案(.env / 備份 / 面板)→ `⤓ Dump` → 抓回原始內容。
  - `.git` 目錄 → `⤓ Dump .git` → 伺服器把整個 .git 拉回並**重建原始碼樹**(回傳重建檔清單)。
  - 洩漏金鑰(AWS / GitHub / JWT…)→ `⤓ Dump key` → 存成金鑰卡(type / value / 來源 / severity)。
- **狀態**(要設計):`idle` → `dumping…`(loading)→ `✓ 已抓存 (size)`(成功、按鈕轉綠)
  → `✗ 失敗(可能已被下架)` → `⛔ 越界(非本 run 標的)`。
- **成功後**:在 shell 抽屜開啟抓到的內容(git 顯示 SUMMARY + 重建檔清單;key 顯示金鑰卡;
  檔案顯示原文),含「複製 / 下載」。Toast:「已抓存 → runs/<id>/dumps/…」。

## 2. 機敏資料的視覺 / 隱私規範 ★你特別要看這塊★

現在 UI 會**顯示並落地真正的機敏內容**:外洩密碼、AWS/GitHub 金鑰、私鑰、重建出來的
原始碼、`/etc/passwd`。設計上必須處理:

- **預設遮蔽 (mask)**:findings 表 / live feed / 報告預覽裡,金鑰與密碼**預設打碼**
  (`AKIA…MPLE`、`ghp_****`、`DB_PASSWORD=•••`),要點「👁 顯示」才展開完整值。
- **SENSITIVE 徽章**:凡 evidence 含 `value` / 密碼 / 私鑰 / 原始碼的 finding,列上加一個
  機敏標記(建議 magenta 或鎖 icon),提醒「點開會看到敏感內容」。
- **複製要提示**:複製金鑰或 dump 內容時,toast「已複製機敏內容,注意保管」。
- **報告匯出的紅線**:REPORT 預設**不**把金鑰明文寫進報告——evidence 內的 `value` 要遮蔽。
  現在的「附證據」開關太粗,請拆成兩個:**「附證據(遮蔽)」** vs **「附機敏明文(危險)」**
  (後者預設關,打開時給紅色警告)。
- **dump 落地提示**:dump 會把機敏內容寫到 `runs/<id>/dumps/`,UI 要提示「已落地磁碟,
  請自行保管/清除」,並在 run 層級給一顆「清除本 run 的 dumps」。
- **授權提醒常駐**:dump 只允許本 run 標的(越界後端直接 403);shell / report 內要有
  「僅限授權標的」的常駐字樣。

## 3. Repro / 重現腳本 viewer

- finding 展開列多一顆 **🔁 重現腳本** → 在 shell 抽屜顯示一份可跑的 **benign PoC**
  (bash/curl):頂部 COMMAND,下面腳本內容 + `expect:`,含「複製 / 下載 .sh」。
- 這是 shell overlay 的一個**變體**(不是工具 log,是產生的腳本),建議給它不同的
  header 標籤(`PoC`)與一顆下載鈕,和「看原始 log」的抽屜視覺上分開。

## 4. Demo 模式 / scope

- 你已把 scope 阻擋移除(👍)。實作有個 `scope_enforce` 開關(demo 模式 = 不鎖)。
  Setup 可給一個小開關或常駐標示 **「DEMO · 不鎖範圍」**,讓 operator 知道現在沒鎖。

## 5.(可選)Payout / 合法揭露路由

- 每筆 confirmed finding 有一組合法揭露/賞金路由(A 委託報酬 / B 標的入 scope 才投稿 /
  C 軟體新洞送廠商)。若要放,建議做成 finding 展開列的一個 tab 或小面板。**非必要**。

---

## 需要你回的
1. Dump 的按鈕 / 狀態 / 型別分派視覺(第 1 節)。
2. **機敏資料的 mask / reveal / SENSITIVE 徽章 / 報告遮蔽規範(第 2 節,最重要)。**
3. Repro 抽屜變體(第 3 節)。
4. Demo 模式標示(第 4 節)。

## 資料參考(給你對應設計)
- **finding** = `{id, severity, confidence, category, stage, title,
  evidence{url, value(機敏), match, cve, reproduce, computed, marker, snippet…},
  reviewed, false_positive}`
  其中 `category` 的 leak 類:`secret-leak / vcs-leak / backup-leak / admin-panel /
  dir-listing / info-leak`。
- **dump 回傳** = `{ok, kind: file|git|key, saved, size, preview, dir, files}`。
- **repro 回傳** = `{id, cve, category, title, severity, filename, script, expect}`。
