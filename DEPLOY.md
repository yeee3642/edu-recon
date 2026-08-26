# 本機部署教學（edu-recon）

適用於**授權的教育體系資安攻防演練**。核心是純 Python 3.10+ stdlib，不裝任何套件也能起 Web 介面；外部掃描器（nmap / sqlmap / hydra / dirsearch）另外裝。掃描器都是 Linux 工具，**建議跑在 Kali / Ubuntu**；Windows 適合開發、開 Web 介面、或只做內建探針（exposures / secrets / xss / phpcgi）。

---

## A. Linux / Kali 本機部署（建議：完整功能）

```bash
# 1. 取得程式
git clone https://github.com/ericchen913900/edu-recon.git
cd edu-recon

# 2.（可選但建議）建 venv，避免污染系統 Python
python3 -m venv .venv
source .venv/bin/activate

# 3. 裝外部掃描器
#    Kali 通常已內建 nmap/sqlmap/hydra/dirsearch；缺的話：
sudo apt update && sudo apt install -y nmap sqlmap hydra dirsearch
#    可選（XSS/子網域，走 go）：
#    go install github.com/hahwul/dalfox/v2@latest
#    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# 4. 拉進 CVE-2024-4577 與 wp2shell 兩支外掛工具（+ php-cgi 依賴）
python3 recon.py setup

# 5. 確認哪些工具就緒
python3 recon.py doctor
```

### 起 Web 操作介面
```bash
python3 recon.py serve --host 127.0.0.1 --port 8770
# 瀏覽器開 http://127.0.0.1:8770
```
若要讓同網段其他機器連（例如你在跳板機上跑）：
```bash
python3 recon.py serve --host 0.0.0.0 --port 8770
```
> ⚠️ 綁 `0.0.0.0` 等於把控制台對整個網路開放，且沒有登入驗證。只在受信任內網、或前面加反向代理 + 驗證時使用。

### 純命令列（不開 Web）
```bash
# 把目標寫進檔案，一行一個
cat > targets.txt <<'EOF'
10.0.0.0/24
lab.school.edu.tw
https://portal.school.edu.tw
EOF

python3 recon.py scan -t targets.txt --intensity full
# 報告在 runs/<run-id>/report.{md,html,json}
```

---

## B. Windows 本機部署（開發 / Web 介面 / 內建探針）

Windows 沒有 nmap/sqlmap/hydra 也能跑——那幾個階段會自動標記 `skipped`，但
**exposures（.git/.env/備份洩漏）、secrets（各種 key 外洩）、xss、phpcgi、triage、報告、Web 介面**都能運作。

```bash
# Git Bash / PowerShell
git clone https://github.com/ericchen913900/edu-recon.git
cd edu-recon

python recon.py doctor        # 看有哪些工具（Windows 通常只有 nmap 若你裝了）
python recon.py serve         # http://127.0.0.1:8770
```
想在 Windows 也有完整掃描器，裝 **Nmap for Windows**，其餘（sqlmap/hydra/dirsearch）
建議走 WSL 或直接用上面的 Linux 部署。

---

## C. 常用設定（config.yaml）

- `intensity`: `full`（全自動最大化，預設）/ `recon`（注入僅列候選）/ `passive`（被動盤點）
- `concurrency`: 同時掃幾個 target（預設 4）
- `nmap_top_ports`: 預設 1000；設 `0` 改成全埠 `-p-`
- `nmap_vuln_scripts`: `true` 會加 `--script vuln`（有 CVE 提示但**較慢**，趕時間可關）
- `hydra_tasks`: 弱密碼併發，預設 4，**壓低以免鎖帳號**
- `subdomain_enabled` / `subdomain_allow_scope`: 列舉並授權清單網域的子網域
- `extra_allowed_cidrs`: 除了目標檔外額外授權的網段

執行時也可覆寫：
```bash
python3 recon.py scan -t targets.txt --intensity recon --concurrency 8 --config config.yaml
```

---

## D. 掃描目標寫法

| 寫法 | 行為 |
|---|---|
| `10.0.0.0/24` | nmap `-sn` ping sweep，逐台存活主機掃 |
| `lab.school.edu.tw` | 列舉子網域後一起掃 |
| `portal.school.edu.tw` | 單一主機 |
| `https://portal.school.edu.tw/app?id=1` | 保留 scheme/port/path/query，`?id=1` 會被 sqli/xss 測試 |
| `192.168.10.20:8080` | 指定埠，nmap 只掃該埠（快、精準） |

---

## E. 安全與範圍

- **範圍鎖定**：只會掃目標檔（＋設定的 CIDR／其子網域）內的主機，每個階段動作前都會再檢查一次範圍，CIDR 展開或 redirect 都不會把你帶到範圍外。
- `full` 強度會**實際執行** sqlmap 注入與 hydra 弱密碼嘗試；只在你有明確書面授權、且是封閉演練環境時使用。
- 產出的報告（尤其 secrets 階段）可能包含真實金鑰／憑證，**當機敏資料保管**。
