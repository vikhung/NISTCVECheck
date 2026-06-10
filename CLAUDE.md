# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案執行原則

1. 所有的交談都以繁體中文為主。
2. 每當討論出架構決策或注意事項，立即更新本文件的對應章節，不要等到對話結束才整理。
3. 程式碼、函式庫應用繁體中文記錄註解，讓使用者知道這段程式碼用途。
4. Node.js 請使用原生功能，不要使用任何需額外下載之套件。

## 執行方式

```bash
node scripts/cve-checker.js               # 掃描本機 Registry（HIGH 以上、近 5 年）
node scripts/cve-checker.js scan.json     # 使用 JSON 檔案輸入（跨平台）
node scripts/cve-checker.js -1 HIGH 5 2020  # FILE MIN_SEVERITY LIMIT MIN_YEAR

node scripts/team-report.js              # 讀取 .\team\ 目錄產生彙總報表
node scripts/team-report.js C:\scans\team

node scripts/web-server.js               # 啟動 Web 伺服器（預設 Port 8093）
npm run web                              # 同上（先自動執行 build.js）
npm run bundle                           # 單獨重新打包 web-client.html + .env.local

powershell -ExecutionPolicy Bypass -File findSW.ps1  # 遠端機器產生 scan.json
```

| 參數 | 有效值 | 預設 |
|------|--------|------|
| `FILE` | 路徑 \| `-1` \| 省略 | PC Registry |
| `MIN_SEVERITY` | LOW/MEDIUM/HIGH/CRITICAL \| `-1` | HIGH |
| `LIMIT` | N \| `-1` | 不限 |
| `MIN_YEAR` | YYYY \| `-1` | 當年 −5 |

**注意**：`args[0]` 是 FILE 而非 severity；傳入 severity 字串程式會報錯提示。

**MIN_YEAR bug**：`-1` 實際對應 `currentYear − 5`（與省略相同），並非「不限年份」，與 `--help` 說明矛盾。修正方式：`cve-checker.js:399` 改 `minYearRaw === -1 ? null : minYearRaw`，並在年份過濾處理 `null`。

不需要 `npm install`。Node.js 最低版本：**18.0.0**。

輸出：`report/vik_result_YYYYMMDD.html` 與 `report/vik_result_YYYYMMDD.json`（目錄自動建立）。

## team-report.js 工作流程

1. 各機器執行 `node scripts/cve-checker.js` 或 `findSW.ps1` → 產生 `vik_result_YYYYMMDD.json`
2. 將各機器的 JSON 複製至 `.\team` 目錄
3. 執行 `node scripts/team-report.js` → 產生 `.\report\team_YYYYMMDD.html`

## .env.local 設定

| 變數 | 說明 | 預設 |
|------|------|------|
| `NIST_API_KEY` | NVD API Key（有 Key：0.7s/req；無：6.5s/req）。必須用 HTTP header `apiKey:` 傳送，放 query param 會 HTTP 404。HTTP 429 自動等 15s 重試 3 次。 | — |
| `HTTPS_PROXY` / `HTTP_PROXY` | Proxy URL，支援 `http://user:pass@host:port`。底層以 `http`+`tls` CONNECT 隧道實作（非 undici 原生 Proxy）。 | — |
| `PROXY_SKIP_TLS_VERIFY` | `true` = 停用 TLS 驗證（SSL Inspection 環境） | false |
| `MAX_CVES_PER_SOFTWARE` | 每個軟體最多查詢幾筆 CVE（NVD 回傳由新至舊，過低會遺漏舊 CVE） | 50 |
| `PORTABLE_ENABLE` | `false` = 完全停用 Portable 功能 | true |
| `PORTABLE_ONLY` | `true` = 只掃描 PORTABLE_N，略過 Registry/JSON 項目 | false |
| `WHITELIST` | 逗號分隔廠牌關鍵字，比對 `publisher` 欄位。可與 `whitelist.txt` 並存（合併去重） | — |
| `PORTABLE_N` | 格式：`名稱\|版本\|發行商`（版本、發行商可省略）。從 0 連續遞增，遇缺口停止。略過白名單/SKIP_PATTERNS，走 CPE 精確查詢。 | — |

範例：
```
PORTABLE_0=Eclipse IDE|202506|Eclipse Foundation
PORTABLE_1=Node.js|24.15.0|OpenJS Foundation
```

## 架構說明

### 核心模組（唯一來源原則）

修改邏輯時只需動一個檔案，`scripts/build.js` 負責將其注入 web 頁面：

| 模組 | 職責 | 修改後需執行 |
|------|------|------------|
| `lib/cve-logic.js` | 所有 CVE 業務邏輯（15 個匯出：`SEVERITY_ORDER`、`compareVersions`、`isSafeVersion`、`getCvss`、`findAllCPEBases`、`cveMatchesCPEBase`、`cveRelevanceCheck`、`cveExactVersionCheck`、`_cpeWords`、`_matchInRange`、`isVersionInAnyRange`、`extractFixedVersion`、`getRecommendedVersion`、`getBranchFixVersion`、`extractAllRanges`） | `node scripts/build.js` |
| `lib/report-html.js` | 匯出 `buildHTMLReport(report)`：純函式，CLI 與 Web 版報表共用 | `node scripts/build.js` |

`lib/report-html.js` 在瀏覽器中依賴 `isSafeVersion`，`build.js` 注入時必須先注入 `cve-logic.js`（`@@CVE_LOGIC@@`）再注入 `report-html.js`（`@@REPORT_HTML@@`）。

### 資料流程

```
Windows Registry  ──┐
                     ├─► softwares[]  ──► 白名單過濾 → SKIP_PATTERNS 過濾 → cleanProductName 去重
findSW.ps1 JSON  ──┘                                                        ──► NVD CVE API 查詢
PORTABLE_N       ──────────────────────────────────────────────────────────► NVD CPE API → NVD CVE API
                                                                             ──► 關聯性檢查 → HTML/JSON 報表
```

### 主要處理邏輯

**輸入 JSON 格式**（`scan.json` 為範例）：
```json
{
  "generatedAt": "2026-05-14T12:49:39.741Z",
  "hostname": "MACHINE-NAME", "username": "user", "ip": "192.168.1.100",
  "softwares": [{ "name": "App Name", "version": "1.0.0", "publisher": "Vendor", "installDate": null, "installPath": null }]
}
```

**Portable 軟體 CPE 查找**（`findAllCPEBases`）：三個 Pass 依序比對，Pass 0 優先（vendor 單獨含關鍵字），Pass 1（vendor+product 合併含關鍵字），Pass 2 fallback（product 含第一個字）。回傳**所有符合**的 `{vendor, product}` 陣列（OR 邏輯），確保同一軟體不同 vendor 名稱（如 PuTTY 的 `putty:putty` 與 `simon_tatham:putty`）均能命中。

**NVD CVE API 限制**：`pubStartDate`/`pubEndDate` 必須成對使用，且範圍上限 120 天，超過回 HTTP 404。因此年份過濾在客戶端以 `minYear` 處理，為刻意設計。

**關聯性檢查回傳值**：
- `true` = 確認相關，保留
- `false` = 確認不符，列入 `mismatchedCVEs`（不顯示）
- `null` = 無 CPE 資料（NVD 未完成 enrichment），同樣過濾。理由：`keywordSearch` 比對描述全文，無 CPE 時無法驗證相關性，保留反而大量誤報。
- **例外**：Portable 軟體若 CPE 已確認但 CVE 無 configurations（`null` 且有 `cpeBases`），標記 `_pendingNvd=true` 保留，供人工確認。

**升級狀態判斷**（優先順序）：✗ 需升級 → ? 手動確認（有 `recommendedVersion` 但任一 CVE `fixedVersion===null`，或無 `recommendedVersion`） → ✓ 無須升級。

### report 物件結構

```
report.{generatedAt, source, hostname, ip, username, scanDate, minSeverity, minYear}
report.summary.{totalSoftware, queriedSoftware, affectedSoftware, totalCVEs}
report.results[]      — 有 CVE（含 recommendedVersion、cpeBase、cveCount、cves[]、mismatchedCVEs[]）
report.cleanResults[] — 已掃描無 CVE（含 cpeBase、mismatchedCVEs[]）
report.errors[]       — API 失敗（含 name、error）
report.whitelisted[]  — 白名單略過（含 matchedRule）
report.skippedByPattern[] / skippedByDedup[] — 過濾/去重略過
```

`cves[]` 每筆：`id、published、lastModified、severity、cvssScore、cvssVersion、description、fixedVersion、alreadyFixed、affectedRanges、cpeRelevant、pendingNvdAnalysis、url`

### Web 伺服器架構（`scripts/web-server.js`）

**NDJSON 代理**（`POST /api/scan`）：採單一長連線串流每筆 NVD 結果，避免舊版 per-request 代理因 NVD 6.5s 延遲超過 keepAliveTimeout 導致 socket 被複用時拋出 TypeError。

**全域速率限制**：`nvdSlot()` 以 Promise 鏈確保所有並行 session 共用同一 NVD 計時器，合計速率不超過 `REQUEST_DELAY`。

**CSP**：每次請求產生隨機 nonce，注入頁面設定 `Content-Security-Policy: script-src 'nonce-...'`。`_bundle.js` 不含 `NIST_API_KEY`（刻意排除）；`PORTABLE_N` bundle 時僅保留 `{name, version}`，不含 publisher。

## 檔案結構

```
lib/cve-logic.js          — CVE 業務邏輯（唯一來源）
lib/report-html.js        — HTML 報表產生（唯一來源）
scripts/
  cve-checker.js          — CLI 主程式
  team-report.js          — 團隊彙整報表
  web-server.js           — HTTP 伺服器
  web-client.src.html     — Web 掃描器模板（含 @@CVE_LOGIC@@ / @@REPORT_HTML@@ 注入點）
  web-client.html         — build artifact（勿直接編輯）
  build.js                — 打包工具：模板 + lib/ → web-client.html + _bundle.js
  _bundle.js              — build artifact，供 web-server.js require()
findSW.ps1                — 遠端機器產生 scan.json
docs/operator.html        — 完整操作手冊
```

## Claude Code 內建指令

| 指令 | 用途 |
|------|------|
| `/code-verify` | 確認 Node.js 版本、JS 語法正確、v18+ API 使用情況 |
| `/code-security` | 靜態安全分析（XSS、命令注入、路徑遍歷等）並評估 Node.js 現代化程度 |
| `/project-document` | 根據實際程式碼狀態，同步更新 `README.md`、`CLAUDE.md`、`docs/operator.html` |
