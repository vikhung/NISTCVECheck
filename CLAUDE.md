# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案執行原則

1. 所有的交談都以繁體中文為主。
2. 每當討論出架構決策或注意事項，立即更新本文件的對應章節，不要等到對話結束才整理。
3. 程式碼、函式庫應用繁體中文記錄註解，讓使用者知道這段程式碼用途。
4. Node.js 請使用原生功能，不要使用任何需額外下載之套件。
5. 操作方式（指令、參數、設定檔）寫在 `README.md`；本文件只放系統處理原則與架構決策。

## 架構說明

### 核心模組（唯一來源原則）

修改邏輯時只需動一個檔案，`scripts/build.js` 負責將其注入 web 頁面：

| 模組 | 職責 | 修改後需執行 |
|------|------|------------|
| `lib/cve-logic.js` | 所有 CVE 業務邏輯（15 個匯出：`SEVERITY_ORDER`、`compareVersions`、`isSafeVersion`、`getCvss`、`findAllCPEBases`、`cveMatchesCPEBase`、`cveRelevanceCheck`、`cveExactVersionCheck`、`_cpeWords`、`_matchInRange`、`isVersionInAnyRange`、`extractFixedVersion`、`getRecommendedVersion`、`getBranchFixVersion`、`extractAllRanges`） | `node scripts/build.js` |
| `lib/report-html.js` | 匯出 `buildHTMLReport(report)`：純函式，CLI 與 Web 版報表共用 | `node scripts/build.js` |
| `lib/nvd-client.js` | NVD API 客戶端（**純 server-side，不注入 web**）：本機 CVE 快取（`data/<key>.json`）、日期分段查詢（120 天/段）、增量更新（`lastModStartDate`）、alias 對應（`CACHE_ALIAS_N`）、CPE 關鍵字查找快取（`data/cpekw_<key>.json`，同一天快取邏輯與 CVE 一致）。匯出 `createNvdClient({ fetchFn, apiKey, delay, cacheDir, aliases, slotFn, logger })`。CLI 與 Web Server 均 require 此模組，確保快取與速率限制共用同一套邏輯。 | — |

`lib/report-html.js` 在瀏覽器中依賴 `isSafeVersion`，`build.js` 注入時必須先注入 `cve-logic.js`（`@@CVE_LOGIC@@`）再注入 `report-html.js`（`@@REPORT_HTML@@`）。

### 資料流程

```
Windows Registry  ──┐
                     ├─► softwares[]  ──► 白名單過濾 → SKIP_PATTERNS 過濾 → cleanProductName 去重
findSW.ps1 JSON  ──┘                                                        ──► nvd-client.fetchCVEs()
PORTABLE_N       ──────────────────────────────────────────────────────────► NVD CPE API → nvd-client.fetchCVEs()
                                                                             ↑
                                                               data/<key>.json（本機快取）
                                                               同一天已查過：直接回傳
                                                               跨天：增量查詢（lastModStartDate）
                                                               未命中：全量查詢（120 天分段）
                                                                             ──► 關聯性檢查 → HTML/JSON 報表
```

**快取檔案結構** (`data/<key>.json`)：
```json
{
  "cveCount": 42,
  "cacheKey": "kw_nodejs",
  "coverageStart": "2021-01-01T00:00:00.000Z",
  "lastFetchedAt": "2026-06-22T10:30:00.000Z",
  "cves": [ /* NVD vulnerabilities[] 原始物件陣列 */ ]
}
```
`cveCount` 為描述性欄位（= `cves.length`），方便人工檢視檔案時不必數陣列長度，無程式邏輯依賴。快取 key 命名：keyword 查詢 → `kw_<sanitized>`；CPE 查詢 → `cpe_<vendor>_<product>`。`sanitizeCacheKey()` 將名稱轉為 lowercase 並將非字母數字字元替換為 `_`。

**CPE 關鍵字查找快取**（`data/cpekw_<sanitized>.json`，獨立於上述 CVE 快取）：`fetchCPEs(keyword)` 查 NVD CPE API（`findAllCPEBases` 用來判斷 vendor:product 的原始資料）時，依關鍵字快取，邏輯與 CVE 快取一致——以 `toDateString()` 比較日期，**同一天**內查過直接回傳快取，跨天才重新查詢並覆寫快取。原因：CPE 資料變動緩慢，但同一天常有多次/多人重複掃描同一軟體，若每次都重新查 CPE 會造成不必要的 API 呼叫。結構：
```json
{ "productCount": 12, "cacheKey": "cpekw_putty", "fetchedAt": "2026-06-22T10:30:00.000Z", "products": [ /* NVD CPE products[] 原始物件陣列 */ ] }
```
`fetchCPEs()` 只回傳 `{ products, fromCache }`，**不在內部印 log**：此時只知道 NVD 原始條目數（可能上百筆，含各版本），不知道 `findAllCPEBases()` 去重後剩幾個 vendor:product。呼叫端（CLI／Web）跑完 `findAllCPEBases` 算出 `cpeBases.length` 後，才合併印成一行：`[CPE 快取] 命中（N 筆，今天已查詢過）` 或 `[CPE] 查詢完成（N 筆）`，N 是去重後的數量，不是原始條目數。
CLI、Web 代理（自動偵測與 `/api/cpe` Portable 預查）三處皆已改走 `nvdClient.fetchCPEs()`，共用同一份快取與全域速率限制。`CACHE_DISABLE=true` 時這份快取同樣停用。

### 主要處理邏輯

**輸入 JSON 格式**（`scan.json` 為範例）：
```json
{
  "generatedAt": "2026-05-14T12:49:39.741Z",
  "hostname": "MACHINE-NAME", "username": "user", "ip": "192.168.1.100",
  "softwares": [{ "name": "App Name", "version": "1.0.0", "publisher": "Vendor", "installDate": null, "installPath": null }]
}
```

**Portable 軟體 CPE 查找**（`findAllCPEBases`）：三個 Pass 依序比對，Pass 0 優先（vendor 單獨含關鍵字），Pass 1（vendor+product 合併含關鍵字），Pass 2 fallback（product 含第一個字）。回傳**所有符合**的 `{vendor, product}` 陣列（OR 邏輯），確保同一軟體不同 vendor 名稱（如 PuTTY 的 `putty:putty` 與 `simon_tatham:putty`，或 Bruno 的 `usebruno:bruno` 與 `yaxim:bruno`）均能命中。

**多 CPE base 查詢（CLI / Web 共用原則）**：`findAllCPEBases` 找到多個 base 時，CLI（`cve-checker.js`）、Web 代理（`web-server.js`）、Web 直連模式（`web-client.src.html`）都必須**逐一查詢每個 base 並依 CVE id 合併去重**，不可只查第一個（曾經的 bug：只查 `cpeBases[0]`，導致第二個 vendor 名稱下的 CVE 永遠不會被查到）。每個 base 各自獨立快取（`data/cpe_<vendor>_<product>.json`），合併只發生在記憶體中、查詢完成後。查詢時須以 log 明確標示「查詢 (i/N)CPE：cpe:2.3:a:vendor:product:*」（含目前進度索引），方便追蹤目前查的是哪一個。

**NVD CVE API 限制**：`pubStartDate`/`pubEndDate` 必須成對使用，且範圍上限 120 天，超過回 HTTP 404。`lib/nvd-client.js` 的 `splitDateRange()` 自動將查詢切為多段（每段 ≤ 120 天，由新到舊）。

**`_httpGet()` 重試範圍**：HTTP 429/503 與逾時（`AbortSignal.timeout(60000)`）原本就會重試（指數退避 30/60/120 秒）；連線層級錯誤（`ECONNRESET`、`ECONNREFUSED`、`ENOTFOUND`、socket hang up、TLS 失敗等，Node `fetch()` 統一包成 `TypeError: fetch failed`，無 HTTP status 可判斷）也納入同一套重試邏輯，視為暫時性問題，而非直接中斷整個掃描。三者共用 `MAX_RETRIES = 3`。

**年份過濾（`minYear`/`coverageStart`）**：快取以軟體（keyword/CPE）為單位，不是以查詢年份為單位，因此同一份快取可能比本次要求的範圍更廣（例如曾被較寬鬆的 `MIN_YEAR` 查過）。`fetchCVEs()` 在三個回傳路徑（快取命中、增量更新、全量查詢）都會以 `_filterFromStart()` 過濾掉 `published < coverageStart` 的項目，因此**呼叫端（CLI／Web 代理）拿到的 `cves` 已經是裁切過的**，不需再自行依年份過濾一次。唯一例外是 `web-client.src.html` 的「直連模式」（無 server proxy、無快取、無日期分段查詢時的 fallback），那裡仍保留 `getFullYear()` 年份過濾，因為該路徑根本沒有經過 `nvd-client.js`。嚴重度（`MIN_SEVERITY`）則維持在呼叫端過濾，因為快取必須保留全部嚴重度的 CVE，才能讓未來更低門檻的查詢直接複用快取而不漏資料。

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

**`GET /api/cve-data?q=<text>`**：CVE 查詢頁籤用，直接讀本機 `data/` 目錄已快取的 CVE（`kw_*.json`/`cpe_*.json`），**不會對 NVD 發出任何請求**。`q`（trim 後需 ≥ 2 字元，否則 400）比對 `cacheKey` 子字串或任一 `cve.cve.id` 子字串，大小寫不分。用 `Array.isArray(parsed.cves)` 排除 `cpekw_*.json`（CPE 查找快取，schema 是 `{products}` 不是 `{cves}`）。`CACHE_DISABLE=true` 時 `_cacheDir` 為 `null`，直接回傳空結果。回傳的 `cves` 為原始 NVD 物件，嚴重度/CVSS 留給前端用已注入的 `getCvss()` 計算（沿用 `/api/scan` 的分工慣例：server 只管資料存取，relevance/版本邏輯留在 `lib/cve-logic.js` 與前端）。

**CSP**：每次請求產生隨機 nonce，注入頁面設定 `Content-Security-Policy: script-src 'nonce-...'`。`_bundle.js` 不含 `NIST_API_KEY`（刻意排除）；`PORTABLE_N` bundle 時僅保留 `{name, version}`，不含 publisher。

## 檔案結構

```
lib/cve-logic.js          — CVE 業務邏輯（唯一來源）
lib/report-html.js        — HTML 報表產生（唯一來源）
lib/nvd-client.js         — NVD API 客戶端（快取 + 日期分段 + 增量更新，唯一來源）
data/                     — 本機 CVE 快取（kw_<name>.json / cpe_<vendor>_<product>.json）+ CPE 查找快取（cpekw_<name>.json），自動建立
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

## MCP 伺服器（`.mcp.json`）

- `context7`：查詢函式庫/框架最新文件（本專案無外部套件依賴，主要用於查 Node.js 內建 API 行為）。
- `playwright`（Edge）：可用於實際開啟 `scripts/web-client.html` 操作驗證 Web 介面功能。
