# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 專案執行原則

### 1. 所有的交談都以繁體中文為主。
### 2. 每當討論出架構決策或注意事項，立即更新本文件的對應章節，不要等到對話結束才整理。
### 3. 程式碼、函式庫應用繁體中文記錄註解，讓使用者知道這段程式碼用途。
### 4. Node.js 請使用原生功能，不要使用任何需額外下載之套件。



## 執行方式

```bash
# 直接掃描 PC Registry（所有預設值：HIGH 以上、近 5 年）
# 注意：Registry 掃描僅支援 Windows
node cve-checker.js
npm start          # 等同上述指令

# 快速測試（HIGH 以上、最多 5 筆軟體）
node cve-checker.js -1 HIGH 5

# 使用預先產生的 JSON 檔案作為輸入（跨平台）
node cve-checker.js scan.json

# 完整參數格式：[FILE] [MIN_SEVERITY] [LIMIT] [MIN_YEAR]
node cve-checker.js -1 HIGH 5 2020
node cve-checker.js scan.json -1 -1 2020   # -1 代表使用該參數的預設值

# 顯示說明（usage 摘要在每次啟動時都會印出；--help 僅讓程式提早結束）
node cve-checker.js --help

# npm 快速指令（package.json 定義）
npm start           # 等同 node cve-checker.js
npm run check       # 等同 node cve-checker.js -1 HIGH 5
npm run bundle      # 等同 node web/build.js（重新打包 web/web-client.html + .env.local → web/_bundle.js）
npm run web         # 自動執行 node web/build.js 再啟動 node web/web-server.js（preweb hook）
```

不需要執行 `npm install`，程式僅使用 Node.js 內建模組（`fs`、`path`、`os`、`child_process`、`crypto`、內建 `fetch`）。Node.js 最低版本需求：**18.0.0**。

**輸出**：`report/vik_result_YYYYMMDD.html`（視覺化報表）與 `report/vik_result_YYYYMMDD.json`（供 team-report.js 讀取）。`report/` 目錄由程式自動建立，無需手動建立。`logs/` 目錄亦由 `web-server.js` 啟動時自動建立。

## team-report.js（團隊彙整報表）

```bash
# 讀取 .\team 目錄中所有 JSON，產生綜合報表至 .\report
node team-report.js

# 可選：指定自訂 team 目錄路徑
node team-report.js C:\scans\team
```

工作流程：
1. 各機器執行 `node cve-checker.js` 或 `findSW.ps1` → 產生 `vik_result_YYYYMMDD.json`
2. 將各機器的 `vik_result_YYYYMMDD.json` 複製至 `.\team` 目錄
3. 執行 `node team-report.js` → 產生 `.\report\team_YYYYMMDD.html`

**注意**：`team-report.js` 現在與 `cve-checker.js` 同樣從 `lib/cve-logic.js` 引用 `compareVersions()` 與 `isSafeVersion()`。若修改版本比較邏輯，只需更新 `lib/cve-logic.js` 一處。

**team-report.js 彙總報表結構：**
- **機器總覽表**：各機器的 CVE 日期範圍（格式 `YYYY/01/01~YYYY/MM/DD`）、軟體總計、掃描數、有弱點數、CVE 數、狀態
- **跨機器需升級軟體彙整**：依受影響機器數排序，顯示每台機器的版本
- **各機器詳細結果**：每台機器的 meta 資訊列、軟體概覽表、**可展開的 CVE 詳細清單**（每筆有弱點軟體各一個 `<details>` 折疊區塊，含 CVE ID/連結、嚴重度、CVSS 版本、描述、安全版本、建議列）

## findSW.ps1

在遠端 Windows 機器上產生輸入 JSON：

```powershell
powershell -ExecutionPolicy Bypass -File findSW.ps1
# 預設輸出：scan.json（UTF-8，無 BOM）

# 可選參數
powershell -ExecutionPolicy Bypass -File findSW.ps1 -Username "john" -OutputPath "C:\scan.json"
```

**與內建 Registry 掃描器的一致性**：兩者均只收錄同時具有 `DisplayName` 和 `DisplayVersion` 的項目，確保掃描結果一致。這樣可自動排除 Windows KB 更新（僅有 `DisplayName` 但無 `DisplayVersion`），避免無意義的 NVD 查詢。

## .env.local 設定

所有環境設定存放於 **`.env.local`**（此檔案不應提交至版本控制；請參考 `.env.local.example`）。程式啟動時以內建解析器讀取（`loadEnv()`，無需 `dotenv` 套件）。

### Proxy（企業環境）

```
HTTPS_PROXY=http://proxy.company.com:8080
```

Node.js 內建 `fetch()`（底層 undici）不自動讀取系統 Proxy 設定，必須明確設定。程式優先讀取 `.env.local` 的 `HTTPS_PROXY`，其次 `HTTP_PROXY`，再其次系統環境變數。支援需要帳密驗證的格式：`http://user:password@proxy:port`。**注意**：程式實際使用 Node.js 內建 `http`＋`tls` 模組透過 CONNECT 建立隧道（`_makeProxyFetch()`），並非 undici 原生 Proxy 支援。

若 Proxy 進行 SSL Inspection（自簽憑證）導致 TLS 驗證失敗，可設定：

```
PROXY_SKIP_TLS_VERIFY=true
```

### NIST NVD API Key

```
NIST_API_KEY=your-api-key-here
```

未設定 Key 時仍可運作，但速率限制較嚴（每次請求間隔 6.5 秒；有 Key 則為 0.7 秒）。API Key 必須透過 HTTP **header** `apiKey:` 傳送（不可放 query param，否則 NVD 回傳 HTTP 404）。HTTP 429 時自動等待 15 秒後重試，最多 3 次。

### 每次查詢最大 CVE 筆數（MAX_CVES_PER_SOFTWARE）

```
MAX_CVES_PER_SOFTWARE=50
```

NVD 回傳順序為發布日期由新至舊，若設定過低可能遺漏較舊的 CVE。

### Portable 功能總開關（PORTABLE_ENABLE）

```
PORTABLE_ENABLE=true
```

`false` = 完全停用 Portable 功能：即使設定了 `PORTABLE_N`，也不會掃描；Web 介面亦隱藏輸入區塊。預設 `true`。

### 掃描模式（PORTABLE_ONLY）

```
PORTABLE_ONLY=false
```

`true` = 只掃描 `PORTABLE_N` 定義的軟體，略過 Registry / JSON 檔案中的項目（Registry 仍會讀取以取得 hostname/username）。`false` = 掃描全部（預設）。`PORTABLE_ENABLE=false` 時此設定無效。

### 白名單（WHITELIST）

```
WHITELIST=Microsoft,Apple,Google
```

逗號分隔，不分大小寫部分比對 `publisher` 欄位。亦可沿用 `whitelist.txt`（兩者並存時自動合併去重，env 項目優先）。

### 免安裝 / 未登錄軟體（PORTABLE_N）

```
PORTABLE_0=Eclipse IDE|202506|Eclipse Foundation
PORTABLE_1=Apache Maven|3.8.6|Apache Software Foundation
PORTABLE_2=Node.js|24.15.0|OpenJS Foundation
PORTABLE_3=Neo4j Community Edition|2025.05.0|Neo4j Inc
```

格式：`軟體名稱|版本|發行商`（版本與發行商可省略）。編號從 0 連續遞增，遇到第一個缺口即停止讀取。這些項目**跳過白名單與 SKIP_PATTERNS**，並透過 CPE API 查找精確識別碼，直接納入 NVD 掃描，計入 `report.summary.totalSoftware`。

## 架構說明

### 共通邏輯模組：`lib/cve-logic.js`

**修改 CVE 業務邏輯時，只需編輯 `lib/cve-logic.js` 一個檔案。**

`lib/cve-logic.js` 是所有 CVE 處理邏輯的唯一來源，包含：`SEVERITY_ORDER`、`compareVersions`、`isSafeVersion`、`getCvss`、`findAllCPEBases`、`cveMatchesCPEBase`、`cveRelevanceCheck`、`cveExactVersionCheck`、`_cpeWords`、`_matchInRange`、`isVersionInAnyRange`、`extractFixedVersion`、`getRecommendedVersion`、`extractAllRanges`（共 14 個匯出）。

- **`cve-checker.js`**：`require('./lib/cve-logic')` 引入
- **`team-report.js`**：`require('./lib/cve-logic')` 引入
- **`web/web-client.html`**：由 `node web/build.js` 將 `lib/cve-logic.js` 完整內嵌（**build artifact，勿直接編輯**）
- **`web/web-client.src.html`**：Web 端的模板原始碼，含 `// @@CVE_LOGIC@@` 注入標記

**修改流程**：編輯 `lib/cve-logic.js` → 執行 `node web/build.js` → `web-client.html` 與 `_bundle.js` 自動更新。

### 共通報表模組：`lib/report-html.js`

**修改報表 HTML 產生邏輯時，只需編輯 `lib/report-html.js` 一個檔案。**

`lib/report-html.js` 匯出單一函式 `buildHTMLReport(report)`：純函式，接收 report 物件，回傳完整 HTML 字串，無任何 I/O 或 Node.js 專屬 API。CLI 與 Web 版報表由此函式統一產生，確保格式一致。

- **`cve-checker.js`**：`generateHTML(report, outputPath)` 內部 `require('./lib/report-html')` 取得 `buildHTMLReport`，產生 HTML 後寫入檔案。
- **`team-report.js`**：**不使用**（team 報表有獨立的 HTML 產生邏輯）。
- **`web/web-client.html`**：由 `node web/build.js` 將 `lib/report-html.js` 完整內嵌（**build artifact，勿直接編輯**）
- **`web/web-client.src.html`**：含 `// @@REPORT_HTML@@` 注入標記，位於 `// @@CVE_LOGIC@@` 之後（注入順序重要：report-html.js 依賴 cve-logic.js 的 `isSafeVersion`，瀏覽器中後者需先定義於作用域）

`lib/report-html.js` 的依賴解析方式：
```js
// Node.js：require 取得；瀏覽器：@@CVE_LOGIC@@ 已注入，typeof isSafeVersion 非 undefined
const _isSafeVersion =
    typeof isSafeVersion !== 'undefined'
        ? isSafeVersion
        : require('./cve-logic').isSafeVersion;
```

**修改流程**：編輯 `lib/report-html.js` → 執行 `node web/build.js` → `web-client.html` 與 `_bundle.js` 自動更新。

### CLI 主程式：`cve-checker.js`

### 資料流程

```
Windows Registry  ──┐
                     ├─► softwares[]  ──► 白名單過濾  ──► SKIP_PATTERNS 過濾
findSW.ps1 JSON  ──┘                                    ──► cleanProductName 去重
                                                         ──► NVD CVE API 查詢（速率限制）
PORTABLE_N       ──────────────────────────────────────► NVD CPE API → NVD CVE API
                                                         ──► 關聯性檢查 → HTML/JSON 報表
```

### 輸入 JSON 格式（`scan.json` 為範例參考檔）

```json
{
  "generatedAt": "2026-05-14T12:49:39.741Z",
  "hostname": "MACHINE-NAME",
  "username": "user",
  "ip": "192.168.1.100",
  "softwares": [
    { "name": "App Name", "version": "1.0.0", "publisher": "Vendor", "installDate": null, "installPath": null }
  ]
}
```

`ip` 為選填欄位，Registry 掃描時由 `getLocalIP()` 自動填入；`findSW.ps1` 產生的 JSON 通常不含此欄位（顯示為 `?`）。

### 主要處理階段

1. **資料來源** — `getInstalledSoftware()` 依輸入來源走兩條路徑：有指定 JSON 檔時以 `JSON.parse(fs.readFileSync(file))` 讀取；否則執行內嵌的 PowerShell 腳本讀取 Windows Registry（將暫存 `.ps1` 以 UTF-8 BOM 寫入，透過 `Buffer.from([0xEF,0xBB,0xBF])` 避免編碼問題）。

2. **三層過濾（Registry/JSON 項目，查詢前）**
   - `matchWhitelist()`：略過 `publisher` 欄位符合白名單關鍵字的軟體
   - `shouldSkip()`：`SKIP_PATTERNS` 正則過濾子元件（VC++ Runtime 子項、Office Click-to-Run 元件、Python 子安裝項）
   - `cleanProductName()` 去重：去除版本號/架構字串後，名稱相同的多筆 Registry 項目合併為一次查詢

   若 `PORTABLE_ONLY=true`，Registry/JSON 項目略過此步驟（不加入 queryMap）。`report.summary.totalSoftware` = Registry/JSON 軟體數（PORTABLE_ONLY 時為 0）+ Portable 數。

3. **Portable 軟體 CPE 查找** — 每筆 `PORTABLE_N` 項目先呼叫 `lookupCPEs(keyword)` 查詢 NVD CPE API，再由 `findAllCPEBases(products, nameWords)` 收集**所有符合**的 `{vendor, product}` 組合，回傳陣列。比對分三個 Pass：
   - **Pass 0**：vendor 欄位單獨即含所有關鍵字（例如 `putty:putty` 的 vendor `putty` 含 `putty`）
   - **Pass 1**：vendor + product 合併後含所有關鍵字（例如 `simon_tatham:putty` 的 `simon tatham putty` 含 `putty`）
   - **Pass 2**（fallback）：僅在前兩 Pass 皆無結果時啟動，以關鍵字第一個字在 product 中比對（避免對「Neo4j Community Edition」等多字詞名稱過度剔除）

   結果陣列存入 `cpeBases`，首項（最優先）另存 `cpeBase = cpeBases[0]` 供版本提取使用；未找到任何 CPE 時降級為關鍵字比對。

   **設計理由**：NVD 對同一軟體可能以多個 vendor 名稱登記（例如 PuTTY 同時有 `cpe:2.3:a:putty:putty:*` 與 `cpe:2.3:a:simon_tatham:putty:*`）。若只取單一 CPE，可能遺漏以另一 vendor 名稱登記的 CVE。收集全部後以 OR 邏輯比對，確保兩種命名方式均能命中。

4. **NVD CVE API** — `searchCVEs(keyword)` 呼叫 NVD CVE API，參數：`keywordSearch`、`resultsPerPage=MAX_CVES_PER_SOFTWARE`、`noRejected`。**注意**：`pubStartDate` 必須與 `pubEndDate` 成對使用，否則 NVD 回傳 HTTP 404；且 **NVD API 強制限制日期範圍上限為 120 天**，超過亦回 HTTP 404，因此無法以 `pubStartDate=YYYY-01-01` 搭配今日日期的方式過濾年份（實際範圍常逾千天）。年份過濾以 `minYear` 在客戶端進行，為刻意設計而非遺漏。

5. **關聯性檢查（兩種模式）+ 精確版本過濾**
   - **Portable 軟體**（有 `cpeBases`）：`cveMatchesCPEBase(cve, bases)` 驗證 CVE CPE 條目中是否含任一 `:vendor:product:`（OR 邏輯）。回傳 `true`（至少一個符合）、`false`（確認均不符）或 `null`（無 CPE 資料，同樣過濾）。
   - **Registry 軟體**（無 `cpeBases`）：`cveRelevanceCheck(cve, searchName)` 驗證搜尋名稱的所有字詞是否都出現在 CPE 條目中。
   - 前述兩項通過後，再執行 `cveExactVersionCheck(installedVersion, cve, searchName, cpeBase)`：若 CVE 的 CPE 設定**全部為精確版本比對**（無 `versionEndExcluding`/`versionStartIncluding` 等範圍欄位），且已安裝版本不在受影響清單中，則同樣判為不符。
   - 關聯性函式回傳值處理原則：`true` = 確認相關，保留；`false` = 確認不符，過濾；`null` = 無 CPE 資料（NVD 未完成 enrichment），**同樣過濾**。三種 non-true 結果（`false` 與 `null`）一律列入 `mismatchedCVEs`，**不計入弱點統計，也不在任何報表或 log 中顯示**；資料仍保存於 JSON 供後續處理。
   - **`null` 過濾的設計理由**：NVD `keywordSearch` 會比對 CVE 描述全文，單字詞如 `bruno` 可能命中無關軟體（例如作者名「Bruno Cavalcante」）。無 CPE 資料時無法驗證相關性，保留反而產生大量誤報，故與 CPE 不符情況一律過濾。

6. **版本邏輯**
   - `extractFixedVersion(cve, searchName, cpeBase)`：讀取 `configurations[].nodes[].cpeMatch[]`；`versionEndExcluding` → `op: ">="`, `versionEndIncluding` → `op: ">"`。
   - `isSafeVersion(installed, rec)`：使用 `compareVersions()`（數字分段比對）。

7. **升級狀態判斷** — 優先順序如下：
   - ✗ 需要升級：有 `recommendedVersion` 且已安裝版本不足
   - ? 請手動確認：已安裝版本達到 `recommendedVersion`，但**同批 CVE 中有任何一筆 `fixedVersion === null`**；或完全無 `recommendedVersion`
   - ✓ 無須升級：有 `recommendedVersion`、版本達到要求，且**所有 CVE 均有明確修復版資訊**

8. **HTML 報表** — `generateHTML(report, outputPath)` 呼叫 `lib/report-html.js` 的 `buildHTMLReport(report)` 產生 HTML 字串後寫入檔案。CLI 與 Web 版使用同一份模板邏輯，格式完全一致。

   **報表區塊順序：**
   1. Header 儀表板（CVE 日期範圍格式 `YYYY/01/01~YYYY/MM/DD`）
   2. 升級建議摘要表（有弱點在前、無弱點在後）
   3. CVE 詳細資訊（可折疊，依發布日期由新至舊排列）
   4. 白名單略過 / SKIP_PATTERNS 略過 / 重複去除

### report 物件結構

```
report.generatedAt    — 報表產生時間（ISO 8601）
report.source         — 資料來源字串（"Windows Registry" 或 "File: /path"）
report.hostname / .ip / .username — 主機資訊（ip 讀自輸入 JSON，可能為空字串）
report.scanDate       — 輸入 JSON 的 generatedAt（Registry 模式同 report.generatedAt）
report.minSeverity / .minYear — 本次掃描參數
report.summary.{totalSoftware, queriedSoftware, affectedSoftware, totalCVEs}
report.results[]      — 有 CVE 的軟體（含 recommendedVersion、cpeBase、cveCount、cves[]、mismatchedCVEs[]）
report.cleanResults[] — 已掃描但無 CVE 超過門檻的軟體（含 cpeBase、mismatchedCVEs[]）
report.errors[]       — NVD API 查詢失敗的項目（含 name、error 欄位）
report.whitelisted[]  — 被白名單略過（含 matchedRule 欄位）
report.skippedByPattern[] — 被 SKIP_PATTERNS 略過
report.skippedByDedup[]   — 被合併至其他條目（含 mergedAs 欄位）
```

`cpeBase`（僅 Portable 軟體有值）：`{ vendor: string, product: string }`，對應 CPE API 查找到的精確識別碼。

`cves[]` 每筆項目含：`id、published、lastModified、severity、cvssScore、cvssVersion、description、fixedVersion、url`，以及 `cpeRelevant`（`true`=確認相關、`false`=確認不符、`null`=無 CPE 資料）。

### 參數對照表

| 位置 | 名稱 | 有效值 | 預設值 |
|------|------|--------|--------|
| `args[0]` | FILE | 檔案路徑 \| `-1` \| 省略 | PC Registry |
| `args[1]` | MIN_SEVERITY | LOW/MEDIUM/HIGH/CRITICAL \| `-1` | HIGH |
| `args[2]` | LIMIT | N \| `-1` | 不限 |
| `args[3]` | MIN_YEAR | YYYY \| `-1` | 當年 −5 |

**重要**：`args[0]` 是 FILE 而非 severity。若直接傳入 severity 名稱（如 `node cve-checker.js HIGH`），程式會偵測到並提示正確用法（`node cve-checker.js -1 HIGH`），然後結束。

**MIN_YEAR 注意（已知程式碼 bug）**：`main()` 第 885 行將 `-1` 對應至 `currentYear − 5`（與省略相同），並非「不限年份」。但 `printUsage` 明確範例 `node cve-checker.js -1 -1 -1 -1  # 不限年份` 與此行為矛盾，屬於程式碼邏輯與使用者說明不符的 bug，而非單純文件錯誤。修正方式：將 `main()` 中 `minYearRaw === -1 ? new Date().getFullYear() - 5 : minYearRaw` 改為 `minYearRaw === -1 ? null : minYearRaw`，並在後續年份過濾邏輯中處理 `null`（跳過過濾）。

### whitelist.txt 格式（向下相容）

```
# 井號開頭為註解
Microsoft
Apple
```

每行一個廠牌關鍵字；不分大小寫部分比對軟體的 `publisher` 欄位。建議改用 `.env.local` 的 `WHITELIST=` 設定；兩者並存時自動合併去重（env 優先）。

## Claude Code 內建指令

在 Claude Code 中以 `/` 前綴呼叫的內建 skill（定義於 `.claude/skills/`）：

| 指令 | 用途 |
|------|------|
| `/code-verify` | 確認 Node.js 版本、三支 JS 語法正確、`team-report.js` 可執行，及 `cve-checker.js` / `web-server.js` 的 v18+ API 使用情況 |
| `/code-security` | 靜態安全分析（XSS、命令注入、路徑遍歷等）並評估 Node.js 現代化程度 |
| `/project-document` | 根據 `*.js` 實際程式碼狀態，同步更新 `README.md`、`CLAUDE.md`、`docs/operator.html` |

## web/web-server.js（Web 伺服器）

```bash
node web/web-server.js          # 預設 Port 8093
node web/web-server.js 9000     # 自訂 Port（位置引數優先）
PORT=9000 node web/web-server.js  # 或以環境變數指定
npm run web                     # 同上（package.json 捷徑）
```

啟動後自動顯示本機與區域網路 IP，其他使用者可直接透過瀏覽器連線，無需安裝任何軟體。僅使用 Node.js 內建模組（`http`、`fs`、`path`、`os`、`crypto`）。

### web-server.js 架構

**NDJSON 代理（`POST /api/scan`）**：接受 `{ keywords: string[], maxCves: number, meta: object }`，串流回應每筆 NVD 查詢結果（`application/x-ndjson`）。第一行回傳 `{ sid }` session ID；後續每行為 `{ keyword, data }` 或 `{ keyword, error }`；串流結束代表掃描完成。採用此設計的原因：舊版的 per-request 代理因 NVD 6.5 秒延遲超過 keep-alive 逾時，導致 socket 被複用時拋出 TypeError，NDJSON 單一長連線可規避此問題。

**全域速率限制佇列**：`nvdSlot()` 以 Promise 鏈確保所有並行 session 共用同一個 NVD 請求計時器（`_nvdLastAt`），任何時刻合計請求速率不超過 `REQUEST_DELAY`。

**頁面注入**：伺服器以 `require('./_bundle')` 載入頁面內容與非敏感設定（`web/_bundle.js` 由 `web/build.js` 預先打包自 `web/web-client.html` 與根目錄 `.env.local`，不含 `NIST_API_KEY`）。每次請求產生隨機 nonce（`crypto.randomBytes`），於 `</body>` 前注入帶 nonce 的 `<script>`，設定 `window.__NVD_PROXY__`、`window.__NVD_DELAY__`，並預填 `PORTABLE_N`、`WHITELIST`、隱藏 API Key 欄位。回應同時附帶 `Content-Security-Policy: script-src 'nonce-...'` 與 `X-Content-Type-Options: nosniff` 標頭。修改 `web-client.html` 或 `.env.local` 後須執行 `node build.js`（`npm run web` 已自動執行）。

**每日滾動日誌**：所有請求與 NVD 查詢進度寫入 `logs/server_YYYYMMDD.log`（append），日期變更時自動切換新檔。

## web/web-client.html（瀏覽器端 Web 掃描器）

單一 HTML 檔案，無需任何後端或 Node.js，直接用瀏覽器開啟即可使用。

```
直接開啟：在 Windows Explorer 雙擊 web/web-client.html
或放置於任何靜態網頁伺服器
```

功能：
- 上傳 `scan.json`（由 `cve-checker.js` 或 `findSW.ps1` 產生）
- 設定 NIST API Key（可選，設定後速率由 6.5 秒/次加快至 0.7 秒/次）
- 設定白名單、最低嚴重度、年份範圍
- 掃描進度即時顯示（可中途取消）
- 下載 `result.html`（視覺化報表，與 CLI 版格式相同）和 `result.json`

報表由 `lib/report-html.js` 的 `buildHTMLReport()` 產生，與 CLI 版格式完全相同（同一份程式碼）。`result.json` 亦與 CLI 版報表格式相容。

**注意事項：**
- 需要瀏覽器能直接連線 `services.nvd.nist.gov`（若遇 CORS 錯誤，表示網路限制，需改用 `web-server.js` 代理模式）
- 不支援 Registry 直接掃描（需透過 scan.json 輸入）；不支援 `PORTABLE_ONLY` 模式與 `.env.local` 的 `PORTABLE_N` 設定（UI 中的「免安裝軟體」列表可手動補充，掃描前自動進行 CPE API 查找，關聯性比對邏輯與 CLI 一致）
- 所有設定（API Key、白名單等）自動儲存於瀏覽器 localStorage

## 其他檔案

- `docs/operator.html` — 完整操作手冊（CLI 版 + Web 版合併，含 tree-view 側欄導覽）
- `scan.json` — 範例輸入檔，可用於測試（來自本機掃描結果）
- `findSW.ps1` — 在無法直接執行 Node.js 的遠端機器上產生掃描 JSON
- `lib/cve-logic.js` — 共通 CVE 業務邏輯（唯一來源，詳見上方架構說明）
- `lib/report-html.js` — 共通報表 HTML 產生邏輯（唯一來源，詳見上方架構說明）；匯出 `buildHTMLReport(report)`
- `web/` — 所有 Web 相關檔案集中於此：
  - `web/web-server.js` — Node.js HTTP 伺服器（讀取根目錄 `.env.local` 與 `logs/`）
  - `web/web-client.src.html` — Web 掃描器的**模板源碼**，含 `// @@CVE_LOGIC@@` 與 `// @@REPORT_HTML@@` 兩個注入標記；編輯此檔後執行 `node web/build.js`
  - `web/web-client.html` — 瀏覽器端 HTML 掃描器（可直接雙擊開啟）；**build artifact**，由 `web/build.js` 從模板 + `lib/cve-logic.js` + `lib/report-html.js` 產生，已納入 git 追蹤
  - `web/build.js` — 讀取 `web/web-client.src.html`，依序將 `lib/cve-logic.js`（注入 `@@CVE_LOGIC@@`）與 `lib/report-html.js`（注入 `@@REPORT_HTML@@`）內嵌為 `web/web-client.html`；再與根目錄 `.env.local` 非敏感設定打包為 `web/_bundle.js`（`NIST_API_KEY` 刻意排除）。**注意**：`PORTABLE_N` 打包時僅保留 `{ name, version }`，`publisher` 欄位不包含在 bundle 內，故 Web 介面預填的 Portable 清單不顯示發行商。
  - `web/_bundle.js` — 由 `web/build.js` 自動生成，供 `web/web-server.js` 以 `require()` 載入（不需手動編輯）。**已納入 git 追蹤**
