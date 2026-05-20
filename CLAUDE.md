# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

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

# 顯示說明
node cve-checker.js --help

# npm 快速指令（package.json 定義）
npm start           # 等同 node cve-checker.js
npm run check       # 等同 node cve-checker.js MEDIUM 5
```

不需要執行 `npm install`，程式僅使用 Node.js 內建模組（`fs`、`path`、`os`、`child_process`、`crypto`、內建 `fetch`）。Node.js 最低版本需求：**18.0.0**。

**輸出**：`report/vik_result_YYYYMMDD.html`（視覺化報表）與 `report/vik_result_YYYYMMDD.json`（供 team-report.js 讀取）。

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

**與內建 Registry 掃描器的差異**：`findSW.ps1` 只收錄同時具有 `DisplayName` 和 `DisplayVersion` 的項目；內建掃描器（`getInstalledSoftware()`）只要有 `DisplayName` 即收錄，`version` 可為空。因此兩者產出的軟體數量可能不同。

## .env.local 設定

所有環境設定存放於 **`.env.local`**（此檔案不應提交至版本控制；請參考 `.env.local.example`）。程式啟動時以內建解析器讀取（`loadEnv()`，無需 `dotenv` 套件）。

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

### 掃描模式（PORTABLE_ONLY）

```
PORTABLE_ONLY=false
```

`true` = 只掃描 `PORTABLE_N` 定義的軟體，略過 Registry / JSON 檔案中的項目（Registry 仍會讀取以取得 hostname/username）。`false` = 掃描全部（預設）。

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

所有邏輯集中於單一檔案：**`cve-checker.js`**。

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
  "softwares": [
    { "name": "App Name", "version": "1.0.0", "publisher": "Vendor", "installDate": null, "installPath": null }
  ]
}
```

### 主要處理階段

1. **資料來源** — `getInstalledSoftware()` 執行內嵌的 PowerShell 腳本（將暫存 `.ps1` 以 UTF-8 BOM 寫入，透過 `Buffer.from([0xEF,0xBB,0xBF])` 避免編碼問題）；或以 `JSON.parse(fs.readFileSync(file))` 讀取指定 JSON 檔案。

2. **三層過濾（Registry/JSON 項目，查詢前）**
   - `matchWhitelist()`：略過 `publisher` 欄位符合白名單關鍵字的軟體
   - `shouldSkip()`：`SKIP_PATTERNS` 正則過濾子元件（VC++ Runtime 子項、Office Click-to-Run 元件、Python 子安裝項）
   - `cleanProductName()` 去重：去除版本號/架構字串後，名稱相同的多筆 Registry 項目合併為一次查詢

   若 `PORTABLE_ONLY=true`，Registry/JSON 項目略過此步驟（不加入 queryMap）。`report.summary.totalSoftware` = Registry/JSON 軟體數（PORTABLE_ONLY 時為 0）+ Portable 數。

3. **Portable 軟體 CPE 查找** — 每筆 `PORTABLE_N` 項目先呼叫 `lookupCPEs(keyword)` 查詢 NVD CPE API，再由 `findBestCPEBase()` 從結果中找出最符合的 `{vendor, product}` 組合（優先全詞比對，次選首詞比對）。找到後記錄為 `cpeBase`，供後續關聯性檢查使用；未找到則降級為關鍵字比對。

4. **NVD CVE API** — `searchCVEs(keyword)` 呼叫 NVD CVE API，參數：`keywordSearch`、`resultsPerPage=MAX_CVES_PER_SOFTWARE`、`noRejected`。**注意**：`pubStartDate` 必須與 `pubEndDate` 成對使用，否則 NVD 回傳 HTTP 404；年份過濾改以 `minYear` 在客戶端篩選。

5. **關聯性檢查（兩種模式）**
   - **Portable 軟體**（有 `cpeBase`）：`cveMatchesCPEBase(cve, vendor, product)` 驗證 CVE CPE 條目中是否含 `:vendor:product:`。回傳 `true`（符合）、`false`（確認不符）或 `null`（無 CPE 資料，保留）。
   - **Registry 軟體**：`cveRelevanceCheck(cve, searchName)` 驗證搜尋名稱的所有字詞是否都出現在 CPE 條目中。
   - 回傳 `false` 的 CVE 列入 `mismatchedCVEs`（含 `mismatchReason`），不計入弱點統計，但在報表「可能誤判」區塊顯示。

6. **版本邏輯**
   - `extractFixedVersion(cve, searchName, cpeBase)`：讀取 `configurations[].nodes[].cpeMatch[]`；`versionEndExcluding` → `op: ">="`, `versionEndIncluding` → `op: ">"`。
   - `isSafeVersion(installed, rec)`：使用 `compareVersions()`（數字分段比對）。

7. **升級狀態判斷** — 優先順序如下：
   - ✗ 需要升級：有 `recommendedVersion` 且已安裝版本不足
   - ? 請手動確認：已安裝版本達到 `recommendedVersion`，但**同批 CVE 中有任何一筆 `fixedVersion === null`**；或完全無 `recommendedVersion`
   - ✓ 無須升級：有 `recommendedVersion`、版本達到要求，且**所有 CVE 均有明確修復版資訊**

8. **HTML 報表** — `generateHTML(report, outputPath)`：純字串樣板，無需外部套件。

   **報表區塊順序：**
   1. Header 儀表板（CVE 日期範圍格式 `YYYY/01/01~YYYY/MM/DD`）
   2. 升級建議摘要表（有弱點在前、無弱點在後）
   3. CVE 詳細資訊（可折疊，依發布日期由新至舊排列）
   4. 可能誤判的 CVE（含 `mismatchReason`）
   5. 白名單略過 / SKIP_PATTERNS 略過 / 重複去除

### report 物件結構

```
report.summary.{totalSoftware, queriedSoftware, affectedSoftware, totalCVEs}
report.results[]      — 有 CVE 的軟體（含 recommendedVersion、cpeBase、cves[]、mismatchedCVEs[]）
report.cleanResults[] — 已掃描但無 CVE 超過門檻的軟體（含 cpeBase、mismatchedCVEs[]）
report.whitelisted[]  — 被白名單略過（含 matchedRule 欄位）
report.skippedByPattern[] — 被 SKIP_PATTERNS 略過
report.skippedByDedup[]   — 被合併至其他條目（含 mergedAs 欄位）
```

`cpeBase`（僅 Portable 軟體有值）：`{ vendor: string, product: string }`，對應 CPE API 查找到的精確識別碼。

### 參數對照表

| 位置 | 名稱 | 有效值 | 預設值 |
|------|------|--------|--------|
| `args[0]` | FILE | 檔案路徑 \| `-1` \| 省略 | PC Registry |
| `args[1]` | MIN_SEVERITY | LOW/MEDIUM/HIGH/CRITICAL \| `-1` | HIGH |
| `args[2]` | LIMIT | N \| `-1` | 不限 |
| `args[3]` | MIN_YEAR | YYYY \| `-1` | 當年 −5 |

**重要**：`args[0]` 是 FILE 而非 severity。若直接傳入 severity 名稱（如 `node cve-checker.js HIGH`），程式會偵測到並提示正確用法（`node cve-checker.js -1 HIGH`），然後結束。

### whitelist.txt 格式（向下相容）

```
# 井號開頭為註解
Microsoft
Apple
```

每行一個廠牌關鍵字；不分大小寫部分比對軟體的 `publisher` 欄位。建議改用 `.env.local` 的 `WHITELIST=` 設定；兩者並存時自動合併去重（env 優先）。

## Claude Code 自訂指令

定義於 `.claude/commands/`，在 Claude Code 中以 `/` 前綴呼叫：

| 指令 | 用途 |
|------|------|
| `/verify` | 確認 Node.js 版本、`team-report.js` 可執行、`cve-checker.js` 語法正確，及 v18+ API 使用情況 |
| `/security-check` | 靜態安全分析（XSS、命令注入、路徑遍歷等）並評估 Node.js 現代化程度 |
| `/update-docs` | 依程式碼實際狀態同步更新 `README.md`、`CLAUDE.md`、`docs/operator.html` |

## web-server.js（Web 伺服器）

```bash
node web-server.js          # 預設 Port 8092
PORT=9000 node web-server.js  # 自訂 Port
npm run web                 # 同上（package.json 捷徑）
```

啟動後自動顯示本機與區域網路 IP，其他使用者可直接透過瀏覽器連線，無需安裝任何軟體。僅使用 Node.js 內建模組（`http`、`fs`、`path`、`os`）。

## web-client.html（瀏覽器端 Web 掃描器）

單一 HTML 檔案，無需任何後端或 Node.js，直接用瀏覽器開啟即可使用。

```
直接開啟：在 Windows Explorer 雙擊 web-client.html
或放置於任何靜態網頁伺服器
```

功能：
- 上傳 `scan.json`（由 `cve-checker.js` 或 `findSW.ps1` 產生）
- 設定 NIST API Key（可選，設定後速率由 6.5 秒/次加快至 0.7 秒/次）
- 設定白名單、最低嚴重度、年份範圍
- 掃描進度即時顯示（可中途取消）
- 下載 `result.html`（視覺化報表，與 CLI 版格式相同）和 `result.json`

報表結構與 `cve-checker.js` 的 `generateHTML()` 輸出相同，`result.json` 亦與 CLI 版報表格式相容。

**注意事項：**
- 需要瀏覽器能直接連線 `services.nvd.nist.gov`（若遇 CORS 錯誤，表示網路限制，需改用本機 CLI 版）
- 不支援 Portable 軟體（`PORTABLE_N`）與 Registry 直接掃描（需透過 scan.json 輸入）
- 所有設定（API Key、白名單等）自動儲存於瀏覽器 localStorage

## 其他檔案

- `docs/operator.html` — 操作員使用說明（HTML 格式）
- `scan.json` — 範例輸入檔，可用於測試（來自本機掃描結果）
- `findSW.ps1` — 在無法直接執行 Node.js 的遠端機器上產生掃描 JSON
