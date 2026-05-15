# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 執行方式

```bash
# 直接掃描 PC Registry（所有預設值：MEDIUM 以上、近 10 年）
node cve-checker.js

# 使用預先產生的 JSON 檔案作為輸入
node cve-checker.js scan.json

# 完整參數格式：[FILE] [MIN_SEVERITY] [LIMIT] [MIN_YEAR]
node cve-checker.js -1 HIGH 5 2020
node cve-checker.js scan.json -1 -1 2020   # -1 代表使用該參數的預設值
```

不需要執行 `npm install`，程式僅使用 Node.js 內建模組（`https`、`fs`、`path`、`os`、`child_process`）。Node.js 最低版本需求：18.0.0。

## support/findSW.ps1

在遠端 Windows 機器上產生輸入 JSON：

```powershell
powershell -ExecutionPolicy Bypass -File support\findSW.ps1
# 預設輸出：Desktop\esrm-scan.json（UTF-8，無 BOM）

# 可選參數
powershell -ExecutionPolicy Bypass -File support\findSW.ps1 -EsrmUsername "john" -OutputPath "C:\scan.json"
```

**與內建 Registry 掃描器的差異**：`findSW.ps1` 只收錄同時具有 `DisplayName` 和 `DisplayVersion` 的項目；內建掃描器（`getInstalledSoftware()`）只要有 `DisplayName` 即收錄，`version` 可為空。因此兩者產出的軟體數量可能不同。

## API Key 設定

NIST NVD API Key 存放於 **`.env.local`**（此檔案不應提交至版本控制）：

```
NIST_API_KEY=your-api-key-here
```

程式啟動時以內建解析器讀取此檔案（`loadEnv()`，無需 `dotenv` 套件）。未設定 Key 時仍可運作，但速率限制較嚴（每次請求間隔 6.5 秒）。API Key 必須透過 HTTP **header** `apiKey:` 傳送（不可放 query param，否則 NVD 回傳 HTTP 404）。

## 架構說明

所有邏輯集中於單一檔案：**`cve-checker.js`**。

### 資料流程

```
Windows Registry  ──┐
                     ├─► softwares[]  ──► 白名單過濾  ──► SKIP_PATTERNS 過濾
findSW.ps1 JSON  ──┘                                    ──► cleanProductName 去重
                                                         ──► NVD API 查詢（速率限制）
                                                         ──► HTML 報表
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

2. **三層過濾（查詢前）**
   - `matchWhitelist()`：略過 `publisher` 欄位符合 `whitelist.txt` 任意關鍵字的軟體（不分大小寫部分比對）
   - `shouldSkip()`：`SKIP_PATTERNS` 正則過濾子元件（VC++ Runtime 子項、Office Click-to-Run 元件、Python 子安裝項）
   - `cleanProductName()` 去重：去除版本號/架構字串後，名稱相同的多筆 Registry 項目合併為一次查詢

3. **NVD API** — `searchCVEs(keyword)` 呼叫 `https://services.nvd.nist.gov/rest/json/cves/2.0`，速率限制：有 Key 時每次請求間隔 700 ms（50 req/30 s）；無 Key 時 6500 ms（5 req/30 s）。

4. **CPE 關聯性檢查** — `cveRelevanceCheck(cve, searchName)` 從 `cve.configurations` 提取 CPE 條目字串，驗證搜尋名稱的所有字詞是否都出現在 CPE 中。回傳 `true`（符合）、`false`（不符，直接排除）或 `null`（無 CPE 資料，保留）。此機制防止關鍵字誤判（例如搜尋「GitHub」卻比對到描述中僅提及 GitHub 儲存庫的 Technicolor 設備 CVE）。

5. **版本邏輯**
   - `extractFixedVersion(cve)`：讀取 `configurations[].nodes[].cpeMatch[]`；`versionEndExcluding` → `op: ">="`, `versionEndIncluding` → `op: ">"`。回傳所有 CPE 比對中的最高版本。
   - `isSafeVersion(installed, rec)`：使用 `compareVersions()`（數字分段比對）檢查已安裝版本是否已滿足修復要求。

6. **HTML 報表** — `generateHTML(report, outputPath)`：純字串樣板，無需外部套件。輸出：`cve-report-YYYY-MM-DD.html`。區塊順序：儀表板統計、升級建議摘要表（有弱點軟體在前，無弱點在後）、可折疊 CVE 詳細資訊、白名單略過、SKIP_PATTERNS 略過、去重略過。

### report 物件結構

```
report.summary.{totalSoftware, queriedSoftware, affectedSoftware, totalCVEs}
report.results[]      — 有 CVE 的軟體（含 recommendedVersion、cves[]）
report.cleanResults[] — 已掃描但無 CVE 超過門檻的軟體
report.whitelisted[]  — 被 whitelist.txt 略過（含 matchedRule 欄位）
report.skippedByPattern[] — 被 SKIP_PATTERNS 略過
report.skippedByDedup[]   — 被合併至其他條目（含 mergedAs 欄位）
```

### 參數對照表

| 位置 | 名稱 | 有效值 | 預設值 |
|------|------|--------|--------|
| `args[0]` | FILE | 檔案路徑 \| `-1` \| 省略 | PC Registry |
| `args[1]` | MIN_SEVERITY | LOW/MEDIUM/HIGH/CRITICAL \| `-1` | MEDIUM |
| `args[2]` | LIMIT | N \| `-1` | 不限 |
| `args[3]` | MIN_YEAR | YYYY \| `-1` | 當年 −10 |

### whitelist.txt 格式

```
# 井號開頭為註解
Microsoft
Apple
```

每行一個廠牌關鍵字；不分大小寫部分比對軟體的 `publisher` 欄位。

## 其他檔案

- `docs/operator.html` — 操作員使用說明（HTML 格式）
- `scan.json` — 範例輸入檔，可用於測試（來自本機掃描結果）
