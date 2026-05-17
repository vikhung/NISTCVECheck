# NISTCVECheck

掃描 Windows 已安裝軟體（從 Registry 或預先產生的 JSON 檔案），並查詢 [NIST NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) 找出已知弱點，最終產生一份自包含的 HTML 報表。

## 系統需求

- Node.js 18 以上（建議使用 v18 LTS 或更新版本）
- Windows（即時 Registry 掃描需要；使用 JSON 檔案輸入則不限平台）
- 無需執行 `npm install`，僅使用 Node.js 內建模組

## 初始設定

複製 `.env.local.example` 為 `.env.local`，並依需求填寫：

```
# NIST NVD API Key（免費申請）
NIST_API_KEY=your-api-key-here

# 每個軟體最多取回的 CVE 筆數（預設 50）
MAX_CVES_PER_SOFTWARE=50

# true = 只掃描 PORTABLE_N 定義的軟體；false = 掃描全部（預設）
PORTABLE_ONLY=false

# 白名單（逗號分隔，符合 publisher 的軟體略過掃描）
WHITELIST=Microsoft,Apple,Google

# 免安裝/未登錄軟體（格式：名稱|版本|發行商）
PORTABLE_0=Eclipse IDE|202506|Eclipse Foundation
PORTABLE_1=Apache Maven|3.8.6|Apache Software Foundation
```

未設定 API Key 仍可正常運作，但速率限制較嚴（每次請求間隔 6.5 秒，有 Key 則為 0.7 秒）。免費申請：[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

## 使用方式

```bash
# 直接掃描本機 Registry（預設值：MEDIUM 以上、近 10 年）
node cve-checker.js

# 使用預先產生的 JSON 檔案
node cve-checker.js scan.json

# 完整語法：[FILE] [MIN_SEVERITY] [LIMIT] [MIN_YEAR]
node cve-checker.js -1 HIGH 5 2020
node cve-checker.js scan.json -1 -1 2020   # -1 代表使用該參數的預設值
```

| 參數 | 有效值 | 預設值 |
|---|---|---|
| `FILE` | 檔案路徑 \| `-1` \| 省略 | 本機 Registry |
| `MIN_SEVERITY` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` \| `-1` | `MEDIUM` |
| `LIMIT` | N \| `-1` | 不限 |
| `MIN_YEAR` | YYYY \| `-1` | 當年 − 10 |

報表輸出至 `report/` 目錄，同時產生 HTML 與 JSON 兩個檔案：

```
report/vik_result_YYYYMMDD.html   ← 視覺化報表
report/vik_result_YYYYMMDD.json   ← 供 team-report.js 讀取
```

## 彙總多台機器報表（team-report.js）

```bash
# 讀取 .\team 目錄中所有 JSON，產生彙總報表至 .\report
node team-report.js

# 或指定自訂 team 目錄
node team-report.js C:\scans\team
```

**工作流程：**

1. 各機器執行 `node cve-checker.js` 或 `findSW.ps1` → 產生 `vik_result_YYYYMMDD.json`
2. 將各機器的 JSON 複製至 `.\team` 目錄
3. 執行 `node team-report.js` → 產生 `.\report\team_YYYYMMDD.html`

彙總報表包含：機器總覽表、跨機器需升級軟體彙整、每台機器詳細結果（含可展開的 CVE 清單）。

## 在遠端機器產生掃描檔

在任意 Windows 機器上執行 `support/findSW.ps1`，產生輸入 JSON：

```powershell
powershell -ExecutionPolicy Bypass -File support\findSW.ps1
# 輸出位置：Desktop\esrm-scan.json

# 自訂使用者名稱或輸出路徑
powershell -ExecutionPolicy Bypass -File support\findSW.ps1 -EsrmUsername "john" -OutputPath "C:\scan.json"
```

將產生的 `.json` 複製回來後，作為第一個參數傳入 `cve-checker.js` 即可。

## 白名單設定

在 `.env.local` 中設定 `WHITELIST=Microsoft,Apple,Google`（逗號分隔）。比對不分大小寫，支援部分比對 `publisher` 欄位。

亦可沿用 `whitelist.txt`（向下相容），兩者並存時自動合併去重（env 優先）。

## 免安裝 / 未登錄軟體

在 `.env.local` 中設定 `PORTABLE_N`，可將未寫入 Registry 的軟體納入掃描：

```
PORTABLE_0=Eclipse IDE|202506|Eclipse Foundation
PORTABLE_1=Apache Maven|3.8.6|Apache Software Foundation
PORTABLE_2=Node.js|24.15.0|OpenJS Foundation
```

格式：`名稱|版本|發行商`（版本與發行商可省略）。這些項目跳過白名單與子元件過濾，並透過 NVD CPE API 查找精確的 `vendor:product` 識別碼，以減少誤判。

若只想掃描 Portable 軟體而略過 Registry，可設定 `PORTABLE_ONLY=true`。

## 升級狀態判斷邏輯

報表中的狀態欄依以下優先順序判斷：

| 狀態 | 條件 |
|------|------|
| ✗ 需要升級 | 有已知修復版，但目前安裝版本未達到 |
| ? 請手動確認 | 目前版本已達修復要求，但**同批 CVE 中有部分無修復版資訊**；或所有 CVE 均無修復版 |
| ✓ 無須升級 | 有修復版，目前版本達到要求，且**所有 CVE 皆有明確修復版** |

> **注意**：若某 CVE 的 NVD 頁面僅列出特定版本受影響、而未標示「Up to (excluding)」範圍，代表 NVD 目前尚未記錄修復版本。此時即使安裝版本符合其他 CVE 的修復要求，整體狀態仍顯示「? 請手動確認」。

## 運作原理

1. 從 Registry 或 JSON 檔案載入軟體清單
2. 查詢 NVD API 前進行三層過濾，減少不必要的 API 呼叫：
   - **白名單**：略過 `publisher` 符合 `WHITELIST`（env）或 `whitelist.txt` 的軟體
   - **SKIP_PATTERNS**：略過已知子元件（VC++ Runtime 子項、Office Click-to-Run 元件、Python 子安裝項）
   - **去重**：去除版本號與架構字串後，名稱相同的多筆項目合併為一次查詢
3. **免安裝軟體**（`PORTABLE_N`）：跳過上述三層過濾，先呼叫 NVD CPE API 查找精確的 `cpe:2.3:a:{vendor}:{product}` 識別碼，再以關鍵字查詢 CVE
4. 每個唯一產品名稱向 NVD CVE API 發出查詢（最多取回 `MAX_CVES_PER_SOFTWARE` 筆，依發布日期由新至舊排列）
5. **關聯性檢查**：
   - Portable 軟體：驗證 CVE CPE 條目中是否含 `:vendor:product:`（精確比對）
   - Registry 軟體：驗證搜尋名稱的所有字詞是否出現在 CPE 條目中（關鍵字比對）
   - 不符者列入「可能誤判」區塊供使用者自行判斷，不計入弱點統計
6. 比對已安裝版本與 CPE 資料中的修復版本，判斷升級狀態
7. 產生 HTML 與 JSON 報表至 `report/vik_result_YYYYMMDD.html / .json`
