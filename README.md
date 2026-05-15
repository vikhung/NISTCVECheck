# NISTCVECheck

掃描 Windows 已安裝軟體（從 Registry 或預先產生的 JSON 檔案），並查詢 [NIST NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) 找出已知弱點，最終產生一份自包含的 HTML 報表。

## 系統需求

- Node.js 18 以上
- Windows（即時 Registry 掃描需要；使用 JSON 檔案輸入則不限平台）
- 無需執行 `npm install`，僅使用 Node.js 內建模組

## 初始設定

在專案根目錄建立 `.env.local`，填入 NIST NVD API Key：

```
NIST_API_KEY=your-api-key-here
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

HTML 報表輸出至 `report/cve-report-YYYY-MM-DD.html`。

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

在 `whitelist.txt` 中每行填入一個廠牌關鍵字，符合的軟體將略過掃描。比對不分大小寫，支援部分比對。

```
# 井號開頭為註解
Microsoft
Apple
```

## 運作原理

1. 從 Registry 或 JSON 檔案載入軟體清單
2. 查詢 NVD API 前進行三層過濾，減少不必要的 API 呼叫：
   - **白名單**：略過 `publisher` 符合 `whitelist.txt` 的軟體
   - **SKIP_PATTERNS**：略過已知子元件（VC++ Runtime 子項、Office Click-to-Run 元件、Python 子安裝項）
   - **去重**：去除版本號與架構字串後，名稱相同的多筆項目合併為一次查詢
3. 每個唯一產品名稱向 NVD CVE API 發出查詢
4. **CPE 關聯性檢查**：過濾誤判 CVE（產品名稱僅出現在描述文字，但未出現在 CPE 設定條目中）
5. 比對已安裝版本與 CPE 資料中的修復版本，判斷是否需要升級
6. 產生 HTML 報表至 `report/cve-report-YYYY-MM-DD.html`
