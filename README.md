# NISTCVECheck

掃描 Windows 已安裝軟體（從 Registry 或預先產生的 JSON 檔案），並查詢 [NIST NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) 找出已知弱點，最終產生一份自包含的 HTML 報表。

## 系統需求

- Node.js 18 以上
- Windows（即時 Registry 掃描需要；使用 JSON 檔案輸入則不限平台）
- 首次使用前執行一次 `npm install`（僅 `adm-zip` 一個套件，供 `npm run package` 產生部署 zip 用；一般掃描/Web 功能 100% 使用 Node.js 內建模組，不需要這個套件也能運作）

## 初始設定

複製 `.env.local.example` 為 `.env.local`，填入 NIST API Key（可選，未設定仍可運作，但速率限制較嚴）：

```
NIST_API_KEY=your-api-key-here
```

免費申請：[nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)

## 常用指令

```bash
# CLI 掃描
node scripts/cve-checker.js                        # 掃描本機 Registry
node scripts/cve-checker.js scan.json              # 使用 JSON 檔案輸入
node scripts/cve-checker.js -1 HIGH 5 2020        # 指定嚴重度/筆數/年份
npm start                                          # = node scripts/cve-checker.js
npm run check                                      # = node scripts/cve-checker.js -1 HIGH 4

# 彙總多台機器
node scripts/team-report.js                        # 讀取 .\team\ 目錄產生彙總報表

# Web 介面
npm run web                                # 啟動 Web 伺服器（預設 Port 8093，先自動執行 build.js）
npm run bundle                             # 單獨重新打包 web-client.html + .env.local

# 部署打包（壓成 zip 帶到公司環境；預設含 CVE 快取、排除機密/大型/建置產物）
npm run package                                    # → dist/NISTCVECheck_deploy_<date>.zip
node scripts/package-deploy.js --no-cache          # 乾淨部署（不含 CVE 快取，約 0.5 MB）
node scripts/package-deploy.js --with-node-modules # 連 node_modules 一起打包（離線環境免 npm install）

# 遠端機器產生 scan.json
powershell -ExecutionPolicy Bypass -File findSW.ps1
```

| 參數 | 有效值 | 預設值 |
|---|---|---|
| `FILE` | 檔案路徑 \| `-1` \| 省略 | 本機 Registry |
| `MIN_SEVERITY` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` \| `-1` | `HIGH` |
| `LIMIT` | N \| `-1` | 不限 |
| `MIN_YEAR` | YYYY \| `-1` | 當年 − 1 |

**注意**：`args[0]` 是 `FILE` 而非 severity；直接傳入 severity 字串程式會報錯提示。

**已知問題（MIN_YEAR）**：`-1` 實際對應「當年 − 1」（與省略相同），並非「不限年份」，與 `--help` 說明矛盾。

報表輸出至 `report/vik_result_YYYYMMDD.html`（視覺化）與 `report/vik_result_YYYYMMDD.json`（供 `scripts/team-report.js` 讀取），目錄自動建立。

## team-report.js 工作流程

1. 各機器執行 `node scripts/cve-checker.js` 或 `findSW.ps1` → 產生 `vik_result_YYYYMMDD.json`
2. 將各機器的 JSON 複製至 `.\team` 目錄
3. 執行 `node scripts/team-report.js`（可指定路徑，如 `node scripts/team-report.js C:\scans\team`）→ 產生 `.\report\team_YYYYMMDD.html`

## .env.local 設定

| 變數 | 說明 | 預設 |
|------|------|------|
| `NIST_API_KEY` | NVD API Key（有 Key：0.7s/req；無：6.5s/req） | — |
| `LOG_LEVEL` | `DEBUG` = 顯示除錯 log（目前為向 NVD 發出的完整 curl 查詢指令）；`INFO` = 不顯示 | INFO |
| `HTTPS_PROXY` / `HTTP_PROXY` | Proxy URL，支援 `http://user:pass@host:port` | — |
| `PROXY_SKIP_TLS_VERIFY` | `true` = 停用 TLS 驗證（SSL Inspection 環境） | false |
| `PORTABLE_ENABLE` | `false` = 完全停用 Portable 功能 | true |
| `PORTABLE_ONLY` | `true` = 只掃描 `PORTABLE_N`，略過 Registry/JSON 項目 | false |
| `WHITELIST` | 逗號分隔廠牌關鍵字，比對 `publisher` 欄位。可與 `whitelist.txt` 並存（合併去重） | — |
| `PORTABLE_N` | 格式：`名稱\|版本\|發行商`（版本、發行商可省略）。從 0 連續遞增，遇缺口停止。略過白名單/SKIP_PATTERNS，走 CPE 精確查詢 | — |
| `CACHE_DISABLE` | `true` = 停用本機 CVE 快取（每次都直接查 NVD API） | false |
| `CACHE_ALIAS_N` | 格式：`canonical\|alias1\|alias2`。第一個為 canonical 名稱，其餘別名查詢時共用同一個快取檔案（`data/cve_cache/kw_<canonical>.json`）。從 0 連續遞增，遇缺口停止 | — |
| `CPE_BASE_N` | 格式：`名稱\|vendor:product[\|vendor:product...]`。為「過於通用」的知名軟體（Python/Git 等）指定標準 CPE base，**跳過 CPE 字典查詢、直接以 `virtualMatchString` 精準查 CVE**（避免退化成關鍵字搜尋而漏報/誤報）。名稱不分大小寫，可列多個 base（OR）。從 0 連續遞增，遇缺口停止 | — |

範例：
```
PORTABLE_0=Eclipse IDE|202506|Eclipse Foundation
PORTABLE_1=Node.js|24.15.0|OpenJS Foundation
CACHE_ALIAS_0=maven|apache maven|apache-maven|mvn
CPE_BASE_0=python|python:python
CPE_BASE_1=git|git-scm:git|git:git
```

## 運作流程（概觀）

每個軟體大致經過三個步驟（完整流程圖見 [`docs/cve-flow.md`](docs/cve-flow.md)）：

1. **找 CPE**：用軟體名查 NVD CPE 字典，鎖定 `vendor:product`。一般軟體（scan.json／Registry）用「軟體名精確比對」避免多產品 vendor 爆量（例如 Webex 只鎖定 `cisco:webex`，不會一次查到 37 個 `webex_*`）；若在 `.env.local` 的 `CPE_BASE_N` 指定過，則直接使用該定義。
2. **查 CVE**：用上一步的 CPE 精準查弱點；找不到 CPE 或軟體名過於通用（如 Git/Python）時，改用關鍵字搜尋描述全文。
3. **補撈新弱點**：NVD 對剛公布的弱點常「尚在分析中」（還沒建立 CPE），這類會被 CPE 查詢漏掉，因此再補查一次關鍵字，把「確實指向本軟體」的新弱點併入，並標記 ⚠ NVD 分析中 供人工確認。

查詢結果會快取於 `data/`，**同一天內重複掃描不會重打 NVD**；隔天再掃只增量補抓異動部分（詳見流程圖文末說明）。

## CVE 過濾原則

掃描結果只保留「CPE 確認相關」的 CVE，以下情況會靜默過濾（不顯示於報表）：

- CVE 的 CPE 條目中不含搜尋軟體名稱的關鍵字
- CVE 只列出特定精確版本受影響，且已安裝版本不在其中
- CVE 尚無 CPE 資料（NVD 未完成 enrichment，無法驗證相關性）

> NVD 的關鍵字搜尋會比對 CVE 描述全文，可能命中無關結果（例如搜尋 `bruno` 時匹配到作者名「Bruno Cavalcante」的 WordPress 主題弱點）。無 CPE 資料時無法驗證相關性，因此一律過濾。

過濾掉的項目仍保存於 JSON 報表的 `mismatchedCVEs` 欄位，供進階使用者自行查閱。

## 資料格式

### 輸入 JSON（`scan.json`）

```json
{
  "generatedAt": "2026-05-14T12:49:39.741Z",
  "hostname": "MACHINE-NAME", "username": "user", "ip": "192.168.1.100",
  "softwares": [{ "name": "App Name", "version": "1.0.0", "publisher": "Vendor", "installDate": null, "installPath": null }]
}
```

### 輸出報表（JSON 報表根結構）

```text
report.{generatedAt, source, hostname, ip, username, scanDate, minSeverity, minYear}
report.summary.{totalSoftware, queriedSoftware, affectedSoftware, totalCVEs}
report.results[]      — 有 CVE（含 recommendedVersion、cpeBase、cveCount、cves[]、mismatchedCVEs[]）
report.cleanResults[] — 已掃描無 CVE（含 cpeBase、mismatchedCVEs[]）
report.errors[]       — API 失敗（含 name、error）
report.whitelisted[]  — 白名單略過（含 matchedRule）
report.skippedByPattern[] / skippedByDedup[] — 過濾/去重略過
```

`cves[]` 每筆：`id、published、lastModified、severity、cvssScore、cvssVersion、description、fixedVersion、alreadyFixed、affectedRanges、cpeRelevant、pendingNvdAnalysis、url`

### 本機快取（`data/`）

分兩個子目錄，避免兩種性質不同的快取混在同一層：

- `data/cve_cache/` — CVE 查詢快取：`kw_<sanitized>.json`（關鍵字查詢）或 `cpe_<vendor>_<product>.json`（CPE 精確查詢）
- `data/cpe_cache/` — CPE 字典查找快取：`cpekw_<sanitized>.json`

```json
// data/cve_cache/kw_nodejs.json
{ "cveCount": 42, "cacheKey": "kw_nodejs", "coverageStart": "2021-01-01T00:00:00.000Z", "lastFetchedAt": "2026-06-22T10:30:00.000Z", "cves": [ /* NVD vulnerabilities[] 原始物件陣列 */ ] }
```

```json
// data/cpe_cache/cpekw_putty.json
{ "productCount": 12, "cacheKey": "cpekw_putty", "fetchedAt": "2026-06-22T10:30:00.000Z", "products": [ /* NVD CPE products[] 原始物件陣列 */ ] }
```

`cveCount`/`productCount` 為描述性欄位，方便人工檢視檔案時不必數陣列長度。快取以「同一天」為單位：當天內已查過直接用快取；CVE 快取跨天會做增量更新（`lastModStartDate`），CPE 字典快取跨天則整批覆寫。`CACHE_DISABLE=true` 可停用所有本機快取。

## 專案結構

```
lib/cve-logic.js          — CVE 業務邏輯（唯一來源）
lib/report-html.js        — HTML 報表產生（唯一來源）
lib/nvd-client.js         — NVD API 客戶端（快取 + 日期分段 + 增量更新，唯一來源）
data/
  cve_cache/              — 本機 CVE 快取，自動建立
  cpe_cache/              — CPE 字典查找快取，自動建立
scripts/
  cve-checker.js          — CLI 主程式
  team-report.js          — 團隊彙整報表
  web-server.js           — HTTP 伺服器
  web-client.src.html     — Web 掃描器模板（含 @@CVE_LOGIC@@ / @@REPORT_HTML@@ 注入點）
  web-client.html         — build artifact（勿直接編輯）
  build.js                — 打包工具：模板 + lib/ → web-client.html + _bundle.js
  _bundle.js              — build artifact，供 web-server.js require()
findSW.ps1                — 遠端機器產生 scan.json
docs/
  operator.html                       — 完整操作手冊
  cve-flow.md                         — CVE 查找流程圖（Mermaid）+ 快取說明
  NISTCVECheck_CVE掃描流程圖.pptx      — CVE 掃描流程圖簡報
```

## 完整操作說明

詳細設定（白名單、免安裝軟體、Web 伺服器、團隊彙整流程等）請參閱 [docs/operator.html](docs/operator.html)。
