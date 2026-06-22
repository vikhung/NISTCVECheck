# NISTCVECheck

掃描 Windows 已安裝軟體（從 Registry 或預先產生的 JSON 檔案），並查詢 [NIST NVD CVE API](https://nvd.nist.gov/developers/vulnerabilities) 找出已知弱點，最終產生一份自包含的 HTML 報表。

## 系統需求

- Node.js 18 以上
- Windows（即時 Registry 掃描需要；使用 JSON 檔案輸入則不限平台）
- 無需執行 `npm install`，僅使用 Node.js 內建模組

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
npm run check                                      # = node scripts/cve-checker.js -1 HIGH 3

# 彙總多台機器
node scripts/team-report.js                        # 讀取 .\team\ 目錄產生彙總報表

# Web 介面
npm run web                                # 啟動 Web 伺服器（預設 Port 8093，先自動執行 build.js）
npm run bundle                             # 單獨重新打包 web-client.html + .env.local

# 遠端機器產生 scan.json
powershell -ExecutionPolicy Bypass -File findSW.ps1
```

| 參數 | 有效值 | 預設值 |
|---|---|---|
| `FILE` | 檔案路徑 \| `-1` \| 省略 | 本機 Registry |
| `MIN_SEVERITY` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` \| `-1` | `HIGH` |
| `LIMIT` | N \| `-1` | 不限 |
| `MIN_YEAR` | YYYY \| `-1` | 當年 − 5 |

**注意**：`args[0]` 是 `FILE` 而非 severity；直接傳入 severity 字串程式會報錯提示。

**已知問題（MIN_YEAR）**：`-1` 實際對應「當年 − 5」（與省略相同），並非「不限年份」，與 `--help` 說明矛盾。

報表輸出至 `report/vik_result_YYYYMMDD.html`（視覺化）與 `report/vik_result_YYYYMMDD.json`（供 `scripts/team-report.js` 讀取），目錄自動建立。

## team-report.js 工作流程

1. 各機器執行 `node scripts/cve-checker.js` 或 `findSW.ps1` → 產生 `vik_result_YYYYMMDD.json`
2. 將各機器的 JSON 複製至 `.\team` 目錄
3. 執行 `node scripts/team-report.js`（可指定路徑，如 `node scripts/team-report.js C:\scans\team`）→ 產生 `.\report\team_YYYYMMDD.html`

## .env.local 設定

| 變數 | 說明 | 預設 |
|------|------|------|
| `NIST_API_KEY` | NVD API Key（有 Key：0.7s/req；無：6.5s/req） | — |
| `HTTPS_PROXY` / `HTTP_PROXY` | Proxy URL，支援 `http://user:pass@host:port` | — |
| `PROXY_SKIP_TLS_VERIFY` | `true` = 停用 TLS 驗證（SSL Inspection 環境） | false |
| `MAX_CVES_PER_SOFTWARE` | 每個軟體最多查詢幾筆 CVE（NVD 回傳由新至舊，過低會遺漏舊 CVE） | 50 |
| `PORTABLE_ENABLE` | `false` = 完全停用 Portable 功能 | true |
| `PORTABLE_ONLY` | `true` = 只掃描 `PORTABLE_N`，略過 Registry/JSON 項目 | false |
| `WHITELIST` | 逗號分隔廠牌關鍵字，比對 `publisher` 欄位。可與 `whitelist.txt` 並存（合併去重） | — |
| `PORTABLE_N` | 格式：`名稱\|版本\|發行商`（版本、發行商可省略）。從 0 連續遞增，遇缺口停止。略過白名單/SKIP_PATTERNS，走 CPE 精確查詢 | — |
| `CACHE_DISABLE` | `true` = 停用本機 CVE 快取（每次都直接查 NVD API） | false |
| `CACHE_ALIAS_N` | 格式：`canonical\|alias1\|alias2`。第一個為 canonical 名稱，其餘別名查詢時共用同一個快取檔案（`data/kw_<canonical>.json`）。從 0 連續遞增，遇缺口停止 | — |

範例：
```
PORTABLE_0=Eclipse IDE|202506|Eclipse Foundation
PORTABLE_1=Node.js|24.15.0|OpenJS Foundation
CACHE_ALIAS_0=maven|apache maven|apache-maven|mvn
```

## CVE 過濾原則

掃描結果只保留「CPE 確認相關」的 CVE，以下情況會靜默過濾（不顯示於報表）：

- CVE 的 CPE 條目中不含搜尋軟體名稱的關鍵字
- CVE 只列出特定精確版本受影響，且已安裝版本不在其中
- CVE 尚無 CPE 資料（NVD 未完成 enrichment，無法驗證相關性）

> NVD 的關鍵字搜尋會比對 CVE 描述全文，可能命中無關結果（例如搜尋 `bruno` 時匹配到作者名「Bruno Cavalcante」的 WordPress 主題弱點）。無 CPE 資料時無法驗證相關性，因此一律過濾。

過濾掉的項目仍保存於 JSON 報表的 `mismatchedCVEs` 欄位，供進階使用者自行查閱。

## 完整操作說明

詳細設定（白名單、免安裝軟體、Web 伺服器、團隊彙整流程等）請參閱 [docs/operator.html](docs/operator.html)。
