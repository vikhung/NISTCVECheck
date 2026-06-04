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
node cve-checker.js                        # 掃描本機 Registry
node cve-checker.js scan.json              # 使用 JSON 檔案輸入
node cve-checker.js -1 HIGH 5 2020        # 指定嚴重度/筆數/年份

# 彙總多台機器
node team-report.js                        # 讀取 .\team\ 目錄產生彙總報表

# Web 介面
npm run web                                # 啟動 Web 伺服器（預設 Port 8093）
```

| 參數 | 有效值 | 預設值 |
|---|---|---|
| `FILE` | 檔案路徑 \| `-1` \| 省略 | 本機 Registry |
| `MIN_SEVERITY` | `LOW` / `MEDIUM` / `HIGH` / `CRITICAL` \| `-1` | `HIGH` |
| `LIMIT` | N \| `-1` | 不限 |
| `MIN_YEAR` | YYYY \| `-1` | 當年 − 5 |

報表輸出至 `report/vik_result_YYYYMMDD.html`（視覺化）與 `report/vik_result_YYYYMMDD.json`（供 team-report.js 讀取）。

## CVE 過濾原則

掃描結果只保留「CPE 確認相關」的 CVE，以下情況會靜默過濾（不顯示於報表）：

- CVE 的 CPE 條目中不含搜尋軟體名稱的關鍵字
- CVE 只列出特定精確版本受影響，且已安裝版本不在其中
- CVE 尚無 CPE 資料（NVD 未完成 enrichment，無法驗證相關性）

> NVD 的關鍵字搜尋會比對 CVE 描述全文，可能命中無關結果（例如搜尋 `bruno` 時匹配到作者名「Bruno Cavalcante」的 WordPress 主題弱點）。無 CPE 資料時無法驗證相關性，因此一律過濾。

過濾掉的項目仍保存於 JSON 報表的 `mismatchedCVEs` 欄位，供進階使用者自行查閱。

## 完整操作說明

詳細設定（白名單、免安裝軟體、Web 伺服器、團隊彙整流程等）請參閱 [docs/operator.html](docs/operator.html)。
