驗證專案目錄可執行程式碼(例如：*.js)是否都能正常執行，並確認輸出檔案格式正確。

---
name: code-verify
description: 當使用者要求驗證程式可執行、確認環境正常、或在環境/程式碼異動後想確認功能完整性時使用。
---


## 執行流程

### 1. 驗證開發環境版本
執行 `node --version`，確認為 v18 以上。


### 2. 驗證所有 JS 語法
分別執行：
- `node --check cve-checker.js`
- `node --check team-report.js`
- `node --check web-server.js`


### 3. 驗證 team-report.js 功能
若 `./team` 目錄有 JSON 檔案，執行 `node team-report.js`，確認：
- 成功讀取 `./team` 目錄中的 JSON 檔案
- 用 Glob 工具搜尋 `report/team_*.html`，確認有符合的檔案
- 用 PowerShell 工具執行 `(Get-Item report\team_*.html).Length` 確認大小 > 0

若 `./team` 目錄無 JSON 檔案，此步驟標記為「略過（無測試資料）」，不視為失敗。


### 4. 驗證關鍵 API（`cve-checker.js` 與 `web-server.js`）
用 Grep 工具確認以下字串存在（正向）及不存在（否定）：
- `fetch` 存在於 `cve-checker.js`；`require('https')` 不存在於 `cve-checker.js` 與 `web-server.js`
- `AbortSignal.timeout` 存在於 `cve-checker.js`
- `execFileSync` 存在；用 pattern `\bexecSync\b` grep 確認無獨立 `execSync` 呼叫
- `randomUUID` 存在於 `cve-checker.js`
- `fs\.promises` 存在於 `cve-checker.js`


## 輸出格式

每個步驟顯示 ✓（通過）或 ✗（失敗），失敗時顯示錯誤訊息。
所有步驟通過後，顯示「✓ 驗證完成，三支程式均正常」。
