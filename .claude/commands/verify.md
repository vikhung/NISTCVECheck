快速驗證 cve-checker.js 和 team-report.js 是否都能正常執行，並確認輸出檔案格式正確。

## 驗證步驟

### 1. 確認 Node.js 版本
執行 `node --version`，確認為 v18 以上。

### 2. 驗證 team-report.js
執行 `node team-report.js`，確認：
- 成功讀取 `./team` 目錄中的 JSON 檔案
- 產生 `./report/team_YYYYMMDDhhmmss.html`
- 輸出檔案存在且大小 > 0

### 3. 驗證 cve-checker.js 語法
執行 `node --check cve-checker.js`，確認無語法錯誤。

### 4. 驗證關鍵 API 存在
執行以下檢查，確認所有 Node.js v18 API 都已正確使用：
- `fetch` 已使用（不使用 `https` 模組）
- `AbortSignal.timeout` 已使用
- `execFileSync` 已使用（不使用 `execSync`）
- `randomUUID` 已使用
- `fs.promises` 已使用

## 輸出格式

每個步驟顯示 ✓（通過）或 ✗（失敗），失敗時顯示錯誤訊息。
所有步驟通過後，顯示「✓ 驗證完成，兩支程式均正常」。
