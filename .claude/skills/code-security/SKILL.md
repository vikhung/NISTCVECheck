對 *.js 進行靜態安全分析，並評估 Node.js v18 現代化改善空間。

---
name: code-security
description: 當使用者要求安全審查、code review 的安全面向、或提交前進行靜態分析時使用。
---


## A. 安全弱點掃描

範圍：`cve-checker.js`、`web-server.js`、`team-report.js`、`web-client.html`
執行前先用 Read 工具讀取 `cve-checker.js`、`web-server.js`、`team-report.js` 的完整內容；`web-client.html` 僅用 Grep 工具搜尋 `innerHTML`、`insertAdjacentHTML`、`eval` 等危險模式，不需整份讀取。不要根據記憶判斷。
只回報信心度 >80%、有實際可利用路徑的問題：

1. **XSS（報表端）**：`cve-checker.js` 產生 HTML 時，NVD API 回傳的資料（CVE 描述、版本號等）是否都經過正確的 HTML 轉義（需包含 `&`、`<`、`>`、`"`、`'` 五個字元）
2. **XSS（伺服器注入端）**：`web-server.js` 動態將 `PORTABLE_N`、`WHITELIST` 值注入 `<script>` 時，是否對特殊字元做轉義（來源雖為 `.env.local`，仍需防守）
3. **Command Injection**：`execFileSync` 的引數是否全部以陣列傳入，有無字串拼接進 shell
4. **Path Traversal**：`web-server.js` 服務靜態檔案時路徑是否有過濾（防止 `../../` 跳出目錄）；使用者傳入的 JSON 檔案路徑是否未經驗證就直接讀取
5. **Prototype Pollution**：是否有對 `JSON.parse` 結果進行遞歸屬性合併，或以外部資料的 key 直接設定物件屬性（如 `target[key] = value`）
6. **可預測的臨時檔名**：臨時 `.ps1` 檔是否使用 `crypto.randomUUID()` 產生

## B. Node.js v18+ 現代化評估

範圍：`cve-checker.js`、`web-server.js`、`team-report.js`（`web-client.html` 為瀏覽器端，不適用）
檢查下列項目是否已採用 v18+ 最佳實踐：

1. HTTP 請求是否使用內建 `fetch()` + `AbortSignal.timeout()`（不使用 `https` 模組）
2. 檔案 I/O 是否使用 `fs.promises`（非同步）
3. 目錄建立是否使用 `fs.promises.mkdir({ recursive: true })`
4. 子行程是否使用 `execFileSync` 陣列引數（不使用 `execSync` 字串）
5. 臨時檔案是否使用 `crypto.randomUUID()`
6. 主函式是否為 `async function main()` 並有 `.catch()` 錯誤處理（僅適用 `cve-checker.js` 與 `team-report.js`；`web-server.js` 為常駐伺服器，直接啟動不需包裝 main，不在此項範圍）

## 輸出格式

**安全弱點**：每筆列出檔名、行號、問題描述、利用情境、修復建議。
**現代化評估**：每項列出狀態（✓ 已符合 / ✗ 需改善）及改善方式。

若兩個維度都沒有問題，明確說明「無發現問題」。
